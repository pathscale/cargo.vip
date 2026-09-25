//! `cargo vip publish`: package a crate and add it to the registry.
//!
//! Publishing is two writes to the bucket, with the same protocol as the
//! registry's own publisher (crates.vip-backend `crates-vip-index`):
//!
//! | Object | Precondition | Meaning |
//! |---|---|---|
//! | `crates/{name}-{version}_{sha}.tar.gz` | `If-None-Match: *` | A published version is immutable. |
//! | the index entry | `If-Match: {etag}` | Append one line, write back only if nobody else did; retry on `412`. |
//!
//! Tarball first: a tarball with no index entry is invisible, an index entry
//! with no tarball breaks every build that resolves to it.
//!
//! A crate is published only if its manifest says `publish = ["vip"]` (or
//! names this registry among others). A crate with the default `publish`
//! could reach crates.io by a stray `cargo publish`, and private source must
//! never leak, so it is refused until the manifest closes that door.

use anyhow::{Context, Result, bail};
use reqwest::Client;
use rusty_s3::actions::{GetObject, PutObject};
use rusty_s3::{Bucket, Credentials, S3Action};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where a dependency lives when `cargo metadata` reports no registry.
const CRATES_IO_INDEX: &str = "https://github.com/rust-lang/crates.io-index";

/// How many times to retry an index write that lost the race.
const CAS_ATTEMPTS: u32 = 8;

const SIGN_TTL: Duration = Duration::from_secs(60);

/// The answer to a write whose precondition failed.
const PRECONDITION_FAILED: u16 = 412;

pub struct Target<'a> {
    pub client: &'a Client,
    pub bucket: &'a Bucket,
    pub credentials: &'a Credentials,
}

/// What the invocation asked for.
pub struct Request {
    pub manifest_path: PathBuf,
    pub dry_run: bool,
    /// The registry's name, as crates spell it in `registry = "…"`.
    pub registry: String,
    /// The index URL this process serves the registry at, which is how
    /// `cargo metadata` reports a dependency on another crate in it.
    pub index_url: String,
}

/// # Errors
/// If the crate may not be published here, cannot be packaged, or a write
/// fails.
pub async fn publish(target: &Target<'_>, req: &Request, config: &[String]) -> Result<()> {
    let metadata = cargo_metadata(&req.manifest_path, config).await?;
    let package = metadata.package_at(&req.manifest_path)?;

    match &package.publish {
        Some(allowed) if allowed.contains(&req.registry) => {}
        Some(allowed) if allowed.is_empty() => {
            bail!("{} has publish = false", package.name)
        }
        _ => bail!(
            "{} does not restrict where it publishes. Add `publish = [\"{}\"]` to its \
             [package], so that no `cargo publish` can send it to crates.io",
            package.name,
            req.registry
        ),
    }

    let status = tokio::process::Command::new(cargo())
        .args(config)
        .args(["package", "--manifest-path"])
        .arg(&req.manifest_path)
        .status()
        .await
        .context("running cargo package")?;
    if !status.success() {
        bail!("cargo package failed");
    }

    let tarball_path = PathBuf::from(&metadata.target_directory)
        .join("package")
        .join(format!("{}-{}.crate", package.name, package.version));
    let tarball = std::fs::read(&tarball_path)
        .with_context(|| format!("reading {}", tarball_path.display()))?;
    let cksum = hex::encode(Sha256::digest(&tarball));
    let entry = package.index_entry(&cksum, &req.index_url)?;

    if req.dry_run {
        println!("{}", serde_json::to_string_pretty(&entry)?);
        tracing::info!("dry run: nothing written");
        return Ok(());
    }

    let key = crate::Registry::crate_key(&package.name, &package.version, &cksum);
    let status = put(
        target,
        &key,
        tarball,
        "application/x-tar",
        ("if-none-match", "*"),
    )
    .await?;
    if status == PRECONDITION_FAILED {
        tracing::info!("tarball already present");
    } else {
        tracing::info!("uploaded {key}");
    }

    let path = index_path(&package.name);
    for attempt in 1..=CAS_ATTEMPTS {
        let (mut body, etag) = get(target, &path).await?;
        for line in body.lines().filter(|l| !l.trim().is_empty()) {
            let existing: Value = serde_json::from_str(line)
                .with_context(|| format!("parsing the index entry for {}", package.name))?;
            if existing["vers"] == entry["vers"] {
                if existing["cksum"] == entry["cksum"] {
                    tracing::info!("{} {} was already published", package.name, package.version);
                    return Ok(());
                }
                bail!(
                    "{} {} is already published with different contents; a published \
                     version is immutable, so bump the version",
                    package.name,
                    package.version
                );
            }
        }
        if !body.is_empty() && !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&entry.to_string());
        body.push('\n');

        let precondition = match &etag {
            Some(etag) => ("if-match", etag.as_str()),
            None => ("if-none-match", "*"),
        };
        let status = put(target, &path, body.into_bytes(), "text/plain", precondition).await?;
        if status != PRECONDITION_FAILED {
            tracing::info!("published {} {}", package.name, package.version);
            return Ok(());
        }
        tracing::warn!(attempt, "the index entry changed underneath; retrying");
    }
    bail!("gave up after {CAS_ATTEMPTS} contended attempts to update the index")
}

fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".into())
}

/// A signed conditional `PUT`. Returns the status: `412` is an expected answer
/// for both callers, not a failure.
async fn put(
    target: &Target<'_>,
    key: &str,
    body: Vec<u8>,
    content_type: &str,
    (header, value): (&str, &str),
) -> Result<u16> {
    let mut action = PutObject::new(target.bucket, Some(target.credentials), key);
    // Signed headers must be sent exactly as signed.
    action.headers_mut().insert("content-type", content_type);
    action.headers_mut().insert(header, value);
    let res = target
        .client
        .put(action.sign(SIGN_TTL))
        .header("content-type", content_type)
        .header(header, value)
        .body(body)
        .send()
        .await
        .with_context(|| format!("writing {key}"))?;
    let status = res.status().as_u16();
    if status == PRECONDITION_FAILED || res.status().is_success() {
        return Ok(status);
    }
    bail!("writing {key}: the bucket answered HTTP {status}")
}

/// The object and its `ETag`, or empty and `None` when there is none yet.
async fn get(target: &Target<'_>, key: &str) -> Result<(String, Option<String>)> {
    let url = GetObject::new(target.bucket, Some(target.credentials), key).sign(SIGN_TTL);
    let res = target
        .client
        .get(url)
        .send()
        .await
        .with_context(|| format!("reading {key}"))?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok((String::new(), None));
    }
    let res = res
        .error_for_status()
        .with_context(|| format!("reading {key}"))?;
    let etag = res
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    Ok((res.text().await?, etag))
}

/// Cargo's sparse-index path for a crate name.
pub fn index_path(name: &str) -> String {
    let name = name.to_lowercase();
    match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[..1]),
        _ => format!("{}/{}/{name}", &name[..2], &name[2..4]),
    }
}

/// Two index URLs name the same registry: equal once the `sparse+` prefix and
/// a trailing slash are set aside.
fn same_index(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.strip_prefix("sparse+")
            .unwrap_or(s)
            .trim_end_matches('/')
            .to_owned()
    };
    norm(a) == norm(b)
}

async fn cargo_metadata(manifest_path: &Path, config: &[String]) -> Result<Metadata> {
    let out = tokio::process::Command::new(cargo())
        .args(config)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(manifest_path)
        .output()
        .await
        .context("running cargo metadata")?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("parsing cargo metadata")
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    target_directory: String,
}

impl Metadata {
    /// `cargo metadata` lists every workspace member whichever manifest it was
    /// pointed at; the manifest path is what identifies the one meant.
    fn package_at(&self, manifest_path: &Path) -> Result<&Package> {
        let wanted = manifest_path
            .canonicalize()
            .with_context(|| format!("resolving {}", manifest_path.display()))?;
        self.packages
            .iter()
            .find(|p| p.manifest_path.canonicalize().is_ok_and(|p| p == wanted))
            .with_context(|| format!("no package has the manifest {}", wanted.display()))
    }
}

#[derive(Deserialize)]
struct Package {
    manifest_path: PathBuf,
    name: String,
    version: String,
    features: BTreeMap<String, Vec<String>>,
    links: Option<String>,
    rust_version: Option<String>,
    /// `None` publishes anywhere, `[]` nowhere, a list only there.
    publish: Option<Vec<String>>,
    dependencies: Vec<MetadataDependency>,
}

#[derive(Deserialize)]
struct MetadataDependency {
    name: String,
    req: String,
    kind: Option<String>,
    optional: bool,
    uses_default_features: bool,
    features: Vec<String>,
    target: Option<String>,
    rename: Option<String>,
    registry: Option<String>,
}

impl Package {
    fn index_entry(&self, cksum: &str, own_index: &str) -> Result<Value> {
        // `dep:` and `pkg?/feat` go in features2, so a cargo too old to parse
        // them skips the field instead of failing on the whole entry.
        let (features2, features): (BTreeMap<_, _>, BTreeMap<_, _>) = self
            .features
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .partition(|(_, values)| {
                values
                    .iter()
                    .any(|f| f.starts_with("dep:") || f.contains("?/"))
            });
        let deps = self
            .dependencies
            .iter()
            .map(|d| d.index_dependency(own_index))
            .collect::<Result<Vec<_>>>()?;
        Ok(without_nulls(json!({
            "name": self.name,
            "vers": self.version,
            "deps": deps,
            "cksum": cksum,
            "features": features,
            "features2": features2,
            "yanked": false,
            "links": self.links,
            "rust_version": self.rust_version,
            "v": 2,
        })))
    }
}

impl MetadataDependency {
    fn index_dependency(&self, own_index: &str) -> Result<Value> {
        let kind = match self.kind.as_deref() {
            None | Some("normal") => "normal",
            Some("dev") => "dev",
            Some("build") => "build",
            Some(other) => bail!("unrecognised dependency kind {other:?} on {}", self.name),
        };
        // The index names a dependency by how it is depended on, with the real
        // package only when renamed; cargo metadata has it the other way round.
        let (name, package) = match &self.rename {
            Some(alias) => (alias.clone(), Some(self.name.clone())),
            None => (self.name.clone(), None),
        };
        // No `registry` means "this registry". So a crates.io dependency must
        // say so, and one in this registry must say nothing: the loopback URL
        // cargo reports for it names this machine, not the registry.
        let registry = match self.registry.as_deref() {
            Some(index) if same_index(index, own_index) => None,
            Some(index) => Some(index.to_owned()),
            None => Some(CRATES_IO_INDEX.to_owned()),
        };
        let mut features = self.features.clone();
        features.sort();
        features.dedup();
        Ok(without_nulls(json!({
            "name": name,
            "req": self.req,
            "features": features,
            "optional": self.optional,
            "default_features": self.uses_default_features,
            "target": self.target,
            "kind": kind,
            "registry": registry,
            "package": package,
        })))
    }
}

/// Drop `null` fields: the index spells an absent optional field by leaving
/// it out.
fn without_nulls(mut value: Value) -> Value {
    if let Value::Object(map) = &mut value {
        map.retain(|_, v| !v.is_null());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{index_path, same_index};

    #[test]
    fn index_paths_follow_the_sparse_layout() {
        assert_eq!(index_path("a"), "1/a");
        assert_eq!(index_path("ab"), "2/ab");
        assert_eq!(index_path("abc"), "3/a/abc");
        assert_eq!(index_path("Pays-Hash"), "pa/ys/pays-hash");
    }

    #[test]
    fn the_loopback_index_is_this_registry() {
        assert!(same_index(
            "sparse+http://127.0.0.1:5000/",
            "sparse+http://127.0.0.1:5000"
        ));
        assert!(!same_index(
            "sparse+http://127.0.0.1:5000/",
            "https://github.com/rust-lang/crates.io-index"
        ));
    }
}
