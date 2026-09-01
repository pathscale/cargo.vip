//! cargo.vip — use a private S3-compatible bucket as a Cargo registry.
//!
//! Cargo authenticates with `Authorization: <token>`. Every S3-compatible store
//! wants an AWS `SigV4` signature and accepts nothing else. So a private bucket is
//! unreachable to cargo on its own, and the usual workarounds are to make the
//! bucket public or to run a registry server.
//!
//! This does neither. It serves the sparse index on loopback, signs each read
//! with the caller's own key, and answers tarball fetches with a presigned
//! redirect so the bytes travel straight from the bucket. Nothing is deployed,
//! and access is exactly what the caller's key is scoped to — revoking a key
//! revokes a person.
//!
//! ```text
//! cargo vip build
//! ```
//!
//! wraps the cargo invocation with `CARGO_REGISTRIES_<NAME>_INDEX` pointed at
//! the listener, so no `.cargo/config.toml` index entry is needed and nothing
//! is left behind when it exits.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use rusty_s3::actions::GetObject;
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// How long a tarball's presigned URL stays valid. Cargo follows the redirect
/// straight away, so this only has to cover clock skew and the transfer.
const DOWNLOAD_TTL: Duration = Duration::from_secs(300);

/// A signed index read is used immediately by this process.
const READ_TTL: Duration = Duration::from_secs(60);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(
    name = "cargo-vip",
    bin_name = "cargo vip",
    version,
    about = "Use a private S3-compatible bucket as a Cargo registry"
)]
struct Args {
    /// Registry name, as used in `registry = "…"` in Cargo.toml.
    #[arg(long, env = "CARGO_VIP_REGISTRY", default_value = "vip")]
    registry: String,

    /// S3 endpoint. Defaults to Tigris; any S3-compatible store works.
    #[arg(
        long,
        env = "CARGO_VIP_ENDPOINT",
        default_value = "https://fly.storage.tigris.dev"
    )]
    endpoint: String,

    #[arg(long, env = "CARGO_VIP_REGION", default_value = "auto")]
    region: String,

    /// Bucket holding the index at the root and tarballs under `crates/`.
    #[arg(long, env = "CARGO_VIP_BUCKET")]
    bucket: Option<String>,

    #[arg(long, env = "CARGO_VIP_KEY_ID", hide_env_values = true)]
    key_id: Option<String>,

    #[arg(long, env = "CARGO_VIP_KEY_SECRET", hide_env_values = true)]
    key_secret: Option<String>,

    /// Serve the index and stay in the foreground, printing the config stanza,
    /// instead of running cargo.
    #[arg(long)]
    serve: bool,

    /// The cargo invocation to wrap, e.g. `cargo vip build --release`.

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cargo_args: Vec<String>,
}

/// `~/.config/cargo-vip/credentials.toml`, so a key need not be pasted into a
/// shell on every invocation.
#[derive(Deserialize, Default)]
struct FileConfig {
    key_id: Option<String>,
    key_secret: Option<String>,
    bucket: Option<String>,
    endpoint: Option<String>,
    region: Option<String>,
}

fn credentials_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|d| d.join("cargo-vip").join("credentials.toml"))
}

fn load_file_config() -> Result<FileConfig> {
    let Some(path) = credentials_path() else {
        return Ok(FileConfig::default());
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

struct Registry {
    client: Client,
    credentials: Credentials,
    bucket: Bucket,
    /// Loopback origin this listener is reachable at. `config.json` is generated
    /// against it rather than stored in the bucket, so nothing published records
    /// how a particular machine reaches the registry.
    origin: String,
}

impl Registry {
    /// The key a tarball is stored under. Content-addressed, and the same
    /// layout the publisher writes, so the two cannot drift.
    fn crate_key(name: &str, version: &str, cksum: &str) -> String {
        format!("crates/{name}-{version}_{cksum}.tar.gz")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .init();

    // `cargo vip build` reaches this binary as `cargo-vip vip build`, so the
    // subcommand name cargo inserts is dropped.
    let raw: Vec<String> = std::env::args()
        .enumerate()
        .filter(|(i, a)| !(*i == 1 && a == "vip"))
        .map(|(_, a)| a)
        .collect();
    let args = Args::parse_from(raw);
    let file = load_file_config()?;

    let (Some(key_id), Some(key_secret)) = (
        args.key_id.or(file.key_id),
        args.key_secret.or(file.key_secret),
    ) else {
        bail!(
            "no credentials: set CARGO_VIP_KEY_ID and CARGO_VIP_KEY_SECRET, or write them to {}",
            credentials_path().unwrap_or_default().display()
        );
    };
    let Some(bucket_name) = args.bucket.or(file.bucket) else {
        bail!("no bucket: pass --bucket or set CARGO_VIP_BUCKET");
    };

    let endpoint = file.endpoint.unwrap_or(args.endpoint);
    let region = file.region.unwrap_or(args.region);

    // Loopback only. The key lives in this process and nothing off the machine
    // should be able to borrow it.
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .context("binding the loopback listener")?;
    let origin = format!("http://{}", listener.local_addr()?);

    let registry = Arc::new(Registry {
        client: Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("building the HTTP client")?,
        credentials: Credentials::new(key_id, key_secret),
        // Path style, which is what S3-compatible stores serve.
        bucket: Bucket::new(
            endpoint
                .parse()
                .with_context(|| format!("parsing {endpoint}"))?,
            UrlStyle::Path,
            bucket_name,
            region,
        )
        .context("building the bucket")?,
        origin: origin.clone(),
    });

    let serving = tokio::spawn(serve(listener, Arc::clone(&registry)));
    let index_url = format!("sparse+{origin}/");

    if args.serve {
        println!("[registries.{}]", args.registry);
        println!("index = \"{index_url}\"");
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    if args.cargo_args.is_empty() {
        bail!("nothing to run: try `cargo vip build`, or --serve to stay in the foreground");
    }

    // Cargo takes the index from the environment, so wrapping a build needs no
    // edit to `.cargo/config.toml`.
    let env_key = format!(
        "CARGO_REGISTRIES_{}_INDEX",
        args.registry.to_uppercase().replace('-', "_")
    );

    let status =
        tokio::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(&args.cargo_args)
            .env(&env_key, &index_url)
            .status()
            .await
            .context("running cargo")?;

    serving.abort();
    std::process::exit(status.code().unwrap_or(1));
}

async fn serve(listener: TcpListener, registry: Arc<Registry>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let registry = Arc::clone(&registry);
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(req, Arc::clone(&registry)));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                tracing::debug!("connection ended: {e}");
            }
        });
    }
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    registry: Arc<Registry>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path().to_owned();
    Ok(match route(&path, &registry).await {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("{path}: {e:#}");
            reply(StatusCode::BAD_GATEWAY, "text/plain", format!("{e:#}"))
        }
    })
}

async fn route(path: &str, registry: &Registry) -> Result<Response<Full<Bytes>>> {
    // Generated, not stored: `dl` has to name this process, and baking a
    // loopback address into the bucket would impose it on every consumer.
    if path == "/config.json" {
        let body = format!(
            "{{\n  \"dl\": \"{origin}/dl/{{crate}}/{{version}}/{{sha256-checksum}}\",\n  \
             \"api\": \"{origin}\",\n  \"auth-required\": false\n}}\n",
            origin = registry.origin,
        );
        return Ok(reply(StatusCode::OK, "application/json", body));
    }

    // Redirect rather than proxy, so a tarball never passes through here.
    if let Some(rest) = path.strip_prefix("/dl/") {
        let parts: Vec<&str> = rest.split('/').collect();
        let [name, version, cksum] = parts[..] else {
            return Ok(reply(
                StatusCode::NOT_FOUND,
                "text/plain",
                "malformed download path",
            ));
        };
        if hex::decode(cksum).map(|b| b.len()) != Ok(32) {
            bail!("download path does not carry a sha256");
        }

        let key = Registry::crate_key(name, version, cksum);
        let url = GetObject::new(&registry.bucket, Some(&registry.credentials), &key)
            .sign(DOWNLOAD_TTL)
            .to_string();

        tracing::info!("{name} {version} -> presigned");
        return Ok(Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header("location", url)
            .body(Full::new(Bytes::new()))
            .expect("valid redirect"));
    }

    // Anything else is an index path. Cargo already knows the sparse layout, so
    // it goes to the bucket as-is under a signed read.
    let key = path.trim_start_matches('/');
    if key.is_empty() {
        return Ok(reply(StatusCode::NOT_FOUND, "text/plain", "no index path"));
    }

    let url = GetObject::new(&registry.bucket, Some(&registry.credentials), key).sign(READ_TTL);
    let res = registry
        .client
        .get(url)
        .send()
        .await
        .context("fetching the index entry")?;

    if res.status() == StatusCode::NOT_FOUND {
        return Ok(reply(
            StatusCode::NOT_FOUND,
            "text/plain",
            "not in this registry",
        ));
    }

    let body = res
        .error_for_status()
        .context("fetching the index entry")?
        .bytes()
        .await
        .context("reading the index entry")?;

    tracing::info!("{key}");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        // Cargo must see a version published seconds ago.
        .header("cache-control", "no-cache")
        .body(Full::new(body))
        .expect("valid response"))
}

fn reply(status: StatusCode, content_type: &str, body: impl Into<String>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body.into())))
        .expect("valid response")
}

#[cfg(test)]
mod tests {
    use super::Registry;

    #[test]
    fn crate_key_is_content_addressed() {
        assert_eq!(
            Registry::crate_key("worktable", "1.0.0-beta.11", "abc123"),
            "crates/worktable-1.0.0-beta.11_abc123.tar.gz",
        );
    }
}
