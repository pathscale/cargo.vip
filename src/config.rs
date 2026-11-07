use crate::broker::issue_credentials;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// `~/.config/cargo-vip/credentials.toml`.
///
/// In the default flow this holds broker tokens, one for each registry bucket.
/// The old top-level `token` field remains readable as a legacy single-token
/// file. `key_id`/`key_secret` are for buckets with no broker in front of them.
#[derive(Deserialize, Serialize, Default)]
#[serde(default)]
pub(super) struct FileConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) broker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) key_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) region: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) registry: Vec<RegistryToken>,
}

impl FileConfig {
    pub(super) fn find_by_bucket(&self, bucket: &str) -> Option<&RegistryToken> {
        self.registry.iter().find(|entry| entry.bucket == bucket)
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct RegistryToken {
    pub(super) bucket: String,
    pub(super) token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) broker: Option<String>,
}

fn credentials_path() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|d| d.join("cargo-vip").join("credentials.toml"))
}

/// Persist credentials without ever opening the final path for truncating write.
/// On Unix the same-directory rename atomically replaces the old regular file;
/// other platforms receive their native rename semantics, which are not
/// promised to be atomic replacement.
pub(super) fn persist_credentials(path: &Path, contents: &[u8]) -> Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;

    let parent = path.parent().context("credential path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let parent_meta =
        fs::symlink_metadata(parent).with_context(|| format!("checking {}", parent.display()))?;
    if parent_meta.file_type().is_symlink() || !parent_meta.is_dir() {
        bail!(
            "credential directory is not a real directory: {}",
            parent.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", parent.display()))?;
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("refusing unsafe credential destination: {}", path.display());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("checking {}", path.display())),
    }

    let mut temporary = None;
    let mut file = None;
    for _ in 0..8 {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).context("generating a credential temporary name")?;
        let candidate = parent.join(format!(".credentials-{}.tmp", hex::encode(random)));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(created) => {
                temporary = Some(candidate);
                file = Some(created);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("creating temporary credentials in {}", parent.display())
                });
            }
        }
    }
    let temporary = temporary.context("could not allocate a unique credential temporary file")?;
    let write_result = (|| -> Result<()> {
        let mut file = file.context("credential temporary file was not opened")?;
        file.write_all(contents)
            .context("writing temporary credentials")?;
        file.sync_all().context("syncing temporary credentials")?;
        drop(file);
        // On Unix, rename replaces the destination directory entry atomically.
        // Other platforms may reject replacement; then the old file remains.
        fs::rename(&temporary, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

pub(super) fn load_file_config() -> Result<FileConfig> {
    let Some(path) = credentials_path() else {
        return Ok(FileConfig::default());
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_credentials_file(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FileConfig::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub(super) fn parse_credentials_file(text: &str) -> Result<FileConfig> {
    toml::from_str(text).map_err(|_| anyhow::anyhow!("could not parse credentials file"))
}

pub(super) fn save_registry_token(file: &mut FileConfig, bucket: &str, token: &str, broker: &str) {
    let entry = RegistryToken {
        bucket: bucket.to_owned(),
        token: token.to_owned(),
        broker: Some(broker.to_owned()),
    };
    if let Some(existing) = file.registry.iter_mut().find(|item| item.bucket == bucket) {
        *existing = entry;
    } else {
        file.registry.push(entry);
    }
}

/// Store a token for the registry management API.
///
/// The token is what gets persisted; the object-store key never is. Revoking
/// the token at the registry therefore ends access at the next build.
pub(super) async fn login(broker: &str, mut file: FileConfig) -> Result<()> {
    use std::io::IsTerminal;

    let Some(path) = credentials_path() else {
        bail!("cannot determine a config directory");
    };

    let stdin = std::io::stdin();
    let token = if stdin.is_terminal() {
        rpassword::prompt_password(format!("Enter your {broker} token: "))
            .context("reading the token")?
    } else {
        let mut token = String::new();
        stdin.read_line(&mut token).context("reading the token")?;
        token
    };
    let token = token.trim();
    if token.is_empty() {
        bail!("no token given");
    }

    // Verify before storing, so a typo fails here and not inside a build.
    let resolved = issue_credentials(broker, token).await?;

    // A pre-multi-registry file has one top-level token but no bucket. Resolve
    // it once so the next write can migrate it without discarding access to a
    // different product. If the old token is no longer valid, keep it intact
    // as a legacy entry while still saving the newly verified token.
    if let Some(legacy_token) = file.token.clone() {
        if legacy_token == token {
            file.token = None;
            file.broker = None;
        } else {
            let Some(legacy_broker) = file.broker.clone() else {
                bail!(
                    "legacy credentials have no recorded broker; migrate them explicitly before login"
                );
            };
            match issue_credentials(&legacy_broker, &legacy_token).await {
                Ok(old) => {
                    if !file.registry.iter().any(|entry| entry.bucket == old.bucket) {
                        save_registry_token(&mut file, &old.bucket, &legacy_token, &legacy_broker);
                    }
                    file.token = None;
                    file.broker = None;
                }
                Err(_) => eprintln!(
                    "warning: could not resolve the previous single-token credentials; keeping them in legacy form"
                ),
            }
        }
    }
    save_registry_token(&mut file, &resolved.bucket, token, broker);

    let text = toml::to_string_pretty(&file).context("serializing credentials")?;
    persist_credentials(&path, text.as_bytes())?;

    eprintln!("logged in; registry bucket {}", resolved.bucket);
    Ok(())
}
