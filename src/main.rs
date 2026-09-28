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

mod publish;

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

/// `registryApi.IssueCredentials` in the registry's generated schema.
const ISSUE_CREDENTIALS: u32 = 20030;

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

    /// Registry management API that issues credentials. The default flow is to
    /// hold no object-store key at all: `cargo vip login` stores a token for
    /// this service, and each run exchanges it for a scoped key held in memory.
    #[arg(long, env = "CARGO_VIP_BROKER", default_value = "wss://api.crates.vip")]
    broker: String,

    /// Use this key directly and never contact the broker. Both halves must be
    /// given. This is the CI path, and the path for any bucket that has no
    /// broker in front of it.
    #[arg(long, env = "CARGO_VIP_KEY_ID", hide_env_values = true)]
    key_id: Option<String>,

    #[arg(long, env = "CARGO_VIP_KEY_SECRET", hide_env_values = true)]
    key_secret: Option<String>,

    /// A registry token, in place of the one `cargo vip login` stored: how CI
    /// passes one, from a secret. A `ReadOnly` token builds; a `Publish` token
    /// also runs `cargo vip publish`.
    #[arg(long, env = "CARGO_VIP_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Serve the index and stay in the foreground, printing the config stanza,
    /// instead of running cargo.
    #[arg(long)]
    serve: bool,

    /// The cargo invocation to wrap, e.g. `cargo vip build --release`.

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cargo_args: Vec<String>,
}

/// `~/.config/cargo-vip/credentials.toml`.
///
/// In the default flow this holds only `token` — a credential for the registry
/// management API, which is revocable and is not an object-store key. The
/// `key_id`/`key_secret` fields exist for buckets with no broker in front of
/// them; setting them skips the broker entirely.
#[derive(Deserialize, Default)]
struct FileConfig {
    broker: Option<String>,
    token: Option<String>,
    key_id: Option<String>,
    key_secret: Option<String>,
    bucket: Option<String>,
    endpoint: Option<String>,
    region: Option<String>,
}

/// What the registry needs to be read, however it was obtained.
struct Resolved {
    key_id: String,
    key_secret: String,
    bucket: String,
    endpoint: String,
    region: String,
}

/// Where credentials come from.
///
/// Tigris has no STS: access keys are long-lived, so fetching per run buys no
/// expiry. What it buys is that the long-lived key is never written to disk —
/// the only thing persisted is the broker token, which the registry can revoke.
enum Source {
    /// Explicit key. Skips the broker.
    Static(Resolved),
    /// Exchange a token for a scoped key at each run.
    Broker { url: String, token: String },
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

/// Decide where credentials come from.
///
/// An explicit key always wins, so CI and any bucket without a broker keep
/// working and never touch the network for credentials. Otherwise the broker
/// token is used, which is the default for a person.
fn source(args: &Args, file: FileConfig) -> Result<Source> {
    let key_id = args.key_id.clone().or(file.key_id);
    let key_secret = args.key_secret.clone().or(file.key_secret);
    let bucket = args.bucket.clone().or(file.bucket);

    match (key_id, key_secret) {
        (Some(key_id), Some(key_secret)) => {
            let Some(bucket) = bucket else {
                bail!("an explicit key needs --bucket or CARGO_VIP_BUCKET");
            };
            Ok(Source::Static(Resolved {
                key_id,
                key_secret,
                bucket,
                endpoint: file.endpoint.unwrap_or_else(|| args.endpoint.clone()),
                region: file.region.unwrap_or_else(|| args.region.clone()),
            }))
        }
        (Some(_), None) | (None, Some(_)) => {
            bail!("--key-id and --key-secret must be given together")
        }
        (None, None) => match args.token.clone().or(file.token) {
            Some(token) => Ok(Source::Broker {
                url: file.broker.unwrap_or_else(|| args.broker.clone()),
                token,
            }),
            None => bail!(
                "not logged in: run `cargo vip login` or set CARGO_VIP_TOKEN, or pass \
                 --key-id/--key-secret with --bucket to use a key directly"
            ),
        },
    }
}

/// Store a token for the registry management API.
///
/// The token is what gets persisted; the object-store key never is. Revoking
/// the token at the registry therefore ends access at the next build.
async fn login(broker: &str) -> Result<()> {
    let Some(path) = credentials_path() else {
        bail!("cannot determine a config directory");
    };

    eprintln!("Paste your {broker} token (it is not echoed to the terminal):");
    let mut token = String::new();
    std::io::stdin()
        .read_line(&mut token)
        .context("reading the token")?;
    let token = token.trim();
    if token.is_empty() {
        bail!("no token given");
    }

    // Verify before storing, so a typo fails here and not inside a build.
    let resolved = issue_credentials(broker, token).await?;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // The broker is stored with the token: a person should not have to repeat
    // --broker on every build, and a token is only meaningful against the
    // registry that issued it.
    std::fs::write(
        &path,
        format!("token = \"{token}\"\nbroker = \"{broker}\"\n"),
    )
    .with_context(|| format!("writing {}", path.display()))?;

    // The file holds a credential; other users on the machine should not read it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting {}", path.display()))?;
    }

    eprintln!("logged in; registry bucket {}", resolved.bucket);
    Ok(())
}

/// Exchange a broker token for a scoped object-store key.
///
/// The registry's management surface is an endpoint-libs WebSocket. A machine
/// signs in with `TokenConnect`, which travels in `Sec-WebSocket-Protocol` at
/// handshake time as `["0tokenconnect", "1<token>"]` (`Init` is for people, with
/// a honey.id access token), and nothing else can be called until it resolves.
/// That is a small enough wire contract to speak directly rather than take a
/// dependency on the server's crate.
async fn issue_credentials(broker: &str, token: &str) -> Result<Resolved> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;

    let mut request = broker
        .into_client_request()
        .with_context(|| format!("{broker} is not a valid WebSocket URL"))?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_str(&format!("0tokenconnect, 1{token}"))
            .context("the token is not valid in a header")?,
    );

    let (mut socket, _) = tokio_tungstenite::connect_async(request)
        .await
        .with_context(|| format!("connecting to {broker}"))?;

    // The handshake reply carries the authenticated identity; a bad token
    // fails here rather than on the call below.
    let _init = next_json(&mut socket).await.context("registry handshake")?;

    socket
        .send(Message::Text(
            serde_json::json!({ "method": ISSUE_CREDENTIALS, "seq": 1, "params": {} })
                .to_string()
                .into(),
        ))
        .await
        .context("requesting credentials")?;

    let reply = next_json(&mut socket)
        .await
        .context("issuing credentials")?;
    let params = reply.get("params").unwrap_or(&reply);

    let field = |name: &str| -> Result<String> {
        params
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .with_context(|| format!("the registry did not return {name}: {reply}"))
    };

    Ok(Resolved {
        key_id: field("keyId")?,
        key_secret: field("keySecret")?,
        bucket: field("bucket")?,
        endpoint: field("endpoint")?,
        region: field("region")?,
    })
}

async fn next_json<S>(socket: &mut S) -> Result<serde_json::Value>
where
    S: futures_util::Stream<
            Item = Result<
                tokio_tungstenite::tungstenite::Message,
                tokio_tungstenite::tungstenite::Error,
            >,
        > + Unpin,
{
    use futures_util::StreamExt;
    while let Some(message) = socket.next().await {
        match message.context("reading from the registry")? {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                let value: serde_json::Value =
                    serde_json::from_str(&text).context("the registry sent invalid JSON")?;
                if let Some(error) = value.get("error") {
                    bail!("the registry refused: {error}");
                }
                return Ok(value);
            }
            tokio_tungstenite::tungstenite::Message::Close(frame) => {
                bail!("the registry closed the connection: {frame:?}");
            }
            _ => {}
        }
    }
    bail!("the registry closed the connection without replying")
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

    if args.cargo_args.first().is_some_and(|a| a == "login") {
        return login(&args.broker).await;
    }

    let resolved = match source(&args, file)? {
        Source::Static(resolved) => resolved,
        Source::Broker { url, token } => issue_credentials(&url, &token).await?,
    };
    let (key_id, key_secret, bucket_name, endpoint, region) = (
        resolved.key_id,
        resolved.key_secret,
        resolved.bucket,
        resolved.endpoint,
        resolved.region,
    );

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
    let loopback = format!("sparse+{origin}/");
    // What crates and lockfiles name the registry by. Never fetched: cargo
    // replaces it with the loopback source, and records the stable URL, so a
    // lockfile and a packaged crate do not change with this run's port.
    let stable = format!("sparse+https://crates.vip/{}/", registry.bucket.name());
    let config = cargo_config(&args.registry, &stable, &loopback);

    if args.serve {
        println!("[registries.{}]", args.registry);
        println!("index = \"{stable}\"");
        println!();
        println!("[source.{}-remote]", args.registry);
        println!("registry = \"{stable}\"");
        println!("replace-with = \"{}-loopback\"", args.registry);
        println!();
        println!("[source.{}-loopback]", args.registry);
        println!("registry = \"{loopback}\"");
        tokio::signal::ctrl_c().await?;
        return Ok(());
    }

    if args.cargo_args.is_empty() {
        bail!("nothing to run: try `cargo vip build`, or --serve to stay in the foreground");
    }

    if args.cargo_args.first().is_some_and(|a| a == "publish") {
        let request = publish_request(&args.cargo_args[1..], &args.registry, &stable)?;
        let target = publish::Target {
            client: &registry.client,
            bucket: &registry.bucket,
            credentials: &registry.credentials,
        };
        let outcome = publish::publish(&target, &request, &config).await;
        serving.abort();
        return outcome;
    }

    // `--config` rather than `.cargo/config.toml`, so wrapping a build edits no
    // file and leaves nothing behind.
    //
    // Cargo does not forward `--config` to an external subcommand such as
    // `cargo clippy`, and source replacement cannot be set from the
    // environment. So the index is also pointed straight at the loopback
    // through the environment, which `--config` outranks for built-in
    // commands; only an external one sees it, and its lockfile then names the
    // loopback.
    let status =
        tokio::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .env(index_env(&args.registry), &loopback)
            .args(&config)
            .args(&args.cargo_args)
            .status()
            .await
            .context("running cargo")?;

    serving.abort();
    std::process::exit(status.code().unwrap_or(1));
}

/// The environment variable that sets `registries.<registry>.index`.
fn index_env(registry: &str) -> String {
    format!(
        "CARGO_REGISTRIES_{}_INDEX",
        registry.to_uppercase().replace('-', "_")
    )
}

/// The `--config` arguments that point cargo at this process: the registry
/// under its stable URL, replaced by the loopback source.
fn cargo_config(registry: &str, stable: &str, loopback: &str) -> Vec<String> {
    [
        format!("registries.{registry}.index=\"{stable}\""),
        format!("source.{registry}-remote.registry=\"{stable}\""),
        format!("source.{registry}-remote.replace-with=\"{registry}-loopback\""),
        format!("source.{registry}-loopback.registry=\"{loopback}\""),
    ]
    .into_iter()
    .flat_map(|setting| ["--config".to_owned(), setting])
    .collect()
}

/// `cargo vip publish [--manifest-path PATH] [--dry-run]`.
fn publish_request(rest: &[String], registry: &str, index_url: &str) -> Result<publish::Request> {
    let mut manifest_path = PathBuf::from("Cargo.toml");
    let mut dry_run = false;
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--manifest-path" => {
                manifest_path = rest.next().context("--manifest-path needs a path")?.into();
            }
            other => match other.strip_prefix("--manifest-path=") {
                Some(path) => manifest_path = path.into(),
                None => bail!("cargo vip publish takes --manifest-path and --dry-run, not {other}"),
            },
        }
    }
    Ok(publish::Request {
        manifest_path,
        dry_run,
        registry: registry.to_owned(),
        index_url: index_url.to_owned(),
    })
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

        tracing::debug!("{name} {version} -> presigned");
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

    tracing::debug!("{key}");
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
