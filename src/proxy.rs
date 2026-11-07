use crate::broker::Resolved;
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::header::HOST;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use rusty_s3::actions::GetObject;
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// How long a tarball's presigned URL stays valid. Cargo follows the redirect
/// straight away, so this only has to cover clock skew and the transfer.
const DOWNLOAD_TTL: Duration = Duration::from_secs(300);

/// A signed index read is used immediately by this process.
const READ_TTL: Duration = Duration::from_secs(60);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct Registry {
    pub(super) client: Client,
    pub(super) credentials: Credentials,
    pub(super) bucket: Bucket,
    /// Loopback origin this listener is reachable at. `config.json` is generated
    /// against it rather than stored in the bucket, so nothing published records
    /// how a particular machine reaches the registry.
    origin: String,
    authority: String,
    access_prefix: String,
}

impl Registry {
    /// The key a tarball is stored under. Content-addressed, and the same
    /// layout the publisher writes, so the two cannot drift.
    pub(super) fn crate_key(name: &str, version: &str, cksum: &str) -> String {
        format!("crates/{name}-{version}_{cksum}.tar.gz")
    }
}

pub(super) struct ActiveProxy {
    pub(super) name: String,
    pub(super) stable: String,
    pub(super) loopback: String,
    pub(super) registry: Arc<Registry>,
}

pub(super) async fn start_proxies(
    resolved: Vec<(String, Resolved)>,
) -> Result<(Vec<ActiveProxy>, Vec<tokio::task::JoinHandle<()>>)> {
    let client = Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("building the HTTP client")?;
    let mut proxies = Vec::new();
    let mut serving = Vec::new();
    for (name, resolved) in resolved {
        // Loopback only. The key lives in this process and nothing off the machine
        // should be able to borrow it.
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("binding the loopback listener")?;
        let authority = listener.local_addr()?.to_string();
        let mut capability = [0u8; 32];
        getrandom::fill(&mut capability).context("generating a loopback access capability")?;
        let access_prefix = hex::encode(capability);
        let origin = format!("http://{authority}/{access_prefix}");
        let registry = Arc::new(Registry {
            client: client.clone(),
            credentials: Credentials::new(resolved.key_id, resolved.key_secret),
            // Path style, which is what S3-compatible stores serve.
            bucket: Bucket::new(
                resolved
                    .endpoint
                    .parse()
                    .context("parsing the object-store endpoint")?,
                UrlStyle::Path,
                resolved.bucket,
                resolved.region,
            )
            .context("building the bucket")?,
            origin: origin.clone(),
            authority,
            access_prefix,
        });
        serving.push(tokio::spawn(serve(listener, Arc::clone(&registry))));
        proxies.push(ActiveProxy {
            name,
            stable: format!("sparse+https://crates.vip/{}/", registry.bucket.name()),
            loopback: format!("sparse+{origin}/"),
            registry,
        });
    }
    Ok((proxies, serving))
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
    if req.method() != Method::GET
        || req.uri().scheme().is_some()
        || req.uri().authority().is_some()
        || req.uri().query().is_some()
        || req.headers().get_all(HOST).iter().count() != 1
        || req
            .headers()
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            != Some(registry.authority.as_str())
    {
        return Ok(reply(
            StatusCode::FORBIDDEN,
            "text/plain",
            "loopback request refused",
        ));
    }

    let prefix = format!("/{}/", registry.access_prefix);
    let Some(relative) = req.uri().path().strip_prefix(&prefix) else {
        return Ok(reply(StatusCode::NOT_FOUND, "text/plain", "not found"));
    };
    let path = format!("/{relative}");
    Ok(if let Ok(response) = route(&path, &registry).await {
        response
    } else {
        tracing::error!("registry upstream request failed");
        reply(
            StatusCode::BAD_GATEWAY,
            "text/plain",
            "registry upstream request failed",
        )
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
        if !valid_download_components(name, version, cksum) {
            return Ok(reply(
                StatusCode::NOT_FOUND,
                "text/plain",
                "malformed download path",
            ));
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
    let Some(key) = path.strip_prefix('/') else {
        return Ok(reply(
            StatusCode::NOT_FOUND,
            "text/plain",
            "invalid sparse index path",
        ));
    };
    if !valid_sparse_index_key(key) {
        return Ok(reply(
            StatusCode::NOT_FOUND,
            "text/plain",
            "invalid sparse index path",
        ));
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

fn valid_crate_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(super) fn valid_download_components(name: &str, version: &str, checksum: &str) -> bool {
    valid_crate_name(name)
        && !version.is_empty()
        && version != "."
        && version != ".."
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
        && checksum.len() == 64
        && checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn valid_sparse_index_key(key: &str) -> bool {
    let parts: Vec<_> = key.split('/').collect();
    match parts.as_slice() {
        ["1", name] => name.len() == 1 && valid_crate_name(name),
        ["2", name] => name.len() == 2 && valid_crate_name(name),
        ["3", first, name] => name.len() == 3 && valid_crate_name(name) && *first == &name[..1],
        [first, second, name] => {
            name.len() >= 4
                && valid_crate_name(name)
                && *first == &name[..2]
                && *second == &name[2..4]
        }
        _ => false,
    }
}

fn reply(status: StatusCode, content_type: &str, body: impl Into<String>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body.into())))
        .expect("valid response")
}
