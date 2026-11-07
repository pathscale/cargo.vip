use anyhow::{Context, Result, bail};

/// `registryApi.IssueCredentials` in the registry's generated schema.
const ISSUE_CREDENTIALS: u32 = 20030;

/// What the registry needs to be read, however it was obtained.
#[derive(Clone)]
pub(super) struct Resolved {
    pub(super) key_id: String,
    pub(super) key_secret: String,
    pub(super) bucket: String,
    pub(super) endpoint: String,
    pub(super) region: String,
}

/// Exchange a broker token for a scoped object-store key.
///
/// The registry's management surface is an endpoint-libs WebSocket. A machine
/// signs in with `TokenConnect`, which travels in `Sec-WebSocket-Protocol` at
/// handshake time as `["0tokenconnect", "1<token>"]` (`Init` is for people, with
/// a honey.id access token), and nothing else can be called until it resolves.
/// That is a small enough wire contract to speak directly rather than take a
/// dependency on the server's crate.
pub(super) async fn issue_credentials(broker: &str, token: &str) -> Result<Resolved> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;

    validate_broker_url(broker)?;
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
            .with_context(|| format!("the registry did not return {name}"))
    };

    Ok(Resolved {
        key_id: field("keyId")?,
        key_secret: field("keySecret")?,
        bucket: field("bucket")?,
        endpoint: field("endpoint")?,
        region: field("region")?,
    })
}

pub(super) fn validate_broker_url(broker: &str) -> Result<()> {
    let broker_url = url::Url::parse(broker).context("invalid broker URL")?;
    if broker_url.scheme() != "wss"
        || !broker_url.username().is_empty()
        || broker_url.password().is_some()
        || broker_url.query().is_some()
    {
        bail!("broker authentication requires wss without URL userinfo or query parameters");
    }
    Ok(())
}

pub(super) async fn next_json<S>(socket: &mut S) -> Result<serde_json::Value>
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
        match message.map_err(|_| anyhow::anyhow!("reading from the registry failed"))? {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                let value: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|_| anyhow::anyhow!("the registry sent invalid JSON"))?;
                if value.get("error").is_some() {
                    bail!("the registry refused the credential request");
                }
                return Ok(value);
            }
            tokio_tungstenite::tungstenite::Message::Close(_) => {
                bail!("the registry closed the connection");
            }
            _ => {}
        }
    }
    bail!("the registry closed the connection without replying")
}
