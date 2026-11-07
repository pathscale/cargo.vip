use crate::broker::{Resolved, issue_credentials, validate_broker_url};
use crate::cli::Args;
use crate::config::FileConfig;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where credentials come from.
///
/// Tigris has no STS: access keys are long-lived, so fetching per run buys no
/// expiry. What it buys is that the long-lived key is never written to disk —
/// the only thing persisted is the broker token, which the registry can revoke.
pub(super) enum Source {
    /// Explicit key. Skips the broker.
    Static(Resolved),
    /// Exchange a token for a scoped key at each run.
    Broker {
        url: String,
        token: String,
        expected_bucket: Option<String>,
        legacy: bool,
    },
}

/// Decide where credentials come from.
///
/// An explicit key keeps working without contacting the broker. A supplied
/// token wins over saved tokens; otherwise select the saved token for the
/// bucket named by this registry's Cargo index.
pub(super) fn source(args: &Args, file: &FileConfig, index: Option<&str>) -> Result<Source> {
    let key_id = args.key_id.clone().or(file.key_id.clone());
    let key_secret = args.key_secret.clone().or(file.key_secret.clone());
    let bucket = args.bucket.clone().or(file.bucket.clone());

    match (key_id, key_secret) {
        (Some(key_id), Some(key_secret)) => {
            let Some(bucket) = bucket else {
                bail!("an explicit key needs --bucket or CARGO_VIP_BUCKET");
            };
            Ok(Source::Static(Resolved {
                key_id,
                key_secret,
                bucket,
                endpoint: file
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| args.endpoint.clone()),
                region: file.region.clone().unwrap_or_else(|| args.region.clone()),
            }))
        }
        (Some(_), None) | (None, Some(_)) => {
            bail!("--key-id and --key-secret must be given together")
        }
        (None, None) => {
            let registry = args.registry.first().map_or("vip", String::as_str);
            let target_bucket = index
                .map(|index| bucket_from_index(index, registry))
                .transpose()?
                .flatten()
                .or_else(|| args.bucket.clone());

            if let Some(token) = args.token.first().cloned() {
                return Ok(Source::Broker {
                    url: args.broker.clone(),
                    token,
                    expected_bucket: target_bucket,
                    legacy: false,
                });
            }

            stored_token_source(file, registry, target_bucket)
        }
    }
}

pub(super) fn stored_token_source(
    file: &FileConfig,
    registry: &str,
    target_bucket: Option<String>,
) -> Result<Source> {
    if let Some(bucket) = target_bucket {
        if let Some(entry) = file.find_by_bucket(&bucket) {
            let (url, token) = saved_broker_pair(file, entry.broker.as_deref(), &entry.token)?;
            return Ok(Source::Broker {
                url,
                token,
                expected_bucket: Some(bucket),
                legacy: false,
            });
        }

        // Old credentials.toml files have no bucket field. Try the old token
        // once and accept it only when the broker confirms it belongs here.
        if let Some(token) = file.token.clone() {
            let (url, token) = saved_broker_pair(file, None, &token)?;
            return Ok(Source::Broker {
                url,
                token,
                expected_bucket: Some(bucket),
                legacy: true,
            });
        }
        bail!(missing_token_message(&bucket));
    }

    match (file.registry.as_slice(), file.token.as_ref()) {
        ([], Some(token)) => Ok(Source::Broker {
            url: saved_broker_pair(file, None, token)?.0,
            token: token.clone(),
            expected_bucket: None,
            legacy: true,
        }),
        ([entry], None) => {
            let (url, token) = saved_broker_pair(file, entry.broker.as_deref(), &entry.token)?;
            Ok(Source::Broker {
                url,
                token,
                expected_bucket: Some(entry.bucket.clone()),
                legacy: false,
            })
        }
        ([], None) => bail!(
            "not logged in: run `cargo vip login` or set CARGO_VIP_TOKEN, or pass \
             --key-id/--key-secret with --bucket to use a key directly"
        ),
        _ => bail!(
            "more than one registry token is stored; set [registries.{registry}].index \
             in .cargo/config.toml or {} to select a bucket",
            index_env(registry)
        ),
    }
}

pub(super) fn saved_broker_pair(
    file: &FileConfig,
    entry_broker: Option<&str>,
    token: &str,
) -> Result<(String, String)> {
    let issuer = entry_broker
        .filter(|broker| !broker.trim().is_empty())
        .or_else(|| file.broker.as_deref().filter(|broker| !broker.trim().is_empty()))
        .ok_or_else(|| anyhow::anyhow!(
            "saved broker token has no recorded issuer; record the verified issuer or explicitly re-enter the token against that issuer"
        ))?;
    validate_broker_url(issuer)?;
    Ok((issuer.to_owned(), token.to_owned()))
}

fn is_crates_vip_index(index: &str) -> bool {
    bucket_from_index(index, "vip").is_ok()
}

pub(super) fn registries_in_toml(text: &str, origin_label: &str) -> Result<Vec<(String, String)>> {
    let config: toml::Value = toml::from_str(text)
        .map_err(|_| anyhow::anyhow!("parsing Cargo config {origin_label}: invalid TOML"))?;
    let Some(registries) = config.get("registries").and_then(toml::Value::as_table) else {
        return Ok(Vec::new());
    };
    Ok(registries
        .iter()
        .filter_map(|(name, value)| {
            value
                .get("index")
                .and_then(toml::Value::as_str)
                .map(|index| (name.clone(), index.to_owned()))
        })
        .collect())
}

pub(super) fn discover_registries(
    cwd: &Path,
    cargo_home: Option<&Path>,
    env_vars: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    let mut found = BTreeMap::new();
    for directory in cwd.ancestors() {
        let cargo_dir = directory.join(".cargo");
        for name in ["config.toml", "config"] {
            let path = cargo_dir.join(name);
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    for (registry, index) in registries_in_toml(&text, &path.display().to_string())?
                    {
                        found.entry(registry).or_insert(index);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", path.display()));
                }
            }
        }
    }
    if let Some(home) = cargo_home {
        for name in ["config.toml", "config"] {
            let path = home.join(name);
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    for (registry, index) in registries_in_toml(&text, &path.display().to_string())?
                    {
                        found.entry(registry).or_insert(index);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", path.display()));
                }
            }
        }
    }
    for (key, value) in env_vars {
        if let Some(upper) = key
            .strip_prefix("CARGO_REGISTRIES_")
            .and_then(|s| s.strip_suffix("_INDEX"))
        {
            if upper == "VIP" && !is_crates_vip_index(value) {
                // Every alias of this environment key has the same non-private index.
                found.retain(|name, _| index_env(name) != key.as_str());
                found.insert("vip".to_owned(), value.clone());
                continue;
            }
            if let Some(name) = found
                .keys()
                .find(|name| name.to_uppercase().replace('-', "_") == upper)
                .cloned()
            {
                found.insert(name, value.clone());
            } else {
                found.insert(upper.to_lowercase(), value.clone());
            }
        }
    }
    Ok(found
        .into_iter()
        // Keep an excluded default-name override so planning cannot recreate it.
        .filter(|(name, index)| name == "vip" || is_crates_vip_index(index))
        .collect())
}

type ActiveRegistryPlan = (Vec<(String, Option<String>)>, Option<String>);

pub(super) fn select_active_registries(
    explicit: &[String],
    discovered: &[(String, String)],
    is_publish: bool,
) -> Result<ActiveRegistryPlan> {
    let excluded_default = discovered
        .iter()
        .any(|(name, index)| name == "vip" && !is_crates_vip_index(index));
    let eligible: Vec<_> = discovered
        .iter()
        .filter(|(_, index)| is_crates_vip_index(index))
        .cloned()
        .collect();
    let indexes: BTreeMap<_, _> = eligible.iter().cloned().collect();
    if is_publish {
        if explicit.len() > 1 {
            bail!("cargo vip publish takes a single --registry");
        }
        let target = if let Some(name) = explicit.first() {
            name.clone()
        } else if excluded_default && eligible.is_empty() {
            bail!(
                "the default registry index is overridden by a non-crates.vip URL; pass --registry <NAME> to select a private registry explicitly"
            );
        } else if eligible.is_empty() || eligible.iter().any(|(name, _)| name == "vip") {
            "vip".to_owned()
        } else if eligible.len() == 1 {
            eligible[0].0.clone()
        } else {
            bail!(
                "multiple registries configured; pass --registry <NAME> to select which registry to publish to"
            );
        };
        let mut active = vec![(target.clone(), indexes.get(&target).cloned())];
        active.extend(
            eligible
                .iter()
                .filter(|(name, _)| name != &target)
                .map(|(name, index)| (name.clone(), Some(index.clone()))),
        );
        Ok((active, Some(target)))
    } else if !explicit.is_empty() {
        Ok((
            explicit
                .iter()
                .map(|name| (name.clone(), indexes.get(name).cloned()))
                .collect(),
            None,
        ))
    } else if !eligible.is_empty() {
        Ok((
            eligible
                .iter()
                .map(|(name, index)| (name.clone(), Some(index.clone())))
                .collect(),
            None,
        ))
    } else if excluded_default {
        // Cargo already has an effective non-private VIP index; leave it alone.
        Ok((Vec::new(), None))
    } else {
        Ok((vec![("vip".to_owned(), None)], None))
    }
}

fn token_env(registry: &str) -> String {
    format!(
        "CARGO_VIP_TOKEN_{}",
        registry.to_uppercase().replace('-', "_")
    )
}

fn parse_tokens(raw: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut tokens = Vec::new();
    for token in raw
        .split(|ch: char| ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if seen.insert(token.to_owned()) {
            tokens.push(token.to_owned());
        }
    }
    tokens
}

pub(super) fn collect_candidate_tokens(
    cli_tokens: &[String],
    mut env_lookup: impl FnMut(&str) -> Option<String>,
) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for raw in cli_tokens
        .iter()
        .cloned()
        .chain(env_lookup("CARGO_VIP_TOKENS"))
        .chain(env_lookup("CARGO_VIP_TOKEN"))
    {
        for token in parse_tokens(&raw) {
            if seen.insert(token.clone()) {
                tokens.push(token);
            }
        }
    }
    tokens
}

fn resolve_static_key(args: &Args, file: &FileConfig) -> Result<Option<Resolved>> {
    let key_id = args.key_id.clone().or(file.key_id.clone());
    let key_secret = args.key_secret.clone().or(file.key_secret.clone());
    if key_id.is_none() && key_secret.is_none() {
        return Ok(None);
    }
    let (Some(key_id), Some(key_secret)) = (key_id, key_secret) else {
        bail!("--key-id and --key-secret must be given together");
    };
    let bucket = args
        .bucket
        .clone()
        .or(file.bucket.clone())
        .context("an explicit key needs --bucket or CARGO_VIP_BUCKET")?;
    Ok(Some(Resolved {
        key_id,
        key_secret,
        bucket,
        endpoint: file
            .endpoint
            .clone()
            .unwrap_or_else(|| args.endpoint.clone()),
        region: file.region.clone().unwrap_or_else(|| args.region.clone()),
    }))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_registry_with(
    args: &Args,
    file: &FileConfig,
    registry_name: &str,
    index_opt: Option<&str>,
    candidate_tokens: &[String],
    per_registry_token: Option<&str>,
    active_count: usize,
    mut exchange: impl FnMut(&str, &str) -> Result<Resolved>,
) -> Result<Resolved> {
    if let Some(resolved) = resolve_static_key(args, file)? {
        return Ok(resolved);
    }
    let expected_bucket = index_opt
        .map(|index| bucket_from_index(index, registry_name))
        .transpose()?
        .flatten()
        .or_else(|| args.bucket.clone());
    let cli_broker = &args.broker;
    if let Some(token) = per_registry_token.filter(|token| !token.is_empty()) {
        let resolved = exchange(cli_broker, token)?;
        if let Some(bucket) = expected_bucket.as_deref() {
            if resolved.bucket != bucket {
                bail!(
                    "the selected token resolves to bucket `{}`, but registry `{}` is configured for bucket `{}`",
                    resolved.bucket,
                    registry_name,
                    bucket
                );
            }
        }
        return Ok(resolved);
    }
    if let Some(bucket) = expected_bucket.as_deref() {
        let mut last_bucket = None;
        for token in candidate_tokens {
            let resolved = exchange(cli_broker, token)?;
            if resolved.bucket == bucket {
                return Ok(resolved);
            }
            last_bucket = Some(resolved.bucket);
        }
        if let Some(entry) = file.find_by_bucket(bucket) {
            let (broker, token) = saved_broker_pair(file, entry.broker.as_deref(), &entry.token)?;
            let resolved = exchange(&broker, &token)?;
            if resolved.bucket != bucket {
                bail!("the saved token did not resolve to its configured registry bucket");
            }
            return Ok(resolved);
        }
        if let Some(token) = &file.token {
            let (broker, token) = saved_broker_pair(file, None, token)?;
            let resolved = exchange(&broker, &token)?;
            if resolved.bucket != bucket {
                bail!("{}", missing_token_message(bucket));
            }
            return Ok(resolved);
        }
        if let Some(other_bucket) = last_bucket {
            bail!(
                "the selected token resolves to bucket `{other_bucket}`, but registry `{registry_name}` is configured for bucket `{bucket}`"
            );
        }
        return Err(anyhow::anyhow!(missing_token_message(bucket)));
    }
    if active_count == 1 {
        if let Some(token) = candidate_tokens.first() {
            return exchange(cli_broker, token);
        }
    }
    match source(args, file, index_opt)? {
        Source::Static(resolved) => Ok(resolved),
        Source::Broker {
            url,
            token,
            expected_bucket,
            legacy,
        } => {
            let resolved = exchange(&url, &token)?;
            if let Some(expected_bucket) = expected_bucket {
                if resolved.bucket != expected_bucket {
                    if legacy {
                        bail!("{}", missing_token_message(&expected_bucket));
                    }
                    bail!(
                        "the selected token resolves to bucket `{}`, but registry `{registry_name}` is configured for bucket `{expected_bucket}`",
                        resolved.bucket
                    );
                }
            }
            Ok(resolved)
        }
    }
}

pub(super) fn missing_token_message(bucket: &str) -> String {
    format!(
        "no token stored for registry bucket `{bucket}`; run `cargo vip login` and enter a token for this bucket"
    )
}

/// Resolve Cargo's index for this registry. Cargo-specific environment
/// settings override the nearest project config; `CARGO_HOME` is the final file
/// fallback just as it is for Cargo.
fn cargo_registry_index(registry: &str) -> Result<Option<String>> {
    let cwd = std::env::current_dir().context("getting the current directory")?;
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let environment_index =
        std::env::var_os(index_env(registry)).map(|index| index.to_string_lossy().into_owned());
    find_registry_index(
        registry,
        &cwd,
        cargo_home.as_deref(),
        environment_index.as_deref(),
    )
}

pub(super) fn find_registry_index(
    registry: &str,
    cwd: &Path,
    cargo_home: Option<&Path>,
    environment_index: Option<&str>,
) -> Result<Option<String>> {
    if let Some(index) = environment_index {
        return Ok(Some(index.to_owned()));
    }

    for directory in cwd.ancestors() {
        if let Some(index) = registry_index_in_dir(directory, registry)? {
            return Ok(Some(index));
        }
    }
    if let Some(cargo_home) = cargo_home {
        if let Some(index) = registry_index_in_cargo_home(cargo_home, registry)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn registry_index_in_dir(directory: &Path, registry: &str) -> Result<Option<String>> {
    let cargo_dir = directory.join(".cargo");
    for name in ["config.toml", "config"] {
        if let Some(index) = registry_index_in_file(&cargo_dir.join(name), registry)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn registry_index_in_cargo_home(directory: &Path, registry: &str) -> Result<Option<String>> {
    for name in ["config.toml", "config"] {
        if let Some(index) = registry_index_in_file(&directory.join(name), registry)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

pub(super) fn registry_index_in_file(path: &Path, registry: &str) -> Result<Option<String>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let config: toml::Value = toml::from_str(&text)
        .map_err(|_| anyhow::anyhow!("parsing Cargo config {}: invalid TOML", path.display()))?;
    let Some(registries) = config.get("registries") else {
        return Ok(None);
    };
    let Some(registry_config) = registries.get(registry) else {
        return Ok(None);
    };
    let Some(index) = registry_config.get("index") else {
        return Ok(None);
    };
    index
        .as_str()
        .map(|index| Some(index.to_owned()))
        .with_context(|| {
            format!(
                "registries.{registry}.index in {} must be a string",
                path.display()
            )
        })
}

pub(super) fn bucket_from_index(index: &str, registry: &str) -> Result<Option<String>> {
    let url = index.strip_prefix("sparse+").unwrap_or(index);
    let (scheme, rest) = url
        .split_once("://")
        .with_context(|| format!("registry {registry:?} index is not a URL"))?;
    if scheme != "https" && scheme != "http" {
        bail!("registry {registry:?} index must use HTTP or HTTPS");
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority
        .rsplit('@')
        .next()
        .unwrap_or(authority)
        .split(':')
        .next()
        .unwrap_or_default();
    if !host.eq_ignore_ascii_case("crates.vip") {
        bail!(
            "registry {registry:?} index is not a crates.vip index URL of the form \
             sparse+https://crates.vip/<bucket>/"
        );
    }
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let bucket = path
        .split('/')
        .find(|part| !part.is_empty())
        .unwrap_or_default();
    if bucket.is_empty() {
        bail!("registry {registry:?} index does not name a bucket");
    }
    // `crates.vip/index/` is the name-only placeholder repositories declared before
    // tokens were kept per bucket. It names no bucket, so the token decides.
    if bucket == PLACEHOLDER_BUCKET {
        return Ok(None);
    }
    Ok(Some(bucket.to_owned()))
}

/// The path segment of the placeholder index `sparse+https://crates.vip/index/`.
const PLACEHOLDER_BUCKET: &str = "index";

pub(super) fn wanted_broker_tokens(
    args: &Args,
    file: &FileConfig,
    name: &str,
    index: Option<&str>,
    specific: Option<&str>,
    candidates: &[String],
    active_count: usize,
) -> Result<Vec<(String, String)>> {
    let cli_broker = &args.broker;
    let expected_bucket = index
        .map(|value| bucket_from_index(value, name))
        .transpose()?
        .flatten()
        .or_else(|| args.bucket.clone());
    let mut wanted = Vec::new();
    if let Some(token) = specific.filter(|token| !token.is_empty()) {
        wanted.push((cli_broker.to_owned(), token.to_owned()));
    } else if let Some(bucket) = expected_bucket.as_deref() {
        wanted.extend(
            candidates
                .iter()
                .map(|token| (cli_broker.to_owned(), token.clone())),
        );
        if let Some(entry) = file.find_by_bucket(bucket) {
            match saved_broker_pair(file, entry.broker.as_deref(), &entry.token) {
                Ok(pair) => wanted.push(pair),
                Err(error) if candidates.is_empty() => return Err(error),
                Err(_) => {}
            }
        } else if let Some(token) = &file.token {
            match saved_broker_pair(file, None, token) {
                Ok(pair) => wanted.push(pair),
                Err(error) if candidates.is_empty() => return Err(error),
                Err(_) => {}
            }
        }
    } else if active_count == 1 && !candidates.is_empty() {
        wanted.push((cli_broker.to_owned(), candidates[0].clone()));
    } else if let Source::Broker { url, token, .. } = source(args, file, index)? {
        wanted.push((url, token));
    }
    Ok(wanted)
}

/// The keys this run uses: explicit, or issued by the broker for each active
/// registry's configured bucket.
#[allow(clippy::too_many_lines)]
pub(super) async fn resolve_active_registries(
    args: &Args,
    file: &FileConfig,
) -> Result<(Vec<(String, Resolved)>, Option<String>)> {
    let is_publish = args.cargo_args.first().is_some_and(|arg| arg == "publish");
    let cwd = std::env::current_dir().context("getting the current directory")?;
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    let env_vars: Vec<(String, String)> = std::env::vars().collect();
    let discovered = discover_registries(&cwd, cargo_home.as_deref(), &env_vars)?;
    let (mut active, publish_target) =
        select_active_registries(&args.registry, &discovered, is_publish)?;
    let static_key = args.key_id.is_some()
        || args.key_secret.is_some()
        || file.key_id.is_some()
        || file.key_secret.is_some();
    if !static_key {
        for (name, index) in &mut active {
            if index.is_none() {
                *index = cargo_registry_index(name)?;
            }
        }
    }
    let candidates = collect_candidate_tokens(&args.token, |key| std::env::var(key).ok());
    let mut cache: BTreeMap<(String, String), Resolved> = BTreeMap::new();
    let active_count = active.len();
    let mut result = Vec::new();
    for (name, index) in active {
        let specific = std::env::var(token_env(&name)).ok();
        let can_skip = can_skip_registry(
            is_publish,
            !args.registry.is_empty(),
            publish_target.as_deref(),
            &name,
        );
        let wanted = if static_key {
            Ok(Vec::new())
        } else {
            wanted_broker_tokens(
                args,
                file,
                &name,
                index.as_deref(),
                specific.as_deref(),
                &candidates,
                active_count,
            )
        };
        let mut exchanges = Vec::new();
        if let Ok(wanted) = &wanted {
            let expected_bucket = index
                .as_deref()
                .map(|value| bucket_from_index(value, &name))
                .transpose()?
                .flatten()
                .or_else(|| args.bucket.clone());
            for (url, token) in wanted {
                let key = (url.clone(), token.clone());
                if !cache.contains_key(&key)
                    && !exchanges.iter().any(|(exchanged, _)| exchanged == &key)
                {
                    let credentials = issue_credentials(url, token).await;
                    let failed = credentials.is_err();
                    exchanges.push((key.clone(), credentials));
                    if failed {
                        break;
                    }
                }
                let cache_match = cache.get(&key).is_some_and(|credentials| {
                    expected_bucket
                        .as_deref()
                        .is_some_and(|bucket| credentials.bucket == bucket)
                });
                let exchange_match = exchanges
                    .iter()
                    .find(|(exchanged, _)| exchanged == &key)
                    .and_then(|(_, credentials)| credentials.as_ref().ok())
                    .is_some_and(|credentials| {
                        expected_bucket
                            .as_deref()
                            .is_some_and(|bucket| credentials.bucket == bucket)
                    });
                if cache_match || exchange_match {
                    break;
                }
            }
        }
        if let Some(credentials) = finish_registry_resolution(
            args,
            file,
            &name,
            index.as_deref(),
            &candidates,
            specific.as_deref(),
            active_count,
            can_skip,
            wanted,
            exchanges,
            &mut cache,
        )? {
            result.push((name, credentials));
        }
    }
    Ok((result, publish_target))
}

pub(super) fn can_skip_registry(
    is_publish: bool,
    target_selected: bool,
    publish_target: Option<&str>,
    registry: &str,
) -> bool {
    is_publish && target_selected && publish_target != Some(registry)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finish_registry_resolution(
    args: &Args,
    file: &FileConfig,
    name: &str,
    index: Option<&str>,
    candidates: &[String],
    specific: Option<&str>,
    active_count: usize,
    can_skip: bool,
    wanted: Result<Vec<(String, String)>>,
    mut exchanges: Vec<((String, String), Result<Resolved>)>,
    cache: &mut BTreeMap<(String, String), Resolved>,
) -> Result<Option<Resolved>> {
    let wanted = match wanted {
        Ok(wanted) => wanted,
        Err(error) if can_skip => {
            tracing::warn!(registry = %name, error = %error,
                "skipping registry whose credentials could not be resolved for publish");
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let expected_bucket = index
        .map(|value| bucket_from_index(value, name))
        .transpose()?
        .flatten()
        .or_else(|| args.bucket.clone());
    for pair in wanted {
        if !cache.contains_key(&pair) {
            let Some(position) = exchanges.iter().position(|(key, _)| key == &pair) else {
                let error = anyhow::anyhow!("credential exchange was not prepared");
                if can_skip {
                    tracing::warn!(registry = %name, error = %error,
                        "skipping registry whose credentials could not be resolved for publish");
                    return Ok(None);
                }
                return Err(error);
            };
            match exchanges.remove(position).1 {
                Ok(credentials) => {
                    cache.insert(pair.clone(), credentials);
                }
                Err(error) if can_skip => {
                    tracing::warn!(registry = %name, error = %error,
                        "skipping registry whose credentials could not be resolved for publish");
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        if expected_bucket.as_deref().is_some_and(|bucket| {
            cache
                .get(&pair)
                .is_some_and(|credentials| credentials.bucket == bucket)
        }) {
            break;
        }
    }
    let resolved = resolve_registry_with(
        args,
        file,
        name,
        index,
        candidates,
        specific,
        active_count,
        |broker, token| {
            cache
                .get(&(broker.to_owned(), token.to_owned()))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("credential exchange was not prepared"))
        },
    );
    match resolved {
        Ok(credentials) => Ok(Some(credentials)),
        Err(error) if can_skip => {
            tracing::warn!(registry = %name, error = %error,
                "skipping registry whose credentials could not be resolved for publish");
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The environment variable that sets `registries.<registry>.index`.
pub(super) fn index_env(registry: &str) -> String {
    format!(
        "CARGO_REGISTRIES_{}_INDEX",
        registry.to_uppercase().replace('-', "_")
    )
}
