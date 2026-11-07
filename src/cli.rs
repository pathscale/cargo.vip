use crate::{publish, registry::index_env};
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "cargo-vip",
    bin_name = "cargo vip",
    version,
    about = "Use a private S3-compatible bucket as a Cargo registry"
)]
pub(super) struct Args {
    /// Registry name(s), as used in `registry = "..."` in Cargo.toml.
    #[arg(long = "registry", env = "CARGO_VIP_REGISTRY", value_delimiter = ',')]
    pub(super) registry: Vec<String>,

    /// S3 endpoint. Defaults to Tigris; any S3-compatible store works.
    #[arg(
        long,
        env = "CARGO_VIP_ENDPOINT",
        default_value = "https://fly.storage.tigris.dev"
    )]
    pub(super) endpoint: String,

    #[arg(long, env = "CARGO_VIP_REGION", default_value = "auto")]
    pub(super) region: String,

    /// Bucket holding the index at the root and tarballs under `crates/`.
    #[arg(long, env = "CARGO_VIP_BUCKET")]
    pub(super) bucket: Option<String>,

    /// Registry management API that issues credentials. The default flow is to
    /// hold no object-store key at all: `cargo vip login` stores a token for
    /// this service, and each run exchanges it for a scoped key held in memory.
    #[arg(long, env = "CARGO_VIP_BROKER", default_value = "wss://api.crates.vip")]
    pub(super) broker: String,

    /// Use this key directly and never contact the broker. Both halves must be
    /// given. This is the CI path, and the path for any bucket that has no
    /// broker in front of it.
    #[arg(long, env = "CARGO_VIP_KEY_ID", hide_env_values = true)]
    pub(super) key_id: Option<String>,

    #[arg(long, env = "CARGO_VIP_KEY_SECRET", hide_env_values = true)]
    pub(super) key_secret: Option<String>,

    /// Registry tokens, in precedence order.
    #[arg(
        long = "token",
        env = "CARGO_VIP_TOKEN",
        value_delimiter = ',',
        hide_env_values = true
    )]
    pub(super) token: Vec<String>,

    /// Serve the index and stay in the foreground, printing the config stanza,
    /// instead of running cargo.
    #[arg(long)]
    pub(super) serve: bool,

    /// Run this executable for `build` or `check` instead of Cargo.
    ///
    /// The driver receives the original Cargo arguments and registry configuration in
    /// `CARGO_VIP_CARGO_CONFIG_JSON`. `CARGO_VIP_BUILD_DRIVER` is the environment equivalent.
    #[arg(long, env = "CARGO_VIP_BUILD_DRIVER", value_name = "EXECUTABLE")]
    pub(super) build_driver: Option<PathBuf>,

    /// The cargo invocation to wrap, e.g. `cargo vip build --release`.

    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub(super) cargo_args: Vec<String>,
}

/// Do not silently send a non-build command back to Cargo when a build driver is selected.
pub(super) fn validate_build_driver_request(args: &Args) -> Result<()> {
    if args.build_driver.is_none() {
        return Ok(());
    }
    if args
        .build_driver
        .as_ref()
        .is_some_and(|path| path.as_os_str().is_empty())
    {
        bail!("--build-driver must name an executable");
    }
    if args.serve {
        bail!("--build-driver cannot be combined with --serve");
    }
    match args.cargo_args.first().map(String::as_str) {
        Some("build" | "check") => Ok(()),
        Some(command) => {
            bail!("--build-driver supports only `build` and `check`; `{command}` is unsupported")
        }
        None => bail!("--build-driver needs a `build` or `check` command"),
    }
}

/// The `--config` arguments that point cargo at this process: the registry
/// under its stable URL, replaced by the loopback source.
pub(super) fn cargo_config(registry: &str, stable: &str, loopback: &str) -> Vec<String> {
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

pub(super) fn cargo_config_all(proxies: &[(String, String, String)]) -> Vec<String> {
    let mut config = Vec::new();
    let mut stable_sources = std::collections::BTreeSet::new();
    for (name, stable, loopback) in proxies {
        let mut registry_config = cargo_config(name, stable, loopback);
        if !stable_sources.insert(stable.clone()) {
            registry_config.retain(|arg| !arg.starts_with(&format!("source.{name}-remote.")));
        }
        config.extend(registry_config);
    }
    config
}

pub(super) fn cargo_env_all(proxies: &[(String, String, String)]) -> Vec<(String, String)> {
    proxies
        .iter()
        .map(|(name, _, loopback)| (index_env(name), loopback.clone()))
        .collect()
}

pub(super) fn env_exports(proxies: &[(String, String, String)]) -> String {
    let mut out = String::new();
    for (name, _, loopback) in proxies {
        out.push_str("export ");
        out.push_str(&index_env(name));
        out.push_str("=\"");
        out.push_str(loopback);
        out.push_str("\"\n");
    }
    out
}

/// `cargo vip publish [--manifest-path PATH] [--dry-run]`.
pub(super) fn publish_request(
    rest: &[String],
    registry: &str,
    index_url: &str,
    loopbacks: Vec<(String, String)>,
) -> Result<publish::Request> {
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
        loopbacks,
    })
}

/// Parse the command line, dropping Cargo's inserted subcommand name when present.
pub(super) fn parse_args() -> Args {
    // `cargo vip build` reaches this binary as `cargo-vip vip build`, so the
    // subcommand name cargo inserts is dropped.
    let raw: Vec<String> = std::env::args()
        .enumerate()
        .filter(|(i, a)| !(*i == 1 && a == "vip"))
        .map(|(_, a)| a)
        .collect();
    Args::parse_from(raw)
}

pub(super) fn print_serve_config(proxies: &[(String, String, String)]) {
    for (i, (name, stable, loopback)) in proxies.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("[registries.{name}]");
        println!("index = \"{stable}\"");
        println!();
        println!("[source.{name}-remote]");
        println!("registry = \"{stable}\"");
        println!("replace-with = \"{name}-loopback\"");
        println!();
        println!("[source.{name}-loopback]");
        println!("registry = \"{loopback}\"");
    }
}

pub(super) async fn run_child(
    args: &Args,
    config: &[String],
    envs: Vec<(String, String)>,
) -> Result<std::process::ExitStatus> {
    // `--config` rather than `.cargo/config.toml`, so wrapping a build edits no
    // file and leaves nothing behind.
    //
    // Cargo does not forward `--config` to an external subcommand such as
    // `cargo clippy`, and source replacement cannot be set from the
    // environment. So the index is also pointed straight at the loopback
    // through the environment, which `--config` outranks for built-in
    // commands; only an external one sees it, and its lockfile then names the
    // loopback.
    if let Some(driver) = &args.build_driver {
        let config_json = serde_json::to_string(config)
            .context("serializing Cargo registry configuration for the build driver")?;
        tokio::process::Command::new(driver)
            .envs(envs)
            .env("CARGO_VIP_CARGO_CONFIG_JSON", config_json)
            .args(&args.cargo_args)
            .status()
            .await
            .with_context(|| format!("running configured build driver `{}`", driver.display()))
    } else {
        tokio::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .envs(envs)
            .args(config)
            .args(&args.cargo_args)
            .status()
            .await
            .context("running cargo")
    }
}
