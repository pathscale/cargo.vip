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
//! the listener, so no temporary `.cargo/config.toml` entry is needed and
//! nothing is left behind when it exits.

mod broker;
mod cli;
mod config;
mod proxy;
mod publish;
mod registry;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, bail};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .init();

    let args = cli::parse_args();
    cli::validate_build_driver_request(&args)?;
    let file = config::load_file_config()?;

    if args.cargo_args.first().is_some_and(|a| a == "login") {
        return config::login(&args.broker, file).await;
    }

    let (resolved, publish_target) = registry::resolve_active_registries(&args, &file).await?;
    let (proxies, serving) = proxy::start_proxies(resolved).await?;
    let triples: Vec<(String, String, String)> = proxies
        .iter()
        .map(|proxy| {
            (
                proxy.name.clone(),
                proxy.stable.clone(),
                proxy.loopback.clone(),
            )
        })
        .collect();
    let config = cli::cargo_config_all(&triples);
    let envs = cli::cargo_env_all(&triples);

    if args.cargo_args.first().is_some_and(|arg| arg == "env") {
        print!("{}", cli::env_exports(&triples));
        if args.serve {
            tokio::signal::ctrl_c().await?;
        }
        for task in serving {
            task.abort();
        }
        return Ok(());
    }
    if args.serve {
        cli::print_serve_config(&triples);
        tokio::signal::ctrl_c().await?;
        for task in serving {
            task.abort();
        }
        return Ok(());
    }
    if args.cargo_args.is_empty() {
        bail!("nothing to run: try `cargo vip build`, or --serve to stay in the foreground");
    }
    if args.cargo_args.first().is_some_and(|a| a == "publish") {
        let target_name = publish_target.as_deref().unwrap_or("vip");
        let proxy = proxies
            .iter()
            .find(|proxy| proxy.name == target_name)
            .context("publish registry proxy was not resolved")?;
        let loopbacks: Vec<(String, String)> = proxies
            .iter()
            .map(|proxy| (proxy.loopback.clone(), proxy.stable.clone()))
            .collect();
        let request =
            cli::publish_request(&args.cargo_args[1..], &proxy.name, &proxy.stable, loopbacks)?;
        let target = publish::Target {
            client: &proxy.registry.client,
            bucket: &proxy.registry.bucket,
            credentials: &proxy.registry.credentials,
        };
        let outcome = publish::publish(&target, &request, &config).await;
        for task in serving {
            task.abort();
        }
        return outcome;
    }

    let status = cli::run_child(&args, &config, envs).await?;
    for task in serving {
        task.abort();
    }
    std::process::exit(status.code().unwrap_or(1));
}
