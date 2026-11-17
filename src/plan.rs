use crate::cli::Args;
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Options extracted from `cargo vip plan ...` before forwarding Cargo flags to
/// `$CARGO build -Z unstable-options --unit-graph`.
#[derive(Debug, Default)]
pub(super) struct PlanRequest {
    pub(super) emit_source_graph: Option<PathBuf>,
    pub(super) every_unit_root: bool,
    pub(super) language_roots: Option<PathBuf>,
    pub(super) compile_with: Option<PathBuf>,
    pub(super) socket: Option<PathBuf>,
    pub(super) out_dir: Option<PathBuf>,
    pub(super) opt_level: Option<String>,
    pub(super) timing: bool,
    pub(super) cargo_build_args: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SerializedUnitGraph {
    version: u32,
    units: Vec<SerializedUnit>,
    roots: Vec<usize>,
}

#[derive(Debug, Deserialize)]
struct SerializedUnit {
    pkg_id: String,
    target: SerializedTarget,
    profile: SerializedProfile,
    platform: Option<String>,
    mode: String,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    dependencies: Vec<SerializedUnitDep>,
}

#[derive(Debug, Deserialize)]
struct SerializedTarget {
    kind: Vec<String>,
    name: String,
    src_path: Option<PathBuf>,
    edition: String,
}

#[derive(Debug, Deserialize)]
struct SerializedProfile {
    name: String,
    opt_level: String,
    debug_assertions: bool,
    overflow_checks: bool,
    #[serde(default)]
    panic: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SerializedUnitDep {
    index: usize,
    extern_crate_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PackageCoords {
    pub(super) name: String,
    pub(super) version: String,
}

pub(super) fn parse_plan_request(rest: &[String]) -> Result<PlanRequest> {
    let mut request = PlanRequest::default();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--emit-source-graph" => {
                request.emit_source_graph = Some(PathBuf::from(next_value(&mut iter, arg)?));
            }
            "--every-unit-root" => request.every_unit_root = true,
            "--language-roots" => {
                request.language_roots = Some(PathBuf::from(next_value(&mut iter, arg)?));
            }
            "--compile-with" | "--compile-with-ekors" => {
                request.compile_with = Some(PathBuf::from(next_value(&mut iter, arg)?));
            }
            "--socket" => {
                request.socket = Some(PathBuf::from(next_value(&mut iter, arg)?));
            }
            "--out-dir" => {
                request.out_dir = Some(PathBuf::from(next_value(&mut iter, arg)?));
            }
            "--opt-level" => {
                request.opt_level = Some(validate_opt_level(&next_value(&mut iter, arg)?)?);
            }
            "--timing" => request.timing = true,
            other => {
                if let Some(value) = other.strip_prefix("--emit-source-graph=") {
                    ensure!(!value.is_empty(), "--emit-source-graph needs a path");
                    request.emit_source_graph = Some(PathBuf::from(value));
                } else if let Some(value) = other.strip_prefix("--language-roots=") {
                    ensure!(!value.is_empty(), "--language-roots needs a path");
                    request.language_roots = Some(PathBuf::from(value));
                } else if let Some(value) = other
                    .strip_prefix("--compile-with=")
                    .or_else(|| other.strip_prefix("--compile-with-ekors="))
                {
                    ensure!(!value.is_empty(), "--compile-with needs an executable path");
                    request.compile_with = Some(PathBuf::from(value));
                } else if let Some(value) = other.strip_prefix("--socket=") {
                    ensure!(!value.is_empty(), "--socket needs a path");
                    request.socket = Some(PathBuf::from(value));
                } else if let Some(value) = other.strip_prefix("--out-dir=") {
                    ensure!(!value.is_empty(), "--out-dir needs a path");
                    request.out_dir = Some(PathBuf::from(value));
                } else if let Some(value) = other.strip_prefix("--opt-level=") {
                    request.opt_level = Some(validate_opt_level(value)?);
                } else {
                    request.cargo_build_args.push(arg.clone());
                }
            }
        }
    }
    if request.compile_with.is_some() {
        ensure!(
            request.socket.is_some() || std::env::var_os("EKOD_SOCKET").is_some(),
            "--socket (or EKOD_SOCKET) is required when --compile-with is used"
        );
        ensure!(
            request.out_dir.is_some(),
            "--out-dir is required when --compile-with is used"
        );
    }
    Ok(request)
}

fn next_value<'a>(iter: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<String> {
    let value = iter
        .next()
        .with_context(|| format!("missing argument to {flag}"))?;
    ensure!(!value.is_empty(), "empty argument to {flag}");
    Ok(value.clone())
}

fn validate_opt_level(level: &str) -> Result<String> {
    ensure!(
        matches!(level, "O0" | "O1" | "O2" | "O3" | "Os" | "Oz" | "Ofast"),
        "unsupported --opt-level {level}; expected O0, O1, O2, O3, Os, Oz, or Ofast"
    );
    Ok(level.to_owned())
}

pub(super) async fn execute_plan(
    _args: &Args,
    request: &PlanRequest,
    config: &[String],
    envs: Vec<(String, String)>,
) -> Result<()> {
    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let host = discover_host_triple(&cargo_bin).await?;
    let manifest_dir = manifest_working_dir(&request.cargo_build_args)?;

    let mut command = tokio::process::Command::new(&cargo_bin);
    command
        .current_dir(&manifest_dir)
        .envs(envs)
        .env("RUSTC_BOOTSTRAP", "1")
        .args(config)
        .arg("build")
        .arg("-Z")
        .arg("unstable-options")
        .arg("--unit-graph")
        .args(&request.cargo_build_args);
    let output = command
        .output()
        .await
        .with_context(|| format!("running `{cargo_bin} build --unit-graph`"))?;
    if !output.stderr.is_empty() {
        use std::io::Write;
        let _ = std::io::stderr().write_all(&output.stderr);
    }
    if !output.status.success() {
        std::process::exit(output.status.code().unwrap_or(1));
    }

    let graph: SerializedUnitGraph =
        serde_json::from_slice(&output.stdout).context("parsing Cargo `--unit-graph` JSON")?;
    ensure!(
        graph.version == 1,
        "unsupported Cargo `--unit-graph` schema version {}",
        graph.version
    );

    print_plan_report(&graph, &host)?;

    if request.emit_source_graph.is_some() || request.compile_with.is_some() {
        let graph_dir = match &request.emit_source_graph {
            Some(dir) => dir.clone(),
            None => request
                .out_dir
                .as_deref()
                .context(
                    "--out-dir is required when --compile-with is used without --emit-source-graph",
                )?
                .join("source-graphs"),
        };
        let language_roots = request
            .language_roots
            .clone()
            .unwrap_or_else(|| infer_language_roots(&graph, &manifest_dir));
        let selected_roots: Vec<usize> = if request.every_unit_root {
            (0..graph.units.len())
                .filter(|&index| graph.units[index].mode != "run-custom-build")
                .collect()
        } else {
            graph.roots.clone()
        };
        let emitted =
            emit_source_graphs(&selected_roots, &graph, &host, &language_roots, &graph_dir)?;
        if let Some(compiler_client) = &request.compile_with {
            let socket =
                match &request.socket {
                    Some(path) => path.clone(),
                    None => PathBuf::from(std::env::var_os("EKOD_SOCKET").context(
                        "--socket or EKOD_SOCKET is required when --compile-with is used",
                    )?),
                };
            let out_dir = request
                .out_dir
                .as_deref()
                .context("--out-dir is required when --compile-with is used")?;
            compile_emitted_graphs(
                compiler_client,
                &socket,
                out_dir,
                request.opt_level.as_deref(),
                request.timing,
                &emitted,
            )
            .await?;
        }
    } else {
        println!("PLAN-ONLY no source-graph emission or compiler execution requested");
    }
    Ok(())
}

async fn discover_host_triple(cargo_bin: &str) -> Result<String> {
    if let Ok(output) = tokio::process::Command::new("rustc")
        .env("RUSTC_WRAPPER", "")
        .arg("-vV")
        .output()
        .await
    {
        if output.status.success() {
            if let Ok(text) = std::str::from_utf8(&output.stdout) {
                if let Some(host) = text.lines().find_map(|line| line.strip_prefix("host: ")) {
                    return Ok(host.trim().to_owned());
                }
            }
        }
    }
    let _ = cargo_bin;
    Ok(default_host_triple().to_owned())
}

const fn default_host_triple() -> &'static str {
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(not(any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "linux"),
        all(target_arch = "x86_64", target_os = "linux"),
    )))]
    {
        "unknown"
    }
}

fn manifest_working_dir(cargo_build_args: &[String]) -> Result<PathBuf> {
    let mut iter = cargo_build_args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--manifest-path" {
            if let Some(path) = iter.next() {
                let canonical = PathBuf::from(path)
                    .canonicalize()
                    .with_context(|| format!("locating manifest `{path}`"))?;
                return Ok(canonical
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf());
            }
        } else if let Some(path) = arg.strip_prefix("--manifest-path=") {
            let canonical = PathBuf::from(path)
                .canonicalize()
                .with_context(|| format!("locating manifest `{path}`"))?;
            return Ok(canonical
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf());
        }
    }
    std::env::current_dir().context("getting current directory")
}

/// Infer `<bootstrap>` when a configured `core` library unit lives at `<bootstrap>/core/src/lib.rs`.
fn infer_language_roots(graph: &SerializedUnitGraph, workspace_dir: &Path) -> PathBuf {
    for unit in &graph.units {
        if target_kind_str(&unit.target) == "library" && crate_name(&unit.target) == "core" {
            if let Some(src_path) = &unit.target.src_path {
                if let Some(core_dir) = src_path.parent().and_then(Path::parent) {
                    if core_dir.file_name().is_some_and(|name| name == "core") {
                        if let Some(bootstrap) = core_dir.parent() {
                            return bootstrap.to_path_buf();
                        }
                    }
                }
            }
        }
    }
    workspace_dir.join("bootstrap")
}

pub(super) fn parse_pkg_id(pkg_id: &str) -> Result<PackageCoords> {
    let (location, fragment) = pkg_id
        .split_once('#')
        .with_context(|| format!("unexpected Cargo PackageIdSpec `{pkg_id}`"))?;
    if let Some((name, version)) = fragment.split_once('@') {
        ensure!(
            !name.is_empty() && !version.is_empty(),
            "malformed Cargo PackageIdSpec `{pkg_id}`"
        );
        return Ok(PackageCoords {
            name: name.to_owned(),
            version: version.to_owned(),
        });
    }
    let trimmed = location.trim_end_matches('/');
    let name = trimmed
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .with_context(|| format!("missing package name in Cargo PackageIdSpec `{pkg_id}`"))?;
    ensure!(
        !fragment.is_empty(),
        "missing package version in Cargo PackageIdSpec `{pkg_id}`"
    );
    Ok(PackageCoords {
        name: name.to_owned(),
        version: fragment.to_owned(),
    })
}

fn crate_name(target: &SerializedTarget) -> String {
    target.name.replace('-', "_")
}

fn target_kind_str(target: &SerializedTarget) -> &'static str {
    let has = |wanted: &str| target.kind.iter().any(|kind| kind == wanted);
    if has("custom-build") {
        "build-script"
    } else if has("bin") {
        "binary"
    } else if has("proc-macro") {
        "proc-macro"
    } else if has("lib") || has("rlib") || has("dylib") || has("cdylib") || has("staticlib") {
        "library"
    } else if has("test") {
        "test"
    } else if has("bench") {
        "bench"
    } else if has("example") {
        "example"
    } else {
        "library"
    }
}

fn unit_role_and_triple(unit: &SerializedUnit, host: &str) -> (&'static str, String) {
    match &unit.platform {
        None => ("host", host.to_owned()),
        Some(triple) => ("target", triple.clone()),
    }
}

fn mode_label(mode: &str) -> &'static str {
    match mode {
        "check" => "Check",
        "test" => "Test",
        "doctest" => "Doctest",
        "doc" => "Doc",
        "docscrape" => "Docscrape",
        "run-custom-build" => "RunCustomBuild",
        _ => "Build",
    }
}

fn kind_label(unit: &SerializedUnit) -> String {
    match &unit.platform {
        None => "Host".to_owned(),
        Some(triple) => format!("Target(CompileTarget {{ name: {triple:?} }})"),
    }
}

fn sorted_features(unit: &SerializedUnit) -> BTreeSet<&str> {
    unit.features.iter().map(String::as_str).collect()
}

fn unit_summary(unit: &SerializedUnit) -> Result<String> {
    let pkg = parse_pkg_id(&unit.pkg_id)?;
    Ok(format!(
        "package={} target={} mode={} kind={} features={:?} profile={} opt={} debug_assertions={}",
        pkg.name,
        unit.target.name,
        mode_label(&unit.mode),
        kind_label(unit),
        sorted_features(unit),
        unit.profile.name,
        unit.profile.opt_level,
        unit.profile.debug_assertions,
    ))
}

fn print_plan_report(graph: &SerializedUnitGraph, host: &str) -> Result<()> {
    println!(
        "GRAPH roots={} units={} host={host}",
        graph.roots.len(),
        graph.units.len()
    );
    for &root_idx in &graph.roots {
        if let Some(root) = graph.units.get(root_idx) {
            println!("ROOT {}", unit_summary(root)?);
        }
    }
    for unit in &graph.units {
        println!("UNIT {}", unit_summary(unit)?);
        for dep in &unit.dependencies {
            if let Some(dep_unit) = graph.units.get(dep.index) {
                let dep_pkg = parse_pkg_id(&dep_unit.pkg_id)?;
                println!(
                    "  EDGE alias={} package={} target={} mode={} kind={} features={:?}",
                    dep.extern_crate_name,
                    dep_pkg.name,
                    dep_unit.target.name,
                    mode_label(&dep_unit.mode),
                    kind_label(dep_unit),
                    sorted_features(dep_unit),
                );
            }
        }
    }
    Ok(())
}

fn unit_key(index: usize) -> String {
    format!("unit-{index}")
}

fn topo_closure(root: usize, graph: &SerializedUnitGraph) -> Vec<usize> {
    fn visit(
        index: usize,
        graph: &SerializedUnitGraph,
        visited: &mut HashSet<usize>,
        order: &mut Vec<usize>,
    ) {
        if !visited.insert(index) {
            return;
        }
        if let Some(unit) = graph.units.get(index) {
            let mut deps: Vec<usize> = unit.dependencies.iter().map(|dep| dep.index).collect();
            deps.sort_by_key(|&dep_idx| unit_key(dep_idx));
            for dep_idx in deps {
                visit(dep_idx, graph, visited, order);
            }
        }
        order.push(index);
    }

    let mut visited = HashSet::new();
    let mut order = Vec::new();
    visit(root, graph, &mut visited, &mut order);
    order
}

fn build_language_roots(
    bootstrap_dir: &Path,
    closure: &[usize],
    graph: &SerializedUnitGraph,
    host: &str,
) -> Result<(Vec<Value>, HashSet<usize>)> {
    let mut roots = Vec::new();
    let mut language_units = HashSet::new();
    for language_name in ["core", "alloc"] {
        let candidate = bootstrap_dir.join(language_name).join("src/lib.rs");
        let Ok(wanted) = candidate.canonicalize() else {
            continue;
        };
        let mut matches = closure.iter().copied().filter(|&index| {
            let unit = &graph.units[index];
            target_kind_str(&unit.target) == "library"
                && crate_name(&unit.target) == language_name
                && unit
                    .target
                    .src_path
                    .as_deref()
                    .and_then(|path| path.canonicalize().ok())
                    .as_deref()
                    == Some(wanted.as_path())
        });
        let Some(matched_idx) = matches.next() else {
            continue;
        };
        ensure!(
            matches.next().is_none(),
            "more than one configured `{language_name}` unit in one closure"
        );
        language_units.insert(matched_idx);
        let unit = &graph.units[matched_idx];
        let (_, triple) = unit_role_and_triple(unit, host);
        let panic_strategy = effective_panic_strategy(unit);
        roots.push(json!({
            "crate": language_name,
            "crate_root": unit
                .target
                .src_path
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            "edition": unit.target.edition,
            "panic_strategy": panic_strategy,
            "target_triple": triple,
            "cfg": []
        }));
    }
    Ok((roots, language_units))
}

fn effective_panic_strategy(unit: &SerializedUnit) -> &str {
    match unit.profile.panic.as_deref() {
        Some("unwind") => "unwind",
        Some("immediate-abort") => "immediate-abort",
        _ => "abort",
    }
}

#[cfg(test)]
pub(super) fn emit_source_graphs_from_json(
    unit_graph_json: &[u8],
    every_unit_root: bool,
    host: &str,
    language_roots: Option<&Path>,
    out_dir: &Path,
) -> Result<Vec<(String, PathBuf)>> {
    let graph: SerializedUnitGraph =
        serde_json::from_slice(unit_graph_json).context("parsing Cargo `--unit-graph` JSON")?;
    ensure!(
        graph.version == 1,
        "unsupported Cargo `--unit-graph` schema version {}",
        graph.version
    );
    let inferred =
        language_roots.map_or_else(|| infer_language_roots(&graph, out_dir), Path::to_path_buf);
    let selected_roots: Vec<usize> = if every_unit_root {
        (0..graph.units.len())
            .filter(|&index| graph.units[index].mode != "run-custom-build")
            .collect()
    } else {
        graph.roots.clone()
    };
    emit_source_graphs(&selected_roots, &graph, host, &inferred, out_dir)
}

#[allow(clippy::too_many_lines)]
fn emit_source_graphs(
    roots: &[usize],
    graph: &SerializedUnitGraph,
    host: &str,
    bootstrap_dir: &Path,
    out_dir: &Path,
) -> Result<Vec<(String, PathBuf)>> {
    fs::create_dir_all(out_dir).with_context(|| {
        format!(
            "creating source-graph output directory {}",
            out_dir.display()
        )
    })?;
    let mut sorted_roots: Vec<usize> = roots.to_vec();
    sorted_roots.sort_by_key(|&idx| unit_key(idx));

    let mut emitted = Vec::new();
    for root_idx in sorted_roots {
        let root_unit = graph
            .units
            .get(root_idx)
            .with_context(|| format!("root unit index {root_idx} out of bounds"))?;
        let root_key = unit_key(root_idx);
        let closure = topo_closure(root_idx, graph);
        let (language_roots, language_units) =
            build_language_roots(bootstrap_dir, &closure, graph, host)?;
        if language_units.contains(&root_idx) {
            let root_pkg = parse_pkg_id(&root_unit.pkg_id)?;
            println!(
                "SOURCE-GRAPH-SKIPPED root={root_key} package={} reason=language-unit",
                root_pkg.name
            );
            continue;
        }

        let mut units_json = Vec::with_capacity(closure.len());
        let mut edges_json = Vec::new();
        let mut identities = HashMap::<String, usize>::new();

        for &unit_idx in &closure {
            let unit = &graph.units[unit_idx];
            let key = unit_key(unit_idx);
            let (role, triple) = unit_role_and_triple(unit, host);
            let pkg = parse_pkg_id(&unit.pkg_id)?;
            let crate_root = unit
                .target
                .src_path
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_default();
            let features: Vec<String> = sorted_features(unit)
                .into_iter()
                .map(str::to_owned)
                .collect();
            let panic_strategy = effective_panic_strategy(unit);
            let rustflags = if panic_strategy == "abort" {
                vec!["-Cpanic=abort".to_owned()]
            } else {
                Vec::new()
            };
            let projected = json!({
                "key": key,
                "identity": {
                    "package_namespace": "crates.io",
                    "package_name": pkg.name,
                    "package_version": pkg.version,
                    "crate_name": crate_name(&unit.target),
                    "logical_target": unit.target.name,
                    "logical_root": unit.target.name,
                    "kind": target_kind_str(&unit.target),
                    "role": role,
                    "target_triple": triple,
                    "edition": unit.target.edition,
                    "panic_strategy": panic_strategy,
                    "features": features,
                    "cfg": []
                },
                "crate_root": crate_root,
                "generator": "none",
                "semantics": {
                    "debug_assertions": unit.profile.debug_assertions,
                    "overflow_checks": unit.profile.overflow_checks,
                    "rustflags": rustflags
                }
            });
            if let Some(previous) = identities.insert(projected["identity"].to_string(), unit_idx) {
                ensure!(
                    previous == unit_idx,
                    "distinct Cargo units {} and {} collapse to one source identity; refusing lossy projection",
                    unit_key(previous),
                    key
                );
            }
            units_json.push(projected);

            let mut sorted_deps: Vec<&SerializedUnitDep> = unit.dependencies.iter().collect();
            sorted_deps.sort_by_key(|dep| (dep.extern_crate_name.clone(), unit_key(dep.index)));
            for dep in sorted_deps {
                if language_units.contains(&unit_idx) || language_units.contains(&dep.index) {
                    continue;
                }
                let dep_unit = graph.units.get(dep.index).with_context(|| {
                    format!("dependency unit index {} out of bounds", dep.index)
                })?;
                if dep_unit.mode == "run-custom-build" && unit.mode != "run-custom-build" {
                    continue;
                }
                let (dep_role, _) = unit_role_and_triple(dep_unit, host);
                edges_json.push(json!({
                    "from": key,
                    "extern_name": dep.extern_crate_name,
                    "to": unit_key(dep.index),
                    "kind": "rust",
                    "role": dep_role
                }));
            }
        }

        let source_graph = json!({
            "schema": "eko.source-graph/1",
            "root": root_key,
            "units": units_json,
            "edges": edges_json,
            "language_roots": language_roots,
        });
        let safe_name = root_key.replace(['/', ':', '@'], "_");
        let graph_path = out_dir.join(format!("{safe_name}.source-graph.json"));
        let body = serde_json::to_string_pretty(&source_graph)? + "\n";
        fs::write(&graph_path, body)
            .with_context(|| format!("writing source-graph {}", graph_path.display()))?;
        println!("SOURCE-GRAPH root={root_key} path={}", graph_path.display());
        emitted.push((root_key, graph_path));
    }
    Ok(emitted)
}

fn count_objects(dir: &Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += count_objects(&path);
            } else if path.extension().is_some_and(|ext| ext == "o") {
                count += 1;
            }
        }
    }
    count
}

async fn compile_emitted_graphs(
    compiler_client: &Path,
    socket: &Path,
    out_dir: &Path,
    opt_level: Option<&str>,
    timing: bool,
    emitted: &[(String, PathBuf)],
) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("creating compile output directory {}", out_dir.display()))?;
    let mut rows = Vec::with_capacity(emitted.len());
    let mut failures = Vec::new();

    for (root_key, graph_path) in emitted {
        let safe_name = root_key.replace(['/', ':', '@'], "_");
        let obj_dir = out_dir.join(format!("obj-{safe_name}"));
        fs::create_dir(&obj_dir).with_context(|| {
            format!(
                "creating fresh object directory {}; use a fresh --out-dir to avoid counting stale objects",
                obj_dir.display()
            )
        })?;
        let started = Instant::now();
        let mut command = tokio::process::Command::new(compiler_client);
        command.arg("--socket").arg(socket).arg("compile");
        if let Some(level) = opt_level {
            command.arg(format!("-{level}"));
        }
        if timing {
            command.arg("--timing");
        }
        command
            .arg(format!("--source-graph={}", graph_path.display()))
            .arg("--target")
            .arg(format!("dir={}", obj_dir.display()));
        let output = command
            .output()
            .await
            .with_context(|| format!("invoking {} for {root_key}", compiler_client.display()))?;
        let elapsed = started.elapsed().as_secs();
        let status = match output.status.code() {
            Some(code) => format!("exit-{code}"),
            None => "signal".to_owned(),
        };
        let stdout_path = out_dir.join(format!("{safe_name}.stdout.log"));
        let stderr_path = out_dir.join(format!("{safe_name}.stderr.log"));
        fs::write(&stdout_path, &output.stdout)
            .with_context(|| format!("writing compile receipt {}", stdout_path.display()))?;
        fs::write(&stderr_path, &output.stderr)
            .with_context(|| format!("writing compile diagnostics {}", stderr_path.display()))?;
        let objects = count_objects(&obj_dir);
        rows.push(format!(
            "{root_key}\t{status}\t{elapsed}s\tobjects={objects}\tstdout={}\tstderr={}",
            stdout_path.display(),
            stderr_path.display(),
        ));
        if !output.status.success() {
            failures.push(format!("{root_key} ({status})"));
        }
    }

    let summary_path = out_dir.join("summary.tsv");
    fs::write(&summary_path, rows.join("\n") + "\n")
        .with_context(|| format!("writing {}", summary_path.display()))?;
    println!("COMPILE-SUMMARY path={}", summary_path.display());
    if !failures.is_empty() {
        bail!(
            "source-graph compilation failed for: {}",
            failures.join(", ")
        );
    }
    Ok(())
}
