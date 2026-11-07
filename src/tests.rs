
use crate::broker::{self, Resolved};
use crate::cli::{self, Args};
use crate::config::{self, FileConfig, RegistryToken};
use crate::proxy::{self, Registry};
use crate::registry::{self, Source};
use clap::CommandFactory;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

fn args() -> Args {
    Args {
        registry: vec!["vip".to_owned()],
        endpoint: "https://fly.storage.tigris.dev".to_owned(),
        region: "auto".to_owned(),
        bucket: None,
        broker: "wss://api.crates.vip".to_owned(),
        key_id: None,
        key_secret: None,
        token: Vec::new(),
        serve: false,
        build_driver: None,
        cargo_args: Vec::new(),
    }
}

fn test_directory() -> PathBuf {
    static NEXT_DIRECTORY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = NEXT_DIRECTORY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "cargo-vip-test-{}-{nonce}-{sequence}",
        std::process::id()
    ))
}

#[cfg(unix)]
#[test]
fn credential_persistence_uses_private_modes_and_replaces_contents() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let root = test_directory();
    fs::create_dir(&root).unwrap();
    let parent = root.join("cargo-vip");
    let path = parent.join("credentials.toml");
    config::persist_credentials(&path, b"old-token").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    config::persist_credentials(&path, b"new-token").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"new-token");
    assert_eq!(
        fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let foreign = root.join("foreign");
    fs::write(&foreign, b"preserve").unwrap();
    let linked = root.join("linked-credentials");
    symlink(&foreign, &linked).unwrap();
    assert!(config::persist_credentials(&linked, b"replacement").is_err());
    assert_eq!(fs::read(&foreign).unwrap(), b"preserve");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn credential_persistence_refuses_a_symlink_parent() {
    use std::os::unix::fs::symlink;

    let root = test_directory();
    fs::create_dir(&root).unwrap();
    let real_parent = root.join("real");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = root.join("cargo-vip");
    symlink(&real_parent, &linked_parent).unwrap();
    assert!(
        config::persist_credentials(&linked_parent.join("credentials.toml"), b"secret").is_err()
    );
    assert!(!real_parent.join("credentials.toml").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn crate_key_is_content_addressed() {
    assert_eq!(
        Registry::crate_key("worktable", "1.0.0-beta.11", "abc123"),
        "crates/worktable-1.0.0-beta.11_abc123.tar.gz",
    );
}

#[test]
fn accepts_sparse_layout_and_ascii_case_without_extra_path_components() {
    for key in ["1/A", "2/Ab", "3/A/AbC", "Fo/Ur/FoUr"] {
        assert!(
            proxy::valid_sparse_index_key(key),
            "expected valid sparse key {key}"
        );
    }
    for key in [
        "1/AA",
        "3/B/AbC",
        "Fo/Ur/FoUr/extra",
        "../crate",
        "%2e%2e/crate",
    ] {
        assert!(
            !proxy::valid_sparse_index_key(key),
            "expected invalid sparse key {key}"
        );
    }
}

#[test]
fn accepts_only_single_component_crate_downloads_with_sha256_checksums() {
    assert!(proxy::valid_download_components(
        "Crate_Name",
        "1.2.3-alpha.1+build.4",
        &"a".repeat(64),
    ));
    assert!(!proxy::valid_download_components(
        "../crate",
        "1.2.3",
        &"a".repeat(64)
    ));
    assert!(!proxy::valid_download_components(
        "crate",
        "../1.2.3",
        &"a".repeat(64)
    ));
    assert!(!proxy::valid_download_components(
        "crate", "1.2.3", "abc123"
    ));
}

#[test]
fn reads_the_legacy_single_token_file() {
    let file: FileConfig =
        toml::from_str("broker = \"wss://old.example\"\ntoken = \"old-token\"\n").unwrap();
    assert_eq!(file.token.as_deref(), Some("old-token"));
    assert!(file.registry.is_empty());
}

#[test]
fn credential_parse_diagnostic_does_not_echo_input() {
    let marker = "synthetic-secret-marker";
    let error = config::parse_credentials_file(&format!("token = \"{marker}\n"))
        .err()
        .expect("malformed credentials must fail");
    let error = format!("{error:#}");
    assert_eq!(error, "could not parse credentials file");
    assert!(!error.contains(marker));
}

fn saved_broker_resolved(args: &Args, token: &str, bucket: &str) -> Resolved {
    Resolved {
        key_id: format!("id-{token}"),
        key_secret: format!("secret-{token}"),
        bucket: bucket.to_owned(),
        endpoint: args.endpoint.clone(),
        region: args.region.clone(),
    }
}

#[test]
fn saved_broker_uses_entry_issuer_then_top_level_fallback() {
    let file = FileConfig {
        broker: Some("wss://top.example/preserved".into()),
        registry: vec![RegistryToken {
            bucket: "alpha".into(),
            token: "saved-secret".into(),
            broker: Some("wss://entry.example/exact".into()),
        }],
        ..FileConfig::default()
    };
    assert_eq!(
        registry::saved_broker_pair(&file, file.registry[0].broker.as_deref(), "saved-secret")
            .unwrap(),
        ("wss://entry.example/exact".into(), "saved-secret".into())
    );
    assert_eq!(
        registry::saved_broker_pair(&file, Some("  "), "saved-secret").unwrap(),
        ("wss://top.example/preserved".into(), "saved-secret".into())
    );

    let malformed = registry::saved_broker_pair(&file, Some("https://bad.example"), "saved-secret")
        .unwrap_err()
        .to_string();
    assert!(malformed.contains("wss"));
    assert!(!malformed.contains("top.example"));
}

#[test]
fn saved_broker_requires_a_recorded_issuer_without_disclosing_values() {
    let file = FileConfig {
        token: Some("legacy-secret".into()),
        ..FileConfig::default()
    };
    let error = registry::stored_token_source(&file, "vip", None)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("record the verified issuer"));
    assert!(!error.contains("legacy-secret"));
    assert!(!error.contains("api.crates.vip"));
    assert!(
        registry::source(
            &args(),
            &FileConfig {
                registry: vec![RegistryToken {
                    bucket: "alpha".into(),
                    token: "entry-secret".into(),
                    broker: None,
                }],
                ..FileConfig::default()
            },
            None,
        )
        .is_err()
    );
}

#[test]
fn saved_broker_legacy_token_uses_only_its_recorded_issuer() {
    let file = FileConfig {
        broker: Some("wss://legacy.example/original".into()),
        token: Some("legacy-token".into()),
        ..FileConfig::default()
    };
    for index in [None, Some("sparse+https://crates.vip/alpha/")] {
        match registry::source(&args(), &file, index).unwrap() {
            Source::Broker { url, token, .. } => {
                assert_eq!(url, "wss://legacy.example/original");
                assert_eq!(token, "legacy-token");
            }
            Source::Static(_) => panic!("expected saved broker credentials"),
        }
    }
}

#[test]
fn saved_broker_candidate_match_wins_before_a_blocked_saved_record() {
    let args = args();
    let file = FileConfig {
        registry: vec![RegistryToken {
            bucket: "alpha".into(),
            token: "saved-secret".into(),
            broker: Some("https://invalid.example".into()),
        }],
        ..FileConfig::default()
    };
    let candidates = vec!["candidate-token".to_owned()];
    let wanted = registry::wanted_broker_tokens(
        &args,
        &file,
        "alpha",
        Some("sparse+https://crates.vip/alpha/"),
        None,
        &candidates,
        1,
    )
    .unwrap();
    assert_eq!(
        wanted,
        vec![(args.broker.clone(), "candidate-token".into())]
    );

    let mut exchanges = Vec::new();
    let resolved = registry::resolve_registry_with(
        &args,
        &file,
        "alpha",
        Some("sparse+https://crates.vip/alpha/"),
        &candidates,
        None,
        1,
        |broker, token| {
            exchanges.push((broker.to_owned(), token.to_owned()));
            Ok(saved_broker_resolved(&args, token, "alpha"))
        },
    )
    .unwrap();
    assert_eq!(resolved.bucket, "alpha");
    assert_eq!(exchanges, vec![(args.broker, "candidate-token".into())]);
}

#[test]
fn saved_broker_unmatched_candidate_returns_issuer_error_without_exchange() {
    let args = args();
    let file = FileConfig {
        registry: vec![RegistryToken {
            bucket: "alpha".into(),
            token: "saved-secret".into(),
            broker: Some("https://invalid.example".into()),
        }],
        ..FileConfig::default()
    };
    let mut exchanges = Vec::new();
    let error = registry::resolve_registry_with(
        &args,
        &file,
        "alpha",
        Some("sparse+https://crates.vip/alpha/"),
        &["candidate-token".into()],
        None,
        1,
        |broker, token| {
            exchanges.push((broker.to_owned(), token.to_owned()));
            Ok(saved_broker_resolved(&args, token, "other"))
        },
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(exchanges.len(), 1);
    assert!(error.contains("wss"));
    assert!(!error.contains("saved-secret"));

    let mut blocked_calls = 0;
    let blocked = registry::resolve_registry_with(
        &args,
        &file,
        "alpha",
        Some("sparse+https://crates.vip/alpha/"),
        &[],
        None,
        1,
        |_, _| {
            blocked_calls += 1;
            Ok(saved_broker_resolved(&args, "saved-secret", "alpha"))
        },
    );
    assert!(blocked.is_err());
    assert_eq!(blocked_calls, 0);
}

#[test]
fn saved_broker_planner_and_resolver_share_the_exact_prepared_pair() {
    let args = args();
    let file = FileConfig {
        broker: Some("wss://issuer.example/original/path".into()),
        registry: vec![RegistryToken {
            bucket: "alpha".into(),
            token: "saved-token".into(),
            broker: Some("  ".into()),
        }],
        ..FileConfig::default()
    };
    let wanted = registry::wanted_broker_tokens(
        &args,
        &file,
        "alpha",
        Some("sparse+https://crates.vip/alpha/"),
        None,
        &[],
        1,
    )
    .unwrap();
    assert_eq!(
        wanted,
        vec![(
            "wss://issuer.example/original/path".into(),
            "saved-token".into()
        )]
    );
    let mut exchanged = Vec::new();
    registry::resolve_registry_with(
        &args,
        &file,
        "alpha",
        Some("sparse+https://crates.vip/alpha/"),
        &[],
        None,
        1,
        |broker, token| {
            exchanged.push((broker.to_owned(), token.to_owned()));
            Ok(saved_broker_resolved(&args, token, "alpha"))
        },
    )
    .unwrap();
    assert_eq!(wanted, exchanged);
}

#[test]
#[allow(clippy::too_many_lines)]
fn saved_broker_planner_and_resolver_cover_record_types_and_index_paths() {
    let args = args();
    let known_index = "sparse+https://crates.vip/alpha/";
    let placeholder_index = "sparse+https://crates.vip/index/";
    let per_bucket = FileConfig {
        broker: Some("wss://top.example/unchanged".into()),
        registry: vec![RegistryToken {
            bucket: "alpha".into(),
            token: "bucket-token".into(),
            broker: Some("wss://entry.example/preserved".into()),
        }],
        ..FileConfig::default()
    };
    for index in [known_index, placeholder_index] {
        let wanted =
            registry::wanted_broker_tokens(&args, &per_bucket, "vip", Some(index), None, &[], 2)
                .unwrap();
        assert_eq!(
            wanted,
            vec![(
                "wss://entry.example/preserved".into(),
                "bucket-token".into()
            )]
        );
        let prepared: Vec<_> = wanted
            .iter()
            .map(|pair| {
                (
                    pair.clone(),
                    Ok(saved_broker_resolved(&args, &pair.1, "alpha")),
                )
            })
            .collect();
        let planned = wanted.clone();
        let mut cache = BTreeMap::new();
        let resolved = registry::finish_registry_resolution(
            &args,
            &per_bucket,
            "vip",
            Some(index),
            &[],
            None,
            2,
            false,
            Ok(wanted),
            prepared,
            &mut cache,
        )
        .unwrap()
        .unwrap();
        assert_eq!(resolved.bucket, "alpha");
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&planned[0]).unwrap().bucket, "alpha");
    }

    let legacy = FileConfig {
        broker: Some("wss://legacy.example/original/path".into()),
        token: Some("legacy-token".into()),
        ..FileConfig::default()
    };
    for (index, expected_bucket) in [(known_index, Some("alpha")), (placeholder_index, None)] {
        let wanted =
            registry::wanted_broker_tokens(&args, &legacy, "vip", Some(index), None, &[], 2)
                .unwrap();
        assert_eq!(
            wanted,
            vec![(
                "wss://legacy.example/original/path".into(),
                "legacy-token".into()
            )]
        );
        let prepared: Vec<_> = wanted
            .iter()
            .map(|pair| {
                (
                    pair.clone(),
                    Ok(saved_broker_resolved(
                        &args,
                        &pair.1,
                        expected_bucket.unwrap_or("discovered-bucket"),
                    )),
                )
            })
            .collect();
        let planned = wanted.clone();
        let mut cache = BTreeMap::new();
        let resolved = registry::finish_registry_resolution(
            &args,
            &legacy,
            "vip",
            Some(index),
            &[],
            None,
            2,
            false,
            Ok(wanted),
            prepared,
            &mut cache,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            resolved.bucket,
            expected_bucket.unwrap_or("discovered-bucket")
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(&planned[0]).unwrap().bucket, resolved.bucket);
    }

    let mut mismatch_calls = 0;
    let mismatch = registry::resolve_registry_with(
        &args,
        &legacy,
        "vip",
        Some(known_index),
        &[],
        None,
        2,
        |_, token| {
            mismatch_calls += 1;
            Ok(saved_broker_resolved(&args, token, "other"))
        },
    )
    .err()
    .unwrap()
    .to_string();
    assert_eq!(mismatch_calls, 1);
    assert!(mismatch.contains(&registry::missing_token_message("alpha")));
}

#[test]
fn saved_broker_issuerless_saved_records_stop_planning_before_any_exchange() {
    let args = args();
    let known_index = "sparse+https://crates.vip/alpha/";
    let placeholder_index = "sparse+https://crates.vip/index/";
    let files = [
        FileConfig {
            registry: vec![RegistryToken {
                bucket: "alpha".into(),
                token: "bucket-token".into(),
                broker: None,
            }],
            ..FileConfig::default()
        },
        FileConfig {
            token: Some("legacy-token".into()),
            ..FileConfig::default()
        },
        FileConfig {
            registry: vec![RegistryToken {
                bucket: "alpha".into(),
                token: "bucket-token".into(),
                broker: Some("  ".into()),
            }],
            ..FileConfig::default()
        },
        FileConfig {
            token: Some("legacy-token".into()),
            broker: Some("  ".into()),
            ..FileConfig::default()
        },
    ];
    for file in &files {
        for index in [known_index, placeholder_index] {
            let wanted =
                registry::wanted_broker_tokens(&args, file, "vip", Some(index), None, &[], 2);
            assert!(
                wanted
                    .as_ref()
                    .unwrap_err()
                    .to_string()
                    .contains("record the verified issuer")
            );

            let mut resolver_calls = 0;
            let error = registry::resolve_registry_with(
                &args,
                file,
                "vip",
                Some(index),
                &[],
                None,
                2,
                |_, _| {
                    resolver_calls += 1;
                    Ok(saved_broker_resolved(&args, "unused", "alpha"))
                },
            )
            .err()
            .unwrap()
            .to_string();
            assert!(error.contains("record the verified issuer"));
            assert_eq!(resolver_calls, 0);
        }
    }
}

#[test]
fn saved_broker_explicit_override_and_static_key_keep_precedence() {
    let args = args();
    let file = FileConfig {
        registry: vec![RegistryToken {
            bucket: "alpha".into(),
            token: "saved-token".into(),
            broker: Some("https://invalid.example".into()),
        }],
        ..FileConfig::default()
    };
    let mut explicit_calls = 0;
    registry::resolve_registry_with(
        &args,
        &file,
        "alpha",
        Some("sparse+https://crates.vip/alpha/"),
        &[],
        Some("per-registry-token"),
        1,
        |broker, token| {
            explicit_calls += 1;
            assert_eq!(broker, args.broker.as_str());
            assert_eq!(token, "per-registry-token");
            Ok(saved_broker_resolved(&args, token, "alpha"))
        },
    )
    .unwrap();
    assert_eq!(explicit_calls, 1);

    let mut static_args = args;
    static_args.bucket = Some("alternate".into());
    static_args.key_id = Some("static-id".into());
    static_args.key_secret = Some("static-secret".into());
    let mut cache = BTreeMap::new();
    let static_result = registry::finish_registry_resolution(
        &static_args,
        &file,
        "alpha",
        Some("sparse+https://crates.vip/alpha/"),
        &[],
        None,
        1,
        false,
        Ok(Vec::new()),
        Vec::new(),
        &mut cache,
    )
    .unwrap()
    .unwrap();
    assert_eq!(static_result.key_id, "static-id");
    assert_eq!(static_result.bucket, "alternate");
    assert!(cache.is_empty());
}

#[test]
#[allow(clippy::too_many_lines)]
fn saved_broker_optional_publish_preparation_error_preserves_target_and_skips_off_target() {
    let mut publish_args = args();
    publish_args.registry = vec!["target".into()];
    let index_placeholder = "sparse+https://crates.vip/index/";
    let discovered = vec![
        (
            "target".to_owned(),
            "sparse+https://crates.vip/alpha/".to_owned(),
        ),
        ("optional".to_owned(), index_placeholder.to_owned()),
    ];
    let (active, publish_target) =
        registry::select_active_registries(&["target".to_owned()], &discovered, true).unwrap();
    assert!(active.iter().any(|(name, index)| {
        name == "optional" && index.as_deref() == Some(index_placeholder)
    }));
    assert_eq!(publish_target.as_deref(), Some("target"));

    let issuerless_file = FileConfig {
        registry: vec![RegistryToken {
            bucket: "alpha".into(),
            token: "saved-token".into(),
            broker: None,
        }],
        ..FileConfig::default()
    };
    let wanted_success = registry::wanted_broker_tokens(
        &publish_args,
        &issuerless_file,
        "target",
        Some("sparse+https://crates.vip/alpha/"),
        Some("target-token"),
        &[],
        active.len(),
    )
    .unwrap();
    assert_eq!(wanted_success.len(), 1);
    let target_pair = wanted_success[0].clone();
    let target = registry::finish_registry_resolution(
        &publish_args,
        &issuerless_file,
        "target",
        Some("sparse+https://crates.vip/alpha/"),
        &[],
        Some("target-token"),
        active.len(),
        registry::can_skip_registry(true, true, publish_target.as_deref(), "target"),
        Ok(wanted_success),
        vec![(
            target_pair,
            Ok(saved_broker_resolved(
                &publish_args,
                "target-token",
                "alpha",
            )),
        )],
        &mut BTreeMap::default(),
    )
    .unwrap();
    assert!(target.is_some());

    let wanted_optional = registry::wanted_broker_tokens(
        &publish_args,
        &issuerless_file,
        "optional",
        Some(index_placeholder),
        None,
        &[],
        2,
    );
    assert!(
        wanted_optional
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("record the verified issuer")
    );

    let optional = registry::finish_registry_resolution(
        &publish_args,
        &issuerless_file,
        "optional",
        Some(index_placeholder),
        &[],
        None,
        active.len(),
        registry::can_skip_registry(true, true, publish_target.as_deref(), "optional"),
        wanted_optional,
        Vec::new(),
        &mut BTreeMap::default(),
    )
    .unwrap();
    assert!(optional.is_none());

    let wanted_target = registry::wanted_broker_tokens(
        &publish_args,
        &issuerless_file,
        "target",
        Some("sparse+https://crates.vip/alpha/"),
        None,
        &[],
        active.len(),
    );
    let target_error = registry::finish_registry_resolution(
        &publish_args,
        &issuerless_file,
        "target",
        Some("sparse+https://crates.vip/alpha/"),
        &[],
        None,
        active.len(),
        registry::can_skip_registry(true, true, publish_target.as_deref(), "target"),
        wanted_target,
        Vec::new(),
        &mut BTreeMap::default(),
    )
    .err()
    .unwrap();
    assert!(
        target_error
            .to_string()
            .contains("record the verified issuer")
    );

    for (command, is_publish) in [("build", false), ("serve", false)] {
        let mut ordinary_args = args();
        ordinary_args.cargo_args = vec![command.to_owned()];
        let wanted = registry::wanted_broker_tokens(
            &ordinary_args,
            &issuerless_file,
            "optional",
            Some(index_placeholder),
            None,
            &[],
            active.len(),
        );
        let error = registry::finish_registry_resolution(
            &ordinary_args,
            &issuerless_file,
            "optional",
            Some(index_placeholder),
            &[],
            None,
            active.len(),
            registry::can_skip_registry(is_publish, false, publish_target.as_deref(), "optional"),
            wanted,
            Vec::new(),
            &mut BTreeMap::default(),
        )
        .err()
        .unwrap();
        assert!(error.to_string().contains("record the verified issuer"));
    }
}

#[test]
fn replacing_a_bucket_token_preserves_other_buckets() {
    let mut file = FileConfig::default();
    config::save_registry_token(&mut file, "alpha", "old-alpha", "wss://alpha.example");
    config::save_registry_token(&mut file, "beta", "beta-token", "wss://beta.example");
    config::save_registry_token(&mut file, "alpha", "new-alpha", "wss://alpha.example");

    assert_eq!(file.registry.len(), 2);
    assert_eq!(file.registry[0].bucket, "alpha");
    assert_eq!(file.registry[0].token, "new-alpha");
    assert_eq!(file.registry[1].bucket, "beta");
    assert_eq!(file.registry[1].token, "beta-token");
}

#[test]
fn registry_tokens_round_trip_as_array_tables() {
    let mut file = FileConfig::default();
    config::save_registry_token(&mut file, "alpha", "alpha-token", "wss://alpha.example");
    config::save_registry_token(&mut file, "beta", "beta-token", "wss://beta.example");

    let encoded = toml::to_string_pretty(&file).unwrap();
    assert!(encoded.contains("[[registry]]"));
    let decoded: FileConfig = toml::from_str(&encoded).unwrap();
    assert_eq!(decoded.registry.len(), 2);
    assert_eq!(decoded.registry[1].bucket, "beta");
    assert_eq!(decoded.registry[1].token, "beta-token");
}

#[test]
fn selects_the_saved_token_for_the_configured_registry_bucket() {
    let mut file = FileConfig::default();
    config::save_registry_token(&mut file, "alpha", "alpha-token", "wss://alpha.example");
    config::save_registry_token(&mut file, "beta", "beta-token", "wss://beta.example");

    let selected =
        registry::source(&args(), &file, Some("sparse+https://crates.vip/beta/")).unwrap();
    match selected {
        Source::Broker {
            token,
            expected_bucket,
            ..
        } => {
            assert_eq!(token, "beta-token");
            assert_eq!(expected_bucket.as_deref(), Some("beta"));
        }
        Source::Static(_) => panic!("expected broker credentials"),
    }
}

#[test]
fn explicit_token_overrides_saved_bucket_tokens() {
    let mut file = FileConfig::default();
    config::save_registry_token(&mut file, "alpha", "alpha-token", "wss://alpha.example");
    let mut args = args();
    args.token = vec!["ci-token".to_owned()];

    let selected = registry::source(&args, &file, Some("sparse+https://crates.vip/beta/")).unwrap();
    match selected {
        Source::Broker { url, token, .. } => {
            assert_eq!(token, "ci-token");
            assert_eq!(url, "wss://api.crates.vip");
        }
        Source::Static(_) => panic!("expected broker credentials"),
    }
}

#[test]
fn discovers_multiple_crates_vip_registries_from_config_and_env() {
    let root = test_directory();
    let cargo = root.join(".cargo");
    fs::create_dir_all(&cargo).unwrap();
    fs::write(cargo.join("config.toml"),
            "[registries.bucket-a]\nindex = \"sparse+https://crates.vip/bucket-a/\"\n[registries.bucket-b]\nindex = \"sparse+https://crates.vip/bucket-b/\"\n[registries.other]\nindex = \"sparse+https://example.com/index/\"\n").unwrap();
    let parsed = registry::registries_in_toml(
        &fs::read_to_string(cargo.join("config.toml")).unwrap(),
        "test",
    )
    .unwrap();
    assert_eq!(parsed.len(), 3);
    let env = vec![(
        "CARGO_REGISTRIES_UPSTREAM_INDEX".to_owned(),
        "sparse+https://crates.vip/upstream/".to_owned(),
    )];
    let found = registry::discover_registries(&root, None, &env).unwrap();
    assert_eq!(
        found,
        vec![
            (
                "bucket-a".to_owned(),
                "sparse+https://crates.vip/bucket-a/".to_owned()
            ),
            (
                "bucket-b".to_owned(),
                "sparse+https://crates.vip/bucket-b/".to_owned()
            ),
            (
                "upstream".to_owned(),
                "sparse+https://crates.vip/upstream/".to_owned()
            ),
        ]
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cargo_config_parse_diagnostic_does_not_echo_malformed_index_line() {
    let marker = "synthetic-index-userinfo-marker";
    let text = format!("[registries.vip]\nindex = \"https://{marker}@crates.vip/private/\n");
    let error = registry::registries_in_toml(&text, "synthetic config").unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("synthetic config"));
    assert!(error.contains("invalid TOML"));
    assert!(!error.contains(marker));

    let root = test_directory();
    fs::create_dir(&root).unwrap();
    let path = root.join("config.toml");
    fs::write(&path, &text).unwrap();
    let result = registry::registry_index_in_file(&path, "vip");
    fs::remove_dir_all(root).unwrap();
    let error = format!("{:#}", result.unwrap_err());
    assert_eq!(
        error,
        format!("parsing Cargo config {}: invalid TOML", path.display())
    );
    assert!(!error.contains(marker));
}

#[test]
fn saved_bucket_mismatch_diagnostic_is_safe() {
    let args = args();
    let mut file = FileConfig::default();
    config::save_registry_token(&mut file, "expected", "saved-token", "wss://issuer.example");
    let pair = ("wss://issuer.example".to_owned(), "saved-token".to_owned());
    let mut cache = BTreeMap::from([(
        pair.clone(),
        Resolved {
            key_id: "id".into(),
            key_secret: "secret".into(),
            bucket: "wrong-bucket".into(),
            endpoint: args.endpoint.clone(),
            region: args.region.clone(),
        },
    )]);
    let error = registry::finish_registry_resolution(
        &args,
        &file,
        "vip",
        Some("sparse+https://crates.vip/expected/"),
        &[],
        None,
        2,
        false,
        Ok(vec![pair.clone()]),
        Vec::new(),
        &mut cache,
    )
    .err()
    .expect("saved bucket mismatch must fail");
    let error = format!("{error:#}");
    assert!(error.contains("configured registry bucket"));
    assert!(!error.contains("saved-token"));

    let fresh = saved_broker_resolved(&args, "saved-token", "wrong-bucket");
    let error = registry::finish_registry_resolution(
        &args,
        &file,
        "vip",
        Some("sparse+https://crates.vip/expected/"),
        &[],
        None,
        2,
        false,
        Ok(vec![pair.clone()]),
        vec![(pair.clone(), Ok(fresh))],
        &mut BTreeMap::new(),
    )
    .err()
    .expect("fresh bucket mismatch must fail");
    let error = format!("{error:#}");
    assert!(error.contains("configured registry bucket"));
    assert!(!error.contains("saved-token"));

    let optional = registry::finish_registry_resolution(
        &args,
        &file,
        "vip",
        Some("sparse+https://crates.vip/expected/"),
        &[],
        None,
        2,
        registry::can_skip_registry(true, true, Some("target"), "vip"),
        Ok(vec![pair]),
        Vec::new(),
        &mut cache,
    )
    .unwrap();
    assert!(optional.is_none());
}

#[test]
fn help_hides_credential_environment_values_in_metadata() {
    let mut command = Args::command();
    for (name, env) in [
        ("key_id", "CARGO_VIP_KEY_ID"),
        ("key_secret", "CARGO_VIP_KEY_SECRET"),
        ("token", "CARGO_VIP_TOKEN"),
    ] {
        let arg = command
            .get_arguments()
            .find(|arg| arg.get_id().as_str() == name)
            .expect("credential argument exists");
        assert_eq!(arg.get_env(), Some(OsStr::new(env)));
        assert!(
            arg.is_hide_env_values_set(),
            "{name} must hide its environment value"
        );
    }
    let help = command.render_long_help().to_string();
    for env in [
        "CARGO_VIP_TOKEN",
        "CARGO_VIP_KEY_SECRET",
        "CARGO_VIP_BUILD_DRIVER",
    ] {
        assert!(help.contains(env), "help must name {env}");
    }
}

#[test]
fn broker_error_diagnostic_does_not_echo_peer_payload() {
    let marker = "synthetic-peer-secret-marker";
    let mut stream = futures_util::stream::iter([Ok::<_, tokio_tungstenite::tungstenite::Error>(
        tokio_tungstenite::tungstenite::Message::Text(format!(r#"{{"error":"{marker}"}}"#).into()),
    )]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let error = runtime
        .block_on(broker::next_json(&mut stream))
        .unwrap_err();
    let error = format!("{error:#}");
    assert_eq!(error, "the registry refused the credential request");
    assert!(!error.contains(marker));
}

#[test]
fn registry_index_errors_do_not_echo_the_index_url() {
    let marker = "synthetic-index-secret-marker";
    let error =
        registry::bucket_from_index(&format!("https://{marker}.example/private/"), "upstream")
            .unwrap_err();
    let error = format!("{error:#}");
    assert!(error.contains("not a crates.vip index URL"));
    assert!(!error.contains(marker));
}

#[test]
fn broker_close_reason_is_not_disclosed() {
    let reason = "synthetic-peer-close-secret";
    let frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
        code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Error,
        reason: reason.into(),
    };
    let mut stream = futures_util::stream::iter([Ok::<_, tokio_tungstenite::tungstenite::Error>(
        tokio_tungstenite::tungstenite::Message::Close(Some(frame)),
    )]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let error = runtime
        .block_on(broker::next_json(&mut stream))
        .expect_err("close frame must fail");
    let error = format!("{error:#}");
    assert!(error.contains("closed the connection"));
    assert!(!error.contains(reason));
}

#[test]
fn non_vip_environment_override_removes_a_non_default_registry() {
    let root = test_directory();
    let cargo = root.join(".cargo");
    fs::create_dir_all(&cargo).unwrap();
    fs::write(
        cargo.join("config.toml"),
        "[registries.upstream]\nindex = \"sparse+https://crates.vip/private/\"\n",
    )
    .unwrap();
    let env = vec![(
        "CARGO_REGISTRIES_UPSTREAM_INDEX".to_owned(),
        "sparse+https://example.com/replacement/".to_owned(),
    )];
    let found = registry::discover_registries(&root, None, &env).unwrap();
    fs::remove_dir_all(root).unwrap();
    assert_eq!(found, Vec::<(String, String)>::new());
}

#[test]
fn non_vip_default_override_is_not_recreated_by_planning() {
    let root = test_directory();
    let cargo = root.join(".cargo");
    fs::create_dir_all(&cargo).unwrap();
    let path = cargo.join("config.toml");
    let lowercase = "[registries.vip]\nindex = \"sparse+https://crates.vip/configured/\"\n";
    let uppercase = "[registries.VIP]\nindex = \"sparse+https://crates.vip/alias/\"\n";
    let upstream = "[registries.upstream]\nindex = \"sparse+https://crates.vip/upstream/\"\n";
    let external = "sparse+https://example.com/replacement/";
    let stable = "sparse+https://crates.vip/upstream/";
    let loopback = "sparse+http://127.0.0.1:12345/";
    let env = vec![("CARGO_REGISTRIES_VIP_INDEX".to_owned(), external.to_owned())];

    for (config, mixed) in [
        (lowercase.to_owned(), false),
        (uppercase.to_owned(), false),
        (format!("{uppercase}{lowercase}"), false),
        (format!("{uppercase}{lowercase}{upstream}"), true),
    ] {
        fs::write(&path, config).unwrap();
        let found = registry::discover_registries(&root, None, &env).unwrap();
        let mut expected = Vec::new();
        if mixed {
            expected.push(("upstream".to_owned(), stable.to_owned()));
        }
        expected.push(("vip".to_owned(), external.to_owned()));
        assert_eq!(found, expected);

        let (active, target) = registry::select_active_registries(&[], &found, false).unwrap();
        assert!(target.is_none());
        let triples: Vec<_> = active
            .into_iter()
            .map(|(name, index)| (name, index.unwrap(), loopback.to_owned()))
            .collect();
        let config = cli::cargo_config_all(&triples);
        let overrides = cli::cargo_env_all(&triples);
        let publish = registry::select_active_registries(&[], &found, true);
        if mixed {
            assert_eq!(config, cli::cargo_config("upstream", stable, loopback));
            assert_eq!(
                overrides,
                vec![(
                    "CARGO_REGISTRIES_UPSTREAM_INDEX".to_owned(),
                    loopback.to_owned()
                )]
            );
            assert_eq!(publish.unwrap().1.as_deref(), Some("upstream"));
        } else {
            assert_eq!(config, Vec::<String>::new());
            assert_eq!(overrides, Vec::<(String, String)>::new());
            assert!(publish.is_err());
        }
        let (explicit, _) =
            registry::select_active_registries(&["vip".to_owned()], &found, false).unwrap();
        assert_eq!(explicit, vec![("vip".to_owned(), None)]);
    }

    fs::write(
        &path,
        format!("[registries.vip]\nindex = \"{external}\"\n{upstream}"),
    )
    .unwrap();
    let found = registry::discover_registries(&root, None, &[]).unwrap();
    fs::remove_dir_all(root).unwrap();
    let (_, target) = registry::select_active_registries(&[], &found, true).unwrap();
    assert_eq!(target.as_deref(), Some("upstream"));
}

#[test]
fn resolves_tokens_from_per_registry_env_and_bucket_matched_pool_and_saved_config() {
    let args = args();
    let tokens = registry::collect_candidate_tokens(&[], |key| {
        (key == "CARGO_VIP_TOKENS").then(|| "cvip_test_a,cvip_test_b".to_owned())
    });
    assert_eq!(tokens, vec!["cvip_test_a", "cvip_test_b"]);
    let resolved = registry::resolve_registry_with(
        &args,
        &FileConfig::default(),
        "bucket-a",
        Some("sparse+https://crates.vip/bucket-a/"),
        &tokens,
        Some("per-registry-token"),
        2,
        |_, token| {
            assert_eq!(token, "per-registry-token");
            Ok(Resolved {
                key_id: "id".into(),
                key_secret: "secret".into(),
                bucket: "bucket-a".into(),
                endpoint: args.endpoint.clone(),
                region: args.region.clone(),
            })
        },
    )
    .unwrap();
    assert_eq!(resolved.bucket, "bucket-a");
}

#[test]
fn matches_shared_tokens_to_buckets_and_falls_back_to_saved_bucket_token() {
    let args = args();
    let mut file = FileConfig::default();
    config::save_registry_token(&mut file, "bucket-b", "saved-b", "wss://saved.example");
    let pool = vec!["cvip_test_a".to_owned(), "cvip_test_b".to_owned()];
    let resolved_a = registry::resolve_registry_with(
        &args,
        &FileConfig::default(),
        "alpha",
        Some("sparse+https://crates.vip/bucket-a/"),
        &pool,
        None,
        2,
        |_, token| {
            Ok(Resolved {
                key_id: "id".into(),
                key_secret: "secret".into(),
                bucket: if token == "cvip_test_a" {
                    "bucket-a"
                } else {
                    "bucket-b"
                }
                .into(),
                endpoint: args.endpoint.clone(),
                region: args.region.clone(),
            })
        },
    )
    .unwrap();
    assert_eq!(resolved_a.bucket, "bucket-a");
    let resolved_b = registry::resolve_registry_with(
        &args,
        &file,
        "beta",
        Some("sparse+https://crates.vip/bucket-b/"),
        &[],
        None,
        2,
        |_, token| {
            assert_eq!(token, "saved-b");
            Ok(Resolved {
                key_id: "id".into(),
                key_secret: "secret".into(),
                bucket: "bucket-b".into(),
                endpoint: args.endpoint.clone(),
                region: args.region.clone(),
            })
        },
    )
    .unwrap();
    assert_eq!(resolved_b.bucket, "bucket-b");
}

#[test]
fn merges_cargo_config_and_env_for_multiple_registries() {
    let triples = vec![
        (
            "vip".to_owned(),
            "sparse+https://crates.vip/bucket-a/".to_owned(),
            "sparse+http://127.0.0.1:1/".to_owned(),
        ),
        (
            "upstream".to_owned(),
            "sparse+https://crates.vip/bucket-b/".to_owned(),
            "sparse+http://127.0.0.1:2/".to_owned(),
        ),
    ];
    let config = cli::cargo_config_all(&triples);
    assert!(
        config
            .iter()
            .any(|value| value.contains("registries.vip.index"))
    );
    assert!(
        config
            .iter()
            .any(|value| value.contains("registries.upstream.index"))
    );
    assert_eq!(cli::cargo_env_all(&triples).len(), 2);
    assert!(cli::env_exports(&triples).contains("CARGO_REGISTRIES_UPSTREAM_INDEX"));
}

#[test]
fn selects_publish_target_across_multiple_registries() {
    let discovered = vec![
        (
            "upstream".to_owned(),
            "sparse+https://crates.vip/bucket-b/".to_owned(),
        ),
        (
            "vip".to_owned(),
            "sparse+https://crates.vip/bucket-a/".to_owned(),
        ),
    ];
    let (active, target) = registry::select_active_registries(&[], &discovered, true).unwrap();
    assert_eq!(target.as_deref(), Some("vip"));
    assert!(active.iter().any(|(name, _)| name == "upstream"));
    let (_, explicit) =
        registry::select_active_registries(&["upstream".to_owned()], &discovered, true).unwrap();
    assert_eq!(explicit.as_deref(), Some("upstream"));
    let only_other = vec![
        discovered[0].clone(),
        (
            "second".to_owned(),
            "sparse+https://crates.vip/bucket-c/".to_owned(),
        ),
    ];
    assert!(registry::select_active_registries(&[], &only_other, true).is_err());
}

#[test]
fn missing_selected_bucket_reports_login_command() {
    let file = FileConfig::default();
    let result = registry::source(&args(), &file, Some("sparse+https://crates.vip/beta/"));
    match result {
        Err(error) => assert_eq!(error.to_string(), registry::missing_token_message("beta")),
        Ok(_) => panic!("expected missing-token error"),
    }
}

#[test]
fn missing_bucket_error_names_the_login_command() {
    assert_eq!(
        registry::missing_token_message("beta"),
        "no token stored for registry bucket `beta`; run `cargo vip login` and enter a token for this bucket"
    );
}

#[test]
fn bucket_comes_from_the_sparse_index_path() {
    assert_eq!(
        registry::bucket_from_index("sparse+https://crates.vip/product-bucket/", "vip").unwrap(),
        Some("product-bucket".to_owned())
    );
    assert!(registry::bucket_from_index("https://example.com/product-bucket/", "vip").is_err());
}

#[test]
fn the_placeholder_index_names_no_bucket() {
    assert_eq!(
        registry::bucket_from_index("sparse+https://crates.vip/index/", "vip").unwrap(),
        None
    );
}

#[test]
fn registry_index_uses_nearest_config_and_environment_override() {
    let root = test_directory();
    let project = root.join("project");
    let nested = project.join("src").join("nested");
    let cargo_home = root.join("cargo-home");
    fs::create_dir_all(project.join(".cargo")).unwrap();
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::create_dir_all(root.join(".cargo")).unwrap();
    fs::write(
        root.join(".cargo/config.toml"),
        "[registries.vip]\nindex = \"sparse+https://crates.vip/parent/\"\n",
    )
    .unwrap();
    fs::write(
        project.join(".cargo/config.toml"),
        "[registries.vip]\nindex = \"sparse+https://crates.vip/project/\"\n",
    )
    .unwrap();
    fs::write(
        cargo_home.join("config.toml"),
        "[registries.vip]\nindex = \"sparse+https://crates.vip/global/\"\n",
    )
    .unwrap();

    let project_index =
        registry::find_registry_index("vip", &nested, Some(&cargo_home), None).unwrap();
    assert_eq!(
        project_index.as_deref(),
        Some("sparse+https://crates.vip/project/")
    );
    let environment_index = registry::find_registry_index(
        "vip",
        &nested,
        Some(&cargo_home),
        Some("sparse+https://crates.vip/environment/"),
    )
    .unwrap();
    assert_eq!(
        environment_index.as_deref(),
        Some("sparse+https://crates.vip/environment/")
    );
    fs::remove_dir_all(root.join(".cargo")).unwrap();
    let unrelated = root.join("unrelated");
    fs::create_dir_all(&unrelated).unwrap();
    let global_index =
        registry::find_registry_index("vip", &unrelated, Some(&cargo_home), None).unwrap();
    assert_eq!(
        global_index.as_deref(),
        Some("sparse+https://crates.vip/global/")
    );
    fs::remove_dir_all(root).unwrap();
}
