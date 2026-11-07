#!/usr/bin/env bash
set -euo pipefail
source .github/release/common.sh
assert_reviewed
version_from_manifest

case "$1" in
  verify)
    dir=$2
    mkdir -p "$dir"
    cargo generate-lockfile
    cargo metadata --locked --format-version 1 > "$dir/workspace.json"
    scan_lock Cargo.lock
    validate_metadata "$dir/workspace.json"
    cp Cargo.lock "$dir/"
    cargo fmt --check
    cargo clippy --all-targets --locked
    cargo test --locked
    cargo package --locked
    prefix="cargo-vip-$VERSION"
    crate="$dir/$prefix.crate"
    cp "target/package/$prefix.crate" "$crate"
    mkdir "$RUNNER_TEMP/packaged-crate"
    tar -xzf "$crate" -C "$RUNNER_TEMP/packaged-crate"
    packaged="$RUNNER_TEMP/packaged-crate/$prefix"
    cp "$packaged/Cargo.lock" "$dir/packaged.lock"
    scan_lock "$dir/packaged.lock"
    cargo metadata --locked --format-version 1 --manifest-path "$packaged/Cargo.toml" > "$dir/packaged.json"
    validate_metadata "$dir/packaged.json"
    # Mirror Cargo's registry upload schema for this single crates.io package.
    # Reject unsupported dependency/manifest variants instead of silently translating them.
    jq -e --rawfile readme "$packaged/README.md" '
      .resolve.root as $root | .packages[] | select(.id == $root) |
      select(.publish == null or .publish == ["crates-io"]) |
      select(.readme == "README.md" and .license_file == null) |
      select(all(.dependencies[]; .path == null and .registry == null and
        .source == "registry+https://github.com/rust-lang/crates.io-index" and .artifact == null)) |
      {name, vers:.version,
        deps:[.dependencies[] | {name, optional, default_features:.uses_default_features,
          features, version_req:.req, target, kind:(.kind // "normal")} +
          (if .rename == null then {} else {explicit_name_in_toml:.rename} end)],
        features, authors, description, documentation, homepage, readme:$readme,
        readme_file:"README.md", keywords, categories, license, license_file, repository,
        badges:{}, links, rust_version}
    ' "$dir/packaged.json" > "$dir/publish.json"
    jq -cn --arg sha "$REVIEWED_SHA" --arg version "$VERSION" --arg run "$GITHUB_RUN_ID" \
      --arg rust "$RUST_VERSION" --arg crate "$(digest "$crate")" \
      --arg lock "$(digest "$dir/Cargo.lock")" --arg packaged_lock "$(digest "$dir/packaged.lock")" \
      --arg workspace "$(digest "$dir/workspace.json")" --arg packaged "$(digest "$dir/packaged.json")" \
      --arg upload "$(digest "$dir/publish.json")" '
      {commit:$sha, version:$version, run_id:$run, rust:$rust, crate_sha256:$crate,
        workspace_lock_sha256:$lock, packaged_lock_sha256:$packaged_lock,
        workspace_resolution_sha256:$workspace, packaged_resolution_sha256:$packaged,
        upload_metadata_sha256:$upload, gates:["fmt","clippy","test","package"]}
    ' > "$dir/evidence.json"
    verify_crate_evidence "$dir" "$GITHUB_RUN_ID"
    ;;
  prepare)
    verify_crate_evidence "$2" "$3"
    tag_state
    registry_state
    initial_registry=$registry
    if [[ $registry == missing ]]; then
      [[ $REGISTRY_TOKEN_PRESENT == true ]] || die 'Set CARGO_REGISTRY_TOKEN before reserving a tag for upload'
      # Cargo Registry Web API: two little-endian u32 lengths followed by
      # their respective JSON and crate byte strings.
      perl -e '
        binmode STDOUT;
        for my $file (@ARGV) {
          open my $fh, "<:raw", $file or die "Cannot open payload input";
          local $/;
          my $bytes = <$fh>;
          die "Invalid payload length" unless defined($bytes) && length($bytes) && length($bytes) <= 0xffffffff;
          print pack("V", length($bytes)), $bytes or die "Cannot write payload";
        }
        close STDOUT or die "Cannot close payload";
      ' "$2/publish.json" "$CRATE" > "$RUNNER_TEMP/crates-io-upload.bin"
    fi
    # An occupied version can reach tag creation only with a matching checksum.
    ensure_tag
    registry_state
    [[ $initial_registry != matching || $registry == matching ]] ||
      die 'Previously observed crate version is temporarily unavailable'
    if [[ $registry == missing ]]; then
      echo 'upload=true' >> "$GITHUB_OUTPUT"
    fi
    ;;
  upload)
    verify_crate_evidence "$2" "$3"
    test -s "$RUNNER_TEMP/crates-io-upload.bin"
    [[ -n ${CARGO_REGISTRY_TOKEN:-} ]] || die 'Missing CARGO_REGISTRY_TOKEN'
    registry_state
    assert_tag
    [[ $registry == missing ]] || exit 0
    request -A 'cargo-vip release workflow (https://github.com/pathscale/cargo.vip)' \
      -X PUT -H "Authorization: $CARGO_REGISTRY_TOKEN" -H 'Accept: application/json' \
      -H 'Content-Type: application/octet-stream' \
      --data-binary "@$RUNNER_TEMP/crates-io-upload.bin" 'https://crates.io/api/v1/crates/new'
    [[ $status == 200 ]] || die "Crate upload returned HTTP $status. Recover using the retained evidence run."
    jq -e '(.errors == null or .errors == []) and (.warnings | type == "object")' <<< "$body" >/dev/null ||
      die 'Crate upload returned invalid JSON. Recover using the retained evidence run.'
    ;;
  confirm)
    verify_crate_evidence "$2" "$3"
    for attempt in {1..12}; do
      registry_state
      [[ $registry == matching ]] && exit 0
      sleep 5
    done
    die 'Version is not visible yet. Wait and rerun with the same evidence run.'
    ;;
  *) die 'Unknown crate operation' ;;
esac
