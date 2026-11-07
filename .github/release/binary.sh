#!/usr/bin/env bash
set -euo pipefail
source .github/release/common.sh

cross_rev=88f49ff79e777bef6d3564531636ee4d3cc2f8d2 # v0.2.5
targets=(aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl)

target_image() {
  case "$1" in
    aarch64-apple-darwin|x86_64-apple-darwin) ;;
    aarch64-unknown-linux-musl)
      echo ghcr.io/cross-rs/aarch64-unknown-linux-musl@sha256:53a761857a806b4f73b209a15bf71eacc38a82d5a02e05b166300c4794d7ad83 ;;
    x86_64-unknown-linux-musl)
      echo ghcr.io/cross-rs/x86_64-unknown-linux-musl@sha256:48da142669b71e8a4ef9f01eec80358dd9c8b174732dd672155041fe4a0f9c2d ;;
    *) die "Unsupported target: $1" ;;
  esac
}

binary_evidence() {
  local dir=$1 target=$2 run=$3 image revision archive
  image=$(target_image "$target")
  revision=''
  [[ -z $image ]] || revision=$cross_rev
  archive="$dir/cargo-vip-$target.tar.gz"
  jq -cn --arg sha "$REVIEWED_SHA" --arg version "$VERSION" --arg target "$target" \
    --arg rust "$RUST_VERSION" --arg image "$image" --arg revision "$revision" \
    --arg run "$run" --arg gate "$EVIDENCE_RUN" --arg evidence "$EVIDENCE_SHA" \
    --arg lock "$(digest "$dir/Cargo.lock")" \
    --arg resolution "$(digest "$dir/target-resolution.json")" --arg archive "$(digest "$archive")" '
    {commit:$sha, version:$version, target:$target, rust:$rust, cross_revision:$revision,
      image:$image, build_run_id:$run, gate_run_id:$gate, gate_evidence_sha256:$evidence,
      lock_sha256:$lock, target_resolution_sha256:$resolution, archive_sha256:$archive}
  '
}

release_state() {
  github "releases/tags/$TAG"
  case "$status" in
    404) release_id='' ;;
    200)
      release_id=$(jq -er --arg tag "$TAG" '
        select(.tag_name == $tag and .draft == false) | .id | select(type == "number")
      ' <<< "$body") || die 'Malformed release or draft release requires operator review'
      ;;
    *) die "Release lookup returned HTTP $status" ;;
  esac
}

asset_inventory() {
  if [[ -z $release_id ]]; then
    assets='[]'
    return
  fi
  github "releases/$release_id/assets?per_page=100"
  [[ $status == 200 ]] || die "Release assets lookup returned HTTP $status"
  assets=$(jq -ce --args '
    $ARGS.positional as $expected |
    select(type == "array" and length < 100) |
    select(all(.[]; (.name | IN($expected[])) and (.id | type == "number") and
      (.state | type == "string"))) |
    select((map(.name) | unique | length) == length)
  ' "${names[@]}" <<< "$body") || die 'Unexpected, duplicate or malformed release assets'
}

asset_record() {
  jq -c --arg name "$1" '.[] | select(.name == $name)' <<< "$assets"
}

asset_matches() {
  jq -e --arg digest "sha256:$2" '.state == "uploaded" and .digest == $digest' <<< "$1" >/dev/null
}

asset_starter() {
  jq -e '.state == "starter" and .size == 0' <<< "$1" >/dev/null
}

assert_reviewed
version_from_manifest

case "$1" in
  build)
    target=$2
    evidence=$3
    dir=$4
    verify_crate_evidence "$evidence" "$EVIDENCE_RUN"
    image=$(target_image "$target")
    mkdir -p "$dir" "$RUNNER_TEMP/binary-package/bin"
    cp "$evidence/Cargo.lock" Cargo.lock
    cargo metadata --locked --format-version 1 --filter-platform "$target" > "$dir/target-resolution.json"
    validate_metadata "$dir/target-resolution.json" target
    if [[ -n $image ]]; then
      sudo systemctl start docker
      cargo install cross --git https://github.com/cross-rs/cross --rev "$cross_rev" --locked
      image_env="CROSS_TARGET_${target^^}_IMAGE"
      env "${image_env//-/_}=$image" cross build --locked --release --target "$target" --bin cargo-vip
    else
      cargo build --locked --release --target "$target" --bin cargo-vip
    fi
    cmp Cargo.lock "$evidence/Cargo.lock"
    cp Cargo.lock "$dir/"
    archive="cargo-vip-$target.tar.gz"
    install -m 755 "target/$target/release/cargo-vip" "$RUNNER_TEMP/binary-package/bin/cargo-vip"
    tar -C "$RUNNER_TEMP/binary-package" -czf "$dir/$archive" bin/cargo-vip
    printf '%s  %s\n' "$(digest "$dir/$archive")" "$archive" > "$dir/$archive.sha256"
    binary_evidence "$dir" "$target" "$GITHUB_RUN_ID" > "$dir/evidence.json"
    ;;
  release)
    crate_dir=$2
    binaries=$3
    verify_crate_evidence "$crate_dir" "$EVIDENCE_RUN"
    [[ $FORCE == true || $FORCE == false ]] || die 'Invalid force input'
    names=()
    files=()
    for target in "${targets[@]}"; do
      dir="$binaries/binary-$REVIEWED_SHA-$target"
      archive="cargo-vip-$target.tar.gz"
      scan_lock "$dir/Cargo.lock"
      cmp "$crate_dir/Cargo.lock" "$dir/Cargo.lock"
      validate_metadata "$dir/target-resolution.json" target
      binary_evidence "$dir" "$target" "$BUILD_RUN" |
        jq -e --slurpfile retained "$dir/evidence.json" '$retained == [.]' >/dev/null
      [[ $(tar -tzf "$dir/$archive") == bin/cargo-vip ]]
      printf '%s  %s\n' "$(digest "$dir/$archive")" "$archive" |
        cmp - "$dir/$archive.sha256"
      names+=("$archive" "$archive.sha256")
      files+=("$dir/$archive" "$dir/$archive.sha256")
    done

    tag_state
    initial_tag=$tag
    release_state
    if [[ $initial_tag == missing && ( -n $release_id || $FORCE == true ) ]]; then
      die 'Existing release or force requires an already matching tag'
    fi
    registry_state
    asset_inventory
    missing=()
    replacements=()
    for index in "${!names[@]}"; do
      name=${names[$index]}
      record=$(asset_record "$name")
      if [[ -z $record ]] || asset_starter "$record"; then
        missing+=("$name")
      elif ! asset_matches "$record" "$(digest "${files[$index]}")"; then
        replacements+=("$name")
      fi
    done
    if (( ${#replacements[@]} > 0 )) && [[ $FORCE != true ]]; then
      die "Conflicting release assets: ${replacements[*]}. Use retained build evidence and force after review."
    fi
    if [[ -n $release_id && ${#missing[@]} == 0 && ${#replacements[@]} == 0 ]]; then
      assert_tag
      echo "$TAG already has the complete verified asset set"
      exit 0
    fi
    if (( ${#missing[@]} > 0 )); then echo "Missing release assets: ${missing[*]}"; fi

    if [[ -z $release_id ]]; then
      ensure_tag
      release_state
      if [[ -z $release_id ]]; then
        payload=$(jq -cn --arg tag "$TAG" --arg sha "$REVIEWED_SHA" \
          '{tag_name:$tag,name:$tag,target_commitish:$sha,draft:false}')
        assert_tag
        github releases -H 'Content-Type: application/json' -d "$payload"
        [[ $status == 201 ]] || die "Release create returned HTTP $status; recheck and retry with the same evidence"
        release_state
      fi
      [[ -n $release_id ]] || die 'Release is not visible yet'
    fi
    expected_release=$release_id
    for index in "${!names[@]}"; do
      name=${names[$index]}
      file=${files[$index]}
      sha=$(digest "$file")
      assert_tag
      release_state
      [[ $release_id == "$expected_release" ]] || die 'Release identity changed'
      asset_inventory
      record=$(asset_record "$name")
      if [[ -n $record ]]; then
        if asset_matches "$record" "$sha"; then continue; fi
        if ! asset_starter "$record"; then
          [[ $FORCE == true && $initial_tag == matching ]] || die "Conflicting release asset: $name"
        fi
        asset_id=$(jq -er '.id' <<< "$record")
        github "releases/assets/$asset_id" -X DELETE
        [[ $status == 204 ]] || die "Asset deletion returned HTTP $status for $name"
      fi
      request -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' -H 'Content-Type: application/octet-stream' \
        --data-binary "@$file" "https://uploads.github.com/repos/$GITHUB_REPOSITORY/releases/$release_id/assets?name=$name"
      [[ $status == 201 ]] || die "Asset upload returned HTTP $status for $name; retry with the same build evidence"
      jq -e --arg name "$name" '.name == $name' <<< "$body" >/dev/null
      asset_matches "$body" "$sha" || die "Uploaded asset checksum missing or incorrect: $name"
    done
    assert_tag
    release_state
    [[ $release_id == "$expected_release" ]] || die 'Release identity changed'
    asset_inventory
    for index in "${!names[@]}"; do
      record=$(asset_record "${names[$index]}")
      asset_matches "$record" "$(digest "${files[$index]}")" || die "Incomplete release asset: ${names[$index]}"
    done
    ;;
  *) die 'Unknown binary operation' ;;
esac
