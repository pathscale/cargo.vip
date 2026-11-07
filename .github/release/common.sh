#!/usr/bin/env bash

die() { echo "$*" >&2; exit 1; }

assert_reviewed() {
  [[ $GITHUB_EVENT_NAME == workflow_dispatch && $GITHUB_REF == refs/heads/master &&
     $REVIEWED_SHA =~ ^[0-9a-f]{40}$ && $REVIEWED_SHA == "$GITHUB_SHA" &&
     $(git rev-parse HEAD) == "$REVIEWED_SHA" ]] || die 'Reviewed checkout identity mismatch'
}

digest() { shasum -a 256 "$1" | cut -d ' ' -f 1; }

version_from_manifest() {
  VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml)
  [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Expected one stable cargo-vip version'
  TAG="v$VERSION"
}

# The lock is parsed by cargo metadata --locked in the originating job.
# Scan the entire lock as well as the resolved metadata to cover inactive packages.
scan_lock() {
  test -r "$1" && test -s "$1" || die "Missing lockfile: $1"
  local status=0
  grep -Eq '^name = "(openssl|openssl-sys|native-tls|openssl-probe|rustls-native-certs|aws-lc-sys)"$' "$1" || status=$?
  [[ $status == 1 ]] || die "Forbidden TLS dependency or failed lock scan: $1"
}

validate_metadata() {
  jq -e --arg version "$VERSION" --arg scope "${2:-full}" '
    .version == 1 and (.workspace_members | length == 1) and
    (.resolve.root as $root | .workspace_members == [$root] and
      any(.packages[]; .id == $root and .name == "cargo-vip" and .version == $version)) and
    (.packages | type == "array" and length > 1 and all(.[]; (.id | type == "string") and
      (.name | type == "string" and
        (test("^(openssl|openssl-sys|native-tls|openssl-probe|rustls-native-certs|aws-lc-sys)$") | not)))) and
    (([.packages[].id] | sort) as $packages |
      ([.resolve.nodes[].id] | sort) as $nodes |
      ($packages == ($packages | unique)) and ($nodes == ($nodes | unique)) and
      (.resolve.root | IN($nodes[])) and
      (if $scope == "target" then ($nodes - $packages) == [] else $nodes == $packages end))
  ' "$1" >/dev/null || die "Invalid or forbidden dependency resolution: $1"
}

# No redirects and no automatic retries for write requests. Keep error bodies out of logs.
request() {
  local response
  response=$(curl -q -sS --connect-timeout 10 --max-time 180 \
    --proto '=https' -w '\n%{http_code}' "$@") || die 'API transport failed'
  status=${response##*$'\n'}
  body=${response%$'\n'*}
  [[ $status =~ ^[1-5][0-9][0-9]$ ]] || die 'Invalid HTTP status'
}

github() {
  local endpoint=$1
  shift
  request -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' "${GITHUB_API_URL}/repos/$GITHUB_REPOSITORY/$endpoint" "$@"
}

verify_workflow_run() {
  local run=$1 workflow=$2
  [[ $run =~ ^[1-9][0-9]*$ ]] || die 'Expected a numeric evidence run ID'
  github "actions/runs/$run"
  [[ $status == 200 ]] || die "Evidence run lookup returned HTTP $status"
  jq -e --arg repo "$GITHUB_REPOSITORY" --arg sha "$REVIEWED_SHA" --arg workflow ".github/workflows/$workflow.yml" '
    .event == "workflow_dispatch" and .head_branch == "master" and .head_sha == $sha and
    .head_repository.full_name == $repo and
    (.path == $workflow or .path == ($workflow + "@refs/heads/master"))
  ' <<< "$body" >/dev/null || die 'Evidence run does not belong to the reviewed workflow'
  echo "run_id=$run" >> "$GITHUB_OUTPUT"
}

verify_crate_evidence() {
  local dir=$1
  local run=$2
  CRATE="$dir/cargo-vip-$VERSION.crate"
  CRATE_SHA=$(digest "$CRATE")
  [[ $CRATE_SHA =~ ^[0-9a-f]{64}$ ]] || die 'Missing crate digest'
  scan_lock "$dir/Cargo.lock"
  scan_lock "$dir/packaged.lock"
  validate_metadata "$dir/workspace.json"
  validate_metadata "$dir/packaged.json"
  jq -e --arg sha "$REVIEWED_SHA" --arg version "$VERSION" --arg run "$run" \
    --arg rust "$RUST_VERSION" --arg crate "$CRATE_SHA" \
    --arg lock "$(digest "$dir/Cargo.lock")" --arg packaged_lock "$(digest "$dir/packaged.lock")" \
    --arg workspace "$(digest "$dir/workspace.json")" --arg packaged "$(digest "$dir/packaged.json")" \
    --arg upload "$(digest "$dir/publish.json")" '
    . == {commit:$sha, version:$version, run_id:$run, rust:$rust, crate_sha256:$crate,
      workspace_lock_sha256:$lock, packaged_lock_sha256:$packaged_lock,
      workspace_resolution_sha256:$workspace, packaged_resolution_sha256:$packaged, upload_metadata_sha256:$upload,
      gates:["fmt","clippy","test","package"]}
  ' "$dir/evidence.json" >/dev/null || die 'Crate evidence identity or digest mismatch'
  tar -xOzf "$CRATE" "cargo-vip-$VERSION/Cargo.lock" | cmp - "$dir/packaged.lock" ||
    die 'Packaged lock does not match the verified crate'
  EVIDENCE_SHA=$(digest "$dir/evidence.json")
  [[ $EVIDENCE_SHA =~ ^[0-9a-f]{64}$ ]] || die 'Missing evidence digest'
  TAG_MESSAGE="cargo-vip evidence run $run sha256:$EVIDENCE_SHA"
}

registry_state() {
  request -A 'cargo-vip release workflow (https://github.com/pathscale/cargo.vip)' \
    "https://crates.io/api/v1/crates/cargo-vip/$VERSION"
  case "$status" in
    404) registry=missing ;;
    200)
      jq -e --arg version "$VERSION" --arg sha "$CRATE_SHA" '
        .version | .crate == "cargo-vip" and .num == $version and .checksum == $sha
      ' <<< "$body" >/dev/null || die 'Published version has invalid metadata or a different checksum'
      registry=matching
      ;;
    *) die "crates.io lookup returned HTTP $status" ;;
  esac
}

tag_state() {
  local ref="refs/tags/$TAG" object sha kind depth
  github "git/ref/tags/$TAG"
  case "$status" in
    404) tag=missing; return ;;
    200) ;;
    *) die "Exact tag lookup returned HTTP $status" ;;
  esac
  object=$(jq -ce --arg ref "$ref" 'select(.ref == $ref) | .object' <<< "$body")
  [[ $(jq -er '.type' <<< "$object") == tag ]] ||
    die "Tag $TAG has no immutable release evidence binding"
  for ((depth=0; depth<16; depth++)); do
    sha=$(jq -er '.sha | select(test("^[0-9a-f]{40}$"))' <<< "$object")
    kind=$(jq -er '.type' <<< "$object")
    case "$kind" in
      commit)
        [[ $sha == "$REVIEWED_SHA" ]] || die "Conflicting tag $TAG at $sha"
        tag=matching
        return
        ;;
      tag)
        github "git/tags/$sha"
        [[ $status == 200 ]] || die "Annotated tag lookup returned HTTP $status"
        if (( depth == 0 )); then
          jq -e --arg name "$TAG" --arg message "$TAG_MESSAGE" '
            .tag == $name and (.message == $message or .message == ($message + "\n"))
          ' <<< "$body" >/dev/null || die "Tag $TAG binds different evidence; recover with its original run"
        fi
        object=$(jq -ce --arg sha "$sha" 'select(.sha == $sha) | .object' <<< "$body")
        ;;
      *) die "Unexpected object type for $ref: $kind" ;;
    esac
  done
  die "Too many annotated tags for $ref"
}

require_tag_protection() {
  local rule
  [[ -n ${GH_TOKEN:-} ]] || die 'Set RELEASE_RULESET_TOKEN in the release environment'
  github 'rulesets?includes_parents=false&per_page=100' -X GET
  [[ $status == 200 ]] || die "Ruleset list returned HTTP $status"
  rule=$(jq -er '
    select(type == "array" and length < 100) |
    map(select(.name == "cargo-vip-release-tags")) |
    select(length == 1) | .[0].id | select(type == "number")
  ' <<< "$body") || die 'Configure the cargo-vip-release-tags ruleset before publishing'
  github "rulesets/$rule" -X GET
  [[ $status == 200 ]] || die "Ruleset lookup returned HTTP $status"
  jq -e '
    .target == "tag" and .enforcement == "active" and .bypass_actors == [] and
    .conditions.ref_name == {include:["refs/tags/v*"], exclude:[]} and
    ([.rules[].type] | sort) == ["deletion","update"]
  ' <<< "$body" >/dev/null || die 'The version-tag ruleset must forbid updates and deletions with no bypass'
}

ensure_tag() {
  tag_state
  if [[ $tag == missing ]]; then
    local payload object_sha
    # The protected ref reserves the commit and the evidence together.
    payload=$(jq -cn --arg tag "$TAG" --arg message "$TAG_MESSAGE" --arg sha "$REVIEWED_SHA" '
      {tag:$tag,message:$message,object:$sha,type:"commit",
        tagger:{name:"github-actions[bot]",email:"41898282+github-actions[bot]@users.noreply.github.com"}}
    ')
    github git/tags -H 'Content-Type: application/json' -d "$payload"
    [[ $status == 201 ]] || die "Annotated tag object creation returned HTTP $status"
    object_sha=$(jq -er '.sha | select(test("^[0-9a-f]{40}$"))' <<< "$body")
    payload=$(jq -cn --arg ref "refs/tags/$TAG" --arg sha "$object_sha" '{ref:$ref,sha:$sha}')
    github git/refs -H 'Content-Type: application/json' -d "$payload"
    [[ $status == 201 || $status == 409 || $status == 422 ]] ||
      die "Non-force tag create returned HTTP $status"
  fi
  assert_tag
}

assert_tag() {
  tag_state
  [[ $tag == matching ]] || die 'Exact evidence-bound tag is missing'
}
