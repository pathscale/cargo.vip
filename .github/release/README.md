# cargo-vip release operations

Dispatch on master with the full SHA of the commit that GitHub will dispatch. Both workflows share one repository concurrency group for version tags. GitHub may replace a pending run when another dispatch queues in the same group. Keep the run IDs for recovery.

Before publication, configure a repository tag ruleset named `cargo-vip-release-tags`. Set it to Active, target `refs/tags/v*` with no exclusions, enable Restrict updates and Restrict deletions, and leave the bypass list empty. Keep the ruleset active during publication and confirm that the repository's effective rules permit creating a missing tag without bypass.

Configure a GitHub Actions environment named `release` that permits deployments from master. Set its `RELEASE_RULESET_TOKEN` secret to a fine-grained token issued to a repository administrator, scoped to this repository with Administration write and Metadata read. GitHub requires ruleset write access to return the bypass list. The inspection step uses this credential only for ruleset GETs and stops if the list is missing or nonempty. Tag and release writes use the workflow's Contents-write token. Supply `CARGO_REGISTRY_TOKEN` for new crates.io uploads.

Both workflows reserve the same protected annotated version tag. Its message records the publisher evidence run ID and SHA-256 of the verified `evidence.json`, which covers the crate, locks, metadata and gate results. A retry must match both the tag's commit and its evidence, even while crates.io returns 404. Recover using the run ID in the tag and keep its original artifact. A tag with missing or different evidence stops publication and requires operator review.

## crates.io

Run **publish** in `verify` mode for evidence only. For a first upload, select `publish` and supply that run's `evidence_run_id`, or leave it blank to run the gate in the same dispatch. The evidence is retained for 30 days, subject to repository settings. When the version is absent, the workflow checks credential presence and frames the upload payload before reserving the tag. The upload step rechecks the version and exact tag before sending the retained bytes.

After an ambiguous upload, allow time for the crates.io version API to become consistent, then rerun the failed publish job. A fresh dispatch at the same master tip can instead reuse the original evidence run ID. Reusing the original workflow run also works after master advances, within GitHub's rerun window. An existing registry version must have the retained checksum before the workflow recognizes success or recovers a missing tag. Preserve the original evidence if the run needs investigation. A new dependency resolution cannot establish provenance for an existing version.

## Binary release

Binary publication currently requires mutable GitHub releases. Confirm the effective repository policy before dispatch: the workflow creates the published release before uploading assets, so an immutable-release policy would leave an empty release that cannot accept them. Do not dispatch this workflow with that policy enabled.

Dispatch **release** with the publisher evidence run ID and the same SHA. Each target keeps its archive, checksum, full lock and target-filtered Cargo resolution for 30 days. The publisher evidence retains the unfiltered workspace and packaged resolutions. Rerun failed jobs to reuse successful matrix jobs and their artifacts. A fresh dispatch at the same master tip can use the original `build_run_id` and publisher `evidence_run_id` to reuse all four archives.

A partial release resumes by adding missing assets. After a 502, retry with the same build evidence. The workflow removes an empty GitHub `starter` record and re-uploads its asset after checking the bound tag and release ID. Complete matching assets are kept. To replace conflicting assets, first verify the release and exact tag, then dispatch with the retained run IDs and `force` enabled. If GitHub immutable releases are enabled, conflicting assets on a published immutable release require administrator review. Unexpected asset names and a conflicting or missing tag on an existing release require operator review. The workflow checks the final set of four archives and four checksum assets against retained evidence.
