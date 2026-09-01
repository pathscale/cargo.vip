# Working agreement — cargo.vip

Client tool. It makes a **private** S3-compatible bucket usable as a Cargo registry by
serving the sparse index on loopback, signing reads with the caller's own key, and
redirecting tarball fetches to presigned URLs.

This repo is **public** and published to crates.io. Nothing here may reference a private
repository, an internal hostname, a bucket name that is not a documented default, or any
credential.

## Invariants

- **No OpenSSL and no system trust store.** `rustls` + `ring` for TLS, `webpki-roots`
  for anchors, `rusty-s3` (`rustcrypto`: `hmac`/`sha2`) for SigV4. CI fails the build if
  `openssl`, `openssl-sys`, `native-tls`, `openssl-probe` or `rustls-native-certs`
  appears in `Cargo.lock`. An AWS SDK drags in `aws-lc-sys` and native certs and must
  not be used.
- **The listener binds `127.0.0.1` only.** The caller's key is in this process. Binding
  anything else hands it to the network.
- **Tarballs are redirected, never proxied.** The download route answers `307` with a
  presigned URL so crate bytes go straight from the bucket. Streaming them through would
  put a whole `.crate` per concurrent download into this process.
- **`config.json` is generated, never read from the bucket.** `dl` must name this
  process, and a loopback address written into the bucket would impose one machine's
  port on every consumer.
- **No publish path.** This is the read side. Publishing is two S3 writes a CI job does
  with the AWS CLI.

## Build & run

```bash
cargo build
cargo test
cargo fmt && cargo clippy --all-targets    # run after every change
```

## Landmines

- **An index entry with no `registry` field means "this same registry".** A crates.io
  dependency must carry
  `"registry": "https://github.com/rust-lang/crates.io-index"` explicitly. This tool only
  reads, but the failure surfaces here — as `no matching package named X found, location
  searched: <this> index` — so the bug is in whatever published the crate.
- **`cargo vip build` arrives as `cargo-vip vip build`.** Cargo inserts the subcommand
  name; `main` drops argv[1] when it is `vip`. Removing that breaks argument parsing in a
  way that looks like a clap bug.
- **Cargo accepts a plain-HTTP index only on loopback.** That is what makes this work
  without a certificate.

## Repo conventions

- Branch is `master`. Never `main`.
- One change per commit. No batch "round" commits.
- No AI attribution in commits, PRs, or issues.
- No copyright, licence, or SPDX banners in source files. Licensing lives in the
  manifest and the LICENSE files.
- CI runs on Ubicloud runners (`ubicloud-standard-N`). Never `ubuntu-latest`.
