# cargo.vip

Use a **private** S3-compatible bucket as a Cargo registry. No server to run, no
public bucket, no proxy in front of your artifacts.

```sh
cargo install cargo-vip
cargo vip build
```

## The problem

Cargo authenticates to a registry with `Authorization: <token>`. Every
S3-compatible store wants an AWS SigV4 signature and accepts nothing else, and
cargo has no signing code. So pointing cargo at a private bucket gives you a
`403`, and the usual answers are to make the bucket public or to stand up a
registry server in front of it.

## What this does instead

`cargo vip` serves the sparse index on loopback, signs each index read with
**your own** access key, and answers tarball fetches with a `307` to a presigned
URL — so the crate bytes travel straight from the bucket and never pass through
this process.

```
cargo ──▶ 127.0.0.1  ──signed GET──▶  bucket        (index, kilobytes)
             │
             └──307 presigned──▶ cargo ──▶ bucket   (tarball, direct)
```

Access is exactly what your key is scoped to. Grant someone a read-only key for
one bucket or prefix and that is what they get; revoke the key and they are out.
There is no shared token and nothing to leak in a URL.

## Setup

By default the tool holds **no object-store credential at all**:

```sh
cargo vip login
```

stores a token for the registry management API in
`~/.config/cargo-vip/credentials.toml` (mode `0600`), keyed by the bucket that
issued it. Each run exchanges the selected token for a scoped access key, kept
**in memory only** and never written to disk. Revoking the token at the
registry ends access at the next build.

Then depend on a private crate as usual:

```toml
[dependencies]
my-crate = { version = "1.0", registry = "vip" }
```

and build through the wrapper:

```sh
cargo vip build
cargo vip test
cargo vip update
```

With one saved token, the wrapper can select it without a registry index in
Cargo config. When you have tokens for multiple products, add an index entry to
each repository so `cargo vip` knows which bucket that project uses.

## Several products on one machine

Each crates.vip app issues tokens for its own bucket. Run `cargo vip login`
once for each product and paste that product's token. Login adds or replaces
only the entry for the bucket returned by the registry; tokens for other
products stay in `~/.config/cargo-vip/credentials.toml`.

In each repository, configure the registry name used by its dependencies. For
the default name, `vip`:

```toml
# .cargo/config.toml
[registries.vip]
index = "sparse+https://crates.vip/<bucket>/"
```

Cargo config is found by walking up from the current directory, so this also
works when you run `cargo vip` from a nested folder. Set
`CARGO_REGISTRIES_VIP_INDEX` to override that index for a run. If a project
uses another registry name, pass it to the wrapper and configure that name:

```toml
[registries.backend]
index = "sparse+https://crates.vip/<backend-bucket>/"
```

```sh
cargo vip --registry backend build
```

The saved credentials file has one `[[registry]]` entry per bucket. A previous
single-token file still works and is migrated the next time a login can resolve
its bucket. If the selected bucket has no saved token, `cargo vip` reports the
bucket and asks you to run `cargo vip login` with a token for it.

### Using a key directly

CI, and any bucket with no broker in front of it, pass the key explicitly. This
skips the broker entirely and never touches the network for credentials:

```sh
cargo vip --key-id "$KEY" --key-secret "$SECRET" --bucket my-crates build
```

or as `CARGO_VIP_KEY_ID`, `CARGO_VIP_KEY_SECRET`, `CARGO_VIP_BUCKET`, or in
`~/.config/cargo-vip/credentials.toml`:

```toml
key_id = "tid_…"
key_secret = "tsec_…"
bucket = "my-crates"
# endpoint = "https://fly.storage.tigris.dev"   # default; any S3 store works
# region = "auto"
```

An explicit key always wins over the broker.

### Keeping it running instead

```sh
cargo vip --serve
```

prints a stanza for `.cargo/config.toml` and stays in the foreground, for when
you would rather use plain `cargo`. The port changes per run, so the wrapper is
usually easier.

## Bucket layout

Whatever wrote your crates must use the standard sparse layout:

| Key | Contents |
|---|---|
| `1/a`, `2/ab`, `3/a/abc`, `ab/cd/name` | index entries, newline-delimited JSON |
| `crates/{name}-{version}_{sha256}.tar.gz` | the `.crate` tarballs |

`config.json` is **not** read from the bucket. It is generated per run, because
`dl` has to name this process, and writing a loopback address into the bucket
would impose one machine's port on everybody.

## Publishing

```
cargo vip publish [--manifest-path PATH] [--dry-run]
```

with a `Publish` token (from `cargo vip login` or `CARGO_VIP_TOKEN`). The
registry hands that token a read-write key on its app's bucket, and the crate
goes in as two writes: the tarball under `If-None-Match: *`, so a published
version is immutable, then the index entry read-modify-written under
`If-Match`, retried if another publisher got there first. Publishing the same
commit again is a no-op; changing a published version is refused.

**A crate is published only if it says `publish = ["vip"]`.** The default
`publish` lets a stray `cargo publish` send private source to crates.io, so
`cargo vip publish` refuses it until the manifest closes that door.

A dependency on another crate in this registry is written as
`{ version = "…", registry = "vip" }`. Its index entry omits `registry`, which
means "this registry"; a crates.io dependency names crates.io explicitly.

## CI

One secret, the registry token, and no object-store key:

```yaml
- run: cargo install cargo-vip --locked
- run: cargo vip build --release
  env:
    CARGO_VIP_TOKEN: ${{ secrets.CRATES_VIP_TOKEN }}
```

A `ReadOnly` token builds; a `Publish` token also runs `cargo vip publish`.

## Lockfiles

A crate names the registry by a stable URL, `sparse+https://crates.vip/<bucket>/`,
which cargo replaces with this run's loopback source. Lockfiles and packaged
crates record the stable URL, so neither changes with the port.

## Security notes

- The listener binds `127.0.0.1` on an ephemeral port. Your key stays in the
  process; nothing off the machine can borrow it.
- Presigned download URLs last 5 minutes.
- TLS is rustls with compiled-in webpki roots. No OpenSSL, no system trust
  store, no C toolchain.

## Licence

MIT OR Apache-2.0.
