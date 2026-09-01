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

Put your credentials in `~/.config/cargo-vip/credentials.toml`:

```toml
key_id = "tid_…"
key_secret = "tsec_…"
bucket = "my-crates"
# endpoint = "https://fly.storage.tigris.dev"   # default; any S3 store works
# region = "auto"
```

Or pass them as `CARGO_VIP_KEY_ID`, `CARGO_VIP_KEY_SECRET`, `CARGO_VIP_BUCKET`.

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

The wrapper sets `CARGO_REGISTRIES_VIP_INDEX` for the child process only, so
there is no `.cargo/config.toml` entry to add and nothing left behind when it
exits.

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

Out of scope. This is a read path. Publishing is two S3 writes — the tarball
under `If-None-Match: *`, and the index entry read-modify-written under
`If-Match` — which a CI job can do with the AWS CLI and no bespoke tool.

One trap worth repeating: an index entry with no `registry` field means "this
same registry", so **every crates.io dependency must name crates.io
explicitly**. Omit it and the crate publishes fine and resolves nowhere.

## Security notes

- The listener binds `127.0.0.1` on an ephemeral port. Your key stays in the
  process; nothing off the machine can borrow it.
- Presigned download URLs last 5 minutes.
- TLS is rustls with compiled-in webpki roots. No OpenSSL, no system trust
  store, no C toolchain.

## Licence

MIT OR Apache-2.0.
