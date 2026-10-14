<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-store-valkey

The Valkey store as a droppable busbar plugin: a cdylib exporting the store C ABI. Drop it in the plugins folder and set store.module: valkey. One Valkey behind a fleet of busbar nodes means shared virtual keys, budgets, usage, and audit across the cluster.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `store` | `valkey` | `busbar-store-valkey-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-store-valkey/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-store-valkey/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

**This plugin's version: v1.0.5.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![CI](https://github.com/GetBusbar/busbar-store-valkey/actions/workflows/ci.yml/badge.svg)](https://github.com/GetBusbar/busbar-store-valkey/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/GetBusbar/busbar-store-valkey/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-store-valkey)
[![Release](https://img.shields.io/github/v/release/GetBusbar/busbar-store-valkey)](https://github.com/GetBusbar/busbar-store-valkey/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The first-party, signed `kind: store` plugin for
[busbar](https://getbusbar.com): the Valkey backend for busbar's durable
governance store, packaged as a droppable `cdylib`. Build it, drop the
resulting `.so`/`.dylib`/`.dll` into the engine's plugins folder, and set
`store: { module: valkey, settings: { url: "redis://..." } }`; the engine
loads it in-process at boot. One
Valkey behind a fleet of busbar nodes means shared virtual keys, budgets,
usage, and audit across the cluster — the multi-node story a single-file
SQLite store cannot offer.

### Renamed: `redis` → `valkey` (BREAKING)

This plugin, its repository, its crates, and its published artifact are now
named for **Valkey** — the Linux-Foundation-governed, BSD-licensed store this
plugin has always actually targeted. Two of those renames are user-visible
breaking changes, and neither is silently compatible:

- **The config alias changed**: `store: { module: redis }` is now
  `store: { module: valkey }`. Busbar core ships a config migrator entry that
  retires the old spelling — but pinned/vendored configs should be updated.
- **The published artifact / signed manifest name changed**:
  `busbar-store-redis-plugin` is now `busbar-store-valkey-plugin`, and the
  release asset is `busbar-store-valkey-<ver>-<target>.tar.gz`. That manifest
  name is the plugin's **trust identity** and the key its anti-downgrade
  version floor is recorded under, so the renamed plugin is a *new* identity to
  the loader: it must be installed fresh, and the old floor does not carry
  over. Uninstall `busbar-store-redis-plugin` before installing this.
- **v1.0.4 and every earlier release are UNLOADABLE by busbar 1.5.3+.** They
  were published under the retired identity, so both config spellings dead-end:
  `store.module: valkey` finds no plugin, and `store.module: redis` is refused
  at config load as a 1.x marker. The first release carrying the loadable
  identity is **v1.0.5**.

Internally, the lib/plugin crates are `busbar-store-valkey` /
`busbar-store-valkey-plugin`, the store type is `ValkeyStore`, and the test
env var is `VALKEY_URL`. The only pre-fork spellings left in this tree are
things upstream owns and we cannot rename: the RESP driver crate on crates.io
(still published under its pre-fork name) and the `redis://` / `rediss://` URL
schemes that driver parses. Nothing busbar-owned says "redis" any more.

### Versioning

This plugin is versioned **independently of busbar** — `v1.0.5` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: the released v1.0.x line **requires busbar 1.5.0+** (the
release that ships the signed hybrid plugin ABI it loads over); the `dev` line
speaks the busbar **1.6.0** record contract and builds against the busbar rev
in [`.busbar-ref`](.busbar-ref). A v1.0.x namespace (schema v6) is upgraded in
place on first connect. Pin both versions
explicitly in production; do not assume they move together.

It is a `cdylib` that implements busbar's store v3 table (`RecordStore` plus the
`StoreSlots` additions of the store SDK in
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract),
`busbar_contract::abi::sdk::store`) and is loaded in-process by busbar over the memory ABI —
`dlopen`'d, not spawned as a separate process. The logic crate states the store's one door
(`store_door!`, `busbar_store_valkey::door`); the cdylib exports it (`export_door!`), and a busbar
build can LINK the same door (`LinkedRow::of(door)`). Both doors run the same code, and
[`tests/conformance.rs`](store-valkey-plugin/tests/conformance.rs) proves they behave as one store.

The store v3 additions are durable in Valkey: every `op_id` write is deduped by a record
(`busbar:op:*`, kept 24 h) written in the same atomic step as its effect (`WATCH`/`MULTI`/`EXEC`,
or one server-side script for the plane append), and the money slots (`busbar:cap:*`,
`busbar:slice:*`), the journal (`busbar:journal:*`), sessions (`busbar:session*`) and the
kernel's records (`busbar:records:*`) are additive keyspaces beside the v7 ones.


- **Multi-node deployments**: a fleet of busbar nodes sharing one Valkey
  instance share virtual keys, per-key/per-group budgets, token usage
  ledgers, and metering/audit rows — the store is the durability layer
  behind the engine's in-memory enforcement counters (boot-hydrate +
  periodic write-behind flush), not a request-hot-path dependency.
- **Fleet-honest accrual**: `add_usage` is a real atomic server-side accumulate
  (`HINCRBY`, each counter floored at 0), so N nodes each flushing their own
  delta-since-last sum to the true fleet total (an absolute `put_usage`
  overwrite would be last-writer-wins across nodes).

This crate (`busbar-store-valkey-plugin`) is intentionally a thin
adapter: all the Valkey schema/serialization logic — and the `open`
that turns the engine's JSON config into a `ValkeyStore` — lives in the
`busbar-store-valkey` library crate it re-exports, in the `store-valkey/`
directory of this repository.

The store holds **no socket and no TLS stack of its own**: it declares one
outbound `tcp` need and speaks RESP2 over the connection busbar's connector
dials, secures and wakes for it. Like 1.5.5's one mutex-guarded connection, the
store keeps ONE connection across ops (dialled, secured, `AUTH`, `SELECT` once);
ops take it in turn, and a read that has nothing yet pends on the op's ticket
instead of blocking a thread. 1.5.5's reconnect-and-retry is kept: a dropped
connection is re-dialled and a read (or idempotent write) retried once on the
fresh one; the non-idempotent writes are never replayed. `open` only parses the
settings; its connect step makes the first connection, migrates the schema and
checks `maxmemory-policy noeviction`, so an unreachable or misconfigured server
still refuses the store at boot, in the store's own words.

## Config

The engine passes `store.settings` through as this plugin's `open`
config, mirroring how the Postgres store plugin receives its libpq URL:

```json
{ "url": "redis://:password@host:6379/0", "connect_timeout_ms": 10000 }
```

| Setting | Required | Notes |
|---|---|---|
| `url` | yes | A `redis://` or `rediss://` (TLS) connection string (`valkey://` / `valkeys://` read the same): `[user[:password]@]host[:port][/db]`, or a unix-socket URL (`unix://`, `redis+unix://`, `valkey+unix://` `/path?db=N&user=U&pass=P`). TLS is busbar's connector's (its trust anchors); `rediss://…#insecure` skips certificate verification, as 1.5.5 did (busbar logs a WARN naming the store instance). |
| `connect_timeout_ms` | no | Bounds every new connection's dial and handshake (TLS, `AUTH`, `SELECT`) in all, as 1.5.5's driver did (default 10000, 1.5.5's). |

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs); `rust-toolchain.toml` pins the version CI uses).
Nothing else: busbar is a pinned git dependency (see [Dependencies](#dependencies)).

```sh
cargo build --release      # cdylib: target/release/libbusbar_store_valkey_plugin.{so,dylib}
cargo test                 # the store's suite, the linked + dropped-in conformance, the end-to-end tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The end-to-end tests boot a REAL `busbar`; they build it from a busbar checkout named by
`BUSBAR_CHECKOUT` (default: a sibling `../busbar`), which must be at the `.busbar-ref` rev.

### Dependencies

`busbar-store-valkey`, the store logic (and the store's one door registration and its `linked` row,
so a busbar build can link it), lives in this repository; `busbar-store-valkey-plugin` re-exports it
as the droppable cdylib. The one busbar crate either names is `busbar-contract` (the plugin contract
and SDK); the tests also use `busbar-plugin-loader`. Both are git dependencies on
[GetBusbar/busbar](https://github.com/GetBusbar/busbar) pinned to the rev in field 1 of
[`.busbar-ref`](.busbar-ref); CI's `pin` job refuses a manifest that names any other rev, a retired
busbar crate, or a sibling path.

### Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_store_valkey_plugin.so \
    --name busbar-store-valkey-plugin --alias valkey --kind store \
    --version 1.0.5 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-store-valkey-1.0.5-x86_64-unknown-linux-gnu.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir` and
set:

```yaml
store:
  module: valkey
  settings: { url: "redis://:password@host:6379/0" }
```

— see [`docs/configuration.md`](https://github.com/GetBusbar/busbar/blob/main/docs/configuration.md)
for the full store config reference.

## Tests

`cargo test` runs the pure unit tests (config parsing) and the real-ABI
end-to-end test in [`tests/e2e.rs`](tests/e2e.rs), which `dlopen`s the
*built* cdylib over the real `busbar-plugin-loader` ABI seam — the same
seam busbar's engine uses — against a **real, live Valkey** (not a mock
or an in-process fake).

Unlike a file-backed store, Valkey has no "reopen the same file"
persistence check available — so this crate's coverage proves
persistence the way that's actually meaningful for a shared backend:
write a key/usage through the `dlopen`'d plugin over the C ABI, drop the
plugin (closing its connection), then read the SAME Valkey instance back
through a **totally independent connection** — the plain
`busbar-store-valkey` library crate, used directly, never touching the
cdylib, the C ABI, or the loader at all. That is the proof that
`store: valkey` operations over the ABI actually land in Valkey, not just
in an in-process cache.

The live-Valkey coverage is gated on the `VALKEY_URL` environment
variable: it skips cleanly when unset locally (no server needed for a
default `cargo test`), but under CI (`CI` set) a missing `VALKEY_URL` is
a **hard failure**, never a silent skip — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml), which runs a
real `valkey/valkey:8` GitHub Actions service container on every push and PR.
On macOS, where GitHub runs no service containers, CI starts a brew-installed `valkey-server`
instead.

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
