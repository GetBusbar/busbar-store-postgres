<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-store-postgres

First-party signed kind:store plugin cdylib: the Postgres backend for busbar's durable governance store, exported over the store C ABI. Drop the built library into the plugins folder and set store.module: postgres to share virtual keys, budgets, and usage across a fleet of busbar nodes.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `store` | `postgres` | `busbar-store-postgres-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-store-postgres/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-store-postgres/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

**This plugin's version: v1.0.0.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![CI](https://github.com/GetBusbar/busbar-store-postgres/actions/workflows/ci.yml/badge.svg)](https://github.com/GetBusbar/busbar-store-postgres/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/GetBusbar/busbar-store-postgres/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-store-postgres)
[![Release](https://img.shields.io/github/v/release/GetBusbar/busbar-store-postgres)](https://github.com/GetBusbar/busbar-store-postgres/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The first-party, signed `kind: store` plugin for
[busbar](https://getbusbar.com): the Postgres backend for busbar's
durable governance store, exported over the store C ABI. Drop the built
`.so`/`.dylib`/`.dll` into the engine's plugins folder and set
`store: { module: postgres, settings: { url: "postgres://..." } }`; the
engine loads it in-process at boot.
One Postgres behind a fleet of busbar nodes means virtual keys,
budgets, and usage are shared across the cluster instead of siloed per
node.

### Versioning

This plugin is versioned **independently of busbar** — `v1.0.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.6.0+** (the release whose store
interface this crate implements: the kind-tagged plane-record verbs, the
name-keyed usage ledger and the dated metering rows). Pin both versions
explicitly in production; do not assume they move together.

### Upgrading from a 1.5.x deployment

The first connect of this build upgrades an existing database **in place**
(schema v6 → v10, inside one transaction, under the same advisory lock every
node's migration takes). Nothing is dropped and no existing row changes
meaning:

- `keys` gains `idp_subject`, `binding_mode`, `minted_by` (NULL for existing
  keys) and `allowed_scopes_by_kind`, which holds non-pool scope grants
  (`mcp_server`, `agent`, …). Pool grants stay in `allowed_pools` exactly as
  1.5.x wrote them.
- `usage_metering` gains `priced_from_ms` (existing rows read `0`, the opening
  rate card) and it joins the primary key, so a rate-card change mid-day opens
  a second row for that day.
- New tables: `usage_ledger_units` and `usage_metering_units` (unit classes
  other than the four reserved token classes), and `plane_records`,
  `plane_chain`, `plane_tokens` (busbar's durable A2A tasks, MCP call log,
  upstream demotions, push-callback capabilities and single-use approvals).

A database a pre-release dev build took to schema v7–v9 keeps its
`mcp_calls`/`tasks`/`task_events`/`mcp_demotions`/`spent_ask_states` tables
untouched; busbar 1.6.0 no longer reads them.

It is a `cdylib` that implements busbar's `RecordStore` trait (via the plugin SDK in
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process.

This repo is a same-repo, 2-crate Cargo workspace: it brings 100% of
what it needs. All the SQL and schema logic lives in the
`busbar-store-postgres` crate (`store-postgres/`, a same-repo sibling
this plugin wraps — a custom build can also link it statically instead
of loading this cdylib); `store-postgres-plugin/src/lib.rs` only adapts
the engine's JSON config (`{"url": "postgres://..."}`) into a
`PostgresStore`.


- **A shared, multi-node governance store.** `store: sqlite` is
  per-node; `store: postgres` puts virtual keys, budgets, and usage
  behind one database so a fleet of busbar nodes agrees on state.
- **Interchangeable with the SQLite backend for everything busbar
  itself does**: the same keys, credentials, tombstone and revision
  semantics, and the same JSON encoding of `allowed_pools`. Two caveats
  worth knowing before you write anything against it directly.
- **The physical tables differ.** Postgres keeps per-model token
  counters in their own `usage_ledger` table, where SQLite folds them
  into `usage_windows` with `model` in the primary key. Write reporting
  queries and ETL against the backend you are actually running, never
  against the assumption that the two are byte-identical.
- **A few error cases differ across backends.** Revoking a credential
  id that names no row is an error here and on MySQL, and a silent
  success on SQLite and Valkey. Appending an audit entry whose `seq`
  already exists is an error here, where the other backends overwrite
  or ignore. Tooling that treats a store error as fatal should not
  assume the same input produces the same outcome on every backend.

### Known limitations (documented honestly, not papered over)

- **No TLS in this build (`NoTls`).** Run the connection over a trusted
  network segment, a local socket, or a TLS-terminating proxy
  (pgbouncer/stunnel).
- **No automatic reconnect.** A persistently dropped connection
  surfaces as store errors on the write-behind flush path and on admin
  operations; a permanently broken connection requires a process
  restart (let your supervisor handle it).

See the doc comments at the top of
[`store-postgres/src/lib.rs`](store-postgres/src/lib.rs)
for the full design rationale — that is where the actual store logic
lives (in this repo now, not busbar); `store-postgres-plugin/` is the
thin `cdylib` adapter around it.

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | A libpq connection string, e.g. `postgres://user:pass@host:5432/busbar`. Connects `NoTls`; run it over a trusted network segment or a TLS-terminating proxy. **No connect timeout is set by default** — a blackholed host wedges engine boot indefinitely. libpq honors a `connect_timeout` query param in the DSN, e.g. `postgres://user:pass@host:5432/busbar?connect_timeout=10`; set one if boot hanging on a dead host is a concern. |

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbar](https://github.com/GetBusbar/busbar) ships publicly
— a sibling checkout of `busbar` at `../busbar` (see
[Dependencies](#dependencies) below).

```sh
cargo build --workspace --release   # cdylib: target/release/libbusbar_store_postgres_plugin.{so,dylib}
cargo test --workspace              # the end-to-end loader tests (see store-postgres-plugin/tests/e2e.rs) — need a real Postgres, see below
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Dependencies

This is a same-repo, 2-crate Cargo workspace (`store-postgres/`, the
real logic crate — which also carries the store's one door, `door`,
from `store_door!` over its `StoreSlots` implementation (`src/v3.rs`) —
and `store-postgres-plugin/`, the thin `cdylib` that exports that door as
`busbar_plugin_door` through `export_door!`; see [members](Cargo.toml)).

Its one busbar dependency is `busbar-contract` (plus
`busbar-plugin-loader`, dev-only, for the conformance and end-to-end
tests): a **git dependency** on
[GetBusbar/busbar](https://github.com/GetBusbar/busbar) pinned to the
rev in field 1 of [`.busbar-ref`](.busbar-ref). No sibling-checkout
path dependency ships in any manifest; CI's `pin` job refuses one, and
refuses a manifest rev that disagrees with `.busbar-ref`.

The end-to-end tests drive the REAL `busbar` binary, built from a
busbar checkout at that same rev: `BUSBAR_CHECKOUT=<path>`, or a
`busbar/` checkout beside this repo (CI checks one out there).

`store-postgres-plugin/tests/conformance.rs` holds the store to ONE
Statement and ONE behaviour through both doors — compiled in (the
logic crate's `door`, through the loader's `load_linked`) and dropped in
(this repo's cdylib, through `load_dropped`), each opened through the
store v3 table — with RED arms that prove the comparison is not
vacuous.

### Tests need a real Postgres

Unlike a `kind: hook` plugin, this store's only meaningful coverage is
against a **live Postgres** — there is no useful mock for "did the SQL
actually persist."

`store-postgres-plugin/tests/e2e.rs` installs the plugin the way an
operator does: it packs the built cdylib into a real tarball with the
same tool the release signs, drops it into a real `plugins.dir`, and
boots a real `busbar` process against `store: { module: postgres }`.
That boot runs against a disposable, freshly created database, so the
schema it finds afterwards can only have come from the boot under test.
Against a shared database the same check would pass whether or not the
plugin ever loaded.

`store-postgres-plugin/tests/admin_api_e2e.rs` goes one step further:
it installs the plugin over the real admin API, restarts onto it, mints
a key with an AWS-shaped credential over that API, and reads both rows
back with a raw client that never touches the plugin, its door or the
loader.

`store-postgres/src/tests.rs` holds the store's own coverage against a
live database: tombstone semantics, slot-safe credential minting,
revocation, snapshot isolation, and each migration boundary on its own
throwaway database (including a released 1.5.x database upgraded in place).
`src/tests/plane_records.rs` covers the plane-record verbs, and
`src/tests/store_conformance.rs` is this repo's own copy of busbar's `Store`
conformance suite, taken verbatim from busbar's in-tree copy and wired in
full.

All of them are gated on the `BUSBAR_TEST_POSTGRES_URL` env var, and
they refuse to skip silently under CI. An unset variable there is a
hard failure, not a quiet pass:

```sh
# Point at any reachable Postgres 16+ database:
export BUSBAR_TEST_POSTGRES_URL=postgres://busbar:busbar@localhost:5432/busbar_test
cargo test --workspace
```

Locally, with the env var unset, most live cases print a `skip:`
message and pass. The trust-state cases (demotions, the single-use token
ledger, push-callback liveness — in `plane_records.rs` and the
`trust_state_…` e2e case) deliberately FAIL instead of skipping, because
their unimplemented form is silently green; run them against a database. Under
CI (`CI` env var set — see `.github/workflows/ci.yml`), a *missing*
`BUSBAR_TEST_POSTGRES_URL` is a **hard failure**, not a silent skip:
CI provisions a real `postgres:16` GitHub Actions service container on
every push, specifically so this coverage can never quietly vanish.

### Pack and sign

Once built, the cdylib is packed and signed like any other busbar
plugin — see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_store_postgres_plugin.so \
    --name busbar-store-postgres-plugin --alias postgres --kind store \
    --version 1.0.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-store-postgres-plugin-1.0.0-x86_64-linux.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir` and
set:

```yaml
store:
  module: postgres
  settings: { url: "postgres://user:pass@host/busbar" }
```

— see [`docs/configuration.md`](https://github.com/GetBusbar/busbar/blob/main/docs/configuration.md)
for the full store config reference.

## Tests

```bash
cargo test --workspace --locked
```

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
