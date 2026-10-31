<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-store-postgres

First-party signed kind:store plugin cdylib: the Postgres backend for busbar's durable governance store, exported over the store C ABI. Drop the built library into the plugins folder and set store.module: postgres to share virtual keys, budgets, and usage across a fleet of busbar nodes.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `store` | `postgres` | `busbar-store-postgres-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-store-postgres/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-store-postgres/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

**This plugin's version: v1.6.0.** (Independently versioned from busbar
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

This plugin is versioned **independently of busbar** — `v1.6.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.6.0+** (the release whose store
interface this crate implements: the kind-tagged plane-record verbs, the
name-keyed usage ledger and the dated metering rows). Pin both versions
explicitly in production; do not assume they move together.

### Upgrading from a 1.5.x deployment

The first connect of this build upgrades an existing database **in place**
(schema v6 → this build's current schema, inside one transaction, under the same advisory lock every
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
  upstream demotions, push-callback capabilities and single-use approvals),
  plus the store v3 tables `store_ops` and `store_records` (op-id dedupe and
  the kernel's records). The store keeps ledger counts, not money: busbar
  derives money from the counts and its rate card.
- Schema v13 drops the tables a pre-release v11/v12 build created for the
  deleted store slots (`money_slots`, `money_slices`, `money_epoch`,
  `store_journal`, `store_sessions`) and their op-id dedupe rows.

A database a pre-release dev build took to schema v7–v9 keeps its
`mcp_calls`/`tasks`/`task_events`/`mcp_demotions`/`spent_ask_states` tables
untouched; busbar 1.6.0 no longer reads them.

It is a `cdylib` that serves busbar's store v3 table (`StoreSlots`, via the plugin SDK in
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process.

This repo is a same-repo, 2-crate Cargo workspace: it brings 100% of
what it needs. All the SQL and schema logic lives in the
`busbar-store-postgres` crate (`store-postgres/`, a same-repo sibling
this plugin wraps — a custom build can also link it statically instead
of loading this cdylib); `store-postgres-plugin/src/lib.rs` only re-exports
that crate and exports its `door` through `export_door!`.


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
  success on SQLite and Valkey. Tooling that treats a store error as
  fatal should not assume the same input produces the same outcome on
  every backend.

### Known limitations (documented honestly, not papered over)

- **The store opens no socket of its own.** It reaches Postgres through
  busbar's connector (the store declares one outbound `tcp` need in the
  `operator-infrastructure` egress class).
- **Up to eight kept connections.** (1.5.x kept one.) The store connects and
  authenticates on demand and keeps up to eight idle connections; an
  operation that finds none free waits for one. A
  connection that fails (or is left inside a transaction) is closed, and
  the next operation connects afresh rather than needing a restart.
- **TLS through busbar.** `sslmode=require`, `verify-ca` and
  `verify-full` secure the connection through busbar's connector and its
  trust anchors (always verifying the certificate and name); `disable`
  connects in plaintext, as 1.5.x (`NoTls`) did. `allow` is plaintext (no
  `SSLRequest`); `prefer` sends the `SSLRequest`, secures the connection on
  the server's `S` WITHOUT verifying its certificate, and goes on in plaintext
  on `N` (libpq's behaviour). An ABSENT `sslmode` is plaintext (the same as
  `disable`; libpq's default of `prefer` is not applied): set `sslmode`
  explicitly. A Unix-socket
  `host` is refused: the store reaches its server over TCP.

See the doc comments at the top of
[`store-postgres/src/lib.rs`](store-postgres/src/lib.rs)
for the full design rationale — that is where the actual store logic
lives (in this repo now, not busbar); `store-postgres-plugin/` is the
thin `cdylib` adapter around it.

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | A libpq connection string, URL (`postgres://user:pass@host:5432/busbar?sslmode=require`) or keyword form (`host=... user=... password=... dbname=...`). Connections go through busbar's connector. See the lists below. |

The only setting is `url`; any other top-level key is refused
(`unknown setting`), and a `url` that is not a string is refused.

**Connection-string options honoured:** `host`, `hostaddr`, `port` (a
comma-separated list of several endpoints, tried in order), `user`,
`password`, `dbname`, `application_name`, `options`, `target_session_attrs`
(`any`, `read-write`, `read-only`), `channel_binding` (`disable` or `prefer`),
`sslmode` (`disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`;
absent means `disable`) and `connect_timeout` (whole seconds; it bounds a new
connection's dial and handshake and defaults to 30 when absent; `0` or less
means no bound, as in libpq; a value that is not a whole number is refused).
The store also asks the server, at startup, for `lock_timeout=30s` and
`idle_in_transaction_session_timeout=60s` unless `options` sets them, and
begins every transaction `READ COMMITTED` or `REPEATABLE READ` explicitly.

**Socket options, accepted as 1.5.5's driver accepted them.** busbar's
connector owns the sockets: it dials every connection with TCP keepalive on,
probing after 60 s idle at the OS's interval and count, with no per-store
setting. So:

- `keepalives=1` (any non-zero) is what happens anyway; `keepalives=0` is
  **refused** (the connector cannot turn keepalive off).
- `keepalives_idle` (`60`, or `0` or less), `keepalives_interval`,
  `tcp_user_timeout` (`0` or less), `keepalives_count`, `keepalives_retries`
  (`0`), `load_balance_hosts=disable` and `sslnegotiation=postgres` are
  what the store does: accepted.
- Any other valid value of those options (say `keepalives_idle=30`,
  `load_balance_hosts=random`, `sslnegotiation=direct`) cannot apply: it is
  accepted and logged once, at debug level, naming the option and why it has
  no effect. Endpoints are always tried in the order given, and TLS is always
  asked for with an `SSLRequest` (`sslmode` still decides whether it is used).
- A value 1.5.5's driver refused (not a number, an unknown keyword) is refused.

**Refused, with an explanation (never silently ignored):** `channel_binding=require` (no SCRAM-PLUS), `sslrootcert`
(trust is busbar's), a Unix-socket `host`, `keepalives=0`, and any unknown
option.

A database stamped with a newer schema than this build is refused at open.

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

Run the whole workspace with `cargo test --workspace --locked`.

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
    --version 1.6.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-store-postgres-plugin-1.6.0-x86_64-linux.tar.gz
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

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
