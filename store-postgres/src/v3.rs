// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the base op set ([`StoreSlots`]): the
//! `op_id`-carrying writes (the usage and metering batches and the plane-record append), the
//! kernel-held records, and the door (`store_door!`) over all of it. The store keeps ledger counts
//! and records only; money is a view on ledger x rate card.
//!
//! DEDUPE (`abi::store` S1-S4), DURABLE: every `op_id` this store APPLIED is a `store_ops` row
//! holding the op's body ([`Dedupe::body_hex`]; `answer` is written empty and never read). The row
//! is inserted FIRST in the op's own transaction with the op's effect: a racing call with the same
//! `op_id` (on this node or another) waits on the primary key, then reads the committed body, which
//! [`Dedupe::answer`] judges a replay or a conflict. A failed op rolls its row back with its
//! effect. Rows are kept [`OP_ID_RETENTION_SECS`] and swept at most once a minute per instance.
//!
//! CONNECTIONS: every slot runs on the instance's ONE kept connection over the host's connector, as
//! straight-line async code by the store SDK's `wire::drive_kept`. The door declares one outbound
//! `tcp` need (`NEEDS`); `open` parses the settings and its connect step reaches the server and
//! ensures the schema, so an unreachable or refusing server fails the load.
//!
//! Every `u64` this module's own record and dedupe columns take is stored BIT-FOR-BIT in a BIGINT
//! (`as i64`). The ops delegated to the base code keep that code's rules: usage and metering totals
//! clamp, and appends refuse a value outside their column.

use std::sync::atomic::Ordering;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::store::column::storable_i64;
use busbar_contract::abi::sdk::store::dedupe::Dedupe;
use busbar_contract::abi::sdk::store::wire::{drive_kept, Body};
use busbar_contract::abi::sdk::store::{Op, OpRefused, OpResult, Scanned, Step, StoreSlots, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, PlaneRecordRef,
    PlaneSelector, RecordStoreError, RecordStoreResult, UsageDelta, UsageLedger, VirtualKey,
};

use crate::pgwire::Transaction;
use crate::{now_secs, render_pg_error, PostgresStore, Session, NAME};

const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The store's one need: the server, dialled over `tcp` at the DSN's `host:port`, in the
/// `operator-infrastructure` egress class.
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
    transport: abi_str("tcp"),
    auth: NO_TEXT,
    target_from: NO_TEXT,
    trust_from: NO_TEXT,
    details: Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_OCTETS,
        flags: 0,
    },
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

// `url` is reference-capable, not secret: a `{env:}`/`{file:}`/`{module:}` reference resolves in
// place (a 1.5.5 `url: {env: VAR}` keeps booting) and a literal passes as written.
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

busbar_contract::store_door!(
    PostgresStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    64,
    needs: NEEDS,
    extensions: EXTENSIONS
);

/// Run one op on the instance's kept connection (a fresh one when none is kept): open the session
/// (a failure is `$fail` of the driver's words), run `$body` on it `$s`, and keep the connection if
/// the session is idle. Every argument the body names is owned.
macro_rules! on_conn {
    ($self:ident, $cx:ident, $fail:expr, |$s:ident| $body:expr) => {{
        let shared = $self.shared();
        let pool = shared.pool.clone();
        drive_kept($cx, &pool, move |wire| -> Body<_> {
            Box::pin(async move {
                let mut $s = match Session::open(wire, shared).await {
                    Ok(s) => s,
                    Err(e) => return Err(($fail)(e)),
                };
                let answer = $body;
                $s.close().await;
                answer
            })
        })
    }};
}

/// How often (seconds) one instance sweeps `store_ops` past its retention.
const SWEEP_EVERY_SECS: u64 = 60;

/// A `u64` into a BIGINT, bit for bit.
fn bits(v: u64) -> i64 {
    v as i64
}

fn pg(e: crate::pgwire::Error) -> String {
    render_pg_error(&e)
}

fn failed(e: RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

fn refused(e: RecordStoreError) -> OpRefused {
    OpRefused::Refused(e.0)
}

/// An apply error the server decided from the values (SQLSTATE class 22 data exception, 23
/// integrity constraint; the text leads with its code, `render_pg_error`) is a refusal: the
/// transaction rolled back and a retry of the same values fails the same way. Anything else
/// (a deadlock, a serialization failure, the chain fork) stays `Failed`.
fn decided(r: OpRefused) -> OpRefused {
    match r {
        OpRefused::Failed(t) if decided_text(&t) => OpRefused::Refused(t),
        other => other,
    }
}

/// `t` leads with a five-character SQLSTATE of class 22 or 23, then `: `.
fn decided_text(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() > 6
        && matches!(&b[..2], b"22" | b"23")
        && b[2..5].iter().all(u8::is_ascii_alphanumeric)
        && &b[5..7] == b": "
}

/// Claim `op` for `body` (its [`Dedupe::body_hex`]) inside `tx`: insert its row (`None`), or read
/// the body a committed call recorded.
async fn claim(tx: &mut Transaction<'_>, op: OpId, body: &str) -> Result<Option<String>, String> {
    let id: &[u8] = &op.0;
    let inserted = tx
        .execute(
            "INSERT INTO store_ops (op_id, body, answer, recorded_at) VALUES ($1, $2, '', $3)
             ON CONFLICT (op_id) DO NOTHING",
            &[&id, &body, &bits(now_secs())],
        )
        .await
        .map_err(pg)?;
    if inserted == 1 {
        return Ok(None);
    }
    let row = tx
        .query_opt("SELECT body FROM store_ops WHERE op_id = $1", &[&id])
        .await
        .map_err(pg)?;
    match row {
        Some(r) => Ok(Some(r.try_get(0).map_err(pg)?)),
        // Swept between the insert and the read (it was past retention): nothing applied, and a
        // retry claims the op afresh.
        None => Err(format!("op_id {op:?} was swept while being claimed; retry")),
    }
}

impl Session {
    /// Forget every `op_id` past its retention, at most once per [`SWEEP_EVERY_SECS`].
    async fn sweep_ops(&mut self) {
        let now = now_secs();
        let last = self.ops_swept_at.load(Ordering::Relaxed);
        if now.saturating_sub(last) < SWEEP_EVERY_SECS
            || self
                .ops_swept_at
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let before = bits(now.saturating_sub(OP_ID_RETENTION_SECS));
        // Best effort: a failed sweep leaves rows that the next sweep takes.
        let _ = self
            .lock()
            .execute("DELETE FROM store_ops WHERE recorded_at < $1", &[&before])
            .await;
    }

    /// One `op_id`-carrying write in ONE transaction with its dedupe row: a new op runs `apply` and
    /// commits (`None`); an op already recorded applies nothing and answers the body found, for
    /// [`Dedupe::answer`]. A refusal from `apply` rolls the row back with the effect.
    async fn deduped(
        &mut self,
        op: OpId,
        body: &str,
        apply: impl AsyncFnOnce(&mut Transaction<'_>) -> OpResult<()>,
    ) -> OpResult<Option<String>> {
        self.sweep_ops().await;
        let mut tx = self
            .lock()
            .transaction()
            .await
            .map_err(|e| OpRefused::Failed(pg(e)))?;
        let found = claim(&mut tx, op, body).await.map_err(OpRefused::Failed)?;
        if found.is_none() {
            apply(&mut tx).await.map_err(decided)?;
            tx.commit().await.map_err(|e| OpRefused::Failed(pg(e)))?;
        }
        Ok(found)
    }

    async fn v3_append_plane_record(
        &mut self,
        op: OpId,
        body: &str,
        record: &busbar_contract::records::PlaneRecord,
    ) -> OpResult<Option<String>> {
        // Decided before BEGIN: a seq or ts the column cannot hold is refused, nothing written.
        storable_i64("append_plane_record", "seq", record.seq).map_err(refused)?;
        storable_i64("append_plane_record", "ts", record.ts).map_err(refused)?;
        self.deduped(op, body, async |tx| {
            if Session::append_plane_record_in(tx, record)
                .await
                .map_err(failed)?
            {
                Ok(())
            } else {
                Err(OpRefused::Failed(format!(
                    "append_plane_record: kind '{}' seq {} was freed between the insert and the \
                     read-back; the record was NOT stored",
                    record.kind, record.seq
                )))
            }
        })
        .await
    }

    /// `record_put` (slot 40): an upsert on `(schema, key)`. An EMPTY value removes the row: it is
    /// the host's strike, so `record_get` then answers `None` and
    /// `record_scan` never returns it. Removing a row that is not there is `Ok`.
    async fn v3_record_put(
        &mut self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        if value.is_empty() {
            return self
                .lock()
                .execute(
                    "DELETE FROM store_records WHERE schema_id = $1 AND key = $2",
                    &[&schema, &key],
                )
                .await
                .map(drop)
                .map_err(pg);
        }
        self.lock()
            .execute(
                "INSERT INTO store_records (schema_id, key, value) VALUES ($1, $2, $3)
                 ON CONFLICT (schema_id, key) DO UPDATE SET value = EXCLUDED.value",
                &[&schema, &key, &value],
            )
            .await
            .map(drop)
            .map_err(pg)
    }

    async fn v3_record_get(
        &mut self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        let row = self
            .lock()
            .query_opt(
                "SELECT value FROM store_records WHERE schema_id = $1 AND key = $2",
                &[&schema, &key],
            )
            .await
            .map_err(pg)?;
        row.map(|r| record(r.try_get(0).map_err(pg)?)).transpose()
    }

    async fn v3_record_scan(
        &mut self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Scanned, String> {
        // `limit` 0 is nothing, never everything.
        if limit == 0 {
            return Ok(Vec::new());
        }
        let rows = self
            .lock()
            .query(
                "SELECT key, value FROM store_records
                 WHERE schema_id = $1
                   AND substring(key FROM 1 FOR octet_length($2::bytea)) = $2::bytea
                 ORDER BY key LIMIT $3",
                &[&schema, &prefix, &i64::from(limit)],
            )
            .await
            .map_err(pg)?;
        rows.iter()
            .map(|r| {
                Ok((
                    r.try_get(0).map_err(pg)?,
                    record(r.try_get(1).map_err(pg)?)?,
                ))
            })
            .collect()
    }

    async fn v3_add_usage_batch(
        &mut self,
        op: OpId,
        body: &str,
        cells: &[(String, u64, UsageDelta)],
    ) -> OpResult<Option<String>> {
        self.deduped(op, body, async |tx| {
            for (bucket, window, delta) in cells {
                Session::add_usage_in(tx, bucket, *window, delta)
                    .await
                    .map_err(failed)?;
            }
            Ok(())
        })
        .await
    }

    async fn v3_add_metering_batch(
        &mut self,
        op: OpId,
        body: &str,
        deltas: &[MeteringDelta],
    ) -> OpResult<Option<String>> {
        for d in deltas {
            storable_i64("add_metering_batch", "priced_from_ms", d.priced_from_ms)
                .map_err(refused)?;
        }
        self.deduped(op, body, async |tx| {
            for d in deltas {
                Session::add_metering_in(tx, d).await.map_err(failed)?;
            }
            Ok(())
        })
        .await
    }
}

/// A stored record's bytes as the table's bounded record.
fn record(bytes: Vec<u8>) -> Result<RecordBytes, String> {
    RecordBytes::new(bytes).map_err(|n| format!("a stored record of {n} bytes is over the ceiling"))
}

/// The store section's settings: its `url`. Shared by `validate` and `open`, so their refusals are
/// the same words.
fn settings_url(settings: &[u8]) -> Result<String, String> {
    let v: serde_json::Value = if settings.trim_ascii().is_empty() {
        serde_json::Value::Object(Default::default())
    } else {
        serde_json::from_slice(settings)
            .map_err(|e| format!("invalid postgres plugin config: {e}"))?
    };
    if let Some(map) = v.as_object() {
        if let Some(k) = map.keys().find(|k| k.as_str() != "url") {
            return Err(format!(
                "invalid postgres plugin config: unknown setting `{k}` (accepted: url)"
            ));
        }
    }
    let url = match v.get("url") {
        None => None,
        Some(serde_json::Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            return Err("invalid postgres plugin config: `url` must be a string".to_string());
        }
    };
    url.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            "postgres plugin config requires a \"url\" (a libpq connection string)".to_string()
        })
}

/// One argument as the slot's body takes it: `:` borrows the owned copy, `=` passes it by value.
macro_rules! pass {
    (: $a:ident) => {
        &$a
    };
    (= $a:ident) => {
        $a
    };
}

/// Each listed base slot: copy its arguments (the body runs across the op's entries) and run the
/// `Session` method of the same name on the op's connection.
macro_rules! legacy_slots {
    ($($name:ident($($arg:ident $sep:tt $ty:ty),*) -> $ret:ty;)*) => {$(
        fn $name(&self, cx: &mut Op<'_>, $($arg: $ty),*) -> Step<RecordStoreResult<$ret>> {
            $(let $arg = $arg.to_owned();)*
            on_conn!(self, cx, RecordStoreError, |s| s.$name($(pass!($sep $arg)),*).await)
        }
    )*};
}

impl StoreSlots for PostgresStore {
    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    fn validate(settings: &[u8]) -> Result<(), String> {
        settings_url(settings).map(drop)
    }

    /// Open from the store section's settings:
    ///
    /// ```json
    /// { "url": "postgres://user:pass@host:5432/busbar" }
    /// ```
    ///
    /// The settings are parsed here; the server is reached by the connect step.
    fn open(settings: &[u8], _host: Option<Host>) -> Result<Self, String> {
        let url = settings_url(settings)?;
        PostgresStore::new(&url).map_err(|e| e.0)
    }

    /// Reach the server and ensure the schema (connect + migrate, at the same moment: the load),
    /// in the driver's words when it cannot.
    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        on_conn!(self, cx, |e| e, |s| s.migrate().await.map_err(|e| e.0))
    }

    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        let d = Dedupe::append(record);
        let (body, record) = (d.body_hex(), record.to_record());
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_append_plane_record(op, &body, &record)
            .await)
        .map(|r| d.answer(r))
    }

    fn record_put(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Step<Result<(), String>> {
        let (schema, key, value) = (schema.to_owned(), key.to_vec(), value.to_vec());
        on_conn!(self, cx, |e| e, |s| s
            .v3_record_put(&schema, &key, &value)
            .await)
    }

    fn record_get(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        key: &[u8],
    ) -> Step<Result<Option<RecordBytes>, String>> {
        let (schema, key) = (schema.to_owned(), key.to_vec());
        on_conn!(self, cx, |e| e, |s| s.v3_record_get(&schema, &key).await)
    }

    fn record_scan(
        &self,
        cx: &mut Op<'_>,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Step<Result<Scanned, String>> {
        let (schema, prefix) = (schema.to_owned(), prefix.to_vec());
        on_conn!(self, cx, |e| e, |s| s
            .v3_record_scan(&schema, &prefix, limit)
            .await)
    }

    fn add_usage_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        let d = Dedupe::usage(cells);
        let body = d.body_hex();
        let cells: Vec<(String, u64, UsageDelta)> = cells
            .iter()
            .map(|(b, w, d)| ((*b).to_owned(), *w, d.clone()))
            .collect();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_add_usage_batch(op, &body, &cells)
            .await)
        .map(|r| d.answer(r))
    }

    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        let d = Dedupe::metering(deltas);
        let (body, deltas) = (d.body_hex(), deltas.to_vec());
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_add_metering_batch(op, &body, &deltas)
            .await)
        .map(|r| d.answer(r))
    }

    // The base op set: each the store's own body, on the op's connection, over owned copies of its
    // arguments (`:` marks a borrowed argument, `=` one passed by value).
    legacy_slots! {
        put_key(key: &VirtualKey) -> ();
        get_key(id: &str) -> Option<VirtualKey>;
        list_keys() -> Vec<VirtualKey>;
        delete_key(id: &str) -> ();
        list_keys_since(since = u64) -> Vec<VirtualKey>;
        get_usage(bucket_id: &str, window_start = u64) -> UsageLedger;
        put_usage(bucket_id: &str, window_start = u64, ledger: &UsageLedger) -> ();
        list_metering(bucket = u64) -> Vec<MeteringRow>;
        put_credential(secret: &CredentialSecret) -> ();
        put_key_with_credential(key: &VirtualKey, secret: &CredentialSecret) -> ();
        list_credentials(key_id: &str) -> Vec<CredentialMeta>;
        revoke_credential(id: &str, reason: &str) -> ();
        list_credentials_since(since = u64) -> Vec<CredentialSecret>;
        list_audit() -> Vec<AuditRecord>;
        add_denylist(sub: &str, reason: &str) -> ();
        list_denylist() -> Vec<String>;
        list_audit_tail(limit = u64) -> Vec<AuditRecord>;
        get_plane_record(kind: &str, id: &str) -> Option<Vec<u8>>;
        list_plane_record_parents(kind: &str) -> Vec<String>;
        purge_plane_records_before(kind: &str, before = u64) -> u64;
        delete_plane_record(kind: &str, id: &str) -> ();
        redeem_plane_token(kind: &str, token: &str, expires_at = u64, now = u64) -> bool;
        plane_token_live(kind: &str, token: &str, expires_at = u64, now = u64) -> bool;
    }

    fn upsert_plane_record(
        &self,
        cx: &mut Op<'_>,
        record: PlaneRecordRef<'_>,
    ) -> Step<RecordStoreResult<()>> {
        let record = record.to_record();
        on_conn!(self, cx, RecordStoreError, |s| s
            .upsert_plane_record(record.view())
            .await)
    }

    fn list_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Step<RecordStoreResult<Vec<Vec<u8>>>> {
        let kind = kind.to_owned();
        let selector = selector.to_static();
        on_conn!(self, cx, RecordStoreError, |s| s
            .list_plane_records(&kind, &selector)
            .await)
    }

    fn purge_plane_records(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
        retention: busbar_contract::records::Retention,
    ) -> Step<RecordStoreResult<u64>> {
        let kind = kind.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s
            .purge_plane_records(&kind, before, retention)
            .await)
    }
}
