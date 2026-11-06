// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the base op set ([`StoreSlots`]): the
//! `op_id`-carrying writes (the usage and metering batches and the plane-record append), the
//! kernel-held records, and the door (`store_door!`) over all of it.

use std::sync::atomic::Ordering;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::store::column::{prefix_end, storable_i64};
use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Request};
use busbar_contract::abi::sdk::store::correction;
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

busbar_contract::statement_extensions!(EXTENSIONS: [
    ("busbar.store.count-scale", b"6"),
    ("busbar.store.count-range", b"i128"),
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
    (busbar_contract::abi::sdk::store::rewrap::INTENT, b"1"),
    (busbar_contract::abi::sdk::store::conditional::CAPABILITY, b"1"),
    (correction::CAPABILITY, b"1"),
]);

/// How many ops of this store the host may have in flight at once.
const MAX_INFLIGHT: u32 = 64;

/// The settings accepted by this plugin's lifecycle parser.
const SETTINGS_SCHEMA: busbar_contract::abi::mechanism::call::Blob =
    busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("settings.schema.json"));

busbar_contract::store_door!(
    PostgresStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    MAX_INFLIGHT,
    needs: NEEDS,
    extensions: EXTENSIONS,
    settings_schema: SETTINGS_SCHEMA
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

/// Rows one sweep statement removes, and how many statements one sweep runs at most.
const SWEEP_BATCH: i64 = 10_000;
const SWEEP_MAX_BATCHES: usize = 10;

/// How often (seconds) one instance sweeps `store_ops` past its retention.
const SWEEP_EVERY_SECS: u64 = 60;

/// Ledger writes share revision authority with correction; append dedupe needs only its receipt.
enum DedupeAuthority {
    Receipt,
    Ledger,
}

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
/// transaction rolled back and a retry of the same values fails the same way.
fn decided(r: OpRefused) -> OpRefused {
    match r {
        OpRefused::Failed(t) if decided_text(&t) => OpRefused::Refused(t),
        other => other,
    }
}

/// `t` leads with a five-character SQLSTATE of class 22 or 23, then `: `.
fn decided_text(t: &str) -> bool {
    let b = t.as_bytes();
    t.starts_with("exact count: ")
        || b.len() > 6
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

        None => Err(format!("op_id {op:?} was swept while being claimed; retry")),
    }
}

impl Session {
    /// All facts and the receipt share the transaction and the ordinary writers' first lock.
    async fn v3_usage_correction(
        &mut self,
        request: &correction::Request,
    ) -> OpResult<correction::Decision> {
        let dedupe = Dedupe::usage_correction(request);
        let normalized_request =
            correction::normalized(request).map_err(|e| OpRefused::Refused(e.to_string()))?;
        let request = &normalized_request;
        let mut tx = self
            .client()
            .transaction()
            .await
            .map_err(|e| OpRefused::Failed(pg(e)))?;
        Session::lock_revision(&mut tx).await.map_err(failed)?;
        if let Some(recorded) = claim(&mut tx, request.op_id, &dedupe.body_hex())
            .await
            .map_err(OpRefused::Failed)?
        {
            dedupe.answer(Ok(Some(recorded)))?;
            tx.rollback().await.map_err(|e| OpRefused::Failed(pg(e)))?;
            return Ok(correction::Decision::Applied);
        }
        let live: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM keys WHERE id=$1 AND deleted_at IS NULL)",
                &[&request.key_id],
            )
            .await
            .map_err(|e| OpRefused::Failed(pg(e)))?
            .try_get(0)
            .map_err(|e| OpRefused::Failed(pg(e)))?;
        let mut metering =
            Self::list_metering_for_key_in(&mut tx, request.day_start, Some(&request.key_id))
                .await
                .map_err(failed)?;
        correction::canonical_metering(&mut metering);
        let mut matches = live && metering == request.metering;
        for change in &request.usage {
            let mut current = Self::get_usage_in(
                &mut tx,
                &change.address.bucket_id,
                change.address.window_start,
            )
            .await
            .map_err(failed)?;
            correction::canonical_ledger(&mut current).map_err(|e| OpRefused::Failed(e.into()))?;
            matches &= current == change.expected;
        }
        if !matches {
            tx.rollback().await.map_err(|e| OpRefused::Failed(pg(e)))?;
            return Ok(correction::Decision::ConditionConflict);
        }
        for change in &request.usage {
            Self::replace_usage_exact_in(&mut tx, change)
                .await
                .map_err(decided)?;
        }

        tx.commit().await.map_err(|e| OpRefused::Failed(pg(e)))?;
        self.sweep_ops().await;
        Ok(correction::Decision::Applied)
    }

    /// NUMERIC stores exact i128 quantity mantissas and independent u64 request counters.
    /// Text parameters avoid narrowing quantities through the wire client's i64 codec.
    async fn replace_usage_exact_in(
        tx: &mut Transaction<'_>,
        change: &correction::UsageChange,
    ) -> OpResult<()> {
        let bucket = &change.address.bucket_id;
        let window = bits(change.address.window_start);
        let row = &change.replacement;
        let requests = row.requests.to_string();
        let billable = row.billable_requests.to_string();
        tx.execute(
            "INSERT INTO usage_windows(bucket_id,window_start,requests,billable_requests)
             VALUES($1,$2,$3::text::numeric,$4::text::numeric)
             ON CONFLICT(bucket_id,window_start) DO UPDATE SET
             requests=EXCLUDED.requests,billable_requests=EXCLUDED.billable_requests",
            &[&bucket, &window, &requests, &billable],
        )
        .await
        .map_err(|e| OpRefused::Failed(pg(e)))?;
        tx.execute(
            "DELETE FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &window],
        )
        .await
        .map_err(|e| OpRefused::Failed(pg(e)))?;
        tx.execute(
            "DELETE FROM usage_ledger_units WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &window],
        )
        .await
        .map_err(|e| OpRefused::Failed(pg(e)))?;
        for model in &row.models {
            let counters = crate::RESERVED_COLUMNS.map(|unit| model.tier(unit).to_string());
            tx.execute(
                "INSERT INTO usage_ledger(bucket_id,window_start,model,tokens_input,tokens_output,tokens_cache_read,tokens_cache_write)
                 VALUES($1,$2,$3,$4::text::numeric,$5::text::numeric,$6::text::numeric,$7::text::numeric)",
                &[&bucket, &window, &model.model, &counters[0], &counters[1], &counters[2], &counters[3]],
            ).await.map_err(|e| OpRefused::Failed(pg(e)))?;
            for (unit, count) in &model.usage_units {
                if crate::is_reserved_unit(unit) {
                    continue;
                }
                let count = count.to_string();
                tx.execute(
                    "INSERT INTO usage_ledger_units(bucket_id,window_start,model,unit,count)
                     VALUES($1,$2,$3,$4,$5::text::numeric)",
                    &[&bucket, &window, &model.model, &unit, &count],
                )
                .await
                .map_err(|e| OpRefused::Failed(pg(e)))?;
            }
        }
        Ok(())
    }

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

        for _ in 0..SWEEP_MAX_BATCHES {
            let removed = self
                .client()
                .execute(
                    "DELETE FROM store_ops WHERE ctid IN
                         (SELECT ctid FROM store_ops WHERE recorded_at < $1 LIMIT $2)",
                    &[&before, &SWEEP_BATCH],
                )
                .await;
            match removed {
                Ok(n) if n == SWEEP_BATCH as u64 => {}
                Ok(_) => break,
                Err(error) => {
                    tracing::warn!("postgres operation receipt sweep failed: {}", pg(error));
                    break;
                }
            }
        }
    }

    /// One `op_id`-carrying write in ONE transaction with its dedupe row: a new op runs `apply` and
    /// commits (`None`); an op already recorded applies nothing and answers the body found, for
    /// [`Dedupe::answer`].
    async fn deduped(
        &mut self,
        op: OpId,
        body: &str,
        authority: DedupeAuthority,
        apply: impl AsyncFnOnce(&mut Transaction<'_>) -> OpResult<()>,
    ) -> OpResult<Option<String>> {
        self.sweep_ops().await;
        let mut tx = self
            .client()
            .transaction()
            .await
            .map_err(|e| OpRefused::Failed(pg(e)))?;
        if matches!(authority, DedupeAuthority::Ledger) {
            Session::lock_revision(&mut tx).await.map_err(failed)?;
        }
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
        storable_i64("append_plane_record", "seq", record.seq).map_err(refused)?;
        storable_i64("append_plane_record", "ts", record.ts).map_err(refused)?;
        self.deduped(op, body, DedupeAuthority::Receipt, async |tx| {
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

    /// A conditional batch observes one pre-state and commits every mutation with its receipt.
    async fn v3_record_transaction(&mut self, request: &Request) -> OpResult<Decision> {
        request
            .validate()
            .map_err(|error| OpRefused::Refused(error.into()))?;
        let dedupe = Dedupe::record_transaction(request);
        let mut tx = self
            .client()
            .transaction()
            .await
            .map_err(|e| decided(OpRefused::Failed(pg(e))))?;

        Session::lock_revision(&mut tx).await.map_err(failed)?;
        if let Some(recorded) = claim(&mut tx, request.op_id, &dedupe.body_hex())
            .await
            .map_err(OpRefused::Failed)?
        {
            dedupe.answer(Ok(Some(recorded)))?;
            tx.rollback()
                .await
                .map_err(|e| decided(OpRefused::Failed(pg(e))))?;
            return Ok(Decision::Applied);
        }
        for predicate in &request.predicates {
            let row = tx
                .query_opt(
                    "SELECT value FROM store_records WHERE schema_id=$1 AND key=$2",
                    &[&predicate.schema, &predicate.key],
                )
                .await
                .map_err(|e| decided(OpRefused::Failed(pg(e))))?;
            let value = row
                .map(|row| row.try_get::<_, Vec<u8>>(0))
                .transpose()
                .map_err(|e| decided(OpRefused::Failed(pg(e))))?;
            let matches = match &predicate.expected {
                Expected::Absent => value.is_none(),
                Expected::Bytes(expected) => value.as_ref() == Some(expected),
            };
            if !matches {
                tx.rollback()
                    .await
                    .map_err(|e| decided(OpRefused::Failed(pg(e))))?;
                return Ok(Decision::ConditionConflict);
            }
        }
        for mutation in &request.mutations {
            match mutation {
                Mutation::Put { schema, key, value } => {
                    Self::record_put_in(&mut tx, schema, key, value).await
                }
                Mutation::Delete { schema, key } => {
                    Self::record_put_in(&mut tx, schema, key, &[]).await
                }
                Mutation::DeleteRange {
                    schema,
                    prefix,
                    exact_key_length,
                } => Self::record_delete_range_in(&mut tx, schema, prefix, *exact_key_length).await,
            }
            .map_err(|e| decided(OpRefused::Failed(e)))?;
        }
        tx.commit().await.map_err(|e| OpRefused::Failed(pg(e)))?;

        self.sweep_ops().await;
        Ok(Decision::Applied)
    }

    /// An ordinary opaque-record write follows the same serialization order as conditional batches.
    async fn v3_record_put(
        &mut self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        let mut tx = self.client().transaction().await.map_err(pg)?;
        Session::lock_revision(&mut tx).await.map_err(|e| e.0)?;
        Self::record_put_in(&mut tx, schema, key, value).await?;
        tx.commit().await.map_err(pg)
    }

    /// Empty legacy puts are deletes; conditional requests use an explicit Delete variant.
    async fn record_put_in(
        tx: &mut Transaction<'_>,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        if value.is_empty() {
            tx.execute(
                "DELETE FROM store_records WHERE schema_id=$1 AND key=$2",
                &[&schema, &key],
            )
            .await
            .map(drop)
            .map_err(pg)
        } else {
            tx.execute(
                "INSERT INTO store_records (schema_id,key,value) VALUES ($1,$2,$3)
                 ON CONFLICT (schema_id,key) DO UPDATE SET value=EXCLUDED.value",
                &[&schema, &key, &value],
            )
            .await
            .map(drop)
            .map_err(pg)
        }
    }

    /// Raw byte-prefix deletion with an exact key width: neighbouring longer scopes survive.
    async fn record_delete_range_in(
        tx: &mut Transaction<'_>,
        schema: &str,
        prefix: &[u8],
        exact_key_length: u64,
    ) -> Result<(), String> {
        let Ok(length) = i64::try_from(exact_key_length) else {
            return Ok(());
        };
        match prefix_end(prefix) {
            Some(end) => {
                tx.execute(
                    "DELETE FROM store_records WHERE schema_id=$1 AND key >= $2 AND key < $3
                 AND octet_length(key)::bigint=$4",
                    &[&schema, &prefix, &end, &length],
                )
                .await
            }
            None => {
                tx.execute(
                    "DELETE FROM store_records WHERE schema_id=$1 AND key >= $2
                 AND octet_length(key)::bigint=$3",
                    &[&schema, &prefix, &length],
                )
                .await
            }
        }
        .map(drop)
        .map_err(pg)
    }

    async fn v3_record_get(
        &mut self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        let row = self
            .client()
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
        if limit == 0 {
            return Ok(Vec::new());
        }

        let limit = i64::from(limit);
        let client = self.client();
        let rows = match prefix_end(prefix) {
            Some(end) => {
                client
                    .query(
                        "SELECT key, value FROM store_records
                         WHERE schema_id = $1 AND key >= $2 AND key < $3
                         ORDER BY key LIMIT $4",
                        &[&schema, &prefix, &end, &limit],
                    )
                    .await
            }
            None => {
                client
                    .query(
                        "SELECT key, value FROM store_records
                         WHERE schema_id = $1 AND key >= $2
                         ORDER BY key LIMIT $3",
                        &[&schema, &prefix, &limit],
                    )
                    .await
            }
        }
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
        let mut ordered: Vec<&(String, u64, UsageDelta)> = cells.iter().collect();
        ordered.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
        self.deduped(op, body, DedupeAuthority::Ledger, async |tx| {
            if ordered
                .iter()
                .any(|(bucket, _, _)| correction::reserved_bucket(bucket))
            {
                return Err(OpRefused::Refused(
                    "reserved usage adjustment requires atomic correction".into(),
                ));
            }
            for (bucket, window, delta) in ordered {
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

        let mut ordered: Vec<&MeteringDelta> = deltas.iter().collect();
        ordered.sort_by_key(|d| (&d.key_id, d.bucket, &d.model, &d.provider, d.priced_from_ms));
        self.deduped(op, body, DedupeAuthority::Ledger, async |tx| {
            for d in ordered {
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

/// Parse with the SDK's wiping settings reader: a host secret marker is restored from its
/// lent slot, and every DSN is captured before any public connection option is parsed.
fn parse_settings(settings: &[u8], secrets: &[&[u8]]) -> Result<PostgresStore, String> {
    use busbar_contract::abi::sdk::cred::{settings_lent, PostgresUrl, SettingsError};

    const BAD: &str = "invalid postgres plugin config";
    let settings = if settings.trim_ascii().is_empty() {
        &b"{}"[..]
    } else {
        settings
    };
    let parse_error = |e: SettingsError| {
        let path = if e.path().is_empty() {
            String::new()
        } else {
            format!("{}: ", e.path())
        };
        format!("{BAD}: {path}{e}")
    };

    let keys: Option<std::collections::HashMap<String, serde::de::IgnoredAny>> =
        settings_lent(settings, secrets).map_err(&parse_error)?;
    if let Some(k) = keys
        .as_ref()
        .and_then(|keys| keys.keys().find(|k| k.as_str() != "url"))
    {
        return Err(format!("{BAD}: unknown setting `{k}` (accepted: url)"));
    }
    let map: Option<std::collections::HashMap<String, Option<PostgresUrl>>> =
        settings_lent(settings, secrets).map_err(parse_error)?;
    let mut map = map.unwrap_or_default();
    let captured = map
        .remove("url")
        .flatten()
        .map(|url| url.0)
        .filter(|url| !url.public().trim().is_empty() || url.password().is_some())
        .ok_or_else(|| format!("{BAD}: `url` is required (a libpq connection string)"))?;
    PostgresStore::captured(captured).map_err(|e| format!("{BAD}: url: {}", e.0))
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
    const RECORD_TRANSACTION: bool = true;
    const USAGE_CORRECTION: bool = true;

    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    fn validate(settings: &[u8]) -> Result<(), String> {
        parse_settings(settings, &[]).map(drop)
    }

    /// Open from the store section's settings:
    ///
    /// ```json
    /// { "url": "postgres://user:pass@host:5432/busbar" }
    /// ```
    ///
    /// The settings are parsed here; the server is reached by the connect step.
    fn open_with_secrets(
        settings: &[u8],
        secrets: &[&[u8]],
        _host: Option<Host>,
    ) -> Result<Self, String> {
        parse_settings(settings, secrets)
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

    fn record_transaction(&self, cx: &mut Op<'_>, request: &Request) -> Step<OpResult<Decision>> {
        let request = request.clone();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_record_transaction(&request)
            .await)
    }

    fn apply_usage_correction(
        &self,
        cx: &mut Op<'_>,
        request: &correction::Request,
    ) -> Step<OpResult<correction::Decision>> {
        if let Err(error) = request.validate() {
            return Step::Ready(Err(OpRefused::Refused(error.into())));
        }
        let request = request.clone();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_usage_correction(&request)
            .await)
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

    legacy_slots! {
        put_key(key: &VirtualKey) -> ();
        get_key(id: &str) -> Option<VirtualKey>;
        list_keys() -> Vec<VirtualKey>;
        delete_key(id: &str) -> ();
        list_keys_since(since = u64) -> Vec<VirtualKey>;
        get_usage(bucket_id: &str, window_start = u64) -> UsageLedger;
        put_usage(bucket_id: &str, window_start = u64, ledger: &UsageLedger) -> ();
        purge_usage_before(before = u64) -> u64;
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

    fn rewrap_credential(
        &self,
        cx: &mut Op<'_>,
        expected: &CredentialSecret,
        replacement: &str,
    ) -> Step<RecordStoreResult<bool>> {
        // Both owned envelopes must be wiped when the parked operation completes or cancels.
        let request = busbar_contract::abi::sdk::store::rewrap::Request::new(expected, replacement);
        on_conn!(self, cx, RecordStoreError, |s| s
            .rewrap_credential(&request.expected, &request.replacement)
            .await)
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

#[cfg(test)]
#[path = "settings_schema_tests.rs"]
mod settings_schema_tests;
