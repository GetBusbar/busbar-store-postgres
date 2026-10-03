// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots this backend answers beyond the 1.5.5 op set ([`StoreSlots`]): the
//! `op_id`-carrying writes, the ledger ops, the money slots and `window_caps`, and the door
//! (`store_door!`) over all of it.
//!
//! DEDUPE (`abi::store` S1-S4), DURABLE: every `op_id` this store APPLIED is a row of `store_ops`
//! holding the op's value fields and its answer. The row is inserted FIRST in the op's own
//! transaction, the op's effect runs in the same transaction, and the answer is written before the
//! commit: a racing call with the same `op_id` (on this node or another) waits on the primary key,
//! then reads the committed row and replays it (same value fields) or is refused (different ones).
//! A failed op rolls its row back with its effect, so only an op that applied is remembered. Rows
//! are kept [`OP_ID_RETENTION_SECS`] and swept at most once a minute per instance.
//!
//! EPOCH: the store table carries no op that advances an epoch, so this store holds one constant
//! epoch (`0`) and accepts the `epoch` a caller states as given, as the node-local stores do.
//!
//! MONEY: a slot `(bucket, pool, dimension, class_key, window_start)` is one `money_slots` row
//! keyed by its rendering; `reserve` locks every slot it draws from (in key order, so two draws
//! never deadlock), tests each cell with 1.5.5's per-dimension rule (`abi::store::ReserveIn`) and
//! applies all or nothing. A grant is valid until `u64::MAX`: nothing in the table expires a slice.
//!
//! CONNECTIONS: every slot runs on the instance's ONE kept connection over the host's connector
//! (1.5.5's one mutex-guarded connection; STORE-KEEP), as straight-line async code by the store
//! SDK's `wire::drive_kept` (busbar THE DESIGN: every call Ready or Pending(wake), no
//! socket of the plugin's own; ARCHITECT rulings 2026-10-03 on Q-L14-1 and Q-L16-2). The door
//! declares one outbound `tcp` need (`NEEDS`, `operator-infrastructure`); `open` parses the
//! settings, and its connect step reaches the server and ensures the schema, so an unreachable or
//! refusing server still fails the load at open, in the driver's words.
//!
//! Every `u64` the ABI hands this module is stored BIT-FOR-BIT in a BIGINT (`as i64` / `as u64`)
//! and every comparison runs here, never in SQL, so no value is clamped or wrapped on the way back.

use std::sync::atomic::Ordering;

use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::store::wire::{drive_kept, Body};
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, Op, OpRefused, OpResult, ReserveRefused,
    Scanned, Step, StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
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

/// THE STORE'S ONE NEED: the server, dialled over `tcp` at the DSN's `host:port` (the store names
/// the target per connection), in the `operator-infrastructure` egress class (private, loopback and
/// plaintext allowed; pinned; cloud metadata hosts refused).
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

busbar_contract::store_door!(
    PostgresStore,
    NAME,
    env!("CARGO_PKG_VERSION"),
    64,
    needs: NEEDS
);

/// RUN ONE OP on the instance's kept connection (a fresh one when none is kept): open the session
/// (a failure is `$fail` of the driver's words), run `$body` on it `$s`, and keep the connection if
/// the session is idle. Every argument the body names is owned (the body runs
/// across the op's entries).
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

/// One `op_id`-carrying write in ONE transaction with its dedupe row: a replay answers the
/// original, a conflict applies nothing, and a new op runs `$apply` (its answer numbers, or `$E`)
/// and is remembered only if it applied (an error rolls the row back with the effect).
macro_rules! deduped {
    ($s:expr, $op:expr, $body:expr, $conflict:expr, $backend:expr, $E:ty, |$tx:ident| $apply:block) => {{
        let op: OpId = $op;
        let (mut tx, seen) = $s.dedupe_begin(op, $body).await.map_err($backend)?;
        match seen {
            Seen::Replay(answer) => answer,
            Seen::Conflict => return Err($conflict),
            Seen::New => {
                let answer = {
                    let $tx = &mut tx;
                    typed::<$E, _>(async { $apply }).await?
                };
                dedupe_finish(tx, op, &answer).await.map_err($backend)?;
                answer
            }
        }
    }};
}

/// Pin an apply block's error type.
fn typed<E, F: std::future::Future<Output = Result<Vec<u64>, E>>>(f: F) -> F {
    f
}

/// How often (seconds) one instance sweeps `store_ops` past its retention.
const SWEEP_EVERY_SECS: u64 = 60;

/// A `u64` into a BIGINT, bit for bit.
fn bits(v: u64) -> i64 {
    v as i64
}

/// A BIGINT back into the `u64` it was written from.
fn unbits(v: i64) -> u64 {
    v as u64
}

fn pg(e: crate::pgwire::Error) -> String {
    render_pg_error(&e)
}

fn failed(e: RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

/// An op's answer, as `store_ops.answer` keeps it: its numbers, space-separated.
fn encode(answer: &[u64]) -> String {
    answer
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode(answer: &str) -> Option<Vec<u64>> {
    answer.split_whitespace().map(|n| n.parse().ok()).collect()
}

/// A slot's key: the cell key's fields, each rendered unambiguously (`Debug` quotes and escapes
/// the strings), so two different slots never share a row.
fn slot(k: &CellKey<'_>) -> String {
    let (dimension, class_key) = match k.dimension {
        Dimension::NanoUnits => (0, ""),
        Dimension::Requests => (1, ""),
        Dimension::Concurrency => (2, ""),
        Dimension::Class(c) => (3, c),
    };
    format!(
        "{:?}|{:?}|{dimension}|{class_key:?}|{}",
        k.bucket, k.pool, k.window_start
    )
}

/// The 1.5.5 admission test for one cell (`abi::store::ReserveIn`, GRANT SIZE): whether drawing
/// `amount` onto `used` under `cap` is refused. `used + amount` is checked: an overflow refuses.
fn exhausted(dimension: &Dimension<'_>, used: u64, amount: u64, cap: u64) -> bool {
    let Some(after) = used.checked_add(amount) else {
        return true;
    };
    match dimension {
        // DIM_CLASS: `tokens >= cap` — the draw that crosses the cap is granted whole.
        Dimension::Class(_) => used >= cap,
        // DIM_NANO_UNITS: `derived >= cap || derived + fee > cap`.
        Dimension::NanoUnits => used >= cap || after > cap,
        // DIM_REQUESTS / DIM_CONCURRENCY: `used + amount > cap`.
        Dimension::Requests | Dimension::Concurrency => after > cap,
    }
}

/// Whether an `op_id` is new, a replay (with its recorded answer), or a conflict.
enum Seen {
    New,
    Replay(Vec<u64>),
    Conflict,
}

/// Claim `op` for `body` inside `tx`: insert its row, or read the row a committed call left.
async fn claim(tx: &mut Transaction<'_>, op: OpId, body: &str) -> Result<Seen, String> {
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
        return Ok(Seen::New);
    }
    let row = tx
        .query_opt(
            "SELECT body, answer FROM store_ops WHERE op_id = $1",
            &[&id],
        )
        .await
        .map_err(pg)?;
    Ok(match row {
        Some(r) if r.get::<_, &str>(0) == body => match decode(r.get(1)) {
            Some(answer) => Seen::Replay(answer),
            None => Seen::Conflict,
        },
        Some(_) => Seen::Conflict,
        // Swept between the insert and the read (it was past retention): nothing applied, and a
        // retry claims the op afresh.
        None => return Err(format!("op_id {op:?} was swept while being claimed; retry")),
    })
}

/// Record a new op's answer on its dedupe row and commit the op's transaction.
async fn dedupe_finish(mut tx: Transaction<'_>, op: OpId, answer: &[u64]) -> Result<(), String> {
    let id: &[u8] = &op.0;
    tx.execute(
        "UPDATE store_ops SET answer = $2 WHERE op_id = $1",
        &[&id, &encode(answer)],
    )
    .await
    .map_err(pg)?;
    tx.commit().await.map_err(pg)
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
            .lock_client()
            .execute("DELETE FROM store_ops WHERE recorded_at < $1", &[&before])
            .await;
    }

    /// Begin an `op_id`-carrying write: sweep, open its transaction, claim the op.
    async fn dedupe_begin(
        &mut self,
        op: OpId,
        body: &str,
    ) -> Result<(Transaction<'_>, Seen), String> {
        self.sweep_ops().await;
        let mut tx = self.lock_client().transaction().await.map_err(pg)?;
        let seen = claim(&mut tx, op, body).await?;
        Ok((tx, seen))
    }

    async fn v3_add_usage(
        &mut self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> OpResult<()> {
        let body = format!("add_usage:{bucket:?}:{window_start}:{delta:?}");
        deduped!(
            self,
            op,
            &body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                Session::add_usage_in(tx, bucket, window_start, delta)
                    .await
                    .map_err(failed)?;
                Ok(Vec::new())
            }
        );
        Ok(())
    }

    async fn v3_add_metering(&mut self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        let body = format!("add_metering:{delta:?}");
        deduped!(
            self,
            op,
            &body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                Session::add_metering_in(tx, delta).await.map_err(failed)?;
                Ok(Vec::new())
            }
        );
        Ok(())
    }

    async fn v3_append_audit(&mut self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        let body = format!("append_audit:{entry:?}");
        deduped!(
            self,
            op,
            &body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                audit_in(tx, entry).await?;
                Ok(Vec::new())
            }
        );
        Ok(())
    }

    async fn v3_append_plane_record(
        &mut self,
        op: OpId,
        record: &busbar_contract::records::PlaneRecord,
    ) -> OpResult<()> {
        let body = format!("append_plane_record:{record:?}");
        deduped!(
            self,
            op,
            &body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                match Session::append_plane_record_in(tx, record)
                    .await
                    .map_err(failed)?
                {
                    true => Ok(Vec::new()),
                    false => Err(OpRefused::Failed(format!(
                    "append_plane_record: kind '{}' seq {} was freed between the insert and the \
                     read-back; the record was NOT stored",
                    record.kind, record.seq
                ))),
                }
            }
        );
        Ok(())
    }

    async fn v3_append_batch(
        &mut self,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> OpResult<Head> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let answer = deduped!(
            self,
            op,
            &body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                // One appender per stream at a time, fleet-wide: the head is read and extended under
                // the stream's transaction-scoped advisory lock.
                tx.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                    &[&stream],
                )
                .await
                .map_err(|e| OpRefused::Failed(pg(e)))?;
                let head: i64 = tx
                    .query_one(
                        "SELECT COALESCE(MAX(seq), 0) FROM store_journal WHERE stream = $1",
                        &[&stream],
                    )
                    .await
                    .map_err(|e| OpRefused::Failed(pg(e)))?
                    .get(0);
                let mut seq = head;
                for r in records {
                    seq += 1;
                    tx.execute(
                        "INSERT INTO store_journal (stream, seq, record) VALUES ($1, $2, $3)",
                        &[&stream, &seq, &r.as_slice()],
                    )
                    .await
                    .map_err(|e| OpRefused::Failed(pg(e)))?;
                }
                Ok(vec![unbits(seq), 0])
            }
        );
        match answer[..] {
            [seq, epoch] => Ok(Head { seq, epoch }),
            _ => Err(OpRefused::Conflict),
        }
    }

    async fn v3_heads(&mut self) -> Result<Vec<(String, Head)>, String> {
        let rows = self
            .lock_client()
            .query(
                "SELECT stream, MAX(seq) FROM store_journal GROUP BY stream ORDER BY stream",
                &[],
            )
            .await
            .map_err(pg)?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.get(0),
                    Head {
                        seq: unbits(r.get(1)),
                        epoch: 0,
                    },
                )
            })
            .collect())
    }

    async fn v3_session_put(
        &mut self,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Result<(), String> {
        self.lock_client()
            .execute(
                "INSERT INTO store_sessions (session, node, principal) VALUES ($1, $2, $3)
                 ON CONFLICT (session) DO UPDATE SET node = EXCLUDED.node,
                     principal = EXCLUDED.principal",
                &[&bits(session), &node, &principal],
            )
            .await
            .map(drop)
            .map_err(pg)
    }

    async fn v3_session_remove(&mut self, session: u64) -> Result<(), String> {
        self.lock_client()
            .execute(
                "DELETE FROM store_sessions WHERE session = $1",
                &[&bits(session)],
            )
            .await
            .map(drop)
            .map_err(pg)
    }

    async fn v3_sessions_for(&mut self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        let rows = self
            .lock_client()
            .query(
                "SELECT session, node FROM store_sessions WHERE principal = $1",
                &[&principal],
            )
            .await
            .map_err(pg)?;
        let mut sessions: Vec<(u64, String)> =
            rows.iter().map(|r| (unbits(r.get(0)), r.get(1))).collect();
        sessions.sort_unstable();
        Ok(sessions)
    }

    async fn v3_record_put(
        &mut self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        self.lock_client()
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
            .lock_client()
            .query_opt(
                "SELECT value FROM store_records WHERE schema_id = $1 AND key = $2",
                &[&schema, &key],
            )
            .await
            .map_err(pg)?;
        row.map(|r| record(r.get(0))).transpose()
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
            .lock_client()
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
            .map(|r| Ok((r.get(0), record(r.get(1))?)))
            .collect()
    }

    /// `reserve` over the cells' slots (each cell's slot key, its dimension and its amount).
    async fn v3_reserve(
        &mut self,
        op: OpId,
        body: &str,
        cells: &[(String, Dimension<'static>, u64)],
    ) -> Result<Vec<Grant>, ReserveRefused> {
        let unavailable = |_: String| ReserveRefused::Unavailable;
        let answer = deduped!(
            self,
            op,
            body,
            ReserveRefused::Conflict,
            unavailable,
            ReserveRefused,
            |tx| {
                let slots: Vec<String> = cells.iter().map(|c| c.0.clone()).collect();
                let rows = tx
                    .query(
                        "SELECT slot, cap, used FROM money_slots WHERE slot = ANY($1)
                     ORDER BY slot FOR UPDATE",
                        &[&slots],
                    )
                    .await
                    .map_err(|_| ReserveRefused::Unavailable)?;
                let mut held: std::collections::HashMap<String, (u64, u64)> = rows
                    .iter()
                    .map(|r| (r.get(0), (unbits(r.get(1)), unbits(r.get(2)))))
                    .collect();
                // The chain draw is all or nothing: each cell is tested against what the cells before
                // it in THIS draw add, and nothing is written until every cell passes.
                for (i, (s, dimension, amount)) in cells.iter().enumerate() {
                    let Some((cap, used)) = held.get_mut(s) else {
                        return Err(ReserveRefused::NoCap { cell: i as u32 });
                    };
                    if exhausted(dimension, *used, *amount, *cap) {
                        return Err(ReserveRefused::Exhausted { cell: i as u32 });
                    }
                    *used = used.saturating_add(*amount);
                }
                let mut answer = Vec::with_capacity(cells.len() * 3);
                for (s, _, amount) in cells {
                    tx.execute(
                        "UPDATE money_slots SET used = $2 WHERE slot = $1",
                        &[s, &bits(held[s].1)],
                    )
                    .await
                    .map_err(|_| ReserveRefused::Unavailable)?;
                    let id: i64 = tx
                        .query_one(
                            "INSERT INTO money_slices (slot, remaining) VALUES ($1, $2)
                         RETURNING slice_id",
                            &[s, &bits(*amount)],
                        )
                        .await
                        .map_err(|_| ReserveRefused::Unavailable)?
                        .get(0);
                    answer.extend([unbits(id), *amount, u64::MAX]);
                }
                Ok(answer)
            }
        );
        if answer.len() != cells.len() * 3 {
            return Err(ReserveRefused::Conflict);
        }
        Ok(answer
            .as_chunks::<3>()
            .0
            .iter()
            .map(|g| Grant {
                slice_id: g[0],
                granted: g[1],
                valid_until_ms: g[2],
            })
            .collect())
    }

    async fn v3_slice_release(
        &mut self,
        op: OpId,
        body: &str,
        items: &[(u64, u64)],
    ) -> OpResult<Vec<u64>> {
        let answer = deduped!(
            self,
            op,
            body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                let mut back_all = Vec::with_capacity(items.len());
                let mut seen = std::collections::HashSet::new();
                for &(id, unspent) in items {
                    let row = tx
                    .query_opt(
                        "SELECT slot, remaining FROM money_slices WHERE slice_id = $1 FOR UPDATE",
                        &[&bits(id)],
                    )
                    .await
                    .map_err(|e| OpRefused::Failed(pg(e)))?;
                    let Some(row) = row else {
                        // An item naming a slice an EARLIER item of this call closed answers 0; any
                        // other unknown slice fails the whole release.
                        if seen.contains(&id) {
                            back_all.push(0);
                            continue;
                        }
                        return Err(OpRefused::Failed(format!(
                            "slice_release: slice {id} is not held"
                        )));
                    };
                    seen.insert(id);
                    let s: String = row.get(0);
                    let left = unbits(row.get(1));
                    let back = unspent.min(left);
                    let closed = if left == back {
                        tx.execute("DELETE FROM money_slices WHERE slice_id = $1", &[&bits(id)])
                            .await
                    } else {
                        tx.execute(
                            "UPDATE money_slices SET remaining = $2 WHERE slice_id = $1",
                            &[&bits(id), &bits(left - back)],
                        )
                        .await
                    };
                    closed.map_err(|e| OpRefused::Failed(pg(e)))?;
                    let used = tx
                        .query_opt(
                            "SELECT used FROM money_slots WHERE slot = $1 FOR UPDATE",
                            &[&s],
                        )
                        .await
                        .map_err(|e| OpRefused::Failed(pg(e)))?;
                    if let Some(used) = used {
                        tx.execute(
                            "UPDATE money_slots SET used = $2 WHERE slot = $1",
                            &[&s, &bits(unbits(used.get(0)).saturating_sub(back))],
                        )
                        .await
                        .map_err(|e| OpRefused::Failed(pg(e)))?;
                    }
                    back_all.push(back);
                }
                Ok(back_all)
            }
        );
        if answer.len() != items.len() {
            return Err(OpRefused::Conflict);
        }
        Ok(answer)
    }

    async fn v3_add_usage_batch(
        &mut self,
        op: OpId,
        body: &str,
        cells: &[(String, u64, UsageDelta)],
    ) -> OpResult<()> {
        deduped!(
            self,
            op,
            body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                for (bucket, window, delta) in cells {
                    Session::add_usage_in(tx, bucket, *window, delta)
                        .await
                        .map_err(failed)?;
                }
                Ok(Vec::new())
            }
        );
        Ok(())
    }

    async fn v3_add_metering_batch(&mut self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        deduped!(
            self,
            op,
            &body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                for d in deltas {
                    Session::add_metering_in(tx, d).await.map_err(failed)?;
                }
                Ok(Vec::new())
            }
        );
        Ok(())
    }

    async fn v3_append_audit_batch(&mut self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
        let body = format!("append_audit_batch:{entries:?}");
        // One transaction: a fork anywhere (against a stored seq or an earlier entry of this batch)
        // rolls the whole batch back.
        deduped!(
            self,
            op,
            &body,
            OpRefused::Conflict,
            OpRefused::Failed,
            OpRefused,
            |tx| {
                for e in entries {
                    audit_in(tx, e).await?;
                }
                Ok(Vec::new())
            }
        );
        Ok(())
    }

    /// `window_caps` over the caps' slots (each cap's slot key, cap and config generation).
    async fn v3_window_caps(
        &mut self,
        op: OpId,
        body: &str,
        caps: &[(String, u64, u64)],
    ) -> Result<(), CapsRefused> {
        deduped!(
            self,
            op,
            body,
            CapsRefused::Conflict,
            CapsRefused::Failed,
            CapsRefused,
            |tx| {
                let fail = |e: crate::pgwire::Error| CapsRefused::Failed(pg(e));
                // Atomic per push: every cap is checked (against the stored cap and the ones before it
                // in this push) before the push's transaction commits; the first conflict rolls it all
                // back.
                for (index, (s, cap_value, config_gen)) in caps.iter().enumerate() {
                    let stored = tx
                        .query_opt(
                            "SELECT cap, config_gen FROM money_slots WHERE slot = $1 FOR UPDATE",
                            &[s],
                        )
                        .await
                        .map_err(fail)?
                        .map(|r| (unbits(r.get(0)), unbits(r.get(1))));
                    match stored {
                        Some((cap, gen)) if gen == *config_gen && cap != *cap_value => {
                            return Err(CapsRefused::CapConflict { index });
                        }
                        Some((_, gen)) if gen >= *config_gen => {}
                        _ => {
                            tx.execute(
                            "INSERT INTO money_slots (slot, cap, config_gen, used) VALUES ($1, $2, $3, 0)
                             ON CONFLICT (slot) DO UPDATE SET cap = EXCLUDED.cap,
                                 config_gen = EXCLUDED.config_gen",
                            &[s, &bits(*cap_value), &bits(*config_gen)],
                        )
                        .await
                        .map_err(fail)?;
                        }
                    }
                }
                Ok(Vec::new())
            }
        );
        Ok(())
    }
}

/// An audit append inside an op's transaction: a vanished conflicting row is a failure here (the
/// transaction cannot be retried from inside), never a success.
async fn audit_in(tx: &mut Transaction<'_>, entry: &AuditRecord) -> OpResult<()> {
    match Session::append_audit_in(tx, entry).await.map_err(failed)? {
        true => Ok(()),
        false => Err(OpRefused::Failed(format!(
            "append_audit: seq {} was freed between the insert and the read-back; the record was \
             NOT stored",
            entry.seq
        ))),
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
    v.get("url")
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            "postgres plugin config requires a \"url\" (a libpq connection string)".to_string()
        })
}

/// A dimension, owned for an op that runs across entries (only its variant is read).
fn dimension_kind(d: &Dimension<'_>) -> Dimension<'static> {
    match d {
        Dimension::NanoUnits => Dimension::NanoUnits,
        Dimension::Requests => Dimension::Requests,
        Dimension::Concurrency => Dimension::Concurrency,
        Dimension::Class(_) => Dimension::Class(""),
    }
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

    /// Reach the server and ensure the schema (1.5.5's connect + migrate, at the same moment: the
    /// load), in the driver's words when it cannot.
    fn connect(&self, cx: &mut Op<'_>) -> Step<Result<(), String>> {
        on_conn!(self, cx, |e| e, |s| s.migrate().await.map_err(|e| e.0))
    }

    fn add_usage_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Step<OpResult<()>> {
        let (bucket, delta) = (bucket.to_owned(), delta.clone());
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_add_usage(op, &bucket, window_start, &delta)
            .await)
    }

    fn add_metering_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        delta: &MeteringDelta,
    ) -> Step<OpResult<()>> {
        let delta = delta.clone();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_add_metering(op, &delta)
            .await)
    }

    fn append_audit_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entry: &AuditRecord,
    ) -> Step<OpResult<()>> {
        let entry = entry.clone();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_append_audit(op, &entry)
            .await)
    }

    fn append_plane_record_op(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Step<OpResult<()>> {
        let record = record.to_record();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_append_plane_record(op, &record)
            .await)
    }

    fn append_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        stream: &str,
        records: &[RecordBytes],
    ) -> Step<OpResult<Head>> {
        let (stream, records) = (stream.to_owned(), records.to_vec());
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_append_batch(op, &stream, &records)
            .await)
    }

    fn heads(&self, cx: &mut Op<'_>) -> Step<Result<Vec<(String, Head)>, String>> {
        on_conn!(self, cx, |e| e, |s| s.v3_heads().await)
    }

    fn session_put(
        &self,
        cx: &mut Op<'_>,
        session: u64,
        node: &str,
        principal: &str,
    ) -> Step<Result<(), String>> {
        let (node, principal) = (node.to_owned(), principal.to_owned());
        on_conn!(self, cx, |e| e, |s| s
            .v3_session_put(session, &node, &principal)
            .await)
    }

    fn session_remove(&self, cx: &mut Op<'_>, session: u64) -> Step<Result<(), String>> {
        on_conn!(self, cx, |e| e, |s| s.v3_session_remove(session).await)
    }

    fn sessions_for(
        &self,
        cx: &mut Op<'_>,
        principal: &str,
    ) -> Step<Result<Vec<(u64, String)>, String>> {
        let principal = principal.to_owned();
        on_conn!(self, cx, |e| e, |s| s.v3_sessions_for(&principal).await)
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

    fn reserve<'c>(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Step<Result<(), ReserveRefused>> {
        let cells: Vec<Cell<'_>> = cells.collect();
        let body = format!("reserve:{epoch}:{cells:?}");
        let owned: Vec<(String, Dimension<'static>, u64)> = cells
            .iter()
            .map(|c| (slot(&c.key), dimension_kind(&c.key.dimension), c.amount))
            .collect();
        let step = on_conn!(self, cx, |_: String| ReserveRefused::Unavailable, |s| s
            .v3_reserve(op, &body, &owned)
            .await);
        match step {
            Step::Ready(Ok(g)) => {
                grants.extend(g);
                Step::Ready(Ok(()))
            }
            Step::Ready(Err(e)) => Step::Ready(Err(e)),
            Step::Pending { wake_at_ns } => Step::Pending { wake_at_ns },
        }
    }

    fn slice_release(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> Step<OpResult<()>> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        let step = on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_slice_release(op, &body, &items)
            .await);
        match step {
            Step::Ready(Ok(back)) => {
                released.extend(back);
                Step::Ready(Ok(()))
            }
            Step::Ready(Err(e)) => Step::Ready(Err(e)),
            Step::Pending { wake_at_ns } => Step::Pending { wake_at_ns },
        }
    }

    fn add_usage_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Step<OpResult<()>> {
        let body = format!("add_usage_batch:{cells:?}");
        let cells: Vec<(String, u64, UsageDelta)> = cells
            .iter()
            .map(|(b, w, d)| ((*b).to_owned(), *w, d.clone()))
            .collect();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_add_usage_batch(op, &body, &cells)
            .await)
    }

    fn add_metering_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Step<OpResult<()>> {
        let deltas = deltas.to_vec();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_add_metering_batch(op, &deltas)
            .await)
    }

    fn append_audit_batch(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        entries: &[AuditRecord],
    ) -> Step<OpResult<()>> {
        let entries = entries.to_vec();
        on_conn!(self, cx, OpRefused::Failed, |s| s
            .v3_append_audit_batch(op, &entries)
            .await)
    }

    fn window_caps(
        &self,
        cx: &mut Op<'_>,
        op: OpId,
        caps: &[Cap<'_>],
    ) -> Step<Result<(), CapsRefused>> {
        let body = format!("window_caps:{caps:?}");
        let caps: Vec<(String, u64, u64)> = caps
            .iter()
            .map(|c| (slot(&c.key), c.cap, c.config_gen))
            .collect();
        on_conn!(self, cx, CapsRefused::Failed, |s| s
            .v3_window_caps(op, &body, &caps)
            .await)
    }

    // ── the 1.5.5 op set (slots 0-32): each the 1.5.5 body, on the op's connection ──────────

    fn put_key(&self, cx: &mut Op<'_>, key: &VirtualKey) -> Step<RecordStoreResult<()>> {
        let key = key.clone();
        on_conn!(self, cx, RecordStoreError, |s| s.put_key(&key).await)
    }

    fn get_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<Option<VirtualKey>>> {
        let id = id.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s.get_key(&id).await)
    }

    fn list_keys(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        on_conn!(self, cx, RecordStoreError, |s| s.list_keys().await)
    }

    fn delete_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        let id = id.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s.delete_key(&id).await)
    }

    fn scrub_key(&self, cx: &mut Op<'_>, id: &str) -> Step<RecordStoreResult<()>> {
        let id = id.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s.scrub_key(&id).await)
    }

    fn list_keys_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<VirtualKey>>> {
        on_conn!(self, cx, RecordStoreError, |s| s
            .list_keys_since(since)
            .await)
    }

    fn get_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
    ) -> Step<RecordStoreResult<UsageLedger>> {
        let bucket_id = bucket_id.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s
            .get_usage(&bucket_id, window_start)
            .await)
    }

    fn put_usage(
        &self,
        cx: &mut Op<'_>,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> Step<RecordStoreResult<()>> {
        let (bucket_id, ledger) = (bucket_id.to_owned(), ledger.clone());
        on_conn!(self, cx, RecordStoreError, |s| s
            .put_usage(&bucket_id, window_start, &ledger)
            .await)
    }

    fn list_metering(
        &self,
        cx: &mut Op<'_>,
        bucket: u64,
    ) -> Step<RecordStoreResult<Vec<MeteringRow>>> {
        on_conn!(self, cx, RecordStoreError, |s| s
            .list_metering(bucket)
            .await)
    }

    fn purge_windows_before(&self, cx: &mut Op<'_>, before: u64) -> Step<RecordStoreResult<u64>> {
        on_conn!(self, cx, RecordStoreError, |s| s
            .purge_windows_before(before)
            .await)
    }

    fn purge_metering_before(&self, cx: &mut Op<'_>, bucket: &str) -> Step<RecordStoreResult<u64>> {
        let bucket = bucket.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s
            .purge_metering_before(&bucket)
            .await)
    }

    fn put_credential(
        &self,
        cx: &mut Op<'_>,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let secret = secret.clone();
        on_conn!(self, cx, RecordStoreError, |s| s
            .put_credential(&secret)
            .await)
    }

    fn put_key_with_credential(
        &self,
        cx: &mut Op<'_>,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> Step<RecordStoreResult<()>> {
        let (key, secret) = (key.clone(), secret.clone());
        on_conn!(self, cx, RecordStoreError, |s| s
            .put_key_with_credential(&key, &secret)
            .await)
    }

    fn list_credentials(
        &self,
        cx: &mut Op<'_>,
        key_id: &str,
    ) -> Step<RecordStoreResult<Vec<CredentialMeta>>> {
        let key_id = key_id.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s
            .list_credentials(&key_id)
            .await)
    }

    fn lookup_credential_secret(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        public_id: &str,
    ) -> Step<RecordStoreResult<Option<CredentialSecret>>> {
        let (kind, public_id) = (kind.to_owned(), public_id.to_owned());
        on_conn!(self, cx, RecordStoreError, |s| s
            .lookup_credential_secret(&kind, &public_id)
            .await)
    }

    fn revoke_credential(
        &self,
        cx: &mut Op<'_>,
        id: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (id, reason) = (id.to_owned(), reason.to_owned());
        on_conn!(self, cx, RecordStoreError, |s| s
            .revoke_credential(&id, &reason)
            .await)
    }

    fn list_credentials_since(
        &self,
        cx: &mut Op<'_>,
        since: u64,
    ) -> Step<RecordStoreResult<Vec<CredentialSecret>>> {
        on_conn!(self, cx, RecordStoreError, |s| s
            .list_credentials_since(since)
            .await)
    }

    fn list_audit(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        on_conn!(self, cx, RecordStoreError, |s| s.list_audit().await)
    }

    fn add_denylist(
        &self,
        cx: &mut Op<'_>,
        sub: &str,
        reason: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (sub, reason) = (sub.to_owned(), reason.to_owned());
        on_conn!(self, cx, RecordStoreError, |s| s
            .add_denylist(&sub, &reason)
            .await)
    }

    fn list_denylist(&self, cx: &mut Op<'_>) -> Step<RecordStoreResult<Vec<String>>> {
        on_conn!(self, cx, RecordStoreError, |s| s.list_denylist().await)
    }

    fn list_audit_tail(
        &self,
        cx: &mut Op<'_>,
        limit: u64,
    ) -> Step<RecordStoreResult<Vec<AuditRecord>>> {
        on_conn!(self, cx, RecordStoreError, |s| s
            .list_audit_tail(limit)
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

    fn get_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<Option<Vec<u8>>>> {
        let (kind, id) = (kind.to_owned(), id.to_owned());
        on_conn!(self, cx, RecordStoreError, |s| s
            .get_plane_record(&kind, &id)
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

    fn list_plane_record_parents(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
    ) -> Step<RecordStoreResult<Vec<String>>> {
        let kind = kind.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s
            .list_plane_record_parents(&kind)
            .await)
    }

    fn purge_plane_records_before(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        before: u64,
    ) -> Step<RecordStoreResult<u64>> {
        let kind = kind.to_owned();
        on_conn!(self, cx, RecordStoreError, |s| s
            .purge_plane_records_before(&kind, before)
            .await)
    }

    fn delete_plane_record(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        id: &str,
    ) -> Step<RecordStoreResult<()>> {
        let (kind, id) = (kind.to_owned(), id.to_owned());
        on_conn!(self, cx, RecordStoreError, |s| s
            .delete_plane_record(&kind, &id)
            .await)
    }

    fn redeem_plane_token(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        let (kind, token) = (kind.to_owned(), token.to_owned());
        on_conn!(self, cx, RecordStoreError, |s| s
            .redeem_plane_token(&kind, &token, expires_at, now)
            .await)
    }

    fn plane_token_live(
        &self,
        cx: &mut Op<'_>,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Step<RecordStoreResult<bool>> {
        let (kind, token) = (kind.to_owned(), token.to_owned());
        on_conn!(self, cx, RecordStoreError, |s| s
            .plane_token_live(&kind, &token, expires_at, now)
            .await)
    }
}
