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
//! Every `u64` the ABI hands this module is stored BIT-FOR-BIT in a BIGINT (`as i64` / `as u64`)
//! and every comparison runs here, never in SQL, so no value is clamped or wrapped on the way back.

use std::sync::atomic::Ordering;

use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, OpResult, ReserveRefused,
    StoreSlots, Tail,
};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::{Head, RecordBytes};
use busbar_contract::records::{
    AuditRecord, MeteringDelta, PlaneRecordRef, RecordStoreError, UsageDelta,
};
use postgres::Transaction;

use crate::{now_secs, render_pg_error, PostgresStore, NAME};

busbar_contract::store_door!(PostgresStore, NAME, env!("CARGO_PKG_VERSION"), 64);

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

fn pg(e: postgres::Error) -> String {
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
fn claim(tx: &mut Transaction<'_>, op: OpId, body: &str) -> Result<Seen, String> {
    let id: &[u8] = &op.0;
    let inserted = tx
        .execute(
            "INSERT INTO store_ops (op_id, body, answer, recorded_at) VALUES ($1, $2, '', $3)
             ON CONFLICT (op_id) DO NOTHING",
            &[&id, &body, &bits(now_secs())],
        )
        .map_err(pg)?;
    if inserted == 1 {
        return Ok(Seen::New);
    }
    let row = tx
        .query_opt(
            "SELECT body, answer FROM store_ops WHERE op_id = $1",
            &[&id],
        )
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

impl PostgresStore {
    /// Forget every `op_id` past its retention, at most once per [`SWEEP_EVERY_SECS`].
    fn sweep_ops(&self) {
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
            .execute("DELETE FROM store_ops WHERE recorded_at < $1", &[&before]);
    }

    /// Run one `op_id`-carrying write in ONE transaction with its dedupe row: a replay answers the
    /// original, a conflict applies nothing, and a new op runs `apply` and is remembered only if it
    /// applied (an error rolls the row back with the effect).
    fn deduped<E>(
        &self,
        op: OpId,
        body: &str,
        conflict: E,
        backend: fn(String) -> E,
        apply: impl FnOnce(&mut Transaction<'_>) -> Result<Vec<u64>, E>,
    ) -> Result<Vec<u64>, E> {
        self.sweep_ops();
        let mut client = self.lock();
        let mut tx = client.transaction().map_err(|e| backend(pg(e)))?;
        match claim(&mut tx, op, body).map_err(backend)? {
            Seen::Replay(answer) => Ok(answer),
            Seen::Conflict => Err(conflict),
            Seen::New => {
                let answer = apply(&mut tx)?;
                let id: &[u8] = &op.0;
                tx.execute(
                    "UPDATE store_ops SET answer = $2 WHERE op_id = $1",
                    &[&id, &encode(&answer)],
                )
                .map_err(|e| backend(pg(e)))?;
                tx.commit().map_err(|e| backend(pg(e)))?;
                Ok(answer)
            }
        }
    }

    fn op(
        &self,
        op: OpId,
        body: &str,
        apply: impl FnOnce(&mut Transaction<'_>) -> OpResult<()>,
    ) -> OpResult<()> {
        self.deduped(op, body, OpRefused::Conflict, OpRefused::Failed, |tx| {
            apply(tx).map(|()| Vec::new())
        })
        .map(drop)
    }
}

/// An audit append inside an op's transaction: a vanished conflicting row is a failure here (the
/// transaction cannot be retried from inside), never a success.
fn audit_in(tx: &mut Transaction<'_>, entry: &AuditRecord) -> OpResult<()> {
    match PostgresStore::append_audit_in(tx, entry).map_err(failed)? {
        true => Ok(()),
        false => Err(OpRefused::Failed(format!(
            "append_audit: seq {} was freed between the insert and the read-back; the record was \
             NOT stored",
            entry.seq
        ))),
    }
}

impl StoreSlots for PostgresStore {
    const TAIL: Tail = Tail {
        ephemeral: false,
        durable_plane: true,
        fork_refusal: true,
    };

    /// Open from the store section's settings:
    ///
    /// ```json
    /// { "url": "postgres://user:pass@host:5432/busbar" }
    /// ```
    fn open(settings: &[u8]) -> Result<Self, String> {
        let v: serde_json::Value = if settings.trim_ascii().is_empty() {
            serde_json::Value::Object(Default::default())
        } else {
            serde_json::from_slice(settings)
                .map_err(|e| format!("invalid postgres plugin config: {e}"))?
        };
        let url = v
            .get("url")
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "postgres plugin config requires a \"url\" (a libpq connection string)".to_string()
            })?;
        PostgresStore::connect(url).map_err(|e| e.0)
    }

    fn add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> OpResult<()> {
        let body = format!("add_usage:{bucket:?}:{window_start}:{delta:?}");
        self.op(op, &body, |tx| {
            Self::add_usage_in(tx, bucket, window_start, delta).map_err(failed)
        })
    }

    fn add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> OpResult<()> {
        let body = format!("add_metering:{delta:?}");
        self.op(op, &body, |tx| {
            Self::add_metering_in(tx, delta).map_err(failed)
        })
    }

    fn append_audit_op(&self, op: OpId, entry: &AuditRecord) -> OpResult<()> {
        let body = format!("append_audit:{entry:?}");
        self.op(op, &body, |tx| audit_in(tx, entry))
    }

    fn append_plane_record_op(&self, op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()> {
        let record = record.to_record();
        let body = format!("append_plane_record:{record:?}");
        self.op(op, &body, |tx| {
            match Self::append_plane_record_in(tx, &record).map_err(failed)? {
                true => Ok(()),
                false => Err(OpRefused::Failed(format!(
                    "append_plane_record: kind '{}' seq {} was freed between the insert and the \
                     read-back; the record was NOT stored",
                    record.kind, record.seq
                ))),
            }
        })
    }

    fn append_batch(&self, op: OpId, stream: &str, records: &[RecordBytes]) -> OpResult<Head> {
        let body = format!("append_batch:{stream:?}:{records:?}");
        let answer = self.deduped(op, &body, OpRefused::Conflict, OpRefused::Failed, |tx| {
            // One appender per stream at a time, fleet-wide: the head is read and extended under
            // the stream's transaction-scoped advisory lock.
            tx.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
                &[&stream],
            )
            .map_err(|e| OpRefused::Failed(pg(e)))?;
            let head: i64 = tx
                .query_one(
                    "SELECT COALESCE(MAX(seq), 0) FROM store_journal WHERE stream = $1",
                    &[&stream],
                )
                .map_err(|e| OpRefused::Failed(pg(e)))?
                .get(0);
            let mut seq = head;
            for r in records {
                seq += 1;
                tx.execute(
                    "INSERT INTO store_journal (stream, seq, record) VALUES ($1, $2, $3)",
                    &[&stream, &seq, &r.as_slice()],
                )
                .map_err(|e| OpRefused::Failed(pg(e)))?;
            }
            Ok(vec![unbits(seq), 0])
        })?;
        match answer[..] {
            [seq, epoch] => Ok(Head { seq, epoch }),
            _ => Err(OpRefused::Conflict),
        }
    }

    fn heads(&self) -> Result<Vec<(String, Head)>, String> {
        let rows = self
            .lock()
            .query(
                "SELECT stream, MAX(seq) FROM store_journal GROUP BY stream ORDER BY stream",
                &[],
            )
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

    fn session_put(&self, session: u64, node: &str, principal: &str) -> Result<(), String> {
        self.lock()
            .execute(
                "INSERT INTO store_sessions (session, node, principal) VALUES ($1, $2, $3)
                 ON CONFLICT (session) DO UPDATE SET node = EXCLUDED.node,
                     principal = EXCLUDED.principal",
                &[&bits(session), &node, &principal],
            )
            .map(drop)
            .map_err(pg)
    }

    fn session_remove(&self, session: u64) -> Result<(), String> {
        self.lock()
            .execute(
                "DELETE FROM store_sessions WHERE session = $1",
                &[&bits(session)],
            )
            .map(drop)
            .map_err(pg)
    }

    fn sessions_for(&self, principal: &str) -> Result<Vec<(u64, String)>, String> {
        let rows = self
            .lock()
            .query(
                "SELECT session, node FROM store_sessions WHERE principal = $1",
                &[&principal],
            )
            .map_err(pg)?;
        let mut sessions: Vec<(u64, String)> =
            rows.iter().map(|r| (unbits(r.get(0)), r.get(1))).collect();
        sessions.sort_unstable();
        Ok(sessions)
    }

    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.lock()
            .execute(
                "INSERT INTO store_records (schema_id, key, value) VALUES ($1, $2, $3)
                 ON CONFLICT (schema_id, key) DO UPDATE SET value = EXCLUDED.value",
                &[&schema, &key, &value],
            )
            .map(drop)
            .map_err(pg)
    }

    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        let row = self
            .lock()
            .query_opt(
                "SELECT value FROM store_records WHERE schema_id = $1 AND key = $2",
                &[&schema, &key],
            )
            .map_err(pg)?;
        row.map(|r| record(r.get(0))).transpose()
    }

    fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
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
            .map_err(pg)?;
        rows.iter()
            .map(|r| Ok((r.get(0), record(r.get(1))?)))
            .collect()
    }

    fn reserve<'c>(
        &self,
        op: OpId,
        epoch: u64,
        cells: impl Iterator<Item = Cell<'c>> + Clone,
        grants: &mut impl Extend<Grant>,
    ) -> Result<(), ReserveRefused> {
        let cells: Vec<Cell<'_>> = cells.collect();
        let body = format!("reserve:{epoch}:{cells:?}");
        let unavailable = |_: String| ReserveRefused::Unavailable;
        let answer = self.deduped(op, &body, ReserveRefused::Conflict, unavailable, |tx| {
            let slots: Vec<String> = cells.iter().map(|c| slot(&c.key)).collect();
            let rows = tx
                .query(
                    "SELECT slot, cap, used FROM money_slots WHERE slot = ANY($1)
                     ORDER BY slot FOR UPDATE",
                    &[&slots],
                )
                .map_err(|_| ReserveRefused::Unavailable)?;
            let mut held: std::collections::HashMap<String, (u64, u64)> = rows
                .iter()
                .map(|r| (r.get(0), (unbits(r.get(1)), unbits(r.get(2)))))
                .collect();
            // The chain draw is all or nothing: each cell is tested against what the cells before
            // it in THIS draw add, and nothing is written until every cell passes.
            for (i, (c, s)) in cells.iter().zip(&slots).enumerate() {
                let Some((cap, used)) = held.get_mut(s) else {
                    return Err(ReserveRefused::NoCap { cell: i as u32 });
                };
                if exhausted(&c.key.dimension, *used, c.amount, *cap) {
                    return Err(ReserveRefused::Exhausted { cell: i as u32 });
                }
                *used = used.saturating_add(c.amount);
            }
            let mut answer = Vec::with_capacity(cells.len() * 3);
            for (c, s) in cells.iter().zip(&slots) {
                tx.execute(
                    "UPDATE money_slots SET used = $2 WHERE slot = $1",
                    &[s, &bits(held[s].1)],
                )
                .map_err(|_| ReserveRefused::Unavailable)?;
                let id: i64 = tx
                    .query_one(
                        "INSERT INTO money_slices (slot, remaining) VALUES ($1, $2)
                         RETURNING slice_id",
                        &[s, &bits(c.amount)],
                    )
                    .map_err(|_| ReserveRefused::Unavailable)?
                    .get(0);
                answer.extend([unbits(id), c.amount, u64::MAX]);
            }
            Ok(answer)
        })?;
        if answer.len() != cells.len() * 3 {
            return Err(ReserveRefused::Conflict);
        }
        grants.extend(answer.chunks_exact(3).map(|g| Grant {
            slice_id: g[0],
            granted: g[1],
            valid_until_ms: g[2],
        }));
        Ok(())
    }

    fn slice_release(
        &self,
        op: OpId,
        epoch: u64,
        items: impl Iterator<Item = (u64, u64)> + Clone,
        released: &mut impl Extend<u64>,
    ) -> OpResult<()> {
        let items: Vec<(u64, u64)> = items.collect();
        let body = format!("slice_release:{epoch}:{items:?}");
        let answer = self.deduped(op, &body, OpRefused::Conflict, OpRefused::Failed, |tx| {
            let mut back_all = Vec::with_capacity(items.len());
            let mut seen = std::collections::HashSet::new();
            for &(id, unspent) in &items {
                let row = tx
                    .query_opt(
                        "SELECT slot, remaining FROM money_slices WHERE slice_id = $1 FOR UPDATE",
                        &[&bits(id)],
                    )
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
                } else {
                    tx.execute(
                        "UPDATE money_slices SET remaining = $2 WHERE slice_id = $1",
                        &[&bits(id), &bits(left - back)],
                    )
                };
                closed.map_err(|e| OpRefused::Failed(pg(e)))?;
                let used = tx
                    .query_opt(
                        "SELECT used FROM money_slots WHERE slot = $1 FOR UPDATE",
                        &[&s],
                    )
                    .map_err(|e| OpRefused::Failed(pg(e)))?;
                if let Some(used) = used {
                    tx.execute(
                        "UPDATE money_slots SET used = $2 WHERE slot = $1",
                        &[&s, &bits(unbits(used.get(0)).saturating_sub(back))],
                    )
                    .map_err(|e| OpRefused::Failed(pg(e)))?;
                }
                back_all.push(back);
            }
            Ok(back_all)
        })?;
        if answer.len() != items.len() {
            return Err(OpRefused::Conflict);
        }
        released.extend(answer);
        Ok(())
    }

    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        let body = format!("add_usage_batch:{cells:?}");
        self.op(op, &body, |tx| {
            for (bucket, window, delta) in cells {
                Self::add_usage_in(tx, bucket, *window, delta).map_err(failed)?;
            }
            Ok(())
        })
    }

    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = format!("add_metering_batch:{deltas:?}");
        self.op(op, &body, |tx| {
            for d in deltas {
                Self::add_metering_in(tx, d).map_err(failed)?;
            }
            Ok(())
        })
    }

    fn append_audit_batch(&self, op: OpId, entries: &[AuditRecord]) -> OpResult<()> {
        let body = format!("append_audit_batch:{entries:?}");
        // One transaction: a fork anywhere (against a stored seq or an earlier entry of this batch)
        // rolls the whole batch back.
        self.op(op, &body, |tx| {
            for e in entries {
                audit_in(tx, e)?;
            }
            Ok(())
        })
    }

    fn window_caps(&self, op: OpId, caps: &[Cap<'_>]) -> Result<(), CapsRefused> {
        let body = format!("window_caps:{caps:?}");
        self.deduped(op, &body, CapsRefused::Conflict, CapsRefused::Failed, |tx| {
            let fail = |e: postgres::Error| CapsRefused::Failed(pg(e));
            // Atomic per push: every cap is checked (against the stored cap and the ones before it
            // in this push) before the push's transaction commits; the first conflict rolls it all
            // back.
            for (index, c) in caps.iter().enumerate() {
                let s = slot(&c.key);
                let stored = tx
                    .query_opt(
                        "SELECT cap, config_gen FROM money_slots WHERE slot = $1 FOR UPDATE",
                        &[&s],
                    )
                    .map_err(fail)?
                    .map(|r| (unbits(r.get(0)), unbits(r.get(1))));
                match stored {
                    Some((cap, gen)) if gen == c.config_gen && cap != c.cap => {
                        return Err(CapsRefused::CapConflict { index });
                    }
                    Some((_, gen)) if gen >= c.config_gen => {}
                    _ => {
                        tx.execute(
                            "INSERT INTO money_slots (slot, cap, config_gen, used) VALUES ($1, $2, $3, 0)
                             ON CONFLICT (slot) DO UPDATE SET cap = EXCLUDED.cap,
                                 config_gen = EXCLUDED.config_gen",
                            &[&s, &bits(c.cap), &bits(c.config_gen)],
                        )
                        .map_err(fail)?;
                    }
                }
            }
            Ok(Vec::new())
        })
        .map(drop)
    }
}

/// A stored record's bytes as the table's bounded record.
fn record(bytes: Vec<u8>) -> Result<RecordBytes, String> {
    RecordBytes::new(bytes).map_err(|n| format!("a stored record of {n} bytes is over the ceiling"))
}
