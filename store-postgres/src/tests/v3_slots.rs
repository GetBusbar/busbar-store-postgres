// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live Postgres: durable `op_id` dedupe (S1-S4)
//! across a reconnect, the money slots (`window_caps`, `reserve`, `slice_release`), the journal
//! (`append_batch`, `heads`), sessions and the kernel-held records. Every name is namespaced per
//! run, so the shared test database never carries one run's rows into another's assertions.

use super::*;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, ReserveRefused, StoreSlots,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use std::sync::atomic::{AtomicU64, Ordering};

/// A namespace unique to this run.
fn ns() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("v3-{}-{nanos}", std::process::id())
}

/// A fresh `op_id` per call, unique across runs (the node half is the run's clock).
fn op() -> OpId {
    static N: AtomicU64 = AtomicU64::new(0);
    let node = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    OpId::from_parts(node, N.fetch_add(1, Ordering::Relaxed))
}

fn store(url: &str) -> PostgresStore {
    connect_store_with_retry(url).expect("connect")
}

fn requests(bucket: &str) -> CellKey<'_> {
    CellKey {
        bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start: 1_790_000_000_000,
    }
}

fn reserve(s: &PostgresStore, op: OpId, cells: &[Cell<'_>]) -> Result<Vec<Grant>, ReserveRefused> {
    let mut grants = Vec::new();
    s.reserve(op, 0, cells.iter().copied(), &mut grants)
        .map(|()| grants)
}

fn release(s: &PostgresStore, op: OpId, items: &[(u64, u64)]) -> Result<Vec<u64>, OpRefused> {
    let mut back = Vec::new();
    s.slice_release(op, 0, items.iter().copied(), &mut back)
        .map(|()| back)
}

/// `open` is the settings' judge: the 1.5.5 refusals, in the store's own words.
#[test]
fn open_refuses_settings_without_a_url() {
    let want = "postgres plugin config requires a \"url\" (a libpq connection string)";
    for settings in [
        &b""[..],
        &b"  "[..],
        &b"{}"[..],
        &br#"{"url": 5}"#[..],
        &br#"{"url": "  "}"#[..],
    ] {
        assert_eq!(
            PostgresStore::open(settings).err().as_deref(),
            Some(want),
            "{settings:?}"
        );
    }
    let e = PostgresStore::open(b"{ not json").err().unwrap();
    assert!(e.starts_with("invalid postgres plugin config:"), "{e}");
}

/// S1/S2/S3/S4: a replay applies nothing and answers the original, a different body is a
/// conflict, a failed op is not recorded, and the log survives a reconnect.
#[test]
fn an_op_id_dedupes_durably_across_a_reconnect() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let bucket = format!("{ns}-b");
    // A window no parallel test's `purge_windows_before` cutoff reaches.
    const WINDOW: u64 = 4_000_000_000_000_000;
    let a = store(&url);
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        ..Default::default()
    };
    let id = op();
    a.add_usage_op(id, &bucket, WINDOW, &delta)
        .expect("applied");
    a.add_usage_op(id, &bucket, WINDOW, &delta)
        .expect("replayed");
    let other = UsageDelta {
        requests: 2,
        ..Default::default()
    };
    assert_eq!(
        a.add_usage_op(id, &bucket, WINDOW, &other),
        Err(OpRefused::Conflict)
    );
    drop(a);

    let b = store(&url);
    b.add_usage_op(id, &bucket, WINDOW, &delta)
        .expect("replayed after a reconnect");
    assert_eq!(
        b.get_usage(&bucket, WINDOW).expect("read").requests,
        1,
        "the replays applied nothing"
    );

    // A fork is FAILED and not recorded: the same op_id with a body that now fits applies.
    let _audit = lock_audit_table();
    let seq = 9_000_000_000_000 + u64::from(std::process::id());
    let rec = |action: &str| AuditRecord {
        seq,
        ts: 1,
        action: action.into(),
        resource: ns.clone(),
        outcome: "ok".into(),
        principal: "p".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };
    let first = op();
    b.append_audit_op(first, &rec("one")).expect("appended");
    let fork = op();
    assert!(matches!(
        b.append_audit_op(fork, &rec("two")),
        Err(OpRefused::Failed(_))
    ));
    b.lock()
        .execute("DELETE FROM audit_log WHERE seq = $1", &[&(seq as i64)])
        .unwrap();
    b.append_audit_op(fork, &rec("two"))
        .expect("a failed op was not recorded, so its retry is evaluated afresh");
    b.lock()
        .execute("DELETE FROM audit_log WHERE seq = $1", &[&(seq as i64)])
        .unwrap();
}

/// The money slots: no cap is NoCap, a cap admits exactly its headroom, a release gives it back,
/// a replayed reserve answers the ORIGINAL grants, and a cap re-pushed at its generation with a
/// different value is a conflict.
#[test]
fn caps_reserve_and_release_follow_the_1_5_5_rules() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let key = requests(&ns);
    let cell = Cell { key, amount: 2 };
    assert_eq!(
        reserve(&s, op(), &[cell]),
        Err(ReserveRefused::NoCap { cell: 0 })
    );
    s.window_caps(
        op(),
        &[Cap {
            key,
            cap: 3,
            config_gen: 1,
        }],
    )
    .expect("cap pushed");
    assert_eq!(
        s.window_caps(
            op(),
            &[Cap {
                key,
                cap: 4,
                config_gen: 1,
            }],
        ),
        Err(CapsRefused::CapConflict { index: 0 })
    );

    let id = op();
    let grants = reserve(&s, id, &[cell]).expect("2 of 3 granted");
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].granted, 2);
    assert_eq!(reserve(&s, id, &[cell]), Ok(grants.clone()), "replay");
    assert_eq!(
        reserve(&s, op(), &[cell]),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "2 + 2 > 3"
    );
    assert_eq!(
        release(&s, op(), &[(grants[0].slice_id, 5)]),
        Ok(vec![2]),
        "the release is clamped to what the slice holds"
    );
    assert!(reserve(&s, op(), &[cell]).is_ok(), "the headroom came back");
    assert!(matches!(
        release(&s, op(), &[(u64::MAX, 1)]),
        Err(OpRefused::Failed(_))
    ));
}

/// The journal, sessions and kernel-held records.
#[test]
fn journal_sessions_and_records_round_trip() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let rows = |n: u8| -> Vec<RecordBytes> {
        (0..n).map(|i| RecordBytes::new(vec![i]).unwrap()).collect()
    };
    let first = s.append_batch(op(), &ns, &rows(2)).expect("appended");
    assert_eq!(first.seq, 2);
    let id = op();
    let second = s.append_batch(id, &ns, &rows(3)).expect("appended");
    assert_eq!(second.seq, 5);
    assert_eq!(s.append_batch(id, &ns, &rows(3)), Ok(second), "replay");
    let heads = s.heads().expect("heads");
    assert_eq!(
        heads
            .iter()
            .find(|(stream, _)| *stream == ns)
            .map(|h| h.1.seq),
        Some(5)
    );

    let principal = format!("{ns}-p");
    s.session_put(u64::MAX, "node-a", &principal).unwrap();
    s.session_put(7, "node-b", &principal).unwrap();
    s.session_put(7, "node-c", &principal).unwrap();
    assert_eq!(
        s.sessions_for(&principal).unwrap(),
        vec![(7, "node-c".to_string()), (u64::MAX, "node-a".to_string())]
    );
    s.session_remove(u64::MAX).unwrap();
    s.session_remove(u64::MAX).unwrap();
    s.session_remove(7).unwrap();
    assert!(s.sessions_for(&principal).unwrap().is_empty());

    s.record_put(&ns, b"a/1", b"one").unwrap();
    s.record_put(&ns, b"a/2", b"two").unwrap();
    s.record_put(&ns, b"b/1", b"other").unwrap();
    s.record_put(&ns, b"a/1", b"uno").unwrap();
    assert_eq!(
        s.record_get(&ns, b"a/1")
            .unwrap()
            .map(|r| r.as_slice().to_vec()),
        Some(b"uno".to_vec())
    );
    assert!(s.record_get(&ns, b"zz").unwrap().is_none());
    let scan: Vec<Vec<u8>> = s
        .record_scan(&ns, b"a/", 10)
        .unwrap()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(scan, vec![b"a/1".to_vec(), b"a/2".to_vec()]);
    assert_eq!(s.record_scan(&ns, b"a/", 1).unwrap().len(), 1);
    assert!(
        s.record_scan(&ns, b"", 0).unwrap().is_empty(),
        "limit 0 is nothing"
    );
}
