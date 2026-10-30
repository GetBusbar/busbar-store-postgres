// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live Postgres: durable `op_id` dedupe (S1-S4)
//! across a reconnect, and the kernel-held records. Every name is namespaced per run, so the shared test database never carries one run's
//! rows into another's assertions.

use super::*;
use busbar_contract::abi::sdk::store::dedupe::Dedupe;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::MeteringDelta;
use std::sync::atomic::{AtomicU64, Ordering};

/// A namespace unique to this run.
fn ns() -> String {
    // The counter keeps two tests started in the same clock tick apart (they would share a bucket
    // and push conflicting caps for it).
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "v3-{}-{nanos}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
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

fn store(url: &str) -> TestStore {
    connect_store_with_retry(url).expect("connect")
}

/// `open` is the settings' judge: the 1.5.5 refusals, in the store's own words.
#[test]
fn open_refuses_settings_without_a_url() {
    let want = "postgres plugin config requires a \"url\" (a libpq connection string)";
    for settings in [&b""[..], &b"  "[..], &b"{}"[..], &br#"{"url": "  "}"#[..]] {
        assert_eq!(
            TestStore::open_slot(settings).err().as_deref(),
            Some(want),
            "{settings:?}"
        );
    }
    // A present url of the wrong type says so, rather than "requires a url".
    for settings in [&br#"{"url": 5}"#[..], &br#"{"url": null}"#[..]] {
        assert_eq!(
            TestStore::open_slot(settings).err().as_deref(),
            Some("invalid postgres plugin config: `url` must be a string"),
            "{settings:?}"
        );
    }
    // An unknown top-level key is refused, never ignored.
    assert_eq!(
        TestStore::open_slot(br#"{"url": "postgres://u@h/d", "x": 1}"#)
            .err()
            .as_deref(),
        Some("invalid postgres plugin config: unknown setting `x` (accepted: url)")
    );
    let e = TestStore::open_slot(b"{ not json").err().unwrap();
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
    // A window no other test writes.
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
    let parent = format!("{ns}-chain");
    let rec = |hash: &str| PlaneRecord {
        kind: "call".into(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq: 1,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: format!("{{\"hash\":\"{hash}\"}}").into_bytes(),
    };
    let clear = |s: &TestStore| {
        s.lock()
            .execute(
                "DELETE FROM plane_chain WHERE kind = 'call' AND parent = $1",
                &[&parent],
            )
            .unwrap();
    };
    clear(&b);
    b.append_plane_record_op(op(), rec("one").view())
        .expect("appended");
    let fork = op();
    assert!(matches!(
        b.append_plane_record_op(fork, rec("two").view()),
        Err(OpRefused::Failed(_))
    ));
    clear(&b);
    b.append_plane_record_op(fork, rec("two").view())
        .expect("a failed op was not recorded, so its retry is evaluated afresh");
    clear(&b);
}

/// S5: a value decided before commit (one a column cannot hold, or a data/integrity error the
/// server raises) is REFUSED, nothing recorded; the same `op_id` with a valid record applies.
#[test]
fn a_write_refused_before_commit_answers_refused_and_records_nothing() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let parent = format!("{ns}-refused");
    let rec = |seq: u64| PlaneRecord {
        kind: "refusedkind".into(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq,
        ts: 5_000_000_000,
        disposition: PlaneDisposition::Active,
        body: b"{}".to_vec(),
    };
    let id = op();
    assert!(matches!(
        s.append_plane_record_op(id, rec(u64::MAX).view()),
        Err(OpRefused::Refused(_))
    ));
    let recorded: i64 = s
        .lock()
        .query_one(
            "SELECT COUNT(*) FROM store_ops WHERE op_id = $1",
            &[&&id.0[..]],
        )
        .unwrap()
        .get(0);
    assert_eq!(recorded, 0, "a refused op records nothing");
    s.append_plane_record_op(id, rec(1).view())
        .expect("the same op_id with a valid record applies");
    s.lock()
        .execute("DELETE FROM plane_chain WHERE kind = 'refusedkind'", &[])
        .unwrap();

    let mut meter = MeteringDelta {
        key_id: format!("{ns}-k"),
        bucket: 1,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 0,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v".into(),
        priced_from_ms: u64::MAX,
        usage_units: Default::default(),
    };
    assert!(matches!(
        s.add_metering_op(op(), &meter),
        Err(OpRefused::Refused(_))
    ));
    meter.priced_from_ms = 0;
    meter.bucket = 4_000_000_000_000_002;
    s.add_metering_op(op(), &meter)
        .expect("a valid delta applies");

    // A NUL in a text value: the server's data exception (class 22) mid-apply, rolled back.
    let delta = UsageDelta {
        requests: 1,
        ..Default::default()
    };
    let nul = op();
    assert!(matches!(
        s.add_usage_op(nul, &format!("{ns}\0b"), 4_000_000_000_000_003, &delta),
        Err(OpRefused::Refused(_))
    ));
    s.add_usage_op(nul, &format!("{ns}-b"), 4_000_000_000_000_003, &delta)
        .expect("a refused op was not recorded");
}

/// A batch applies its cells and deltas in key order whatever the caller's order, so two nodes
/// writing overlapping batches take row locks in one order (no 40P01). Fresh heap rows land in
/// application order, which `ctid` shows.
#[test]
fn a_batch_applies_in_key_order() {
    let Some(url) = live_url() else {
        return;
    };
    let tmp = super::TempDb::create(&url, "spg_order");
    let s = store(&tmp.url());
    let delta = UsageDelta {
        requests: 1,
        ..Default::default()
    };
    let cells = [
        ("b2", 5, delta.clone()),
        ("b1", 5, delta.clone()),
        ("b1", 3, delta.clone()),
    ];
    s.add_usage_batch_op(op(), &cells).expect("applied");
    let order: Vec<(String, i64)> = s
        .lock()
        .query(
            "SELECT bucket_id, window_start FROM usage_windows ORDER BY ctid",
            &[],
        )
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    assert_eq!(
        order,
        [("b1".to_string(), 3), ("b1".to_string(), 5), ("b2".to_string(), 5)]
    );

    let m = |key: &str, model: &str| MeteringDelta {
        key_id: key.into(),
        bucket: 7,
        model: model.into(),
        provider: "p".into(),
        tokens_input: 1,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let deltas = [m("k2", "a"), m("k1", "b"), m("k1", "a")];
    s.add_metering_batch_op(op(), &deltas).expect("applied");
    let order: Vec<(String, String)> = s
        .lock()
        .query("SELECT key_id, model FROM usage_metering ORDER BY ctid", &[])
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    let want = |k: &str, m: &str| (k.to_string(), m.to_string());
    assert_eq!(order, [want("k1", "a"), want("k1", "b"), want("k2", "a")]);
}

/// A new op records its body as the SDK's digest (64 hex digits), not a `{:?}` dump.
#[test]
fn a_new_op_records_its_digest() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let bucket = format!("{ns}-b");
    let delta = UsageDelta {
        requests: 1,
        ..Default::default()
    };
    let id = op();
    s.add_usage_op(id, &bucket, 4_000_000_000_000_001, &delta)
        .expect("applied");
    let cells = [(bucket.as_str(), 4_000_000_000_000_001, delta)];
    let recorded: String = s
        .lock()
        .query_one("SELECT body FROM store_ops WHERE op_id = $1", &[&&id.0[..]])
        .unwrap()
        .get(0);
    assert_eq!(recorded, Dedupe::usage(&cells).body_hex());
}

/// A body an older build recorded (`<slot>:{:?}`) still replays across the upgrade, and a
/// different op under its `op_id` is still a conflict; neither applies anything.
#[test]
fn an_op_recorded_by_an_older_build_replays() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let old_row = |id: OpId, body: String| {
        s.lock()
            .execute(
                "INSERT INTO store_ops (op_id, body, answer, recorded_at) VALUES ($1, $2, '', $3)",
                &[&&id.0[..], &body, &(now_secs() as i64)],
            )
            .unwrap();
    };

    // Usage.
    const WINDOW: u64 = 4_000_000_000_000_002;
    let bucket = format!("{ns}-b");
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        ..Default::default()
    };
    let cells = [(bucket.as_str(), WINDOW, delta.clone())];
    let id = op();
    old_row(id, format!("add_usage_batch:{cells:?}"));
    s.add_usage_op(id, &bucket, WINDOW, &delta)
        .expect("an older body replays");
    let other = UsageDelta {
        requests: 2,
        ..Default::default()
    };
    assert_eq!(
        s.add_usage_op(id, &bucket, WINDOW, &other),
        Err(OpRefused::Conflict)
    );
    assert_eq!(s.get_usage(&bucket, WINDOW).expect("read").requests, 0);

    // Metering.
    const BUCKET: u64 = 4_000_000_000_000_003;
    let key_id = format!("{ns}-k");
    let m = MeteringDelta {
        key_id: key_id.clone(),
        bucket: BUCKET,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 10,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: "v".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    };
    let id = op();
    old_row(
        id,
        format!("add_metering_batch:{:?}", std::slice::from_ref(&m)),
    );
    s.add_metering_op(id, &m).expect("an older body replays");
    let other = MeteringDelta {
        tokens_input: 11,
        ..m.clone()
    };
    assert_eq!(s.add_metering_op(id, &other), Err(OpRefused::Conflict));
    assert!(s
        .list_metering(BUCKET)
        .expect("read")
        .iter()
        .all(|r| r.key_id != key_id));

    // Plane-record append (the older build recorded the owned record).
    let parent = format!("{ns}-chain");
    let rec = |hash: &str| PlaneRecord {
        kind: "call".into(),
        id: parent.clone(),
        parent: Some(parent.clone()),
        seq: 1,
        ts: 1,
        disposition: PlaneDisposition::Active,
        body: format!("{{\"hash\":\"{hash}\"}}").into_bytes(),
    };
    let id = op();
    old_row(id, format!("append_plane_record:{:?}", rec("one")));
    s.append_plane_record_op(id, rec("one").view())
        .expect("an older body replays");
    assert_eq!(
        s.append_plane_record_op(id, rec("two").view()),
        Err(OpRefused::Conflict)
    );
    let n: i64 = s
        .lock()
        .query_one(
            "SELECT count(*) FROM plane_chain WHERE kind = 'call' AND parent = $1",
            &[&parent],
        )
        .unwrap()
        .get(0);
    assert_eq!(n, 0, "the replay and the conflict applied nothing");
}

/// The journal, sessions and kernel-held records.
#[test]
fn records_round_trip() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
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

/// Record keys are raw bytes: NUL, 0xFF and non-UTF-8 sequences are keys like any other, a scan runs
/// in byte order, and a prefix equal to a whole key returns that key too.
#[test]
fn record_keys_are_raw_bytes_scanned_in_byte_order() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let keys: [&[u8]; 7] = [
        &[0xFF, 0x00],
        &[0x00],
        &[0xFF],
        &[0xC3, 0x28],
        &[0x00, 0xFF],
        &[0xFF, 0xFF],
        &[0x7F],
    ];
    for (i, k) in keys.iter().enumerate() {
        s.record_put(&ns, k, &[i as u8]).unwrap();
    }
    let scan = |prefix: &[u8]| -> Vec<Vec<u8>> {
        s.record_scan(&ns, prefix, 100)
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    };
    assert_eq!(
        scan(&[]),
        vec![
            vec![0x00],
            vec![0x00, 0xFF],
            vec![0x7F],
            vec![0xC3, 0x28],
            vec![0xFF],
            vec![0xFF, 0x00],
            vec![0xFF, 0xFF],
        ]
    );
    assert_eq!(
        scan(&[0xFF]),
        vec![vec![0xFF], vec![0xFF, 0x00], vec![0xFF, 0xFF]],
        "a prefix equal to a whole key includes that key"
    );
    assert_eq!(scan(&[0x00]), vec![vec![0x00], vec![0x00, 0xFF]]);
    assert_eq!(scan(&[0xC3, 0x28]), vec![vec![0xC3, 0x28]]);
    assert!(scan(&[0xC3, 0x29]).is_empty());
}

/// AN EMPTY PUT REMOVES THE ROW (slot 40's rule, ARCHITECT 2026-10-21): the host writes every
/// strike as an empty `record_put` and reads empty as absent, so the row LEAVES the table:
/// `record_get` answers `None`, `record_scan` never returns it, and the table shrinks. Removing a
/// row that is not there is `Ok`.
#[test]
fn an_empty_put_removes_the_row() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let held = || -> i64 {
        s.lock()
            .query_one(
                "SELECT COUNT(*) FROM store_records WHERE schema_id = $1",
                &[&ns],
            )
            .expect("count")
            .get(0)
    };
    s.record_put(&ns, b"a/1", b"one").unwrap();
    s.record_put(&ns, b"a/2", b"two").unwrap();
    assert_eq!(held(), 2);

    s.record_put(&ns, b"a/1", b"").unwrap();
    assert_eq!(held(), 1, "the struck row left the table");
    assert!(s.record_get(&ns, b"a/1").unwrap().is_none());
    let scan: Vec<(Vec<u8>, Vec<u8>)> = s
        .record_scan(&ns, b"a/", 10)
        .unwrap()
        .into_iter()
        .map(|(k, v)| (k, v.as_slice().to_vec()))
        .collect();
    assert_eq!(
        scan,
        vec![(b"a/2".to_vec(), b"two".to_vec())],
        "a scan never returns a struck row"
    );

    s.record_put(&ns, b"a/9", b"").unwrap();
    assert_eq!(held(), 1, "a strike of nothing is Ok and changes nothing");
    s.record_put(&ns, b"a/1", b"again").unwrap();
    assert_eq!(
        s.record_get(&ns, b"a/1")
            .unwrap()
            .map(|r| r.as_slice().to_vec()),
        Some(b"again".to_vec())
    );
}
