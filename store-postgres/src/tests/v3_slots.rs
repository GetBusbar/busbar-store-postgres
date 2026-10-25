// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live Postgres: durable `op_id` dedupe (S1-S4)
//! across a reconnect, the kernel-held records, and the v13 upgrade that drops the deleted slots'
//! tables. Every name is namespaced per run, so the shared test database never carries one run's
//! rows into another's assertions.

use super::*;
use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;
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

/// A store in a SCHEMA of its own, so a test that rewinds the schema version touches no other test's
/// tables. The schema is dropped with the guard.
struct Iso {
    admin: std::cell::RefCell<postgres::Client>,
    schema: String,
    url: String,
    store: Option<TestStore>,
}

impl Iso {
    fn new(url: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!(
            "f1_{}_{nanos}_{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        let mut admin = connect_client_with_retry(url);
        admin
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .expect("create the test schema");
        let sep = if url.contains('?') { '&' } else { '?' };
        let url = format!("{url}{sep}options=-c%20search_path%3D{schema}");
        let store = Some(store(&url));
        Iso {
            admin: admin.into(),
            schema,
            url,
            store,
        }
    }

    fn s(&self) -> &TestStore {
        self.store.as_ref().expect("open")
    }

    /// A RESTART: the instance goes away and a fresh one opens over the same state.
    fn restart(&mut self) {
        self.store = None;
        self.store = Some(store(&self.url));
    }
}

impl Drop for Iso {
    fn drop(&mut self) {
        self.store = None;
        let _ = self
            .admin
            .get_mut()
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema));
    }
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

/// v13 drops the deleted slots' tables and their dedupe rows, and keeps a kept slot's dedupe row: a
/// v12 database (the money and journal tables present, a `reserve` and an `add_usage_batch` op on
/// record) opens at v13 with the first gone and the second still answering its replay.
#[test]
fn the_v13_upgrade_drops_the_money_and_dead_slot_tables() {
    let Some(url) = live_url() else {
        return;
    };
    let mut iso = Iso::new(&url);
    let schema = iso.schema.clone();
    let bucket = format!("{}-b", ns());
    const WINDOW: u64 = 4_000_000_000_000_001;
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        ..Default::default()
    };
    let kept = op();
    iso.s()
        .add_usage_op(kept, &bucket, WINDOW, &delta)
        .expect("applied");
    iso.admin
        .borrow_mut()
        .batch_execute(&format!(
            "SET search_path TO {schema};
             CREATE TABLE money_slots (slot TEXT PRIMARY KEY, cap BIGINT NOT NULL,
                 config_gen BIGINT NOT NULL, used BIGINT NOT NULL);
             CREATE TABLE money_slices (slice_id BIGSERIAL PRIMARY KEY, slot TEXT NOT NULL,
                 remaining BIGINT NOT NULL, valid_until_ms BIGINT NOT NULL DEFAULT 0);
             CREATE TABLE money_epoch (one BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (one),
                 epoch BIGINT NOT NULL);
             CREATE TABLE store_journal (stream TEXT NOT NULL, seq BIGINT NOT NULL,
                 record BYTEA NOT NULL, PRIMARY KEY (stream, seq));
             CREATE TABLE store_sessions (session BIGINT PRIMARY KEY, node TEXT NOT NULL,
                 principal TEXT NOT NULL);
             INSERT INTO money_slots VALUES ('s', 5, 1, 2);
             INSERT INTO store_ops VALUES ('\\x00ff'::bytea, 'reserve:0:[]', '7', 0);
             DELETE FROM busbar_schema;
             INSERT INTO busbar_schema (version) VALUES (12);"
        ))
        .expect("rewind to a v12 database");
    iso.restart();

    let mut admin = iso.admin.borrow_mut();
    for table in [
        "money_slots",
        "money_slices",
        "money_epoch",
        "store_journal",
        "store_sessions",
    ] {
        let present: bool = admin
            .query_one(
                "SELECT to_regclass($1) IS NOT NULL",
                &[&format!("{schema}.{table}")],
            )
            .unwrap()
            .get(0);
        assert!(!present, "{table} is dropped");
    }
    let ops: Vec<String> = admin
        .query(&format!("SELECT body FROM {schema}.store_ops"), &[])
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert!(
        ops.iter().all(|b| !b.starts_with("reserve:")),
        "a deleted slot's dedupe row goes: {ops:?}"
    );
    let version: i64 = admin
        .query_one(
            &format!("SELECT MAX(version) FROM {schema}.busbar_schema"),
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(version, 13);
    drop(admin);
    iso.s()
        .add_usage_op(kept, &bucket, WINDOW, &delta)
        .expect("a kept slot's op replays across the upgrade");
    assert_eq!(
        iso.s().get_usage(&bucket, WINDOW).expect("read").requests,
        1,
        "the replay applied nothing"
    );
}
