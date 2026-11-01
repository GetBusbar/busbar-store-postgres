// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request, VERSION,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::store_calls::{StoreCalls, StoreFailure};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

#[path = "conditional_records_faults.rs"]
mod faults;

const SCHEMA: &str = "conditional-test";

fn request(predicates: Vec<Predicate>, mutations: Vec<Mutation>) -> Request {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Request {
        version: VERSION,
        op_id: OpId::from_parts(0x5047, NEXT.fetch_add(1, Ordering::Relaxed)),
        predicates,
        mutations,
    }
}
fn predicate(key: &[u8], expected: Expected) -> Predicate {
    Predicate {
        schema: SCHEMA.into(),
        key: key.into(),
        expected,
    }
}
fn put(key: &[u8], value: &[u8]) -> Mutation {
    Mutation::Put {
        schema: SCHEMA.into(),
        key: key.into(),
        value: value.into(),
    }
}
fn delete(key: &[u8]) -> Mutation {
    Mutation::Delete {
        schema: SCHEMA.into(),
        key: key.into(),
    }
}
fn apply(store: &TestStore, request: &Request) -> Result<Decision, StoreFailure> {
    harness::block_on(StoreCalls::record_transaction(&**store, request))
}
fn rows(store: &TestStore) -> Vec<(Vec<u8>, Vec<u8>)> {
    store
        .record_scan(SCHEMA, b"", u32::MAX)
        .unwrap()
        .into_iter()
        .map(|(k, v)| (k, v.as_slice().to_vec()))
        .collect()
}
fn revision(store: &TestStore) -> i64 {
    store
        .lock()
        .query_one("SELECT revision FROM store_revision WHERE only_row", &[])
        .unwrap()
        .get(0)
}
fn receipts(store: &TestStore) -> i64 {
    store
        .lock()
        .query_one("SELECT COUNT(*) FROM store_ops", &[])
        .unwrap()
        .get(0)
}
fn until(mut predicate: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

#[test]
fn all_predicates_use_prestate_and_receipts_replay_before_rechecking_conditions() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_prestate");
    let store = TestStore::open(&db.url()).unwrap();
    assert!(StoreCalls::supports_record_transaction(&*store));
    store.record_put(SCHEMA, b"state", b"old").unwrap();
    store
        .record_put(SCHEMA, b"event\0\xff", b"previous")
        .unwrap();
    let before = revision(&store);
    let r = request(
        vec![
            predicate(b"state", Expected::Bytes(b"old".to_vec())),
            predicate(b"absent", Expected::Absent),
        ],
        vec![
            put(b"state", b"new"),
            delete(b"event\0\xff"),
            put(b"absent", b"created"),
        ],
    );
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    let expected = rows(&store);
    assert_eq!(
        expected,
        vec![
            (b"absent".to_vec(), b"created".to_vec()),
            (b"state".to_vec(), b"new".to_vec())
        ]
    );
    assert_eq!(
        revision(&store),
        before,
        "generic records preserve their existing lock-only revision policy"
    );
    assert_eq!(receipts(&store), 1);
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert_eq!(
        apply(&reopened, &r).unwrap(),
        Decision::Applied,
        "receipt wins even though original predicates are now false"
    );
    let mut changed = r.clone();
    changed.mutations[0] = put(b"state", b"changed body");
    assert!(matches!(
        apply(&reopened, &changed),
        Err(StoreFailure::Conflict)
    ));
    assert_eq!(rows(&reopened), expected);
    assert_eq!(receipts(&reopened), 1);
    assert_eq!(revision(&reopened), before);
    let losing = request(
        vec![predicate(b"state", Expected::Bytes(b"old".to_vec()))],
        vec![put(b"state", b"wrong")],
    );
    assert_eq!(
        apply(&reopened, &losing).unwrap(),
        Decision::ConditionConflict
    );
    assert_eq!(rows(&reopened), expected);
    assert_eq!(
        receipts(&reopened),
        1,
        "a condition conflict records no receipt"
    );
    assert_eq!(revision(&reopened), before);
    // That definitively unused id can be replanned; an Applied id above cannot.
    let mut replanned = losing;
    replanned.predicates[0].expected = Expected::Bytes(b"new".to_vec());
    assert_eq!(apply(&reopened, &replanned).unwrap(), Decision::Applied);
}

#[test]
fn malformed_requests_leave_rows_revisions_and_receipts_unchanged() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_invalid");
    let store = TestStore::open(&db.url()).unwrap();
    let valid = request(
        vec![predicate(b"key", Expected::Absent)],
        vec![put(b"key", b"v")],
    );
    let mut invalid = Vec::new();
    let mut r = valid.clone();
    r.version += 1;
    invalid.push(r);
    let mut r = valid.clone();
    r.predicates.clear();
    invalid.push(r);
    let mut r = valid.clone();
    r.mutations.clear();
    invalid.push(r);
    let mut r = valid.clone();
    r.predicates.push(r.predicates[0].clone());
    invalid.push(r);
    let mut r = valid.clone();
    r.mutations.push(r.mutations[0].clone());
    invalid.push(r);
    let mut r = valid;
    r.mutations[0] = put(b"key", b"");
    invalid.push(r);
    let before = revision(&store);
    for r in invalid {
        assert!(apply(&store, &r).is_err());
        assert!(rows(&store).is_empty());
        assert_eq!(receipts(&store), 0);
        assert_eq!(revision(&store), before);
    }
}

fn race(db: &TempDb, left: Request, right: Request) -> [Decision; 2] {
    // Both opens precede the blocker and workers. Actual server lock waits establish the schedule.
    let a = TestStore::open(&db.url()).unwrap();
    let b = TestStore::open(&db.url()).unwrap();
    let mut blocker = connect_client_with_retry(&db.url());
    blocker
        .batch_execute("BEGIN; SELECT revision FROM store_revision WHERE only_row FOR UPDATE")
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let launch = |store: TestStore, r: Request| {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let result = apply(&store, &r);
            let _ = tx.send(result);
        })
    };
    let a = launch(a, left);
    let b = launch(b, right);
    drop(tx);
    let blocked = until(|| {
        blocker.query_one(
        "SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database()
         AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%store_revision%FOR UPDATE%'", &[],
    ).unwrap().get::<_, i64>(0) == 2
    });
    blocker.batch_execute("ROLLBACK").unwrap(); // Always release before assertions or worker joins.
    assert!(
        blocked,
        "both distinct op_ids must lock before reading even an absent predicate"
    );
    let results = [
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap(),
    ];
    a.join().unwrap();
    b.join().unwrap();
    results
}

#[test]
fn distinct_ids_on_the_same_absent_predicate_have_exactly_one_winner() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_absent");
    let r = |value: &[u8]| {
        request(
            vec![predicate(b"state", Expected::Absent)],
            vec![put(b"state", value), put(b"event", value)],
        )
    };
    let decisions = race(&db, r(b"left"), r(b"right"));
    assert_eq!(
        decisions
            .iter()
            .filter(|d| **d == Decision::Applied)
            .count(),
        1
    );
    assert_eq!(
        decisions
            .iter()
            .filter(|d| **d == Decision::ConditionConflict)
            .count(),
        1
    );
    let reopened = TestStore::open(&db.url()).unwrap();
    let actual = rows(&reopened);
    assert_eq!(actual.len(), 2);
    assert_eq!(actual[0].1, actual[1].1);
    assert_eq!(receipts(&reopened), 1);
}

#[test]
fn writer_and_retirement_compete_on_the_same_prestate_without_resurrection_or_cut_chain() {
    let Some(url) = live_url() else { return };
    for writer_first in [true, false] {
        let db = TempDb::create(&url, "spg_conditional_retire");
        let seed = TestStore::open(&db.url()).unwrap();
        let a = TestStore::open(&db.url()).unwrap();
        let b = TestStore::open(&db.url()).unwrap();
        seed.record_put(SCHEMA, b"state", b"old").unwrap();
        seed.record_put(SCHEMA, b"event", b"old").unwrap();
        let before = revision(&seed);
        seed.lock().batch_execute(
            "CREATE FUNCTION pause_conditional_state() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
             IF OLD.key=decode('7374617465','hex') THEN PERFORM pg_advisory_xact_lock(170018); END IF;
             IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END $$;
             CREATE TRIGGER pause_conditional_state BEFORE UPDATE OR DELETE ON store_records
             FOR EACH ROW EXECUTE FUNCTION pause_conditional_state()",
        ).unwrap();
        let writer = request(
            vec![predicate(b"state", Expected::Bytes(b"old".to_vec()))],
            vec![put(b"state", b"new"), put(b"event", b"new")],
        );
        let retirement = request(
            vec![predicate(b"state", Expected::Bytes(b"old".to_vec()))],
            vec![delete(b"state"), delete(b"event")],
        );
        let (first, second) = if writer_first {
            (writer, retirement)
        } else {
            (retirement, writer)
        };
        let mut blocker = connect_client_with_retry(&db.url());
        blocker
            .batch_execute("SELECT pg_advisory_lock(170018)")
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let first_tx = tx.clone();
        let first_worker = std::thread::spawn(move || {
            let _ = first_tx.send((0, apply(&a, &first)));
        });
        // The first transaction has checked its predicate and reached its mutation; its result
        // is unpublished. The second must wait before evaluating the same old predicate.
        let paused = until(|| {
            blocker.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND pid<>pg_backend_pid())", &[]).unwrap().get::<_,bool>(0)
        });
        let second_worker = std::thread::spawn(move || {
            let _ = tx.send((1, apply(&b, &second)));
        });
        let serializing = until(|| {
            blocker.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%store_revision%FOR UPDATE%' AND pid<>pg_backend_pid())", &[]).unwrap().get::<_,bool>(0)
        });
        let precommit = rows(&seed);
        blocker
            .batch_execute("SELECT pg_advisory_unlock(170018)")
            .unwrap();
        let results = [
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        ];
        first_worker.join().unwrap();
        second_worker.join().unwrap();
        assert!(
            paused && serializing,
            "actual backend waits establish both publication orders"
        );
        for (order, result) in results {
            assert_eq!(
                result.unwrap(),
                if order == 0 {
                    Decision::Applied
                } else {
                    Decision::ConditionConflict
                }
            );
        }
        assert_eq!(
            precommit,
            vec![
                (b"event".to_vec(), b"old".to_vec()),
                (b"state".to_vec(), b"old".to_vec())
            ]
        );
        let expected = if writer_first {
            vec![
                (b"event".to_vec(), b"new".to_vec()),
                (b"state".to_vec(), b"new".to_vec()),
            ]
        } else {
            vec![]
        };
        assert_eq!(rows(&seed), expected);
        assert_eq!(receipts(&seed), 1);
        assert_eq!(revision(&seed), before);
    }
}

#[test]
fn a_statement_error_rolls_back_all_mutations_and_the_receipt_before_exact_retry() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_rollback");
    let store = TestStore::open(&db.url()).unwrap();
    store.record_put(SCHEMA, b"a", b"old").unwrap();
    store.record_put(SCHEMA, b"z", b"old").unwrap();
    let before = rows(&store);
    let rev = revision(&store);
    store.lock().batch_execute(
        "CREATE FUNCTION reject_conditional_z() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
         IF NEW.key=decode('7a','hex') THEN RAISE EXCEPTION 'conditional rollback probe'; END IF; RETURN NEW; END $$;
         CREATE TRIGGER reject_conditional_z BEFORE INSERT OR UPDATE ON store_records FOR EACH ROW EXECUTE FUNCTION reject_conditional_z()",
    ).unwrap();
    let r = request(
        vec![predicate(b"a", Expected::Bytes(b"old".to_vec()))],
        vec![put(b"a", b"new"), put(b"z", b"new")],
    );
    assert!(apply(&store, &r).is_err());
    assert_eq!(rows(&store), before);
    assert_eq!(revision(&store), rev);
    assert_eq!(receipts(&store), 0);
    store.lock().batch_execute("DROP TRIGGER reject_conditional_z ON store_records; DROP FUNCTION reject_conditional_z()").unwrap();
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    assert_eq!(receipts(&store), 1);
}

#[test]
fn a_reader_sees_the_old_or_new_batch_while_the_second_mutation_is_blocked() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_snapshot");
    let store = Arc::new(TestStore::open(&db.url()).unwrap());
    store.record_put(SCHEMA, b"a", b"old").unwrap();
    store.record_put(SCHEMA, b"z", b"old").unwrap();
    store.lock().batch_execute(
        "CREATE FUNCTION pause_conditional_z() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
         IF NEW.key=decode('7a','hex') THEN PERFORM pg_advisory_xact_lock(170017); END IF; RETURN NEW; END $$;
         CREATE TRIGGER pause_conditional_z BEFORE UPDATE ON store_records FOR EACH ROW EXECUTE FUNCTION pause_conditional_z()",
    ).unwrap();
    let mut blocker = connect_client_with_retry(&db.url());
    blocker
        .batch_execute("SELECT pg_advisory_lock(170017)")
        .unwrap();
    let r = request(
        vec![predicate(b"a", Expected::Bytes(b"old".to_vec()))],
        vec![put(b"a", b"new"), put(b"z", b"new")],
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let write = {
        let store = store.clone();
        std::thread::spawn(move || {
            let _ = tx.send(apply(&store, &r));
        })
    };
    let blocked = until(|| {
        blocker.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory' AND pid<>pg_backend_pid())",&[]).unwrap().get::<_,bool>(0)
    });
    let while_blocked = rows(&store);
    blocker
        .batch_execute("SELECT pg_advisory_unlock(170017)")
        .unwrap();
    let result = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    write.join().unwrap();
    assert!(blocked);
    assert_eq!(
        while_blocked,
        vec![
            (b"a".to_vec(), b"old".to_vec()),
            (b"z".to_vec(), b"old".to_vec())
        ]
    );
    assert_eq!(result.unwrap(), Decision::Applied);
    assert_eq!(
        rows(&store),
        vec![
            (b"a".to_vec(), b"new".to_vec()),
            (b"z".to_vec(), b"new".to_vec())
        ]
    );
}

#[test]
fn range_retirement_is_binary_exact_length_scoped_atomic_and_receipt_replayable() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_range");
    let store = TestStore::open(&db.url()).unwrap();
    let prefix = b"owner/task/";
    let key = |scope: &[u8], seq: u64| [scope, &seq.to_be_bytes()].concat();
    let a = key(prefix, 1);
    let b = key(prefix, 2);
    let neighbour = key(b"owner/task/other/", 1);
    for k in [&a, &b, &neighbour] {
        store.record_put(SCHEMA, k, b"event").unwrap();
    }
    store.record_put(SCHEMA, prefix, b"short").unwrap();
    store.record_put("other-schema", &a, b"other").unwrap();
    store.record_put(SCHEMA, b"state", b"terminal").unwrap();
    let range = Mutation::DeleteRange {
        schema: SCHEMA.into(),
        prefix: prefix.to_vec(),
        exact_key_length: a.len() as u64,
    };
    let r = request(
        vec![predicate(b"state", Expected::Bytes(b"terminal".to_vec()))],
        vec![delete(b"state"), range.clone()],
    );
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    assert!(store.record_get(SCHEMA, &a).unwrap().is_none());
    assert!(store.record_get(SCHEMA, &b).unwrap().is_none());
    assert!(store.record_get(SCHEMA, &neighbour).unwrap().is_some());
    assert!(store.record_get(SCHEMA, prefix).unwrap().is_some());
    assert!(store.record_get("other-schema", &a).unwrap().is_some());
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    assert_eq!(receipts(&store), 1);
    // A declared full-u64 length has no BYTEA matches; it is never truncated to a smaller width.
    let impossible = request(
        vec![predicate(b"state", Expected::Absent)],
        vec![Mutation::DeleteRange {
            schema: SCHEMA.into(),
            prefix: Vec::new(),
            exact_key_length: u64::MAX,
        }],
    );
    assert_eq!(apply(&store, &impossible).unwrap(), Decision::Applied);
    assert!(store.record_get(SCHEMA, &neighbour).unwrap().is_some());
    // Point/range overlap is a malformed batch, not an order-dependent deletion plan.
    let overlapping = request(
        vec![predicate(b"state", Expected::Absent)],
        vec![range, put(&a, b"rewrite")],
    );
    let before = rows(&store);
    assert!(apply(&store, &overlapping).is_err());
    assert_eq!(rows(&store), before);
    assert_eq!(receipts(&store), 2);
}

#[test]
fn ordinary_record_put_and_delete_cannot_bypass_the_conditional_serialization_lock() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_ordinary");
    let store = Arc::new(TestStore::open(&db.url()).unwrap());
    let before = revision(&store);
    for value in [b"new".to_vec(), Vec::new()] {
        store.record_put(SCHEMA, b"state", b"old").unwrap();
        let mut blocker = connect_client_with_retry(&db.url());
        blocker
            .batch_execute("BEGIN; SELECT revision FROM store_revision WHERE only_row FOR UPDATE")
            .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = {
            let store = store.clone();
            std::thread::spawn(move || {
                let _ = tx.send(store.record_put(SCHEMA, b"state", &value));
            })
        };
        let blocked = until(|| {
            blocker.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%store_revision%FOR UPDATE%')", &[]).unwrap().get::<_,bool>(0)
        });
        let precommit = rows(&store);
        blocker.batch_execute("ROLLBACK").unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
        worker.join().unwrap();
        assert!(blocked, "legacy writes participate in the same first lock");
        assert_eq!(precommit, vec![(b"state".to_vec(), b"old".to_vec())]);
    }
    assert_eq!(revision(&store), before);
    assert_eq!(receipts(&store), 0);
}

#[test]
fn a_range_error_rolls_back_prior_points_and_deleted_rows_with_the_applied_receipt() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_range_rollback");
    let store = TestStore::open(&db.url()).unwrap();
    for key in [b"a".as_slice(), b"z".as_slice(), b"marker".as_slice()] {
        store.record_put(SCHEMA, key, b"old").unwrap();
    }
    let before = rows(&store);
    store.lock().batch_execute(
        "CREATE FUNCTION reject_range_z() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
         IF OLD.key=decode('7a','hex') THEN RAISE EXCEPTION 'range rollback probe'; END IF; RETURN OLD; END $$;
         CREATE TRIGGER reject_range_z BEFORE DELETE ON store_records FOR EACH ROW EXECUTE FUNCTION reject_range_z()",
    ).unwrap();
    let r = request(
        vec![predicate(b"marker", Expected::Bytes(b"old".to_vec()))],
        vec![
            put(b"marker", b"new"),
            Mutation::DeleteRange {
                schema: SCHEMA.into(),
                prefix: Vec::new(),
                exact_key_length: 1,
            },
        ],
    );
    assert!(apply(&store, &r).is_err());
    assert_eq!(rows(&store), before);
    assert_eq!(receipts(&store), 0);
    store
        .lock()
        .batch_execute(
            "DROP TRIGGER reject_range_z ON store_records; DROP FUNCTION reject_range_z()",
        )
        .unwrap();
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    assert_eq!(rows(&store), vec![(b"marker".to_vec(), b"new".to_vec())]);
    assert_eq!(receipts(&store), 1);
}

#[test]
fn an_all_ff_prefix_range_uses_exact_binary_width_without_a_synthetic_upper_bound() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_ff");
    let store = TestStore::open(&db.url()).unwrap();
    let exact = b"\xff\xff\0\x01";
    let longer = b"\xff\xff\0\x01\x02";
    let outside = b"\xff\xfe\xff\xff";
    for key in [exact.as_slice(), longer.as_slice(), outside.as_slice()] {
        store.record_put(SCHEMA, key, b"v").unwrap();
    }
    let r = request(
        vec![predicate(b"absent", Expected::Absent)],
        vec![Mutation::DeleteRange {
            schema: SCHEMA.into(),
            prefix: b"\xff\xff".to_vec(),
            exact_key_length: 4,
        }],
    );
    assert_eq!(apply(&store, &r).unwrap(), Decision::Applied);
    assert!(store.record_get(SCHEMA, exact).unwrap().is_none());
    assert!(store.record_get(SCHEMA, longer).unwrap().is_some());
    assert!(store.record_get(SCHEMA, outside).unwrap().is_some());
}

#[test]
fn applied_receipts_keep_the_existing_retention_window_and_expired_rows_can_be_swept() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_retention");
    let store = TestStore::open(&db.url()).unwrap();
    let original = request(
        vec![predicate(b"original", Expected::Absent)],
        vec![put(b"original", b"v")],
    );
    assert_eq!(apply(&store, &original).unwrap(), Decision::Applied);
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    let another = request(
        vec![predicate(b"fresh", Expected::Absent)],
        vec![put(b"fresh", b"v")],
    );
    assert_eq!(apply(&reopened, &another).unwrap(), Decision::Applied);
    assert_eq!(
        apply(&reopened, &original).unwrap(),
        Decision::Applied,
        "an in-window receipt still replays after a sweep and reopen"
    );
    reopened
        .lock()
        .execute(
            "UPDATE store_ops SET recorded_at=0 WHERE op_id=$1",
            &[&original.op_id.0.as_slice()],
        )
        .unwrap();
    drop(reopened);
    let reopened = TestStore::open(&db.url()).unwrap();
    let third = request(
        vec![predicate(b"third", Expected::Absent)],
        vec![put(b"third", b"v")],
    );
    assert_eq!(apply(&reopened, &third).unwrap(), Decision::Applied);
    let old: i64 = reopened
        .lock()
        .query_one(
            "SELECT COUNT(*) FROM store_ops WHERE op_id=$1",
            &[&original.op_id.0.as_slice()],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        old, 0,
        "the existing periodic sweep still removes expired applied receipts"
    );
    assert_eq!(
        apply(&reopened, &original).unwrap(),
        Decision::ConditionConflict,
        "expired receipt is not fabricated from an existing value"
    );
    assert_eq!(rows(&reopened).len(), 3);
}
