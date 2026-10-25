// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store v3 slots ([`StoreSlots`]) against a live Postgres: durable `op_id` dedupe (S1-S4)
//! across a reconnect, the money slots (`window_caps`, `reserve`, `slice_release`), the journal
//! (`append_batch`, `heads`), sessions and the kernel-held records. Every name is namespaced per
//! run, so the shared test database never carries one run's rows into another's assertions.

use super::*;
use busbar_contract::abi::sdk::store::{
    Cap, CapsRefused, Cell, CellKey, Dimension, Grant, OpRefused, ReserveRefused,
};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
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

fn requests(bucket: &str) -> CellKey<'_> {
    CellKey {
        bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start: 1_790_000_000_000,
    }
}

fn reserve(s: &TestStore, op: OpId, cells: &[Cell<'_>]) -> Result<Vec<Grant>, ReserveRefused> {
    let mut grants = Vec::new();
    s.reserve(op, 0, cells.iter().copied(), &mut grants)
        .map(|()| grants)
}

fn reserve_at(
    s: &TestStore,
    op: OpId,
    epoch: u64,
    cells: &[Cell<'_>],
) -> Result<Vec<Grant>, ReserveRefused> {
    let mut grants = Vec::new();
    s.reserve(op, epoch, cells.iter().copied(), &mut grants)
        .map(|()| grants)
}

fn release(s: &TestStore, op: OpId, items: &[(u64, u64)]) -> Result<Vec<u64>, OpRefused> {
    let mut back = Vec::new();
    s.slice_release(op, 0, items.iter().copied(), &mut back)
        .map(|()| back)
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

/// RED before slice life (e): a release on window 0 is final. The holder of a 6-unit window-0 slice
/// spent 4 and hands back 2; the slice closes, so a second release returns 0, the 4 spent stay
/// counted (6 more fill the cap of 10) and nothing past the cap is granted. A slice on a rolling
/// window keeps the partial-release rule: what it still holds can be handed back later.
#[test]
fn a_release_on_window_0_is_final() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let zero = CellKey {
        bucket: &ns,
        pool: None,
        dimension: Dimension::NanoUnits,
        window_start: 0,
    };
    s.window_caps(
        op(),
        &[Cap {
            key: zero,
            cap: 10,
            config_gen: 1,
        }],
    )
    .expect("the window-0 cap is pushed");
    let draw = |amount: u64| reserve(&s, op(), &[Cell { key: zero, amount }]);
    let g = draw(6).expect("a window-0 draw within its cap")[0];
    assert_eq!(release(&s, op(), &[(g.slice_id, 2)]), Ok(vec![2]));
    assert_eq!(
        release(&s, op(), &[(g.slice_id, 4)]),
        Ok(vec![0]),
        "a window-0 slice stayed open after its release"
    );
    assert_eq!(draw(6).expect("the returned 2 are drawable")[0].granted, 6);
    assert_eq!(
        draw(1),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "the spent part of a released window-0 slice was not counted"
    );

    let rolling = requests(&ns);
    s.window_caps(
        op(),
        &[Cap {
            key: rolling,
            cap: 10,
            config_gen: 1,
        }],
    )
    .expect("the rolling cap is pushed");
    let g = reserve(
        &s,
        op(),
        &[Cell {
            key: rolling,
            amount: 6,
        }],
    )
    .expect("a rolling draw")[0];
    assert_eq!(release(&s, op(), &[(g.slice_id, 2)]), Ok(vec![2]));
    assert_eq!(
        release(&s, op(), &[(g.slice_id, 4)]),
        Ok(vec![4]),
        "a rolling-window slice keeps what it still holds for a later release"
    );
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

/// A store in a SCHEMA of its own. The fleet epoch is one row for the whole database, so a test that
/// raises it must not do so in `public`: every other test reserves at epoch 0 and would be stale.
/// The schema is dropped with the guard.
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

    /// A second, independent instance over the same state (another node of the fleet).
    fn node(&self) -> TestStore {
        store(&self.url)
    }

    /// The database's clock in ms: the store's one clock.
    fn now_ms(&self) -> u64 {
        let ms: i64 = self
            .admin
            .borrow_mut()
            .query_one(
                "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint",
                &[],
            )
            .unwrap()
            .get(0);
        ms as u64
    }

    /// Move the store's clock forward by `ms`: every slice's expiry moves back by as much.
    fn advance_ms(&self, ms: u64) {
        self.admin
            .borrow_mut()
            .execute(
                &format!(
                    "UPDATE {}.money_slices SET valid_until_ms = valid_until_ms - $1",
                    self.schema
                ),
                &[&(ms as i64)],
            )
            .unwrap();
    }

    fn cap(&self, bucket: &str, cap: u64) {
        self.s()
            .window_caps(
                op(),
                &[Cap {
                    key: requests(bucket),
                    cap,
                    config_gen: 1,
                }],
            )
            .expect("the cap is pushed");
    }

    fn draw(&self, bucket: &str, amount: u64, epoch: u64) -> Result<Grant, ReserveRefused> {
        reserve_at(
            self.s(),
            op(),
            epoch,
            &[Cell {
                key: requests(bucket),
                amount,
            }],
        )
        .map(|g| g[0])
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

const TTL: u64 = busbar_contract::abi::store::SLICE_TTL_MS;

/// Rule (b): a reserve under an epoch below the stored one is StaleEpoch, applies nothing and records
/// nothing under its `op_id` (the same id retried under a current epoch is evaluated afresh).
#[test]
fn a_stale_epoch_is_refused_and_applies_nothing() {
    let Some(url) = live_url() else {
        return;
    };
    let iso = Iso::new(&url);
    iso.cap("stale", 10);
    iso.draw("stale", 1, 2).expect("epoch 2 draws");
    let id = op();
    let cell = Cell {
        key: requests("stale"),
        amount: 1,
    };
    assert_eq!(
        reserve_at(iso.s(), id, 1, &[cell]),
        Err(ReserveRefused::StaleEpoch),
        "a reserve under an epoch below the stored one is StaleEpoch"
    );
    assert!(
        reserve_at(iso.s(), id, 2, &[cell]).is_ok(),
        "the refused reserve left a row under its op_id"
    );
    iso.draw("stale", 8, 2)
        .expect("the stale reserve applied nothing: 1 + 1 + 8 of 10");
    assert_eq!(
        iso.draw("stale", 1, 2).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

/// Rule (a): the stored epoch survives a restart, and a second node sees the same fleet epoch.
#[test]
fn the_epoch_survives_a_restart() {
    let Some(url) = live_url() else {
        return;
    };
    let mut iso = Iso::new(&url);
    iso.cap("restart", 10);
    iso.draw("restart", 1, 3).expect("epoch 3 draws");
    let other = iso.node();
    iso.restart();
    assert_eq!(
        iso.draw("restart", 1, 2).map(drop),
        Err(ReserveRefused::StaleEpoch),
        "the epoch was lost on restart"
    );
    assert_eq!(
        reserve_at(
            &other,
            op(),
            2,
            &[Cell {
                key: requests("restart"),
                amount: 1
            }]
        ),
        Err(ReserveRefused::StaleEpoch),
        "another node of the fleet did not see the epoch"
    );
}

/// Rule (c): a grant is valid for at most SLICE_TTL_MS from the store's clock, and an expired slice's
/// unreturned part is drawable again.
#[test]
fn a_grant_is_bounded_and_an_expired_slice_returns_to_the_window() {
    let Some(url) = live_url() else {
        return;
    };
    let iso = Iso::new(&url);
    iso.cap("ttl", 5);
    let before = iso.now_ms();
    let g = iso.draw("ttl", 5, 2).expect("draws the whole window");
    let after = iso.now_ms();
    assert!(
        g.valid_until_ms >= before + TTL && g.valid_until_ms <= after + TTL,
        "valid_until_ms {} is not within [{before} + SLICE_TTL_MS, {after} + SLICE_TTL_MS]",
        g.valid_until_ms
    );
    assert_eq!(
        iso.draw("ttl", 1, 2).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
    iso.advance_ms(TTL + 1);
    iso.draw("ttl", 5, 2)
        .expect("an expired slice's unspent returned to the window");
}

/// A release applies whatever the epoch, returns each unit once, and an expiry after the release
/// returns nothing more.
#[test]
fn a_stale_epoch_release_applies_exactly_once() {
    let Some(url) = live_url() else {
        return;
    };
    let iso = Iso::new(&url);
    iso.cap("release", 10);
    iso.cap("release-fence", 1);
    let g = iso.draw("release", 4, 5).expect("epoch 5 draws");
    iso.draw("release-fence", 1, 6).expect("epoch 6 draws");
    let rel = |id: u64, epoch: u64, n: u64| {
        let mut back = Vec::new();
        iso.s()
            .slice_release(op(), epoch, [(id, n)].into_iter(), &mut back)
            .map(|()| back)
    };
    assert_eq!(rel(g.slice_id, 5, 4), Ok(vec![4]), "never refused");
    assert_eq!(rel(g.slice_id, 6, 4), Ok(vec![0]), "nothing left");
    iso.advance_ms(TTL + 1);
    iso.draw("release", 10, 6)
        .expect("the returned 4 are drawable");
    assert_eq!(
        iso.draw("release", 1, 6).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "expiry returned the released slice again"
    );
    assert_eq!(
        rel(g.slice_id, 6, 4),
        Ok(vec![0]),
        "a slice closed and gone answers 0"
    );
}

/// A closed rolling-window slice is a granted id: a later release of it (a new `op_id`) answers 0 and
/// does not fail the batch it rides in; an id never granted still FAILS.
#[test]
fn a_closed_slice_releases_zero_and_a_never_granted_id_fails() {
    let Some(url) = live_url() else {
        return;
    };
    let iso = Iso::new(&url);
    iso.cap("closed", 10);
    iso.cap("closed-peer", 10);
    let a = iso.draw("closed", 3, 0).expect("draw a");
    let b = iso.draw("closed-peer", 4, 0).expect("draw b");
    let rel = |items: &[(u64, u64)]| release(iso.s(), op(), items);
    assert_eq!(rel(&[(a.slice_id, 3)]), Ok(vec![3]), "fully returned");
    assert_eq!(
        rel(&[(b.slice_id, 4), (a.slice_id, 3)]),
        Ok(vec![4, 0]),
        "the closed slice answers 0 and the other item still lands"
    );
    assert_eq!(rel(&[(a.slice_id, 3)]), Ok(vec![0]));
    // Expired and reclaimed by a later reserve is closed too.
    let c = iso.draw("closed", 2, 0).expect("draw c");
    iso.advance_ms(TTL + 1);
    iso.draw("closed", 10, 0).expect("c's 2 came back");
    assert_eq!(rel(&[(c.slice_id, 2)]), Ok(vec![0]));
    let last: i64 = iso
        .admin
        .borrow_mut()
        .query_one(
            &format!(
                "SELECT pg_sequence_last_value('{}.money_slices_slice_id_seq'::regclass)",
                iso.schema
            ),
            &[],
        )
        .unwrap()
        .get(0);
    for never in [last as u64 + 1, last as u64 + 1000, u64::MAX, 0] {
        assert!(
            matches!(rel(&[(never, 1)]), Err(OpRefused::Failed(_))),
            "slice {never} was never granted"
        );
    }
}

/// Two nodes pushing the first cap of a new window at once: the higher generation wins whichever
/// lands first, and the same generation with a different cap is a CapConflict for exactly one.
#[test]
fn a_concurrent_first_cap_push_keeps_the_higher_generation() {
    let Some(url) = live_url() else {
        return;
    };
    const ROUNDS: usize = 150;
    let iso = Iso::new(&url);
    let barrier = std::sync::Barrier::new(2);
    let push = |cap: u64, gen: u64, tag: &'static str| {
        let node = iso.node();
        let barrier = &barrier;
        move || {
            (0..ROUNDS)
                .map(|i| {
                    barrier.wait();
                    node.window_caps(
                        op(),
                        &[Cap {
                            key: requests(&format!("race-{tag}-{i}")),
                            cap,
                            config_gen: gen,
                        }],
                    )
                })
                .collect::<Vec<_>>()
        }
    };
    // Round i of "lt" is gen 6 cap 200 against gen 5 cap 100; of "eq" gen 7 cap 100 against 200.
    let (hi, lo) = std::thread::scope(|sc| {
        let hi = sc.spawn(push(200, 6, "lt"));
        let lo = sc.spawn(push(100, 5, "lt"));
        (hi.join().unwrap(), lo.join().unwrap())
    });
    assert!(hi.iter().all(Result::is_ok), "{hi:?}");
    assert!(lo.iter().all(Result::is_ok), "{lo:?}");
    let mut admin = connect_client_with_retry(&iso.url);
    let rows = admin
        .query("SELECT slot, cap, config_gen FROM money_slots", &[])
        .unwrap();
    let lower_won = rows
        .iter()
        .filter(|r| r.get::<_, i64>(1) != 200 || r.get::<_, i64>(2) != 6)
        .count();
    assert_eq!(rows.len(), ROUNDS);
    assert_eq!(lower_won, 0, "a lower generation overwrote a higher one");

    let (x, y) = std::thread::scope(|sc| {
        let x = sc.spawn(push(100, 7, "eq"));
        let y = sc.spawn(push(200, 7, "eq"));
        (x.join().unwrap(), y.join().unwrap())
    });
    for (i, (x, y)) in x.iter().zip(&y).enumerate() {
        let ok = x.is_ok() as u8 + y.is_ok() as u8;
        let conflict = [x, y]
            .iter()
            .filter(|r| matches!(r, Err(CapsRefused::CapConflict { index: 0 })))
            .count();
        assert_eq!(
            (ok, conflict),
            (1, 1),
            "round {i}: the same generation with a different cap must conflict: {x:?} {y:?}"
        );
    }
}

/// A slice of 2^63 or more is stored as negative bits; it must still expire and come back.
#[test]
fn a_huge_expired_slice_returns_to_the_window() {
    let Some(url) = live_url() else {
        return;
    };
    let iso = Iso::new(&url);
    iso.cap("huge", u64::MAX);
    iso.draw("huge", u64::MAX - 1, 0).expect("a huge draw");
    iso.advance_ms(TTL + 1);
    iso.draw("huge", u64::MAX - 1, 0)
        .expect("the expired huge slice came back");
}

/// The v11 -> v12 step: slices a v11 build left open (granted `u64::MAX`, never expiring) are
/// stamped to expire one SLICE_TTL_MS after the upgrade, the epoch row exists at 0, and the step
/// runs once.
#[test]
fn the_v12_upgrade_stamps_open_slices_and_creates_the_epoch() {
    let Some(url) = live_url() else {
        return;
    };
    let mut iso = Iso::new(&url);
    iso.cap("legacy", 5);
    iso.draw("legacy", 5, 0).expect("a slice");
    {
        // Put the schema back to what a v11 build left: no epoch table, no expiry column.
        let mut c = iso.admin.borrow_mut();
        c.batch_execute(&format!(
            "DROP TABLE {0}.money_epoch;
             ALTER TABLE {0}.money_slices DROP COLUMN valid_until_ms;
             ALTER TABLE {0}.money_slices ADD COLUMN valid_until_ms BIGINT NOT NULL DEFAULT 0;
             DELETE FROM {0}.busbar_schema WHERE version >= 12;
             INSERT INTO {0}.busbar_schema (version) VALUES (11);",
            iso.schema
        ))
        .unwrap();
    }
    let before = iso.now_ms();
    iso.restart();
    let after = iso.now_ms();
    let (until, epoch): (i64, i64) = {
        let mut c = iso.admin.borrow_mut();
        let u = c
            .query_one(
                &format!("SELECT valid_until_ms FROM {}.money_slices", iso.schema),
                &[],
            )
            .unwrap()
            .get(0);
        let e = c
            .query_one(
                &format!("SELECT epoch FROM {}.money_epoch", iso.schema),
                &[],
            )
            .unwrap()
            .get(0);
        (u, e)
    };
    assert_eq!(epoch, 0);
    assert!(
        (before + TTL) as i64 <= until && until <= (after + TTL) as i64,
        "the stranded slice expires one TTL after the upgrade, not never: {until}"
    );
    iso.advance_ms(TTL + 1);
    iso.draw("legacy", 5, 0)
        .expect("the stranded slice's money came back");
}

/// A chain draw is all or nothing across cells: cell 1 exhausted is reported as cell 1 and cell 0's
/// slot is unchanged.
#[test]
fn a_multi_cell_reserve_is_all_or_nothing() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let (a, b) = (format!("{ns}-a"), format!("{ns}-b"));
    for (bucket, cap) in [(&a, 5), (&b, 1)] {
        s.window_caps(
            op(),
            &[Cap {
                key: requests(bucket),
                cap,
                config_gen: 1,
            }],
        )
        .unwrap();
    }
    let cells = |x: u64, y: u64| {
        [
            Cell {
                key: requests(&a),
                amount: x,
            },
            Cell {
                key: requests(&b),
                amount: y,
            },
        ]
    };
    assert_eq!(
        reserve(&s, op(), &cells(5, 2)),
        Err(ReserveRefused::Exhausted { cell: 1 })
    );
    let both = reserve(&s, op(), &cells(5, 1)).expect("cell 0 kept all its headroom");
    assert_eq!(both.len(), 2);
    assert_eq!(
        reserve(&s, op(), &cells(1, 1)),
        Err(ReserveRefused::Exhausted { cell: 0 })
    );
}

/// The per-dimension admission rules and the checked sum.
#[test]
fn the_dimension_rules_and_the_overflow_refusal() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let key = |bucket: &'static str, dimension| CellKey {
        bucket: Box::leak(format!("{ns}-{bucket}").into_boxed_str()),
        pool: None,
        dimension,
        window_start: 1_790_000_000_000,
    };
    let cap = |k: CellKey<'_>, cap| {
        s.window_caps(
            op(),
            &[Cap {
                key: k,
                cap,
                config_gen: 1,
            }],
        )
        .unwrap()
    };
    let draw = |k: CellKey<'_>, amount| reserve(&s, op(), &[Cell { key: k, amount }]);

    // Class: best effort, the draw that crosses the cap is granted whole; at the cap it is refused.
    let class = key("class", Dimension::Class("tok"));
    cap(class, 10);
    assert_eq!(draw(class, 9).unwrap()[0].granted, 9);
    assert_eq!(
        draw(class, 5).unwrap()[0].granted,
        5,
        "crossing, granted whole"
    );
    assert_eq!(draw(class, 1), Err(ReserveRefused::Exhausted { cell: 0 }));

    // Concurrency: a gauge, `used + amount > cap` refuses, a release reopens it.
    let gauge = key("gauge", Dimension::Concurrency);
    cap(gauge, 2);
    let g1 = draw(gauge, 1).unwrap()[0];
    draw(gauge, 1).unwrap();
    assert_eq!(draw(gauge, 1), Err(ReserveRefused::Exhausted { cell: 0 }));
    assert_eq!(release(&s, op(), &[(g1.slice_id, 1)]), Ok(vec![1]));
    draw(gauge, 1).expect("the released permit is drawable");

    // NanoUnits: refused at the cap and when the draw would cross it.
    let nano = key("nano", Dimension::NanoUnits);
    cap(nano, 10);
    assert_eq!(draw(nano, 11), Err(ReserveRefused::Exhausted { cell: 0 }));
    draw(nano, 10).unwrap();

    // A sum past u64::MAX is a refusal, never a wrap or a saturated grant.
    let big = key("big", Dimension::Requests);
    cap(big, u64::MAX);
    draw(big, u64::MAX - 1).unwrap();
    assert_eq!(draw(big, 5), Err(ReserveRefused::Exhausted { cell: 0 }));
}

/// A newer generation replaces the cap, an older one is ignored.
#[test]
fn window_caps_a_newer_generation_replaces_and_an_older_is_ignored() {
    let Some(url) = live_url() else {
        return;
    };
    let ns = ns();
    let s = store(&url);
    let push = |cap, config_gen| {
        s.window_caps(
            op(),
            &[Cap {
                key: requests(&ns),
                cap,
                config_gen,
            }],
        )
    };
    let stored = || -> (i64, i64) {
        let r = s
            .lock()
            .query_one(
                "SELECT cap, config_gen FROM money_slots WHERE slot LIKE '%' || $1 || '%'",
                &[&ns],
            )
            .unwrap();
        (r.get(0), r.get(1))
    };
    push(5, 1).unwrap();
    push(8, 2).unwrap();
    assert_eq!(stored(), (8, 2), "the newer generation replaced the cap");
    push(3, 1).unwrap();
    assert_eq!(stored(), (8, 2), "an older generation was ignored");
    push(8, 2).unwrap();
    assert_eq!(push(9, 2), Err(CapsRefused::CapConflict { index: 0 }));
}

/// Two nodes appending to one stream at once both land, with distinct contiguous seqs.
#[test]
fn concurrent_append_batches_on_one_stream_both_land() {
    let Some(url) = live_url() else {
        return;
    };
    const ROUNDS: usize = 60;
    let ns = ns();
    let barrier = std::sync::Barrier::new(2);
    let run = || {
        let node = store(&url);
        let (ns, barrier) = (&ns, &barrier);
        move || {
            let rows: Vec<RecordBytes> = (0..3u8)
                .map(|i| RecordBytes::new(vec![i]).unwrap())
                .collect();
            (0..ROUNDS)
                .map(|i| {
                    barrier.wait();
                    node.append_batch(op(), &format!("{ns}-{i}"), &rows)
                })
                .collect::<Vec<_>>()
        }
    };
    let (x, y) = std::thread::scope(|sc| {
        let (x, y) = (sc.spawn(run()), sc.spawn(run()));
        (x.join().unwrap(), y.join().unwrap())
    });
    for (i, (x, y)) in x.iter().zip(&y).enumerate() {
        let mut seqs = [
            x.as_ref().ok().map(|h| h.seq),
            y.as_ref().ok().map(|h| h.seq),
        ];
        seqs.sort();
        assert_eq!(seqs, [Some(3), Some(6)], "round {i}: {x:?} {y:?}");
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

/// Rule (c): past `valid_until_ms` a slice IS expired and its unreturned part went back to headroom
/// at expiry, so a release of it answers 0 even when no reserve has reclaimed it yet, and the
/// headroom comes back exactly once.
#[test]
fn a_release_of_an_expired_slice_returns_zero_and_headroom_returns_once() {
    let Some(url) = live_url() else {
        return;
    };
    let iso = Iso::new(&url);
    iso.cap("expired-release", 5);
    let g = iso
        .draw("expired-release", 5, 0)
        .expect("draws the whole cap");
    // NO reserve between the expiry and the release: the slice is still a row.
    iso.advance_ms(TTL + 1);
    assert_eq!(
        release(iso.s(), op(), &[(g.slice_id, 5)]),
        Ok(vec![0]),
        "an expired slice's remainder is already back in headroom"
    );
    iso.draw("expired-release", 5, 0)
        .expect("the whole cap is drawable again");
    assert_eq!(
        iso.draw("expired-release", 1, 0).map(drop),
        Err(ReserveRefused::Exhausted { cell: 0 }),
        "headroom came back exactly once"
    );
}

/// A `MakeWriter` that keeps what the subscriber writes, for asserting on a log line.
#[derive(Clone, Default)]
struct LogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> LogSink {
        self.clone()
    }
}

/// `ReserveRefused::Unavailable` has no payload on the ABI, so the reason it drops is logged first
/// (inside a door call the plugin's `tracing` events are captured into its own log). Every site that
/// answers Unavailable goes through `reserve_unavailable`; the line carries the reason it is given
/// (SQLSTATE and message, already free of the DSN's password) and the answer stays Unavailable.
///
/// The door call itself cannot be observed from a logic-crate test: the door swaps in the contract's
/// call capture as the thread's subscriber for the span of the call, so a subscriber installed here
/// sees nothing from inside it. The helper is therefore driven directly, and the live path that
/// reaches it is covered by the Unavailable answer below.
#[test]
fn an_unavailable_reserve_logs_the_reason_it_drops() {
    let sink = LogSink::default();
    let sub = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .finish();
    let refused = tracing::subscriber::with_default(sub, || {
        crate::v3::reserve_unavailable("42P01: relation \"money_epoch\" does not exist".into())
    });
    assert_eq!(refused, ReserveRefused::Unavailable);
    let log = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(
        log.contains("WARN") && log.contains("reserve refused as unavailable"),
        "{log}"
    );
    assert!(
        log.contains("42P01") && log.contains("money_epoch"),
        "{log}"
    );
    assert!(!log.contains("postgres://"), "never the DSN: {log}");

    // And the live path: a reserve whose fence table is gone answers Unavailable.
    let Some(url) = live_url() else {
        return;
    };
    let iso = Iso::new(&url);
    iso.cap("unavail", 5);
    iso.admin
        .borrow_mut()
        .batch_execute(&format!("DROP TABLE {}.money_epoch", iso.schema))
        .unwrap();
    assert_eq!(
        iso.draw("unavail", 1, 0).map(drop),
        Err(ReserveRefused::Unavailable)
    );
}
