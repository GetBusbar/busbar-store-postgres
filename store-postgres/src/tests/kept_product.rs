// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Kept-connection bounds and EOF recovery through the actual Postgres door and real server.

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use busbar_contract::records::RecordStore;

use super::{connect_client_with_retry, harness::open_loaded, live_url, TempDb};

fn tagged_url(url: &str, tag: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}application_name={tag}")
}

fn backends(raw: &mut postgres::Client, tag: &str) -> Vec<i32> {
    raw.query(
        "SELECT pid FROM pg_stat_activity WHERE application_name=$1 ORDER BY pid",
        &[&tag],
    )
    .expect("observe the actual server backends")
    .iter()
    .map(|row| row.get(0))
    .collect()
}

#[test]
fn concurrent_product_ops_wait_beyond_the_actual_kept_connection_bound() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_wire_bound");
    let url = database.url();
    let tag = format!("bb_wire_bound_{}", std::process::id());
    let settings = serde_json::json!({"url": tagged_url(&url, &tag)}).to_string();
    let store = Arc::new(open_loaded(&settings).expect("the actual store opens"));
    let mut raw = connect_client_with_retry(&url);
    let mut blocker = raw.transaction().expect("begin the real table lock");
    blocker
        .batch_execute("LOCK TABLE denylist IN ACCESS EXCLUSIVE MODE")
        .expect("hold all product reads at the real database");
    let operations = crate::KEPT_CONNECTIONS + 4;
    let start = Arc::new(Barrier::new(operations + 1));
    let workers: Vec<_> = (0..operations)
        .map(|_| {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                RecordStore::list_denylist(&*store)
            })
        })
        .collect();
    start.wait();
    let mut observer = connect_client_with_retry(&url);
    let deadline = Instant::now() + Duration::from_secs(15);
    let held = loop {
        let held = backends(&mut observer, &tag);
        assert!(
            held.len() <= crate::KEPT_CONNECTIONS,
            "actual server connections exceed the product bound: {held:?}"
        );
        if held.len() == crate::KEPT_CONNECTIONS {
            break held;
        }
        assert!(
            Instant::now() < deadline,
            "all bounded connections reach the database: {held:?}"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        workers.iter().all(|worker| !worker.is_finished()),
        "the real table lock holds every read, including the operations waiting for a lease"
    );
    blocker.commit().expect("release the real database lock");
    for worker in workers {
        worker
            .join()
            .expect("the operation thread")
            .expect("every queued read completes");
    }
    assert_eq!(
        backends(&mut observer, &tag),
        held,
        "queued operations reuse the bounded physical backends rather than opening extras"
    );
}

#[test]
fn a_closed_product_connection_fails_its_write_and_the_next_op_connects_fresh() {
    let Some(url) = live_url() else { return };
    let database = TempDb::create(&url, "spg_wire_eof");
    let url = database.url();
    let tag = format!("bb_wire_eof_{}", std::process::id());
    let settings = serde_json::json!({"url": tagged_url(&url, &tag)}).to_string();
    let store = open_loaded(&settings).expect("the actual store opens");
    let mut raw = connect_client_with_retry(&url);
    let before = backends(&mut raw, &tag);
    assert_eq!(before.len(), 1, "opening leaves exactly one kept backend");
    let terminated: bool = raw
        .query_one("SELECT pg_terminate_backend($1)", &[&before[0]])
        .expect("the owned test server terminates its actual backend")
        .get(0);
    assert!(terminated);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !backends(&mut raw, &tag).is_empty() {
        assert!(Instant::now() < deadline, "the old backend exits");
        std::thread::sleep(Duration::from_millis(10));
    }
    let failed_key = format!("{tag}-failed");
    assert!(
        RecordStore::add_denylist(&store, &failed_key, "closed").is_err(),
        "a write on the terminated kept connection reports the actual EOF/refusal"
    );
    let fresh_key = format!("{tag}-fresh");
    RecordStore::add_denylist(&store, &fresh_key, "fresh")
        .expect("the next product operation connects afresh");
    let after = backends(&mut raw, &tag);
    assert_eq!(after.len(), 1, "the new connection is kept");
    assert_ne!(
        after, before,
        "the fresh operation runs on a different real backend"
    );
    assert!(RecordStore::list_denylist(&store)
        .expect("the fresh read")
        .contains(&fresh_key));
    assert!(!RecordStore::list_denylist(&store)
        .expect("the failed write left no row")
        .contains(&failed_key));
    raw.execute("DELETE FROM denylist WHERE sub=$1", &[&fresh_key])
        .expect("remove the owning test row");
}
