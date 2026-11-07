// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Kept-connection bounds and EOF recovery through the actual Postgres door and real server.

use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use busbar_contract::persistence::*;

use super::native_tests::{
    address, assert_applied, candidate, open, page, put, read, run, Fixture,
};

fn tagged_url(url: &str, tag: &str) -> String {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        let separator = if url.contains('?') { '&' } else { '?' };
        format!("{url}{separator}application_name={tag}")
    } else {
        format!("{url} application_name={tag}")
    }
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
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn concurrent_product_ops_wait_beyond_the_actual_kept_connection_bound() {
    let fixture = Fixture::fresh();
    let url = fixture.url.clone();
    let tag = format!("bb_wire_bound_{}", std::process::id());
    let store = open(&tagged_url(&url, &tag));
    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut blocker = raw.transaction().expect("begin the real table lock");
    blocker
        .batch_execute("LOCK TABLE busbar_persistence_v4.records IN ACCESS EXCLUSIVE MODE")
        .expect("hold all product reads at the real database");
    let operations = crate::KEPT_CONNECTIONS + 4;
    let start = Arc::new(Barrier::new(operations + 1));
    let workers: Vec<_> = (0..operations)
        .map(|_| {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                page(&store, 80, None, None, 100)
            })
        })
        .collect();
    start.wait();
    let mut observer = postgres::Client::connect(&url, postgres::NoTls).unwrap();
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
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn a_closed_product_connection_fails_its_write_and_the_next_op_connects_fresh() {
    let fixture = Fixture::fresh();
    let url = fixture.url.clone();
    let tag = format!("bb_wire_eof_{}", std::process::id());
    let store = open(&tagged_url(&url, &tag));
    let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
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
    let failed_key = address(80, b"failed-eof");
    let original = candidate(
        &store,
        2,
        1,
        vec![],
        vec![put(failed_key.clone(), b"closed")],
        None,
    );
    assert!(
        run(store.commit(original)).is_err(),
        "the write on the terminated kept connection reports EOF/unknown"
    );
    let fresh_key = address(80, b"fresh-eof");
    assert_applied(run(store.commit(candidate(
        &store,
        3,
        1,
        vec![],
        vec![put(fresh_key.clone(), b"fresh")],
        None,
    ))));
    let after = backends(&mut raw, &tag);
    assert_eq!(after.len(), 1, "the new connection is kept");
    assert_ne!(after, before, "the next operation connects afresh");
    let ReadResult::Values { values, .. } =
        read(&store, vec![failed_key, fresh_key], None).unwrap()
    else {
        panic!("native read values")
    };
    assert!(
        values[0].is_none(),
        "the EOF attempt had no effects in this terminated-connection fixture"
    );
    assert!(values[1].is_some(), "the fresh native commit is readable");
}
