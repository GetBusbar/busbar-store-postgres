// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{MeteringDelta, ModelTokens};
use std::time::{Duration, Instant};

#[test]
fn an_absolute_usage_write_waits_on_the_window_before_touching_its_ledger() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_usage_order");
    let writer = TestStore::open(&db.url()).unwrap();
    let reader = TestStore::open(&db.url()).unwrap();
    let ledger = UsageLedger {
        requests: 7,
        billable_requests: 7,
        models: vec![ModelTokens {
            model: "model".into(),
            usage_units: [("tokens_input".into(), 1)].into_iter().collect(),
        }],
    };
    writer.put_usage("bucket", 60, &ledger).unwrap();
    let mut holder = connect_client_with_retry(&db.url());
    let mut probe = connect_client_with_retry(&db.url());
    probe.batch_execute("BEGIN").unwrap();
    let pid: i32 = holder
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    holder.batch_execute("BEGIN; SELECT * FROM usage_windows WHERE bucket_id='bucket' AND window_start=60 FOR UPDATE").unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = tx.send(writer.put_usage("bucket", 60, &ledger));
    });
    let until = Instant::now() + Duration::from_secs(5);
    let observed = loop {
        match holder.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))", &[&pid]) {
            Ok(row) if row.get::<_, bool>(0) => break Ok(true),
            Ok(_) if Instant::now() >= until => break Ok(false),
            Ok(_) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => break Err(error),
        }
    };
    let ledger_lock = probe.query("SELECT model FROM usage_ledger WHERE bucket_id='bucket' AND window_start=60 FOR UPDATE NOWAIT", &[]);
    let probe_released = probe.batch_execute("ROLLBACK");
    let holder_released = holder.batch_execute("ROLLBACK");
    let written = rx.recv_timeout(Duration::from_secs(5));
    worker.join().unwrap();
    probe_released.unwrap();
    holder_released.unwrap();
    assert!(
        observed.unwrap(),
        "the actual store client must reach the window lock wait"
    );
    assert!(
        ledger_lock.is_ok(),
        "a writer waiting on its window must not already lock/delete ledger rows"
    );
    written.unwrap().unwrap();
    assert_eq!(reader.get_usage("bucket", 60).unwrap().requests, 7);
}

#[test]
fn usage_model_lists_cross_the_existing_bind_frame_width_without_a_new_admission_limit() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_usage_bind");
    let store = TestStore::open(&db.url()).unwrap();
    let count = (usize::from(u16::MAX) - 2) / 5 + 1;
    let ledger = UsageLedger {
        requests: 7,
        billable_requests: 7,
        models: (0..count)
            .map(|i| ModelTokens {
                model: format!("m{i}"),
                usage_units: [("tokens_input".into(), 1)].into_iter().collect(),
            })
            .collect(),
    };
    store
        .put_usage("bucket", 60, &ledger)
        .expect("a valid list can span Bind frames");
    let got = store.get_usage("bucket", 60).unwrap();
    assert_eq!(got.models.len(), count);
    assert_eq!(got.requests, 7);
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: (0..count)
            .map(|i| mtd(format!("m{i}"), 1, 0, 0, 0))
            .collect(),
    };
    store.add_usage("bucket", 60, &delta).unwrap();
    let got = store.get_usage("bucket", 60).unwrap();
    assert_eq!(got.requests, 8);
    assert!(got
        .models
        .iter()
        .all(|model| model.tier("tokens_input") == 2));
    let mut invalid = ledger;
    invalid.requests = 999;
    invalid.models[0]
        .usage_units
        .insert("tokens_input".into(), 99);
    invalid.models.push(invalid.models[0].clone());
    assert!(store.put_usage("bucket", 60, &invalid).is_err());
    let unchanged = store.get_usage("bucket", 60).unwrap();
    assert_eq!(
        unchanged.requests, 8,
        "a later chunk failure rolls the counter back too"
    );
    assert_eq!(unchanged.models.len(), count);
    assert!(unchanged
        .models
        .iter()
        .all(|model| model.tier("tokens_input") == 2));
}

#[test]
fn open_usage_and_metering_unit_lists_cross_the_bind_frame_width_atomically() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_units_bind");
    let store = TestStore::open(&db.url()).unwrap();
    let count = (usize::from(u16::MAX) - 5) / 2 + 1;
    let units: BTreeMap<String, u64> = (0..count).map(|i| (format!("unit{i}"), 1)).collect();
    let ledger = UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            model: "model".into(),
            usage_units: units.clone(),
        }],
    };
    store.put_usage("bucket", 60, &ledger).unwrap();
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokensDelta {
            model: "model".into(),
            usage_units: units.iter().map(|(k, v)| (k.clone(), *v as i64)).collect(),
        }],
    };
    store.add_usage("bucket", 60, &delta).unwrap();
    let got = store.get_usage("bucket", 60).unwrap();
    assert_eq!(got.models[0].usage_units.len(), count);
    assert!(got.models[0].usage_units.values().all(|value| *value == 2));
    let metering = MeteringDelta {
        key_id: "key".into(),
        bucket: 60,
        model: "model".into(),
        provider: "provider".into(),
        tokens_input: 0,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: units,
    };
    store.add_metering(&metering).unwrap();
    let got = store.list_metering(60).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].usage_units.len(), count);
    assert!(got[0].usage_units.values().all(|value| *value == 1));
}
