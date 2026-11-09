// SPDX-License-Identifier: Apache-2.0
//! Native persistence conformance through the actual linked and dropped PostgreSQL doors.
mod common;
#[path = "support/door_refusals.rs"]
mod door_refusals;
#[path = "support/host_boundaries.rs"]
mod host_boundaries;
#[path = "support/store_contract.rs"]
mod store_contract;
use busbar_contract::persistence::*;
use busbar_plugin_loader::dispatch::kinds::{secret::Secret, store_v4::StoreV4 as Store};
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher,
    LinkedRow, NoSink, Plugin,
};
use busbar_plugin_loader::store_v4::LoadedPersistence;
use std::sync::Arc;
type Loaded = (Plugin<Store>, Arc<Dispatcher>);
fn linked() -> Loaded {
    let d = common::dispatcher();
    let row = LinkedRow::of_kind::<Store>(
        busbar_store_postgres::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
    .unwrap();
    (load_linked::<Store>(&row, common::bind(&d)).unwrap(), d)
}
fn dropped(lib: &std::path::Path, stated: &[u8]) -> Loaded {
    let d = common::dispatcher();
    (
        load_dropped::<Store>(lib, stated, common::bind(&d)).unwrap(),
        d,
    )
}
fn cdylib() -> std::path::PathBuf {
    common::plugin_path()
}
fn packed_rendering(lib: &std::path::Path) -> Vec<u8> {
    rendering_of_library(lib).unwrap().unwrap()
}
fn open(load: Loaded, settings: &[u8]) -> Result<LoadedPersistence, String> {
    common::run(LoadedPersistence::open(
        load.0,
        load.1,
        settings,
        common::limits(),
    ))
}
fn scenario(store: &LoadedPersistence, url: &str) -> serde_json::Value {
    common::initialize(store);
    let at = common::address(9, b"opaque-value");
    assert!(matches!(
        common::commit(store, 2, vec![], vec![common::put(at.clone(), b"v1")]),
        Decision::Applied(_)
    ));
    let exact = Predicate {
        address: at.clone(),
        expected: ExpectedValue::Exact(busbar_contract::Secret::new(b"v1".to_vec())),
    };
    assert!(matches!(
        common::commit(store, 3, vec![exact], vec![common::put(at.clone(), b"v2")]),
        Decision::Applied(_)
    ));
    assert!(common::present(store, at.clone()));
    let raw = common::raw_value(url, &at).unwrap();
    let scanned = common::run(store.scan(Arc::new(Scan {
        dataset: store.info().dataset,
        namespace: NamespaceId(at.namespace),
        prefix: vec![],
        after: None,
        generation: None,
        max_items: 10,
        max_bytes: 4096,
        allow_change: true,
    })))
    .unwrap();
    assert_eq!(scanned.rows.len(), 1);
    assert!(scanned.next.is_none());
    let first = common::commit(
        store,
        4,
        vec![Predicate {
            address: common::address(9, b"once"),
            expected: ExpectedValue::Absent,
        }],
        vec![common::put(common::address(9, b"once"), b"spent")],
    );
    let second = common::commit(
        store,
        5,
        vec![Predicate {
            address: common::address(9, b"once"),
            expected: ExpectedValue::Absent,
        }],
        vec![common::put(common::address(9, b"once"), b"spent")],
    );
    assert!(matches!(first, Decision::Applied(_)));
    assert!(matches!(second, Decision::ConditionConflict));
    assert!(matches!(
        common::commit(store, 6, vec![], vec![Mutation::Delete(at.clone())]),
        Decision::Applied(_)
    ));
    assert!(!common::present(store, at));
    serde_json::json!({"after_upsert":String::from_utf8(raw).unwrap(),"first_claim":true,"second_claim":false,"after_delete":null,"scan_rows":scanned.rows.len()})
}
fn transcript(
    open: &dyn Fn(&str) -> Result<LoadedPersistence, String>,
    live: Option<&str>,
) -> serde_json::Value {
    let refusals:Vec<_>=["","{}","{ not json",r#"{"url":5}"#,r#"{"url":"host=127.0.0.1 port=1 user=conf password=s3cret-conf dbname=x connect_timeout=2"}"#].iter().map(|s|open(s).expect_err("invalid settings refused")).collect();
    assert!(refusals[..4]
        .iter()
        .all(|s| s == "primitive store open failed"));
    assert!(!refusals[4].contains("s3cret-conf"));
    let durable = live.map(|url| {
        let database = common::temp_db::TempDb::create(url, "pg_transcript");
        let url = database.url();
        let store = open(&serde_json::json!({"url":url}).to_string()).unwrap();
        scenario(&store, &url)
    });
    serde_json::json!({"refusals":refusals,"durable":durable})
}
#[test]
fn the_linked_and_the_dropped_in_postgres_store_are_one_store() {
    let live = common::postgres_url();
    assert_eq!(
        transcript(&common::linked, live.as_deref()),
        transcript(&common::dropped, live.as_deref())
    );
}
/// RED: DIFFERENT bytes (the object's magic broken) are not the store. The foreign image is
/// written under its own directory, so the loader `dlopen`s a path no good image was ever loaded
/// from, whatever order the tests in this target run in.
#[test]
fn foreign_bytes_dropped_in_are_not_the_postgres_store() {
    let lib = common::plugin_path();
    let mut foreign = std::fs::read(&lib).expect("read the cdylib");
    foreign[..4].copy_from_slice(b"XXXX");
    let dir = std::env::temp_dir().join(format!("store-postgres-conf-red-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let broken = dir.join(lib.file_name().unwrap());
    std::fs::write(&broken, &foreign).unwrap();
    let red = match common::dropped_at(&broken, "{}") {
        Ok(_) => panic!("foreign bytes opened as the store"),
        Err(e) => e,
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        !red.contains("`url` is required"),
        "foreign bytes cannot speak the store's own refusal: {red}"
    );
}

/// RED: the store's library asked for as another kind is refused before any slot runs.
#[test]
fn the_postgres_store_library_loaded_as_another_kind_is_refused() {
    let lib = common::plugin_path();
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let bind = Bind {
        instance: Arc::from("store-postgres-as-secret"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    assert!(
        load_dropped::<Secret>(&lib, &common::stated(), bind).is_err(),
        "a store library loaded as kind secret"
    );
}

#[test]
fn fresh_linked_and_dropped_images_open_ready_read_and_close() {
    let admin = common::postgres_url().expect("owned live PostgreSQL fixture required");
    for use_dropped in [false, true] {
        let database = common::temp_db::TempDb::create(&admin, "pg_lifecycle");
        let settings = serde_json::to_vec(&serde_json::json!({"url":database.url()})).unwrap();
        let store = open(
            if use_dropped {
                dropped(&cdylib(), &common::stated())
            } else {
                linked()
            },
            &settings,
        )
        .unwrap();
        common::run(store.clock(store.info().dataset)).unwrap();
        assert!(!common::present(&store, common::address(9, b"absent")));
        drop(store);
    }
}
