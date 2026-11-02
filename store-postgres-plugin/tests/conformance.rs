// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE POSTGRES STORE, BOTH DOORS, ONE TABLE** — the store's linked + dropped-in conformance on

mod common;

#[path = "support/door_refusals.rs"]
mod door_refusals;
#[path = "support/host_boundaries.rs"]
mod host_boundaries;
#[path = "support/store_contract.rs"]
mod store_contract;

/// The live Postgres's address (`BUSBAR_TEST_POSTGRES_URL`'s authority; the service container's
fn upstream() -> &'static str {
    static AT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    AT.get_or_init(|| {
        let url = std::env::var("BUSBAR_TEST_POSTGRES_URL").unwrap_or_default();
        url.split_once("://")
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.rsplit_once('@').map_or(Some(rest), |(_, at)| Some(at)))
            .and_then(|at| at.split('/').next())
            .filter(|at| !at.is_empty())
            .unwrap_or("localhost:5432")
            .to_owned()
    })
}

/// The live server a fold's filled settings name, on a connection of the `postgres` driver's own.
fn fold_client(settings: &[u8]) -> postgres::Client {
    let v: serde_json::Value =
        serde_json::from_slice(settings).expect("conformance.json's settings are JSON");
    let url = v["url"]
        .as_str()
        .expect("conformance.json's settings name a url");

    let url = url
        .replace("localhost:52670", upstream())
        .replace("sslmode=require", "sslmode=disable");
    postgres::Client::connect(&url, postgres::NoTls)
        .expect("the live Postgres accepts the test client")
}

fn stamp_newer_schema(_: &str, settings: &[u8]) {
    fold_client(settings)
        .execute(
            "INSERT INTO busbar_schema (version) VALUES ($1)",
            &[&i64::MAX],
        )
        .expect("stamp a newer schema in the fold's private schema");
}

/// The suite's namespace hook: the fold's schema, made before its open.
fn create_fold_schema(namespace: &str, settings: &[u8]) {
    fold_client(settings)
        .batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS \"{namespace}\""))
        .expect("the fold's schema is created");
}

/// The suite's namespace hook: the fold's schema and everything the store made in it, dropped after
fn drop_fold_schema(namespace: &str, settings: &[u8]) {
    fold_client(settings)
        .batch_execute(&format!("DROP SCHEMA IF EXISTS \"{namespace}\" CASCADE"))
        .expect("the fold's schema is dropped");
}

use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore};
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher,
    LinkedRow, NoSink, Plugin,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use std::sync::Arc;

/// The live Postgres, by this repo's one gate: set → `Some`; unset under CI → a FAILURE (the
fn live_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => panic!(
            "BUSBAR_TEST_POSTGRES_URL is unset under CI: the Postgres service container must \
             provision it. Refusing to skip the durable half of the both-doors conformance."
        ),
        Err(_) => {
            eprintln!("skip (durable scenario only): set BUSBAR_TEST_POSTGRES_URL");
            None
        }
    }
}

/// One durable scenario through `store`, every id namespaced by `ns` so the two doors (and
fn scenario(store: &dyn RecordStore, ns: &str) -> serde_json::Value {
    let kind = "conformance_task";
    let child = "conformance_event";
    let id = format!("{ns}-task");
    let rec = |kind: &str, id: String, parent: Option<String>, seq: u64, body: &str| PlaneRecord {
        kind: kind.into(),
        id,
        parent,
        seq,
        ts: 1_700_000_000 + seq,
        disposition: PlaneDisposition::Active,
        body: body.as_bytes().to_vec(),
    };
    let text = |b: Option<Vec<u8>>| b.map(|b| String::from_utf8_lossy(&b).into_owned());
    store
        .upsert_plane_record(rec(kind, id.clone(), None, 0, "v1").view())
        .expect("upsert");
    store
        .upsert_plane_record(rec(kind, id.clone(), None, 0, "v2").view())
        .expect("upsert over");
    let got = text(store.get_plane_record(kind, &id).expect("get"));
    for seq in 1..=2 {
        store
            .append_plane_record(
                rec(
                    child,
                    format!("{ns}-e{seq}"),
                    Some(id.clone()),
                    seq,
                    &format!("event {seq}"),
                )
                .view(),
            )
            .expect("append");
    }
    let chain: Vec<String> = store
        .list_plane_records(child, &PlaneSelector::Parent(id.clone().into()))
        .expect("list")
        .into_iter()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .collect();
    let token = format!("{ns}-token");
    let first = store
        .redeem_plane_token("conformance_token", &token, u64::MAX, 1_900_000_000)
        .expect("redeem");
    let second = store
        .redeem_plane_token("conformance_token", &token, u64::MAX, 1_900_000_000)
        .expect("redeem again");
    store.delete_plane_record(kind, &id).expect("delete");

    store
        .delete_plane_record(child, &id)
        .expect("delete the event chain");
    let gone = text(store.get_plane_record(kind, &id).expect("get after delete"));
    serde_json::json!({
        "after_upsert": got,
        "chain": chain,
        "redeemed": [first, second],
        "after_delete": gone,
    })
}

/// What one door does with the store, as one comparable transcript.
fn transcript(
    tag: &str,
    open: &dyn Fn(&str) -> Result<LoadedStore, String>,
    live: Option<&str>,
) -> serde_json::Value {
    let refusals: Vec<String> = [
        "",
        "{}",
        "{ not json",
        r#"{"url": 5}"#,
        r#"{"url": "host=127.0.0.1 port=1 user=conf password=s3cret-conf dbname=x connect_timeout=2"}"#,
    ]
    .iter()
    .map(|cfg| match open(cfg) {
        Ok(_) => format!("opened with {cfg:?}"),
        Err(e) => e,
    })
    .collect();
    let durable = live.map(|url| {
        let cfg = serde_json::json!({ "url": url }).to_string();
        let store = open(&cfg).expect("the store opens");
        let ns = format!("conf-{}-{tag}", std::process::id());
        scenario(&store, &ns)
    });
    serde_json::json!({
        "refusals": refusals,
        "durable": durable,
    })
}

/// The Postgres store behaves as ONE store through either door; the RED arms below show the
#[test]
fn the_linked_and_the_dropped_in_postgres_store_are_one_store() {
    let live = live_url();

    let linked = transcript("linked", &common::linked, live.as_deref());
    let dropped_in = transcript("dropped", &common::dropped, live.as_deref());
    assert_eq!(linked, dropped_in, "the two doors are not one store");

    let refusals = linked["refusals"].as_array().unwrap();
    assert_eq!(
        refusals[0],
        "plugin 'busbar-store-postgres' open failed: invalid postgres plugin config: `url` is \
         required (a libpq connection string)"
    );
    assert_eq!(refusals[1], refusals[0]);
    assert!(
        refusals[2].as_str().unwrap().starts_with(
            "plugin 'busbar-store-postgres' open failed: invalid postgres plugin config:"
        ),
        "{refusals:?}"
    );
    assert_eq!(
        refusals[3],
        "plugin 'busbar-store-postgres' open failed: invalid postgres plugin config: url: \
         settings: invalid type: integer `***`, expected a string",
        "a present non-string url says so"
    );
    let unreachable = refusals[4].as_str().unwrap();
    assert!(
        unreachable.contains("postgres store: failed to connect: ")
            && unreachable.contains("error connecting to server"),
        "the unreachable server is refused as a connect failure: {unreachable}"
    );
    assert!(
        !unreachable.contains("s3cret-conf"),
        "the refusal never echoes the DSN password: {unreachable}"
    );
    if live.is_some() {
        assert_eq!(
            linked["durable"],
            serde_json::json!({
                "after_upsert": "v2",
                "chain": ["event 1", "event 2"],
                "redeemed": [true, false],
                "after_delete": null,
            })
        );
    }
}

/// RED: DIFFERENT bytes (the object's magic broken) are not the store. The foreign image is
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
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
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

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{UsageDelta, VirtualKey};
use busbar_plugin_loader::dispatch::kinds::store::Store;
type Loaded = (Plugin<Store>, Arc<Dispatcher>);
fn linked() -> Loaded {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(busbar_store_postgres::door).expect("Postgres statement");
    let p = load_linked::<Store>(&row, common::bind(&d)).expect("linked Postgres loads");
    (p, d)
}
fn dropped(lib: &std::path::Path, stated: &[u8]) -> Loaded {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_dropped::<Store>(lib, stated, common::bind(&d)).expect("dropped Postgres loads");
    (p, d)
}
fn cdylib() -> std::path::PathBuf {
    common::plugin_path()
}
fn packed_rendering(lib: &std::path::Path) -> Vec<u8> {
    rendering_of_library(lib)
        .expect("library rendering")
        .expect("door exists")
}
fn inputs() -> String {
    let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!("BUSBAR_TEST_POSTGRES_URL must name CI's provisioned Postgres service")
        }
        Err(_) => "postgres://busbar:busbar@localhost:5432/busbar_test".into(),
    };
    let separator = if url.contains('?') { '&' } else { '?' };
    let mut config: serde_json::Value =
        serde_json::from_str(include_str!("conformance.json")).unwrap();
    config["settings"]["url"] = serde_json::json!(format!(
        "{url}{separator}options=-c%20search_path%3D{{fold}}"
    ));
    config.to_string()
}
