// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE POSTGRES STORE, BOTH DOORS, ONE TABLE** — the store's linked + dropped-in conformance on
//! the store kind's door (THE DESIGN §11), run against the busbar rev this repo pins
//! (`.busbar-ref`).
//!
//! The store is held two ways at once: COMPILED IN (the logic crate's `door`, the row a busbar build
//! that links it registers) and DROPPED IN (this crate's built cdylib, admitted against the same
//! Statement). Each is opened through the store v3 table and must agree, byte for byte, on:
//!
//! * the Statement both doors render;
//! * every refusal the store's own `open` gives (no config, an empty object, malformed JSON, a
//!   non-string url, and an unreachable server — which proves the plugin's own connect path runs,
//!   and that it scrubs nothing it should not);
//! * with a live Postgres (`BUSBAR_TEST_POSTGRES_URL`, the same gate the rest of this repo's live
//!   tests use: unset under CI is a FAILURE, unset locally skips only this scenario), one durable
//!   scenario per door — upsert, point read, a child chain, single-use token redemption, delete.
//!
//! RED ARMS, each its own test and always run (no database needed): the library asked for as
//! `kind: secret` is refused before any slot is called, and DIFFERENT bytes (the cdylib with its
//! object magic broken) are not the store — so the comparison above cannot pass vacuously.

mod common;

// THE PUBLISHED SUITE (busbar-plugin-loader's `conformance` feature, at the pin): the linked door and
// the built cdylib, each through the one loader, driven by the store kind's script over the live
// Postgres `conformance.json` names; exact crossing counts, the two folds equal, its RED arms.
busbar_plugin_loader::conformance_suite! {
    door: busbar_store_postgres::door,
    cdylib: "busbar_store_postgres_plugin",
    inputs: include_str!("conformance.json"),
}

use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore};
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{load_dropped, Bind, DispatchConfig, Dispatcher, NoSink};
use busbar_plugin_loader::store_v3::LoadedStore;
use std::sync::Arc;

/// The live Postgres, by this repo's one gate: set → `Some`; unset under CI → a FAILURE (the
/// service container must provision it); unset locally → `None` (the durable scenario is skipped,
/// everything else still runs).
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
/// concurrent runs) never read each other's rows; the transcript names ids WITHOUT the namespace.
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
        .redeem_plane_token("conformance_token", &token, 2_000_000_000, 1_900_000_000)
        .expect("redeem");
    let second = store
        .redeem_plane_token("conformance_token", &token, 2_000_000_000, 1_900_000_000)
        .expect("redeem again");
    store.delete_plane_record(kind, &id).expect("delete");
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
/// comparison is not vacuous.
#[test]
fn the_linked_and_the_dropped_in_postgres_store_are_one_store() {
    let live = live_url();

    let linked = transcript("linked", &common::linked, live.as_deref());
    let dropped_in = transcript("dropped", &common::dropped, live.as_deref());
    assert_eq!(linked, dropped_in, "the two doors are not one store");

    // The refusals are the store's OWN words, and the unreachable-server one scrubs the password.
    let refusals = linked["refusals"].as_array().unwrap();
    assert_eq!(
        refusals[0],
        "plugin 'busbar-store-postgres' open failed: postgres plugin config requires a \"url\" \
         (a libpq connection string)"
    );
    assert_eq!(refusals[1], refusals[0]);
    assert!(
        refusals[2].as_str().unwrap().starts_with(
            "plugin 'busbar-store-postgres' open failed: invalid postgres plugin config:"
        ),
        "{refusals:?}"
    );
    assert_eq!(refusals[3], refusals[0], "a non-string url is no url");
    let unreachable = refusals[4].as_str().unwrap();
    assert!(
        !unreachable.contains("s3cret-conf") && !unreachable.starts_with("opened"),
        "the unreachable server must refuse, and never echo the password: {unreachable}"
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
/// written under its own directory, so the loader `dlopen`s a path no good image was ever loaded
/// from, whatever order the tests in this target run in.
#[test]
fn foreign_bytes_dropped_in_are_not_the_postgres_store() {
    let lib = common::cdylib();
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
        !red.contains("requires a \"url\""),
        "foreign bytes cannot speak the store's own refusal: {red}"
    );
}

/// RED: the store's library asked for as another kind is refused before any slot runs.
#[test]
fn the_postgres_store_library_loaded_as_another_kind_is_refused() {
    let lib = common::cdylib();
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("store-postgres-as-secret"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    };
    assert!(
        load_dropped::<Secret>(&lib, &common::stated(), bind).is_err(),
        "a store library loaded as kind secret"
    );
}
