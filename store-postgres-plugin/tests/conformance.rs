// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE POSTGRES STORE, BOTH DOORS, ONE ROW** — the store's linked + dropped-in conformance, run
//! against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The store is held two ways at once: LINKED (its `linked::STORE` statement and boundary, the row a
//! busbar build that compiles it in registers) and DROPPED IN (this crate's built cdylib, signed
//! first-party under the SAME statement into a temp `plugins/` directory and found by the loader's
//! scan). Each arm is opened by the one `open_store` and must agree, byte for byte, on:
//!
//! * the row's statement and its first-party standing;
//! * every refusal the store's own `open` gives (no config, an empty object, malformed JSON, a
//!   non-string url, and an unreachable server — which proves the plugin's own connect path runs,
//!   and that it scrubs nothing it should not);
//! * with a live Postgres (`BUSBAR_TEST_POSTGRES_URL`, the same gate the rest of this repo's live
//!   tests use: unset under CI is a FAILURE, unset locally skips only this scenario), one durable
//!   scenario per arm — upsert, point read, a child chain, single-use token redemption, delete.
//!
//! RED ARMS, in the same test and always run (no database needed): the same bytes signed as
//! `kind: secret` are refused at the kind handshake naming both kinds, and the same statement over
//! DIFFERENT bytes (the cdylib with its object magic broken) is not the same store — its transcript differs from the
//! linked one, so the comparison above cannot pass vacuously.

use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

/// The version both arms state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_store_postgres_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-store-postgres-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// The statement both arms carry, as `kind`.
fn statement(kind: &str) -> Manifest {
    let (name, alias, _) = busbar_store_postgres::linked::STORE;
    let abi = busbar_plugin_loader::supported_abi(kind)
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: kind.into(),
        version: VERSION.into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: abi,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

/// The LINKED row: exactly what a busbar build that compiles this store in states.
fn linked_row() -> LinkedPlugin {
    let (_, _, entry) = busbar_store_postgres::linked::STORE;
    LinkedPlugin::boundary(statement("store"), entry)
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/`
/// directory, scanned under a policy holding the release key.
fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir =
        std::env::temp_dir().join(format!("store-postgres-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libstore.so", lib).unwrap();
    std::fs::write(dir.join("store.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed store scans")
}

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

/// One durable scenario through `store`, every id namespaced by `ns` so the two arms (and
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
        .upsert_plane_record(&rec(kind, id.clone(), None, 0, "v1"))
        .expect("upsert");
    store
        .upsert_plane_record(&rec(kind, id.clone(), None, 0, "v2"))
        .expect("upsert over");
    let got = text(store.get_plane_record(kind, &id).expect("get"));
    for seq in 1..=2 {
        store
            .append_plane_record(&rec(
                child,
                format!("{ns}-e{seq}"),
                Some(id.clone()),
                seq,
                &format!("event {seq}"),
            ))
            .expect("append");
    }
    let chain: Vec<String> = store
        .list_plane_records(child, &PlaneSelector::Parent(id.clone()))
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
fn transcript(tag: &str, registry: &PluginRegistry, live: Option<&str>) -> serde_json::Value {
    let (_, alias, _) = busbar_store_postgres::linked::STORE;
    let p = registry.resolve(alias).expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let refusals: Vec<String> = [
        "",
        "{}",
        "{ not json",
        r#"{"url": 5}"#,
        r#"{"url": "host=127.0.0.1 port=1 user=conf password=s3cret-conf dbname=x connect_timeout=2"}"#,
    ]
    .iter()
    .map(|cfg| match registry.open_store(alias, cfg) {
        Ok(_) => format!("opened with {cfg:?}"),
        Err(e) => e,
    })
    .collect();
    let durable = live.map(|url| {
        let cfg = serde_json::json!({ "url": url }).to_string();
        let store = registry.open_store(alias, &cfg).expect("the store opens");
        let ns = format!("conf-{}-{tag}", std::process::id());
        scenario(store.as_ref(), &ns)
    });
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "refusals": refusals,
        "durable": durable,
    })
}

/// The Postgres store registers ONE row and behaves as ONE store through either door — and the
/// RED arms show the comparison is not vacuous.
#[test]
fn the_linked_and_the_dropped_in_postgres_store_are_one_store() {
    let live = live_url();
    let row = linked_row();
    assert_eq!(row.manifest.name, "busbar-store-postgres");
    assert_eq!(row.manifest.alias, "postgres");
    let lib = cdylib();

    let linked_registry = PluginRegistry::empty().link(vec![row]).unwrap();
    let linked_no_db = transcript("linked-no-db", &linked_registry, None);
    // RED ARM 2 — RUN FIRST: the same statement over DIFFERENT bytes (the object's magic broken) is
    // not the same store. It must run before ANY good image is dropped in: on Linux the loader
    // dlopens a memfd as `/proc/self/fd/N`, a Rust cdylib stays resident after its handle drops, and
    // glibc answers a later dlopen of the same path string with the object already loaded — without
    // reading the new bytes. Run after a good arm, this arm would be served the real store.
    let mut foreign = lib.clone();
    foreign[..4].copy_from_slice(b"XXXX");
    let red_registry = dropped("red", statement("store"), &foreign);
    let red = transcript("red", &red_registry, None);
    assert_ne!(
        red, linked_no_db,
        "different bytes must not pass as the store"
    );
    assert!(
        !red["refusals"][0]
            .as_str()
            .unwrap()
            .contains("requires a \"url\""),
        "foreign bytes cannot speak the store's own refusal: {red}"
    );

    let linked = transcript("linked", &linked_registry, live.as_deref());
    let dropped_registry = dropped("dropped", statement("store"), &lib);
    let dropped_in = transcript("dropped", &dropped_registry, live.as_deref());
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
    assert_eq!(linked["first_party"], true);
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

    // RED ARM 1: the same bytes signed as another kind are refused at the kind handshake.
    let wrong = dropped("as-secret", statement("secret"), &lib);
    let e = match wrong.open_secret("postgres", "{}") {
        Ok(_) => panic!("a store library signed as secret opened"),
        Err(e) => e,
    };
    assert!(
        e.contains(
            "plugin 'busbar-store-postgres' exports kind 'store' but is being loaded as 'secret'"
        ),
        "{e}"
    );
}
