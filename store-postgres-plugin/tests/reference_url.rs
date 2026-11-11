// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `url` is reference-capable rather than a declared secret field; literal 1.5.5 URLs remain accepted.

use std::sync::Arc;

use busbar_contract::secret_fields::resolve_declared_fields;
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4 as Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};

const URL: &str = "postgres://busbar@db.internal:5432/busbar";

fn linked() -> (Plugin<Store>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let bind = Bind {
        instance: Arc::from("reference-url"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    };
    let row = LinkedRow::of_kind::<Store>(
        busbar_store_postgres::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
    .expect("the row renders");
    (load_linked::<Store>(&row, bind).expect("the door loads"), d)
}

#[test]
fn the_url_is_not_declared_secret() {
    let (p, _d) = linked();
    assert!(
        !p.secret_refs().iter().any(|f| f == "url"),
        "{:?}",
        p.secret_refs()
    );
}

#[test]
fn a_reference_at_the_url_resolves_as_the_kernel_resolves_it() {
    let (p, _d) = linked();
    let mut v = serde_json::json!({"url":{
        "module":"env", "settings":{"key":"REFCAP_URL_FOR_TEST"}
    }});
    let mut resolved = 0;
    resolve_declared_fields(
        &mut v,
        p.secret_refs(),
        p.reference_fields(),
        p.name(),
        |field, reference| {
            assert_eq!(field, "url");
            let busbar_contract::secret_ref::SecretRef::Source(source) = reference else {
                panic!("the URL names its admitted source");
            };
            assert_eq!(source.module, "env");
            assert_eq!(source.settings.key_names(), ["key"]);
            resolved += 1;
            Ok(URL.to_string())
        },
    )
    .expect("a reference at the url resolves");
    assert_eq!(v["url"], URL);
    assert_eq!(resolved, 1);
}

#[test]
fn a_literal_url_passes_as_written() {
    let (p, _d) = linked();
    let settings = format!(r#"{{"url":"{URL}"}}"#);
    let mut v: serde_json::Value = serde_json::from_str(&settings).unwrap();
    resolve_declared_fields(
        &mut v,
        p.secret_refs(),
        p.reference_fields(),
        p.name(),
        |_, _| Err("a literal url resolves nothing".to_string()),
    )
    .expect("a literal url passes as written");
    assert_eq!(v["url"], URL);
}
