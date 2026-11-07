// SPDX-License-Identifier: Apache-2.0
//! Native atomic effects, replay and schema fencing through both actual deliveries.
use super::*;
#[test]
fn all_store_slots_match_through_linked_and_fresh_dropped_postgres() {
    let admin = common::postgres_url().expect("owned live PostgreSQL fixture required");
    let mut runs = vec![];
    for use_dropped in [false, true] {
        let database = common::temp_db::TempDb::create(&admin, "pg_contract");
        let url = database.url();
        let settings = serde_json::to_vec(&serde_json::json!({"url":url})).unwrap();
        let store = open(
            if use_dropped {
                dropped(&cdylib(), &common::stated())
            } else {
                linked()
            },
            &settings,
        )
        .unwrap();
        runs.push(scenario(&store, &url));
        let original = store.info();
        let attempt = common::prepare(
            &store,
            10,
            vec![Predicate {
                address: common::address(8, b"durable"),
                expected: ExpectedValue::Absent,
            }],
            vec![common::put(
                common::address(8, b"durable"),
                b"binary\0value",
            )],
        );
        assert!(matches!(
            common::run(store.commit(attempt.clone())).unwrap(),
            Decision::Applied(_)
        ));
        drop(store);
        let reopened = open(
            if use_dropped {
                dropped(&cdylib(), &common::stated())
            } else {
                linked()
            },
            &settings,
        )
        .unwrap();
        assert_eq!(reopened.info(), original);
        assert!(matches!(
            common::run(reopened.commit(attempt)).unwrap(),
            Decision::Applied(_)
        ));
        assert_eq!(
            common::raw_value(&url, &common::address(8, b"durable")).unwrap(),
            b"binary\0value"
        );
        assert!(matches!(
            common::commit(
                &reopened,
                10,
                vec![],
                vec![common::put(common::address(8, b"durable"), b"different")]
            ),
            Decision::OpIdConflict
        ));
    }
    assert_eq!(runs[0], runs[1]);
}
#[test]
fn postgres_refuses_a_schema_newer_than_its_build_through_both_doors() {
    let admin = common::postgres_url().expect("owned live PostgreSQL fixture required");
    for use_dropped in [false, true] {
        let database = common::temp_db::TempDb::create(&admin, "pg_newer");
        let url = database.url();
        let settings = serde_json::to_vec(&serde_json::json!({"url":url})).unwrap();
        let load = || {
            if use_dropped {
                dropped(&cdylib(), &common::stated())
            } else {
                linked()
            }
        };
        drop(open(load(), &settings).unwrap());
        let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        let mut facts: Vec<u8> = raw
            .query_one("SELECT facts FROM busbar_persistence_v4.metadata", &[])
            .unwrap()
            .get(0);
        facts[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        raw.execute(
            "UPDATE busbar_persistence_v4.metadata SET facts=$1",
            &[&facts],
        )
        .unwrap();
        assert!(
            open(load(), &settings).is_err(),
            "newer native physical format refused"
        );
        let after: Vec<u8> = raw
            .query_one("SELECT facts FROM busbar_persistence_v4.metadata", &[])
            .unwrap()
            .get(0);
        assert_eq!(facts, after, "refusal cannot rewrite source metadata");
    }
}
