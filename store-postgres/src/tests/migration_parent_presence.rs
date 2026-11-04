// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn envelope(kind: &str, id: &str, parent: Option<&str>) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(str::to_string),
        seq: 0,
        ts: 2_000_000_001,
        disposition: PlaneDisposition::Active,
        body: vec![0, 255, 17],
    }
}

fn chain_rows(raw: &mut postgres::Client) -> Vec<String> {
    raw.query(
        "SELECT row_to_json(r)::text FROM
         (SELECT kind,parent,seq,id,ts,disposition,body FROM plane_chain ORDER BY kind,parent,seq) r",
        &[],
    )
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}

fn global_revision(raw: &mut postgres::Client) -> i64 {
    raw.query_one("SELECT revision FROM store_revision WHERE only_row", &[])
        .unwrap()
        .get(0)
}

fn schemas(raw: &mut postgres::Client) -> Vec<i64> {
    raw.query("SELECT version FROM busbar_schema ORDER BY version", &[])
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
}

fn legacy_v6(raw: &mut postgres::Client) {
    raw.batch_execute(
        "ALTER TABLE plane_chain DROP COLUMN has_parent;
         DELETE FROM busbar_schema; INSERT INTO busbar_schema(version) VALUES (6)",
    )
    .unwrap();
}

fn append_v13(raw: &mut postgres::Client, record: &PlaneRecord) {
    let parent = record.parent.as_deref().unwrap_or(&record.id);
    raw.execute(
        "INSERT INTO plane_chain (kind,parent,seq,id,ts,disposition,body)
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (kind,parent,seq) DO NOTHING",
        &[
            &record.kind,
            &parent,
            &(record.seq as i64),
            &record.id,
            &(record.ts as i64),
            &"active",
            &record.body,
        ],
    )
    .unwrap();
}

#[test]
fn released_v6_ambiguous_parent_presence_refuses_without_rewriting_and_retries_identically() {
    let Some(url) = live_url() else { return };

    for (kind, parented) in [("task_event", true), ("call", true), ("opaque", false)] {
        let db = TempDb::create(&url, "spg_parent_ambiguous");
        let store = TestStore::open(&db.url()).unwrap();
        let record = envelope(
            kind,
            "historical-parent",
            parented.then_some("historical-parent"),
        );
        drop(store);
        let mut raw = connect_client_with_retry(&db.url());
        legacy_v6(&mut raw);
        append_v13(&mut raw, &record);
        let safe = envelope("safe", "child", Some("different-parent"));
        append_v13(&mut raw, &safe);
        let rows = chain_rows(&mut raw);
        let versions = schemas(&mut raw);
        let revision = global_revision(&mut raw);
        for _ in 0..2 {
            let error = TestStore::open(&db.url())
                .err()
                .expect("lost legacy parent presence requires provenance, not a guessed migration");
            assert!(
                error.contains("released-v6 plane_chain parent presence is ambiguous"),
                "{error}"
            );
            assert!(
                error.contains("authoritative envelope provenance"),
                "{error}"
            );
            assert_eq!(
                chain_rows(&mut raw),
                rows,
                "every envelope remains byte-identical"
            );
            assert_eq!(
                schemas(&mut raw),
                versions,
                "no version stamp was committed"
            );
            assert_eq!(global_revision(&mut raw), revision);
            let has_column: bool = raw.query_one(
                "SELECT EXISTS(SELECT 1 FROM information_schema.columns
                 WHERE table_schema='public' AND table_name='plane_chain' AND column_name='has_parent')",
                &[],
            ).unwrap().get(0);
            assert!(!has_column, "the transactional DDL was rolled back too");
        }
    }
}

#[test]
fn released_v6_unambiguous_parent_migrates_reopens_and_accepts_identical_replay() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_parent_safe");
    let store = TestStore::open(&db.url()).unwrap();
    let record = envelope("task_event", "child", Some("parent"));
    drop(store);
    let mut raw = connect_client_with_retry(&db.url());
    legacy_v6(&mut raw);
    append_v13(&mut raw, &record);
    let before = chain_rows(&mut raw);
    let revision = global_revision(&mut raw);
    for _ in 0..2 {
        let reopened = TestStore::open(&db.url()).unwrap();
        assert_eq!(
            reopened.list_plane_record_parents("task_event").unwrap(),
            vec!["parent"]
        );
        assert_eq!(
            reopened
                .list_plane_records("task_event", &PlaneSelector::Parent("parent".into()))
                .unwrap(),
            vec![record.body.clone()]
        );
        reopened
            .append_plane_record(record.view())
            .expect("identical legacy parented replay");
        assert_eq!(chain_rows(&mut raw), before);
        assert_eq!(global_revision(&mut raw), revision);
        assert_eq!(schemas(&mut raw).last().copied(), Some(SCHEMA_VERSION));
    }
}

#[test]
fn current_schema_presence_bits_are_preserved_without_guessed_reconstruction() {
    let Some(url) = live_url() else { return };
    let version = SCHEMA_VERSION;
    {
        let db = TempDb::create(&url, "spg_parent_present");
        let store = TestStore::open(&db.url()).unwrap();
        let parentless = envelope("opaque", "alone", None);
        let parented = envelope("task_event", "task", Some("task"));
        for record in [&parentless, &parented] {
            store.append_plane_record(record.view()).unwrap();
        }
        drop(store);
        let mut raw = connect_client_with_retry(&db.url());
        raw.batch_execute("DELETE FROM busbar_schema").unwrap();
        raw.execute(
            "INSERT INTO busbar_schema(version) VALUES ($1)",
            &[&version],
        )
        .unwrap();
        let rows = chain_rows(&mut raw);
        let revision = global_revision(&mut raw);
        let reopened = TestStore::open(&db.url()).unwrap();
        assert!(reopened
            .list_plane_record_parents("opaque")
            .unwrap()
            .is_empty());
        assert_eq!(
            reopened.get_plane_record("opaque", "alone").unwrap(),
            Some(parentless.body.clone())
        );
        assert_eq!(
            reopened.list_plane_record_parents("task_event").unwrap(),
            vec!["task"]
        );
        for record in [&parentless, &parented] {
            reopened.append_plane_record(record.view()).unwrap();
        }
        assert_eq!(chain_rows(&mut raw), rows);
        assert_eq!(global_revision(&mut raw), revision);
    }
}
