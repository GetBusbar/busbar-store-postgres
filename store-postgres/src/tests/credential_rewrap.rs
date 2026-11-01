// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::{Arc, Barrier};

#[path = "credential_rewrap_uncertain.rs"]
mod uncertain;

fn rewrap(
    store: &TestStore,
    expected: &CredentialSecret,
    replacement: &str,
) -> RecordStoreResult<bool> {
    RecordStore::rewrap_credential(&**store, expected, replacement)
}

fn row(store: &TestStore) -> CredentialSecret {
    store
        .lookup_credential_secret("sigv4", "public")
        .unwrap()
        .unwrap()
}

fn revision(store: &TestStore) -> i64 {
    store
        .lock()
        .query_one("SELECT revision FROM store_revision WHERE only_row", &[])
        .unwrap()
        .get(0)
}

#[test]
fn loaded_doors_race_one_rewrap_and_the_committed_envelope_survives_reopen() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    store
        .put_credential(&sample_cred("owner", 0, "public"))
        .unwrap();
    let expected = row(&store);
    let before = revision(&store);
    assert!(!rewrap(&store, &expected, &expected.secret).unwrap());
    let mut altered = expected.clone();
    altered.meta.updated_at += 1;
    assert!(!rewrap(&store, &altered, "altered-metadata").unwrap());
    assert_eq!(revision(&store), before);
    let gate = Arc::new(Barrier::new(3));
    let connections = [
        TestStore::open(&db.url()).unwrap(),
        TestStore::open(&db.url()).unwrap(),
    ];
    let writers: Vec<_> = connections
        .into_iter()
        .zip(["envelope-a", "envelope-b"])
        .map(|(connection, envelope)| {
            let gate = Arc::clone(&gate);
            let expected = expected.clone();
            std::thread::spawn(move || {
                gate.wait();
                (envelope, rewrap(&connection, &expected, envelope).unwrap())
            })
        })
        .collect();
    gate.wait();
    let outcomes: Vec<_> = writers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|(_, applied)| *applied).count(), 1);
    let winner = outcomes.iter().find(|(_, applied)| *applied).unwrap().0;
    let current = row(&store);
    let mut wanted = expected.clone();
    wanted.secret = winner.into();
    wanted.meta.revision = current.meta.revision;
    assert!(current == wanted);
    assert!(current.meta.revision > expected.meta.revision);
    assert_eq!(revision(&store), before + 1);
    assert!(!rewrap(&store, &expected, "stale").unwrap());
    assert!(!rewrap(&store, &current, &current.secret).unwrap());
    let mut ordinary = current.clone();
    ordinary.secret = "ordinary-put-must-not-rotate".into();
    assert!(store.put_credential(&ordinary).is_err());
    assert!(row(&store) == current);
    assert_eq!(revision(&store), before + 1);
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert!(row(&reopened) == current);
}

#[test]
fn loaded_rewrap_cannot_resurrect_revoked_deleted_or_reclaimed_rows() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_dead");
    for delete in [false, true] {
        let store = TestStore::open(&db.url()).unwrap();
        let owner = if delete { "deleted" } else { "revoked" };
        let public = owner;
        store.put_key(&sample_key(owner)).unwrap();
        store
            .put_credential(&sample_cred(owner, 0, public))
            .unwrap();
        let expected = store
            .lookup_credential_secret("sigv4", public)
            .unwrap()
            .unwrap();
        if delete {
            store.delete_key(owner).unwrap();
        } else {
            store
                .revoke_credential(&expected.meta.id, "revoked")
                .unwrap();
        }
        let retired = store.list_credentials_since(0).unwrap();
        let before = revision(&store);
        assert!(!rewrap(&store, &expected, "resurrection").unwrap());
        assert!(store.list_credentials_since(0).unwrap() == retired);
        assert_eq!(revision(&store), before);
        if !delete {
            store
                .put_credential(&sample_cred(owner, 0, "reclaimed"))
                .unwrap();
            let reclaimed = store.list_credentials_since(0).unwrap();
            let before = revision(&store);
            assert!(!rewrap(&store, &expected, "resurrection").unwrap());
            assert!(store.list_credentials_since(0).unwrap() == reclaimed);
            assert_eq!(revision(&store), before);
        }
    }
}

#[test]
fn a_failed_loaded_rewrap_rolls_back_its_revision_and_envelope() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_fail");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    store
        .put_credential(&sample_cred("owner", 0, "public"))
        .unwrap();
    let expected = row(&store);
    let before = revision(&store);
    store.lock().batch_execute("CREATE FUNCTION refuse_rewrap() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected write failure'; END $$; CREATE TRIGGER refuse_rewrap BEFORE UPDATE OF secret ON credentials FOR EACH ROW EXECUTE FUNCTION refuse_rewrap();").unwrap();
    assert!(rewrap(&store, &expected, "replacement").is_err());
    assert!(row(&store) == expected);
    assert_eq!(revision(&store), before);
    store
        .lock()
        .batch_execute("DROP TRIGGER refuse_rewrap ON credentials; DROP FUNCTION refuse_rewrap();")
        .unwrap();
    store.lock().batch_execute("CREATE FUNCTION suppress_rewrap() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER suppress_rewrap BEFORE UPDATE OF secret ON credentials FOR EACH ROW EXECUTE FUNCTION suppress_rewrap();").unwrap();
    assert!(rewrap(&store, &expected, "replacement").is_err());
    assert!(row(&store) == expected);
    assert_eq!(revision(&store), before);
    store
        .lock()
        .batch_execute(
            "DROP TRIGGER suppress_rewrap ON credentials; DROP FUNCTION suppress_rewrap();",
        )
        .unwrap();
    assert!(rewrap(&store, &expected, "replacement").unwrap());
    assert_eq!(revision(&store), before + 1);
}

#[test]
fn loaded_rewrap_compares_every_field_and_keeps_large_timestamp_precision() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_exact");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    let mut credential = sample_cred("owner", 0, "public");
    credential.meta.created_at = (1_u64 << 53) + 1;
    credential.meta.updated_at = (1_u64 << 53) + 3;
    credential.meta.expires_at = Some((1_u64 << 53) + 5);
    store.put_credential(&credential).unwrap();
    let expected = row(&store);
    credential.meta.revision = expected.meta.revision;
    assert!(expected == credential);
    let before = revision(&store);
    for field in 0..13 {
        let mut stale = expected.clone();
        match field {
            0 => stale.meta.id.push('x'),
            1 => stale.meta.key_id.push('x'),
            2 => stale.meta.kind.push('x'),
            3 => stale.meta.slot += 1,
            4 => stale.meta.public_id.push('x'),
            5 => stale.meta.secret_form = SecretForm::None,
            6 => stale.meta.created_at += 1,
            7 => stale.meta.updated_at += 1,
            8 => stale.meta.expires_at = stale.meta.expires_at.map(|value| value + 1),
            9 => stale.meta.revoked_at = Some(1),
            10 => stale.meta.revoke_reason = Some("changed".into()),
            11 => stale.meta.revision += 1,
            12 => stale.secret.push('x'),
            _ => unreachable!(),
        }
        assert!(
            !rewrap(&store, &stale, "replacement").unwrap(),
            "field {field}"
        );
        assert!(row(&store) == expected, "field {field}");
        assert_eq!(revision(&store), before, "field {field}");
    }
    assert!(rewrap(&store, &expected, "replacement").unwrap());
    let current = row(&store);
    let mut wanted = expected;
    wanted.secret = "replacement".into();
    wanted.meta.revision = (before + 1) as u64;
    assert!(current == wanted);
    assert_eq!(revision(&store), before + 1);
}

#[test]
fn larger_u64_expectations_do_not_alias_a_credential_stored_at_the_signed_boundary() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_boundary");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    let mut credential = sample_cred("owner", 0, "public");
    credential.meta.created_at = i64::MAX as u64;
    credential.meta.updated_at = i64::MAX as u64;
    credential.meta.expires_at = Some(i64::MAX as u64);
    store.put_credential(&credential).unwrap();
    let expected = row(&store);
    let before = revision(&store);
    for value in [i64::MAX as u64 + 1, u64::MAX] {
        for field in 0..3 {
            let mut outside = expected.clone();
            match field {
                0 => outside.meta.created_at = value,
                1 => outside.meta.updated_at = value,
                2 => outside.meta.expires_at = Some(value),
                _ => unreachable!(),
            }
            assert!(!rewrap(&store, &outside, "replacement").unwrap());
            assert!(row(&store) == expected);
            assert_eq!(revision(&store), before);
        }
    }
    assert!(rewrap(&store, &expected, "replacement").unwrap());
    let mut wanted = expected;
    wanted.secret = "replacement".into();
    wanted.meta.revision = (before + 1) as u64;
    assert!(row(&store) == wanted);
    assert_eq!(revision(&store), before + 1);
}

#[test]
fn loaded_rewrap_refuses_a_retired_owner_even_with_a_surviving_credential_row() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_owner");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    store
        .put_credential(&sample_cred("owner", 0, "public"))
        .unwrap();
    let expected = row(&store);
    let before = revision(&store);
    store
        .lock()
        .execute(
            "UPDATE keys SET deleted_at=1, enabled=FALSE WHERE id='owner'",
            &[],
        )
        .unwrap();
    assert!(!rewrap(&store, &expected, "replacement").unwrap());
    assert!(row(&store) == expected);
    assert_eq!(revision(&store), before);
    store
        .lock()
        .execute("DELETE FROM keys WHERE id='owner'", &[])
        .unwrap();
    assert!(!rewrap(&store, &expected, "replacement").unwrap());
    assert!(store
        .lookup_credential_secret("sigv4", "public")
        .unwrap()
        .is_none());
    assert_eq!(revision(&store), before);
}

#[test]
fn loaded_rewrap_waits_for_the_revision_lock_before_locking_the_credential() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_lock");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    store
        .put_credential(&sample_cred("owner", 0, "public"))
        .unwrap();
    let expected = row(&store);
    let connection = TestStore::open(&db.url()).unwrap();
    let mut blocker = connect_client_with_retry(&db.url());
    let blocker_pid: i32 = blocker
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    blocker
        .batch_execute("BEGIN; SELECT revision FROM store_revision WHERE only_row FOR UPDATE;")
        .unwrap();
    let (answer, result) = std::sync::mpsc::channel();
    let expected_id = expected.meta.id.clone();
    let worker = std::thread::spawn(move || {
        answer
            .send(rewrap(&connection, &expected, "replacement"))
            .unwrap();
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut premature = None;
    let waited = loop {
        if let Ok(outcome) = result.try_recv() {
            premature = Some(outcome);
            break false;
        }
        let waiting: bool = store
            .lock()
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
             AND $1 = ANY(pg_blocking_pids(pid)))",
                &[&blocker_pid],
            )
            .unwrap()
            .get(0);
        if waiting {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let revoke = blocker
        .query_one(
            "SELECT id FROM credentials WHERE id=$1 FOR UPDATE NOWAIT",
            &[&expected_id],
        )
        .and_then(|_| {
            blocker.batch_execute(
                "UPDATE store_revision SET revision=revision+1 WHERE only_row;
         UPDATE credentials SET revoked_at=7, revoke_reason='concurrent revocation', updated_at=7,
             secret=NULL, secret_form='none', revision=(SELECT revision FROM store_revision)
         WHERE public_id='public'; COMMIT;",
            )
        });
    if revoke.is_err() {
        blocker.batch_execute("ROLLBACK").unwrap();
    }
    let outcome = premature.unwrap_or_else(|| {
        result
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("rewrap finishes after the revision lock is released")
    });
    worker.join().unwrap();
    revoke.expect("rewrap must not hold the credential while waiting for the revision row");
    assert!(waited, "rewrap must wait for the held revision row");
    assert!(!outcome.unwrap());
    let retired = row(&store);
    assert_eq!(retired.meta.revoked_at, Some(7));
    assert_eq!(
        retired.meta.revoke_reason.as_deref(),
        Some("concurrent revocation")
    );
    assert_eq!(retired.meta.secret_form, SecretForm::None);
    assert!(retired.secret.is_empty());
    assert_eq!(revision(&store) as u64, retired.meta.revision);
}
