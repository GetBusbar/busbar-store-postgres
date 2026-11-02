// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn stored(store: &TestStore, public: &str) -> CredentialSecret {
    store
        .lookup_credential_secret("sigv4", public)
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
fn ordinary_and_paired_credential_puts_preserve_the_full_timestamp_domain_and_retry_identity() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_credential_u64");
    for paired in [false, true] {
        for (index, (created, updated, expires)) in [
            (0, 0, None),
            (i64::MAX as u64, i64::MAX as u64, Some(i64::MAX as u64)),
            (i64::MAX as u64 + 1, i64::MAX as u64 + 1, Some(u64::MAX)),
            (u64::MAX, u64::MAX, Some(i64::MAX as u64)),
            (0, u64::MAX, Some(0)),
        ]
        .into_iter()
        .enumerate()
        {
            let store = TestStore::open(&db.url()).unwrap();
            let owner = format!("owner_{paired}_{index}");
            let public = format!("public_{paired}_{index}");
            let key = sample_key(&owner);
            let mut credential = sample_cred(&owner, 0, &public);
            credential.meta.created_at = created;
            credential.meta.updated_at = updated;
            credential.meta.expires_at = expires;
            if paired {
                store.put_key_with_credential(&key, &credential).unwrap();
            } else {
                store.put_key(&key).unwrap();
                store.put_credential(&credential).unwrap();
            }
            let actual = stored(&store, &public);
            let mut wanted = credential.clone();
            wanted.meta.revision = actual.meta.revision;
            assert!(actual == wanted, "paired={paired}, case={index}");
            assert_eq!(
                store.list_credentials(&owner).unwrap(),
                vec![wanted.meta.clone()]
            );
            let before_retry = revision(&store);
            store.put_credential(&credential).unwrap();
            assert_eq!(revision(&store), before_retry);
            let mut different = credential.clone();
            different.meta.updated_at ^= 1;
            assert!(store.put_credential(&different).is_err());
            assert!(store.put_key_with_credential(&key, &different).is_err());
            assert!(stored(&store, &public) == wanted);
            assert_eq!(revision(&store), before_retry);
            drop(store);
            let reopened = TestStore::open(&db.url()).unwrap();
            assert!(stored(&reopened, &public) == wanted);
            assert_eq!(revision(&reopened), before_retry);
        }
    }
}

#[test]
fn rewrap_preserves_high_timestamp_bits_and_compares_them_without_signed_aliasing() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_credential_u64_cas");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    let mut credential = sample_cred("owner", 0, "public");
    credential.meta.created_at = i64::MAX as u64 + 1;
    credential.meta.updated_at = u64::MAX;
    credential.meta.expires_at = Some(u64::MAX);
    store.put_credential(&credential).unwrap();
    let expected = stored(&store, "public");
    credential.meta.revision = expected.meta.revision;
    assert!(expected == credential);
    assert!(expected.meta.is_live(u64::MAX - 1));
    assert!(!expected.meta.is_live(u64::MAX));
    let before = revision(&store);
    let mut stale = expected.clone();
    stale.meta.updated_at -= 1;
    assert!(!store.rewrap_credential(&stale, "replacement").unwrap());
    assert_eq!(revision(&store), before);
    assert!(store.rewrap_credential(&expected, "replacement").unwrap());
    let mut wanted = expected.clone();
    wanted.secret = "replacement".into();
    wanted.meta.revision = (before + 1) as u64;
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert!(stored(&reopened, "public") == wanted);
    assert!(!reopened
        .rewrap_credential(&expected, "stale replay")
        .unwrap());
    assert!(!reopened.rewrap_credential(&wanted, "replacement").unwrap());
    assert_eq!(revision(&reopened), before + 1);
}

#[test]
fn v15_positive_timestamp_migration_changes_neither_row_bits_nor_revisions() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_credential_v15");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    let mut credential = sample_cred("owner", 0, "public");

    credential.meta.created_at = i64::MAX as u64;
    credential.meta.updated_at = 17;
    credential.meta.expires_at = Some(99);
    store.put_credential(&credential).unwrap();
    let expected = stored(&store, "public");
    let before = revision(&store);
    store
        .lock()
        .batch_execute("DELETE FROM busbar_schema; INSERT INTO busbar_schema(version) VALUES (15)")
        .unwrap();
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert!(stored(&reopened, "public") == expected);
    assert_eq!(revision(&reopened), before);
    let raw = reopened.lock().query_one(
        "SELECT created_at,updated_at,expires_at,(SELECT MAX(version) FROM busbar_schema) FROM credentials WHERE public_id='public'", &[],
    ).unwrap();
    assert_eq!(raw.get::<_, i64>(0), i64::MAX);
    assert_eq!(raw.get::<_, i64>(1), 17);
    assert_eq!(raw.get::<_, Option<i64>>(2), Some(99));
    assert_eq!(raw.get::<_, i64>(3), SCHEMA_VERSION);
}

#[test]
fn v15_negative_timestamp_provenance_is_refused_without_partial_migration() {
    let Some(url) = live_url() else { return };
    for field in ["created_at", "updated_at", "expires_at", "revoked_at"] {
        let db = TempDb::create(&url, "spg_credential_negative");
        let store = TestStore::open(&db.url()).unwrap();
        store.put_key(&sample_key("owner")).unwrap();
        store
            .put_credential(&sample_cred("owner", 0, "public"))
            .unwrap();
        let before = revision(&store);
        store.lock().batch_execute(&format!(
            "UPDATE credentials SET {field}=-1 WHERE public_id='public'; DELETE FROM busbar_schema; INSERT INTO busbar_schema(version) VALUES (15)"
        )).unwrap();
        drop(store);
        let error = TestStore::open(&db.url())
            .err()
            .expect("pre-v16 negative timestamp provenance is unknown");
        assert!(error.contains("negative credential timestamp"), "{error}");
        let mut raw = connect_client_with_retry(&db.url());
        let unchanged = raw.query_one(&format!(
            "SELECT {field},(SELECT MAX(version) FROM busbar_schema),(SELECT revision FROM store_revision WHERE only_row) FROM credentials WHERE public_id='public'"
        ), &[]).unwrap();
        assert_eq!(unchanged.get::<_, i64>(0), -1);
        assert_eq!(unchanged.get::<_, i64>(1), 15);
        assert_eq!(unchanged.get::<_, i64>(2), before);
    }
}

#[test]
fn current_encoding_decodes_revocation_bits_and_revoke_preserves_the_original_revocation() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_credential_revoke_bits");
    let store = TestStore::open(&db.url()).unwrap();
    store.put_key(&sample_key("owner")).unwrap();
    store
        .put_credential(&sample_cred("owner", 0, "public"))
        .unwrap();
    store.lock().batch_execute(
        "UPDATE credentials SET revoked_at=-1,updated_at=-2,revoke_reason='original',secret=NULL,secret_form='none' WHERE public_id='public'"
    ).unwrap();
    drop(store);
    let reopened = TestStore::open(&db.url()).unwrap();
    let retired = stored(&reopened, "public");
    assert_eq!(retired.meta.revoked_at, Some(u64::MAX));
    assert_eq!(retired.meta.updated_at, u64::MAX - 1);
    assert_eq!(retired.meta.secret_form, SecretForm::None);
    assert!(retired.secret.is_empty());
    reopened
        .revoke_credential(&retired.meta.id, "replacement reason")
        .unwrap();
    assert!(stored(&reopened, "public") == retired);
}
