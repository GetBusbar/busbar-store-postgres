// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The family's credential rules (R3, R4, R5, R7) and the one-text-per-condition refusals (W2),
//! against a live Postgres.

use super::*;

fn fresh(tag: &str) -> (TestStore, String) {
    let url = live_url().expect("callers return early without a live url");
    let store = connect_store_with_retry(&url).expect("connect");
    let id = format!("vk_{tag}_{}", unique_suffix());
    hard_reset(&store, &id);
    (store, id)
}

fn store_revision(store: &TestStore) -> i64 {
    store
        .lock()
        .query_one("SELECT revision FROM store_revision", &[])
        .unwrap()
        .get(0)
}

struct IsolatedSchema {
    client: postgres::Client,
    name: String,
}

impl Drop for IsolatedSchema {
    fn drop(&mut self) {
        let _ = self
            .client
            .batch_execute(&format!("DROP SCHEMA \"{}\" CASCADE", self.name));
    }
}

// Revision assertions need a private counter: unrelated tests mutate the shared database.
fn isolated(tag: &str) -> (TestStore, String, IsolatedSchema) {
    let url = live_url().expect("callers return early without a live url");
    let name = format!("credential_{tag}_{}", unique_suffix());
    let mut client = connect_client_with_retry(&url);
    client
        .batch_execute(&format!("CREATE SCHEMA \"{name}\""))
        .expect("create private schema");
    let schema = IsolatedSchema { client, name };
    let sep = if url.contains('?') { '&' } else { '?' };
    let url = format!("{url}{sep}options=-csearch_path%3D{}", schema.name);
    let store = connect_store_with_retry(&url).expect("connect to private schema");
    let id = format!("vk_{tag}_{}", unique_suffix());
    (store, id, schema)
}

/// R3: a revoked credential id is never minted again; a NEW id into the revoked occupant's slot
/// reclaims the slot, its `created_at` the new credential's.
#[test]
fn a_revoked_credential_id_is_never_reminted_but_its_slot_is_reclaimed() {
    if live_url().is_none() {
        return;
    }
    let (store, id) = fresh("r3");
    store.put_key(&sample_key(&id)).unwrap();
    let old = sample_cred(&id, 0, &format!("AKIA_R3_OLD_{id}"));
    store.put_credential(&old).unwrap();
    store.revoke_credential(&old.meta.id, "rotated").unwrap();

    let e = store.put_credential(&old).unwrap_err();
    assert_eq!(
        e.0,
        format!(
            "put_credential: credential '{}' is revoked; a revoked credential is never re-minted",
            old.meta.id
        )
    );

    let mut fresh_cred = sample_cred(&id, 0, &format!("AKIA_R3_NEW_{id}"));
    fresh_cred.meta.created_at = 777;
    store.put_credential(&fresh_cred).unwrap();
    let metas = store.list_credentials(&id).unwrap();
    assert_eq!(metas.len(), 1, "the slot's row was replaced: {metas:?}");
    assert_eq!(metas[0].id, fresh_cred.meta.id);
    assert_eq!(metas[0].created_at, 777);
    assert!(metas[0].revoked_at.is_none());
    hard_reset(&store, &id);
}

/// R4: re-putting a live credential with identical content is Ok and writes nothing; different
/// content is refused.
#[test]
fn reputting_a_live_credential_is_ok_when_identical_and_refused_when_different() {
    if live_url().is_none() {
        return;
    }
    let (store, id, _schema) = isolated("r4");
    store.put_key(&sample_key(&id)).unwrap();
    let c = sample_cred(&id, 0, &format!("AKIA_R4_{id}"));
    store.put_credential(&c).unwrap();
    let before = store.list_credentials(&id).unwrap();
    let counter = store_revision(&store);

    store.put_credential(&c).expect("identical content is Ok");
    assert_eq!(store.list_credentials(&id).unwrap(), before, "no write");
    assert_eq!(store_revision(&store), counter, "no revision spent");

    let mut changed = c.clone();
    changed.secret = "v1:plain:other".into();
    let want = format!(
        "put_credential: slot 0 for key '{id}' kind 'sigv4' holds a live credential; revoke it first"
    );
    assert_eq!(store.put_credential(&changed).unwrap_err().0, want);
    let mut other_id = c.clone();
    other_id.meta.id = format!("cred_other_{id}");
    assert_eq!(store.put_credential(&other_id).unwrap_err().0, want);
    assert_eq!(store.list_credentials(&id).unwrap(), before, "untouched");
    hard_reset(&store, &id);
}

/// R5: `put_key_with_credential` refuses up front, writing nothing, and upserts over a live key.
#[test]
fn put_key_with_credential_refuses_up_front_and_upserts_over_a_live_key() {
    if live_url().is_none() {
        return;
    }
    let (store, id, _schema) = isolated("r5");

    let mut carrying = sample_key(&id);
    carrying.deleted_at = Some(5);
    carrying.enabled = false;
    let cred = sample_cred(&id, 0, &format!("AKIA_R5_{id}"));
    assert_eq!(
        store
            .put_key_with_credential(&carrying, &cred)
            .unwrap_err()
            .0,
        format!(
            "put_key_with_credential: key '{id}' is tombstoned; a credential is never minted onto it"
        )
    );
    let counter = store_revision(&store);
    assert!(store.get_key(&id).unwrap().is_none(), "nothing written");

    let mut stranger = sample_cred(&id, 0, &format!("AKIA_R5_S_{id}"));
    stranger.meta.key_id = "vk_someone_else".into();
    assert_eq!(
        store
            .put_key_with_credential(&sample_key(&id), &stranger)
            .unwrap_err()
            .0,
        format!(
            "put_key_with_credential: the credential names key 'vk_someone_else', not the key \
             '{id}' being minted with it"
        )
    );
    assert!(store.get_key(&id).unwrap().is_none(), "nothing written");
    assert_eq!(store_revision(&store), counter, "no revision spent");

    store.put_key(&sample_key(&id)).unwrap();
    store.delete_key(&id).unwrap();
    let e = store
        .put_key_with_credential(&sample_key(&id), &cred)
        .unwrap_err();
    assert!(e.0.contains("never reissued"), "{e:?}");
    assert!(store.list_credentials(&id).unwrap().is_empty());
    hard_reset(&store, &id);

    let live_id = format!("{id}_live");
    hard_reset(&store, &live_id);
    store.put_key(&sample_key(&live_id)).unwrap();
    let mut renamed = sample_key(&live_id);
    renamed.name = "renamed".into();
    let c = sample_cred(&live_id, 0, &format!("AKIA_R5_L_{id}"));
    store.put_key_with_credential(&renamed, &c).unwrap();
    assert_eq!(store.get_key(&live_id).unwrap().unwrap().name, "renamed");
    assert_eq!(store.list_credentials(&live_id).unwrap().len(), 1);
    hard_reset(&store, &live_id);
}

/// R7: a revoked credential keeps no secret; the repeat is a no-op.
#[test]
fn revoking_a_credential_destroys_its_secret() {
    if live_url().is_none() {
        return;
    }
    let (store, id) = fresh("r7");
    store.put_key(&sample_key(&id)).unwrap();
    let c = sample_cred(&id, 0, &format!("AKIA_R7_{id}"));
    store.put_credential(&c).unwrap();
    let minted = store.list_credentials(&id).unwrap()[0].revision;

    store.revoke_credential(&c.meta.id, "leaked").unwrap();
    let row = store
        .lock()
        .query_one(
            "SELECT secret IS NULL, secret_form FROM credentials WHERE id=$1",
            &[&c.meta.id],
        )
        .unwrap();
    assert!(row.get::<_, bool>(0), "the secret column is NULL");
    assert_eq!(row.get::<_, String>(1), "none");

    let all = store.list_credentials_since(0).unwrap();
    let got = all.iter().find(|s| s.meta.id == c.meta.id).expect("listed");
    assert_eq!(got.secret, "", "no secret material");
    assert_eq!(got.meta.secret_form, SecretForm::None);
    assert_eq!(got.meta.revoke_reason.as_deref(), Some("leaked"));
    let revoked_rev = got.meta.revision;
    assert!(revoked_rev > minted);

    store.revoke_credential(&c.meta.id, "again").unwrap();
    let again = store.list_credentials(&id).unwrap();
    assert_eq!(again[0].revision, revoked_rev, "a repeat bumps nothing");
    assert_eq!(again[0].revoke_reason.as_deref(), Some("leaked"));
    hard_reset(&store, &id);
}

/// W2: one text per condition, the op's own name in it.
#[test]
fn refusals_read_one_text_per_condition() {
    if live_url().is_none() {
        return;
    }
    let (store, id) = fresh("w2");

    assert_eq!(
        store.revoke_credential("cred_nope", "x").unwrap_err().0,
        "revoke_credential: unknown id 'cred_nope'"
    );

    let orphan = sample_cred(&id, 0, &format!("AKIA_W2_{id}"));
    assert_eq!(
        store.put_credential(&orphan).unwrap_err().0,
        format!("put_credential: key '{id}' does not exist; a credential must hang off a real key")
    );

    store.put_key(&sample_key(&id)).unwrap();
    store.delete_key(&id).unwrap();
    assert_eq!(
        store.put_credential(&orphan).unwrap_err().0,
        format!(
            "put_credential: key '{id}' is tombstoned; its credentials were revoked with it and \
             are never reissued"
        )
    );
    hard_reset(&store, &id);

    let a = format!("{id}_a");
    let b = format!("{id}_b");
    hard_reset(&store, &a);
    hard_reset(&store, &b);
    store.put_key(&sample_key(&a)).unwrap();
    store.put_key(&sample_key(&b)).unwrap();
    let public_id = format!("AKIA_W2_SHARED_{id}");
    store
        .put_credential(&sample_cred(&a, 0, &public_id))
        .unwrap();
    let mut clash = sample_cred(&b, 0, &public_id);
    clash.meta.id = format!("cred_clash_{id}");
    assert_eq!(
        store.put_credential(&clash).unwrap_err().0,
        format!("put_credential: public_id '{public_id}' is already in use for kind 'sigv4'")
    );
    hard_reset(&store, &a);
    hard_reset(&store, &b);
}

/// W5: deterministic list orders.
#[test]
fn lists_come_back_in_a_deterministic_order() {
    if live_url().is_none() {
        return;
    }
    let (store, id) = fresh("w5");
    let ids: Vec<String> = ["c", "a", "b"]
        .iter()
        .map(|s| format!("{id}_{s}"))
        .collect();
    for k in &ids {
        hard_reset(&store, k);
        store.put_key(&sample_key(k)).unwrap();
    }
    let listed: Vec<String> = store
        .list_keys()
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .filter(|k| k.starts_with(&id))
        .collect();
    let mut want = listed.clone();
    want.sort();
    assert_eq!(listed, want, "list_keys breaks created_at ties by id");

    let owner = &ids[0];
    store
        .put_credential(&sample_cred(owner, 1, &format!("AKIA_W5_1_{id}")))
        .unwrap();
    store
        .put_credential(&sample_cred(owner, 0, &format!("AKIA_W5_0_{id}")))
        .unwrap();
    let slots: Vec<u8> = store
        .list_credentials(owner)
        .unwrap()
        .iter()
        .map(|c| c.slot)
        .collect();
    assert_eq!(slots, [0, 1], "list_credentials is (kind, slot) ascending");
    for k in &ids {
        hard_reset(&store, k);
    }
}
