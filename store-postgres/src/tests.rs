// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the Postgres store (schema v7, generic credentials): DSN-password scrubbing plus
//! (gated on `BUSBAR_TEST_POSTGRES_URL`) real round-trip and invariant coverage against a live
//! `postgres:16`.

use super::*;
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, ModelTokensDelta, PlaneDisposition, PlaneRecord,
    PlaneSelector, RecordStore, SecretForm,
};

#[path = "tests/harness.rs"]
mod harness;

#[path = "tests/credential_rewrap.rs"]
mod credential_rewrap;

#[path = "tests/credential_timestamps.rs"]
mod credential_timestamps;

#[path = "tests/usage_transactions.rs"]
mod usage_transactions;

#[path = "tests/usage_keys.rs"]
mod usage_keys;

#[path = "tests/usage_correction.rs"]
mod usage_correction;

#[path = "tests/conditional_records.rs"]
mod conditional_records;

#[path = "tests/migration_parent_presence.rs"]
mod migration_parent_presence;

pub(crate) use harness::TestStore;

/// The verify path's read, which is no longer a store op: a credential's secret by `(kind,
/// public_id)`, read back through the revision delta (which carries every row, revoked or not).
trait Lookup {
    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>>;
}

impl Lookup for TestStore {
    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> RecordStoreResult<Option<CredentialSecret>> {
        Ok(self
            .list_credentials_since(0)?
            .into_iter()
            .find(|c| c.meta.kind == kind && c.meta.public_id == public_id))
    }
}

/// One model's ledger row from the four RESERVED token classes (zero classes left out, the way the
/// store reads them back).
fn mt(
    model: impl Into<String>,
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
) -> ModelTokens {
    let mut usage_units = BTreeMap::new();
    for (u, v) in [
        (UNIT_INPUT, input),
        (UNIT_OUTPUT, output),
        (UNIT_CACHE_READ, cache_read),
        (UNIT_CACHE_WRITE, cache_write),
    ] {
        if v != 0 {
            usage_units.insert(u.to_string(), v);
        }
    }
    ModelTokens {
        model: model.into(),
        usage_units,
    }
}

/// The signed twin of [`mt`], for `add_usage`.
fn mtd(
    model: impl Into<String>,
    input: i64,
    output: i64,
    cache_read: i64,
    cache_write: i64,
) -> ModelTokensDelta {
    let mut usage_units = BTreeMap::new();
    for (u, v) in [
        (UNIT_INPUT, input),
        (UNIT_OUTPUT, output),
        (UNIT_CACHE_READ, cache_read),
        (UNIT_CACHE_WRITE, cache_write),
    ] {
        if v != 0 {
            usage_units.insert(u.to_string(), v);
        }
    }
    ModelTokensDelta {
        model: model.into(),
        usage_units,
    }
}

/// Drift guard, no live DB needed: `CRED_SECRET_COLUMN_INDEX` must stay in sync with
/// `CRED_META_COLUMNS`' own column count, since `str::split` isn't const-evaluable and the constant
/// is hand-maintained.
#[test]
fn cred_secret_column_index_matches_cred_meta_columns_count() {
    assert_eq!(
        CRED_META_COLUMNS.split(',').count(),
        CRED_SECRET_COLUMN_INDEX,
        "CRED_SECRET_COLUMN_INDEX must equal CRED_META_COLUMNS' column count -- update it if you \
         changed CRED_META_COLUMNS"
    );
}

/// Constructors capture passwords once, and the only remaining error-redaction path uses Cred.
#[test]
fn captured_dsn_passwords_redact_peer_errors_without_plaintext_custody() {
    for (dsn, expected) in [
        ("postgres://user:s3cr3t@host:5432/db", "s3cr3t"),
        ("postgresql://u:p%40ss@host/db", "p@ss"),
        ("host=db user=u password=kwsecret dbname=x", "kwsecret"),
        ("host = db user = u password = spaced dbname = x", "spaced"),
        ("host=db password='quoted secret' user=u", "quoted secret"),
        ("postgres://user@host:5432/db?password=inquery", "inquery"),
        (
            "postgres://user@host:5432/db?connect_timeout=10&password=after",
            "after",
        ),
        ("postgres://u:secret@host/db?options=label@other", "secret"),
        (
            r"host=db user=u password='quote\' and\\slash'",
            "quote' and\\slash",
        ),
        (r"host=db user=u password=escaped\ space", "escaped space"),
        ("host=db user=u password='two  spaces'", "two  spaces"),
        (
            "host=db user=u password='before?password=after'",
            "before?password=after",
        ),
        (
            "host=db user=u password='before://u:wrong@host'",
            "before://u:wrong@host",
        ),
    ] {
        let store = PostgresStore::new(dsn).unwrap();
        assert_eq!(
            store.shared.config.redact(format!("auth: {expected}")),
            "auth: <redacted>"
        );
        assert!(!format!("{:?}", store.shared.config).contains(expected));
    }
    for dsn in ["postgres://host:5432/db?user=u", "host=db user=u"] {
        let store = PostgresStore::new(dsn).unwrap();
        assert_eq!(store.shared.config.redact("plain".into()), "plain");
    }
    for dsn in [
        "host=db user=u password='unterminated",
        "host=db sslpassword=hidden user=u",
        "postgres://u:hidden@host/db?invalid=hidden",
    ] {
        let error = PostgresStore::new(dsn).err().expect("invalid DSN").0;
        assert!(!error.contains("hidden") && !error.contains("password='unterminated"));
    }
}

fn live_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_POSTGRES_URL is unset under CI: the Postgres service container must \
                 provision it. Refusing to silently skip the only live-DB coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the live Postgres tests");
            None
        }
    }
}

/// Open a raw `postgres::Client` with bounded retry-with-backoff. Used only where a test genuinely
/// needs a SECOND connection independent of the store's (e.g. holding a REPEATABLE READ snapshot
/// open on one connection while the store writes on its own) -- there the connection cannot be
/// reused away.
fn connect_client_with_retry(url: &str) -> postgres::Client {
    let mut last_err = None;
    for attempt in 0..10u32 {
        match postgres::Client::connect(url, postgres::NoTls) {
            Ok(c) => return c,
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1)));
            }
        }
    }
    panic!("connect (after retries): {:?}", last_err.unwrap());
}

/// The store under test, opened with bounded retry-with-backoff: through the REAL loader on a
/// dispatcher, its connections over the host's connection path (the loader's test `TcpConns`), so
/// every op goes through the door exactly as busbar runs it.
fn connect_store_with_retry(url: &str) -> Result<TestStore, String> {
    let mut last_err = None;
    for attempt in 0..10u32 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
        }
        match TestStore::open(url) {
            Ok(store) => return Ok(store),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("loop ran at least once"))
}

/// TRUE reset for test isolation -- unlike `delete_key` (a deliberate tombstone that can never fully
/// reset a row by design), this raw-SQL wipe gives each test a genuinely clean slate for its id, so
/// re-running the suite (or running it twice in a row) never sees stale state
/// from a prior run leaking into the CHECK constraints (e.g. re-minting into a row still marked
/// `deleted_at` from a previous run's tombstone would violate `keys_tombstone_disabled`).
fn hard_reset(store: &TestStore, id: &str) {
    let mut client = store.lock();
    for sql in [
        "DELETE FROM credentials WHERE key_id=$1",
        "DELETE FROM keys WHERE id=$1",
        "DELETE FROM usage_metering WHERE key_id=$1",
        "DELETE FROM usage_windows WHERE bucket_id=$1",
        "DELETE FROM usage_ledger WHERE bucket_id=$1",
        "DELETE FROM usage_ledger_units WHERE bucket_id=$1",
        "DELETE FROM usage_metering_units WHERE key_id=$1",
    ] {
        client
            .execute(sql, &[&id])
            .unwrap_or_else(|e| panic!("hard_reset `{sql}`: {e}"));
    }
}

fn sample_key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: "binding:x:g1".into(),
        name: "k".into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 100,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    }
}

fn sample_cred(key_id: &str, slot: u8, public_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: format!("cred_{public_id}"),
            key_id: key_id.into(),
            kind: "sigv4".into(),
            slot,
            public_id: public_id.into(),
            secret_form: SecretForm::Recoverable,
            created_at: 100,
            updated_at: 100,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:supersecret".into(),
    }
}

/// Basic key round-trip, including the new fields (generation_hash, expires_at, deleted_at,
/// revision) and the allowed_pools NULL-vs-'[]' distinction.
#[test]
fn key_roundtrip_new_fields() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let (rt1, rt2) = (
        format!("vk_rt1_{}", unique_suffix()),
        format!("vk_rt2_{}", unique_suffix()),
    );
    hard_reset(&store, &rt1);
    hard_reset(&store, &rt2);

    let mut k = sample_key(&rt1);
    k.expires_at = Some(999);
    k.allowed_scopes = Some(vec![]);
    store.put_key(&k).unwrap();
    let back = store.get_key(&rt1).unwrap().unwrap();
    assert_eq!(back.generation_hash, "binding:x:g1");
    assert_eq!(back.expires_at, Some(999));
    assert_eq!(back.deleted_at, None);
    assert_eq!(
        back.allowed_scopes,
        Some(vec![]),
        "explicit empty grant must round-trip as Some([]), not None"
    );
    assert!(back.revision > 0, "put_key must stamp a nonzero revision");

    let mut k2 = sample_key(&rt2);
    k2.allowed_scopes = None;
    store.put_key(&k2).unwrap();
    let back2 = store.get_key(&rt2).unwrap().unwrap();
    assert_eq!(
        back2.allowed_scopes, None,
        "omitted grant must round-trip as None, not Some([])"
    );
}

/// THE core invariant: delete_key is a TOMBSTONE. The row survives (deleted_at set, enabled=false),
/// every credential is destroyed, and usage_metering (which FKs nothing here but conceptually
/// depends on key_id resolving) still finds the key by id afterward.
#[test]
fn delete_key_is_a_tombstone_not_a_hard_delete() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_owned = format!("vk_tombstone1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store, id);

    let key = sample_key(id);
    let cred = sample_cred(id, 0, &format!("AKIA_TOMBSTONE1_{id}"));
    store.put_key_with_credential(&key, &cred).unwrap();
    assert_eq!(store.list_credentials(id).unwrap().len(), 1);

    store.delete_key(id).unwrap();

    let after = store.get_key(id).unwrap();
    assert!(
        after.is_some(),
        "the keys row must survive a delete_key call (tombstone, not hard delete)"
    );
    let after = after.unwrap();
    assert!(!after.is_live(), "is_live() must be false once tombstoned");
    assert!(!after.enabled, "enabled must be forced false");
    assert!(after.deleted_at.is_some(), "deleted_at must be set");

    let creds = store.list_credentials(id).unwrap();
    assert!(
        creds.is_empty(),
        "every credential row for the key must be destroyed on delete"
    );

    let deleted_at_first = after.deleted_at;
    store.delete_key(id).unwrap();
    let after2 = store.get_key(id).unwrap().unwrap();
    assert_eq!(
        after2.deleted_at, deleted_at_first,
        "a repeat delete must not change deleted_at"
    );
}

/// `delete_key` must stamp `deleted_at` with a WALL-CLOCK time, not with the store-global revision
/// counter.
#[test]
fn delete_key_stamps_deleted_at_with_a_wall_clock_time_not_the_revision() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_owned = format!("vk_deleted_at_clock1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();

    let wall = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let before = wall();
    store.delete_key(id).unwrap();
    let after = wall();

    let deleted_at = store
        .get_key(id)
        .unwrap()
        .unwrap()
        .deleted_at
        .expect("delete_key must set deleted_at");
    assert!(
        deleted_at >= before && deleted_at <= after,
        "deleted_at must be the wall-clock second the delete landed (expected {before}..={after}), \
         got {deleted_at} -- a value far below the current Unix time means the revision counter was \
         bound to this column instead of a clock read"
    );
    assert!(
        deleted_at > 1_700_000_000,
        "deleted_at must be a plausible present-day Unix time, got {deleted_at} -- a small integer \
         here is a counter, not a clock"
    );
}

/// put_key_with_credential must REFUSE to re-mint over a tombstoned id.
#[test]
fn put_key_with_credential_refuses_to_remint_over_a_tombstone() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_owned = format!("vk_remint_over_tombstone1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store, id);

    let key = sample_key(id);
    let cred = sample_cred(id, 0, &format!("AKIA_REMINT1_{id}"));
    store.put_key_with_credential(&key, &cred).unwrap();
    store.delete_key(id).unwrap();
    let tombstoned = store.get_key(id).unwrap().unwrap();
    assert!(tombstoned.deleted_at.is_some(), "precondition: tombstoned");
    assert!(!tombstoned.enabled, "precondition: disabled");

    let mut remint = sample_key(id);
    remint.enabled = true;
    remint.deleted_at = None;
    let remint_cred = sample_cred(id, 0, &format!("AKIA_REMINT1_NEW_{id}"));
    let err = store
        .put_key_with_credential(&remint, &remint_cred)
        .expect_err("re-minting over a tombstoned id must be refused, not silently resurrected");
    assert!(
        err.to_string().contains("never reissued"),
        "the refusal must say why: {err}"
    );

    let after = store.get_key(id).unwrap().unwrap();
    assert!(
        after.deleted_at.is_some(),
        "the tombstone must survive the refused re-mint"
    );
    assert!(
        !after.enabled,
        "the refused re-mint must not have flipped enabled: {after:?}"
    );

    assert!(
        store.list_credentials(id).unwrap().is_empty(),
        "a refused re-mint must not write the paired credential"
    );
}

/// Credential minting is slot-safe: minting into a slot holding a LIVE credential must fail, not
/// silently clobber it.
#[test]
fn credential_slot_guard_rejects_clobbering_a_live_credential() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_owned = format!("vk_slotguard1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();

    let c0 = sample_cred(id, 0, &format!("AKIA_SLOT0_A_{id}"));
    store.put_credential(&c0).unwrap();

    let c0b = sample_cred(id, 0, &format!("AKIA_SLOT0_B_{id}"));
    let err = store.put_credential(&c0b);
    assert!(err.is_err(), "minting into an occupied LIVE slot must fail");

    let live = store
        .lookup_credential_secret("sigv4", &format!("AKIA_SLOT0_A_{id}"))
        .unwrap();
    assert!(
        live.is_some(),
        "the original live credential must survive a rejected clobber attempt"
    );

    let c1 = sample_cred(id, 1, &format!("AKIA_SLOT1_A_{id}"));
    store.put_credential(&c1).unwrap();
    assert_eq!(store.list_credentials(id).unwrap().len(), 2);

    let cred0_id = c0.meta.id.clone();
    store.revoke_credential(&cred0_id, "rotated").unwrap();
    let c0c = sample_cred(id, 0, &format!("AKIA_SLOT0_C_{id}"));
    store.put_credential(&c0c).unwrap();
    let resolved = store
        .lookup_credential_secret("sigv4", &format!("AKIA_SLOT0_C_{id}"))
        .unwrap()
        .expect("re-mint into a revoked slot must succeed");
    assert_eq!(resolved.meta.slot, 0);
}

/// put_credential_tx must bind CredentialMeta::updated_at to its own column, not silently reuse
/// created_at's parameter for both.
#[test]
fn put_credential_binds_updated_at_to_its_own_column_not_created_at() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_owned = format!("vk_updated_at1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();

    let mut cred = sample_cred(id, 0, &format!("AKIA_UPDATEDAT1_{id}"));
    cred.meta.created_at = 100;
    cred.meta.updated_at = 200;
    store.put_credential(&cred).unwrap();

    let got = store
        .list_credentials(id)
        .unwrap()
        .into_iter()
        .find(|m| m.public_id == format!("AKIA_UPDATEDAT1_{id}"))
        .expect("the minted credential must be listed");
    assert_eq!(got.created_at, 100, "created_at must round-trip untouched");
    assert_eq!(
        got.updated_at, 200,
        "updated_at must round-trip as its own distinct value, not be silently overwritten by \
         created_at's"
    );
}

/// revoke_credential kills ONE credential independent of the key: the key stays enabled, the OTHER
/// slot's credential stays live, only the targeted one is revoked.
#[test]
fn revoke_credential_is_independent_of_the_key_and_other_slots() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_owned = format!("vk_revoke1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();
    let c0 = sample_cred(id, 0, &format!("AKIA_REVOKE1_A_{id}"));
    let c1 = sample_cred(id, 1, &format!("AKIA_REVOKE1_B_{id}"));
    store.put_credential(&c0).unwrap();
    store.put_credential(&c1).unwrap();

    store.revoke_credential(&c0.meta.id, "leaked").unwrap();

    let key = store.get_key(id).unwrap().unwrap();
    assert!(
        key.enabled,
        "revoking a credential must not touch the key's enabled flag"
    );
    assert!(key.is_live());

    let creds = store.list_credentials(id).unwrap();
    let meta0 = creds.iter().find(|c| c.id == c0.meta.id).unwrap();
    let meta1 = creds.iter().find(|c| c.id == c1.meta.id).unwrap();
    assert!(
        meta0.revoked_at.is_some(),
        "the targeted credential must be revoked"
    );
    assert!(
        meta1.revoked_at.is_none(),
        "the OTHER slot's credential must be untouched"
    );

    let resolved = store
        .lookup_credential_secret("sigv4", &format!("AKIA_REVOKE1_A_{id}"))
        .unwrap()
        .expect("the verify path must still resolve a revoked credential, not report it unknown");
    assert!(
        resolved.meta.revoked_at.is_some(),
        "the credential the verify path resolves must carry the revocation, or every caller's \
         liveness check admits a revoked secret"
    );
    assert!(
        !resolved.meta.is_live(0),
        "a revoked credential must never read as live on the verify path"
    );

    let untouched = store
        .lookup_credential_secret("sigv4", &format!("AKIA_REVOKE1_B_{id}"))
        .unwrap()
        .expect("the other slot's credential must still resolve");
    assert!(
        untouched.meta.is_live(0),
        "the credential that was NOT revoked must read as live, or liveness is not discriminating"
    );

    store
        .revoke_credential(&c0.meta.id, "leaked again")
        .unwrap();
}

/// `revoke_credential` must FAIL LOUD on a credential id that does not exist, rather than reporting
/// a successful revocation of nothing.
#[test]
fn revoke_credential_errors_on_an_unknown_id_but_stays_idempotent_on_a_revoked_one() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_owned = format!("vk_revoke_unknown1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();

    let err = store
        .revoke_credential("cred_this_id_was_never_minted", "leaked")
        .expect_err("revoking an id that names no row must be an error, not a reported success");
    assert!(
        err.0.contains("cred_this_id_was_never_minted"),
        "the error should name the id that could not be revoked: {}",
        err.0
    );

    let cred = sample_cred(id, 0, &format!("AKIA_REVOKE_UNKNOWN1_{id}"));
    store.put_credential(&cred).unwrap();
    store.revoke_credential(&cred.meta.id, "leaked").unwrap();
    let after_first = store
        .list_credentials(id)
        .unwrap()
        .into_iter()
        .find(|c| c.id == cred.meta.id)
        .expect("the revoked credential must still be listed");
    assert!(
        after_first.revoked_at.is_some(),
        "the first revoke must actually revoke"
    );
    assert_eq!(after_first.revoke_reason.as_deref(), Some("leaked"));

    store
        .revoke_credential(&cred.meta.id, "leaked again")
        .expect("re-revoking an already-revoked credential must stay a no-op success");
    let after_second = store
        .list_credentials(id)
        .unwrap()
        .into_iter()
        .find(|c| c.id == cred.meta.id)
        .expect("the credential must still be listed");
    assert_eq!(
        after_second.revoke_reason.as_deref(),
        Some("leaked"),
        "a repeat revoke must NOT rewrite revoke_reason: the first revocation's recorded reason is \
         the true one, and overwriting it loses why the credential was actually killed"
    );
    assert_eq!(
        after_second.revoked_at, after_first.revoked_at,
        "a repeat revoke must not move revoked_at"
    );
    assert_eq!(
        after_second.updated_at, after_first.updated_at,
        "a repeat revoke must not touch updated_at"
    );
    assert_eq!(
        after_second.revision, after_first.revision,
        "a repeat revoke must not burn a store-global revision, or every retry churns the \
         hydration delta for a row that did not change"
    );
}

/// HYDRATION-DELTA SOUNDNESS, the same invariant the SQLite and MySQL schemas have to hold. A
/// revision-based delta consumer polling list_keys_since/list_credentials_since must be able to
/// observe a delete_key tombstone AND infer the credential deletion from it, because the
/// credential rows are hard-deleted and produce no delta of their own.
#[test]
fn hydration_delta_makes_credential_deletion_observable_via_the_key_tombstone() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_owned = format!("vk_hydrate1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store, id);

    let key = sample_key(id);
    let cred = sample_cred(id, 0, &format!("AKIA_HYDRATE1_{id}"));
    store.put_key_with_credential(&key, &cred).unwrap();

    let watermark = store.get_key(id).unwrap().unwrap().revision;

    store.delete_key(id).unwrap();

    let key_deltas = store.list_keys_since(watermark).unwrap();
    let tombstoned = key_deltas
        .iter()
        .find(|k| k.id == id)
        .expect("the tombstoned key MUST appear in the delta since the pre-delete watermark");
    assert!(
        !tombstoned.is_live(),
        "the delta must show the key as tombstoned"
    );

    assert!(
        store.list_credentials(id).unwrap().is_empty(),
        "delete_key must have hard-deleted the credential row for a correct baseline to compare \
         the delta behavior below against"
    );

    let cred_deltas = store.list_credentials_since(watermark).unwrap();
    assert!(
        cred_deltas.iter().all(|c| c.meta.key_id != id),
        "a hard-deleted credential produces no further delta -- this is the documented gap the \
         consumer-side contract (see RecordStore::list_credentials_since's doc) exists to close"
    );
}

/// A concurrent-instance race: two independent connections both try to delete the same key. Exactly
/// one does the real work; both must return Ok (idempotent), and the final state must be a single,
/// consistent tombstone -- not a partial/interleaved one.
#[test]
fn concurrent_delete_of_the_same_key_is_safe_and_idempotent() {
    let Some(url) = live_url() else { return };
    let store_a = connect_store_with_retry(&url).expect("connect a");
    let store_b = connect_store_with_retry(&url).expect("connect b");

    let store_c = connect_store_with_retry(&url).expect("connect c");
    let id_owned = format!("vk_concurrent_del1_{}", unique_suffix());
    let id = id_owned.as_str();
    hard_reset(&store_a, id);
    store_a.put_key(&sample_key(id)).unwrap();
    let cred = sample_cred(id, 0, &format!("AKIA_CONCURRENT1_{id}"));
    store_a.put_credential(&cred).unwrap();

    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handle = {
        let start = start.clone();
        let id_c = id.to_string();
        std::thread::spawn(move || {
            start.wait();
            store_c.delete_key(&id_c)
        })
    };
    start.wait();
    let r1 = store_b.delete_key(id);
    let r2 = handle.join().unwrap();
    assert!(
        r1.is_ok() && r2.is_ok(),
        "both concurrent deletes must succeed (idempotent), got {r1:?} / {r2:?}"
    );

    let after = store_a.get_key(id).unwrap().unwrap();
    assert!(!after.is_live());
    assert!(store_a.list_credentials(id).unwrap().is_empty());
}

/// A concurrent `add_usage` landing between `get_usage`'s reads must not be half-visible. A writer
/// adds one request and one NEW model per call, so any consistent snapshot has exactly as many model
/// rows as requests; `get_usage` itself is read in a loop against it.
#[test]
fn get_usage_never_returns_a_torn_snapshot_under_a_concurrent_writer() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_torn_usage");
    let url = db.url();
    let reader = connect_store_with_retry(&url).expect("connect");
    let writer = connect_store_with_retry(&url).expect("connect");
    let bucket = format!("vk_torn_{}", unique_suffix());
    let ws = 20_270_301u64;
    let done = std::sync::atomic::AtomicBool::new(false);

    struct Finished<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for Finished<'_> {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let reads = std::thread::scope(|s| {
        let w = s.spawn(|| {
            let _finished = Finished(&done);
            for i in 0..400 {
                writer
                    .add_usage(
                        &bucket,
                        ws,
                        &UsageDelta {
                            requests: 1,
                            billable_requests: 1,
                            models: vec![mtd(format!("m{i}"), 1, 0, 0, 0)],
                        },
                    )
                    .unwrap();
            }
        });
        let mut reads = 0;
        while !done.load(std::sync::atomic::Ordering::SeqCst) {
            let got = reader.get_usage(&bucket, ws).unwrap();
            assert_eq!(
                got.models.len() as u64,
                got.requests,
                "a torn read: {} requests beside {} model rows",
                got.requests,
                got.models.len()
            );
            reads += 1;
        }
        w.join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        reads
    });
    assert!(reads > 0);
    hard_reset(&reader, &bucket);
}

/// usage_metering round-trip including the new fields (billable_requests, key_group_at_use,
/// pricing_version) and the renamed tokens_cache_write (was tokens_cache_creation).
#[test]
fn metering_roundtrip_new_fields() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let bucket = 20_270_101u64;
    let meter_key = format!("vk_meter_new1_{}", unique_suffix());
    hard_reset(&store, &meter_key);
    store
        .add_metering(&busbar_contract::records::MeteringDelta {
            key_id: meter_key.clone(),
            bucket,
            model: "m".into(),
            provider: "p".into(),
            tokens_input: 10,
            tokens_output: 20,
            tokens_cache_read: 1,
            tokens_cache_write: 2,
            requests: 3,
            billable_requests: 2,
            key_group_at_use: "growth".into(),
            pricing_version: "2026-07".into(),
            priced_from_ms: 0,
            usage_units: Default::default(),
        })
        .unwrap();
    let rows = store.list_metering(bucket).unwrap();
    let row = rows.iter().find(|r| r.key_id == meter_key).unwrap();
    assert_eq!(row.tokens_cache_write, 2);
    assert_eq!(row.billable_requests, 2);
    assert_eq!(row.key_group_at_use, "growth");
    assert_eq!(row.pricing_version, "2026-07");
}

/// Password capture uses strict percent decoding before a public parser sees the DSN.
#[test]
fn password_capture_percent_decoding_edge_cases() {
    let store = PostgresStore::new("postgres://u:%41@host/db").unwrap();
    assert_eq!(
        store.shared.config.redact("auth: A".into()),
        "auth: <redacted>"
    );
    for password in ["a%1", "abc%", "%ff"] {
        assert!(PostgresStore::new(&format!("postgres://u:{password}@host/db")).is_err());
    }
}

/// `is_undefined_table` must discriminate the ONE SQLSTATE (`42P01`/undefined_table) it exists to
/// recognize from every other error class, so neither an inverted comparison nor an unconditional
/// true/false passes.
#[test]
fn is_undefined_table_matches_only_the_real_sqlstate() {
    let missing = crate::pgwire::Error::server("42P01", "relation \"x\" does not exist");
    assert!(
        is_undefined_table(&missing),
        "a missing table must be classified as undefined_table: {missing}"
    );
    let syntax_err = crate::pgwire::Error::server("42601", "syntax error at or near \"SELEC\"");
    assert!(
        !is_undefined_table(&syntax_err),
        "a syntax error must NOT be misclassified as undefined_table: {syntax_err}"
    );
    assert!(!is_undefined_table(&crate::pgwire::Error::connect(
        "refused"
    )));
}

/// `labels_to_storage`'s serialization -- not just the empty-map default -- must round-trip a
/// non-empty label set.
#[test]
fn labels_round_trip_non_empty_map() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let labels_id = format!("vk_labels_rt_{}", unique_suffix());
    hard_reset(&store, &labels_id);

    let mut k = sample_key(&labels_id);
    k.labels = std::collections::BTreeMap::from([
        ("team".to_string(), "growth".to_string()),
        ("env".to_string(), "prod".to_string()),
    ]);
    store.put_key(&k).unwrap();
    let back = store.get_key(&labels_id).unwrap().unwrap();
    assert_eq!(back.labels.get("team").map(String::as_str), Some("growth"));
    assert_eq!(back.labels.get("env").map(String::as_str), Some("prod"));
    assert_eq!(back.labels.len(), 2);
}

/// `secret_form_to_storage`/`secret_form_from_storage` for all three `SecretForm` variants, pure
/// (no DB needed) and independent of which credential fixtures happen to default to `Recoverable`
/// elsewhere -- catches a deleted `"recoverable"` or `"digest"` match arm silently falling through
/// to an unrelated secret form.
#[test]
fn secret_form_storage_round_trip_all_variants() {
    assert_eq!(secret_form_to_storage(SecretForm::None), "none");
    assert_eq!(
        secret_form_to_storage(SecretForm::Recoverable),
        "recoverable"
    );
    assert_eq!(secret_form_to_storage(SecretForm::Digest), "digest");

    assert_eq!(secret_form_from_storage("none").unwrap(), SecretForm::None);
    assert_eq!(
        secret_form_from_storage("recoverable").unwrap(),
        SecretForm::Recoverable
    );
    assert_eq!(
        secret_form_from_storage("digest").unwrap(),
        SecretForm::Digest
    );
    assert!(secret_form_from_storage("garbage").is_err());
}

/// `put_usage`/`add_usage`'s multi-row `VALUES (...)` batching (comma insertion gated on `i > 0`,
/// and each row's placeholder `base = 3 + i * 5`) is only exercised by a call with 2+ models -- every
/// existing test used exactly one model, so `i > 0` vs `i < 0`, and `+`/`*` in the offset arithmetic,
/// were never distinguished (with one model, `i` is always 0, and both branches degenerate to the
/// same single-row SQL).
#[test]
fn put_usage_and_add_usage_batch_multiple_models_correctly() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let bucket_owned = format!("vk_multi_model_batch_{}", unique_suffix());
    let bucket = bucket_owned.as_str();
    let ws = 20_270_401u64;
    let ws2 = ws + 1;
    for w in [ws, ws2] {
        let _ = store.lock().execute(
            "DELETE FROM usage_windows WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &clamp(w)],
        );
        let _ = store.lock().execute(
            "DELETE FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &clamp(w)],
        );
    }

    store
        .put_usage(
            bucket,
            ws,
            &UsageLedger {
                requests: 3,
                billable_requests: 2,
                models: vec![
                    mt("model-a", 10, 20, 1, 2),
                    mt("model-b", 30, 40, 3, 4),
                    mt("model-c", 50, 60, 5, 6),
                ],
            },
        )
        .unwrap();

    let got = store.get_usage(bucket, ws).unwrap();
    let mut models = got.models;
    models.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(
        models.len(),
        3,
        "all three model rows must land as three distinct, correctly delimited rows"
    );
    assert_eq!(models[0].model, "model-a");
    assert_eq!(models[0].tier(UNIT_INPUT), 10);
    assert_eq!(models[0].tier(UNIT_OUTPUT), 20);
    assert_eq!(models[1].model, "model-b");
    assert_eq!(models[1].tier(UNIT_INPUT), 30);
    assert_eq!(models[1].tier(UNIT_CACHE_WRITE), 4);
    assert_eq!(models[2].model, "model-c");
    assert_eq!(models[2].tier(UNIT_CACHE_READ), 5);
    assert_eq!(models[2].tier(UNIT_CACHE_WRITE), 6);

    store
        .add_usage(
            bucket,
            ws2,
            &UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![mtd("model-x", 7, 8, 0, 0), mtd("model-y", 9, 11, 0, 0)],
            },
        )
        .unwrap();
    let got2 = store.get_usage(bucket, ws2).unwrap();
    let mut models2 = got2.models;
    models2.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(
        models2.len(),
        2,
        "both delta model rows must land distinctly"
    );
    assert_eq!(models2[0].model, "model-x");
    assert_eq!(models2[0].tier(UNIT_INPUT), 7);
    assert_eq!(models2[1].model, "model-y");
    assert_eq!(models2[1].tier(UNIT_OUTPUT), 11);
}

/// Raw usage pins at u64::MAX without narrowing corrected counters back through BIGINT.
#[test]
fn usage_accruals_pin_at_the_column_maximum() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let max = i64::MAX;
    let bucket = format!("vk_sat_{}", unique_suffix());
    let ws = 20_270_501u64;
    let mut open_units = mtd("m", max, max, max, max);
    open_units.usage_units.insert("audio_s".into(), max);
    let delta = UsageDelta {
        requests: max,
        billable_requests: max,
        models: vec![open_units],
    };
    store.add_usage(&bucket, ws, &delta).unwrap();
    store.add_usage(&bucket, ws, &delta).unwrap();
    store.add_usage(&bucket, ws, &delta).unwrap();
    let got = store.get_usage(&bucket, ws).unwrap();
    assert_eq!(got.requests, u64::MAX);
    assert_eq!(got.billable_requests, u64::MAX);
    assert_eq!(got.models[0].tier(UNIT_INPUT), u64::MAX);
    assert_eq!(got.models[0].tier(UNIT_CACHE_WRITE), u64::MAX);
    assert_eq!(got.models[0].tier("audio_s"), u64::MAX);

    let mut refund = mtd("m", -1, 0, 0, 0);
    refund.usage_units.insert("audio_s".into(), -1);
    store
        .add_usage(
            &bucket,
            ws,
            &UsageDelta {
                requests: -1,
                billable_requests: 0,
                models: vec![refund],
            },
        )
        .unwrap();
    let got = store.get_usage(&bucket, ws).unwrap();
    assert_eq!(got.requests, u64::MAX - 1);
    assert_eq!(got.models[0].tier(UNIT_INPUT), u64::MAX - 1);
    assert_eq!(got.models[0].tier("audio_s"), u64::MAX - 1);
}

/// The metering twin of the usage pin above.
#[test]
fn metering_accruals_pin_at_the_column_maximum() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let max = i64::MAX;
    let key = format!("vk_sat_m_{}", unique_suffix());
    let mut units = BTreeMap::new();
    units.insert("audio_s".to_string(), u64::MAX);
    let meter = busbar_contract::records::MeteringDelta {
        key_id: key.clone(),
        bucket: 20_270_502,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: u64::MAX,
        tokens_output: u64::MAX,
        tokens_cache_read: u64::MAX,
        tokens_cache_write: u64::MAX,
        requests: u64::MAX,
        billable_requests: u64::MAX,
        key_group_at_use: "g".into(),
        pricing_version: "v".into(),
        priced_from_ms: 0,
        usage_units: units,
    };
    store.add_metering(&meter).unwrap();
    store.add_metering(&meter).unwrap();
    let rows = store.list_metering(20_270_502).unwrap();
    let row = rows.iter().find(|r| r.key_id == key).unwrap();
    assert_eq!(row.tokens_input, max as u64);
    assert_eq!(row.requests, max as u64);
    assert_eq!(row.billable_requests, max as u64);
    assert_eq!(row.usage_units["audio_s"], max as u64);
}

/// The denylist pair: `add_denylist` is idempotent, a repeat add keeps the first reason.
#[test]
fn denylist_add_is_listed_and_a_repeat_add_is_a_no_op() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let sub = format!("sub_denylist_{}", unique_suffix());
    let _ = store
        .lock()
        .execute("DELETE FROM denylist WHERE sub=$1", &[&sub]);

    let wall = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let before = wall();
    store.add_denylist(&sub, "first reason").unwrap();
    let after = wall();
    assert!(
        store.list_denylist().unwrap().contains(&sub),
        "an added subject must appear in list_denylist"
    );

    let created_at: i64 = store
        .lock()
        .query_one("SELECT created_at FROM denylist WHERE sub=$1", &[&sub])
        .unwrap()
        .get(0);
    assert!(
        (before..=after).contains(&read_u64(created_at)),
        "denylist.created_at must be the wall-clock second the subject was denied (expected \
         {before}..={after}), got {created_at}"
    );

    store.add_denylist(&sub, "corrected reason").unwrap();
    let stored_reason: String = store
        .lock()
        .query_one("SELECT reason FROM denylist WHERE sub=$1", &[&sub])
        .unwrap()
        .get(0);
    assert_eq!(
        stored_reason, "first reason",
        "re-denylisting a subject is a no-op (the contract): the first reason stands"
    );
    let occurrences = store
        .list_denylist()
        .unwrap()
        .iter()
        .filter(|s| *s == &sub)
        .count();
    assert_eq!(
        occurrences, 1,
        "a repeat add must not duplicate the subject"
    );

    let _ = store
        .lock()
        .execute("DELETE FROM denylist WHERE sub=$1", &[&sub]);
}

/// `list_audit_tail` must return the tail OLDEST FIRST, and `list_audit` must return the whole log
/// in the same direction.
#[test]
fn list_audit_tail_returns_the_newest_entries_oldest_first() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_audittail");
    let store = connect_store_with_retry(&tmp.url()).expect("connect");

    for seq in 1..=4i64 {
        store
            .lock()
            .execute(
                "INSERT INTO audit_log (seq, ts, action, resource, outcome, principal, prev_hash, hash)
                 VALUES ($1, $2, 'key.mint', $3, 'applied', 'vk_tail_test', $4, $5)",
                &[
                    &seq,
                    &(1_700_000_000 + seq),
                    &format!("key:{seq}"),
                    &format!("h{}", seq - 1),
                    &format!("h{seq}"),
                ],
            )
            .unwrap();
    }

    let tail: Vec<u64> = store
        .list_audit_tail(3)
        .unwrap()
        .iter()
        .map(|r| r.seq)
        .collect();
    assert_eq!(
        tail,
        vec![2, 3, 4],
        "list_audit_tail must return the NEWEST entries in OLDEST-FIRST order, so a hash-chain \
         verifier reads prev_hash -> hash forwards"
    );

    let all_via_tail: Vec<u64> = store
        .list_audit_tail(100)
        .unwrap()
        .iter()
        .map(|r| r.seq)
        .collect();
    assert_eq!(all_via_tail, vec![1, 2, 3, 4]);

    let full = store.list_audit().unwrap();
    assert_eq!(
        full.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4],
        "list_audit must return the whole log in seq order"
    );
    assert_eq!(full[0].hash, "h1", "the records themselves must round-trip");
    assert_eq!(full[3].prev_hash, "h3");
}

/// `list_keys` is deliberately UNFILTERED: it must include tombstoned rows, because
/// `list_keys_since`'s fallback consumers need the tombstone visible to drive credential eviction.
#[test]
fn list_keys_includes_tombstoned_rows() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = format!("vk_list_tombstoned_{}", unique_suffix());
    hard_reset(&store, &id);
    store.put_key(&sample_key(&id)).unwrap();
    store.delete_key(&id).unwrap();

    let listed = store.list_keys().unwrap();
    let found = listed
        .iter()
        .find(|k| k.id == id)
        .expect("list_keys must include a tombstoned key, not filter it out");
    assert!(
        !found.is_live(),
        "the listed row must be the tombstone itself"
    );

    hard_reset(&store, &id);
}

/// `list_credentials_since` must actually return credentials. Its only previous appearance in this
/// file was a NEGATIVE assertion (`all(|c| c.key_id != id)`), which `all()` satisfies vacuously on
/// an empty vec, so deleting the whole method from the impl left the trait's `Ok(Vec::new())`
/// default in place, kept the crate compiling, kept the suite green, and silently stopped every
/// credential from ever reaching a hydrating node.
#[test]
fn list_credentials_since_returns_new_credentials_with_their_secret() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = format!("vk_cred_since_{}", unique_suffix());
    hard_reset(&store, &id);
    store.put_key(&sample_key(&id)).unwrap();

    let watermark = store.get_key(&id).unwrap().unwrap().revision;
    let public_id = format!("AKIA_SINCE_{}", unique_suffix());
    let cred = sample_cred(&id, 0, &public_id);
    store.put_credential(&cred).unwrap();

    let deltas = store.list_credentials_since(watermark).unwrap();
    let ours = deltas
        .iter()
        .find(|c| c.meta.key_id == id)
        .expect("a credential minted after the watermark must appear in the delta");
    assert_eq!(ours.meta.public_id, public_id);
    assert_eq!(
        ours.secret, cred.secret,
        "the delta must carry the secret material: hydration on a sibling node has no other source \
         for it, and a wrong column index here reads back empty rather than failing"
    );
    assert!(
        ours.meta.revision > watermark,
        "the delta row must carry a revision above the watermark that selected it"
    );

    let after = store.list_credentials_since(ours.meta.revision).unwrap();
    assert!(
        !after.iter().any(|c| c.meta.key_id == id),
        "a credential at or below the watermark must not be returned again"
    );

    hard_reset(&store, &id);
}

/// `put_credential_tx`'s SECOND failure branch: the slot is free, so the guarded upsert is not what
/// blocked the write, and the insert was rejected by the cross-key `UNIQUE (kind, public_id)`
/// constraint instead.
#[test]
fn put_credential_rejects_a_public_id_already_used_by_another_key() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id_a = format!("vk_pubid_a_{}", unique_suffix());
    let id_b = format!("vk_pubid_b_{}", unique_suffix());
    hard_reset(&store, &id_a);
    hard_reset(&store, &id_b);
    store.put_key(&sample_key(&id_a)).unwrap();
    store.put_key(&sample_key(&id_b)).unwrap();

    let public_id = format!("AKIA_SHARED_{}", unique_suffix());
    store
        .put_credential(&sample_cred(&id_a, 0, &public_id))
        .unwrap();

    let mut clash = sample_cred(&id_b, 0, &public_id);
    clash.meta.id = format!("cred_clash_{}", unique_suffix());
    let err = store
        .put_credential(&clash)
        .expect_err("minting a credential whose public_id is already in use must fail");
    assert!(
        err.0.contains("public_id"),
        "the error should name the constraint that rejected the mint: {}",
        err.0
    );
    assert!(
        store.list_credentials(&id_b).unwrap().is_empty(),
        "the rejected mint must leave no row behind on the second key"
    );

    let original = store
        .lookup_credential_secret("sigv4", &public_id)
        .unwrap()
        .expect("the first key's credential must survive the rejected clash");
    assert_eq!(original.meta.key_id, id_a);

    hard_reset(&store, &id_a);
    hard_reset(&store, &id_b);
}

/// A unique-enough suffix (pid + nanos) for names that must not collide across concurrently
/// running test binaries against the SAME shared Postgres instance (this repo's own `e2e.rs` uses
/// the identical pattern for its temp work directory).
fn unique_suffix() -> String {
    format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// Split a `postgres://user:pass@host:port/db` URL into its `(userinfo, host:port, db)` parts.
fn split_url(url: &str) -> (&str, &str, &str) {
    let rest = url.split("://").nth(1).expect("url must have a scheme");
    let (userinfo, host_and_db) = rest.rsplit_once('@').expect("url must have userinfo");
    let (host_port, db) = host_and_db
        .split_once('/')
        .expect("url must have a db path");
    (userinfo, host_port, db)
}

fn isolated_db_url(url: &str, db_name: &str) -> String {
    let (userinfo, host_port, _) = split_url(url);
    format!("postgres://{userinfo}@{host_port}/{db_name}")
}

fn role_url(url: &str, db_name: &str, user: &str, pass: &str) -> String {
    let (_, host_port, _) = split_url(url);
    format!("postgres://{user}:{pass}@{host_port}/{db_name}")
}

fn create_fresh_database(url: &str, db_name: &str) {
    let mut maint = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let _ = maint.execute(&format!("DROP DATABASE IF EXISTS {db_name}"), &[]);
    maint
        .execute(&format!("CREATE DATABASE {db_name}"), &[])
        .unwrap();
}

fn drop_database(url: &str, db_name: &str) {
    if let Ok(mut maint) = postgres::Client::connect(url, postgres::NoTls) {
        let _ = maint.execute(
            &format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"),
            &[],
        );
    }
}

/// A disposable database that removes itself on drop, INCLUDING when a panic unwinds partway
/// through the test.
struct TempDb {
    admin_url: String,
    name: String,
    /// Cluster-scoped roles outlive the database they were used in, so they need dropping too, and
    /// `DROP OWNED BY` must run while the database still exists.
    role: Option<String>,
}

impl TempDb {
    fn create(admin_url: &str, prefix: &str) -> Self {
        let name = format!("{prefix}_{}", unique_suffix());
        create_fresh_database(admin_url, &name);
        Self {
            admin_url: admin_url.to_string(),
            name,
            role: None,
        }
    }

    fn url(&self) -> String {
        isolated_db_url(&self.admin_url, &self.name)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn owns_role(&mut self, role: &str) {
        self.role = Some(role.to_string());
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        if let Some(role) = &self.role {
            if let Ok(mut c) = postgres::Client::connect(&self.url(), postgres::NoTls) {
                let _ = c.batch_execute(&format!(
                    "DROP OWNED BY {role}; DROP ROLE IF EXISTS {role};"
                ));
            }
        }
        drop_database(&self.admin_url, &self.name);
    }
}

/// Every store transaction opens with `SET LOCAL lock_timeout` and
/// `idle_in_transaction_session_timeout` (no startup `options`, which poolers refuse): a trigger
/// on `keys` reports what the transaction sees.
#[test]
fn a_store_transaction_runs_with_the_lock_and_idle_timeouts() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_txto");
    let iso_url = tmp.url();
    let store = connect_store_with_retry(&iso_url).expect("fresh open");
    store
        .lock()
        .batch_execute(
            "CREATE FUNCTION probe_timeouts() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
                 RAISE EXCEPTION 'probe lock_timeout=% idle=%',
                     current_setting('lock_timeout'),
                     current_setting('idle_in_transaction_session_timeout');
             END $$;
             CREATE TRIGGER probe BEFORE INSERT ON keys
                 FOR EACH ROW EXECUTE FUNCTION probe_timeouts();",
        )
        .unwrap();
    let e = store.put_key(&sample_key("txto")).unwrap_err().to_string();
    assert!(e.contains("probe lock_timeout=30s idle=1min"), "{e}");
}

/// `migrate_locked`'s undefined-table bootstrap path on a genuinely fresh (separate, disposable)
/// database rather than the shared test database -- which, once any test has run against it, never
/// again presents an undefined `busbar_schema` or a version < `SCHEMA_VERSION`, so this code was
/// structurally unreachable from every other test in this file.
#[test]
fn migrate_bootstraps_fresh_database() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_fresh");
    let iso_url = tmp.url();

    let store =
        connect_store_with_retry(&iso_url).expect("connect must bootstrap a fresh database");

    let mut check = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    let version: i64 = check
        .query_one("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        version, SCHEMA_VERSION,
        "a fresh database must land on the current schema version"
    );

    drop(store);
    drop(check);
}

/// The v13 drops belong to a pre-release v11/v12 database only: on a fresh database or a released
#[test]
fn the_v13_drops_never_touch_a_fresh_or_a_released_database() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_v13keep");
    let iso_url = tmp.url();
    let other_apps =
        "CREATE TABLE store_sessions (session TEXT); CREATE TABLE money_slots (slot TEXT);";
    postgres::Client::connect(&iso_url, postgres::NoTls)
        .unwrap()
        .batch_execute(other_apps)
        .unwrap();
    drop(connect_store_with_retry(&iso_url).expect("fresh open"));
    let kept = |c: &mut postgres::Client| -> bool {
        c.query_one(
            "SELECT to_regclass('store_sessions') IS NOT NULL AND to_regclass('money_slots') IS NOT NULL",
            &[],
        )
        .unwrap()
        .get(0)
    };
    let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    assert!(
        kept(&mut c),
        "a fresh open dropped another application's table"
    );

    c.batch_execute("DELETE FROM busbar_schema; INSERT INTO busbar_schema (version) VALUES (6);")
        .unwrap();
    drop(connect_store_with_retry(&iso_url).expect("released v6 upgrade"));
    assert!(
        kept(&mut c),
        "a released v6 upgrade dropped another application's table"
    );
}

/// An unreleased schema marker cannot authorize deleting tables or operation records.
#[test]
fn an_unreleased_schema_is_refused_without_dropping_tables_or_operation_rows() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_v13");
    let iso_url = tmp.url();
    drop(connect_store_with_retry(&iso_url).expect("fresh open"));
    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(
            "CREATE TABLE money_slots (slot TEXT PRIMARY KEY);
             CREATE TABLE money_slices (slot TEXT);
             CREATE TABLE money_epoch (epoch BIGINT);
             CREATE TABLE store_journal (stream TEXT);
             CREATE TABLE store_sessions (session TEXT);
             INSERT INTO store_ops (op_id, body, answer, recorded_at) VALUES
                 ('\\x01', 'reserve:cells', '', 1),
                 ('\\x02', 'append_batch:x', '', 1),
                 ('\\x03', 'add_usage_batch:x', '', 1),
                 ('\\x04', 'add_metering_batch:x', '', 1),
                 ('\\x05', 'append_plane_record:x', '', 1),
                 ('\\x06', 'abcdef0123', '', 1);
             INSERT INTO store_records (schema_id, key, value) VALUES ('s', '\\x01', '\\x02');
             DELETE FROM busbar_schema;
             INSERT INTO busbar_schema (version) VALUES (12);",
        )
        .unwrap();
    }
    let error = match connect_store_with_retry(&iso_url) {
        Ok(_) => {
            panic!("an unreleased schema marker must not be treated as a production migration")
        }
        Err(error) => error,
    };
    assert!(error.contains("newer"));
    let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    for t in [
        "money_slots",
        "money_slices",
        "money_epoch",
        "store_journal",
        "store_sessions",
    ] {
        let there: bool = c
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&t])
            .unwrap()
            .get(0);
        assert!(there, "refusing an unreleased schema must preserve {t}");
    }
    let kept: Vec<String> = c
        .query("SELECT body FROM store_ops ORDER BY body", &[])
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        kept,
        [
            "abcdef0123",
            "add_metering_batch:x",
            "add_usage_batch:x",
            "append_batch:x",
            "append_plane_record:x",
            "reserve:cells"
        ]
    );
    let records: i64 = c
        .query_one("SELECT COUNT(*) FROM store_records", &[])
        .unwrap()
        .get(0);
    assert_eq!(records, 1);
    let version: i64 = c
        .query_one("SELECT MAX(version) FROM busbar_schema", &[])
        .unwrap()
        .get(0);
    assert_eq!(version, 12);
}

/// A malformed unsigned usage counter, or a NULL where the store reads a value, answers an
/// error (never the stored value), not a panic.
#[test]
fn a_row_that_does_not_decode_is_an_error_not_a_panic() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_decode");
    let iso_url = tmp.url();
    let store = connect_store_with_retry(&iso_url).expect("connect");
    store
        .lock()
        .batch_execute(
            "ALTER TABLE usage_windows ALTER COLUMN requests TYPE TEXT;
             INSERT INTO usage_windows (bucket_id, window_start, requests) VALUES ('b', 1, 'malformed-counter');
             ALTER TABLE keys ALTER COLUMN name DROP NOT NULL;
             INSERT INTO keys (id, generation_hash, name, created_at) VALUES ('k', 'g', NULL, 1);",
        )
        .unwrap();
    let err = store
        .get_usage("b", 1)
        .expect_err("a malformed unsigned counter cannot decode");
    assert_eq!(err.0, "invalid unsigned usage counter");
    assert!(!err.0.contains("malformed-counter"), "{err:?}");
    let err = store.get_key("k").expect_err("NULL into a non-Option");
    assert!(err.0.contains("name"), "{err:?}");
}

/// An op held on the server (here waiting on the `store_revision` row lock) does not hold up a
/// second op: the instance keeps more than one connection.
#[test]
fn a_held_op_does_not_block_a_second_op() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let mut holder = connect_client_with_retry(&url);
    holder
        .batch_execute("BEGIN; UPDATE store_revision SET revision = revision WHERE only_row")
        .unwrap();
    let id = format!("vk_held_{}", unique_suffix());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|s| {
        let held = s.spawn(|| store.put_key(&sample_key(&id)));
        std::thread::sleep(std::time::Duration::from_millis(300));
        s.spawn(|| {
            let _ = tx.send(store.get_key("vk_held_nothing_here"));
        });
        let second = rx.recv_timeout(std::time::Duration::from_secs(5));
        holder.batch_execute("ROLLBACK").unwrap();
        held.join()
            .unwrap()
            .expect("the held put_key finishes once released");
        assert!(
            matches!(second, Ok(Ok(None))),
            "a second op must run while the first is held: {second:?}"
        );
    });
    hard_reset(&store, &id);
}

/// `since = 0` returns every row, and a row at revision 0 (a 1.5.x row the revision bump never
/// touched) always reads as changed.
#[test]
fn revision_zero_rows_are_in_every_delta() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = format!("vk_rev0_{}", unique_suffix());
    hard_reset(&store, &id);
    store
        .lock()
        .batch_execute(&format!(
            "INSERT INTO keys (id, generation_hash, name, created_at, revision)
                 VALUES ('{id}', 'g', 'n', 1, 0);
             INSERT INTO credentials (id, key_id, kind, slot, public_id, secret, secret_form,
                                      created_at, updated_at, revision)
                 VALUES ('c_{id}', '{id}', 'sigv4', 0, 'p_{id}', 's', 'recoverable', 1, 1, 0);"
        ))
        .unwrap();
    for since in [0, 1, u64::MAX / 2] {
        assert!(
            store
                .list_keys_since(since)
                .unwrap()
                .iter()
                .any(|k| k.id == id),
            "key at revision 0, since {since}"
        );
        assert!(
            store
                .list_credentials_since(since)
                .unwrap()
                .iter()
                .any(|c| c.meta.key_id == id),
            "credential at revision 0, since {since}"
        );
    }
    hard_reset(&store, &id);
}

/// Re-minting a revoked slot is a new credential: its `created_at` is the new mint's.
#[test]
fn re_minting_a_revoked_slot_takes_the_new_created_at() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = format!("vk_remint_{}", unique_suffix());
    hard_reset(&store, &id);
    store.put_key(&sample_key(&id)).unwrap();
    let mut first = sample_cred(&id, 0, &format!("AKIA_RM1_{id}"));
    first.meta.created_at = 100;
    store.put_credential(&first).unwrap();
    store.revoke_credential(&first.meta.id, "rotated").unwrap();
    let mut second = sample_cred(&id, 0, &format!("AKIA_RM2_{id}"));
    second.meta.created_at = 500;
    second.meta.updated_at = 500;
    store.put_credential(&second).unwrap();
    let got = store.list_credentials(&id).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].created_at, 500, "not the predecessor's 100");
    hard_reset(&store, &id);
}

/// The redeem sweep (`kind`, `expires_at`) has its index on a fresh database.
#[test]
fn plane_tokens_has_its_sweep_index() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_idx");
    let store = connect_store_with_retry(&tmp.url()).expect("connect");
    let def: Option<String> = store
        .lock()
        .query_opt(
            "SELECT indexdef FROM pg_indexes WHERE indexname = 'plane_tokens_kind_expires'",
            &[],
        )
        .unwrap()
        .map(|r| r.get(0));
    assert!(
        def.is_some_and(|d| d.contains("(kind, expires_at)")),
        "plane_tokens_kind_expires on (kind, expires_at)"
    );
}

/// A credential deleted (a `delete_key` cascade) between the revoke's existence check and its
/// write names no row any more: the unknown-id error, not a story about a concurrent mint.
#[test]
fn revoking_a_credential_deleted_underneath_says_unknown_id() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = format!("vk_revdel_{}", unique_suffix());
    hard_reset(&store, &id);
    store.put_key(&sample_key(&id)).unwrap();
    let cred = sample_cred(&id, 0, &format!("AKIA_RD_{id}"));
    store.put_credential(&cred).unwrap();
    let mut holder = connect_client_with_retry(&url);
    holder
        .batch_execute(&format!(
            "BEGIN; SELECT 1 FROM credentials WHERE id = '{}' FOR UPDATE",
            cred.meta.id
        ))
        .unwrap();
    let err = std::thread::scope(|s| {
        let revoke = s.spawn(|| store.revoke_credential(&cred.meta.id, "r"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let blocked: bool = holder.query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pg_backend_pid() = ANY(pg_blocking_pids(pid)))", &[]
            ).unwrap().get(0);
            if blocked {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "revoke must reach the held row lock"
            );
            std::thread::yield_now();
        }
        holder
            .batch_execute(&format!(
                "DELETE FROM credentials WHERE id = '{}'; COMMIT",
                cred.meta.id
            ))
            .unwrap();
        revoke.join().unwrap().expect_err("the row is gone")
    });
    assert_eq!(
        err.0,
        format!("revoke_credential: unknown id '{}'", cred.meta.id),
        "{err:?}"
    );
    assert!(!err.0.contains("concurrent mint"), "{err:?}");
    hard_reset(&store, &id);
}

/// A rolling-upgrade migration chosen as a deadlock victim (40P01) against a node holding locks
/// in the other order is retried, not failed.
#[test]
fn a_migration_deadlock_victim_is_retried() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_dead");
    let iso_url = tmp.url();
    drop(connect_store_with_retry(&iso_url).expect("fresh open"));
    let mut node = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    node.batch_execute(&format!(
        "DELETE FROM busbar_schema; INSERT INTO busbar_schema(version) VALUES ({FIRST_RELEASED_SCHEMA});
         CREATE SEQUENCE migration_attempt;
         CREATE FUNCTION fail_first_migration() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
           IF nextval('migration_attempt') = 1 THEN
             RAISE EXCEPTION 'injected migration deadlock' USING ERRCODE = '40P01';
           END IF;
           RETURN NEW;
         END $$;
         CREATE TRIGGER migration_deadlock BEFORE INSERT ON busbar_schema
         FOR EACH ROW EXECUTE FUNCTION fail_first_migration();"
    )).unwrap();
    TestStore::open(&iso_url).expect("a server-decided deadlock is retried");
    let attempts: i64 = node
        .query_one("SELECT last_value FROM migration_attempt", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        attempts, 2,
        "the first migration failed and exactly one retry succeeded"
    );
}

/// A database stamped ABOVE this build is refused at open, with the reason: an older binary would
/// ignore newer rules (the epoch fence among them).
#[test]
fn migrate_refuses_a_database_stamped_newer_than_this_build() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_newer");
    let iso_url = tmp.url();
    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(&format!(
            "CREATE TABLE busbar_schema (version BIGINT PRIMARY KEY);
             INSERT INTO busbar_schema (version) VALUES ({});",
            SCHEMA_VERSION + 1
        ))
        .unwrap();
    }
    let err = TestStore::open(&iso_url)
        .err()
        .expect("a newer schema is refused");

    assert!(
        err.ends_with(&format!(
            "postgres store: database schema v{} is newer than this build (v{SCHEMA_VERSION}); \
             refusing to open",
            SCHEMA_VERSION + 1
        )),
        "{err}"
    );
}

/// `migrate`/`migrate_locked` must never silently succeed against a role that lacks real read
/// access to its own bookkeeping table -- built with a role granted CREATE/INSERT but deliberately
/// NEVER SELECT on `busbar_schema`, so a genuine SQLSTATE 42501 (insufficient_privilege) surfaces
/// somewhere in `migrate_locked`'s statement sequence (Postgres requires SELECT on the target table
/// for `INSERT ... ON CONFLICT`, even `DO NOTHING`, confirmed empirically against this exact
/// fixture -- not just for the version-probe `SELECT` itself), and `connect()` must propagate that
/// as an `Err`, never proceed as if the database were merely fresh.
#[test]
fn migrate_propagates_a_non_undefined_table_error_and_never_silently_succeeds() {
    let Some(url) = live_url() else { return };
    let mut tmp = TempDb::create(&url, "spg_perm");
    let iso_url = tmp.url();
    let role = format!("spg_limited_{}", unique_suffix());

    tmp.owns_role(&role);

    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD 'limited';
             GRANT CREATE, USAGE ON SCHEMA public TO {role};
             CREATE TABLE busbar_schema (version BIGINT PRIMARY KEY);
             GRANT INSERT ON busbar_schema TO {role};"
        ))
        .unwrap();
    }

    let limited_url = role_url(&url, tmp.name(), &role, "limited");

    {
        let mut raw = postgres::Client::connect(&limited_url, postgres::NoTls).unwrap();
        let probe_err = raw
            .query_opt("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[])
            .unwrap_err();
        assert_eq!(
            probe_err.code(),
            Some(&postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
            "test setup sanity: the probe query must fail with insufficient_privilege, not \
             undefined_table, for this test to mean anything: {probe_err}"
        );
        assert_ne!(
            probe_err.code(),
            Some(&postgres::error::SqlState::UNDEFINED_TABLE)
        );
    }

    let err = match TestStore::open(&limited_url) {
        Ok(_) => panic!(
            "migrate must never silently succeed against a role that can't actually read its own \
             bookkeeping table"
        ),
        Err(e) => e,
    };
    assert!(
        err.contains("42501") || err.to_lowercase().contains("permission denied"),
        "the refusal must carry the insufficient_privilege (42501) denial, got: {err}"
    );
}

/// TWO NODES BOOTING AGAINST ONE FRESH DATABASE. Every node runs `migrate()` on connect, and a fleet
/// restarted together does it at the same instant; `pg_advisory_lock` is what serialises them.
#[test]
fn two_nodes_opening_a_fresh_database_together_both_migrate_cleanly() {
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_race");
    let iso_url = tmp.url();

    let start = std::sync::Arc::new(std::sync::Barrier::new(2));
    let nodes: Vec<_> = (0..2)
        .map(|_| {
            let (start, iso_url) = (start.clone(), iso_url.clone());
            std::thread::spawn(move || {
                start.wait();
                TestStore::open(&iso_url)
            })
        })
        .collect();
    let opened: Vec<_> = nodes.into_iter().map(|n| n.join().unwrap()).collect();
    for (i, r) in opened.iter().enumerate() {
        assert!(
            r.is_ok(),
            "node {i} failed to open a fresh database while another migrated it: {:?}",
            r.as_ref().err()
        );
    }

    let store = opened.into_iter().next().unwrap().unwrap();
    for table in [
        "keys",
        "credentials",
        "usage_windows",
        "usage_ledger",
        "usage_ledger_units",
        "usage_metering",
        "usage_metering_units",
        "audit_log",
        "denylist",
        "store_revision",
        "plane_records",
        "plane_chain",
        "plane_tokens",
        "store_ops",
        "store_records",
    ] {
        let there: bool = store
            .lock()
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table])
            .unwrap()
            .get(0);
        assert!(there, "{table} must exist after the race");
    }
    let stamped: i64 = store
        .lock()
        .query_one(
            "SELECT COUNT(*) FROM busbar_schema WHERE version=$1",
            &[&SCHEMA_VERSION],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        stamped, 1,
        "the schema version must be stamped exactly once"
    );
}

/// The `Store` contract conformance suite — THIS crate's own copy, at `src/tests/store_conformance.rs`.
#[path = "tests/store_conformance.rs"]
mod store_conformance;

/// The cross-backend `Store` conformance checks, answered by this backend — EVERY check the suite
/// offers: the key/credential/audit rulings the fleet used to settle differently per backend, and
/// the 1.6.0 plane-record battery.
mod conformance {
    use super::plane_records::lock_plane_purge;
    use super::store_conformance as conf;
    use super::{clamp, connect_store_with_retry, live_url, TestStore};

    /// A per-process, PER-CHECK namespace. Short enough for every id column in the schema.
    fn ns(check: &str) -> String {
        format!("vk_c{}{}", std::process::id(), check)
    }

    /// Delete every row this suite is about to write, so a rerun (or a crashed prior run that left
    /// rows behind) starts from the same state as a first run.
    fn reset(store: &TestStore, ns: &str, seq: u64) {
        let mut client = store.lock();
        for id in conf::key_ids(ns) {
            let _ = client.execute("DELETE FROM credentials WHERE key_id=$1", &[&id]);
            let _ = client.execute("DELETE FROM keys WHERE id=$1", &[&id]);
        }
        for id in conf::credential_ids(ns) {
            let _ = client.execute("DELETE FROM credentials WHERE id=$1", &[&id]);
        }
        let _ = client.execute("DELETE FROM audit_log WHERE seq=$1", &[&clamp(seq)]);
        let prefix = format!("{ns}_");
        let n = prefix.chars().count() as i32;
        let _ = client.execute(
            "DELETE FROM plane_records WHERE left(id, $2) = $1",
            &[&prefix, &n],
        );
        let _ = client.execute(
            "DELETE FROM plane_chain WHERE left(parent, $2) = $1",
            &[&prefix, &n],
        );
        let _ = client.execute(
            "DELETE FROM plane_tokens WHERE left(token, $2) = $1",
            &[&prefix, &n],
        );
    }

    fn setup(check: &str, seq: u64) -> Option<(TestStore, String)> {
        let url = live_url()?;
        let store = connect_store_with_retry(&url).expect("connect");
        let ns = ns(check);
        reset(&store, &ns, seq);
        Some((store, ns))
    }

    #[test]
    fn put_key_does_not_resurrect_a_tombstone() {
        let Some((store, ns)) = setup("put", 0) else {
            return;
        };
        conf::assert_put_key_does_not_resurrect_a_tombstone(&*store, &ns);
    }

    #[test]
    fn delete_key_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("del", 0) else {
            return;
        };
        conf::assert_delete_key_unknown_id_is_an_error(&*store, &ns);
    }

    #[test]
    fn revoke_credential_unknown_id_is_an_error() {
        let Some((store, ns)) = setup("rev", 0) else {
            return;
        };
        conf::assert_revoke_credential_unknown_id_is_an_error(&*store, &ns);
    }

    #[test]
    fn put_credential_requires_a_live_key() {
        let Some((store, ns)) = setup("live", 0) else {
            return;
        };
        conf::assert_put_credential_requires_a_live_key(&*store, &ns);
    }

    #[test]
    fn put_key_with_credential_is_atomic() {
        let Some((store, ns)) = setup("atom", 0) else {
            return;
        };
        conf::assert_put_key_with_credential_is_atomic(&*store, &ns);
    }

    #[test]
    fn plane_task_upsert_get_list() {
        let Some((store, ns)) = setup("ptask", 0) else {
            return;
        };
        conf::assert_plane_task_upsert_get_list(&*store, &ns);
    }

    #[test]
    fn plane_event_chain_is_ordered_by_seq() {
        let Some((store, ns)) = setup("pchain", 0) else {
            return;
        };
        conf::assert_plane_event_chain_is_ordered_by_seq(&*store, &ns);
    }

    #[test]
    fn plane_call_parents_enumerated() {
        let Some((store, ns)) = setup("pprin", 0) else {
            return;
        };
        conf::assert_plane_call_parents_enumerated(&*store, &ns);
    }

    #[test]
    fn plane_demotion_upsert_list_delete() {
        let Some((store, ns)) = setup("pdem", 0) else {
            return;
        };
        conf::assert_plane_demotion_upsert_list_delete(&*store, &ns);
    }

    #[test]
    fn plane_purge_honours_the_cutoff() {
        let Some((store, ns)) = setup("pcut", 0) else {
            return;
        };

        let _guard = lock_plane_purge();
        conf::assert_plane_purge_honours_the_cutoff(&*store, &ns);
    }

    #[test]
    fn plane_purge_task_keeps_active_rows() {
        let Some((store, ns)) = setup("pkeep", 0) else {
            return;
        };
        let _guard = lock_plane_purge();
        conf::assert_plane_purge_task_keeps_active_rows(&*store, &ns);
    }

    #[test]
    fn plane_token_is_single_use() {
        let Some((store, ns)) = setup("ptok", 0) else {
            return;
        };
        conf::assert_plane_token_is_single_use(&*store, &ns);
    }
}

#[path = "tests/plane_records.rs"]
mod plane_records;

#[path = "tests/v160_shapes.rs"]
mod v160_shapes;

#[path = "tests/credential_rules.rs"]
mod credential_rules;

#[path = "tests/v3_slots.rs"]
mod v3_slots;

#[path = "tests/tls.rs"]
mod tls;

#[test]
fn usage_cleanup_keeps_boundaries_billing_and_rolls_back_every_usage_table() {
    use busbar_contract::store_calls::StoreCalls;
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_usage_cleanup");
    let store = TestStore::open(&tmp.url()).expect("isolated store opens");
    store
        .lock()
        .batch_execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
         SELECT bucket, stamp, 3, 2
         FROM unnest(ARRAY['first','second']) AS bucket
         CROSS JOIN unnest(ARRAY[0,9,10,11,9223372036854775807]::bigint[]) AS stamp;
         INSERT INTO usage_ledger (bucket_id,window_start,model,tokens_input)
         SELECT bucket_id,window_start,model,5 FROM usage_windows
         CROSS JOIN unnest(ARRAY['alpha','beta']) AS model;
         INSERT INTO usage_ledger_units (bucket_id,window_start,model,unit,count)
         SELECT bucket_id,window_start,model,'audio_seconds',7 FROM usage_ledger;
         INSERT INTO usage_metering (key_id,bucket,model,provider,requests)
         VALUES ('billed',9,'alpha','provider',17);
         INSERT INTO usage_metering_units (key_id,bucket,model,provider,unit,count)
         VALUES ('billed',9,'alpha','provider','audio_seconds',19);",
        )
        .unwrap();
    let counts = || {
        let row = store
            .lock()
            .query_one(
                "SELECT (SELECT count(*) FROM usage_windows),
                    (SELECT count(*) FROM usage_ledger),
                    (SELECT count(*) FROM usage_ledger_units)",
                &[],
            )
            .unwrap();
        [
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2),
        ]
    };
    let purge = |before| harness::block_on(StoreCalls::purge_usage_before(&*store, before));
    assert_eq!(purge(0).unwrap(), 0);
    assert_eq!(counts(), [10, 20, 20]);
    assert_eq!(
        purge(10).unwrap(),
        2,
        "count windows, never models or open units"
    );
    assert_eq!(counts(), [8, 16, 16]);
    assert_eq!(purge(10).unwrap(), 0);
    let at_cutoff = store.get_usage("first", 10).unwrap();
    assert_eq!(at_cutoff.requests, 3);
    assert_eq!(at_cutoff.models.len(), 2);
    assert!(at_cutoff
        .models
        .iter()
        .all(|model| model.usage_units.get("audio_seconds") == Some(&7)));
    store
        .lock()
        .batch_execute(
            "CREATE FUNCTION reject_usage_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN RAISE EXCEPTION 'usage cleanup rollback fixture'; END $$;
         CREATE TRIGGER reject_usage_cleanup BEFORE DELETE ON usage_ledger_units
         FOR EACH ROW EXECUTE FUNCTION reject_usage_cleanup();",
        )
        .unwrap();
    let refusal = purge(11).unwrap_err().to_string();
    assert!(
        refusal.contains("usage cleanup rollback fixture"),
        "{refusal}"
    );
    assert_eq!(
        store.get_usage("first", 10).unwrap(),
        at_cutoff,
        "a later delete failure rolls the whole usage ledger back"
    );
    assert_eq!(counts(), [8, 16, 16]);
    store
        .lock()
        .batch_execute("DROP TRIGGER reject_usage_cleanup ON usage_ledger_units")
        .unwrap();
    assert_eq!(
        purge(i64::MAX as u64).unwrap(),
        4,
        "the exact cutoff is retained"
    );
    assert_eq!(counts(), [4, 8, 8]);
    assert_eq!(
        purge(i64::MAX as u64 + 1).unwrap(),
        2,
        "an unsigned cutoff beyond the SQL maximum includes the maximum stored window"
    );
    assert_eq!(purge(u64::MAX).unwrap(), 0);
    assert_eq!(counts(), [2, 4, 4], "window zero is permanent");
    let row = store
        .lock()
        .query_one(
            "SELECT (SELECT requests FROM usage_metering WHERE key_id='billed'),
                (SELECT count FROM usage_metering_units WHERE key_id='billed')",
            &[],
        )
        .unwrap();
    assert_eq!(
        (row.get::<_, i64>(0), row.get::<_, i64>(1)),
        (17, 19),
        "billing history and its open units are untouched"
    );
    let reopened = TestStore::open(&tmp.url()).unwrap();
    assert_eq!(reopened.get_usage("first", 0).unwrap().requests, 3);
    assert_eq!(
        reopened
            .get_usage("first", i64::MAX as u64)
            .unwrap()
            .requests,
        0
    );
}

#[test]
fn usage_cleanup_waits_for_a_usage_writer_and_removes_its_complete_old_window() {
    use busbar_contract::store_calls::StoreCalls;
    let Some(url) = live_url() else { return };
    let tmp = TempDb::create(&url, "spg_usage_writer");
    let store = TestStore::open(&tmp.url()).unwrap();
    let mut writer = connect_client_with_retry(&tmp.url());
    writer
        .batch_execute(
            "BEGIN;
         INSERT INTO usage_windows (bucket_id,window_start,requests) VALUES ('writer',9,3);",
        )
        .unwrap();
    let worker_url = tmp.url();
    let (answer, result) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let cleanup = TestStore::open(&worker_url).unwrap();
        let removed = harness::block_on(StoreCalls::purge_usage_before(&*cleanup, 10));
        answer.send(removed).unwrap();
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut premature = None;
    let waited_on_writer = loop {
        if let Ok(answer) = result.try_recv() {
            premature = Some(answer);
            break false;
        }
        let waiting: i64 = store
            .lock()
            .query_one(
                "SELECT count(*) FROM pg_locks
             WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database())
               AND relation='usage_windows'::regclass
               AND mode='ShareRowExclusiveLock' AND NOT granted",
                &[],
            )
            .unwrap()
            .get(0);
        if waiting != 0 {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };

    let write = writer.batch_execute(
        "INSERT INTO usage_ledger (bucket_id,window_start,model,tokens_input)
         VALUES ('writer',9,'alpha',5);
         INSERT INTO usage_ledger_units (bucket_id,window_start,model,unit,count)
         VALUES ('writer',9,'alpha','audio_seconds',7);
         COMMIT;",
    );
    if write.is_err() {
        writer.batch_execute("ROLLBACK").unwrap();
    }
    let removed = premature.unwrap_or_else(|| {
        result
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("cleanup finishes after the writer commits")
    });
    worker.join().unwrap();
    write.expect("the usage writer and cleanup must both finish without a lock-order deadlock");
    assert!(
        waited_on_writer,
        "cleanup must synchronize with the in-flight usage transaction"
    );
    assert_eq!(removed.unwrap(), 1);
    let row = store
        .lock()
        .query_one(
            "SELECT (SELECT count(*) FROM usage_windows),
                (SELECT count(*) FROM usage_ledger),
                (SELECT count(*) FROM usage_ledger_units)",
            &[],
        )
        .unwrap();
    assert_eq!(
        [
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ],
        [0, 0, 0],
        "no child rows from the committed old window survive"
    );
}

#[test]
fn legacy_revoked_secrets_are_scrubbed_on_upgrade_and_on_repeated_revoke() {
    let Some(url) = live_url() else { return };
    for upgrade in [false, true] {
        let tmp = TempDb::create(&url, "spg_revoked_scrub");
        let store = TestStore::open(&tmp.url()).unwrap();
        store.put_key(&sample_key("owner")).unwrap();
        let credential = sample_cred("owner", 0, "LEGACY_REVOKED");
        store.put_credential(&credential).unwrap();

        store
            .lock()
            .execute(
                "UPDATE credentials SET revoked_at=123, revoke_reason='original', updated_at=123
             WHERE id=$1",
                &[&credential.meta.id],
            )
            .unwrap();
        let before = store
            .list_credentials_since(0)
            .unwrap()
            .into_iter()
            .find(|c| c.meta.id == credential.meta.id)
            .unwrap();
        assert!(!before.secret.is_empty());
        let owner = store.get_key("owner").unwrap();
        if upgrade {
            let mut conn = store.lock();
            conn.execute("DELETE FROM busbar_schema", &[]).unwrap();
            conn.execute(
                "INSERT INTO busbar_schema(version) VALUES ($1)",
                &[&FIRST_RELEASED_SCHEMA],
            )
            .unwrap();
        }
        drop(store);
        let store = TestStore::open(&tmp.url()).unwrap();
        if !upgrade {
            store
                .revoke_credential(&credential.meta.id, "replacement reason")
                .unwrap();
        }
        let after = store
            .list_credentials_since(0)
            .unwrap()
            .into_iter()
            .find(|c| c.meta.id == credential.meta.id)
            .unwrap();
        assert!(
            after.secret.is_empty(),
            "historically revoked credentials must not retain secret material"
        );
        assert_eq!(after.meta.secret_form, SecretForm::None);
        assert!(
            after.meta.revision > before.meta.revision,
            "scrubbing is observable in hydration deltas"
        );
        let mut expected = before.meta;
        expected.secret_form = SecretForm::None;
        expected.revision = after.meta.revision;
        assert_eq!(
            after.meta, expected,
            "preserve original revocation and identity metadata"
        );
        assert_eq!(store.get_key("owner").unwrap(), owner);
        assert!(store
            .lock()
            .query_one(
                "SELECT secret IS NULL FROM credentials WHERE id=$1",
                &[&credential.meta.id]
            )
            .unwrap()
            .get::<_, bool>(0));
        store
            .revoke_credential(&credential.meta.id, "another reason")
            .unwrap();
        let again = store
            .list_credentials_since(0)
            .unwrap()
            .into_iter()
            .find(|c| c.meta.id == credential.meta.id)
            .unwrap();
        assert_eq!(
            again, after,
            "an already-scrubbed revoke remains a true no-op"
        );
    }
}

#[path = "tests/metering_attribution.rs"]
mod metering_attribution;

#[path = "tests/token_clock.rs"]
mod token_clock;

#[path = "../tests-support/postgres_io.rs"]
mod postgres_io;

#[path = "../tests-support/postgres_clock.rs"]
mod postgres_clock;

#[path = "tests/kept_product.rs"]
mod kept_product;

#[test]
fn corrupt_key_labels_are_refused() {
    for invalid in ["{", "[]", "null", "{\"key\":1}"] {
        assert!(labels_from_storage(invalid).is_err());
    }
    assert!(labels_from_storage("{}").unwrap().is_empty());
}

#[test]
fn server_diagnostics_escape_controls_and_bound_output() {
    let error = pgwire::Error::server("22000", &format!("bad\n\u{1b}{}", "x".repeat(5000)));
    let rendered = render_pg_error(&error);
    assert!(rendered.starts_with("22000:"));
    assert!(!rendered.chars().any(char::is_control));
    assert!(rendered.ends_with("[truncated]"));
    assert!(rendered.len() < 4200);
}
