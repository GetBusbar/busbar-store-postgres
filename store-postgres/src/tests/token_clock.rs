// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
const TOKEN_KIND: &str = "clock-authority-fixture";
const WINNER_TOKEN: &str = "winner";
const OTHER_TOKEN: &str = "other";
const EXPIRED_TOKEN: &str = "expired";
const SLOW_CALLER: u64 = u64::MIN;
const FAST_CALLER: u64 = u64::MAX;
const RETAINED_EXPIRY: u64 = i64::MAX as u64;
const EXPIRED_AT_EPOCH: u64 = u64::MIN;
fn token_expiry(store: &TestStore, kind: &str, token: &str) -> Option<u64> {
    store
        .lock()
        .query_opt(
            "SELECT expires_at FROM plane_tokens WHERE kind=$1 AND token=$2",
            &[&kind, &token],
        )
        .unwrap()
        .map(|r| r.get::<_, i64>(0) as u64)
}

#[test]
fn caller_skew_never_reopens_or_rewrites_a_live_redemption() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_token_clock");
    let store = TestStore::open(&db.url()).unwrap();
    assert!(store
        .redeem_plane_token(TOKEN_KIND, WINNER_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
    assert!(store
        .redeem_plane_token(TOKEN_KIND, OTHER_TOKEN, u64::MAX, FAST_CALLER)
        .unwrap());
    for offered_expiry in [RETAINED_EXPIRY - 1, u64::MAX] {
        assert!(!store
            .redeem_plane_token(TOKEN_KIND, WINNER_TOKEN, offered_expiry, FAST_CALLER)
            .unwrap());
        assert_eq!(
            token_expiry(&store, TOKEN_KIND, WINNER_TOKEN),
            Some(RETAINED_EXPIRY)
        );
    }
    assert!(!store
        .redeem_plane_token(TOKEN_KIND, WINNER_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
}

#[test]
fn expired_presentation_is_false_without_creating_or_sweeping_rows() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_token_clock");
    let store = TestStore::open(&db.url()).unwrap();
    assert!(store
        .redeem_plane_token(TOKEN_KIND, WINNER_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
    const EXPIRED_WITNESS: &str = "expired-witness";
    store
        .lock()
        .execute(
            "INSERT INTO plane_tokens(kind,token,expires_at) VALUES ($1,$2,$3)",
            &[&TOKEN_KIND, &EXPIRED_WITNESS, &(EXPIRED_AT_EPOCH as i64)],
        )
        .unwrap();
    assert!(!store
        .redeem_plane_token(TOKEN_KIND, EXPIRED_TOKEN, EXPIRED_AT_EPOCH, SLOW_CALLER)
        .unwrap());
    assert_eq!(token_expiry(&store, TOKEN_KIND, EXPIRED_TOKEN), None);
    assert_eq!(
        token_expiry(&store, TOKEN_KIND, EXPIRED_WITNESS),
        Some(EXPIRED_AT_EPOCH)
    );
    assert_eq!(
        token_expiry(&store, TOKEN_KIND, WINNER_TOKEN),
        Some(RETAINED_EXPIRY)
    );
}

pub(super) fn assert_strict_boundary(kind: &str) {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, Retention};
    const TICKET_KIND: &str = "ticket";
    const RECEIPT_BYTES: &[u8] = b"boundary-receipt";
    const DATABASE_SECOND: u64 = 1_900_000_000;
    const TEST_CLOCK_SETTING: &str = "busbar.test_database_clock";
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_token_clock");
    let mut raw = connect_client_with_retry(&db.url());
    raw.batch_execute(&format!(
        "ALTER DATABASE {} SET {TEST_CLOCK_SETTING} = '{DATABASE_SECOND}'",
        db.name()
    ))
    .unwrap();
    let store = TestStore::open(&db.url()).unwrap();
    let receipt = PlaneRecord {
        kind: TICKET_KIND.into(),
        id: WINNER_TOKEN.into(),
        parent: None,
        seq: 0,
        ts: DATABASE_SECOND,
        disposition: PlaneDisposition::Terminal,
        body: RECEIPT_BYTES.to_vec(),
    };
    store.upsert_plane_record(receipt.view()).unwrap();
    assert!(store
        .plane_token_live(TICKET_KIND, WINNER_TOKEN, DATABASE_SECOND, FAST_CALLER)
        .unwrap());
    assert!(store
        .plane_token_live(TICKET_KIND, WINNER_TOKEN, DATABASE_SECOND, FAST_CALLER)
        .unwrap());
    assert!(store
        .redeem_plane_token(kind, WINNER_TOKEN, DATABASE_SECOND, FAST_CALLER)
        .unwrap());
    assert!(store
        .redeem_plane_token(kind, OTHER_TOKEN, RETAINED_EXPIRY, FAST_CALLER)
        .unwrap());
    assert!(!store
        .redeem_plane_token(kind, WINNER_TOKEN, DATABASE_SECOND, SLOW_CALLER)
        .unwrap());
    assert_eq!(
        token_expiry(&store, kind, WINNER_TOKEN),
        Some(DATABASE_SECOND)
    );
    assert_eq!(
        store
            .purge_plane_records(TICKET_KIND, FAST_CALLER, Retention::Age)
            .unwrap(),
        0
    );
    assert_eq!(
        store.get_plane_record(TICKET_KIND, WINNER_TOKEN).unwrap(),
        Some(RECEIPT_BYTES.to_vec())
    );
    drop(store);
    let after_expiry = DATABASE_SECOND + 1;
    raw.batch_execute(&format!(
        "ALTER DATABASE {} SET {TEST_CLOCK_SETTING} = '{after_expiry}'",
        db.name()
    ))
    .unwrap();
    let reopened = TestStore::open(&db.url()).unwrap();
    assert!(!reopened
        .plane_token_live(TICKET_KIND, WINNER_TOKEN, DATABASE_SECOND, SLOW_CALLER)
        .unwrap());
    assert!(!reopened
        .redeem_plane_token(kind, WINNER_TOKEN, DATABASE_SECOND, SLOW_CALLER)
        .unwrap());
    assert_eq!(
        reopened
            .purge_plane_records(TICKET_KIND, FAST_CALLER, Retention::Age)
            .unwrap(),
        1
    );
    assert!(reopened
        .redeem_plane_token(kind, WINNER_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
    assert!(!reopened
        .redeem_plane_token(kind, WINNER_TOKEN, RETAINED_EXPIRY, FAST_CALLER)
        .unwrap());
    drop(reopened);

    const INVALID_CLOCK: &str = "invalid-clock-fixture";
    raw.batch_execute(&format!(
        "ALTER DATABASE {} SET {TEST_CLOCK_SETTING} = '{INVALID_CLOCK}'",
        db.name()
    ))
    .unwrap();
    let broken = TestStore::open(&db.url()).unwrap();
    assert!(broken
        .redeem_plane_token(kind, EXPIRED_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .is_err());
    assert!(broken
        .plane_token_live(TICKET_KIND, WINNER_TOKEN, DATABASE_SECOND, SLOW_CALLER)
        .is_err());
    assert!(broken
        .purge_plane_records(TICKET_KIND, FAST_CALLER, Retention::Age)
        .is_err());
    assert_eq!(token_expiry(&broken, kind, EXPIRED_TOKEN), None);
    assert_eq!(
        token_expiry(&broken, kind, WINNER_TOKEN),
        Some(RETAINED_EXPIRY)
    );
}

#[test]
fn database_clock_boundary_is_strict() {
    assert_strict_boundary(TOKEN_KIND);
}

#[test]
fn ticket_retention_caps_fast_callers_and_preserves_other_kinds() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, Retention};
    const TICKET_KIND: &str = "ticket";
    const ORDINARY_KIND: &str = "ordinary-clock-control";
    const LIVE_ID: &str = "live-receipt";
    const OLD_ID: &str = "old-receipt";
    const RECEIPT_BYTES: &[u8] = b"persisted-receipt";
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_ticket_clock");
    let store = TestStore::open(&db.url()).unwrap();
    let record = |kind: &str, id: &str, expiry| PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: None,
        seq: 0,
        ts: expiry,
        disposition: PlaneDisposition::Active,
        body: RECEIPT_BYTES.to_vec(),
    };
    store
        .upsert_plane_record(record(TICKET_KIND, LIVE_ID, RETAINED_EXPIRY).view())
        .unwrap();
    store
        .upsert_plane_record(record(TICKET_KIND, OLD_ID, EXPIRED_AT_EPOCH).view())
        .unwrap();
    store
        .upsert_plane_record(record(ORDINARY_KIND, LIVE_ID, RETAINED_EXPIRY).view())
        .unwrap();
    assert_eq!(
        store
            .purge_plane_records(TICKET_KIND, FAST_CALLER, Retention::Age)
            .unwrap(),
        1
    );
    assert_eq!(
        store.get_plane_record(TICKET_KIND, LIVE_ID).unwrap(),
        Some(RECEIPT_BYTES.to_vec())
    );
    assert_eq!(store.get_plane_record(TICKET_KIND, OLD_ID).unwrap(), None);
    assert_eq!(
        store
            .purge_plane_records(ORDINARY_KIND, FAST_CALLER, Retention::Age)
            .unwrap(),
        1
    );
    assert_eq!(
        store.get_plane_record(ORDINARY_KIND, LIVE_ID).unwrap(),
        None
    );

    store
        .upsert_plane_record(record(TICKET_KIND, LIVE_ID, EXPIRED_AT_EPOCH).view())
        .unwrap();
    assert_eq!(
        store
            .purge_plane_records(TICKET_KIND, SLOW_CALLER, Retention::Age)
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .purge_plane_records(TICKET_KIND, FAST_CALLER, Retention::Age)
            .unwrap(),
        1
    );
}

#[test]
fn ticket_peek_checks_store_deadline_without_spending() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord};
    const TICKET_KIND: &str = "ticket";
    const ORDINARY_KIND: &str = "ordinary-peek-control";
    const MISSING_TOKEN: &str = "missing";
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_ticket_peek");
    let store = TestStore::open(&db.url()).unwrap();
    let record = |kind: &str, id: &str, deadline, disposition| PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: None,
        seq: 0,
        ts: deadline,
        disposition,
        body: id.as_bytes().to_vec(),
    };
    store
        .upsert_plane_record(
            record(
                TICKET_KIND,
                WINNER_TOKEN,
                RETAINED_EXPIRY,
                PlaneDisposition::Terminal,
            )
            .view(),
        )
        .unwrap();
    for _ in 0..2 {
        assert!(store
            .plane_token_live(TICKET_KIND, WINNER_TOKEN, RETAINED_EXPIRY, FAST_CALLER)
            .unwrap());
        assert_eq!(token_expiry(&store, TICKET_KIND, WINNER_TOKEN), None);
    }
    for wrong_deadline in [RETAINED_EXPIRY - 1, u64::MAX] {
        assert!(!store
            .plane_token_live(TICKET_KIND, WINNER_TOKEN, wrong_deadline, SLOW_CALLER)
            .unwrap());
    }
    assert!(!store
        .plane_token_live(TICKET_KIND, MISSING_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
    store
        .upsert_plane_record(
            record(
                TICKET_KIND,
                EXPIRED_TOKEN,
                EXPIRED_AT_EPOCH,
                PlaneDisposition::Terminal,
            )
            .view(),
        )
        .unwrap();
    assert!(!store
        .plane_token_live(TICKET_KIND, EXPIRED_TOKEN, EXPIRED_AT_EPOCH, SLOW_CALLER)
        .unwrap());
    store
        .upsert_plane_record(
            record(
                TICKET_KIND,
                OTHER_TOKEN,
                RETAINED_EXPIRY,
                PlaneDisposition::Active,
            )
            .view(),
        )
        .unwrap();
    assert!(!store
        .plane_token_live(TICKET_KIND, OTHER_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
    store
        .upsert_plane_record(
            record(
                ORDINARY_KIND,
                OTHER_TOKEN,
                RETAINED_EXPIRY,
                PlaneDisposition::Active,
            )
            .view(),
        )
        .unwrap();
    assert!(store
        .plane_token_live(ORDINARY_KIND, OTHER_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
    assert!(!store
        .plane_token_live(ORDINARY_KIND, OTHER_TOKEN, RETAINED_EXPIRY, FAST_CALLER)
        .unwrap());
    assert!(store
        .redeem_plane_token(TICKET_KIND, WINNER_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
    assert!(!store
        .redeem_plane_token(TICKET_KIND, WINNER_TOKEN, RETAINED_EXPIRY, FAST_CALLER)
        .unwrap());
    store
        .delete_plane_record(TICKET_KIND, WINNER_TOKEN)
        .unwrap();
    assert!(!store
        .plane_token_live(TICKET_KIND, WINNER_TOKEN, RETAINED_EXPIRY, SLOW_CALLER)
        .unwrap());
}
