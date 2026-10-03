// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kind-tagged PLANE-RECORD verbs (busbar 1.6.0) against a live Postgres.
//!
//! These are the 1.5.x typed task / MCP-call / demotion / spent-approval tests, carried onto the
//! neutral surface that replaced those methods. The property under test is never "the write
//! returned Ok": every one of the eight verbs DEFAULTS to accept-and-keep-nothing (and the two token
//! verbs to a refusal), so a write's return value is worthless as evidence of durability. The only
//! honest way to know a deployment has durable plane state is to READ IT BACK, and to know it
//! survives a deploy, to read it back on a NEW CONNECTION after the writing one is gone.
//!
//! The bodies are serialized stand-in rows carrying the field names the engine's rows use. This
//! store never decodes a body — it returns it verbatim — so the tests decode it themselves.

use super::*;

/// Timestamps are BANDED. `purge_plane_records_before` is GLOBAL per kind and cannot be scoped to a
/// task or a principal, so against the SHARED live database a purge test's cutoff would delete every
/// other test's old rows if the timestamps overlapped. Everything below the top of this band belongs
/// to the purge tests (this file's and the conformance suite's, which sweep at 100_000); every other
/// test writes ABOVE it.
const PURGE_BAND_TOP: u64 = 1_000_100_000;
const LIVE_TS: u64 = 2_000_000_000;

/// Every test that SWEEPS a kind holds this, including the conformance suite's two purge checks:
/// a sweep reaches every row of the kind below its cutoff, so two sweeping tests running at once
/// would each count (and delete) the other's rows. The rest of the suite stays parallel.
static PLANE_PURGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(super) fn lock_plane_purge() -> std::sync::MutexGuard<'static, ()> {
    PLANE_PURGE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn body(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("serialize a stand-in body")
}

fn decode(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).expect("a body this suite wrote decodes")
}

fn task(id: &str, state: &str, ts: u64, disposition: PlaneDisposition) -> PlaneRecord {
    PlaneRecord {
        kind: "task".into(),
        id: id.into(),
        parent: None,
        seq: 0,
        ts,
        disposition,
        body: body(serde_json::json!({
            "task_id": id,
            "context_id": format!("ctx-{id}"),
            "principal": "vk_a",
            "direction": "inbound",
            "state": state,
            "agent_id": "planner",
            "artifact_cursor": 4,
            "push_callback": "https://caller.example/push",
            "created_at": LIVE_TS,
            "updated_at": ts,
        })),
    }
}

fn event(task_id: &str, seq: u64, kind: &str, prev_hash: &str, hash: &str) -> PlaneRecord {
    PlaneRecord {
        kind: "task_event".into(),
        id: task_id.into(),
        parent: Some(task_id.into()),
        seq,
        ts: LIVE_TS + seq,
        disposition: PlaneDisposition::Active,
        body: body(serde_json::json!({
            "seq": seq,
            "prev_hash": prev_hash,
            "hash": hash,
            "content": { "kind": kind, "request_id": format!("req-{seq}") },
        })),
    }
}

fn call(principal: &str, seq: u64, ts: u64, prev_hash: &str, hash: &str) -> PlaneRecord {
    PlaneRecord {
        kind: "call".into(),
        id: principal.into(),
        parent: Some(principal.into()),
        seq,
        ts,
        disposition: PlaneDisposition::Active,
        body: body(serde_json::json!({
            "seq": seq,
            "prev_hash": prev_hash,
            "hash": hash,
            "content": {
                "server": "srv",
                "tool": "srv_read_file",
                "tool_digest": format!("sha256:tool{seq}"),
                "pin_generation": 3,
                "request_id": format!("req-{seq}"),
            },
        })),
    }
}

fn demotion(server: &str, reason: &str, recorded_at: u64) -> PlaneRecord {
    PlaneRecord {
        kind: "demotion".into(),
        id: server.into(),
        parent: None,
        seq: 0,
        ts: recorded_at,
        disposition: PlaneDisposition::Active,
        body: body(serde_json::json!({
            "server": server, "reason": reason, "recorded_at": recorded_at,
        })),
    }
}

/// Live Postgres is SHARED across tests, so each test owns its own ids and clears them first.
fn reset(store: &TestStore, kind: &str, ids: &[&str]) {
    let mut c = store.lock();
    for id in ids {
        c.execute(
            "DELETE FROM plane_records WHERE kind=$1 AND id=$2",
            &[&kind, id],
        )
        .expect("clear this test's own records");
        c.execute(
            "DELETE FROM plane_chain WHERE kind=$1 AND parent=$2",
            &[&kind, id],
        )
        .expect("clear this test's own chains");
    }
}

fn reset_tokens(store: &TestStore, kind: &str, tokens: &[&str]) {
    let mut c = store.lock();
    for t in tokens {
        let _ = c.execute(
            "DELETE FROM plane_tokens WHERE kind=$1 AND token=$2",
            &[&kind, t],
        );
    }
}

/// Own the whole low band of a kind: a previous run's leftovers would otherwise be counted by the
/// exact-count assertions the purge tests make.
fn clear_purge_band(store: &TestStore) {
    let top = clamp(PURGE_BAND_TOP);
    let mut c = store.lock();
    c.execute(
        "DELETE FROM plane_chain pc USING plane_records pr
         WHERE pr.kind = 'task' AND pc.kind = 'task_event' AND pc.parent = pr.id AND pr.ts < $1",
        &[&top],
    )
    .expect("clear the purge band's event chains");
    c.execute(
        "DELETE FROM plane_records WHERE kind IN ('task', 'call') AND ts < $1",
        &[&top],
    )
    .expect("clear the purge band's records");
    c.execute(
        "DELETE FROM plane_chain WHERE kind IN ('task_event', 'call') AND ts < $1",
        &[&top],
    )
    .expect("clear the purge band's chains");
}

fn chain(store: &TestStore, kind: &str, parent: &str) -> Vec<serde_json::Value> {
    store
        .list_plane_records(kind, &PlaneSelector::Parent(parent.to_string().into()))
        .unwrap()
        .iter()
        .map(|b| decode(b))
        .collect()
}

fn task_state(store: &TestStore, id: &str) -> Option<String> {
    store
        .get_plane_record("task", id)
        .unwrap()
        .map(|b| decode(&b)["state"].as_str().unwrap().to_string())
}

fn listed_task_ids(store: &TestStore) -> Vec<String> {
    store
        .list_plane_records("task", &PlaneSelector::All)
        .unwrap()
        .iter()
        .filter_map(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .filter_map(|v| v["task_id"].as_str().map(str::to_string))
        .collect()
}

// ── the `call` kind: the durable MCP tool-call log ───────────────────────────────────────────

/// THE TEST THAT MATTERS. A round-trip on one live handle cannot distinguish a backend that wrote
/// to the server from one holding a HashMap behind the same trait. So this DROPS the store — closing
/// its connection entirely — then connects a genuinely new one and verifies the per-principal hash
/// chain still links from the bodies the server hands back.
#[test]
fn an_mcp_call_chain_survives_dropping_the_connection_and_reconnecting() {
    let Some(url) = live_url() else { return };
    let p = "vk_mcp_restart";
    {
        let store = connect_store_with_retry(&url).expect("connect");
        reset(&store, "call", &[p]);
        store
            .append_plane_record(call(p, 1, LIVE_TS + 100, "", "h1").view())
            .unwrap();
        store
            .append_plane_record(call(p, 2, LIVE_TS + 200, "h1", "h2").view())
            .unwrap();
        store
            .append_plane_record(call(p, 3, LIVE_TS + 300, "h2", "h3").view())
            .unwrap();
        drop(store);
    }

    let reopened = connect_store_with_retry(&url).expect("reconnect");
    let got = chain(&reopened, "call", p);
    assert_eq!(
        got.len(),
        3,
        "the call log must survive a reconnect; got {} records back, which is the \
         accept-and-keep-nothing behaviour this backend exists to replace",
        got.len()
    );
    assert_eq!(got[0]["prev_hash"], "", "seq 1 opens the chain");
    for w in got.windows(2) {
        assert_eq!(
            w[1]["prev_hash"], w[0]["hash"],
            "the per-principal chain must still link after a reconnect"
        );
    }
    assert_eq!(
        got.iter()
            .map(|r| r["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    // The opaque body round-trips verbatim.
    assert_eq!(got[2]["content"]["tool_digest"], "sha256:tool3");
    assert_eq!(got[2]["content"]["request_id"], "req-3");
    assert_eq!(got[1]["content"]["pin_generation"], 3);
    reset(&reopened, "call", &[p]);
}

/// The boot enumeration: a restart has to resume a chain for a principal this process has not yet
/// seen, so the store must be able to name every principal holding records — each exactly once.
#[test]
fn mcp_call_principals_are_enumerable_after_a_reconnect() {
    let Some(url) = live_url() else { return };
    let (a, b) = ("vk_mcp_enum_a", "vk_mcp_enum_b");
    {
        let store = connect_store_with_retry(&url).expect("connect");
        reset(&store, "call", &[a, b]);
        store
            .append_plane_record(call(a, 1, LIVE_TS + 100, "", "a1").view())
            .unwrap();
        store
            .append_plane_record(call(b, 1, LIVE_TS + 100, "", "b1").view())
            .unwrap();
        store
            .append_plane_record(call(a, 2, LIVE_TS + 101, "a1", "a2").view())
            .unwrap();
        drop(store);
    }
    let reopened = connect_store_with_retry(&url).expect("reconnect");
    let principals = reopened.list_plane_record_parents("call").unwrap();
    for want in [a, b] {
        assert_eq!(
            principals.iter().filter(|p| p.as_str() == want).count(),
            1,
            "{want} must be enumerable after a reconnect, exactly once"
        );
    }
    // The chain scope is the principal: a scoped read returns only its own.
    assert_eq!(chain(&reopened, "call", a).len(), 2);
    assert_eq!(chain(&reopened, "call", b).len(), 1);
    assert!(
        chain(&reopened, "call", "vk_mcp_nonexistent").is_empty(),
        "a principal with no records reads back empty, not an error"
    );
    // The enumeration is per KIND: a call principal is not a task-event parent.
    assert!(!reopened
        .list_plane_record_parents("task_event")
        .unwrap()
        .contains(&a.to_string()));
    reset(&reopened, "call", &[a, b]);
}

/// Retention must ACTUALLY DELETE and report a real count — a purge that returns a number it did not
/// perform is worse than one that reports nothing purged. The `call` kind drops EVERY row older than
/// the cutoff, whatever its disposition.
#[test]
fn purge_calls_before_deletes_and_returns_a_real_count() {
    let Some(url) = live_url() else { return };
    let _guard = lock_plane_purge();
    let store = connect_store_with_retry(&url).expect("connect");
    clear_purge_band(&store);
    let p = "vk_mcp_purge";
    reset(&store, "call", &[p]);
    store
        .append_plane_record(call(p, 1, 1_000_000_100, "", "h1").view())
        .unwrap();
    store
        .append_plane_record(call(p, 2, 1_000_000_200, "h1", "h2").view())
        .unwrap();
    store
        .append_plane_record(call(p, 3, 1_000_000_300, "h2", "h3").view())
        .unwrap();

    assert_eq!(
        store
            .purge_plane_records_before("call", 1_000_000_200)
            .unwrap(),
        1,
        "exactly the one row strictly older than the cutoff goes, and the count is one performed"
    );
    assert_eq!(
        chain(&store, "call", p)
            .iter()
            .map(|r| r["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![2, 3],
        "rows at or after the cutoff must remain — `before` is strictly less-than"
    );
    assert_eq!(
        store
            .purge_plane_records_before("call", 1_000_001_000)
            .unwrap(),
        2,
        "the remaining two rows must actually be removed"
    );
    assert!(chain(&store, "call", p).is_empty());
    // A sweep of one kind never reaches another kind's rows.
    assert_eq!(
        store
            .purge_plane_records_before("no_such_kind", u64::MAX)
            .unwrap(),
        0
    );
    clear_purge_band(&store);
}

/// A record arriving on an occupied `(kind, parent, seq)` is settled the way `append_audit` settles
/// a duplicate seq: IDENTICAL is the retry and succeeds; DIFFERENT is a forked or tampered log and is
/// an error. Overwriting would destroy the second case instead of reporting it.
#[test]
fn a_replayed_mcp_call_is_idempotent_but_a_forked_one_is_refused() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let p = "vk_mcp_replay";
    reset(&store, "call", &[p]);

    let rec = call(p, 1, LIVE_TS + 100, "", "h1");
    store.append_plane_record(rec.view()).unwrap();
    store
        .append_plane_record(rec.view())
        .expect("an identical replay is the at-least-once retry and must succeed");
    assert_eq!(
        chain(&store, "call", p).len(),
        1,
        "a replay must not duplicate the row"
    );

    let forked = call(p, 1, LIVE_TS + 100, "", "DIFFERENT");
    let err = store
        .append_plane_record(forked.view())
        .expect_err("a different record at an occupied position is a fork and must error");
    assert!(
        !format!("{err}").contains("DIFFERENT"),
        "the error must not echo stored or caller content back"
    );
    assert_eq!(
        chain(&store, "call", p)[0]["hash"],
        "h1",
        "the refused fork must not have overwritten the record already on record"
    );

    // Identical body, different sidecar: still a different record, still a fork.
    let mut moved = call(p, 1, LIVE_TS + 100, "", "h1");
    moved.ts += 1;
    store
        .append_plane_record(moved.view())
        .expect_err("the same body at a different ts is not the retry; it is a fork");
    reset(&store, "call", &[p]);
}

// ── the `task` / `task_event` kinds: the durable A2A task store ──────────────────────────────

/// A live task written, rewritten (the state transition durability exists for: working becoming
/// interrupted), and read back through a NEW connection.
#[test]
fn an_in_flight_task_survives_dropping_the_store_and_reconnecting() {
    let Some(url) = live_url() else { return };
    let (t1, t2) = ("t_restart_1", "t_restart_2");
    let second = task(
        t1,
        "input-required",
        LIVE_TS + 300,
        PlaneDisposition::Active,
    );
    {
        let store = connect_store_with_retry(&url).expect("connect");
        reset(&store, "task", &[t1, t2]);
        store
            .upsert_plane_record(
                task(t1, "working", LIVE_TS + 200, PlaneDisposition::Active).view(),
            )
            .unwrap();
        store.upsert_plane_record(second.view()).unwrap();
        store
            .upsert_plane_record(
                task(t2, "submitted", LIVE_TS + 210, PlaneDisposition::Active).view(),
            )
            .unwrap();
        drop(store);
    }

    let reopened = connect_store_with_retry(&url).expect("reconnect");
    let got = reopened.get_plane_record("task", t1).unwrap().expect(
        "an in-flight task must survive a restart; got None back after reconnecting, which is the \
         accept-and-keep-nothing shape of the trait default this backend exists to replace",
    );
    assert_eq!(
        got, second.body,
        "the body must round-trip byte-for-byte, and it must be the SECOND write"
    );
    // UPSERT, not append: two writes for one id leave ONE row.
    let ids: Vec<String> = listed_task_ids(&reopened)
        .into_iter()
        .filter(|t| t == t1 || t == t2)
        .collect();
    assert_eq!(
        ids.len(),
        2,
        "an upsert by id replaces, never appends: {ids:?}"
    );
    assert!(
        reopened
            .get_plane_record("task", "t_nonexistent_task")
            .unwrap()
            .is_none(),
        "an unknown id reads back None, not an error"
    );
    // A point-read is per KIND: the same id under another kind is a different record.
    assert!(reopened.get_plane_record("demotion", t1).unwrap().is_none());
    reset(&reopened, "task", &[t1, t2]);
}

/// The kind's listing is deliberately UNFILTERED. The boot rehydrate wants the active rows, the
/// retention sweep the terminal ones and the scoped listing one principal's; a store that
/// pre-filtered for any one of those would break the other two.
#[test]
fn listing_tasks_returns_every_row_including_terminal_ones_after_a_reconnect() {
    let Some(url) = live_url() else { return };
    let rows = [
        ("t_list_working", "working", PlaneDisposition::Active),
        (
            "t_list_interrupted",
            "input-required",
            PlaneDisposition::Active,
        ),
        ("t_list_completed", "completed", PlaneDisposition::Terminal),
        ("t_list_failed", "failed", PlaneDisposition::Terminal),
    ];
    let ids: Vec<&str> = rows.iter().map(|r| r.0).collect();
    {
        let store = connect_store_with_retry(&url).expect("connect");
        reset(&store, "task", &ids);
        for (id, state, d) in rows {
            store
                .upsert_plane_record(task(id, state, LIVE_TS + 200, d).view())
                .unwrap();
        }
        drop(store);
    }
    let reopened = connect_store_with_retry(&url).expect("reconnect");
    let mut mine: Vec<String> = listed_task_ids(&reopened)
        .into_iter()
        .filter(|t| ids.contains(&t.as_str()))
        .collect();
    mine.sort();
    let mut expect: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
    expect.sort();
    assert_eq!(
        mine, expect,
        "the listing is unfiltered: terminal rows are returned too, and every row survives a \
         reconnect"
    );
    reset(&reopened, "task", &ids);
}

/// The per-task provenance chain, read back after a reconnect. It never writes the task itself: an
/// event and the first task write are independent write-throughs with no ordering between them, so
/// appending an event for a task with no row yet has to WORK (no foreign key between the tables).
#[test]
fn a_task_event_chain_survives_a_reconnect_and_still_links() {
    let Some(url) = live_url() else { return };
    let (t1, t2) = ("t_chain_1", "t_chain_2");
    {
        let store = connect_store_with_retry(&url).expect("connect");
        reset(&store, "task_event", &[t1, t2]);
        // Appended OUT of order: the read must still come back oldest-first by seq.
        store
            .append_plane_record(event(t1, 2, "task.working", "e1", "e2").view())
            .unwrap();
        store
            .append_plane_record(event(t1, 1, "task.submitted", "", "e1").view())
            .unwrap();
        store
            .append_plane_record(event(t1, 3, "task.interrupted", "e2", "e3").view())
            .unwrap();
        // A second task's chain is independent — it must not leak into the first one's read.
        store
            .append_plane_record(event(t2, 1, "task.submitted", "", "f1").view())
            .unwrap();
        drop(store);
    }
    let reopened = connect_store_with_retry(&url).expect("reconnect");
    let got = chain(&reopened, "task_event", t1);
    assert_eq!(
        got.iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the chain must survive a reconnect, oldest-first by seq — the order the verifier reads"
    );
    assert_eq!(got[0]["prev_hash"], "", "seq 1 opens the chain");
    for w in got.windows(2) {
        assert_eq!(
            w[1]["prev_hash"], w[0]["hash"],
            "the per-task chain must still link"
        );
    }
    assert_eq!(got[2]["content"]["kind"], "task.interrupted");
    assert_eq!(chain(&reopened, "task_event", t2).len(), 1);
    assert!(
        chain(&reopened, "task_event", "t_unknown_chain").is_empty(),
        "a task with no events reads back empty, not an error"
    );
    reset(&reopened, "task_event", &[t1, t2]);
}

/// A replayed `(task, seq)`: IDENTICAL is the write-through retrying and succeeds without a
/// duplicate; DIFFERENT is refused as a fork.
///
/// BEHAVIOUR CHANGE vs 1.5.x, and it is the 1.6.0 contract's: the typed `append_task_event` UPSERTED
/// on `(task_id, seq)`. `append_plane_record` is append-only for every kind — busbar's reference
/// backends (`store-memory`, `store-example-plugin`) refuse a different record at an occupied chain
/// position — because two writers silently overwriting each other's chain rows is the defect the
/// fork check exists to report.
#[test]
fn a_replayed_task_event_is_idempotent_but_a_forked_one_is_refused() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let t = "t_replay_event";
    reset(&store, "task_event", &[t]);

    let e = event(t, 1, "task.submitted", "", "e1");
    store.append_plane_record(e.view()).unwrap();
    store
        .append_plane_record(e.view())
        .expect("an identical replay must succeed, not be rejected as a fork");
    assert_eq!(
        chain(&store, "task_event", t).len(),
        1,
        "a replay must not duplicate the row"
    );

    store
        .append_plane_record(event(t, 1, "task.submitted", "", "e1-rewritten").view())
        .expect_err("a different record at an occupied (task, seq) is a fork");
    let got = chain(&store, "task_event", t);
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0]["hash"], "e1",
        "the refused fork must not have overwritten the original"
    );
    reset(&store, "task_event", &[t]);
}

/// Retention drops TERMINAL task rows only, strictly older than the cutoff, and returns a count it
/// actually performed. Terminality is the envelope's `disposition` sidecar, set by the engine — this
/// store never decodes the body to decide, so an ACTIVE row is kept however old and whatever state
/// word its body carries.
#[test]
fn purge_tasks_before_drops_only_terminal_rows_and_returns_a_real_count() {
    let Some(url) = live_url() else { return };
    let _guard = lock_plane_purge();
    let store = connect_store_with_retry(&url).expect("connect");
    clear_purge_band(&store);

    let old = 1_000_000_100;
    for state in ["completed", "failed", "canceled", "rejected"] {
        store
            .upsert_plane_record(
                task(
                    &format!("t_purge_old_{state}"),
                    state,
                    old,
                    PlaneDisposition::Terminal,
                )
                .view(),
            )
            .unwrap();
    }
    // Old and ACTIVE — never dropped, no matter how old. `completed` here stands in for a body whose
    // state word looks terminal: the sidecar, not the body, decides.
    for state in [
        "input-required",
        "auth-required",
        "working",
        "submitted",
        "completed",
    ] {
        store
            .upsert_plane_record(
                task(
                    &format!("t_purge_old_active_{state}"),
                    state,
                    old,
                    PlaneDisposition::Active,
                )
                .view(),
            )
            .unwrap();
    }
    // Terminal but at the cutoff exactly, and terminal but newer — both kept.
    store
        .upsert_plane_record(
            task(
                "t_purge_at_cutoff",
                "completed",
                1_000_000_200,
                PlaneDisposition::Terminal,
            )
            .view(),
        )
        .unwrap();
    store
        .upsert_plane_record(
            task(
                "t_purge_newer",
                "completed",
                1_000_000_300,
                PlaneDisposition::Terminal,
            )
            .view(),
        )
        .unwrap();

    assert_eq!(
        store
            .purge_plane_records_before("task", 1_000_000_200)
            .unwrap(),
        4,
        "only the four TERMINAL rows strictly older than the cutoff go, and the count must be one \
         actually performed rather than a guess"
    );
    let mut left: Vec<String> = listed_task_ids(&store)
        .into_iter()
        .filter(|t| t.starts_with("t_purge_"))
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec![
            "t_purge_at_cutoff",
            "t_purge_newer",
            "t_purge_old_active_auth-required",
            "t_purge_old_active_completed",
            "t_purge_old_active_input-required",
            "t_purge_old_active_submitted",
            "t_purge_old_active_working",
        ],
        "an active task is never dropped by retention, and `before` is strictly less-than so a row \
         exactly at the cutoff is kept"
    );
    assert_eq!(
        store
            .purge_plane_records_before("task", 1_000_000_200)
            .unwrap(),
        0,
        "re-running the same purge removes nothing"
    );
    clear_purge_band(&store);
}

/// Retention has to bound the EVENT chain too: nothing else ever removes a `task_event` row, so a
/// purged task takes its chain with it — in the same transaction — and nothing belonging to any
/// other task.
#[test]
fn purging_a_task_takes_its_provenance_chain_with_it_and_no_other() {
    let Some(url) = live_url() else { return };
    let _guard = lock_plane_purge();
    let store = connect_store_with_retry(&url).expect("connect");
    clear_purge_band(&store);

    let (gone, stays) = ("t_cascade_gone", "t_cascade_stays");
    reset(&store, "task_event", &[gone, stays]);
    store
        .upsert_plane_record(
            task(gone, "completed", 1_000_000_100, PlaneDisposition::Terminal).view(),
        )
        .unwrap();
    store
        .upsert_plane_record(task(stays, "working", 1_000_000_100, PlaneDisposition::Active).view())
        .unwrap();
    store
        .append_plane_record(event(gone, 1, "task.submitted", "", "g1").view())
        .unwrap();
    store
        .append_plane_record(event(gone, 2, "task.completed", "g1", "g2").view())
        .unwrap();
    store
        .append_plane_record(event(stays, 1, "task.submitted", "", "s1").view())
        .unwrap();

    assert_eq!(
        store
            .purge_plane_records_before("task", 1_000_000_200)
            .unwrap(),
        1,
        "exactly the one terminal task in this band is swept"
    );
    assert!(
        chain(&store, "task_event", gone).is_empty(),
        "the purged task's events go with it; otherwise the chain grows unbounded"
    );
    assert_eq!(
        chain(&store, "task_event", stays).len(),
        1,
        "another task's chain must be untouched by that purge"
    );
    reset(&store, "task", &[gone, stays]);
    reset(&store, "task_event", &[gone, stays]);
    clear_purge_band(&store);
}

/// Two ids differing ONLY IN CASE are two records, and the same for two chains. Postgres's default
/// collations are deterministic so this passes without the explicit `COLLATE "C"` too; the point of
/// pinning it is that this store does not choose the database it is pointed at.
#[test]
fn task_ids_differing_only_in_case_are_distinct_tasks() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let (lower, upper) = ("t_case_fold", "T_CASE_FOLD");
    reset(&store, "task", &[lower, upper]);
    reset(&store, "task_event", &[lower, upper]);

    store
        .upsert_plane_record(task(lower, "working", LIVE_TS + 400, PlaneDisposition::Active).view())
        .unwrap();
    store
        .upsert_plane_record(
            task(
                upper,
                "completed",
                LIVE_TS + 400,
                PlaneDisposition::Terminal,
            )
            .view(),
        )
        .unwrap();
    assert_eq!(task_state(&store, lower).as_deref(), Some("working"));
    assert_eq!(
        task_state(&store, upper).as_deref(),
        Some("completed"),
        "the second write must not have upserted over the first: they are two tasks"
    );

    store
        .append_plane_record(event(lower, 1, "task.submitted", "", "l1").view())
        .unwrap();
    store
        .append_plane_record(event(upper, 1, "task.submitted", "", "u1").view())
        .unwrap();
    assert_eq!(chain(&store, "task_event", lower)[0]["hash"], "l1");
    assert_eq!(
        chain(&store, "task_event", upper)[0]["hash"],
        "u1",
        "one task's chain must not answer for another's"
    );
    reset(&store, "task", &[lower, upper]);
    reset(&store, "task_event", &[lower, upper]);
}

/// A `u64` a signed BIGINT cannot hold is REFUSED, not clamped: `clamp` would pin it to `i64::MAX`,
/// so the record read back would not be the record written — a chain position silently moved, a
/// retention timestamp silently changed — and nothing would ever have reported an error.
#[test]
fn a_sidecar_value_beyond_the_storable_range_is_refused_rather_than_clamped() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let t = "t_out_of_range";
    reset(&store, "task", &[t]);
    reset(&store, "task_event", &[t]);

    let err = store
        .upsert_plane_record(task(t, "working", u64::MAX, PlaneDisposition::Active).view())
        .expect_err("a ts above i64::MAX must be refused, never silently clamped");
    assert!(
        format!("{err}").contains("ts"),
        "the refusal names the field; got {err}"
    );
    let mut seq_too_big = task(t, "working", LIVE_TS, PlaneDisposition::Active);
    seq_too_big.seq = u64::MAX;
    store
        .upsert_plane_record(seq_too_big.view())
        .expect_err("a seq above i64::MAX must be refused");
    assert!(
        store.get_plane_record("task", t).unwrap().is_none(),
        "a refused write must leave no row behind"
    );

    let mut e = event(t, 1, "task.submitted", "", "e1");
    e.seq = u64::MAX;
    store
        .append_plane_record(e.view())
        .expect_err("an appended seq above i64::MAX must be refused too");
    assert!(chain(&store, "task_event", t).is_empty());

    // The largest value that DOES fit round-trips, so the guard is a ceiling and not a blanket
    // refusal of large values.
    let mut top = event(t, 1, "task.submitted", "", "e1");
    top.seq = i64::MAX as u64;
    store.append_plane_record(top.view()).unwrap();
    assert_eq!(chain(&store, "task_event", t).len(), 1);
    reset(&store, "task", &[t]);
    reset(&store, "task_event", &[t]);
}

// ── the `demotion` kind, the `ask` token ledger, and the `push_config` capability ───────────
//
// Security state, and the trait defaults are the hole: the upsert/list/delete verbs default to
// accept-and-keep-nothing, so a backend that implements none of them compiles, ships and reports
// every demotion recorded while discarding it — a quarantined upstream that gets the operator's
// approval back at the next restart. Every case reads back through a RECONNECTED store, and the
// ledger cases include genuinely independent connections — which is what a second node is.

/// THE LIVE URL, OR A FAILURE. Deliberately NOT `live_url()`, whose `None` arm lets a case return
/// green having tested nothing: these are exactly the properties where a skipped test costs an
/// operator something.
fn require_live_url() -> String {
    std::env::var("BUSBAR_TEST_POSTGRES_URL").unwrap_or_else(|_| {
        panic!(
            "BUSBAR_TEST_POSTGRES_URL is unset. These cases are the ONLY coverage of the durable \
             demotion record, the single-use token ledger and the push-callback capability on this \
             backend, and all of them fail SILENTLY when unimplemented. Point this at a live \
             Postgres, e.g. postgres://busbar:busbar@127.0.0.1:5432/busbar_test"
        )
    })
}

/// Per-process namespacing: a fixed key would have two concurrent runs redeeming each other's
/// tokens and reading each other's demotions.
fn trust_ns(tag: &str) -> String {
    format!("{}-{}", tag, std::process::id())
}

const TRUST_NOW: u64 = 2_000_000_000;

fn demotions(store: &TestStore) -> Vec<serde_json::Value> {
    store
        .list_plane_records("demotion", &PlaneSelector::All)
        .unwrap()
        .iter()
        .map(|b| decode(b))
        .collect()
}

/// A DEMOTION OUTLIVES THE PROCESS THAT RECORDED IT. Without this row on the server a restart hands
/// a quarantined upstream its approval back.
#[test]
fn a_demotion_survives_dropping_the_store_and_reconnecting() {
    let url = require_live_url();
    let (a, b, c) = (
        trust_ns("srv-payments"),
        trust_ns("srv-search"),
        trust_ns("srv-mail"),
    );
    {
        let store = connect_store_with_retry(&url).expect("connect");
        reset(&store, "demotion", &[&a, &b, &c]);
        store
            .upsert_plane_record(demotion(&a, "tool-drift", TRUST_NOW).view())
            .unwrap();
        // UPSERT by id: a second demotion of one upstream REPLACES the row.
        store
            .upsert_plane_record(demotion(&a, "digest-mismatch", TRUST_NOW + 10).view())
            .unwrap();
        store
            .upsert_plane_record(demotion(&b, "tool-drift", TRUST_NOW + 20).view())
            .unwrap();
        store
            .upsert_plane_record(demotion(&c, "tool-drift", TRUST_NOW + 30).view())
            .unwrap();
        store
            .delete_plane_record("demotion", &c)
            .expect("a later agreeing observation clears the quarantine");
        store
            .delete_plane_record("demotion", &trust_ns("srv-never-demoted"))
            .expect("clearing a row that is not there is a no-op, not an error");
        drop(store);
    }

    let reopened = connect_store_with_retry(&url).expect("reconnect");
    let mut mine: Vec<(String, String)> = demotions(&reopened)
        .into_iter()
        .filter(|r| {
            r["server"] == a.as_str() || r["server"] == b.as_str() || r["server"] == c.as_str()
        })
        .map(|r| {
            (
                r["server"].as_str().unwrap().to_string(),
                r["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    mine.sort();
    let mut expect = vec![
        (a.clone(), "digest-mismatch".to_string()),
        (b.clone(), "tool-drift".to_string()),
    ];
    expect.sort();
    assert_eq!(
        mine, expect,
        "the boot read must put every recorded quarantine back in force — upserted to the LATEST \
         reason, and WITHOUT the one a later agreeing observation cleared"
    );
    reset(&reopened, "demotion", &[&a, &b, &c]);
}

/// THE SINGLE-USE LEDGER ACROSS A RESTART. The seal on a single-use approval verifies on its second
/// presentation exactly as on its first; only a record that the first happened tells them apart.
#[test]
fn a_reconnected_store_refuses_a_second_redemption_of_the_same_token() {
    let url = require_live_url();
    let (spent, fresh) = (trust_ns("nonce-restart"), trust_ns("nonce-restart-other"));
    {
        let store = connect_store_with_retry(&url).expect("connect");
        reset_tokens(&store, "ask", &[&spent, &fresh]);
        assert!(
            store
                .redeem_plane_token("ask", &spent, TRUST_NOW + 900, TRUST_NOW)
                .unwrap(),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        drop(store);
    }

    let reopened = connect_store_with_retry(&url).expect("reconnect");
    assert!(
        !reopened
            .redeem_plane_token("ask", &spent, TRUST_NOW + 900, TRUST_NOW + 1)
            .unwrap(),
        "a restart handed a spent approval back"
    );
    // THE CONTROL: a ledger that refused everything would satisfy the case above.
    assert!(
        reopened
            .redeem_plane_token("ask", &fresh, TRUST_NOW + 900, TRUST_NOW + 2)
            .unwrap(),
        "a different token is not the one that was spent"
    );
    reset_tokens(&reopened, "ask", &[&spent, &fresh]);
}

/// The ledger is keyed by `(kind, token)`: one token string spent under one kind is a different
/// capability from the same string under another, so neither redemption may refuse the other.
#[test]
fn a_token_is_single_use_within_its_kind_not_across_kinds() {
    let url = require_live_url();
    let token = trust_ns("nonce-kinds");
    let store = connect_store_with_retry(&url).expect("connect");
    reset_tokens(&store, "ask", &[&token]);
    reset_tokens(&store, "other_kind", &[&token]);
    assert!(store
        .redeem_plane_token("ask", &token, TRUST_NOW + 900, TRUST_NOW)
        .unwrap());
    assert!(
        store
            .redeem_plane_token("other_kind", &token, TRUST_NOW + 900, TRUST_NOW)
            .unwrap(),
        "the same token string under another kind is a different ledger entry"
    );
    assert!(!store
        .redeem_plane_token("ask", &token, TRUST_NOW + 900, TRUST_NOW)
        .unwrap());
    reset_tokens(&store, "ask", &[&token]);
    reset_tokens(&store, "other_kind", &[&token]);
}

/// TWO CONNECTIONS ARE TWO NODES OF A FLEET. They share the signing key, so they share the SEAL, and
/// the second redemption is an ordinary request a load balancer sends somewhere else.
#[test]
fn a_second_node_cannot_redeem_a_token_the_first_already_spent() {
    let url = require_live_url();
    let nonce = trust_ns("nonce-fleet");
    let node_a = connect_store_with_retry(&url).expect("node A connects");
    let node_b = connect_store_with_retry(&url).expect("node B connects");
    reset_tokens(&node_a, "ask", &[&nonce]);

    assert!(node_a
        .redeem_plane_token("ask", &nonce, TRUST_NOW + 900, TRUST_NOW)
        .unwrap());
    assert!(
        !node_b
            .redeem_plane_token("ask", &nonce, TRUST_NOW + 900, TRUST_NOW)
            .unwrap(),
        "a second node redeemed a token the first already spent"
    );
    reset_tokens(&node_a, "ask", &[&nonce]);
}

/// CONCURRENT REDEMPTION IS THE ATTACK. Eight independent CONNECTIONS race on one token through a
/// barrier — the arrangement a read-then-write implementation answers "first" to eight times.
#[test]
fn exactly_one_of_many_racing_nodes_wins_the_redemption() {
    let url = require_live_url();
    let nonce = trust_ns("nonce-race");
    let cleanup = connect_store_with_retry(&url).expect("connect");
    reset_tokens(&cleanup, "ask", &[&nonce]);
    drop(cleanup);

    let n = 8usize;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(n));
    let winners: usize = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let url = url.clone();
                let nonce = nonce.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                scope.spawn(move || {
                    let node = connect_store_with_retry(&url).expect("a racing node connects");
                    barrier.wait();
                    node.redeem_plane_token("ask", &nonce, TRUST_NOW + 900, TRUST_NOW)
                        .expect("redeem_plane_token") as usize
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    });
    assert_eq!(
        winners, 1,
        "exactly one redemption of one token may be the first; {winners} were each told they were"
    );
    let cleanup = connect_store_with_retry(&url).expect("connect");
    reset_tokens(&cleanup, "ask", &[&nonce]);
}

/// THE LEDGER IS BOUNDED BY ONE VALIDITY WINDOW: `now` rides every redemption so lapsed entries go
/// in the same call, and an entry still inside its window is never swept.
#[test]
fn redeeming_evicts_entries_whose_token_can_no_longer_be_presented() {
    let url = require_live_url();
    let (short, long, other) = (
        trust_ns("nonce-short"),
        trust_ns("nonce-long"),
        trust_ns("nonce-sweeper"),
    );
    let store = connect_store_with_retry(&url).expect("connect");
    reset_tokens(&store, "ask", &[&short, &long, &other]);

    assert!(store
        .redeem_plane_token("ask", &short, TRUST_NOW + 10, TRUST_NOW)
        .unwrap());
    assert!(store
        .redeem_plane_token("ask", &long, TRUST_NOW + 10_000, TRUST_NOW)
        .unwrap());
    let later = TRUST_NOW + 11;
    assert!(store
        .redeem_plane_token("ask", &other, later + 900, later)
        .unwrap());

    let still_there = |nonce: &str| -> bool {
        store
            .lock()
            .query_one(
                "SELECT COUNT(*) FROM plane_tokens WHERE kind='ask' AND token=$1",
                &[&nonce],
            )
            .map(|r| r.get::<_, i64>(0) > 0)
            .expect("count the ledger row")
    };
    assert!(
        !still_there(&short),
        "the lapsed entry must be evicted by the redemption's sweep"
    );
    assert!(
        still_there(&long),
        "a token still inside its window must NOT be swept — that is the double redemption"
    );
    reset_tokens(&store, "ask", &[&short, &long, &other]);
}

/// REFUSED RATHER THAN CLAMPED: a `now` clamped to `i64::MAX` would sweep the kind's entire ledger
/// and then report the insert as a first redemption — every spent token reopened at once.
#[test]
fn the_ledger_refuses_values_it_cannot_store_faithfully() {
    let url = require_live_url();
    let nonce = trust_ns("nonce-range");
    let srv = trust_ns("srv-range");
    let store = connect_store_with_retry(&url).expect("connect");
    reset_tokens(&store, "ask", &[&nonce]);
    reset(&store, "demotion", &[&srv]);

    store
        .redeem_plane_token("ask", &nonce, u64::MAX, TRUST_NOW)
        .expect_err("an unstorable expires_at must be an error, never a silent first redemption");
    store
        .redeem_plane_token("ask", &nonce, TRUST_NOW + 900, u64::MAX)
        .expect_err("an unstorable now must be an error");
    store
        .upsert_plane_record(demotion(&srv, "tool-drift", u64::MAX).view())
        .expect_err("an unstorable ts must be an error rather than a mangled row");

    assert!(store
        .redeem_plane_token("ask", &nonce, i64::MAX as u64, TRUST_NOW)
        .unwrap());
    reset_tokens(&store, "ask", &[&nonce]);
    reset(&store, "demotion", &[&srv]);
}

/// `plane_token_live` is MULTI-use and SPENDS NOTHING: a push-callback configuration is live across
/// every callback of a running task, dies the moment the write that made its task terminal flips its
/// disposition, and holds nothing once deleted.
#[test]
fn plane_token_live_carries_a_task_and_dies_with_it() {
    let url = require_live_url();
    let id = trust_ns("push-live");
    let store = connect_store_with_retry(&url).expect("connect");
    reset(&store, "push_config", &[&id]);
    let config = |disposition| PlaneRecord {
        kind: "push_config".into(),
        id: id.clone(),
        parent: None,
        seq: 0,
        ts: TRUST_NOW,
        disposition,
        body: b"{}".to_vec(),
    };

    store
        .upsert_plane_record(config(PlaneDisposition::Active).view())
        .unwrap();
    for nth in 1..=3 {
        assert!(
            store
                .plane_token_live("push_config", &id, TRUST_NOW + 100, TRUST_NOW + 20)
                .unwrap(),
            "callback {nth} of a running task was refused; the check spent the token"
        );
    }
    // A second connection — another node — sees the same capability.
    let other = connect_store_with_retry(&url).expect("second node");
    assert!(other
        .plane_token_live("push_config", &id, TRUST_NOW + 100, TRUST_NOW + 20)
        .unwrap());

    store
        .upsert_plane_record(config(PlaneDisposition::Terminal).view())
        .unwrap();
    assert!(
        !store
            .plane_token_live("push_config", &id, TRUST_NOW + 100, TRUST_NOW + 20)
            .unwrap(),
        "a token whose task has finished is still live — this is the replay"
    );

    store
        .upsert_plane_record(config(PlaneDisposition::Active).view())
        .unwrap();
    store.delete_plane_record("push_config", &id).unwrap();
    assert!(!store
        .plane_token_live("push_config", &id, TRUST_NOW + 100, TRUST_NOW + 20)
        .unwrap());
    reset(&store, "push_config", &[&id]);
}

/// The deadline is a real one (live AT `expires_at`, dead one second past it), and an unknown kind or
/// token holds nothing live.
#[test]
fn plane_token_live_refuses_a_lapsed_token_and_an_unknown_one() {
    let url = require_live_url();
    let id = trust_ns("push-lapse");
    let store = connect_store_with_retry(&url).expect("connect");
    reset(&store, "push_config", &[&id]);
    store
        .upsert_plane_record(
            (PlaneRecord {
                kind: "push_config".into(),
                id: id.clone(),
                parent: None,
                seq: 0,
                ts: TRUST_NOW,
                disposition: PlaneDisposition::Active,
                body: b"{}".to_vec(),
            })
            .view(),
        )
        .unwrap();

    assert!(store
        .plane_token_live("push_config", &id, 100, 100)
        .unwrap());
    assert!(
        !store
            .plane_token_live("push_config", &id, 100, 101)
            .unwrap(),
        "a token one second past its deadline is still live"
    );
    assert!(!store.plane_token_live("ask", &id, 100, 20).unwrap());
    assert!(!store
        .plane_token_live("push_config", &trust_ns("push-never"), 100, 20)
        .unwrap());
    reset(&store, "push_config", &[&id]);
}

/// THE IDENTITY COLUMNS CARRY AN EXPLICIT COLLATION, asserted from the catalogue so the DDL cannot
/// quietly lose it. Under an inherited non-deterministic ICU collation two ids differing only in case
/// would collide on a primary key, and a token differing only in case from a spent one would be
/// refused as spent.
#[test]
fn the_plane_identity_columns_pin_a_byte_exact_collation() {
    let url = require_live_url();
    let store = connect_store_with_retry(&url).expect("connect");
    for (table, column) in [
        ("plane_records", "kind"),
        ("plane_records", "id"),
        ("plane_records", "parent"),
        ("plane_chain", "kind"),
        ("plane_chain", "parent"),
        ("plane_chain", "id"),
        ("plane_tokens", "kind"),
        ("plane_tokens", "token"),
    ] {
        let collation: Option<String> = store
            .lock()
            .query_one(
                "SELECT c.collname FROM pg_attribute a
                   JOIN pg_class t ON t.oid = a.attrelid
                   LEFT JOIN pg_collation c ON c.oid = a.attcollation
                  WHERE t.relname = $1 AND a.attname = $2 AND a.attnum > 0",
                &[&table, &column],
            )
            .map(|r| r.get(0))
            .unwrap_or_else(|e| panic!("{table}.{column} must exist in the catalogue: {e}"));
        assert_eq!(
            collation.as_deref(),
            Some("C"),
            "{table}.{column} must pin COLLATE \"C\""
        );
    }
}
