// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-postgres-plugin` cdylib, loaded the way a REAL operator
//! actually loads a plugin — not via a direct in-process load of the library
//! (flagged, correctly, as testing a mechanism no end user ever uses: nobody imports
//! `busbar-plugin-loader` and calls its internal function).
//!
//! `load_and_exercise_postgres_plugin_via_file_drop` instead: packs the built cdylib into a real
//! tarball (the same `busbar-plugin-pack` tool CI's own SIGNOFF step uses), drops it into a real
//! `plugins.dir`, and boots a REAL `busbar` process (no `--validate`) against a config naming
//! `store: { module: postgres }` — the documented file-drop install path (see
//! `crates/plugin-loader/src/lib.rs::list_plugin_files`/boot-time discovery).
//!
//! `--validate` is DELIBERATELY not used for the load-proof itself: it is manifest-only by design
//! ("no server, no network, no state, no dlopen" — `crates/busbar/src/main.rs`'s own `--help` text)
//! and never opens the store, so checking the schema after `--validate` alone would prove nothing
//! about the real boot path. A clean `--validate` run first proves the file-dropped plugin passes
//! the trust/manifest gate; then a REAL BOOT (no `--validate` flag) is the only thing that actually
//! `dlopen`s the plugin and runs `Store::connect`/migration (busbar's own gate-assembly code calls
//! `plugin_registry.open_store` synchronously during construction, before the listener ever binds —
//! see `crates/busbar/src/main.rs`), so that's what proves the persistence claim.
//!
//! Persistence is then proven the same two independent ways the prior direct-call test used (kept —
//! this part was always sound, only the LOADING mechanism was wrong):
//!   1. The boot runs against a DISPOSABLE, freshly created, genuinely empty database, and is polled
//!      via a RAW independent `postgres::Client` connection (never the store itself, so this
//!      check can't create the schema itself) for the `keys` table to appear within a timeout. The
//!      empty database is what makes this a proof rather than a formality: against the shared test
//!      database, every live unit test in this workspace has already migrated a `keys` table into
//!      existence, so the same poll would break true on its first iteration even if `busbar` had
//!      failed to load the plugin and exited immediately. Then the schema VERSION the boot wrote is
//!      read back, and the child is confirmed still running rather than having died after migrating.
//!   2. Only AFTER those proofs, a second, independent open of the LINKED door (bypassing the
//!      plugin/ABI/loader entirely) confirms the store type itself can talk to the same schema.
//!
//! The two ABI-contract error-path tests below (`bad_config_fails_over_abi`, `refuses_non_plugin`)
//! are DELIBERATELY left loading the dropped-in door directly (`common::dropped_at`) — they test the loader's own error-surface
//! contract in isolation (a legitimate internal unit-test target: "does a bad config produce a clean
//! Err across the ABI, never a panic"), which is a different question from "does a real end-user
//! install work," and converting them to a full process-boot-and-capture-stderr harness for each
//! error shape is a much larger, lower-value lift than the persistence test's conversion.

//! These development fixtures permit unsigned plugins; they verify manifest and archive
//! integrity and loading, not production release-signature trust policy.

mod common;
use common::temp_db::TempDb;

use common::{build_real_binaries, plugin_path, postgres_url, E2E_RELEASE_PRIVKEY};

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// RAII guard for a spawned child process: kills and reaps it on drop, including when a panic
/// unwinds partway through the test (unlike a manual `child.kill()` call placed after the code that
/// might panic, which never runs if an earlier assertion fails first).
struct ChildGuard(Child, PathBuf);

impl ChildGuard {
    fn output(&self) -> String {
        std::fs::read_to_string(&self.1).unwrap_or_else(|e| format!("<log unreadable: {e}>"))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

/// Every `env:` secret-ref name a config text references, in first-seen order, de-duplicated.
fn referenced_env_vars(text: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for (i, _) in text.match_indices("env:") {
        let rest = &text[i + 4..];
        let name: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && !v.contains(&name) {
            v.push(name);
        }
    }
    v
}

/// Set a harmless placeholder for every `{ env: NAME }` `config_text` references, so `--validate`
/// (which now resolves built-in secrets, see `referenced_env_vars`) has something to resolve.
fn set_referenced_secret_envs(cmd: &mut Command, config_text: &str) {
    for name in referenced_env_vars(config_text) {
        cmd.env(
            name,
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
    }
}

/// THE REAL END-TO-END INSTALL PROOF: pack the plugin, drop it in a real `plugins.dir`, run the real
/// `busbar --validate` against a config naming `store: { module: postgres }` (trust/manifest gate
/// proof), then boot a REAL `busbar` process (no `--validate`) and poll for real Postgres to
/// actually be touched — via the documented file-drop mechanism, never a direct `load_store()` call.
#[test]
fn load_and_exercise_postgres_plugin_via_file_drop() {
    let Some(admin_url) = postgres_url() else {
        return;
    };

    let so_path = plugin_path();

    let tmp = TempDb::create(&admin_url, "spg_filedrop");
    let url = tmp.url();

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-pg-filedrop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    let tarball = work.join("store-postgres.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-postgres",
            "--alias",
            "postgres",
            "--kind",
            "store",
            "--version",
            env!("CARGO_PKG_VERSION"),
            "--publisher",
            "busbar",
            "--description",
            "e2e file-drop proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
        ])
        .env("BUSBAR_SIGN_KEY", E2E_RELEASE_PRIVKEY)
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    std::fs::copy(&tarball, plugins_dir.join("store-postgres.tar.gz")).unwrap();
    let archive_pin = busbar_contract::redacted::sha256_hex(
        &std::fs::read(plugins_dir.join("store-postgres.tar.gz")).unwrap(),
    );

    let config = work.join("config.yaml");
    let providers = work.join("providers.yaml");

    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    let config_text = format!(
        "listen: \"127.0.0.1:0\"\n\
         store:\n  module: postgres\n  settings: {{ url: \"{url}\" }}\n\
         plugins:\n  enabled: true\n  dir: {}\n  fetch:\n    - url: \"https://plugins.example/store-postgres.tar.gz\"\n      sha256: \"{archive_pin}\"\n  trust:\n    allow_unsigned: true\n\
         auth:\n  chain: []\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );
    std::fs::write(&config, &config_text).unwrap();

    let mut validate_cmd = Command::new(&busbar_bin);
    validate_cmd
        .arg("--validate")
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers);
    set_referenced_secret_envs(&mut validate_cmd, &config_text);
    let out = validate_cmd.output().expect("run busbar --validate");
    assert!(
        out.status.success(),
        "busbar --validate must succeed with the file-dropped postgres plugin: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let boot_log = work.join("boot.log");
    let boot_log_out = std::fs::File::create(&boot_log).expect("create the boot log");
    let boot_log_err = boot_log_out.try_clone().expect("dup the boot log handle");
    let mut boot_cmd = Command::new(&busbar_bin);
    boot_cmd
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_STATE_FILE", "")
        .stdout(Stdio::from(boot_log_out))
        .stderr(Stdio::from(boot_log_err));

    set_referenced_secret_envs(&mut boot_cmd, &config_text);
    let child = boot_cmd.spawn().expect("spawn a real busbar boot");
    let mut guard = ChildGuard(child, boot_log);

    let deadline = Instant::now() + Duration::from_secs(15);
    let booted = loop {
        if let Ok(mut raw) = postgres::Client::connect(&url, postgres::NoTls) {
            if let Ok(row) = raw.query_one(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='keys')",
                &[],
            ) {
                let exists: bool = row.get(0);
                if exists {
                    break true;
                }
            }
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!(
                "busbar exited before creating the postgres schema (status: {status})\n\
                 --- boot output ---\n{}",
                guard.output()
            );
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        booted,
        "a real busbar boot with the file-dropped postgres plugin must create the `keys` table \
         (via RecordStore::connect/migrate) within 15s -- proof the real dlopen+connect path executed \
         during boot, not a no-op\n--- boot output ---\n{}",
        guard.output()
    );

    let mut raw = postgres::Client::connect(&url, postgres::NoTls)
        .expect("raw connect to the fresh database");
    let version: i64 = raw
        .query_one("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[])
        .expect("the boot must have created busbar_schema")
        .get(0);
    assert_eq!(
        version,
        busbar_store_postgres::SCHEMA_VERSION,
        "the plugin-loaded boot must have landed the current schema version"
    );

    assert!(
        matches!(guard.0.try_wait(), Ok(None)),
        "the real busbar boot must still be running on the file-dropped postgres store, not have \
         exited after creating the schema\n--- boot output ---\n{}",
        guard.output()
    );

    let _direct = common::linked(&cfg(&url)).expect(
        "connect directly, bypassing the plugin entirely, to confirm the schema the real boot \
         created is usable",
    );

    drop(_direct);
    drop(raw);
    drop(guard);
    let _ = std::fs::remove_dir_all(&work);
}

/// END-TO-END FAILURE (ABI-contract unit test, see module doc for why this stays a direct
/// dropped-in load): an `open()` config that cannot produce a usable store surfaces back across
/// the door as a clean `Err`, never a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_postgres_plugin_bad_config_fails_over_abi() {
    let path = plugin_path();

    let err = common::dropped_at(&path, "{ not json")
        .expect_err("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid postgres plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = common::dropped_at(&path, "{}").expect_err("a config missing url must fail to load");
    assert!(
        err.contains("`url` is required"),
        "expected the plugin's own missing-url message, got: {err}"
    );

    let err = common::dropped_at(
        &path,
        &cfg("postgres://u:p@127.0.0.1:1/definitely_not_a_real_db"),
    )
    .expect_err("an unreachable postgres target must fail to load");
    assert!(
        err.contains("postgres store: failed to connect: ")
            && err.contains("error connecting to server"),
        "expected tokio-postgres's own connect-failure message to survive the ABI crossing, got: {err}"
    );
}

/// A non-plugin library (or a missing file) is refused with a clear error, never a crash. Same
/// ABI-contract-unit-test rationale as above.
#[test]
fn refuses_non_plugin() {
    let err = match common::dropped_at(std::path::Path::new("/definitely/not/a/plugin.so"), "{}") {
        Err(e) => e,
        Ok(_) => panic!("a missing library must not load"),
    };
    assert!(err.contains("the library did not load"), "got: {err}");
}

/// Serialize a stand-in plane-record body. The store never decodes a body, so the shape only has to
/// be something THIS test can decode again on the way back.
fn plane_body(v: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&v).expect("serialize a stand-in body")
}

fn plane_decode(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).expect("a body this test wrote decodes")
}

/// THE DURABILITY PROOF FOR THE `call` PLANE KIND (the MCP call log), OVER THE REAL PLUGIN PATH.
#[test]
fn mcp_call_log_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore};

    let path = plugin_path();
    let Some(url) = postgres_url() else {
        return;
    };
    let cfg = cfg(&url);

    let direct = common::linked(&cfg).expect("connect directly to verify");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let kind = format!("call_abi_{stamp}");
    let p_main = format!("vk_abi_main_{stamp}");
    let p_other = format!("vk_abi_other_{stamp}");

    let call = |principal: &str, seq: u64, prev: &str, hash: &str| PlaneRecord {
        kind: kind.clone(),
        id: principal.into(),
        parent: Some(principal.into()),
        seq,
        ts: 2_000 + seq,
        disposition: PlaneDisposition::Active,
        body: plane_body(serde_json::json!({
            "seq": seq,
            "prev_hash": prev,
            "hash": hash,
            "content": {
                "server": "srv",
                "tool": "srv_read_file",
                "outcome": "dispatched",
                "tool_digest": format!("sha256:tool{seq}"),
                "pin_generation": 3,
                "request_id": format!("req-{seq}"),
            },
        })),
    };
    let chain = |store: &dyn RecordStore, principal: &str| -> Vec<serde_json::Value> {
        store
            .list_plane_records(&kind, &PlaneSelector::Parent(principal.to_string().into()))
            .expect("list_plane_records over the ABI")
            .iter()
            .map(|b| plane_decode(b))
            .collect()
    };

    {
        let store = common::dropped_at(&path, &cfg)
            .expect("the postgres plugin must load over the real ABI");
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_plane_record(call(&p_main, seq, prev, hash).view())
                .expect("append_plane_record over the ABI");
        }
        store
            .append_plane_record(call(&p_other, 1, "", "o1").view())
            .expect("append_plane_record over the ABI");

        drop(store);
    }

    let store = common::dropped_at(&path, &cfg)
        .expect("the postgres plugin must load again over the real ABI");

    let calls = chain(&store, &p_main);
    assert_eq!(
        calls
            .iter()
            .map(|c| c["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-principal call chain must survive the unload/reload over the plugin ABI in chain \
         order; got {} record(s) back, which is the accept-and-keep-nothing shape of the trait \
         default an unrelayed seam substitutes",
        calls.len()
    );
    for w in calls.windows(2) {
        assert_eq!(
            w[1]["prev_hash"], w[0]["hash"],
            "the chain must still link after the reload"
        );
    }

    assert_eq!(calls[2]["content"]["tool_digest"], "sha256:tool3");
    assert_eq!(calls[2]["content"]["request_id"], "req-3");
    assert_eq!(calls[2]["content"]["outcome"], "dispatched");
    assert_eq!(calls[1]["content"]["pin_generation"], 3);
    assert_eq!(
        chain(&store, &p_other).len(),
        1,
        "one principal's chain must not carry another's records"
    );

    store
        .append_plane_record(call(&p_main, 3, "h2", "h3").view())
        .expect("an identical replay is Ok over the ABI");
    assert!(
        store
            .append_plane_record(call(&p_main, 3, "h2", "FORKED").view())
            .is_err(),
        "a forked chain must surface as an error across the ABI, not be swallowed"
    );

    let principals = store
        .list_plane_record_parents(&kind)
        .expect("list_plane_record_parents");
    assert_eq!(
        principals,
        vec![p_main.clone(), p_other.clone()],
        "the boot enumeration must name every principal holding records, exactly once each"
    );

    assert_eq!(
        store
            .purge_plane_records_before(&kind, 2_002)
            .expect("purge"),
        2,
        "both records at ts 2001 go (one per principal); the one sitting exactly at the cutoff stays"
    );
    assert_eq!(chain(&store, &p_main).len(), 2);
    assert!(chain(&store, &p_other).is_empty());
    assert_eq!(
        store
            .list_plane_record_parents(&kind)
            .expect("list_plane_record_parents"),
        vec![p_main.clone()],
        "a principal whose chain the sweep emptied must leave the enumeration, or a boot keeps \
         resuming a chain with nothing in it"
    );
    drop(store);

    let direct_calls = chain(&direct, &p_main);
    assert_eq!(
        direct_calls
            .iter()
            .map(|c| c["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![2, 3],
        "the records must be physically present in Postgres, not just cached in-process by the plugin"
    );
    assert_eq!(direct_calls[1]["hash"], "h3");

    RecordStore::purge_plane_records_before(&direct, &kind, i64::MAX as u64)
        .expect("clean up this run's records");
}

/// THE DURABILITY PROOF FOR THE `task` / `task_event` PLANE KINDS (the A2A task store), OVER THE REAL
/// PLUGIN PATH.
#[test]
fn task_store_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore};

    let path = plugin_path();
    let Some(admin_url) = postgres_url() else {
        return;
    };

    let db = TempDb::create(&admin_url, "spg_task_durability");
    let cfg = cfg(&db.url());
    let direct = common::linked(&cfg).expect("connect directly to verify");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let t_live = format!("task_abi_live_{stamp}");
    let t_done = format!("task_abi_done_{stamp}");
    const BASE_TS: u64 = 4_000_000_000;

    let task = |id: &str, state: &str, ts: u64, cursor: u64, d: PlaneDisposition| PlaneRecord {
        kind: "task".into(),
        id: id.into(),
        parent: None,
        seq: 0,
        ts,
        disposition: d,
        body: plane_body(serde_json::json!({
            "task_id": id,
            "context_id": format!("ctx-{id}"),
            "principal": "vk_task_abi",
            "state": state,
            "artifact_cursor": cursor,
            "updated_at": ts,
        })),
    };
    let event = |id: &str, seq: u64, kind: &str, prev: &str, hash: &str| PlaneRecord {
        kind: "task_event".into(),
        id: id.into(),
        parent: Some(id.into()),
        seq,
        ts: BASE_TS + seq,
        disposition: PlaneDisposition::Active,
        body: plane_body(serde_json::json!({
            "seq": seq, "prev_hash": prev, "hash": hash,
            "content": { "kind": kind, "request_id": format!("req-{seq}") },
        })),
    };
    let events = |store: &dyn RecordStore, id: &str| -> Vec<serde_json::Value> {
        store
            .list_plane_records("task_event", &PlaneSelector::Parent(id.to_string().into()))
            .expect("list_plane_records over the ABI")
            .iter()
            .map(|b| plane_decode(b))
            .collect()
    };
    let interrupted = task(
        &t_live,
        "input-required",
        BASE_TS + 20,
        9,
        PlaneDisposition::Active,
    );

    {
        let store = common::dropped_at(&path, &cfg)
            .expect("the postgres plugin must load over the real ABI");
        store
            .upsert_plane_record(
                task(
                    &t_live,
                    "working",
                    BASE_TS + 100,
                    3,
                    PlaneDisposition::Active,
                )
                .view(),
            )
            .expect("upsert_plane_record over the ABI");

        store
            .upsert_plane_record(interrupted.view())
            .expect("upsert_plane_record over the ABI");
        store
            .upsert_plane_record(
                task(
                    &t_done,
                    "completed",
                    BASE_TS + 50,
                    1,
                    PlaneDisposition::Terminal,
                )
                .view(),
            )
            .expect("upsert_plane_record over the ABI");
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_plane_record(event(&t_live, seq, "task.working", prev, hash).view())
                .expect("append_plane_record over the ABI");
        }
        store
            .append_plane_record(event(&t_done, 1, "task.completed", "", "d1").view())
            .expect("append_plane_record over the ABI");
        drop(store);
    }

    let store = common::dropped_at(&path, &cfg)
        .expect("the postgres plugin must load again over the real ABI");

    let got = store
        .get_plane_record("task", &t_live)
        .expect("get_plane_record")
        .expect(
            "an in-flight task must survive the unload/reload over the plugin ABI; got None back, \
             which is exactly the accept-and-keep-nothing shape of the trait default",
        );
    assert_eq!(
        got, interrupted.body,
        "the body must round-trip byte-for-byte, and it must be the SECOND write: the upsert keys \
         on (kind, id)"
    );
    assert!(
        store
            .get_plane_record("task", &format!("task_abi_nonexistent_{stamp}"))
            .expect("a point-read of an unknown id is not an error")
            .is_none(),
        "an unknown task id reads back None, not an error"
    );

    let mut mine: Vec<String> = store
        .list_plane_records("task", &PlaneSelector::All)
        .expect("list_plane_records")
        .iter()
        .map(|b| {
            plane_decode(b)["task_id"]
                .as_str()
                .unwrap_or("")
                .to_string()
        })
        .filter(|id| *id == t_live || *id == t_done)
        .collect();
    mine.sort();
    assert_eq!(
        mine,
        vec![t_done.clone(), t_live.clone()],
        "the listing is UNFILTERED — the terminal row is returned too — and the upserted task \
         appears exactly ONCE"
    );

    let chain = events(&store, &t_live);
    assert_eq!(
        chain
            .iter()
            .map(|e| e["seq"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-task provenance chain must survive the reload, oldest-first by seq"
    );
    for w in chain.windows(2) {
        assert_eq!(w[1]["prev_hash"], w[0]["hash"], "the chain must still link");
    }
    assert_eq!(chain[2]["content"]["request_id"], "req-3");
    assert_eq!(
        events(&store, &t_done).len(),
        1,
        "one task's chain must not carry another's events"
    );

    store
        .append_plane_record(event(&t_live, 3, "task.working", "h2", "h3").view())
        .expect("an identical replay is Ok");
    assert!(store
        .append_plane_record(event(&t_live, 3, "task.working", "h2", "rewritten").view())
        .is_err());
    assert_eq!(events(&store, &t_live).len(), 3, "no 4th event");

    assert_eq!(
        store
            .purge_plane_records("task", BASE_TS + 100, busbar_contract::records::Retention::TerminalOnly)
            .expect("purge_plane_records_before"),
        1,
        "only the TERMINAL row older than the cutoff goes; an active task is never swept no matter \
         how old"
    );
    assert!(store
        .get_plane_record("task", &t_done)
        .expect("get_plane_record")
        .is_none());
    assert!(store
        .get_plane_record("task", &t_live)
        .expect("get_plane_record")
        .is_some());
    assert!(
        events(&store, &t_done).is_empty(),
        "a swept task's chain must go with it or it is unbounded forever"
    );
    drop(store);

    let direct_task = RecordStore::get_plane_record(&direct, "task", &t_live)
        .expect("get_plane_record via the direct connection")
        .expect("the task must be physically present in Postgres, not just cached in-process");
    let direct_task = plane_decode(&direct_task);
    assert_eq!(direct_task["artifact_cursor"], 9);
    assert_eq!(direct_task["state"], "input-required");
    assert_eq!(events(&direct, &t_live).len(), 3);

    RecordStore::upsert_plane_record(
        &direct,
        task(
            &t_live,
            "canceled",
            BASE_TS + 20,
            9,
            PlaneDisposition::Terminal,
        )
        .view(),
    )
    .expect("clean up this run's task");
    assert_eq!(
        RecordStore::purge_plane_records_before(&direct, "task", i64::MAX as u64)
            .expect("clean up this run's rows"),
        1,
        "exactly the surviving task is swept"
    );
    assert!(
        events(&direct, &t_live).is_empty(),
        "the remaining chain is cascaded too"
    );
}

/// THE DURABILITY PROOF FOR THE TRUST STATE — the `demotion` kind and the single-use `ask` token
/// ledger — OVER THE REAL PLUGIN PATH.
#[test]
fn trust_state_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore};

    let path = plugin_path();
    let url = std::env::var("BUSBAR_TEST_POSTGRES_URL").unwrap_or_else(|_| {
        panic!(
            "BUSBAR_TEST_POSTGRES_URL is unset, and this case must not skip: it is the only \
             over-the-ABI proof that a demotion and a spent approval survive a restart on this \
             backend, and both fail SILENTLY when unrelayed"
        )
    });
    let cfg = cfg(&url);

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let srv_demoted = format!("srv_abi_demoted_{stamp}");
    let srv_cleared = format!("srv_abi_cleared_{stamp}");
    let nonce_restart = format!("nonce_abi_restart_{stamp}");
    let nonce_fleet = format!("nonce_abi_fleet_{stamp}");
    let nonce_fresh = format!("nonce_abi_fresh_{stamp}");
    const NOW: u64 = 4_000_000_000;

    let ask_kind = format!("ask_abi_{stamp}");

    let demotion = |server: &str, reason: &str, at: u64| PlaneRecord {
        kind: "demotion".into(),
        id: server.into(),
        parent: None,
        seq: 0,
        ts: at,
        disposition: PlaneDisposition::Active,
        body: plane_body(serde_json::json!({
            "server": server, "reason": reason, "recorded_at": at,
        })),
    };
    let demotions = |store: &dyn RecordStore| -> Vec<(String, String)> {
        store
            .list_plane_records("demotion", &PlaneSelector::All)
            .expect("list_plane_records")
            .iter()
            .map(|b| plane_decode(b))
            .map(|v| {
                (
                    v["server"].as_str().unwrap_or("").to_string(),
                    v["reason"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    };

    {
        let store = common::dropped_at(&path, &cfg)
            .expect("the postgres plugin must load over the real ABI");
        store
            .upsert_plane_record(demotion(&srv_demoted, "tool-drift", NOW).view())
            .expect("upsert_plane_record");
        store
            .upsert_plane_record(demotion(&srv_demoted, "digest-mismatch", NOW + 10).view())
            .expect("upsert_plane_record");
        store
            .upsert_plane_record(demotion(&srv_cleared, "tool-drift", NOW + 20).view())
            .expect("upsert_plane_record");
        store
            .delete_plane_record("demotion", &srv_cleared)
            .expect("a later agreeing observation clears the quarantine");
        assert!(
            store
                .redeem_plane_token(&ask_kind, &nonce_restart, u64::MAX, NOW)
                .expect("redeem_plane_token"),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        drop(store);
    }

    let store = common::dropped_at(&path, &cfg)
        .expect("the postgres plugin must load again over the real ABI");

    let mine: Vec<(String, String)> = demotions(&store)
        .into_iter()
        .filter(|(s, _)| *s == srv_demoted || *s == srv_cleared)
        .collect();
    assert_eq!(
        mine,
        vec![(srv_demoted.clone(), "digest-mismatch".to_string())],
        "the boot read must put the recorded quarantine back in force — at its LATEST reason, and \
         without the one a later agreeing observation cleared"
    );

    assert!(
        !store
            .redeem_plane_token(&ask_kind, &nonce_restart, u64::MAX, NOW + 1)
            .expect("redeem_plane_token"),
        "a restart handed a spent approval back over the plugin ABI"
    );

    let node_b = common::dropped_at(&path, &cfg)
        .expect("a second node loads the same plugin against the same database");
    assert!(store
        .redeem_plane_token(&ask_kind, &nonce_fleet, u64::MAX, NOW + 2)
        .expect("redeem_plane_token"));
    assert!(
        !node_b
            .redeem_plane_token(&ask_kind, &nonce_fleet, u64::MAX, NOW + 3)
            .expect("redeem_plane_token"),
        "a second node redeemed an approval the first already spent"
    );

    assert!(
        node_b
            .redeem_plane_token(&ask_kind, &nonce_fresh, u64::MAX, NOW + 4)
            .expect("redeem_plane_token"),
        "a freshly minted approval is not the one that was spent"
    );

    let direct = common::linked(&cfg).expect("connect directly to verify and clean up");
    assert!(
        demotions(&direct)
            .iter()
            .any(|(s, r)| *s == srv_demoted && r == "digest-mismatch"),
        "the demotion must be physically present in Postgres, not merely cached in the plugin"
    );
    assert!(
        !RecordStore::redeem_plane_token(&direct, &ask_kind, &nonce_restart, u64::MAX, NOW + 5)
            .expect("redeem_plane_token via the direct connection"),
        "the spent-token row must be physically present in Postgres"
    );

    RecordStore::delete_plane_record(&direct, "demotion", &srv_demoted)
        .expect("clean up this run's demotion");
}
