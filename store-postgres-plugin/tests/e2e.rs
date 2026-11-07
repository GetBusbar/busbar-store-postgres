// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Actual file-drop boot plus native persistence across plugin unload/reload.
//! Business policy is exercised through the core HTTP scenario in admin_api_e2e.

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
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='busbar_persistence_v4' AND table_name='metadata')",
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
        "a real busbar boot with the file-dropped postgres plugin must create the native metadata table \
         (via primitive Store readiness) within 15s -- proof the real dlopen+connect path executed \
         during boot, not a no-op\n--- boot output ---\n{}",
        guard.output()
    );

    let mut raw = postgres::Client::connect(&url, postgres::NoTls)
        .expect("raw connect to the fresh database");
    let facts: Vec<u8> = raw
        .query_one("SELECT facts FROM busbar_persistence_v4.metadata", &[])
        .expect("native metadata committed")
        .get(0);
    let facts = busbar_contract::abi::sdk::store::v4::metadata::decode(&facts).unwrap();
    assert_ne!(facts.dataset.0, [0; 16]);

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
        err.contains("postgres") && (err.contains("ready failed") || err.contains("open failed")),
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

use busbar_contract::persistence::*;
use std::sync::Arc;
fn body(value: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}
fn raw_json(url: &str, at: &Address) -> serde_json::Value {
    serde_json::from_slice(&common::raw_value(url, at).unwrap()).unwrap()
}
fn page(store: &busbar_plugin_loader::store_v4::LoadedPersistence, namespace: u8) -> Page {
    common::run(store.scan(Arc::new(Scan {
        dataset: store.info().dataset,
        namespace: NamespaceId([namespace; 16]),
        prefix: vec![],
        after: None,
        generation: None,
        allow_change: false,
        max_items: 100,
        max_bytes: 1 << 20,
    })))
    .unwrap()
}
#[test]
fn mcp_call_log_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    let Some(admin) = postgres_url() else { return };
    let database = TempDb::create(&admin, "spg_calls");
    let url = database.url();
    let settings = cfg(&url);
    let store = common::dropped(&settings).unwrap();
    common::initialize(&store);
    let mut last = None;
    for seq in 1u64..=3 {
        let at = common::address(30, &seq.to_be_bytes());
        let bytes = body(
            serde_json::json!({"seq":seq,"prev_hash":if seq==1 {String::new()} else {format!("h{}",seq-1)},"hash":format!("h{seq}"),"content":{"server":"srv","tool":"srv_read_file","outcome":"dispatched","tool_digest":format!("sha256:tool{seq}"),"pin_generation":3,"request_id":format!("req-{seq}")}}),
        );
        let candidate = common::prepare(
            &store,
            seq as u128 + 1,
            vec![Predicate {
                address: at.clone(),
                expected: ExpectedValue::Absent,
            }],
            vec![common::put(at, &bytes)],
        );
        assert!(matches!(
            common::run(store.commit(candidate.clone())).unwrap(),
            Decision::Applied(_)
        ));
        last = Some(candidate);
    }
    assert!(matches!(
        common::commit(
            &store,
            5,
            vec![],
            vec![common::put(
                common::address(31, &1u64.to_be_bytes()),
                b"other principal"
            )]
        ),
        Decision::Applied(_)
    ));
    let info = store.info();
    drop(store);
    let store = common::dropped(&settings).unwrap();
    assert_eq!(store.info(), info);
    assert_eq!(
        page(&store, 30)
            .rows
            .iter()
            .map(|(at, _)| u64::from_be_bytes(at.key.as_slice().try_into().unwrap()))
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let calls: Vec<_> = (1u64..=3)
        .map(|seq| raw_json(&url, &common::address(30, &seq.to_be_bytes())))
        .collect();
    for pair in calls.windows(2) {
        assert_eq!(pair[1]["prev_hash"], pair[0]["hash"]);
    }
    assert_eq!(calls[2]["content"]["tool_digest"], "sha256:tool3");
    assert_eq!(calls[2]["content"]["request_id"], "req-3");
    assert_eq!(calls[2]["content"]["outcome"], "dispatched");
    assert_eq!(calls[1]["content"]["pin_generation"], 3);
    assert_eq!(page(&store, 31).rows.len(), 1);
    assert!(matches!(
        common::run(store.commit(last.unwrap())).unwrap(),
        Decision::Applied(_)
    ));
    assert!(matches!(
        common::commit(
            &store,
            4,
            vec![],
            vec![common::put(
                common::address(30, &3u64.to_be_bytes()),
                b"FORKED"
            )]
        ),
        Decision::OpIdConflict
    ));
    assert_eq!(page(&store, 30).rows.len(), 3);
    assert!(matches!(
        common::commit(
            &store,
            6,
            vec![],
            vec![Mutation::Delete(common::address(30, &1u64.to_be_bytes()))]
        ),
        Decision::Applied(_)
    ));
    let direct = common::linked(&settings).unwrap();
    assert_eq!(
        page(&direct, 30)
            .rows
            .iter()
            .map(|(at, _)| u64::from_be_bytes(at.key.as_slice().try_into().unwrap()))
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(
        raw_json(&url, &common::address(30, &3u64.to_be_bytes()))["hash"],
        "h3"
    );
}
#[test]
fn task_store_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    let Some(admin) = postgres_url() else { return };
    let database = TempDb::create(&admin, "spg_tasks");
    let url = database.url();
    let settings = cfg(&url);
    let store = common::dropped(&settings).unwrap();
    common::initialize(&store);
    let live = common::address(32, b"live");
    let done = common::address(32, b"done");
    let original = body(
        serde_json::json!({"task_id":"live","state":"working","artifact_cursor":3,"updated_at":4000000100u64}),
    );
    let interrupted = body(
        serde_json::json!({"task_id":"live","state":"input-required","artifact_cursor":9,"updated_at":4000000020u64}),
    );
    assert!(matches!(
        common::commit(
            &store,
            2,
            vec![],
            vec![common::put(live.clone(), &original)]
        ),
        Decision::Applied(_)
    ));
    assert!(matches!(
        common::commit(
            &store,
            3,
            vec![],
            vec![
                common::put(live.clone(), &interrupted),
                common::put(
                    done.clone(),
                    &body(serde_json::json!({"task_id":"done","state":"completed"}))
                )
            ]
        ),
        Decision::Applied(_)
    ));
    for seq in 1u64..=3 {
        assert!(matches!(
            common::commit(
                &store,
                seq as u128 + 3,
                vec![],
                vec![common::put(
                    common::address(33, &seq.to_be_bytes()),
                    &body(
                        serde_json::json!({"seq":seq,"prev_hash":if seq==1 {String::new()} else {format!("h{}",seq-1)},"hash":format!("h{seq}"),"content":{"kind":"task.working","request_id":format!("req-{seq}")}})
                    )
                )]
            ),
            Decision::Applied(_)
        ));
    }
    assert!(matches!(
        common::commit(
            &store,
            7,
            vec![],
            vec![common::put(
                common::address(34, &1u64.to_be_bytes()),
                b"done event"
            )]
        ),
        Decision::Applied(_)
    ));
    drop(store);
    let store = common::dropped(&settings).unwrap();
    assert!(common::present(&store, live.clone()));
    assert!(!common::present(&store, common::address(32, b"unknown")));
    assert_eq!(common::raw_value(&url, &live).unwrap(), interrupted);
    assert_eq!(page(&store, 32).rows.len(), 2);
    assert_eq!(page(&store, 33).rows.len(), 3);
    assert_eq!(page(&store, 34).rows.len(), 1);
    let events: Vec<_> = (1u64..=3)
        .map(|seq| raw_json(&url, &common::address(33, &seq.to_be_bytes())))
        .collect();
    for pair in events.windows(2) {
        assert_eq!(pair[1]["prev_hash"], pair[0]["hash"]);
    }
    assert_eq!(events[2]["content"]["request_id"], "req-3");
    // Core supplies the terminal selection and atomic cascade; the backend sees only these effects.
    assert!(matches!(
        common::commit(
            &store,
            8,
            vec![],
            vec![
                Mutation::Delete(done.clone()),
                Mutation::DeleteRange {
                    namespace: NamespaceId([34; 16]),
                    prefix: vec![],
                    exact_key_length: 8
                }
            ]
        ),
        Decision::Applied(_)
    ));
    assert!(common::present(&store, live.clone()));
    assert!(!common::present(&store, done));
    assert!(page(&store, 34).rows.is_empty());
    assert!(matches!(
        common::commit(
            &store,
            9,
            vec![],
            vec![
                Mutation::Delete(live.clone()),
                Mutation::DeleteRange {
                    namespace: NamespaceId([33; 16]),
                    prefix: vec![],
                    exact_key_length: 8
                }
            ]
        ),
        Decision::Applied(_)
    ));
    let direct = common::linked(&settings).unwrap();
    assert!(!common::present(&direct, live));
    assert!(page(&direct, 33).rows.is_empty());
}
#[test]
fn trust_state_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    let Some(admin) = postgres_url() else { return };
    let database = TempDb::create(&admin, "spg_trust");
    let url = database.url();
    let settings = cfg(&url);
    let store = common::dropped(&settings).unwrap();
    common::initialize(&store);
    let demoted = common::address(35, b"demoted");
    let cleared = common::address(35, b"cleared");
    let nonce = common::address(36, b"restart");
    assert!(matches!(
        common::commit(
            &store,
            2,
            vec![],
            vec![
                common::put(demoted.clone(), b"tool-drift"),
                common::put(cleared.clone(), b"tool-drift")
            ]
        ),
        Decision::Applied(_)
    ));
    assert!(matches!(
        common::commit(
            &store,
            3,
            vec![],
            vec![
                common::put(demoted.clone(), b"digest-mismatch"),
                Mutation::Delete(cleared.clone())
            ]
        ),
        Decision::Applied(_)
    ));
    assert!(matches!(
        common::commit(
            &store,
            4,
            vec![Predicate {
                address: nonce.clone(),
                expected: ExpectedValue::Absent
            }],
            vec![common::put(nonce.clone(), b"spent")]
        ),
        Decision::Applied(_)
    ));
    drop(store);
    let store = common::dropped(&settings).unwrap();
    assert_eq!(page(&store, 35).rows.len(), 1);
    assert_eq!(
        common::raw_value(&url, &demoted).unwrap(),
        b"digest-mismatch"
    );
    assert!(!common::present(&store, cleared));
    assert!(matches!(
        common::commit(
            &store,
            5,
            vec![Predicate {
                address: nonce.clone(),
                expected: ExpectedValue::Absent
            }],
            vec![common::put(nonce.clone(), b"spent")]
        ),
        Decision::ConditionConflict
    ));
    let node_b = common::dropped(&settings).unwrap();
    let fleet = common::address(36, b"fleet");
    assert!(matches!(
        common::commit(
            &store,
            6,
            vec![Predicate {
                address: fleet.clone(),
                expected: ExpectedValue::Absent
            }],
            vec![common::put(fleet.clone(), b"spent")]
        ),
        Decision::Applied(_)
    ));
    assert!(matches!(
        common::commit(
            &node_b,
            7,
            vec![Predicate {
                address: fleet.clone(),
                expected: ExpectedValue::Absent
            }],
            vec![common::put(fleet, b"spent")]
        ),
        Decision::ConditionConflict
    ));
    assert!(matches!(
        common::commit(
            &node_b,
            8,
            vec![Predicate {
                address: common::address(36, b"fresh"),
                expected: ExpectedValue::Absent
            }],
            vec![common::put(common::address(36, b"fresh"), b"spent")]
        ),
        Decision::Applied(_)
    ));
    let direct = common::linked(&settings).unwrap();
    assert!(common::present(&direct, demoted));
    assert!(common::present(&direct, nonce));
}
