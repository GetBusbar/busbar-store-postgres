// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Real admin HTTP install and key/credential issuance against the native PostgreSQL door.
//! HTTP asserts core semantics; an independent native-record read witnesses persistence.

mod common;
use common::temp_db::TempDb;

use base64::Engine as _;
use common::{build_real_binaries, plugin_path, postgres_url, E2E_RELEASE_PRIVKEY};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an
/// explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// RAII guard for a spawned child process: kills and reaps it on drop, including when a panic
/// unwinds partway through the test. Same pattern as `e2e.rs`'s own `ChildGuard`.
///
/// It also owns the path this child's stdout+stderr were redirected to. THAT IS LOAD-BEARING, not
/// bookkeeping. This test used to spawn busbar with `.stderr(Stdio::null())`, so when a boot failed
/// the only thing anyone ever saw was
///
///     boot #1 exited before its admin listener came up (status: exit status: 1)
///
/// -- an exit code and nothing else, with busbar's own diagnosis of WHY thrown away at the point it
/// was produced. qa-gate run 31059945604 lost this leg to a fail-closed config refusal that busbar
/// printed in full and this harness deleted; the actual cause had to be recovered from a DIFFERENT
/// job's logs. A test that can only report "it exited" cannot be debugged from its own output, so
/// every boot now logs to a file and every failure path prints that file.
///
/// A FILE, not `Stdio::piped()`: nothing here reads the pipe while the child runs, so a child that
/// out-talked the pipe buffer would block forever on write and turn a clean failure into a hang.
struct ChildGuard(Child, PathBuf);

impl ChildGuard {
    /// The child's captured output, formatted for a panic message. Never panics itself: this runs
    /// on the failure path, where a second, unrelated panic would bury the first.
    fn output(&self) -> String {
        match std::fs::read_to_string(&self.1) {
            Ok(s) if s.trim().is_empty() => "  (the child produced no output)".to_string(),
            Ok(s) => s
                .lines()
                .map(|l| format!("  | {l}"))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(e) => format!("  (could not read {}: {e})", self.1.display()),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `busbar` with its stdout+stderr captured to `log`, and wrap it in a `ChildGuard` that
/// knows where to find them.
fn spawn_busbar(cmd: &mut Command, log: PathBuf, what: &str) -> ChildGuard {
    let out = std::fs::File::create(&log)
        .unwrap_or_else(|e| panic!("create the {what} log at {}: {e}", log.display()));
    let err = out
        .try_clone()
        .unwrap_or_else(|e| panic!("dup the {what} log handle: {e}"));
    let child = cmd
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn the real busbar for {what}: {e}"));
    ChildGuard(child, log)
}

/// Reserve a free loopback port for the admin listener (bind-then-drop; the standard, small-TOCTOU
/// pattern for handing a port to a spawned external process — the same trade-off `listen:
/// "127.0.0.1:0"` in `e2e.rs` accepts for the data-plane listener, except busbar itself doesn't
/// report back which port it took for `:0`, so the admin listener needs a port this test can name
/// in the config file up front).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The disposable database owns all records; this guard removes only test files.
struct RunCleanup {
    work: PathBuf,
}
impl Drop for RunCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.work);
    }
}

/// Poll `http://127.0.0.1:{port}/api/v1/admin/plugins` (any admin GET works — we just need a TCP
/// accept + HTTP response) until the admin listener is up, or the child has already exited.
fn wait_for_admin_listener(
    client: &reqwest::blocking::Client,
    admin_base: &str,
    token: &str,
    guard: &mut ChildGuard,
    what: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .get(format!("{admin_base}/plugins"))
            .header("x-admin-token", token)
            .send()
            .is_ok()
        {
            return;
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!(
                "{what} exited before its admin listener came up (status: {status})\n\
                 --- {what} output ---\n{}",
                guard.output()
            );
        }
        if Instant::now() >= deadline {
            panic!(
                "{what}'s admin listener never came up within 15s\n\
                 --- {what} output ---\n{}",
                guard.output()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// THE REAL END-TO-END PROOF: install the real cdylib over the real admin API, restart onto it
/// (the only real activation mechanism busbar exposes for a store-kind plugin), mint a virtual key
/// and AWS credential through the running instance over the same admin API, and independently
/// confirm both rows landed in real Postgres.
#[test]
fn install_over_admin_api_then_mint_a_key_and_verify_postgres_directly() {
    let Some(admin_url) = postgres_url() else {
        return;
    };
    let database = TempDb::create(&admin_url, "spg_admin");
    let url = database.url();

    let so_path = plugin_path();

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-pg-adminapi-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _run_cleanup = RunCleanup { work: work.clone() };
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    let tarball_path = work.join("store-postgres.tar.gz");
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
            "admin-api e2e proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball_path.to_str().unwrap(),
        ])
        .env("BUSBAR_SIGN_KEY", E2E_RELEASE_PRIVKEY)
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");
    let tarball_bytes = std::fs::read(&tarball_path).unwrap();
    let file = "store-postgres.tar.gz";

    let admin_port = free_port();
    let admin_token = "spg-adminapi-e2e-token";
    let admin_base = format!("http://127.0.0.1:{admin_port}/api/v1/admin");
    let client = reqwest::blocking::Client::new();

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();
    let providers_and_common = format!(
        "listen: \"127.0.0.1:0\"\n\
         admin_listen: \"127.0.0.1:{admin_port}\"\n\
         plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
         identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         auth:\n  chain: [keys]\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth: [admin-tokens]\n\
             credentials:\n  at_rest:\n    key: {{ env: BUSBAR_SIGNING_KEY }}\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );

    let config1 = work.join("config1.yaml");
    std::fs::write(
        &config1,
        format!("{providers_and_common}store:\n  module: memory\n"),
    )
    .unwrap();

    let mut guard1 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config1)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env(
                "MOCK_KEY",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot1.log"),
        "boot #1 (memory store, admin listener up)",
    );
    wait_for_admin_listener(&client, &admin_base, admin_token, &mut guard1, "boot #1");

    let install_body = serde_json::json!({
        "file": file,
        "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball_bytes),
    });
    let install_resp = client
        .post(format!("{admin_base}/plugins"))
        .header("x-admin-token", admin_token)
        .json(&install_body)
        .send()
        .unwrap();
    let install_status = install_resp.status();
    let install_body_text = install_resp.text().unwrap_or_default();
    assert_eq!(
        install_status.as_u16(),
        201,
        "plugin install must succeed over the real admin API: {install_body_text}"
    );
    assert!(
        plugins_dir.join(file).exists(),
        "the admin API's own install handler must have written the tarball to plugins.dir \
         (this test never writes it there itself)"
    );

    let unauth_file = "store-postgres-unauthorized.tar.gz";
    let unauth_body = serde_json::json!({
        "file": unauth_file,
        "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball_bytes),
    });
    match client
        .post(format!("{admin_base}/plugins"))
        .json(&unauth_body)
        .send()
    {
        Ok(unauth) => assert_eq!(
            unauth.status().as_u16(),
            401,
            "plugin install without x-admin-token must be rejected with 401, not accepted"
        ),
        Err(_error) => {
            let alive = client
                .get(format!("{admin_base}/plugins?type=store"))
                .header("x-admin-token", admin_token)
                .send()
                .expect("the admin surface must still answer after rejecting the unauthenticated install; a dead server is not evidence that the token guard held");
            assert_eq!(
                alive.status().as_u16(),
                200,
                "an authenticated read must still succeed after the rejected unauthenticated write"
            );
        }
    }

    assert!(
        !plugins_dir.join(unauth_file).exists(),
        "an unauthenticated install must not write a tarball into plugins.dir"
    );
    let after_unauth: serde_json::Value = client
        .get(format!("{admin_base}/plugins?type=store"))
        .header("x-admin-token", admin_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(
        !after_unauth["items"]
            .as_array()
            .expect("plugins list has items")
            .iter()
            .any(|p| p["target"] == unauth_file),
        "an unauthenticated install must not appear in the real catalog"
    );

    let list: serde_json::Value = client
        .get(format!("{admin_base}/plugins?type=store"))
        .header("x-admin-token", admin_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let items = list["items"].as_array().expect("plugins list has items");
    assert!(
        items
            .iter()
            .any(|p| p["target"] == file && p["name"] == "busbar-store-postgres"),
        "the installed postgres plugin must be listed in the real catalog: {items:?}"
    );

    drop(guard1);

    let retained = std::fs::read(plugins_dir.join(file)).expect("read the admin-installed archive");
    assert_eq!(
        retained, tarball_bytes,
        "the admin install retains the exact uploaded signed archive"
    );
    let archive_pin = busbar_contract::redacted::sha256_hex(&retained);
    let pinned_common = providers_and_common.replacen(
        "  trust:\n",
        &format!("  fetch:\n    - url: \"https://plugins.example/{file}\"\n      sha256: \"{archive_pin}\"\n  trust:\n"),
        1,
    );

    let config2 = work.join("config2.yaml");
    std::fs::write(
        &config2,
        format!("{pinned_common}store:\n  module: postgres\n  settings: {{ url: \"{url}\" }}\n"),
    )
    .unwrap();

    let mut guard2 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config2)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env(
                "MOCK_KEY",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot2.log"),
        "boot #2 (postgres store, the admin-installed plugin)",
    );

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
        if let Ok(Some(status)) = guard2.0.try_wait() {
            panic!(
                "boot #2 exited before creating the postgres schema (status: {status})\n\
                 --- boot #2 output ---\n{}",
                guard2.output()
            );
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        booted,
        "boot #2, restarted onto the admin-installed postgres plugin, must reach a migrated \
         native metadata table within 15s\n\
         --- boot #2 output ---\n{}",
        guard2.output()
    );
    wait_for_admin_listener(&client, &admin_base, admin_token, &mut guard2, "boot #2");

    let mint_body = serde_json::json!({
        "name": "spg-adminapi-e2e-key",
        "labels": {},
        "issue_aws_credential": true,
    });
    let mint_resp = client
        .post(format!("{admin_base}/keys"))
        .header("x-admin-token", admin_token)
        .json(&mint_body)
        .send()
        .unwrap();
    let mint_status = mint_resp.status();
    let mint_json: serde_json::Value = mint_resp.json().unwrap();
    assert_eq!(
        mint_status.as_u16(),
        201,
        "minting a key over the real admin API must succeed: {mint_json}"
    );
    let minted_id = mint_json["id"]
        .as_str()
        .expect("minted key response has an id")
        .to_string();
    let access_key_id = mint_json["aws_access_key_id"]
        .as_str()
        .expect("issue_aws_credential:true must return an aws_access_key_id")
        .to_string();
    assert!(
        mint_json["aws_secret_access_key"].is_string(),
        "issue_aws_credential:true must also return an aws_secret_access_key: {mint_json}"
    );

    drop(guard2);
    let mut guard3 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config2)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env(
                "MOCK_KEY",
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot3.log"),
        "boot #3 (reopen issued identity)",
    );
    wait_for_admin_listener(&client, &admin_base, admin_token, &mut guard3, "boot #3");
    let response = client
        .get(format!("{admin_base}/keys/{minted_id}"))
        .header("x-admin-token", admin_token)
        .send()
        .unwrap();
    assert!(response.status().is_success());
    let key: serde_json::Value = response.json().unwrap();
    assert_eq!(key["name"], "spg-adminapi-e2e-key");
    assert_eq!(key["enabled"], true);
    let mut raw = postgres::Client::connect(&url, postgres::NoTls)
        .expect("independent native persistence witness");
    // Exact canonical schema from kernel governance/persistence/identity.rs:
    // identity namespace v1; keys::framed tags K/C; JSON {version:1,record:...}.
    // Confidential namespace rows remain opaque and are never parsed.
    let namespace = b"busbar.identity1".as_slice();
    let framed = |tag: u8, id: &str| {
        let mut key = vec![tag];
        key.extend_from_slice(&(id.len() as u32).to_be_bytes());
        key.extend_from_slice(id.as_bytes());
        key
    };
    let stored_key: Vec<u8> = raw
        .query_one(
            "SELECT value FROM busbar_persistence_v4.records WHERE namespace=$1 AND key=$2",
            &[&namespace, &framed(b'K', &minted_id)],
        )
        .unwrap()
        .get(0);
    let stored_key: serde_json::Value =
        serde_json::from_slice(&stored_key).expect("canonical key JSON");
    assert_eq!(stored_key["version"], 1);
    assert_eq!(stored_key["record"]["id"], minted_id);
    assert_eq!(stored_key["record"]["name"], "spg-adminapi-e2e-key");
    assert_eq!(stored_key["record"]["enabled"], true);
    let credentials:Vec<serde_json::Value>=raw.query("SELECT key,value FROM busbar_persistence_v4.records WHERE namespace=$1 AND substring(key FROM 1 FOR 1)=$2",&[&namespace, &b"C".as_slice()]).unwrap().into_iter().map(|row| {
        let key:Vec<u8>=row.get(0);let bytes:Vec<u8>=row.get(1);
        let value:serde_json::Value=serde_json::from_slice(&bytes).expect("canonical credential metadata JSON");
        assert_eq!(value["version"],1);
        assert_eq!(key,framed(b'C',value["record"]["id"].as_str().unwrap()));
        value
    }).collect();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0]["record"]["key_id"], minted_id);
    assert_eq!(credentials[0]["record"]["kind"], "sigv4");
    assert_eq!(credentials[0]["record"]["public_id"], access_key_id);
    drop(guard3);
    drop(raw);
}
