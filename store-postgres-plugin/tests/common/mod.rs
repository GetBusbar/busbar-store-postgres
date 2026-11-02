// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store's two doors, as this repo's tests open them: COMPILED IN (the logic crate's `door`,

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of, Bind, ConnTable, DispatchConfig, Dispatcher,
    LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;
#[path = "../../../store-postgres/tests-support/postgres_io.rs"]
pub mod postgres_io;

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
pub fn cdylib() -> PathBuf {
    plugin_path()
}

/// The Statement rendering the signed manifest states: the linked door's own (the cdylib is the
pub fn stated() -> Vec<u8> {
    rendering_of(busbar_store_postgres::door).expect("the store renders its Statement")
}

/// A fresh `op_id` for every bridge write: a node half no other open (in this run or an earlier
pub fn mint() -> busbar_contract::abi::store::OpId {
    static NODE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        nanos ^ (u64::from(std::process::id()) << 40)
    });
    busbar_contract::abi::store::OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// The instance's binding: its connections over the loader's test connection table (plain TCP),
pub fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("store-postgres-test"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Host(postgres_io::host(d.conn_waker(), Default::default())),
    }
}

/// The store through its COMPILED-IN door, opened on `settings`.
pub fn linked(settings: &str) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(busbar_store_postgres::door).map_err(|e| e.to_string())?;
    let p = load_linked::<Store>(&row, bind(&d)).map_err(|e| e.to_string())?;
    LoadedStore::open(p, d, settings.as_bytes(), mint)
}

/// The library at `path` through the DROPPED-IN door, admitted against [`stated`] and opened on
pub fn dropped_at(path: &Path, settings: &str) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_dropped::<Store>(path, &stated(), bind(&d)).map_err(|e| e.to_string())?;
    LoadedStore::open(p, d, settings.as_bytes(), mint)
}

/// This crate's cdylib through the DROPPED-IN door.
pub fn dropped(settings: &str) -> Result<LoadedStore, String> {
    dropped_at(&cdylib(), settings)
}

pub fn postgres_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_POSTGRES_URL is unset under CI: the postgres:16 service container must \
                 provision it. Refusing to silently skip the only real-install-path coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the live-Postgres e2e tests");
            None
        }
    }
}

/// The actual own-library artifact built for this run. CI supplies its absolute path.
/// Developers build the cdylib into Cargo's profile directory before running these tests.
pub fn plugin_path() -> PathBuf {
    let artifact = match std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
            path
        }
        None => {
            let exe = std::env::current_exe().expect("test executable");
            let profile = exe
                .parent()
                .and_then(Path::parent)
                .expect("Cargo profile directory");
            profile.join(busbar_plugin_loader::plugin_library_filename(
                "busbar_store_postgres_plugin",
            ))
        }
    };
    assert!(artifact.is_file(),"actual freshly built Postgres cdylib missing at {}; build busbar-store-postgres-plugin and set BUSBAR_PLUGIN_CDYLIB to its absolute path",artifact.display());
    artifact
}

/// The busbar checkout the real binaries are built from: `BUSBAR_CHECKOUT` when set, else a sibling
pub fn busbar_root() -> PathBuf {
    let root = std::env::var_os("BUSBAR_CHECKOUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../busbar"));
    root.canonicalize().unwrap_or_else(|e| {
        panic!(
            "no busbar checkout at {} ({e}): set BUSBAR_CHECKOUT to a checkout of GetBusbar/busbar \
             at the .busbar-ref rev, or check it out beside this repo",
            root.display()
        )
    })
}

/// Build (once, cached by cargo) and return the path to the real `busbar` binary and the real
pub fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbar_root();

    for args in [
        &[
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--target-dir",
            "target",
            "--bin",
            "busbar",
        ][..],
        &[
            "build",
            "--release",
            "--locked",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "pack",
            "--bin",
            "busbar-plugin-pack",
        ][..],
    ] {
        let status = Command::new("cargo")
            .args(args)
            .env("BUSBAR_RELEASE_PUBKEY", E2E_RELEASE_PUBKEY)
            .env_remove("CARGO_TARGET_DIR")
            .current_dir(&root)
            .status()
            .expect("run cargo build for busbar + busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    let release = root.join("target").join("release");
    (release.join("busbar"), release.join("busbar-plugin-pack"))
}

/// THE TEST-ONLY FIRST-PARTY KEYPAIR (ed25519, `busbar-plugin-pack keygen`), never the release key.
pub const E2E_RELEASE_PUBKEY: &str =
    "9209607c315f66473c8cca8bf9a7b8031115d01bb47341613cebf57f0e4f271c";
pub const E2E_RELEASE_PRIVKEY: &str =
    "290f2453f236650ab21b85a95d49b9dab088518e829e4d524b01e441636ab327";
