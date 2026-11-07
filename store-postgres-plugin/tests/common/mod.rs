// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store's two doors, as this repo's tests open them: COMPILED IN (the logic crate's `door`,
//! through the loader's `load_linked`) and DROPPED IN (this crate's built cdylib, `dlopen`ed by the
//! loader's `load_dropped`, which resolves `busbar_plugin_door` and admits it against the Statement
//! the signed manifest would carry).

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use busbar_contract::persistence::*;
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4 as Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of, Bind, ConnTable, DispatchConfig, Dispatcher,
    LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};
#[path = "../../../store-postgres/tests-support/postgres_io.rs"]
pub mod postgres_io;

/// The actual freshly built own-library artifact selected by [`plugin_path`]. Missing is a
/// test failure, never a skip.
pub fn cdylib() -> PathBuf {
    plugin_path()
}

/// The Statement rendering the signed manifest states: the linked door's own (the cdylib is the
/// same crate).
pub fn stated() -> Vec<u8> {
    rendering_of(busbar_store_postgres::v4::door).expect("the store renders its Statement")
}

/// The instance's binding: its connections over the loader's test connection table (plain TCP),
/// woken through the dispatcher, as busbar's one connector serves a store's `tcp` need.
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
pub fn linked(settings: &str) -> Result<LoadedPersistence, String> {
    let d = dispatcher();
    let row = LinkedRow::of_kind::<Store>(
        busbar_store_postgres::v4::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
    .map_err(|e| e.to_string())?;
    let p = load_linked::<Store>(&row, bind(&d)).map_err(|e| e.to_string())?;
    run(LoadedPersistence::open(p, d, settings.as_bytes(), limits()))
}

/// The library at `path` through the DROPPED-IN door, admitted against [`stated`] and opened on
/// `settings`.
pub fn dropped_at(path: &Path, settings: &str) -> Result<LoadedPersistence, String> {
    let d = dispatcher();
    let p = load_dropped::<Store>(path, &stated(), bind(&d)).map_err(|e| e.to_string())?;
    run(LoadedPersistence::open(p, d, settings.as_bytes(), limits()))
}

/// This crate's cdylib through the DROPPED-IN door.
pub fn dropped(settings: &str) -> Result<LoadedPersistence, String> {
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
/// `busbar/` beside this repo.
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
/// `busbar-plugin-pack` binary, both from the sibling busbar checkout — never a fixture, never a
/// stub, the exact binaries a real release ships.
pub fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbar_root();
    if let (Some(busbar), Some(pack)) = (
        std::env::var_os("BUSBAR_E2E_BINARY"),
        std::env::var_os("BUSBAR_PLUGIN_PACK_BINARY"),
    ) {
        let paths = (PathBuf::from(busbar), PathBuf::from(pack));
        assert!(
            paths.0.is_file() && paths.1.is_file(),
            "explicit real binaries must exist"
        );
        return paths;
    }
    let output = std::env::temp_dir().join("postgres-real-binaries");
    std::fs::create_dir_all(&output).unwrap();

    for args in [
        &[
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            "dist/default/Cargo.toml",
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
            .env(
                "RUSTUP_TOOLCHAIN",
                std::env::var_os("RUSTUP_TOOLCHAIN").unwrap_or_else(|| "1.98".into()),
            )
            .args(args)
            .env("BUSBAR_RELEASE_PUBKEY", E2E_RELEASE_PUBKEY)
            .env("CARGO_TARGET_DIR", &output)
            .current_dir(&root)
            .status()
            .expect("run cargo build for busbar + busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    let release = output.join("release");
    (release.join("busbar"), release.join("busbar-plugin-pack"))
}

/// THE TEST-ONLY FIRST-PARTY KEYPAIR (ed25519, `busbar-plugin-pack keygen`), never the release key.
pub const E2E_RELEASE_PUBKEY: &str =
    "9209607c315f66473c8cca8bf9a7b8031115d01bb47341613cebf57f0e4f271c";
pub const E2E_RELEASE_PRIVKEY: &str =
    "290f2453f236650ab21b85a95d49b9dab088518e829e4d524b01e441636ab327";

#[allow(dead_code)]
pub(crate) mod temp_db;

#[path = "../../../store-postgres/tests-support/postgres_clock.rs"]
mod postgres_clock;
pub fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(postgres_clock::PostgresClock),
    ))
}
pub fn limits() -> Limits {
    Limits {
        descriptor_bytes: 16 << 20,
        output_items: 4096,
        output_bytes: 16 << 20,
        decode_bytes: 32 << 20,
    }
}
pub fn run<F: std::future::Future>(future: F) -> F::Output {
    struct Wake(std::thread::Thread);
    impl std::task::Wake for Wake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Wake(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(answer) => return answer,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}
pub const WRITER: [u8; 16] = [2; 16];
pub fn address(namespace: u8, key: &[u8]) -> Address {
    Address {
        namespace: [namespace; 16],
        key: key.to_vec(),
    }
}
pub fn put(address: Address, bytes: &[u8]) -> Mutation {
    Mutation::Put {
        address,
        value: busbar_contract::Secret::new(bytes.to_vec()),
    }
}
pub fn prepare(
    store: &LoadedPersistence,
    operation: u128,
    predicates: Vec<Predicate>,
    mutations: Vec<Mutation>,
) -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: store.info().dataset,
            writer_epoch: 1,
            writer: WRITER,
            execution_epoch: 1,
            operation: operation.to_le_bytes(),
        },
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: busbar_contract::Secret::new(b"original result".to_vec()),
    })
    .unwrap()
}
pub fn initialize(store: &LoadedPersistence) {
    let root = Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    };
    let writer = Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key(WRITER).to_vec(),
    };
    let candidate = prepare(
        store,
        1,
        vec![
            Predicate {
                address: root.clone(),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: writer.clone(),
                expected: ExpectedValue::Absent,
            },
        ],
        vec![
            put(
                root,
                &control::Dataset {
                    id: store.info().dataset,
                    writer_epoch: 1,
                }
                .encode()
                .unwrap(),
            ),
            put(
                writer,
                &control::Writer {
                    retired_through: 0,
                    admitted_through: 1,
                }
                .encode()
                .unwrap(),
            ),
        ],
    );
    assert!(matches!(
        run(store.commit(candidate)).unwrap(),
        Decision::Applied(_)
    ));
}
pub fn commit(
    store: &LoadedPersistence,
    operation: u128,
    predicates: Vec<Predicate>,
    mutations: Vec<Mutation>,
) -> Decision {
    run(store.commit(prepare(store, operation, predicates, mutations))).unwrap()
}
pub fn present(store: &LoadedPersistence, at: Address) -> bool {
    match run(store.read(Arc::new(Read {
        dataset: store.info().dataset,
        addresses: vec![at],
        time: None,
    })))
    .unwrap()
    {
        ReadResult::Values { mut values, .. } => values.pop().unwrap().is_some(),
        _ => panic!("unconditional read has no time refusal"),
    }
}
pub fn raw_value(url: &str, at: &Address) -> Option<Vec<u8>> {
    postgres::Client::connect(url, postgres::NoTls)
        .unwrap()
        .query_opt(
            "SELECT value FROM busbar_persistence_v4.records WHERE namespace=$1 AND key=$2",
            &[&at.namespace.as_slice(), &at.key],
        )
        .unwrap()
        .map(|row| row.get(0))
}
