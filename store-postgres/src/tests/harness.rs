// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE UNDER TEST, AS BUSBAR RUNS IT: the store's door loaded through the real loader on a

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Wake, Waker};

use crate::tests::postgres_clock::PostgresClock;
use crate::tests::postgres_io;
use busbar_contract::abi::sdk::store::{OpRefused, StoreSlots};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, UsageDelta};
use busbar_contract::store_calls::{StoreCalls, StoreFailure};
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;

struct Unpark(std::thread::Thread);
impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Run `f` to completion on this thread.
pub(crate) fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::park();
    }
}

/// A fresh `op_id` for every bridge write: a node half no other open (in this run or an earlier
fn mint() -> OpId {
    static NODE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        nanos ^ (u64::from(std::process::id()) << 40)
    });
    OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// The clock alone, on the dispatcher's timebase; all other services are refused.

/// The store's linked door opened on `settings` over the loader, its needs on the production connector.
pub(crate) fn open_loaded(settings: &str) -> Result<LoadedStore, String> {
    open_loaded_over(settings, |d| {
        postgres_io::host(d.conn_waker(), Default::default())
    })
}

/// [`open_loaded`], its needs on the table `conns` builds (a production connector that trusts a test CA).
pub(crate) fn open_loaded_over(
    settings: &str,
    conns: impl FnOnce(&Dispatcher) -> Arc<dyn busbar_contract::conn::DeclaredConns>,
) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(PostgresClock),
    ));
    let conns = conns(&d);
    let row = LinkedRow::of(crate::door).map_err(|e| e.to_string())?;
    let p = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("store-postgres-test"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: ConnTable::Host(conns),
        },
    )
    .map_err(|e| e.to_string())?;
    LoadedStore::open(p, d, settings.as_bytes(), mint)
}

/// THE STORE UNDER TEST.
pub(crate) struct TestStore {
    store: LoadedStore,
    url: String,
    raw: Mutex<Option<postgres::Client>>,
}

impl std::ops::Deref for TestStore {
    type Target = LoadedStore;
    fn deref(&self) -> &LoadedStore {
        &self.store
    }
}

fn op_refused(f: StoreFailure) -> OpRefused {
    match f {
        StoreFailure::Conflict => OpRefused::Conflict,
        StoreFailure::Refused(t) => OpRefused::Refused(t),
        StoreFailure::Failed(t) | StoreFailure::Fault(t) => OpRefused::Failed(t),
        other => OpRefused::Failed(other.to_string()),
    }
}

fn text(f: StoreFailure) -> String {
    match f {
        StoreFailure::Failed(t) | StoreFailure::Refused(t) | StoreFailure::Fault(t) => t,
        other => other.to_string(),
    }
}

impl TestStore {
    /// The store on the connection string `url`.
    pub(crate) fn open(url: &str) -> Result<Self, String> {
        let settings = serde_json::json!({ "url": url }).to_string();
        Ok(Self {
            store: open_loaded(&settings)?,
            url: url.to_owned(),
            raw: Mutex::new(None),
        })
    }

    /// `StoreSlots::open` on `settings` (the settings' judge), with no host.
    pub(crate) fn open_slot(settings: &[u8]) -> Result<(), String> {
        <crate::PostgresStore as StoreSlots>::open_with_secrets(settings, &[], None).map(drop)
    }

    /// An INDEPENDENT driver connection to the same database, for raw SQL.
    pub(crate) fn lock(&self) -> RawGuard<'_> {
        let mut g = self.raw.lock().unwrap_or_else(PoisonError::into_inner);
        if g.is_none() {
            *g = Some(super::connect_client_with_retry(&self.url));
        }
        RawGuard(g)
    }

    pub(crate) fn add_usage_op(
        &self,
        op: OpId,
        bucket: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> Result<(), OpRefused> {
        let cells = [(bucket, window_start, delta.clone())];
        block_on(StoreCalls::add_usage_batch(&self.store, op, &cells)).map_err(op_refused)
    }

    pub(crate) fn add_usage_batch_op(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> Result<(), OpRefused> {
        block_on(StoreCalls::add_usage_batch(&self.store, op, cells)).map_err(op_refused)
    }

    pub(crate) fn add_metering_batch_op(
        &self,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> Result<(), OpRefused> {
        block_on(StoreCalls::add_metering_batch(&self.store, op, deltas)).map_err(op_refused)
    }

    pub(crate) fn add_metering_op(&self, op: OpId, delta: &MeteringDelta) -> Result<(), OpRefused> {
        let deltas = [delta.clone()];
        block_on(StoreCalls::add_metering_batch(&self.store, op, &deltas)).map_err(op_refused)
    }

    pub(crate) fn append_plane_record_op(
        &self,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> Result<(), OpRefused> {
        block_on(StoreCalls::append_plane_record(&self.store, op, record)).map_err(op_refused)
    }

    pub(crate) fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        let value = RecordBytes::new(value.to_vec()).map_err(|n| format!("{n} bytes"))?;
        block_on(StoreCalls::record_put(&self.store, schema, key, &value)).map_err(text)
    }

    pub(crate) fn record_get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        block_on(StoreCalls::record_get(&self.store, schema, key)).map_err(text)
    }

    pub(crate) fn record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        block_on(StoreCalls::record_scan(&self.store, schema, prefix, limit)).map_err(text)
    }
}

/// [`TestStore::lock`]'s connection.
pub(crate) struct RawGuard<'a>(MutexGuard<'a, Option<postgres::Client>>);

impl std::ops::Deref for RawGuard<'_> {
    type Target = postgres::Client;
    fn deref(&self) -> &postgres::Client {
        self.0.as_ref().expect("connected")
    }
}

impl std::ops::DerefMut for RawGuard<'_> {
    fn deref_mut(&mut self) -> &mut postgres::Client {
        self.0.as_mut().expect("connected")
    }
}
