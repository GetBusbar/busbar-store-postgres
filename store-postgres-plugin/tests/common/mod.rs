// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store's two doors, as this repo's tests open them: COMPILED IN (the logic crate's `door`,
//! through the loader's `load_linked`) and DROPPED IN (this crate's built cdylib, `dlopen`ed by the
//! loader's `load_dropped`, which resolves `busbar_plugin_door` and admits it against the Statement
//! the signed manifest would carry). Either way the store is one [`LoadedStore`], called through
//! the store v3 table.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of, Bind, ConnTable, DispatchConfig, Dispatcher,
    LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use busbar_plugin_loader::tcp_conns::TcpConns;

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: the dropped-in door is what these tests prove.
pub fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_store_postgres_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-store-postgres-plugin cdylib ({file}) is not built"))
}

/// The Statement rendering the signed manifest states: the linked door's own (the cdylib is the
/// same crate).
pub fn stated() -> Vec<u8> {
    rendering_of(busbar_store_postgres::door).expect("the store renders its Statement")
}

/// A fresh `op_id` for every bridge write: a node half no other open (in this run or an earlier
/// one) used. The store dedupes `op_id`s DURABLY, so two opens sharing a node half against one
/// database would replay or refuse each other's writes; a kernel's node id is unique per node, and
/// this stands in for it.
fn mint() -> busbar_contract::abi::store::OpId {
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
/// woken through the dispatcher, as busbar's one connector serves a store's `tcp` need.
fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("store-postgres-test"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Host(Arc::new(TcpConns::new(d.conn_waker()))),
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
/// `settings`.
pub fn dropped_at(path: &Path, settings: &str) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_dropped::<Store>(path, &stated(), bind(&d)).map_err(|e| e.to_string())?;
    LoadedStore::open(p, d, settings.as_bytes(), mint)
}

/// This crate's cdylib through the DROPPED-IN door.
pub fn dropped(settings: &str) -> Result<LoadedStore, String> {
    dropped_at(&cdylib(), settings)
}
