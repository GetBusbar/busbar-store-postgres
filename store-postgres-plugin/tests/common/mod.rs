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
    load_dropped, load_linked, rendering_of, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v3::LoadedStore;

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

fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("store-postgres-test"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

/// The store through its COMPILED-IN door, opened on `settings`.
pub fn linked(settings: &str) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(busbar_store_postgres::door).map_err(|e| e.to_string())?;
    let p = load_linked::<Store>(&row, bind(&d)).map_err(|e| e.to_string())?;
    LoadedStore::open(p, d, settings.as_bytes(), 1)
}

/// The library at `path` through the DROPPED-IN door, admitted against [`stated`] and opened on
/// `settings`.
pub fn dropped_at(path: &Path, settings: &str) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let p = load_dropped::<Store>(path, &stated(), bind(&d)).map_err(|e| e.to_string())?;
    LoadedStore::open(p, d, settings.as_bytes(), 2)
}

/// This crate's cdylib through the DROPPED-IN door.
pub fn dropped(settings: &str) -> Result<LoadedStore, String> {
    dropped_at(&cdylib(), settings)
}
