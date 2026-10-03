// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store
//! carries (`kind: store`, alias `postgres`). Drop it into the engine's plugins folder and set
//! `store: { module: postgres, settings: { url: "postgres://..." } }`; the engine loads it
//! in-process at boot. One Postgres behind a fleet of busbar nodes means shared virtual keys,
//! budgets, and usage across the cluster.
//!
//! All the store lives in the `busbar-store-postgres` crate, including its one door (`door`, from
//! `store_door!`). This crate re-exports the logic crate so the library it builds carries exactly
//! the code a busbar build that links the store runs — one source, both doors (DECISIONS #2 rule
//! (1)) — and exports that same `door` as `busbar_plugin_door`. It also registers the store on the
//! cold store lane the busbar kernel at the pin boots a configured store through (`cold`).

#![deny(unsafe_code)]

pub use busbar_store_postgres::*;

/// THE DROPPED-IN DOOR. Allowed unsafe code: the exported symbol is `#[unsafe(no_mangle)]`.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_postgres::door);
}

/// The store a busbar at the pin BOOTS. Its kernel opens a configured dropped-in store through the
/// cold store lane (`PluginRegistry::open_store` -> `load_store_image`: `busbar_abi`,
/// `busbar_plugin_kind`, `busbar_open`, ...), not through the door; an image that exports only
/// `busbar_plugin_door` answers `busbar_plugin_kind` with NULL there and the boot is refused
/// (BUSBAR-9007 "returned a null kind string"). This registration answers that lane over the same
/// [`PostgresStore`], opened by the door's own `open` slot (same settings, same refusals).
fn open_cold(cfg: &str) -> Result<busbar_contract::abi::sdk::StoreHandle, String> {
    use busbar_contract::abi::sdk::store::StoreSlots;
    <PostgresStore as StoreSlots>::open(cfg.as_bytes())
        .map(|s| Box::new(s) as busbar_contract::abi::sdk::StoreHandle)
}

/// THE COLD LANE's registration (`export_store_plugin!`): the contract SDK's frozen symbols answer
/// through it. The macro's boundary functions are `unsafe extern "C-unwind"` by the cold ABI's own
/// definition, and it registers through a load-time initializer section.
#[allow(unsafe_code)]
mod cold {
    busbar_contract::abi::sdk::export_store_plugin!(super::open_cold);
}
