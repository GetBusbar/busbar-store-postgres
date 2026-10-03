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
//! (1)) — and exports that same `door` as the image's ONE symbol, `busbar_plugin_door`.

#![deny(unsafe_code)]

pub use busbar_store_postgres::*;

/// THE DROPPED-IN DOOR. The one module allowed unsafe code: the exported symbol is
/// `#[unsafe(no_mangle)]`.
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_postgres::door);
}
