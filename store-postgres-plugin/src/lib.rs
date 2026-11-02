// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store

#![deny(unsafe_code)]

pub use busbar_store_postgres::*;

/// The dropped-in door. Allowed unsafe code: the exported symbol is `#[unsafe(no_mangle)]`.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_postgres::door);
}
