// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store
//! carries (`kind: store`, alias `postgres`). Drop it into the engine's plugins folder and set
//! `store: { module: postgres, settings: { url: "postgres://..." } }`; the engine loads it
//! in-process at boot. One Postgres behind a fleet of busbar nodes means shared virtual keys,
//! budgets, and usage across the cluster.
//!
//! All the store lives in the `busbar-store-postgres` crate, including its one door registration
//! (`export_store_plugin!(open)`): the frozen symbols the loader looks up are the SDK's, defined once,
//! and they answer through that door. This crate re-exports the logic crate so the library it builds
//! carries exactly the code a busbar build that links the store runs — one source, both doors
//! (DECISIONS #2 rule (1)). Do NOT call the export macro here: two door registrations in one image.

#![deny(unsafe_code)]

pub use busbar_store_postgres::*;
