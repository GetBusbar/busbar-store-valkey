// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Valkey store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store
//! carries (`kind: store`, alias `valkey`). Drop it in the engine's plugins folder and set
//! `store: { module: valkey, settings: { url: "redis://..." } }`; the engine loads it in-process at
//! boot. One Valkey instance behind a fleet of busbar nodes means shared virtual keys, credentials,
//! budgets, usage, and audit across the cluster.
//!
//! All the store lives in the `busbar-store-valkey` crate, including its config adapter (`open`) and
//! its one door registration (`export_store_plugin!(open)`): the frozen symbols the loader looks up
//! are the contract SDK's, defined once, and they answer through that door. This crate re-exports the
//! logic crate so the library it builds carries exactly the code a busbar build that links the store
//! runs — one source, both doors (DECISIONS #2 rule (1)). Calling the export macro again here would
//! register a second door in one image.

#![deny(unsafe_code)]

pub use busbar_store_valkey::*;
