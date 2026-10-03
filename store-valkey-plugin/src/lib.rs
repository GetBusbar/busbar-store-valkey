// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Valkey store as a droppable busbar plugin** — the `cdylib` a signed tarball of the store
//! carries (`kind: store`, alias `valkey`). Drop it in the engine's plugins folder and set
//! `store: { module: valkey, settings: { url: "redis://..." } }`; the engine loads it in-process at
//! boot. One Valkey instance behind a fleet of busbar nodes means shared virtual keys, credentials,
//! budgets, usage, and audit across the cluster.
//!
//! All the store lives in the `busbar-store-valkey` crate, including its one door
//! (`busbar_store_valkey::door`, `store_door!` over the store v3 table). This crate re-exports the
//! logic crate, so the library it builds carries exactly the code a busbar build that links the
//! store runs, and exports that door as the image's ONE symbol, `busbar_plugin_door`
//! (`export_door!`, unconditionally) — one source, both doors (DECISIONS #2 rule (1)).
//!
//! This crate is `deny`, not `forbid`: the export macro's `#[unsafe(no_mangle)]` is the one reviewed
//! exemption (a `forbid` cannot be lifted for it). No other `unsafe` exists here.

#![deny(unsafe_code)]

pub use busbar_store_valkey::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_store_valkey::door);
}
