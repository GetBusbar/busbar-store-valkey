// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-valkey-plugin` cdylib loaded over the REAL loader
//! (`load_dropped`, then `LoadedStore::open`, the way the host opens a store: see [`load`]) against
//! a REAL, live Valkey (not a mock, not an in-process fake): a `Box<dyn RecordStore>`
//! indistinguishable from a compiled-in store, backed by `dlopen`'d code answering over the store
//! kind's memory ABI.
//!
//! Unlike a file-backed store (see store-sqlite's plugin end-to-end test, which reopens the
//! same file), Valkey has no "close and reopen the same file" persistence signal to check. Instead
//! this proves persistence the way that is actually meaningful for a SHARED backend:
//!
//!   1. `dlopen` the plugin, write a key + usage ledger through it over the memory ABI, then DROP it
//!      (which runs the door's `close`, closing the plugin's own Valkey connection).
//!   2. Open the library's linked door through the same loader and ABI on a fresh connection to
//!      the SAME Valkey instance and confirm the data is present. The admin e2e case additionally
//!      checks raw rows with the independent upstream RESP client.
//!
//! If the plugin's `put_key`/`put_usage` over the ABI were silent no-ops (or wrote to some
//! in-process cache rather than Valkey), step 2 would come back empty even though a same-session
//! read-after-write through the plugin looked fine.
//!
//! Gated on `VALKEY_URL` (a docker `valkey:7` GitHub Actions service container in this repo's CI —
//! see `.github/workflows/ci.yml`). Skips cleanly when unset locally; under `CI` a missing
//! `VALKEY_URL` is a HARD FAILURE, never a silent skip, so the only over-the-ABI coverage of the
//! durable Valkey store path cannot quietly vanish.

use busbar_contract::records::{
    ModelTokens, PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, RecordStoreResult,
    ScopeRef, UsageLedger, VirtualKey,
};
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, rendering_of_library, Bind, DispatchConfig, Dispatcher, NoSink,
};
use busbar_plugin_loader::plugin_library_filename;
use busbar_plugin_loader::store_v3::LoadedStore;
#[path = "../../test-support/valkey_io.rs"]
mod valkey_io;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "../../test-support/database.rs"]
mod database;

/// A node id no earlier run or instance used, for `LoadedStore::open`: its bridge mints each op id
/// as `(node, counter from 0)`, and this store's dedupe is DURABLE, so two instances sharing a node
/// would replay each other's op ids (the kernel draws the node from the OS CSPRNG per process).
fn node() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    (t ^ (u64::from(std::process::id()) << 32))
        .wrapping_add(N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) << 48)
        | 1
}

/// The node's one `op_id` allocator (`LoadedStore::open` mints the bridge's writes from it): a node
/// half no earlier run used (the dedupe is durable) and one counter.
fn mint() -> busbar_contract::abi::store::OpId {
    static NODE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(node);
    busbar_contract::abi::store::OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// Open the built cdylib the way the host opens a dropped-in store: its Statement rendered as
/// `busbar-plugin-pack` renders it into the signed manifest, `load_dropped` (dlopen,
/// `busbar_plugin_door`, the Statement compared byte for byte), then `LoadedStore::open`. Dropping
/// the handle closes the instance and unloads the library.
fn load(path: &Path, cfg: &str) -> Result<Box<dyn RecordStore>, String> {
    let stated = rendering_of_library(path)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "the library exports no busbar_plugin_door".to_string())?;
    let (dispatcher, bind) = host("store-valkey-e2e");
    let plugin = load_dropped::<Store>(path, &stated, bind).map_err(|e| e.to_string())?;
    let store = LoadedStore::open(plugin, dispatcher, cfg.as_bytes(), mint)?;
    Ok(Box::new(store))
}

/// A dispatcher and a bind over the loader's test connection table (plain TCP, the host's
/// connector path): every store op is one connection the "host" dials.
fn host(instance: &str) -> (Arc<Dispatcher>, Bind) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let conns: Arc<dyn busbar_contract::conn::DeclaredConns> = valkey_io::host(
        dispatcher.conn_waker(),
        busbar_contract::transport::EgressTrust::default(),
    );
    let bind = Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::Host(conns),
    };
    (dispatcher, bind)
}

/// The store through its COMPILED-IN door (`busbar_store_valkey::door`, never the cdylib): the
/// independent leg the dropped-in store's writes are read back and cleaned up through.
struct ValkeyStore;

impl ValkeyStore {
    fn connect(url: &str) -> Result<LoadedStore, String> {
        let (dispatcher, bind) = host("store-valkey-e2e-direct");
        let row = busbar_plugin_loader::dispatch::LinkedRow::of(busbar_store_valkey::door)
            .map_err(|e| e.to_string())?;
        let plugin = busbar_plugin_loader::dispatch::load_linked::<Store>(&row, bind)
            .map_err(|e| e.to_string())?;
        let cfg = format!("{{\"url\":{}}}", serde_json::Value::String(url.to_string()));
        LoadedStore::open(plugin, dispatcher, cfg.as_bytes(), mint)
    }
}

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an
/// explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The newest mtime across every workspace crate's `src/` — "how fresh must a cdylib be to be the
/// one this source tree describes".
///
/// Deliberately ONLY `src/**/*.rs` of each workspace member: editing a `tests/` file or a
/// `[dev-dependencies]` line recompiles the test binary but NOT the lib, so including those would
/// fail a perfectly current cdylib.
fn newest_source_mtime() -> std::time::SystemTime {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the plugin crate always sits under the workspace root");
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    for e in std::fs::read_dir(ws_root).into_iter().flatten().flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk_newest_source(&src, &mut newest);
        }
    }
    newest
}

/// The walk behind [`newest_source_mtime`]: the newest `.rs` mtime under `dir`, skipping the
/// `cfg(test)`-only sources (`tests.rs` and any `tests/` directory), which the non-test lib's
/// dep-info omits, so editing them never relinks the cdylib.
fn walk_newest_source(dir: &std::path::Path, newest: &mut std::time::SystemTime) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            walk_newest_source(&p, newest);
        } else if p.extension().is_some_and(|x| x == "rs")
            && p.file_name().is_none_or(|n| n != "tests.rs")
        {
            if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                if m > *newest {
                    *newest = m;
                }
            }
        }
    }
}

#[test]
fn newest_source_mtime_ignores_the_cfg_test_only_sources() {
    let dir = std::env::temp_dir().join(format!("bb-newest-src-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    let t0 = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    let t1 = t0 + std::time::Duration::from_secs(500);
    let touch = |p: std::path::PathBuf, t| {
        std::fs::write(&p, "").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(t)
            .unwrap();
    };
    touch(dir.join("lib.rs"), t0);
    touch(dir.join("tests.rs"), t1);
    touch(dir.join("tests").join("slots_tests.rs"), t1);
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    walk_newest_source(&dir, &mut newest);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(newest, t0, "test-only sources must not count");
}

/// Locate the cdylib THIS `cargo test` invocation just built — never a leftover artifact.
///
/// This looks ONLY in `target/<profile>/deps/`, never `target/<profile>/`, and that distinction is
/// the whole point of this function.
///
/// `cargo` emits the lib target's cdylib into `deps/` as part of the very build graph that produces
/// this test binary (this package's lib unit is compiled with BOTH declared crate-types — see
/// `[lib] crate-type = ["cdylib", "rlib"]` in Cargo.toml), so `deps/libbusbar_store_valkey_plugin.dylib` is by construction up to
/// date with the source tree under test. Cargo only *uplifts* a copy to `target/<profile>/` for
/// `cargo build`, NEVER for `cargo test`. A lookup in `target/<profile>/` therefore reads an
/// artifact that nothing in this test's dependency graph refreshes: whatever some earlier `cargo
/// build` left there, from any commit — or nothing at all.
///
/// Both outcomes of that are lies about durability, and the second is the dangerous one:
///   * NOTHING there  -> the old code `return`ed with a "skip:" line and reported GREEN. That is how
///     `cargo test` can pass with ZERO over-the-ABI coverage of the durable store path.
///   * STALE artifact -> a cdylib built before an ABI change answers every write `Ok(())` and every
///     read empty, which is BYTE-FOR-BYTE the signature of the unrelayed-seam defect this file
///     exists to catch (that defect was real: `DynStore`'s `impl Store` overrode 24 methods, none of
///     them the task/call-log methods, so `put_task` took the accept-and-keep-nothing trait
///     default). RED on a stale artifact is indistinguishable from RED on the real bug — and an
///     artifact NEWER than a regression reports GREEN while the shipped ABI is broken. Proven, not
///     theorised: with a regressed plugin in the tree and a good cdylib in `target/debug/`, the old
///     lookup passed and this one fails.
///
/// Same hazard, and the same reasoning, as the engine's `crates/busbar/Cargo.toml` dev-dependency on
/// `busbar-store-example-plugin`: keep the cdylib in the build graph so no test can judge a stale
/// one. Here the plugin's lib IS this package, so that graph edge already exists — what was missing
/// was reading the artifact that edge actually produces.
///
/// Panics rather than skipping: a missing cdylib under `cargo test` means the build graph changed
/// shape, and the only honest report of that is a failure, not a silent pass.
fn plugin_path() -> PathBuf {
    let fresh = if let Some(path) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        let path = PathBuf::from(path);
        assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
        path
    } else {
        let exe = std::env::current_exe().expect("current_exe");
        exe.parent()
            .expect("deps directory")
            .join(plugin_library_filename("busbar_store_valkey_plugin"))
    };
    assert!(
        fresh.exists(),
        "the store-valkey-plugin cdylib is not at {}, where cargo emits it for the same build that produced \
         this test binary. Refusing to fall back to target/<profile>/ (an artifact only `cargo \
         build` refreshes) or to skip: judging a stale cdylib is exactly how an unrelayed plugin \
         ABI reads as green.",
        fresh.display()
    );

    let built = std::fs::metadata(&fresh)
        .and_then(|m| m.modified())
        .expect("cdylib mtime");
    let newest_src = newest_source_mtime();
    assert!(
        built >= newest_src,
        "STALE ARTIFACT — THIS IS NOT A DURABILITY FAILURE. {} predates this workspace's sources, \
         so it cannot answer for the code in the tree; a pre-change cdylib returns empty for every \
         read, which reads exactly like an unrelayed plugin ABI. Run `cargo build -p {}` (or just \
         `cargo test`, which rebuilds it) and re-run.",
        fresh.display(),
        "busbar-store-valkey-plugin"
    );
    fresh
}

/// The live `VALKEY_URL`, mirroring `busbar-store-valkey`'s own `live_store()` gating discipline
/// (see `busbar-store-valkey`'s own `live_store()`): skip cleanly when unset LOCALLY, but a
/// missing `VALKEY_URL` under `CI` is a hard failure, not a silent skip — CI provisions the
/// `valkey:7` service container and must set this env var (see `.github/workflows/ci.yml`).
fn valkey_url() -> Option<String> {
    match std::env::var("VALKEY_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "VALKEY_URL is unset under CI: the valkey:7 service container must provision it \
                 (see .github/workflows/ci.yml). Refusing to silently skip the only over-the-ABI \
                 coverage of the durable valkey store path."
            );
        }
        Err(_) => {
            eprintln!("skip: set VALKEY_URL (a live Valkey) to run the valkey plugin e2e test");
            None
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
struct CallRow {
    principal: String,
    seq: u64,
    ts: u64,
    server: String,
    tool: String,
    outcome: String,
    reason: String,
    tool_digest: String,
    pin_generation: u64,
    request_id: String,
    prev_hash: String,
    hash: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
struct TaskRow {
    task_id: String,
    context_id: String,
    principal: String,
    direction: String,
    state: String,
    agent_id: String,
    artifact_cursor: u64,
    push_callback: String,
    created_at: u64,
    updated_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
struct TaskEventRow {
    task_id: String,
    seq: u64,
    ts: u64,
    kind: String,
    context_id: String,
    principal: String,
    agent_id: String,
    state: String,
    request_id: String,
    prev_hash: String,
    hash: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
struct DemotionRow {
    server: String,
    reason: String,
    recorded_at: u64,
}

fn body<T: serde::Serialize>(row: &T) -> Vec<u8> {
    serde_json::to_vec(row).expect("encode a test row")
}

fn row<T: serde::de::DeserializeOwned>(body: &[u8]) -> T {
    serde_json::from_slice(body).expect("a body this suite wrote decodes as the row it wrote")
}

/// The typed names, over the neutral verbs, for any `RecordStore` — the plugin-backed
/// `Box<dyn RecordStore>` and the direct `ValkeyStore` alike.
trait Vocab: RecordStore {
    fn put_task(&self, t: &TaskRow) -> RecordStoreResult<()> {
        let terminal = ["completed", "failed", "canceled", "rejected"].contains(&t.state.as_str());
        self.upsert_plane_record(
            PlaneRecord {
                kind: "task".into(),
                id: t.task_id.clone(),
                parent: None,
                seq: 0,
                ts: t.updated_at,
                disposition: if terminal {
                    PlaneDisposition::Terminal
                } else {
                    PlaneDisposition::Active
                },
                body: body(t),
            }
            .view(),
        )
    }
    fn get_task(&self, id: &str) -> RecordStoreResult<Option<TaskRow>> {
        Ok(self.get_plane_record("task", id)?.map(|b| row(&b)))
    }
    fn list_tasks(&self) -> RecordStoreResult<Vec<TaskRow>> {
        Ok(self
            .list_plane_records("task", &PlaneSelector::All)?
            .iter()
            .filter_map(|b| serde_json::from_slice(b).ok())
            .collect())
    }
    fn purge_tasks_before(&self, before: u64) -> RecordStoreResult<u64> {
        self.purge_plane_records(
            "task",
            before,
            busbar_contract::records::Retention::TerminalOnly,
        )
    }
    fn append_task_event(&self, e: &TaskEventRow) -> RecordStoreResult<()> {
        self.append_plane_record(
            PlaneRecord {
                kind: "task_event".into(),
                id: e.task_id.clone(),
                parent: Some(e.task_id.clone()),
                seq: e.seq,
                ts: e.ts,
                disposition: PlaneDisposition::Active,
                body: body(e),
            }
            .view(),
        )
    }
    fn list_task_events(&self, task_id: &str) -> RecordStoreResult<Vec<TaskEventRow>> {
        Ok(self
            .list_plane_records("task_event", &PlaneSelector::Parent(task_id.into()))?
            .iter()
            .map(|b| row(b))
            .collect())
    }
    fn append_mcp_call(&self, r: &CallRow) -> RecordStoreResult<()> {
        self.append_plane_record(
            PlaneRecord {
                kind: "call".into(),
                id: r.principal.clone(),
                parent: Some(r.principal.clone()),
                seq: r.seq,
                ts: r.ts,
                disposition: PlaneDisposition::Active,
                body: body(r),
            }
            .view(),
        )
    }
    fn list_mcp_calls(&self, principal: &str) -> RecordStoreResult<Vec<CallRow>> {
        Ok(self
            .list_plane_records("call", &PlaneSelector::Parent(principal.into()))?
            .iter()
            .map(|b| row(b))
            .collect())
    }
    fn list_mcp_call_principals(&self) -> RecordStoreResult<Vec<String>> {
        self.list_plane_record_parents("call")
    }
    fn purge_mcp_calls_before(&self, before: u64) -> RecordStoreResult<u64> {
        self.purge_plane_records_before("call", before)
    }
    fn put_mcp_demotion(&self, d: &DemotionRow) -> RecordStoreResult<()> {
        self.upsert_plane_record(
            PlaneRecord {
                kind: "demotion".into(),
                id: d.server.clone(),
                parent: None,
                seq: 0,
                ts: d.recorded_at,
                disposition: PlaneDisposition::Active,
                body: body(d),
            }
            .view(),
        )
    }
    fn list_mcp_demotions(&self) -> RecordStoreResult<Vec<DemotionRow>> {
        Ok(self
            .list_plane_records("demotion", &PlaneSelector::All)?
            .iter()
            .filter_map(|b| serde_json::from_slice(b).ok())
            .collect())
    }
    fn clear_mcp_demotion(&self, server: &str) -> RecordStoreResult<()> {
        self.delete_plane_record("demotion", server)
    }
    fn redeem_ask_state(&self, nonce: &str, expires_at: u64, now: u64) -> RecordStoreResult<bool> {
        self.redeem_plane_token("ask", nonce, expires_at, now)
    }
}

impl<T: RecordStore + ?Sized> Vocab for T {}

fn key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: "binding:vk_e2e_dlopen:g0".into(),
        name: "e2e-dlopen-key".into(),
        allowed_scopes: Some(vec![ScopeRef::pool("p")]),
        enabled: true,
        created_at: 42,
        group: Some("infra".into()),
        labels: std::collections::BTreeMap::from([("env".into(), "e2e".into())]),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    }
}

fn ledger() -> UsageLedger {
    UsageLedger {
        requests: 5,
        billable_requests: 5,
        models: vec![ModelTokens {
            model: "gpt-5".into(),
            usage_units: [("input".to_string(), 20), ("output".to_string(), 8)]
                .into_iter()
                .collect(),
        }],
    }
}

/// END-TO-END PERSISTENCE: dlopen the real valkey plugin against a REAL, live Valkey, write a key +
/// usage through it over the memory ABI, drop the plugin (closing its connection: dropping the `LoadedStore`
/// runs the door's `close`), then verify the data actually landed in Valkey two
/// independent ways:
///   1. re-dlopen the SAME cdylib against the SAME `VALKEY_URL` — a fresh door `open`/fresh
///      `LoadedStore` instance, proving the plugin itself doesn't just hold an in-memory cache
///      across calls.
///   2. open the library's linked door through the same loader and ABI on a fresh connection,
///      proving the dropped door's data survives its lifetime.
///
/// This is the proof that `store: valkey` operations over the ABI aren't silently no-ops.
#[test]
fn load_and_exercise_valkey_plugin_persists_to_real_valkey_across_reopen() {
    let path = plugin_path();
    let Some(url) = valkey_url() else {
        return;
    };
    let mut isolated: url::Url = url.parse().unwrap();
    isolated.set_path("/14");
    let url = isolated.to_string();
    let _database = database::Database::take(&url);
    let cfg = serde_json::json!({ "url": url }).to_string();

    let direct = ValkeyStore::connect(&url).expect("connect directly to seed/clean up");
    let vk_id = format!(
        "vk_e2e_dlopen_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let vk_id = vk_id.as_str();

    let vk = key(vk_id);

    {
        let store = load(&path, &cfg).expect("load valkey plugin against a real Valkey");
        store.put_key(&vk).expect("put_key over the ABI");
        store
            .put_usage(vk_id, 200, &ledger())
            .expect("put_usage over the ABI");
        assert_eq!(
            store
                .get_key(vk_id)
                .expect("get_key over the ABI")
                .expect("present in the same session")
                .id,
            vk_id
        );
    }

    let reopened = load(&path, &cfg).expect("re-load valkey plugin against the same URL");
    let got = reopened
        .get_key(vk_id)
        .expect("get_key after reopen")
        .expect("the key must survive a full plugin close + reopen against the same Valkey");
    assert_eq!(got.group.as_deref(), Some("infra"));
    assert_eq!(got.labels.get("env").map(String::as_str), Some("e2e"));
    let usage = reopened
        .get_usage(vk_id, 200)
        .expect("get_usage after reopen");
    assert_eq!(usage.requests, 5, "usage ledger must survive the reopen");
    let m = usage
        .models
        .iter()
        .find(|m| m.model == "gpt-5")
        .expect("model row survives reopen");
    assert_eq!((m.tier("input"), m.tier("output")), (20, 8));
    drop(reopened);

    let direct_key = RecordStore::get_key(&direct, vk_id)
        .expect("get_key via the direct connection")
        .expect("the key must be physically present in Valkey, bypassing the plugin");
    assert_eq!(direct_key.name, "e2e-dlopen-key");
    assert_eq!(direct_key.allowed_scopes, Some(vec![ScopeRef::pool("p")]));
    let direct_usage =
        RecordStore::get_usage(&direct, vk_id, 200).expect("get_usage via the direct connection");
    assert_eq!(
        direct_usage.requests, 5,
        "usage must be physically present in Valkey, not just cached in-process by the plugin"
    );

    let _ = RecordStore::delete_key(&direct, vk_id);
}

/// END-TO-END FAILURE: an `open()` config that cannot produce a usable store — malformed JSON, a
/// config missing `url`, and a `url` Valkey itself refuses to parse — surfaces back across the C
/// ABI as a clean `Err`, never a panic or a silently-succeeded load. Needs no live Valkey: every
/// case here fails before (or instead of) actually connecting.
#[test]
fn load_and_exercise_valkey_plugin_bad_config_fails_over_abi() {
    let path = plugin_path();

    let err = load(&path, "{ not json")
        .err()
        .expect("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid valkey plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = load(&path, "{}")
        .err()
        .expect("a config missing url must fail to load");
    assert!(
        err.contains("`url` is required"),
        "expected the plugin's own missing-url message, got: {err}"
    );

    let err = load(&path, r#"{"url":"not-a-valkey-url"}"#)
        .err()
        .expect("an unparseable valkey url must fail to load, not silently succeed");
    assert!(
        err.contains("invalid valkey plugin config: url: "),
        "expected the plugin's own connect-failure context, got: {err}"
    );
}

/// RAII guard for a spawned child process: kills and reaps it on drop, including when a panic
/// unwinds partway through the test.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The busbar checkout the real binaries are built from: `BUSBAR_CHECKOUT` when set (CI checks
/// GetBusbar/busbar out at the `.busbar-ref` rev and points this at it), otherwise a sibling
/// `../busbar` beside this repo. It must be the rev `.busbar-ref` pins — the rev this plugin's
/// contract comes from. A missing checkout is a FAILURE, never a skip: this is the only proof that
/// a real busbar installs and boots on this store.
fn busbar_root() -> PathBuf {
    let root = match std::env::var_os("BUSBAR_CHECKOUT") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../busbar"),
    };
    root.canonicalize().unwrap_or_else(|e| {
        panic!(
            "no busbar checkout at {} ({e}): set BUSBAR_CHECKOUT to a checkout of \
             GetBusbar/busbar at the .busbar-ref rev",
            root.display()
        )
    })
}

/// Build (once, cached by cargo) the real `busbar` binary and the real `busbar-plugin-pack` tool
/// from that checkout — never a fixture, never a stub. The pack tool is a feature-gated bin of
/// `busbar-plugin-loader` in busbar 1.6.0. busbar is the `test-harness` build, the one that takes a
/// test's first-party key ([`HARNESS_FIRST_PARTY_KEY_ENV`]); no release build reads it.
fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbar_root();
    let toolchain =
        std::env::var_os("RUSTUP_TOOLCHAIN").unwrap_or_else(|| std::ffi::OsString::from("1.98"));
    let target = match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => root.join(dir),
        None => root.join("target"),
    };
    for args in [
        &[
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--features",
            "test-harness",
            "--bin",
            "busbar",
        ][..],
        &[
            "build",
            "--locked",
            "--release",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "pack",
            "--bin",
            "busbar-plugin-pack",
        ][..],
    ] {
        let status = Command::new("cargo")
            .env("RUSTUP_TOOLCHAIN", &toolchain)
            .args(args)
            .arg("--target-dir")
            .arg(&target)
            .current_dir(&root)
            .status()
            .expect("run cargo build for busbar + busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    (
        target.join("release/busbar"),
        target.join("release/busbar-plugin-pack"),
    )
}

/// A placeholder provider credential: busbar 1.6.0 refuses to boot on an unresolvable provider
/// credential (BUSBAR-9007), and the mock provider is never dialled.
const SECRET_PLACEHOLDER: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// THE FIRST-PARTY KEY THIS TEST SIGNS THE PLUGIN WITH (its ed25519 secret, 64 hex): the store's
/// `tcp` need sits in the `operator-infrastructure` egress class, which the host grants to a
/// FIRST-PARTY plugin only (`BUSBAR-1.6.0.md` §5), and no test holds the embedded release key's
/// private half. So the pack tool signs with this key (`BUSBAR_SIGN_KEY`), and the child busbar, a
/// `test-harness` build, takes its public half as its first-party key through the harness seam
/// ([`HARNESS_FIRST_PARTY_KEY_ENV`], ARCHITECT ruling busbar #700), as busbar's own end-to-end
/// battery admits a first-party plugin it signed.
const HARNESS_SIGN_KEY: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";

/// The variable a `test-harness` busbar reads its first-party key from (busbar's
/// `root::boot::HARNESS_FIRST_PARTY_KEY_ENV`).
const HARNESS_FIRST_PARTY_KEY_ENV: &str = "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY";

/// The public half of [`HARNESS_SIGN_KEY`], 64 hex: what the child trusts as first-party.
fn harness_public_key() -> String {
    let mut secret = [0_u8; 32];
    for (i, b) in secret.iter_mut().enumerate() {
        *b = u8::from_str_radix(&HARNESS_SIGN_KEY[2 * i..2 * i + 2], 16).expect("hex");
    }
    busbar_plugin_loader::sign::SigningKey::from_bytes(&secret)
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A free-at-the-moment localhost port (bind-then-drop; a TOCTOU race is possible in principle
/// but is the standard, accepted pattern for test port allocation and hasn't been a problem for
/// the sibling repos' own equivalents).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn poll_admin_up(admin: &str, token: &str, client: &reqwest::blocking::Client) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(resp) = client
            .get(format!("{admin}/plugins?type=store"))
            .bearer_auth(token)
            .send()
        {
            if resp.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Point at a DIFFERENT logical Valkey database (index 15, the conventional "spare" db a lot of
/// Valkey tooling reserves for tests) than [`valkey_url`]'s own `/0`, which every OTHER test in this
/// file/crate shares. A real `busbar` boot (unlike a plain `Store` call) HYDRATES every existing
/// virtual key at startup and validates its `group` against the config's own `groups:` block —
/// this test's config intentionally defines none, so ANY leftover key from another test sharing
/// db 0 (e.g. the dlopen persistence test above, which mints a key with `group: "infra"`) makes
/// boot fail outright with an unrelated "group does not exist" error. Same server, same
/// `VALKEY_URL` host/port, just an isolated `SELECT`ed database — proven the strongest fix short of
/// a second Valkey container (confirmed necessary: this test failed with exactly that pollution
/// before being pointed at its own db).
fn admin_test_valkey_url(base: &str) -> String {
    valkey_url_in_db(base, 15)
}

/// The databases the live tests use: `/0` the url's own (shared), `/15` the admin end-to-end test,
/// `/14` conformance's folds, `/11` to `/13` store-valkey's schema-refusal tests, and this one for
/// the two durability proofs that sweep a whole kind (`call`, terminal `task`).
const SWEEP_DB: u32 = 10;

/// `base` pointed at database `db`.
fn valkey_url_in_db(base: &str, db: u32) -> String {
    let (base, query) = base
        .split_once('?')
        .map_or((base, ""), |(base, q)| (base, q));
    let without_path = match base.rfind('/') {
        Some(i) if base[..i].contains("://") => &base[..i],
        _ => base,
    };
    if query.is_empty() {
        format!("{without_path}/{db}")
    } else {
        format!("{without_path}/{db}?{query}")
    }
}

#[test]
fn admin_api_installs_the_valkey_plugin_and_writes_land_in_real_valkey() {
    const INSTALLED_ARCHIVE: &str = "busbar-store-valkey-plugin-0.0.0-e2e.tar.gz";
    let Some(base_url) = valkey_url() else { return };
    let url = admin_test_valkey_url(&base_url);
    let _database = database::Database::take(&url);
    let so_path = plugin_path();

    let direct = ValkeyStore::connect(&url).expect("connect directly to seed/clean up");

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-valkey-admin-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    let tarball = work.join("store-valkey.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-valkey",
            "--alias",
            "valkey",
            "--kind",
            "store",
            "--version",
            env!("CARGO_PKG_VERSION"),
            "--publisher",
            "busbar",
            "--description",
            "e2e admin-api install proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
        ])
        .env("BUSBAR_SIGN_KEY", HARNESS_SIGN_KEY)
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    let admin_token = format!("e2e-admin-{}-{}", std::process::id(), free_port());
    let port = free_port();

    let admin_port = loop {
        let candidate = free_port();
        if candidate != port {
            break candidate;
        }
    };
    let admin = format!("http://127.0.0.1:{admin_port}/api/v1/admin");

    let providers = work.join("providers.yaml");
    let config = work.join("config.yaml");
    let overlay = work.join("overlay.json");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();

    let config_text = |bootstrap_pin: Option<&str>, store_url: Option<&str>| {
        let fetch = bootstrap_pin
            .map(|sha256| {
                format!(
                    "  fetch:\n    - url: \"https://plugins.invalid/{INSTALLED_ARCHIVE}\"\n      sha256: \"{sha256}\"\n"
                )
            })
            .unwrap_or_default();
        let store = store_url.map_or_else(
            || "store:\n  module: memory\n".to_string(),
            |url| {
                format!(
                    "store:\n  module: busbar-store-valkey\n  settings:\n    url: {}\n",
                    serde_json::to_string(url).expect("the Store URL encodes as a YAML string")
                )
            },
        );
        format!(
            "listen: \"127.0.0.1:{port}\"\n\
             admin_listen: \"127.0.0.1:{admin_port}\"\n\
             identity-providers:\n  admin-tokens:\n    module: admin-tokens\n    token: {{ env: E2E_ADMIN_TOKEN }}\n\
             auth:\n  chain: [keys]\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth: [admin-tokens]\n\
             credentials:\n  at_rest:\n    key: {{ env: BUSBAR_SIGNING_KEY }}\n\
             plugins:\n  enabled: true\n  dir: {}\n{fetch}  trust:\n    allow_unsigned: true\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n\
             {store}",
            plugins_dir.display()
        )
    };
    std::fs::write(&config, config_text(None, None)).unwrap();

    let client = reqwest::blocking::Client::new();

    let spawn = |label: &str| {
        let log = std::fs::File::create(work.join(format!("busbar-{label}.log")))
            .expect("create boot log file");
        let mut cmd = Command::new(&busbar_bin);
        cmd.env("BUSBAR_CONFIG", &config)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("E2E_ADMIN_TOKEN", &admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("MOCK_KEY", SECRET_PLACEHOLDER)
            .env("BUSBAR_STATE_FILE", "")
            .env("BUSBAR_CONFIG_OVERLAY", &overlay)
            .env(HARNESS_FIRST_PARTY_KEY_ENV, harness_public_key())
            .stdout(Stdio::from(log.try_clone().expect("clone log fd")))
            .stderr(Stdio::from(log));
        cmd.spawn().expect("spawn a real busbar boot")
    };
    let boot_log = |label: &str| {
        std::fs::read_to_string(work.join(format!("busbar-{label}.log"))).unwrap_or_default()
    };

    let mut guard = ChildGuard(spawn("1"));
    assert!(
        poll_admin_up(&admin, &admin_token, &client),
        "busbar (boot #1) must come up with the admin listener responsive; log:\n{}",
        boot_log("1")
    );

    let tarball_bytes = std::fs::read(&tarball).unwrap();
    use base64::Engine as _;
    let tarball_b64 = base64::engine::general_purpose::STANDARD.encode(&tarball_bytes);
    let install_resp = client
        .post(format!("{admin}/plugins"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "file": INSTALLED_ARCHIVE,
            "tarball_b64": tarball_b64,
        }))
        .send()
        .expect("POST /api/v1/admin/plugins");
    let install_status = install_resp.status();
    let install_body: serde_json::Value = install_resp.json().unwrap_or(serde_json::Value::Null);
    assert_eq!(
        install_status.as_u16(),
        201,
        "expected 201 from POST /api/v1/admin/plugins, got {install_status}: {install_body}"
    );
    assert_eq!(
        install_body.get("name").and_then(|v| v.as_str()),
        Some("busbar-store-valkey"),
        "install response must name the installed plugin: {install_body}"
    );

    let installed_bytes = std::fs::read(plugins_dir.join(INSTALLED_ARCHIVE))
        .expect("the successful admin install retained its archive");
    assert_eq!(
        installed_bytes, tarball_bytes,
        "install retains the supplied archive bytes"
    );
    let archive_sha256 = busbar_plugin_loader::sign::sha256_hex(&installed_bytes);
    std::fs::write(&config, config_text(Some(&archive_sha256), None)).unwrap();

    let settings_resp = client
        .put(format!("{admin}/config/settings"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "store": { "module": "busbar-store-valkey", "settings": { "url": url } },
            "persist": true,
        }))
        .send()
        .expect("PUT /api/v1/admin/config/settings");
    let settings_status = settings_resp.status();
    let settings_body = settings_resp.text().unwrap_or_default();
    assert!(
        settings_status.is_success(),
        "PUT /api/v1/admin/config/settings must succeed: {settings_status}: {settings_body}"
    );

    std::fs::write(&config, config_text(Some(&archive_sha256), Some(&url))).unwrap();

    let restart = client
        .post(format!("{admin}/restart"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({ "confirm": true }))
        .send()
        .expect("POST /api/v1/admin/restart");
    let restart_status = restart.status();
    let restart_body = restart.text().unwrap_or_default();
    assert!(
        restart_status.is_success(),
        "restart must be accepted: {restart_status}: {restart_body}"
    );

    let exit_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match guard.0.try_wait().expect("observe restart exit") {
            Some(status) => {
                assert!(status.success(), "restart must exit successfully: {status}");
                break;
            }
            None => assert!(
                Instant::now() < exit_deadline,
                "the accepted restart must exit boot #1; log:\n{}",
                boot_log("1")
            ),
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let guard2 = ChildGuard(spawn("2"));
    assert!(
        poll_admin_up(&admin, &admin_token, &client),
        "busbar (boot #2, with the valkey plugin persisted as store.module) must come back up; \
         log:\n{}",
        boot_log("2")
    );
    assert!(
        !boot_log("2").contains("does not match any plugin"),
        "the valkey plugin persisted as store.module must resolve to the installed plugin, not \
         be rejected as unmatched: {}",
        boot_log("2")
    );

    let list_resp = client
        .get(format!("{admin}/plugins?type=store"))
        .bearer_auth(&admin_token)
        .send()
        .expect("GET /api/v1/admin/plugins?type=store");
    let list_body = list_resp.text().unwrap_or_default();
    assert!(
        list_body.contains("busbar-store-valkey"),
        "the restarted instance must list the installed valkey plugin: {list_body}"
    );

    let mint_resp = client
        .post(format!("{admin}/keys"))
        .bearer_auth(&admin_token)
        .json(&serde_json::json!({
            "name": "e2e-admin-install-verify",
            "issue_aws_credential": true,
        }))
        .send()
        .expect("POST /api/v1/admin/keys");
    let mint_status = mint_resp.status();
    let mint_body: serde_json::Value = mint_resp.json().expect("mint response must be JSON");
    assert_eq!(
        mint_status.as_u16(),
        201,
        "expected 201 from POST /api/v1/admin/keys, got {mint_status}: {mint_body}"
    );
    let key_id = mint_body
        .get("id")
        .and_then(|v| v.as_str())
        .expect("mint response must carry an id")
        .to_string();
    assert!(
        key_id.starts_with("vk_"),
        "unexpected key id shape: {key_id}"
    );
    let access_key_id = mint_body
        .get("aws_access_key_id")
        .and_then(|v| v.as_str())
        .expect("issue_aws_credential:true must return aws_access_key_id")
        .to_string();

    let get_resp = client
        .get(format!("{admin}/keys/{key_id}"))
        .bearer_auth(&admin_token)
        .send()
        .expect("GET /api/v1/admin/keys/{id}");
    assert!(
        get_resp.status().is_success(),
        "GET /api/v1/admin/keys/{{id}} must find the just-minted key: {}",
        get_resp.status()
    );

    drop(guard2);
    drop(guard);

    let vk = RecordStore::get_key(&direct, &key_id)
        .expect("get_key via the direct connection")
        .expect("the virtual key minted through the real admin API must be physically in Valkey");
    assert_eq!(vk.id, key_id);
    assert_eq!(vk.name, "e2e-admin-install-verify");
    let creds = RecordStore::list_credentials(&direct, &key_id)
        .expect("list_credentials via the direct connection");
    let cred = creds
        .iter()
        .find(|c| c.public_id == access_key_id)
        .expect("the sigv4 credential minted alongside the key must be physically in Valkey");
    assert_eq!(cred.kind, "sigv4");
    assert_eq!(cred.key_id, key_id);

    let mut raw = redis::Client::open(url.as_str())
        .and_then(|c| c.get_connection())
        .expect("raw valkey connection for the strongest independent check");
    let raw_key_row: Option<String> =
        redis::Commands::get(&mut raw, format!("busbar:key:{key_id}")).unwrap();
    let raw_key_row = raw_key_row.expect("busbar:key:<id> must be physically present in Valkey");
    assert!(
        raw_key_row.contains(&key_id) && raw_key_row.contains("e2e-admin-install-verify"),
        "raw Valkey row must contain the minted key's own id and name: {raw_key_row}"
    );

    let _ = RecordStore::delete_key(&direct, &key_id);
    let _ = std::fs::remove_dir_all(&work);
}

/// THE DURABILITY PROOF FOR THE FOUR MCP CALL-LOG METHODS, OVER THE REAL PLUGIN PATH.
///
/// This repo ships `feat/durable-mcp-call-log` — `append_mcp_call`/`list_mcp_calls`/
/// `list_mcp_call_principals`/`purge_mcp_calls_before` against a real Valkey. Every existing test of
/// those four calls `ValkeyStore` DIRECTLY, in-process, and NONE of them can see the failure that
/// actually matters in production, because in production this backend is ONLY ever reached as a
/// plugin: conformance boots the in-process RAM store, so the plugin seam is the only path a real
/// deployment takes and was, until this test, the one path with zero coverage of these methods.
///
/// The contract DEFAULTS every plane-record verb to accept-and-keep-nothing. A plugin
/// seam that does not RELAY them silently substitutes those defaults: every `append_mcp_call`
/// returns `Ok`, every `list_mcp_calls` answers empty, and a deployment loses every tool-call record
/// while reporting success. That is not hypothetical — the ABI once carried four store methods while
/// the trait carried ten, so exactly this happened. A unit test passing while the ABI drops every
/// write is the precise shape this test exists to make impossible.
///
/// So it goes through [`load`]: a REAL `dlopen` of the built cdylib, the real memory ABI, the real
/// `LoadedStore`. It writes AT ARITY > 1 (three chained records for one principal
/// and one for a second), DROPS the handle — which runs `the door's `close`` and UNLOADS the library, so
/// nothing this process still holds can answer the reads — then `dlopen`s AGAIN over the same file
/// and reads everything back. A restart is what proves durability; a single-row same-session round
/// trip would not distinguish a relayed method from a lucky trait default, and a multi-row one
/// across an unload/reload cannot be faked by either.
///
/// A third leg reads the same rows through a fresh linked door and the same loader and store ABI.
#[test]
fn mcp_call_log_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    let path = plugin_path();
    let Some(base_url) = valkey_url() else {
        return;
    };
    let url = valkey_url_in_db(&base_url, SWEEP_DB);
    let _database = database::Database::take(&url);
    let cfg = serde_json::json!({ "url": url }).to_string();

    let direct = ValkeyStore::connect(&url).expect("connect directly to clean up and verify");
    Vocab::purge_mcp_calls_before(&direct, u64::MAX).expect("wipe the call log before this run");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let p_main = format!("vk_abi_main_{stamp}");
    let p_other = format!("vk_abi_other_{stamp}");

    let call = |principal: &str, seq: u64, prev: &str, hash: &str| CallRow {
        principal: principal.to_string(),
        seq,
        ts: 2_000 + seq,
        server: "srv".to_string(),
        tool: "srv_read_file".to_string(),
        outcome: "dispatched".to_string(),
        reason: String::new(),
        tool_digest: format!("sha256:tool{seq}"),
        pin_generation: 3,
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };

    {
        let store = load(&path, &cfg).expect("the valkey plugin must load over the real ABI");
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_mcp_call(&call(&p_main, seq, prev, hash))
                .expect("append_mcp_call over the ABI");
        }
        store
            .append_mcp_call(&call(&p_other, 1, "", "o1"))
            .expect("append_mcp_call over the ABI");

        drop(store);
    }

    let store = load(&path, &cfg).expect("the valkey plugin must load again over the real ABI");

    let calls = store.list_mcp_calls(&p_main).expect("list_mcp_calls");
    assert_eq!(
        calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-principal call chain must survive the unload/reload over the plugin ABI in chain \
         order; got {} record(s) back, which is the accept-and-keep-nothing shape of the trait \
         default an unrelayed seam substitutes",
        calls.len()
    );
    for w in calls.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the chain must still link after the reload: seq {} carries prev_hash {:?} but seq {} \
             persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }

    assert_eq!(calls[2].tool_digest, "sha256:tool3");
    assert_eq!(calls[2].request_id, "req-3");
    assert_eq!(calls[2].tool, "srv_read_file");
    assert_eq!(calls[2].outcome, "dispatched");
    assert_eq!(calls[1].pin_generation, 3);
    assert_eq!(
        store
            .list_mcp_calls(&p_other)
            .expect("list_mcp_calls")
            .len(),
        1,
        "one principal's chain must not carry another's records"
    );

    let principals = store
        .list_mcp_call_principals()
        .expect("list_mcp_call_principals");
    assert_eq!(
        principals,
        vec![p_main.clone(), p_other.clone()],
        "the boot enumeration must name every principal holding records, exactly once each, sorted"
    );

    assert_eq!(
        store.purge_mcp_calls_before(2_002).expect("purge"),
        2,
        "both records at ts 2001 go (one per principal); the one sitting exactly at the cutoff stays"
    );
    assert_eq!(
        store.list_mcp_calls(&p_main).expect("list_mcp_calls").len(),
        2
    );
    assert!(store
        .list_mcp_calls(&p_other)
        .expect("list_mcp_calls")
        .is_empty());
    assert_eq!(
        store
            .list_mcp_call_principals()
            .expect("list_mcp_call_principals"),
        vec![p_main.clone()],
        "a principal whose chain the sweep emptied must leave the enumeration, or a boot keeps \
         resuming a chain with nothing in it"
    );
    drop(store);

    let direct_calls =
        Vocab::list_mcp_calls(&direct, &p_main).expect("list_mcp_calls via the direct connection");
    assert_eq!(
        direct_calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![2, 3],
        "the records must be physically present in Valkey, not just cached in-process by the plugin"
    );
    assert_eq!(direct_calls[1].hash, "h3");

    Vocab::purge_mcp_calls_before(&direct, u64::MAX).expect("clean up this run's records");
}

/// THE DURABILITY PROOF FOR THE SIX A2A TASK-STORE METHODS, OVER THE REAL PLUGIN PATH.
///
/// The sibling proof above does this for the MCP call log; this one exists because the task methods
/// are a SEPARATE half of the same defaulted seam and half the fleet used to be missing them.
/// The contract defaults the upsert to `Ok(())`, the point read to `Ok(None)` and the listing to
/// `Ok(vec![])`: a backend that does not override them ACCEPTS EVERY WRITE AND REPORTS SUCCESS while
/// keeping nothing. An operator would find "task state survives a restart" false on their own
/// deployment, which is the worst place to discover it.
///
/// The conformance suite cannot see this: it boots the in-process RAM store, where those defaults
/// ARE the honest answer and nothing looks wrong. The plugin seam is the ONLY path a real Valkey
/// deployment takes, so it is the only path worth proving on. A unit test against `ValkeyStore`
/// proves the function compiles and works in-process; it does not prove the plugin path reaches it.
///
/// So: a REAL `dlopen` of the built cdylib, the real memory ABI, the real `LoadedStore`. Write at arity > 1
/// (two tasks, one of them UPSERTED a second time, plus two independent provenance chains), DROP the
/// handle — `the door's `close`` runs and the library is unloaded, so nothing this process still holds can
/// answer the reads — then `dlopen` again and read everything back. A third leg reads the same rows
/// through the plain `ValkeyStore`, never touching the cdylib, so a plugin answering out of its own
/// in-process cache still fails.
#[test]
fn task_store_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    let path = plugin_path();
    let Some(base_url) = valkey_url() else {
        return;
    };
    let url = valkey_url_in_db(&base_url, SWEEP_DB);
    let _database = database::Database::take(&url);
    let cfg = serde_json::json!({ "url": url }).to_string();

    let direct = ValkeyStore::connect(&url).expect("connect directly to clean up and verify");
    Vocab::purge_tasks_before(&direct, u64::MAX).expect("wipe terminal tasks before this run");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let t_live = format!("task_abi_live_{stamp}");
    let t_done = format!("task_abi_done_{stamp}");

    const BASE_TS: u64 = 4_000_000_000;

    let task = |id: &str, state: &str, updated_at: u64, cursor: u64| TaskRow {
        task_id: id.to_string(),
        context_id: format!("ctx-{id}"),
        principal: "vk_task_abi".to_string(),
        direction: "inbound".to_string(),
        state: state.to_string(),
        agent_id: "agent-7".to_string(),
        artifact_cursor: cursor,
        push_callback: "https://callback.example/hook".to_string(),
        created_at: BASE_TS,
        updated_at,
    };
    let event = |id: &str, seq: u64, kind: &str, prev: &str, hash: &str| TaskEventRow {
        task_id: id.to_string(),
        seq,
        ts: BASE_TS + seq,
        kind: kind.to_string(),
        context_id: format!("ctx-{id}"),
        principal: "vk_task_abi".to_string(),
        agent_id: "agent-7".to_string(),
        state: "working".to_string(),
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };

    {
        let store = load(&path, &cfg).expect("the valkey plugin must load over the real ABI");
        store
            .put_task(&task(&t_live, "working", BASE_TS + 100, 3))
            .expect("put_task over the ABI");

        store
            .put_task(&task(&t_live, "input-required", BASE_TS + 200, 9))
            .expect("put_task over the ABI");
        store
            .put_task(&task(&t_done, "completed", BASE_TS + 50, 1))
            .expect("put_task over the ABI");

        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_task_event(&event(&t_live, seq, "task.working", prev, hash))
                .expect("append_task_event over the ABI");
        }
        store
            .append_task_event(&event(&t_done, 1, "task.completed", "", "d1"))
            .expect("append_task_event over the ABI");

        drop(store);
    }

    let store = load(&path, &cfg).expect("the valkey plugin must load again over the real ABI");

    let got = store.get_task(&t_live).expect("get_task").expect(
        "an in-flight task must survive the unload/reload over the plugin ABI; got None back, \
         which is exactly the accept-and-keep-nothing shape of the trait default an unimplemented \
         backend (or an unrelayed seam) substitutes",
    );
    assert_eq!(
        got,
        task(&t_live, "input-required", BASE_TS + 200, 9),
        "every field must round-trip, and the row read back must be the SECOND write: put_task \
         upserts by task_id"
    );
    assert!(
        store
            .get_task(&format!("task_abi_nonexistent_{stamp}"))
            .expect("get_task on an unknown id is not an error")
            .is_none(),
        "an unknown task id reads back None, not an error"
    );

    let listed = store.list_tasks().expect("list_tasks");
    let mine = listed
        .iter()
        .filter(|t| t.task_id == t_live || t.task_id == t_done)
        .map(|t| t.task_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        mine,
        vec![t_done.clone(), t_live.clone()],
        "list_tasks is UNFILTERED — the terminal row is returned too — and the upserted task \
         appears exactly ONCE; got {} of this run's rows back",
        mine.len()
    );

    let events = store.list_task_events(&t_live).expect("list_task_events");
    assert_eq!(
        events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-task provenance chain must survive the reload, oldest-first by seq; got {} \
         event(s), the empty shape of the trait default",
        events.len()
    );
    for w in events.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the chain must still link after the reload: seq {} carries prev_hash {:?} but seq {} \
             persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    assert_eq!(events[2].kind, "task.working");
    assert_eq!(events[2].request_id, "req-3");
    assert_eq!(
        store
            .list_task_events(&t_done)
            .expect("list_task_events")
            .len(),
        1,
        "one task's chain must not carry another's events"
    );

    store
        .append_task_event(&event(&t_live, 3, "task.working", "h2", "h3"))
        .expect("an identical replay over the ABI is the retry and succeeds");
    let mut forked = event(&t_live, 3, "task.working", "h2", "h3");
    forked.state = "input-required".to_string();
    store
        .append_task_event(&forked)
        .expect_err("a different event at an occupied seq is refused over the ABI too");
    let events = store.list_task_events(&t_live).expect("list_task_events");
    assert_eq!(events.len(), 3, "a replay must not append a 4th event");
    assert_eq!(
        events[2].state, "working",
        "and a refused fork overwrites nothing"
    );

    assert_eq!(
        store
            .purge_tasks_before(BASE_TS + 100)
            .expect("purge_tasks_before"),
        1,
        "only the TERMINAL row older than the cutoff goes; the interrupted task is never swept no \
         matter how old, because an interrupt waiting on a human is exactly the row that \
         legitimately sits still"
    );
    assert!(
        store.get_task(&t_done).expect("get_task").is_none(),
        "the purged task is gone"
    );
    assert!(
        store.get_task(&t_live).expect("get_task").is_some(),
        "a non-terminal task is never purged"
    );
    assert!(
        store
            .list_task_events(&t_done)
            .expect("list_task_events")
            .is_empty(),
        "the purge is the ONLY retention method the contract gives task_events, so a swept task's \
         chain must go with it or it is unbounded forever"
    );
    drop(store);

    let direct_task = Vocab::get_task(&direct, &t_live)
        .expect("get_task via the direct connection")
        .expect("the task must be physically present in Valkey, not just cached in-process");
    assert_eq!(direct_task.artifact_cursor, 9);
    assert_eq!(direct_task.state, "input-required");
    assert_eq!(
        Vocab::list_task_events(&direct, &t_live)
            .expect("list_task_events via the direct connection")
            .len(),
        3
    );

    Vocab::put_task(&direct, &task(&t_live, "canceled", BASE_TS + 200, 9))
        .expect("clean up this run's task");
    Vocab::purge_tasks_before(&direct, u64::MAX).expect("clean up this run's rows");
}

/// THE DURABILITY PROOF FOR THE FOUR TRUST-STATE METHODS, OVER THE REAL PLUGIN PATH.
///
/// Same reasoning as the task-store test above, and a sharper cost. The contract defaults the
/// demotion's upsert / listing / delete to accept-and-keep-nothing, so a seam that does not RELAY them
/// discards a demotion while reporting success, and a restart hands a quarantined upstream the
/// operator's approval back. The redemption defaults FAIL-CLOSED (`Ok(false)`), so an unrelayed seam
/// refuses every confirmation; what this proves is the other half — that a relayed ledger is really
/// shared and durable, so a single-use approval executes once, not once per node and once per
/// restart.
///
/// A Valkey deployment reaches this backend ONLY over the plugin seam, and it is the backend a
/// FLEET reaches for first — so the second-node case below is the ordinary deployment, not an
/// exotic one. A real `dlopen`, the real memory ABI, the real `LoadedStore`; two simultaneous loads are the
/// fleet, a drop and a reload is the restart, and a third leg reads through the plain `ValkeyStore`
/// so a plugin answering out of its own in-process state still fails.
///
/// Skips locally when no Valkey is configured and fails under CI, like its siblings
/// ([`valkey_url`]): it is the only over-the-ABI coverage of two properties whose unimplemented form
/// is silently green.
#[test]
fn trust_state_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    let path = plugin_path();
    let Some(url) = valkey_url() else {
        return;
    };
    let mut isolated: url::Url = url.parse().unwrap();
    isolated.set_path("/14");
    let url = isolated.to_string();
    let _database = database::Database::take(&url);
    let cfg = serde_json::json!({ "url": url }).to_string();

    let direct = ValkeyStore::connect(&url).expect("connect directly to clean up and verify");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let srv_demoted = format!("srv_abi_demoted_{stamp}");
    let srv_cleared = format!("srv_abi_cleared_{stamp}");
    let nonce_restart = format!("nonce_abi_restart_{stamp}");
    let nonce_fleet = format!("nonce_abi_fleet_{stamp}");
    let nonce_fresh = format!("nonce_abi_fresh_{stamp}");
    const NOW: u64 = 4_000_000_000;

    let demotion = |server: &str, reason: &str, at: u64| DemotionRow {
        server: server.to_string(),
        reason: reason.to_string(),
        recorded_at: at,
    };

    {
        let store = load(&path, &cfg).expect("the valkey plugin must load over the real ABI");
        store
            .put_mcp_demotion(&demotion(&srv_demoted, "tool-drift", NOW))
            .expect("put_mcp_demotion");

        store
            .put_mcp_demotion(&demotion(&srv_demoted, "digest-mismatch", NOW + 10))
            .expect("put_mcp_demotion");
        store
            .put_mcp_demotion(&demotion(&srv_cleared, "tool-drift", NOW + 20))
            .expect("put_mcp_demotion");
        store
            .clear_mcp_demotion(&srv_cleared)
            .expect("a later agreeing observation clears the quarantine");
        assert!(
            store
                .redeem_ask_state(&nonce_restart, u64::MAX, NOW)
                .expect("redeem_ask_state"),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );

        drop(store);
    }

    let store = load(&path, &cfg).expect("the valkey plugin must load again over the real ABI");

    let mine = store
        .list_mcp_demotions()
        .expect("list_mcp_demotions")
        .into_iter()
        .filter(|r| r.server == srv_demoted || r.server == srv_cleared)
        .collect::<Vec<_>>();
    assert_eq!(
        mine,
        vec![demotion(&srv_demoted, "digest-mismatch", NOW + 10)],
        "the boot read must put the recorded quarantine back in force — at its LATEST reason, and \
         without the one a later agreeing observation cleared. An empty answer here is the \
         accept-and-keep-nothing trait default an unrelayed seam substitutes, and it means a \
         restart hands a demoted upstream the operator's approval back"
    );

    assert!(
        !store
            .redeem_ask_state(&nonce_restart, u64::MAX, NOW + 1)
            .expect("redeem_ask_state"),
        "a restart handed a spent approval back over the plugin ABI. The approval has not lapsed — \
         outliving a restart is the point of it — so the only thing that changed is that the \
         process which recorded the redemption is gone"
    );

    let node_b = load(&path, &cfg).expect("a second node loads the same plugin");
    assert!(store
        .redeem_ask_state(&nonce_fleet, u64::MAX, NOW + 2)
        .expect("redeem_ask_state"));
    assert!(
        !node_b
            .redeem_ask_state(&nonce_fleet, u64::MAX, NOW + 3)
            .expect("redeem_ask_state"),
        "a second node redeemed an approval the first already spent, which is one operator \
         confirmation executing once per node"
    );

    assert!(
        node_b
            .redeem_ask_state(&nonce_fresh, u64::MAX, NOW + 4)
            .expect("redeem_ask_state"),
        "a freshly minted approval is not the one that was spent; refusing it would make the shared \
         ledger a blanket refusal of every confirmation after the first"
    );
    drop(store);
    drop(node_b);

    assert!(
        Vocab::list_mcp_demotions(&direct)
            .expect("list_mcp_demotions via the direct connection")
            .iter()
            .any(|r| r.server == srv_demoted && r.reason == "digest-mismatch"),
        "the demotion must be physically present in Valkey, not merely cached in the plugin"
    );
    assert!(
        !Vocab::redeem_ask_state(&direct, &nonce_restart, u64::MAX, NOW + 5)
            .expect("redeem_ask_state via the direct connection"),
        "the spent-approval entry must be physically present in Valkey: a direct connection that \
         never loaded the plugin has to see the redemption the plugin recorded"
    );

    Vocab::clear_mcp_demotion(&direct, &srv_demoted).expect("clean up this run's demotion");
}
