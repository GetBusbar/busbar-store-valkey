// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE VALKEY STORE, BOTH DOORS, ONE TABLE** — the store's linked + dropped-in conformance on the
//! store kind's memory ABI (store v3), run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The store is held two ways at once: LINKED (the logic crate's `door`, as a busbar build that
//! compiles it in registers it: `LinkedRow::of(door)` through the loader's `load_linked`) and
//! DROPPED IN (this crate's built cdylib, its Statement rendered the way `busbar-plugin-pack`
//! renders it into the signed manifest, then `dlopen`ed by the loader's `load_dropped`). Each is
//! bound to its own dispatcher, opened the way the host opens a store (`LoadedStore`), and driven
//! through the same transcript:
//!
//! - the name its Statement states;
//! - the refusals the store's own `open` gives for settings that cannot produce a store (no `url`,
//!   malformed JSON, a URL the driver refuses, an unreachable server) — each in the store's own
//!   words, across the door;
//! - against the live Valkey (`VALKEY_URL`): one scenario over every surface a governance store
//!   answers — a key (mint, read, tombstone, the tombstone guard), a credential (mint, the live-owner
//!   refusal, lookup, revoke), the usage ledger (additive, floored), metering (the dated split), the
//!   audit chain (replay, fork), the plane-record verbs (upsert, chain append, replay, fork, listing,
//!   parents, terminal-only purge with its cascade, single-use token, live token) — and the store v3
//!   slots (window caps, a whole-cell reserve, its replay, a release, the journal and its replay,
//!   records, sessions).
//!
//! The two transcripts must agree line for line. Each arm runs in its own namespace (fresh ids, a
//! fresh plane kind), so the arms never read each other's rows; the namespace is replaced by a fixed
//! token before comparing.
//!
//! THE RED ARMS, each its own test: the library asked for as another kind is refused before it is
//! opened; a manifest whose Statement is one byte off the library's own is refused; and (live) a
//! PERTURBED dropped-in arm — its namespace already holding a different record at a position the
//! scenario appends to — must NOT produce the linked transcript.
//!
//! The live leg follows this repo's Valkey gate: skipped locally without `VALKEY_URL`, a HARD
//! FAILURE under `CI` without it. A missing cdylib is always a failure, never a skip: this test IS
//! the dropped-in door's proof.

// THE PUBLISHED SUITE (busbar-plugin-loader's `conformance` feature, at the pin): the linked door and
// the built cdylib, each through the one loader, driven by the store kind's script over the live
// Valkey `conformance.json` names; exact crossing counts, the two folds equal, its RED arms.
//
// THE HOST (ARCHITECT Q-P4-9): the store's `tcp` need is served by busbar's own connector, composed
// as the root composes it (`conformance_host`, rendered by the fleet template), and the store asks
// for TLS (`rediss://`): the suite's TLS front answers, its certificate chaining to the suite's test
// CA, the anchors only the HOST's TLS is handed (`tls:`); the front carries the secured connection to
// the live Valkey. So every fold proves the store's connection is secured by the host, verified
// against the anchors.
//
// EACH FOLD'S KEYSPACE (Q-P4-8): the store's keys are fixed (`busbar:*`) and its settings name no key
// prefix, and a fold namespace is no database number, so `{fold}` has nowhere to go in the url. The
// suite's folds therefore run in a database of their own (`/14`; this repo's other live tests use the
// url's `/0` and the admin end-to-end test `/15`), one fold at a time: the namespace hooks below take
// that database for the fold and flush it before the fold opens, and flush it and hand it on when
// the fold ends, on an independent connection of the `redis` client. Every fold starts on an empty
// keyspace and leaves none; nothing in the store's behaviour changes.
#[path = "support/conformance_host.rs"]
mod conformance_host;

busbar_plugin_loader::conformance_suite! {
    door: busbar_store_valkey::door,
    cdylib: "busbar_store_valkey_plugin",
    inputs: include_str!("conformance.json"),
    host: host,
    tls: conformance_host::anchors(),
    namespace: (take_fold_keyspace, drop_fold_keyspace),
}

/// The live Valkey's address (`VALKEY_URL`'s authority; the service's default when unset).
fn upstream() -> &'static str {
    static AT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    AT.get_or_init(|| {
        let url = std::env::var("VALKEY_URL").unwrap_or_default();
        url.split_once("://")
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.rsplit_once('@').map_or(Some(rest), |(_, at)| Some(at)))
            .and_then(|at| at.split(['/', '?']).next())
            .filter(|at| !at.is_empty())
            .unwrap_or("127.0.0.1:6379")
            .to_owned()
    })
}

/// `rediss://` negotiates nothing in the clear: the TLS handshake is the connection's first byte.
fn no_preamble(_: &mut std::net::TcpStream) -> bool {
    true
}

/// The host the suite binds the store over, with the TLS front its settings name already listening.
fn host(
    wake: std::sync::Arc<dyn Fn(u64) + Send + Sync>,
    anchors: Option<&str>,
) -> std::sync::Arc<dyn busbar_contract::conn::DeclaredConns> {
    conformance_host::tls_front(no_preamble, upstream());
    conformance_host::host(wake, anchors)
}

/// The fold's database on the live server, on a connection of the `redis` client's own: straight to
/// the server, in the clear (the TLS front is the store's, not this client's).
fn fold_client(settings: &[u8]) -> redis::RedisResult<redis::Connection> {
    let v: serde_json::Value =
        serde_json::from_slice(settings).expect("conformance.json's settings are JSON");
    let url = v["url"]
        .as_str()
        .expect("conformance.json's settings name a url")
        .replace(
            &format!("rediss://{}", conformance_host::FAR_END),
            &format!("redis://{}", upstream()),
        );
    redis::Client::open(url.as_str())?.get_connection()
}

fn flush_fold_keyspace(settings: &[u8]) -> redis::RedisResult<()> {
    redis::cmd("FLUSHDB").query::<()>(&mut fold_client(settings)?)
}

/// The suite's database, held by one fold at a time: the namespace of the fold holding it.
fn fold_gate() -> &'static (std::sync::Mutex<Option<String>>, std::sync::Condvar) {
    static GATE: std::sync::OnceLock<(std::sync::Mutex<Option<String>>, std::sync::Condvar)> =
        std::sync::OnceLock::new();
    GATE.get_or_init(Default::default)
}

/// Hand the suite's database on (the fold that held it is over).
fn release_fold_keyspace(namespace: &str) {
    let (held, freed) = fold_gate();
    let mut held = held
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if held.as_deref() == Some(namespace) {
        *held = None;
    }
    freed.notify_all();
}

/// The suite's namespace hook, before the fold's open: the fold takes the suite's database (waiting
/// while another fold holds it) and it is flushed, so the fold opens on an empty keyspace.
fn take_fold_keyspace(namespace: &str, settings: &[u8]) {
    let (held, freed) = fold_gate();
    let mut slot = held
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    while slot.is_some() {
        slot = freed
            .wait(slot)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    *slot = Some(namespace.to_owned());
    drop(slot);
    if let Err(e) = flush_fold_keyspace(settings) {
        // No fold runs, so no drop hook will hand the database on: hand it on here.
        release_fold_keyspace(namespace);
        panic!("the fold's keyspace is not flushed before its open: {e}");
    }
}

/// The suite's namespace hook, after the fold (its failure included): everything the store wrote in
/// the fold is flushed, and the database is handed to the next fold.
fn drop_fold_keyspace(namespace: &str, settings: &[u8]) {
    let flushed = flush_fold_keyspace(settings);
    release_fold_keyspace(namespace);
    flushed.unwrap_or_else(|e| panic!("the fold's keyspace is not flushed after the fold: {e}"));
}

use std::path::{Path, PathBuf};
use std::sync::Arc;

use busbar_contract::abi::sdk::store::{Cap, Cell, CellKey, Dimension};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, ModelTokensDelta,
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, SecretForm, UsageDelta, VirtualKey,
};
use busbar_contract::store_calls::StoreCalls;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher,
    LinkedRow, NoSink, Plugin,
};
use busbar_plugin_loader::store_v3::LoadedStore;

/// The live server, per this repo's gate.
fn valkey_url() -> Option<String> {
    match std::env::var("VALKEY_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => panic!(
            "VALKEY_URL is unset under CI: the Valkey service must provision it. Refusing to skip \
             the live leg of the both-doors proof."
        ),
        Err(_) => {
            eprintln!("skip (live leg only): set VALKEY_URL to compare the doors on a live Valkey");
            None
        }
    }
}

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_store_valkey_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-store-valkey-plugin cdylib ({file}) is not built"))
}

/// What a door is bound to: its own dispatcher's adopter, no envelope sink, no connections.
/// The node's one `op_id` allocator (`LoadedStore::open` mints the bridge's writes from it): a node
/// half no earlier run used (the dedupe is durable) and one counter.
fn mint() -> busbar_contract::abi::store::OpId {
    static NODE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let node = *NODE.get_or_init(|| unique() | 1);
    busbar_contract::abi::store::OpId::from_parts(
        node,
        N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
    )
}

/// The bind the host makes: the store's declared need served by the loader's test connection table
/// (plain TCP, the host's connector path).
fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("store-valkey-conformance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Host(Arc::new(busbar_plugin_loader::tcp_conns::TcpConns::new(
            d.conn_waker(),
        ))),
    }
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

/// The library's Statement as `busbar-plugin-pack` renders it into the signed manifest.
fn packed_rendering(lib: &Path) -> Vec<u8> {
    rendering_of_library(lib)
        .expect("the library's door renders")
        .expect("the library exports a door")
}

/// One door, loaded one way: a plugin and the dispatcher that adopted it.
type Loaded = (Plugin<Store>, Arc<Dispatcher>);

/// THE LINKED DOOR: the row a busbar build that compiles this store in registers.
fn linked() -> Loaded {
    let d = dispatcher();
    let row = LinkedRow::of(busbar_store_valkey::door).expect("the door states its Statement");
    let p = load_linked::<Store>(&row, bind(&d)).expect("the linked door loads");
    (p, d)
}

/// THE DROPPED-IN DOOR: the built cdylib against the rendering its manifest would carry.
fn dropped(lib: &Path, stated: &[u8]) -> Loaded {
    let d = dispatcher();
    let p = load_dropped::<Store>(lib, stated, bind(&d)).expect("the dropped-in door loads");
    (p, d)
}

fn block<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

/// A number no other arm, instance or earlier run uses.
fn unique() -> u64 {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    (t ^ (u64::from(std::process::id()) << 32))
        .wrapping_add(N.fetch_add(1, std::sync::atomic::Ordering::Relaxed) << 48)
        | 1
}

/// A fresh op id (the dedupe is durable: an op id from an earlier run would replay).
fn op(counter: u64) -> OpId {
    OpId::from_parts(unique(), counter * 2 + 1)
}

/// Open the store through one door (`LoadedStore`, the way the host opens it), on a node id no
/// other instance uses: the bridge mints op ids as `(node, counter from 0)` and the dedupe is
/// durable.
fn open(load: &impl Fn() -> Loaded, settings: &str) -> Result<LoadedStore, String> {
    let (plugin, dispatcher) = load();
    LoadedStore::open(plugin, dispatcher, settings.as_bytes(), mint)
}

/// One `Result` as comparable text: `ok:<debug>` or `err:<message>`.
fn r<T: std::fmt::Debug, E: std::fmt::Display>(res: Result<T, E>) -> String {
    match res {
        Ok(v) => format!("ok:{v:?}"),
        Err(e) => format!("err:{e}"),
    }
}

/// The live scenario, in namespace `ns`, through `store`. Every observable the scenario produces is
/// one line of the returned transcript.
fn scenario(loaded: &LoadedStore, ns: &str) -> Vec<String> {
    // The 1.5.5 op set through the store's `RecordStore` face (the v3 slots below are `StoreCalls`).
    let store: &dyn RecordStore = loaded;
    let mut t = Vec::new();
    let kind = format!("conf_{ns}");
    let key_id = format!("{ns}_key");
    let key = VirtualKey {
        id: key_id.clone(),
        generation_hash: format!("binding:{key_id}:g1"),
        name: "conformance".into(),
        enabled: true,
        created_at: 1_000,
        group: Some("g".into()),
        idp_subject: Some("alice".into()),
        ..Default::default()
    };
    // KEYS: mint, read back (revision is store-stamped, so only its presence is compared).
    t.push(r(store.put_key(&key)));
    let back = store.get_key(&key_id).unwrap().expect("the key reads back");
    t.push(format!(
        "key:{}:{}:{:?}:{:?}:{}",
        back.id,
        back.name,
        back.group,
        back.idp_subject,
        back.revision > 0
    ));
    // CREDENTIALS: the owner must be live; mint; lookup; revoke; unknown revoke refused.
    let cred = |id: &str, owner: &str| CredentialSecret {
        meta: CredentialMeta {
            id: format!("{ns}_{id}"),
            key_id: owner.into(),
            kind: "sigv4".into(),
            slot: 0,
            public_id: format!("AKIA{ns}{id}"),
            secret_form: SecretForm::Recoverable,
            created_at: 1_000,
            updated_at: 1_000,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: format!("v1:plain:{id}"),
    };
    t.push(r(
        store.put_credential(&cred("orphan", &format!("{ns}_nokey")))
    ));
    t.push(r(store.put_credential(&cred("c1", &key_id))));
    t.push(format!(
        "lookup:{:?}",
        store
            .lookup_credential_secret("sigv4", &format!("AKIA{ns}c1"))
            .unwrap()
            .map(|c| (c.meta.id, c.secret))
    ));
    t.push(r(store.revoke_credential(&format!("{ns}_c1"), "leaked")));
    t.push(r(store.revoke_credential(&format!("{ns}_nope"), "x")));
    // THE TOMBSTONE: delete, the guard, idempotency, the unknown id.
    t.push(r(store.delete_key(&key_id)));
    t.push(r(store.delete_key(&key_id)));
    t.push(r(store.put_key(&key)));
    t.push(r(store.delete_key(&format!("{ns}_absent"))));
    t.push(format!(
        "tomb:{:?}",
        store
            .get_key(&key_id)
            .unwrap()
            .map(|k| (k.enabled, k.deleted_at.is_some()))
    ));
    // USAGE: additive, floored at 0, open units beside the reserved ones.
    let delta = |input: i64, calls: i64| UsageDelta {
        requests: input.signum(),
        billable_requests: 0,
        models: vec![ModelTokensDelta {
            model: "m".into(),
            usage_units: [
                ("input".to_string(), input),
                ("tool_calls".to_string(), calls),
            ]
            .into_iter()
            .collect(),
        }],
    };
    let bucket = format!("{ns}_bucket");
    t.push(r(store.add_usage(&bucket, 60, &delta(10, 2))));
    t.push(r(store.add_usage(&bucket, 60, &delta(-30, 1))));
    t.push(format!("usage:{:?}", store.get_usage(&bucket, 60).unwrap()));
    // METERING: a price change splits the cell.
    let bucket_n: u64 = 7_000_000_000 + u64::from(std::process::id());
    for priced_from_ms in [0, 0, 5_000] {
        t.push(r(store.add_metering(&MeteringDelta {
            key_id: key_id.clone(),
            bucket: bucket_n,
            model: "m".into(),
            provider: "p".into(),
            tokens_input: 3,
            tokens_output: 1,
            tokens_cache_read: 0,
            tokens_cache_write: 0,
            requests: 1,
            billable_requests: 1,
            key_group_at_use: "g".into(),
            pricing_version: "v".into(),
            priced_from_ms,
            usage_units: [("tool_calls".to_string(), 1)].into_iter().collect(),
        })));
    }
    let mut cells: Vec<_> = store
        .list_metering(bucket_n)
        .unwrap()
        .into_iter()
        .filter(|m| m.key_id == key_id)
        .map(|m| (m.priced_from_ms, m.requests, m.tokens_input, m.usage_units))
        .collect();
    cells.sort();
    t.push(format!("metering:{cells:?}"));
    // AUDIT: an identical replay is Ok, a different record at the seq is a fork.
    let seq = 950_000_000 + u64::from(std::process::id()) * 10 + (ns.len() as u64 % 10);
    let audit = |action: &str| AuditRecord {
        seq,
        ts: 1,
        action: action.into(),
        resource: "r".into(),
        outcome: "applied".into(),
        principal: "p".into(),
        prev_hash: String::new(),
        hash: "h".into(),
    };
    t.push(r(store.append_audit(&audit("a"))));
    t.push(r(store.append_audit(&audit("a"))));
    t.push(r(store
        .append_audit(&audit("b"))
        .map_err(|e| e.to_string().replace(&seq.to_string(), "SEQ"))));
    // PLANE RECORDS, in a kind nothing else writes.
    let rec = |id: &str, parent: Option<&str>, seq: u64, ts: u64, terminal: bool, body: &str| {
        PlaneRecord {
            kind: kind.clone(),
            id: id.into(),
            parent: parent.map(Into::into),
            seq,
            ts,
            disposition: if terminal {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
            },
            body: body.as_bytes().to_vec(),
        }
    };
    t.push(r(store.upsert_plane_record(
        rec("t1", None, 0, 10, false, "v1").view(),
    )));
    t.push(r(store.upsert_plane_record(
        rec("t1", None, 0, 11, false, "v2").view(),
    )));
    t.push(r(store.upsert_plane_record(
        rec("t2", None, 0, 12, true, "done").view(),
    )));
    for (seq, body) in [(2, "e2"), (1, "e1"), (3, "e3")] {
        t.push(r(store.append_plane_record(
            rec("t1", Some("t1"), seq, 20, false, body).view(),
        )));
    }
    t.push(r(store.append_plane_record(
        rec("t1", Some("t1"), 2, 20, false, "e2").view(),
    )));
    t.push(r(store.append_plane_record(
        rec("t1", Some("t1"), 2, 20, false, "FORK").view(),
    )));
    t.push(r(store.append_plane_record(
        rec("p:x", Some("p:x"), 1, 30, false, "c1").view(),
    )));
    let text = |bodies: Vec<Vec<u8>>| {
        bodies
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .collect::<Vec<_>>()
    };
    t.push(format!(
        "get:{:?}",
        store
            .get_plane_record(&kind, "t1")
            .unwrap()
            .map(|b| text(vec![b]))
    ));
    t.push(format!(
        "all:{:?}",
        text(
            store
                .list_plane_records(&kind, &PlaneSelector::All)
                .unwrap()
        )
    ));
    t.push(format!(
        "chain:{:?}",
        text(
            store
                .list_plane_records(&kind, &PlaneSelector::Parent("t1".into()))
                .unwrap()
        )
    ));
    t.push(format!(
        "parents:{:?}",
        store.list_plane_record_parents(&kind).unwrap()
    ));
    t.push(format!(
        "live:{:?}",
        [
            store.plane_token_live(&kind, "t1", 100, 50).unwrap(),
            store.plane_token_live(&kind, "t1", 100, 101).unwrap(),
            store.plane_token_live(&kind, "t2", 100, 50).unwrap(),
        ]
    ));
    t.push(format!(
        "purge:{}",
        store.purge_plane_records_before(&kind, 25).unwrap()
    ));
    t.push(format!(
        "after-purge:{:?}",
        text(
            store
                .list_plane_records(&kind, &PlaneSelector::All)
                .unwrap()
        )
    ));
    t.push(r(store.delete_plane_record(&kind, "t1")));
    t.push(format!(
        "after-delete:{:?}/{:?}",
        text(
            store
                .list_plane_records(&kind, &PlaneSelector::All)
                .unwrap()
        ),
        store.list_plane_record_parents(&kind).unwrap()
    ));
    let tok = format!("{ns}_tok");
    t.push(format!(
        "redeem:{:?}",
        [
            store
                .redeem_plane_token(&kind, &tok, 4_000_000_000, 3_999_999_000)
                .unwrap(),
            store
                .redeem_plane_token(&kind, &tok, 4_000_000_000, 3_999_999_001)
                .unwrap(),
        ]
    ));
    // THE STORE V3 SLOTS, through the door's own table.
    let bucket = format!("{ns}_cap");
    let k = CellKey {
        bucket: &bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start: 60,
    };
    let cells = [Cell { key: k, amount: 2 }, Cell { key: k, amount: 1 }];
    let stream = format!("{ns}_stream");
    let schema = format!("{ns}_schema");
    let principal = format!("{ns}_principal");
    let session = unique() >> 2;
    block(async {
        t.push(format!(
            "reserve, no cap = {:?}",
            StoreCalls::reserve(loaded, op(1), 0, &cells).await
        ));
        let caps = [Cap {
            key: k,
            cap: 3,
            config_gen: 1,
        }];
        t.push(format!(
            "window_caps = {:?}",
            StoreCalls::window_caps(loaded, op(2), &caps).await
        ));
        let id = op(3);
        let grants = StoreCalls::reserve(loaded, id, 0, &cells).await;
        t.push(format!(
            "reserve = {:?}",
            grants.as_ref().map(|g| g
                .iter()
                .map(|g| (g.granted, g.valid_until_ms))
                .collect::<Vec<_>>())
        ));
        let replay = StoreCalls::reserve(loaded, id, 0, &cells).await;
        t.push(format!(
            "replay answers the original grants = {}",
            replay.as_ref().ok() == grants.as_ref().ok()
        ));
        t.push(format!(
            "reserve past the cap = {:?}",
            StoreCalls::reserve(loaded, op(4), 0, &cells[1..]).await
        ));
        if let Ok(g) = &grants {
            let items = [(g[0].slice_id, 5)];
            t.push(format!(
                "release = {:?}",
                StoreCalls::slice_release(loaded, op(5), 0, &items).await
            ));
        }
        let rb = |b: &[u8]| RecordBytes::new(b.to_vec()).unwrap();
        let id = op(6);
        t.push(format!(
            "append_batch = {:?}",
            StoreCalls::append_batch(loaded, id, &stream, &[rb(b"one"), rb(b"two")]).await
        ));
        t.push(format!(
            "append_batch replay = {:?}",
            StoreCalls::append_batch(loaded, id, &stream, &[rb(b"one"), rb(b"two")]).await
        ));
        t.push(format!(
            "append_batch reused op id = {:?}",
            StoreCalls::append_batch(loaded, id, &stream, &[rb(b"three")]).await
        ));
        t.push(format!(
            "record_put = {:?}",
            StoreCalls::record_put(loaded, &schema, b"k", &rb(b"v")).await
        ));
        t.push(format!(
            "record_get = {:?}",
            StoreCalls::record_get(loaded, &schema, b"k")
                .await
                .map(|v| v.map(|v| String::from_utf8_lossy(v.as_slice()).into_owned()))
        ));
        t.push(format!(
            "session_put = {:?}",
            StoreCalls::session_put(loaded, session, "node-a", &principal).await
        ));
        t.push(format!(
            "sessions_for = {:?}",
            StoreCalls::sessions_for(loaded, &principal)
                .await
                .map(|v| v.into_iter().map(|(_, node)| node).collect::<Vec<_>>())
        ));
        t.push(format!(
            "session_remove = {:?}",
            StoreCalls::session_remove(loaded, session).await
        ));
    });
    t.iter().map(|l| l.replace(ns, "NS")).collect()
}

/// What one door does, as one comparable transcript. `load` loads the door afresh: a refused
/// `open` consumes the instance it was offered. `plant` writes through the opened store before the
/// scenario runs (the perturbed RED arm).
fn transcript(
    load: impl Fn() -> Loaded,
    live: Option<(&str, &str)>,
    plant: impl Fn(&LoadedStore, &str),
) -> Vec<String> {
    let mut t = vec![format!("name = {}", load().0.name())];
    for cfg in [
        "",
        "{ not json",
        r#"{"url":"not-a-valkey-url"}"#,
        r#"{"url":"redis://127.0.0.1:1/0","connect_timeout_ms":300}"#,
    ] {
        t.push(format!("open {cfg:?} = {:?}", open(&load, cfg).map(|_| ())));
    }
    if let Some((url, ns)) = live {
        let s = open(&load, &serde_json::json!({ "url": url }).to_string())
            .expect("the store opens against the live Valkey");
        t.push(format!("facts = {:?}", s.facts()));
        plant(&s, ns);
        t.extend(scenario(&s, ns));
    }
    t
}

/// The two transcripts are equal, line for line; a divergence names its first line.
fn same(linked: &[String], dropped: &[String]) {
    for (i, (a, b)) in linked.iter().zip(dropped).enumerate() {
        assert_eq!(
            a, b,
            "the two doors diverge at line {i}:\n linked:     {a}\n dropped in: {b}"
        );
    }
    assert_eq!(
        linked.len(),
        dropped.len(),
        "the two doors ran different scripts"
    );
}

/// A fresh namespace for one arm.
fn ns(arm: &str) -> String {
    format!("vkconf{arm}{:x}", unique())
}

/// The Valkey store behaves as ONE store through either door, and the dropped-in library states the
/// linked door's Statement byte for byte.
#[test]
fn the_linked_and_the_dropped_in_valkey_store_are_one_store() {
    let url = valkey_url();
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    assert_eq!(
        stated,
        LinkedRow::of(busbar_store_valkey::door)
            .expect("the linked row")
            .statement,
        "the dropped-in library states the linked door's Statement byte for byte"
    );

    let (ns_l, ns_d) = (ns("l"), ns("d"));
    let linked = transcript(
        linked,
        url.as_deref().map(|u| (u, ns_l.as_str())),
        |_, _| {},
    );
    let dropped_in = transcript(
        || dropped(&lib, &stated),
        url.as_deref().map(|u| (u, ns_d.as_str())),
        |_, _| {},
    );
    same(&linked, &dropped_in);
    assert_eq!(linked[0], format!("name = {}", busbar_store_valkey::NAME));

    // The transcript is about the store, not about nothing: the refusals are the store's own words,
    // and (live) the scenario did what a governance store is for.
    assert!(linked[1].contains("requires a \\\"url\\\""), "{linked:#?}");
    assert!(
        linked[2].contains("invalid valkey plugin config"),
        "{linked:#?}"
    );
    assert!(
        linked[3].contains("valkey plugin: failed to connect"),
        "{linked:#?}"
    );
    assert!(
        linked[4].contains("valkey plugin: failed to connect"),
        "{linked:#?}"
    );
    if url.is_some() {
        let has = |needle: &str| linked.iter().any(|l| l.contains(needle));
        let find = |p: &str| {
            linked
                .iter()
                .find(|l| l.starts_with(p))
                .unwrap_or_else(|| panic!("no {p} line in {linked:#?}"))
                .clone()
        };
        assert!(find("facts").contains("ephemeral: false"), "{linked:#?}");
        assert!(
            has("does not exist; a credential must hang off a real key"),
            "{linked:#?}"
        );
        assert!(
            has("is tombstoned and its id is never reissued"),
            "{linked:#?}"
        );
        assert!(has("the chain has forked"), "{linked:#?}");
        assert!(has("the audit chain has forked"), "{linked:#?}");
        assert!(has(r#"chain:["e1", "e2", "e3"]"#), "{linked:#?}");
        assert!(has(r#"parents:["p:x", "t1"]"#), "{linked:#?}");
        assert!(has("live:[true, false, false]"), "{linked:#?}");
        assert!(
            has("purge:5"),
            "a kind other than `task` drops EVERY row older than the cutoff (t1, t2, e1-e3): \
             {linked:#?}"
        );
        assert!(has("redeem:[true, false]"), "{linked:#?}");
        assert!(has("metering:[(0, 2, 6"), "{linked:#?}");
        assert!(find("reserve, no cap").contains("NoCap"), "{linked:#?}");
        assert_eq!(
            find("reserve ="),
            format!("reserve = Ok([(2, {m}), (1, {m})])", m = u64::MAX)
        );
        assert!(find("replay").ends_with("true"), "{linked:#?}");
        assert!(find("reserve past").contains("Exhausted"), "{linked:#?}");
        assert_eq!(find("release"), "release = Ok([2])");
        assert!(
            find("append_batch =").contains("seq: 2, epoch: 0"),
            "{linked:#?}"
        );
        assert_eq!(
            find("append_batch replay"),
            find("append_batch =").replace("append_batch =", "append_batch replay =")
        );
        assert_eq!(
            find("append_batch reused"),
            "append_batch reused op id = Err(Conflict)"
        );
        assert_eq!(find("record_get"), "record_get = Ok(Some(\"v\"))");
        assert_eq!(find("sessions_for"), "sessions_for = Ok([\"node-a\"])");
    }
}

/// RED ARM (live): a PERTURBED dropped-in store — its namespace already holds a different record at
/// a chain position the scenario appends to — must not reproduce the linked transcript. Without a
/// server the perturbation is the settings: an unreachable server is another store.
#[test]
fn a_perturbed_dropped_in_store_does_not_pass_for_the_linked_one() {
    let url = valkey_url();
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let (ns_l, ns_r) = (ns("l"), ns("r"));
    let linked = transcript(
        linked,
        url.as_deref().map(|u| (u, ns_l.as_str())),
        |_, _| {},
    );
    let red = match url.as_deref() {
        Some(u) => transcript(
            || dropped(&lib, &stated),
            Some((u, ns_r.as_str())),
            |s, ns| {
                RecordStore::append_plane_record(
                    s,
                    PlaneRecord {
                        kind: format!("conf_{ns}"),
                        id: "t1".into(),
                        parent: Some("t1".into()),
                        seq: 3,
                        ts: 20,
                        disposition: PlaneDisposition::Active,
                        body: b"planted".to_vec(),
                    }
                    .view(),
                )
                .expect("plant a rival record");
            },
        ),
        None => {
            let mut t = transcript(|| dropped(&lib, &stated), None, |_, _| {});
            t.push(format!(
                "open unreachable = {:?}",
                open(
                    &|| dropped(&lib, &stated),
                    r#"{"url":"redis://127.0.0.1:2/0","connect_timeout_ms":300}"#
                )
                .map(|_| ())
            ));
            t
        }
    };
    assert_ne!(
        red, linked,
        "a perturbed store must not pass for the linked one"
    );
}

/// RED ARM: the library asked for as another kind is refused before it is opened.
#[test]
fn a_store_library_asked_for_as_a_secret_is_refused() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let d = dispatcher();
    let e = match load_dropped::<Secret>(&lib, &stated, bind(&d)) {
        Ok(_) => panic!("a store library loaded as secret"),
        Err(e) => e.to_string(),
    };
    assert!(
        e.contains("the manifest states kind Store, not Secret"),
        "{e}"
    );
}

/// RED ARM: a manifest whose Statement is one byte off the library's own is refused.
#[test]
fn a_statement_one_byte_off_is_refused() {
    let lib = cdylib();
    let mut other = packed_rendering(&lib);
    other.push(0);
    let d = dispatcher();
    let e = match load_dropped::<Store>(&lib, &other, bind(&d)) {
        Ok(_) => panic!("a library loaded under a Statement that is not its own"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("repack the plugin"), "{e}");
}
