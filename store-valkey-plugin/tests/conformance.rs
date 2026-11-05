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
//!   plane-record verbs (upsert, chain append, replay, fork, listing,
//!   parents, terminal-only purge with its cascade, single-use token, live token) — and the store v3
//!   slots (the usage batch, its replay and its reused op id, records).
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

#[path = "../../test-support/database.rs"]
mod database;
#[path = "support/store_behavior.rs"]
mod store_behavior;
#[path = "../../test-support/valkey_io.rs"]
mod valkey_io;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, MeteringDelta, ModelTokensDelta, PlaneDisposition,
    PlaneRecord, PlaneSelector, RecordStore, SecretForm, UsageDelta, VirtualKey,
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

/// This crate's built cdylib, from `deps/` only: the copy the build graph of this very test binary
/// refreshed (`target/<profile>/` is uplifted by `cargo build` alone and can be stale). A missing
/// artifact is a failure, never a skip.
fn cdylib() -> PathBuf {
    let path = if let Some(path) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        let path = PathBuf::from(path);
        assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
        path
    } else {
        let exe = std::env::current_exe().expect("the test binary has a path");
        exe.parent().expect("target/<profile>/deps").join(
            busbar_plugin_loader::plugin_library_filename("busbar_store_valkey_plugin"),
        )
    };
    assert!(
        path.is_file(),
        "fresh Valkey cdylib missing: {}; build it first",
        path.display()
    );
    path
}

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
        conns: ConnTable::Host(valkey_io::host(
            d.conn_waker(),
            busbar_contract::transport::EgressTrust::default(),
        )),
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
            .list_credentials_since(0)
            .unwrap()
            .into_iter()
            .find(|c| c.meta.kind == "sigv4" && c.meta.public_id == format!("AKIA{ns}c1"))
            .map(|c| (c.meta.id, c.secret))
    ));
    t.push(r(store.revoke_credential(&format!("{ns}_c1"), "leaked")));
    t.push(r(store.revoke_credential(&format!("{ns}_nope"), "x")));

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

    let delta = |input: i64, calls: i64| UsageDelta {
        requests: input.signum(),
        billable_requests: 0,
        models: vec![ModelTokensDelta {
            scale: 6,
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

    let bucket_n: u64 = 7_000_000_000 + u64::from(std::process::id());
    for priced_from_ms in [0, 0, 5_000] {
        t.push(r(store.add_metering(&MeteringDelta {
            scale: 6,
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

    let schema = format!("{ns}_schema");
    let usage_bucket = format!("{ns}_batch");
    let cells = [(usage_bucket.as_str(), 60, delta(5, 1))];
    block(async {
        let id = op(1);
        t.push(format!(
            "add_usage_batch = {:?}",
            StoreCalls::add_usage_batch(loaded, id, &cells).await
        ));
        t.push(format!(
            "add_usage_batch replay = {:?}",
            StoreCalls::add_usage_batch(loaded, id, &cells).await
        ));
        t.push(format!(
            "add_usage_batch reused op id = {:?}",
            StoreCalls::add_usage_batch(loaded, id, &[(usage_bucket.as_str(), 60, delta(9, 1))])
                .await
        ));
        let rb = |b: &[u8]| RecordBytes::new(b.to_vec()).unwrap();
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

    assert!(linked[1].contains("`url` is required"), "{linked:#?}");
    assert!(
        linked[2].contains("invalid valkey plugin config"),
        "{linked:#?}"
    );
    assert!(
        linked[3].contains("invalid valkey plugin config: url: ")
            && !linked[3].contains("failed to connect"),
        "{linked:#?}"
    );
    assert!(
        linked[4].contains("valkey store: failed to connect"),
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
        assert_eq!(find("add_usage_batch ="), "add_usage_batch = Ok(())");
        assert_eq!(
            find("add_usage_batch replay"),
            "add_usage_batch replay = Ok(())"
        );
        assert_eq!(
            find("add_usage_batch reused"),
            "add_usage_batch reused op id = Err(Conflict)"
        );
        assert_eq!(find("record_get"), "record_get = Ok(Some(\"v\"))");
    }
}

/// RED ARM (live): a PERTURBED dropped-in store — its namespace already holds a different record at
/// a chain position the scenario appends to — must not reproduce the linked transcript. It needs a
/// server: skipped locally without `VALKEY_URL`, a failure under CI ([`valkey_url`]); an arm that
/// perturbed nothing would pass vacuously.
#[test]
fn a_perturbed_dropped_in_store_does_not_pass_for_the_linked_one() {
    let Some(u) = valkey_url() else { return };
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let (ns_l, ns_r) = (ns("l"), ns("r"));
    let linked = transcript(linked, Some((u.as_str(), ns_l.as_str())), |_, _| {});
    let red = transcript(
        || dropped(&lib, &stated),
        Some((u.as_str(), ns_r.as_str())),
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
    );
    let chain = |lines: &[String]| lines.iter().find(|line| line.contains("chain:")).cloned();
    assert!(chain(&linked).unwrap().contains("e3"));
    assert!(chain(&red).unwrap().contains("planted"));
    assert_ne!(chain(&red), chain(&linked));
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
    use busbar_contract::abi::mechanism::rendering::read;
    use busbar_plugin_loader::dispatch::LoadError;

    let lib = cdylib();
    let mut other = packed_rendering(&lib);
    let name = read(&other).expect("the library's Statement parses").name;
    let name_at = other
        .windows(name.len())
        .position(|bytes| bytes == name.as_bytes())
        .expect("the rendered Statement contains its name");
    other[name_at] = if other[name_at] == b'a' { b'b' } else { b'a' };
    assert_ne!(
        read(&other)
            .expect("the one-byte mutation preserves a valid Statement")
            .name,
        name
    );
    let d = dispatcher();
    let row = LinkedRow {
        statement: other.clone(),
        ..LinkedRow::of(busbar_store_valkey::door).expect("actual linked door")
    };
    assert!(matches!(
        load_linked::<Store>(&row, bind(&d)),
        Err(LoadError::StatementMismatch)
    ));
    let e = match load_dropped::<Store>(&lib, &other, bind(&d)) {
        Ok(_) => panic!("a library loaded under a Statement that is not its own"),
        Err(e) => e,
    };
    assert!(matches!(&e, LoadError::StatementMismatch), "{e}");
    assert!(e.to_string().contains("repack the plugin"), "{e}");
}

#[test]
fn a_statement_with_trailing_bytes_is_refused_as_malformed() {
    use busbar_plugin_loader::dispatch::LoadError;

    let lib = cdylib();
    let mut malformed = packed_rendering(&lib);
    let end = malformed.len();
    malformed.push(0);
    let d = dispatcher();
    let error = match load_dropped::<Store>(&lib, &malformed, bind(&d)) {
        Ok(_) => panic!("a library loaded under a Statement with trailing bytes"),
        Err(error) => error,
    };
    match error {
        LoadError::Rendering(why) => assert_eq!(why, format!("byte {end} is not the end")),
        other => panic!("expected a malformed Statement refusal, got {other}"),
    }
}

/// The former store-kind script, now explicit calls against this shipped store.
#[test]
fn linked_and_dropped_preserve_every_store_operation() {
    let url =
        std::env::var("VALKEY_URL").expect("VALKEY_URL is required for the migrated live suite");
    let mut url: url::Url = url.parse().expect("VALKEY_URL");
    url.set_path("/14");
    assert_eq!(
        store_behavior::behavior(false, url.as_str()),
        store_behavior::behavior(true, url.as_str())
    );
}

#[test]
fn networked_store_requires_a_connection_table_in_both_forms() {
    use busbar_plugin_loader::dispatch::LoadError;
    let row = LinkedRow::of(busbar_store_valkey::door).unwrap();
    let stated = packed_rendering(&cdylib());
    for dropped_in in [false, true] {
        let d = dispatcher();
        let bind = Bind {
            conns: ConnTable::NoNeeds,
            ..bind(&d)
        };
        let result = if dropped_in {
            load_dropped::<Store>(&cdylib(), &stated, bind)
        } else {
            load_linked::<Store>(&row, bind)
        };
        let error = result.expect_err("networked store without table refuses");
        assert!(
            matches!(error, LoadError::NoConnectionTable { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("plugin 'busbar-store-valkey'"));
        load_linked::<Store>(
            &row,
            Bind {
                conns: ConnTable::Probe,
                ..self::bind(&d)
            },
        )
        .expect("probe is admitted");
    }
}

#[test]
fn schema_newer_than_this_build_is_refused_through_both_doors() {
    let url =
        std::env::var("VALKEY_URL").expect("VALKEY_URL is required for the migrated live suite");
    let mut url: url::Url = url.parse().unwrap();
    url.set_path("/14");
    for dropped_in in [false, true] {
        let db = database::Database::take(url.as_str());
        redis::cmd("SET")
            .arg("busbar:schema")
            .arg(i64::MAX)
            .query::<()>(&mut db.connection().unwrap())
            .unwrap();
        let cfg = serde_json::json!({"url": url.as_str()}).to_string();
        let lib = cdylib();
        let stated = packed_rendering(&lib);
        let result = if dropped_in {
            open(&|| dropped(&lib, &stated), &cfg)
        } else {
            open(&linked, &cfg)
        };
        let error = result.expect_err("newer schema refuses boot");
        assert!(error.contains("schema"), "{error}");
        assert!(error.contains(&i64::MAX.to_string()), "{error}");
    }
}

/// Only malformed ABI metadata is changed; every product slot stays the real Valkey implementation.
#[test]
fn actual_valkey_door_rejects_incompatible_abi_and_layout() {
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_plugin_loader::dispatch::{load::rendering_of_raw, LoadError};
    use std::sync::atomic::{AtomicPtr, Ordering};
    static MALFORMED: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    extern "C" fn malformed() -> *const Door {
        MALFORMED.load(Ordering::SeqCst)
    }
    // SAFETY: the actual shipped SDK door is static and complete.
    let real = unsafe { Door::read_parts(busbar_store_valkey::door()) };
    let kind = KindCode::Store;
    let row = LinkedRow::of(busbar_store_valkey::door).unwrap();
    let lib = cdylib();
    for abi in [real.kind_abi + 1, real.kind_abi.wrapping_sub(1)] {
        // SAFETY: preserve all static product pointers, changing ABI admission metadata only.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                kind_abi: abi,
                ..real
            })
        };
        MALFORMED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
        let want = LoadError::KindAbi {
            kind,
            door: abi,
            host: real.kind_abi,
        };
        assert_eq!(rendering_of_raw(malformed).err(), Some(want.clone()));
        assert_eq!(LinkedRow::of_raw(malformed).err(), Some(want));
        let mut stated = row.statement.clone();
        let offset = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        stated[offset..offset + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped::<Store>(&lib, &stated, bind(&dispatcher())).err(),
            Some(LoadError::ManifestKindAbi {
                stated: abi,
                host: real.kind_abi
            })
        );
    }
    for layout in [real.layout ^ 1, 0] {
        // SAFETY: preserve static product pointers, changing layout admission metadata only.
        let door = unsafe { Door::__from_parts(DoorParts { layout, ..real }) };
        MALFORMED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
        let refused = rendering_of_raw(malformed).unwrap_err();
        assert!(matches!(refused, LoadError::KindLayout { .. }), "{refused}");
        assert!(refused
            .to_string()
            .contains("rebuild against this busbar-contract"));
        assert_eq!(LinkedRow::of_raw(malformed).err(), Some(refused.clone()));
        let malformed_row = LinkedRow {
            statement: row.statement.clone(),
            door: malformed,
        };
        assert_eq!(
            load_linked::<Store>(&malformed_row, bind(&dispatcher())).err(),
            Some(refused)
        );
    }
}

#[path = "support/tls_front.rs"]
mod tls_front;

#[test]
fn linked_and_dropped_store_use_the_hosts_tls_trust_and_refuse_untrusted_peers() {
    let url =
        std::env::var("VALKEY_URL").expect("VALKEY_URL is required for the migrated live suite");
    let mut url: url::Url = url.parse().unwrap();
    let backend = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap_or(6379));
    let (front, ca) = tls_front::start(&backend);
    let (host, port) = front.split_once(':').unwrap();
    url.set_scheme("rediss").unwrap();
    url.set_host(Some(host)).unwrap();
    url.set_port(Some(port.parse().unwrap())).unwrap();
    url.set_path("/14");
    let mut backend_url = url.clone();
    backend_url.set_scheme("redis").unwrap();
    let backend: url::Url = format!("redis://{backend}").parse().unwrap();
    backend_url.set_host(backend.host_str()).unwrap();
    backend_url.set_port(backend.port()).unwrap();
    let _db = database::Database::take(backend_url.as_str());
    let settings = serde_json::json!({"url": url.as_str()}).to_string();
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    for dropped_in in [false, true] {
        let load = |trusted| {
            let d = dispatcher();
            let trust = busbar_contract::transport::EgressTrust {
                extra_anchors: if trusted {
                    vec![ca.clone()]
                } else {
                    Vec::new()
                },
                ..Default::default()
            };
            let bind = Bind {
                conns: ConnTable::Host(valkey_io::host(d.conn_waker(), trust)),
                ..bind(&d)
            };
            let p = if dropped_in {
                load_dropped::<Store>(&lib, &stated, bind)
            } else {
                load_linked::<Store>(&LinkedRow::of(busbar_store_valkey::door).unwrap(), bind)
            }
            .unwrap();
            (p, d)
        };
        let error = open(&|| load(false), &settings)
            .expect_err("self-signed peer must refuse without anchor");
        assert!(error.contains("failed to connect"), "{error}");
        let store = open(&|| load(true), &settings).expect("the host trusts the test CA");
        let id = ns("tls");
        let key = VirtualKey {
            id: id.clone(),
            generation_hash: format!("binding:{id}"),
            enabled: true,
            ..Default::default()
        };
        RecordStore::put_key(&store, &key).unwrap();
        assert_eq!(
            RecordStore::get_key(&store, &id)
                .unwrap()
                .unwrap()
                .generation_hash,
            key.generation_hash
        );
    }
}

/// A genuine successful Valkey OPEN must be closed once when the host's READY fails.
#[test]
fn a_failed_ready_closes_the_actual_opened_valkey_store_once() {
    use busbar_contract::abi::mechanism::call::{AbiStr, Op, OutHead, Outcome, RawOutcome};
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    static DOOR: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    static READY: AtomicUsize = AtomicUsize::new(0);
    static CLOSED: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_FAILED: AtomicUsize = AtomicUsize::new(0);
    static CLOSE: std::sync::OnceLock<Op> = std::sync::OnceLock::new();
    extern "C" fn door() -> *const Door {
        DOOR.load(Ordering::SeqCst)
    }
    extern "C" fn ready(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
        READY.fetch_add(1, Ordering::SeqCst);
        let failed = RawOutcome::of(Outcome::Failed);
        let text = "Valkey test: discovery refused";
        // SAFETY: loader supplies a complete lifecycle output head.
        unsafe {
            (*out.cast::<OutHead>()).outcome = failed;
            (*out.cast::<OutHead>()).error = AbiStr {
                ptr: text.as_ptr(),
                len: text.len(),
            };
        }
        failed
    }
    extern "C" fn close(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        CLOSED.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the unchanged real instance and host frames go to the original CLOSE once.
        let Some(close) = CLOSE.get() else {
            CLOSE_FAILED.fetch_add(1, Ordering::SeqCst);
            return RawOutcome::of(Outcome::Failed);
        };
        let result = unsafe { close(instance, input, out) };
        if result.outcome() != Outcome::Ready {
            CLOSE_FAILED.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
    let url =
        std::env::var("VALKEY_URL").expect("VALKEY_URL is required for the migrated live suite");
    let mut url: url::Url = url.parse().unwrap();
    url.set_path("/14");
    let _db = database::Database::take(url.as_str());
    // SAFETY: the real door and Ops are complete immutable SDK-owned statics.
    let real = unsafe { Door::read_parts(busbar_store_valkey::door()) };
    let mut ops = unsafe {
        real.ops
            .cast::<busbar_contract::abi::store::Ops>()
            .read_unaligned()
    };
    CLOSE.set(ops.head.close.unwrap()).unwrap();
    ops.head.close = Some(close);
    let ops = Box::leak(Box::new(ops));
    // SAFETY: retain the actual product table with one forwarding cleanup observer and one failing READY input.
    let restated = unsafe {
        Door::__from_parts(DoorParts {
            size: std::mem::size_of::<Door>() as u32,
            ready: Some(ready),
            ops: std::ptr::from_ref(ops).cast(),
            ..real
        })
    };
    DOOR.store(Box::into_raw(Box::new(restated)), Ordering::SeqCst);
    let d = dispatcher();
    let plugin = load_linked::<Store>(&LinkedRow::of_raw(door).unwrap(), bind(&d)).unwrap();
    let held = Arc::clone(&plugin.inner);
    let first = || held.crossings.load(Ordering::SeqCst) - held.resumes.load(Ordering::SeqCst);
    let before = first();
    let error = LoadedStore::open(
        plugin,
        d,
        serde_json::json!({"url": url.as_str()})
            .to_string()
            .as_bytes(),
        mint,
    )
    .expect_err("READY fails");
    assert_eq!(
        error,
        "plugin 'busbar-store-valkey' ready failed: Valkey test: discovery refused"
    );
    assert_eq!(READY.load(Ordering::SeqCst), 1);
    assert_eq!(CLOSED.load(Ordering::SeqCst), 1);
    assert_eq!(CLOSE_FAILED.load(Ordering::SeqCst), 0);
    assert_eq!(first() - before, 3, "OPEN, failing READY, cleanup CLOSE");
}

#[path = "support/connection_ownership.rs"]
mod connection_ownership;

#[test]
fn both_actual_doors_refuse_every_other_plugin_kind() {
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_plugin_loader::dispatch::{kinds, LoadError};
    let row = LinkedRow::of(busbar_store_valkey::door).unwrap();
    let lib = cdylib();
    let d = dispatcher();
    assert_eq!(
        load_linked::<kinds::auth::Auth>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Auth
        })
    );
    assert_eq!(
        load_dropped::<kinds::auth::Auth>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Auth
        })
    );
    assert_eq!(
        load_linked::<kinds::export::Export>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Export
        })
    );
    assert_eq!(
        load_dropped::<kinds::export::Export>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Export
        })
    );
    assert_eq!(
        load_linked::<kinds::hook::Hook>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Hook
        })
    );
    assert_eq!(
        load_dropped::<kinds::hook::Hook>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Hook
        })
    );
    assert_eq!(
        load_linked::<kinds::plane::Plane>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Plane
        })
    );
    assert_eq!(
        load_dropped::<kinds::plane::Plane>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Plane
        })
    );
    assert_eq!(
        load_linked::<kinds::secret::Secret>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Secret
        })
    );
    assert_eq!(
        load_dropped::<kinds::secret::Secret>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Secret
        })
    );
    assert_eq!(
        load_linked::<kinds::transport::Transport>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Transport
        })
    );
    assert_eq!(
        load_dropped::<kinds::transport::Transport>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Transport
        })
    );
}
