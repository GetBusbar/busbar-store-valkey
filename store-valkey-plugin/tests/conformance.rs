// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE STORE, BOTH DOORS, ONE TABLE** — the Valkey store's linked + dropped-in conformance on the
//! store kind's memory ABI (store v3), run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The store is held two ways at once: LINKED (the logic crate's `door`, as a busbar build that
//! compiles it in registers it: `LinkedRow::of(door)` through the loader's `load_linked`) and
//! DROPPED IN (this crate's built cdylib, its Statement rendered the way `busbar-plugin-pack`
//! renders it into the signed manifest, then `dlopen`ed by the loader's `load_dropped`). Each is
//! bound to its own dispatcher and opened the way the host opens a store (`LoadedStore`), and gives
//! one transcript: the Statement facts, the refusals the store's own `open` answers for bad
//! settings, and — against a live Valkey (`VALKEY_URL`) — a scenario over every surface a governance
//! store answers: a key (mint, read, tombstone, the tombstone guard), a credential (mint, the
//! live-owner refusal, lookup, revoke), the usage ledger (additive, floored), metering (the dated
//! split), the audit chain (replay, fork), the plane-record verbs (upsert, chain append, replay,
//! fork, listing, parents, terminal-only purge with its cascade, single-use token, live token),
//! and the v3 slots (window caps, a whole-cell reserve, its replay, a release, the journal,
//! sessions and records). The two transcripts must agree line for line.
//!
//! Each arm runs in its own namespace (fresh ids, a fresh plane kind, its own stream, schema and
//! principal), so the arms never read each other's rows; the namespace is replaced by a fixed token
//! before comparing.
//!
//! THE RED ARMS, same test: the library asked for as another kind is refused before `dlopen`; a
//! manifest rendering that is not the library's own Statement is refused; and (live) a PERTURBED
//! dropped-in arm — its namespace already holding a different record at a position the scenario
//! appends to — must NOT produce the linked transcript, so the comparison can see a difference.
//!
//! The live scenario follows this repo's Valkey gate: skipped locally without `VALKEY_URL`, a HARD
//! FAILURE under `CI` without it. Everything else needs no server and always runs. A missing cdylib
//! PANICS: this test IS the dropped-in door's proof.

use std::path::PathBuf;
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
    load_dropped, load_linked, rendering_of_library, Bind, DispatchConfig, Dispatcher, LinkedRow,
    NoSink, Plugin,
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
fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("store-valkey-conformance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig::default()))
}

/// The library's Statement as `busbar-plugin-pack` renders it into the signed manifest.
fn packed_rendering(lib: &std::path::Path) -> Vec<u8> {
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
fn dropped(lib: &std::path::Path, stated: &[u8]) -> Loaded {
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

/// A fresh op id (the dedupe is durable: an op id from an earlier run would replay).
fn op(counter: u64) -> OpId {
    OpId::from_parts(node(), counter * 2 + 1)
}

/// The epoch the scenario draws at (fixed at 0 until WIRE-STORE adds the advance).
const EPOCH: u64 = 0;

/// One `Result` as comparable text: `ok:<debug>` or `err:<message>`.
fn r<T: std::fmt::Debug, E: std::fmt::Display>(res: Result<T, E>) -> String {
    match res {
        Ok(v) => format!("ok:{v:?}"),
        Err(e) => format!("err:{e}"),
    }
}

/// The live scenario, in namespace `ns`, through `store`. Every observable the scenario produces is
/// one line of the returned transcript.
fn scenario(store: &dyn RecordStore, ns: &str) -> Vec<String> {
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
    t.iter().map(|l| l.replace(ns, "NS")).collect()
}

/// The v3 slots, in namespace `ns`, through `s`: window caps, a whole-cell reserve, its replay, a
/// release, the journal, sessions and records. Slice ids are one counter shared by every arm, so
/// the transcript carries amounts, never ids.
fn slots(s: &LoadedStore, ns: &str) -> Vec<String> {
    let mut t = Vec::new();
    let bucket = format!("{ns}_bucket_v3");
    let (stream, schema, principal) = (
        format!("{ns}_stream"),
        format!("{ns}_schema"),
        format!("{ns}_principal"),
    );
    let k = CellKey {
        bucket: &bucket,
        pool: None,
        dimension: Dimension::Requests,
        window_start: 60,
    };
    let cells = [Cell { key: k, amount: 2 }, Cell { key: k, amount: 1 }];
    block(async {
        t.push(format!(
            "reserve, no cap = {:?}",
            StoreCalls::reserve(s, op(1), EPOCH, &cells).await
        ));
        let caps = [Cap {
            key: k,
            cap: 3,
            config_gen: 1,
        }];
        t.push(format!(
            "window_caps = {:?}",
            StoreCalls::window_caps(s, op(2), &caps).await
        ));
        let id = op(3);
        let grants = StoreCalls::reserve(s, id, EPOCH, &cells).await;
        t.push(format!(
            "reserve = {:?}",
            grants
                .as_ref()
                .map(|g| g.iter().map(|g| g.granted).collect::<Vec<_>>())
        ));
        let replay = StoreCalls::reserve(s, id, EPOCH, &cells).await;
        t.push(format!(
            "replay answers the original grants = {}",
            replay.as_ref().ok() == grants.as_ref().ok()
        ));
        t.push(format!(
            "reserve past the cap = {:?}",
            StoreCalls::reserve(s, op(4), EPOCH, &cells[1..]).await
        ));
        if let Ok(g) = &grants {
            let items = [(g[0].slice_id, 5)];
            t.push(format!(
                "release = {:?}",
                StoreCalls::slice_release(s, op(5), EPOCH, &items).await
            ));
        }
        let r = |b: &[u8]| RecordBytes::new(b.to_vec()).unwrap();
        t.push(format!(
            "append_batch = {:?}",
            StoreCalls::append_batch(s, op(6), &stream, &[r(b"one"), r(b"two")]).await
        ));
        t.push(format!(
            "record_put = {:?}",
            StoreCalls::record_put(s, &schema, b"k", &r(b"v")).await
        ));
        t.push(format!(
            "record_get = {:?}",
            StoreCalls::record_get(s, &schema, b"k")
                .await
                .map(|v| v.map(|v| String::from_utf8_lossy(v.as_slice()).into_owned()))
        ));
        t.push(format!(
            "session_put = {:?}",
            StoreCalls::session_put(s, 42_424_242, "node-a", &principal).await
        ));
        t.push(format!(
            "sessions_for = {:?}",
            StoreCalls::sessions_for(s, &principal).await
        ));
        t.push(format!(
            "session_remove = {:?}",
            StoreCalls::session_remove(s, 42_424_242).await
        ));
    });
    t.iter().map(|l| l.replace(ns, "NS")).collect()
}

/// What one door does with `url`, as one comparable transcript. `load` loads the door afresh: a
/// refused `open` consumes the instance it was offered.
fn transcript(load: impl Fn() -> Loaded, live: Option<(&str, &str)>) -> Vec<String> {
    let mut t = vec![format!("name = {}", load().0.name())];
    // The store's own `open`, refusing settings it cannot run, in its own words.
    for cfg in [
        "{ not json",
        "{}",
        r#"{"url":"not-a-valkey-url"}"#,
        r#"{"url":"redis://127.0.0.1:1/0","connect_timeout_ms":300}"#,
    ] {
        let (plugin, dispatcher) = load();
        let answer = LoadedStore::open(plugin, dispatcher, cfg.as_bytes(), node()).map(|_| ());
        t.push(format!("open {cfg:?} = {answer:?}"));
    }
    let Some((url, ns)) = live else {
        return t;
    };
    let (plugin, dispatcher) = load();
    let settings = serde_json::json!({ "url": url }).to_string();
    let s = LoadedStore::open(plugin, dispatcher, settings.as_bytes(), node())
        .expect("the store opens against the live Valkey");
    t.push(format!("facts = {:?}", s.facts()));
    t.extend(scenario(&s, ns));
    t.extend(slots(&s, ns));
    t
}

/// A fresh namespace for one arm.
fn ns(arm: &str) -> String {
    format!(
        "vkconf{arm}{}x{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 1_000_000_000
    )
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

/// The Valkey store behaves as ONE store through either door — and the library asked for as another
/// kind, under a Statement that is not its own, or perturbed in its namespace, does not pass for it
/// (the RED arms).
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

    let (ns_linked, ns_dropped) = (ns("l"), ns("d"));
    let linked = transcript(linked, url.as_deref().map(|u| (u, ns_linked.as_str())));
    let dropped_in = transcript(
        || dropped(&lib, &stated),
        url.as_deref().map(|u| (u, ns_dropped.as_str())),
    );
    same(&linked, &dropped_in);
    assert_eq!(linked[0], format!("name = {}", busbar_store_valkey::NAME));

    // The transcript is about the store, not about nothing: the refusals are the store's own words,
    // and (live) the scenario did what a governance store is for.
    assert!(
        linked[1].contains("invalid valkey plugin config"),
        "{linked:#?}"
    );
    assert!(linked[2].contains("requires a \\\"url\\\""), "{linked:#?}");
    assert!(linked[3].contains("failed to connect"), "{linked:#?}");
    assert!(linked[4].contains("failed to connect"), "{linked:#?}");
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
        assert_eq!(find("reserve ="), "reserve = Ok([2, 1])");
        assert!(find("replay").ends_with("true"), "{linked:#?}");
        assert!(find("reserve past").contains("Exhausted"), "{linked:#?}");
        assert_eq!(find("release"), "release = Ok([2])");
        assert!(find("append_batch").contains("seq: 2"), "{linked:#?}");
        assert_eq!(find("record_get"), "record_get = Ok(Some(\"v\"))");
        assert!(find("sessions_for").contains("node-a"), "{linked:#?}");
    }

    // RED ARM 1: the library asked for as another kind is refused before it is opened.
    let d = dispatcher();
    let e = match load_dropped::<Secret>(&lib, &stated, bind(&d)) {
        Ok(_) => panic!("a store library loaded as secret"),
        Err(e) => e.to_string(),
    };
    assert!(
        e.contains("the manifest states kind Store, not Secret"),
        "{e}"
    );

    // RED ARM 2: a manifest whose Statement is not the library's own is refused.
    let mut other = stated.clone();
    other.push(0);
    let d = dispatcher();
    let e = match load_dropped::<Store>(&lib, &other, bind(&d)) {
        Ok(_) => panic!("a library loaded under a Statement that is not its own"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains("repack the plugin"), "{e}");

    // RED ARM 3 (live): a PERTURBED dropped-in arm — its namespace already holds a different
    // record at a chain position the scenario appends to — must not reproduce the linked transcript.
    if let Some(u) = url.as_deref() {
        let ns_red = ns("r");
        let (plugin, dispatcher) = dropped(&lib, &stated);
        let direct = LoadedStore::open(
            plugin,
            dispatcher,
            serde_json::json!({ "url": u }).to_string().as_bytes(),
            node(),
        )
        .expect("the store opens");
        RecordStore::append_plane_record(
            &direct,
            PlaneRecord {
                kind: format!("conf_{ns_red}"),
                id: "t1".into(),
                parent: Some("t1".into()),
                seq: 3,
                ts: 20,
                disposition: PlaneDisposition::Active,
                body: b"planted".to_vec(),
            }
            .view(),
        )
        .expect("plant");
        let red = transcript(|| dropped(&lib, &stated), Some((u, ns_red.as_str())));
        assert_ne!(
            red, linked,
            "a perturbed arm must be told apart from the linked one"
        );
    }
}
