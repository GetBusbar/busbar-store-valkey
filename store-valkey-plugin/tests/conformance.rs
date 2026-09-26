// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE VALKEY STORE, BOTH DOORS, ONE ROW** — the store's linked + dropped-in conformance, run
//! against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The store is held two ways at once: LINKED (its `linked::STORE` statement and boundary, the row a
//! busbar build that compiles it in registers) and DROPPED IN (this crate's built cdylib, signed
//! first-party under the SAME statement into a temp `plugins/` directory and found by the loader's
//! scan). Each arm is opened by the one `open_store`, and driven through the same transcript:
//!
//! - the row both doors state, and whether it is first-party;
//! - the refusals `open` gives for configs that cannot produce a store (malformed JSON, no `url`, a
//!   URL the driver refuses, an unreachable server) — each in the store's own words, across the door;
//! - against the live Valkey (`VALKEY_URL`): one scenario over every surface a governance store
//!   answers — a key (mint, read, tombstone, the tombstone guard), a credential (mint, the live-owner
//!   refusal, lookup, revoke), the usage ledger (additive, floored), metering (the dated split), the
//!   audit chain (replay, fork), and the plane-record verbs (upsert, chain append, replay, fork,
//!   listing, parents, terminal-only purge with its cascade, single-use token, live token).
//!
//! The two transcripts must agree byte for byte. Each arm runs in its own namespace (fresh ids, a
//! fresh plane kind), so the arms never read each other's rows; the namespace is replaced by a fixed
//! token before comparing.
//!
//! THE RED ARMS, in the same test:
//! - the same cdylib signed as `secret` is refused at the kind handshake, naming both kinds;
//! - a PERTURBED dropped-in arm — the same bytes, the same statement, but its namespace already
//!   holding a different record at a position the scenario appends to — must NOT produce the linked
//!   transcript: the comparison above is only worth something if it can see a difference.
//!
//! The live leg follows this repo's Valkey gate: skipped locally without `VALKEY_URL`, a HARD
//! FAILURE under `CI` without it. A missing cdylib is always a failure, never a skip: this test IS the
//! dropped-in door's proof.

use busbar_contract::records::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, ModelTokensDelta,
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStore, SecretForm, UsageDelta, VirtualKey,
};
use busbar_plugin_loader::sign::{sign, Manifest, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}

/// The version both arms state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_store_valkey_plugin");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-store-valkey-plugin cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// The statement a `kind` row of this store makes, at the newest payload schema the loader speaks
/// for that kind.
fn statement(kind: &str, name: &str, alias: &str) -> Manifest {
    let abi = busbar_plugin_loader::supported_abi(kind)
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: kind.into(),
        version: VERSION.into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: abi,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

/// The LINKED row: exactly what a busbar build that links this store states for `linked::STORE`.
fn linked_row() -> LinkedPlugin {
    let (name, alias, entry) = busbar_store_valkey::linked::STORE;
    LinkedPlugin::boundary(statement("store", name, alias), entry)
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/`
/// directory, scanned under a policy holding the release key.
fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("store-valkey-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libstore.so", lib).unwrap();
    std::fs::write(dir.join("store.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    let registry =
        busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed store scans");
    let _ = std::fs::remove_dir_all(&dir);
    registry
}

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

/// `open`'s error, or a note that it opened.
fn open_refusal(registry: &PluginRegistry, alias: &str, cfg: &str) -> String {
    match registry.open_store(alias, cfg) {
        Ok(_) => "opened".into(),
        Err(e) => e,
    }
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
    t.push(r(
        store.upsert_plane_record(&rec("t1", None, 0, 10, false, "v1"))
    ));
    t.push(r(
        store.upsert_plane_record(&rec("t1", None, 0, 11, false, "v2"))
    ));
    t.push(r(
        store.upsert_plane_record(&rec("t2", None, 0, 12, true, "done"))
    ));
    for (seq, body) in [(2, "e2"), (1, "e1"), (3, "e3")] {
        t.push(r(store.append_plane_record(&rec(
            "t1",
            Some("t1"),
            seq,
            20,
            false,
            body,
        ))));
    }
    t.push(r(store.append_plane_record(&rec(
        "t1",
        Some("t1"),
        2,
        20,
        false,
        "e2",
    ))));
    t.push(r(store.append_plane_record(&rec(
        "t1",
        Some("t1"),
        2,
        20,
        false,
        "FORK",
    ))));
    t.push(r(store.append_plane_record(&rec(
        "p:x",
        Some("p:x"),
        1,
        30,
        false,
        "c1",
    ))));
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

/// What one door does with the store's alias, as one comparable transcript.
fn transcript(
    registry: &PluginRegistry,
    alias: &str,
    live: Option<(&str, &str)>,
) -> serde_json::Value {
    let p = registry.resolve(alias).expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let refusals = [
        "{ not json".to_string(),
        "{}".to_string(),
        r#"{"url":"not-a-valkey-url"}"#.to_string(),
        r#"{"url":"redis://127.0.0.1:1/0","connect_timeout_ms":300}"#.to_string(),
    ]
    .map(|cfg| open_refusal(registry, alias, &cfg));
    let scenario = live.map(|(url, ns)| {
        let store = registry
            .open_store(alias, &serde_json::json!({ "url": url }).to_string())
            .expect("the store opens against the live Valkey");
        scenario(store.as_ref(), ns)
    });
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "refusals": refusals,
        "scenario": scenario,
    })
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

/// The Valkey store registers ONE row and behaves as ONE store through either door — and neither a
/// wrong-kind signing nor a perturbed store passes for it (the RED arms).
#[test]
fn the_linked_and_the_dropped_in_valkey_store_are_one_store() {
    let row = linked_row();
    let (manifest, alias) = (row.manifest.clone(), row.manifest.alias.clone());
    assert_eq!(manifest.name, "busbar-store-valkey");
    assert_eq!(alias, "valkey");
    let lib = cdylib();
    let url = valkey_url();

    let linked_registry = PluginRegistry::empty().link(vec![row]).unwrap();
    let ns_linked = ns("l");
    let linked = transcript(
        &linked_registry,
        &alias,
        url.as_deref().map(|u| (u, ns_linked.as_str())),
    );
    let dropped_registry = dropped("dropped", manifest.clone(), &lib);
    let ns_dropped = ns("d");
    let dropped_in = transcript(
        &dropped_registry,
        &alias,
        url.as_deref().map(|u| (u, ns_dropped.as_str())),
    );
    assert_eq!(linked, dropped_in, "the two doors are not one store");

    // The transcript is about the store, not about nothing: the refusals are the store's own words,
    // and (live) the scenario did what a governance store is for.
    let refusals = linked["refusals"].as_array().unwrap();
    assert!(
        refusals[0]
            .as_str()
            .unwrap()
            .contains("invalid valkey plugin config"),
        "{refusals:?}"
    );
    assert!(
        refusals[1].as_str().unwrap().contains("requires a \"url\""),
        "{refusals:?}"
    );
    assert!(
        refusals[2]
            .as_str()
            .unwrap()
            .contains("valkey plugin: failed to connect"),
        "{refusals:?}"
    );
    assert!(
        refusals[3]
            .as_str()
            .unwrap()
            .contains("valkey plugin: failed to connect"),
        "{refusals:?}"
    );
    assert_eq!(linked["first_party"], true);
    if url.is_some() {
        let lines: Vec<String> = linked["scenario"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
        assert!(
            has("does not exist; a credential must hang off a real key"),
            "{lines:?}"
        );
        assert!(
            has("is tombstoned and its id is never reissued"),
            "{lines:?}"
        );
        assert!(has("the chain has forked"), "{lines:?}");
        assert!(has("the audit chain has forked"), "{lines:?}");
        assert!(has(r#"chain:["e1", "e2", "e3"]"#), "{lines:?}");
        assert!(has(r#"parents:["p:x", "t1"]"#), "{lines:?}");
        assert!(has("live:[true, false, false]"), "{lines:?}");
        assert!(
            has("purge:5"),
            "a kind other than `task` drops EVERY row older than the cutoff (t1, t2, e1-e3): \
             {lines:?}"
        );
        assert!(has("redeem:[true, false]"), "{lines:?}");
        assert!(has("metering:[(0, 2, 6"), "{lines:?}");
    }

    // RED ARM 1: the same bytes signed as another kind are refused at the kind handshake.
    let wrong = dropped(
        "as-secret",
        statement("secret", "busbar-store-valkey", "valkey-as-secret"),
        &lib,
    );
    let e = match wrong.open_secret("valkey-as-secret", "{}") {
        Ok(_) => panic!("a store library signed as secret opened; it must be refused"),
        Err(e) => e,
    };
    assert!(
        e.contains("exports kind 'store' but is being loaded as 'secret'"),
        "the handshake refusal must name both kinds: {e}"
    );

    // RED ARM 2: a PERTURBED dropped-in store — its namespace already holds a different record at a
    // chain position the scenario appends to — must not reproduce the linked transcript. Server-free,
    // the perturbation is the statement: the same bytes under another alias are another row.
    let red = match url.as_deref() {
        Some(u) => {
            let ns_red = ns("r");
            let direct = dropped_registry
                .open_store(&alias, &serde_json::json!({ "url": u }).to_string())
                .unwrap();
            direct
                .append_plane_record(&PlaneRecord {
                    kind: format!("conf_{ns_red}"),
                    id: "t1".into(),
                    parent: Some("t1".into()),
                    seq: 3,
                    ts: 20,
                    disposition: PlaneDisposition::Active,
                    body: b"planted".to_vec(),
                })
                .unwrap();
            transcript(&dropped_registry, &alias, Some((u, ns_red.as_str())))
        }
        None => {
            let other = Manifest {
                alias: "valkey-red".into(),
                ..manifest
            };
            transcript(&dropped("red", other, &lib), "valkey-red", None)
        }
    };
    assert_ne!(
        red, linked,
        "a perturbed store must not pass for the linked one"
    );
}
