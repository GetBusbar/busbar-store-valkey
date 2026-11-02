// SPDX-License-Identifier: Apache-2.0
//! Valkey product cases formerly driven by the pinned kit: ordinary loader/store calls.
use std::fmt::{Debug, Display};

use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, MeteringDelta, ModelTokensDelta, PlaneDisposition,
    PlaneRecord, PlaneSelector, RecordStore, ScopeRef, SecretForm, UsageDelta, UsageLedger,
    VirtualKey,
};
use busbar_contract::store_calls::StoreCalls;

use super::{scratch, Door};
const LIVE_REPLAY_DEADLINE: u64 = u64::MAX;
const _: () = assert!(busbar_contract::abi::store::KIND_SLOTS == 31);
fn ans<T: Debug, E: Display>(r: Result<T, E>) -> String {
    match r {
        Ok(v) => format!("= {v:?}"),
        Err(e) => format!("! {e}"),
    }
}

fn text_of(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn block<T>(rt: &tokio::runtime::Runtime, f: impl std::future::Future<Output = T>) -> T {
    rt.block_on(f)
}

fn op(n: u64) -> OpId {
    OpId::from_parts(2, n)
}

fn key(id: &str, group: Option<&str>) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("h_{id}"),
        name: format!("key {id}"),
        enabled: true,
        group: group.map(str::to_string),
        created_at: 100,
        ..Default::default()
    }
}

fn delta(requests: i64, input: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            model: "m".to_string(),
            usage_units: [("input".to_string(), input)].into_iter().collect(),
        }],
    }
}

fn meter(key_id: &str, provider: &str, input: u64) -> MeteringDelta {
    MeteringDelta {
        key_id: key_id.into(),
        bucket: 86_400,
        model: "m".into(),
        provider: provider.into(),
        tokens_input: input,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: "g".into(),
        pricing_version: "v1".into(),
        priced_from_ms: 0,
        usage_units: Default::default(),
    }
}

fn secret(kind: &str, id: &str, key_id: &str, public_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: id.into(),
            key_id: key_id.into(),
            kind: kind.into(),
            slot: 0,
            public_id: public_id.into(),
            secret_form: SecretForm::Recoverable,
            created_at: 5,
            updated_at: 5,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: format!("v1:plain:s3cret-{id}"),
    }
}

fn plane(kind: &str, id: &str, parent: Option<&str>, seq: u64, body: &[u8]) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(str::to_string),
        seq,
        ts: 7,
        disposition: if seq == 2 {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: body.to_vec(),
    }
}

fn scoped_key() -> VirtualKey {
    VirtualKey {
        id: "vk_scopekinds".into(),
        generation_hash: "binding:vk_scopekinds:1".into(),
        name: "scope-kinds".into(),
        allowed_scopes: Some(vec![
            ScopeRef::pool("fast"),
            ScopeRef {
                kind: "engine_server".into(),
                value: "filesystem".into(),
            },
            ScopeRef {
                kind: "engine_tool".into(),
                value: "filesystem_read_file".into(),
            },
        ]),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    }
}

pub(super) fn behavior(
    by_dropped: bool,
    url: &str,
) -> std::collections::BTreeMap<&'static str, String> {
    let _database = database::Database::take(url);
    let cfg = serde_json::json!({"url": url}).to_string();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let (p, d) = if by_dropped {
        dropped(&lib, &stated)
    } else {
        linked()
    };
    let held = p.inner.clone();
    let count = || {
        let resumes = held.resumes.load(std::sync::atomic::Ordering::SeqCst);
        held.crossings.load(std::sync::atomic::Ordering::SeqCst) - resumes
    };
    let mut answers = std::collections::BTreeMap::new();
    {
        let before = count();
        let value = format!(
            "{:?} {} max_inflight={} {:?}",
            p.kind(),
            p.name(),
            p.max_inflight(),
            p.context::<busbar_plugin_loader::dispatch::kinds::store::StoreFacts>()
        );
        assert_eq!(count() - before, 0, "facts: exact first crossings");
        answers.insert("facts", value)
    };
    let before_open = count();
    let open_pin = 1 + u64::from(p.has_ready());
    let st = busbar_plugin_loader::store_v3::LoadedStore::open(
        p,
        d.clone(),
        cfg.as_bytes(),
        super::mint,
    )
    .expect("Valkey opens");
    assert_eq!(
        count() - before_open,
        open_pin,
        "open: exact first crossings"
    );
    let b: &dyn RecordStore = &st;
    let before_ready = count();
    let ready = st.plugin().ready(&d, std::time::Duration::from_secs(30));
    assert_eq!(
        count() - before_ready,
        u64::from(st.plugin().has_ready()),
        "ready: exact first crossings"
    );
    assert!(ready.is_ok(), "the honest door becomes ready: {ready:?}");
    answers.insert(
        "ready",
        format!("has_ready={} {ready:?}", st.plugin().has_ready()),
    );
    answers.insert("open", format!("Ready {:?}", st.facts()));
    {
        let before = count();
        let row = busbar_plugin_loader::dispatch::LinkedRow::of(busbar_store_valkey::door).unwrap();
        let result = if by_dropped {
            busbar_plugin_loader::dispatch::load_dropped::<
                busbar_plugin_loader::dispatch::kinds::hook::Hook,
            >(&lib, &stated, super::bind(&d))
        } else {
            busbar_plugin_loader::dispatch::load_linked::<
                busbar_plugin_loader::dispatch::kinds::hook::Hook,
            >(&row, super::bind(&d))
        };
        assert!(matches!(
            result,
            Err(busbar_plugin_loader::dispatch::LoadError::ManifestKind { .. })
        ));
        assert_eq!(count() - before, 0, "wrong kind makes no crossing");
        answers.insert("refused as another kind", "refused=true".into());
    }
    let keys = |r: Result<Vec<VirtualKey>, busbar_contract::records::RecordStoreError>| {
        ans(r.map(|mut ks| {
            ks.sort_by(|a, b| a.id.cmp(&b.id));
            ks.into_iter()
                .map(|k| (k.id, k.revision, k.deleted_at.is_some(), k.group))
                .collect::<Vec<_>>()
        }))
    };
    {
        let before = count();
        let value = { ans(b.put_key(&key("vk_conf_grouped", Some("conf-group")))) };
        assert_eq!(count() - before, 1, "put grouped: exact first crossings");
        answers.insert("put grouped", value)
    };
    {
        let before = count();
        let value = { ans(b.put_key(&key("vk_conf_plain", None))) };
        assert_eq!(count() - before, 1, "put plain: exact first crossings");
        answers.insert("put plain", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b
                    .get_key("vk_conf_grouped")
                    .map(|k| k.map(|k| (k.id, k.group))))
            }
        };
        assert_eq!(count() - before, 2, "get grouped: exact first crossings");
        answers.insert("get grouped", value)
    };
    {
        let before = count();
        let value = { ans(b.get_key("vk_conf_absent").map(|k| k.map(|k| k.id))) };
        assert_eq!(count() - before, 1, "get absent: exact first crossings");
        answers.insert("get absent", value)
    };
    {
        let before = count();
        let value = { keys(b.list_keys()) };
        assert_eq!(count() - before, 2, "key list: exact first crossings");
        answers.insert("key list", value)
    };
    {
        let before = count();
        let value = { ans(b.delete_key("vk_conf_plain")) };
        assert_eq!(count() - before, 1, "delete plain: exact first crossings");
        answers.insert("delete plain", value)
    };
    {
        let before = count();
        let value = { ans(b.delete_key("vk_conf_absent")) };
        assert_eq!(count() - before, 1, "delete absent: exact first crossings");
        answers.insert("delete absent", value)
    };
    {
        let before = count();
        let value = { ans(b.put_key(&key("vk_conf_plain", None))) };
        assert_eq!(count() - before, 1, "relive plain: exact first crossings");
        answers.insert("relive plain", value)
    };
    {
        let before = count();
        let value = { keys(b.list_keys_since(0)) };
        assert_eq!(count() - before, 2, "keys since 0: exact first crossings");
        answers.insert("keys since 0", value)
    };

    let (ub, w) = ("conf-usage", 1_700_000_000_u64);
    {
        let before = count();
        let value = { ans(b.get_usage(ub, w)) };
        assert_eq!(
            count() - before,
            2,
            "usage untouched: exact first crossings"
        );
        answers.insert("usage untouched", value)
    };
    {
        let before = count();
        let value = { ans(b.add_usage(ub, w, &delta(2, 30))) };
        assert_eq!(count() - before, 1, "add usage: exact first crossings");
        answers.insert("add usage", value)
    };
    {
        let before = count();
        let value = { ans(b.get_usage(ub, w)) };
        assert_eq!(count() - before, 2, "usage: exact first crossings");
        answers.insert("usage", value)
    };
    let mut set = UsageLedger::default();
    set.apply_delta(&delta(9, 1));
    {
        let before = count();
        let value = { ans(b.put_usage("j", w * 2, &set)) };
        assert_eq!(count() - before, 1, "put usage: exact first crossings");
        answers.insert("put usage", value)
    };
    {
        let before = count();
        let value = { ans(b.get_usage("j", w * 2)) };
        assert_eq!(count() - before, 2, "usage j: exact first crossings");
        answers.insert("usage j", value)
    };
    {
        let before = count();
        let value = { ans(b.get_usage(ub, w)) };
        assert_eq!(count() - before, 2, "usage again: exact first crossings");
        answers.insert("usage again", value)
    };

    {
        let before = count();
        let value = { ans(b.add_metering(&meter("vk_conf_grouped", "p", 3))) };
        assert_eq!(count() - before, 1, "meter p 3: exact first crossings");
        answers.insert("meter p 3", value)
    };
    {
        let before = count();
        let value = { ans(b.add_metering(&meter("vk_conf_grouped", "p", 4))) };
        assert_eq!(count() - before, 1, "meter p 4: exact first crossings");
        answers.insert("meter p 4", value)
    };
    {
        let before = count();
        let value = { ans(b.add_metering(&meter("vk_conf_grouped", "q", 1))) };
        assert_eq!(count() - before, 1, "meter q 1: exact first crossings");
        answers.insert("meter q 1", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b.list_metering(86_400).map(|mut v| {
                    v.sort_by(|x, y| x.provider.cmp(&y.provider));
                    v
                }))
            }
        };
        assert_eq!(count() - before, 2, "metering: exact first crossings");
        answers.insert("metering", value)
    };

    {
        let before = count();
        let value = { ans(b.put_key(&key("k1", None))) };
        assert_eq!(count() - before, 1, "put k1: exact first crossings");
        answers.insert("put k1", value)
    };
    {
        let before = count();
        let value = { ans(b.put_credential(&secret("sigv4", "c1", "k1", "pub1"))) };
        assert_eq!(count() - before, 1, "cred c1: exact first crossings");
        answers.insert("cred c1", value)
    };
    {
        let before = count();
        let value = { ans(b.put_credential(&secret("sigv4", "c9", "k1", "pub9"))) };
        assert_eq!(
            count() - before,
            1,
            "cred c9 (live slot): exact first crossings"
        );
        answers.insert("cred c9 (live slot)", value)
    };
    {
        let before = count();
        let value = {
            ans(b.put_key_with_credential(&key("k2", None), &secret("sigv4", "c2", "k2", "pub2")))
        };
        assert_eq!(count() - before, 1, "key+cred k2: exact first crossings");
        answers.insert("key+cred k2", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b
                    .list_credentials("k1")
                    .map(|v| v.into_iter().map(|c| c.id).collect::<Vec<_>>()))
            }
        };
        assert_eq!(count() - before, 2, "creds k1: exact first crossings");
        answers.insert("creds k1", value)
    };
    {
        let before = count();
        let value = { ans(b.revoke_credential("c1", "rotated")) };
        assert_eq!(count() - before, 1, "revoke c1: exact first crossings");
        answers.insert("revoke c1", value)
    };
    {
        let before = count();
        let value = { ans(b.revoke_credential("zz", "x")) };
        assert_eq!(count() - before, 1, "revoke absent: exact first crossings");
        answers.insert("revoke absent", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b.list_credentials_since(0).map(|mut v| {
                    v.sort_by(|x, y| x.meta.id.cmp(&y.meta.id));
                    v.into_iter()
                        .map(|c| (c.meta.id, c.meta.revoked_at.is_some()))
                        .collect::<Vec<_>>()
                }))
            }
        };
        assert_eq!(count() - before, 2, "creds since: exact first crossings");
        answers.insert("creds since", value)
    };

    {
        let before = count();
        let value = { ans(b.list_audit()) };
        assert_eq!(count() - before, 1, "audit: exact first crossings");
        answers.insert("audit", value)
    };
    {
        let before = count();
        let value = { ans(b.list_audit_tail(1)) };
        assert_eq!(count() - before, 1, "audit tail 1: exact first crossings");
        answers.insert("audit tail 1", value)
    };
    {
        let before = count();
        let value = { ans(b.add_denylist("x", "why")) };
        assert_eq!(count() - before, 1, "deny x: exact first crossings");
        answers.insert("deny x", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b.list_denylist().map(|mut v| {
                    v.sort();
                    v
                }))
            }
        };
        assert_eq!(count() - before, 2, "deny: exact first crossings");
        answers.insert("deny", value)
    };

    let bodies = |r: busbar_contract::records::RecordStoreResult<Vec<Vec<u8>>>| {
        ans(r.map(|v| {
            let mut v: Vec<String> = v.iter().map(|b| text_of(b)).collect();
            v.sort();
            v
        }))
    };
    {
        let before = count();
        let value = { ans(b.upsert_plane_record(plane("task", "t1", None, 0, b"{}").view())) };
        assert_eq!(count() - before, 1, "upsert t1: exact first crossings");
        answers.insert("upsert t1", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b
                    .get_plane_record("task", "t1")
                    .map(|v| v.map(|v| text_of(&v))))
            }
        };
        assert_eq!(count() - before, 1, "get t1: exact first crossings");
        answers.insert("get t1", value)
    };
    {
        let before = count();
        let value = { ans(b.append_plane_record(plane("ev", "e", Some("t1"), 1, b"1").view())) };
        assert_eq!(count() - before, 1, "append e1: exact first crossings");
        answers.insert("append e1", value)
    };
    {
        let before = count();
        let value = { ans(b.append_plane_record(plane("ev", "e", Some("t1"), 2, b"2").view())) };
        assert_eq!(count() - before, 1, "append e2: exact first crossings");
        answers.insert("append e2", value)
    };
    {
        let before = count();
        let value = { ans(b.append_plane_record(plane("ev", "e", Some("t1"), 2, b"x").view())) };
        assert_eq!(count() - before, 1, "append e2 fork: exact first crossings");
        answers.insert("append e2 fork", value)
    };
    {
        let before = count();
        let value = { bodies(b.list_plane_records("ev", &PlaneSelector::Parent("t1".into()))) };
        assert_eq!(count() - before, 1, "list ev t1: exact first crossings");
        answers.insert("list ev t1", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b.list_plane_record_parents("ev").map(|mut v| {
                    v.sort();
                    v
                }))
            }
        };
        assert_eq!(count() - before, 2, "parents ev: exact first crossings");
        answers.insert("parents ev", value)
    };
    {
        let before = count();
        let value =
            { ans(b.purge_plane_records("ev", 100, busbar_contract::records::Retention::Age)) };
        assert_eq!(count() - before, 1, "purge ev: exact first crossings");
        answers.insert("purge ev", value)
    };

    {
        let before = count();
        let value =
            { ans(b.append_plane_record(plane("rt", "r", Some("p"), 1, b"active").view())) };
        assert_eq!(count() - before, 1, "append rt1: exact first crossings");
        answers.insert("append rt1", value)
    };
    {
        let before = count();
        let value =
            { ans(b.append_plane_record(plane("rt", "r", Some("p"), 2, b"terminal").view())) };
        assert_eq!(count() - before, 1, "append rt2: exact first crossings");
        answers.insert("append rt2", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b.purge_plane_records(
                    "rt",
                    100,
                    busbar_contract::records::Retention::TerminalOnly,
                ))
            }
        };
        assert_eq!(
            count() - before,
            1,
            "purge rt terminal-only: exact first crossings"
        );
        answers.insert("purge rt terminal-only", value)
    };
    {
        let before = count();
        let value = { bodies(b.list_plane_records("rt", &PlaneSelector::Parent("p".into()))) };
        assert_eq!(count() - before, 1, "list rt kept: exact first crossings");
        answers.insert("list rt kept", value)
    };
    {
        let before = count();
        let value =
            { ans(b.purge_plane_records("rt", 100, busbar_contract::records::Retention::Age)) };
        assert_eq!(count() - before, 1, "purge rt age: exact first crossings");
        answers.insert("purge rt age", value)
    };
    {
        let before = count();
        let value = { bodies(b.list_plane_records("rt", &PlaneSelector::Parent("p".into()))) };
        assert_eq!(count() - before, 1, "list rt aged: exact first crossings");
        answers.insert("list rt aged", value)
    };
    {
        let before = count();
        let value = { ans(b.delete_plane_record("task", "t1")) };
        assert_eq!(count() - before, 1, "delete t1: exact first crossings");
        answers.insert("delete t1", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b
                    .get_plane_record("task", "t1")
                    .map(|v| v.map(|v| text_of(&v))))
            }
        };
        assert_eq!(count() - before, 1, "get t1 after: exact first crossings");
        answers.insert("get t1 after", value)
    };

    {
        let before = count();
        let value =
            { ans(b.upsert_plane_record(plane("ctask", "c1", Some("p"), 0, b"c1").view())) };
        assert_eq!(
            count() - before,
            1,
            "upsert c1 under p: exact first crossings"
        );
        answers.insert("upsert c1 under p", value)
    };
    {
        let before = count();
        let value =
            { ans(b.upsert_plane_record(plane("ctask", "c2", Some("p"), 0, b"c2").view())) };
        assert_eq!(
            count() - before,
            1,
            "upsert c2 under p: exact first crossings"
        );
        answers.insert("upsert c2 under p", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b
                    .get_plane_record("ctask", "c1")
                    .map(|v| v.map(|v| text_of(&v))))
            }
        };
        assert_eq!(count() - before, 1, "get c1: exact first crossings");
        answers.insert("get c1", value)
    };
    {
        let before = count();
        let value = { bodies(b.list_plane_records("ctask", &PlaneSelector::Parent("p".into()))) };
        assert_eq!(count() - before, 1, "list ctask p: exact first crossings");
        answers.insert("list ctask p", value)
    };
    {
        let before = count();
        let value = { ans(b.delete_plane_record("ctask", "c1")) };
        assert_eq!(count() - before, 1, "delete c1: exact first crossings");
        answers.insert("delete c1", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b
                    .get_plane_record("ctask", "c1")
                    .map(|v| v.map(|v| text_of(&v))))
            }
        };
        assert_eq!(count() - before, 1, "get c1 after: exact first crossings");
        answers.insert("get c1 after", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(b
                    .get_plane_record("ctask", "c2")
                    .map(|v| v.map(|v| text_of(&v))))
            }
        };
        assert_eq!(count() - before, 1, "get c2: exact first crossings");
        answers.insert("get c2", value)
    };
    {
        let before = count();
        let value = { ans(b.plane_token_live("tok", "x", 100, 1)) };
        assert_eq!(count() - before, 1, "token live: exact first crossings");
        answers.insert("token live", value)
    };
    {
        let before = count();
        let value = { ans(b.redeem_plane_token("tok", "x", LIVE_REPLAY_DEADLINE, 1)) };
        assert_eq!(count() - before, 1, "redeem: exact first crossings");
        answers.insert("redeem", value)
    };
    {
        let before = count();
        let value = { ans(b.redeem_plane_token("tok", "x", LIVE_REPLAY_DEADLINE, 1)) };
        assert_eq!(count() - before, 1, "redeem again: exact first crossings");
        answers.insert("redeem again", value)
    };

    let batch = [(ub, w, delta(1, 5)), (ub, w, delta(1, 5))];
    {
        let before = count();
        let value = { ans(block(&rt, st.add_usage_batch(op(8), &batch))) };
        assert_eq!(count() - before, 1, "usage batch: exact first crossings");
        answers.insert("usage batch", value)
    };
    {
        let before = count();
        let value = { ans(block(&rt, st.add_usage_batch(op(8), &batch))) };
        assert_eq!(
            count() - before,
            1,
            "usage batch replay: exact first crossings"
        );
        answers.insert("usage batch replay", value)
    };
    {
        let before = count();
        let value = { ans(block(&rt, st.add_usage_batch(op(8), &batch[..1]))) };
        assert_eq!(
            count() - before,
            1,
            "usage batch conflict: exact first crossings"
        );
        answers.insert("usage batch conflict", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(block(
                    &rt,
                    st.add_metering_batch(op(9), &[meter("vk_conf_grouped", "p", 1)]),
                ))
            }
        };
        assert_eq!(count() - before, 1, "metering batch: exact first crossings");
        answers.insert("metering batch", value)
    };
    let rec = |v: &[u8]| RecordBytes::new(v.to_vec()).expect("a record");
    let shown = |v: Option<RecordBytes>| v.map(|v| text_of(v.as_slice()));
    {
        let before = count();
        let value = {
            {
                ans(block(
                    &rt,
                    st.record_put("conf-schema", b"a/1", &rec(b"one")),
                ))
            }
        };
        assert_eq!(count() - before, 1, "record put a/1: exact first crossings");
        answers.insert("record put a/1", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(block(
                    &rt,
                    st.record_put("conf-schema", b"a/2", &rec(b"two")),
                ))
            }
        };
        assert_eq!(count() - before, 1, "record put a/2: exact first crossings");
        answers.insert("record put a/2", value)
    };
    {
        let before = count();
        let value =
            { ans(block(&rt, StoreCalls::record_get(&st, "conf-schema", b"a/1")).map(shown)) };
        assert_eq!(count() - before, 1, "record get: exact first crossings");
        answers.insert("record get", value)
    };
    {
        let before = count();
        let value =
            { ans(block(&rt, StoreCalls::record_get(&st, "conf-schema", b"zz")).map(shown)) };
        assert_eq!(
            count() - before,
            1,
            "record get absent: exact first crossings"
        );
        answers.insert("record get absent", value)
    };
    let scan = || {
        ans(
            block(&rt, st.record_scan("conf-schema", b"a/", 5)).map(|mut v| {
                v.sort_by(|x, y| x.0.cmp(&y.0));
                v.into_iter()
                    .map(|(k, v)| (text_of(&k), text_of(v.as_slice())))
                    .collect::<Vec<_>>()
            }),
        )
    };
    {
        let before = count();
        let value = (scan)();
        assert_eq!(count() - before, 1, "record scan: exact first crossings");
        answers.insert("record scan", value)
    };

    {
        let before = count();
        let value = { ans(block(&rt, st.record_put("conf-schema", b"a/1", &rec(b"")))) };
        assert_eq!(
            count() - before,
            1,
            "record put a/1 empty: exact first crossings"
        );
        answers.insert("record put a/1 empty", value)
    };
    {
        let before = count();
        let value =
            { ans(block(&rt, StoreCalls::record_get(&st, "conf-schema", b"a/1")).map(shown)) };
        assert_eq!(
            count() - before,
            1,
            "record get emptied: exact first crossings"
        );
        answers.insert("record get emptied", value)
    };
    {
        let before = count();
        let value = (scan)();
        assert_eq!(
            count() - before,
            1,
            "record scan emptied: exact first crossings"
        );
        answers.insert("record scan emptied", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(block(
                    &rt,
                    StoreCalls::upsert_plane_record(&st, plane("task", "t2", None, 0, b"b").view()),
                ))
            }
        };
        assert_eq!(count() - before, 1, "typed upsert: exact first crossings");
        answers.insert("typed upsert", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(block(&rt, StoreCalls::get_plane_record(&st, "task", "t2"))
                    .map(|v| v.map(|v| text_of(&v))))
            }
        };
        assert_eq!(count() - before, 1, "typed get: exact first crossings");
        answers.insert("typed get", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(block(
                    &rt,
                    StoreCalls::append_plane_record(
                        &st,
                        op(13),
                        plane("ev", "f", Some("t2"), 1, b"1").view(),
                    ),
                ))
            }
        };
        assert_eq!(count() - before, 1, "typed append: exact first crossings");
        answers.insert("typed append", value)
    };
    {
        let before = count();
        let value = {
            {
                bodies(
                    block(
                        &rt,
                        StoreCalls::list_plane_records(
                            &st,
                            "ev",
                            &PlaneSelector::Parent("t2".into()),
                        ),
                    )
                    .map_err(|e| busbar_contract::records::RecordStoreError(e.to_string())),
                )
            }
        };
        assert_eq!(count() - before, 1, "typed list: exact first crossings");
        answers.insert("typed list", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(block(
                    &rt,
                    StoreCalls::delete_plane_record(&st, "task", "t2"),
                ))
            }
        };
        assert_eq!(count() - before, 1, "typed delete: exact first crossings");
        answers.insert("typed delete", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(block(
                    &rt,
                    StoreCalls::redeem_plane_token(&st, "tok", "y", LIVE_REPLAY_DEADLINE, 1),
                ))
            }
        };
        assert_eq!(count() - before, 1, "typed redeem: exact first crossings");
        answers.insert("typed redeem", value)
    };
    {
        let before = count();
        let value = {
            {
                ans(block(
                    &rt,
                    StoreCalls::plane_token_live(&st, "tok", "y", 100, 1),
                ))
            }
        };
        assert_eq!(count() - before, 1, "typed live: exact first crossings");
        answers.insert("typed live", value)
    };
    {
        let before = count();
        let value = { ans(b.get_usage(ub, w)) };
        assert_eq!(
            count() - before,
            2,
            "usage at the end: exact first crossings"
        );
        answers.insert("usage at the end", value)
    };

    {
        let before = count();
        let value = { ans(block(&rt, st.purge_usage_before(w * 2))) };
        assert_eq!(count() - before, 1, "usage purge: exact first crossings");
        answers.insert("usage purge", value)
    };
    {
        let before = count();
        let value = { ans(b.get_usage(ub, w)) };
        assert_eq!(count() - before, 2, "usage purged: exact first crossings");
        answers.insert("usage purged", value)
    };
    {
        let before = count();
        let value = { ans(b.get_usage("j", w * 2)) };
        assert_eq!(count() - before, 2, "usage kept: exact first crossings");
        answers.insert("usage kept", value)
    };

    let sk = scoped_key();
    {
        let before = count();
        let value = { ans(b.put_key(&sk)) };
        assert_eq!(count() - before, 1, "scope-kind put: exact first crossings");
        answers.insert("scope-kind put", value)
    };
    let before_scope = count();
    let (answer, back) = {
        match b.get_key(&sk.id) {
            Ok(Some(k)) => {
                let want = VirtualKey {
                    revision: k.revision,
                    ..scoped_key()
                };
                let same = serde_json::to_vec(&k).ok() == serde_json::to_vec(&want).ok();
                let line = format!(
                    "identical={same} plane_grants={}",
                    k.scope_allowed("engine_tool", "filesystem_read_file")
                        && k.scope_allowed("engine_server", "filesystem")
                        && !k.scope_allowed("pool", "filesystem_read_file")
                );
                (line, Some(k))
            }
            other => (ans(other.map(|k| k.map(|k| k.id))), None),
        }
    };
    assert_eq!(
        count() - before_scope,
        2,
        "scope-kind get: exact first crossings"
    );
    answers.insert("scope-kind get", answer);
    {
        let before = count();
        let value = {
            match b.list_keys() {
                Ok(ks) => {
                    let listed = ks.iter().find(|k| k.id == sk.id);
                    format!(
                        "identical={}",
                        listed.is_some()
                            && listed.and_then(|k| serde_json::to_vec(k).ok())
                                == back.as_ref().and_then(|k| serde_json::to_vec(k).ok())
                    )
                }
                Err(e) => format!("! {e}"),
            }
        };
        assert_eq!(
            count() - before,
            2,
            "scope-kind list: exact first crossings"
        );
        answers.insert("scope-kind list", value)
    };

    let at = |label: &str| answers.get(label).expect(label).as_str();
    let tail = |label: &str| at(label).split_once(' ').map_or("", |x| x.1);
    for (label, answer) in &answers {
        assert!(!answer.contains("faulted"), "{label}: {answer}");
    }
    assert!(at("open").starts_with("Ready "), "open: {}", at("open"));
    assert_eq!(at("refused as another kind"), "refused=true");
    for label in [
        "put grouped",
        "put plain",
        "delete plain",
        "add usage",
        "put usage",
        "meter p 3",
        "cred c1",
        "key+cred k2",
        "revoke c1",
        "deny x",
        "upsert t1",
        "append e1",
        "append e2",
        "delete t1",
        "usage batch",
        "metering batch",
        "record put a/1",
        "record put a/1 empty",
        "typed upsert",
        "typed delete",
        "scope-kind put",
    ] {
        assert!(at(label).starts_with("= "), "{label}: {}", at(label));
    }
    assert_eq!(
        at("get grouped"),
        format!(
            "= Some(({:?}, Some({:?})))",
            "vk_conf_grouped", "conf-group"
        ),
        "a key put is the key got"
    );
    for label in [
        "get absent",
        "get t1 after",
        "record get absent",
        "record get emptied",
    ] {
        assert_eq!(at(label), "= None", "{label}");
    }
    for label in ["delete absent", "relive plain", "append e2 fork"] {
        assert!(
            at(label).starts_with("! "),
            "refused: {label}: {}",
            at(label)
        );
    }
    assert_eq!(
        at("list ev t1"),
        "= [\"1\", \"2\"]",
        "a refused sequence fork leaves both original events intact"
    );
    assert!(
        at("cred c9 (live slot)").starts_with("! "),
        "a live slot is not taken twice"
    );
    assert_eq!(at("usage batch replay"), at("usage batch"));
    assert_eq!(at("usage batch conflict"), "! STORE_OPID_CONFLICT");
    for label in ["upsert c1 under p", "upsert c2 under p", "delete c1"] {
        assert!(at(label).starts_with("= "), "{label}: {}", at(label));
    }
    assert_eq!(
        at("get c1"),
        "= Some(\"c1\")",
        "a parented upsert reads back by its own id"
    );
    assert_eq!(
        at("list ctask p"),
        "= [\"c1\", \"c2\"]",
        "two ids under one parent are two records, both listed under it"
    );
    assert_eq!(at("get c1 after"), "= None", "deleted by its own id");
    assert_eq!(at("get c2"), "= Some(\"c2\")", "deleting c1 leaves c2");

    for label in ["append rt1", "append rt2"] {
        assert!(at(label).starts_with("= "), "{label}: {}", at(label));
    }
    assert_eq!(
        at("purge rt terminal-only"),
        "= 1",
        "a terminal-only purge drops the old TERMINAL row and only it"
    );
    assert_eq!(
        at("list rt kept"),
        r#"= ["active"]"#,
        "a terminal-only purge keeps an ACTIVE row however old"
    );
    assert_eq!(
        at("purge rt age"),
        "= 1",
        "an age purge drops the old ACTIVE row"
    );
    assert_eq!(
        at("list rt aged"),
        "= []",
        "nothing old survives an age purge"
    );
    assert_eq!(at("redeem"), "= true");
    assert_eq!(at("redeem again"), "= false", "a token is redeemed once");
    assert_eq!(at("record get"), "= Some(\"one\")");
    assert_eq!(
        at("record scan"),
        "= [(\"a/1\", \"one\"), (\"a/2\", \"two\")]"
    );
    assert_eq!(
        at("record scan emptied"),
        "= [(\"a/2\", \"two\")]",
        "an empty put removes the row: the scan never returns it"
    );

    assert!(
        tail("usage again").contains("UsageLedger { requests: 2,"),
        "{}",
        at("usage again")
    );
    assert!(
        tail("usage at the end").contains("UsageLedger { requests: 4,"),
        "{}",
        at("usage at the end")
    );
    assert_eq!(at("usage purge"), "= 1", "the one window before the cutoff");
    assert!(
        tail("usage purged").contains("UsageLedger { requests: 0,"),
        "{}",
        at("usage purged")
    );
    assert!(
        tail("usage kept").contains("UsageLedger { requests: 9,"),
        "{}",
        at("usage kept")
    );
    assert_eq!(at("scope-kind get"), "identical=true plane_grants=true");
    assert_eq!(at("scope-kind list"), "identical=true");
    drop(st);
    answers
}
