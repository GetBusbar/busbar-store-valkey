// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn schema_marker_disappearance_is_not_success() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(6);
    let got: Option<String> = redis::Script::new(SET_SCHEMA_MARKER.source_for_test())
        .key(SCHEMA_KEY)
        .arg("6")
        .arg(SCHEMA_VERSION)
        .invoke(&mut raw)
        .unwrap();
    assert_eq!(got.as_deref(), Some("missing"));
    assert!(!raw.exists::<_, bool>(SCHEMA_KEY).unwrap());
    raw.set::<_, _, ()>(SCHEMA_KEY, "not-a-number").unwrap();
    let error = ValkeyStore::connect(&url_for_db(6))
        .err()
        .expect("corrupt marker refused")
        .0;
    assert!(error.contains("busbar:schema") && error.contains("NOTHING was changed"));
    assert_eq!(raw.get::<_, String>(SCHEMA_KEY).unwrap(), "not-a-number");
}

#[test]
fn legacy_task_and_demotion_forks_preserve_sources_and_marker() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(6);
    let url = url_for_db(6);
    let store = ValkeyStore::connect(&url).unwrap();
    for kind in ["task", "demotion"] {
        let record = PlaneRecord {
            kind: kind.into(),
            id: "collision".into(),
            parent: None,
            seq: 0,
            ts: 1,
            disposition: PlaneDisposition::Active,
            body: b"existing".to_vec(),
        };
        store.append_plane_record(record.view()).unwrap();
    }
    let task = sample_task("collision", "working", 2);
    let key = format!("{}collision", crate::legacy::TASK_ROW_PREFIX);
    raw.set::<_, _, ()>(&key, serde_json::to_string(&task).unwrap())
        .unwrap();
    raw.set::<_, _, ()>(SCHEMA_KEY, 6).unwrap();
    assert!(ValkeyStore::connect(&url).is_err());
    assert!(raw.exists::<_, bool>(&key).unwrap());
    assert_eq!(raw.get::<_, i64>(SCHEMA_KEY).unwrap(), 6);
    raw.del::<_, ()>(&key).unwrap();
    let dem = demotion("collision", "evidence", 2);
    raw.hset::<_, _, _, ()>(
        crate::legacy::MCP_DEMOTIONS_HASH,
        "collision",
        serde_json::to_string(&dem).unwrap(),
    )
    .unwrap();
    assert!(ValkeyStore::connect(&url).is_err());
    assert!(raw
        .hexists::<_, _, bool>(crate::legacy::MCP_DEMOTIONS_HASH, "collision")
        .unwrap());
    assert_eq!(raw.get::<_, i64>(SCHEMA_KEY).unwrap(), 6);
}

#[test]
fn corrupt_plane_delete_and_purge_validate_before_removing_any_row() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(6);
    let store = ValkeyStore::connect(&url_for_db(6)).unwrap();
    for seq in [1, 2] {
        let record = PlaneRecord {
            kind: "audit_corrupt".into(),
            id: "event".into(),
            parent: Some("chain".into()),
            seq,
            ts: seq,
            disposition: PlaneDisposition::Terminal,
            body: vec![1],
        };
        store.append_plane_record(record.view()).unwrap();
    }
    let prefix = format!("busbar:plane:{}:", hex(b"audit_corrupt"));
    let rec = format!("{prefix}rec");
    raw.hset::<_, _, _, ()>(&rec, "2:chain", "1t{bad}").unwrap();
    assert!(store.delete_plane_record("audit_corrupt", "chain").is_err());
    assert_eq!(raw.hlen::<_, usize>(&rec).unwrap(), 2);
    assert!(store
        .purge_plane_records_before("audit_corrupt", 10)
        .is_err());
    assert_eq!(raw.hlen::<_, usize>(&rec).unwrap(), 2);
}

#[test]
fn malformed_credential_members_refuse_complete_listing() {
    let Some(store) = live_store() else { return };
    let key = uid("bad_member");
    store
        .with_conn(|c| c.sadd::<_, _, ()>(cred_ids_key(&key), "invalid"))
        .unwrap();
    assert!(store.list_credentials(&key).is_err());
    store
        .with_conn(|c| c.del::<_, ()>(cred_ids_key(&key)))
        .unwrap();
}

#[test]
fn duplicate_protocol_options_use_the_historical_last_value() {
    let url = url::Url::parse("redis://localhost?protocol=bad&protocol=2").unwrap();
    assert!(check_protocol(&url).is_ok());
    let url = url::Url::parse("redis://localhost?protocol=2&protocol=bad").unwrap();
    assert!(check_protocol(&url).is_err());
}
