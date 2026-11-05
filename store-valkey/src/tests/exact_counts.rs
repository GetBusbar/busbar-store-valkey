// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{
    MeteringDelta, ModelTokens, ModelTokensDelta, RecordStore, UsageDelta, UsageLedger,
};
use std::collections::BTreeMap;

fn delta(scale: u32, amount: i64, requests: i64) -> UsageDelta {
    UsageDelta {
        requests,
        billable_requests: requests,
        models: vec![ModelTokensDelta {
            scale,
            model: "exact-model".into(),
            usage_units: BTreeMap::from([
                ("input".into(), amount),
                ("audio_seconds".into(), amount),
            ]),
        }],
    }
}

fn meter(key: &str, scale: u32, amount: u64, requests: u64) -> MeteringDelta {
    MeteringDelta {
        scale,
        key_id: key.into(),
        bucket: 0,
        model: "exact-model".into(),
        provider: "provider".into(),
        tokens_input: amount,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests,
        billable_requests: requests,
        key_group_at_use: "group".into(),
        pricing_version: "opening".into(),
        priced_from_ms: 0,
        usage_units: BTreeMap::from([("audio_seconds".into(), amount)]),
    }
}

fn exercise(store: &dyn RecordStore, key: &str) {
    store.add_usage(key, 0, &delta(0, 2, 1)).unwrap();
    let op = OpId::from_parts(0xe81, 1);
    let cells = [(key, 0, delta(6, 123_456, 2))];
    store.add_usage_batch_deduped(op, &cells).unwrap();
    store.add_usage_batch_deduped(op, &cells).unwrap();
    let got = store.get_usage(key, 0).unwrap();
    assert_eq!((got.requests, got.billable_requests), (3, 3));
    assert_eq!(got.models[0].scale, 6);
    assert_eq!(got.models[0].usage_units["input"], 2_123_456);
    assert_eq!(got.models[0].usage_units["audio_seconds"], 2_123_456);
    store.add_usage(key, 0, &delta(6, -123_455, 0)).unwrap();
    assert_eq!(
        store.get_usage(key, 0).unwrap().models[0].usage_units["input"],
        2_000_001
    );
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 0, delta(6, 1, 2))])
        .is_err());

    store.add_metering(&meter(key, 0, 2, 1)).unwrap();
    let op = OpId::from_parts(0xe81, 2);
    let meters = [meter(key, 6, 123_456, 2)];
    store.add_metering_batch_deduped(op, &meters).unwrap();
    store.add_metering_batch_deduped(op, &meters).unwrap();
    let before = store.list_metering(0).unwrap();
    let got = before.iter().find(|row| row.key_id == key).unwrap();
    assert_eq!(
        (
            got.scale,
            got.tokens_input,
            got.requests,
            got.billable_requests
        ),
        (6, 2_123_456, 3, 3)
    );
    assert_eq!(got.usage_units["audio_seconds"], 2_123_456);
    let op = OpId::from_parts(0xe81, 3);
    assert!(store
        .add_metering_batch_deduped(
            op,
            &[meter(key, 6, 1, 1), meter(key, 6, i64::MAX as u64, 1)]
        )
        .is_err());
    assert_eq!(
        store.list_metering(0).unwrap(),
        before,
        "overflow rolls the entire batch back"
    );
    store
        .add_metering_batch_deduped(op, &[meter(key, 6, 1, 1)])
        .unwrap();

    let max = UsageLedger {
        requests: 7,
        billable_requests: 5,
        models: vec![ModelTokens {
            scale: 6,
            model: "exact-model".into(),
            usage_units: BTreeMap::from([("input".into(), i64::MAX as u64)]),
        }],
    };
    store.put_usage(key, 0, &max).unwrap();
    let op = OpId::from_parts(0xe81, 4);
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1)), (key, 0, delta(6, 1, 1))])
        .is_err());
    assert_eq!(store.get_usage(key, 0).unwrap(), max);
    assert_eq!(store.get_usage(key, 1).unwrap(), UsageLedger::default());
    // A refused operation leaves no receipt; the same id can now commit another body.
    store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1))])
        .unwrap();
    assert_eq!(
        store.get_usage(key, 1).unwrap().models[0].usage_units["input"],
        1
    );
    assert!(store.add_usage(key, 2, &delta(3, 1, 1)).is_err());
    assert_eq!(store.get_usage(key, 2).unwrap(), UsageLedger::default());
}

#[test]
fn exact_counts_decimal_legacy_replay_and_atomic_overflow() {
    let Some(_) = live_store() else { return };
    let (_database, _raw) = fresh_db_client(6);
    let store = ValkeyStore::connect(&url_for_db(6)).unwrap();
    store.put_key(&vk("exact-counts")).unwrap();
    exercise(&store, "exact-counts");
}

fn migrated(store: &dyn RecordStore) {
    let row = store.get_usage("legacy", 0).unwrap();
    assert_eq!((row.requests, row.billable_requests), (7, 5));
    let model = row
        .models
        .iter()
        .find(|row| row.model == "exact-model")
        .unwrap();
    assert_eq!(model.scale, 6);
    assert_eq!(model.usage_units["input"], 2_000_000);
    assert_eq!(model.usage_units["audio_seconds"], 3_000_000);
    let rows = store.list_metering(0).unwrap();
    let row = rows.iter().find(|row| row.key_id == "legacy").unwrap();
    assert_eq!(
        (row.scale, row.tokens_input, row.requests),
        (6, 4_000_000, 9)
    );
    assert_eq!(row.usage_units["audio_seconds"], 5_000_000);
}

#[test]
fn exact_counts_legacy_migration_preflight_reopen_idempotent() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(6);
    let url = url_for_db(6);
    let store = ValkeyStore::connect(&url).unwrap();
    store.put_key(&vk("legacy")).unwrap();
    drop(store);
    let usage = usage_key("legacy", 0);
    let row = attributed_metering_row(0, "legacy", "exact-model", "provider", 0, "", "");
    redis::pipe()
        .set(SCHEMA_KEY, 7)
        .ignore()
        .hset(&usage, "requests", 7)
        .ignore()
        .hset(&usage, "billable_requests", 5)
        .ignore()
        .hset(&usage, usage_field("exact-model", "input"), 2)
        .ignore()
        .hset(
            &usage,
            usage_field("exact-model", "audio_seconds"),
            "9223372036855",
        )
        .ignore()
        .sadd(metering_set(0), &row)
        .ignore()
        .hset(&row, "key_id", "legacy")
        .ignore()
        .hset(&row, "model", "exact-model")
        .ignore()
        .hset(&row, "provider", "provider")
        .ignore()
        .hset(&row, "tokens_input", 4)
        .ignore()
        .hset(&row, "requests", 9)
        .ignore()
        .hset(&row, "u:audio_seconds", 5)
        .ignore()
        .query::<()>(&mut raw)
        .unwrap();
    assert!(ValkeyStore::connect(&url).is_err());
    let value: String = raw
        .hget(&usage, usage_field("exact-model", "input"))
        .unwrap();
    assert_eq!(value, "2");
    let version: i64 = raw.get(SCHEMA_KEY).unwrap();
    assert_eq!(version, 7);
    raw.hset::<_, _, _, ()>(&usage, usage_field("exact-model", "audio_seconds"), 3)
        .unwrap();
    for _ in 0..2 {
        let store = ValkeyStore::connect(&url).unwrap();
        migrated(&store);
    }
    let store = ValkeyStore::connect(&url).unwrap();
    store.add_usage("legacy", 0, &delta(6, 1, 0)).unwrap();
    drop(store);
    let store = ValkeyStore::connect(&url).unwrap();
    assert_eq!(
        store.get_usage("legacy", 0).unwrap().models[0].usage_units["input"],
        2_000_001
    );
}
