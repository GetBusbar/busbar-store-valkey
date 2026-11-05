// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::store::OpId;
use busbar_contract::records::{
    MeteringDelta, ModelTokens, ModelTokensDelta, RecordStore, UsageDelta, UsageLedger,
};
use std::collections::BTreeMap;

fn delta(scale: u32, amount: i128, requests: i64) -> UsageDelta {
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

fn meter(key: &str, scale: u32, amount: i128, requests: u64) -> MeteringDelta {
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
        .add_metering_batch_deduped(op, &[meter(key, 6, 1, 1), meter(key, 6, i128::MAX, 1)])
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
            usage_units: BTreeMap::from([("input".into(), i128::MAX)]),
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
    assert_eq!(model.usage_units["bytes"], i128::from(u64::MAX) * 1_000_000);
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
            "170141183460469231731687303715885",
        )
        .ignore()
        .hset(
            &usage,
            usage_field("exact-model", "bytes"),
            u64::MAX.to_string(),
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

#[test]
fn exact_quantity_decoder_preserves_i128_and_rejects_invalid_totals() {
    for quantity in [0, i128::from(u64::MAX) + 1, i128::MAX] {
        assert_eq!(quantity_count(&quantity.to_string()).unwrap(), quantity);
    }
    for invalid in ["-1", "170141183460469231731687303715884105728", "1.5"] {
        assert!(quantity_count(invalid).is_err());
    }
    assert_eq!(ledger_count(&u64::MAX.to_string()).unwrap(), u64::MAX);
}

#[test]
fn exact_counts_i128_accrual_min_refund_and_replay() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(6);
    let url = url_for_db(6);
    let store = ValkeyStore::connect(&url).unwrap();
    let key = "wide-exact-counts";
    store.put_key(&vk(key)).unwrap();
    let wide = i128::from(u64::MAX) + 1;
    store.add_usage(key, 0, &delta(6, wide, 1)).unwrap();
    assert_eq!(
        store.get_usage(key, 0).unwrap().models[0].usage_units["input"],
        wide
    );
    let op = OpId::from_parts(0xe82, 1);
    let cells = [(key, 0, delta(6, i128::MAX - wide, 2))];
    store.add_usage_batch_deduped(op, &cells).unwrap();
    store.add_usage_batch_deduped(op, &cells).unwrap();
    let before = store.get_usage(key, 0).unwrap();
    assert_eq!(before.models[0].usage_units["input"], i128::MAX);
    assert_eq!(before.requests, 3);
    let stored: String = raw
        .hget(usage_key(key, 0), usage_field("exact-model", "input"))
        .unwrap();
    assert_eq!(stored, i128::MAX.to_string());
    let op = OpId::from_parts(0xe82, 2);
    assert!(store
        .add_usage_batch_deduped(op, &[(key, 1, delta(6, 1, 1)), (key, 0, delta(6, 1, 1))])
        .is_err());
    assert_eq!(store.get_usage(key, 0).unwrap(), before);
    assert_eq!(store.get_usage(key, 1).unwrap(), UsageLedger::default());
    let refund = [(key, 0, delta(6, i128::MIN, -1))];
    store.add_usage_batch_deduped(op, &refund).unwrap();
    store.add_usage_batch_deduped(op, &refund).unwrap();
    let reopened = ValkeyStore::connect(&url).unwrap();
    let got = reopened.get_usage(key, 0).unwrap();
    assert_eq!(got.models[0].usage_units.get("input"), None);
    assert_eq!(got.models[0].usage_units.get("audio_seconds"), None);
    assert_eq!(got.requests, 2);

    let meter_op = OpId::from_parts(0xe82, 3);
    let meters = [meter(key, 6, wide, u64::MAX)];
    reopened
        .add_metering_batch_deduped(meter_op, &meters)
        .unwrap();
    reopened
        .add_metering_batch_deduped(meter_op, &meters)
        .unwrap();
    let rows = reopened.list_metering(0).unwrap();
    let row = rows.iter().find(|row| row.key_id == key).unwrap();
    assert_eq!(
        (
            row.tokens_input,
            row.usage_units["audio_seconds"],
            row.requests
        ),
        (wide, wide, u64::MAX)
    );
}

#[test]
fn exact_counts_v8_micros_are_validated_without_rescaling() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(6);
    let url = url_for_db(6);
    let key = usage_key("micro-upgrade", 0);
    raw.set::<_, _, ()>(SCHEMA_KEY, "08").unwrap();
    raw.hset::<_, _, _, ()>(
        &key,
        usage_field("exact-model", "input"),
        i128::MAX.to_string(),
    )
    .unwrap();
    raw.hset::<_, _, _, ()>(&key, "requests", u64::MAX.to_string())
        .unwrap();
    raw.hset::<_, _, _, ()>(
        &key,
        usage_field("exact-model", "audio_seconds"),
        "170141183460469231731687303715884105728",
    )
    .unwrap();
    assert!(ValkeyStore::connect(&url).is_err());
    assert_eq!(raw.get::<_, String>(SCHEMA_KEY).unwrap(), "08");
    assert_eq!(
        raw.hget::<_, _, String>(&key, usage_field("exact-model", "input"))
            .unwrap(),
        i128::MAX.to_string()
    );
    raw.hset::<_, _, _, ()>(&key, usage_field("exact-model", "audio_seconds"), "1")
        .unwrap();
    for _ in 0..2 {
        let store = ValkeyStore::connect(&url).unwrap();
        let got = store.get_usage("micro-upgrade", 0).unwrap();
        assert_eq!(got.requests, u64::MAX);
        assert_eq!(got.models[0].usage_units["input"], i128::MAX);
        assert_eq!(got.models[0].usage_units["audio_seconds"], 1);
        assert_eq!(raw.get::<_, i64>(SCHEMA_KEY).unwrap(), SCHEMA_VERSION);
    }
}

#[test]
fn i128_quantity_json_remains_exact_numeric_tokens() {
    let ledger = UsageLedger {
        requests: u64::MAX,
        billable_requests: u64::MAX,
        models: vec![ModelTokens {
            scale: 6,
            model: "wide".into(),
            usage_units: BTreeMap::from([("input".into(), i128::MAX)]),
        }],
    };
    let wire = serde_json::to_string(&ledger).unwrap();
    assert!(wire.contains("\"input\":170141183460469231731687303715884105727"));
    assert_eq!(serde_json::from_str::<UsageLedger>(&wire).unwrap(), ledger);
    let change = delta(6, i128::MIN, i64::MIN);
    let wire = serde_json::to_string(&change).unwrap();
    assert!(wire.contains("\"input\":-170141183460469231731687303715884105728"));
    assert_eq!(serde_json::from_str::<UsageDelta>(&wire).unwrap(), change);
}
