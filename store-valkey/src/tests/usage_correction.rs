// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Exact acceptance through the real loaded door, sharing ordinary writers' RESP authority.

use super::super::{database, fresh_db_client, interleave, url_for_db, vk};
use super::*;
use busbar_contract::abi::sdk::store::{correction, dedupe::Dedupe};
use busbar_contract::records::{
    MeteringDelta, MeteringRow, ModelTokens, ModelTokensDelta, UsageLedger, UNIT_INPUT,
};
use busbar_contract::store_calls;
use correction::{Decision, Request, UsageAddress, UsageChange};
use redis::Commands;
use std::sync::atomic::Ordering;
use std::time::Duration;

const DAY_START: u64 = 1_700_006_400;
const PRICED_FROM_MS: u64 = 1_700_006_400_000;
const PRIVATE_DATABASE: u32 = 6;
const SHORT_RECEIPT_TTL: i64 = 600;
const INITIAL: u64 = 100;
const CORRECTED: u64 = 40;
const FIXTURE_MODEL: &str = "correction-model";
const FIXTURE_PROVIDER: &str = "correction-provider";
const FIXTURE_GROUP: &str = "original-group";
const FIXTURE_PRICE: &str = "original-price";
const OPEN_UNIT: &str = "tool:calls";
const WAIT: Duration = Duration::from_secs(5);
const EXEC: &[u8] = b"$4\r\nEXEC\r\n";

fn setup() -> Option<(database::Database, redis::Connection, ValkeyStore, String)> {
    let _ = live_store()?;
    let (database, raw) = fresh_db_client(PRIVATE_DATABASE);
    let url = url_for_db(PRIVATE_DATABASE);
    let store = ValkeyStore::connect(&url).unwrap();
    assert!(store_calls::StoreCalls::supports_usage_correction(&store));
    Some((database, raw, store, url))
}

fn ledger(count: u64) -> UsageLedger {
    UsageLedger {
        requests: count,
        billable_requests: count,
        models: vec![ModelTokens {
            model: FIXTURE_MODEL.into(),
            usage_units: [(UNIT_INPUT.into(), count), (OPEN_UNIT.into(), count)].into(),
        }],
    }
}

fn metering(key: &str) -> MeteringDelta {
    MeteringDelta {
        bucket: DAY_START,
        key_id: key.into(),
        model: FIXTURE_MODEL.into(),
        provider: FIXTURE_PROVIDER.into(),
        tokens_input: INITIAL,
        tokens_output: INITIAL + 1,
        tokens_cache_read: INITIAL + 2,
        tokens_cache_write: INITIAL + 3,
        requests: INITIAL + 4,
        billable_requests: INITIAL + 5,
        key_group_at_use: FIXTURE_GROUP.into(),
        pricing_version: FIXTURE_PRICE.into(),
        priced_from_ms: PRICED_FROM_MS,
        usage_units: [(OPEN_UNIT.into(), INITIAL + 6)].into(),
    }
}

fn candidate(store: &ValkeyStore) -> Request {
    let key = fresh("correction-key");
    store.put_key(&vk(&key)).unwrap();
    Slots::add_metering_batch(store, op(1), &[metering(&key)]).unwrap();
    let bucket = fresh("correction-usage");
    store
        .put_usage(&bucket, DAY_START, &ledger(INITIAL))
        .unwrap();
    let mut rows = store.list_metering(DAY_START).unwrap();
    rows.retain(|row| row.key_id == key);
    correction::canonical_metering(&mut rows);
    Request {
        version: correction::VERSION,
        op_id: op(2),
        key_id: key,
        day_start: DAY_START,
        metering: rows,
        usage: vec![UsageChange {
            address: UsageAddress {
                bucket_id: bucket,
                window_start: DAY_START,
            },
            expected: ledger(INITIAL),
            replacement: ledger(CORRECTED),
        }],
    }
}

fn apply(store: &ValkeyStore, request: &Request) -> OpResult<Decision> {
    call(store_calls::StoreCalls::apply_usage_correction(
        store, request,
    ))
}
fn op_receipt(id: OpId) -> String {
    format!("busbar:op:{}", crate::hex(&id.0))
}
fn receipt(request: &Request) -> String {
    op_receipt(request.op_id)
}
fn physical(request: &Request, index: usize) -> String {
    let address = &request.usage[index].address;
    crate::usage_key(&address.bucket_id, address.window_start)
}
fn read(store: &ValkeyStore, request: &Request, index: usize) -> UsageLedger {
    let address = &request.usage[index].address;
    store
        .get_usage(&address.bucket_id, address.window_start)
        .unwrap()
}

#[test]
fn two_nodes_cannot_accept_the_same_prestate_twice() {
    let Some((_database, mut raw, store, url)) = setup() else {
        return;
    };
    let first = candidate(&store);
    let mut second = first.clone();
    second.op_id = op(3);
    let clients = [
        ValkeyStore::connect(&url).unwrap(),
        ValkeyStore::connect(&url).unwrap(),
    ];
    let requests = [first, second];
    let answers = std::thread::scope(|scope| {
        let workers: Vec<_> = clients
            .into_iter()
            .zip(requests.clone())
            .map(|(client, request)| scope.spawn(move || apply(&client, &request)))
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        answers
            .iter()
            .filter(|answer| **answer == Decision::Applied)
            .count(),
        1
    );
    assert_eq!(
        answers
            .iter()
            .filter(|answer| **answer == Decision::ConditionConflict)
            .count(),
        1
    );
    for (request, answer) in requests.iter().zip(answers) {
        assert_eq!(
            raw.exists::<_, bool>(receipt(request)).unwrap(),
            answer == Decision::Applied
        );
        assert_eq!(read(&store, request, 0), ledger(CORRECTED));
    }
}

#[test]
fn exact_receipt_precedes_live_key_metering_and_usage_predicates_without_renewing_ttl() {
    let Some((_database, mut raw, store, url)) = setup() else {
        return;
    };
    let request = candidate(&store);
    assert_eq!(apply(&store, &request).unwrap(), Decision::Applied);
    assert_eq!(
        raw.hget::<_, _, Vec<u8>>(receipt(&request), "b").unwrap(),
        Dedupe::usage_correction(&request).body().to_vec()
    );
    raw.expire::<_, ()>(receipt(&request), SHORT_RECEIPT_TTL)
        .unwrap();
    store
        .put_usage(
            &request.usage[0].address.bucket_id,
            DAY_START,
            &ledger(INITIAL + 1),
        )
        .unwrap();
    store.delete_key(&request.key_id).unwrap();
    let reopened = ValkeyStore::connect(&url).unwrap();
    assert_eq!(apply(&reopened, &request).unwrap(), Decision::Applied);
    assert_eq!(read(&store, &request, 0), ledger(INITIAL + 1));
    assert!(raw.ttl::<_, i64>(receipt(&request)).unwrap() <= SHORT_RECEIPT_TTL);
    let mut changed = request.clone();
    changed.usage[0].replacement = ledger(CORRECTED + 1);
    assert!(matches!(
        apply(&reopened, &changed),
        Err(OpRefused::Conflict)
    ));
}

#[test]
fn complete_c4_and_historical_attribution_are_predicates_with_no_conflict_receipt() {
    let Some((_database, mut raw, store, _)) = setup() else {
        return;
    };
    let original = candidate(&store);
    let perturbations: [fn(&mut MeteringRow); 12] = [
        |row| row.tokens_input += 1,
        |row| row.tokens_output += 1,
        |row| row.tokens_cache_read += 1,
        |row| row.tokens_cache_write += 1,
        |row| row.requests += 1,
        |row| row.billable_requests += 1,
        |row| *row.usage_units.get_mut(OPEN_UNIT).unwrap() += 1,
        |row| row.key_group_at_use.push('x'),
        |row| row.pricing_version.push('x'),
        |row| row.priced_from_ms += 1,
        |row| row.provider.push('x'),
        |row| row.model.push('x'),
    ];
    for perturb in perturbations {
        let mut request = original.clone();
        request.op_id = op(10);
        perturb(&mut request.metering[0]);
        assert_eq!(
            apply(&store, &request).unwrap(),
            Decision::ConditionConflict
        );
        assert!(!raw.exists::<_, bool>(receipt(&request)).unwrap());
        assert_eq!(read(&store, &request, 0), ledger(INITIAL));
    }
    let mut missing = original.clone();
    missing.metering.clear();
    assert_eq!(
        apply(&store, &missing).unwrap(),
        Decision::ConditionConflict
    );
    assert!(!raw.exists::<_, bool>(receipt(&missing)).unwrap());
}

#[test]
fn absence_and_full_u64_rows_are_compared_and_replaced_without_float_or_signed_narrowing() {
    let Some((_database, mut raw, store, _)) = setup() else {
        return;
    };
    let mut request = candidate(&store);
    let absent = fresh("correction-absent");
    request.usage.push(UsageChange {
        address: UsageAddress {
            bucket_id: absent,
            window_start: u64::MAX,
        },
        expected: UsageLedger::default(),
        replacement: ledger(u64::MAX),
    });
    request.usage.sort_by(|a, b| a.address.cmp(&b.address));
    assert_eq!(apply(&store, &request).unwrap(), Decision::Applied);
    for (index, change) in request.usage.iter().enumerate() {
        assert_eq!(read(&store, &request, index), change.replacement);
    }
    let mut next = request.clone();
    next.op_id = op(30);
    for change in &mut next.usage {
        change.expected = change.replacement.clone();
    }
    let wide = next
        .usage
        .iter_mut()
        .find(|change| change.replacement.requests == u64::MAX)
        .unwrap();
    wide.expected.requests -= 1;
    assert_eq!(apply(&store, &next).unwrap(), Decision::ConditionConflict);
    assert!(!raw.exists::<_, bool>(receipt(&next)).unwrap());
    let wide = next
        .usage
        .iter_mut()
        .find(|change| change.replacement.requests == u64::MAX)
        .unwrap();
    wide.expected.requests = u64::MAX;
    wide.replacement = ledger(u64::MAX - 1);
    assert_eq!(apply(&store, &next).unwrap(), Decision::Applied);
    for (index, change) in next.usage.iter().enumerate() {
        assert_eq!(read(&store, &next, index), change.replacement);
    }
}

#[test]
fn wrong_types_and_invalid_requests_never_commit_any_row_or_receipt() {
    let Some((_database, mut raw, store, _)) = setup() else {
        return;
    };
    for target in 0..6 {
        let mut request = candidate(&store);
        request.usage.push(UsageChange {
            address: UsageAddress {
                bucket_id: fresh("correction-second"),
                window_start: DAY_START,
            },
            expected: UsageLedger::default(),
            replacement: ledger(CORRECTED),
        });
        request.usage.sort_by(|a, b| a.address.cmp(&b.address));
        let meter = &request.metering[0];
        let row = crate::attributed_metering_row(
            DAY_START,
            &meter.key_id,
            &meter.model,
            &meter.provider,
            meter.priced_from_ms,
            &meter.key_group_at_use,
            &meter.pricing_version,
        );
        let targets = [
            receipt(&request),
            format!("{}{}", crate::KEY_PREFIX, request.key_id),
            crate::metering_set(DAY_START),
            physical(&request, 0),
            physical(&request, 1),
            row,
        ];
        let poisoned = &targets[target];
        let saved: redis::Value = redis::cmd("DUMP").arg(poisoned).query(&mut raw).unwrap();
        raw.set::<_, _, ()>(poisoned, "wrong-type").unwrap();

        if target == 1 {
            raw.del::<_, ()>(poisoned).unwrap();
            raw.hset::<_, _, _, ()>(poisoned, "field", "wrong-type")
                .unwrap();
        }
        assert!(matches!(
            apply(&store, &request),
            Err(OpRefused::Refused(_))
        ));
        for (index, change) in request.usage.iter().enumerate() {
            if physical(&request, index) != *poisoned {
                assert_eq!(read(&store, &request, index), change.expected);
            }
        }
        if target != 0 {
            assert!(!raw.exists::<_, bool>(receipt(&request)).unwrap());
        }
        raw.del::<_, ()>(poisoned).unwrap();
        if let redis::Value::BulkString(bytes) = saved {
            redis::cmd("RESTORE")
                .arg(poisoned)
                .arg(0)
                .arg(bytes)
                .query::<()>(&mut raw)
                .unwrap();
        }
    }
    let request = candidate(&store);
    let mut invalid = request.clone();
    invalid.usage.push(invalid.usage[0].clone());
    assert!(matches!(
        apply(&store, &invalid),
        Err(OpRefused::Refused(_))
    ));
    assert!(!raw.exists::<_, bool>(receipt(&invalid)).unwrap());
    assert_eq!(read(&store, &request, 0), ledger(INITIAL));
}

#[test]
fn ordinary_usage_metering_insert_and_key_delete_invalidate_the_same_watched_candidate() {
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    enum Writer {
        Usage,
        AbsentUsage,
        MeteringUpdate,
        MeteringInsert,
        KeyDelete,
    }
    for writer in [
        Writer::Usage,
        Writer::AbsentUsage,
        Writer::MeteringUpdate,
        Writer::MeteringInsert,
        Writer::KeyDelete,
    ] {
        let mut request = candidate(&fast);
        if matches!(writer, Writer::AbsentUsage) {
            request.usage[0].expected = UsageLedger::default();
            raw.del::<_, ()>(physical(&request, 0)).unwrap();
        }
        let expected = request.clone();
        let gate = interleave::gate(&url, true, |chunk| interleave::contains(chunk, EXEC));
        let slow = ValkeyStore::connect(&gate.url).unwrap();
        let worker = gate.spawn(move || apply(&slow, &request));
        gate.held.recv_timeout(WAIT).unwrap();
        match writer {
            Writer::Usage | Writer::AbsentUsage => {
                let delta = UsageDelta {
                    requests: 1,
                    billable_requests: 0,
                    models: Vec::new(),
                };
                Slots::add_usage_batch(
                    &fast,
                    op(40),
                    &[(&expected.usage[0].address.bucket_id, DAY_START, delta)],
                )
                .unwrap();
            }
            Writer::MeteringUpdate => {
                Slots::add_metering_batch(&fast, op(41), &[metering(&expected.key_id)]).unwrap();
            }
            Writer::MeteringInsert => {
                let mut new = metering(&expected.key_id);
                new.pricing_version.push('x');
                Slots::add_metering_batch(&fast, op(41), &[new]).unwrap();
            }
            Writer::KeyDelete => fast.delete_key(&expected.key_id).unwrap(),
        }
        gate.release.send(()).unwrap();
        assert_eq!(worker.join().unwrap().unwrap(), Decision::ConditionConflict);
        assert!(!raw.exists::<_, bool>(receipt(&expected)).unwrap());
        assert_ne!(read(&fast, &expected, 0), ledger(CORRECTED));
    }
}

#[test]
fn wrong_type_after_preflight_aborts_the_whole_exec_and_retry_refuses_without_effects() {
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let request = candidate(&fast);
    let expected = request.clone();
    let gate = interleave::gate(&url, true, |chunk| interleave::contains(chunk, EXEC));
    let slow = ValkeyStore::connect(&gate.url).unwrap();
    let worker = gate.spawn(move || apply(&slow, &request));
    gate.held.recv_timeout(WAIT).unwrap();
    raw.set::<_, _, ()>(physical(&expected, 0), "wrong-type")
        .unwrap();
    gate.release.send(()).unwrap();
    assert!(matches!(worker.join().unwrap(), Err(OpRefused::Refused(_))));
    assert!(!raw.exists::<_, bool>(receipt(&expected)).unwrap());
    assert_eq!(
        raw.get::<_, String>(physical(&expected, 0)).unwrap(),
        "wrong-type"
    );
}

#[test]
fn lost_exec_reply_never_reconnects_and_only_exact_receipt_replay_confirms_commit() {
    use super::conditional_records::{Mode, Proxy};
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let request = candidate(&fast);
    let proxy = Proxy::start(url.clone(), Mode::DropExec);
    let slow = ValkeyStore::connect(&proxy.url).unwrap();
    assert!(matches!(apply(&slow, &request), Err(OpRefused::Failed(_))));
    assert_eq!(proxy.execs.load(Ordering::SeqCst), 1);
    assert_eq!(read(&fast, &request, 0), ledger(CORRECTED));
    assert!(raw.exists::<_, bool>(receipt(&request)).unwrap());
    fast.put_usage(
        &request.usage[0].address.bucket_id,
        DAY_START,
        &ledger(INITIAL),
    )
    .unwrap();
    drop(slow);
    let reopened = ValkeyStore::connect(&url).unwrap();
    assert_eq!(apply(&reopened, &request).unwrap(), Decision::Applied);
    assert_eq!(read(&fast, &request, 0), ledger(INITIAL));
    let mut changed = request.clone();
    changed.usage[0].replacement.requests += 1;
    assert!(matches!(
        apply(&reopened, &changed),
        Err(OpRefused::Conflict)
    ));
}

#[test]
fn legacy_reserved_writes_refuse_fresh_effects_but_replay_exact_existing_receipts() {
    let Some((_database, mut raw, store, _)) = setup() else {
        return;
    };
    let delta = UsageDelta {
        requests: 1,
        billable_requests: 0,
        models: Vec::new(),
    };
    for bucket in [correction::ADJUST_UP_BUCKET, correction::ADJUST_DOWN_BUCKET] {
        let id = op(50);
        let cells = [(bucket, DAY_START, delta.clone())];
        assert!(matches!(
            Slots::add_usage_batch(&store, id, &cells),
            Err(OpRefused::Refused(_))
        ));
        assert!(!raw.exists::<_, bool>(op_receipt(id)).unwrap());
        assert!(store
            .put_usage(bucket, DAY_START, &ledger(CORRECTED))
            .is_err());
        assert_eq!(
            store.get_usage(bucket, DAY_START).unwrap(),
            UsageLedger::default()
        );

        raw.hset::<_, _, _, ()>(op_receipt(id), "b", &Dedupe::usage(&cells).body()[..])
            .unwrap();
        Slots::add_usage_batch(&store, id, &cells).unwrap();
        let changed = [(
            bucket,
            DAY_START,
            UsageDelta {
                requests: 2,
                ..delta.clone()
            },
        )];
        assert!(matches!(
            Slots::add_usage_batch(&store, id, &changed),
            Err(OpRefused::Conflict)
        ));
        assert_eq!(
            store.get_usage(bucket, DAY_START).unwrap(),
            UsageLedger::default()
        );
    }
}

#[test]
fn atomic_correction_replaces_plain_and_both_reserved_adjustment_rows_together() {
    let Some((_database, _raw, store, _)) = setup() else {
        return;
    };
    let mut request = candidate(&store);
    for bucket in [correction::ADJUST_UP_BUCKET, correction::ADJUST_DOWN_BUCKET] {
        request.usage.push(UsageChange {
            address: UsageAddress {
                bucket_id: bucket.into(),
                window_start: DAY_START,
            },
            expected: UsageLedger::default(),
            replacement: ledger(CORRECTED),
        });
    }
    request.usage.sort_by(|a, b| a.address.cmp(&b.address));
    assert_eq!(apply(&store, &request).unwrap(), Decision::Applied);
    for (index, change) in request.usage.iter().enumerate() {
        assert_eq!(read(&store, &request, index), change.replacement);
    }
}

#[test]
fn high_correction_survives_accrual_refund_saturation_and_reopen() {
    let Some((_database, _raw, store, url)) = setup() else {
        return;
    };
    let mut request = candidate(&store);
    const HIGH: u64 = u64::MAX - 10;
    request.usage[0].replacement = ledger(HIGH);
    request.usage[0].replacement.models.push(ModelTokens {
        model: String::new(),
        usage_units: [(UNIT_INPUT.into(), HIGH), (OPEN_UNIT.into(), HIGH)].into(),
    });
    correction::canonical_ledger(&mut request.usage[0].replacement).unwrap();
    assert_eq!(apply(&store, &request).unwrap(), Decision::Applied);
    let delta = |count| UsageDelta {
        requests: count,
        billable_requests: count,
        models: [String::new(), FIXTURE_MODEL.into()]
            .into_iter()
            .map(|model| ModelTokensDelta {
                model,
                usage_units: [(UNIT_INPUT.into(), count), (OPEN_UNIT.into(), count)].into(),
            })
            .collect(),
    };
    let bucket = &request.usage[0].address.bucket_id;
    let mut expected = request.usage[0].replacement.clone();
    for count in [3, -7, i64::MAX, i64::MIN, i64::MIN] {
        let change = delta(count);
        expected.apply_delta(&change);
        Slots::add_usage_batch(&store, op(60), &[(bucket, DAY_START, change)]).unwrap();
        let reopened = ValkeyStore::connect(&url).unwrap();
        let mut actual = read(&reopened, &request, 0);
        correction::canonical_ledger(&mut actual).unwrap();
        correction::canonical_ledger(&mut expected).unwrap();
        assert_eq!(actual, expected);
    }

    store
        .put_usage(bucket, DAY_START, &ledger(u64::MAX))
        .unwrap();
    assert_eq!(read(&store, &request, 0), ledger(u64::MAX));
}

#[test]
fn same_id_commit_between_receipt_and_usage_read_retries_to_the_receipt() {
    let Some((_database, _raw, fast, url)) = setup() else {
        return;
    };
    let request = candidate(&fast);
    let key = physical(&request, 0).into_bytes();
    let gate = interleave::gate(&url, true, move |chunk| {
        interleave::contains(chunk, b"HGETALL") && interleave::contains(chunk, &key)
    });
    let slow = ValkeyStore::connect(&gate.url).unwrap();
    let slow_request = request.clone();
    let worker = gate.spawn(move || apply(&slow, &slow_request));
    gate.held.recv_timeout(WAIT).unwrap();
    assert_eq!(apply(&fast, &request).unwrap(), Decision::Applied);
    fast.put_usage(
        &request.usage[0].address.bucket_id,
        DAY_START,
        &ledger(INITIAL + 1),
    )
    .unwrap();
    gate.release.send(()).unwrap();
    assert_eq!(worker.join().unwrap().unwrap(), Decision::Applied);
    assert_eq!(read(&fast, &request, 0), ledger(INITIAL + 1));
}

#[test]
fn pending_cancellation_and_instance_destruction_before_exec_leave_no_effect_or_receipt() {
    use std::future::Future;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use std::task::{Poll, Waker};

    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let request = candidate(&fast);
    let key = physical(&request, 0).into_bytes();
    let gate = interleave::gate(&url, true, move |chunk| {
        interleave::contains(chunk, b"HGETALL") && interleave::contains(chunk, &key)
    });
    let slow = ValkeyStore::connect(&gate.url).unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let wake = Arc::new(Mutex::new(None::<Waker>));
    let cancel_worker = cancelled.clone();
    let wake_worker = wake.clone();
    let slow_request = request.clone();
    let worker = gate.spawn(move || {
        block(async {
            let mut operation =
                store_calls::StoreCalls::apply_usage_correction(&slow, &slow_request);
            std::future::poll_fn(|cx| {
                *wake_worker.lock().unwrap() = Some(cx.waker().clone());
                if cancel_worker.load(Ordering::SeqCst) {
                    return Poll::Ready(());
                }
                match Future::poll(operation.as_mut(), cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(answer) => {
                        panic!("held correction unexpectedly answered: {answer:?}")
                    }
                }
            })
            .await;
            drop(operation);
        });
        drop(slow);
    });
    gate.held.recv_timeout(WAIT).unwrap();
    cancelled.store(true, Ordering::SeqCst);
    wake.lock()
        .unwrap()
        .take()
        .expect("pending operation's waker")
        .wake();
    worker.join().unwrap();
    gate.release.send(()).unwrap();
    drop(gate);
    assert!(!raw.exists::<_, bool>(receipt(&request)).unwrap());
    assert_eq!(read(&fast, &request, 0), ledger(INITIAL));
    assert_eq!(apply(&fast, &request).unwrap(), Decision::Applied);
}

#[test]
fn cross_slot_rejection_never_enters_multi_or_writes_a_receipt() {
    use super::conditional_records::{Mode, Proxy};
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let request = candidate(&fast);
    let proxy = Proxy::start(url, Mode::CrossSlot);
    let slow = ValkeyStore::connect(&proxy.url).unwrap();
    assert!(matches!(apply(&slow, &request), Err(OpRefused::Refused(_))));
    assert_eq!(proxy.multis.load(Ordering::SeqCst), 0);
    assert_eq!(proxy.execs.load(Ordering::SeqCst), 0);
    assert!(!raw.exists::<_, bool>(receipt(&request)).unwrap());
    assert_eq!(read(&fast, &request, 0), ledger(INITIAL));
}
