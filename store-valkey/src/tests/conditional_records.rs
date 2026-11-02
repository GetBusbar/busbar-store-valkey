// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! The negotiated primitive through real loaded doors; a RESP proxy controls the commit seam.
use super::super::{database, fresh_db_client, url_for_db};
use super::*;
use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request, VERSION,
};
use busbar_contract::store_calls::StoreCalls;
use redis::Commands;
use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn setup() -> Option<(database::Database, redis::Connection, ValkeyStore, String)> {
    let _ = live_store()?;

    let (database, raw) = fresh_db_client(6);
    let url = url_for_db(6);
    let store = ValkeyStore::connect(&url).unwrap();
    assert!(StoreCalls::supports_record_transaction(&store));
    Some((database, raw, store, url))
}
fn transact(store: &ValkeyStore, request: &Request) -> OpResult<Decision> {
    call(StoreCalls::record_transaction(store, request))
}
fn predicate(schema: &str, key: &[u8], expected: Expected) -> Predicate {
    Predicate {
        schema: schema.into(),
        key: key.to_vec(),
        expected,
    }
}
fn put(schema: &str, key: &[u8], value: &[u8]) -> Mutation {
    Mutation::Put {
        schema: schema.into(),
        key: key.to_vec(),
        value: value.to_vec(),
    }
}
fn candidate(schema: &str, key: &[u8], expected: Expected, value: &[u8]) -> Request {
    Request {
        version: VERSION,
        op_id: op(1),
        predicates: vec![predicate(schema, key, expected)],
        mutations: vec![put(schema, key, value)],
    }
}
fn physical(schema: &str) -> (String, String) {
    let prefix = format!("busbar:records:{}", crate::hex(schema.as_bytes()));
    (format!("{prefix}:k"), format!("{prefix}:v"))
}
fn receipt(request: &Request) -> String {
    format!("busbar:op:{}", crate::hex(&request.op_id.0))
}
fn read(store: &ValkeyStore, schema: &str, key: &[u8]) -> Option<Vec<u8>> {
    Slots::record_get(store, schema, key)
        .unwrap()
        .map(|value| value.as_slice().to_vec())
}

#[test]
fn two_loaded_clients_racing_absence_have_exactly_one_atomic_winner() {
    let Some((_database, mut raw, store, url)) = setup() else {
        return;
    };
    let schema = fresh("conditional-race");
    let requests = [
        candidate(&schema, b"owner", Expected::Absent, b"one"),
        candidate(&schema, b"owner", Expected::Absent, b"two"),
    ];

    let connections = [
        ValkeyStore::connect(&url).unwrap(),
        ValkeyStore::connect(&url).unwrap(),
    ];
    let answers = std::thread::scope(|scope| {
        let workers: Vec<_> = connections
            .into_iter()
            .zip(requests.clone())
            .map(|(connection, request)| {
                let (start, started) = mpsc::channel();
                let worker = scope.spawn(move || {
                    started.recv().expect("race worker started");
                    transact(&connection, &request)
                });
                (start, worker)
            })
            .collect();
        for (start, _) in &workers {
            start.send(()).unwrap();
        }
        workers
            .into_iter()
            .map(|(_, worker)| worker.join().unwrap().unwrap())
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
        if answer == Decision::Applied {
            assert_eq!(
                read(&store, &schema, b"owner"),
                match &request.mutations[0] {
                    Mutation::Put { value, .. } => Some(value.clone()),
                    _ => unreachable!(),
                }
            );
        }
    }
}

#[test]
fn exact_prestate_and_replay_keep_receipts_and_revision_semantics() {
    let Some((_database, mut raw, store, url)) = setup() else {
        return;
    };
    let schema = fresh("conditional-exact");
    let revision = (1u64 << 53) + 7;
    raw.set::<_, _, ()>(crate::REVISION_KEY, revision).unwrap();
    let original = [0, 255, 0, 128, 42];
    Slots::record_put(&store, &schema, b"\0binary\xff", &original).unwrap();
    let mut request = candidate(
        &schema,
        b"\0binary\xff",
        Expected::Bytes(original.to_vec()),
        &u64::MAX.to_le_bytes(),
    );
    request
        .predicates
        .push(predicate(&schema, b"absent", Expected::Absent));
    request.mutations.push(Mutation::Delete {
        schema: schema.clone(),
        key: b"absent".to_vec(),
    });
    assert_eq!(transact(&store, &request).unwrap(), Decision::Applied);
    assert_eq!(
        read(&store, &schema, b"\0binary\xff"),
        Some(u64::MAX.to_le_bytes().to_vec())
    );
    let body: Vec<u8> = raw.hget(receipt(&request), "b").unwrap();
    assert_eq!(body, request.fingerprint().to_vec());
    let ttl: i64 = raw.ttl(receipt(&request)).unwrap();
    assert!(ttl > 0 && ttl <= 86400);
    raw.expire::<_, ()>(receipt(&request), 600).unwrap();
    Slots::record_put(&store, &schema, b"\0binary\xff", b"later-writer").unwrap();
    let reopened = ValkeyStore::connect(&url).unwrap();
    assert_eq!(
        transact(&reopened, &request).unwrap(),
        Decision::Applied,
        "receipt precedes now-false predicates"
    );
    assert_eq!(
        read(&reopened, &schema, b"\0binary\xff"),
        Some(b"later-writer".to_vec())
    );
    assert!(
        raw.ttl::<_, i64>(receipt(&request)).unwrap() <= 600,
        "replay does not extend retention"
    );
    let mut changed = request.clone();
    changed.mutations[0] = put(&schema, b"\0binary\xff", b"changed");
    assert!(matches!(
        transact(&store, &changed),
        Err(OpRefused::Conflict)
    ));
    let mut conflict = request.clone();
    conflict.op_id = op(2);
    assert_eq!(
        transact(&store, &conflict).unwrap(),
        Decision::ConditionConflict
    );
    assert!(!raw.exists::<_, bool>(receipt(&conflict)).unwrap());
    let noop = candidate(
        &schema,
        b"\0binary\xff",
        Expected::Bytes(b"later-writer".to_vec()),
        b"later-writer",
    );
    assert_eq!(transact(&store, &noop).unwrap(), Decision::Applied);
    assert!(
        raw.exists::<_, bool>(receipt(&noop)).unwrap(),
        "an applied no-op still owns its replay receipt"
    );
    assert_eq!(raw.get::<_, u64>(crate::REVISION_KEY).unwrap(), revision);
}

#[test]
fn wrong_types_and_invalid_requests_never_partially_execute() {
    let Some((_database, mut raw, store, _)) = setup() else {
        return;
    };
    for target in 0..5 {
        let a = fresh("conditional-type-a");
        let b = fresh("conditional-type-b");
        let mut request = candidate(&a, b"guard", Expected::Absent, b"A");
        request.mutations.push(put(&b, b"second", b"B"));
        let (ak, av) = physical(&a);
        let (bk, bv) = physical(&b);
        let opkey = receipt(&request);
        let poisoned = [&ak, &av, &bk, &bv, &opkey][target];
        raw.set::<_, _, ()>(poisoned, "wrong-type").unwrap();
        assert!(matches!(
            transact(&store, &request),
            Err(OpRefused::Refused(_))
        ));
        for key in [&ak, &av, &bk, &bv, &opkey] {
            if key == poisoned {
                assert_eq!(raw.get::<_, String>(key).unwrap(), "wrong-type");
            } else {
                assert!(
                    !raw.exists::<_, bool>(key).unwrap(),
                    "no partial mutation at {key}"
                );
            }
        }
    }
    let schema = fresh("conditional-invalid");
    let base = candidate(&schema, b"guard", Expected::Absent, b"value");
    let mut requests = Vec::new();
    let mut invalid = base.clone();
    invalid.predicates.clear();
    requests.push(invalid);
    let mut invalid = base.clone();
    invalid.mutations.clear();
    requests.push(invalid);
    let mut invalid = base.clone();
    invalid.predicates.push(invalid.predicates[0].clone());
    requests.push(invalid);
    let mut invalid = base.clone();
    invalid.mutations.push(invalid.mutations[0].clone());
    requests.push(invalid);
    for request in requests {
        assert!(matches!(
            transact(&store, &request),
            Err(OpRefused::Refused(_))
        ));
        assert!(!raw.exists::<_, bool>(receipt(&request)).unwrap());
    }
    assert_eq!(read(&store, &schema, b"guard"), None);
}

#[derive(Clone, Copy)]
pub(super) enum Mode {
    HoldExec,
    HoldPredicate,
    DropExec,
    CrossSlot,
}
pub(super) struct Proxy {
    pub(super) url: String,
    held: Receiver<()>,
    release: Option<Sender<()>>,
    pub(super) execs: Arc<AtomicUsize>,
    pub(super) multis: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    stream: Arc<Mutex<Option<TcpStream>>>,
    worker: Option<std::thread::JoinHandle<()>>,
    /// Owned by the proxy so unwind releases its gate and socket before joining the operation.
    operation: Option<std::thread::JoinHandle<OpResult<Decision>>>,
}
fn encode(value: redis::Value, out: &mut Vec<u8>) {
    match value {
        redis::Value::Nil => out.extend_from_slice(b"$-1\r\n"),
        redis::Value::Okay => out.extend_from_slice(b"+OK\r\n"),
        redis::Value::SimpleString(text) => {
            out.extend_from_slice(format!("+{text}\r\n").as_bytes())
        }
        redis::Value::Int(n) => out.extend_from_slice(format!(":{n}\r\n").as_bytes()),
        redis::Value::BulkString(bytes) => {
            out.extend_from_slice(format!("${}\r\n", bytes.len()).as_bytes());
            out.extend_from_slice(&bytes);
            out.extend_from_slice(b"\r\n");
        }
        redis::Value::Array(values) => {
            out.extend_from_slice(format!("*{}\r\n", values.len()).as_bytes());
            for value in values {
                encode(value, out);
            }
        }
        _ => panic!("unexpected RESP2 response"),
    }
}
impl Proxy {
    pub(super) fn start(upstream: String, mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("redis://{}/6", listener.local_addr().unwrap());
        let (held_tx, held) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let execs = Arc::new(AtomicUsize::new(0));
        let count = execs.clone();
        let multis = Arc::new(AtomicUsize::new(0));
        let multi_count = multis.clone();
        let stream = Arc::new(Mutex::new(None));
        let retained = stream.clone();
        let worker = std::thread::spawn(move || {
            let mut client = loop {
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                match listener.accept() {
                    Ok((client, _)) => break client,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            drop(listener);
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            *retained.lock().unwrap() = Some(client.try_clone().unwrap());
            let mut server = redis::Client::open(upstream)
                .unwrap()
                .get_connection()
                .unwrap();
            let mut parser = redis::Parser::new();
            let mut held_once = false;
            while let Ok(command) = parser.parse_value(&mut client) {
                let fields: Vec<Vec<u8>> = redis::from_redis_value(command).unwrap();
                let name = std::str::from_utf8(&fields[0]).unwrap();
                if name == "WATCH" && matches!(mode, Mode::CrossSlot) {
                    client
                        .write_all(b"-CROSSSLOT Keys in request don't hash to the same slot\r\n")
                        .unwrap();
                    continue;
                }
                if name == "HGET"
                    && fields
                        .get(1)
                        .is_some_and(|key| key.starts_with(b"busbar:records:"))
                    && matches!(mode, Mode::HoldPredicate)
                    && !held_once
                {
                    held_once = true;
                    held_tx.send(()).unwrap();
                    let _ = released.recv_timeout(Duration::from_secs(10));
                }
                if name == "MULTI" {
                    multi_count.fetch_add(1, Ordering::SeqCst);
                }
                if name == "EXEC" {
                    count.fetch_add(1, Ordering::SeqCst);
                    if matches!(mode, Mode::HoldExec) && !held_once {
                        held_once = true;
                        held_tx.send(()).unwrap();
                        let _ = released.recv_timeout(Duration::from_secs(10));
                    }
                }
                let reply: redis::RedisResult<redis::Value> =
                    redis::cmd(name).arg(&fields[1..]).query(&mut server);
                if name == "EXEC" && matches!(mode, Mode::DropExec) {
                    assert!(
                        matches!(reply, Ok(redis::Value::Array(_))),
                        "EXEC must commit before reply loss"
                    );
                    let _ = client.shutdown(Shutdown::Both);
                    return;
                }
                let mut response = Vec::new();
                match reply {
                    Ok(value) => encode(value, &mut response),
                    Err(error) => response.extend_from_slice(format!("-{error}\r\n").as_bytes()),
                };
                if client.write_all(&response).is_err() {
                    return;
                }
            }
        });
        Self {
            url,
            held,
            release: Some(release),
            execs,
            multis,
            stop,
            stream,
            worker: Some(worker),
            operation: None,
        }
    }
    fn start_operation(&mut self, store: ValkeyStore, request: Request) {
        assert!(
            self.operation.is_none(),
            "one controlled operation per proxy"
        );
        self.operation = Some(std::thread::spawn(move || transact(&store, &request)));
    }

    fn finish_operation(&mut self) -> OpResult<Decision> {
        self.operation
            .take()
            .expect("operation started")
            .join()
            .unwrap()
    }

    fn resume(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.resume();
        self.stop.store(true, Ordering::SeqCst);
        if let Some(stream) = self
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let operation_panic = self.operation.take().and_then(|worker| worker.join().err());
        let proxy_panic = self.worker.take().and_then(|worker| worker.join().err());
        if !std::thread::panicking() {
            if let Some(error) = operation_panic.or(proxy_panic) {
                std::panic::resume_unwind(error);
            }
        }
    }
}

#[test]
fn ordinary_scan_sees_only_complete_prestate_or_complete_committed_batch() {
    let Some((_database, _raw, reader, url)) = setup() else {
        return;
    };
    let schema = fresh("conditional-read");
    for key in [b"a", b"b"] {
        Slots::record_put(&reader, &schema, key, b"old").unwrap();
    }
    let mut request = candidate(&schema, b"a", Expected::Bytes(b"old".to_vec()), b"new");
    request.mutations.push(put(&schema, b"b", b"new"));
    let mut proxy = Proxy::start(url, Mode::HoldExec);
    let writer = ValkeyStore::connect(&proxy.url).unwrap();
    proxy.start_operation(writer, request);
    proxy.held.recv_timeout(Duration::from_secs(5)).unwrap();
    let values = || {
        Slots::record_scan(&reader, &schema, b"", 10)
            .unwrap()
            .into_iter()
            .map(|(_, value)| value.as_slice().to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(values(), [b"old".to_vec(), b"old".to_vec()]);
    proxy.resume();
    assert_eq!(proxy.finish_operation().unwrap(), Decision::Applied);
    assert_eq!(values(), [b"new".to_vec(), b"new".to_vec()]);
}

#[test]
fn mutation_after_comparison_aborts_watch_and_never_acknowledges_the_stale_candidate() {
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let schema = fresh("conditional-abort");
    let request = candidate(&schema, b"guard", Expected::Absent, b"candidate");
    let expected = request.clone();
    let mut proxy = Proxy::start(url, Mode::HoldExec);
    let slow = ValkeyStore::connect(&proxy.url).unwrap();
    proxy.start_operation(slow, request);
    proxy.held.recv_timeout(Duration::from_secs(5)).unwrap();
    Slots::record_put(&fast, &schema, b"guard", b"winner").unwrap();
    proxy.resume();
    assert_eq!(
        proxy.finish_operation().unwrap(),
        Decision::ConditionConflict
    );
    assert_eq!(read(&fast, &schema, b"guard"), Some(b"winner".to_vec()));
    assert!(!raw.exists::<_, bool>(receipt(&expected)).unwrap());
    assert_eq!(
        proxy.execs.load(Ordering::SeqCst),
        2,
        "aborted write EXEC followed by read-only conflict validation"
    );
}

#[test]
fn wrong_type_installed_after_validation_aborts_before_any_mutation() {
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let a = fresh("conditional-type-race-a");
    let b = fresh("conditional-type-race-b");
    let mut request = candidate(&a, b"guard", Expected::Absent, b"A");
    request.mutations.push(put(&b, b"second", b"B"));
    let expected = request.clone();
    let mut proxy = Proxy::start(url, Mode::HoldExec);
    let slow = ValkeyStore::connect(&proxy.url).unwrap();
    proxy.start_operation(slow, request);
    proxy.held.recv_timeout(Duration::from_secs(5)).unwrap();
    raw.set::<_, _, ()>(physical(&b).0, "wrong-type").unwrap();
    proxy.resume();
    assert!(matches!(
        proxy.finish_operation(),
        Err(OpRefused::Refused(_))
    ));
    assert_eq!(read(&fast, &a, b"guard"), None);
    assert_eq!(read(&fast, &b, b"second"), None);
    assert!(!raw.exists::<_, bool>(receipt(&expected)).unwrap());
}

#[test]
fn lost_exec_reply_reconciles_only_the_same_id_and_body_after_reopen() {
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let schema = fresh("conditional-lost");
    let request = candidate(&schema, b"guard", Expected::Absent, b"committed");
    let proxy = Proxy::start(url.clone(), Mode::DropExec);
    let slow = ValkeyStore::connect(&proxy.url).unwrap();
    assert!(matches!(
        transact(&slow, &request),
        Err(OpRefused::Failed(_))
    ));
    assert_eq!(proxy.execs.load(Ordering::SeqCst), 1);
    assert_eq!(read(&fast, &schema, b"guard"), Some(b"committed".to_vec()));
    assert!(raw.exists::<_, bool>(receipt(&request)).unwrap());
    Slots::record_put(&fast, &schema, b"guard", b"later").unwrap();
    drop(slow);
    let reopened = ValkeyStore::connect(&url).unwrap();
    assert_eq!(transact(&reopened, &request).unwrap(), Decision::Applied);
    assert_eq!(read(&reopened, &schema, b"guard"), Some(b"later".to_vec()));
    let mut changed = request.clone();
    changed.mutations[0] = put(&schema, b"guard", b"different");
    assert!(matches!(
        transact(&reopened, &changed),
        Err(OpRefused::Conflict)
    ));
}

#[test]
fn cross_slot_watch_is_refused_before_multi_or_receipt() {
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let schema = fresh("conditional-cluster");
    let request = candidate(&schema, b"guard", Expected::Absent, b"value");
    let proxy = Proxy::start(url, Mode::CrossSlot);
    let store = ValkeyStore::connect(&proxy.url).unwrap();
    assert!(matches!(
        transact(&store, &request),
        Err(OpRefused::Refused(_))
    ));
    assert_eq!(proxy.execs.load(Ordering::SeqCst), 0);
    assert_eq!(proxy.multis.load(Ordering::SeqCst), 0);
    assert_eq!(read(&fast, &schema, b"guard"), None);
    assert!(!raw.exists::<_, bool>(receipt(&request)).unwrap());
}

#[test]
fn range_delete_uses_exact_schema_binary_prefix_and_exact_key_length() {
    let Some((_database, mut raw, store, _)) = setup() else {
        return;
    };
    let schema = fresh("conditional-range");
    let neighbor = format!("{schema}-other");
    for (target, key) in [
        (&schema, b"p\x00a".as_slice()),
        (&schema, b"p\x00b".as_slice()),
        (&schema, b"p\x00long".as_slice()),
        (&schema, b"q\x00a".as_slice()),
        (&neighbor, b"p\x00a".as_slice()),
    ] {
        Slots::record_put(&store, target, key, b"kept-before").unwrap();
    }
    let request = Request {
        version: VERSION,
        op_id: op(8),
        predicates: vec![predicate(
            &schema,
            b"p\x00a",
            Expected::Bytes(b"kept-before".to_vec()),
        )],
        mutations: vec![Mutation::DeleteRange {
            schema: schema.clone(),
            prefix: b"p\x00".to_vec(),
            exact_key_length: 3,
        }],
    };
    assert_eq!(transact(&store, &request).unwrap(), Decision::Applied);
    for key in [b"p\x00a", b"p\x00b"] {
        assert_eq!(read(&store, &schema, key), None);
    }
    for (target, key) in [
        (&schema, b"p\x00long".as_slice()),
        (&schema, b"q\x00a".as_slice()),
        (&neighbor, b"p\x00a".as_slice()),
    ] {
        assert_eq!(read(&store, target, key), Some(b"kept-before".to_vec()));
    }
    assert_eq!(raw.zcard::<_, usize>(physical(&schema).0).unwrap(), 2);
    assert_eq!(
        transact(&store, &request).unwrap(),
        Decision::Applied,
        "applied receipt wins over deleted predicate"
    );
    let mut changed = request.clone();
    changed.mutations[0] = Mutation::DeleteRange {
        schema: schema.clone(),
        prefix: b"p\x00".to_vec(),
        exact_key_length: 7,
    };
    assert!(matches!(
        transact(&store, &changed),
        Err(OpRefused::Conflict)
    ));
}

#[test]
fn range_delete_retries_the_same_candidate_when_a_matching_key_is_inserted_before_exec() {
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let schema = fresh("conditional-range-phantom");
    Slots::record_put(&fast, &schema, b"p1", b"old").unwrap();
    let request = Request {
        version: VERSION,
        op_id: op(9),
        predicates: vec![predicate(&schema, b"guard", Expected::Absent)],
        mutations: vec![Mutation::DeleteRange {
            schema: schema.clone(),
            prefix: b"p".to_vec(),
            exact_key_length: 2,
        }],
    };
    let expected = request.clone();
    let mut proxy = Proxy::start(url, Mode::HoldExec);
    let slow = ValkeyStore::connect(&proxy.url).unwrap();
    proxy.start_operation(slow, request);
    proxy.held.recv_timeout(Duration::from_secs(5)).unwrap();
    Slots::record_put(&fast, &schema, b"p2", b"phantom").unwrap();
    proxy.resume();
    assert_eq!(proxy.finish_operation().unwrap(), Decision::Applied);
    assert_eq!(
        proxy.execs.load(Ordering::SeqCst),
        2,
        "the first EXEC aborts and the same candidate re-enumerates"
    );
    assert_eq!(read(&fast, &schema, b"p1"), None);
    assert_eq!(read(&fast, &schema, b"p2"), None);
    assert_eq!(
        raw.hget::<_, _, Vec<u8>>(receipt(&expected), "b").unwrap(),
        expected.fingerprint().to_vec()
    );
}

#[test]
fn same_id_commit_between_receipt_and_predicate_read_is_applied_not_condition_conflict() {
    let Some((_database, mut raw, fast, url)) = setup() else {
        return;
    };
    let schema = fresh("conditional-same-id-race");
    let request = candidate(&schema, b"guard", Expected::Absent, b"committed");
    let slow_request = request.clone();
    let mut proxy = Proxy::start(url, Mode::HoldPredicate);
    let slow = ValkeyStore::connect(&proxy.url).unwrap();
    proxy.start_operation(slow, slow_request);
    proxy.held.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(transact(&fast, &request).unwrap(), Decision::Applied);
    Slots::record_put(&fast, &schema, b"guard", b"later-writer").unwrap();
    proxy.resume();
    assert_eq!(
        proxy.finish_operation().unwrap(),
        Decision::Applied,
        "receipt must win over a predicate made false by this same operation"
    );
    assert_eq!(
        read(&fast, &schema, b"guard"),
        Some(b"later-writer".to_vec())
    );
    assert_eq!(
        raw.hget::<_, _, Vec<u8>>(receipt(&request), "b").unwrap(),
        request.fingerprint().to_vec()
    );
    assert_eq!(
        proxy.execs.load(Ordering::SeqCst),
        1,
        "only the read-only snapshot check aborts"
    );
}
