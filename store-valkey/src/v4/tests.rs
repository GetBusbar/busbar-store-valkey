// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

struct Server {
    child: Child,
    path: PathBuf,
    conn: redis::Connection,
    port: u16,
}
impl Server {
    fn start() -> Self {
        let root = std::env::var_os("BUSBAR_V4_TEST_TMP")
            .expect("set BUSBAR_V4_TEST_TMP to a disposable task directory");
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = PathBuf::from(root).join(format!("server-{}", hex(&random)));
        std::fs::create_dir_all(&path).unwrap();
        let configuration = path.join("valkey.conf");
        std::fs::write(&configuration, b"enable-debug-command yes\n").unwrap();
        let socket = path.join("v.sock");
        let binary =
            std::env::var_os("BUSBAR_VALKEY_SERVER").unwrap_or_else(|| "valkey-server".into());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut child = Command::new(binary)
            .arg(&configuration)
            .args([
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--unixsocket",
            ])
            .arg(&socket)
            .arg("--dir")
            .arg(&path)
            .stdout(Stdio::from(
                std::fs::File::create(path.join("server.log")).unwrap(),
            ))
            .stderr(Stdio::from(
                std::fs::File::options()
                    .append(true)
                    .open(path.join("server.log"))
                    .unwrap(),
            ))
            .spawn()
            .expect("disposable Valkey server");
        let client = redis::Client::open(format!("redis+unix://{}", socket.display())).unwrap();
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let conn = loop {
            match client.get_connection() {
                Ok(c) => break c,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = std::fs::remove_dir_all(&path);
                    panic!("disposable server: {e}");
                }
            }
        };
        Self {
            child,
            path,
            conn,
            port,
        }
    }
    fn eval(&mut self, script: &str, args: &[Vec<u8>]) -> Vec<Vec<u8>> {
        redis::cmd("EVAL")
            .arg(format!("{COMMON}\n{script}"))
            .arg(1)
            .arg(META)
            .arg(args)
            .query(&mut self.conn)
            .unwrap()
    }
    fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        redis::cmd("GET").arg(key).query(&mut self.conn).unwrap()
    }
    fn set(&mut self, key: &str, value: &[u8]) {
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .query(&mut self.conn)
            .unwrap();
    }
    fn del(&mut self, key: &str) {
        let _: () = redis::cmd("DEL").arg(key).query(&mut self.conn).unwrap();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "failed native server evidence retained: {}",
                self.path.display()
            );
        } else {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
fn backend() -> OwnBackend {
    let value = OwnBackend::open(
        br#"{"url":"redis://127.0.0.1:1","input_budget":67108864,"durability":"ephemeral"}"#,
        &[],
        None,
    )
    .unwrap();
    value.0.info.set(value.0.proposed).unwrap();
    value
}
fn candidate(backend: &OwnBackend, op: u8, mutations: Vec<Mutation<Own>>) -> Candidate<Own> {
    Candidate {
        id: AttemptId {
            dataset: backend.info().dataset,
            writer: [2; 16],
            operation: [op; 16],
            writer_epoch: 1,
            execution_epoch: 1,
        },
        codec: p::CANDIDATE_VERSION,
        predicates: Vec::new(),
        mutations,
        time: None,
        result: Secret::held(vec![op]),
    }
}
fn prepare(c: Candidate<Own>) -> PreparedCandidate<Own> {
    PreparedCandidate::new(c).unwrap()
}
fn bootstrap(backend: &OwnBackend) -> PreparedCandidate<Own> {
    let addresses = [
        Address {
            namespace: control::NAMESPACE.0,
            key: control::DATASET_KEY.to_vec(),
        },
        Address {
            namespace: control::NAMESPACE.0,
            key: control::writer_key([2; 16]).to_vec(),
        },
    ];
    let values = [
        control::Dataset {
            id: backend.info().dataset,
            writer_epoch: 1,
        }
        .encode()
        .unwrap()
        .to_vec(),
        control::Writer {
            retired_through: 0,
            admitted_through: 1,
        }
        .encode()
        .unwrap()
        .to_vec(),
    ];
    let mut c = candidate(
        backend,
        1,
        addresses
            .iter()
            .zip(values)
            .map(|(address, value)| Mutation::Put {
                address: address.clone(),
                value: Secret::held(value),
            })
            .collect(),
    );
    c.predicates = addresses
        .into_iter()
        .map(|address| Predicate {
            address,
            expected: ExpectedValue::Absent,
        })
        .collect();
    c.result = Secret::held(Vec::new());
    prepare(c)
}
fn apply(server: &mut Server, backend: &OwnBackend, c: &PreparedCandidate<Own>) -> Vec<Vec<u8>> {
    server.eval(COMMIT, &backend.commit_args(c, backend.info()).unwrap())
}
fn at(key: &[u8]) -> Address {
    Address {
        namespace: [7; 16],
        key: key.to_vec(),
    }
}
fn put(key: &[u8], value: &[u8]) -> Mutation<Own> {
    Mutation::Put {
        address: at(key),
        value: Secret::held(value.to_vec()),
    }
}

#[test]
fn v4_settings_require_explicit_resource_and_durability_admission() {
    assert!(OwnBackend::validate(br#"{"url":"redis://localhost"}"#).is_err());
    assert!(OwnBackend::validate(
        br#"{"url":"redis://localhost","input_budget":16777216,"durability":"ephemeral"}"#
    )
    .is_ok());
    assert!(OwnBackend::validate(
        br#"{"url":"redis://localhost","input_budget":16777216,"durability":"quorum"}"#
    )
    .is_err());
    assert!(OwnBackend::validate(
        br#"{"url":"redis://localhost","input_budget":0,"durability":"local"}"#
    )
    .is_err());
}
#[test]
fn v4_physical_addresses_are_binary_injective_and_same_slot() {
    let info = backend().info();
    let base = prefix(info);
    assert!(base.contains(&format!("{{{}}}", hex(&info.dataset.0))));
    assert_ne!(
        record(&base, [1; 16], b"a:b"),
        record(&base, [2; 16], b"a:b")
    );
    assert!(record(&base, [1; 16], b"\0\xff").ends_with(":00ff"));
    assert_eq!(u64bytes(&u64::MAX.to_le_bytes()), Ok(u64::MAX));
    let mut invalid = &b"\x04\0\0\0ab"[..];
    assert_eq!(framed(&mut invalid), Err(Failure::Corrupt));
}

#[test]
#[ignore = "launches an isolated real Valkey; set BUSBAR_V4_TEST_TMP and BUSBAR_VALKEY_SERVER"]
fn v4_real_server_atomic_receipts_fences_ranges_scans_and_bootstrap() {
    let mut s = Server::start();
    let b = backend();
    let info = b.info();
    let base = prefix(info);
    // Legacy data, including an old schema marker, forbids initializing metadata.
    s.set("busbar:schema", b"9");
    assert_eq!(
        s.eval(CONNECT, &[persistent(info), base.as_bytes().to_vec()])[0],
        b"refused"
    );
    assert_eq!(s.get(META), None);
    s.del("busbar:schema");
    let first = s.eval(CONNECT, &[persistent(info), base.as_bytes().to_vec()]);
    assert_eq!(first[1], persistent(info));
    let different = backend().info();
    assert_eq!(
        s.eval(
            CONNECT,
            &[persistent(different), prefix(different).into_bytes()]
        )[1],
        persistent(info)
    );
    let initial = bootstrap(&b);
    let saved = apply(&mut s, &b, &initial);
    assert_eq!(saved[0], b"applied");
    let nsgen = record(&base, control::GENERATION_NAMESPACE.0, &[7; 16]);
    let c = prepare(candidate(
        &b,
        3,
        vec![
            put(b"a\0", b"secret"),
            put(b"a\xff", b""),
            put(b"abc", b"other"),
        ],
    ));
    let answer = apply(&mut s, &b, &c);
    assert_eq!(answer[0], b"applied");
    assert_eq!(
        s.get(&record(&base, [7; 16], b"a\0")),
        Some(b"\x01secret".to_vec())
    );
    assert_eq!(
        s.get(&nsgen),
        Some([vec![1], 1_u64.to_le_bytes().to_vec()].concat())
    );
    // Exact replay returns the original observation and never advances generation.
    assert_eq!(apply(&mut s, &b, &c), answer);
    let conflicting = prepare(candidate(&b, 3, vec![put(b"x", b"different")]));
    assert_eq!(apply(&mut s, &b, &conflicting)[0], b"opconflict");
    let scanargs = vec![
        persistent(info),
        base.as_bytes().to_vec(),
        nsgen.as_bytes().to_vec(),
        Vec::new(),
        b"0".to_vec(),
        Vec::new(),
        b"1".to_vec(),
        b"100".to_vec(),
        record_prefix(&base, [7; 16]).into_bytes(),
        hex(b"a").into_bytes(),
        b"0".to_vec(),
    ];
    let page = s.eval(SCAN, &scanargs);
    assert_eq!(page[0], b"page");
    assert_eq!(page[3], b"a\0");
    assert_eq!(page[4], b"1");
    let mut next = scanargs.clone();
    next[3] = page[1].clone();
    next[5] = hex(&page[3]).into_bytes();
    next[10] = b"1".to_vec();
    let second = s.eval(SCAN, &next);
    assert_eq!(second[3], b"abc");
    let mut fail = candidate(&b, 4, vec![put(b"z", b"must not publish")]);
    fail.predicates.push(Predicate {
        address: at(b"a\0"),
        expected: ExpectedValue::Exact(Secret::held(b"wrong".to_vec())),
    });
    assert_eq!(apply(&mut s, &b, &prepare(fail))[0], b"condition");
    assert_eq!(s.get(&record(&base, [7; 16], b"z")), None);
    let mut timed = candidate(&b, 5, vec![put(b"time", b"no")]);
    timed.time = Some(TimeGuard {
        not_before: None,
        before: Some(1),
    });
    assert_eq!(apply(&mut s, &b, &prepare(timed))[0], b"time");
    // Range matching uses exact raw length, is atomic, and scrubs the old secret at the same address.
    let deleted = prepare(candidate(
        &b,
        6,
        vec![Mutation::DeleteRange {
            namespace: NamespaceId([7; 16]),
            prefix: b"a".to_vec(),
            exact_key_length: 2,
        }],
    ));
    assert_eq!(apply(&mut s, &b, &deleted)[0], b"applied");
    assert_eq!(s.get(&record(&base, [7; 16], b"a\0")), Some(vec![0]));
    assert_eq!(
        s.get(&record(&base, [7; 16], b"abc")),
        Some(b"\x01other".to_vec())
    );
    assert_eq!(s.eval(SCAN, &next)[0], b"stale");
    // Generation arithmetic preserves all u64 bits and refuses overflow before effects.
    s.set(
        &nsgen,
        &[vec![1], (u64::MAX - 1).to_le_bytes().to_vec()].concat(),
    );
    assert_eq!(
        apply(
            &mut s,
            &b,
            &prepare(candidate(&b, 7, vec![put(b"max", b"yes")]))
        )[0],
        b"applied"
    );
    assert_eq!(
        s.get(&nsgen),
        Some([vec![1], u64::MAX.to_le_bytes().to_vec()].concat())
    );
    assert_eq!(
        apply(
            &mut s,
            &b,
            &prepare(candidate(&b, 8, vec![put(b"overflow", b"no")]))
        )[0],
        b"refused"
    );
    assert_eq!(s.get(&record(&base, [7; 16], b"overflow")), None);
    // Stored malformed authority never degrades into a missing grant.
    let writer = record(&base, control::NAMESPACE.0, &control::writer_key([2; 16]));
    s.set(&writer, b"\x01bad");
    assert_eq!(
        apply(
            &mut s,
            &b,
            &prepare(candidate(&b, 9, vec![put(b"bad", b"no")]))
        )[0],
        b"corrupt"
    );
    let closed = control::Writer {
        retired_through: 1,
        admitted_through: 1,
    }
    .encode()
    .unwrap();
    s.set(&writer, &[vec![1], closed.to_vec()].concat());
    assert_eq!(apply(&mut s, &b, &c), answer); // replay precedes retirement
    assert_eq!(
        apply(
            &mut s,
            &b,
            &prepare(candidate(&b, 9, vec![put(b"closed", b"no")]))
        )[0],
        b"expired"
    );
    s.del(&record(&base, control::NAMESPACE.0, control::DATASET_KEY));
    let reinit = bootstrap(&b);
    let mut args = b.commit_args(&reinit, info).unwrap();
    args[3] = format!("{base}o:new:root").into_bytes();
    assert_eq!(s.eval(COMMIT, &args)[0], b"expired");
}

#[test]
#[ignore = "launches an isolated real Valkey; set BUSBAR_V4_TEST_TMP and BUSBAR_VALKEY_SERVER"]
fn v4_real_server_decodes_exact_control_formats_and_collects_only_closed_receipts() {
    let mut s = Server::start();
    let b = backend();
    let info = b.info();
    let base = prefix(info);
    s.eval(CONNECT, &[persistent(info), base.as_bytes().to_vec()]);
    let dataset = control::Dataset {
        id: info.dataset,
        writer_epoch: u64::MAX,
    }
    .encode()
    .unwrap();
    let writer = control::Writer {
        retired_through: u64::MAX - 1,
        admitted_through: u64::MAX,
    }
    .encode()
    .unwrap();
    let check =
        "return {(dataset(ARGV[1],ARGV[2]) and 'yes' or 'no'),(writer(ARGV[3]) and 'yes' or 'no')}";
    assert_eq!(
        s.eval(
            check,
            &[dataset.to_vec(), info.dataset.0.to_vec(), writer.to_vec()]
        ),
        vec![b"yes".to_vec(), b"yes".to_vec()]
    );
    for length in 0..32 {
        assert_eq!(
            s.eval(
                check,
                &[
                    dataset[..length].to_vec(),
                    info.dataset.0.to_vec(),
                    writer[..length.min(23)].to_vec()
                ]
            ),
            vec![b"no".to_vec(), b"no".to_vec()]
        );
    }
    for index in 4..8 {
        let mut bad = dataset;
        bad[index] = 1;
        let mut badwriter = writer;
        badwriter[index] = 1;
        assert_eq!(
            s.eval(
                check,
                &[bad.to_vec(), info.dataset.0.to_vec(), badwriter.to_vec()]
            ),
            vec![b"no".to_vec(), b"no".to_vec()]
        );
    }
    let high = 9007199254740993_u64.to_le_bytes();
    let low = 9007199254740992_u64.to_le_bytes();
    assert_eq!(
        s.eval(
            "return {tostring(cmp(ARGV[1],ARGV[2])),inc(ARGV[2]),dec64('18446744073709551615')}",
            &[high.to_vec(), low.to_vec()]
        ),
        vec![
            b"1".to_vec(),
            high.to_vec(),
            u64::MAX.to_le_bytes().to_vec()
        ]
    );
    assert_eq!(apply(&mut s, &b, &bootstrap(&b))[0], b"applied");
    let root = record(&base, control::NAMESPACE.0, control::DATASET_KEY);
    let writerkey = record(&base, control::NAMESPACE.0, &control::writer_key([2; 16]));
    let w = control::Writer {
        retired_through: 1,
        admitted_through: 2,
    }
    .encode()
    .unwrap();
    s.set(&writerkey, &[vec![1], w.to_vec()].concat());
    let original = prepare(candidate(&b, 30, vec![put(b"old", b"no")]));
    assert_eq!(apply(&mut s, &b, &original)[0], b"expired");
    // Bootstrap receipt at epoch 1 is collectible; an active epoch 2 receipt is retained.
    let mut c = candidate(&b, 31, vec![put(b"active", b"yes")]);
    c.id.execution_epoch = 2;
    assert_eq!(apply(&mut s, &b, &prepare(c))[0], b"applied");
    let oldreceipt = format!("{base}o:{}:{}", hex(&[2; 16]), hex(&[1; 16]));
    let active = format!("{base}o:{}:{}", hex(&[2; 16]), hex(&[31; 16]));
    let args = vec![
        persistent(info),
        writerkey.as_bytes().to_vec(),
        1_u64.to_le_bytes().to_vec(),
        format!("{base}o:{}:", hex(&[2; 16])).into_bytes(),
    ];
    assert_eq!(s.eval(GC, &args)[0], b"ok");
    assert_eq!(s.get(&oldreceipt), None);
    assert!(s.get(&active).is_some());
    // Replay after receipt collection remains fenced; missing root never reinitializes.
    assert_eq!(apply(&mut s, &b, &bootstrap(&b))[0], b"expired");
    s.del(&root);
    assert_eq!(apply(&mut s, &b, &original)[0], b"expired");
}

use crate::tests::valkey_io;

#[test]
#[ignore = "launches an isolated real Valkey; set BUSBAR_V4_TEST_TMP and BUSBAR_VALKEY_SERVER"]
fn v4_real_server_door_uses_host_connections_and_returns_persistent_metadata() {
    use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};
    let mut server = Server::start();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let dispatcher=Arc::new(Dispatcher::new(DispatchConfig::default()));
        let conns=valkey_io::host(dispatcher.conn_waker(),busbar_contract::transport::EgressTrust::default());
        let open=||{
            let row=LinkedRow::of_kind::<StoreV4>(super::door as busbar_contract::abi::mechanism::door::DoorFn).unwrap();
            load_linked::<StoreV4>(&row,Bind{instance:Arc::from("valkey-v4-disposable"),max_inflight_cap:64,sink:Arc::new(NoSink),dispatcher:dispatcher.adopter(),conns:ConnTable::Host(conns.clone())}).unwrap()
        };
        let bytes=serde_json::to_vec(&serde_json::json!({"url":format!("redis://127.0.0.1:{}",server.port),"input_budget":67108864,"durability":"ephemeral"})).unwrap();
        let limits=||Limits{descriptor_bytes:1<<20,output_items:1<<20,output_bytes:1<<24,decode_bytes:1<<25};
        let local_bytes=serde_json::to_vec(&serde_json::json!({"url":format!("redis://127.0.0.1:{}",server.port),"input_budget":67108864,"durability":"local"})).unwrap();
        assert!(LoadedPersistence::open(open(),dispatcher.clone(),&local_bytes,limits()).await.is_err());
        assert_eq!(server.get(META),None); // Failed durability admission writes nothing.
        let store=LoadedPersistence::open(open(),dispatcher.clone(),&bytes,limits()).await.unwrap();
        let info=store.info();let clock=store.clock(info.dataset).await.unwrap();assert_eq!(clock.authority,info.clock_authority);
        let again=LoadedPersistence::open(open(),dispatcher.clone(),&bytes,limits()).await.unwrap();assert_eq!(again.info(),info);
        let addresses=[Address{namespace:control::NAMESPACE.0,key:control::DATASET_KEY.to_vec()},Address{namespace:control::NAMESPACE.0,key:control::writer_key([2;16]).to_vec()}];
        let values=[control::Dataset{id:info.dataset,writer_epoch:1}.encode().unwrap().to_vec(),control::Writer{retired_through:0,admitted_through:1}.encode().unwrap().to_vec()];
        let id=AttemptId{dataset:info.dataset,writer:[2;16],operation:[1;16],writer_epoch:1,execution_epoch:1};
        let initial=p::Candidate{id,codec:p::CANDIDATE_VERSION,predicates:addresses.iter().map(|a|Predicate{address:a.clone(),expected:ExpectedValue::Absent}).collect(),mutations:addresses.into_iter().zip(values).map(|(address,value)|Mutation::Put{address,value:Secret::new(value)}).collect(),time:None,result:Secret::new(Vec::new())};
        assert!(matches!(store.commit(PreparedCandidate::new(initial).unwrap()).await.unwrap(),Decision::Applied(_)));
        let c=p::Candidate{id:AttemptId{operation:[3;16],..id},codec:p::CANDIDATE_VERSION,predicates:Vec::new(),mutations:vec![Mutation::Put{address:at(b"host"),value:Secret::new(b"through connector".to_vec())}],time:None,result:Secret::new(b"result".to_vec())};
        let c=PreparedCandidate::new(c).unwrap();
        assert!(matches!(store.commit(c.clone()).await.unwrap(),Decision::Applied(_)));
        assert!(matches!(store.commit(c).await.unwrap(),Decision::Applied(_)));
        let read=store.read(Arc::new(p::Read{dataset:info.dataset,addresses:vec![at(b"host"),at(b"absent")],time:None})).await.unwrap();
        assert!(matches!(read,ReadResult::Values{values,..} if values.len()==2 && values[0].is_some() && values[1].is_none()));
        let scan=store.scan(Arc::new(p::Scan{dataset:info.dataset,namespace:NamespaceId([7;16]),prefix:Vec::new(),after:None,generation:None,allow_change:false,max_items:10,max_bytes:1024})).await.unwrap();
        assert_eq!(scan.rows.len(),1);assert_eq!(scan.rows[0].0.key,b"host");assert_eq!(scan.generation,1);assert!(scan.next.is_none());
        assert_eq!(server.get(&record(&prefix(info),[7;16],b"host")),Some(b"\x01through connector".to_vec()));
        let timed=store.read(Arc::new(p::Read{dataset:info.dataset,addresses:Vec::new(),time:Some(TimeGuard{not_before:None,before:Some(1)})})).await.unwrap();
        assert!(matches!(timed,ReadResult::TimeGuardFailed{..}));
        for (key,value) in [("appendfsync","always"),("no-appendfsync-on-rewrite","no"),("appendonly","yes")] {
            let _:()=redis::cmd("CONFIG").arg("SET").arg(key).arg(value).query(&mut server.conn).unwrap();
        }
        let local=LoadedPersistence::open(open(),dispatcher.clone(),&local_bytes,limits()).await.unwrap();
        assert_eq!(local.info().durability,Durability::Local);
        assert_eq!(local.info().dataset,info.dataset);

    });
}

#[test]
#[ignore = "large admitted-range witness; isolated Valkey and explicit task tmp required"]
fn v4_real_server_legacy_ceiling_range_uses_one_native_mset() {
    let mut s = Server::start();
    let b = backend();
    let info = b.info();
    let base = prefix(info);
    s.eval(CONNECT, &[persistent(info), base.as_bytes().to_vec()]);
    assert_eq!(apply(&mut s, &b, &bootstrap(&b))[0], b"applied");
    // The exact legacy 16-MiB transaction admits 838856 four-byte deletion keys.
    // Exercise this implementation's entire discovery/validation/publication path,
    // including generation and receipt metadata, without a new cardinality cap.
    const COUNT: u32 = 838856;
    for first in (0..COUNT).step_by(10000) {
        let mut batch = redis::pipe();
        for key in first..(first + 10000).min(COUNT) {
            batch
                .cmd("SET")
                .arg(record(&base, [7; 16], &key.to_be_bytes()))
                .arg(b"\x01old secret")
                .ignore();
        }
        let _: () = batch.query(&mut s.conn).unwrap();
    }
    let c = prepare(candidate(
        &b,
        40,
        vec![Mutation::DeleteRange {
            namespace: NamespaceId([7; 16]),
            prefix: Vec::new(),
            exact_key_length: 4,
        }],
    ));
    let applied = apply(&mut s, &b, &c);
    assert_eq!(applied[0], b"applied");
    assert_eq!(
        s.get(&record(&base, [7; 16], &0_u32.to_be_bytes())),
        Some(vec![0])
    );
    assert_eq!(
        s.get(&record(&base, [7; 16], &(COUNT - 1).to_be_bytes())),
        Some(vec![0])
    );
    assert_eq!(apply(&mut s, &b, &c), applied);
    assert_eq!(
        s.get(&record(&base, control::GENERATION_NAMESPACE.0, &[7; 16])),
        Some([vec![1], 1_u64.to_le_bytes().to_vec()].concat())
    );
}

#[test]
#[ignore = "launches an isolated real Valkey; set BUSBAR_V4_TEST_TMP and BUSBAR_VALKEY_SERVER"]
fn v4_real_server_lost_reply_replays_after_expiry_and_preparation_error_publishes_nothing() {
    let mut s = Server::start();
    let b = backend();
    let info = b.info();
    let base = prefix(info);
    s.eval(CONNECT, &[persistent(info), base.as_bytes().to_vec()]);
    apply(&mut s, &b, &bootstrap(&b));
    let (seconds, _): (u64, u64) = redis::cmd("TIME").query(&mut s.conn).unwrap();
    let mut c = candidate(&b, 50, vec![put(b"lost reply", b"once")]);
    c.time = Some(TimeGuard {
        not_before: None,
        before: Some(seconds + 2),
    });
    let c = prepare(c);
    let args = b.commit_args(&c, info).unwrap();
    let mut command = redis::cmd("EVAL");
    command
        .arg(format!("{COMMON}\n{COMMIT}"))
        .arg(1)
        .arg(META)
        .arg(&*args);
    let client = redis::Client::open(format!("redis://127.0.0.1:{}", s.port)).unwrap();
    let mut dropped = client.get_connection().unwrap();
    dropped
        .send_packed_command(&command.get_packed_command())
        .unwrap();
    drop(dropped); // The caller has relinquished its reply; no rollback is inferred.
    let receipt = String::from_utf8(args[3].clone()).unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(1);
    let original = loop {
        if let Some(r) = s.get(&receipt) {
            break r;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    loop {
        let (now, _): (u64, u64) = redis::cmd("TIME").query(&mut s.conn).unwrap();
        if now >= seconds + 2 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let replay = apply(&mut s, &b, &c);
    assert_eq!(replay[0], b"applied");
    assert_eq!(replay[1], original[44..52]);
    assert_eq!(replay[2], b"2");
    assert_eq!(
        s.get(&record(&base, control::GENERATION_NAMESPACE.0, &[7; 16])),
        Some([vec![1], 1_u64.to_le_bytes().to_vec()].concat())
    );
    let bad = record(&base, [7; 16], b"wrong type");
    let _: () = redis::cmd("LPUSH")
        .arg(&bad)
        .arg("list")
        .query(&mut s.conn)
        .unwrap();
    let request = prepare(candidate(
        &b,
        51,
        vec![
            put(b"first prepared", b"never"),
            put(b"wrong type", b"never"),
        ],
    ));
    let args = b.commit_args(&request, info).unwrap();
    let refused: redis::RedisResult<redis::Value> = redis::cmd("EVAL")
        .arg(format!("{COMMON}\n{COMMIT}"))
        .arg(1)
        .arg(META)
        .arg(&*args)
        .query(&mut s.conn);
    assert!(refused.unwrap_err().to_string().contains("V4_CORRUPT"));
    assert_eq!(s.get(&record(&base, [7; 16], b"first prepared")), None);
    assert_eq!(s.get(std::str::from_utf8(&args[3]).unwrap()), None);
}

#[test]
#[ignore = "launches an isolated real Valkey; set BUSBAR_V4_TEST_TMP and BUSBAR_VALKEY_SERVER"]
fn v4_real_server_control_changes_require_predicates_and_monotonic_fences() {
    let mut s = Server::start();
    let b = backend();
    let info = b.info();
    let base = prefix(info);
    s.eval(CONNECT, &[persistent(info), base.as_bytes().to_vec()]);
    apply(&mut s, &b, &bootstrap(&b));
    let target = Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key([4; 16]).to_vec(),
    };
    let initial = control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
    .encode()
    .unwrap();
    let change = |op: u8, old: Option<&[u8]>, next: &[u8]| {
        let mut c = candidate(
            &b,
            op,
            vec![Mutation::Put {
                address: target.clone(),
                value: Secret::held(next.to_vec()),
            }],
        );
        c.predicates.push(Predicate {
            address: target.clone(),
            expected: match old {
                Some(v) => ExpectedValue::Exact(Secret::held(v.to_vec())),
                None => ExpectedValue::Absent,
            },
        });
        prepare(c)
    };
    let unguarded = prepare(candidate(
        &b,
        60,
        vec![Mutation::Put {
            address: target.clone(),
            value: Secret::held(initial.to_vec()),
        }],
    ));
    assert_eq!(apply(&mut s, &b, &unguarded)[0], b"refused");
    assert_eq!(
        apply(&mut s, &b, &change(61, None, &initial))[0],
        b"applied"
    );
    let high = control::Writer {
        retired_through: 9007199254740993,
        admitted_through: u64::MAX,
    }
    .encode()
    .unwrap();
    assert_eq!(
        apply(&mut s, &b, &change(62, Some(&initial), &high))[0],
        b"applied"
    );
    let backwards = control::Writer {
        retired_through: 9007199254740992,
        admitted_through: u64::MAX,
    }
    .encode()
    .unwrap();
    assert_eq!(
        apply(&mut s, &b, &change(63, Some(&high), &backwards))[0],
        b"refused"
    );
    assert_eq!(
        apply(&mut s, &b, &change(64, Some(&high), b"bad"))[0],
        b"refused"
    );
    for (op, mutation) in [
        (65, Mutation::Delete(target.clone())),
        (
            66,
            Mutation::DeleteRange {
                namespace: control::NAMESPACE,
                prefix: Vec::new(),
                exact_key_length: 17,
            },
        ),
        (
            67,
            Mutation::Put {
                address: Address {
                    namespace: control::GENERATION_NAMESPACE.0,
                    key: [7; 16].to_vec(),
                },
                value: Secret::held(1_u64.to_le_bytes().to_vec()),
            },
        ),
    ] {
        assert_eq!(
            apply(&mut s, &b, &prepare(candidate(&b, op, vec![mutation])))[0],
            b"refused"
        );
    }
    assert_eq!(
        s.get(&record(&base, control::NAMESPACE.0, &target.key)),
        Some([vec![1], high.to_vec()].concat())
    );
}

#[test]
#[ignore = "isolated native automatic bootstrap; explicit task tmp/server required"]
fn native_bootstrap_scoped_account_captures_pages_and_denies_old_reconnect() {
    native_bootstrap_lifecycle(false, false);
}

#[test]
#[ignore = "isolated native crash-resume lifecycle; explicit task tmp/server required"]
fn native_bootstrap_crash_resume_retains_snapshot_target_and_activation() {
    native_bootstrap_lifecycle(true, false);
}

#[test]
#[ignore = "isolated native source larger than live allocation budget; explicit task tmp/server required"]
fn native_bootstrap_source_larger_than_live_budget() {
    native_bootstrap_lifecycle(false, true);
}

fn native_bootstrap_lifecycle(resume: bool, large: bool) {
    use busbar_contract::persistence::lifecycle::{self as l, PreparedStore};
    let mut server = Server::start();
    server.set("busbar:schema", b"9");
    server.set("busbar:key:binary", &[0, 255, b'x']);
    if large {
        let _: () = redis::cmd("CONFIG")
            .arg("SET")
            .arg("rdbcompression")
            .arg("no")
            .query(&mut server.conn)
            .unwrap();
        for index in 0..2048 {
            server.set(
                &format!("busbar:key:large:{index}"),
                &vec![((index % 251) + 1) as u8; 4096],
            );
        }
    }
    let _: () = redis::cmd("HSET")
        .arg("busbar:meter:binary")
        .arg(&[0, 255])
        .arg(&[255, 0])
        .query(&mut server.conn)
        .unwrap();
    let _: () = redis::cmd("ACL")
        .arg("SETUSER")
        .arg("busbar")
        .arg("on")
        .arg(">fixture")
        .arg("~busbar:*")
        .arg("+@all")
        .query(&mut server.conn)
        .unwrap();
    let _: () = redis::cmd("ACL")
        .arg("SETUSER")
        .arg("default")
        .arg("off")
        .query(&mut server.conn)
        .unwrap();
    let admin: u64 = redis::cmd("CLIENT")
        .arg("ID")
        .query(&mut server.conn)
        .unwrap();
    let _: redis::RedisResult<()> = redis::cmd("CLIENT")
        .arg("KILL")
        .arg("ID")
        .arg(admin)
        .arg("SKIPME")
        .arg("no")
        .query(&mut server.conn);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let budget=if large{2*1024*1024}else{64*1024*1024};
        let make_prepared=|| native_prepared(&format!("redis://busbar:fixture@127.0.0.1:{}",server.port),budget);
        let mut prepared=make_prepared();
        let response=prepared.bootstrap(Arc::new(l::Request::Inspect{bounds:l::Bounds{items:1024,bytes:1<<20}})).await.unwrap();
        let l::Response::Inspected(inspected)=response.as_ref() else{panic!("inspection response")};
        assert_eq!(inspected.state,l::InspectionState::Legacy);
        assert!(inspected.capabilities.contains(&l::NativeCapability::PersistentFence));
        let response=prepared.bootstrap(Arc::new(l::Request::BeginOrResume{expected_source:inspected.source.clone().unwrap(),
            route_digest:[7;32],target_format:l::CORE_FORMAT,operation_id:[8;16]})).await.unwrap_or_else(|error|panic!("native Begin failed: {error:?}; forged={},latched={}",busbar_plugin_loader::dispatch::handle::forged(),busbar_plugin_loader::dispatch::handle::latched()));
        let l::Response::Begun(upgrade)=response.as_ref() else{panic!("begin response")};
        assert_eq!(upgrade.catalogue.len(),1);
        let mut upgrade=copy_native_upgrade(upgrade);
        drop(response);
        if resume {
            drop(prepared);
            prepared=make_prepared();
            let response=prepared.bootstrap(Arc::new(l::Request::Inspect{bounds:l::Bounds{items:1024,bytes:1<<20}})).await.unwrap();
            let l::Response::Inspected(inspection)=response.as_ref() else{panic!("resumed inspection")};
            assert_eq!(inspection.state,l::InspectionState::InProgress);
            let response=prepared.bootstrap(Arc::new(l::Request::BeginOrResume{expected_source:inspection.source.clone().unwrap(),route_digest:[7;32],target_format:l::CORE_FORMAT,operation_id:[8;16]})).await.unwrap_or_else(|error|panic!("native Begin failed: {error:?}; forged={},latched={}",busbar_plugin_loader::dispatch::handle::forged(),busbar_plugin_loader::dispatch::handle::latched()));
            let l::Response::Begun(resumed)=response.as_ref() else{panic!("resumed upgrade")};
            assert_eq!(resumed.snapshot,upgrade.snapshot);
            assert_eq!(resumed.reference.id,upgrade.reference.id);
            assert_eq!(resumed.target,upgrade.target);
            upgrade=copy_native_upgrade(resumed);
        }
        assert_eq!(prepared.phase(),l::Phase::Upgrading);
        let expected=busbar_contract::persistence::legacy_row::encode::<Own>(&[
            busbar_contract::persistence::legacy_row::Cell::Integer(0),busbar_contract::persistence::legacy_row::Cell::Integer(1),busbar_contract::persistence::legacy_row::Cell::Integer(-1),
            busbar_contract::persistence::legacy_row::Cell::Blob(b"busbar:key:binary"),busbar_contract::persistence::legacy_row::Cell::Blob(b""),busbar_contract::persistence::legacy_row::Cell::Blob(&[0,255,b'x'])],4096).unwrap();
        let expected=Secret::new(expected.expose_own(&Own::here()).clone());
        let mut cursor=None;let mut binary=false;let mut rows=0;
        loop {
            let page=prepared.bootstrap(Arc::new(l::Request::SourcePage{upgrade:upgrade.reference.clone(),snapshot:upgrade.snapshot,
                family:[1;16],selector:l::SourceSelector::Scan{table:0},cursor,bounds:if large{l::Bounds{items:16,bytes:131072}}else{l::Bounds{items:2,bytes:4096}}})).await.unwrap();
            let l::Response::SourcePage(page)=page.as_ref() else{panic!("page response")};
            rows+=page.rows.len();
            for row in &page.rows{
                binary|=row.value==expected;
            }
            cursor=page.next.clone();if cursor.is_none(){break};
        }
        assert!(binary);assert!(rows>=6);
        let client=redis::Client::open(format!("redis://busbar:fixture@127.0.0.1:{}",server.port)).unwrap();
        let mut old=client.get_connection().unwrap();
        if large {
            let raw:Vec<u8>=redis::cmd("GET").arg("busbar:v4:bootstrap").query(&mut old).unwrap();
            let control:serde_json::Value=serde_json::from_slice(&raw).unwrap();
            assert!(control["length"].as_u64().unwrap()>budget as u64);
            assert!(rows>=2054);
        }
        assert!(redis::cmd("SET").arg("busbar:key:old").arg("must fail").query::<()>(&mut old).is_err());
        assert_eq!(redis::cmd("GET").arg("busbar:key:binary").query::<Vec<u8>>(&mut old).unwrap(),[0,255,b'x']);
        drop(old);
        let target=prepared.target(upgrade.reference.clone()).await.unwrap();
        assert_eq!(target.info(),upgrade.target);
        assert!(prepared.bootstrap(Arc::new(l::Request::CheckFence{upgrade:upgrade.reference.clone()})).await.is_ok());
        let info=target.info();
        let root=Address{namespace:control::NAMESPACE.0,key:control::DATASET_KEY.to_vec()};
        let writer=Address{namespace:control::NAMESPACE.0,key:control::writer_key([2;16]).to_vec()};
        let initial=PreparedCandidate::new(Candidate{
            id:AttemptId{dataset:info.dataset,writer_epoch:1,writer:[2;16],execution_epoch:1,operation:[1;16]},codec:p::CANDIDATE_VERSION,
            predicates:vec![Predicate{address:root.clone(),expected:ExpectedValue::Absent},Predicate{address:writer.clone(),expected:ExpectedValue::Absent}],
            mutations:vec![Mutation::Put{address:root,value:Secret::new(control::Dataset{id:info.dataset,writer_epoch:1}.encode().unwrap().to_vec())},
                Mutation::Put{address:writer,value:Secret::new(control::Writer{retired_through:0,admitted_through:1}.encode().unwrap().to_vec())}],
            time:None,result:Secret::new(Vec::new()),
        }).unwrap();
        let initial_result=target.commit(initial).await.unwrap();
        assert!(matches!(initial_result,Decision::Applied(_)),"native initialization decision: {initial_result:?}");
        let activation=native_checkpoint(target.as_ref(),2,b"activated",l::CompletionPhase::Activation).await;
        let finished=prepared.bootstrap(Arc::new(l::Request::Finish{upgrade:upgrade.reference.clone(),activation_receipt:activation.clone()})).await.unwrap();
        let l::Response::RecoveryReady(recovery)=finished.as_ref() else{panic!("recovery-only native selection")};
        let recovery=recovery.clone();
        drop(finished);
        assert!(prepared.serving().is_err());
        if resume {
            // An activation reply can be lost with the process. Reclaim native
            // custody, resolve the same activation receipt, then OPEN once.
            drop(target);
            drop(prepared);
            prepared=make_prepared();
            let response=prepared.bootstrap(Arc::new(l::Request::Inspect{bounds:l::Bounds{items:1024,bytes:1<<20}})).await.unwrap();
            let l::Response::Inspected(inspection)=response.as_ref() else{panic!("activation-resume inspection")};
            assert_eq!(inspection.state,l::InspectionState::InProgress);
            let response=prepared.bootstrap(Arc::new(l::Request::BeginOrResume{expected_source:inspection.source.clone().unwrap(),route_digest:[7;32],target_format:l::CORE_FORMAT,operation_id:[8;16]})).await.unwrap_or_else(|error|panic!("native Begin failed: {error:?}; forged={},latched={}",busbar_plugin_loader::dispatch::handle::forged(),busbar_plugin_loader::dispatch::handle::latched()));
            let l::Response::Begun(resumed)=response.as_ref() else{panic!("activation-resume upgrade")};
            assert_eq!(resumed.snapshot,upgrade.snapshot);
            assert_eq!(resumed.target,upgrade.target);
            upgrade=copy_native_upgrade(resumed);
            let finished=prepared.bootstrap(Arc::new(l::Request::Finish{upgrade:upgrade.reference.clone(),activation_receipt:activation})).await.unwrap();
            assert!(matches!(finished.as_ref(),l::Response::RecoveryReady(observed) if observed==&recovery));
        }
        let binding=l::OpenBinding::Recovery(recovery);
        let reopened=prepared.open(binding.clone()).await.unwrap();
        let same_open=prepared.open(binding).await.unwrap();
        assert!(Arc::ptr_eq(&reopened,&same_open),"recovery OPEN must retain the same backend");
        let observed=reopened.read(Arc::new(p::Read{dataset:info.dataset,addresses:vec![Address{namespace:[9;16],key:b"upgrade-checkpoint".to_vec()}],time:None})).await.unwrap();
        assert!(matches!(observed,ReadResult::Values{values,..} if values==vec![Some(Secret::new(b"activated".to_vec()))]));
        let complete=native_checkpoint(reopened.as_ref(),3,b"complete",l::CompletionPhase::Complete).await;
        let finished=prepared.bootstrap(Arc::new(l::Request::Finish{upgrade:upgrade.reference.clone(),activation_receipt:complete})).await.unwrap();
        assert!(matches!(finished.as_ref(),l::Response::ServingReady(_)));
        let serving=prepared.serving().unwrap();assert_eq!(serving.info(),info);
        assert!(Arc::ptr_eq(&reopened,&serving),"Complete must adopt the same recovered backend");
        let observed=serving.read(Arc::new(p::Read{dataset:info.dataset,addresses:vec![Address{namespace:[9;16],key:b"upgrade-checkpoint".to_vec()}],time:None})).await.unwrap();
        assert!(matches!(observed,ReadResult::Values{values,..} if values==vec![Some(Secret::new(b"complete".to_vec()))]));
    });
}

use busbar_contract::services::{
    Caller, DiskDest, HookAsk, Later, NestAsk, Ran, RecordsList, Stored,
};

struct BootstrapClock(Instant);
impl busbar_contract::services::HostServices for BootstrapClock {
    fn now(&self) -> busbar_contract::services::Reading {
        busbar_contract::services::Reading {
            wall_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .try_into()
                .unwrap(),
            mono_ns: self.0.elapsed().as_nanos().try_into().unwrap(),
        }
    }
    fn dest_judge(&self, _dest: &str, _class: u32, _flags: u32, _later: Option<Later>) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn records_get(&self, _caller: &Caller, _kind: &str, _key: &[u8], _later: Later) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn records_list(&self, _caller: &Caller, _list: RecordsList, _later: Later) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn records_claim(
        &self,
        _caller: &Caller,
        _kind: &str,
        _key: &[u8],
        _ttl_ms: u64,
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn sign(&self, _caller: &Caller, _data: &[u8]) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn trust_sight(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _hash: &str,
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn trust_unreached(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn trust_sight_item(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: &str,
        _digest: &str,
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn trust_decide(
        &self,
        _caller: &Caller,
        _key: busbar_contract::services::TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn trust_state(&self, _caller: &Caller, _counterparty: &str) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn trust_serves(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _item: Option<&str>,
        _digest: Option<&str>,
    ) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn trust_due(&self, _caller: &Caller) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn trust_verify(
        &self,
        _caller: &Caller,
        _counterparty: &str,
        _payload: &[u8],
        _signatures: &[u8],
    ) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn entitlement_check(&self, _caller: &Caller, _unit: Option<u64>, _target: &str) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn session_emit(&self, _caller: &Caller, _session: u64, _bytes: &[u8]) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn ticket_mint(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _ttl_secs: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn ticket_take(&self, _caller: &Caller, _unit: Option<u64>) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn random_fill(&self, _len: u64) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn records_secret(&self, _kind: &str, _id: &str, _later: Later) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn work_open(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _kind: &str,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn work_find(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _reference: &[u8],
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn work_settle(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _record: &[u8],
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn work_resume(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _handle: u64,
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn disk_append(&self, _dest: &DiskDest, _bytes: Vec<u8>, _later: Later) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn verify_lookup(&self, _caller: &Caller, _key: &[u8], _later: Later) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn verify_store(&self, _caller: &Caller, _key: &[u8], _entry: &[u8], _ttl_ms: u64) -> Stored {
        panic!("unexpected non-clock bootstrap service")
    }
    fn content_scan(
        &self,
        _caller: &Caller,
        _unit: Option<u64>,
        _content: &[u8],
        _later: Later,
    ) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn hook_call(&self, _caller: &Caller, _unit: Option<u64>, _ask: HookAsk, _later: Later) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
    fn snapshot_read(&self, _caller: &Caller, _scope: u32, _later: Later) -> Ran {
        panic!("unexpected non-clock bootstrap service")
    }
}

async fn native_checkpoint(
    backend: &dyn p::PersistenceBackend,
    operation: u8,
    value: &[u8],
    phase: p::lifecycle::CompletionPhase,
) -> p::lifecycle::ActivationReceipt {
    let info = backend.info();
    let address = Address {
        namespace: [9; 16],
        key: b"upgrade-checkpoint".to_vec(),
    };
    let attempt = AttemptId {
        dataset: info.dataset,
        writer_epoch: 1,
        writer: [2; 16],
        execution_epoch: 1,
        operation: [operation; 16],
    };
    let candidate = PreparedCandidate::new(Candidate {
        id: attempt,
        codec: p::CANDIDATE_VERSION,
        predicates: Vec::new(),
        mutations: vec![Mutation::Put {
            address: address.clone(),
            value: Secret::new(value.to_vec()),
        }],
        time: None,
        result: Secret::new(vec![operation]),
    })
    .unwrap();
    let fingerprint = candidate.fingerprint();
    assert!(matches!(
        backend.commit(candidate).await.unwrap(),
        Decision::Applied(_)
    ));
    p::lifecycle::ActivationReceipt {
        attempt,
        candidate_fingerprint: fingerprint,
        original_result: Secret::new(vec![operation]),
        checkpoint_address: address,
        checkpoint_value_digest: p::archive::digest(value),
        phase,
    }
}

fn copy_native_upgrade(value: &p::lifecycle::Upgrade) -> p::lifecycle::Upgrade {
    p::lifecycle::Upgrade {
        reference: value.reference.clone(),
        source: value.source.clone(),
        snapshot: value.snapshot,
        target: value.target,
        native_step: value.native_step,
        catalogue: value.catalogue.clone(),
    }
}

struct NativePrepared {
    prepared: busbar_plugin_loader::store_v4::LoadedPrepared,
    dispatcher: Arc<busbar_plugin_loader::dispatch::Dispatcher>,
}
impl std::ops::Deref for NativePrepared {
    type Target = busbar_plugin_loader::store_v4::LoadedPrepared;
    fn deref(&self) -> &Self::Target {
        &self.prepared
    }
}
impl Drop for NativePrepared {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "native bootstrap dispatcher stats: {:?}",
                self.dispatcher.stats()
            );
        }
    }
}

fn native_prepared(url: &str, budget: usize) -> NativePrepared {
    use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use busbar_plugin_loader::store_v4::{Limits, LoadedPrepared};
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(BootstrapClock(Instant::now())),
    ));
    let conns = valkey_io::host(
        dispatcher.conn_waker(),
        busbar_contract::transport::EgressTrust::default(),
    );
    let row =
        LinkedRow::of_kind::<StoreV4>(super::door as busbar_contract::abi::mechanism::door::DoorFn)
            .unwrap();
    let plugin = load_linked::<StoreV4>(
        &row,
        Bind {
            instance: Arc::from("valkey-bootstrap"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(conns),
        },
    )
    .unwrap();
    let bytes = serde_json::to_vec(
        &serde_json::json!({"url":url,"input_budget":budget,"durability":"ephemeral"}),
    )
    .unwrap();
    let prepared = LoadedPrepared::new(
        plugin,
        dispatcher.clone(),
        &bytes,
        Limits {
            descriptor_bytes: 1 << 20,
            output_items: 4096,
            output_bytes: 1 << 20,
            decode_bytes: 1 << 24,
        },
    )
    .unwrap();
    NativePrepared {
        prepared,
        dispatcher,
    }
}

#[test]
#[ignore = "isolated native authority refusal; explicit task tmp/server required"]
fn native_bootstrap_default_account_refuses_before_conversion() {
    use busbar_contract::persistence::lifecycle::{self as l, PreparedStore};
    let mut server = Server::start();
    server.set("busbar:schema", b"9");
    server.set("busbar:key:old", b"retained");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let prepared = native_prepared(
            &format!("redis://127.0.0.1:{}", server.port),
            64 * 1024 * 1024,
        );
        let response = prepared
            .bootstrap(Arc::new(l::Request::Inspect {
                bounds: l::Bounds {
                    items: 1024,
                    bytes: 1 << 20,
                },
            }))
            .await
            .unwrap();
        let l::Response::Inspected(inspection) = response.as_ref() else {
            panic!("default inspection")
        };
        assert_eq!(inspection.state, l::InspectionState::Legacy);
        assert!(!inspection
            .capabilities
            .contains(&l::NativeCapability::PersistentFence));
        let result = prepared
            .bootstrap(Arc::new(l::Request::BeginOrResume {
                expected_source: inspection.source.clone().unwrap(),
                route_digest: [7; 32],
                target_format: l::CORE_FORMAT,
                operation_id: [8; 16],
            }))
            .await;
        assert!(
            matches!(result, Err(l::Error::MissingCapability)),
            "default native refusal: {result:?}"
        );
    });
    assert_eq!(server.get("busbar:key:old"), Some(b"retained".to_vec()));
    assert_eq!(server.get("busbar:v4:bootstrap"), None);
    assert_eq!(server.get(META), None);
    server.set("busbar:key:old", b"unconverted");
}
