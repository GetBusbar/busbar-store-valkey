// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The real store door and RESP handshake over a host table that fragments writes and replies.
use super::*;
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece, PieceKind, Ticket,
};
use busbar_contract::store_calls::StoreCalls;
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Condvar, Mutex};
use std::task::{Context, Poll, Waker};

#[derive(Default)]
struct Stream {
    input: Vec<u8>,
    reply: VecDeque<u8>,
}
#[derive(Default)]
struct Script {
    streams: HashMap<ConnId, Stream>,
    opens: u64,
    closes: usize,
    writes: usize,
    auth: Vec<Vec<u8>>,
    refuse_auth: bool,
    fail_get: bool,
    hold_auth: bool,
    held: bool,
}
#[derive(Default)]
struct Fragmented {
    script: Mutex<Script>,
    changed: Condvar,
}
impl Fragmented {
    fn wait_for(&self, condition: impl Fn(&Script) -> bool) {
        let (script, timeout) = self
            .changed
            .wait_timeout_while(self.script.lock().unwrap(), Duration::from_secs(5), |s| {
                !condition(s)
            })
            .unwrap();
        assert!(condition(&script), "script did not progress: {timeout:?}");
    }
}
impl Conns for Fragmented {
    fn open(&self, _: InstanceId, _: NeedId, desc: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        assert!(matches!(
            desc.target,
            "cache.internal:6379" | "unix:/run/v.sock"
        ));
        let mut s = self.script.lock().unwrap();
        s.opens += 1;
        let id = ConnId(s.opens);
        s.streams.insert(id, Stream::default());
        Ok(id)
    }
    fn write(
        &self,
        _: InstanceId,
        id: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        let mut s = self.script.lock().unwrap();
        s.writes += 1;
        let input = &s.streams.get(&id).ok_or(ConnError::Closed)?.input;
        if s.hold_auth && id.0 > 1 && input.len() >= 6 {
            s.held = true;
            self.changed.notify_all();
            return Ok(0);
        }

        if s.writes % 3 == 1 {
            return Ok(0);
        }
        let n = bytes.len().min(3);
        let stream = s.streams.get_mut(&id).unwrap();
        stream.input.extend_from_slice(&bytes[..n]);
        let Some((value, used)) = resp::parse(&stream.input).unwrap() else {
            return Ok(n);
        };
        let packet: Vec<u8> = stream.input.drain(..used).collect();
        let resp::Value::Array(args) = value else {
            panic!("a command must be an array")
        };
        let resp::Value::Data(word) = &args[0] else {
            panic!("command word must be a bulk string")
        };
        let reply = match word.as_slice() {
            b"AUTH" => {
                s.auth.push(packet);
                if s.refuse_auth {
                    b"-ERR credential CANARY sealed+password / CANARY%20sealed%2Bpassword refused\r\n".to_vec()
                } else {
                    b"+OK\r\n".to_vec()
                }
            }
            b"SELECT" => b"+OK\r\n".to_vec(),
            b"GET" => format!(
                "${}\r\n{}\r\n",
                SCHEMA_VERSION.to_string().len(),
                SCHEMA_VERSION
            )
            .into_bytes(),
            b"CONFIG" => b"*2\r\n$16\r\nmaxmemory-policy\r\n$10\r\nnoeviction\r\n".to_vec(),
            b"HGET" if s.fail_get => {
                s.fail_get = false;
                return Err(ConnError::Closed);
            }
            b"HGET" => b"$-1\r\n".to_vec(),
            other => panic!("unexpected command {other:?}"),
        };
        s.streams.get_mut(&id).unwrap().reply.extend(reply);
        Ok(n)
    }
    fn read(
        &self,
        _: InstanceId,
        id: ConnId,
        _: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let mut s = self.script.lock().unwrap();
        let stream = s.streams.get_mut(&id).ok_or(ConnError::Closed)?;
        let n = buf.len().min(2).min(stream.reply.len());
        if n == 0 {
            return Err(ConnError::Pending);
        }
        for byte in &mut buf[..n] {
            *byte = stream.reply.pop_front().unwrap();
        }
        Ok(Piece {
            kind: PieceKind::Body,
            stream: busbar_contract::ids::StreamId(0),
            len: n,
            end: false,
            status: None,
            status_code: None,
            status_namespace: None,
            retry_after_secs: None,
            fault: None,
            reason: None,
            declared_len: None,
        })
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(
        &self,
        _: InstanceId,
        _: ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, ConnError> {
        Ok(Default::default())
    }
    fn close(&self, _: InstanceId, id: ConnId) -> Result<(), ConnError> {
        let mut s = self.script.lock().unwrap();
        s.streams.remove(&id);
        s.closes += 1;
        self.changed.notify_all();
        Ok(())
    }
}
impl DeclaredConns for Fragmented {
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.open_with_security(
            caller,
            need,
            &OpenDesc {
                timeout_ms: if dial_timeout_ms == 0 {
                    desc.timeout_ms
                } else {
                    dial_timeout_ms
                },
                ..desc.clone()
            },
            require_secure,
        )
    }

    fn declare(
        &self,
        _: InstanceId,
        _: NeedId,
        _: &busbar_contract::abi::mechanism::rendering::ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        Ok(())
    }
    fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
        Some(Ok(()))
    }
    fn serves_scheme(&self, scheme: &str) -> bool {
        scheme == "tcp"
    }
}
fn open_script(table: Arc<Fragmented>) -> Result<LoadedStore, String> {
    open_script_url(
        table,
        "redis://alice:CANARY%20sealed%2Bpassword@cache.internal/2",
    )
}
fn open_script_url(table: Arc<Fragmented>, url: &str) -> Result<LoadedStore, String> {
    let d = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(ClockOnly),
    ));
    let p = load_linked::<Store>(
        &LinkedRow::of(crate::door).unwrap(),
        Bind {
            instance: Arc::from("sealed-auth"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::Host(table),
        },
    )
    .unwrap();
    LoadedStore::open(
        p,
        d,
        &serde_json::to_vec(&serde_json::json!({"url": url})).unwrap(),
        mint,
    )
}
const AUTH: &[u8] = b"*3\r\n$4\r\nAUTH\r\n$5\r\nalice\r\n$22\r\nCANARY sealed+password\r\n";

#[test]
fn sealed_auth_survives_partial_writes_pending_and_kept_reuse() {
    let table = Arc::new(Fragmented::default());
    let store = open_script(table.clone()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(runtime
        .block_on(StoreCalls::record_get(&store, "auth", b"key"))
        .unwrap()
        .is_none());
    let s = table.script.lock().unwrap();
    assert_eq!(s.opens, 1);
    assert_eq!(s.auth.iter().map(Vec::as_slice).collect::<Vec<_>>(), [AUTH]);
    assert!(s.writes > AUTH.len() / 3);
}
#[test]
fn an_auth_refusal_redacts_raw_and_decoded_password_and_closes_the_stream() {
    let table = Arc::new(Fragmented::default());
    table.script.lock().unwrap().refuse_auth = true;
    let error = open_script(table.clone()).unwrap_err();
    assert!(!error.contains("CANARY"), "{error}");
    assert!(
        error.contains("<redacted>") && error.contains("refused"),
        "{error}"
    );
    table.wait_for(|s| s.closes == 1);
    assert_eq!(
        table
            .script
            .lock()
            .unwrap()
            .auth
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
        [AUTH]
    );
}
#[test]
fn cancelling_a_partly_written_reconnect_auth_closes_it_and_dials_fresh() {
    let table = Arc::new(Fragmented::default());
    let store = open_script(table.clone()).unwrap();
    {
        let mut s = table.script.lock().unwrap();
        s.fail_get = true;
        s.hold_auth = true;
    }
    let mut call = Box::pin(StoreCalls::record_get(&store, "auth", b"key"));
    assert!(matches!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
    table.wait_for(|s| s.held);
    drop(call);
    table.wait_for(|s| s.closes >= 2);
    table.script.lock().unwrap().hold_auth = false;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(runtime
        .block_on(StoreCalls::record_get(&store, "auth", b"key"))
        .unwrap()
        .is_none());
    let s = table.script.lock().unwrap();
    assert_eq!(s.opens, 3);
    assert_eq!(
        s.auth.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        [AUTH, AUTH],
        "the cancelled stream never completed AUTH"
    );
}

#[test]
fn the_actual_slot_captures_lent_url_markers_before_retaining_config() {
    use busbar_contract::abi::sdk::store::StoreSlots;
    let doc = br#"{"url":{"$secret":0},"connect_timeout_ms":250}"#;
    let url = b"redis://alice:CANARY%20sealed%2Bpassword@cache.internal/2";
    let store = <crate::ValkeyStore as StoreSlots>::open_with_secrets(doc, &[url], None).unwrap();
    assert_auth(&store.inner.target, Some("alice"), "CANARY sealed+password");
    assert_eq!(store.inner.target.db, 2);
    assert_eq!(store.inner.connect_timeout, Duration::from_millis(250));
    assert!(!format!("{store:?}").contains("CANARY"));
    for (settings, lent) in [
        (doc.as_slice(), Vec::<&[u8]>::new()),
        (br#"{"url":{"$secret":4}}"#.as_slice(), vec![url.as_slice()]),
        (
            br#"{"url":{"$secret":0}}"#.as_slice(),
            vec![b"\xff".as_slice()],
        ),
    ] {
        let error = <crate::ValkeyStore as StoreSlots>::open_with_secrets(settings, &lent, None)
            .unwrap_err();
        assert!(
            error.starts_with("invalid valkey plugin config: "),
            "{error}"
        );
        assert!(!error.contains("CANARY"), "{error}");
    }
}

#[test]
fn url_auth_distinguishes_user_and_password_forms_and_unix_query_precedence() {
    for url in ["redis://alice@h", "redis://alice:@h", "redis://:@h"] {
        assert!(parse_url(url).unwrap().auth.is_none(), "{url}");
    }
    assert_auth(&parse_url("redis://:pw@h").unwrap(), None, "pw");
    assert_auth(
        &parse_url("unix:/run/v.sock?user=&pass=").unwrap(),
        Some(""),
        "",
    );
    let target = parse_url(
        "valkey+unix:///run/v.sock?user=first&user=last&pass=first&%70ass=last+%FF&db=1&db=2",
    )
    .unwrap();
    assert_auth(&target, Some("last"), "last \u{fffd}");
    assert_eq!(target.db, 2);
    assert!(parse_url("redis://u:%FF@h")
        .unwrap_err()
        .to_string()
        .contains("Password is not valid UTF-8"));
}

#[test]
fn actual_auth_packets_preserve_default_user_empty_unix_password_and_absence() {
    for (url, expected) in [
        (
            "redis://:pw@cache.internal",
            Some(b"*2\r\n$4\r\nAUTH\r\n$2\r\npw\r\n".as_slice()),
        ),
        (
            "unix:/run/v.sock?user=&pass=",
            Some(b"*3\r\n$4\r\nAUTH\r\n$0\r\n\r\n$0\r\n\r\n".as_slice()),
        ),
        ("redis://alice:@cache.internal", None),
    ] {
        let table = Arc::new(Fragmented::default());
        let store = open_script_url(table.clone(), url).unwrap();
        let got = table.script.lock().unwrap().auth.clone();
        assert_eq!(
            got.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            expected.into_iter().collect::<Vec<_>>()
        );
        drop(store);
        table.wait_for(|s| s.closes == 1);
    }
}

#[test]
fn typed_settings_capture_keeps_object_only_shape_and_refusal_order() {
    for json in [
        r#"["redis://:CANARY@h"]"#,
        r#"[{"url":"redis://:CANARY@h"}]"#,
    ] {
        assert_eq!(
            settings_err(json),
            "invalid valkey plugin config: expected a JSON object, got an array"
        );
    }
    assert_eq!(
        settings_err(r#"{"url":5,"zzz":"CANARY"}"#),
        "invalid valkey plugin config: unknown setting `zzz` (accepted: url, connect_timeout_ms)",
    );
    assert_eq!(
        settings_err(r#"{"url":"redis://u:%FF@h/x"}"#),
        "invalid valkey plugin config: url: Invalid database number - InvalidClientConfig",
    );
}
