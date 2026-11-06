// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::Arc;

fn row(store: &ValkeyStore, public: &str) -> CredentialSecret {
    store
        .lookup_credential_secret("sigv4", public)
        .unwrap()
        .unwrap()
}

fn owned(store: &ValkeyStore, owner: &str) -> Vec<CredentialSecret> {
    let mut rows: Vec<_> = store
        .list_credentials_since(0)
        .unwrap()
        .into_iter()
        .filter(|c| c.meta.key_id == owner)
        .collect();
    rows.sort_by(|a, b| a.meta.id.cmp(&b.meta.id));
    rows
}

#[test]
fn loaded_doors_rewrap_once_with_exact_large_metadata_and_survive_reopen() {
    let Some(store) = live_store() else { return };
    let owner = format!("vk_rewrap_{}", unique_suffix());
    let public = format!("{owner}_public");
    store.put_key(&vk(&owner)).unwrap();
    let mut credential = cred(&owner, &public, 0);
    credential.meta.created_at = (1u64 << 53) + 1;
    store.put_credential(&credential).unwrap();
    let expected = row(&store, &public);
    assert_eq!(expected.meta.created_at, credential.meta.created_at);
    assert!(!store
        .rewrap_credential(&expected, &expected.secret)
        .unwrap());
    let mut altered = expected.clone();
    altered.meta.created_at += 1;
    assert!(!store
        .rewrap_credential(&altered, "altered-metadata")
        .unwrap());
    let connections = [live_store().unwrap(), live_store().unwrap()];
    let outcomes = std::thread::scope(|scope| {
        let writers: Vec<_> = connections
            .into_iter()
            .zip(["envelope-a", "envelope-b"])
            .map(|(connection, envelope)| {
                let (start, started) = std::sync::mpsc::channel();
                let expected = expected.clone();
                let writer = scope.spawn(move || {
                    started.recv().expect("race worker started");
                    (
                        envelope,
                        connection.rewrap_credential(&expected, envelope).unwrap(),
                    )
                });
                (start, writer)
            })
            .collect();
        for (start, _) in &writers {
            start.send(()).unwrap();
        }
        writers
            .into_iter()
            .map(|(_, writer)| writer.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|(_, applied)| *applied).count(), 1);
    let winner = outcomes.iter().find(|(_, applied)| *applied).unwrap().0;
    let current = row(&store, &public);
    let mut wanted = expected.clone();
    wanted.secret = winner.into();
    wanted.meta.revision = current.meta.revision;
    assert!(current == wanted);
    assert!(current.meta.revision > expected.meta.revision);
    assert!(!store.rewrap_credential(&expected, "stale").unwrap());
    assert!(!store.rewrap_credential(&current, &current.secret).unwrap());
    let mut ordinary = current.clone();
    ordinary.secret = "ordinary-put-must-not-rotate".into();
    assert!(store.put_credential(&ordinary).is_err());
    assert!(row(&store, &public) == current);
    drop(store);
    assert!(row(&live_store().unwrap(), &public) == current);
}

#[test]
fn loaded_rewrap_cannot_resurrect_revoked_deleted_or_reclaimed_credentials() {
    let Some(store) = live_store() else { return };
    for delete in [false, true] {
        let owner = format!("vk_rewrap_dead_{}", unique_suffix());
        let public = format!("{owner}_public");
        store.put_key(&vk(&owner)).unwrap();
        store.put_credential(&cred(&owner, &public, 0)).unwrap();
        let expected = row(&store, &public);
        if delete {
            store.delete_key(&owner).unwrap();
        } else {
            store
                .revoke_credential(&expected.meta.id, "revoked")
                .unwrap();
        }
        let retired = owned(&store, &owner);
        assert!(!store.rewrap_credential(&expected, "resurrection").unwrap());
        assert!(owned(&store, &owner) == retired);
        if !delete {
            store
                .put_credential(&cred(&owner, &format!("{owner}_new"), 0))
                .unwrap();
            let reclaimed = owned(&store, &owner);
            assert!(!store.rewrap_credential(&expected, "resurrection").unwrap());
            assert!(owned(&store, &owner) == reclaimed);
        }
    }
}

#[test]
fn loaded_rewrap_checks_the_whole_row_and_preserves_revision_on_every_refusal() {
    let Some(_) = live_store() else { return };

    let (_database, mut raw) = fresh_db_client(1);
    let store = ValkeyStore::connect(&url_for_db(1)).unwrap();
    let owner = uid("vk_cas_snapshot");
    let public = uid("vk_cas_public");
    let key = vk(&owner);
    let mut offered = cred(&owner, &public, 0);
    offered.meta.created_at = u64::MAX - 2;
    offered.meta.updated_at = u64::MAX - 1;
    offered.meta.expires_at = Some(u64::MAX);
    store.put_key_with_credential(&key, &offered).unwrap();
    let expected = row(&store, &public);
    let row_key = cred_row_key(&owner, "sigv4", 0);
    let owner_key = format!("{KEY_PREFIX}{owner}");
    let before: String = raw.get(&row_key).unwrap();
    let owner_before: String = raw.get(&owner_key).unwrap();
    let revision: u64 = raw.get(REVISION_KEY).unwrap();
    let mutations: &[fn(&mut CredentialSecret)] = &[
        |c| c.meta.id.push('x'),
        |c| c.meta.key_id.push('x'),
        |c| c.meta.kind.push('x'),
        |c| c.meta.slot = 1,
        |c| c.meta.public_id.push('x'),
        |c| c.meta.secret_form = SecretForm::Digest,
        |c| c.meta.created_at -= 1,
        |c| c.meta.updated_at -= 1,
        |c| c.meta.expires_at = None,
        |c| c.meta.revoked_at = Some(u64::MAX),
        |c| c.meta.revoke_reason = Some("changed".into()),
        |c| c.meta.revision += 1,
        |c| c.secret.push('x'),
    ];
    for mutate in mutations {
        let mut stale = expected.clone();
        mutate(&mut stale);
        assert!(!store.rewrap_credential(&stale, "replacement").unwrap());
        assert_eq!(raw.get::<_, String>(&row_key).unwrap(), before);
        assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), revision);
    }
    assert!(!store
        .rewrap_credential(&expected, &expected.secret)
        .unwrap());
    assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), revision);

    for pointer_key in [
        cred_id_key(&expected.meta.id),
        cred_pub_key("sigv4", &public),
    ] {
        let pointer: String = raw.get(&pointer_key).unwrap();
        raw.set::<_, _, ()>(&pointer_key, "different:owner:0")
            .unwrap();
        let result = store.rewrap_credential(&expected, "replacement");
        raw.set::<_, _, ()>(&pointer_key, pointer).unwrap();
        assert!(!result.unwrap());
        assert_eq!(raw.get::<_, String>(&row_key).unwrap(), before);
        assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), revision);
    }
    for missing in [false, true] {
        if missing {
            raw.del::<_, ()>(&owner_key).unwrap();
        } else {
            let mut dead = key.clone();
            dead.deleted_at = Some(u64::MAX);
            raw.set::<_, _, ()>(&owner_key, serde_json::to_string(&dead).unwrap())
                .unwrap();
        }
        let result = store.rewrap_credential(&expected, "replacement");
        raw.set::<_, _, ()>(&owner_key, &owner_before).unwrap();
        assert!(!result.unwrap());
        assert_eq!(raw.get::<_, String>(&row_key).unwrap(), before);
        assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), revision);
    }

    let saved_index = "cas-saved-index";
    raw.rename::<_, _, ()>(CREDS_BYREV, saved_index).unwrap();
    raw.set::<_, _, ()>(CREDS_BYREV, "wrong-type").unwrap();
    let result = store.rewrap_credential(&expected, "replacement");
    let after: String = raw.get(&row_key).unwrap();
    let after_revision: u64 = raw.get(REVISION_KEY).unwrap();
    raw.del::<_, ()>(CREDS_BYREV).unwrap();
    raw.rename::<_, _, ()>(saved_index, CREDS_BYREV).unwrap();
    assert!(
        result.is_err(),
        "WRONGTYPE must fail before any queued write"
    );
    assert_eq!(after, before);
    assert_eq!(after_revision, revision);
    assert!(store.rewrap_credential(&expected, "replacement").unwrap());
    let current = row(&store, &public);
    let mut wanted = expected;
    wanted.secret = "replacement".into();
    wanted.meta.revision = revision + 1;
    assert!(current == wanted);
    assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), revision + 1);
    assert_eq!(raw.get::<_, String>(&owner_key).unwrap(), owner_before);
    redis::cmd("FLUSHDB").query::<()>(&mut raw).unwrap();
}

#[test]
fn loaded_rewrap_rechecks_revocation_and_index_type_changed_before_exec() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(2);
    let url = url_for_db(2);
    let fast = ValkeyStore::connect(&url).unwrap();
    for revoke in [false, true] {
        let owner = uid("vk_cas_race");
        let public = uid("vk_cas_race_public");
        fast.put_key_with_credential(&vk(&owner), &cred(&owner, &public, 0))
            .unwrap();
        let expected = row(&fast, &public);
        let row_key = cred_row_key(&owner, "sigv4", 0);
        let gate = interleave::gate(&url, true, |chunk| {
            interleave::contains(chunk, b"$4\r\nEXEC\r\n")
        });
        let slow = ValkeyStore::connect(&gate.url).unwrap();
        let old = expected.clone();
        let writer = gate.spawn(move || slow.rewrap_credential(&old, "must-not-win"));
        let held = gate.held.recv_timeout(std::time::Duration::from_secs(10));
        if held.is_ok() {
            if revoke {
                fast.revoke_credential(&expected.meta.id, "raced").unwrap();
            } else {
                raw.rename::<_, _, ()>(CREDS_BYREV, "cas-race-saved-index")
                    .unwrap();
                raw.set::<_, _, ()>(CREDS_BYREV, "wrong-type").unwrap();
            }
        }
        let before: String = raw.get(&row_key).unwrap();
        let revision: u64 = raw.get(REVISION_KEY).unwrap();
        let _ = gate.release.send(());
        let result = writer.join().unwrap();
        let after: String = raw.get(&row_key).unwrap();
        let after_revision: u64 = raw.get(REVISION_KEY).unwrap();
        if !revoke && held.is_ok() {
            raw.del::<_, ()>(CREDS_BYREV).unwrap();
            raw.rename::<_, _, ()>("cas-race-saved-index", CREDS_BYREV)
                .unwrap();
        }
        held.expect("rewrap paused after checks and before EXEC");
        if revoke {
            assert!(!result.unwrap());
        } else {
            assert!(result.is_err());
        }
        assert_eq!(after, before);
        assert_eq!(after_revision, revision);
    }
    redis::cmd("FLUSHDB").query::<()>(&mut raw).unwrap();
}

struct ReplyProxy {
    worker: Option<std::thread::JoinHandle<()>>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    stream: Arc<std::sync::Mutex<Option<std::net::TcpStream>>>,
    release: Option<std::sync::mpsc::Sender<()>>,
}

impl ReplyProxy {
    fn join(mut self) -> std::thread::Result<()> {
        self.worker.take().expect("reply proxy worker").join()
    }
}

impl Drop for ReplyProxy {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
            self.stopping
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(stream) = self
                .stream
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
            if let Err(error) = worker.join() {
                if !std::thread::panicking() {
                    std::panic::resume_unwind(error);
                }
            }
        }
    }
}

fn lose_rewrap_reply(
    url: String,
    before_commit_row: Option<String>,
    after_command: impl FnOnce() + Send + 'static,
    release_on_drop: Option<std::sync::mpsc::Sender<()>>,
) -> (String, ReplyProxy) {
    use std::io::Write;

    fn encode(value: redis::Value, bytes: &mut Vec<u8>) {
        match value {
            redis::Value::Nil => bytes.extend_from_slice(b"$-1\r\n"),
            redis::Value::Okay => bytes.extend_from_slice(b"+OK\r\n"),
            redis::Value::SimpleString(s) => {
                bytes.extend_from_slice(format!("+{s}\r\n").as_bytes())
            }
            redis::Value::Int(n) => bytes.extend_from_slice(format!(":{n}\r\n").as_bytes()),
            redis::Value::BulkString(s) => {
                bytes.extend_from_slice(format!("${}\r\n", s.len()).as_bytes());
                bytes.extend_from_slice(&s);
                bytes.extend_from_slice(b"\r\n");
            }
            redis::Value::Array(values) => {
                bytes.extend_from_slice(format!("*{}\r\n", values.len()).as_bytes());
                for value in values {
                    encode(value, bytes);
                }
            }
            _ => panic!("the RESP2 proxy received an unsupported response"),
        }
    }

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_url = format!(
        "redis://{}/{}",
        listener.local_addr().unwrap(),
        db_of_url(&url)
    );
    listener.set_nonblocking(true).unwrap();
    let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let running = stopping.clone();
    let stream = Arc::new(std::sync::Mutex::new(None));
    let retained = stream.clone();

    let timeout = std::time::Duration::from_secs(10);
    let mut server = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection_with_timeout(timeout)
        .unwrap();
    server.set_read_timeout(Some(timeout)).unwrap();
    server.set_write_timeout(Some(timeout)).unwrap();
    let proxy = std::thread::spawn(move || {
        let mut client = loop {
            if running.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            match listener.accept() {
                Ok((client, _)) => break client,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        {
            let mut socket = retained.lock().unwrap();
            if running.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            *socket = Some(client.try_clone().unwrap());
        }

        drop(listener);
        client
            .set_nonblocking(false)
            .expect("blocking proxy client");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        client
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut parser = redis::Parser::new();
        while let Ok(command) = parser.parse_value(&mut client) {
            let fields: Vec<String> = redis::from_redis_value(command).unwrap();
            let reply: redis::Value = redis::cmd(&fields[0])
                .arg(&fields[1..])
                .query(&mut server)
                .unwrap();
            let held = match &before_commit_row {
                Some(row) => fields[0] == "GET" && fields.get(1) == Some(row),
                None => fields[0] == "EXEC",
            };
            if held {
                if before_commit_row.is_none() {
                    assert!(
                        matches!(reply, redis::Value::Array(_)),
                        "the transaction committed"
                    );
                }
                after_command();
                let _ = client.shutdown(std::net::Shutdown::Both);
                return;
            }
            let mut response = Vec::new();
            encode(reply, &mut response);
            client.write_all(&response).unwrap();
        }
    });
    (
        proxy_url,
        ReplyProxy {
            worker: Some(proxy),
            stopping,
            stream,
            release: release_on_drop,
        },
    )
}

#[test]
fn loaded_rewrap_lost_exec_reply_returns_error_without_replaying_the_commit() {
    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(3);
    let url = url_for_db(3);
    let fast = ValkeyStore::connect(&url).unwrap();
    let owner = uid("vk_cas_lost_reply");
    let public = uid("vk_cas_lost_public");
    fast.put_key_with_credential(&vk(&owner), &cred(&owner, &public, 0))
        .unwrap();
    let expected = row(&fast, &public);
    let revision: u64 = raw.get(REVISION_KEY).unwrap();
    let (proxy_url, proxy) = lose_rewrap_reply(url, None, || {}, None);
    let (slow, table) = open_on(&settings_for(&proxy_url), plain);
    let slow = slow.unwrap();
    let dials = table.dial_timeouts().len();
    let result = slow.rewrap_credential(&expected, "committed-envelope");
    proxy.join().unwrap();
    let current = row(&fast, &public);
    let mut wanted = expected;
    wanted.secret = "committed-envelope".into();
    wanted.meta.revision = revision + 1;
    assert!(
        result.is_err(),
        "a lost commit reply is ambiguous, never false"
    );
    assert_eq!(
        table.dial_timeouts().len(),
        dials,
        "no reconnect after ambiguous EXEC"
    );
    assert!(
        current == wanted,
        "a separate read reconciles the committed envelope"
    );
    assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), revision + 1);
    assert!(!fast.rewrap_credential(&current, &current.secret).unwrap());
    assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), revision + 1);
    redis::cmd("FLUSHDB").query::<()>(&mut raw).unwrap();
}

#[test]
fn loaded_rewrap_cancellation_is_noop_before_commit_and_reconciled_after_commit() {
    use busbar_contract::abi::mechanism::call::{
        Blob, DeadlineClass, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
    };
    use busbar_contract::abi::mechanism::{extensions, lifecycle};
    use busbar_contract::abi::sdk::store::rewrap;
    use busbar_contract::abi::store::{slot, BlobIn};
    use busbar_plugin_loader::dispatch::{in_head, out_head, Frame};

    let Some(_) = live_store() else { return };
    let (_database, mut raw) = fresh_db_client(4);
    let url = url_for_db(4);
    let fast = ValkeyStore::connect(&url).unwrap();
    for before_commit in [true, false] {
        let owner = uid("vk_cas_cancel");
        let public = uid("vk_cas_cancel_public");
        fast.put_key_with_credential(&vk(&owner), &cred(&owner, &public, 0))
            .unwrap();
        let expected = row(&fast, &public);
        let revision: u64 = raw.get(REVISION_KEY).unwrap();
        let (observed_tx, observed) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let held_row = before_commit.then(|| cred_row_key(&owner, "sigv4", 0));
        let (proxy_url, proxy) = lose_rewrap_reply(
            url.clone(),
            held_row,
            move || {
                let _ = observed_tx.send(());
                let _ = released.recv_timeout(std::time::Duration::from_secs(30));
            },
            Some(release.clone()),
        );
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let (slow, table) =
            open_on_dispatcher(Arc::clone(&dispatcher), &settings_for(&proxy_url), plain);
        let slow = slow.unwrap();
        let dials = table.dial_timeouts().len();

        let lent = Arc::new((
            serde_json::to_vec(&rewrap::Request::new(&expected, "cancelled-envelope")).unwrap(),
            extensions::encode(&[(rewrap::INTENT, b"1")]),
        ));
        let weak = Arc::downgrade(&lent);
        let mut head = in_head();
        head.extensions = Blob {
            ptr: lent.1.as_ptr(),
            len: lent.1.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        let frame = Frame::new(
            BlobIn {
                head,
                record: Blob {
                    ptr: lent.0.as_ptr(),
                    len: lent.0.len(),
                    fmt: BLOB_JSON,
                    flags: BLOB_SECRET,
                },
            },
            out_head(),
        );
        let ticket = dispatcher.mint(0).unwrap();
        let reply = dispatcher.submit_lent(
            slow.plugin(),
            ticket,
            slot::PUT_CREDENTIAL,
            frame,
            DeadlineClass::Call,
            0,
            lent.clone(),
        );
        drop(lent);
        let reached = observed.recv_timeout(std::time::Duration::from_secs(10));
        let early = reply.wait(std::time::Duration::ZERO);
        let pending = early.is_none();
        if let Some(done) = early {
            if done.lease != 0 {
                slow.plugin().call(
                    lifecycle::slot::RELEASE,
                    &mut Frame::new(
                        lifecycle::ReleaseIn {
                            head: in_head(),
                            lease: done.lease,
                        },
                        out_head(),
                    ),
                );
            }
        }
        drop(reply);
        dispatcher.recycle(ticket);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while (weak.strong_count() != 0 || slow.plugin().inflight() != 0)
            && std::time::Instant::now() < until
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let cancelled = weak.strong_count() == 0 && slow.plugin().inflight() == 0;
        let _ = release.send(());
        proxy.join().unwrap();
        reached.expect("the request reached its held backend reply");
        assert!(
            pending,
            "the real ABI operation is pending before cancellation"
        );
        assert!(
            cancelled,
            "CANCEL retires the operation before the held reply is released"
        );
        assert_eq!(
            table.dial_timeouts().len(),
            dials,
            "cancellation must not replay the operation"
        );
        let current = row(&fast, &public);
        let mut wanted = expected.clone();
        if !before_commit {
            wanted.secret = "cancelled-envelope".into();
            wanted.meta.revision = revision + 1;
        }
        assert!(
            current == wanted,
            "the committed row determines reconciliation"
        );
        let committed_revision = revision + u64::from(!before_commit);
        assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), committed_revision);
        assert!(!fast.rewrap_credential(&current, &current.secret).unwrap());
        assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), committed_revision);
        if before_commit {
            assert!(fast.rewrap_credential(&expected, "retry-envelope").unwrap());
            assert_eq!(raw.get::<_, u64>(REVISION_KEY).unwrap(), revision + 1);
        }
        assert!(row(&ValkeyStore::connect(&url).unwrap(), &public) == row(&fast, &public));
    }
    redis::cmd("FLUSHDB").query::<()>(&mut raw).unwrap();
}
