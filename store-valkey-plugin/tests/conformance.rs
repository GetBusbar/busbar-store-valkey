// SPDX-License-Identifier: Apache-2.0
//! Actual linked/dropped primitive doors and native host ownership.
mod support;
use busbar_contract::persistence::PersistenceBackend;
use busbar_contract::{persistence as p, Secret};
use busbar_plugin_loader::dispatch::kinds::{
    secret::Secret as SecretKind, store_v4::StoreV4 as Store,
};
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, Bind, ConnTable, LinkedRow, Plugin,
};
use busbar_plugin_loader::store_v4::LoadedPersistence;
use std::sync::Arc;
use support::*;
#[test]
fn a_store_library_asked_for_as_a_secret_is_refused() {
    let lib = cdylib();
    let stated = packed_rendering(&lib);
    let d = dispatcher();
    let e = match load_dropped::<SecretKind>(&lib, &stated, bind(&d)) {
        Ok(_) => panic!("a store library loaded as secret"),
        Err(e) => e.to_string(),
    };
    assert!(
        e.contains("the manifest states kind Store, not Secret"),
        "{e}"
    );
}

/// RED ARM: a manifest whose Statement is one byte off the library's own is refused.
#[test]
fn a_statement_one_byte_off_is_refused() {
    use busbar_contract::abi::mechanism::rendering::read;
    use busbar_plugin_loader::dispatch::LoadError;

    let lib = cdylib();
    let mut other = packed_rendering(&lib);
    let name = read(&other).expect("the library's Statement parses").name;
    let name_at = other
        .windows(name.len())
        .position(|bytes| bytes == name.as_bytes())
        .expect("the rendered Statement contains its name");
    other[name_at] = if other[name_at] == b'a' { b'b' } else { b'a' };
    assert_ne!(
        read(&other)
            .expect("the one-byte mutation preserves a valid Statement")
            .name,
        name
    );
    let d = dispatcher();
    let row = LinkedRow {
        statement: other.clone(),
        ..LinkedRow::of(busbar_store_valkey::door).expect("actual linked door")
    };
    assert!(matches!(
        load_linked::<Store>(&row, bind(&d)),
        Err(LoadError::StatementMismatch)
    ));
    let e = match load_dropped::<Store>(&lib, &other, bind(&d)) {
        Ok(_) => panic!("a library loaded under a Statement that is not its own"),
        Err(e) => e,
    };
    assert!(matches!(&e, LoadError::StatementMismatch), "{e}");
    assert!(e.to_string().contains("repack the plugin"), "{e}");
}

#[test]
fn a_statement_with_trailing_bytes_is_refused_as_malformed() {
    use busbar_plugin_loader::dispatch::LoadError;

    let lib = cdylib();
    let mut malformed = packed_rendering(&lib);
    let end = malformed.len();
    malformed.push(0);
    let d = dispatcher();
    let error = match load_dropped::<Store>(&lib, &malformed, bind(&d)) {
        Ok(_) => panic!("a library loaded under a Statement with trailing bytes"),
        Err(error) => error,
    };
    match error {
        LoadError::Rendering(why) => assert_eq!(why, format!("byte {end} is not the end")),
        other => panic!("expected a malformed Statement refusal, got {other}"),
    }
}

#[test]
fn networked_store_requires_a_connection_table_in_both_forms() {
    use busbar_plugin_loader::dispatch::LoadError;
    let row = LinkedRow::of(busbar_store_valkey::door).unwrap();
    let stated = packed_rendering(&cdylib());
    for dropped_in in [false, true] {
        let d = dispatcher();
        let bind = Bind {
            conns: ConnTable::NoNeeds,
            ..bind(&d)
        };
        let result = if dropped_in {
            load_dropped::<Store>(&cdylib(), &stated, bind)
        } else {
            load_linked::<Store>(&row, bind)
        };
        let error = result.expect_err("networked store without table refuses");
        assert!(
            matches!(error, LoadError::NoConnectionTable { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("plugin 'busbar-store-valkey'"));
        load_linked::<Store>(
            &row,
            Bind {
                conns: ConnTable::Probe,
                ..self::bind(&d)
            },
        )
        .expect("probe is admitted");
    }
}

/// Only malformed ABI metadata is changed; every product slot stays the real Valkey implementation.
#[test]
fn actual_valkey_door_rejects_incompatible_abi_and_layout() {
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_plugin_loader::dispatch::{load::rendering_of_raw, LoadError};
    use std::sync::atomic::{AtomicPtr, Ordering};
    static MALFORMED: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    extern "C" fn malformed() -> *const Door {
        MALFORMED.load(Ordering::SeqCst)
    }
    // SAFETY: the actual shipped SDK door is static and complete.
    let real = unsafe { Door::read_parts(busbar_store_valkey::door()) };
    let kind = KindCode::Store;
    let row = LinkedRow::of(busbar_store_valkey::door).unwrap();
    let lib = cdylib();
    for abi in [real.kind_abi + 1, real.kind_abi.wrapping_sub(1)] {
        // SAFETY: preserve all static product pointers, changing ABI admission metadata only.
        let door = unsafe {
            Door::__from_parts(DoorParts {
                kind_abi: abi,
                ..real
            })
        };
        MALFORMED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
        let want = LoadError::KindAbi {
            kind,
            door: abi,
            host: real.kind_abi,
        };
        assert_eq!(rendering_of_raw(malformed).err(), Some(want.clone()));
        assert_eq!(LinkedRow::of_raw(malformed).err(), Some(want));
        let mut stated = row.statement.clone();
        let offset = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        stated[offset..offset + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped::<Store>(&lib, &stated, bind(&dispatcher())).err(),
            Some(LoadError::ManifestKindAbi {
                stated: abi,
                host: real.kind_abi
            })
        );
    }
    for layout in [real.layout ^ 1, 0] {
        // SAFETY: preserve static product pointers, changing layout admission metadata only.
        let door = unsafe { Door::__from_parts(DoorParts { layout, ..real }) };
        MALFORMED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
        let refused = rendering_of_raw(malformed).unwrap_err();
        assert!(matches!(refused, LoadError::KindLayout { .. }), "{refused}");
        assert!(refused
            .to_string()
            .contains("rebuild against this busbar-contract"));
        assert_eq!(LinkedRow::of_raw(malformed).err(), Some(refused.clone()));
        let malformed_row = LinkedRow {
            statement: row.statement.clone(),
            door: malformed,
        };
        assert_eq!(
            load_linked::<Store>(&malformed_row, bind(&dispatcher())).err(),
            Some(refused)
        );
    }
}

#[test]
fn both_actual_doors_refuse_every_other_plugin_kind() {
    use busbar_contract::abi::mechanism::KindCode;
    use busbar_plugin_loader::dispatch::{kinds, LoadError};
    let row = LinkedRow::of(busbar_store_valkey::door).unwrap();
    let lib = cdylib();
    let d = dispatcher();
    assert_eq!(
        load_linked::<kinds::auth::Auth>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Auth
        })
    );
    assert_eq!(
        load_dropped::<kinds::auth::Auth>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Auth
        })
    );
    assert_eq!(
        load_linked::<kinds::export::Export>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Export
        })
    );
    assert_eq!(
        load_dropped::<kinds::export::Export>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Export
        })
    );
    assert_eq!(
        load_linked::<kinds::hook::Hook>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Hook
        })
    );
    assert_eq!(
        load_dropped::<kinds::hook::Hook>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Hook
        })
    );
    assert_eq!(
        load_linked::<kinds::plane::Plane>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Plane
        })
    );
    assert_eq!(
        load_dropped::<kinds::plane::Plane>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Plane
        })
    );
    assert_eq!(
        load_linked::<kinds::secret::Secret>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Secret
        })
    );
    assert_eq!(
        load_dropped::<kinds::secret::Secret>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Secret
        })
    );
    assert_eq!(
        load_linked::<kinds::transport::Transport>(&row, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Transport
        })
    );
    assert_eq!(
        load_dropped::<kinds::transport::Transport>(&lib, &row.statement, bind(&d)).err(),
        Some(LoadError::ManifestKind {
            stated: KindCode::Store,
            want: KindCode::Transport
        })
    );
}

#[path = "support/connection_ownership.rs"]
mod connection_ownership;
#[path = "support/tls_front.rs"]
mod tls_front;

#[test]
fn linked_and_dropped_preserve_every_primitive_operation() {
    let Some(url) = valkey_url() else { return };
    let url = db_url(&url, 14);
    block(async {
        for dropped in [false, true] {
            let _db = database::Database::take(&url);
            let backend = open(dropped, &url).await;
            bootstrap(&backend).await;
            let info = backend.info();
            let address = p::Address {
                namespace: [9; 16],
                key: b"binary".to_vec(),
            };
            let candidate = prepared(
                info,
                2,
                vec![p::Predicate {
                    address: address.clone(),
                    expected: p::ExpectedValue::Absent,
                }],
                vec![p::Mutation::Put {
                    address: address.clone(),
                    value: Secret::new(vec![0, 255]),
                }],
            );
            assert!(matches!(
                backend.commit(candidate.clone()).await.unwrap(),
                p::Decision::Applied(_)
            ));
            assert!(matches!(
                backend.commit(candidate).await.unwrap(),
                p::Decision::Applied(_)
            ));
            assert!(matches!(
                backend
                    .commit(prepared(
                        info,
                        2,
                        vec![],
                        vec![p::Mutation::Delete(address.clone())]
                    ))
                    .await
                    .unwrap(),
                p::Decision::OpIdConflict
            ));
            let scan = |generation| p::Scan {
                dataset: info.dataset,
                namespace: p::NamespaceId([9; 16]),
                prefix: vec![],
                after: None,
                generation,
                allow_change: false,
                max_items: 16,
                max_bytes: 4096,
            };
            let page = backend.scan(Arc::new(scan(None))).await.unwrap();
            assert_eq!(page.rows.len(), 1);
            assert_eq!(page.rows[0].0, address);
            assert!(matches!(
                backend
                    .commit(prepared(
                        info,
                        3,
                        vec![p::Predicate {
                            address: address.clone(),
                            expected: p::ExpectedValue::Exact(Secret::new(vec![1]))
                        }],
                        vec![p::Mutation::Delete(address.clone())]
                    ))
                    .await
                    .unwrap(),
                p::Decision::ConditionConflict
            ));
            assert!(matches!(
                backend
                    .commit(prepared(
                        info,
                        4,
                        vec![],
                        vec![p::Mutation::DeleteRange {
                            namespace: p::NamespaceId([9; 16]),
                            prefix: b"bin".to_vec(),
                            exact_key_length: 6
                        }]
                    ))
                    .await
                    .unwrap(),
                p::Decision::Applied(_)
            ));
            assert!(matches!(
                backend.scan(Arc::new(scan(Some(page.generation)))).await,
                Err(p::Failure::StaleScan)
            ));
            assert!(
                matches!(backend.read(Arc::new(p::Read{dataset:info.dataset,addresses:vec![address],time:None})).await.unwrap(),p::ReadResult::Values{values,..} if values==vec![None])
            );
            assert!(matches!(
                backend.clock(p::DatasetId([0; 16])).await,
                Err(p::Failure::Refused)
            ));
            assert_eq!(
                backend.clock(info.dataset).await.unwrap().authority,
                info.clock_authority
            );
        }
    });
}

#[test]
fn linked_and_dropped_store_use_the_hosts_tls_trust_and_refuse_untrusted_peers() {
    let Some(base) = valkey_url() else { return };
    let backend: url::Url = db_url(&base, 14).parse().unwrap();
    let _db = database::Database::take(backend.as_str());
    let (front, ca) = tls_front::start(&format!(
        "{}:{}",
        backend.host_str().unwrap(),
        backend.port().unwrap_or(6379)
    ));
    let mut url = backend.clone();
    url.set_scheme("rediss").unwrap();
    let (host, port) = front.split_once(':').unwrap();
    url.set_host(Some(host)).unwrap();
    url.set_port(Some(port.parse().unwrap())).unwrap();
    block(async {
        for dropped in [false, true] {
            for trusted in [false, true] {
                let dispatcher = dispatcher();
                let trust = busbar_contract::transport::EgressTrust {
                    extra_anchors: if trusted {
                        vec![ca.clone()]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                };
                let bind = Bind {
                    conns: ConnTable::Host(valkey_io::host(dispatcher.conn_waker(), trust)),
                    ..bind(&dispatcher)
                };
                let plugin = plugin(dropped, bind);
                let result =
                    LoadedPersistence::open(plugin, dispatcher, &settings(url.as_str()), limits())
                        .await;
                if trusted {
                    let backend = result.expect("host trusts supplied CA");
                    backend.clock(backend.info().dataset).await.unwrap();
                } else {
                    assert!(result.is_err(), "untrusted self-signed peer must refuse");
                }
            }
        }
    });
}

/// A genuine successful Valkey OPEN must be closed once when the host's READY fails.
#[test]
fn a_failed_ready_closes_the_actual_opened_valkey_store_once() {
    use busbar_contract::abi::mechanism::call::{AbiStr, Op, OutHead, Outcome, RawOutcome};
    use busbar_contract::abi::mechanism::door::{Door, DoorParts};
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
    static DOOR: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
    static READY: AtomicUsize = AtomicUsize::new(0);
    static CLOSED: AtomicUsize = AtomicUsize::new(0);
    static CLOSE_FAILED: AtomicUsize = AtomicUsize::new(0);
    static CLOSE: std::sync::OnceLock<Op> = std::sync::OnceLock::new();
    extern "C" fn door() -> *const Door {
        DOOR.load(Ordering::SeqCst)
    }
    extern "C" fn ready(_: *mut c_void, _: *const c_void, out: *mut c_void) -> RawOutcome {
        READY.fetch_add(1, Ordering::SeqCst);
        let failed = RawOutcome::of(Outcome::Failed);
        let text = "Valkey test: discovery refused";
        // SAFETY: loader supplies a complete lifecycle output head.
        unsafe {
            (*out.cast::<OutHead>()).outcome = failed;
            (*out.cast::<OutHead>()).error = AbiStr {
                ptr: text.as_ptr(),
                len: text.len(),
            };
        }
        failed
    }
    extern "C" fn close(
        instance: *mut c_void,
        input: *const c_void,
        out: *mut c_void,
    ) -> RawOutcome {
        CLOSED.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the unchanged real instance and host frames go to the original CLOSE once.
        let Some(close) = CLOSE.get() else {
            CLOSE_FAILED.fetch_add(1, Ordering::SeqCst);
            return RawOutcome::of(Outcome::Failed);
        };
        let result = unsafe { close(instance, input, out) };
        if result.outcome() != Outcome::Ready {
            CLOSE_FAILED.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
    let url =
        std::env::var("VALKEY_URL").expect("VALKEY_URL is required for the migrated live suite");
    let mut url: url::Url = url.parse().unwrap();
    url.set_path("/14");
    let _db = database::Database::take(url.as_str());
    // SAFETY: the real door and Ops are complete immutable SDK-owned statics.
    let real = unsafe { Door::read_parts(busbar_store_valkey::door()) };
    let mut ops = unsafe {
        real.ops
            .cast::<busbar_contract::abi::store::v4::Ops>()
            .read_unaligned()
    };
    CLOSE.set(ops.head.close.unwrap()).unwrap();
    ops.head.close = Some(close);
    let ops = Box::leak(Box::new(ops));
    // SAFETY: retain the actual product table with one forwarding cleanup observer and one failing READY input.
    let restated = unsafe {
        Door::__from_parts(DoorParts {
            size: std::mem::size_of::<Door>() as u32,
            ready: Some(ready),
            ops: std::ptr::from_ref(ops).cast(),
            ..real
        })
    };
    DOOR.store(Box::into_raw(Box::new(restated)), Ordering::SeqCst);
    let d = dispatcher();
    let plugin = load_linked::<Store>(&LinkedRow::of_raw(door).unwrap(), bind(&d)).unwrap();
    let held = Arc::clone(&plugin.inner);
    let first = || held.crossings.load(Ordering::SeqCst) - held.resumes.load(Ordering::SeqCst);
    let before = first();
    let error = block(LoadedPersistence::open(
        plugin,
        d,
        &settings(url.as_str()),
        limits(),
    ))
    .expect_err("READY fails");
    assert!(error.to_string().contains("ready failed"), "{error}");
    assert_eq!(READY.load(Ordering::SeqCst), 1);
    assert_eq!(CLOSED.load(Ordering::SeqCst), 1);
    assert_eq!(CLOSE_FAILED.load(Ordering::SeqCst), 0);
    assert_eq!(
        first() - before,
        4,
        "OPEN, metadata RELEASE, failing READY, cleanup CLOSE"
    );
}

#[test]
fn both_actual_valkey_images_complete_a_successful_minimal_lifecycle() {
    use std::sync::atomic::Ordering;
    let Some(base) = valkey_url() else { return };
    let url = db_url(&base, 14);
    let _db = database::Database::take(&url);
    block(async {
        for dropped in [false, true] {
            let dispatcher = dispatcher();
            let plugin = plugin(dropped, bind(&dispatcher));
            assert!(!plugin.has_ready());
            let held = Arc::clone(&plugin.inner);
            let first =
                || held.crossings.load(Ordering::SeqCst) - held.resumes.load(Ordering::SeqCst);
            let before = first();
            let backend = LoadedPersistence::open(plugin, dispatcher, &settings(&url), limits())
                .await
                .unwrap();
            assert_eq!(
                first() - before,
                2,
                "one successful OPEN and metadata RELEASE; optional READY absent"
            );
            let info = backend.info();
            assert!(
                matches!(backend.read(Arc::new(p::Read{dataset:info.dataset,addresses:vec![p::Address{namespace:[9;16],key:b"missing".to_vec()}],time:None})).await.unwrap(),p::ReadResult::Values{values,..} if values==vec![None])
            );
            let before_close = first();
            assert!(before_close > before + 1);
            drop(backend);
            assert_eq!(first() - before_close, 1, "exactly one CLOSE");
        }
    });
}
