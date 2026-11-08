// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]
use busbar_contract::{persistence as p, Secret};
use busbar_plugin_loader::dispatch::{
    kinds::store_v4::StoreV4, load_dropped, load_linked, rendering_of_library, Bind, ConnTable,
    DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
#[path = "../../../test-support/database.rs"]
pub mod database;
#[path = "../../../test-support/valkey_io.rs"]
pub mod valkey_io;
pub fn valkey_url() -> Option<String> {
    match std::env::var("VALKEY_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!("CI requires VALKEY_URL for real Valkey witnesses")
        }
        Err(_) => None,
    }
}
pub fn db_url(base: &str, db: u32) -> String {
    let mut url: url::Url = base.parse().unwrap();
    url.set_path(&format!("/{db}"));
    url.to_string()
}
pub fn cdylib() -> PathBuf {
    let path = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe().unwrap().parent().unwrap().join(
                busbar_plugin_loader::plugin_library_filename("busbar_store_valkey_plugin"),
            )
        });
    assert!(
        path.is_absolute() && path.is_file(),
        "fresh cdylib missing: {}",
        path.display()
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let latest = [
        "store-valkey/src",
        "store-valkey-plugin/src",
        "vendor/rdb-parser/src",
    ]
    .into_iter()
    .map(|dir| latest_source(&root.join(dir)))
    .max()
    .unwrap();
    assert!(
        std::fs::metadata(&path).unwrap().modified().unwrap() >= latest,
        "stale actual cdylib: {}",
        path.display()
    );
    path
}
fn latest_source(directory: &Path) -> std::time::SystemTime {
    let mut latest = std::time::SystemTime::UNIX_EPOCH;
    for entry in std::fs::read_dir(directory).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_none_or(|name| name != "tests") {
                latest = latest.max(latest_source(&path));
            }
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && path.file_name().is_none_or(|name| name != "tests.rs")
        {
            latest = latest.max(entry.metadata().unwrap().modified().unwrap());
        }
    }
    latest
}
pub fn packed_rendering(path: &Path) -> Vec<u8> {
    rendering_of_library(path)
        .unwrap()
        .expect("actual exported door")
}
pub fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ))
}
pub fn bind(dispatcher: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("valkey-native-plugin"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Host(valkey_io::host(dispatcher.conn_waker(), Default::default())),
    }
}
pub fn plugin(dropped: bool, bind: Bind) -> Plugin<StoreV4> {
    if dropped {
        let lib = cdylib();
        load_dropped::<StoreV4>(&lib, &packed_rendering(&lib), bind)
    } else {
        let row = LinkedRow::of(busbar_store_valkey::door).unwrap();
        load_linked::<StoreV4>(&row, bind)
    }
    .unwrap()
}
pub fn linked() -> (Plugin<StoreV4>, Arc<Dispatcher>) {
    let dispatcher = dispatcher();
    (plugin(false, bind(&dispatcher)), dispatcher)
}
pub fn dropped(lib: &Path, stated: &[u8]) -> (Plugin<StoreV4>, Arc<Dispatcher>) {
    let dispatcher = dispatcher();
    (
        load_dropped::<StoreV4>(lib, stated, bind(&dispatcher)).unwrap(),
        dispatcher,
    )
}
pub fn settings(url: &str) -> Vec<u8> {
    serde_json::to_vec(
        &serde_json::json!({"url":url,"input_budget":67108864,"durability":"ephemeral"}),
    )
    .unwrap()
}
pub fn limits() -> Limits {
    Limits {
        descriptor_bytes: 1 << 20,
        output_items: 4096,
        output_bytes: 1 << 20,
        decode_bytes: 1 << 24,
    }
}
pub async fn open(dropped: bool, url: &str) -> LoadedPersistence {
    let dispatcher = dispatcher();
    LoadedPersistence::open(
        plugin(dropped, bind(&dispatcher)),
        dispatcher,
        &settings(url),
        limits(),
    )
    .await
    .expect("actual primitive door opens")
}
pub fn block<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}
pub fn prepared(
    info: p::BackendInfo,
    operation: u8,
    predicates: Vec<p::Predicate>,
    mutations: Vec<p::Mutation>,
) -> p::PreparedCandidate {
    p::PreparedCandidate::new(p::Candidate {
        id: p::AttemptId {
            dataset: info.dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [operation; 16],
        },
        codec: p::CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(b"applied".to_vec()),
    })
    .unwrap()
}
pub async fn bootstrap(backend: &dyn p::PersistenceBackend) {
    let info = backend.info();
    let root = p::Address {
        namespace: p::control::NAMESPACE.0,
        key: p::control::DATASET_KEY.to_vec(),
    };
    let writer = p::Address {
        namespace: p::control::NAMESPACE.0,
        key: p::control::writer_key([2; 16]).to_vec(),
    };
    let candidate = p::Candidate {
        id: p::AttemptId {
            dataset: info.dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [1; 16],
        },
        codec: p::CANDIDATE_VERSION,
        predicates: vec![
            p::Predicate {
                address: root.clone(),
                expected: p::ExpectedValue::Absent,
            },
            p::Predicate {
                address: writer.clone(),
                expected: p::ExpectedValue::Absent,
            },
        ],
        mutations: vec![
            p::Mutation::Put {
                address: root,
                value: Secret::new(
                    p::control::Dataset {
                        id: info.dataset,
                        writer_epoch: 1,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            },
            p::Mutation::Put {
                address: writer,
                value: Secret::new(
                    p::control::Writer {
                        retired_through: 0,
                        admitted_through: 1,
                    }
                    .encode()
                    .unwrap()
                    .to_vec(),
                ),
            },
        ],
        time: None,
        result: Secret::new(vec![]),
    };
    assert!(matches!(
        backend
            .commit(p::PreparedCandidate::new(candidate).unwrap())
            .await
            .unwrap(),
        p::Decision::Applied(_)
    ));
}
