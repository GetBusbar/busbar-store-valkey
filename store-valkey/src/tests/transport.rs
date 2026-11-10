// SPDX-License-Identifier: Apache-2.0
//! Existing connector witnesses exercised through primitive Store calls.
use super::recorded_connector::RecordedConnector;
use super::*;
use busbar_contract::persistence::PersistenceBackend;
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};
fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}
fn live_store() -> Option<()> {
    std::env::var("BUSBAR_V4_TRANSPORT_URL").ok().map(|_| ())
}
fn clock(store: &LoadedPersistence) {
    assert_eq!(
        run(store.clock(store.info().dataset)).unwrap().authority,
        store.info().clock_authority
    );
}
enum Front {
    Tcp,
    Unix(std::path::PathBuf),
    Tls(Arc<rustls::ServerConfig>),
}

/// A proxy in front of the live server.
struct Proxy {
    /// Where the front listens: `127.0.0.1:port`, or the socket path.
    at: String,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    /// Every front connection's socket, to drop them all.
    live: Arc<std::sync::Mutex<Vec<Shut>>>,
}

enum Shut {
    Tcp(std::net::TcpStream),
    Unix(std::os::unix::net::UnixStream),
}

/// The live server's `host:port`, database and userinfo, as `VALKEY_URL` names them.
fn live_parts() -> (String, i64, String) {
    let url = std::env::var("BUSBAR_V4_TRANSPORT_URL").expect("BUSBAR_V4_TRANSPORT_URL");
    let u = url::Url::parse(&url).expect("VALKEY_URL parses");
    let addr = format!(
        "{}:{}",
        u.host_str().expect("a host"),
        u.port().unwrap_or(6379)
    );
    let db = u.path().trim_matches('/').parse().unwrap_or(0);
    let userinfo = match (u.username(), u.password()) {
        ("", None) => String::new(),
        (user, Some(p)) => format!("{user}:{p}@"),
        (user, None) => format!("{user}@"),
    };
    (addr, db, userinfo)
}

/// Copy `from` to `to` until either ends.
fn pump(mut from: impl std::io::Read, mut to: impl std::io::Write) {
    let mut buf = [0_u8; 16 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() || to.flush().is_err() {
                    return;
                }
            }
        }
    }
}

impl Proxy {
    fn start(front: Front) -> Self {
        let (backend, _, _) = live_parts();
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let live = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (count, held) = (accepted.clone(), live.clone());
        let at = match front {
            Front::Unix(path) => {
                let _ = std::fs::remove_file(&path);
                let l = std::os::unix::net::UnixListener::bind(&path).expect("bind the socket");
                std::thread::spawn(move || {
                    for s in l.incoming() {
                        let Ok(s) = s else { return };
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        held.lock()
                            .unwrap()
                            .push(Shut::Unix(s.try_clone().unwrap()));
                        let b = std::net::TcpStream::connect(&backend).expect("the live server");
                        let (s2, b2) = (s.try_clone().unwrap(), b.try_clone().unwrap());
                        std::thread::spawn(move || pump(s, b));
                        std::thread::spawn(move || pump(b2, s2));
                    }
                });
                path.display().to_string()
            }
            Front::Tcp | Front::Tls(_) => {
                let tls = match front {
                    Front::Tls(c) => Some(c),
                    _ => None,
                };
                let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
                let at = l.local_addr().unwrap().to_string();
                std::thread::spawn(move || {
                    for s in l.incoming() {
                        let Ok(s) = s else { return };
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        held.lock().unwrap().push(Shut::Tcp(s.try_clone().unwrap()));
                        let b = std::net::TcpStream::connect(&backend).expect("the live server");
                        match &tls {
                            None => {
                                let (s2, b2) = (s.try_clone().unwrap(), b.try_clone().unwrap());
                                std::thread::spawn(move || pump(s, b));
                                std::thread::spawn(move || pump(b2, s2));
                            }
                            Some(config) => {
                                let conn = rustls::ServerConnection::new(config.clone()).unwrap();
                                std::thread::spawn(move || tls_pump(conn, s, b));
                            }
                        }
                    }
                });
                at
            }
        };
        Self { at, accepted, live }
    }

    /// How many connections the store made.
    fn accepted(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Drop every connection the store holds (a server going away under it).
    fn drop_all(&self) {
        for s in self.live.lock().unwrap().drain(..) {
            match s {
                Shut::Tcp(t) => {
                    let _ = t.shutdown(std::net::Shutdown::Both);
                }
                Shut::Unix(u) => {
                    let _ = u.shutdown(std::net::Shutdown::Both);
                }
            }
        }
    }
}

/// TLS-terminate `front` and forward the plaintext to `back` (one TLS stream, two directions).
fn tls_pump(conn: rustls::ServerConnection, front: std::net::TcpStream, back: std::net::TcpStream) {
    use std::io::{Read, Write};
    front
        .set_read_timeout(Some(std::time::Duration::from_millis(5)))
        .unwrap();
    let tls = Arc::new(std::sync::Mutex::new(rustls::StreamOwned::new(conn, front)));
    let (t2, mut b2) = (tls.clone(), back.try_clone().unwrap());
    std::thread::spawn(move || {
        let mut buf = [0_u8; 16 * 1024];
        loop {
            match b2.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let mut t = t2.lock().unwrap();
                    if t.write_all(&buf[..n]).is_err() || t.flush().is_err() {
                        return;
                    }
                }
            }
        }
    });
    let mut back = back;
    let mut buf = [0_u8; 16 * 1024];
    loop {
        let got = tls.lock().unwrap().read(&mut buf);
        match got {
            Ok(0) => return,
            Ok(n) => {
                if back.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(_) => return,
        }
    }
}

/// The store's door opened on `settings` on a dispatcher of its own, over the connection table
/// `table` builds; the table too, to read what it was asked.
fn open_on(
    settings: &str,
    table: impl FnOnce(&Dispatcher) -> RecordedConnector,
) -> (Result<LoadedPersistence, String>, Arc<RecordedConnector>) {
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let t = Arc::new(table(&d));
    let row =
        LinkedRow::of_kind::<StoreV4>(crate::door as busbar_contract::abi::mechanism::door::DoorFn)
            .unwrap();
    let p = load_linked::<StoreV4>(
        &row,
        Bind {
            instance: Arc::from("valkey-transport"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::Host(
                busbar_contract::conn::admissions::AdmissionAuthority::issue(
                    &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
                    t.clone(),
                    busbar_contract::secret_ref::Sugars::default(),
                ),
            ),
        },
    )
    .unwrap();
    let mut settings: serde_json::Value = serde_json::from_str(settings).unwrap();
    settings["input_budget"] = 67108864.into();
    settings["durability"] = "ephemeral".into();
    let limits = Limits {
        descriptor_bytes: 1 << 20,
        output_items: 1 << 20,
        output_bytes: 1 << 24,
        decode_bytes: 1 << 25,
    };
    let result = run(LoadedPersistence::open(
        p,
        d,
        &serde_json::to_vec(&settings).unwrap(),
        limits,
    ));
    (result, t)
}
fn plain(d: &Dispatcher) -> RecordedConnector {
    RecordedConnector::new(d.conn_waker())
}
fn trusting_nothing(d: &Dispatcher) -> RecordedConnector {
    RecordedConnector::new(d.conn_waker())
}
fn settings_for(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}
fn tls_server() -> (Arc<rustls::ServerConfig>, Vec<u8>) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    (Arc::new(config), ca.der().to_vec())
}
fn self_signed_tls_server() -> Arc<rustls::ServerConfig> {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .unwrap();
    Arc::new(config)
}

#[test]
fn the_store_keeps_one_connection_across_ops() {
    if live_store().is_none() {
        return;
    }
    let proxy = Proxy::start(Front::Tcp);
    let (_, db, userinfo) = live_parts();
    let (store, _) = open_on(
        &settings_for(&format!("redis://{userinfo}{}/{db}", proxy.at)),
        plain,
    );
    let store = store.expect("opens through the proxy");
    clock(&store);
    clock(&store);
    clock(&store);
    assert_eq!(
        proxy.accepted(),
        1,
        "the open and every op share one kept connection"
    );
}

#[test]
fn a_unix_socket_url_reaches_the_server() {
    if live_store().is_none() {
        return;
    }
    let (_, db, _) = live_parts();
    let dir = std::env::temp_dir().join(format!("vk-unix-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (n, scheme) in ["redis+unix", "unix", "valkey+unix"].iter().enumerate() {
        let path = dir.join(format!("s{n}.sock"));
        let proxy = Proxy::start(Front::Unix(path.clone()));
        let (store, _) = open_on(
            &settings_for(&format!("{scheme}://{}?db={db}", proxy.at)),
            plain,
        );
        let store = store.unwrap_or_else(|e| panic!("{scheme}: {e}"));
        clock(&store);
        clock(&store);
        assert_eq!(proxy.accepted(), 1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn connect_timeout_ms_is_the_dial_timeout() {
    if live_store().is_none() {
        return;
    }
    let url = std::env::var("BUSBAR_V4_TRANSPORT_URL").unwrap();
    let (store, table) = open_on(
        &serde_json::json!({ "url": url, "connect_timeout_ms": 1234 }).to_string(),
        plain,
    );
    clock(&store.expect("opens"));
    assert_eq!(table.dial_timeouts(), vec![1234]);
    let (store, table) = open_on(&settings_for(&url), plain);
    clock(&store.expect("opens"));
    assert_eq!(table.dial_timeouts(), vec![10_000]);
    let (store, _) = open_on(
        &serde_json::json!({ "url": url, "connect_timeout_ms": 0 }).to_string(),
        plain,
    );
    assert!(!store
        .expect_err("a zero timeout refuses the load")
        .is_empty());
}

#[test]
fn a_rediss_url_is_secured_through_the_hosts_connector() {
    if live_store().is_none() {
        return;
    }
    let (config, ca) = tls_server();
    let proxy = Proxy::start(Front::Tls(config));
    let port = proxy.at.rsplit_once(':').unwrap().1.to_string();
    let (_, db, userinfo) = live_parts();
    let url = format!("rediss://{userinfo}127.0.0.1:{port}/{db}");
    let (store, _) = open_on(&settings_for(&url), |d| {
        RecordedConnector::with_trust(
            d.conn_waker(),
            busbar_contract::transport::EgressTrust {
                extra_anchors: vec![ca.clone()],
                ..Default::default()
            },
        )
    });
    let store = store.expect("opens over TLS");
    clock(&store);
    clock(&store);
    assert_eq!(proxy.accepted(), 1, "one secured connection, kept");

    let (untrusted, table) = open_on(&settings_for(&url), trusting_nothing);
    let err = untrusted.expect_err("the TLS certificate must be trusted");
    let tls_cause = table
        .security_failure()
        .expect("the actual connector retains the security failure");
    assert_eq!(
        tls_cause.stage,
        busbar_contract::abi::host::conn::connector::CAUSE_SECURITY
    );
    assert_eq!(
        tls_cause.text,
        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer).to_string()
    );
    let tls_error = Some(tls_cause.text);
    assert!(
        tls_error
            .as_deref()
            .is_some_and(|error| error.contains("UnknownIssuer")),
        "the refusal must be certificate verification: {tls_error:?}; host refusal: {err}"
    );
    assert!(!err.is_empty());
}

#[test]
fn rediss_insecure_skips_certificate_verification() {
    if live_store().is_none() {
        return;
    }
    let proxy = Proxy::start(Front::Tls(self_signed_tls_server()));
    let port = proxy.at.rsplit_once(':').unwrap().1.to_string();
    let (_, db, userinfo) = live_parts();
    let verified = format!("rediss://{userinfo}127.0.0.1:{port}/{db}");
    let (refused, _) = open_on(&settings_for(&verified), trusting_nothing);
    let err = refused.expect_err("a self-signed certificate is not trusted");
    assert!(!err.is_empty());
    let (store, _) = open_on(
        &settings_for(&format!("{verified}#insecure")),
        trusting_nothing,
    );
    let store = store.expect("#insecure accepts the self-signed certificate");
    clock(&store);
    clock(&store);
    assert_eq!(
        proxy.accepted(),
        2,
        "the refused dial, then one kept connection"
    );
}

#[test]
fn a_dropped_connection_is_discarded_before_the_next_primitive_call() {
    if live_store().is_none() {
        return;
    }
    let proxy = Proxy::start(Front::Tcp);
    let (_, db, userinfo) = live_parts();
    let (store, _) = open_on(
        &settings_for(&format!("redis://{userinfo}{}/{db}", proxy.at)),
        plain,
    );
    let store = store.expect("opens");
    clock(&store);
    proxy.drop_all();
    assert!(run(store.clock(store.info().dataset)).is_err());
    clock(&store);
    assert_eq!(proxy.accepted(), 2, "the next primitive call dials fresh");
}
