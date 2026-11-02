// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TCP interleaving fixture whose sockets and workers retire before database custody ends.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock, RwLockReadGuard};

/// Read-held by every live [`Gate`], write-held by a test that empties the server's script cache
/// (`SCRIPT FLUSH` is server-wide): a gated test warms the cache and then holds a script call, and a
/// flush landing in the gap makes that call answer `NOSCRIPT` and run twice.
pub(super) static SCRIPT_CACHE: RwLock<()> = RwLock::new(());

#[derive(Default)]
struct Connections {
    stopping: AtomicBool,
    sockets: Mutex<Vec<TcpStream>>,
}

impl Connections {
    fn close(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        for socket in self
            .sockets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
        {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

pub(super) struct Proxy {
    pub url: String,
    connections: Arc<Connections>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.connections.close();
        if let Some(worker) = self.worker.take() {
            if let Err(error) = worker.join() {
                if !std::thread::panicking() {
                    std::panic::resume_unwind(error);
                }
            }
        }
    }
}

pub(super) struct Gate {
    _script_cache: RwLockReadGuard<'static, ()>,
    pub url: String,
    pub held: Receiver<()>,
    pub release: Sender<()>,
    proxy: Proxy,
}

impl Gate {
    pub fn spawn<T: Send + 'static>(&self, run: impl FnOnce() -> T + Send + 'static) -> Worker<T> {
        Worker {
            worker: Some(std::thread::spawn(run)),
            release: self.release.clone(),
            connections: self.proxy.connections.clone(),
        }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        let _ = self.release.send(());
    }
}

pub(super) struct Worker<T> {
    worker: Option<std::thread::JoinHandle<T>>,
    release: Sender<()>,
    connections: Arc<Connections>,
}

impl<T> Worker<T> {
    pub fn join(mut self) -> std::thread::Result<T> {
        self.worker.take().expect("operation worker").join()
    }
}

impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.release.send(());
            self.connections.close();
            if let Err(error) = worker.join() {
                if !std::thread::panicking() {
                    std::panic::resume_unwind(error);
                }
            }
        }
    }
}

pub(super) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn repoint(url: &str, addr: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("a tcp url");
    let (auth, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let user = auth.rsplit_once('@').map(|(u, _)| format!("{u}@"));
    format!("{scheme}://{}{addr}/{tail}", user.unwrap_or_default())
}

pub(super) fn upstream_addr(url: &str) -> String {
    let rest = url.split_once("://").expect("a tcp url").1;
    let auth = rest.split(['/', '?']).next().unwrap();
    auth.rsplit_once('@').map_or(auth, |(_, h)| h).to_string()
}

type Hook = Arc<dyn Fn(&[u8]) + Send + Sync>;

fn proxy(valkey_url: &str, before: Hook, after: Hook) -> Proxy {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    let upstream: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(&upstream_addr(valkey_url))
        .expect("resolve upstream")
        .collect();
    let connections = Arc::new(Connections::default());
    let running = connections.clone();
    let worker = std::thread::spawn(move || {
        std::thread::scope(|scope| {
            while !running.stopping.load(Ordering::SeqCst) {
                let mut client = match listener.accept() {
                    Ok((client, _)) => client,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                let mut server = upstream.iter().find_map(|address| {
                    if running.stopping.load(Ordering::SeqCst) {
                        return None;
                    }
                    TcpStream::connect_timeout(address, std::time::Duration::from_secs(10)).ok()
                });
                if running.stopping.load(Ordering::SeqCst) {
                    break;
                }
                let mut server = server.take().expect("upstream");
                {
                    let mut sockets = running.sockets.lock().unwrap();
                    if running.stopping.load(Ordering::SeqCst) {
                        break;
                    }
                    sockets.push(client.try_clone().unwrap());
                    sockets.push(server.try_clone().unwrap());
                }
                let mut back = server.try_clone().unwrap();
                let mut to_client = client.try_clone().unwrap();
                scope.spawn(move || {
                    let mut buf = [0u8; 16384];
                    while let Ok(n @ 1..) = back.read(&mut buf) {
                        if to_client.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    let _ = to_client.shutdown(Shutdown::Both);
                    let _ = back.shutdown(Shutdown::Both);
                });
                let (before, after) = (before.clone(), after.clone());
                scope.spawn(move || {
                    let mut buf = [0u8; 16384];
                    while let Ok(n @ 1..) = client.read(&mut buf) {
                        before(&buf[..n]);
                        if server.write_all(&buf[..n]).is_err() {
                            break;
                        }
                        after(&buf[..n]);
                    }
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = server.shutdown(Shutdown::Both);
                });
            }
        });
    });
    Proxy {
        url: repoint(valkey_url, &addr),
        connections,
        worker: Some(worker),
    }
}

pub(super) fn gate(
    valkey_url: &str,
    before: bool,
    trigger: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
) -> Gate {
    let script_cache = SCRIPT_CACHE.read().unwrap_or_else(|e| e.into_inner());
    let (held_tx, held) = channel();
    let (release, release_rx) = channel();
    let release_rx = Mutex::new(release_rx);
    let held_tx = Mutex::new(held_tx);
    let fired = AtomicBool::new(false);
    let hold: Hook = Arc::new(move |chunk| {
        if trigger(chunk) && !fired.swap(true, Ordering::SeqCst) {
            let _ = held_tx.lock().unwrap().send(());
            let _ = release_rx.lock().unwrap().recv();
        }
    });
    let nop: Hook = Arc::new(|_| {});
    let (b, a) = if before { (hold, nop) } else { (nop, hold) };
    let proxy = proxy(valkey_url, b, a);
    Gate {
        _script_cache: script_cache,
        url: proxy.url.clone(),
        held,
        release,
        proxy,
    }
}

pub(super) fn tamper(
    valkey_url: &str,
    trigger: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    tamper: impl Fn() + Send + Sync + 'static,
) -> Proxy {
    let before: Hook = Arc::new(move |chunk| {
        if trigger(chunk) {
            tamper();
        }
    });
    proxy(valkey_url, before, Arc::new(|_| {}))
}
