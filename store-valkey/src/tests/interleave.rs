// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A deterministic interleaving seam: a TCP proxy in front of the live Valkey that PAUSES one
//! client right after it sends a command naming a trigger, until the test releases it. The test
//! runs another writer to completion in the gap.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

/// A running gate: `url` is the `VALKEY_URL` pointed at the proxy.
pub(super) struct Gate {
    pub url: String,
    /// Fires once, when the trigger command has been forwarded and the client is held.
    pub held: Receiver<()>,
    /// Releases the held client.
    pub release: Sender<()>,
}

pub(super) fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// The authority of `url` swapped for `addr`.
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

/// A proxy to the Valkey at `valkey_url`: `before` runs on each client chunk ahead of forwarding it,
/// `after` right after. Returns the proxy's address.
fn proxy(valkey_url: &str, before: Hook, after: Hook) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap().to_string();
    let upstream = upstream_addr(valkey_url);
    std::thread::spawn(move || {
        for client in listener.incoming() {
            let Ok(mut client) = client else { return };
            let mut server = TcpStream::connect(&upstream).expect("upstream");
            let mut back = server.try_clone().unwrap();
            let mut to_client = client.try_clone().unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 16384];
                while let Ok(n @ 1..) = back.read(&mut buf) {
                    if to_client.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
            let (before, after) = (before.clone(), after.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 16384];
                while let Ok(n @ 1..) = client.read(&mut buf) {
                    before(&buf[..n]);
                    if server.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    after(&buf[..n]);
                }
            });
        }
    });
    addr
}

/// Hold the first client that sends a chunk `trigger` accepts until `release`: before
/// forwarding that chunk when `before`, else right after it.
pub(super) fn gate(
    valkey_url: &str,
    before: bool,
    trigger: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
) -> Gate {
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
    let addr = proxy(valkey_url, b, a);
    Gate {
        url: repoint(valkey_url, &addr),
        held,
        release,
    }
}

/// A proxy that runs `tamper` ahead of every client chunk `trigger` accepts; the proxy's url.
pub(super) fn tamper(
    valkey_url: &str,
    trigger: impl Fn(&[u8]) -> bool + Send + Sync + 'static,
    tamper: impl Fn() + Send + Sync + 'static,
) -> String {
    let before: Hook = Arc::new(move |chunk| {
        if trigger(chunk) {
            tamper();
        }
    });
    let addr = proxy(valkey_url, before, Arc::new(|_| {}));
    repoint(valkey_url, &addr)
}
