// SPDX-License-Identifier: Apache-2.0
//! A TLS terminator in front of the actual Valkey integration service, with a private CA.
use std::io::{Read, Write};
use std::sync::Arc;

pub fn start(upstream: &str) -> (String, Vec<u8>) {
    let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let ca = certificate.cert.der().to_vec();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls_pki_types::CertificateDer::from(
                certificate.cert.der().to_vec(),
            )],
            rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
                certificate.signing_key.serialize_der(),
            )),
        )
        .unwrap();
    let config = Arc::new(config);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let upstream = upstream.to_owned();
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(socket) = incoming else { return };
            let config = Arc::clone(&config);
            let upstream = upstream.clone();
            std::thread::spawn(move || {
                let mut server = rustls::StreamOwned::new(
                    rustls::ServerConnection::new(config).unwrap(),
                    socket,
                );
                while server.conn.is_handshaking() {
                    if server.conn.complete_io(&mut server.sock).is_err() {
                        return;
                    }
                }
                let Ok(mut backend) = std::net::TcpStream::connect(upstream) else {
                    return;
                };
                server.sock.set_nonblocking(true).unwrap();
                backend.set_nonblocking(true).unwrap();
                let mut buffer = [0_u8; 16 * 1024];
                loop {
                    for from_client in [true, false] {
                        let read = if from_client {
                            server.read(&mut buffer)
                        } else {
                            backend.read(&mut buffer)
                        };
                        match read {
                            Ok(0) => return,
                            Ok(n) => {
                                // Response/request bursts are bounded by this test's small records.
                                let result = if from_client {
                                    backend.set_nonblocking(false).unwrap();
                                    backend
                                        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                                        .unwrap();
                                    let result = backend.write_all(&buffer[..n]);
                                    backend.set_nonblocking(true).unwrap();
                                    result
                                } else {
                                    server.sock.set_nonblocking(false).unwrap();
                                    server
                                        .sock
                                        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
                                        .unwrap();
                                    let result = server
                                        .write_all(&buffer[..n])
                                        .and_then(|()| server.flush());
                                    server.sock.set_nonblocking(true).unwrap();
                                    result
                                };
                                if result.is_err() {
                                    return;
                                }
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                            Err(_) => return,
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            });
        }
    });
    (format!("127.0.0.1:{port}"), ca)
}
