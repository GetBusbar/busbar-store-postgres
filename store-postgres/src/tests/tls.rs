// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TLS THROUGH THE HOST, and the KEPT connection, live (ARCHITECT rulings 2026-10-03: TLS,
//! STORE-KEEP).
//!
//! * `sslmode=verify-full` asks the server for TLS (`SSLRequest`), and on its `S` the store secures
//!   the stream through the host (`Wire::upgrade_secure`); here the host is the loader's test table
//!   trusting a CA minted for the run, and the server is an in-test TLS proxy in front of the live
//!   server (it answers the `SSLRequest`, accepts TLS, and forwards the plaintext). A write and a
//!   read round-trip; without the CA the load fails in the driver's words.
//! * The instance keeps ONE connection across its ops (1.5.5's one mutex-guarded connection): every
//!   op of a store runs on the same server backend.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::records::RecordStore;
use busbar_plugin_loader::tcp_conns::TcpConns;

use super::harness::{close_instance, open_loaded_over};
use super::live_url;
use crate::pgwire::Config;

/// A CA and a `localhost` server config it signed: (ca_der, server config).
fn minted() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
    let key = rcgen::KeyPair::generate().expect("key");
    let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("params")
        .signed_by(&key, &issuer)
        .expect("leaf");
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls_pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .expect("server config");
    (ca.der().to_vec(), Arc::new(server))
}

/// Pump bytes both ways between the TLS side and the server until either closes.
fn pump(mut tls: rustls::StreamOwned<rustls::ServerConnection, TcpStream>, mut up: TcpStream) {
    if tls.sock.set_nonblocking(true).is_err() || up.set_nonblocking(true).is_err() {
        return;
    }
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let mut moved = false;
        match tls.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                moved = true;
                if write_all(&mut up, &buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
        match up.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                moved = true;
                if write_all(&mut tls, &buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(_) => return,
        }
        if !moved {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn write_all(w: &mut impl Write, mut b: &[u8]) -> std::io::Result<()> {
    while !b.is_empty() {
        match w.write(b) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(n) => b = &b[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
    loop {
        match w.flush() {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => return Err(e),
        }
    }
}

/// A TLS proxy in front of `upstream` (`host:port`), speaking Postgres's `SSLRequest` opening: its
/// port.
fn tls_proxy(upstream: String, server: Arc<rustls::ServerConfig>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let (server, upstream) = (server.clone(), upstream.clone());
            std::thread::spawn(move || {
                // SSLRequest: length 8, code 80877103.
                let mut req = [0_u8; 8];
                if s.read_exact(&mut req).is_err() || req != [0, 0, 0, 8, 4, 210, 22, 47] {
                    return;
                }
                if s.write_all(b"S").is_err() {
                    return;
                }
                let mut conn = rustls::ServerConnection::new(server).expect("tls conn");
                while conn.is_handshaking() {
                    if conn.complete_io(&mut s).is_err() {
                        return;
                    }
                }
                let Ok(up) = TcpStream::connect(&upstream) else {
                    return;
                };
                pump(rustls::StreamOwned::new(conn, s), up);
            });
        }
    });
    port
}

/// The live server's settings with the proxy in front: `postgres://...@localhost:<port>/...?sslmode=verify-full`.
fn through_proxy(url: &str, port: u16) -> (String, String) {
    let c = Config::parse(url).expect("the live url parses");
    let upstream = format!("{}:{}", c.host, c.port);
    let tls = format!(
        "postgres://{}:{}@localhost:{port}/{}?sslmode=verify-full",
        c.user,
        c.password.clone().unwrap_or_default(),
        c.dbname.clone().unwrap_or_default()
    );
    (upstream, tls)
}

/// TLS: `sslmode=verify-full` through the host's TLS (the test table trusting the run's CA) carries
/// the connect step, a write and a read.
#[test]
fn verify_full_secures_the_connection_through_the_host() {
    let Some(url) = live_url() else { return };
    let (ca_der, server) = minted();
    let (upstream, _) = through_proxy(&url, 0);
    let port = tls_proxy(upstream, server);
    let (_, tls_url) = through_proxy(&url, port);
    let settings = serde_json::json!({ "url": tls_url }).to_string();
    let store = open_loaded_over(&settings, |d| {
        Arc::new(TcpConns::with_roots(d.conn_waker(), &ca_der))
    })
    .expect("the store opens over TLS");
    let sub = format!("tls-{}", std::process::id());
    RecordStore::add_denylist(&store, &sub, "over tls").expect("a write over TLS");
    assert!(
        RecordStore::list_denylist(&store)
            .expect("a read over TLS")
            .contains(&sub),
        "the write is read back over TLS"
    );
    close_instance(&store);
}

/// TLS: a host that does not trust the server's certificate refuses the handshake, and the load
/// fails in the driver's words.
#[test]
fn an_untrusted_server_certificate_fails_the_load_in_the_drivers_words() {
    let Some(url) = live_url() else { return };
    let (_, server) = minted();
    let (upstream, _) = through_proxy(&url, 0);
    let port = tls_proxy(upstream, server);
    let (_, tls_url) = through_proxy(&url, port);
    let settings = serde_json::json!({ "url": tls_url }).to_string();
    // A table with no trust: every upgrade refused.
    let e = open_loaded_over(&settings, |d| Arc::new(TcpConns::new(d.conn_waker())))
        .expect_err("no TLS without trust");
    assert!(
        e.contains("open failed: error performing TLS handshake"),
        "the driver's words: {e}"
    );
}

/// STORE-KEEP: every op of one store runs on the same server backend (one kept connection), and
/// the store holds one connection while idle.
#[test]
fn the_store_keeps_one_connection_across_its_ops() {
    let Some(url) = live_url() else { return };
    let app = format!("bb_keep_{}", std::process::id());
    let sep = if url.contains('?') { '&' } else { '?' };
    let settings =
        serde_json::json!({ "url": format!("{url}{sep}application_name={app}") }).to_string();
    let store = open_loaded_over(&settings, |d| Arc::new(TcpConns::new(d.conn_waker())))
        .expect("the store opens");
    let mut raw = super::connect_client_with_retry(&url);
    let backends = |raw: &mut postgres::Client| -> Vec<i32> {
        raw.query(
            "SELECT pid FROM pg_stat_activity WHERE application_name = $1",
            &[&app],
        )
        .expect("pg_stat_activity")
        .iter()
        .map(|r| r.get(0))
        .collect()
    };
    let after_open = backends(&mut raw);
    assert_eq!(after_open.len(), 1, "the connect step's connection is kept");
    for i in 0..5 {
        RecordStore::add_denylist(&store, &format!("{app}-{i}"), "keep").expect("a write");
        RecordStore::list_denylist(&store).expect("a read");
    }
    assert_eq!(
        backends(&mut raw),
        after_open,
        "every op ran on the one kept backend"
    );
    close_instance(&store);
}
