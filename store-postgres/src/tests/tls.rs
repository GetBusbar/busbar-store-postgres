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
//! * The connect path against fake servers and the live one: a hostile or silent server, the connect
//!   timeout, endpoint failover and `target_session_attrs`.
//! * The instance keeps ONE connection across its ops (1.5.5's one mutex-guarded connection): every
//!   op of a store runs on the same server backend.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::records::RecordStore;
use busbar_test_kit::tcp_conns::{SecureDial, SecuredSock, TcpConns};

use super::harness::open_loaded_over;
use super::live_url;
use crate::pgwire::Config;

/// The host's TLS for the test table ([`TcpConns::with_tls`]): rustls trusting `ca_der` alone,
/// verifying the certificate and the name; the handshake runs to completion on the blocking socket
/// the table hands it.
struct Trusting(Arc<rustls::ClientConfig>);

fn trusting(ca_der: &[u8]) -> Arc<dyn SecureDial> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls_pki_types::CertificateDer::from(ca_der.to_vec()))
        .expect("the test CA is a root certificate");
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    Arc::new(Trusting(Arc::new(config)))
}

impl SecureDial for Trusting {
    fn secure(
        &self,
        server: &str,
        _verify_off: bool,
        mut tcp: TcpStream,
    ) -> std::io::Result<Box<dyn SecuredSock>> {
        let name = rustls_pki_types::ServerName::try_from(server.to_owned())
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
        let mut tls = rustls::ClientConnection::new(Arc::clone(&self.0), name)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
        while tls.is_handshaking() {
            tls.complete_io(&mut tcp)?;
        }
        Ok(Box::new(Secured(rustls::StreamOwned::new(tls, tcp))))
    }
}

/// A stream [`Trusting`] secured.
struct Secured(rustls::StreamOwned<rustls::ClientConnection, TcpStream>);

impl Read for Secured {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}

impl Write for Secured {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl SecuredSock for Secured {
    fn tcp(&self) -> &TcpStream {
        self.0.get_ref()
    }
    fn close(&mut self) {
        self.0.conn.send_close_notify();
        let _ = self.0.flush();
        let _ = self.0.sock.shutdown(std::net::Shutdown::Both);
    }
}

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
    let upstream = c.targets()[0].1.clone();
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
        Arc::new(TcpConns::with_tls(d.conn_waker(), trusting(&ca_der)))
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
    // Dropping the store closes its instance, and its kept connection with it.
    drop(store);
    let gone = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(20));
        backends(&mut raw).is_empty()
    });
    assert!(gone, "closing the instance closes its kept connection");
}

// ── the connect path against servers that misbehave ─────────────────────────────────────────

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Instant;

use busbar_contract::abi::sdk::store::OpRefused;
use busbar_contract::abi::store::OpId;

use super::harness::{open_loaded, TestStore};

/// One backend message: tag, length, body.
fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![tag];
    m.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    m.extend_from_slice(body);
    m
}

/// `AuthenticationOk` and `ReadyForQuery`: a server that lets anyone in.
fn welcome() -> Vec<u8> {
    let mut m = msg(b'R', &0_u32.to_be_bytes());
    m.extend(msg(b'Z', b"I"));
    m
}

/// A FATAL `ErrorResponse` with SQLSTATE `code`.
fn fatal(code: &str, text: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (tag, v) in [(b'S', "FATAL"), (b'C', code), (b'M', text)] {
        body.push(tag);
        body.extend_from_slice(v.as_bytes());
        body.push(0);
    }
    body.push(0);
    msg(b'E', &body)
}

/// Serve every connection on a thread running `handler`: the port.
fn fake_server(handler: impl Fn(TcpStream) + Send + Sync + 'static) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("addr").port();
    let handler = Arc::new(handler);
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(s) = s else { return };
            let handler = handler.clone();
            std::thread::spawn(move || handler(s));
        }
    });
    port
}

/// A server that accepts the connection and never answers it.
fn silent_server() -> u16 {
    fake_server(|mut s| {
        let mut b = [0_u8; 1024];
        while s.read(&mut b).is_ok_and(|n| n > 0) {}
    })
}

/// The StartupMessage a client opens with (no SSLRequest), read whole.
fn read_startup(s: &mut TcpStream) -> std::io::Result<()> {
    let mut len = [0_u8; 4];
    s.read_exact(&mut len)?;
    let mut rest = vec![0_u8; (u32::from_be_bytes(len) as usize).saturating_sub(4)];
    s.read_exact(&mut rest)
}

/// One frontend message after startup: (tag, body).
fn read_frontend(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0_u8; 5];
    s.read_exact(&mut head)?;
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let mut body = vec![0_u8; len.saturating_sub(4)];
    s.read_exact(&mut body)?;
    Ok((head[0], body))
}

/// A server that answers the extended-protocol `SHOW transaction_read_only` with `value`, counting
/// the statements it was sent (`shows`) and every other one (`others`).
fn read_only_server(value: &'static str, shows: Arc<AtomicUsize>, others: Arc<AtomicUsize>) -> u16 {
    fake_server(move |mut s| {
        if read_startup(&mut s).is_err() || s.write_all(&welcome()).is_err() {
            return;
        }
        let (mut sql, mut bound) = (String::new(), false);
        while let Ok((tag, body)) = read_frontend(&mut s) {
            match tag {
                b'P' => {
                    // Parse: the statement name, then the query text.
                    let text = &body[body.iter().position(|b| *b == 0).unwrap_or(0) + 1..];
                    sql = String::from_utf8_lossy(
                        &text[..text.iter().position(|b| *b == 0).unwrap_or(0)],
                    )
                    .into_owned();
                    if sql.starts_with("SHOW") {
                        shows.fetch_add(1, Ordering::SeqCst);
                    } else {
                        others.fetch_add(1, Ordering::SeqCst);
                    }
                }
                b'Q' => {
                    others.fetch_add(1, Ordering::SeqCst);
                    let mut out = msg(b'C', b"OK\0");
                    out.extend(msg(b'Z', b"I"));
                    if s.write_all(&out).is_err() {
                        return;
                    }
                }
                b'B' => bound = true,
                b'S' => {
                    let mut out = Vec::new();
                    if bound {
                        out.extend(msg(b'2', b""));
                        let mut row = 1_i16.to_be_bytes().to_vec();
                        row.extend_from_slice(&(value.len() as i32).to_be_bytes());
                        row.extend_from_slice(value.as_bytes());
                        out.extend(msg(b'D', &row));
                        out.extend(msg(b'C', b"SHOW\0"));
                        bound = false;
                    } else {
                        out.extend(msg(b'1', b""));
                        out.extend(msg(b't', &0_i16.to_be_bytes()));
                        let mut col = b"transaction_read_only\0".to_vec();
                        col.extend_from_slice(&0_i32.to_be_bytes());
                        col.extend_from_slice(&0_i16.to_be_bytes());
                        col.extend_from_slice(&25_i32.to_be_bytes());
                        col.extend_from_slice(&(-1_i16).to_be_bytes());
                        col.extend_from_slice(&(-1_i32).to_be_bytes());
                        col.extend_from_slice(&0_i16.to_be_bytes());
                        let mut rd = 1_i16.to_be_bytes().to_vec();
                        rd.extend(col);
                        out.extend(msg(b'T', &rd));
                    }
                    out.extend(msg(b'Z', b"I"));
                    if s.write_all(&out).is_err() {
                        return;
                    }
                }
                _ => {}
            }
        }
        let _ = sql;
    })
}

/// Open the store on `settings` on a thread, so a connect that never returns FAILS the test
/// instead of hanging it: the open's result, or `None` past `within`.
fn open_within(settings: String, within: Duration) -> Option<Result<(), String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(open_loaded(&settings).map(drop));
    });
    rx.recv_timeout(within).ok()
}

/// A keyword connection string for the live server's credentials at `endpoints` (host, port),
/// with `extra` options.
fn dsn_at(live: &str, endpoints: &[(&str, u16)], extra: &str) -> String {
    let c = Config::parse(live).expect("the live url parses");
    let hosts: Vec<&str> = endpoints.iter().map(|e| e.0).collect();
    let ports: Vec<String> = endpoints.iter().map(|e| e.1.to_string()).collect();
    format!(
        "host={} port={} user='{}' password='{}' dbname='{}' {extra}",
        hosts.join(","),
        ports.join(","),
        c.user,
        c.password.clone().unwrap_or_default(),
        c.dbname.clone().unwrap_or_default()
    )
}

/// The live server's (host, port).
fn live_endpoint(live: &str) -> (String, u16) {
    let c = Config::parse(live).expect("the live url parses");
    let target = c.targets()[0].1.clone();
    let (h, p) = target.rsplit_once(':').expect("host:port");
    (h.to_string(), p.parse().expect("port"))
}

fn settings_of(dsn: &str) -> String {
    serde_json::json!({ "url": dsn }).to_string()
}

/// D8 (RED before: the plaintext that followed the server's `S` stayed in the client's buffer, the
/// host's upgrade guard looked only at the wire's input, and startup parsed it as TLS-protected):
/// a server that answers the SSLRequest with `S` and an authentication-ok in ONE write is refused
/// before the upgrade (CVE-2021-23222).
#[test]
fn plaintext_after_the_servers_s_is_refused_before_the_upgrade() {
    let (ca_der, server) = minted();
    let port = fake_server(move |mut s| {
        let mut req = [0_u8; 8];
        if s.read_exact(&mut req).is_err() {
            return;
        }
        // "S" and the injected AuthenticationOk + ReadyForQuery in ONE write.
        let mut first = b"S".to_vec();
        first.extend(welcome());
        if s.write_all(&first).is_err() {
            return;
        }
        let mut conn = rustls::ServerConnection::new(server.clone()).expect("tls conn");
        while conn.is_handshaking() {
            if conn.complete_io(&mut s).is_err() {
                return;
            }
        }
        // Read what the client sends first, then close: nothing here answers the startup.
        let mut tls = rustls::StreamOwned::new(conn, s);
        let _ = tls.read(&mut [0_u8; 1024]);
    });
    let settings = settings_of(&format!(
        "postgres://u:zq9pw@localhost:{port}/d?sslmode=verify-full"
    ));
    let e = open_loaded_over(&settings, |d| {
        Arc::new(TcpConns::with_tls(d.conn_waker(), trusting(&ca_der)))
    })
    .expect_err("a server that injects plaintext is refused");
    assert!(
        e.contains("server sent unencrypted data after accepting TLS"),
        "{e}"
    );
}

/// B9 (RED by mutation: fall back to plaintext on any answer): a server that answers the
/// SSLRequest with `N` fails the open, it is not talked to in the clear.
#[test]
fn a_server_that_declines_tls_fails_the_open() {
    let port = fake_server(|mut s| {
        let mut req = [0_u8; 8];
        if s.read_exact(&mut req).is_ok() {
            let _ = s.write_all(b"N");
            // A plaintext fallback would send its startup next; answer it so a fallback connects.
            if read_startup(&mut s).is_ok() {
                let _ = s.write_all(&welcome());
                let _ = read_frontend(&mut s);
            }
        }
    });
    let e = open_loaded(&settings_of(&format!(
        "postgres://u:zq9pw@127.0.0.1:{port}/d?sslmode=require"
    )))
    .expect_err("no TLS, no connection");
    assert!(e.contains("server does not support TLS"), "{e}");
}

/// `sslmode=prefer` asks with an SSLRequest and, on the server's `N`, goes on to the startup in
/// plaintext (libpq); the open then fails only on the server's own refusal.
#[test]
fn prefer_continues_in_plaintext_when_the_server_answers_n() {
    let port = fake_server(|mut s| {
        let mut req = [0_u8; 8];
        if s.read_exact(&mut req).is_ok() && req == [0, 0, 0, 8, 4, 210, 22, 47] {
            let _ = s.write_all(b"N");
            if read_startup(&mut s).is_ok() {
                let _ = s.write_all(&fatal("3D000", "no such database"));
            }
        }
    });
    let e = open_loaded(&settings_of(&format!(
        "postgres://u:zq9pw@127.0.0.1:{port}/d?sslmode=prefer"
    )))
    .expect_err("the fake server refuses the startup");
    assert!(e.contains("3D000"), "plaintext startup followed the N: {e}");
}

/// `sslmode=allow` is plaintext: no SSLRequest is sent, the first message is the startup.
#[test]
fn allow_sends_no_sslrequest() {
    let first = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let seen = first.clone();
    let port = fake_server(move |mut s| {
        let mut head = [0_u8; 8];
        if s.read_exact(&mut head).is_ok() {
            seen.store(
                u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
                Ordering::SeqCst,
            );
            let _ = s.write_all(&fatal("3D000", "no such database"));
        }
    });
    let e = open_loaded(&settings_of(&format!(
        "postgres://u:zq9pw@127.0.0.1:{port}/d?sslmode=allow"
    )))
    .expect_err("the fake server refuses the startup");
    assert!(e.contains("3D000"), "{e}");
    assert_eq!(
        first.load(Ordering::SeqCst),
        196_608,
        "a v3.0 startup, not an SSLRequest"
    );
}

/// `sslmode=prefer` against a server that answers `S` secures the connection.
#[test]
fn prefer_secures_the_connection_when_the_server_answers_s() {
    let Some(url) = live_url() else { return };
    let (ca_der, server) = minted();
    let (upstream, _) = through_proxy(&url, 0);
    let port = tls_proxy(upstream, server);
    let (_, tls_url) = through_proxy(&url, port);
    let tls_url = tls_url.replace("sslmode=verify-full", "sslmode=prefer");
    let settings = serde_json::json!({ "url": tls_url }).to_string();
    let store = open_loaded_over(&settings, |d| {
        Arc::new(TcpConns::with_tls(d.conn_waker(), trusting(&ca_der)))
    })
    .expect("prefer upgrades over the proxy's S");
    RecordStore::list_denylist(&store).expect("a read over TLS");
}

/// The startup options a plaintext client sends a server that refuses it.
fn startup_options(dsn_query: &str) -> String {
    let seen = Arc::new(std::sync::Mutex::new(String::new()));
    let sink = seen.clone();
    let port = fake_server(move |mut s| {
        let mut len = [0_u8; 4];
        if s.read_exact(&mut len).is_err() {
            return;
        }
        let mut rest = vec![0_u8; (u32::from_be_bytes(len) as usize).saturating_sub(4)];
        if s.read_exact(&mut rest).is_err() {
            return;
        }
        let parts: Vec<&[u8]> = rest[4..].split(|b| *b == 0).collect();
        for kv in parts.chunks(2) {
            if kv[0] == b"options" {
                *sink.lock().unwrap() = String::from_utf8_lossy(kv[1]).into_owned();
            }
        }
        let _ = s.write_all(&fatal("3D000", "no such database"));
    });
    let e = open_loaded(&settings_of(&format!(
        "postgres://u:zq9pw@127.0.0.1:{port}/d{dsn_query}"
    )))
    .expect_err("the fake server refuses the startup");
    assert!(e.contains("3D000"), "{e}");
    let got = seen.lock().unwrap().clone();
    got
}

/// A stalled peer holding a row lock must not block the fleet forever: the store asks for a lock
/// timeout and an idle-in-transaction timeout at startup, unless the DSN sets its own.
#[test]
fn startup_asks_for_lock_and_idle_in_transaction_timeouts() {
    let o = startup_options("");
    assert!(o.contains("-c lock_timeout=30s"), "{o}");
    assert!(
        o.contains("-c idle_in_transaction_session_timeout=60s"),
        "{o}"
    );
    let o = startup_options("?options=-c%20lock_timeout%3D5s");
    assert!(
        o.contains("lock_timeout=5s") && !o.contains("lock_timeout=30s"),
        "{o}"
    );
    assert!(o.contains("idle_in_transaction_session_timeout=60s"), "{o}");
}

/// A peer that is not Postgres (an HTTP error page) declares a message length of ~1.3 GiB; the
/// client refuses it by its header, naming the length, rather than waiting to buffer it.
#[test]
fn an_oversized_declared_message_length_is_refused() {
    let port = fake_server(|mut s| {
        let mut b = [0_u8; 1024];
        if s.read(&mut b).is_ok() {
            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            std::thread::sleep(Duration::from_secs(5));
        }
    });
    let started = Instant::now();
    let e = open_within(
        settings_of(&format!("postgres://u:zq9pw@127.0.0.1:{port}/d")),
        Duration::from_secs(4),
    )
    .expect("the open returned promptly")
    .expect_err("not a Postgres server");
    assert!(
        e.contains("protocol error") && e.contains("1414811695"),
        "{e}"
    );
    assert!(started.elapsed() < Duration::from_secs(4));
}

/// D37 (RED before: `connect_timeout` was ignored, `Wire::bound` never called, and a server that
/// accepts TCP and never answers held the instance's one connection forever): the dial AND the
/// handshake are bounded, and the failure is the connection's timeout.
#[test]
fn connect_timeout_bounds_a_server_that_never_answers() {
    let port = silent_server();
    let started = Instant::now();
    let settings = settings_of(&format!(
        "postgres://u:zq9pw@127.0.0.1:{port}/d?connect_timeout=2"
    ));
    let got = open_within(settings, Duration::from_secs(20))
        .expect("the open returned: connect_timeout bounds the handshake");
    let e = got.expect_err("a silent server never completes the handshake");
    let took = started.elapsed();
    assert!(
        e.contains("deadline passed"),
        "the connection's timeout, not another failure: {e}"
    );
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(10),
        "bounded by connect_timeout=2: {took:?}"
    );
}

/// D37/B2 (RED before: the first endpoint's handshake hung): the first endpoint accepts and stays
/// silent, the second is the live server; the open moves on after the bound passes, which needs the
/// bound lifted before the first connection is closed (a passed bound answers `close` too).
#[test]
fn an_endpoint_that_times_out_hands_over_to_the_next() {
    let Some(url) = live_url() else { return };
    let silent = silent_server();
    let (host, port) = live_endpoint(&url);
    let dsn = dsn_at(
        &url,
        &[("127.0.0.1", silent), (&host, port)],
        "connect_timeout=2",
    );
    let started = Instant::now();
    let got = open_within(settings_of(&dsn), Duration::from_secs(30))
        .expect("the open returned: a silent endpoint does not hold the connect");
    got.expect("the second endpoint answered");
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "the first endpoint was given its bound"
    );
}

/// D37: `connect_timeout` bounds a NEW connection's dial and handshake, never the wait for the
/// instance's one kept connection. Op A holds it longer than the timeout (blocked on a row lock);
/// op B queued behind it still succeeds.
#[test]
fn an_op_queued_behind_a_long_one_is_not_cut_by_connect_timeout() {
    let Some(url) = live_url() else { return };
    let sep = if url.contains('?') { '&' } else { '?' };
    let store = TestStore::open(&format!("{url}{sep}connect_timeout=1")).expect("the store opens");
    let sub = format!("bb_hold_{}", std::process::id());
    let mut raw = super::connect_client_with_retry(&url);
    raw.batch_execute("BEGIN").expect("begin");
    raw.execute(
        "INSERT INTO denylist (sub, reason, created_at) VALUES ($1, 'held', 0)
         ON CONFLICT (sub) DO NOTHING",
        &[&sub],
    )
    .expect("hold the row");
    std::thread::scope(|scope| {
        let a = scope.spawn(|| RecordStore::add_denylist(&*store, &sub, "blocked behind the lock"));
        std::thread::sleep(Duration::from_millis(300));
        let b = scope.spawn(|| RecordStore::list_denylist(&*store));
        std::thread::sleep(Duration::from_millis(2500));
        raw.batch_execute("COMMIT").expect("release the row");
        a.join().unwrap().expect("op A finished");
        b.join()
            .unwrap()
            .expect("op B, queued longer than connect_timeout, still ran");
    });
    raw.batch_execute(&format!("DELETE FROM denylist WHERE sub = '{sub}'"))
        .expect("cleanup");
}

/// D12 (RED before: failover covered the dial only): an endpoint that accepts and then refuses the
/// startup (57P03, the server starting up) hands over to the next.
#[test]
fn a_startup_refusal_moves_on_to_the_next_endpoint() {
    let Some(url) = live_url() else { return };
    let starting = fake_server(|mut s| {
        if read_startup(&mut s).is_ok() {
            let _ = s.write_all(&fatal("57P03", "the database system is starting up"));
        }
    });
    let (host, port) = live_endpoint(&url);
    let dsn = dsn_at(&url, &[("127.0.0.1", starting), (&host, port)], "");
    open_loaded(&settings_of(&dsn)).expect("the second endpoint accepted the connection");
    // All endpoints refusing: every endpoint's failure is in the error, host and port named.
    let a = fake_server(|mut s| {
        if read_startup(&mut s).is_ok() {
            let _ = s.write_all(&fatal("57P03", "first starting up"));
        }
    });
    let b = fake_server(|mut s| {
        if read_startup(&mut s).is_ok() {
            let _ = s.write_all(&fatal("53300", "last: too many connections"));
        }
    });
    let e = open_loaded(&settings_of(&format!(
        "host=127.0.0.1,127.0.0.1 port={a},{b} user=u password=zq9pw dbname=d"
    )))
    .expect_err("every endpoint refused");
    assert!(
        e.contains(&format!("127.0.0.1:{a}: 57P03")) && e.contains(&format!("127.0.0.1:{b}: 53300")),
        "every endpoint's error: {e}"
    );
    assert!(!e.contains("zq9pw"), "{e}");
}

/// D10 (RED before: `target_session_attrs` was ignored): `read-write` refuses a server that is
/// read-only for the session, `read-only` one that is not.
#[test]
fn target_session_attrs_refuses_a_server_of_the_wrong_kind() {
    let Some(url) = live_url() else { return };
    let (host, port) = live_endpoint(&url);
    let e = open_loaded(&settings_of(&dsn_at(
        &url,
        &[(&host, port)],
        "target_session_attrs=read-write options='-c default_transaction_read_only=on'",
    )))
    .expect_err("a read-only session is refused for read-write");
    assert!(e.contains("does not allow writes"), "{e}");
    let e = open_loaded(&settings_of(&dsn_at(
        &url,
        &[(&host, port)],
        "target_session_attrs=read-only",
    )))
    .expect_err("a writable session is refused for read-only");
    assert!(e.contains("is not read-only"), "{e}");
    open_loaded(&settings_of(&dsn_at(
        &url,
        &[(&host, port)],
        "target_session_attrs=read-write",
    )))
    .expect("a writable server satisfies read-write");
}

/// D10: a standby listed first is passed over for the primary (the failover the attribute exists
/// for): the first endpoint answers `on`, the second is the live server.
#[test]
fn a_read_only_first_endpoint_is_passed_over_for_read_write() {
    let Some(url) = live_url() else { return };
    let (shows, others) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let standby = read_only_server("on", shows.clone(), others.clone());
    let (host, port) = live_endpoint(&url);
    let dsn = dsn_at(
        &url,
        &[("127.0.0.1", standby), (&host, port)],
        "target_session_attrs=read-write",
    );
    open_loaded(&settings_of(&dsn)).expect("the primary took the connection");
    assert!(shows.load(Ordering::SeqCst) >= 1, "the standby was asked");
    assert_eq!(
        others.load(Ordering::SeqCst),
        0,
        "nothing but the session check ran on the standby"
    );
}

/// D25 (RED before: an ErrorResponse followed by EOF read as "connection closed" and the server's
/// reason was dropped): a FATAL answer to the first simple query (the migration's advisory lock)
/// surfaces the server's SQLSTATE and message.
#[test]
fn a_fatal_then_eof_on_a_simple_query_surfaces_the_servers_reason() {
    let port = fake_server(|mut s| {
        if read_startup(&mut s).is_err() || s.write_all(&welcome()).is_err() {
            return;
        }
        if read_frontend(&mut s).is_ok() {
            let _ = s.write_all(&fatal(
                "57P01",
                "terminating connection due to administrator command",
            ));
        }
    });
    let e = open_loaded(&settings_of(&format!(
        "postgres://u:zq9pw@127.0.0.1:{port}/d"
    )))
    .expect_err("the server shut the session down");
    assert!(
        e.contains("57P01") && e.contains("administrator command"),
        "{e}"
    );
}

/// D25, the extended protocol's first round (`run`): the FATAL answers the Parse, and the drain
/// that follows hits EOF; the original error is the one reported.
#[test]
fn a_fatal_then_eof_on_a_parse_surfaces_the_servers_reason() {
    let port = fake_server(|mut s| {
        if read_startup(&mut s).is_err() || s.write_all(&welcome()).is_err() {
            return;
        }
        while let Ok((tag, _)) = read_frontend(&mut s) {
            match tag {
                b'Q' => {
                    let mut out = msg(b'C', b"OK\0");
                    out.extend(msg(b'Z', b"I"));
                    if s.write_all(&out).is_err() {
                        return;
                    }
                }
                b'P' => {
                    let _ = s.write_all(&fatal(
                        "57P01",
                        "terminating connection due to administrator command",
                    ));
                    return;
                }
                _ => {}
            }
        }
    });
    let e = open_loaded(&settings_of(&format!(
        "postgres://u:zq9pw@127.0.0.1:{port}/d"
    )))
    .expect_err("the server shut the session down");
    assert!(
        e.contains("57P01") && e.contains("administrator command"),
        "{e}"
    );
}

/// D44 (RED before: a transaction dropped uncommitted, as an `op_id` conflict leaves it, made the
/// session non-idle, the kept connection was discarded and the next op dialled TCP+TLS+SCRAM
/// afresh): after a refused op the next op runs on the same backend.
#[test]
fn a_refused_op_keeps_the_connection() {
    let Some(url) = live_url() else { return };
    let app = format!("bb_refuse_{}", std::process::id());
    let sep = if url.contains('?') { '&' } else { '?' };
    let store = TestStore::open(&format!("{url}{sep}application_name={app}")).expect("opens");
    let mut raw = super::connect_client_with_retry(&url);
    let backend = |raw: &mut postgres::Client| -> Vec<(i32, String)> {
        raw.query(
            "SELECT pid, backend_start::text FROM pg_stat_activity WHERE application_name = $1",
            &[&app],
        )
        .expect("pg_stat_activity")
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
    };
    let op = || {
        static N: AtomicUsize = AtomicUsize::new(0);
        let node = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        OpId::from_parts(node, N.fetch_add(1, Ordering::Relaxed) as u64)
    };
    let delta = |requests: i64| busbar_contract::records::UsageDelta {
        requests,
        ..Default::default()
    };
    let id = op();
    store
        .add_usage_op(id, &app, 4_000_000_000_000_002, &delta(1))
        .expect("applied");
    let before = backend(&mut raw);
    assert_eq!(before.len(), 1, "one kept connection: {before:?}");
    assert_eq!(
        store.add_usage_op(id, &app, 4_000_000_000_000_002, &delta(2)),
        Err(OpRefused::Conflict),
        "the same op_id with another body is refused"
    );
    store.record_get(&app, b"k").expect("the next op");
    assert_eq!(
        backend(&mut raw),
        before,
        "the refused op and the op after it ran on the one backend"
    );
}

/// B3: a failover DSN whose first endpoint is down keeps the connection that the second gave:
/// the next op asks for that endpoint first and reuses the kept connection, instead of dialling
/// the first, finding the kept connection is for another target and evicting it.
#[test]
fn a_failover_dsn_keeps_the_endpoint_that_connected() {
    let Some(url) = live_url() else { return };
    // A port nothing listens on: bound, then released.
    let dead = TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    let app = format!("bb_failover_{}", std::process::id());
    let (host, port) = live_endpoint(&url);
    let dsn = dsn_at(
        &url,
        &[("127.0.0.1", dead), (&host, port)],
        &format!("application_name={app}"),
    );
    let store = TestStore::open(&dsn).expect("the second endpoint answered");
    let mut raw = super::connect_client_with_retry(&url);
    let backends = |raw: &mut postgres::Client| -> Vec<(i32, String)> {
        raw.query(
            "SELECT pid, backend_start::text FROM pg_stat_activity WHERE application_name = $1",
            &[&app],
        )
        .expect("pg_stat_activity")
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
    };
    let after_open = backends(&mut raw);
    assert_eq!(after_open.len(), 1, "one connection after the open");
    for i in 0..3 {
        RecordStore::add_denylist(&*store, &format!("{app}-{i}"), "failover").expect("a write");
    }
    assert_eq!(
        backends(&mut raw),
        after_open,
        "every op ran on the connection the open kept"
    );
}

/// Oracle cell `store.boot|postgres|url-options` (RED before: `keepalives` was refused at parse,
/// so the boot never dialed): the cell's exact URL, against a server that answers its startup as
/// the oracle's mock does (FATAL 28000), reaches the dial, sends the StartupMessage 1.5.5 sent,
/// and fails on the server's refusal, as 1.5.5's boot did (1.5.5 printed `db error`; this store
/// names the SQLSTATE and the server's message).
#[test]
fn the_oracle_url_options_cell_dials_and_fails_with_the_servers_refusal() {
    let sent = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
    let seen = sent.clone();
    let port = fake_server(move |mut s| {
        let mut len = [0_u8; 4];
        if s.read_exact(&mut len).is_err() {
            return;
        }
        let mut rest = vec![0_u8; (u32::from_be_bytes(len) as usize).saturating_sub(4)];
        if s.read_exact(&mut rest).is_err() {
            return;
        }
        let mut it = rest[4..]
            .split(|b| *b == 0)
            .map(|x| String::from_utf8_lossy(x).into_owned());
        let mut params = Vec::new();
        while let (Some(k), Some(v)) = (it.next(), it.next()) {
            if k.is_empty() {
                break;
            }
            params.push((k, v));
        }
        *seen.lock().unwrap() = params;
        let _ = s.write_all(&fatal("28000", "oracle capture: no database here"));
    });
    let url = format!(
        "postgres://oracle:oracle-pw@127.0.0.1:{port}/busbar?application_name=busbar-oracle\
         &options=-c%20statement_timeout%3D5000&connect_timeout=5&keepalives=1\
         &target_session_attrs=any"
    );
    let e = open_within(settings_of(&url), Duration::from_secs(20))
        .expect("the open finished")
        .expect_err("the server refused the startup");
    assert!(
        e.contains("28000") && e.contains("no database here") && !e.contains("oracle-pw"),
        "{e}"
    );
    let want: Vec<(String, String)> = [
        ("client_encoding", "UTF8"),
        ("user", "oracle"),
        ("database", "busbar"),
        (
            "options",
            "-c statement_timeout=5000 -c lock_timeout=30s \
             -c idle_in_transaction_session_timeout=60s",
        ),
        ("application_name", "busbar-oracle"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
    .collect();
    assert_eq!(
        *sent.lock().unwrap(),
        want,
        "the StartupMessage 1.5.5 sent, plus the store's own server timeouts"
    );
}
