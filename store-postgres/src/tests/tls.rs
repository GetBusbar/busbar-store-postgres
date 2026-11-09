// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exercises host-provided TLS and reuse of a kept connection.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::native_tests::{address, assert_applied, candidate, open_over, put, read, run, Fixture};
use crate::tests::postgres_io;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::*;
use busbar_contract::persistence::*;
use busbar_contract::transport::{ConnFacts, EgressTrust};

use crate::pgwire::Config;

// Observe only the TLS request made by this store. Socket I/O, ownership, readiness,
// certificate verification and connection security all stay in the production connector.
type TlsFailure = Arc<Mutex<Option<String>>>;
struct TlsRequest {
    host: Arc<dyn DeclaredConns>,
    failure: Option<TlsFailure>,
    verify_off: bool,
}
fn trusting_host(
    wake: ConnWake,
    ca: &[u8],
    failure: Option<TlsFailure>,
    verify_off: bool,
) -> Arc<dyn DeclaredConns> {
    Arc::new(TlsRequest {
        host: postgres_io::host(
            wake,
            EgressTrust {
                extra_anchors: vec![ca.to_vec()],
                ..Default::default()
            },
        ),
        failure,
        verify_off,
    })
}
impl Conns for TlsRequest {
    fn open(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.host.open(owner, need, desc)
    }
    fn write(
        &self,
        owner: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        self.host.write(owner, conn, bytes, end, text)
    }
    fn read(
        &self,
        owner: InstanceId,
        conn: ConnId,
        ticket: u64,
        bytes: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.host.read(owner, conn, ticket, bytes)
    }
    fn wait(&self, owner: InstanceId, conns: &[ConnId], ticket: u64) -> Result<usize, ConnError> {
        self.host.wait(owner, conns, ticket)
    }
    fn facts(&self, owner: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.host.facts(owner, conn)
    }
    fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.host.close(owner, conn)
    }
}
impl DeclaredConns for TlsRequest {
    fn open_request(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        secure: bool,
        timeout: u64,
    ) -> Result<ConnId, ConnError> {
        self.host.open_request(owner, need, desc, secure, timeout)
    }
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        self.host.declare(owner, need, spec, target, trust)
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.host.declared(owner, need)
    }
    fn serves_scheme(&self, scheme: &str) -> bool {
        self.host.serves_scheme(scheme)
    }
    fn landed(&self, owner: InstanceId, conn: ConnId, ticket: u64) -> Result<(), ConnError> {
        self.host.landed(owner, conn, ticket)
    }
    fn cause(&self, owner: InstanceId, conn: ConnId) -> Option<ConnCause> {
        self.host.cause(owner, conn)
    }
    fn upgrade_secure(
        &self,
        owner: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        ticket: u64,
    ) -> Result<(), ConnError> {
        assert_eq!(
            verify_off, self.verify_off,
            "the host must receive the requested TLS verification mode"
        );
        let result = self
            .host
            .upgrade_secure(owner, conn, name, trust, verify_off, ticket);
        if let Err(error) = &result {
            if *error != ConnError::Pending {
                if let Some(failure) = &self.failure {
                    *failure.lock().unwrap() = Some(format!("{error:?}"));
                }
            }
        }
        result
    }
}

/// A CA and a `localhost` server config it signed: (ca_der, server config).
fn minted() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    minted_by("store-postgres test CA")
}

fn minted_by(ca_name: &str) -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, ca_name);
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let issuer = rcgen::Issuer::from_params(&ca_params, ca_key);
    let key = rcgen::KeyPair::generate().expect("key");
    let leaf =
        rcgen::CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
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

/// The live server's settings with the proxy's one listening address in front.
fn through_proxy(url: &str, port: u16) -> (String, String) {
    let c = Config::parse(url).expect("the live url parses");
    let upstream = c.targets()[0].1.clone();
    let tls = dsn_at(url, &[("127.0.0.1", port)], "sslmode=verify-full");
    (upstream, tls)
}

fn dsn_at(live: &str, endpoints: &[(&str, u16)], extra: &str) -> String {
    let hosts: Vec<&str> = endpoints.iter().map(|e| e.0).collect();
    let ports: Vec<String> = endpoints.iter().map(|e| e.1.to_string()).collect();
    let query_value = |text: &str| -> String {
        text.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    if !live.starts_with("postgres://") && !live.starts_with("postgresql://") {
        return format!(
            "{live} host={} port={} {extra}",
            hosts.join(","),
            ports.join(",")
        );
    }
    let mut url = format!(
        "{live}{}host={}&port={}",
        if live.contains('?') { '&' } else { '?' },
        query_value(&hosts.join(",")),
        query_value(&ports.join(","))
    );
    for (key, value) in crate::pgwire::keywords(extra).expect("public fixture options") {
        url.push_str(&format!("&{}={}", query_value(&key), query_value(&value)));
    }
    url
}

#[test]
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn verify_full_secures_primitive_commits_and_reads_through_the_host() {
    let fixture = Fixture::fresh();
    let (ca_der, server) = minted();
    let (upstream, _) = through_proxy(&fixture.url, 0);
    let port = tls_proxy(upstream, server);
    let (_, url) = through_proxy(&fixture.url, port);
    let store = open_over(&url, |dispatcher| {
        trusting_host(dispatcher.conn_waker(), &ca_der, None, false)
    })
    .expect("native door opens over verified TLS");
    let at = address(80, b"tls-primitive");
    let original = candidate(
        &store,
        2,
        1,
        vec![],
        vec![put(at.clone(), b"over tls")],
        None,
    );
    assert_applied(run(store.commit(original)));
    let ReadResult::Values { values, .. } = read(&store, vec![at], None).unwrap() else {
        panic!("native read values")
    };
    assert!(
        values[0].is_some(),
        "the TLS commit is read through the primitive door"
    );
}

#[test]
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn an_untrusted_server_certificate_refuses_the_native_door() {
    let fixture = Fixture::empty();
    let (_, server) = minted_by("store-postgres untrusted issuer");
    let (other_ca, _) = minted_by("store-postgres trusted issuer");
    let (upstream, _) = through_proxy(&fixture.url, 0);
    let port = tls_proxy(upstream, server);
    let (_, url) = through_proxy(&fixture.url, port);
    let failure: TlsFailure = Arc::new(Mutex::new(None));
    assert!(open_over(&url, |dispatcher| trusting_host(
        dispatcher.conn_waker(),
        &other_ca,
        Some(failure.clone()),
        false
    ))
    .is_err());
    assert_eq!(
        failure.lock().unwrap().as_deref(),
        Some("Refused"),
        "the production connector rejects the unknown issuer"
    );
}

#[test]
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn prefer_secures_the_native_door_when_the_server_accepts_tls() {
    let fixture = Fixture::empty();
    let (ca_der, server) = minted();
    let (upstream, _) = through_proxy(&fixture.url, 0);
    let port = tls_proxy(upstream, server);
    let (_, url) = through_proxy(&fixture.url, port);
    let url = url.replace("sslmode=verify-full", "sslmode=prefer");
    let store = open_over(&url, |dispatcher| {
        trusting_host(dispatcher.conn_waker(), &ca_der, None, true)
    })
    .expect("prefer upgrades on the server's S");
    read(&store, vec![address(80, b"not-present")], None).expect("primitive read over TLS");
}

use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Instant;

fn open_loaded(
    settings: &str,
) -> Result<Arc<busbar_plugin_loader::store_v4::LoadedPersistence>, String> {
    open_loaded_over(settings, |dispatcher| {
        postgres_io::host(dispatcher.conn_waker(), Default::default())
    })
}
fn open_loaded_over(
    settings: &str,
    host: impl FnOnce(&Arc<busbar_plugin_loader::dispatch::Dispatcher>) -> Arc<dyn DeclaredConns>,
) -> Result<Arc<busbar_plugin_loader::store_v4::LoadedPersistence>, String> {
    let settings: serde_json::Value =
        serde_json::from_str(settings).map_err(|_| "invalid fixture settings")?;
    open_over(
        settings["url"].as_str().ok_or("fixture url is absent")?,
        host,
    )
}

fn msg(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut m = vec![tag];
    m.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    m.extend_from_slice(body);
    m
}

fn welcome() -> Vec<u8> {
    let mut m = msg(b'R', &0_u32.to_be_bytes());
    m.extend(msg(b'Z', b"I"));
    m
}

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

fn silent_server() -> u16 {
    fake_server(|mut s| {
        let mut b = [0_u8; 1024];
        while s.read(&mut b).is_ok_and(|n| n > 0) {}
    })
}

fn read_startup(s: &mut TcpStream) -> std::io::Result<()> {
    let mut len = [0_u8; 4];
    s.read_exact(&mut len)?;
    let mut rest = vec![0_u8; (u32::from_be_bytes(len) as usize).saturating_sub(4)];
    s.read_exact(&mut rest)
}

fn read_frontend(s: &mut TcpStream) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0_u8; 5];
    s.read_exact(&mut head)?;
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let mut body = vec![0_u8; len.saturating_sub(4)];
    s.read_exact(&mut body)?;
    Ok((head[0], body))
}

fn open_within(settings: String, within: Duration) -> Option<Result<(), String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(open_loaded(&settings).map(drop));
    });
    rx.recv_timeout(within).ok()
}

fn settings_of(dsn: &str) -> String {
    serde_json::json!({ "url": dsn }).to_string()
}

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
    assert_eq!(e, "primitive store open failed");
    let got = seen.lock().unwrap().clone();
    got
}

#[test]
fn plaintext_after_the_servers_s_is_refused_before_the_upgrade() {
    let (ca_der, server) = minted();
    let port = fake_server(move |mut s| {
        let mut req = [0_u8; 8];
        if s.read_exact(&mut req).is_err() {
            return;
        }

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

        let mut tls = rustls::StreamOwned::new(conn, s);
        let _ = tls.read(&mut [0_u8; 1024]);
    });
    // Match fake_server's IPv4 listener; localhost can resolve to IPv6 first.
    let settings = settings_of(&format!(
        "postgres://u:zq9pw@127.0.0.1:{port}/d?sslmode=verify-full"
    ));
    let e = open_loaded_over(&settings, |d| {
        trusting_host(d.conn_waker(), &ca_der, None, false)
    })
    .expect_err("a server that injects plaintext is refused");
    assert!(!e.is_empty());
}

#[test]
fn a_server_that_declines_tls_fails_the_open() {
    let port = fake_server(|mut s| {
        let mut req = [0_u8; 8];
        if s.read_exact(&mut req).is_ok() {
            let _ = s.write_all(b"N");

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
    assert!(!e.is_empty());
}

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
    assert!(!e.is_empty());
}

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
    assert!(!e.is_empty());
    assert_eq!(
        first.load(Ordering::SeqCst),
        196_608,
        "a v3.0 startup, not an SSLRequest"
    );
}

#[test]
fn startup_carries_no_options_of_the_stores_own() {
    assert_eq!(
        startup_options(""),
        "",
        "no `options` in the startup message"
    );
    assert_eq!(
        startup_options("?options=-c%20statement_timeout%3D5000"),
        "-c statement_timeout=5000"
    );
}

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
    assert!(!e.is_empty());
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn an_oversized_authentication_frame_is_refused_at_its_header() {
    let port = fake_server(|mut s| {
        if read_startup(&mut s).is_ok() {
            let mut message = vec![b'R'];
            message.extend_from_slice(&((1_u32 << 30) + 3).to_be_bytes());
            let _ = s.write_all(&message);
            std::thread::sleep(Duration::from_secs(3));
        }
    });
    let error = open_within(
        settings_of(&format!("postgres://u:zq9pw@127.0.0.1:{port}/d")),
        Duration::from_secs(1),
    )
    .expect("header rejected promptly")
    .expect_err("oversized auth frame");
    assert!(!error.is_empty());
}

#[test]
fn a_quoted_password_with_an_escaped_quote_is_scrubbed_whole() {
    let port = fake_server(|mut s| {
        if read_startup(&mut s).is_ok() {
            let _ = s.write_all(&fatal("28P01", "bad password it's tail-of-secret for u"));
        }
    });
    let dsn =
        format!("host=127.0.0.1 port={port} user=u dbname=d password='it\\'s tail-of-secret'");
    let e = open_loaded(&settings_of(&dsn)).expect_err("the server refuses");
    assert!(!e.is_empty());
    assert!(
        !e.contains("tail-of-secret") && !e.contains("it's"),
        "no part of the password survives: {e}"
    );
}

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
    assert!(!e.is_empty());
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(10),
        "bounded by connect_timeout=2: {took:?}"
    );
}

#[test]
fn a_fatal_then_eof_on_a_simple_query_refuses_the_native_open() {
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
    assert!(!e.is_empty());
}

#[test]
fn a_fatal_then_eof_on_a_parse_refuses_the_native_open() {
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
    assert!(!e.is_empty());
}

#[test]
fn the_oracle_url_options_cell_preserves_startup_bytes_and_refuses() {
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
    assert!(!e.is_empty());
    let want: Vec<(String, String)> = [
        ("client_encoding", "UTF8"),
        ("user", "oracle"),
        ("database", "busbar"),
        ("options", "-c statement_timeout=5000"),
        ("application_name", "busbar-oracle"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
    .collect();
    assert_eq!(*sent.lock().unwrap(), want, "the StartupMessage 1.5.5 sent");
}

#[test]
fn an_oversized_parameter_description_is_refused_at_its_header() {
    let port = fake_server(|mut s| {
        if read_startup(&mut s).is_ok()
            && s.write_all(&welcome()).is_ok()
            && read_frontend(&mut s).is_ok()
        {
            let mut message = vec![b't'];
            message.extend_from_slice(&(4 + 2 + 4 * u32::from(u16::MAX) + 1).to_be_bytes());
            let _ = s.write_all(&message);
            std::thread::sleep(Duration::from_secs(3));
        }
    });
    let error = open_within(
        settings_of(&format!("postgres://u:zq9pw@127.0.0.1:{port}/d")),
        Duration::from_secs(1),
    )
    .expect("header rejected promptly")
    .expect_err("oversized parameter description");
    assert!(!error.is_empty());
}

#[path = "auth.rs"]
mod auth;
