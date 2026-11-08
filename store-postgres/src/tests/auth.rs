// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The real loaded store's authentication caller over the host connection table. The wrapper
//! observes only the initialized slice lent to write, forces short writes and Pending, and
//! never keeps a credential pointer or a copy of the offered bytes.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use crate::tests::postgres_io;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnWake, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
};
use busbar_contract::transport::ConnFacts;

use super::open_loaded_over;
use super::{fake_server, fatal, msg, read_frontend, read_startup, settings_of};
use std::io::{Read, Write};
use std::time::Duration;

#[derive(Default)]
struct Counts {
    short: AtomicUsize,
    pending: AtomicUsize,
    closed: AtomicUsize,
}

#[derive(Default)]
struct Progress {
    auth_left: usize,
    auth_written: usize,
    pended: bool,
}

struct PartialConns {
    inner: Arc<dyn busbar_contract::conn::DeclaredConns>,
    wake: ConnWake,
    counts: Arc<Counts>,
    progress: Mutex<Progress>,
    fault: bool,
}

impl Conns for PartialConns {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        *self.progress.lock().unwrap() = Progress::default();
        self.inner.open(caller, need, desc)
    }

    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        let mut progress = self.progress.lock().unwrap();
        if progress.auth_left == 0 && bytes.first() == Some(&b'p') {
            progress.auth_left = bytes.len();
            progress.auth_written = 0;
            progress.pended = false;
        }

        if progress.auth_left > 0 && progress.auth_written >= 6 && !progress.pended {
            progress.pended = true;
            if self.fault {
                return Err(ConnError::Fault);
            }
            self.counts.pending.fetch_add(1, Ordering::Relaxed);
            return Err(ConnError::Pending);
        }
        let offered = bytes.len().min(3);
        let written = self.inner.write(
            caller,
            conn,
            &bytes[..offered],
            end && offered == bytes.len(),
            text,
        )?;
        if offered < bytes.len() {
            self.counts.short.fetch_add(1, Ordering::Relaxed);
        }
        if progress.auth_left > 0 {
            progress.auth_left -= written;
            progress.auth_written += written;
        }
        Ok(written)
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.inner.read(caller, conn, ticket, buf)
    }

    fn wait(&self, caller: InstanceId, _set: &[ConnId], ticket: u64) -> Result<usize, ConnError> {
        let wake = self.wake.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1));
            wake(caller, ticket);
        });
        Err(ConnError::Pending)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.inner.facts(caller, conn)
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.counts.closed.fetch_add(1, Ordering::Relaxed);
        self.inner.close(caller, conn)
    }
}

impl DeclaredConns for PartialConns {
    fn open_request(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        *self.progress.lock().unwrap() = Progress::default();
        self.inner
            .open_request(owner, need, desc, require_secure, dial_timeout_ms)
    }

    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        self.inner.declare(owner, need, spec, target, trust)
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.inner.declared(owner, need)
    }

    fn landed(&self, owner: InstanceId, conn: ConnId, ticket: u64) -> Result<(), ConnError> {
        self.inner.landed(owner, conn, ticket)
    }
    fn cause(&self, owner: InstanceId, conn: ConnId) -> Option<busbar_contract::conn::ConnCause> {
        self.inner.cause(owner, conn)
    }
    fn serves_scheme(&self, scheme: &str) -> bool {
        self.inner.serves_scheme(scheme)
    }
}

fn loaded(settings: &str, fault: bool) -> (String, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let observed = counts.clone();
    let error = open_loaded_over(settings, |dispatcher| {
        let wake = dispatcher.conn_waker();
        Arc::new(PartialConns {
            inner: postgres_io::host(wake.clone(), Default::default()),
            wake,
            counts: observed,
            progress: Mutex::new(Progress::default()),
            fault,
        })
    })
    .expect_err("the scripted peer ends the connect with a refusal");
    assert!(
        error.contains("postgres v4 connection unavailable"),
        "native errors remain content-free: {error}"
    );
    (error, counts)
}

fn request(code: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = code.to_be_bytes().to_vec();
    body.extend_from_slice(payload);
    msg(b'R', &body)
}

/// Credential messages remain byte-for-byte PostgreSQL frames under partial host writes and a
/// parked write.
#[test]
fn cleartext_and_md5_frames_survive_partial_and_pending_host_writes() {
    for (method, code, salt) in [("password", 3, Vec::new()), ("md5", 5, vec![1, 2, 3, 4])] {
        let (tx, rx) = mpsc::channel();
        let port = fake_server(move |mut socket| {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            read_startup(&mut socket).unwrap();
            socket.write_all(&request(code, &salt)).unwrap();
            let frame = read_frontend(&mut socket).unwrap();
            tx.send(frame).unwrap();
            socket.write_all(&request(0, &[])).unwrap();
            socket
                .write_all(&fatal("57P03", "authentication-complete"))
                .unwrap();
        });
        let settings = settings_of(&format!(
            "host=127.0.0.1 port={port} user=wire-user password=sealed-wire-secret require_auth={method} connect_timeout=3"
        ));
        let (error, counts) = loaded(&settings, false);
        assert!(!error.is_empty());
        assert!(!error.contains("sealed-wire-secret"));
        let (tag, body) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut expected = if method == "password" {
            b"sealed-wire-secret".to_vec()
        } else {
            postgres_protocol::authentication::md5_hash(
                b"wire-user",
                b"sealed-wire-secret",
                [1, 2, 3, 4],
            )
            .into_bytes()
        };
        expected.push(0);
        assert_eq!((tag, body), (b'p', expected));
        assert!(counts.short.load(Ordering::Relaxed) > 0);
        assert_eq!(counts.pending.load(Ordering::Relaxed), 1);
        assert!(counts.closed.load(Ordering::Relaxed) > 0);
    }
}

#[test]
fn the_signed_default_floor_refuses_cleartext_and_md5_before_a_password_write() {
    for (code, payload) in [(3, Vec::new()), (5, vec![1, 2, 3, 4])] {
        let (tx, rx) = mpsc::channel();
        let port = fake_server(move |mut socket| {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            read_startup(&mut socket).unwrap();
            socket.write_all(&request(code, &payload)).unwrap();
            let mut offered = [0_u8; 8];
            tx.send(socket.read(&mut offered).unwrap()).unwrap();
        });
        let settings = settings_of(&format!(
            "postgres://wire-user:sealed-wire-secret@127.0.0.1:{port}/db?connect_timeout=3"
        ));
        let (error, counts) = loaded(&settings, false);
        assert!(!error.is_empty());
        assert!(!error.contains("sealed-wire-secret"));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
        assert_eq!(counts.pending.load(Ordering::Relaxed), 0);
    }
}

/// A failed write after a credential prefix cannot return the half-authenticated socket to the
/// kept pool.
#[test]
fn a_partial_authentication_write_failure_discards_the_connection() {
    let (tx, rx) = mpsc::channel();
    let port = fake_server(move |mut socket| {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_startup(&mut socket).unwrap();
        socket.write_all(&request(3, &[])).unwrap();
        let mut prefix = Vec::new();
        socket.read_to_end(&mut prefix).unwrap();
        tx.send(prefix).unwrap();
    });
    let settings = settings_of(&format!(
        "host=127.0.0.1 port={port} user=u password=sealed-wire-secret require_auth=password connect_timeout=3"
    ));
    for _ in 0..2 {
        let (error, counts) = loaded(&settings, true);
        assert!(!error.is_empty());
        assert!(counts.closed.load(Ordering::Relaxed) > 0);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"p\0\0\0\x17s"
        );
    }
}

/// The nonce is fresh on reconnect, n,, remains the unsupported channel-binding header even
/// when PLUS is offered, and the peer must prove the password before AuthenticationOk is read.
#[test]
fn scram_uses_a_fresh_nonce_and_rejects_an_invalid_server_verifier() {
    let (tx, rx) = mpsc::channel();
    let port = fake_server(move |mut socket| {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_startup(&mut socket).unwrap();
        socket
            .write_all(&request(10, b"SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0"))
            .unwrap();
        let (tag, initial) = read_frontend(&mut socket).unwrap();
        assert_eq!(tag, b'p');
        let prefix = b"SCRAM-SHA-256\0";
        assert!(initial.starts_with(prefix));
        let declared =
            u32::from_be_bytes(initial[prefix.len()..prefix.len() + 4].try_into().unwrap())
                as usize;
        let first = std::str::from_utf8(&initial[prefix.len() + 4..]).unwrap();
        assert_eq!(declared, first.len());
        let nonce = first.strip_prefix("n,,n=,r=").unwrap();
        assert!(!nonce.is_empty() && !nonce.contains(','));
        let server_first = format!("r={nonce}server-extension,s=QUJD,i=4096");
        socket
            .write_all(&request(11, server_first.as_bytes()))
            .unwrap();
        let (tag, final_body) = read_frontend(&mut socket).unwrap();
        assert_eq!(tag, b'p');
        let final_text = std::str::from_utf8(&final_body).unwrap();
        let proof = final_text
            .strip_prefix(&format!("c=biws,r={nonce}server-extension,p="))
            .unwrap();
        assert_eq!(proof.len(), 44);
        assert!(!final_text.contains("sealed-wire-secret"));
        tx.send(nonce.to_owned()).unwrap();

        let mut tail = request(12, b"v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        tail.extend(request(0, &[]));
        tail.extend(fatal("57P03", "must-not-be-reached"));
        socket.write_all(&tail).unwrap();
    });
    let settings = settings_of(&format!(
        "postgres://wire-user:sealed-wire-secret@127.0.0.1:{port}/db?connect_timeout=3"
    ));
    let mut nonces = Vec::new();
    for _ in 0..2 {
        let (error, counts) = loaded(&settings, false);
        assert!(!error.is_empty());
        assert!(!error.contains("must-not-be-reached"));
        assert!(counts.pending.load(Ordering::Relaxed) >= 2);
        assert!(counts.closed.load(Ordering::Relaxed) > 0);
        nonces.push(rx.recv_timeout(Duration::from_secs(5)).unwrap());
    }
    assert_ne!(nonces[0], nonces[1]);
}

#[test]
fn malformed_scram_continue_and_wrong_authentication_stage_write_no_proof() {
    for server_first in [
        Some("r=wrong-nonce,s=QUJD,i=4096"),
        Some("r={nonce}server,s=QUJD,i=4096,i=4096"),
        Some("r={nonce}server,s=QUJD,i=100001"),
        Some("r={nonce}server,s=QUJD,i=0"),
        Some("r={nonce}server,s=QUJD,i=01"),
        None,
    ] {
        let (tx, rx) = mpsc::channel();
        let port = fake_server(move |mut socket| {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            read_startup(&mut socket).unwrap();
            socket
                .write_all(&request(10, b"SCRAM-SHA-256\0\0"))
                .unwrap();
            let (_, initial) = read_frontend(&mut socket).unwrap();
            let first = std::str::from_utf8(&initial[b"SCRAM-SHA-256\0".len() + 4..]).unwrap();
            let nonce = first.strip_prefix("n,,n=,r=").unwrap();
            let next = server_first.map_or_else(
                || request(0, &[]),
                |first| request(11, first.replace("{nonce}", nonce).as_bytes()),
            );
            socket.write_all(&next).unwrap();
            let mut unexpected = [0_u8; 8];
            tx.send(socket.read(&mut unexpected).unwrap()).unwrap();
        });
        let (error, _) = loaded(
            &settings_of(&format!(
                "postgres://u:sealed-wire-secret@127.0.0.1:{port}/db?connect_timeout=3"
            )),
            false,
        );
        assert!(!error.is_empty());
        assert!(!error.contains("sealed-wire-secret"));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    }
}

/// Valid legacy configurations below 4096 keep working through the PostgreSQL-specific recipe;
/// the generic SDK recipe's minimum does not silently become this caller's policy.
#[test]
fn valid_legacy_scram_iteration_counts_reach_the_proof_write() {
    for iterations in [1, 4095] {
        let (tx, rx) = mpsc::channel();
        let port = fake_server(move |mut socket| {
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            read_startup(&mut socket).unwrap();
            socket
                .write_all(&request(10, b"SCRAM-SHA-256\0\0"))
                .unwrap();
            let (_, initial) = read_frontend(&mut socket).unwrap();
            let first = std::str::from_utf8(&initial[b"SCRAM-SHA-256\0".len() + 4..]).unwrap();
            let nonce = first.strip_prefix("n,,n=,r=").unwrap();
            socket
                .write_all(&request(
                    11,
                    format!("r={nonce}server,s=QUJD,i={iterations}").as_bytes(),
                ))
                .unwrap();
            let (tag, proof) = read_frontend(&mut socket).unwrap();
            tx.send(tag == b'p' && proof.starts_with(b"c=biws,r="))
                .unwrap();
            socket.write_all(&request(12, b"e=invalid-proof")).unwrap();
        });
        let (error, _) = loaded(
            &settings_of(&format!(
                "postgres://u:sealed-wire-secret@127.0.0.1:{port}/db?connect_timeout=3"
            )),
            false,
        );
        assert!(!error.is_empty());
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
    }
}

#[test]
fn startup_parameters_keep_their_public_wire_encoding_and_order() {
    let (tx, rx) = mpsc::channel();
    let port = fake_server(move |mut socket| {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut length = [0_u8; 4];
        socket.read_exact(&mut length).unwrap();
        let mut body = vec![0_u8; u32::from_be_bytes(length) as usize - 4];
        socket.read_exact(&mut body).unwrap();
        tx.send(body).unwrap();
        socket
            .write_all(&fatal("57P03", "startup-observed"))
            .unwrap();
    });
    let settings = settings_of(&format!(
        "host=127.0.0.1 port={port} user=wire-user password=sealed-wire-secret dbname=db application_name=wire-app options='-c statement_timeout=7' connect_timeout=3"
    ));
    let (error, _) = loaded(&settings, false);
    assert!(!error.is_empty());
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        b"\0\x03\0\0client_encoding\0UTF8\0user\0wire-user\0database\0db\0options\0-c statement_timeout=7\0application_name\0wire-app\0\0"
    );
}

#[test]
fn a_nul_password_is_refused_before_a_cleartext_frame_is_written() {
    let (tx, rx) = mpsc::channel();
    let port = fake_server(move |mut socket| {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        read_startup(&mut socket).unwrap();
        socket.write_all(&request(3, &[])).unwrap();
        let mut unexpected = [0_u8; 8];
        tx.send(socket.read(&mut unexpected).unwrap()).unwrap();
    });
    let (error, _) = loaded(
        &settings_of(&format!(
            "postgres://u:before%00after@127.0.0.1:{port}/db?require_auth=password&connect_timeout=3"
        )),
        false,
    );
    assert!(!error.is_empty());
    assert!(!error.contains("before") && !error.contains("after"));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
}

#[test]
fn an_explicit_authentication_floor_can_refuse_an_unauthenticated_server() {
    let port = fake_server(move |mut socket| {
        read_startup(&mut socket).unwrap();
        socket.write_all(&super::welcome()).unwrap();
    });
    let (error, _) = loaded(
        &settings_of(&format!(
            "postgres://u:sealed-wire-secret@127.0.0.1:{port}/db?require_auth=scram-sha-256&connect_timeout=3"
        )),
        false,
    );
    assert!(!error.is_empty());
}
