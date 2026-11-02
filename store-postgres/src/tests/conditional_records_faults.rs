// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnWake, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
};
use busbar_contract::transport::ConnFacts;
use busbar_test_kit::tcp_conns::TcpConns;
use std::sync::Mutex;

#[derive(Default)]
struct Gate {
    armed: bool,
    held: Option<(InstanceId, ConnId, u64)>,
    lost: bool,
}
pub(in crate::tests) struct WithheldCommit {
    tcp: TcpConns,
    wake: ConnWake,
    gate: Mutex<Gate>,
}
impl WithheldCommit {
    pub(in crate::tests) fn new(wake: ConnWake) -> Self {
        Self {
            tcp: TcpConns::new(wake.clone()),
            wake,
            gate: Mutex::new(Gate::default()),
        }
    }
    pub(in crate::tests) fn arm(&self) {
        self.gate.lock().unwrap().armed = true;
    }
    pub(in crate::tests) fn is_held(&self) -> bool {
        self.gate.lock().unwrap().held.is_some()
    }
    pub(in crate::tests) fn lose_reply(&self) {
        let held = {
            let mut gate = self
                .gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            gate.lost = true;
            gate.held
        };
        if let Some((owner, conn, ticket)) = held {
            let _ = self.tcp.close(owner, conn);
            (self.wake)(owner, ticket);
        }
    }
}
impl Conns for WithheldCommit {
    fn open(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.tcp.open(owner, need, desc)
    }
    fn write(
        &self,
        owner: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        let n = self.tcp.write(owner, conn, bytes, end, text)?;
        if bytes.first() == Some(&b'Q') && bytes.get(5..) == Some(b"COMMIT\0") && n == bytes.len() {
            let mut gate = self.gate.lock().unwrap();
            if gate.armed {
                gate.held = Some((owner, conn, 0));
            }
        }
        Ok(n)
    }
    fn read(
        &self,
        owner: InstanceId,
        conn: ConnId,
        ticket: u64,
        bytes: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let mut gate = self.gate.lock().unwrap();
        if gate.held.is_some_and(|(o, c, _)| o == owner && c == conn) {
            gate.held = Some((owner, conn, ticket));
            return Err(if gate.lost {
                ConnError::Closed
            } else {
                ConnError::Pending
            });
        }
        drop(gate);
        self.tcp.read(owner, conn, ticket, bytes)
    }
    fn wait(&self, owner: InstanceId, conns: &[ConnId], ticket: u64) -> Result<usize, ConnError> {
        self.tcp.wait(owner, conns, ticket)
    }
    fn facts(&self, owner: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.tcp.facts(owner, conn)
    }
    fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.tcp.close(owner, conn)
    }
}
impl DeclaredConns for WithheldCommit {
    fn open_request(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.tcp
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
        self.tcp.declare(owner, need, spec, target, trust)
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.tcp.declared(owner, need)
    }
    fn serves_scheme(&self, scheme: &str) -> bool {
        self.tcp.serves_scheme(scheme)
    }
}

struct ReleaseOnExit(Arc<WithheldCommit>);
impl Drop for ReleaseOnExit {
    fn drop(&mut self) {
        self.0.lose_reply();
    }
}

#[test]
fn a_committed_batch_with_a_lost_reply_replays_its_exact_receipt_after_reopen() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_conditional_lost");
    let seed = TestStore::open(&db.url()).unwrap();
    let before = revision(&seed);
    drop(seed);
    let mut gate = None;
    let settings = serde_json::json!({"url": db.url()}).to_string();
    let loaded = harness::open_loaded_over(&settings, |dispatcher| {
        let wake = dispatcher.conn_waker();
        let table = Arc::new(WithheldCommit {
            tcp: TcpConns::new(wake.clone()),
            wake,
            gate: Mutex::new(Gate::default()),
        });
        gate = Some(table.clone());
        table
    })
    .unwrap();
    let gate = gate.unwrap();
    gate.gate.lock().unwrap().armed = true;
    let _release_on_exit = ReleaseOnExit(gate.clone());
    let r = request(
        vec![predicate(b"state", Expected::Absent)],
        vec![put(b"state", b"committed"), put(b"event", b"committed")],
    );
    let sent = r.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let answer = harness::block_on(StoreCalls::record_transaction(&loaded, &sent));
        let _ = tx.send(answer);
    });
    let mut raw = connect_client_with_retry(&db.url());

    let witnessed = until(|| {
        let held = gate.gate.lock().unwrap().held.is_some();
        held && raw.query_one(
            "SELECT (SELECT COUNT(*) FROM store_records WHERE schema_id='conditional-test' AND value=decode('636f6d6d6974746564','hex'))=2
             AND EXISTS(SELECT 1 FROM store_ops WHERE op_id=$1)", &[&r.op_id.0.as_slice()],
        ).unwrap().get::<_,bool>(0)
    });
    let premature = rx.try_recv();
    let waiting_for_reply = matches!(premature, Err(std::sync::mpsc::TryRecvError::Empty));
    gate.lose_reply();
    let unknown = premature.unwrap_or_else(|_| rx.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
    assert!(
        witnessed,
        "a real SQL commit, not a synthetic successful response, is required"
    );
    assert!(waiting_for_reply);
    assert!(
        unknown.is_err(),
        "the withheld server response was not consumed as Applied"
    );
    let reopened = TestStore::open(&db.url()).unwrap();
    let committed = rows(&reopened);
    assert_eq!(committed.len(), 2);
    assert_eq!(apply(&reopened, &r).unwrap(), Decision::Applied);
    assert_eq!(rows(&reopened), committed);
    assert_eq!(receipts(&reopened), 1);
    assert_eq!(revision(&reopened), before);
    let mut changed = r;
    changed.mutations[0] = put(b"state", b"different");
    assert!(matches!(
        apply(&reopened, &changed),
        Err(StoreFailure::Conflict)
    ));
    assert_eq!(rows(&reopened), committed);
}
