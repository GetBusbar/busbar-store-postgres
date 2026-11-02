use super::*;
use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::Ticket as DispatchTicket;
use busbar_contract::abi::sdk::store::rewrap as protocol;
use busbar_contract::abi::store::{slot, BlobIn};
use busbar_contract::conn::{
    ConnError, ConnId, ConnWake, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
};
use busbar_contract::services::Reading;
use busbar_contract::transport::ConnFacts;
use busbar_plugin_loader::dispatch::kinds::store::Store;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow,
    NoSink, Reply,
};
use busbar_plugin_loader::store_v3::LoadedStore;
use busbar_test_kit::services_double::{Double, ServicesDouble};
use busbar_test_kit::tcp_conns::TcpConns;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Default)]
struct Gate {
    armed: bool,
    held: Option<(InstanceId, ConnId, u64)>,
    closed: usize,
    commits: usize,
    failed: bool,
}

struct WithheldCommit {
    tcp: TcpConns,
    wake: ConnWake,
    state: Mutex<Gate>,
}

impl WithheldCommit {
    fn lose_reply(&self) {
        let held = {
            let mut state = self.state.lock().unwrap();
            state.failed = true;
            state.held
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
        let written = self.tcp.write(owner, conn, bytes, end, text)?;
        // The real pgwire client emits COMMIT as a complete PostgreSQL Simple Query frame.
        if bytes.first() == Some(&b'Q')
            && bytes.get(5..) == Some(b"COMMIT\0")
            && written == bytes.len()
        {
            let mut state = self.state.lock().unwrap();
            if state.armed {
                state.commits += 1;
                state.held = Some((owner, conn, 0));
            }
        }
        Ok(written)
    }

    fn read(
        &self,
        owner: InstanceId,
        conn: ConnId,
        ticket: u64,
        bytes: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let mut state = self.state.lock().unwrap();
        if state
            .held
            .is_some_and(|(caller, id, _)| caller == owner && id == conn)
        {
            state.held = Some((owner, conn, ticket));
            return Err(if state.failed {
                ConnError::Closed
            } else {
                ConnError::Pending
            });
        }
        drop(state);
        self.tcp.read(owner, conn, ticket, bytes)
    }

    fn wait(&self, owner: InstanceId, conns: &[ConnId], ticket: u64) -> Result<usize, ConnError> {
        self.tcp.wait(owner, conns, ticket)
    }

    fn facts(&self, owner: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.tcp.facts(owner, conn)
    }

    fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let result = self.tcp.close(owner, conn);
        self.state.lock().unwrap().closed += 1;
        result
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

struct Clock;
impl ServicesDouble for Clock {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: busbar_plugin_loader::dispatch::now_ns(),
        }
    }
}

fn loaded(url: &str) -> (LoadedStore, Arc<Dispatcher>, Arc<WithheldCommit>) {
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(Double(Clock)),
    ));
    let wake = dispatcher.conn_waker();
    let gate = Arc::new(WithheldCommit {
        tcp: TcpConns::new(wake.clone()),
        wake,
        state: Mutex::new(Gate::default()),
    });
    let row = LinkedRow::of(crate::door).unwrap();
    let plugin = load_linked::<Store>(
        &row,
        Bind {
            instance: Arc::from("postgres-rewrap-uncertain"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(gate.clone()),
        },
    )
    .unwrap();
    let settings = serde_json::json!({"url": url}).to_string();
    let store = LoadedStore::open(plugin, dispatcher.clone(), settings.as_bytes(), || {
        busbar_contract::abi::store::OpId::from_parts(1, 1)
    })
    .unwrap();
    gate.state.lock().unwrap().armed = true;
    (store, dispatcher, gate)
}

fn submit(
    store: &LoadedStore,
    dispatcher: &Arc<Dispatcher>,
    expected: &CredentialSecret,
) -> (Reply<BlobIn, OutHead>, DispatchTicket) {
    let owned = Arc::new((
        serde_json::to_vec(&protocol::Request::new(expected, "replacement")).unwrap(),
        extensions::encode(&[(protocol::INTENT, b"1")]),
    ));
    let mut head = in_head();
    head.extensions = Blob {
        ptr: owned.1.as_ptr(),
        len: owned.1.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let frame = Frame::new(
        BlobIn {
            head,
            record: Blob {
                ptr: owned.0.as_ptr(),
                len: owned.0.len(),
                fmt: BLOB_JSON,
                flags: BLOB_SECRET,
            },
        },
        out_head(),
    );
    let ticket = dispatcher.mint(0).unwrap();
    let reply = dispatcher.submit_lent(
        store.plugin(),
        ticket,
        slot::PUT_CREDENTIAL,
        frame,
        DeadlineClass::Call,
        busbar_plugin_loader::dispatch::now_ns() + 20_000_000_000,
        owned,
    );
    (reply, ticket)
}

fn until(mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn quiet(store: &TestStore, application: &str) -> bool {
    store.lock().query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", &[&application]).unwrap().get::<_, i64>(0) == 0
}

fn replacement_committed(store: &TestStore, before: i64) -> bool {
    let record = store
        .lock()
        .query_one(
            "SELECT secret, revision, (SELECT revision FROM store_revision WHERE only_row)
         FROM credentials WHERE public_id='public'",
            &[],
        )
        .unwrap();
    record.get::<_, Option<String>>(0).as_deref() == Some("replacement")
        && record.get::<_, i64>(1) == before + 1
        && record.get::<_, i64>(2) == before + 1
}

fn reconcile(db: &TempDb, expected: &CredentialSecret, before: i64) {
    let reopened = TestStore::open(&db.url()).unwrap();
    let mut wanted = expected.clone();
    wanted.secret = "replacement".into();
    wanted.meta.revision = (before + 1) as u64;
    assert!(row(&reopened) == wanted);
    assert_eq!(revision(&reopened), before + 1);
    assert!(!rewrap(&reopened, expected, "stale retry").unwrap());
    assert!(!rewrap(&reopened, &wanted, "replacement").unwrap());
    let mut ordinary = wanted.clone();
    ordinary.secret = "ordinary retry".into();
    assert!(reopened.put_credential(&ordinary).is_err());
    assert!(row(&reopened) == wanted);
    assert_eq!(revision(&reopened), before + 1);
}

#[test]
fn a_committed_rewrap_with_a_lost_sql_reply_reconciles_once_after_reopen() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_lost");
    let observer = TestStore::open(&db.url()).unwrap();
    observer.put_key(&sample_key("owner")).unwrap();
    observer
        .put_credential(&sample_cred("owner", 0, "public"))
        .unwrap();
    let expected = row(&observer);
    let before = revision(&observer);
    let application = format!("lost_{}", unique_suffix());
    let (store, dispatcher, gate) = loaded(&format!("{}?application_name={application}", db.url()));
    let (reply, ticket) = submit(&store, &dispatcher, &expected);
    let committed = until(|| replacement_committed(&observer, before));
    let withheld = reply.wait(Duration::ZERO).is_none();
    gate.lose_reply();
    let outcome = reply.wait(Duration::from_secs(5));
    drop(reply);
    let retired = until(|| quiet(&observer, &application));
    drop(store);
    dispatcher.recycle(ticket);
    assert!(
        committed && withheld,
        "the server must commit before the undelivered result is lost"
    );
    assert!(outcome.is_some_and(|done| done.outcome != Outcome::Ready));
    assert!(
        retired,
        "the failed connection must not survive or be pooled"
    );
    assert_eq!(gate.state.lock().unwrap().commits, 1);
    reconcile(&db, &expected, before);
}

#[test]
fn cancelling_a_committed_rewrap_with_a_withheld_reply_preserves_its_single_effect() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_cancel_after");
    let observer = TestStore::open(&db.url()).unwrap();
    observer.put_key(&sample_key("owner")).unwrap();
    observer
        .put_credential(&sample_cred("owner", 0, "public"))
        .unwrap();
    let expected = row(&observer);
    let before = revision(&observer);
    let application = format!("after_{}", unique_suffix());
    let (store, dispatcher, gate) = loaded(&format!("{}?application_name={application}", db.url()));
    let (reply, ticket) = submit(&store, &dispatcher, &expected);
    let committed = until(|| replacement_committed(&observer, before));
    let withheld = reply.wait(Duration::ZERO).is_none();
    drop(reply); // Actual dispatcher client drop reaches the SDK CANCEL path.
    let cancelled =
        until(|| gate.state.lock().unwrap().closed != 0 && quiet(&observer, &application));
    drop(store);
    dispatcher.recycle(ticket);
    assert!(committed && withheld);
    assert!(
        cancelled,
        "CANCEL must close the transaction's held wire before instance CLOSE"
    );
    assert_eq!(gate.state.lock().unwrap().commits, 1);
    reconcile(&db, &expected, before);
}

#[test]
fn cancelling_a_rewrap_waiting_for_the_revision_row_has_no_effect_to_reconcile() {
    let Some(url) = live_url() else { return };
    let db = TempDb::create(&url, "spg_rewrap_cancel_before");
    let observer = TestStore::open(&db.url()).unwrap();
    observer.put_key(&sample_key("owner")).unwrap();
    observer
        .put_credential(&sample_cred("owner", 0, "public"))
        .unwrap();
    let expected = row(&observer);
    let before = revision(&observer);
    let application = format!("before_{}", unique_suffix());
    let (store, dispatcher, gate) = loaded(&format!("{}?application_name={application}", db.url()));
    let mut blocker = connect_client_with_retry(&db.url());
    blocker
        .batch_execute("BEGIN; SELECT revision FROM store_revision WHERE only_row FOR UPDATE")
        .unwrap();
    let (reply, ticket) = submit(&store, &dispatcher, &expected);
    let waiting = until(|| {
        observer.lock().query_one(
        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND wait_event_type='Lock')", &[&application],
    ).unwrap().get::<_, bool>(0)
    });
    drop(reply);
    let cancelled = until(|| gate.state.lock().unwrap().closed != 0);
    // Always unlock before assertions, including a RED where cancellation did not close the wire.
    // PostgreSQL need not notice a disconnected client until its blocked statement resumes.
    blocker.batch_execute("ROLLBACK").unwrap();
    let retired = until(|| quiet(&observer, &application));
    drop(store);
    dispatcher.recycle(ticket);
    assert!(waiting && cancelled && retired);
    assert_eq!(gate.state.lock().unwrap().commits, 0);
    let reopened = TestStore::open(&db.url()).unwrap();
    assert!(row(&reopened) == expected);
    assert_eq!(revision(&reopened), before);
    assert!(rewrap(&reopened, &expected, "replacement").unwrap());
    reconcile(&db, &expected, before);
}
