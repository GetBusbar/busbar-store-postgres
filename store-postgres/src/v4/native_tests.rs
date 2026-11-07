// SPDX-License-Identifier: Apache-2.0
//! Explicit native qualification: run ignored `v4::native_tests` with the dedicated
//! BUSBAR_TEST_POSTGRES_V4_URL pointing at a disposable PostgreSQL administrator.
//! These tests never silently substitute an in-memory backend or skip assertions.
use super::*;
use crate::tests::{postgres_clock, postgres_io};
use busbar_contract::persistence::control;
use busbar_contract::Secret as KernelSecret;
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v4::{Limits, LoadedPersistence};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    mpsc, Barrier,
};
use std::time::{Duration, Instant};
pub(super) fn run<F: std::future::Future>(future: F) -> F::Output {
    struct Wake(std::thread::Thread);
    impl std::task::Wake for Wake {
        fn wake(self: Arc<Self>) {
            self.0.unpark()
        }
    }
    let waker = std::task::Waker::from(Arc::new(Wake(std::thread::current())));
    let mut cx = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => return v,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}
pub(super) fn open(url: &str) -> Arc<LoadedPersistence> {
    open_over(url, |dispatcher| {
        postgres_io::host(dispatcher.conn_waker(), Default::default())
    })
    .expect("native v4 door opens")
}
pub(super) fn open_over(
    url: &str,
    host: impl FnOnce(&Arc<Dispatcher>) -> Arc<dyn busbar_contract::conn::DeclaredConns>,
) -> Result<Arc<LoadedPersistence>, String> {
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(postgres_clock::PostgresClock),
    ));
    let conns = host(&dispatcher);
    let row =
        LinkedRow::of_kind::<StoreV4>(super::door as busbar_contract::abi::mechanism::door::DoorFn)
            .unwrap();
    let plugin = load_linked::<StoreV4>(
        &row,
        Bind {
            instance: Arc::from("postgres-v4-native"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(conns),
        },
    )
    .map_err(|error| format!("{error:?}"))?;
    run(LoadedPersistence::open(
        plugin,
        dispatcher,
        serde_json::json!({"url":url}).to_string().as_bytes(),
        Limits {
            descriptor_bytes: 16 * 1024 * 1024,
            output_items: 4096,
            output_bytes: 4 * 1024 * 1024,
            decode_bytes: 8 * 1024 * 1024,
        },
    ))
    .map(Arc::new)
    .map_err(|error| format!("{error:?}"))
}
pub(super) struct Fixture {
    pub(super) url: String,
    pub(super) raw: postgres::Client,
    pub(super) store: Arc<LoadedPersistence>,
}
impl Fixture {
    pub(super) fn empty() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let admin = std::env::var("BUSBAR_TEST_POSTGRES_V4_URL")
            .expect("explicit native test endpoint required");
        let mut client = postgres::Client::connect(&admin, postgres::NoTls).unwrap();
        let name = format!(
            "v4_native_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap();
        let url = format!("{admin} dbname={name}");
        let raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        let store = open(&url);
        Self { url, raw, store }
    }
    pub(super) fn fresh() -> Self {
        let f = Self::empty();
        assert_applied(run(f.store.commit(initial(&f.store))));
        f
    }
    fn client(&self) -> postgres::Client {
        postgres::Client::connect(&self.url, postgres::NoTls).unwrap()
    }
}
pub(super) fn address(ns: u8, key: &[u8]) -> Address {
    Address {
        namespace: [ns; 16],
        key: key.to_vec(),
    }
}
pub(super) fn put(a: Address, v: &[u8]) -> Mutation {
    Mutation::Put {
        address: a,
        value: KernelSecret::new(v.to_vec()),
    }
}
pub(super) fn candidate(
    store: &LoadedPersistence,
    operation: u8,
    epoch: u64,
    predicates: Vec<Predicate>,
    mutations: Vec<Mutation>,
    time: Option<TimeGuard>,
) -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: store.info().dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: epoch,
            operation: [operation; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time,
        result: KernelSecret::new(vec![operation]),
    })
    .unwrap()
}
pub(super) fn initial(store: &LoadedPersistence) -> PreparedCandidate {
    let root = Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    };
    let writer = writer_address();
    let admission = Address {
        namespace: busbar_contract::persistence::lifecycle::ADMISSION_NAMESPACE,
        key: busbar_contract::persistence::lifecycle::ADMISSION_KEY.to_vec(),
    };
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: store.info().dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [1; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![
            absent(root.clone()),
            absent(writer.clone()),
            absent(admission.clone()),
        ],
        mutations: vec![
            put(admission, b"opaque-native-qualification-marker"),
            put(
                root,
                &control::Dataset {
                    id: store.info().dataset,
                    writer_epoch: 1,
                }
                .encode()
                .unwrap(),
            ),
            put(
                writer,
                &control::Writer {
                    retired_through: 0,
                    admitted_through: 1,
                }
                .encode()
                .unwrap(),
            ),
        ],
        time: None,
        result: KernelSecret::new(vec![]),
    })
    .unwrap()
}
fn writer_address() -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key([2; 16]).to_vec(),
    }
}
fn absent(a: Address) -> Predicate {
    Predicate {
        address: a,
        expected: ExpectedValue::Absent,
    }
}
fn exact(a: Address, v: &[u8]) -> Predicate {
    Predicate {
        address: a,
        expected: ExpectedValue::Exact(KernelSecret::new(v.to_vec())),
    }
}
pub(super) fn assert_applied(result: Result<Decision, Failure>) {
    assert!(matches!(result, Ok(Decision::Applied(_))), "{result:?}")
}
pub(super) fn read(
    store: &LoadedPersistence,
    addresses: Vec<Address>,
    time: Option<TimeGuard>,
) -> Result<ReadResult, Failure> {
    run(store.read(Arc::new(Read {
        dataset: store.info().dataset,
        addresses,
        time,
    })))
}
pub(super) fn page(
    store: &LoadedPersistence,
    ns: u8,
    generation: Option<u64>,
    after: Option<Vec<u8>>,
    items: usize,
) -> Result<Page, Failure> {
    run(store.scan(Arc::new(Scan {
        dataset: store.info().dataset,
        namespace: NamespaceId([ns; 16]),
        prefix: vec![],
        after,
        generation,
        allow_change: false,
        max_items: items,
        max_bytes: 2 * 1024 * 1024,
    })))
}
fn now(raw: &mut postgres::Client) -> u64 {
    raw.query_one(
        "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
        &[],
    )
    .unwrap()
    .get::<_, i64>(0) as u64
}
fn wait(raw: &mut postgres::Client, mut condition: impl FnMut(&mut postgres::Client) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition(raw) {
        assert!(Instant::now() < deadline, "native wait deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn wait_blocked(raw: &mut postgres::Client, holder: i32) {
    wait(raw, |c| {
        c.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)))",&[&holder]).unwrap().get(0)
    });
}
fn lock_namespace(raw: &mut postgres::Client, ns: u8) -> i32 {
    let pid = raw
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    raw.batch_execute("BEGIN").unwrap();
    raw.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&super::native::namespace_lock([ns; 16])],
    )
    .unwrap();
    pid
}

fn core_identity_crossing() {
    use busbar_contract::records::{CredentialMeta, CredentialSecret, SecretForm, VirtualKey};
    use busbar_kernel::persistence::facade::Limits as CoreLimits;
    use busbar_kernel::persistence::startup::{Progress, Startup};

    fn advance_to(startup: &mut Startup, expected: Progress) {
        for _ in 0..32 {
            if run(startup.advance()).expect("native startup advances") == expected {
                return;
            }
        }
        panic!("native startup did not reach {expected:?} within 32 steps");
    }
    fn raw_record(f: &mut Fixture, namespace: [u8; 16], key: &[u8]) -> Vec<u8> {
        f.raw
            .query_one(
                "SELECT value FROM busbar_persistence_v4.records WHERE namespace=$1 AND key=$2",
                &[&&namespace[..], &key],
            )
            .unwrap()
            .get(0)
    }

    // Physical setup alone must leave logical initialization to the core gate.
    let mut f = Fixture::empty();
    let info = f.store.info();
    let count: i64 = f
        .raw
        .query_one("SELECT count(*) FROM busbar_persistence_v4.records", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    let limits = CoreLimits {
        pending_operations: 32,
        conflict_retries: 4,
        scan_items: 2,
        scan_bytes: 1024 * 1024,
    };
    let mut startup = Startup::new(f.store.clone(), limits, true).unwrap();
    assert!(startup.store().is_none());
    advance_to(&mut startup, Progress::Admitted);
    let core = startup
        .store()
        .expect("startup admits native identity store");
    let first_authority = core.authority().unwrap();
    let root = raw_record(&mut f, control::NAMESPACE.0, control::DATASET_KEY);
    let manifest = raw_record(&mut f, *b"busbar.format1\0\0", b"active");
    assert_eq!(manifest.len(), 80);
    assert_eq!(&manifest[..8], b"BSCFMT1\0");
    assert_eq!(control::Dataset::decode(&root).unwrap().id, info.dataset);
    let key = VirtualKey {
        id: "native-owner".into(),
        name: "native attribution".into(),
        generation_hash: "generation".into(),
        enabled: true,
        created_at: 7,
        ..Default::default()
    };
    let credential = CredentialSecret {
        meta: CredentialMeta {
            id: "native-credential".into(),
            key_id: key.id.clone(),
            kind: "signing".into(),
            slot: 0,
            public_id: "native-public".into(),
            secret_form: SecretForm::Recoverable,
            created_at: 7,
            updated_at: 7,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:aead:opaque:native:envelope".into(),
    };
    run(core.identity().put_key_with_credential(&key, &credential)).unwrap();
    let hydrated = run(core.identity().list_credentials_since(0)).unwrap();
    assert_eq!(hydrated.len(), 1);
    assert_eq!(hydrated[0].secret, credential.secret);
    assert_eq!(
        run(core.identity().get_key(&key.id)).unwrap().unwrap().name,
        key.name
    );
    let namespace = busbar_kernel::governance::persistence::identity::CONFIDENTIAL.0;
    let stored: Vec<u8> = f
        .raw
        .query_one(
            "SELECT value FROM busbar_persistence_v4.records WHERE namespace=$1",
            &[&&namespace[..]],
        )
        .unwrap()
        .get(0);
    assert_eq!(stored, credential.secret.as_bytes());
    run(core
        .identity()
        .revoke_credential(&credential.meta.id, "native revoke"))
    .unwrap();
    let revoked = run(core.identity().list_credentials_since(0)).unwrap();
    assert_eq!(revoked.len(), 1);
    assert!(revoked[0].secret.is_empty());
    assert!(revoked[0].meta.revoked_at.is_some());
    assert_eq!(
        revoked[0].meta.revoke_reason.as_deref(),
        Some("native revoke")
    );
    let metadata = run(core.identity().list_credentials(&key.id)).unwrap();
    assert_eq!(metadata.len(), 1);
    assert!(metadata[0].revoked_at.is_some());
    assert_eq!(metadata[0].secret_form, SecretForm::None);
    let cleared: Vec<u8> = f
        .raw
        .query_one(
            "SELECT value FROM busbar_persistence_v4.records WHERE namespace=$1",
            &[&&namespace[..]],
        )
        .unwrap()
        .get(0);
    assert!(cleared.is_empty());

    // A new physical connection uses the same format and dataset, and receives
    // independent business authority without reinitializing logical storage.
    let reopened = open(&f.url);
    assert_eq!(reopened.info(), info);
    let mut second = Startup::new(reopened, limits, false).unwrap();
    advance_to(&mut second, Progress::Admitted);
    let second_core = second.store().unwrap();
    let second_authority = second_core.authority().unwrap();
    assert_ne!(second_authority.writer, first_authority.writer);
    assert_eq!(second_authority.writer_epoch, first_authority.writer_epoch);
    assert_eq!(
        raw_record(&mut f, control::NAMESPACE.0, control::DATASET_KEY),
        root
    );
    assert_eq!(
        raw_record(&mut f, *b"busbar.format1\0\0", b"active"),
        manifest
    );
    assert_eq!(
        run(second_core.identity().get_key(&key.id))
            .unwrap()
            .unwrap()
            .name,
        key.name
    );
    let reopened_credentials = run(second_core.identity().list_credentials(&key.id)).unwrap();
    assert_eq!(reopened_credentials.len(), 1);
    assert!(reopened_credentials[0].revoked_at.is_some());

    startup.begin_retirement().unwrap();
    advance_to(&mut startup, Progress::Retired);
    assert!(startup.store().is_none());
    let retired = control::Writer::decode(&raw_record(
        &mut f,
        control::NAMESPACE.0,
        &control::writer_key(first_authority.writer),
    ))
    .unwrap();
    assert_eq!(retired.retired_through, first_authority.execution_epoch);
    assert_eq!(retired.admitted_through, first_authority.execution_epoch);
    assert!(!retired.admits(first_authority.execution_epoch));
    let live = control::Writer::decode(&raw_record(
        &mut f,
        control::NAMESPACE.0,
        &control::writer_key(second_authority.writer),
    ))
    .unwrap();
    assert!(live.admits(second_authority.execution_epoch));
    assert_eq!(run(second.advance()).unwrap(), Progress::Admitted);
    assert!(second.store().is_some());
    run(second_core.identity().put_key(&VirtualKey {
        id: "second-writer-after-retirement".into(),
        ..key.clone()
    }))
    .unwrap();
}

#[test]
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn native_identity_atomic_receipt_range_scan_and_unsigned_epochs() {
    let mut f = Fixture::fresh();
    let info = f.store.info();
    assert_eq!(info.durability, Durability::Local);
    assert_eq!(open(&f.url).info(), info);
    let long = address(10, &vec![255; 10_000]);
    let a = address(10, &[0, 0]);
    let b = address(10, &[0, 255]);
    let neighbor = address(10, &[0, 0, 0]);
    let seed = candidate(
        &f.store,
        2,
        1,
        vec![absent(a.clone())],
        vec![
            put(a.clone(), b"a"),
            put(b.clone(), b"b"),
            put(neighbor.clone(), b"neighbor"),
            put(long.clone(), b"long"),
        ],
        None,
    );
    assert_applied(run(f.store.commit(seed.clone())));
    let original: Vec<u8> = f
        .raw
        .query_one(
            "SELECT observed FROM busbar_persistence_v4.receipts WHERE operation=$1",
            &[&&[2u8; 16][..]],
        )
        .unwrap()
        .get(0);
    let before = page(&f.store, 10, None, None, 1).unwrap();
    assert_eq!(before.rows[0].0, a);
    assert!(before.next.is_some());
    assert_applied(run(f.store.commit(seed)));
    let unchanged = page(&f.store, 10, None, None, 100).unwrap();
    assert_eq!(unchanged.generation, before.generation);
    assert_eq!(unchanged.rows.len(), 4);
    assert_eq!(unchanged.rows[3].0, long);
    let replay: Vec<u8> = f
        .raw
        .query_one(
            "SELECT observed FROM busbar_persistence_v4.receipts WHERE operation=$1",
            &[&&[2u8; 16][..]],
        )
        .unwrap()
        .get(0);
    assert_eq!(replay, original);
    let conflict = candidate(
        &f.store,
        2,
        1,
        vec![],
        vec![put(a.clone(), b"different")],
        None,
    );
    assert!(matches!(
        run(f.store.commit(conflict)),
        Ok(Decision::OpIdConflict)
    ));
    assert_applied(run(f.store.commit(candidate(
        &f.store,
        3,
        1,
        vec![],
        vec![Mutation::DeleteRange {
            namespace: NamespaceId([10; 16]),
            prefix: vec![0],
            exact_key_length: 2,
        }],
        None,
    ))));
    let stale = page(&f.store, 10, Some(before.generation), before.next, 1);
    assert!(
        matches!(stale, Err(Failure::StaleScan)),
        "stale page: {stale:?}"
    );
    match read(&f.store, vec![a, b, neighbor, long], None).unwrap() {
        ReadResult::Values { values, .. } => {
            assert!(values[0].is_none() && values[1].is_none());
            assert_eq!(values[2], Some(KernelSecret::new(b"neighbor".to_vec())));
            assert_eq!(values[3], Some(KernelSecret::new(b"long".to_vec())));
        }
        other => panic!("{other:?}"),
    }
    let old = control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
    .encode()
    .unwrap();
    let new = control::Writer {
        retired_through: 0,
        admitted_through: u64::MAX,
    }
    .encode()
    .unwrap();
    assert_applied(run(f.store.commit(candidate(
        &f.store,
        4,
        1,
        vec![exact(writer_address(), &old)],
        vec![put(writer_address(), &new)],
        None,
    ))));
    assert_applied(run(f.store.commit(candidate(
        &f.store,
        5,
        u64::MAX,
        vec![],
        vec![put(address(11, b"max"), b"unsigned")],
        None,
    ))));
    let epoch: Vec<u8> = f
        .raw
        .query_one(
            "SELECT epoch FROM busbar_persistence_v4.receipts WHERE operation=$1",
            &[&&[5u8; 16][..]],
        )
        .unwrap()
        .get(0);
    assert_eq!(epoch, u64::MAX.to_le_bytes());
    // Inject an impossible digest collision to exercise a failure after an
    // earlier mutation has executed. Neither that effect nor a receipt may commit.
    let collision = address(15, b"collision-target");
    let mut bytes = collision.namespace.to_vec();
    bytes.extend_from_slice(&collision.key);
    let digest = busbar_contract::abi::sdk::digest::sha256(&bytes);
    f.raw.execute("INSERT INTO busbar_persistence_v4.records(locator,namespace,key,value) VALUES($1,$2,$3,$4)", &[&&digest[..],&&collision.namespace[..],&&b"different-full-key"[..],&&b"retained"[..]]).unwrap();
    let earlier = address(15, b"must-roll-back");
    let failed = candidate(
        &f.store,
        6,
        u64::MAX,
        vec![],
        vec![
            put(earlier.clone(), b"partial"),
            put(collision, b"forbidden-overwrite"),
        ],
        None,
    );
    // The public commit boundary preserves uncertainty after a native fault.
    // Independent SQL below proves this particular execution rolled back.
    let collision_result = run(f.store.commit(failed));
    assert!(
        matches!(collision_result, Err(Failure::Unknown)),
        "{collision_result:?}"
    );
    match read(&f.store, vec![earlier], None).unwrap() {
        ReadResult::Values { values, .. } => assert!(values[0].is_none()),
        other => panic!("{other:?}"),
    }
    let retained: Vec<u8> = f
        .raw
        .query_one(
            "SELECT value FROM busbar_persistence_v4.records WHERE locator=$1",
            &[&&digest[..]],
        )
        .unwrap()
        .get(0);
    assert_eq!(retained, b"retained");
    let receipts: i64 = f
        .raw
        .query_one(
            "SELECT count(*) FROM busbar_persistence_v4.receipts WHERE operation=$1",
            &[&&[6u8; 16][..]],
        )
        .unwrap()
        .get(0);
    assert_eq!(receipts, 0);
    core_identity_crossing();
}

#[test]
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn native_blocked_read_and_commit_cross_expiry() {
    let mut f = Fixture::fresh();
    let a = address(12, b"guarded");
    assert_applied(run(f.store.commit(candidate(
        &f.store,
        2,
        1,
        vec![],
        vec![put(a.clone(), b"old")],
        None,
    ))));
    let pid = lock_namespace(&mut f.raw, 12);
    let expiry = now(&mut f.raw) + 2;
    let store = f.store.clone();
    let at = a.clone();
    let (send, recv) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        send.send(read(
            &store,
            vec![at],
            Some(TimeGuard {
                not_before: None,
                before: Some(expiry),
            }),
        ))
        .unwrap()
    });
    wait_blocked(&mut f.raw, pid);
    wait(&mut f.raw, |c| now(c) >= expiry);
    assert!(recv.try_recv().is_err());
    f.raw.batch_execute("COMMIT").unwrap();
    assert!(
        matches!(recv.recv_timeout(Duration::from_secs(10)).unwrap(),Ok(ReadResult::TimeGuardFailed{observed_at})if observed_at.unix_seconds>=expiry)
    );
    reader.join().unwrap();
    // A permitted clock observation must describe the value committed while
    // this reader waited, rather than a snapshot established before admission.
    let pid = lock_namespace(&mut f.raw, 12);
    let admitted_at = now(&mut f.raw) + 2;
    let store = f.store.clone();
    let at = a.clone();
    let reader = std::thread::spawn(move || {
        read(
            &store,
            vec![at],
            Some(TimeGuard {
                not_before: Some(admitted_at),
                before: None,
            }),
        )
    });
    wait_blocked(&mut f.raw, pid);
    f.raw
        .execute(
            "UPDATE busbar_persistence_v4.records SET value=$1 WHERE namespace=$2 AND key=$3",
            &[&&b"fresh"[..], &&a.namespace[..], &&a.key[..]],
        )
        .unwrap();
    wait(&mut f.raw, |c| now(c) >= admitted_at);
    f.raw.batch_execute("COMMIT").unwrap();
    match reader.join().unwrap().unwrap() {
        ReadResult::Values {
            observed_at,
            values,
        } => {
            assert!(observed_at.unix_seconds >= admitted_at);
            assert_eq!(values[0], Some(KernelSecret::new(b"fresh".to_vec())));
        }
        other => panic!("{other:?}"),
    }
    let pid = lock_namespace(&mut f.raw, 12);
    let expiry = now(&mut f.raw) + 2;
    let request = candidate(
        &f.store,
        3,
        1,
        vec![exact(a.clone(), b"old")],
        vec![put(a.clone(), b"forbidden")],
        Some(TimeGuard {
            not_before: None,
            before: Some(expiry),
        }),
    );
    let store = f.store.clone();
    let (send, recv) = mpsc::channel();
    let writer = std::thread::spawn(move || send.send(run(store.commit(request))).unwrap());
    wait_blocked(&mut f.raw, pid);
    f.raw
        .execute(
            "UPDATE busbar_persistence_v4.records SET value=$1 WHERE namespace=$2 AND key=$3",
            &[&&b"changed"[..], &&a.namespace[..], &&a.key[..]],
        )
        .unwrap();
    wait(&mut f.raw, |c| now(c) >= expiry);
    f.raw.batch_execute("COMMIT").unwrap();
    assert!(
        matches!(recv.recv_timeout(Duration::from_secs(10)).unwrap(),Ok(Decision::TimeGuardFailed{observed_at})if observed_at.unix_seconds>=expiry)
    );
    writer.join().unwrap();
    // The temporal guard now permits execution; predicates must still see the
    // newer committed value after waiting, so this candidate cannot apply.
    let pid = lock_namespace(&mut f.raw, 12);
    let admitted_at = now(&mut f.raw) + 2;
    let request = candidate(
        &f.store,
        4,
        1,
        vec![exact(a.clone(), b"changed")],
        vec![put(a.clone(), b"stale-snapshot-write")],
        Some(TimeGuard {
            not_before: Some(admitted_at),
            before: None,
        }),
    );
    let store = f.store.clone();
    let writer = std::thread::spawn(move || run(store.commit(request)));
    wait_blocked(&mut f.raw, pid);
    f.raw
        .execute(
            "UPDATE busbar_persistence_v4.records SET value=$1 WHERE namespace=$2 AND key=$3",
            &[&&b"fresh-again"[..], &&a.namespace[..], &&a.key[..]],
        )
        .unwrap();
    wait(&mut f.raw, |c| now(c) >= admitted_at);
    f.raw.batch_execute("COMMIT").unwrap();
    assert!(matches!(
        writer.join().unwrap(),
        Ok(Decision::ConditionConflict)
    ));
    match read(&f.store, vec![a], None).unwrap() {
        ReadResult::Values { values, .. } => {
            assert_eq!(values[0], Some(KernelSecret::new(b"fresh-again".to_vec())))
        }
        other => panic!("{other:?}"),
    };
    let receipts: i64 = f
        .raw
        .query_one(
            "SELECT count(*) FROM busbar_persistence_v4.receipts WHERE operation=$1",
            &[&&[3u8; 16][..]],
        )
        .unwrap()
        .get(0);
    assert_eq!(receipts, 0);
}

#[test]
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn native_absence_predicates_are_atomic_between_connections() {
    let f = Fixture::fresh();
    let barrier = Arc::new(Barrier::new(3));
    let a = address(13, b"claim");
    let mut workers = vec![];
    for operation in [2, 3] {
        let store = f.store.clone();
        let request = candidate(
            &store,
            operation,
            1,
            vec![absent(a.clone())],
            vec![put(a.clone(), &[operation])],
            None,
        );
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            run(store.commit(request))
        }));
    }
    barrier.wait();
    let answers: Vec<_> = workers.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(
        answers
            .iter()
            .filter(|r| matches!(r, Ok(Decision::Applied(_))))
            .count(),
        1
    );
    assert_eq!(
        answers
            .iter()
            .filter(|r| matches!(r, Ok(Decision::ConditionConflict)))
            .count(),
        1
    );
}

#[test]
#[ignore = "requires explicit disposable BUSBAR_TEST_POSTGRES_V4_URL; native qualification"]
fn native_retirement_waits_for_admitted_writer_and_preserves_replay() {
    let mut f = Fixture::fresh();
    let a = address(14, b"inflight");
    assert_applied(run(f.store.commit(candidate(
        &f.store,
        2,
        1,
        vec![],
        vec![put(a.clone(), b"old")],
        None,
    ))));
    let initial = control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
    .encode()
    .unwrap();
    let admitted = control::Writer {
        retired_through: 0,
        admitted_through: 2,
    }
    .encode()
    .unwrap();
    let retired = control::Writer {
        retired_through: 1,
        admitted_through: 2,
    }
    .encode()
    .unwrap();
    assert_applied(run(f.store.commit(candidate(
        &f.store,
        3,
        1,
        vec![exact(writer_address(), &initial)],
        vec![put(writer_address(), &admitted)],
        None,
    ))));
    let mut holder = f.client();
    let pid: i32 = holder
        .query_one("SELECT pg_backend_pid()", &[])
        .unwrap()
        .get(0);
    holder.batch_execute("BEGIN").unwrap();
    holder.query_one("SELECT value FROM busbar_persistence_v4.records WHERE namespace=$1 AND key=$2 FOR UPDATE",&[&&a.namespace[..],&&a.key[..]]).unwrap();
    let request = candidate(
        &f.store,
        4,
        1,
        vec![],
        vec![put(a.clone(), b"committed-before-retirement")],
        None,
    );
    let replay = request.clone();
    let store = f.store.clone();
    let first = std::thread::spawn(move || run(store.commit(request)));
    wait_blocked(&mut f.raw, pid);
    let retirement = candidate(
        &f.store,
        5,
        2,
        vec![exact(writer_address(), &admitted)],
        vec![put(writer_address(), &retired)],
        None,
    );
    let store = f.store.clone();
    let (send, recv) = mpsc::channel();
    let closing = std::thread::spawn(move || send.send(run(store.commit(retirement))).unwrap());
    wait(&mut f.raw, |c| {
        c.query_one("SELECT count(*)>=2 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'",&[]).unwrap().get(0)
    });
    assert!(recv.try_recv().is_err());
    holder.batch_execute("COMMIT").unwrap();
    assert_applied(first.join().unwrap());
    assert_applied(recv.recv_timeout(Duration::from_secs(10)).unwrap());
    closing.join().unwrap();
    assert_applied(run(f.store.commit(replay)));
    assert!(matches!(
        run(f.store.commit(candidate(
            &f.store,
            6,
            1,
            vec![],
            vec![put(a, b"must-not-run")],
            None
        ))),
        Ok(Decision::ExpiredUnknown)
    ));
}
