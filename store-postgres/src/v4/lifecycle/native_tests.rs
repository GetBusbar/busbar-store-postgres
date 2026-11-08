// SPDX-License-Identifier: Apache-2.0
//! Automatic lifecycle witnesses across the actual fifth ABI slot and native sockets.
use super::*;
use crate::tests::{postgres_clock, postgres_io};
use crate::v4::native_tests::run;
use busbar_contract::persistence::lifecycle::PreparedStore;
use busbar_contract::redacted::Kernel;
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v4::{Limits, LoadedPrepared};
use std::sync::atomic::{AtomicU64, Ordering};
const BOUNDS: Bounds = Bounds {
    items: 4096,
    bytes: 4 * 1024 * 1024,
};
fn prepared(url: &str) -> LoadedPrepared {
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(postgres_clock::PostgresClock),
        busbar_contract::services::test_caller_binding(),
    ));
    let conns = postgres_io::host(dispatcher.conn_waker(), Default::default());
    let row = LinkedRow::of_kind::<StoreV4>(
        crate::v4::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
    .unwrap();
    let plugin = load_linked::<StoreV4>(
        &row,
        Bind {
            instance: Arc::from("postgres-native-lifecycle"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(conns),
        },
    )
    .unwrap();
    LoadedPrepared::new(
        plugin,
        dispatcher,
        serde_json::json!({"url":url}).to_string().as_bytes(),
        Limits {
            descriptor_bytes: 16 * 1024 * 1024,
            output_items: 4096,
            output_bytes: 4 * 1024 * 1024,
            decode_bytes: 8 * 1024 * 1024,
        },
    )
    .unwrap()
}
struct Fixture {
    admin: postgres::Client,
    raw: postgres::Client,
    url: String,
    database: String,
    role: String,
}
impl Fixture {
    fn new(released: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let admin_url = std::env::var("BUSBAR_TEST_POSTGRES_V4_URL")
            .expect("explicit disposable PostgreSQL required");
        let mut admin = postgres::Client::connect(&admin_url, postgres::NoTls).unwrap();
        let database = format!(
            "lifecycle_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let role = format!("{database}_owner");
        admin
            .batch_execute(&format!("CREATE ROLE {role} LOGIN"))
            .unwrap();
        admin
            .batch_execute(&format!("CREATE DATABASE {database} OWNER {role}"))
            .unwrap();
        let url = format!("{admin_url} dbname={database} user={role}");
        let mut raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        assert!(!raw
            .query_one(
                "SELECT rolsuper FROM pg_roles WHERE rolname=current_user",
                &[]
            )
            .unwrap()
            .get::<_, bool>(0));
        if released {
            raw.batch_execute(include_str!("../../../tests/fixtures/1.5.5/dump.sql"))
                .unwrap();
        }
        Self {
            admin,
            raw,
            url,
            database,
            role,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self
            .admin
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.database));
        let _ = self
            .admin
            .batch_execute(&format!("DROP ROLE {}", self.role));
    }
}
fn inspect(p: &LoadedPrepared) -> Arc<Response<Kernel>> {
    run(p.bootstrap(Arc::new(Request::Inspect { bounds: BOUNDS }))).unwrap()
}
fn begin(p: &LoadedPrepared, source: &SourceIdentity) -> Arc<Response<Kernel>> {
    run(p.bootstrap(Arc::new(Request::BeginOrResume {
        expected_source: source.clone(),
        route_digest: [9; 32],
        target_format: CORE_FORMAT,
        operation_id: [7; 16],
    })))
    .unwrap()
}
fn page(
    p: &LoadedPrepared,
    up: &Upgrade<Kernel>,
    table: u32,
    cursor: Option<Secret<Vec<u8>>>,
) -> Arc<Response<Kernel>> {
    run(p.bootstrap(Arc::new(Request::SourcePage {
        upgrade: up.reference.clone(),
        snapshot: up.snapshot,
        family: [3; 16],
        selector: SourceSelector::Scan { table },
        cursor,
        bounds: Bounds {
            items: 1,
            bytes: 64 * 1024,
        },
    })))
    .unwrap()
}
fn no_write(raw: &mut postgres::Client, sql: &str) {
    let error = raw.batch_execute(sql).unwrap_err();
    assert_eq!(
        error.code().map(|code| code.code()),
        Some("55000"),
        "{sql}: {error}"
    );
}
fn address(key: &[u8]) -> Address {
    Address {
        namespace: [5; 16],
        key: key.to_vec(),
    }
}
fn predicate(address: Address, bytes: Option<&[u8]>) -> Predicate {
    Predicate {
        address,
        expected: bytes
            .map(|v| ExpectedValue::Exact(Secret::new(v.to_vec())))
            .unwrap_or(ExpectedValue::Absent),
    }
}
fn put(address: Address, bytes: &[u8]) -> Mutation {
    Mutation::Put {
        address,
        value: Secret::new(bytes.to_vec()),
    }
}
fn checkpoint(
    target: &dyn MigrationTarget,
    up: &Upgrade<Kernel>,
    phase: CompletionPhase,
) -> ActivationReceipt<Kernel> {
    let value = if phase == CompletionPhase::Activation {
        b"checkpoint-activation".as_slice()
    } else {
        b"checkpoint-complete".as_slice()
    };
    let checkpoint_address = address(b"checkpoint");
    let marker = CompletionMarker {
        version: VERSION,
        phase,
        upgrade: up.reference.id,
        source: up.source.dataset,
        target: up.target.dataset,
        checkpoint_address: checkpoint_address.clone(),
        checkpoint_value_digest: sha256(value),
    };
    let encoded = codec::encode_completion_marker(&marker, BOUNDS).unwrap();
    let marker_address = completion_marker_address(up.reference.id);
    let mut predicates = Vec::new();
    let mut mutations = Vec::new();
    if phase == CompletionPhase::Activation {
        let active = Address {
            namespace: ADMISSION_NAMESPACE,
            key: ADMISSION_KEY.to_vec(),
        };
        for a in [&active, &checkpoint_address, &marker_address] {
            predicates.push(predicate(a.clone(), None));
        }
        // Opaque bytes at the provider boundary; semantic admission belongs to core.
        mutations.push(put(active, b"native-lifecycle-test-admission"));
    } else {
        predicates.push(predicate(
            checkpoint_address.clone(),
            Some(b"checkpoint-activation"),
        ));
    }
    mutations.push(put(checkpoint_address.clone(), value));
    mutations.push(Mutation::Put {
        address: marker_address,
        value: encoded,
    });
    let attempt = AttemptId {
        dataset: up.target.dataset,
        writer_epoch: 1,
        writer: [2; 16],
        execution_epoch: 1,
        operation: if phase == CompletionPhase::Activation {
            [1; 16]
        } else {
            [2; 16]
        },
    };
    let candidate = PreparedCandidate::new(Candidate {
        id: attempt,
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(vec![42]),
    })
    .unwrap();
    let fingerprint = candidate.fingerprint();
    let decision = run(target.commit(candidate)).unwrap();
    let Decision::Applied(original_result) = decision else {
        panic!("checkpoint not applied: {decision:?}")
    };
    ActivationReceipt {
        attempt,
        candidate_fingerprint: fingerprint,
        original_result,
        checkpoint_address,
        checkpoint_value_digest: sha256(value),
        phase,
    }
}
#[test]
#[ignore = "requires explicit disposable PostgreSQL"]
fn released_source_guards_pages_and_completion_restart() {
    let mut fixture = Fixture::new(true);
    let cached = fixture
        .raw
        .prepare("UPDATE public.keys SET name=name WHERE id=$1")
        .unwrap();
    let original: i64 = fixture
        .raw
        .query_one("SELECT count(*) FROM public.keys", &[])
        .unwrap()
        .get(0);
    let p = prepared(&fixture.url);
    let inspected = inspect(&p);
    let Response::Inspected(i) = inspected.as_ref() else {
        panic!()
    };
    assert_eq!(i.state, InspectionState::Legacy);
    assert!(!fixture
        .raw
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='busbar_upgrade_v1')",
            &[]
        )
        .unwrap()
        .get::<_, bool>(0));
    let begun = begin(&p, i.source.as_ref().unwrap());
    let Response::Begun(up) = begun.as_ref() else {
        panic!()
    };
    assert_eq!(up.source.format.unwrap().logical, 0);
    assert_eq!(
        fixture
            .raw
            .execute(&cached, &[&"absent-key"])
            .unwrap_err()
            .code()
            .unwrap()
            .code(),
        "55000"
    );
    for sql in [
        "INSERT INTO public.store_revision(only_row,revision) VALUES(true,0) ON CONFLICT(only_row) DO NOTHING",
        "INSERT INTO public.busbar_schema(version) VALUES(6) ON CONFLICT DO NOTHING",
        "DELETE FROM public.keys WHERE false",
    ] {
        no_write(&mut fixture.raw, sql);
    }
    let count: i64 = fixture
        .raw
        .query_one("SELECT count(*) FROM public.keys", &[])
        .unwrap()
        .get(0);
    assert_eq!(count, original);
    let table = up.catalogue.iter().position(|t| t.name == "keys").unwrap() as u32;
    let first = page(&p, up, table, None);
    let Response::SourcePage(first) = first.as_ref() else {
        panic!()
    };
    assert_eq!(first.rows.len(), 1);
    let cursor = first
        .next
        .clone()
        .expect("released fixture has multiple keys");
    let second = page(&p, up, table, Some(cursor.clone()));
    let Response::SourcePage(second) = second.as_ref() else {
        panic!()
    };
    let target = run(p.target(up.reference.clone())).unwrap();
    let root = Address {
        namespace: busbar_contract::persistence::control::NAMESPACE.0,
        key: busbar_contract::persistence::control::DATASET_KEY.to_vec(),
    };
    let writer = Address {
        namespace: busbar_contract::persistence::control::NAMESPACE.0,
        key: busbar_contract::persistence::control::writer_key([2; 16]).to_vec(),
    };
    let initial = PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: up.target.dataset,
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [5; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![
            predicate(root.clone(), None),
            predicate(writer.clone(), None),
        ],
        mutations: vec![
            put(
                root,
                &busbar_contract::persistence::control::Dataset {
                    id: up.target.dataset,
                    writer_epoch: 1,
                }
                .encode()
                .unwrap(),
            ),
            put(
                writer,
                &busbar_contract::persistence::control::Writer {
                    retired_through: 0,
                    admitted_through: 1,
                }
                .encode()
                .unwrap(),
            ),
        ],
        time: None,
        result: Secret::new(vec![]),
    })
    .unwrap();
    assert!(matches!(
        run(target.commit(initial)),
        Ok(Decision::Applied(_))
    ));
    let activation = checkpoint(target.as_ref(), up, CompletionPhase::Activation);
    let ready = run(p.bootstrap(Arc::new(Request::Finish {
        upgrade: up.reference.clone(),
        activation_receipt: activation.clone(),
    })))
    .unwrap();
    let Response::RecoveryReady(ready) = ready.as_ref() else {
        panic!()
    };
    let opened = run(p.open(OpenBinding::Recovery(ready.clone()))).unwrap();
    assert!(p.serving().is_err());
    assert_eq!(opened.info(), target.info());
    let mut forged = activation.clone();
    forged.phase = CompletionPhase::Complete;
    assert!(run(p.bootstrap(Arc::new(Request::Finish {
        upgrade: up.reference.clone(),
        activation_receipt: forged,
    })))
    .is_err());
    // Failed native proof must release its transaction before the real commit.
    let complete = checkpoint(target.as_ref(), up, CompletionPhase::Complete);
    // Process loss after Complete Applied but before native FinishComplete.
    let snapshot = up.snapshot;
    let upgrade_id = up.reference.id;
    let target_info = up.target;
    drop(opened);
    drop(target);
    drop(p);
    // No live reader lock remains: persistent TRUNCATE enforcement still rejects.
    no_write(&mut fixture.raw, "TRUNCATE public.keys CASCADE");
    let resumed = prepared(&fixture.url);
    let inspected = inspect(&resumed);
    let Response::Inspected(i) = inspected.as_ref() else {
        panic!()
    };
    assert_eq!(i.state, InspectionState::InProgress);
    let begun = begin(&resumed, i.source.as_ref().unwrap());
    let Response::Begun(up) = begun.as_ref() else {
        panic!()
    };
    assert_eq!(up.snapshot, snapshot);
    assert_eq!(up.reference.id, upgrade_id);
    assert_eq!(up.target, target_info);
    let replay = page(&resumed, up, table, Some(cursor));
    let Response::SourcePage(replay) = replay.as_ref() else {
        panic!()
    };
    assert_eq!(replay.coverage_digest, second.coverage_digest);
    assert_eq!(replay.rows[0].native_key, second.rows[0].native_key);
    assert_eq!(replay.rows[0].value, second.rows[0].value);
    let ready = run(resumed.bootstrap(Arc::new(Request::Finish {
        upgrade: up.reference.clone(),
        activation_receipt: activation,
    })))
    .unwrap();
    let Response::RecoveryReady(ready) = ready.as_ref() else {
        panic!()
    };
    let opened = run(resumed.open(OpenBinding::Recovery(ready.clone()))).unwrap();
    assert!(resumed.serving().is_err());
    let done = run(resumed.bootstrap(Arc::new(Request::Finish {
        upgrade: up.reference.clone(),
        activation_receipt: complete,
    })))
    .unwrap();
    assert!(matches!(done.as_ref(), Response::ServingReady(_)));
    let serving = resumed.serving().unwrap();
    assert!(Arc::ptr_eq(&opened, &serving));
}
#[test]
#[ignore = "requires explicit disposable PostgreSQL"]
fn fresh_origin_blocks_released_startup_and_remains_logically_empty() {
    let mut fixture = Fixture::new(false);
    let p = prepared(&fixture.url);
    let inspection = inspect(&p);
    let Response::Inspected(i) = inspection.as_ref() else {
        panic!()
    };
    assert_eq!(i.state, InspectionState::Empty);
    let opened = run(p.open(OpenBinding::Empty)).unwrap();
    // This is the first DML of the released SCHEMA transaction; keys is later.
    no_write(
        &mut fixture.raw,
        "BEGIN; CREATE TABLE IF NOT EXISTS public.store_revision(only_row boolean PRIMARY KEY DEFAULT true CHECK(only_row),revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0)); INSERT INTO public.store_revision(only_row,revision) VALUES(true,0) ON CONFLICT(only_row) DO NOTHING; CREATE TABLE public.keys(id text PRIMARY KEY); COMMIT",
    );
    fixture.raw.batch_execute("ROLLBACK").unwrap();
    assert!(!fixture.raw.query_one("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='keys')",&[]).unwrap().get::<_,bool>(0));
    drop(opened);
    drop(p);
    let resumed = prepared(&fixture.url);
    let inspection = inspect(&resumed);
    let Response::Inspected(i) = inspection.as_ref() else {
        panic!()
    };
    assert_eq!(i.state, InspectionState::Empty);
    assert!(i.source.is_none());
    run(resumed.open(OpenBinding::Empty)).unwrap();
}
