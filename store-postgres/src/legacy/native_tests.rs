// SPDX-License-Identifier: Apache-2.0
//! Native import witnesses use a test-only door solely to obtain an existing host
//! Wire lease. Production import is not exposed through normal Store operations.
use super::*;
use busbar_contract::abi::sdk::store::v4::backend::{Backend, Committed};
use busbar_contract::abi::sdk::store::{Op, Step};
use busbar_contract::persistence as p;
use busbar_plugin_loader::dispatch::kinds::store_v4::StoreV4;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use busbar_plugin_loader::store_v4::{Limits as DoorLimits, LoadedPersistence};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

busbar_contract::own_seal!(Own);
struct Probe {
    settings: Zeroizing<Vec<u8>>,
    own: Own,
}
impl Backend for Probe {
    type Owner = Own;
    fn owner(&self) -> &Own {
        &self.own
    }
    fn input_budget(&self) -> usize {
        1024 * 1024
    }
    fn validate(_: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn open(
        settings: &[u8],
        _: &[&[u8]],
        _: Option<
            busbar_contract::abi::sdk::conn::Host<busbar_contract::plugin::markers::StoreKind>,
        >,
    ) -> Result<Self, String> {
        Ok(Self {
            settings: Zeroizing::new(settings.to_vec()),
            own: Own::here(),
        })
    }
    fn connect_prepared(
        &self,
        _: &mut Op<'_>,
        _: &p::lifecycle::OpenBinding,
    ) -> Step<Result<(), String>> {
        Step::Ready(Err(
            "historical qualification probe has no serving binding".into()
        ))
    }
    fn bootstrap(
        &self,
        _: &mut Op<'_>,
        _: &p::lifecycle::Request<Own>,
    ) -> Step<Result<p::lifecycle::Response<Own>, p::lifecycle::Error>> {
        Step::Ready(Err(p::lifecycle::Error::MissingCapability))
    }
    fn connect(&self, op: &mut Op<'_>) -> Step<Result<(), String>> {
        let settings = self.settings.clone();
        busbar_contract::abi::sdk::store::wire::drive(op, move |wire| {
            Box::pin(async move {
                let json: serde_json::Value = serde_json::from_slice(&settings).unwrap();
                let url = json["url"].as_str().unwrap();
                let case = json["case"].as_str().unwrap();
                let settings = serde_json::json!({"url":url}).to_string();
                let limits = Limits {
                    rows: 1,
                    page_bytes: 4096,
                    row_bytes: if case == "oversized" { 32 } else { 4096 },
                };
                let result = Reader::<Own>::open(wire, settings.as_bytes(), &[], limits).await;
                if matches!(case, "unknown" | "damaged" | "newer") {
                    let expected = if case == "damaged" {
                        Error::Damaged
                    } else {
                        Error::Unsupported
                    };
                    assert!(matches!(result, Err(error) if error == expected));
                    return Ok(());
                }
                let mut reader = result.map_err(|error| format!("import probe {error:?}"))?;
                let flags = reader.session.as_mut().unwrap().client().query_one("SELECT current_setting('transaction_read_only')='on',current_setting('transaction_isolation')='repeatable read'",&[]).await.unwrap();
                assert!(flags.try_get::<_, bool>(0).unwrap());
                assert!(flags.try_get::<_, bool>(1).unwrap());
                if case == "oversized" {
                    for _ in 0..32 {
                        match reader.page().await {
                            Err(Error::Budget) => break,
                            Ok(page) => {
                                assert!(!page.exhausted, "oversized row was silently skipped")
                            }
                            Err(error) => panic!("unexpected refusal {error:?}"),
                        }
                    }
                    assert!(matches!(reader.page().await, Err(Error::Closed)));
                    return Ok(());
                }
                let version = match case {
                    "released" => 6,
                    "dev7" => 7,
                    "dev8" => 8,
                    _ => 9,
                };
                assert_eq!(reader.catalogue().schema_version, version);
                assert!(!reader.catalogue().snapshot.is_empty());
                let mut observed = Vec::new();
                let mut pages = 0;
                loop {
                    let page = reader.page().await.unwrap();
                    assert!(page.rows.len() <= 1);
                    if pages == 0 {
                        // A second native session changes data after snapshot capture.
                        // Every later table remains tied to the first reader snapshot.
                        let mut writer = postgres::Client::connect(url, postgres::NoTls).unwrap();
                        writer
                            .batch_execute("UPDATE public.keys SET name='changed-after-snapshot'")
                            .unwrap();
                    }
                    for row in &page.rows {
                        let table = &reader.catalogue().tables[row.table];
                        let decoded =
                            legacy_row::Row::decode(row.bytes.expose_own(&Own::here())).unwrap();
                        if table.name == "keys" {
                            let name = table
                                .columns
                                .iter()
                                .position(|column| column.name == "name")
                                .unwrap();
                            assert!(
                                decoded.cells().nth(name).unwrap()
                                    != Cell::Text(b"changed-after-snapshot")
                            );
                        }
                        if table.name == "usage_ledger" && version == 9 {
                            let quantity = table
                                .columns
                                .iter()
                                .position(|column| column.name == "tokens_input")
                                .unwrap();
                            assert_eq!(
                                decoded.cells().nth(quantity),
                                Some(Cell::Text(b"170141183460469231731687303715884105727"))
                            );
                        }
                        if table.name == "usage_ledger" && matches!(version, 7 | 8) {
                            let quantity = table
                                .columns
                                .iter()
                                .position(|column| column.name == "tokens_input")
                                .unwrap();
                            assert_eq!(
                                decoded.cells().nth(quantity),
                                Some(Cell::Integer(i64::MAX))
                            );
                        }
                        if table.name == "store_records" {
                            assert_eq!(decoded.cells().nth(2), Some(Cell::Blob(&[0, 255, 0])));
                        }
                        observed.push((row.table, row._ordinal));
                    }
                    pages += 1;
                    if page.exhausted {
                        break;
                    }
                    assert!(pages < 100, "bounded fixture traverses");
                }
                assert!(observed.len() >= 8);
                assert!(observed.windows(2).all(|pair| pair[0] < pair[1]));
                assert!(reader.page().await.unwrap().exhausted);
                assert!(reader.page().await.unwrap().rows.is_empty());
                reader.close().await.unwrap();
                Ok(())
            })
        })
    }
    fn info(&self) -> p::BackendInfo {
        p::BackendInfo {
            dataset: p::DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: p::Durability::Local,
        }
    }
    fn read(&self, _: &mut Op<'_>, _: &p::Read) -> Step<Result<p::ReadResult<Own>, p::Failure>> {
        Step::Ready(Err(p::Failure::Refused))
    }
    fn scan(&self, _: &mut Op<'_>, _: &p::Scan) -> Step<Result<p::Page<Own>, p::Failure>> {
        Step::Ready(Err(p::Failure::Refused))
    }
    fn commit(
        &self,
        _: &mut Op<'_>,
        _: &p::PreparedCandidate<Own>,
    ) -> Step<Result<Committed<Own>, p::Failure>> {
        Step::Ready(Err(p::Failure::Refused))
    }
    fn clock(
        &self,
        _: &mut Op<'_>,
        _: p::DatasetId,
    ) -> Step<Result<p::ClockObservation, p::Failure>> {
        Step::Ready(Err(p::Failure::Refused))
    }
}
busbar_contract::store_v4_door!(Probe,"postgres-import-probe","0",8,needs:crate::settings::NEEDS);

fn run<F: std::future::Future>(future: F) -> F::Output {
    struct Wake(std::thread::Thread);
    impl std::task::Wake for Wake {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(Arc::new(Wake(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}
fn probe(url: &str, case: &str) {
    let dispatcher = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(crate::tests::postgres_clock::PostgresClock),
        busbar_contract::services::test_caller_binding(),
    ));
    let conns = crate::tests::postgres_io::host(dispatcher.conn_waker(), Default::default());
    let row = LinkedRow::of_kind::<StoreV4>(door as busbar_contract::abi::mechanism::door::DoorFn)
        .unwrap();
    let plugin = load_linked::<StoreV4>(
        &row,
        Bind {
            instance: Arc::from("historical-import-probe"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(
                busbar_contract::conn::admissions::AdmissionAuthority::issue(
                    &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
                    conns,
                    Default::default(),
                ),
            ),
        },
    )
    .unwrap();
    let settings = serde_json::json!({"url":url,"case":case}).to_string();
    run(LoadedPersistence::open(
        plugin,
        dispatcher,
        settings.as_bytes(),
        DoorLimits {
            descriptor_bytes: 1024 * 1024,
            output_items: 16,
            output_bytes: 4096,
            decode_bytes: 8192,
        },
    ))
    .expect("native import probe");
}
struct Fixture {
    admin: postgres::Client,
    name: String,
    url: String,
    raw: postgres::Client,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let admin_url = std::env::var("BUSBAR_TEST_POSTGRES_IMPORT_URL")
            .expect("explicit disposable native administrator endpoint");
        let mut admin = postgres::Client::connect(&admin_url, postgres::NoTls).unwrap();
        let name = format!(
            "corefix_import_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        admin
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap();
        let url = format!("{admin_url} dbname={name}");
        let raw = postgres::Client::connect(&url, postgres::NoTls).unwrap();
        Self {
            admin,
            name,
            url,
            raw,
        }
    }
    fn released(&mut self) {
        // The published fixture remains immutable. This restores it into a new
        // disposable database, with provenance covered by its MANIFEST.tsv.
        self.raw
            .batch_execute(include_str!("../../tests/fixtures/1.5.5/dump.sql"))
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self
            .admin
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name));
    }
}

#[test]
#[ignore = "requires approved disposable BUSBAR_TEST_POSTGRES_IMPORT_URL"]
fn native_legacy_import_released_snapshot_pages_and_damage_refusal() {
    let mut fixture = Fixture::new();
    fixture.released();
    probe(&fixture.url, "released");
    let stamps: Vec<i64> = fixture
        .raw
        .query(
            "SELECT version FROM public.busbar_schema ORDER BY version",
            &[],
        )
        .unwrap()
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(stamps, vec![6]);
    assert_eq!(
        fixture
            .raw
            .query_one(
                "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        9
    );
    fixture
        .raw
        .batch_execute("CREATE TABLE public.unknown_import_table (id bigint)")
        .unwrap();
    probe(&fixture.url, "unknown");
    fixture.raw.batch_execute("DROP TABLE public.unknown_import_table; ALTER TABLE public.credentials DROP CONSTRAINT credentials_public_id_uniq").unwrap();
    probe(&fixture.url, "damaged");
}

#[test]
#[ignore = "requires approved disposable BUSBAR_TEST_POSTGRES_IMPORT_URL"]
fn native_legacy_import_current_numeric_blob_and_oversized_row_refusal() {
    let mut fixture = Fixture::new();
    fixture.raw.batch_execute(include_str!("dev9.sql")).unwrap();
    fixture.raw.batch_execute("INSERT INTO public.busbar_schema VALUES (9); INSERT INTO public.keys(id,generation_hash,name,created_at) VALUES('native-test','fingerprint','original',0); INSERT INTO public.store_records VALUES('schema',decode('00','hex'),decode('00ff00','hex')); INSERT INTO public.usage_ledger VALUES('native-test',0,'model',170141183460469231731687303715884105727,0,0,0); INSERT INTO public.denylist VALUES('test','reason',0); INSERT INTO public.usage_windows VALUES('native-test',0,1,1); INSERT INTO public.store_ops VALUES(decode('00','hex'),'body','answer',0)").unwrap();
    probe(&fixture.url, "current");
    probe(&fixture.url, "oversized");
    fixture
        .raw
        .batch_execute("INSERT INTO public.busbar_schema VALUES(10)")
        .unwrap();
    probe(&fixture.url, "newer");
}

#[test]
#[ignore = "requires approved disposable BUSBAR_TEST_POSTGRES_IMPORT_URL"]
fn native_legacy_import_dev_seven_and_eight_keep_exact_bigints() {
    for version in [7, 8] {
        let mut fixture = Fixture::new();
        fixture
            .raw
            .batch_execute(include_str!("dev7_8.sql"))
            .unwrap();
        fixture.raw.batch_execute(&format!("INSERT INTO public.busbar_schema VALUES ({version}); INSERT INTO public.keys(id,generation_hash,name,created_at) VALUES('native-test','fingerprint','original',0); INSERT INTO public.store_records VALUES('schema',decode('00','hex'),decode('00ff00','hex')); INSERT INTO public.usage_ledger VALUES('native-test',0,'model',9223372036854775807,0,0,0); INSERT INTO public.denylist VALUES('test','reason',0); INSERT INTO public.usage_windows VALUES('native-test',0,1,1); INSERT INTO public.store_ops VALUES(decode('00','hex'),'body','answer',0)")).unwrap();
        probe(&fixture.url, if version == 7 { "dev7" } else { "dev8" });
    }
}
