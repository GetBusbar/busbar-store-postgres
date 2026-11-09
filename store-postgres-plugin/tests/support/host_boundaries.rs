// SPDX-License-Identifier: Apache-2.0
//! Host refusal inputs around the actual Postgres door and actual connector.
use super::*;
use busbar_contract::abi::mechanism::{
    call::{AbiStr, Op, Outcome, RawOutcome},
    door::Door,
};
use std::sync::{
    atomic::{AtomicPtr, AtomicU64, Ordering},
    Mutex,
};
static READY_DOOR: AtomicPtr<Door> = AtomicPtr::new(std::ptr::null_mut());
static READY_COUNT: AtomicU64 = AtomicU64::new(0);
static CLOSE_COUNT: AtomicU64 = AtomicU64::new(0);
static ORIGINAL_CLOSE: Mutex<Option<Op>> = Mutex::new(None);
static CLOSE_ANSWER: Mutex<Option<Outcome>> = Mutex::new(None);
extern "C" fn ready_door() -> *const Door {
    READY_DOOR.load(Ordering::SeqCst)
}
extern "C" fn fail_ready(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    READY_COUNT.fetch_add(1, Ordering::SeqCst);
    let result = RawOutcome::of(Outcome::Failed);
    // SAFETY: READY lends a full writable OutHead; the error is process-static.
    unsafe {
        let o = &mut *out.cast::<busbar_contract::abi::mechanism::call::OutHead>();
        o.outcome = result;
        o.error = AbiStr::of("postgres discovery refused");
    }
    result
}
extern "C" fn observe_close(
    instance: *mut std::ffi::c_void,
    input: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> RawOutcome {
    CLOSE_COUNT.fetch_add(1, Ordering::SeqCst);
    let close = ORIGINAL_CLOSE.lock().unwrap().unwrap();
    // SAFETY: forwards unchanged matching CLOSE frames and actual live instance once.
    let answer = unsafe { close(instance, input, out) };
    *CLOSE_ANSWER.lock().unwrap() = Some(answer.outcome());
    answer
}
#[test]
fn failed_postgres_ready_closes_the_actual_successful_open_once() {
    // SAFETY: the actual macro door and full store operation table are static.
    let real = busbar_store_postgres::door().parts();
    let mut ops = unsafe {
        real.ops
            .cast::<busbar_contract::abi::store::v4::Ops>()
            .read_unaligned()
    };
    *ORIGINAL_CLOSE.lock().unwrap() = ops.head.close;
    ops.head.close = Some(observe_close);
    let ops = Box::leak(Box::new(ops));
    // Only READY fails and CLOSE observes; every store operation remains the real product's.
    let door = unsafe {
        Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
            size: std::mem::size_of::<Door>() as u32,
            ready: Some(fail_ready),
            ops: std::ptr::from_ref(ops).cast(),
            ..real
        })
    };
    READY_DOOR.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
    let settings =
        serde_json::to_vec(&serde_json::json!({"url":"postgres://test@127.0.0.1/test"})).unwrap();
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let row = LinkedRow::of_raw(ready_door).expect("actual restated door");
    let p = load_linked::<Store>(&row, common::bind(&d)).expect("actual restated door loads");
    let plugin_name = p.name().to_string();
    let held = p.test_invocation_probe();
    let first = || {
        let (crossings, resumes) = held();
        crossings - resumes
    };
    let before = first();
    let e = match common::run(LoadedPersistence::open(p, d, &settings, common::limits())) {
        Err(error) => error,
        Ok(_) => panic!("READY fails"),
    };
    assert_eq!(
        e,
        format!("plugin '{plugin_name}' ready failed: postgres discovery refused")
    );
    assert_eq!(READY_COUNT.load(Ordering::SeqCst), 1, "READY never retried");
    assert_eq!(
        CLOSE_COUNT.load(Ordering::SeqCst),
        1,
        "successful OPEN closed exactly once"
    );
    assert_eq!(*CLOSE_ANSWER.lock().unwrap(), Some(Outcome::Ready));
    assert_eq!(first() - before, 3, "OPEN, failed READY, cleanup CLOSE");
}

#[test]
fn postgres_declares_exactly_its_statement_needs_and_requested_profile() {
    let row = LinkedRow::of_kind::<Store>(
        busbar_store_postgres::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
    .unwrap();
    let statement = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    let declares: serde_json::Value =
        serde_json::from_str(include_str!("../../../store-postgres/declares.json")).unwrap();
    let mut stated: Vec<_> = statement
        .needs
        .iter()
        .map(|n| n.transport.as_str())
        .collect();
    stated.sort();
    stated.dedup();
    let mut declared: Vec<_> = declares["needs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    declared.sort();
    declared.dedup();
    assert_eq!(stated, declared);
    #[cfg(debug_assertions)]
    assert!(
        std::env::var_os("BUSBAR_EXPECT_RELEASE").is_none(),
        "release profile requested"
    );
}

use busbar_contract::abi::host::conn::connector::{service, EstablishIn, IoIn, StreamIn};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::conn::ConnError;
use busbar_plugin_loader::dispatch::conn_services::CONN_SLOTS;
use std::ffi::c_void;
fn head(op: u32, size: usize) -> ServiceHead {
    ServiceHead {
        size: u32::try_from(size).unwrap_or(u32::MAX),
        op,
        handle: CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        },
    }
}

fn out() -> ServiceOut {
    // SAFETY: a plain repr(C) value of integers and a NULL/0 string: all-zero is valid.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    out.size = std::mem::size_of::<ServiceOut>() as u32;
    out
}

fn answered(raw: RawOutcome, o: &ServiceOut) -> (Outcome, u64, String) {
    let text = if o.error.ptr.is_null() {
        String::new()
    } else {
        // SAFETY: the host's text, `'static` (interned) or held for the call.
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) })
            .into_owned()
    };
    (raw.outcome(), o.value, text)
}

fn establish(p: &Plugin<Store>, need: u32, target: &str) -> (Outcome, u64, String) {
    let none = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    let i = EstablishIn {
        head: head(service::ESTABLISH, std::mem::size_of::<EstablishIn>()),
        need,
        timeout_ms: 5_000,
        target: AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        },
        within: none,
        member: none,
    };
    let mut o = out();
    let f = CONN_SLOTS.establish.expect("the host offers ESTABLISH");
    // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
    let raw = unsafe {
        f(
            p.test_host_context(),
            std::ptr::from_ref(&i).cast::<c_void>(),
            &mut o,
        )
    };
    answered(raw, &o)
}

fn io(p: &Plugin<Store>, stream: u64, write: bool) -> (Outcome, u64, String) {
    let mut buf = *b"x";
    let (op, f) = if write {
        (service::WRITE, CONN_SLOTS.write)
    } else {
        (service::READ, CONN_SLOTS.read)
    };
    let i = IoIn {
        head: head(op, std::mem::size_of::<IoIn>()),
        stream,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
    };
    let mut o = out();
    // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let raw = unsafe {
            f.expect("the host offers READ and WRITE")(
                p.test_host_context(),
                std::ptr::from_ref(&i).cast::<c_void>(),
                &mut o,
            )
        };
        let answer = answered(raw, &o);
        if answer.0 != Outcome::Pending || std::time::Instant::now() >= until {
            return answer;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn close_stream(p: &Plugin<Store>, stream: u64) -> (Outcome, u64, String) {
    let i = StreamIn {
        head: head(service::CLOSE, std::mem::size_of::<StreamIn>()),
        stream,
    };
    let mut o = out();
    // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
    let raw = unsafe {
        CONN_SLOTS.close.expect("the host offers CLOSE")(
            p.test_host_context(),
            std::ptr::from_ref(&i).cast::<c_void>(),
            &mut o,
        )
    };
    answered(raw, &o)
}

#[test]
fn actual_postgres_instances_refuse_undeclared_needs_and_foreign_connections() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let d = Arc::new(Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    ));
    let table = common::postgres_io::host(d.conn_waker(), Default::default());
    let row = LinkedRow::of_kind::<Store>(
        busbar_store_postgres::door as busbar_contract::abi::mechanism::door::DoorFn,
    )
    .unwrap();
    let owner = load_linked::<Store>(
        &row,
        Bind {
            conns: ConnTable::Host(table.clone()),
            ..common::bind(&d)
        },
    )
    .unwrap();
    let other = load_linked::<Store>(
        &row,
        Bind {
            conns: ConnTable::Host(table),
            ..common::bind(&d)
        },
    )
    .unwrap();
    owner.test_in_host_operation(|| {
        let (outcome, stream, text) = establish(&owner, 0, &target);
        assert_eq!(outcome, Outcome::Ready, "declared need opens: {text}");
        let _accepted = listener
            .accept()
            .expect("actual TCP carrier reaches the listener");
        for need in [1, u32::MAX] {
            let (answer, _, text) = establish(&owner, need, &target);
            assert_eq!(
                (answer, text.as_str()),
                (Outcome::Refused, ConnError::UndeclaredNeed.text())
            );
        }
        assert_eq!(io(&owner, stream, true).0, Outcome::Ready, "owner writes");
        for (what, (answer, _, text)) in [
            ("write", io(&other, stream, true)),
            ("read", io(&other, stream, false)),
            ("close", close_stream(&other, stream)),
        ] {
            assert_eq!(
                (answer, text.as_str()),
                (Outcome::Refused, ConnError::NotOwner.text()),
                "foreign {what}"
            );
        }
        assert_eq!(
            io(&owner, stream, true).0,
            Outcome::Ready,
            "owner connection untouched"
        );
        assert_eq!(close_stream(&owner, stream).0, Outcome::Ready);
    });
}
