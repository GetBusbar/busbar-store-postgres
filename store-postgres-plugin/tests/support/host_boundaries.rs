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
    let real = unsafe { Door::read_parts(busbar_store_postgres::door()) };
    let mut ops = unsafe {
        real.ops
            .cast::<busbar_contract::abi::store::Ops>()
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
    let name = format!(
        "postgres_ready_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let config: serde_json::Value =
        serde_json::from_str(&inputs().replace("{fold}", &name)).unwrap();
    let settings = serde_json::to_vec(&config["settings"]).unwrap();
    create_fold_schema(&name, &settings);
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of_raw(ready_door).expect("actual restated door");
    let p = load_linked::<Store>(&row, common::bind(&d)).expect("actual restated door loads");
    let plugin_name = p.name().to_string();
    let held = Arc::clone(&p.inner);
    let first = || held.crossings.load(Ordering::SeqCst) - held.resumes.load(Ordering::SeqCst);
    let before = first();
    let e = LoadedStore::open(p, d, &settings, common::mint)
        .err()
        .expect("READY fails");
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
    drop_fold_schema(&name, &settings);
}

#[test]
fn postgres_declares_exactly_its_statement_needs_and_requested_profile() {
    let row = LinkedRow::of(busbar_store_postgres::door).unwrap();
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
    if std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some() {
        assert!(!cfg!(debug_assertions), "release profile requested");
    }
}
