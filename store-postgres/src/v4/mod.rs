// SPDX-License-Identifier: Apache-2.0
//! Normal primitive PostgreSQL door. Legacy decoding remains separate.
use crate::{ConnectionSettings, Session};
use busbar_contract::abi::sdk::store::v4::backend::{Backend as NativeBackend, Committed};
use busbar_contract::abi::sdk::store::v4::retirement::Horizon;
use busbar_contract::abi::sdk::store::wire::{drive_kept, Body};
use busbar_contract::abi::sdk::store::{Op, Step};
use busbar_contract::persistence::*;
use busbar_contract::redacted::Secret;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
type Horizons = Arc<Mutex<HashMap<[u8; 16], Horizon>>>;
use zeroize::Zeroizing;
mod lifecycle;
mod native;
use std::sync::atomic::{AtomicBool, Ordering};
busbar_contract::own_seal!(Own);
struct Backend {
    store: ConnectionSettings,
    info: Arc<OnceLock<BackendInfo>>,
    own: Own,
    horizons: Horizons,
    lifecycle: Arc<lifecycle::NativeLifecycle>,
    opened: Arc<AtomicBool>,
}
macro_rules! connection {
    ($self:ident, $op:ident, $error:expr, |$session:ident| $body:expr) => {{
        let shared = $self.store.shared();
        let pool = shared.pool.clone();
        drive_kept($op, &pool, move |wire| -> Body<_> {
            Box::pin(async move {
                let mut $session = Session::open(wire, shared).await.map_err(|_| $error)?;
                let answer = $body;
                $session.close().await;
                answer
            })
        })
    }};
}
impl NativeBackend for Backend {
    type Owner = Own;
    fn owner(&self) -> &Own {
        &self.own
    }
    // Explicit ABI allocation admission: spans already carry u32 value dimensions.
    // No lower aggregate batch limit is imposed by this adapter.
    fn input_budget(&self) -> usize {
        isize::MAX as usize
    }
    fn validate(settings: &[u8]) -> Result<(), String> {
        crate::settings::parse(settings, &[]).map(drop)
    }
    fn open(
        settings: &[u8],
        secrets: &[&[u8]],
        _: Option<
            busbar_contract::abi::sdk::conn::Host<busbar_contract::plugin::markers::StoreKind>,
        >,
    ) -> Result<Self, String> {
        Ok(Self {
            store: crate::settings::parse(settings, secrets)?,
            info: Arc::new(OnceLock::new()),
            own: Own::here(),
            horizons: Arc::default(),
            lifecycle: Arc::new(lifecycle::NativeLifecycle::new()),
            opened: Arc::new(AtomicBool::new(false)),
        })
    }
    fn connect(&self, op: &mut Op<'_>) -> Step<Result<(), String>> {
        let info = self.info.clone();
        let opened = self.opened.clone();
        connection!(
            self,
            op,
            "postgres v4 connection unavailable".to_string(),
            |s| {
                let allow = lifecycle::admit(&mut s, None)
                    .await
                    .map_err(|_| "postgres v4 admission refused".to_string())?;
                match native::connect(&mut s, allow).await {
                    Ok(value) => {
                        if let Some(old) = info.get() {
                            if *old != value {
                                return Err("postgres v4 identity changed".into());
                            }
                        } else {
                            let _ = info.set(value);
                        }
                        opened.store(true, Ordering::Release);
                        Ok(())
                    }
                    Err(_) => Err("postgres v4 admission refused".into()),
                }
            }
        )
    }
    fn connect_prepared(
        &self,
        op: &mut Op<'_>,
        binding: &busbar_contract::persistence::lifecycle::OpenBinding,
    ) -> Step<Result<(), String>> {
        let binding = binding.clone();
        // Snapshot/control and the ordinary reopen must observe one native instance.
        // The retained owner is shared without copying a socket or executor.
        let lifecycle = self.lifecycle.clone();
        let info = self.info.clone();
        let opened = self.opened.clone();
        connection!(
            self,
            op,
            "postgres v4 connection unavailable".to_string(),
            |s| {
                lifecycle
                    .verify_open(&mut s)
                    .await
                    .map_err(|_| "postgres v4 prepared instance changed".to_string())?;
                let allow = lifecycle::admit(&mut s, Some(&binding))
                    .await
                    .map_err(|_| "postgres v4 prepared binding refused".to_string())?;
                let value = native::connect(&mut s, allow)
                    .await
                    .map_err(|_| "postgres v4 admission refused".to_string())?;
                if info.get().is_some_and(|old| *old != value) {
                    return Err("postgres v4 identity changed".into());
                }
                let _ = info.set(value);
                opened.store(true, Ordering::Release);
                Ok(())
            }
        )
    }
    fn bootstrap(
        &self,
        op: &mut Op<'_>,
        request: &busbar_contract::persistence::lifecycle::Request<Own>,
    ) -> Step<
        Result<
            busbar_contract::persistence::lifecycle::Response<Own>,
            busbar_contract::persistence::lifecycle::Error,
        >,
    > {
        self.lifecycle
            .bootstrap(op, self.store.shared(), self.info.clone(), request)
    }
    fn info(&self) -> BackendInfo {
        *self.info.get().expect("connected v4 backend")
    }
    fn read(&self, op: &mut Op<'_>, request: &Read) -> Step<Result<ReadResult<Own>, Failure>> {
        let request = Read {
            dataset: request.dataset,
            addresses: request.addresses.clone(),
            time: request.time,
        };
        let info = self.info();
        if !self.opened.load(Ordering::Acquire) {
            return self
                .lifecycle
                .target(op, self.store.shared(), move |s, info| {
                    Box::pin(async move { native::read(s, info, request).await })
                });
        }
        connection!(self, op, Failure::Unavailable, |s| native::read(
            &mut s, info, request
        )
        .await)
    }
    fn scan(&self, op: &mut Op<'_>, request: &Scan) -> Step<Result<Page<Own>, Failure>> {
        let request = Scan {
            dataset: request.dataset,
            namespace: request.namespace,
            prefix: request.prefix.clone(),
            after: request.after.clone(),
            generation: request.generation,
            allow_change: request.allow_change,
            max_items: request.max_items,
            max_bytes: request.max_bytes,
        };
        let info = self.info();
        if !self.opened.load(Ordering::Acquire) {
            return self
                .lifecycle
                .target(op, self.store.shared(), move |s, info| {
                    Box::pin(async move { native::scan(s, info, request).await })
                });
        }
        connection!(self, op, Failure::Unavailable, |s| native::scan(
            &mut s, info, request
        )
        .await)
    }
    fn commit(
        &self,
        op: &mut Op<'_>,
        request: &PreparedCandidate<Own>,
    ) -> Step<Result<Committed<Own>, Failure>> {
        let request = request.clone();
        let info = self.info();
        let horizons = self.horizons.clone();
        if !self.opened.load(Ordering::Acquire) {
            return self
                .lifecycle
                .target(op, self.store.shared(), move |s, info| {
                    Box::pin(async move {
                        let result = native::commit(s, info, request).await.map_err(|error| {
                            if error == Failure::Unavailable {
                                Failure::Refused
                            } else {
                                error
                            }
                        });
                        if matches!(
                            &result,
                            Ok(Committed {
                                decision: Decision::Applied(_),
                                ..
                            })
                        ) {
                            let _ = native::maintain(s, info, &horizons).await;
                        }
                        result
                    })
                });
        }
        connection!(self, op, Failure::Unknown, |s| {
            let result = native::commit(&mut s, info, request).await.map_err(|e| {
                if e == Failure::Unavailable {
                    Failure::Refused
                } else {
                    e
                }
            });
            if matches!(
                &result,
                Ok(Committed {
                    decision: Decision::Applied(_),
                    ..
                })
            ) {
                let _ = native::maintain(&mut s, info, &horizons).await;
            }
            result
        })
    }
    fn clock(
        &self,
        op: &mut Op<'_>,
        dataset: DatasetId,
    ) -> Step<Result<ClockObservation, Failure>> {
        let info = self.info();
        if !self.opened.load(Ordering::Acquire) {
            return self
                .lifecycle
                .target(op, self.store.shared(), move |s, info| {
                    Box::pin(async move { native::clock(s, info, dataset).await })
                });
        }
        connection!(self, op, Failure::Unavailable, |s| native::clock(
            &mut s, info, dataset
        )
        .await)
    }
}
busbar_contract::store_v4_door!(Backend, crate::NAME, env!("CARGO_PKG_VERSION"), 64, needs: crate::settings::NEEDS,
    settings_schema: busbar_contract::abi::mechanism::call::Blob::json(include_bytes!("../settings.schema.json")));
fn held(bytes: Vec<u8>) -> Secret<Vec<u8>, Own> {
    let mut bytes = Zeroizing::new(bytes);
    Secret::held(std::mem::take(&mut *bytes))
}

#[cfg(test)]
mod native_tests;

#[cfg(test)]
#[path = "../tests/kept_product.rs"]
mod kept_product;
#[cfg(test)]
#[path = "../tests/tls.rs"]
mod transport_tests;
