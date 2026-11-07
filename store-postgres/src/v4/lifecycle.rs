// SPDX-License-Identifier: Apache-2.0
//! Automatic native pre-open ownership. The three clients use SDK Channels,
//! never three clones of one socket and never a private executor.
use super::{native, Own};
use crate::{Session, Shared};
use busbar_contract::abi::sdk::store::wire::{drive_channels, Body, Channels, Wire};
use busbar_contract::abi::sdk::store::{Op, Step};
use busbar_contract::abi::sdk::{digest::sha256, store::v4::metadata};
use busbar_contract::persistence::{lifecycle::*, *};
use busbar_contract::redacted::{constant_time_eq, Secret};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;
mod control;
mod guards;
mod origin;

fn db(error: crate::pgwire::Error) -> Error {
    match error.code().map(|code| code.code()) {
        Some("55P03" | "40P01" | "40001") => Error::Busy,
        Some("42501") => Error::MissingCapability,
        _ => Error::Unavailable,
    }
}
fn source_error(error: crate::legacy::Error) -> Error {
    use crate::legacy::Error as E;
    match error {
        E::Unavailable => Error::Unavailable,
        E::Unsupported => Error::UnsupportedFormat,
        E::Damaged => Error::Corrupt,
        E::Budget => Error::Bounds,
        E::Closed => Error::SourceChanged,
    }
}
fn native_error(error: Failure) -> Error {
    match error {
        Failure::Corrupt => Error::Corrupt,
        Failure::Refused => Error::Refused,
        _ => Error::Unavailable,
    }
}
fn bounds(bounds: Bounds) -> Result<crate::legacy::Limits, Error> {
    let bytes = bounds.bytes as usize;
    if bounds.items == 0 || bounds.items > 4096 || !(1024..=512 * 1024 * 1024).contains(&bytes) {
        return Err(Error::Bounds);
    }
    Ok(crate::legacy::Limits {
        rows: bounds.items as usize,
        page_bytes: ((bytes - 512) / 4).min(64 * 1024 * 1024),
        row_bytes: ((bytes - 512) / 8).min(64 * 1024 * 1024),
    })
}
fn catalogue(catalogue: &crate::legacy::Catalogue) -> Vec<archive::Table> {
    catalogue
        .tables
        .iter()
        .map(|table| archive::Table {
            name: table.name.clone(),
            columns: table.columns.iter().map(|c| c.name.clone()).collect(),
            native_layout: table.native_layout.clone(),
        })
        .collect()
}
fn layout(catalogue: &crate::legacy::Catalogue) -> Result<Digest, Error> {
    let bytes = serde_json::to_vec(&catalogue.tables).map_err(|_| Error::Corrupt)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(Error::Bounds);
    }
    Ok(sha256(&bytes))
}
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LiveIdentity {
    database_oid: String,
    database_name: String,
    server_address: String,
    server_port: i32,
    postmaster: String,
}
impl LiveIdentity {
    async fn read(session: &mut Session) -> Result<Self, Error> {
        let row=session.client().query_one("SELECT d.oid::text,d.datname::text,COALESCE(pg_catalog.inet_server_addr()::text,'unix'),COALESCE(pg_catalog.inet_server_port(),0),pg_catalog.pg_postmaster_start_time()::text,pg_catalog.pg_backend_pid() FROM pg_catalog.pg_database d WHERE d.datname=current_database()",&[]).await.map_err(db)?;
        let actual: i32 = row.try_get(5).map_err(db)?;
        if session.client().native_pid() != Some(actual) {
            return Err(Error::MissingCapability);
        }
        Ok(Self {
            database_oid: row.try_get(0).map_err(db)?,
            database_name: row.try_get(1).map_err(db)?,
            server_address: row.try_get(2).map_err(db)?,
            server_port: row.try_get(3).map_err(db)?,
            postmaster: row.try_get(4).map_err(db)?,
        })
    }
    fn bytes(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::Corrupt)
    }
    fn source(&self, catalogue: &crate::legacy::Catalogue) -> Result<SourceIdentity, Error> {
        let anchor = sha256(&self.bytes()?);
        let mut dataset = [0; 16];
        dataset.copy_from_slice(&anchor[..16]);
        Ok(SourceIdentity {
            native_anchor: anchor,
            dataset: DatasetId(dataset),
            format: Some(Format {
                owner: POSTGRES_SOURCE_OWNER,
                physical: catalogue.schema_version as u32,
                logical: 0,
                codec: 1,
            }),
            catalogue_digest: catalogue.digest,
            layout_digest: layout(catalogue)?,
        })
    }
    fn same_database(&self, catalogue: &crate::legacy::Catalogue) -> Result<(), Error> {
        let previous: Self =
            serde_json::from_slice(&catalogue.native_identity).map_err(|_| Error::Corrupt)?;
        if self.database_oid != previous.database_oid
            || self.database_name != previous.database_name
        {
            return Err(Error::SourceChanged);
        }
        Ok(())
    }
}
#[derive(Default)]
struct State {
    control: Option<Session>,
    source: Option<crate::legacy::Reader<Own>>,
    source_idle: Option<Session>,
    target: Option<Session>,
    live: Option<LiveIdentity>,
    inspected: Option<SourceIdentity>,
    record: Option<control::Record>,
    authority: Option<Secret<Vec<u8>, Own>>,
    poisoned: bool,
}
pub(super) struct NativeLifecycle {
    channels: Channels,
    state: Arc<Mutex<Option<State>>>,
}
impl NativeLifecycle {
    pub(super) fn new() -> Self {
        Self {
            channels: Channels::new(3),
            state: Arc::new(Mutex::new(Some(State::default()))),
        }
    }
    pub(super) fn bootstrap(
        &self,
        op: &mut Op<'_>,
        shared: Arc<Shared>,
        info: Arc<std::sync::OnceLock<BackendInfo>>,
        request: &Request<Own>,
    ) -> Step<Result<Response<Own>, Error>> {
        let request = request.clone();
        let state = self.state.clone();
        drive_channels(op, &self.channels, move |wires| -> Body<_> {
            Box::pin(async move {
                let mut held = StateLease::take(state)?;
                if held.state().poisoned {
                    held.state().reset(&wires, shared.clone(), &request).await?;
                }
                let result = held.state().request(wires, shared, &request).await;
                if result.is_err() {
                    held.state().poisoned = true;
                }
                held.complete = true;
                if let Ok(Response::Begun(upgrade)) = &result {
                    if info.get().is_some_and(|old| *old != upgrade.target) {
                        return Err(Error::SourceChanged);
                    }
                    let _ = info.set(upgrade.target);
                }
                result
            })
        })
    }
    pub(super) async fn verify_open(&self, session: &mut Session) -> Result<(), Error> {
        let (expected, record) = {
            let held = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let state = held.as_ref().ok_or(Error::Busy)?;
            (
                state.live.clone().ok_or(Error::Refused)?,
                state.record.clone(),
            )
        };
        if LiveIdentity::read(session).await? != expected {
            return Err(Error::SourceChanged);
        }
        if let Some(record) = record {
            if control::kind(session).await? != control::Kind::Legacy
                || control::read(session).await?.id != record.id
                || target_info(session).await? != record.target()?
            {
                return Err(Error::SourceChanged);
            }
        }
        Ok(())
    }
    pub(super) fn target<T, F>(
        &self,
        op: &mut Op<'_>,
        shared: Arc<Shared>,
        body: F,
    ) -> Step<Result<T, Failure>>
    where
        T: Send + 'static,
        F: for<'a> FnOnce(
                &'a mut Session,
                BackendInfo,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<T, Failure>> + Send + 'a>,
            > + Send
            + 'static,
    {
        let state = self.state.clone();
        drive_channels(op, &self.channels, move |wires| -> Body<_> {
            Box::pin(async move {
                let mut held = StateLease::take(state).map_err(|_| Failure::Unavailable)?;
                if held.state().poisoned {
                    let record = held.state().record.clone().ok_or(Failure::Refused)?;
                    let authority = held.state().authority.clone().ok_or(Failure::Refused)?;
                    let request = Request::CheckFence {
                        upgrade: UpgradeRef {
                            id: record.id,
                            authority,
                        },
                    };
                    held.state()
                        .reset(&wires, shared.clone(), &request)
                        .await
                        .map_err(|_| Failure::Unavailable)?;
                }
                let state = held.state();
                let record = state.record.as_ref().ok_or(Failure::Refused)?.clone();
                if state.target.is_none() {
                    let mut session = Session::open(wires[2].clone(), shared)
                        .await
                        .map_err(|_| Failure::Unavailable)?;
                    let control = control::read(&mut session)
                        .await
                        .map_err(|_| Failure::Refused)?;
                    if control.id != record.id
                        || target_info(&mut session)
                            .await
                            .map_err(|_| Failure::Corrupt)?
                            != record.target().map_err(|_| Failure::Corrupt)?
                    {
                        return Err(Failure::Refused);
                    }
                    if LiveIdentity::read(&mut session)
                        .await
                        .map_err(|_| Failure::Unavailable)?
                        != state.live.clone().ok_or(Failure::Refused)?
                    {
                        return Err(Failure::Refused);
                    }
                    state.target = Some(session);
                }
                let result = body(
                    state.target.as_mut().ok_or(Failure::Unavailable)?,
                    record.target().map_err(|_| Failure::Corrupt)?,
                )
                .await;
                if result.is_err() {
                    held.state().poisoned = true;
                }
                held.complete = true;
                result
            })
        })
    }
}
struct StateLease {
    owner: Arc<Mutex<Option<State>>>,
    value: Option<State>,
    complete: bool,
}
impl StateLease {
    fn take(owner: Arc<Mutex<Option<State>>>) -> Result<Self, Error> {
        let value = owner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or(Error::Busy)?;
        Ok(Self {
            owner,
            value: Some(value),
            complete: false,
        })
    }
    fn state(&mut self) -> &mut State {
        self.value.as_mut().expect("retained native session")
    }
}
impl Drop for StateLease {
    fn drop(&mut self) {
        if let Some(mut value) = self.value.take() {
            if !self.complete {
                value.poisoned = true;
            }
            *self.owner.lock().unwrap_or_else(|e| e.into_inner()) = Some(value);
        }
    }
}
impl State {
    async fn reset(
        &mut self,
        wires: &[Wire],
        shared: Arc<Shared>,
        request: &Request<Own>,
    ) -> Result<(), Error> {
        let record = self.record.clone();
        let authority = self.authority.clone();
        self.control = None;
        self.source = None;
        self.source_idle = None;
        self.target = None;
        for wire in wires {
            wire.close().await;
        }
        self.poisoned = false;
        let _ = self
            .inspect(
                wires,
                shared.clone(),
                Bounds {
                    items: 4096,
                    bytes: 16 * 1024 * 1024,
                },
            )
            .await?;
        self.authority = authority;
        if let Some(record) = record {
            if !matches!(
                request,
                Request::Inspect { .. } | Request::BeginOrResume { .. }
            ) {
                self.inspected = Some(record.source.identity());
                self.begin(
                    wires,
                    shared,
                    &record.source.identity(),
                    record.route,
                    record.target_format.format(),
                    record.operation,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn control(
        &mut self,
        wires: &[Wire],
        shared: Arc<Shared>,
    ) -> Result<&mut Session, Error> {
        if self.control.is_none() {
            self.control = Some(
                Session::open(wires[0].clone(), shared)
                    .await
                    .map_err(|_| Error::Unavailable)?,
            );
        }
        self.control.as_mut().ok_or(Error::Unavailable)
    }
    async fn source_client(
        &mut self,
        wires: &[Wire],
        shared: Arc<Shared>,
    ) -> Result<Session, Error> {
        if let Some(reader) = self.source.take() {
            return reader.release_snapshot().await.map_err(source_error);
        }
        if let Some(session) = self.source_idle.take() {
            return Ok(session);
        }
        Session::open(wires[1].clone(), shared)
            .await
            .map_err(|_| Error::Unavailable)
    }
    async fn request(
        &mut self,
        wires: Vec<Wire>,
        shared: Arc<Shared>,
        request: &Request<Own>,
    ) -> Result<Response<Own>, Error> {
        if wires.len() != 3 {
            return Err(Error::MissingCapability);
        }
        match request {
            Request::Inspect { bounds } => self
                .inspect(&wires, shared, *bounds)
                .await
                .map(Response::Inspected),
            Request::BeginOrResume {
                expected_source,
                route_digest,
                target_format,
                operation_id,
            } => self
                .begin(
                    &wires,
                    shared,
                    expected_source,
                    *route_digest,
                    *target_format,
                    *operation_id,
                )
                .await
                .map(Response::Begun),
            Request::SourcePage {
                upgrade,
                snapshot,
                family,
                selector,
                cursor,
                bounds,
            } => self
                .page(
                    upgrade,
                    *snapshot,
                    *family,
                    selector,
                    cursor.as_ref(),
                    *bounds,
                )
                .await
                .map(Response::SourcePage),
            Request::Target { upgrade } => {
                self.authorize(upgrade)?;
                self.check(upgrade).await?;
                let record = self.record.as_ref().ok_or(Error::Refused)?;
                Ok(Response::Target(TargetBinding {
                    upgrade: record.id,
                    info: record.target()?,
                    binding: self.authority.as_ref().ok_or(Error::Refused)?.clone(),
                }))
            }
            Request::CheckFence { upgrade } => self.check(upgrade).await.map(Response::Fence),
            Request::Finish {
                upgrade,
                activation_receipt,
            } => self.finish(upgrade, activation_receipt).await,
        }
    }
    async fn inspect(
        &mut self,
        wires: &[Wire],
        shared: Arc<Shared>,
        limit: Bounds,
    ) -> Result<Inspection<Own>, Error> {
        let _ = bounds(limit)?;
        let control = self.control(wires, shared.clone()).await?;
        let live = LiveIdentity::read(control).await?;
        if control::kind(control).await? == control::Kind::EmptyOrigin {
            let info = target_info(control).await?;
            origin::verify(control, info).await?;
            let marker = admission_marker(control).await?;
            let source = if marker.is_some() {
                Some(current_identity(control, &live, info).await?)
            } else {
                if !origin::logical_empty(control).await? {
                    return Err(Error::UnsupportedFormat);
                }
                None
            };
            self.inspected = source.clone();
            self.live = Some(live);
            return Ok(Inspection {
                state: if source.is_some() {
                    InspectionState::Current
                } else {
                    InspectionState::Empty
                },
                source,
                admission_marker: marker,
                catalogue: vec![],
                capabilities: vec![NativeCapability::CurrentOpen],
            });
        }
        if control::exists(control).await? {
            let record = control::read(control).await?;
            live.same_database(&record.catalogue)?;
            guards::verify(control, &record).await?;
            if record.target()? != target_info(control).await? {
                return Err(Error::SourceChanged);
            }
            let tables = catalogue(&record.catalogue);
            check_inventory_budget(&tables, limit)?;
            let current = record.step == 3;
            if current {
                admit(control, None).await?;
            }
            let marker = admission_marker(control).await?;
            let source = if current {
                current_identity(control, &live, record.target()?).await?
            } else {
                record.source.identity()
            };
            self.inspected = Some(source.clone());
            self.record = Some(record);
            self.live = Some(live);
            return Ok(Inspection {
                state: if current {
                    InspectionState::Current
                } else {
                    InspectionState::InProgress
                },
                source: Some(source),
                admission_marker: marker,
                catalogue: tables,
                capabilities: capabilities(),
            });
        }
        let native:bool=control.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='busbar_persistence_v4')",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
        if native {
            let foreign:bool=control.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname NOT IN ('information_schema','busbar_persistence_v4') AND c.relkind IN ('r','p','v','m','f','S'))",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
            if foreign {
                return Err(Error::UnsupportedFormat);
            }
            let info = target_info(control).await?;
            let marker = admission_marker(control).await?;
            if marker.is_none() {
                if !origin::logical_empty(control).await? {
                    return Err(Error::UnsupportedFormat);
                }
                self.inspected = None;
                self.live = Some(live);
                return Ok(Inspection {
                    state: InspectionState::Empty,
                    source: None,
                    admission_marker: None,
                    catalogue: vec![],
                    capabilities: vec![NativeCapability::CurrentOpen],
                });
            }
            let source = current_identity(control, &live, info).await?;
            self.inspected = Some(source.clone());
            self.live = Some(live);
            return Ok(Inspection {
                state: InspectionState::Current,
                source: Some(source),
                admission_marker: marker,
                catalogue: vec![],
                capabilities: vec![NativeCapability::CurrentOpen],
            });
        }
        let nonempty:bool=control.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','v','m','f','S'))",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
        if !nonempty {
            self.live = Some(live);
            return Ok(Inspection {
                state: InspectionState::Empty,
                source: None,
                admission_marker: None,
                catalogue: vec![],
                capabilities: vec![NativeCapability::CurrentOpen],
            });
        }
        let mut source_session = self.source_client(wires, shared).await?;
        if LiveIdentity::read(&mut source_session).await? != live {
            return Err(Error::SourceChanged);
        }
        let reader = crate::legacy::Reader::from_native_session(
            source_session,
            bounds(limit)?,
            live.bytes()?,
            None,
        )
        .await
        .map_err(source_error)?;
        let source = live.source(reader.catalogue())?;
        let tables = catalogue(reader.catalogue());
        check_inventory_budget(&tables, limit)?;
        self.source = Some(reader);
        self.inspected = Some(source.clone());
        self.live = Some(live);
        Ok(Inspection {
            state: InspectionState::Legacy,
            source: Some(source),
            admission_marker: None,
            catalogue: tables,
            capabilities: capabilities(),
        })
    }
    async fn begin(
        &mut self,
        wires: &[Wire],
        shared: Arc<Shared>,
        expected: &SourceIdentity,
        route: Digest,
        target_format: Format,
        operation: Id,
    ) -> Result<Upgrade<Own>, Error> {
        if route == [0; 32] || operation == [0; 16] || target_format != CORE_FORMAT {
            return Err(Error::UnsupportedFormat);
        }
        if self.inspected.as_ref() != Some(expected) {
            return Err(Error::SourceChanged);
        }
        let live = self.live.clone().ok_or(Error::Refused)?;
        let mut authority = self.authority.clone();
        let mut source_client = self.source_client(wires, shared.clone()).await?;
        let control = self.control(wires, shared).await?;
        if LiveIdentity::read(control).await? != live
            || LiveIdentity::read(&mut source_client).await? != live
        {
            return Err(Error::SourceChanged);
        }
        control::own_locks(control).await?;
        let record = if control::exists(control).await? {
            let record = control::read(control).await?;
            if record.source.identity() != *expected
                || record.route != route
                || record.target_format.format() != target_format
            {
                return Err(Error::SourceChanged);
            }
            guards::verify(control, &record).await?;
            record
        } else {
            guards::privileges(control).await?;
            let relations = control::relations(control).await?;
            begin_native(control).await?;
            if LiveIdentity::read(control).await? != live {
                let _ = control.client().batch_execute("ROLLBACK").await;
                return Err(Error::SourceChanged);
            }
            let result = async {
                control
                    .client()
                    .batch_execute(&guards::lock_sql(&relations))
                    .await
                    .map_err(db)?;
                let captured =
                    crate::legacy::inspect_native_catalogue(control, live.bytes()?, None)
                        .await
                        .map_err(source_error)?;
                if live.source(&captured)? != *expected {
                    return Err(Error::SourceChanged);
                }
                let observed_relations = control::relations(control).await?;
                if observed_relations.len() != relations.len()
                    || observed_relations
                        .iter()
                        .zip(&relations)
                        .any(|(a, b)| a.name != b.name || a.oid != b.oid || a.owner != b.owner)
                {
                    return Err(Error::SourceChanged);
                }
                control
                    .client()
                    .batch_execute(control::CONTROL_DDL)
                    .await
                    .map_err(db)?;
                let guard_digest = guards::install(control, &relations).await?;
                let id = random_id(control).await?;
                let snapshot = random_id(control).await?;
                let target = initialize_target(control).await?;
                let record = control::Record {
                    version: 1,
                    id,
                    operation,
                    route,
                    target_format: control::StoredFormat::new(target_format),
                    source: control::Source::new(expected),
                    catalogue: captured,
                    relations,
                    target_metadata: metadata::encode(target)
                        .map_err(|_| Error::Corrupt)?
                        .to_vec(),
                    snapshot,
                    guard_digest,
                    step: 1,
                    activation: None,
                    complete: None,
                };
                control::write(control, &record).await?;
                Ok(record)
            }
            .await;
            match result {
                Ok(record) => {
                    control
                        .client()
                        .batch_execute("COMMIT")
                        .await
                        .map_err(|_| Error::Unknown)?;
                    record
                }
                Err(error) => {
                    let _ = control.client().batch_execute("ROLLBACK").await;
                    return Err(error);
                }
            }
        };
        live.same_database(&record.catalogue)?;
        let (guard, _) = guards::verify(control, &record).await?;
        if record.target()? != target_info(control).await? {
            return Err(Error::SourceChanged);
        }
        // The consistent data snapshot starts only after every guard committed.
        let source_live = LiveIdentity::read(&mut source_client).await?;
        if source_live != LiveIdentity::read(control).await? {
            return Err(Error::SourceChanged);
        }
        let source_record = control::read(&mut source_client).await?;
        if source_record.id != record.id || source_record.guard_digest != record.guard_digest {
            return Err(Error::SourceChanged);
        }
        let source = crate::legacy::Reader::from_native_session(
            source_client,
            crate::legacy::Limits {
                rows: 4096,
                page_bytes: 64 * 1024 * 1024,
                row_bytes: 64 * 1024 * 1024,
            },
            record.catalogue.native_identity.clone(),
            Some(guard),
        )
        .await
        .map_err(source_error)?;
        if source.catalogue().digest != record.catalogue.digest
            || layout(source.catalogue())? != layout(&record.catalogue)?
        {
            return Err(Error::SourceChanged);
        }
        if authority.is_none() {
            authority = Some(super::held(random_id(control).await?.to_vec()));
        }
        let reference = UpgradeRef {
            id: record.id,
            authority: authority.as_ref().ok_or(Error::Refused)?.clone(),
        };
        self.authority = authority;
        let reply = Upgrade {
            reference,
            source: record.source.identity(),
            snapshot: record.snapshot,
            target: record.target()?,
            native_step: record.step as u64,
            catalogue: catalogue(source.catalogue()),
        };
        self.source = Some(source);
        self.record = Some(record);
        Ok(reply)
    }
    fn authorize(&self, reference: &UpgradeRef<Own>) -> Result<(), Error> {
        let record = self.record.as_ref().ok_or(Error::Refused)?;
        let authority = self.authority.as_ref().ok_or(Error::Refused)?;
        if reference.id != record.id
            || !constant_time_eq(
                authority.expose_own(&Own::here()),
                reference.authority.expose_own(&Own::here()),
            )
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
    async fn check(&mut self, reference: &UpgradeRef<Own>) -> Result<Fence, Error> {
        self.authorize(reference)?;
        let record = self.record.as_ref().ok_or(Error::Refused)?.clone();
        let control = self.control.as_mut().ok_or(Error::SourceChanged)?;
        control::own_locks(control).await?;
        let observed = control::read(control).await?;
        if observed.id != record.id
            || observed.route != record.route
            || observed.guard_digest != record.guard_digest
            || observed.source.identity() != record.source.identity()
        {
            return Err(Error::SourceChanged);
        }
        let live = LiveIdentity::read(control).await?;
        live.same_database(&record.catalogue)?;
        let (guard, enforcement) = guards::verify(control, &record).await?;
        let source = self.source.as_mut().ok_or(Error::SourceChanged)?;
        let session = source.native_session().map_err(source_error)?;
        if LiveIdentity::read(session).await? != live {
            return Err(Error::SourceChanged);
        }
        let source_control = control::read(session).await?;
        if source_control.id != record.id || source_control.guard_digest != enforcement {
            return Err(Error::SourceChanged);
        }
        // Both identity and catalogue are re-read on the exact held RR snapshot.
        let captured = crate::legacy::inspect_native_catalogue(
            session,
            record.catalogue.native_identity.clone(),
            Some(guard),
        )
        .await
        .map_err(source_error)?;
        if captured.digest != record.catalogue.digest
            || layout(&captured)? != layout(&record.catalogue)?
        {
            return Err(Error::SourceChanged);
        }
        let flags=session.client().query_one("SELECT current_setting('transaction_read_only')='on',current_setting('transaction_isolation')='repeatable read',pg_catalog.txid_current_snapshot()::text,pg_catalog.pg_backend_pid()",&[]).await.map_err(db)?;
        if !flags.try_get::<_, bool>(0).map_err(db)? || !flags.try_get::<_, bool>(1).map_err(db)? {
            return Err(Error::SourceChanged);
        }
        let snapshot: String = flags.try_get(2).map_err(db)?;
        let pid: i32 = flags.try_get(3).map_err(db)?;
        let mut observation = live.bytes()?;
        observation.extend_from_slice(&record.id);
        observation.extend_from_slice(&record.snapshot);
        observation.extend_from_slice(snapshot.as_bytes());
        observation.extend_from_slice(&pid.to_le_bytes());
        observation.extend_from_slice(&enforcement);
        Ok(Fence {
            upgrade: record.id,
            source: record.source.identity(),
            enforcement_digest: enforcement,
            observation_digest: sha256(&observation),
            snapshot: record.snapshot,
        })
    }
    async fn page(
        &mut self,
        reference: &UpgradeRef<Own>,
        snapshot: Id,
        family: Id,
        selector: &SourceSelector<Own>,
        cursor: Option<&Secret<Vec<u8>, Own>>,
        limit: Bounds,
    ) -> Result<SourcePage<Own>, Error> {
        self.check(reference).await?;
        let limits = bounds(limit)?;
        let record = self.record.as_ref().ok_or(Error::Refused)?;
        if snapshot != record.snapshot || family == [0; 16] {
            return Err(Error::SourceChanged);
        }
        let (table, exact) = match selector {
            SourceSelector::Scan { table } => (*table, None),
            SourceSelector::Exact { table, key } => {
                (*table, Some(key.expose_own(&Own::here()).as_slice()))
            }
            SourceSelector::IndexPrefix { .. } => return Err(Error::MissingCapability),
        };
        if exact.is_some() && cursor.is_some() {
            return Err(Error::SourceChanged);
        }
        let source_digest = source_digest(record)?;
        let (after, mut coverage) = match cursor {
            Some(cursor) => parse_cursor(
                cursor.expose_own(&Own::here()),
                snapshot,
                family,
                table,
                source_digest,
            )?,
            None => (None, coverage_start(source_digest, family, table)),
        };
        let (native, exhausted) = self
            .source
            .as_mut()
            .ok_or(Error::SourceChanged)?
            .native_table_page(table as usize, after.as_deref(), exact, limits)
            .await
            .map_err(source_error)?;
        let mut rows = Vec::with_capacity(native.len());
        let mut last = None;
        for row in native {
            let mut input = Zeroizing::new(Vec::new());
            input
                .try_reserve(32 + row.native_key.len() + row.bytes.expose_own(&Own::here()).len())
                .map_err(|_| Error::Bounds)?;
            input.extend_from_slice(&coverage);
            input.extend_from_slice(&row.native_key);
            input.extend_from_slice(row.bytes.expose_own(&Own::here()));
            coverage = sha256(&input);
            last = Some(row.native_key.clone());
            rows.push(SourceRow {
                table: row.table as u32,
                native_key: super::held(row.native_key),
                value: row.bytes,
            });
        }
        let next = if exhausted || exact.is_some() {
            None
        } else {
            last.map(|key| {
                super::held(cursor_bytes(
                    snapshot,
                    family,
                    table,
                    &key,
                    coverage,
                    source_digest,
                ))
            })
        };
        Ok(SourcePage {
            snapshot,
            family,
            rows,
            next,
            source_digest,
            coverage_digest: coverage,
        })
    }
    async fn finish(
        &mut self,
        reference: &UpgradeRef<Own>,
        proof: &ActivationReceipt<Own>,
    ) -> Result<Response<Own>, Error> {
        self.check(reference).await?;
        let mut record = self.record.as_ref().ok_or(Error::Refused)?.clone();
        let control = self.control.as_mut().ok_or(Error::SourceChanged)?;
        begin_native(control).await?;
        let result = async {
            let observed = control::read(control).await?;
            if observed.id != record.id
                || observed.guard_digest != record.guard_digest
                || observed.route != record.route
                || observed.source.identity() != record.source.identity()
                || observed.target_metadata != record.target_metadata
            {
                return Err(Error::SourceChanged);
            }
            record = observed;
            let digest = receipt_digest(proof)?;
            if proof.phase == CompletionPhase::Activation && record.activation == Some(digest) {
                if record.step < 3 {
                    verify_native_receipt(control, &record, proof).await?;
                }
                verify_current_marker(control, &record, proof).await?;
            } else if proof.phase == CompletionPhase::Complete && record.complete == Some(digest) {
                verify_current_marker(control, &record, proof).await?;
            } else {
                verify_receipt(control, &record, proof).await?;
            }

            match proof.phase {
                CompletionPhase::Activation => {
                    if record.activation.is_some_and(|held| held != digest) {
                        return Err(Error::SourceChanged);
                    }
                    record.activation = Some(digest);
                    record.step = record.step.max(2);
                }
                CompletionPhase::Complete => {
                    if record.activation.is_none() {
                        return Err(Error::Refused);
                    }
                    if record.complete.is_some_and(|held| held != digest) {
                        return Err(Error::SourceChanged);
                    }
                    record.complete = Some(digest);
                    record.step = 3;
                }
            }
            control::write(control, &record).await?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => control
                .client()
                .batch_execute("COMMIT")
                .await
                .map_err(|_| Error::Unknown)?,
            Err(error) => {
                let _ = control.client().batch_execute("ROLLBACK").await;
                return Err(error);
            }
        }
        let recovery = recovery(&record)?;
        let result = match proof.phase {
            CompletionPhase::Activation => Response::RecoveryReady(recovery),
            CompletionPhase::Complete => Response::ServingReady(ServingReady {
                recovery,
                completed_checkpoint_digest: proof.checkpoint_value_digest,
            }),
        };
        self.record = Some(record);
        Ok(result)
    }
}
fn capabilities() -> Vec<NativeCapability> {
    vec![
        NativeCapability::Snapshot,
        NativeCapability::PersistentFence,
        NativeCapability::Resume,
        NativeCapability::InactiveTarget,
        NativeCapability::CurrentOpen,
    ]
}
fn check_inventory_budget(tables: &[archive::Table], limit: Bounds) -> Result<(), Error> {
    let size = tables.iter().try_fold(256usize, |size, table| {
        size.checked_add(
            table.name.len()
                + table.native_layout.len()
                + table.columns.iter().map(|s| s.len() + 8).sum::<usize>(),
        )
        .ok_or(Error::Bounds)
    })?;
    if tables.len() > limit.items as usize || size > limit.bytes as usize {
        return Err(Error::Bounds);
    }
    Ok(())
}
async fn random_id(session: &mut Session) -> Result<Id, Error> {
    let row = session
        .client()
        .query_one("SELECT uuid_send(gen_random_uuid())", &[])
        .await
        .map_err(db)?;
    let id: Vec<u8> = row.try_get(0).map_err(db)?;
    let id: Id = id.try_into().map_err(|_| Error::Corrupt)?;
    if id == [0; 16] {
        return Err(Error::Corrupt);
    }
    Ok(id)
}
async fn begin_native(session: &mut Session) -> Result<(), Error> {
    session.client().batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED; SET LOCAL search_path=pg_catalog; SET LOCAL synchronous_commit=on; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s'; SELECT pg_catalog.pg_advisory_xact_lock(-1)").await.map_err(db)?;
    let durable:bool=session.client().query_one("SELECT current_setting('fsync')='on' AND current_setting('full_page_writes')='on' AND current_setting('synchronous_commit')='on' AND NOT pg_catalog.pg_is_in_recovery() AND current_setting('transaction_read_only')='off'",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if !durable {
        let _ = session.client().batch_execute("ROLLBACK").await;
        return Err(Error::MissingCapability);
    }
    Ok(())
}
async fn initialize_target(session: &mut Session) -> Result<BackendInfo, Error> {
    let exists:bool=session.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='busbar_persistence_v4')",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if exists {
        return Err(Error::SourceChanged);
    }
    session
        .client()
        .batch_execute(native::SCHEMA)
        .await
        .map_err(db)?;
    let info = BackendInfo {
        dataset: DatasetId(random_id(session).await?),
        atomic_domain: random_id(session).await?,
        clock_authority: random_id(session).await?,
        physical_version: 1,
        durability: Durability::Local,
    };
    let metadata = metadata::encode(info).map_err(|_| Error::Corrupt)?;
    session
        .client()
        .execute(
            "INSERT INTO busbar_persistence_v4.metadata(singleton,facts) VALUES(true,$1)",
            &[&metadata.as_slice()],
        )
        .await
        .map_err(db)?;
    Ok(info)
}
async fn target_info(session: &mut Session) -> Result<BackendInfo, Error> {
    native::validate_schema(session.client())
        .await
        .map_err(native_error)?;
    let rows = session
        .client()
        .query(
            "SELECT singleton,facts FROM busbar_persistence_v4.metadata LIMIT 2",
            &[],
        )
        .await
        .map_err(db)?;
    if rows.len() != 1 || !rows[0].try_get::<_, bool>(0).map_err(db)? {
        return Err(Error::Corrupt);
    }
    let bytes: &[u8] = rows[0].try_get(1).map_err(db)?;
    let info = metadata::decode(bytes).map_err(|_| Error::Corrupt)?;
    if info.physical_version != 1 || info.durability != Durability::Local {
        return Err(Error::UnsupportedFormat);
    }
    Ok(info)
}
async fn current_identity(
    _session: &mut Session,
    live: &LiveIdentity,
    info: BackendInfo,
) -> Result<SourceIdentity, Error> {
    let metadata = metadata::encode(info).map_err(|_| Error::Corrupt)?;
    let mut native = live.bytes()?;
    native.extend_from_slice(&info.dataset.0);
    Ok(SourceIdentity {
        native_anchor: sha256(&native),
        dataset: info.dataset,
        format: Some(CORE_FORMAT),
        catalogue_digest: sha256(native::SCHEMA.as_bytes()),
        layout_digest: sha256(&metadata),
    })
}
async fn admission_marker(session: &mut Session) -> Result<Option<Secret<Vec<u8>, Own>>, Error> {
    let address = Address {
        namespace: ADMISSION_NAMESPACE,
        key: ADMISSION_KEY.to_vec(),
    };
    read_value(session, &address).await
}
async fn read_value(
    session: &mut Session,
    address: &Address,
) -> Result<Option<Secret<Vec<u8>, Own>>, Error> {
    let mut key = Zeroizing::new(address.namespace.to_vec());
    key.extend_from_slice(&address.key);
    let locator = sha256(&key);
    let rows=session.client().query("SELECT CASE WHEN octet_length(value)<=67108864 THEN value ELSE NULL END FROM busbar_persistence_v4.records WHERE locator=$1 AND namespace=$2 AND key=$3",&[&&locator[..],&&address.namespace[..],&address.key.as_slice()]).await.map_err(db)?;
    if rows.len() > 1 {
        return Err(Error::Corrupt);
    }
    match rows.first() {
        None => Ok(None),
        Some(row) => {
            let value: Option<&[u8]> = row.try_get(0).map_err(db)?;
            Ok(Some(super::held(value.ok_or(Error::Bounds)?.to_vec())))
        }
    }
}
async fn completion_marker(
    session: &mut Session,
    record: &control::Record,
) -> Result<CompletionMarker, Error> {
    let bytes = read_value(session, &completion_marker_address(record.id))
        .await?
        .ok_or(Error::Refused)?;
    let marker = codec::decode_completion_marker(
        bytes.expose_own(&Own::here()),
        Bounds {
            items: 64,
            bytes: 1024 * 1024,
        },
    )?;
    if marker.upgrade != record.id
        || marker.source != record.source.identity().dataset
        || marker.target != record.target()?.dataset
    {
        return Err(Error::SourceChanged);
    }
    Ok(marker)
}
async fn verify_native_receipt(
    session: &mut Session,
    record: &control::Record,
    proof: &ActivationReceipt<Own>,
) -> Result<(), Error> {
    if proof.attempt.dataset != record.target()?.dataset {
        return Err(Error::SourceChanged);
    }
    let rows=session.client().query("SELECT fingerprint,epoch,CASE WHEN octet_length(result)<=67108864 THEN result ELSE NULL END FROM busbar_persistence_v4.receipts WHERE writer=$1 AND operation=$2",&[&&proof.attempt.writer[..],&&proof.attempt.operation[..]]).await.map_err(db)?;
    if rows.len() != 1 {
        return Err(Error::Refused);
    }
    let fingerprint: &[u8] = rows[0].try_get(0).map_err(db)?;
    let epoch: &[u8] = rows[0].try_get(1).map_err(db)?;
    let result: Option<&[u8]> = rows[0].try_get(2).map_err(db)?;
    if fingerprint != proof.candidate_fingerprint
        || epoch != proof.attempt.execution_epoch.to_le_bytes()
        || !constant_time_eq(
            result.ok_or(Error::Bounds)?,
            proof.original_result.expose_own(&Own::here()),
        )
    {
        return Err(Error::Refused);
    }
    Ok(())
}
async fn verify_receipt(
    session: &mut Session,
    record: &control::Record,
    proof: &ActivationReceipt<Own>,
) -> Result<(), Error> {
    verify_native_receipt(session, record, proof).await?;
    let checkpoint = read_value(session, &proof.checkpoint_address)
        .await?
        .ok_or(Error::Refused)?;
    if sha256(checkpoint.expose_own(&Own::here())) != proof.checkpoint_value_digest {
        return Err(Error::SourceChanged);
    }
    let marker = completion_marker(session, record).await?;
    if marker.phase != proof.phase
        || marker.checkpoint_address != proof.checkpoint_address
        || marker.checkpoint_value_digest != proof.checkpoint_value_digest
    {
        return Err(Error::Refused);
    }
    Ok(())
}
fn receipt_digest(proof: &ActivationReceipt<Own>) -> Result<Digest, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve(256 + proof.checkpoint_address.key.len())
        .map_err(|_| Error::Bounds)?;
    bytes.extend_from_slice(b"postgres-native-completion-v1\0");
    bytes.extend_from_slice(&proof.attempt.dataset.0);
    bytes.extend_from_slice(&proof.attempt.writer_epoch.to_le_bytes());
    bytes.extend_from_slice(&proof.attempt.writer);
    bytes.extend_from_slice(&proof.attempt.execution_epoch.to_le_bytes());
    bytes.extend_from_slice(&proof.attempt.operation);
    bytes.extend_from_slice(&proof.candidate_fingerprint);
    bytes.extend_from_slice(&sha256(proof.original_result.expose_own(&Own::here())));
    bytes.extend_from_slice(&proof.checkpoint_address.namespace);
    bytes.extend_from_slice(&(proof.checkpoint_address.key.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&proof.checkpoint_address.key);
    bytes.extend_from_slice(&proof.checkpoint_value_digest);
    bytes.push(match proof.phase {
        CompletionPhase::Activation => 0,
        CompletionPhase::Complete => 1,
    });
    Ok(sha256(&bytes))
}
fn recovery(record: &control::Record) -> Result<RecoveryReady, Error> {
    let activation = record.activation.ok_or(Error::Refused)?;
    let mut selected = record.id.to_vec();
    selected.extend_from_slice(&record.target_metadata);
    selected.extend_from_slice(&activation);
    Ok(RecoveryReady {
        upgrade: record.id,
        target: record.target()?.dataset,
        activation_receipt_digest: activation,
        selector_digest: sha256(&selected),
    })
}
fn source_digest(record: &control::Record) -> Result<Digest, Error> {
    let mut bytes = record.id.to_vec();
    bytes.extend_from_slice(&record.snapshot);
    bytes.extend_from_slice(&record.source.identity().native_anchor);
    bytes.extend_from_slice(&record.source.identity().catalogue_digest);
    bytes.extend_from_slice(&record.source.identity().layout_digest);
    Ok(sha256(&bytes))
}
fn coverage_start(source: Digest, family: Id, table: u32) -> Digest {
    let mut bytes = source.to_vec();
    bytes.extend_from_slice(&family);
    bytes.extend_from_slice(&table.to_le_bytes());
    sha256(&bytes)
}
fn cursor_bytes(
    snapshot: Id,
    family: Id,
    table: u32,
    key: &[u8],
    coverage: Digest,
    source: Digest,
) -> Vec<u8> {
    let mut bytes = b"PGCURS01".to_vec();
    bytes.extend_from_slice(&snapshot);
    bytes.extend_from_slice(&family);
    bytes.extend_from_slice(&table.to_le_bytes());
    bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
    bytes.extend_from_slice(key);
    bytes.extend_from_slice(&coverage);
    bytes.extend_from_slice(&source);
    let hash = sha256(&bytes);
    bytes.extend_from_slice(&hash);
    bytes
}
fn parse_cursor(
    bytes: &[u8],
    snapshot: Id,
    family: Id,
    table: u32,
    source: Digest,
) -> Result<(Option<Vec<u8>>, Digest), Error> {
    if bytes.len() < 144
        || &bytes[..8] != b"PGCURS01"
        || bytes[8..24] != snapshot
        || bytes[24..40] != family
        || bytes[40..44] != table.to_le_bytes()
    {
        return Err(Error::SourceChanged);
    }
    let length = u32::from_le_bytes(bytes[44..48].try_into().map_err(|_| Error::Corrupt)?) as usize;
    let end = 48usize.checked_add(length).ok_or(Error::Bounds)?;
    if length > 64
        || end.checked_add(96) != Some(bytes.len())
        || bytes[end + 32..end + 64] != source
        || sha256(&bytes[..end + 64]) != bytes[end + 64..]
    {
        return Err(Error::Corrupt);
    }
    let coverage = bytes[end..end + 32]
        .try_into()
        .map_err(|_| Error::Corrupt)?;
    Ok((Some(bytes[48..end].to_vec()), coverage))
}

/// Ordinary OPEN independently authenticates and verifies the selected physical
/// generation. Pending selection is available solely with its exact recovery binding.
pub(super) async fn admit(
    session: &mut Session,
    binding: Option<&OpenBinding>,
) -> Result<bool, Error> {
    session.client().batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path=pg_catalog; SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='30s'; SELECT pg_catalog.pg_advisory_xact_lock_shared(-1)").await.map_err(db)?;
    let result=async {
        let kind=control::kind(session).await?;
        if kind==control::Kind::EmptyOrigin {
            let info=target_info(session).await?;origin::verify(session,info).await?;
            verify_current_binding(session,binding,info).await?;
            return Ok(true);
        }
        let exists=kind==control::Kind::Legacy;
        if exists {
            let record=control::read(session).await?;
            let live=LiveIdentity::read(session).await?;live.same_database(&record.catalogue)?;
            let (function,_)=guards::verify(session,&record).await?;
            let captured=crate::legacy::inspect_native_catalogue(session,record.catalogue.native_identity.clone(),Some(function)).await.map_err(source_error)?;
            if captured.digest!=record.catalogue.digest || layout(&captured)?!=layout(&record.catalogue)? || target_info(session).await?!=record.target()?{return Err(Error::SourceChanged);}
            let marker=completion_marker(session,&record).await?;
            let checkpoint=read_value(session,&marker.checkpoint_address).await?.ok_or(Error::Refused)?;
            if sha256(checkpoint.expose_own(&Own::here()))!=marker.checkpoint_value_digest{return Err(Error::SourceChanged);}
            match binding {
                Some(OpenBinding::Recovery(expected)) if record.step>=2 && recovery(&record)?==*expected=>{},
                Some(OpenBinding::Current{source,admission_marker_digest}) if record.step==3 && marker.phase==CompletionPhase::Complete=>{
                    let actual=current_identity(session,&live,record.target()?).await?;
                    if actual!=*source || marker_digest(admission_marker(session).await?.as_ref())!=*admission_marker_digest{return Err(Error::SourceChanged);}
                }
                None if record.step==3 && marker.phase==CompletionPhase::Complete=>{},
                _=>return Err(Error::Refused),
            }
            if record.step<2 || admission_marker(session).await?.is_none(){return Err(Error::Refused);}
            Ok(true)
        } else {
            match binding {
                Some(OpenBinding::Empty)=>{
                    let any:bool=session.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','v','m','f','S'))",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
                    if any {
                        let native:bool=session.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='busbar_persistence_v4')",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
                        if !native{return Err(Error::SourceChanged);}
                        let info=target_info(session).await?;verify_current_binding(session,binding,info).await?;
                    }
                }
                Some(OpenBinding::Current{source,admission_marker_digest})=>{
                    let live=LiveIdentity::read(session).await?;let info=target_info(session).await?;
                    if current_identity(session,&live,info).await?!=*source || marker_digest(admission_marker(session).await?.as_ref())!=*admission_marker_digest{return Err(Error::SourceChanged);}
                }
                Some(OpenBinding::Recovery(_))=>return Err(Error::Refused),
                None=>{
                    let native:bool=session.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='busbar_persistence_v4')",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
                    if native {let info=target_info(session).await?;verify_current_binding(session,None,info).await?;}
                },
            }
            Ok(false)
        }
    }.await;
    let rolled_back = session.client().batch_execute("ROLLBACK").await.map_err(db);
    match result {
        Ok(allowed) => {
            rolled_back?;
            Ok(allowed)
        }
        Err(error) => Err(error),
    }
}
fn marker_digest(marker: Option<&Secret<Vec<u8>, Own>>) -> Digest {
    marker.map_or([0; 32], |bytes| sha256(bytes.expose_own(&Own::here())))
}
pub(super) async fn pin_receipts(session: &mut Session) -> Result<bool, Failure> {
    if !control::exists(session)
        .await
        .map_err(|_| Failure::Unavailable)?
    {
        return Ok(false);
    }
    Ok(control::read(session)
        .await
        .map_err(|_| Failure::Corrupt)?
        .step
        < 3)
}

async fn verify_current_binding(
    session: &mut Session,
    binding: Option<&OpenBinding>,
    info: BackendInfo,
) -> Result<(), Error> {
    let marker = admission_marker(session).await?;
    if marker.is_none() && !origin::logical_empty(session).await? {
        return Err(Error::UnsupportedFormat);
    }
    match binding {
        Some(OpenBinding::Empty) => {
            if !origin::logical_empty(session).await? {
                return Err(Error::SourceChanged);
            }
        }
        Some(OpenBinding::Current {
            source,
            admission_marker_digest,
        }) => {
            let live = LiveIdentity::read(session).await?;
            if current_identity(session, &live, info).await? != *source
                || marker_digest(marker.as_ref()) != *admission_marker_digest
            {
                return Err(Error::SourceChanged);
            }
        }
        Some(OpenBinding::Recovery(_)) => return Err(Error::Refused),
        None => {}
    }
    Ok(())
}
pub(super) async fn establish_origin(
    session: &mut Session,
    info: BackendInfo,
) -> Result<(), Failure> {
    match control::kind(session).await.map_err(|_| Failure::Corrupt)? {
        control::Kind::Missing => {
            begin_native(session).await.map_err(|_| Failure::Refused)?;
            let result=async {
                if target_info(session).await?!=info{return Err(Error::SourceChanged);}
                // Current metadata may survive an interrupted genuinely-empty
                // initialization. Never classify newly present old tables as empty.
                let foreign:bool=session.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname NOT IN ('information_schema','busbar_persistence_v4') AND c.relkind IN ('r','p','v','m','f','S'))",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
                if foreign{return Err(Error::SourceChanged);}
                origin::install(session,info).await
            }.await;
            match result {
                Ok(()) => session
                    .client()
                    .batch_execute("COMMIT")
                    .await
                    .map_err(|_| Failure::Unknown),
                Err(_) => {
                    let _ = session.client().batch_execute("ROLLBACK").await;
                    Err(Failure::Refused)
                }
            }
        }
        control::Kind::EmptyOrigin => origin::verify(session, info)
            .await
            .map_err(|_| Failure::Corrupt),
        control::Kind::Legacy => Ok(()),
    }
}

async fn verify_current_marker(
    session: &mut Session,
    record: &control::Record,
    original: &ActivationReceipt<Own>,
) -> Result<(), Error> {
    let marker = completion_marker(session, record).await?;
    if marker.checkpoint_address != original.checkpoint_address {
        return Err(Error::SourceChanged);
    }
    if original.phase == CompletionPhase::Complete
        && (marker.phase != CompletionPhase::Complete
            || marker.checkpoint_value_digest != original.checkpoint_value_digest)
    {
        return Err(Error::SourceChanged);
    }
    if marker.phase == CompletionPhase::Activation
        && marker.checkpoint_value_digest != original.checkpoint_value_digest
    {
        return Err(Error::SourceChanged);
    }
    let checkpoint = read_value(session, &marker.checkpoint_address)
        .await?
        .ok_or(Error::Refused)?;
    if sha256(checkpoint.expose_own(&Own::here())) != marker.checkpoint_value_digest {
        return Err(Error::SourceChanged);
    }
    Ok(())
}

#[cfg(test)]
mod native_tests;
