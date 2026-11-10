// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::pgwire::Transaction;
use busbar_contract::abi::sdk::store::v4::metadata;
use busbar_contract::persistence::control;
use std::collections::{BTreeMap, BTreeSet};
pub(super) const SCHEMA: &str = "CREATE SCHEMA busbar_persistence_v4;
CREATE TABLE busbar_persistence_v4.metadata (singleton boolean PRIMARY KEY CHECK(singleton), facts bytea NOT NULL);
CREATE TABLE busbar_persistence_v4.records (locator bytea PRIMARY KEY, namespace bytea NOT NULL, key bytea NOT NULL, value bytea NOT NULL);
CREATE TABLE busbar_persistence_v4.receipts (writer bytea NOT NULL, operation bytea NOT NULL, fingerprint bytea NOT NULL, epoch bytea NOT NULL, observed bytea NOT NULL, result bytea NOT NULL, PRIMARY KEY(writer,operation));";
fn db(_: crate::pgwire::Error) -> Failure {
    Failure::Unavailable
}
fn exact<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], Failure> {
    bytes.try_into().map_err(|_| Failure::Corrupt)
}
fn number(bytes: Vec<u8>) -> Result<u64, Failure> {
    Ok(u64::from_le_bytes(exact(bytes)?))
}
fn locator(address: &Address) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(16 + address.key.len());
    bytes.extend_from_slice(&address.namespace);
    bytes.extend_from_slice(&address.key);
    busbar_contract::abi::sdk::digest::sha256(&bytes)
}
// This database-local key space is reserved for the canonical v4 adapter.
// Gate sorts before every nonnegative namespace hash. Hash collisions only add
// contention: merging duplicate keys always promotes shared to exclusive.
const GLOBAL_GATE: i64 = -1;
#[derive(Default, Debug, PartialEq, Eq)]
struct LockPlan(BTreeMap<i64, bool>);
pub(super) fn namespace_lock(namespace: [u8; 16]) -> i64 {
    let digest = busbar_contract::abi::sdk::digest::sha256(&namespace);
    i64::from_le_bytes(digest[..8].try_into().expect("digest width")) & i64::MAX
}
impl LockPlan {
    fn key(&mut self, key: i64, exclusive: bool) {
        self.0
            .entry(key)
            .and_modify(|old| *old |= exclusive)
            .or_insert(exclusive);
    }
    fn namespace(&mut self, namespace: [u8; 16], exclusive: bool) {
        self.key(namespace_lock(namespace), exclusive);
    }
    fn address(&mut self, address: &Address) {
        if address.namespace == control::GENERATION_NAMESPACE.0 {
            if let Ok(namespace) = <[u8; 16]>::try_from(address.key.as_slice()) {
                self.namespace(namespace, false);
            }
        } else {
            self.namespace(address.namespace, false);
        }
    }
    fn candidate<O>(candidate: &Candidate<O>) -> Self {
        let mut plan = Self::default();
        plan.namespace(control::NAMESPACE.0, false);
        for predicate in &candidate.predicates {
            plan.address(&predicate.address);
        }
        for mutation in &candidate.mutations {
            let namespace = match mutation {
                Mutation::Put { address, .. } | Mutation::Delete(address) => address.namespace,
                Mutation::DeleteRange { namespace, .. } => namespace.0,
            };
            plan.namespace(namespace, true);
        }
        plan
    }
}
async fn advisory(tx: &mut Transaction<'_>, key: i64, exclusive: bool) -> Result<(), Failure> {
    let sql = if exclusive {
        "SELECT pg_catalog.pg_advisory_xact_lock($1)"
    } else {
        "SELECT pg_catalog.pg_advisory_xact_lock_shared($1)"
    };
    tx.query_one(sql, &[&key]).await.map_err(db)?;
    Ok(())
}
async fn locks(
    tx: &mut Transaction<'_>,
    exclusive_gate: bool,
    plan: &LockPlan,
) -> Result<(), Failure> {
    advisory(tx, GLOBAL_GATE, exclusive_gate).await?;
    for (&key, &exclusive) in &plan.0 {
        advisory(tx, key, exclusive).await?;
    }
    Ok(())
}
async fn begin(s: &mut Session) -> Result<Transaction<'_>, Failure> {
    let mut tx = s.client().transaction().await.map_err(db)?;
    tx.batch_execute(
        "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; SET LOCAL synchronous_commit = on",
    )
    .await
    .map_err(db)?;
    let row = tx.query_one("SELECT current_setting('fsync') = 'on' AND current_setting('full_page_writes') = 'on' AND current_setting('synchronous_commit') = 'on' AND NOT pg_catalog.pg_is_in_recovery() AND current_setting('transaction_read_only') = 'off'", &[]).await.map_err(db)?;
    if !row.try_get::<_, bool>(0).map_err(db)? {
        return Err(Failure::Refused);
    }
    Ok(tx)
}
pub(super) async fn connect(s: &mut Session, allow_legacy: bool) -> Result<BackendInfo, Failure> {
    let mut tx = begin(s).await?;
    locks(&mut tx, true, &LockPlan::default()).await?;
    let exists: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='busbar_persistence_v4')", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if !exists {
        let nonempty: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','v','m','f','S'))", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
        if nonempty {
            return Err(Failure::Refused);
        }
        tx.batch_execute(SCHEMA).await.map_err(db)?;
        let row = tx.query_one("SELECT uuid_send(gen_random_uuid()), uuid_send(gen_random_uuid()), uuid_send(gen_random_uuid())", &[]).await.map_err(db)?;
        let info = BackendInfo {
            dataset: DatasetId(exact(row.try_get(0).map_err(db)?)?),
            atomic_domain: exact(row.try_get(1).map_err(db)?)?,
            clock_authority: exact(row.try_get(2).map_err(db)?)?,
            physical_version: 1,
            durability: Durability::Local,
        };
        let bytes = metadata::encode(info).map_err(|_| Failure::Corrupt)?;
        tx.execute(
            "INSERT INTO busbar_persistence_v4.metadata VALUES(true,$1)",
            &[&&bytes[..]],
        )
        .await
        .map_err(db)?;
    }
    let foreign: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE left(n.nspname,3)<>'pg_' AND n.nspname NOT IN ('information_schema','busbar_persistence_v4') AND c.relkind IN ('r','p','v','m','f','S'))", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if foreign && !allow_legacy {
        return Err(Failure::Refused);
    }
    validate_schema(tx.client()).await?;
    let rows = tx
        .query(
            "SELECT singleton, facts FROM busbar_persistence_v4.metadata",
            &[],
        )
        .await
        .map_err(db)?;
    if rows.len() != 1 || !rows[0].try_get::<_, bool>(0).map_err(db)? {
        return Err(Failure::Corrupt);
    }
    let bytes: Vec<u8> = rows[0].try_get(1).map_err(db)?;
    let info = metadata::decode(&bytes).map_err(|_| Failure::Corrupt)?;
    if info.physical_version != 1 || info.durability != Durability::Local {
        return Err(Failure::Refused);
    }
    tx.commit().await.map_err(db)?;
    super::lifecycle::establish_origin(s, info).await?;
    Ok(info)
}
pub(super) async fn validate_schema(tx: &mut crate::pgwire::Client) -> Result<(), Failure> {
    let rows = tx.query("SELECT c.relname::text,a.attname::text,t.typname::text,a.attnotnull FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid JOIN pg_catalog.pg_type t ON t.oid=a.atttypid WHERE n.nspname='busbar_persistence_v4' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum", &[]).await.map_err(db)?;
    let expected = [
        ("metadata", "singleton", "bool"),
        ("metadata", "facts", "bytea"),
        ("receipts", "writer", "bytea"),
        ("receipts", "operation", "bytea"),
        ("receipts", "fingerprint", "bytea"),
        ("receipts", "epoch", "bytea"),
        ("receipts", "observed", "bytea"),
        ("receipts", "result", "bytea"),
        ("records", "locator", "bytea"),
        ("records", "namespace", "bytea"),
        ("records", "key", "bytea"),
        ("records", "value", "bytea"),
    ];
    if rows.len() != expected.len() {
        return Err(Failure::Corrupt);
    }
    for (r, (table, column, ty)) in rows.iter().zip(expected) {
        if r.try_get::<_, String>(0).map_err(db)? != table
            || r.try_get::<_, String>(1).map_err(db)? != column
            || r.try_get::<_, String>(2).map_err(db)? != ty
            || !r.try_get::<_, bool>(3).map_err(db)?
        {
            return Err(Failure::Corrupt);
        }
    }
    let constraints = tx.query("SELECT c.relname::text,pg_catalog.pg_get_constraintdef(k.oid)::text FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='busbar_persistence_v4' ORDER BY c.relname,k.contype,k.conname", &[]).await.map_err(db)?;
    let expected = [
        ("metadata", "CHECK (singleton)"),
        ("metadata", "PRIMARY KEY (singleton)"),
        ("receipts", "PRIMARY KEY (writer, operation)"),
        ("records", "PRIMARY KEY (locator)"),
    ];
    if constraints.len() != expected.len() {
        return Err(Failure::Corrupt);
    }
    for (r, (table, def)) in constraints.iter().zip(expected) {
        if r.try_get::<_, String>(0).map_err(db)? != table
            || r.try_get::<_, String>(1).map_err(db)? != def
        {
            return Err(Failure::Corrupt);
        }
    }
    let safe: bool = tx.query_one("SELECT count(*)=3 AND bool_and(c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relhassubclass AND NOT c.relhasrules AND NOT c.relhastriggers) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='busbar_persistence_v4' AND c.relkind IN ('r','p','v','m','f','S')", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if !safe {
        return Err(Failure::Corrupt);
    }
    let indexes: bool = tx.query_one("SELECT count(*)=3 AND bool_and(i.indisprimary AND i.indisunique AND i.indisvalid AND i.indisready) FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='busbar_persistence_v4'", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
    let defaults: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_attrdef d JOIN pg_catalog.pg_class c ON c.oid=d.adrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='busbar_persistence_v4')", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if !indexes || defaults {
        return Err(Failure::Corrupt);
    }
    Ok(())
}
async fn observation(
    tx: &mut Transaction<'_>,
    info: BackendInfo,
) -> Result<ClockObservation, Failure> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp()))::bigint",
            &[],
        )
        .await
        .map_err(db)?
        .try_get(0)
        .map_err(db)?;
    Ok(ClockObservation {
        authority: info.clock_authority,
        unix_seconds: u64::try_from(now).map_err(|_| Failure::Corrupt)?,
    })
}
async fn get(
    tx: &mut Transaction<'_>,
    a: &Address,
    share: bool,
) -> Result<Option<Secret<Vec<u8>, Own>>, Failure> {
    if a.namespace == control::GENERATION_NAMESPACE.0 && a.key.len() != 16 {
        return Ok(None);
    }
    let digest = locator(a);
    let sql = if share {
        "SELECT namespace,key,value FROM busbar_persistence_v4.records WHERE locator=$1 FOR SHARE"
    } else {
        "SELECT namespace,key,value FROM busbar_persistence_v4.records WHERE locator=$1"
    };
    let Some(row) = tx.query_opt(sql, &[&&digest[..]]).await.map_err(db)? else {
        return Ok(None);
    };
    let ns: Vec<u8> = row.try_get(0).map_err(db)?;
    let key: Vec<u8> = row.try_get(1).map_err(db)?;
    if ns != a.namespace || key != a.key {
        return Err(Failure::Corrupt);
    }
    Ok(Some(held(row.try_get(2).map_err(db)?)))
}
fn control_address(key: &[u8]) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: key.to_vec(),
    }
}
fn generation_address(ns: [u8; 16]) -> Address {
    Address {
        namespace: control::GENERATION_NAMESPACE.0,
        key: ns.to_vec(),
    }
}
async fn generation(tx: &mut Transaction<'_>, ns: [u8; 16]) -> Result<u64, Failure> {
    match get(tx, &generation_address(ns), false).await? {
        None => Ok(0),
        Some(v) => {
            let b: &[u8] = v.expose_own(&Own::here());
            let n = u64::from_le_bytes(b.try_into().map_err(|_| Failure::Corrupt)?);
            if n == 0 {
                Err(Failure::Corrupt)
            } else {
                Ok(n)
            }
        }
    }
}
async fn put(tx: &mut Transaction<'_>, a: &Address, value: &[u8]) -> Result<(), Failure> {
    // Verify full address even for a digest conflict: never overwrite a collision.
    get(tx, a, false).await?;
    let digest = locator(a);
    let changed=tx.execute("INSERT INTO busbar_persistence_v4.records(locator,namespace,key,value) VALUES($1,$2,$3,$4) ON CONFLICT(locator) DO UPDATE SET value=EXCLUDED.value WHERE records.namespace=EXCLUDED.namespace AND records.key=EXCLUDED.key",&[&&digest[..],&&a.namespace[..],&&a.key[..],&value]).await.map_err(db)?;
    if changed != 1 {
        return Err(Failure::Corrupt);
    }
    Ok(())
}
pub(super) async fn clock(
    s: &mut Session,
    info: BackendInfo,
    dataset: DatasetId,
) -> Result<ClockObservation, Failure> {
    if dataset != info.dataset {
        return Err(Failure::Refused);
    }
    let mut tx = begin(s).await?;
    locks(&mut tx, false, &LockPlan::default()).await?;
    bind(&mut tx, info).await?;
    let answer = observation(&mut tx, info).await?;
    tx.commit().await.map_err(db)?;
    Ok(answer)
}
pub(super) async fn read(
    s: &mut Session,
    info: BackendInfo,
    r: Read,
) -> Result<ReadResult<Own>, Failure> {
    if r.dataset != info.dataset {
        return Err(Failure::Refused);
    }
    let mut tx = begin(s).await?;
    let mut plan = LockPlan::default();
    for address in &r.addresses {
        plan.address(address);
    }
    locks(&mut tx, false, &plan).await?;
    bind(&mut tx, info).await?;
    let now = observation(&mut tx, info).await?;
    let result = if r.time.is_some_and(|t| !t.permits(now.unix_seconds)) {
        ReadResult::TimeGuardFailed { observed_at: now }
    } else {
        let mut values = Vec::new();
        for a in &r.addresses {
            values.push(get(&mut tx, a, false).await?)
        }
        ReadResult::Values {
            observed_at: now,
            values,
        }
    };
    tx.commit().await.map_err(db)?;
    Ok(result)
}
pub(super) async fn scan(
    s: &mut Session,
    info: BackendInfo,
    r: Scan,
) -> Result<Page<Own>, Failure> {
    if r.dataset != info.dataset || r.max_items == 0 || r.max_bytes == 0 {
        return Err(Failure::Refused);
    }
    let mut tx = begin(s).await?;
    let mut plan = LockPlan::default();
    plan.namespace(r.namespace.0, false);
    locks(&mut tx, r.namespace == control::GENERATION_NAMESPACE, &plan).await?;
    bind(&mut tx, info).await?;
    let generation = generation(&mut tx, r.namespace.0).await?;
    if !r.allow_change && r.generation.is_some_and(|g| g != generation) {
        return Err(Failure::StaleScan);
    }
    // Raw bytea ordering, independent of the fixed-width indexed point locator.
    let row_limit = i64::try_from(r.max_items.saturating_add(1)).unwrap_or(i64::MAX);
    let rows=tx.query("SELECT key,value FROM busbar_persistence_v4.records WHERE namespace=$1 AND substring(key FROM 1 FOR octet_length($2::bytea))=$2 AND ($3::bool=false OR key>$4) ORDER BY key LIMIT $5",&[&&r.namespace.0[..],&&r.prefix[..],&r.after.is_some(),&r.after.as_deref().unwrap_or_default(),&row_limit]).await.map_err(db)?;
    let mut page = Page {
        generation,
        rows: Vec::new(),
        next: None,
    };
    let mut used = 0usize;
    for row in rows {
        let key: Vec<u8> = row.try_get(0).map_err(db)?;
        let value = held(row.try_get(1).map_err(db)?);
        let size = key
            .len()
            .checked_add(value.expose_own(&Own::here()).len())
            .ok_or(Failure::Refused)?;
        if page.rows.len() == r.max_items || used.checked_add(size).is_none_or(|n| n > r.max_bytes)
        {
            if page.rows.is_empty() {
                return Err(Failure::Refused);
            }
            page.next = page.rows.last().map(|(a, _)| a.key.clone());
            break;
        }
        used += size;
        page.rows.push((
            Address {
                namespace: r.namespace.0,
                key,
            },
            value,
        ));
    }
    tx.commit().await.map_err(db)?;
    Ok(page)
}
pub(super) async fn commit(
    s: &mut Session,
    info: BackendInfo,
    prepared: PreparedCandidate<Own>,
) -> Result<Committed<Own>, Failure> {
    let c = prepared.candidate();
    if c.id.dataset != info.dataset {
        return Err(Failure::Refused);
    }
    let mut tx = begin(s).await?;
    let plan = LockPlan::candidate(c);
    locks(&mut tx, control::initialization(c, info.dataset), &plan).await?;
    bind(&mut tx, info).await?;
    if let Some(row)=tx.query_opt("SELECT fingerprint,epoch,observed,result FROM busbar_persistence_v4.receipts WHERE writer=$1 AND operation=$2",&[&&c.id.writer[..],&&c.id.operation[..]]).await.map_err(db)?{
        let fp=exact::<32>(row.try_get(0).map_err(db)?)?;let epoch=number(row.try_get(1).map_err(db)?)?;let observed_at=ClockObservation{authority:info.clock_authority,unix_seconds:number(row.try_get(2).map_err(db)?)?};
        let result=held(row.try_get(3).map_err(db)?);
        let decision=if fp==prepared.fingerprint() && epoch==c.id.execution_epoch{Decision::Applied(result)}else{Decision::OpIdConflict};
        tx.commit().await.map_err(db)?;return Ok(Committed{observed_at,decision})
    }
    let root = get(&mut tx, &control_address(control::DATASET_KEY), true).await?;
    let initializing = if root.is_none() && control::initialization(c, info.dataset) {
        tx.batch_execute("LOCK TABLE busbar_persistence_v4.records, busbar_persistence_v4.receipts IN EXCLUSIVE MODE").await.map_err(db)?;
        let empty:bool=tx.query_one("SELECT NOT EXISTS(SELECT 1 FROM busbar_persistence_v4.records) AND NOT EXISTS(SELECT 1 FROM busbar_persistence_v4.receipts)",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
        if !empty {
            return Err(Failure::Refused);
        }
        true
    } else {
        false
    };
    let writer = get(
        &mut tx,
        &control_address(&control::writer_key(c.id.writer)),
        true,
    )
    .await?;
    if !initializing {
        let admitted = match (root.as_ref(), writer.as_ref()) {
            (Some(root), Some(writer)) => {
                let root = control::Dataset::decode(root.expose_own(&Own::here()))
                    .ok_or(Failure::Corrupt)?;
                let writer = control::Writer::decode(writer.expose_own(&Own::here()))
                    .ok_or(Failure::Corrupt)?;
                if root.id != info.dataset {
                    return Err(Failure::Corrupt);
                }
                root.writer_epoch == c.id.writer_epoch && writer.admits(c.id.execution_epoch)
            }
            (root, writer) => {
                if let Some(v) = root {
                    let decoded = control::Dataset::decode(v.expose_own(&Own::here()))
                        .ok_or(Failure::Corrupt)?;
                    if decoded.id != info.dataset {
                        return Err(Failure::Corrupt);
                    }
                }
                if let Some(v) = writer {
                    control::Writer::decode(v.expose_own(&Own::here())).ok_or(Failure::Corrupt)?;
                }
                false
            }
        };
        if !admitted {
            let observed_at = observation(&mut tx, info).await?;
            return Ok(Committed {
                observed_at,
                decision: Decision::ExpiredUnknown,
            });
        }
    }
    // Share locks survive until COMMIT. Retirement's UPDATE must wait for these
    // admitted transactions before its durable floor can establish an age proof.
    let observed_at = observation(&mut tx, info).await?;
    if c.time.is_some_and(|t| !t.permits(observed_at.unix_seconds)) {
        return Ok(Committed {
            observed_at,
            decision: Decision::TimeGuardFailed { observed_at },
        });
    }
    for p in &c.predicates {
        let value = get(&mut tx, &p.address, false).await?;
        let matches = match (&p.expected, value.as_ref()) {
            (ExpectedValue::Absent, None) => true,
            (ExpectedValue::Exact(expected), Some(actual)) => {
                expected.expose_own(&Own::here()) == actual.expose_own(&Own::here())
            }
            _ => false,
        };
        if !matches {
            return Ok(Committed {
                observed_at,
                decision: Decision::ConditionConflict,
            });
        }
    }
    let mut namespaces = BTreeSet::new();
    for m in &c.mutations {
        let namespace = match m {
            Mutation::Put { address, .. } | Mutation::Delete(address) => address.namespace,
            Mutation::DeleteRange { namespace, .. } => namespace.0,
        };
        if namespace == control::GENERATION_NAMESPACE.0 {
            return Err(Failure::Refused);
        }
        if namespace == control::NAMESPACE.0 {
            let Mutation::Put { address, value } = m else {
                return Err(Failure::Refused);
            };
            let key = control::Key::decode(&address.key).ok_or(Failure::Refused)?;
            let p = c
                .predicates
                .iter()
                .find(|p| p.address == *address)
                .ok_or(Failure::Refused)?;
            let previous = get(&mut tx, address, false).await?;
            match (&p.expected, previous.as_ref()) {
                (ExpectedValue::Absent, None) => {}
                (ExpectedValue::Exact(e), Some(a))
                    if e.expose_own(&Own::here()) == a.expose_own(&Own::here()) => {}
                _ => return Err(Failure::Refused),
            }
            if !initializing {
                control::replacement(
                    key,
                    info.dataset,
                    previous
                        .as_ref()
                        .map(|p| p.expose_own(&Own::here()).as_slice()),
                    value.expose_own(&Own::here()),
                )?;
            }
        }
        namespaces.insert(namespace);
    }
    // Namespace-exclusive transaction locks stabilize predicates and ranges,
    // including absence, and protect every affected generation through COMMIT.
    let mut advances = Vec::new();
    for ns in namespaces {
        advances.push((
            ns,
            generation(&mut tx, ns)
                .await?
                .checked_add(1)
                .ok_or(Failure::Refused)?,
        ))
    }
    for m in &c.mutations {
        match m {
            Mutation::Put { address, value } => {
                put(&mut tx, address, value.expose_own(&Own::here())).await?
            }
            Mutation::Delete(address) => {
                get(&mut tx, address, false).await?;
                let digest = locator(address);
                tx.execute("DELETE FROM busbar_persistence_v4.records WHERE locator=$1 AND namespace=$2 AND key=$3",&[&&digest[..],&&address.namespace[..],&&address.key[..]]).await.map_err(db)?;
            }
            Mutation::DeleteRange {
                namespace,
                prefix,
                exact_key_length,
            } => {
                let length = exact_key_length.to_string();
                tx.execute("DELETE FROM busbar_persistence_v4.records WHERE namespace=$1 AND substring(key FROM 1 FOR octet_length($2::bytea))=$2 AND octet_length(key)::numeric=$3::text::numeric",&[&&namespace.0[..],&&prefix[..],&length]).await.map_err(db)?;
            }
        }
    }
    for (ns, generation) in advances {
        put(&mut tx, &generation_address(ns), &generation.to_le_bytes()).await?;
    }
    let fp = prepared.fingerprint();
    let epoch = c.id.execution_epoch.to_le_bytes();
    let now = observed_at.unix_seconds.to_le_bytes();
    tx.execute("INSERT INTO busbar_persistence_v4.receipts(writer,operation,fingerprint,epoch,observed,result) VALUES($1,$2,$3,$4,$5,$6)",&[&&c.id.writer[..],&&c.id.operation[..],&&fp[..],&&epoch[..],&&now[..],&c.result.expose_own(&Own::here()).as_slice()]).await.map_err(db)?;
    tx.commit().await.map_err(|_| Failure::Unknown)?;
    Ok(Committed {
        observed_at,
        decision: Decision::Applied(held(c.result.expose_own(&Own::here()).clone())),
    })
}
/// Separate best-effort maintenance; its failure never changes an Applied reply.
/// Observe only floors from a fresh transaction after the effects' durable commit.
pub(super) async fn maintain(
    s: &mut Session,
    info: BackendInfo,
    horizons: &Horizons,
) -> Result<(), Failure> {
    if super::lifecycle::pin_receipts(s).await? {
        return Ok(());
    }
    use std::time::Instant;
    let mut tx = begin(s).await?;
    let mut plan = LockPlan::default();
    plan.namespace(control::NAMESPACE.0, false);
    locks(&mut tx, false, &plan).await?;
    bind(&mut tx, info).await?;
    let rows = tx
        .query(
            "SELECT key FROM busbar_persistence_v4.records WHERE namespace=$1",
            &[&&control::NAMESPACE.0[..]],
        )
        .await
        .map_err(db)?;
    for row in rows {
        let key: Vec<u8> = row.try_get(0).map_err(db)?;
        let Some(control::Key::Writer(writer)) = control::Key::decode(&key) else {
            continue;
        };
        let value = get(&mut tx, &control_address(&key), true)
            .await?
            .ok_or(Failure::Corrupt)?;
        let floor = control::Writer::decode(value.expose_own(&Own::here()))
            .ok_or(Failure::Corrupt)?
            .retired_through;
        let collectible = {
            let now = Instant::now();
            let mut cache = horizons.lock().map_err(|_| Failure::Corrupt)?;
            cache
                .entry(writer)
                .or_insert_with(|| Horizon::new(floor, now))
                .observe(floor, now)?
        };
        if collectible == 0 {
            continue;
        }
        let floor_bytes = collectible.to_le_bytes();
        // Compare unsigned little-endian epochs by bytes from most significant
        // to least significant, before LIMIT. Active epochs never hide old rows.
        let receipts=tx.query("SELECT operation,epoch FROM busbar_persistence_v4.receipts WHERE writer=$1 AND ROW(get_byte(epoch,7),get_byte(epoch,6),get_byte(epoch,5),get_byte(epoch,4),get_byte(epoch,3),get_byte(epoch,2),get_byte(epoch,1),get_byte(epoch,0)) <= ROW(get_byte($2::bytea,7),get_byte($2::bytea,6),get_byte($2::bytea,5),get_byte($2::bytea,4),get_byte($2::bytea,3),get_byte($2::bytea,2),get_byte($2::bytea,1),get_byte($2::bytea,0)) LIMIT 1000", &[&&writer[..], &&floor_bytes[..]]).await.map_err(db)?;
        for receipt in receipts {
            let operation = exact::<16>(receipt.try_get(0).map_err(db)?)?;
            let epoch = number(receipt.try_get(1).map_err(db)?)?;
            if epoch == 0 {
                return Err(Failure::Corrupt);
            }
            if epoch <= collectible {
                tx.execute(
                    "DELETE FROM busbar_persistence_v4.receipts WHERE writer=$1 AND operation=$2",
                    &[&&writer[..], &&operation[..]],
                )
                .await
                .map_err(db)?;
            }
        }
    }
    tx.commit().await.map_err(db)
}

async fn bind(tx: &mut Transaction<'_>, info: BackendInfo) -> Result<(), Failure> {
    let rows = tx
        .query(
            "SELECT singleton,facts FROM busbar_persistence_v4.metadata",
            &[],
        )
        .await
        .map_err(db)?;
    if rows.len() != 1 || !rows[0].try_get::<_, bool>(0).map_err(db)? {
        return Err(Failure::Corrupt);
    }
    let facts: Vec<u8> = rows[0].try_get(1).map_err(db)?;
    if metadata::decode(&facts).map_err(|_| Failure::Corrupt)? != info {
        return Err(Failure::Corrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lock_plan_maps_generations_and_promotes_collisions() {
        let namespace = [9; 16];
        let mut plan = LockPlan::default();
        plan.address(&generation_address(namespace));
        assert_eq!(plan.0.get(&namespace_lock(namespace)), Some(&false));
        plan.namespace(namespace, true);
        plan.namespace(namespace, false);
        // Simulate a distinct namespace hashing to the same native lock ID.
        plan.key(namespace_lock(namespace), false);
        assert_eq!(plan.0.len(), 1);
        assert_eq!(plan.0.get(&namespace_lock(namespace)), Some(&true));
        let before = plan.0.clone();
        plan.address(&Address {
            namespace: control::GENERATION_NAMESPACE.0,
            key: vec![0; 15],
        });
        plan.address(&Address {
            namespace: control::GENERATION_NAMESPACE.0,
            key: vec![0; 17],
        });
        assert_eq!(plan.0, before);
        assert!(plan.0.keys().all(|key| *key >= 0));
    }
    #[test]
    fn candidate_lock_order_is_independent_of_selector_order() {
        let address = |namespace| Address {
            namespace,
            key: vec![1],
        };
        let mut candidate = Candidate::<Own> {
            id: AttemptId {
                dataset: DatasetId([1; 16]),
                writer_epoch: 1,
                writer: [2; 16],
                execution_epoch: 1,
                operation: [3; 16],
            },
            codec: CANDIDATE_VERSION,
            time: None,
            result: held(vec![]),
            predicates: vec![
                Predicate {
                    address: generation_address([4; 16]),
                    expected: ExpectedValue::Absent,
                },
                Predicate {
                    address: address([5; 16]),
                    expected: ExpectedValue::Absent,
                },
            ],
            mutations: vec![
                Mutation::Put {
                    address: address([4; 16]),
                    value: held(vec![1]),
                },
                Mutation::DeleteRange {
                    namespace: NamespaceId([6; 16]),
                    prefix: vec![],
                    exact_key_length: 1,
                },
            ],
        };
        let first = LockPlan::candidate(&candidate);
        assert_eq!(first.0.get(&namespace_lock([4; 16])), Some(&true));
        assert_eq!(first.0.get(&namespace_lock([5; 16])), Some(&false));
        assert_eq!(first.0.get(&namespace_lock([6; 16])), Some(&true));
        assert_eq!(
            first.0.get(&namespace_lock(control::NAMESPACE.0)),
            Some(&false)
        );
        candidate.predicates.reverse();
        candidate.mutations.reverse();
        assert_eq!(first, LockPlan::candidate(&candidate));
        let keys: Vec<_> = first.0.keys().copied().collect();
        assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
        candidate.mutations.push(Mutation::Put {
            address: control_address(control::DATASET_KEY),
            value: held(vec![]),
        });
        assert_eq!(
            LockPlan::candidate(&candidate)
                .0
                .get(&namespace_lock(control::NAMESPACE.0)),
            Some(&true)
        );
    }
    #[test]
    fn exact_unsigned_framing() {
        for n in [0, 1, i64::MAX as u64, (i64::MAX as u64) + 1, u64::MAX] {
            assert_eq!(number(n.to_le_bytes().to_vec()), Ok(n))
        }
        assert_eq!(number(vec![0; 7]), Err(Failure::Corrupt));
        assert_eq!(number(vec![0; 9]), Err(Failure::Corrupt));
    }
    #[test]
    fn locator_uses_full_binary_address() {
        let a = Address {
            namespace: [1; 16],
            key: vec![0, 255, 0],
        };
        let mut b = a.clone();
        b.key.push(0);
        assert_ne!(locator(&a), locator(&b));
        b = a.clone();
        b.namespace[0] = 2;
        assert_ne!(locator(&a), locator(&b));
        let long = Address {
            namespace: [0; 16],
            key: vec![255; 100_000],
        };
        assert_eq!(locator(&long).len(), 32);
    }
}
