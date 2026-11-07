// SPDX-License-Identifier: Apache-2.0
//! One backend-owned physical journal. Semantic checkpoints remain target records.
use super::*;
use serde::{Deserialize, Serialize};

pub(super) const CONTROL_SCHEMA: &str = "busbar_upgrade_v1";
pub(super) const CONTROL_DDL: &str = "CREATE SCHEMA busbar_upgrade_v1; CREATE TABLE busbar_upgrade_v1.control(singleton boolean PRIMARY KEY CHECK(singleton), body bytea NOT NULL)";
pub(super) const OLD_MIGRATE_LOCK: i64 = 0x6275_7362_6172_5f70;
pub(super) const UPGRADE_LOCK: i64 = 0x6275_7362_6172_7550;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    anchor: [u8; 32],
    dataset: [u8; 16],
    format: Option<StoredFormat>,
    catalogue: [u8; 32],
    layout: [u8; 32],
}
impl Source {
    pub(super) fn new(source: &SourceIdentity) -> Self {
        Self {
            anchor: source.native_anchor,
            dataset: source.dataset.0,
            format: source.format.map(StoredFormat::new),
            catalogue: source.catalogue_digest,
            layout: source.layout_digest,
        }
    }
    pub(super) fn identity(&self) -> SourceIdentity {
        SourceIdentity {
            native_anchor: self.anchor,
            dataset: DatasetId(self.dataset),
            format: self.format.as_ref().map(StoredFormat::format),
            catalogue_digest: self.catalogue,
            layout_digest: self.layout,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredFormat {
    owner: [u8; 16],
    physical: u32,
    logical: u32,
    codec: u32,
}
impl StoredFormat {
    pub(super) fn new(format: Format) -> Self {
        Self {
            owner: format.owner,
            physical: format.physical,
            logical: format.logical,
            codec: format.codec,
        }
    }
    pub(super) fn format(&self) -> Format {
        Format {
            owner: self.owner,
            physical: self.physical,
            logical: self.logical,
            codec: self.codec,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Relation {
    pub name: String,
    pub oid: u32,
    pub owner: u32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u32,
    pub id: Id,
    pub operation: Id,
    pub route: Digest,
    pub target_format: StoredFormat,
    pub source: Source,
    pub catalogue: crate::legacy::Catalogue,
    pub relations: Vec<Relation>,
    pub target_metadata: Vec<u8>,
    pub snapshot: Id,
    pub guard_digest: Digest,
    /// 1: immutable source and inactive target; 2: recovery-only selector.
    /// Serving completion is separately attested by the core admission marker.
    pub step: u8,
    pub activation: Option<Digest>,
    pub complete: Option<Digest>,
}
impl Record {
    pub(super) fn target(&self) -> Result<BackendInfo, Error> {
        busbar_contract::abi::sdk::store::v4::metadata::decode(&self.target_metadata)
            .map_err(|_| Error::Corrupt)
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        if self.version != 1
            || self.id == [0; 16]
            || self.operation == [0; 16]
            || self.route == [0; 32]
            || self.snapshot == [0; 16]
            || self.relations.len() != self.catalogue.tables.len()
            || self.relations.is_empty()
            || self.relations.len() > 16
            || !matches!(self.step, 1..=3)
            || (self.step >= 2) != self.activation.is_some()
            || (self.step == 3) != self.complete.is_some()
        {
            return Err(Error::Corrupt);
        }
        if self
            .relations
            .iter()
            .zip(&self.catalogue.tables)
            .any(|(relation, table)| relation.name != table.name || relation.oid == 0)
        {
            return Err(Error::Corrupt);
        }
        let target = self.target()?;
        if target.physical_version != 1
            || target.durability != Durability::Local
            || self.target_format.format().physical != 1
        {
            return Err(Error::UnsupportedFormat);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Missing,
    Legacy,
    EmptyOrigin,
}
pub(super) async fn kind(session: &mut Session) -> Result<Kind, Error> {
    let schema: bool = session
        .client()
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname=$1)",
            &[&CONTROL_SCHEMA],
        )
        .await
        .map_err(db)?
        .try_get(0)
        .map_err(db)?;
    if !schema {
        return Ok(Kind::Missing);
    }
    let tables=session.client().query("SELECT c.relname::text,c.relkind::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind IN ('r','p','v','m','f','S') ORDER BY c.relname LIMIT 2",&[&CONTROL_SCHEMA]).await.map_err(db)?;
    if tables.len() != 1 || tables[0].try_get::<_, String>(1).map_err(db)? != "r" {
        return Err(Error::Corrupt);
    }
    match tables[0].try_get::<_, String>(0).map_err(db)?.as_str() {
        "control" => Ok(Kind::Legacy),
        "origin" => Ok(Kind::EmptyOrigin),
        _ => Err(Error::Corrupt),
    }
}
pub(super) async fn exists(session: &mut Session) -> Result<bool, Error> {
    Ok(kind(session).await? == Kind::Legacy)
}
pub(super) async fn read(session: &mut Session) -> Result<Record, Error> {
    verify_journal(session, "control").await?;
    let rows=session.client().query("SELECT singleton,CASE WHEN octet_length(body)<=4194304 THEN body ELSE NULL END FROM busbar_upgrade_v1.control LIMIT 2",&[]).await.map_err(db)?;
    if rows.len() != 1 || !rows[0].try_get::<_, bool>(0).map_err(db)? {
        return Err(Error::Corrupt);
    }
    let bytes: Option<&[u8]> = rows[0].try_get(1).map_err(db)?;
    let record: Record =
        serde_json::from_slice(bytes.ok_or(Error::Bounds)?).map_err(|_| Error::Corrupt)?;
    record.validate()?;
    Ok(record)
}
pub(super) async fn write(session: &mut Session, record: &Record) -> Result<(), Error> {
    let bytes = Zeroizing::new(serde_json::to_vec(record).map_err(|_| Error::Corrupt)?);
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(Error::Bounds);
    }
    session.client().execute("INSERT INTO busbar_upgrade_v1.control(singleton,body) VALUES(true,$1) ON CONFLICT(singleton) DO UPDATE SET body=EXCLUDED.body",&[&bytes.as_slice()]).await.map_err(db)?;
    Ok(())
}
pub(super) async fn relations(session: &mut Session) -> Result<Vec<Relation>, Error> {
    let rows=session.client().query("SELECT c.relname::text,c.oid,c.relowner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname LIMIT 17",&[]).await.map_err(db)?;
    if rows.is_empty() || rows.len() > 16 {
        return Err(Error::UnsupportedFormat);
    }
    rows.iter()
        .map(|row| {
            Ok(Relation {
                name: row.try_get(0).map_err(db)?,
                oid: row.try_get(1).map_err(db)?,
                owner: row.try_get(2).map_err(db)?,
            })
        })
        .collect()
}
pub(super) async fn own_locks(session: &mut Session) -> Result<(), Error> {
    // Idempotently reuse locks owned by this exact session; never stack lock counts.
    for key in [OLD_MIGRATE_LOCK, UPGRADE_LOCK] {
        let ours:bool=session.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() AND granted AND classid=($1::bigint>>32)::oid AND objid=($1::bigint & 4294967295)::oid AND objsubid=1)",&[&key]).await.map_err(db)?.try_get(0).map_err(db)?;
        if !ours {
            let acquired: bool = session
                .client()
                .query_one("SELECT pg_catalog.pg_try_advisory_lock($1)", &[&key])
                .await
                .map_err(db)?
                .try_get(0)
                .map_err(db)?;
            if !acquired {
                return Err(Error::Busy);
            }
        }
    }
    Ok(())
}

/// Both physical journals have the same exact owned shape; neither is a source row.
pub(super) async fn verify_journal(session: &mut Session, table: &str) -> Result<(), Error> {
    let relation = format!("busbar_upgrade_v1.{table}");
    let safe: bool = session.client().query_one("SELECT c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relhasrules AND NOT c.relhastriggers AND NOT c.relhassubclass AND NOT c.relispartition AND (SELECT count(*)=2 AND bool_and(a.attnotnull AND a.atttypmod=-1 AND a.attidentity='' AND a.attgenerated='' AND NOT a.atthasdef AND ((a.attnum=1 AND a.attname='singleton' AND a.atttypid='boolean'::regtype) OR (a.attnum=2 AND a.attname='body' AND a.atttypid='bytea'::regtype))) FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0) AND (SELECT count(*)=1 AND bool_and(i.indisprimary AND i.indisunique AND i.indisvalid AND i.indisready AND i.indnkeyatts=1 AND i.indnatts=1 AND i.indkey::text='1' AND i.indpred IS NULL AND i.indexprs IS NULL) FROM pg_catalog.pg_index i WHERE i.indrelid=c.oid) FROM pg_catalog.pg_class c WHERE c.oid=$1::text::regclass", &[&relation]).await.map_err(db)?.try_get(0).map_err(db)?;
    if !safe {
        return Err(Error::Corrupt);
    }
    let constraints = session.client().query("SELECT pg_catalog.pg_get_constraintdef(k.oid)::text,k.convalidated AND NOT k.condeferrable AND NOT k.condeferred AND k.conislocal AND k.coninhcount=0 FROM pg_catalog.pg_constraint k WHERE k.conrelid=$1::text::regclass ORDER BY k.contype", &[&relation]).await.map_err(db)?;
    if constraints.len() != 2
        || constraints[0].try_get::<_, String>(0).map_err(db)? != "CHECK (singleton)"
        || constraints[1].try_get::<_, String>(0).map_err(db)? != "PRIMARY KEY (singleton)"
        || constraints
            .iter()
            .any(|row| row.try_get::<_, bool>(1).ok() != Some(true))
    {
        return Err(Error::Corrupt);
    }
    Ok(())
}
