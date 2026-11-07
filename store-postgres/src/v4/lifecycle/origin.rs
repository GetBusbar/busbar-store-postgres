// SPDX-License-Identifier: Apache-2.0
//! Fresh/native-only physical origin, not a historical source or semantic upgrade.
use super::*;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyOrigin {
    version: u32,
    target_metadata: Vec<u8>,
    relations: Vec<control::Relation>,
    guard_digest: Digest,
}
const DDL: &str = "CREATE SCHEMA busbar_upgrade_v1; CREATE TABLE busbar_upgrade_v1.origin(singleton boolean PRIMARY KEY CHECK(singleton), body bytea NOT NULL); CREATE TABLE public.busbar_schema(version bigint PRIMARY KEY); CREATE TABLE public.store_revision(only_row boolean PRIMARY KEY DEFAULT true CHECK(only_row),revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0))";

pub(super) async fn install(session: &mut Session, info: BackendInfo) -> Result<(), Error> {
    // The caller owns the canonical native gate and has proved no old relations.
    guards::privileges(session).await?;
    session.client().batch_execute(DDL).await.map_err(db)?;
    let relations = control::relations(session).await?;
    if relations.len() != 2
        || relations[0].name != "busbar_schema"
        || relations[1].name != "store_revision"
    {
        return Err(Error::SourceChanged);
    }
    let guard_digest = guards::install(session, &relations).await?;
    let origin = EmptyOrigin {
        version: 1,
        target_metadata: metadata::encode(info).map_err(|_| Error::Corrupt)?.to_vec(),
        relations,
        guard_digest,
    };
    let bytes = serde_json::to_vec(&origin).map_err(|_| Error::Corrupt)?;
    session
        .client()
        .execute(
            "INSERT INTO busbar_upgrade_v1.origin(singleton,body) VALUES(true,$1)",
            &[&bytes.as_slice()],
        )
        .await
        .map_err(db)?;
    Ok(())
}
pub(super) async fn verify(session: &mut Session, info: BackendInfo) -> Result<(), Error> {
    if control::kind(session).await? != control::Kind::EmptyOrigin {
        return Err(Error::SourceChanged);
    }
    control::verify_journal(session, "origin").await?;
    let rows=session.client().query("SELECT singleton,CASE WHEN octet_length(body)<=16384 THEN body ELSE NULL END FROM busbar_upgrade_v1.origin LIMIT 2",&[]).await.map_err(db)?;
    if rows.len() != 1 || !rows[0].try_get::<_, bool>(0).map_err(db)? {
        return Err(Error::Corrupt);
    }
    let bytes: Option<&[u8]> = rows[0].try_get(1).map_err(db)?;
    let origin: EmptyOrigin =
        serde_json::from_slice(bytes.ok_or(Error::Bounds)?).map_err(|_| Error::Corrupt)?;
    if origin.version != 1
        || metadata::decode(&origin.target_metadata).map_err(|_| Error::Corrupt)? != info
        || origin.relations.len() != 2
        || origin.relations[0].name != "busbar_schema"
        || origin.relations[1].name != "store_revision"
    {
        return Err(Error::Corrupt);
    }
    guards::verify_relations(session, &origin.relations, origin.guard_digest).await?;
    let actual = control::relations(session).await?;
    if actual.len() != 2
        || actual
            .iter()
            .zip(&origin.relations)
            .any(|(a, b)| a.name != b.name || a.oid != b.oid || a.owner != b.owner)
    {
        return Err(Error::SourceChanged);
    }
    let columns=session.client().query("SELECT c.relname::text,a.attname::text,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(pg_catalog.pg_get_expr(d.adbin,d.adrelid),'')::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum LIMIT 4",&[]).await.map_err(db)?;
    let expected = [
        ("busbar_schema", "version", "bigint", ""),
        ("store_revision", "only_row", "boolean", "true"),
        ("store_revision", "revision", "bigint", "0"),
    ];
    if columns.len() != expected.len() {
        return Err(Error::SourceChanged);
    }
    for (row, (table, column, ty, default)) in columns.iter().zip(expected) {
        if row.try_get::<_, String>(0).map_err(db)? != table
            || row.try_get::<_, String>(1).map_err(db)? != column
            || row.try_get::<_, String>(2).map_err(db)? != ty
            || !row.try_get::<_, bool>(3).map_err(db)?
            || row.try_get::<_, String>(4).map_err(db)? != default
        {
            return Err(Error::SourceChanged);
        }
    }
    let constraints=session.client().query("SELECT c.relname::text,pg_catalog.pg_get_constraintdef(k.oid)::text,k.convalidated AND NOT k.condeferrable AND NOT k.condeferred AND k.conislocal AND k.coninhcount=0 FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,k.contype,k.conname LIMIT 5",&[]).await.map_err(db)?;
    let expected_constraints = [
        ("busbar_schema", "PRIMARY KEY (version)"),
        ("store_revision", "CHECK (only_row)"),
        ("store_revision", "CHECK ((revision >= 0))"),
        ("store_revision", "PRIMARY KEY (only_row)"),
    ];
    if constraints.len() != expected_constraints.len() {
        return Err(Error::SourceChanged);
    }
    for (row, (table, definition)) in constraints.iter().zip(expected_constraints) {
        if row.try_get::<_, String>(0).map_err(db)? != table
            || row.try_get::<_, String>(1).map_err(db)? != definition
            || !row.try_get::<_, bool>(2).map_err(db)?
        {
            return Err(Error::SourceChanged);
        }
    }
    let indexes:bool=session.client().query_one("SELECT count(*)=2 AND bool_and(i.indisprimary AND i.indisunique AND i.indisvalid AND i.indisready AND i.indnkeyatts=1 AND i.indnatts=1 AND i.indkey::text='1' AND i.indpred IS NULL AND i.indexprs IS NULL AND am.amname='btree') FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid JOIN pg_catalog.pg_am am ON am.oid=x.relam WHERE n.nspname='public'",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if !indexes {
        return Err(Error::SourceChanged);
    }
    let safe:bool=session.client().query_one("SELECT NOT EXISTS(SELECT 1 FROM public.busbar_schema) AND NOT EXISTS(SELECT 1 FROM public.store_revision) AND (SELECT count(*)=2 AND bool_and(c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND NOT c.relhasrules AND NOT c.relhassubclass AND NOT c.relispartition) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S'))",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if !safe {
        return Err(Error::SourceChanged);
    }
    Ok(())
}
pub(super) async fn logical_empty(session: &mut Session) -> Result<bool, Error> {
    session.client().query_one("SELECT NOT EXISTS(SELECT 1 FROM busbar_persistence_v4.records) AND NOT EXISTS(SELECT 1 FROM busbar_persistence_v4.receipts)",&[]).await.map_err(db)?.try_get(0).map_err(db)
}
