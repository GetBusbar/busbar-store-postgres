// SPDX-License-Identifier: Apache-2.0
//! Persistent source enforcement on original relation OIDs, including zero-row
//! startup INSERTs, prepared statements, COPY and supported TRUNCATE statements.
use super::*;
use control::Relation;
pub(super) const BODY: &str = "BEGIN RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Busbar historical source is frozen for startup upgrade'; END";
pub(super) fn ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
pub(super) fn lock_sql(relations: &[Relation]) -> String {
    format!(
        "LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE",
        relations
            .iter()
            .map(|r| format!("public.{}", ident(&r.name)))
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub(super) async fn privileges(session: &mut Session) -> Result<(), Error> {
    // Creating owned schemas/functions and triggers requires ordinary native
    // ownership privileges. No role changes, global hooks or superuser operations.
    let allowed:bool=session.client().query_one("SELECT pg_catalog.has_database_privilege(current_database(),'CREATE') AND pg_catalog.has_schema_privilege('public','USAGE,CREATE') AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' AND NOT pg_catalog.pg_has_role(c.relowner,'USAGE'))",&[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if !allowed {
        return Err(Error::MissingCapability);
    }
    Ok(())
}
pub(super) async fn install(
    session: &mut Session,
    relations: &[Relation],
) -> Result<Digest, Error> {
    session.client().batch_execute(&format!("CREATE FUNCTION busbar_upgrade_v1.reject_legacy_write() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $busbar_guard${BODY}$busbar_guard$")).await.map_err(db)?;
    for relation in relations {
        session.client().batch_execute(&format!("CREATE TRIGGER busbar_legacy_reject_v1 BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON public.{} FOR EACH STATEMENT EXECUTE FUNCTION busbar_upgrade_v1.reject_legacy_write(); ALTER TABLE public.{} ENABLE ALWAYS TRIGGER busbar_legacy_reject_v1",ident(&relation.name),ident(&relation.name))).await.map_err(db)?;
    }
    let function: u32 = session
        .client()
        .query_one(
            "SELECT 'busbar_upgrade_v1.reject_legacy_write()'::regprocedure::oid",
            &[],
        )
        .await
        .map_err(db)?
        .try_get(0)
        .map_err(db)?;
    digest(function, relations)
}
pub(super) async fn verify(
    session: &mut Session,
    record: &control::Record,
) -> Result<(u32, Digest), Error> {
    verify_relations(session, &record.relations, record.guard_digest).await
}
pub(super) async fn verify_relations(
    session: &mut Session,
    relations: &[Relation],
    expected: Digest,
) -> Result<(u32, Digest), Error> {
    let functions=session.client().query("SELECT p.oid,p.prosrc::text,p.prorettype='trigger'::regtype,p.pronargs,p.prosecdef,p.proleakproof,p.provolatile::text,l.lanname::text,p.proconfig,p.proowner,p.proname::text FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE n.nspname='busbar_upgrade_v1' ORDER BY p.proname LIMIT 2",&[]).await.map_err(db)?;
    if functions.len() != 1 {
        return Err(Error::SourceChanged);
    }
    let row = &functions[0];
    let function: u32 = row.try_get(0).map_err(db)?;
    let args: i16 = row.try_get(3).map_err(db)?;
    let config: Option<Vec<String>> = row.try_get(8).map_err(db)?;
    if row.try_get::<_, String>(10).map_err(db)? != "reject_legacy_write"
        || row.try_get::<_, String>(1).map_err(db)? != BODY
        || !row.try_get::<_, bool>(2).map_err(db)?
        || args != 0
        || row.try_get::<_, bool>(4).map_err(db)?
        || row.try_get::<_, bool>(5).map_err(db)?
        || row.try_get::<_, String>(6).map_err(db)? != "v"
        || row.try_get::<_, String>(7).map_err(db)? != "plpgsql"
        || config.as_deref() != Some(&["search_path=pg_catalog".into()])
    {
        return Err(Error::SourceChanged);
    }
    let triggers=session.client().query("SELECT c.relname::text,c.oid,c.relowner,t.tgname::text,t.tgfoid,t.tgtype,t.tgenabled::text,t.tgnargs,t.tgqual IS NULL,t.tgoldtable IS NULL,t.tgnewtable IS NULL,cardinality(t.tgattr::smallint[]) FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname LIMIT 17",&[]).await.map_err(db)?;
    if triggers.len() != relations.len() {
        return Err(Error::SourceChanged);
    }
    for (trigger, relation) in triggers.iter().zip(relations) {
        if trigger.try_get::<_, String>(0).map_err(db)? != relation.name
            || trigger.try_get::<_, u32>(1).map_err(db)? != relation.oid
            || trigger.try_get::<_, u32>(2).map_err(db)? != relation.owner
            || trigger.try_get::<_, String>(3).map_err(db)? != "busbar_legacy_reject_v1"
            || trigger.try_get::<_, u32>(4).map_err(db)? != function
            || trigger.try_get::<_, i16>(5).map_err(db)? != 62
            || trigger.try_get::<_, String>(6).map_err(db)? != "A"
            || trigger.try_get::<_, i16>(7).map_err(db)? != 0
            || !(8..=10).all(|i| trigger.try_get::<_, bool>(i).unwrap_or(false))
            || trigger.try_get::<_, i32>(11).map_err(db)? != 0
        {
            return Err(Error::SourceChanged);
        }
    }
    let digest = digest(function, relations)?;
    if expected != [0; 32] && digest != expected {
        return Err(Error::SourceChanged);
    }
    Ok((function, digest))
}

fn digest(function: u32, relations: &[Relation]) -> Result<Digest, Error> {
    #[derive(serde::Serialize)]
    struct Enforcement<'a> {
        version: u32,
        function: u32,
        body: &'a str,
        relations: &'a [Relation],
        always: bool,
    }
    let bytes = serde_json::to_vec(&Enforcement {
        version: 1,
        function,
        body: BODY,
        relations,
        always: true,
    })
    .map_err(|_| Error::Corrupt)?;
    Ok(sha256(&bytes))
}
