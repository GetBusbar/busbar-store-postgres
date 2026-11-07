// SPDX-License-Identifier: Apache-2.0
//! Explicit historical import over the existing host wire. This entry never opens
//! the serving door or runs schema migration. Keep the reader inside the same
//! `wire::Body` for its entire lifetime; the eventual migration ABI must preserve
//! that host operation/connection lease across pages. A dropped/failed operation
//! must discard its connection, never continue this reader on a replacement.

use crate::{pgwire, Session};
use busbar_contract::abi::sdk::store::wire::Wire;
use busbar_contract::persistence::legacy_row::{self, Cell};
use busbar_contract::redacted::{OwnerSeal, Secret};
use postgres_types::{FromSql, Type};
use zeroize::Zeroizing;

mod catalogue;

/// Content-free errors: database errors can echo source secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    Unsupported,
    Damaged,
    Budget,
    Closed,
}
fn db(_: pgwire::Error) -> Error {
    Error::Unavailable
}

/// Explicit output allocation bounds. Transient native decoding is bounded by
/// `page_bytes + 3 * row_bytes` plus fixed-size metadata and wire framing.
/// Native metadata has independent fixed bounds.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub rows: usize,
    pub page_bytes: usize,
    pub row_bytes: usize,
}
impl Limits {
    fn validate(self) -> Result<Self, Error> {
        if self.rows == 0
            || self.rows > 4096
            || self.row_bytes < 32
            || self.row_bytes > 64 * 1024 * 1024
            || self.page_bytes < self.row_bytes
            || self.page_bytes > 64 * 1024 * 1024
        {
            return Err(Error::Budget);
        }
        Ok(self)
    }
}

/// Physical column facts in original ordinal order. Decimal NUMERIC values are
/// exported as their exact PostgreSQL decimal text, never through floating point.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Column {
    pub name: String,
    pub physical_type: String,
    pub required: bool,
    pub collation: String,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    /// Actual validated structural catalogue, including defaults, constraints
    /// and index definitions. No row payloads or connection secrets occur here.
    pub native_layout: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Catalogue {
    pub schema_version: i64,
    pub upgraded_from_six: bool,
    /// Includes retained older stamps, which normal migrations do not delete.
    pub version_stamps: Vec<i64>,
    pub tables: Vec<Table>,
    /// Canonical physical profile digest; excludes the live snapshot identity.
    pub digest: [u8; 32],
    /// Exact cluster system identifier plus database OID/name, read natively.
    /// Reading pg_control_system requires explicit administrative privileges.
    pub native_identity: Vec<u8>,
    /// Snapshot transaction visibility plus server/database/session identity.
    /// This identifies this live snapshot, not a durable resumable export.
    pub snapshot: String,
}

/// A position is valid only in the owning live reader; it is never a restart
/// cursor. Restart requires a newly verified source snapshot and coordinator plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub table: usize,
    pub row: u64,
}
#[derive(Debug)]
pub struct SourceRow<O> {
    pub table: usize,
    pub ordinal: u64,
    /// Exact native heap tuple identity, scoped by table and live snapshot.
    pub native_key: Vec<u8>,
    pub bytes: Secret<Vec<u8>, O>,
    encoded_len: usize,
}
#[derive(Debug)]
pub struct Page<O> {
    pub rows: Vec<SourceRow<O>>,
    pub next: Cursor,
    pub exhausted: bool,
}

/// One read-only repeatable snapshot and one server cursor at a time. No source
/// row survives a page except a single bounded, protected pending row.
pub struct Reader<O: OwnerSeal> {
    session: Option<Session>,
    catalogue: Catalogue,
    limits: Limits,
    cursor: Cursor,
    declared: bool,
    exhausted: bool,
    pending: Option<SourceRow<O>>,
}
impl<O: OwnerSeal> Reader<O> {
    /// Parse connection settings without invoking normal OPEN/migrate. The wire
    /// must be provided by the host's existing declared connection machinery.
    pub async fn open(
        wire: Wire,
        settings: &[u8],
        secrets: &[&[u8]],
        limits: Limits,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let store = crate::settings::parse(settings, secrets).map_err(|_| Error::Unsupported)?;
        let shared = store.shared();
        let client = pgwire::Client::connect(wire, &shared.config, &shared.endpoint)
            .await
            .map_err(db)?;
        let mut session = Session { client, shared };
        // Read-only is established before the first catalogue query. Bound locks
        // and scans, and make RLS refuse instead of silently hiding source rows.
        session.client().batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path = pg_catalog; SET LOCAL statement_timeout = '30s'; SET LOCAL lock_timeout = '5s'; SET LOCAL row_security = off; SET LOCAL max_parallel_workers_per_gather = 0; SET LOCAL work_mem = '1MB'").await.map_err(db)?;
        let result = identify(&mut session).await;
        let catalogue = match result {
            Ok(catalogue) => catalogue,
            Err(error) => {
                let _ = session.client().batch_execute("ROLLBACK").await;
                session.close().await;
                return Err(error);
            }
        };
        Ok(Self {
            session: Some(session),
            catalogue,
            limits,
            cursor: Cursor { table: 0, row: 0 },
            declared: false,
            exhausted: false,
            pending: None,
        })
    }
    /// Automatic lifecycle entry. Identity was read from independent native
    /// channels; a guard OID is supplied only after its complete DDL was verified.
    pub(crate) async fn from_native_session(
        mut session: Session,
        limits: Limits,
        identity: Vec<u8>,
        guard: Option<u32>,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        session.client().batch_execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path=pg_catalog; SET LOCAL statement_timeout='30s'; SET LOCAL lock_timeout='5s'; SET LOCAL row_security=off; SET LOCAL max_parallel_workers_per_gather=0; SET LOCAL work_mem='1MB'").await.map_err(db)?;
        let catalogue = identify_native(&mut session, Some(identity), guard).await?;
        Ok(Self {
            session: Some(session),
            catalogue,
            limits,
            cursor: Cursor { table: 0, row: 0 },
            declared: false,
            exhausted: false,
            pending: None,
        })
    }
    pub(crate) fn native_session(&mut self) -> Result<&mut Session, Error> {
        self.session.as_mut().ok_or(Error::Closed)
    }
    pub(crate) async fn release_snapshot(mut self) -> Result<Session, Error> {
        self.pending = None;
        let mut session = self.session.take().ok_or(Error::Closed)?;
        session
            .client()
            .batch_execute("ROLLBACK")
            .await
            .map_err(db)?;
        Ok(session)
    }
    pub fn catalogue(&self) -> &Catalogue {
        &self.catalogue
    }
    pub fn cursor(&self) -> Cursor {
        self.pending.as_ref().map_or(self.cursor, |row| Cursor {
            table: row.table,
            row: row.ordinal,
        })
    }

    /// Return bounded rows in table-name / native cursor order. Physical
    /// order is stable within this held snapshot, including duplicate logical
    /// metering identities in historical schemas without a primary key.
    pub async fn page(&mut self) -> Result<Page<O>, Error> {
        if self.session.is_none() {
            return Err(Error::Closed);
        }
        let result = self.page_inner().await;
        if result.is_err() {
            self.pending = None;
            if let Some(mut session) = self.session.take() {
                let _ = session.client().batch_execute("ROLLBACK").await;
                session.close().await;
            }
        }
        result
    }
    async fn page_inner(&mut self) -> Result<Page<O>, Error> {
        let mut rows = Vec::new();
        let mut size = 0usize;
        while rows.len() < self.limits.rows && !self.exhausted {
            let row = match self.pending.take() {
                Some(row) => row,
                None => match self.fetch().await? {
                    Some(row) => row,
                    None => break,
                },
            };
            // Secret ownership stays protected; length does not expose contents.
            let len = row.encoded_len;
            if size.checked_add(len).ok_or(Error::Budget)? > self.limits.page_bytes {
                self.pending = Some(row);
                break;
            }
            size += len;
            rows.push(row);
        }
        Ok(Page {
            rows,
            next: self.cursor(),
            exhausted: self.exhausted && self.pending.is_none(),
        })
    }
    async fn fetch(&mut self) -> Result<Option<SourceRow<O>>, Error> {
        while self.cursor.table < self.catalogue.tables.len() {
            let table = &self.catalogue.tables[self.cursor.table];
            let session = self.session.as_mut().ok_or(Error::Closed)?;
            if !self.declared {
                let sql = cursor_sql(table, self.limits.row_bytes);
                session.client().batch_execute(&sql).await.map_err(db)?;
                self.declared = true;
            }
            // FETCH 1 prevents a database-sized driver result collection. The
            // SELECT gates every cell on its uncompressed encoded row size.
            let native = session
                .client()
                .query("FETCH FORWARD 1 FROM busbar_legacy_import", &[])
                .await
                .map_err(db)?;
            if native.is_empty() {
                session
                    .client()
                    .batch_execute("CLOSE busbar_legacy_import")
                    .await
                    .map_err(db)?;
                self.cursor.table += 1;
                self.cursor.row = 0;
                self.declared = false;
                continue;
            }
            if native.len() != 1 {
                return Err(Error::Damaged);
            }
            let ordinal = self.cursor.row;
            self.cursor.row = ordinal.checked_add(1).ok_or(Error::Budget)?;
            return Ok(Some(decode_native_row::<O>(
                &native[0],
                table,
                self.cursor.table,
                ordinal,
                self.limits.row_bytes,
            )?));
        }
        self.exhausted = true;
        Ok(None)
    }
    /// Read one compiled table selector inside the retained snapshot. A native
    /// heap key is an exclusive restart cursor because persistent guards prevent
    /// all supported source mutations and retain the original relations.
    pub(crate) async fn native_table_page(
        &mut self,
        table_index: usize,
        after: Option<&[u8]>,
        exact: Option<&[u8]>,
        limits: Limits,
    ) -> Result<(Vec<SourceRow<O>>, bool), Error> {
        let limits = limits.validate()?;
        let table = self
            .catalogue
            .tables
            .get(table_index)
            .ok_or(Error::Unsupported)?;
        let mut sql = cursor_sql(table, limits.row_bytes).replace(
            "DECLARE busbar_legacy_import ",
            "DECLARE busbar_upgrade_selected ",
        );
        if let Some(key) = exact {
            sql.push_str(&format!(" WHERE ctid={}::tid", native_tid(key)?));
        } else if let Some(key) = after {
            sql.push_str(&format!(" WHERE ctid>{}::tid", native_tid(key)?));
        }
        sql.push_str(" ORDER BY ctid");
        let session = self.session.as_mut().ok_or(Error::Closed)?;
        session.client().batch_execute(&sql).await.map_err(db)?;
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let mut exhausted = false;
        while rows.len() < limits.rows {
            let native = session
                .client()
                .query("FETCH FORWARD 1 FROM busbar_upgrade_selected", &[])
                .await
                .map_err(db)?;
            if native.is_empty() {
                exhausted = true;
                break;
            }
            if native.len() != 1 {
                return Err(Error::Damaged);
            }
            let row = decode_native_row::<O>(
                &native[0],
                table,
                table_index,
                rows.len() as u64,
                limits.row_bytes,
            )?;
            let charged = row.encoded_len.checked_add(256).ok_or(Error::Budget)?;
            if bytes.checked_add(charged).ok_or(Error::Budget)? > limits.page_bytes {
                if rows.is_empty() {
                    return Err(Error::Budget);
                }
                break;
            }
            bytes += charged;
            rows.push(row);
        }
        session
            .client()
            .batch_execute("CLOSE busbar_upgrade_selected")
            .await
            .map_err(db)?;
        Ok((rows, exhausted))
    }
    /// Release snapshot and host connection. No source mutation is performed.
    pub async fn close(mut self) -> Result<(), Error> {
        self.pending = None;
        if let Some(mut session) = self.session.take() {
            let result = session.client().batch_execute("ROLLBACK").await.map_err(db);
            session.close().await;
            result?;
        }
        Ok(())
    }
}

fn decode_native_row<O: OwnerSeal>(
    row: &pgwire::Row,
    table: &Table,
    table_index: usize,
    ordinal: u64,
    row_bytes: usize,
) -> Result<SourceRow<O>, Error> {
    if !row.try_get::<_, bool>(0).map_err(db)? {
        return Err(Error::Budget);
    }
    let native_key = row.try_get::<_, &str>(1).map_err(db)?.as_bytes().to_vec();
    let mut cells = Vec::with_capacity(table.columns.len());
    for index in 0..table.columns.len() {
        cells.push(
            row.try_get::<_, NativeCell>(index + 2)
                .map_err(|_| Error::Damaged)?,
        );
    }
    let borrowed: Vec<_> = cells.iter().map(NativeCell::borrow).collect();
    let bytes = legacy_row::encode::<O>(
        &borrowed,
        row_bytes
            .checked_sub(native_key.len())
            .ok_or(Error::Budget)?,
    )
    .map_err(|_| Error::Budget)?;
    let encoded_len = borrowed
        .iter()
        .map(|cell| match cell {
            Cell::Null => 1,
            Cell::Text(v) | Cell::Blob(v) => 9 + v.len(),
            _ => 9,
        })
        .sum::<usize>()
        + 12
        + native_key.len();
    Ok(SourceRow {
        table: table_index,
        ordinal,
        native_key,
        bytes,
        encoded_len,
    })
}

fn native_tid(bytes: &[u8]) -> Result<String, Error> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::Damaged)?;
    let body = text
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or(Error::Damaged)?;
    let (block, offset) = body.split_once(',').ok_or(Error::Damaged)?;
    let block: u32 = block.parse().map_err(|_| Error::Damaged)?;
    let offset: u16 = offset.parse().map_err(|_| Error::Damaged)?;
    if offset == 0 {
        return Err(Error::Damaged);
    }
    Ok(format!("'({block},{offset})'"))
}

fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
fn cursor_sql(table: &Table, budget: usize) -> String {
    let expressions: Vec<_> = table
        .columns
        .iter()
        .map(|column| {
            let name = quoted(&column.name);
            if column.physical_type.starts_with("numeric(") {
                format!("{name}::text")
            } else {
                name
            }
        })
        .collect();
    let sizes: Vec<_> = table
        .columns
        .iter()
        .zip(&expressions)
        .map(|(column, expr)| {
            let size = match column.physical_type.as_str() {
                "text" | "bytea" => format!("octet_length({expr})::bigint"),
                ty if ty.starts_with("numeric(") => format!("octet_length({expr})::bigint"),
                _ => "0::bigint".to_owned(),
            };
            // Neutral framing is 9 + payload, NULL is one byte. Native integers
            // and booleans become exact integer cells (9 bytes).
            format!("CASE WHEN {expr} IS NULL THEN 1::bigint ELSE 9::bigint + {size} END")
        })
        .collect();
    let fits = format!(
        "(12::bigint + octet_length(ctid::text)::bigint + {} <= {budget})",
        sizes.join(" + ")
    );
    let columns = expressions
        .iter()
        .map(|expr| format!("CASE WHEN {fits} THEN {expr} ELSE NULL END"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "DECLARE busbar_legacy_import NO SCROLL CURSOR FOR SELECT {fits},ctid::text,{columns} FROM public.{}",
        quoted(&table.name)
    )
}

// Raw copies are wiping-owned and never formatted. Native pgwire row custody is
// separate; this decoder does not stringify errors containing source values.
enum NativeCell {
    Null,
    Integer(i64),
    Real(u64),
    Text(Zeroizing<Vec<u8>>),
    Blob(Zeroizing<Vec<u8>>),
}
impl Drop for NativeCell {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        match self {
            Self::Integer(value) => value.zeroize(),
            Self::Real(value) => value.zeroize(),
            _ => {}
        }
    }
}
impl NativeCell {
    fn borrow(&self) -> Cell<'_> {
        match self {
            Self::Null => Cell::Null,
            Self::Integer(v) => Cell::Integer(*v),
            Self::Real(v) => Cell::RealBits(*v),
            Self::Text(v) => Cell::Text(v),
            Self::Blob(v) => Cell::Blob(v),
        }
    }
}
impl<'a> FromSql<'a> for NativeCell {
    fn from_sql(
        ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let malformed = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid native legacy cell",
            )
        };
        Ok(match *ty {
            Type::BOOL if raw == [0] || raw == [1] => Self::Integer(i64::from(raw[0])),
            Type::INT2 => {
                Self::Integer(i16::from_be_bytes(raw.try_into().map_err(|_| malformed())?) as i64)
            }
            Type::INT4 => {
                Self::Integer(i32::from_be_bytes(raw.try_into().map_err(|_| malformed())?) as i64)
            }
            Type::INT8 => {
                Self::Integer(i64::from_be_bytes(raw.try_into().map_err(|_| malformed())?))
            }
            Type::FLOAT8 => {
                Self::Real(u64::from_be_bytes(raw.try_into().map_err(|_| malformed())?))
            }
            Type::TEXT => Self::Text(Zeroizing::new(raw.to_vec())),
            Type::BYTEA => Self::Blob(Zeroizing::new(raw.to_vec())),
            _ => return Err(malformed().into()),
        })
    }
    fn from_sql_null(_: &Type) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Self::Null)
    }
    fn accepts(ty: &Type) -> bool {
        matches!(
            *ty,
            Type::BOOL
                | Type::INT2
                | Type::INT4
                | Type::INT8
                | Type::FLOAT8
                | Type::TEXT
                | Type::BYTEA
        )
    }
}

fn expected(version: i64, upgraded: bool) -> Vec<Table> {
    let source = if version == 6 {
        catalogue::RELEASED
    } else {
        catalogue::DEV
    };
    source
        .lines()
        .map(|line| {
            let (name, fields) = line.split_once('|').expect("static catalogue");
            let mut columns: Vec<_> = fields
                .split(',')
                .map(|field| {
                    let mut parts = field.split(':');
                    Column {
                        name: parts.next().unwrap().into(),
                        physical_type: parts.next().unwrap().into(),
                        required: parts.next() == Some("1"),
                        collation: parts.next().unwrap().into(),
                    }
                })
                .collect();
            if version == 9 {
                for column in &mut columns {
                    if (name.starts_with("usage_ledger") || name.starts_with("usage_metering"))
                        && (column.name.starts_with("tokens_") || column.name == "count")
                    {
                        column.physical_type = "numeric(39,0)".into();
                    }
                    if name == "usage_metering"
                        && matches!(column.name.as_str(), "requests" | "billable_requests")
                    {
                        column.physical_type = "numeric(20,0)".into();
                    }
                }
            }
            if upgraded {
                for column in &mut columns {
                    if (name == "usage_windows"
                        && matches!(column.name.as_str(), "requests" | "billable_requests"))
                        || (version < 9
                            && name.starts_with("usage_ledger")
                            && (column.name.starts_with("tokens_") || column.name == "count"))
                    {
                        column.physical_type = "numeric(20,0)".into();
                    }
                    if name == "usage_metering"
                        && matches!(column.name.as_str(), "key_group_at_use" | "pricing_version")
                    {
                        column.collation = "C".into();
                    }
                }
                if name == "usage_metering_units" {
                    for field in ["key_group_at_use", "pricing_version"] {
                        columns.push(Column {
                            name: field.into(),
                            physical_type: "text".into(),
                            required: true,
                            collation: "C".into(),
                        });
                    }
                }
            }
            Table {
                name: name.into(),
                columns,
                native_layout: Vec::new(),
            }
        })
        .collect()
}

async fn identify(session: &mut Session) -> Result<Catalogue, Error> {
    identify_native(session, None, None).await
}
pub(crate) async fn inspect_native_catalogue(
    session: &mut Session,
    identity: Vec<u8>,
    guard: Option<u32>,
) -> Result<Catalogue, Error> {
    identify_native(session, Some(identity), guard).await
}

async fn identify_native(
    session: &mut Session,
    identity: Option<Vec<u8>>,
    guard: Option<u32>,
) -> Result<Catalogue, Error> {
    let allowed: Vec<String> = if guard.is_some() {
        vec!["busbar_upgrade_v1".into(), "busbar_persistence_v4".into()]
    } else {
        vec![]
    };
    let native = session.client().query("SELECT n.nspname::text,c.relname::text,c.relkind::text,c.relpersistence::text,c.relrowsecurity,c.relhassubclass,c.relispartition,c.relhasrules FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE left(n.nspname,3) <> 'pg_' AND n.nspname <> 'information_schema' AND NOT(n.nspname=ANY($1::text[])) AND c.relkind IN ('r','p','v','m','f','S') ORDER BY n.nspname,c.relname LIMIT 33", &[&allowed]).await.map_err(db)?;
    if native.is_empty() || native.len() > 16 {
        return Err(Error::Unsupported);
    }
    let mut table_names = Vec::new();
    for row in native {
        let namespace: String = row.try_get(0).map_err(db)?;
        let name: String = row.try_get(1).map_err(db)?;
        let kind: String = row.try_get(2).map_err(db)?;
        let persistence: String = row.try_get(3).map_err(db)?;
        if namespace != "public"
            || kind != "r"
            || persistence != "p"
            || row.try_get::<_, bool>(4).map_err(db)?
            || row.try_get::<_, bool>(5).map_err(db)?
            || row.try_get::<_, bool>(6).map_err(db)?
            || row.try_get::<_, bool>(7).map_err(db)?
        {
            return Err(Error::Unsupported);
        }
        table_names.push(name);
    }
    if !table_names.iter().any(|name| name == "busbar_schema") {
        return Err(Error::Unsupported);
    }
    // Prevent DDL after identification, without excluding ordinary source writers.
    // Their data changes remain outside this repeatable-read snapshot.
    let locks = table_names
        .iter()
        .map(|name| format!("public.{}", quoted(name)))
        .collect::<Vec<_>>()
        .join(",");
    session
        .client()
        .batch_execute(&format!("LOCK TABLE {locks} IN ACCESS SHARE MODE"))
        .await
        .map_err(db)?;
    let native = session
        .client()
        .query(
            "SELECT version FROM public.busbar_schema ORDER BY version LIMIT 5",
            &[],
        )
        .await
        .map_err(db)?;
    if native.is_empty() || native.len() > 4 {
        return Err(Error::Damaged);
    }
    let stamps = native
        .iter()
        .map(|row| row.try_get::<_, i64>(0).map_err(|_| Error::Damaged))
        .collect::<Result<Vec<_>, _>>()?;
    if stamps.iter().any(|v| !(6..=9).contains(v))
        || stamps.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(Error::Unsupported);
    }
    let version = *stamps.last().ok_or(Error::Damaged)?;
    let native = session.client().query("SELECT c.relname::text,a.attname::text,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(coll.collname::text,'-'),a.attnum::smallint,a.attisdropped,a.attgenerated::text,a.attidentity::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_catalog.pg_collation coll ON coll.oid=a.attcollation WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 ORDER BY c.relname,a.attnum LIMIT 513", &[]).await.map_err(db)?;
    if native.len() > 512 {
        return Err(Error::Budget);
    }
    let mut tables: Vec<Table> = Vec::new();
    for row in native {
        let name: String = row.try_get(0).map_err(db)?;
        if tables.last().is_none_or(|table| table.name != name) {
            tables.push(Table {
                name,
                columns: Vec::new(),
                native_layout: Vec::new(),
            });
        }
        let table = tables.last_mut().ok_or(Error::Damaged)?;
        let ordinal: i16 = row.try_get(5).map_err(db)?;
        if ordinal as usize != table.columns.len() + 1
            || row.try_get::<_, bool>(6).map_err(db)?
            || !row.try_get::<_, String>(7).map_err(db)?.is_empty()
            || !row.try_get::<_, String>(8).map_err(db)?.is_empty()
        {
            return Err(Error::Damaged);
        }
        table.columns.push(Column {
            name: row.try_get(1).map_err(db)?,
            physical_type: row.try_get(2).map_err(db)?,
            required: row.try_get(3).map_err(db)?,
            collation: row.try_get(4).map_err(db)?,
        });
    }
    let upgraded = if tables == expected(version, false) {
        false
    } else if version != 6 && tables == expected(version, true) {
        true
    } else {
        return Err(Error::Unsupported);
    };
    if tables
        .iter()
        .map(|table| &table.name)
        .ne(table_names.iter())
    {
        return Err(Error::Damaged);
    }
    // The automatic path admits only its exact verified native guard delta.
    // Ordinary archives never accept user triggers or rewrite rules.
    let guards: i64 = session.client().query_one("SELECT count(*)::bigint FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal AND ($1::oid IS NULL OR t.tgfoid<>$1::oid OR t.tgname<>'busbar_legacy_reject_v1' OR t.tgtype<>62 OR t.tgenabled<>'A' OR t.tgnargs<>0 OR t.tgqual IS NOT NULL OR t.tgoldtable IS NOT NULL OR t.tgnewtable IS NOT NULL)",&[&guard]).await.map_err(db)?.try_get(0).map_err(db)?;
    if guards != 0 {
        return Err(Error::Unsupported);
    }
    validate_constraints(session, &tables, version, upgraded).await?;
    fill_native_layout(session, &mut tables).await?;
    let revision = session
        .client()
        .query(
            "SELECT only_row,revision FROM public.store_revision LIMIT 2",
            &[],
        )
        .await
        .map_err(db)?;
    if revision.len() != 1
        || !revision[0].try_get::<_, bool>(0).map_err(db)?
        || revision[0].try_get::<_, i64>(1).map_err(db)? < 0
    {
        return Err(Error::Damaged);
    }
    // Native FK violations are structural damage, without decoding Busbar policy.
    let orphan: bool = session.client().query_one("SELECT EXISTS(SELECT 1 FROM public.credentials c LEFT JOIN public.keys k ON c.key_id=k.id WHERE k.id IS NULL)", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if orphan {
        return Err(Error::Damaged);
    }
    let snapshot: String = session.client().query_one("SELECT left(pg_catalog.txid_current_snapshot()::text,4097) || '/' || (SELECT oid::text FROM pg_catalog.pg_database WHERE datname=current_database()) || '/' || pg_catalog.pg_postmaster_start_time()::text || '/' || COALESCE(pg_catalog.inet_server_addr()::text,'unix') || '/' || COALESCE(pg_catalog.inet_server_port()::text,'0') || '/' || pg_catalog.pg_backend_pid()::text", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if snapshot
        .split('/')
        .next()
        .is_none_or(|part| part.len() > 4096)
    {
        return Err(Error::Budget);
    }
    let native_identity = match identity {
        Some(value) => value,
        None => native_identity(session).await?,
    };
    Ok(Catalogue {
        schema_version: version,
        upgraded_from_six: upgraded,
        version_stamps: stamps,
        native_identity,
        digest: catalogue_digest(version, upgraded, &tables),
        tables,
        snapshot,
    })
}

fn catalogue_digest(version: i64, upgraded: bool, tables: &[Table]) -> [u8; 32] {
    let mut bytes = b"busbar-postgres-legacy-catalogue-v1\0".to_vec();
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.push(u8::from(upgraded));
    fn field(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes.extend_from_slice(&(tables.len() as u32).to_be_bytes());
    for table in tables {
        field(&mut bytes, &table.name);
        bytes.extend_from_slice(&(table.columns.len() as u32).to_be_bytes());
        for column in &table.columns {
            field(&mut bytes, &column.name);
            field(&mut bytes, &column.physical_type);
            bytes.push(u8::from(column.required));
            field(&mut bytes, &column.collation);
        }
    }
    busbar_contract::abi::sdk::digest::sha256(&bytes)
}

fn primary(table: &str, version: i64, upgraded: bool) -> &'static str {
    match table {
        "audit_log" => "seq",
        "busbar_schema" => "version",
        "credentials" | "keys" => "id",
        "denylist" => "sub",
        "store_revision" => "only_row",
        "usage_windows" => "bucket_id,window_start",
        "usage_ledger" => "bucket_id,window_start,model",
        "usage_ledger_units" => "bucket_id,window_start,model,unit",
        "usage_metering" if upgraded => "",
        "usage_metering_units" if upgraded => "",
        "usage_metering" if version == 6 => "key_id,bucket,model,provider",
        "usage_metering" => "key_id,bucket,model,provider,priced_from_ms",
        "usage_metering_units" => "key_id,bucket,model,provider,priced_from_ms,unit",
        "plane_records" => "kind,id",
        "plane_chain" => "kind,parent,seq",
        "plane_tokens" => "kind,token",
        "store_ops" => "op_id",
        "store_records" => "schema_id,key",
        _ => "",
    }
}

async fn validate_constraints(
    session: &mut Session,
    tables: &[Table],
    version: i64,
    upgraded: bool,
) -> Result<(), Error> {
    let rows = session.client().query("SELECT c.relname::text,k.contype::text,k.convalidated,k.condeferrable,COALESCE((SELECT string_agg(a.attname::text,',' ORDER BY u.ord) FROM unnest(k.conkey) WITH ORDINALITY u(attnum,ord) JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid AND a.attnum=u.attnum),''),left(pg_catalog.pg_get_constraintdef(k.oid),4097) FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,k.contype,k.conname LIMIT 65", &[]).await.map_err(db)?;
    if rows.len() > 64 {
        return Err(Error::Budget);
    }
    let mut primary_seen = std::collections::BTreeSet::new();
    let mut unique_seen = std::collections::BTreeSet::new();
    let mut checks = std::collections::BTreeSet::new();
    let mut foreign = 0;
    for row in rows {
        let table: String = row.try_get(0).map_err(db)?;
        let kind: String = row.try_get(1).map_err(db)?;
        let cols: String = row.try_get(4).map_err(db)?;
        if !row.try_get::<_, bool>(2).map_err(db)? || row.try_get::<_, bool>(3).map_err(db)? {
            return Err(Error::Damaged);
        }
        match kind.as_str() {
            "p" if cols == primary(&table, version, upgraded) && !cols.is_empty() => {
                if !primary_seen.insert(table) {
                    return Err(Error::Damaged);
                }
            }
            "u" if table == "credentials"
                && matches!(cols.as_str(), "kind,public_id" | "key_id,kind,slot") =>
            {
                if !unique_seen.insert(cols) {
                    return Err(Error::Damaged);
                }
            }
            "f" if table == "credentials" && cols == "key_id" => foreign += 1,
            "c" => {
                let definition: String = row.try_get(5).map_err(db)?;
                if definition.len() > 4096 {
                    return Err(Error::Budget);
                }
                let signature = normalize_check(&definition);
                if !expected_checks(&table).contains(&signature.as_str())
                    || !checks.insert((table, signature))
                {
                    return Err(Error::Damaged);
                }
            }
            _ => return Err(Error::Damaged),
        }
    }
    if unique_seen.len() != 2
        || foreign != 1
        || checks.len() != if version == 6 { 7 } else { 9 }
        || tables
            .iter()
            .filter(|table| !primary(&table.name, version, upgraded).is_empty())
            .any(|table| !primary_seen.contains(&table.name))
    {
        return Err(Error::Damaged);
    }
    let damaged: bool = session.client().query_one("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND (NOT i.indisvalid OR NOT i.indisready)) OR EXISTS(SELECT 1 FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND k.contype='f' AND (k.confrelid <> 'public.keys'::regclass OR k.confkey <> ARRAY[1]::smallint[] OR k.confdeltype <> 'c'))", &[]).await.map_err(db)?.try_get(0).map_err(db)?;
    if damaged {
        return Err(Error::Damaged);
    }
    Ok(())
}

fn normalize_check(definition: &str) -> String {
    let mut remaining = definition;
    let mut quoted = false;
    let mut normalized = String::new();
    while !remaining.is_empty() {
        if !quoted {
            if let Some(after) = remaining.strip_prefix("::text") {
                if after
                    .chars()
                    .next()
                    .is_none_or(|ch| !ch.is_alphanumeric() && ch != '_')
                {
                    remaining = after;
                    continue;
                }
            }
        }
        let ch = remaining.chars().next().expect("nonempty SQL");
        remaining = &remaining[ch.len_utf8()..];
        if ch == '\'' {
            normalized.push(ch);
            if quoted && remaining.starts_with('\'') {
                normalized.push('\'');
                remaining = &remaining[1..];
            } else {
                quoted = !quoted;
            }
        } else if quoted || (!ch.is_whitespace() && !matches!(ch, '(' | ')')) {
            normalized.push(ch);
        }
    }
    normalized
}
fn expected_checks(table: &str) -> &'static [&'static str] {
    match table {
        "keys" => &["CHECKdeleted_atISNULLORenabled=false"],
        "store_revision" => &["CHECKonly_row", "CHECKrevision>=0"],
        "credentials" => &[
            "CHECKkind='sigv4'",
            "CHECKslot=ANYARRAY[0,1]",
            "CHECKsecret_form=ANYARRAY['none','recoverable','digest']",
            "CHECKsecret_form='none'=secretISNULL",
        ],
        "plane_records" | "plane_chain" => &["CHECKdisposition=ANYARRAY['active','terminal']"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    busbar_contract::own_seal!(Own);

    #[test]
    fn legacy_native_cells_preserve_signed_bits_decimal_text_null_and_blob() {
        let cases = [
            (
                Type::INT8,
                i64::MIN.to_be_bytes().to_vec(),
                Cell::Integer(i64::MIN),
            ),
            (
                Type::INT2,
                (-1i16).to_be_bytes().to_vec(),
                Cell::Integer(-1),
            ),
            (Type::BOOL, vec![1], Cell::Integer(1)),
            (
                Type::FLOAT8,
                (-0.0f64).to_bits().to_be_bytes().to_vec(),
                Cell::RealBits((-0.0f64).to_bits()),
            ),
            (
                Type::TEXT,
                b"170141183460469231731687303715884105727".to_vec(),
                Cell::Text(b"170141183460469231731687303715884105727"),
            ),
            (Type::BYTEA, vec![255, 0, 1], Cell::Blob(&[255, 0, 1])),
            (Type::TEXT, vec![], Cell::Text(b"")),
        ];
        for (ty, raw, expected) in cases {
            let native = NativeCell::from_sql(&ty, &raw).unwrap();
            let encoded = legacy_row::encode::<Own>(&[native.borrow()], 1024).unwrap();
            assert_eq!(
                legacy_row::Row::decode(encoded.expose_own(&Own::here()))
                    .unwrap()
                    .cells()
                    .next(),
                Some(expected)
            );
        }
        assert_eq!(
            NativeCell::from_sql_null(&Type::TEXT).unwrap().borrow(),
            Cell::Null
        );
        assert!(NativeCell::from_sql(&Type::INT8, b"short").is_err());
        assert!(NativeCell::from_sql(&Type::BOOL, &[2]).is_err());
        assert!(
            !NativeCell::accepts(&Type::NUMERIC),
            "decimal conversion is explicit SQL text"
        );
    }

    #[test]
    fn legacy_catalogue_distinguishes_released_dev_scale_and_upgrade_profiles() {
        let released = expected(6, false);
        assert_eq!(released.len(), 9);
        assert!(!released.iter().any(|table| table.name == "plane_records"));
        assert_eq!(
            released
                .iter()
                .find(|table| table.name == "keys")
                .unwrap()
                .columns
                .len(),
            11
        );
        let seven = expected(7, false);
        let eight = expected(8, false);
        assert_eq!(
            seven, eight,
            "physical bigint is shared; schema stamp determines scale in core"
        );
        assert_eq!(seven.len(), 16);
        let nine = expected(9, false);
        assert_ne!(nine, eight);
        assert_ne!(
            catalogue_digest(7, false, &seven),
            catalogue_digest(8, false, &eight)
        );
        assert_ne!(
            catalogue_digest(9, false, &nine),
            catalogue_digest(9, true, &expected(9, true))
        );
        assert!(nine
            .iter()
            .find(|table| table.name == "usage_ledger")
            .unwrap()
            .columns
            .iter()
            .filter(|column| column.name.starts_with("tokens_"))
            .all(|column| column.physical_type == "numeric(39,0)"));
        for version in 7..=9 {
            let upgraded = expected(version, true);
            assert_ne!(upgraded, expected(version, false));
            assert_eq!(primary("usage_metering", version, true), "");
            assert_eq!(
                upgraded
                    .iter()
                    .find(|table| table.name == "usage_metering_units")
                    .unwrap()
                    .columns
                    .len(),
                9
            );
        }
    }

    #[test]
    fn legacy_cursor_gates_uncompressed_payloads_and_allocation_budgets() {
        let table = expected(9, false)
            .into_iter()
            .find(|table| table.name == "usage_metering")
            .unwrap();
        let sql = cursor_sql(&table, 4096);
        assert!(sql.starts_with("DECLARE busbar_legacy_import NO SCROLL CURSOR FOR SELECT"));
        assert!(sql.contains("octet_length(\"tokens_input\"::text)::bigint"));
        assert!(sql.contains("THEN \"tokens_input\"::text ELSE NULL END"));
        assert!(sql.ends_with("FROM public.\"usage_metering\""));
        for limits in [
            Limits {
                rows: 0,
                page_bytes: 1024,
                row_bytes: 1024,
            },
            Limits {
                rows: 1,
                page_bytes: 1023,
                row_bytes: 1024,
            },
            Limits {
                rows: 1,
                page_bytes: usize::MAX,
                row_bytes: 1024,
            },
        ] {
            assert_eq!(limits.validate().unwrap_err(), Error::Budget);
        }
        assert!(Limits {
            rows: 1,
            page_bytes: 1024,
            row_bytes: 1024
        }
        .validate()
        .is_ok());
        assert_eq!(
            normalize_check("CHECK (((secret_form = 'none'::text) = (secret IS NULL)))"),
            expected_checks("credentials")[3]
        );
        for literal in ["no ne", "n(one)", "no::textne"] {
            let altered = format!("CHECK (((secret_form = '{literal}'::text) = (secret IS NULL)))");
            assert_ne!(normalize_check(&altered), expected_checks("credentials")[3]);
        }
    }
}

#[cfg(test)]
mod native_tests;

async fn fill_native_layout(session: &mut Session, tables: &mut [Table]) -> Result<(), Error> {
    use std::collections::BTreeMap;
    let mut columns: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let mut constraints: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let mut indexes: BTreeMap<String, Vec<serde_json::Value>> = BTreeMap::new();
    let rows = session.client().query("SELECT c.relname::text,a.attnum::smallint,a.attname::text,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,COALESCE(coll.collname::text,'-'),left(COALESCE(pg_catalog.pg_get_expr(d.adbin,d.adrelid),''),4097),a.attgenerated::text,a.attidentity::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_catalog.pg_collation coll ON coll.oid=a.attcollation LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum LIMIT 513", &[]).await.map_err(db)?;
    if rows.len() > 512 {
        return Err(Error::Budget);
    }
    for row in rows {
        let table: String = row.try_get(0).map_err(db)?;
        let default: String = row.try_get(6).map_err(db)?;
        if default.len() > 4096 {
            return Err(Error::Budget);
        }
        columns.entry(table).or_default().push(serde_json::json!([
            row.try_get::<_, i16>(1).map_err(db)?,
            row.try_get::<_, String>(2).map_err(db)?,
            row.try_get::<_, String>(3).map_err(db)?,
            row.try_get::<_, bool>(4).map_err(db)?,
            row.try_get::<_, String>(5).map_err(db)?,
            default,
            row.try_get::<_, String>(7).map_err(db)?,
            row.try_get::<_, String>(8).map_err(db)?
        ]));
    }
    let rows = session.client().query("SELECT c.relname::text,k.conname::text,k.contype::text,k.convalidated,k.condeferrable,k.condeferred,left(pg_catalog.pg_get_constraintdef(k.oid),4097),COALESCE(k.conkey::text,''),CASE WHEN k.confrelid=0 THEN '' ELSE k.confrelid::regclass::text END,COALESCE(k.confkey::text,''),k.confupdtype::text,k.confdeltype::text,k.confmatchtype::text FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,k.conname LIMIT 65", &[]).await.map_err(db)?;
    if rows.len() > 64 {
        return Err(Error::Budget);
    }
    for row in rows {
        let table: String = row.try_get(0).map_err(db)?;
        let definition: String = row.try_get(6).map_err(db)?;
        if definition.len() > 4096 {
            return Err(Error::Budget);
        }
        constraints
            .entry(table)
            .or_default()
            .push(serde_json::json!([
                row.try_get::<_, String>(1).map_err(db)?,
                row.try_get::<_, String>(2).map_err(db)?,
                row.try_get::<_, bool>(3).map_err(db)?,
                row.try_get::<_, bool>(4).map_err(db)?,
                row.try_get::<_, bool>(5).map_err(db)?,
                definition,
                row.try_get::<_, String>(7).map_err(db)?,
                row.try_get::<_, String>(8).map_err(db)?,
                row.try_get::<_, String>(9).map_err(db)?,
                row.try_get::<_, String>(10).map_err(db)?,
                row.try_get::<_, String>(11).map_err(db)?,
                row.try_get::<_, String>(12).map_err(db)?
            ]));
    }
    let rows = session.client().query("SELECT c.relname::text,x.relname::text,left(pg_catalog.pg_get_indexdef(i.indexrelid),4097),i.indisunique,i.indisprimary,i.indisvalid,i.indisready,i.indimmediate,i.indislive,i.indnullsnotdistinct FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_class x ON x.oid=i.indexrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' ORDER BY c.relname,x.relname LIMIT 129", &[]).await.map_err(db)?;
    if rows.len() > 128 {
        return Err(Error::Budget);
    }
    for row in rows {
        let table: String = row.try_get(0).map_err(db)?;
        let definition: String = row.try_get(2).map_err(db)?;
        if definition.len() > 4096 {
            return Err(Error::Budget);
        }
        indexes.entry(table).or_default().push(serde_json::json!([
            row.try_get::<_, String>(1).map_err(db)?,
            definition,
            row.try_get::<_, bool>(3).map_err(db)?,
            row.try_get::<_, bool>(4).map_err(db)?,
            row.try_get::<_, bool>(5).map_err(db)?,
            row.try_get::<_, bool>(6).map_err(db)?,
            row.try_get::<_, bool>(7).map_err(db)?,
            row.try_get::<_, bool>(8).map_err(db)?,
            row.try_get::<_, bool>(9).map_err(db)?
        ]));
    }
    let mut total = 0usize;
    for table in tables {
        table.native_layout = serde_json::to_vec(&serde_json::json!({"format":"postgres-native-layout-v1","schema":"public","table":table.name,"relation":{"kind":"r","persistence":"p","row_security":false,"has_children":false,"is_partition":false},"columns":columns.remove(&table.name).ok_or(Error::Damaged)?,"constraints":constraints.remove(&table.name).unwrap_or_default(),"indexes":indexes.remove(&table.name).unwrap_or_default()})).map_err(|_|Error::Damaged)?;
        total = total
            .checked_add(table.native_layout.len())
            .ok_or(Error::Budget)?;
        if table.native_layout.len() > 1024 * 1024 || total > 4 * 1024 * 1024 {
            return Err(Error::Budget);
        }
    }
    if !columns.is_empty() || !constraints.is_empty() || !indexes.is_empty() {
        return Err(Error::Damaged);
    }
    Ok(())
}

async fn native_identity(session: &mut Session) -> Result<Vec<u8>, Error> {
    #[derive(serde::Serialize)]
    struct Identity {
        format: &'static str,
        system_identifier: String,
        database_oid: String,
        database_name: String,
    }
    let row = session.client().query_one("SELECT s.system_identifier::text,d.oid::text,d.datname::text FROM pg_catalog.pg_control_system() s CROSS JOIN pg_catalog.pg_database d WHERE d.datname=current_database()", &[]).await.map_err(db)?;
    let bytes = serde_json::to_vec(&Identity {
        format: "postgres-native-identity-v1",
        system_identifier: row.try_get(0).map_err(db)?,
        database_oid: row.try_get(1).map_err(db)?,
        database_name: row.try_get(2).map_err(db)?,
    })
    .map_err(|_| Error::Damaged)?;
    if bytes.len() > 1024 {
        return Err(Error::Budget);
    }
    Ok(bytes)
}
