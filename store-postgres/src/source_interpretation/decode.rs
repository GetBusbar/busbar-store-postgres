// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! postgres's historical native column/type/unit interpretation.
use busbar_contract::persistence::legacy_row::{Cell, Row};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, MeteringRow, ModelTokens, ScopeRef, SecretForm, UsageLedger,
    VirtualKey, RESERVED_UNITS,
};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Profile {
    Released6,
    Dev7,
    Dev8,
    Dev9,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Columns,
    Type,
    Range,
    Invalid,
    Unsupported,
}

/// Credential bytes remain borrowed from the reader's wiping custody. In
/// particular a revoked historical envelope is evidence, not a new live secret.
pub struct Credential<'a> {
    pub meta: CredentialMeta,
    pub envelope: Option<&'a [u8]>,
}

/// One admitted usage fragment with explicit request-counter semantics.
pub struct UsageCell {
    pub bucket: String,
    pub window: u64,
    pub model: String,
    pub sum_requests: bool,
    pub ledger: UsageLedger,
}

pub enum HistoricalRow<'a> {
    Key {
        key: VirtualKey,
        updated_at: Option<u64>,
    },
    Credential(Credential<'a>),
    Denied {
        subject: String,
        reason: String,
        created_at: u64,
    },
    Revision(u64),
    Schema(u64),
    /// Development candidates and old receipts cannot be submitted using a new
    /// execution identity. Preserve the original frame in a separate archive.
    Opaque {
        table: String,
        original: Row<'a>,
    },
    MeteringUnit {
        bucket: u64,
        key_id: String,
        provider: String,
        model: String,
        priced_from_ms: u64,
        key_group_at_use: Option<String>,
        pricing_version: Option<String>,
        unit: String,
        count: i128,
    },
    UsageUnit {
        bucket: String,
        window: u64,
        model: String,
        unit: String,
        count: i128,
    },
    Usage(UsageCell),
    Metering {
        bucket: u64,
        row: MeteringRow,
    },
    /// The original encoded physical row must also be retained as the immutable
    /// preimage. Parsing never recomputes its hash or signs a replacement event.
    Audit(AuditRecord),
}

const KEYS: &[&str] = &[
    "id",
    "name",
    "key_group",
    "allowed_pools",
    "labels",
    "enabled",
    "generation_hash",
    "created_at",
    "updated_at",
    "expires_at",
    "deleted_at",
    "revision",
];
const CREDENTIALS: &[&str] = &[
    "id",
    "key_id",
    "kind",
    "slot",
    "public_id",
    "secret",
    "secret_form",
    "created_at",
    "updated_at",
    "expires_at",
    "revoked_at",
    "revoke_reason",
    "revision",
];
const USAGE: &[&str] = &[
    "window_start",
    "bucket_id",
    "model",
    "requests",
    "billable_requests",
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];
const METERING: &[&str] = &[
    "bucket",
    "key_id",
    "provider",
    "model",
    "key_group_at_use",
    "pricing_version",
    "requests",
    "billable_requests",
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];
const AUDIT: &[&str] = &[
    "seq",
    "ts",
    "action",
    "resource",
    "outcome",
    "principal",
    "prev_hash",
    "hash",
];

struct Columns<'a, 'b> {
    unsigned: bool,
    decimal: bool,
    names: &'b [&'b str],
    values: Vec<Cell<'a>>,
}
impl<'a, 'b> Columns<'a, 'b> {
    fn new(
        unsigned: bool,
        names: &'b [&'b str],
        row: Row<'a>,
        expected: &[&str],
    ) -> Result<Self, Error> {
        if names.len() != expected.len()
            || row.cells().len() != names.len()
            || names
                .iter()
                .enumerate()
                .any(|(i, n)| !expected.contains(n) || names[..i].contains(n))
        {
            return Err(Error::Columns);
        }
        Ok(Self {
            unsigned,
            decimal: false,
            names,
            values: row.cells().collect(),
        })
    }
    fn cell(&self, name: &str) -> Cell<'a> {
        self.values[self
            .names
            .iter()
            .position(|n| *n == name)
            .expect("validated columns")]
    }
    fn bytes(&self, name: &str) -> Result<&'a [u8], Error> {
        match self.cell(name) {
            Cell::Text(v) | Cell::Blob(v) => Ok(v),
            _ => Err(Error::Type),
        }
    }
    fn text(&self, name: &str) -> Result<String, Error> {
        std::str::from_utf8(self.bytes(name)?)
            .map(str::to_owned)
            .map_err(|_| Error::Type)
    }
    fn optional_text(&self, name: &str) -> Result<Option<String>, Error> {
        if self.cell(name) == Cell::Null {
            Ok(None)
        } else {
            self.text(name).map(Some)
        }
    }
    fn uint(&self, name: &str) -> Result<u64, Error> {
        match self.cell(name) {
            Cell::Integer(v) if self.unsigned => Ok(u64::from_le_bytes(v.to_le_bytes())),
            Cell::Integer(v) => v.try_into().map_err(|_| Error::Range),
            Cell::Text(v) if self.decimal => std::str::from_utf8(v)
                .map_err(|_| Error::Type)?
                .parse()
                .map_err(|_| Error::Range),
            _ => Err(Error::Type),
        }
    }
    fn quantity(&self, name: &str) -> Result<i128, Error> {
        let value = match self.cell(name) {
            Cell::Text(v) if self.decimal => std::str::from_utf8(v)
                .map_err(|_| Error::Type)?
                .parse()
                .map_err(|_| Error::Range)?,
            Cell::Integer(_) => i128::from(self.uint(name)?),
            _ => return Err(Error::Type),
        };
        if value < 0 {
            return Err(Error::Range);
        }
        Ok(value)
    }
    fn revision(&self) -> Result<u64, Error> {
        match self.cell("revision") {
            Cell::Integer(v) => u64::try_from(v).map_err(|_| Error::Range),
            _ => Err(Error::Type),
        }
    }
    fn timestamp(&self, name: &str) -> Result<u64, Error> {
        match self.cell(name) {
            Cell::Integer(v) => Ok(u64::from_le_bytes(v.to_le_bytes())),
            _ => Err(Error::Type),
        }
    }
    fn optional_timestamp(&self, name: &str) -> Result<Option<u64>, Error> {
        if self.cell(name) == Cell::Null {
            Ok(None)
        } else {
            self.timestamp(name).map(Some)
        }
    }
    fn boolean(&self, name: &str) -> Result<bool, Error> {
        match self.uint(name)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Invalid),
        }
    }
    fn json<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<T, Error> {
        serde_json::from_slice(self.bytes(name)?).map_err(|_| Error::Invalid)
    }
    fn tokens(&self) -> Result<BTreeMap<String, i128>, Error> {
        let mut values = BTreeMap::new();
        for (column, unit) in [
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_write",
        ]
        .into_iter()
        .zip(RESERVED_UNITS)
        {
            values.insert(unit.to_owned(), self.quantity(column)?);
        }
        Ok(values)
    }
}

pub fn decode<'a>(
    profile: Profile,
    table: &str,
    columns: &[&str],
    row: Row<'a>,
) -> Result<HistoricalRow<'a>, Error> {
    let key_table = "keys";
    let dev = profile != Profile::Released6;
    let scale = if matches!(profile, Profile::Dev8 | Profile::Dev9) {
        6
    } else {
        0
    };
    if dev
        && matches!(
            table,
            "store_ops" | "store_records" | "plane_records" | "plane_tokens" | "plane_chain"
        )
    {
        let expected: &[&str] = match table {
            "store_ops" => &["op_id", "body", "answer", "recorded_at"],
            "store_records" => &["schema_id", "key", "value"],
            "plane_tokens" => &["kind", "token", "expires_at"],
            "plane_chain" => &[
                "kind",
                "parent",
                "seq",
                "id",
                "ts",
                "disposition",
                "body",
                "has_parent",
            ],
            _ => &["kind", "id", "parent", "seq", "ts", "disposition", "body"],
        };
        Columns::new(false, columns, row, expected)?;
        return Ok(HistoricalRow::Opaque {
            table: table.to_owned(),
            original: row,
        });
    }
    if dev && matches!(table, "usage_ledger_units" | "usage_metering_units") {
        return decode_units(scale, table, columns, row);
    }
    let mut expected = if table == key_table {
        KEYS
    } else {
        match table {
            "credentials" => CREDENTIALS,
            "usage_windows" => USAGE,
            "usage_metering" => METERING,
            "audit_log" => AUDIT,
            "denylist" => &["sub", "reason", "created_at"],
            "store_revision" => &["id", "revision"],
            "busbar_schema" => &["version"],
            "usage_ledger" => &[
                "bucket_id",
                "window_start",
                "model",
                "tokens_input",
                "tokens_output",
                "tokens_cache_read",
                "tokens_cache_write",
            ],
            _ => return Err(Error::Unsupported),
        }
    };
    let adjusted;
    if dev && table == key_table {
        adjusted = KEYS
            .iter()
            .copied()
            .filter(|name| *name != "updated_at")
            .chain([
                "allowed_scopes_by_kind",
                "idp_subject",
                "binding_mode",
                "minted_by",
                "idp_provider",
            ])
            .collect::<Vec<_>>();
        expected = &adjusted;
    } else if dev && table == "usage_metering" {
        adjusted = METERING
            .iter()
            .copied()
            .chain(["priced_from_ms"])
            .collect::<Vec<_>>();
        expected = &adjusted;
    } else if table == key_table {
        adjusted = KEYS
            .iter()
            .copied()
            .filter(|name| *name != "updated_at")
            .collect::<Vec<_>>();
        expected = &adjusted;
    } else if table == "store_revision" {
        expected = &["only_row", "revision"];
    } else if table == "usage_windows" {
        expected = &["bucket_id", "window_start", "requests", "billable_requests"];
    }
    let mut c = Columns::new(false, columns, row, expected)?;
    c.decimal = dev;
    if table == key_table {
        let group = c.optional_text("key_group")?;
        let pools: Option<Vec<String>> = if c.cell("allowed_pools") == Cell::Null {
            None
        } else {
            Some(c.json("allowed_pools")?)
        };
        let mut key = VirtualKey {
            id: c.text("id")?,
            generation_hash: c.text("generation_hash")?,
            name: c.text("name")?,
            allowed_scopes: pools.map(|v| v.into_iter().map(ScopeRef::pool).collect()),
            enabled: c.boolean("enabled")?,
            created_at: c.timestamp("created_at")?,
            group,
            labels: c.json("labels")?,
            expires_at: c.optional_timestamp("expires_at")?,
            deleted_at: c.optional_timestamp("deleted_at")?,
            revision: c.revision()?,
            idp_subject: None,
            binding_mode: None,
            minted_by: None,
            idp_provider: None,
        };
        if dev {
            key.idp_subject = c.optional_text("idp_subject")?;
            key.binding_mode = c.optional_text("binding_mode")?;
            key.minted_by = c.optional_text("minted_by")?;
            key.idp_provider = c.optional_text("idp_provider")?;
            let scope_column = "allowed_scopes_by_kind";
            if c.cell(scope_column) != Cell::Null {
                let ext: BTreeMap<String, Vec<String>> = c.json(scope_column)?;
                let scopes = key.allowed_scopes.get_or_insert_with(Vec::new);
                for (kind, values) in ext {
                    if kind == "pool" {
                        return Err(Error::Invalid);
                    }
                    for value in values {
                        if scopes.iter().any(|s| s.kind == kind && s.value == value) {
                            return Err(Error::Invalid);
                        }
                        scopes.push(ScopeRef {
                            kind: kind.clone(),
                            value,
                        });
                    }
                }
            }
        }
        if key.deleted_at.is_some() && key.enabled
            || key.expires_at.is_some_and(|v| v <= key.created_at)
        {
            return Err(Error::Invalid);
        }
        return Ok(HistoricalRow::Key {
            key,
            updated_at: None,
        });
    }
    Ok(match table {
        "credentials" => {
            let form = match c.bytes("secret_form")? {
                b"none" => SecretForm::None,
                b"recoverable" => SecretForm::Recoverable,
                b"digest" => SecretForm::Digest,
                _ => return Err(Error::Invalid),
            };
            let envelope = if c.cell("secret") == Cell::Null {
                None
            } else {
                Some(c.bytes("secret")?)
            };
            let meta = CredentialMeta {
                id: c.text("id")?,
                key_id: c.text("key_id")?,
                kind: c.text("kind")?,
                slot: c.uint("slot")?.try_into().map_err(|_| Error::Range)?,
                public_id: c.text("public_id")?,
                secret_form: form,
                created_at: c.timestamp("created_at")?,
                updated_at: c.timestamp("updated_at")?,
                expires_at: c.optional_timestamp("expires_at")?,
                revoked_at: c.optional_timestamp("revoked_at")?,
                revoke_reason: c.optional_text("revoke_reason")?,
                revision: c.revision()?,
            };
            if meta.slot > 1
                || (form == SecretForm::None && envelope.is_some())
                || (form != SecretForm::None
                    && envelope.is_none()
                    && !(dev && meta.revoked_at.is_some()))
                || meta.revoke_reason.is_some() && meta.revoked_at.is_none()
                || meta.expires_at.is_some_and(|v| v <= meta.created_at)
            {
                return Err(Error::Invalid);
            }
            HistoricalRow::Credential(Credential { meta, envelope })
        }
        "usage_windows" | "usage_ledger" => {
            let requests_only = table == "usage_windows";
            let tokens_only = table == "usage_ledger";
            let model = if requests_only {
                String::new()
            } else {
                c.text("model")?
            };
            let mut ledger = UsageLedger {
                requests: if tokens_only { 0 } else { c.uint("requests")? },
                billable_requests: if tokens_only {
                    0
                } else {
                    c.uint("billable_requests")?
                },
                models: vec![],
            };
            let tokens = if requests_only {
                BTreeMap::new()
            } else {
                c.tokens()?
            };
            if model.is_empty() {
                if tokens.values().any(|v| *v != 0) {
                    return Err(Error::Invalid);
                }
            } else {
                if ledger.requests != 0 || ledger.billable_requests != 0 {
                    return Err(Error::Invalid);
                }
                ledger.models.push(ModelTokens {
                    scale,
                    model: model.clone(),
                    usage_units: tokens,
                });
            }
            ledger.normalize_scale6().map_err(|_| Error::Range)?;
            HistoricalRow::Usage(UsageCell {
                sum_requests: false,
                bucket: c.text("bucket_id")?,
                window: c.timestamp("window_start")?,
                model,
                ledger,
            })
        }
        "usage_metering" => {
            let bucket = c.uint("bucket")?;
            let mut row = MeteringRow {
                scale,
                key_id: c.text("key_id")?,
                model: c.text("model")?,
                provider: c.text("provider")?,
                tokens_input: c.quantity("tokens_input")?,
                tokens_output: c.quantity("tokens_output")?,
                tokens_cache_read: c.quantity("tokens_cache_read")?,
                tokens_cache_write: c.quantity("tokens_cache_write")?,
                requests: c.uint("requests")?,
                billable_requests: c.uint("billable_requests")?,
                key_group_at_use: c.text("key_group_at_use")?,
                pricing_version: c.text("pricing_version")?,
                priced_from_ms: if dev {
                    c.timestamp("priced_from_ms")?
                } else {
                    0
                },
                usage_units: BTreeMap::new(),
            };
            row.normalize_scale6().map_err(|_| Error::Range)?;
            HistoricalRow::Metering { bucket, row }
        }
        "denylist" => HistoricalRow::Denied {
            subject: c.text("sub")?,
            reason: c.text("reason")?,
            created_at: c.timestamp("created_at")?,
        },
        "store_revision" => {
            let valid = c.boolean("only_row")?;
            if !valid {
                return Err(Error::Invalid);
            }
            HistoricalRow::Revision(c.revision()?)
        }
        "busbar_schema" => {
            let version = c.uint("version")?;
            if !(6..=9).contains(&version) {
                return Err(Error::Unsupported);
            }
            HistoricalRow::Schema(version)
        }
        "audit_log" => HistoricalRow::Audit(AuditRecord {
            seq: c.uint("seq")?,
            ts: c.timestamp("ts")?,
            action: c.text("action")?,
            resource: c.text("resource")?,
            outcome: c.text("outcome")?,
            principal: c.text("principal")?,
            prev_hash: c.text("prev_hash")?,
            hash: c.text("hash")?,
        }),
        _ => return Err(Error::Unsupported),
    })
}

fn decode_units<'a>(
    scale: u32,
    table: &str,
    columns: &[&str],
    row: Row<'a>,
) -> Result<HistoricalRow<'a>, Error> {
    let meter = table == "usage_metering_units";
    let attributed = columns.contains(&"key_group_at_use") || columns.contains(&"pricing_version");
    if attributed && !meter {
        return Err(Error::Columns);
    }
    if !meter && table != "usage_ledger_units" {
        return Err(Error::Unsupported);
    }
    let mut expected = if meter {
        vec![
            "bucket",
            "key_id",
            "provider",
            "model",
            "priced_from_ms",
            "unit",
            "count",
        ]
    } else {
        vec!["window_start", "bucket_id", "model", "unit", "count"]
    };
    if attributed {
        expected.extend(["key_group_at_use", "pricing_version"]);
    }
    let mut c = Columns::new(false, columns, row, &expected)?;
    c.decimal = true;
    let count = busbar_contract::count::Count::from_stored(c.quantity("count")?, scale)
        .map_err(|_| Error::Range)?
        .micros();
    if meter {
        let bucket = c.uint("bucket")?;
        Ok(HistoricalRow::MeteringUnit {
            bucket,
            key_id: c.text("key_id")?,
            provider: c.text("provider")?,
            model: c.text("model")?,
            priced_from_ms: c.timestamp("priced_from_ms")?,
            key_group_at_use: if attributed {
                Some(c.text("key_group_at_use")?)
            } else {
                None
            },
            pricing_version: if attributed {
                Some(c.text("pricing_version")?)
            } else {
                None
            },
            unit: c.text("unit")?,
            count,
        })
    } else {
        Ok(HistoricalRow::UsageUnit {
            bucket: c.text("bucket_id")?,
            window: c.timestamp("window_start")?,
            model: c.text("model")?,
            unit: c.text("unit")?,
            count,
        })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
