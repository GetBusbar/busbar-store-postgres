// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owning native source reader declaration and historical interpretation.
pub(crate) const SOURCE_OWNER: [u8; 16] = *b"legacy.postgr.v1";
use busbar_contract::persistence::{
    archive,
    lifecycle::{DocumentSemantics, Error, SourceCodec, SourceReader},
};

pub(crate) fn descriptor(physical: u32) -> Result<SourceReader, Error> {
    let documents = match physical {
        6 => DocumentSemantics::Historical,
        7..=9 => DocumentSemantics::Current,
        _ => return Err(Error::UnsupportedFormat),
    };
    SourceReader::new(SourceCodec::HistoricalV1, documents, {
        let mut hash = archive::Hasher::new();
        hash.update(include_bytes!("source_interpretation.rs"));
        hash.update(include_bytes!("source_interpretation/decode.rs"));
        hash.update(include_bytes!("v4/lifecycle.rs"));
        hash.update(include_bytes!("v4/lifecycle/control.rs"));
        hash.update(include_bytes!("v4/lifecycle/guards.rs"));
        hash.update(include_bytes!("v4/lifecycle/origin.rs"));
        hash.update(include_bytes!("../../Cargo.lock"));
        hash.finish()
    })
}

mod decode;
use busbar_contract::{
    persistence::{
        archive::Table,
        legacy_row::{Cell, Row},
        lifecycle::{
            source::{
                AccountingRole, HistoricalFact, RequestAggregation, SourceChunk, SourceEvidence,
            },
            SourceRow,
        },
    },
    redacted::OwnerSeal,
    Secret,
};
use decode::{HistoricalRow, Profile};

fn corrupt(error: decode::Error) -> Error {
    match error {
        decode::Error::Range => Error::Bounds,
        decode::Error::Unsupported => Error::UnsupportedFormat,
        _ => Error::Corrupt,
    }
}
fn profile(physical: u32) -> Result<Profile, Error> {
    match physical {
        6 => Ok(Profile::Released6),
        7 => Ok(Profile::Dev7),
        8 => Ok(Profile::Dev8),
        9 => Ok(Profile::Dev9),
        _ => Err(Error::UnsupportedFormat),
    }
}

pub(crate) fn interpret<O: OwnerSeal>(
    physical: u32,
    table: &Table,
    original: &SourceRow<O>,
    semantic_bytes: usize,
    owner: &O,
) -> Result<SourceChunk<O>, Error> {
    let bytes = original.value.expose_own(owner);
    if bytes
        .len()
        .checked_mul(64)
        .and_then(|n| n.checked_add(1024))
        .is_none_or(|n| n > semantic_bytes)
    {
        return Err(Error::Bounds);
    }
    let profile = profile(physical)?;
    let role = AccountingRole::Fragment;
    let columns = table.columns.iter().map(String::as_str).collect::<Vec<_>>();
    let row = Row::decode(bytes).map_err(|_| Error::Corrupt)?;
    let decoded = decode::decode(profile, &table.name, &columns, row).map_err(corrupt)?;
    let fact = match decoded {
        HistoricalRow::Key { key, updated_at } => HistoricalFact::Key {
            value: key,
            updated_at,
        },
        HistoricalRow::Credential(value) => HistoricalFact::Credential {
            meta: value.meta,
            envelope: Secret::held(value.envelope.unwrap_or_default().to_vec()),
        },
        HistoricalRow::Denied {
            subject,
            reason,
            created_at,
        } => HistoricalFact::Denial {
            subject,
            reason,
            created_at,
        },
        HistoricalRow::Revision(value) => HistoricalFact::Revision(value),
        HistoricalRow::Usage(value) => HistoricalFact::Usage {
            bucket: value.bucket,
            window: value.window,
            model: value.model,
            requests: if value.sum_requests {
                RequestAggregation::Sum
            } else {
                RequestAggregation::Dedicated
            },
            ledger: value.ledger,
            role,
        },
        HistoricalRow::Metering { bucket, row } => HistoricalFact::Metering { bucket, row, role },
        HistoricalRow::UsageUnit {
            bucket,
            window,
            model,
            unit,
            count,
        } => HistoricalFact::UsageUnit {
            bucket,
            window,
            model,
            unit,
            count,
            role,
        },
        HistoricalRow::MeteringUnit {
            bucket,
            key_id,
            provider,
            model,
            priced_from_ms,
            key_group_at_use,
            pricing_version,
            unit,
            count,
        } => HistoricalFact::MeteringUnit {
            bucket,
            key_id,
            provider,
            model,
            priced_from_ms,
            key_group_at_use,
            pricing_version,
            unit,
            count,
            role,
        },
        HistoricalRow::Audit(value) => HistoricalFact::Audit(value),
        HistoricalRow::Opaque { table, original } => archival(&table, &columns, original)?,
        HistoricalRow::Schema(version) => {
            let _ = version;
            HistoricalFact::EvidenceOnly
        }
    };
    let mut group = archive::Hasher::new();
    group.update(b"postgres.interpreted-row/1\0");
    group.update(&original.table.to_le_bytes());
    group.update(original.native_key.expose_own(owner));
    Ok(SourceChunk {
        reader: descriptor(physical)?,
        family: fact.family(),
        group: Secret::held(group.finish().to_vec()),
        sequence: 0,
        complete: true,
        evidence: vec![SourceEvidence {
            table: original.table,
            native_key: original.native_key.clone(),
            value_digest: archive::digest(bytes),
        }],
        facts: vec![fact],
    })
}
fn archival<O: OwnerSeal>(
    table: &str,
    columns: &[&str],
    row: Row<'_>,
) -> Result<HistoricalFact<O>, Error> {
    let values = row.cells().collect::<Vec<_>>();
    let cell = |name: &str| -> Result<Cell<'_>, Error> {
        columns
            .iter()
            .position(|found| *found == name)
            .and_then(|at| values.get(at))
            .copied()
            .ok_or(Error::Corrupt)
    };
    let bytes = |name| -> Result<&[u8], Error> {
        match cell(name)? {
            Cell::Text(v) | Cell::Blob(v) => Ok(v),
            _ => Err(Error::Corrupt),
        }
    };
    let text = |name| -> Result<&str, Error> {
        std::str::from_utf8(bytes(name)?).map_err(|_| Error::Corrupt)
    };
    let optional = |name| -> Result<Option<String>, Error> {
        if cell(name)? == Cell::Null {
            Ok(None)
        } else {
            text(name).map(|v| Some(v.to_owned()))
        }
    };
    let timestamp = |name| -> Result<u64, Error> {
        match cell(name)? {
            Cell::Integer(v) => Ok(u64::from_le_bytes(v.to_le_bytes())),
            _ => Err(Error::Corrupt),
        }
    };
    Ok(match table {
        "store_records" => HistoricalFact::Record {
            schema: text("schema_id")?.to_owned(),
            key: Secret::held(bytes("key")?.to_vec()),
            value: Secret::held(bytes("value")?.to_vec()),
        },
        "plane_tokens" => {
            text("token")?;
            HistoricalFact::Token {
                kind: text("kind")?.to_owned(),
                token: Secret::held(bytes("token")?.to_vec()),
                expires_at: timestamp("expires_at")?,
            }
        }
        "store_ops" => {
            let operation = bytes("op_id")?.try_into().map_err(|_| Error::Corrupt)?;
            let body = bytes("body")?;
            let answer = bytes("answer")?;
            let historical_digest = if body.len() == 64
                && body
                    .iter()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(v))
            {
                let nibble = |v| if v <= b'9' { v - b'0' } else { v - b'a' + 10 };
                let mut digest = [0; 32];
                for (slot, pair) in digest.iter_mut().zip(body.as_chunks::<2>().0) {
                    *slot = nibble(pair[0]) * 16 + nibble(pair[1]);
                }
                Some(digest)
            } else {
                None
            };
            HistoricalFact::Receipt {
                operation,
                body: Secret::held(body.to_vec()),
                answer: Secret::held(answer.to_vec()),
                recorded_at: Some(timestamp("recorded_at")?),
                expires_at_ms: None,
                historical_digest,
                completed_shape: historical_digest.is_some() && answer.is_empty(),
            }
        }
        "plane_records" | "plane_chain" => {
            let id = text("id")?;
            let mut parent = optional("parent")?;
            let sequence = match cell("seq")? {
                Cell::Integer(value) => u64::try_from(value).map_err(|_| Error::Corrupt)?,
                _ => return Err(Error::Corrupt),
            };
            let append = Some(table == "plane_chain");
            if append == Some(true) {
                match cell("has_parent")? {
                    Cell::Integer(1) if parent.is_some() => {}
                    Cell::Integer(0) if parent.as_deref() == Some("") => parent = None,
                    _ => return Err(Error::Corrupt),
                }
            }
            if append == Some(false) && sequence != 0 {
                return Err(Error::Corrupt);
            }
            let disposition = match text("disposition")? {
                "active" => busbar_contract::records::PlaneDisposition::Active,
                "terminal" => busbar_contract::records::PlaneDisposition::Terminal,
                _ => return Err(Error::Corrupt),
            };
            HistoricalFact::History {
                kind: text("kind")?.to_owned(),
                id: id.to_owned(),
                parent,
                sequence,
                timestamp: timestamp("ts")?,
                disposition,
                body: Secret::held(bytes("body")?.to_vec()),
                append,
            }
        }
        _ => return Err(Error::UnsupportedFormat),
    })
}

/// Empty tables still participate in physical format admission.
pub(crate) fn validate_catalogue(physical: u32, tables: &[archive::Table]) -> Result<(), Error> {
    let expected: &[&str] = match physical {
        6 => &[
            "audit_log",
            "busbar_schema",
            "credentials",
            "denylist",
            "keys",
            "store_revision",
            "usage_ledger",
            "usage_metering",
            "usage_windows",
        ],
        7..=9 => &[
            "audit_log",
            "busbar_schema",
            "credentials",
            "denylist",
            "keys",
            "plane_chain",
            "plane_records",
            "plane_tokens",
            "store_ops",
            "store_records",
            "store_revision",
            "usage_ledger",
            "usage_ledger_units",
            "usage_metering",
            "usage_metering_units",
            "usage_windows",
        ],
        _ => return Err(Error::UnsupportedFormat),
    };
    if tables.len() != expected.len()
        || expected
            .iter()
            .any(|name| !tables.iter().any(|table| table.name == *name))
    {
        return Err(Error::UnsupportedFormat);
    }
    for (index, table) in tables.iter().enumerate() {
        if tables[..index].iter().any(|old| old.name == table.name)
            || table.columns.is_empty()
            || table.columns.len() > 64
            || table
                .columns
                .iter()
                .enumerate()
                .any(|(at, column)| table.columns[..at].contains(column))
        {
            return Err(Error::Corrupt);
        }
    }
    Ok(())
}

#[cfg(test)]
mod catalogue_tests {
    use super::*;
    #[test]
    fn empty_unknown_or_missing_native_tables_cannot_bypass_format_admission() {
        let data: serde_json::Value = serde_json::from_slice(include_bytes!(
            "source_interpretation/fixtures/postgres-1.5.5-rows.json"
        ))
        .unwrap();
        let mut tables = data
            .as_object()
            .unwrap()
            .keys()
            .map(|name| archive::Table {
                name: name.clone(),
                columns: vec!["native-column".into()],
                native_layout: vec![],
            })
            .collect::<Vec<_>>();
        validate_catalogue(6, &tables).unwrap();
        tables.push(archive::Table {
            name: "unknown-empty-table".into(),
            columns: vec!["native-column".into()],
            native_layout: vec![],
        });
        assert!(validate_catalogue(6, &tables).is_err());
        tables.pop();
        tables.pop();
        assert!(validate_catalogue(6, &tables).is_err());
    }
}

#[cfg(test)]
mod receipt_tests {
    use super::*;
    use busbar_contract::persistence::{archive, legacy_row, lifecycle::SourceRow};
    busbar_contract::own_seal!(Owner);
    #[test]
    fn historical_receipt_preserves_original_bytes_and_digest_domain() {
        let operation = [7u8; 16];
        let body = [b'a'; 64];
        let value = legacy_row::encode::<Owner>(
            &[
                Cell::Blob(&operation),
                Cell::Text(&body),
                Cell::Text(b""),
                Cell::Integer(12),
            ],
            4096,
        )
        .unwrap();
        let expected = archive::digest(value.expose_own(&Owner::here()));
        let table = archive::Table {
            name: "store_ops".into(),
            columns: ["op_id", "body", "answer", "recorded_at"]
                .map(str::to_owned)
                .to_vec(),
            native_layout: vec![1],
        };
        let row = SourceRow {
            table: 0,
            native_key: Secret::held(operation.to_vec()),
            value,
        };
        let chunk = interpret(9, &table, &row, 65536, &Owner::here()).unwrap();
        assert_eq!(chunk.evidence[0].value_digest, expected);
        assert_eq!(chunk.evidence[0].native_key, row.native_key);
        let HistoricalFact::Receipt {
            operation: found,
            body: original,
            answer,
            recorded_at,
            historical_digest,
            completed_shape,
            ..
        } = &chunk.facts[0]
        else {
            panic!()
        };
        assert_eq!(*found, operation);
        assert_eq!(original.expose_own(&Owner::here()), &body);
        assert!(answer.expose_own(&Owner::here()).is_empty());
        assert_eq!(*recorded_at, Some(12));
        assert!(*completed_shape);
        assert_eq!(*historical_digest, Some([0xaa; 32]));
    }
}
