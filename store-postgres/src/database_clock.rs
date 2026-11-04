// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::{IntoStoreResult, RecordStoreError, RecordStoreResult, Transaction};

pub(crate) async fn now(tx: &mut Transaction<'_>) -> RecordStoreResult<u64> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp()))::bigint",
            &[],
        )
        .await
        .store()?
        .try_get(0)
        .store()?;
    u64::try_from(now).map_err(|_| RecordStoreError("database clock precedes Unix epoch".into()))
}
