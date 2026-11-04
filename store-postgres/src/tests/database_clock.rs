// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::{IntoStoreResult, RecordStoreError, RecordStoreResult, Transaction};
#[path = "../database_clock.rs"]
mod real;
pub(crate) async fn now(tx: &mut Transaction<'_>) -> RecordStoreResult<u64> {
    const TEST_CLOCK_SETTING: &str = "busbar.test_database_clock";
    let fixture: Option<String> = tx
        .query_one("SELECT current_setting($1,true)", &[&TEST_CLOCK_SETTING])
        .await
        .store()?
        .try_get(0)
        .store()?;
    if let Some(fixture) = fixture {
        let now = fixture
            .parse::<i64>()
            .map_err(|_| RecordStoreError("invalid database clock fixture".into()))?;
        return u64::try_from(now)
            .map_err(|_| RecordStoreError("database clock precedes Unix epoch".into()));
    }
    real::now(tx).await
}
