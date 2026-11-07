// SPDX-License-Identifier: Apache-2.0
//! Host clock for the Postgres transaction deadline and cancellation tests.
//! The other host services are deliberately unavailable to this store.
use busbar_contract::services::*;
pub struct PostgresClock;
#[allow(unused_variables)]
impl HostServices for PostgresClock {
    fn now(&self) -> Reading {
        Reading {
            wall_ns: 0,
            mono_ns: busbar_plugin_loader::dispatch::now_ns(),
        }
    }
    fn snapshot_read(&self, _caller: &Caller, _scope: u32, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_unreached(&self, caller: &Caller, counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight_item(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: &str,
        digest: &str,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_decide(
        &self,
        caller: &Caller,
        key: TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_state(&self, caller: &Caller, counterparty: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_serves(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_due(&self, caller: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_verify(
        &self,
        caller: &Caller,
        counterparty: &str,
        payload: &[u8],
        signatures: &[u8],
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn entitlement_check(&self, caller: &Caller, unit: Option<u64>, target: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn session_emit(&self, caller: &Caller, session: u64, bytes: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn ticket_mint(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        ttl_secs: u64,
        record: &[u8],
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn ticket_take(&self, caller: &Caller, unit: Option<u64>) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn random_fill(&self, len: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn records_secret(&self, kind: &str, id: &str, later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_settle(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        handle: u64,
        record: &[u8],
        later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_lookup(&self, caller: &Caller, key: &[u8], later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn content_scan(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        content: &[u8],
        later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn hook_call(&self, caller: &Caller, unit: Option<u64>, ask: HookAsk, later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
}
