// SPDX-License-Identifier: Apache-2.0
//! Physical column catalogues extracted from the published fixture and pinned dev DDL.
// Released fixture MANIFEST.tsv: PostgreSQL plugin v1.0.6, schema 6.
pub(super) const RELEASED: &str = r#"audit_log|seq:bigint:1:-,ts:bigint:1:-,action:text:1:default,resource:text:1:default,outcome:text:1:default,principal:text:1:default,prev_hash:text:1:default,hash:text:1:default
busbar_schema|version:bigint:1:-
credentials|id:text:1:default,key_id:text:1:default,kind:text:1:default,slot:smallint:1:-,public_id:text:1:default,secret:text:0:default,secret_form:text:1:default,created_at:bigint:1:-,updated_at:bigint:1:-,expires_at:bigint:0:-,revoked_at:bigint:0:-,revoke_reason:text:0:default,revision:bigint:1:-
denylist|sub:text:1:default,reason:text:1:default,created_at:bigint:1:-
keys|id:text:1:default,generation_hash:text:1:default,name:text:1:default,allowed_pools:text:0:default,enabled:boolean:1:-,created_at:bigint:1:-,key_group:text:0:default,labels:text:1:default,expires_at:bigint:0:-,deleted_at:bigint:0:-,revision:bigint:1:-
store_revision|only_row:boolean:1:-,revision:bigint:1:-
usage_ledger|bucket_id:text:1:default,window_start:bigint:1:-,model:text:1:default,tokens_input:bigint:1:-,tokens_output:bigint:1:-,tokens_cache_read:bigint:1:-,tokens_cache_write:bigint:1:-
usage_metering|key_id:text:1:default,bucket:bigint:1:-,model:text:1:default,provider:text:1:default,tokens_input:bigint:1:-,tokens_output:bigint:1:-,tokens_cache_read:bigint:1:-,tokens_cache_write:bigint:1:-,requests:bigint:1:-,billable_requests:bigint:1:-,key_group_at_use:text:1:default,pricing_version:text:1:default
usage_windows|bucket_id:text:1:default,window_start:bigint:1:-,requests:bigint:1:-,billable_requests:bigint:1:-"#;
// Schema 7/8 fresh DDL: 0283f54^ and 0283f54, before 988248a widened schema 9.
pub(super) const DEV: &str = r#"audit_log|seq:bigint:1:-,ts:bigint:1:-,action:text:1:default,resource:text:1:default,outcome:text:1:default,principal:text:1:default,prev_hash:text:1:default,hash:text:1:default
busbar_schema|version:bigint:1:-
credentials|id:text:1:default,key_id:text:1:default,kind:text:1:default,slot:smallint:1:-,public_id:text:1:default,secret:text:0:default,secret_form:text:1:default,created_at:bigint:1:-,updated_at:bigint:1:-,expires_at:bigint:0:-,revoked_at:bigint:0:-,revoke_reason:text:0:default,revision:bigint:1:-
denylist|sub:text:1:default,reason:text:1:default,created_at:bigint:1:-
keys|id:text:1:default,generation_hash:text:1:default,name:text:1:default,allowed_pools:text:0:default,enabled:boolean:1:-,created_at:bigint:1:-,key_group:text:0:default,labels:text:1:default,expires_at:bigint:0:-,deleted_at:bigint:0:-,revision:bigint:1:-,idp_subject:text:0:default,binding_mode:text:0:default,minted_by:text:0:default,idp_provider:text:0:default,allowed_scopes_by_kind:text:0:default
plane_chain|kind:text:1:C,parent:text:1:C,seq:bigint:1:-,id:text:1:C,ts:bigint:1:-,disposition:text:1:default,body:bytea:1:-,has_parent:boolean:1:-
plane_records|kind:text:1:C,id:text:1:C,parent:text:0:C,seq:bigint:1:-,ts:bigint:1:-,disposition:text:1:default,body:bytea:1:-
plane_tokens|kind:text:1:C,token:text:1:C,expires_at:bigint:1:-
store_ops|op_id:bytea:1:-,body:text:1:default,answer:text:1:default,recorded_at:bigint:1:-
store_records|schema_id:text:1:C,key:bytea:1:-,value:bytea:1:-
store_revision|only_row:boolean:1:-,revision:bigint:1:-
usage_ledger|bucket_id:text:1:default,window_start:bigint:1:-,model:text:1:default,tokens_input:bigint:1:-,tokens_output:bigint:1:-,tokens_cache_read:bigint:1:-,tokens_cache_write:bigint:1:-
usage_ledger_units|bucket_id:text:1:default,window_start:bigint:1:-,model:text:1:default,unit:text:1:C,count:bigint:1:-
usage_metering|key_id:text:1:default,bucket:bigint:1:-,model:text:1:default,provider:text:1:default,tokens_input:bigint:1:-,tokens_output:bigint:1:-,tokens_cache_read:bigint:1:-,tokens_cache_write:bigint:1:-,requests:bigint:1:-,billable_requests:bigint:1:-,key_group_at_use:text:1:default,pricing_version:text:1:default,priced_from_ms:bigint:1:-
usage_metering_units|key_id:text:1:default,bucket:bigint:1:-,model:text:1:default,provider:text:1:default,priced_from_ms:bigint:1:-,unit:text:1:C,count:bigint:1:-
usage_windows|bucket_id:text:1:default,window_start:bigint:1:-,requests:bigint:1:-,billable_requests:bigint:1:-"#;
