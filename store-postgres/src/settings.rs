// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Connection admission shared by normal primitive serving and explicit source reading.
use crate::ConnectionSettings;
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_OCTETS};
use busbar_contract::abi::sdk::door::abi_str;

const NO_TEXT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The store's one need: the server, dialled over `tcp` at the DSN's `host:port`, in the
/// `operator-infrastructure` egress class.
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPERATOR_INFRASTRUCTURE,
    transport: abi_str("tcp"),
    auth: NO_TEXT,
    target_from: NO_TEXT,
    trust_from: NO_TEXT,
    details: Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_OCTETS,
        flags: 0,
    },
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

pub(crate) fn parse(settings: &[u8], secrets: &[&[u8]]) -> Result<ConnectionSettings, String> {
    use crate::credentials::PostgresUrl;
    use busbar_contract::abi::sdk::cred::{settings_lent, SettingsError};

    const BAD: &str = "invalid postgres plugin config";
    let settings = if settings.trim_ascii().is_empty() {
        &b"{}"[..]
    } else {
        settings
    };
    let parse_error = |e: SettingsError| {
        let path = if e.path().is_empty() {
            String::new()
        } else {
            format!("{}: ", e.path())
        };
        format!("{BAD}: {path}{e}")
    };

    let keys: Option<std::collections::HashMap<String, serde::de::IgnoredAny>> =
        settings_lent(settings, secrets).map_err(&parse_error)?;
    if let Some(k) = keys
        .as_ref()
        .and_then(|keys| keys.keys().find(|k| k.as_str() != "url"))
    {
        return Err(format!("{BAD}: unknown setting `{k}` (accepted: url)"));
    }
    let map: Option<std::collections::HashMap<String, Option<PostgresUrl>>> =
        settings_lent(settings, secrets).map_err(parse_error)?;
    let mut map = map.unwrap_or_default();
    let captured = map
        .remove("url")
        .flatten()
        .map(|url| url.0)
        .filter(|url| !url.public().trim().is_empty() || url.password().is_some())
        .ok_or_else(|| format!("{BAD}: `url` is required (a libpq connection string)"))?;
    ConnectionSettings::captured(captured).map_err(|e| format!("{BAD}: url: {}", e))
}
