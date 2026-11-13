// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Shared connector and configuration assertions; primitive invariants live in v4/native_tests.
use super::*;

#[path = "../tests-support/postgres_clock.rs"]
pub(crate) mod postgres_clock;
#[path = "../tests-support/postgres_io.rs"]
pub(crate) mod postgres_io;

/// A clearly synthetic password generated at test time, so no credential-shaped literal sits in
/// source: `test-only-<tag>-<random hex>`.
fn test_secret(tag: &str) -> String {
    use std::hash::BuildHasher;
    let hex = std::collections::hash_map::RandomState::new().hash_one(tag);
    format!("test-only-{tag}-{hex:016x}")
}

/// Constructors capture passwords once, and the only remaining error-redaction path uses Cred.
#[test]
fn captured_dsn_passwords_redact_peer_errors_without_plaintext_custody() {
    let s = test_secret("dsn");
    for (dsn, expected) in [
        (format!("postgres://user:{s}@host:5432/db"), s.clone()),
        (
            format!("postgresql://u:{s}%40ss@host/db"),
            format!("{s}@ss"),
        ),
        (format!("host=db user=u password={s} dbname=x"), s.clone()),
        (
            format!("host = db user = u password = {s} dbname = x"),
            s.clone(),
        ),
        (
            format!("host=db password='{s} quoted' user=u"),
            format!("{s} quoted"),
        ),
        (
            format!("postgres://user@host:5432/db?password={s}"),
            s.clone(),
        ),
        (
            format!("postgres://user@host:5432/db?connect_timeout=10&password={s}"),
            s.clone(),
        ),
        (
            format!("postgres://u:{s}@host/db?options=label@other"),
            s.clone(),
        ),
        (
            format!(r"host=db user=u password='{s}\' and\\slash'"),
            format!("{s}' and\\slash"),
        ),
        (
            format!(r"host=db user=u password={s}\ space"),
            format!("{s} space"),
        ),
        (
            format!("host=db user=u password='{s}  spaces'"),
            format!("{s}  spaces"),
        ),
        (
            format!("host=db user=u password='{s}?password=after'"),
            format!("{s}?password=after"),
        ),
        (
            format!("host=db user=u password='{s}://u:x@host'"),
            format!("{s}://u:x@host"),
        ),
    ] {
        let store = ConnectionSettings::new(&dsn).unwrap();
        assert_eq!(
            store.shared.config.redact(format!("auth: {expected}")),
            "auth: <redacted>"
        );
        assert!(!format!("{:?}", store.shared.config).contains(&expected));
    }
    for dsn in ["postgres://host:5432/db?user=u", "host=db user=u"] {
        let store = ConnectionSettings::new(dsn).unwrap();
        assert_eq!(store.shared.config.redact("plain".into()), "plain");
    }
    let hidden = test_secret("hidden");
    for dsn in [
        format!("host=db user=u password='{hidden}"),
        format!("host=db sslpassword={hidden} user=u"),
        format!("postgres://u:{hidden}@host/db?invalid={hidden}"),
    ] {
        let error = ConnectionSettings::new(&dsn).err().expect("invalid DSN");
        assert!(!error.contains(&hidden) && !error.contains(&format!("password='{hidden}")));
    }
}

#[test]
fn server_diagnostics_escape_controls_and_bound_output() {
    let error = pgwire::Error::server("22000", &format!("bad\n\u{1b}{}", "x".repeat(5000)));
    let rendered = render_pg_error(&error);
    assert!(rendered.starts_with("22000:"));
    assert!(!rendered.chars().any(char::is_control));
    assert!(rendered.ends_with("[truncated]"));
    assert!(rendered.len() < 4200);
}
