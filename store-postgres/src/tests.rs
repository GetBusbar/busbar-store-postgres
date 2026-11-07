// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Shared connector and configuration assertions; primitive invariants live in v4/native_tests.
use super::*;

#[path = "../tests-support/postgres_clock.rs"]
pub(crate) mod postgres_clock;
#[path = "../tests-support/postgres_io.rs"]
pub(crate) mod postgres_io;

/// Constructors capture passwords once, and the only remaining error-redaction path uses Cred.
#[test]
fn captured_dsn_passwords_redact_peer_errors_without_plaintext_custody() {
    for (dsn, expected) in [
        ("postgres://user:s3cr3t@host:5432/db", "s3cr3t"),
        ("postgresql://u:p%40ss@host/db", "p@ss"),
        ("host=db user=u password=kwsecret dbname=x", "kwsecret"),
        ("host = db user = u password = spaced dbname = x", "spaced"),
        ("host=db password='quoted secret' user=u", "quoted secret"),
        ("postgres://user@host:5432/db?password=inquery", "inquery"),
        (
            "postgres://user@host:5432/db?connect_timeout=10&password=after",
            "after",
        ),
        ("postgres://u:secret@host/db?options=label@other", "secret"),
        (
            r"host=db user=u password='quote\' and\\slash'",
            "quote' and\\slash",
        ),
        (r"host=db user=u password=escaped\ space", "escaped space"),
        ("host=db user=u password='two  spaces'", "two  spaces"),
        (
            "host=db user=u password='before?password=after'",
            "before?password=after",
        ),
        (
            "host=db user=u password='before://u:wrong@host'",
            "before://u:wrong@host",
        ),
    ] {
        let store = ConnectionSettings::new(dsn).unwrap();
        assert_eq!(
            store.shared.config.redact(format!("auth: {expected}")),
            "auth: <redacted>"
        );
        assert!(!format!("{:?}", store.shared.config).contains(expected));
    }
    for dsn in ["postgres://host:5432/db?user=u", "host=db user=u"] {
        let store = ConnectionSettings::new(dsn).unwrap();
        assert_eq!(store.shared.config.redact("plain".into()), "plain");
    }
    for dsn in [
        "host=db user=u password='unterminated",
        "host=db sslpassword=hidden user=u",
        "postgres://u:hidden@host/db?invalid=hidden",
    ] {
        let error = ConnectionSettings::new(dsn).err().expect("invalid DSN");
        assert!(!error.contains("hidden") && !error.contains("password='unterminated"));
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
