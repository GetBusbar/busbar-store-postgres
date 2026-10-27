// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `pgwire.rs`.

use super::{begin_sql, Config, IsolationLevel, SslMode};

#[test]
fn a_url_parses_into_its_parts() {
    let c = Config::parse(
        "postgres://u%40x:p%3Ass@db.internal:6543/busbar?sslmode=require&application_name=bb",
    )
    .unwrap();
    assert_eq!(c.user, "u@x");
    assert_eq!(c.password.as_deref(), Some("p:ss"));
    assert_eq!(c.targets()[0].1, "db.internal:6543");
    assert_eq!(c.dbname.as_deref(), Some("busbar"));
    assert_eq!(c.ssl, SslMode::Require);
    assert_eq!(c.application_name.as_deref(), Some("bb"));
    let c = Config::parse("postgresql://u@[::1]/d").unwrap();
    assert_eq!(c.targets()[0].1, "[::1]:5432");
    assert_eq!(c.password, None);
}

#[test]
fn the_keyword_form_parses_with_spaces_and_quotes() {
    let c = Config::parse("host = db port=5433 user=u password='se cret' dbname=x sslmode=require")
        .unwrap();
    assert_eq!(c.targets()[0].1, "db:5433");
    assert_eq!(c.password.as_deref(), Some("se cret"));
    assert_eq!(c.ssl, SslMode::Require);
}

#[test]
fn what_the_host_cannot_dial_is_refused() {
    assert!(Config::parse("host=/var/run/postgresql user=u").is_err());
    assert!(Config::parse("host=db").is_err(), "no user");
    assert!(Config::parse("host=db user=u bogus=1").is_err());
    assert!(Config::parse("host=db user=u sslmode=sometimes").is_err());
    assert!(Config::parse("host=a,b port=1,2,3 user=u").is_err());
}

/// libpq's MULTI-HOST list (busbar oracle store.boot|postgres|multi-host): every endpoint, in
/// order, each with its own port or the one shared; a connect the first refuses tries the next.
/// RED before: "multiple hosts are not supported".
#[test]
fn a_multi_host_list_names_every_endpoint_in_order() {
    let c = Config::parse("postgres://u:p@127.0.0.1:1,db:5433,[::1]/d").unwrap();
    let t: Vec<String> = c.targets().into_iter().map(|(_, t)| t).collect();
    assert_eq!(t, ["127.0.0.1:1", "db:5433", "[::1]:5432"]);
    let c = Config::parse("host=a,b port=6000 user=u").unwrap();
    let t: Vec<String> = c.targets().into_iter().map(|(_, t)| t).collect();
    assert_eq!(t, ["a:6000", "b:6000"]);
    let c = Config::parse("host=a,b port=1,2 user=u").unwrap();
    assert_eq!(c.targets()[1], ("b", "b:2".to_string()));
}

/// D11 (RED before: `host` and `hostaddr` shared one slot, the last won): `hostaddr` is the
/// address that is dialled and `host` the name the TLS check and the errors use (libpq, and the
/// 1.5.5 driver), paired by position; a hostaddr that is no IP, or a list of another length, is
/// refused.
#[test]
fn hostaddr_is_dialled_and_host_is_the_name() {
    let c = Config::parse("host=db.internal hostaddr=10.1.2.3 port=6000 user=u").unwrap();
    assert_eq!(c.targets(), [("db.internal", "10.1.2.3:6000".to_string())]);
    let c = Config::parse("host=a,b hostaddr=10.0.0.1,::1 user=u").unwrap();
    assert_eq!(
        c.targets(),
        [
            ("a", "10.0.0.1:5432".to_string()),
            ("b", "[::1]:5432".to_string())
        ]
    );
    let c = Config::parse("hostaddr=10.1.2.3 user=u").unwrap();
    assert_eq!(c.targets(), [("10.1.2.3", "10.1.2.3:5432".to_string())]);
    let e = Config::parse("host=db hostaddr=not-an-ip user=u").unwrap_err();
    assert!(e.to_string().contains("hostaddr"), "{e}");
    assert!(Config::parse("host=a,b hostaddr=10.0.0.1 user=u").is_err());
    // The port list matches the longer of the two lists.
    let c = Config::parse("hostaddr=10.0.0.1,10.0.0.2 port=1,2 user=u").unwrap();
    assert_eq!(c.targets()[1].1, "10.0.0.2:2");
}

/// D10 (RED before: any value was accepted and ignored): `target_session_attrs` is `any`,
/// `read-write` or `read-only` (the 1.5.5 driver's set); anything else is refused naming them.
#[test]
fn target_session_attrs_takes_the_drivers_values_only() {
    for ok in ["any", "read-write", "read-only"] {
        Config::parse(&format!("host=db user=u target_session_attrs={ok}")).unwrap();
    }
    let e = Config::parse("host=db user=u target_session_attrs=primary").unwrap_err();
    assert!(e.to_string().contains("target_session_attrs"), "{e}");
    assert!(
        e.to_string().contains("read-write"),
        "names the accepted values: {e}"
    );
}

/// D9 (RED before: both were accepted and silently ignored): this client has no SCRAM-PLUS, so
/// `channel_binding=require` could not be honoured, and the connection is verified against
/// busbar's trust anchors, so a per-store `sslrootcert` could not be. 1.5.5 refused both.
#[test]
fn what_this_client_cannot_honour_is_refused_not_ignored() {
    let e = Config::parse("host=db user=u channel_binding=require").unwrap_err();
    assert!(e.to_string().contains("channel_binding"), "{e}");
    Config::parse("host=db user=u channel_binding=prefer").unwrap();
    Config::parse("host=db user=u channel_binding=disable").unwrap();
    assert!(Config::parse("host=db user=u channel_binding=sometimes").is_err());
    let e = Config::parse("host=db user=u sslrootcert=/etc/ca.pem").unwrap_err();
    assert!(e.to_string().contains("sslrootcert"), "{e}");
    let e = Config::parse("postgres://u@db/d?sslmode=verify-full&sslrootcert=/ca.pem").unwrap_err();
    assert!(e.to_string().contains("sslrootcert"), "{e}");
}

/// A downgrade nobody asked for is refused: `prefer` and `allow` would fall back to plaintext
/// silently, so they are errors that say what to use; `disable` is plaintext on request, and
/// an ABSENT `sslmode` is plaintext too (documented in the README), not a refused request.
/// The message never echoes the password.
#[test]
fn sslmode_prefer_and_allow_are_refused_not_downgraded() {
    for mode in ["prefer", "allow"] {
        for dsn in [
            format!("host=db user=u password=zq9pw sslmode={mode}"),
            format!("postgres://u:zq9pw@db/d?sslmode={mode}"),
        ] {
            let e = Config::parse(&dsn).unwrap_err().to_string();
            assert!(
                e.contains(&format!("sslmode={mode} is not supported"))
                    && e.contains("never falls back silently")
                    && e.contains("verify-full")
                    && !e.contains("zq9pw"),
                "{dsn}: {e}"
            );
        }
    }
    assert_eq!(
        Config::parse("host=db user=u sslmode=disable").unwrap().ssl,
        SslMode::Plain
    );
    assert_eq!(Config::parse("host=db user=u").unwrap().ssl, SslMode::Plain);
    for mode in ["require", "verify-ca", "verify-full"] {
        let c = Config::parse(&format!("host=db user=u sslmode={mode}")).unwrap();
        assert_eq!(c.ssl, SslMode::Require, "{mode}");
    }
}

/// Connect options this store neither applies nor can apply (the host's connector owns the
/// sockets) are refused with an explanation, not accepted and ignored; the message never
/// echoes the password.
#[test]
fn connect_options_the_store_cannot_apply_are_refused_not_ignored() {
    for opt in [
        "keepalives=1",
        "keepalives_idle=30",
        "keepalives_interval=10",
        "keepalives_count=3",
        "keepalives_retries=3",
        "load_balance_hosts=random",
        "tcp_user_timeout=5000",
        "sslnegotiation=direct",
    ] {
        let name = opt.split('=').next().unwrap();
        for dsn in [
            format!("host=db user=u password=zq9pw {opt}"),
            format!("postgres://u:zq9pw@db/d?{opt}"),
        ] {
            let e = Config::parse(&dsn).unwrap_err().to_string();
            assert!(
                e.contains(&format!("{name} is not supported by this store"))
                    && !e.contains("zq9pw"),
                "{dsn}: {e}"
            );
        }
    }
}

/// D37 (RED before: accepted and ignored): `connect_timeout` is whole seconds as the driver
/// reads it, a number that is not one is refused.
#[test]
fn connect_timeout_is_whole_seconds() {
    for ok in ["5", "0", "-1"] {
        Config::parse(&format!("host=db user=u connect_timeout={ok}")).unwrap();
    }
    let e = Config::parse("host=db user=u connect_timeout=soon").unwrap_err();
    assert!(e.to_string().contains("connect_timeout"), "{e}");
    assert!(Config::parse("postgres://u@db/d?connect_timeout=2.5").is_err());
    // Zero or less is no bound (libpq's reading); more than zero is whole seconds.
    let ms = |v: &str| {
        Config::parse(&format!("host=db user=u connect_timeout={v}"))
            .unwrap()
            .connect_timeout_ms
    };
    assert_eq!((ms("5"), ms("0"), ms("-1")), (Some(5000), None, None));
    let e = Config::parse("host=db user=u connect_timeout=soon").unwrap_err();
    assert!(e.to_string().contains("whole number of seconds"), "{e}");
}

/// D26 (RED before: the unparsed fragment was echoed): a configuration error never repeats a
/// token of the string that is not a well-formed `key=`, because a password with a space, a `?`
/// or a missing `user:` prefix splits there and its tail would be echoed; an unknown option's
/// key is named only when the string carries no password.
#[test]
fn a_config_error_never_echoes_a_password_tail() {
    for dsn in [
        "host=db user=u password=pa zq9tail",
        "postgres://u:pa?zq9tail@h/db",
        "u:zq9tail@h/db",
        "host=db user=u password='pa zq9tail' zq9tail",
    ] {
        let e = Config::parse(dsn).unwrap_err().to_string();
        assert!(
            !e.contains("zq9tail"),
            "{dsn}: the error echoed a fragment: {e}"
        );
    }
    // The key of an unknown option is the operator's, when no password rides along.
    let e = Config::parse("host=db user=u zq9key=1")
        .unwrap_err()
        .to_string();
    assert!(e.contains("zq9key"), "{e}");
    let e = Config::parse("host=db user=u password=s3 zq9key=1")
        .unwrap_err()
        .to_string();
    assert!(!e.contains("zq9key") && e.contains("unknown option"), "{e}");
    let e = Config::parse("postgres://u:s3@db/d?zq9key=1")
        .unwrap_err()
        .to_string();
    assert!(!e.contains("zq9key") && e.contains("unknown option"), "{e}");
}

/// B9: the store reaches its server over TCP, so a Unix-socket host is refused in the URL
/// forms too (RED by mutation: drop the `starts_with('/')` refusal).
#[test]
fn a_unix_socket_host_is_refused_in_every_url_form() {
    let e = Config::parse("postgres://u@%2Fvar%2Frun%2Fpostgresql/d").unwrap_err();
    assert!(e.to_string().contains("Unix-socket"), "{e}");
    let e = Config::parse("postgres://u@/d?host=/tmp").unwrap_err();
    assert!(e.to_string().contains("Unix-socket"), "{e}");
    let e = Config::parse("postgres://u@db1,%2Ftmp/d").unwrap_err();
    assert!(e.to_string().contains("Unix-socket"), "{e}");
}

/// 1.5.5 dialled `hostaddr` and used `host` only as a name, so a socket-path host beside a
/// hostaddr worked; the Unix-socket refusal is of what is DIALLED (RED before: refused).
#[test]
fn a_socket_path_host_beside_a_hostaddr_is_dialled_by_address() {
    let c = Config::parse("host=/tmp hostaddr=127.0.0.1 user=u").unwrap();
    assert_eq!(c.targets(), [("127.0.0.1", "127.0.0.1:5432".to_string())]);
    let c = Config::parse("postgres://u@%2Ftmp/d?hostaddr=127.0.0.1").unwrap();
    assert_eq!(c.targets(), [("127.0.0.1", "127.0.0.1:5432".to_string())]);
    assert!(Config::parse("host=/tmp user=u").is_err());
}

/// D28 (RED before: `ranges[i]` indexed out of bounds, a panic): a DataRow with fewer fields
/// than the RowDescription named columns is an error on the missing column, not a panic.
#[test]
fn a_data_row_short_of_its_columns_is_an_error_not_a_panic() {
    use bytes::BytesMut;
    use fallible_iterator::FallibleIterator;
    use postgres_protocol::message::backend::Message;
    use postgres_types::Type;
    use std::sync::Arc;

    // A DataRow of ONE field ("ab") against a RowDescription of two columns.
    let mut raw = BytesMut::from(&b"D\0\0\0\x0c\0\x01\0\0\0\x02ab"[..]);
    let Some(Message::DataRow(body)) = Message::parse(&mut raw).unwrap() else {
        panic!("a data row");
    };
    let column = |name: &str| super::Column {
        name: name.to_string(),
        type_: Type::TEXT,
    };
    let columns: Arc<[super::Column]> = vec![column("a"), column("b")].into();
    let mut ranges = Vec::new();
    let mut it = body.ranges();
    while let Some(r) = it.next().unwrap() {
        ranges.push(r);
    }
    let row = super::Row {
        columns,
        body,
        ranges,
    };
    assert_eq!(row.try_get::<_, &str>(0).unwrap(), "ab");
    let e = row.try_get::<_, &str>(1).unwrap_err();
    assert!(e.to_string().contains("column 1"), "{e}");
}

#[test]
fn a_snapshot_transaction_begins_repeatable_read() {
    assert_eq!(
        begin_sql(Some(IsolationLevel::RepeatableRead)),
        "BEGIN ISOLATION LEVEL REPEATABLE READ"
    );
    assert_eq!(begin_sql(None), "BEGIN");
}
