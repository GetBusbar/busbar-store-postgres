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

/// libpq's `prefer` and `allow` parse (1.5.5 accepted them); the password is never echoed by a
/// later refusal.
#[test]
fn sslmode_prefer_and_allow_parse() {
    for mode in ["prefer", "allow"] {
        for dsn in [
            format!("host=db user=u password=zq9pw sslmode={mode}"),
            format!("postgres://u:zq9pw@db/d?sslmode={mode}"),
        ] {
            Config::parse(&dsn).unwrap_or_else(|e| panic!("{dsn}: {e}"));
        }
    }
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

/// The libpq socket options a 1.5.5 DSN carried are ACCEPTED (1.5.5's driver accepted them; a 1.5.5
/// config keeps booting): what the host's connector does anyway is accepted quietly, what it cannot
/// apply is accepted and logged at debug, naming the option and why. A value the driver refused is
/// refused, and `keepalives=0`, which the connector cannot honour, is refused with the reason; no
/// message echoes the password.
#[test]
fn socket_options_are_accepted_and_what_cannot_apply_is_logged() {
    let logged = |dsn: &str| -> (Result<(), String>, String) {
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || Sink(sink.clone()))
            .finish();
        let r = tracing::subscriber::with_default(subscriber, || {
            Config::parse(dsn).map(drop).map_err(|e| e.to_string())
        });
        let text = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        (r, text)
    };
    // Applied (the connector already does it): accepted, nothing logged.
    for opt in [
        "keepalives=1",
        "keepalives=7",
        "keepalives_idle=60",
        "keepalives_idle=0",
        "keepalives_interval=0",
        "keepalives_count=0",
        "keepalives_retries=0",
        "tcp_user_timeout=0",
        "load_balance_hosts=disable",
        "sslnegotiation=postgres",
    ] {
        for dsn in [
            format!("host=db user=u password=zq9pw {opt}"),
            format!("postgres://u:zq9pw@db/d?{opt}"),
        ] {
            let (r, text) = logged(&dsn);
            assert_eq!(r, Ok(()), "{dsn}");
            assert!(!text.contains("has no effect"), "{dsn}: {text}");
        }
    }
    // Cannot apply: accepted, ONE debug line naming the option and why.
    for (opt, why) in [
        ("keepalives_idle=30", "after 60 s idle"),
        ("keepalives_interval=10", "no per-store setting"),
        ("keepalives_count=3", "no per-store setting"),
        ("keepalives_retries=3", "no per-store setting"),
        ("tcp_user_timeout=5000", "no per-store setting"),
        ("load_balance_hosts=random", "tried in the order given"),
        ("sslnegotiation=direct", "SSLRequest"),
    ] {
        for dsn in [
            format!("host=db user=u password=zq9pw {opt}"),
            format!("postgres://u:zq9pw@db/d?{opt}"),
        ] {
            let (r, text) = logged(&dsn);
            assert_eq!(r, Ok(()), "{dsn}");
            let lines: Vec<&str> = text
                .lines()
                .filter(|l| l.contains("has no effect"))
                .collect();
            assert_eq!(lines.len(), 1, "{dsn}: {text}");
            assert!(
                lines[0].contains("DEBUG")
                    && lines[0].contains(&format!("option {opt} has no effect"))
                    && lines[0].contains(why)
                    && !lines[0].contains("zq9pw"),
                "{dsn}: {text}"
            );
        }
    }
    // keepalives=0 cannot be honoured: refused, with the reason.
    for dsn in [
        "host=db user=u password=zq9pw keepalives=0",
        "postgres://u:zq9pw@db/d?keepalives=0",
    ] {
        let e = Config::parse(dsn).unwrap_err().to_string();
        assert!(
            e.contains("keepalives=0 is not supported")
                && e.contains("cannot turn it off")
                && !e.contains("zq9pw"),
            "{dsn}: {e}"
        );
    }
    // A value the driver refused is refused.
    for opt in [
        "keepalives=yes",
        "keepalives=-1",
        "keepalives_idle=soon",
        "keepalives_interval=1.5",
        "keepalives_count=-1",
        "keepalives_retries=x",
        "tcp_user_timeout=x",
        "load_balance_hosts=roundrobin",
        "sslnegotiation=tls",
    ] {
        let name = opt.split('=').next().unwrap();
        let e = Config::parse(&format!("postgres://u:zq9pw@db/d?{opt}"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(&format!("invalid value for option `{name}`")) && !e.contains("zq9pw"),
            "{opt}: {e}"
        );
    }
}

/// A `MakeWriter` target appending to a shared buffer.
struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
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
    assert!(e.to_string().contains("column `b`"), "{e}");
}

#[test]
fn a_snapshot_transaction_begins_repeatable_read() {
    assert_eq!(
        begin_sql(Some(IsolationLevel::RepeatableRead)),
        "BEGIN ISOLATION LEVEL REPEATABLE READ"
    );
    assert_eq!(begin_sql(None), "BEGIN");
}

/// The connection's prepared statements stay bounded: past `STATEMENTS_KEPT` the least recently
/// run is dropped and its Close queued for the next Parse; a stale statement is dropped the same
/// way, and `26000` (the session's statements deallocated) drops them all.
#[test]
fn prepared_statements_drop_the_least_recently_run_past_the_bound() {
    use std::sync::Arc;

    let stmt = |n: usize| {
        Arc::new(super::Statement {
            name: format!("s{n}"),
            types: Vec::new(),
            columns: Vec::new().into(),
        })
    };
    let mut c = super::Cache::default();
    for n in 0..super::STATEMENTS_KEPT {
        c.get(&format!("q{n}"));
        c.insert(&format!("q{n}"), stmt(n));
    }
    assert!(c.closing.is_empty());
    // q0 runs again, so q1 is now the least recently run.
    assert_eq!(c.get("q0").map(|s| s.name.clone()).as_deref(), Some("s0"));
    c.get("new");
    c.insert("new", stmt(9999));
    assert_eq!(c.by_sql.len(), super::STATEMENTS_KEPT);
    assert_eq!(c.closing, ["s1"]);
    assert!(c.get("q1").is_none() && c.get("q0").is_some());

    c.forget("q0");
    assert_eq!(c.closing, ["s1", "s0"]);
    c.forget_all();
    assert!(c.by_sql.is_empty());
    assert_eq!(c.closing.len(), super::STATEMENTS_KEPT + 1);

    let stale = super::Error::server("26000", "prepared statement \"s3\" does not exist");
    assert!(super::is_stale_statement(&stale));
    let changed = super::Error::server("0A000", "cached plan must not change result type");
    assert!(super::is_stale_statement(&changed));
    assert!(!super::is_stale_statement(&super::Error::server(
        "42P01", "no table"
    )));
}
