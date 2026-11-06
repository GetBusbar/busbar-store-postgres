// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `pgwire.rs`.

use super::*;

#[test]
fn a_url_parses_into_its_parts() {
    let c = Config::parse(
        "postgres://u%40x:p%3Ass@db.internal:6543/busbar?sslmode=require&application_name=bb",
    )
    .unwrap();
    assert_eq!(c.user, "u@x");
    assert_eq!(c.redact("auth: p:ss".into()), "auth: <redacted>");
    assert_eq!(c.targets()[0].1, "db.internal:6543");
    assert_eq!(c.dbname.as_deref(), Some("busbar"));
    assert_eq!(c.ssl, SslMode::Require);
    assert_eq!(c.application_name.as_deref(), Some("bb"));
    let c = Config::parse("postgresql://u@[::1]/d").unwrap();
    assert_eq!(c.targets()[0].1, "[::1]:5432");
    assert!(c.credentials.password().is_none());
}

#[test]
fn the_keyword_form_parses_with_spaces_and_quotes() {
    let c = Config::parse("host = db port=5433 user=u password='se cret' dbname=x sslmode=require")
        .unwrap();
    assert_eq!(c.targets()[0].1, "db:5433");
    assert_eq!(c.redact("auth: se cret".into()), "auth: <redacted>");
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
/// busbar's trust anchors, so a per-store `sslrootcert` could not be.
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

/// Each `sslmode` maps to its libpq behaviour: `disable` and `allow` are plaintext, `prefer` asks
/// for TLS and takes plaintext on `N`, the `require` family insists.
#[test]
fn sslmode_values_map_to_their_modes() {
    for (mode, want) in [("allow", SslMode::Plain), ("prefer", SslMode::Prefer)] {
        let c = Config::parse(&format!("host=db user=u sslmode={mode}")).unwrap();
        assert_eq!(c.ssl, want, "{mode}");
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

/// Accept settings implemented by the connector; refuse requests whose behavior is unavailable.
#[test]
fn socket_options_accept_only_effective_settings() {
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

    for opt in [
        "keepalives=1",
        "keepalives=7",
        "keepalives_idle=60",
        "keepalives_idle=0",
        "keepalives_idle=-1",
        "keepalives_interval=0",
        "keepalives_interval=-1",
        "keepalives_count=0",
        "keepalives_retries=0",
        "tcp_user_timeout=0",
        "tcp_user_timeout=-1",
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
            let error = r.expect_err("unsupported behavior must fail validation");
            let name = opt.split('=').next().unwrap();
            assert!(
                error.contains(name)
                    && error.contains("not supported")
                    && error.contains(why)
                    && !error.contains("zq9pw"),
                "{dsn}: {error}"
            );
            assert!(!text.contains("has no effect"), "{dsn}: {text}");

            let settings = serde_json::json!({ "url": dsn }).to_string();
            let error =
                <crate::PostgresStore as busbar_contract::abi::sdk::store::StoreSlots>::validate(
                    settings.as_bytes(),
                )
                .expect_err("the Store lifecycle must reject the same unsupported settings");
            assert!(
                error.contains("invalid postgres plugin config: url:"),
                "{error}"
            );
            assert!(error.contains(name) && !error.contains("zq9pw"), "{error}");
        }
    }

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
    let fractional = Config::parse("postgres://u@db/d?connect_timeout=2.5").unwrap_err();
    assert!(fractional.to_string().contains("whole number of seconds"));

    let ms = |v: &str| {
        Config::parse(&format!("host=db user=u connect_timeout={v}"))
            .unwrap()
            .connect_timeout_ms
    };
    assert_eq!((ms("5"), ms("0"), ms("-1")), (Some(5000), Some(0), Some(0)));
    assert!(e.to_string().contains("whole number of seconds"), "{e}");
}

/// A DSN without `connect_timeout` still bounds the handshake (30 s); the DSN's value wins, and 0
/// is the explicit "no bound".
#[test]
fn an_unset_connect_timeout_defaults_to_thirty_seconds() {
    let bound = |dsn: &str| Config::parse(dsn).unwrap().connect_bound_ms();
    assert_eq!(bound("host=db user=u"), 30_000);
    assert_eq!(bound("host=db user=u connect_timeout=5"), 5_000);
    assert_eq!(bound("host=db user=u connect_timeout=0"), 0);
    assert_eq!(bound("host=db user=u connect_timeout=-1"), 0);
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
        "postgres://u:pa?zq9tail=value@h/db",
        "u:zq9tail@h/db",
        "host=db user=u password='pa zq9tail' zq9tail",
    ] {
        let e = Config::parse(dsn).unwrap_err().to_string();
        assert!(
            !e.contains("zq9tail"),
            "{dsn}: the error echoed a fragment: {e}"
        );
    }

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
        "BEGIN ISOLATION LEVEL REPEATABLE READ; SET LOCAL lock_timeout = '30s'; \
         SET LOCAL idle_in_transaction_session_timeout = '60s'"
    );
    assert_eq!(
        begin_sql(None),
        "BEGIN ISOLATION LEVEL READ COMMITTED; SET LOCAL lock_timeout = '30s'; \
         SET LOCAL idle_in_transaction_session_timeout = '60s'",
        "a DSN's default_transaction_isolation must not change the store's reasoning"
    );
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

#[test]
fn text_after_a_bracketed_ipv6_host_is_not_silently_discarded() {
    for suffix in ["garbage", ":5432trailer"] {
        let url = format!("postgres://user:hidden@[::1]{suffix}/db");
        let error = match Config::parse(&url) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("malformed host/port tail must be refused"),
        };
        assert!(!error.contains("hidden"));
    }
    assert!(Config::parse("postgres://user@[::1]:5432/db").is_ok());
    assert!(Config::parse("postgres://user@[::1]/db").is_ok());
}

#[test]
fn nul_bytes_in_postgres_startup_fields_are_refused_during_parse() {
    for option in ["user", "dbname", "application_name", "options"] {
        let url = format!("postgres://user:hidden@host/db?{option}=before%00after");
        let error = match Config::parse(&url) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("startup strings cannot encode NUL"),
        };
        assert!(error.contains(option), "{error}");
        assert!(!error.contains("before") && !error.contains("after") && !error.contains("hidden"));
    }
    let error = match Config::parse("host=host user='before\0after'") {
        Err(error) => error.to_string(),
        Ok(_) => panic!("keyword startup strings also refuse NUL"),
    };
    assert!(error.contains("user"));
}

#[test]
fn captured_passwords_preserve_last_wins_and_decode_semantics() {
    for (dsn, decoded) in [
        ("postgres://u:first@host/db?password=second", "second"),
        (
            "postgres://u:first@host/db?password=second&password=third",
            "third",
        ),
        (
            "postgres://u:first@host/db?%70assword=second%40value",
            "second@value",
        ),
        ("postgres://u:first@host/db?password=second&password=", ""),
        ("host=db user=u password=first password=second", "second"),
        ("host=db user=u password=first password=", ""),
        ("postgres://u@host/db?password=literal+plus", "literal+plus"),
        (
            "postgres://u@host/db?password=literal%2Bplus",
            "literal+plus",
        ),
    ] {
        let config = Config::parse(dsn).unwrap();
        assert_eq!(config.credentials.password().unwrap().len(), decoded.len());
        assert_eq!(
            config.redact(format!("auth: {decoded}")),
            if decoded.is_empty() {
                "auth: "
            } else {
                "auth: <redacted>"
            },
            "the effective password stays sealed and still redacts peer echoes"
        );
        if !decoded.is_empty() {
            assert!(!format!("{config:?}").contains(decoded));
        }
    }
}

#[test]
fn captured_passwords_do_not_hide_invalid_options_or_invalid_encoding() {
    for dsn in [
        "postgres://u@host/db?pass=hidden",
        "postgres://u@host/db?password=bad%zz",
        "postgres://u@host/db?password=bad%ff",
        "postgres://u:bad%4@host/db",
        "host=db user=u password='unterminated",
        "host=db user=u password=hidden unknown=hidden",
    ] {
        let error = Config::parse(dsn).unwrap_err().to_string();
        assert!(!error.contains("hidden"), "{error}");
    }
}

#[test]
fn require_auth_is_validated_and_captured_without_relaxing_the_floor() {
    use busbar_contract::abi::sdk::cred::PgAuth;
    let strict = Config::parse("postgres://u:hidden@host/db").unwrap();
    assert!(strict.credentials.floor().pg().allows(PgAuth::ScramSha256));
    assert!(strict.credentials.floor().pg().allows(PgAuth::None));
    assert!(!strict.credentials.floor().pg().allows(PgAuth::Password));
    assert!(!strict.credentials.floor().pg().allows(PgAuth::Md5));
    let explicit =
        Config::parse("host=db user=u password=hidden require_auth=md5,password").unwrap();
    assert!(explicit.credentials.floor().pg().allows(PgAuth::Password));
    assert!(explicit.credentials.floor().pg().allows(PgAuth::Md5));
    assert!(!explicit.credentials.floor().pg().allows(PgAuth::None));
    assert!(!explicit
        .credentials
        .floor()
        .pg()
        .allows(PgAuth::ScramSha256));
    for dsn in [
        r"host=db user=u password=hidden require_auth=pass\word",
        "host=db user=u password=hidden require_auth = 'password'",
        "postgres://u:hidden@host/db?%72equire_auth=%70assword",
    ] {
        let config = Config::parse(dsn).unwrap();
        assert!(config.credentials.floor().pg().allows(PgAuth::Password));
        assert!(!config.credentials.floor().pg().allows(PgAuth::Md5));
    }
    let tls = Config::parse("postgres://u:hidden@host/db?sslmode=require").unwrap();
    assert!(tls.credentials.password().unwrap().secure_required());
    for value in ["", "hidden", "md5,md5", "password,!md5"] {
        let error = Config::parse(&format!("host=db user=u require_auth={value}"))
            .unwrap_err()
            .to_string();
        assert!(!error.contains("hidden"), "{error}");
    }
}

#[test]
fn scram_public_message_validation_preserves_strict_native_grammar() {
    for first in [
        "s=QUJD,r=nonce,i=4096",
        "r=nonce,s=QUJD,i=4096,r=other",
        "m=required,r=nonce,s=QUJD,i=4096",
        "r=bad nonce,s=QUJD,i=4096",
        "r=nonce,s=QUJD,i=4096x",
        "r=nonce,s=QUJD,i=100001",
        "r=nonce,s=QUJD,i=0",
        "r=nonce,s=QUJD,i=01",
        "r=nonce,s=QUJD,i=04096",
        "r=nonce,s=QUJD,i=4294967296",
    ] {
        assert!(
            super::scram_server_first(first.as_bytes()).is_err(),
            "{first}"
        );
    }
    for first in [
        "r=nonce,s=QUJD,i=1",
        "r=nonce,s=QUJD,i=4095",
        "r=nonce,s=QUJD,i=4096",
        "r=nonce,s=QUJD,i=100000",
    ] {
        assert_eq!(super::scram_server_first(first.as_bytes()).unwrap(), first);
    }
    for final_message in [
        "e=invalid-proof",
        "v=QUJD,e=invalid-proof",
        "e=invalid-proof,v=QUJD",
        "v=QUJD,v=QUJD",
        "v=QUJD,",
        "v=not base64",
    ] {
        assert!(super::scram_server_final(final_message.as_bytes()).is_err());
    }
    assert!(super::scram_server_first(b"r=nonce,s=QUJD,i=4096\xff").is_err());
    assert!(super::scram_server_final(b"v=QUJD\xff").is_err());
    assert_eq!(super::scram_server_final(b"v=QUJD").unwrap(), "v=QUJD");
}

#[test]
fn captured_dsn_redaction_covers_raw_decoded_and_superseded_passwords() {
    let config = Config::parse("postgres://u:first%40value@host/db?password=last%2Bvalue").unwrap();
    assert_eq!(
        config.redact("first%40value first@value last%2Bvalue last+value".into()),
        "<redacted> <redacted> <redacted> <redacted>",
    );
}

#[test]
fn the_sdk_verifier_link_accepts_the_known_native_scram_exchange() {
    let config = Config::parse("host=db user=u password=foobar").unwrap();
    let (_, link) = config
        .credentials
        .password()
        .unwrap()
        .pg_scram_sha256_postgres(
            "n=,r=9IZ2O01zb9IgiIZ1WJ/zgpJB",
            "r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY,s=fs3IXBy7U7+IvVjZ,i=4096",
            b"n,,",
        )
        .unwrap();
    assert!(link.verify("v=U+ppxD5XUKtradnv8e2MkeupiA8FU87Sg8CXzXHDAzw="));
}

impl Config {
    /// Every endpoint, in the order a connect tries them: `(name, dial host:port)`.
    #[must_use]
    pub fn targets(&self) -> Vec<(&str, String)> {
        self.endpoints
            .iter()
            .map(|e| (e.name.as_str(), target(&e.dial, e.port)))
            .collect()
    }
}
impl Error {
    /// A server failure with SQLSTATE `code` and `message`, as an `ErrorResponse` decodes.
    #[must_use]
    pub fn server(code: &str, message: &str) -> Self {
        Self::new(Kind_::Db(DbError {
            severity: "ERROR".to_string(),
            code: SqlState(code.to_string()),
            message: message.to_string(),
            constraint: None,
        }))
    }
}

#[test]
fn authentication_and_control_message_limits_preserve_data_rows() {
    assert_eq!(message_limit(b'R', false), 30_000);
    assert_eq!(message_limit(b'D', false), 30_000);
    assert_eq!(message_limit(b'R', true), 30_000);
    assert_eq!(message_limit(b'D', true), (1 << 30) + 4);
}

#[test]
fn malformed_server_error_is_a_protocol_error() {
    for body in [
        b"Munterminated".as_slice(),
        b"Mmessage\0\0".as_slice(),
        b"SERROR\0C23514\0\0".as_slice(),
    ] {
        let mut frame = BytesMut::new();
        frame.extend_from_slice(b"E");
        frame.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(body);
        let Message::ErrorResponse(body) = Message::parse(&mut frame).unwrap().unwrap() else {
            panic!("error response");
        };
        let error = Error::response(&body);
        assert!(error.code().is_none());
        assert!(error.to_string().contains("error parsing response"));
    }
}

#[test]
fn an_empty_server_message_preserves_its_sqlstate() {
    let body = b"SERROR\0C23514\0M\0\0";
    let mut frame = BytesMut::new();
    frame.extend_from_slice(b"E");
    frame.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    frame.extend_from_slice(body);
    let Message::ErrorResponse(body) = Message::parse(&mut frame).unwrap().unwrap() else {
        panic!("error response");
    };
    let error = Error::response(&body);
    assert_eq!(error.code().map(SqlState::code), Some("23514"));
    assert_eq!(error.as_db_error().unwrap().message(), "");
}

#[test]
fn a_long_row_description_keeps_the_data_ceiling_after_authentication() {
    // libpq's VALID_LONG_MESSAGE_TYPE includes RowDescription: a wide result's description may
    // exceed the 30,000-byte control cap.
    assert_eq!(message_limit(b'T', true), MAX_MESSAGE_LEN);
    assert_eq!(message_limit(b'T', false), MAX_CONTROL_MESSAGE_LEN);
}
