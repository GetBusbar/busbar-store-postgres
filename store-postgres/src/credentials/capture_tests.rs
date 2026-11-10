// SPDX-License-Identifier: Apache-2.0
// Native capture assertions transferred from the SDK. Secret bytes are observed only by test-seal.
use super::*;
use busbar_contract::abi::sdk::cred::settings;
use busbar_contract::abi::sdk::test_support::chip::observe_credential;
fn password(url: &CredUrl) -> Option<Vec<u8>> {
    url.password().map(|value| {
        let mut out = Vec::new();
        observe_credential(&value.original, |bytes| out.extend_from_slice(bytes));
        out
    })
}
#[test]
fn postgres_capture_preserves_last_wins_and_native_decoding() {
    let p = CredUrl::parse_postgres(
        "postgres://u:first@h/db?password=second&%70assword=last+%2B&sslmode=require",
    )
    .unwrap();
    assert_eq!(password(&p).as_deref(), Some(&b"last++"[..]));
    assert_eq!(p.public(), "postgres://u@h/db?sslmode=require");
    assert!(p.password().unwrap().secure_required());
    assert_eq!(
        p.redact_echo("first second last++ last+%2b"),
        "<redacted> <redacted> <redacted> <redacted>"
    );
    let p =
        CredUrl::parse_postgres("host=db password='one' password=two\\ words user=app").unwrap();
    assert_eq!(password(&p).as_deref(), Some(&b"two words"[..]));
    assert_eq!(
        p.redact_echo(r"one two words two\ words"),
        "<redacted> <redacted> <redacted>"
    );
    assert_eq!(
        CredUrl::parse_postgres("user=u password=")
            .unwrap()
            .password()
            .unwrap()
            .len(),
        0
    );
    assert!(CredUrl::parse_postgres("user=u")
        .unwrap()
        .password()
        .is_none());
    for invalid in ["%", "%1", "%GG", "%ff"] {
        assert!(CredUrl::parse_postgres(&format!("postgres://u:{invalid}@h/db")).is_err());
        assert!(CredUrl::parse_postgres(&format!("postgres://u@h/db?password={invalid}")).is_err());
    }

    let p = CredUrl::parse_postgres("postgres://u@h/db?pass=value").unwrap();
    assert!(p.password().is_none());
    assert!(p.public().contains("pass=value"));
}

#[test]
fn postgres_capture_applies_exact_keyword_and_query_auth_policy() {
    for text in [
        r"user=u password=p require_auth=pass\word",
        "user=u password=p require_auth = 'md5,password'",
        "user=u\u{2003}password=p\u{2003}require_auth\u{2003}=\u{2003}password",
        "postgres://u:p@h/db?options=x#y&%72equire_auth=%70assword",
    ] {
        let p = CredUrl::parse_postgres(text).unwrap();
        assert!(p.floor().allows(PgAuth::Password));
        assert!(p.password().unwrap().pg_password_message().is_ok());
    }
    let typed: PostgresUrl = settings(br#""  postgres://u:p@h/db  ""#).unwrap();
    assert_eq!(typed.0.public(), "postgres://u@h/db");
    assert!(CredUrl::parse_postgres("  postgres://u:p@h/db  ").is_err());
}

#[test]
fn percent_spelled_postgres_tls_mode_keeps_secure_requirement() {
    let p = CredUrl::parse_postgres("postgres://u:p@h/db?%73slmode=%72equire").unwrap();
    assert!(p.password().unwrap().secure_required());
    assert!(p.password().unwrap().secure_required());
}
#[test]
fn raw_delimiters_do_not_turn_a_path_or_query_into_native_userinfo() {
    for text in [
        "postgres://u:secret?tail@db/d",
        "postgres://u:secret/tail@db/d",
    ] {
        assert!(CredUrl::parse_postgres(text).is_err());
    }
}
