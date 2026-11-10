// SPDX-License-Identifier: Apache-2.0
// Protocol assertions transferred from the SDK, observing bytes only through the dev-only host writer.
use super::*;
use busbar_contract::abi::sdk::cred::SealedWrite;
use busbar_contract::abi::sdk::test_support::chip::drive_sealed;
use std::task::Poll;
fn cred(s: &str) -> Password {
    Password::capture(Zeroizing::new(s.as_bytes().to_vec()), false)
}
fn allowing(s: &str) -> Password {
    let mut password = cred(s);
    password.floor = RequireAuth::parse("password,md5,scram-sha-256").unwrap();
    password
}
fn from_url(s: &str) -> Password {
    CredUrl::parse_postgres(s)
        .unwrap()
        .password()
        .unwrap()
        .clone()
}
trait WireInspect {
    fn wire(&self) -> Vec<u8>;
}
impl WireInspect for Seal {
    fn wire(&self) -> Vec<u8> {
        let copy = SealedValue::compose(&[Part::Sealed(self)]).field();
        let mut writer = SealedWrite::message(copy);
        let mut out = Vec::new();
        assert!(matches!(
            drive_sealed::<()>(&mut writer, |bytes| {
                out.extend_from_slice(bytes);
                Poll::Ready(Ok(bytes.len()))
            }),
            Poll::Ready(Ok(()))
        ));
        out
    }
}
#[test]
fn scram_sha256_matches_rfc_7677() {
    let c = cred("pencil");
    let (seal, link) = c
        .pg_scram_sha256(
            "n=user,r=rOprNGfwEbeRWgbNEkqO",
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            b"n,,",
        )
        .expect("scram");
    let want = b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    let w = seal.wire();
    assert_eq!(w[0], b'p');
    assert_eq!(&w[1..5], &((want.len() + 4) as i32).to_be_bytes());
    assert_eq!(&w[5..], &want[..]);
    assert!(link.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
}

#[test]
fn scram_refuses_a_wrong_server_signature_a_foreign_nonce_and_a_cheap_iteration_count() {
    let c = cred("pencil");
    let (_, link) = c
        .pg_scram_sha256("n=,r=abc", "r=abcdef,s=QUJD,i=4096", b"n,,")
        .expect("scram");
    assert!(!link.verify("v=AAAA"));
    assert!(c
        .pg_scram_sha256("n=,r=abc", "r=xyz123,s=QUJD,i=4096", b"n,,")
        .is_err());
    assert!(c
        .pg_scram_sha256("n=,r=abc", "r=abcdef,s=QUJD,i=1", b"n,,")
        .is_err());
}

#[test]
fn pg_messages_are_whole() {
    let c = allowing("s3cr3t-pw");
    assert_eq!(
        c.pg_password_message().expect("allowed").wire(),
        b"p\0\0\0\x0es3cr3t-pw\0"
    );
    let md5 = c.pg_md5_message("alice", [1, 2, 3, 4]).expect("allowed");
    let body = b"md544a496913670b4e45995c33c22115d02\0";
    assert_eq!(md5.wire()[0], b'p');
    assert_eq!(&md5.wire()[5..], &body[..]);
}

#[test]
fn pg_scram_applies_saslprep_before_deriving_the_proof() {
    let proof = |password: &str| {
        cred(password)
            .pg_scram_sha256("n=,r=abc", "r=abcdef,s=QUJD,i=4096", b"n,,")
            .expect("SCRAM")
            .0
    };

    for (input, normalized) in [
        ("I\u{00ad}X", "IX"),
        ("a\u{00a0}b", "a b"),
        ("\u{00aa}", "a"),
        ("\u{2168}", "IX"),
        ("\u{0627}\u{00ad}\u{0628}", "\u{0627}\u{0628}"),
        ("\u{2f868}", "\u{2136a}"),
        (
            "\u{0627}\u{00ad}\u{2132}\u{0628}",
            "\u{0627}\u{2132}\u{0628}",
        ),
    ] {
        assert_eq!(proof(input).wire(), proof(normalized).wire());
    }
    assert_ne!(proof("USER").wire(), proof("user").wire());
}

#[test]
fn pg_scram_raw_fallback_uses_the_original_bytes_not_a_partly_mapped_password() {
    use base64::Engine as _;
    use ring::{hmac, pbkdf2};
    for bytes in [
        &b"a\xffb"[..],
        "\u{00ad}".as_bytes(),
        "I\u{00ad}\u{0007}X".as_bytes(),
        "a\u{e000}b".as_bytes(),
        "a\u{0221}b".as_bytes(),
        "\u{1d2c}".as_bytes(),
        "\u{0627}\u{00ad}\u{1885}\u{0628}".as_bytes(),
        "a\u{0627}b".as_bytes(),
        "\u{0627}1".as_bytes(),
    ] {
        let c = Password::capture(Zeroizing::new(bytes.to_vec()), false);
        let (_, link) = c
            .pg_scram_sha256("n=,r=abc", "r=abcdef,s=QUJD,i=4096", b"n,,")
            .expect("PostgreSQL accepts original bytes when SASLprep fails");

        let mut salted = Zeroizing::new([0_u8; 32]);
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(4096).unwrap(),
            b"ABC",
            bytes,
            &mut salted[..],
        );
        let server_key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &salted[..]),
            b"Server Key",
        );
        let signature = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, server_key.as_ref()),
            b"n=,r=abc,r=abcdef,s=QUJD,i=4096,c=biws,r=abcdef",
        );
        assert!(link.verify(&format!(
            "v={}",
            base64::engine::general_purpose::STANDARD.encode(signature.as_ref())
        )));
    }
}

#[test]
fn pg_cleartext_and_md5_are_refused_unless_require_auth_allows_them() {
    let first = "n=,r=abc";
    let server_first = "r=abcdef,s=QUJD,i=4096";
    let strict = from_url("postgres://u:pw@db/app");
    let e = strict
        .pg_password_message()
        .err()
        .expect("cleartext refused");
    assert!(
        e.0.contains("clear") && e.0.contains("require_auth=password"),
        "{e}"
    );
    let e = strict
        .pg_md5_message("u", [1, 2, 3, 4])
        .err()
        .expect("md5 refused");
    assert!(
        e.0.contains("MD5") && e.0.contains("require_auth=md5"),
        "{e}"
    );
    assert!(strict.pg_scram_sha256(first, server_first, b"n,,").is_ok());

    let tls = from_url("postgres://u:pw@db/app?sslmode=verify-full");
    assert!(tls.pg_password_message().is_err() && tls.pg_md5_message("u", [0; 4]).is_err());

    let md5 = from_url("postgres://u:pw@db/app?require_auth=md5");
    assert!(md5.pg_md5_message("u", [1, 2, 3, 4]).is_ok());
    assert!(md5.pg_password_message().is_err());
    assert!(md5.pg_scram_sha256(first, server_first, b"n,,").is_err());
    let clear = from_url("host=db user=u password=pw require_auth=password,scram-sha-256");
    assert!(clear.pg_password_message().is_ok());
    assert!(clear.pg_md5_message("u", [0; 4]).is_err());
    assert!(clear.pg_scram_sha256(first, server_first, b"n,,").is_ok());

    assert!(cred("pw").pg_password_message().is_err());
    assert!(cred("pw").pg_md5_message("u", [0; 4]).is_err());
}

#[test]
fn postgres_store_scram_keeps_native_positive_iteration_bounds() {
    let c = cred("pencil");
    for iterations in [1, 4095, 4096, 100_000] {
        let first = format!("r=abcdef,s=QUJD,i={iterations}");
        assert!(c
            .pg_scram_sha256_postgres("n=,r=abc", &first, b"n,,")
            .is_ok());
    }
    for iterations in ["0", "01", "+1", "-1", "100001", "4294967296", "1x", ""] {
        let first = format!("r=abcdef,s=QUJD,i={iterations}");
        assert!(c
            .pg_scram_sha256_postgres("n=,r=abc", &first, b"n,,")
            .is_err());
    }

    assert!(c
        .pg_scram_sha256("n=,r=abc", "r=abcdef,s=QUJD,i=4095", b"n,,")
        .is_err());
    let md5 = from_url("host=db user=u password=pencil require_auth=md5");
    assert!(md5
        .pg_scram_sha256_postgres("n=,r=abc", "r=abcdef,s=QUJD,i=1", b"n,,")
        .is_err());
}

#[test]
fn scram_server_final_rejects_ambiguous_or_malformed_attributes() {
    const SIG: &str = "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
    fn link() -> super::ScramLink {
        cred("pencil").pg_scram_sha256_postgres(
            "n=user,r=rOprNGfwEbeRWgbNEkqO",
            "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096",
            b"n,,",
        ).unwrap().1
    }
    assert!(link().verify(&format!("v={SIG}")));
    assert!(link().verify(&format!("v={SIG},x=extension")));
    for value in [
        format!("e=failed,v={SIG}"),
        format!("v={SIG},e=failed"),
        format!("v={SIG},v={SIG}"),
        format!("v={SIG},"),
        format!("v={SIG},xx=bad"),
        format!("v={SIG},x="),
        format!("v={SIG},m=required"),
        format!("v={SIG},x=bad value"),
        format!("v={SIG},x=one,x=two"),
        format!("x=one,v={SIG}"),
    ] {
        assert!(!link().verify(&value));
    }
}

#[test]
fn postgres_nonce_has_native_shape_and_cleartext_refuses_nul_only_at_its_recipe() {
    let nonce = super::pg_scram_nonce().unwrap();
    assert_eq!(nonce.len(), 24);
    assert!(nonce
        .bytes()
        .all(|b| matches!(b, b'!'..=b'+' | b'-'..=b'~')));
    let c = CredUrl::parse_postgres(
        "user=u password='p\0word' require_auth=password,md5,scram-sha-256",
    )
    .unwrap()
    .password()
    .unwrap()
    .clone();
    assert!(c.pg_password_message().is_err());
    assert!(c.pg_md5_message("u", [1, 2, 3, 4]).is_ok());
    assert!(c
        .pg_scram_sha256_postgres("n=,r=abc", "r=abcdef,s=QUJD,i=1", b"n,,")
        .is_ok());
}
