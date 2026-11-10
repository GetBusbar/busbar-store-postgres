// SPDX-License-Identifier: Apache-2.0
use super::*;
use base64::Engine as _;
use busbar_contract::abi::sdk::chip::{CredentialPart as Part, Digest, Refused, SealedValue};
use busbar_contract::abi::sdk::cred::Seal;
/// RULING S4: a Postgres server asked for the password in clear.
pub const PG_CLEARTEXT_REFUSED: Refused = Refused(
    "the server asked for the password in clear (AuthenticationCleartextPassword), which the \
     operator's connection string does not allow: busbar sends only SCRAM-SHA-256 unless \
     `require_auth` allows the weaker method (add `require_auth=password`, or use SCRAM on the \
     server)",
);

/// RULING S4: a Postgres server asked for MD5.
pub const PG_MD5_REFUSED: Refused = Refused(
    "the server asked for MD5 password authentication, which the operator's connection string \
     does not allow: busbar sends only SCRAM-SHA-256 unless `require_auth` allows the weaker \
     method (add `require_auth=md5`, or set the role's password with SCRAM on the server)",
);

/// The operator's `require_auth` leaves SCRAM-SHA-256 out (libpq's rule).
pub const PG_SCRAM_REFUSED: Refused = Refused(
    "the server asked for SCRAM-SHA-256, which the operator's `require_auth` does not name",
);

/// A fresh 24-character PostgreSQL SCRAM nonce (printable ASCII excluding comma).
pub fn pg_scram_nonce() -> Result<String, Refused> {
    let mut nonce = String::with_capacity(24);
    while nonce.len() < 24 {
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| Refused("no randomness for the SCRAM nonce"))?;
        for b in random {
            if b >= 186 {
                continue;
            }
            let c = 0x21 + b % 93;
            nonce.push(if c == b',' { '~' } else { c as char });
            if nonce.len() == 24 {
                break;
            }
        }
    }
    Ok(nonce)
}

/// What a SCRAM exchange left to check: the server's signature, held until the server-final
#[allow(missing_debug_implementations)]
pub struct ScramLink(SealedValue);

impl ScramLink {
    /// Whether `server_final` (`v=<base64>`) proves the server knew the password.
    pub fn verify(self, server_final: &str) -> bool {
        let mut attrs = server_final.split(',');
        let Some(v) = attrs.next().and_then(|a| a.strip_prefix("v=")) else {
            return false;
        };
        let mut seen = [false; 128];
        seen[b'v' as usize] = true;
        for attr in attrs {
            let b = attr.as_bytes();
            if b.len() < 3
                || !b[0].is_ascii_alphabetic()
                || b[1] != b'='
                || matches!(b[0], b'e' | b'm')
                || seen[b[0] as usize]
                || !b[2..]
                    .iter()
                    .all(|b| matches!(b, b'!'..=b'+' | b'-'..=b'~'))
            {
                return false;
            }
            seen[b[0] as usize] = true;
        }
        let Ok(got) = base64::engine::general_purpose::STANDARD.decode(v) else {
            return false;
        };
        self.0.verify_eq(&got)
    }
}

fn message(body: &SealedValue) -> Seal {
    SealedValue::compose(&[
        Part::Public(b"p"),
        Part::Public(&((body.len() + 4) as i32).to_be_bytes()),
        Part::Value(body),
    ])
    .field()
}

impl Password {
    fn allows(&self, method: PgAuth, refused: Refused) -> Result<(), Refused> {
        if self.floor.allows(method) {
            Ok(())
        } else {
            Err(refused)
        }
    }
    pub(crate) fn pg_password_message(&self) -> Result<Seal, Refused> {
        self.allows(PgAuth::Password, PG_CLEARTEXT_REFUSED)?;
        if self.contains_nul {
            return Err(Refused("NUL byte in PostgreSQL cleartext password"));
        }
        Ok(message(&SealedValue::compose(&[
            Part::Credential(&self.original),
            Part::Public(&[0]),
        ])))
    }
    pub(crate) fn pg_md5_message(&self, user: &str, salt: [u8; 4]) -> Result<Seal, Refused> {
        self.allows(PgAuth::Md5, PG_MD5_REFUSED)?;
        let inner = SealedValue::compose(&[
            Part::Credential(&self.original),
            Part::Public(user.as_bytes()),
        ])
        .digest(Digest::Md5)
        .hex_lower();
        let outer = SealedValue::compose(&[Part::Value(&inner), Part::Public(&salt)])
            .digest(Digest::Md5)
            .hex_lower();
        Ok(message(&SealedValue::compose(&[
            Part::Public(b"md5"),
            Part::Value(&outer),
            Part::Public(&[0]),
        ])))
    }
    #[cfg(test)]
    fn pg_scram_sha256(
        &self,
        client_first_bare: &str,
        server_first: &str,
        channel_binding: &[u8],
    ) -> Result<(Seal, ScramLink), Refused> {
        self.scram(client_first_bare, server_first, channel_binding, false)
    }
    pub(crate) fn pg_scram_sha256_postgres(
        &self,
        client_first_bare: &str,
        server_first: &str,
        channel_binding: &[u8],
    ) -> Result<(Seal, ScramLink), Refused> {
        self.scram(client_first_bare, server_first, channel_binding, true)
    }
    fn scram(
        &self,
        client_first_bare: &str,
        server_first: &str,
        channel_binding: &[u8],
        native_iterations: bool,
    ) -> Result<(Seal, ScramLink), Refused> {
        self.allows(PgAuth::ScramSha256, PG_SCRAM_REFUSED)?;
        const BAD: Refused = Refused("the SCRAM server-first message is malformed");
        let attr = |msg: &'_ str, k: &str| -> Option<String> {
            msg.split(',')
                .find_map(|a| a.strip_prefix(k).map(str::to_owned))
        };
        let cnonce = attr(client_first_bare, "r=")
            .ok_or(Refused("the SCRAM client-first message has no nonce"))?;
        let nonce = attr(server_first, "r=").ok_or(BAD)?;
        if !nonce.starts_with(&cnonce) || nonce.len() <= cnonce.len() {
            return Err(Refused(
                "the SCRAM server nonce does not extend the client nonce",
            ));
        }
        let salt = base64::engine::general_purpose::STANDARD
            .decode(attr(server_first, "s=").ok_or(BAD)?)
            .map_err(|_| BAD)?;
        let iteration_text = attr(server_first, "i=").ok_or(BAD)?;
        if native_iterations
            && (!matches!(iteration_text.as_bytes().first(), Some(b'1'..=b'9'))
                || !iteration_text.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(BAD);
        }
        let iterations: u32 = iteration_text.parse().map_err(|_| BAD)?;
        if native_iterations {
            if !(1..=100_000).contains(&iterations) {
                return Err(Refused("the SCRAM iteration count is outside 1..=100000"));
            }
        } else if !(4096..=1_000_000).contains(&iterations) {
            return Err(Refused(
                "the SCRAM iteration count is outside 4096..=1000000",
            ));
        }
        let salted = self
            .prepared
            .sealed_value()
            .pbkdf2_sha256(&salt, iterations)?;
        let client_key = salted.hmac_sha256(&SealedValue::compose(&[Part::Public(b"Client Key")]));
        let stored_key = client_key.digest(Digest::Sha256);
        let server_key = salted.hmac_sha256(&SealedValue::compose(&[Part::Public(b"Server Key")]));
        let without_proof = format!(
            "c={},r={nonce}",
            base64::engine::general_purpose::STANDARD.encode(channel_binding)
        );
        let auth_message = format!("{client_first_bare},{server_first},{without_proof}");
        let auth_message = SealedValue::compose(&[Part::Public(auth_message.as_bytes())]);
        let client_sig = stored_key.hmac_sha256(&auth_message);
        let proof = client_key.xor(&client_sig)?.base64();
        let server_sig = server_key.hmac_sha256(&auth_message);
        let body = SealedValue::compose(&[
            Part::Public(without_proof.as_bytes()),
            Part::Public(b",p="),
            Part::Value(&proof),
        ]);
        Ok((message(&body), ScramLink(server_sig)))
    }
}

#[cfg(test)]
#[path = "transferred_tests.rs"]
mod tests;
