// SPDX-License-Identifier: Apache-2.0
use super::decode::{decode, hex};
use super::*;
fn strict(s: &str) -> Result<Bytes, &'static str> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if b.get(i + 1).and_then(|&c| hex(c)).is_none()
                || b.get(i + 2).and_then(|&c| hex(c)).is_none()
            {
                return Err("invalid percent encoding");
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    let out = decode(s);
    core::str::from_utf8(&out).map_err(|_| "invalid percent encoding")?;
    Ok(out)
}

fn remember(echoes: &mut Vec<Cred>, raw: &str, decoded: &Bytes) {
    echoes.push(Cred::captured(Zeroizing::new(raw.as_bytes().to_vec())));
    echoes.push(Cred::captured(decoded.clone()));
}

pub(super) fn visit_postgres_keyword<'a>(
    text: &'a str,
    mut visit: impl FnMut(&'a str, Bytes, &'a str) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let mut i = 0;
    let next = |i: usize| text[i..].chars().next();
    loop {
        while next(i).is_some_and(char::is_whitespace) {
            i += next(i).expect("character").len_utf8();
        }
        if i == text.len() {
            return Ok(());
        }
        let start = i;
        while next(i).is_some_and(|c| c != '=' && !c.is_whitespace()) {
            i += next(i).expect("character").len_utf8();
        }
        let key = &text[start..i];
        while next(i).is_some_and(char::is_whitespace) {
            i += next(i).expect("character").len_utf8();
        }
        if next(i) != Some('=') {
            return Err("unexpected EOF: a connection parameter without `=` (expected key=value)");
        }
        i += 1;
        while next(i).is_some_and(char::is_whitespace) {
            i += next(i).expect("character").len_utf8();
        }
        let mut value = Zeroizing::new(String::with_capacity(text.len() - i));
        if next(i) == Some('\'') {
            i += 1;
            loop {
                let Some(c) = next(i) else {
                    return Err("unterminated quoted connection parameter value");
                };
                i += c.len_utf8();
                if c == '\'' {
                    break;
                }
                if c == '\\' {
                    let Some(c) = next(i) else {
                        return Err("unterminated quoted connection parameter value");
                    };
                    i += c.len_utf8();
                    value.push(c);
                } else {
                    value.push(c);
                }
            }
        } else {
            while let Some(c) = next(i).filter(|c| !c.is_whitespace()) {
                i += c.len_utf8();
                if c == '\\' {
                    if let Some(c) = next(i) {
                        i += c.len_utf8();
                        value.push(c);
                    }
                } else {
                    value.push(c);
                }
            }
        }
        let bytes = Zeroizing::new(value.as_bytes().to_vec());
        visit(key, bytes, &text[start..i])?;
    }
}

fn postgres_policy(mut url: CredUrl, require_auth: Option<Bytes>) -> CredUrl {
    let floor = require_auth
        .as_ref()
        .and_then(|v| core::str::from_utf8(v).ok())
        .and_then(|v| RequireAuth::parse(v).ok())
        .unwrap_or(RequireAuth::DEFAULT);
    url.floor = floor;
    if let Some(password) = &mut url.password {
        password.floor = floor;
    }
    url
}

pub(super) fn postgres(text: &str) -> Result<CredUrl, &'static str> {
    let mut echoes = Vec::new();
    let mut found = None;
    let mut require_auth = None;
    let prefix = text
        .strip_prefix("postgres://")
        .map(|r| ("postgres://", r))
        .or_else(|| {
            text.strip_prefix("postgresql://")
                .map(|r| ("postgresql://", r))
        });
    let Some((head, rest)) = prefix else {
        let mut kept = Vec::new();
        visit_postgres_keyword(text, |key, value, raw| {
            if key == "password" {
                let raw_value = raw.split_once('=').expect("visited keyword").1.trim_start();
                let raw_value = raw_value
                    .strip_prefix('\'')
                    .and_then(|v| v.strip_suffix('\''))
                    .unwrap_or(raw_value);
                remember(&mut echoes, raw_value, &value);
                found = Some((value, PasswordAt::Keyword));
            } else {
                if key == "require_auth" {
                    require_auth = Some(value.clone());
                }
                let value = core::str::from_utf8(&value).expect("keyword characters are UTF-8");

                kept.push(format!(
                    "{key}='{}'",
                    value.replace('\\', "\\\\").replace('\'', "\\'")
                ));
            }
            Ok(())
        })?;
        return Ok(postgres_policy(
            captured(kept.join(" "), found, echoes),
            require_auth,
        ));
    };
    let (main, query) = rest
        .split_once('?')
        .map_or((rest, None), |(m, q)| (m, Some(q)));
    let authority_end = main.find('/').unwrap_or(main.len());
    let authority = &main[..authority_end];
    if !authority.contains('@') && !authority.starts_with('[') {
        if let Some((_, port)) = authority.rsplit_once(':') {
            if rest[authority.len()..].contains('@') && port.parse::<u16>().is_err() {
                return Err(
                    if query
                        .is_some_and(|q| q.split('&').any(|p| !p.is_empty() && !p.contains('=')))
                    {
                        "invalid query parameter (expected key=value)"
                    } else {
                        "invalid value for option `port`"
                    },
                );
            }
        }
    }
    let mut public = String::with_capacity(text.len());
    public.push_str(head);
    if let Some((userinfo, host)) = authority.rsplit_once('@') {
        if let Some((user, pass)) = userinfo.split_once(':') {
            let b = strict(pass)?;
            remember(&mut echoes, pass, &b);
            found = Some((b, PasswordAt::Userinfo));
            public.push_str(user);
        } else {
            public.push_str(userinfo);
        }
        public.push('@');
        public.push_str(host);
    } else {
        public.push_str(authority);
    }
    public.push_str(&main[authority_end..]);
    if let Some(query) = query {
        let mut kept = Vec::new();
        for pair in query.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let key = strict(key)?;
                if &key[..] == b"require_auth" {
                    require_auth = Some(strict(value)?);
                }
                if &key[..] == b"password" {
                    let b = strict(value)?;
                    remember(&mut echoes, value, &b);
                    found = Some((b, PasswordAt::Query("password")));
                    continue;
                }
                if &key[..] == b"sslmode" {
                    let value = strict(value)?;
                    let value = core::str::from_utf8(&value).expect("strict UTF-8");

                    if matches!(
                        value,
                        "disable" | "allow" | "prefer" | "require" | "verify-ca" | "verify-full"
                    ) {
                        kept.push(format!("sslmode={value}"));
                        continue;
                    }
                }
            }
            kept.push(pair.to_owned());
        }
        if !kept.is_empty() {
            public.push('?');
            public.push_str(&kept.join("&"));
        }
    }
    Ok(postgres_policy(
        captured(public, found, echoes),
        require_auth,
    ))
}
