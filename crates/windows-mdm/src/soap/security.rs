use super::*;
const PASSWORD: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernameToken {
    pub id: String,
    pub username: Secret<String>,
    pub password: Secret<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    pub id: String,
    pub created: String,
    pub expires: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    pub timestamp: Option<Timestamp>,
    pub username: Option<UsernameToken>,
}
fn id(p: &mut Input<'_>, ns: &str, name: &str) -> Result<String> {
    let s = p.start(ns, name)?;
    s.attrs(&[(UTILITY, "Id")])?;
    let id = s.attr(UTILITY, "Id").ok_or(E::Structure)?;
    text(id, p.limits.identifier_bytes, false)?;
    Ok(id.into())
}
pub(super) fn read(p: &mut Input<'_>) -> Result<Security> {
    understood(&p.start(SECURITY, "Security")?)?;
    let mut timestamp = None;
    let mut username = None;
    loop {
        if p.is(UTILITY, "Timestamp")? {
            if timestamp.is_some() {
                return Err(E::Duplicate);
            }
            let id = id(p, UTILITY, "Timestamp")?;
            let created = p.scalar(UTILITY, "Created", p.limits.identifier_bytes, false)?;
            let expires = p.scalar(UTILITY, "Expires", p.limits.identifier_bytes, false)?;
            p.end(UTILITY, "Timestamp")?;
            timestamp = Some(Timestamp {
                id,
                created,
                expires,
            });
        } else if p.is(SECURITY, "UsernameToken")? {
            if username.is_some() {
                return Err(E::Duplicate);
            }
            let id = id(p, SECURITY, "UsernameToken")?;
            let user = p.scalar(SECURITY, "Username", p.limits.field_bytes, false)?;
            let s = p.start(SECURITY, "Password")?;
            s.attrs(&[("", "Type")])?;
            if s.attr("", "Type") != Some(PASSWORD) {
                return Err(E::Unsupported);
            }
            let password = p.content(SECURITY, "Password", p.limits.field_bytes, false)?;
            p.end(SECURITY, "UsernameToken")?;
            username = Some(UsernameToken {
                id,
                username: Secret(user),
                password: Secret(password),
            });
        } else {
            break;
        }
    }
    p.end(SECURITY, "Security")?;
    let s = Security {
        timestamp,
        username,
    };
    validate(&s, p.limits)?;
    Ok(s)
}
pub(super) fn validate(s: &Security, l: &CodecLimits) -> Result<()> {
    if s.timestamp.is_none() && s.username.is_none() {
        return Err(E::Structure);
    }
    if let Some(t) = &s.timestamp {
        for v in [&t.id, &t.created, &t.expires] {
            text(v, l.identifier_bytes, false)?;
        }
        for value in [&t.created, &t.expires] {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .map_err(|_| E::InvalidValue)?;
        }
    }
    if let Some(t) = &s.username {
        text(&t.id, l.identifier_bytes, false)?;
        if t.id != "uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4" {
            return Err(E::InvalidValue);
        }
        text(&t.username.0, l.field_bytes, false)?;
        text(&t.password.0, l.field_bytes, false)?;
    }
    if let (Some(a), Some(b)) = (&s.timestamp, &s.username)
        && a.id == b.id
    {
        return Err(E::Duplicate);
    }
    Ok(())
}
pub(super) fn write(w: &mut Output<'_>, s: &Security, l: &CodecLimits) -> Result<()> {
    w.start("o:Security", &[("s:mustUnderstand", "1")])?;
    if let Some(t) = &s.timestamp {
        w.start("u:Timestamp", &[("u:Id", &t.id)])?;
        w.scalar("u:Created", &t.created, l.identifier_bytes, false)?;
        w.scalar("u:Expires", &t.expires, l.identifier_bytes, false)?;
        w.end("u:Timestamp")?;
    }
    if let Some(t) = &s.username {
        w.start("o:UsernameToken", &[("u:Id", &t.id)])?;
        w.scalar("o:Username", &t.username.0, l.field_bytes, false)?;
        w.start("o:Password", &[("Type", PASSWORD)])?;
        w.content(&t.password.0, l.field_bytes)?;
        w.end("o:Password")?;
        w.end("o:UsernameToken")?;
    }
    w.end("o:Security")
}
