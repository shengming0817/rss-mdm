use crate::{core::*, db::*};
use rss_contract::Timepoint;
use rss_request_context::TenantId;
use rss_transactional_messaging_postgres::PgError;
use serde_json::{Value, json};
fn array(v: &Value, n: usize) -> Result<&[Value], PgError> {
    v.as_array()
        .filter(|a| a.len() == n)
        .map(Vec::as_slice)
        .ok_or_else(|| fault("codec::array"))
}
fn s(v: &Value) -> Result<&str, PgError> {
    v.as_str().ok_or_else(|| fault("codec::s"))
}
fn n(v: &Value) -> Result<u64, PgError> {
    v.as_u64().ok_or_else(|| fault("codec::n"))
}
fn id(v: &Value) -> Result<Id, PgError> {
    data("codec::id", Id::new(s(v)?))
}
fn optional(v: &Value) -> Result<Option<Id>, PgError> {
    if v.is_null() {
        Ok(None)
    } else {
        Ok(Some(id(v)?))
    }
}
pub(crate) fn kind(k: Kind) -> u8 {
    match k {
        Kind::Software => 0,
        Kind::Script => 1,
        Kind::Configuration => 2,
    }
}
fn read_kind(v: &Value) -> Result<Kind, PgError> {
    match n(v)? {
        0 => Ok(Kind::Software),
        1 => Ok(Kind::Script),
        2 => Ok(Kind::Configuration),
        _ => Err(fault("codec::read_kind")),
    }
}
fn artifact(a: &Artifact) -> Value {
    json!([a.reference().as_str(), a.length(), a.digest().bytes()])
}
fn read_artifact(v: &Value) -> Result<Artifact, PgError> {
    let a = array(v, 3)?;
    data(
        "codec::read_artifact",
        Artifact::new(
            id(&a[0])?,
            n(&a[1])?,
            Digest::from_bytes(data(
                "codec::read_artifact",
                serde_json::from_value(a[2].clone()),
            )?),
        ),
    )
}
fn declaration(d: &Declaration) -> Value {
    match d {
        Declaration::Software {
            package,
            artifact: a,
            install,
            detect,
            uninstall,
        } => json!([
            0,
            artifact(a),
            package.source().as_str(),
            package.package().as_str(),
            package.version().as_str(),
            install.as_str(),
            detect.as_str(),
            uninstall.as_ref().map(Id::as_str)
        ]),
        Declaration::Script {
            artifact: a,
            interpreter,
            detect,
        } => json!([1, artifact(a), interpreter.as_str(), detect.as_str()]),
        Declaration::Configuration {
            artifact: a,
            schema,
            apply,
            detect,
            remove,
        } => json!([
            2,
            artifact(a),
            schema.as_str(),
            apply.as_str(),
            detect.as_str(),
            remove.as_ref().map(Id::as_str)
        ]),
    }
}
fn read_declaration(v: &Value) -> Result<Declaration, PgError> {
    let a = v
        .as_array()
        .ok_or_else(|| fault("codec::read_declaration"))?;
    match n(a.first().ok_or_else(|| fault("codec::read_declaration"))?)? {
        0 => {
            let a = array(v, 8)?;
            Ok(Declaration::Software {
                artifact: read_artifact(&a[1])?,
                package: Package::new(id(&a[2])?, id(&a[3])?, id(&a[4])?),
                install: id(&a[5])?,
                detect: id(&a[6])?,
                uninstall: optional(&a[7])?,
            })
        }
        1 => {
            let a = array(v, 4)?;
            Ok(Declaration::Script {
                artifact: read_artifact(&a[1])?,
                interpreter: id(&a[2])?,
                detect: id(&a[3])?,
            })
        }
        2 => {
            let a = array(v, 6)?;
            Ok(Declaration::Configuration {
                artifact: read_artifact(&a[1])?,
                schema: id(&a[2])?,
                apply: id(&a[3])?,
                detect: id(&a[4])?,
                remove: optional(&a[5])?,
            })
        }
        _ => Err(fault("codec::read_declaration")),
    }
}
pub(crate) fn version(v: &Version) -> Result<Vec<u8>, PgError> {
    encode(&json!([
        1,
        v.tenant().to_string(),
        v.resource().as_str(),
        v.label().as_str(),
        kind(v.kind()),
        v.variants()
            .iter()
            .map(|v| json!([
                match v.platform() {
                    Platform::Windows => 0,
                    Platform::MacOS => 1,
                },
                match v.architecture() {
                    Architecture::X86_64 => 0,
                    Architecture::Aarch64 => 1,
                },
                v.key().as_str(),
                declaration(v.declaration())
            ]))
            .collect::<Vec<_>>(),
        v.digest().bytes()
    ]))
}
pub(crate) fn read_version(bytes: &[u8]) -> Result<Version, PgError> {
    let v: Value = decode(bytes)?;
    let a = array(&v, 7)?;
    if n(&a[0])? != 1 {
        return Err(fault("codec::read_version"));
    }
    let t = data("codec::read_version", TenantId::parse(s(&a[1])?))?;
    let items = a[5]
        .as_array()
        .ok_or_else(|| fault("codec::read_version"))?;
    if items.len() > 64 {
        return Err(fault("codec::read_version"));
    }
    let variants = items
        .iter()
        .map(|v| {
            let a = array(v, 4)?;
            let platform = match n(&a[0])? {
                0 => Platform::Windows,
                1 => Platform::MacOS,
                _ => return Err(fault("codec::read_version")),
            };
            let architecture = match n(&a[1])? {
                0 => Architecture::X86_64,
                1 => Architecture::Aarch64,
                _ => return Err(fault("codec::read_version")),
            };
            Ok(Variant::new(
                platform,
                architecture,
                id(&a[2])?,
                read_declaration(&a[3])?,
            ))
        })
        .collect::<Result<Vec<_>, PgError>>()?;
    let value = data(
        "codec::read_version",
        Version::new(t, id(&a[2])?, id(&a[3])?, read_kind(&a[4])?, variants),
    )?;
    let expected: [u8; 32] = data("codec::read_version", serde_json::from_value(a[6].clone()))?;
    if value.digest().bytes() != expected {
        return Err(fault("codec::read_version"));
    }
    Ok(value)
}
fn state(s: State) -> u8 {
    match s {
        State::Frozen => 0,
        State::Active => 1,
        State::Deprecated => 2,
        State::Archived => 3,
    }
}
fn read_state(v: &Value) -> Result<State, PgError> {
    match n(v)? {
        0 => Ok(State::Frozen),
        1 => Ok(State::Active),
        2 => Ok(State::Deprecated),
        3 => Ok(State::Archived),
        _ => Err(fault("codec::read_state")),
    }
}
pub(crate) fn header(r: &Resource) -> Result<Vec<u8>, PgError> {
    let s = r.snapshot();
    encode(&json!([
        1,
        s.tenant.to_string(),
        s.key.as_str(),
        kind(s.kind),
        s.changed_at.map(|t| t.unix_seconds()),
        s.versions
            .iter()
            .map(|v| json!([v.version.label().as_str(), state(v.state)]))
            .collect::<Vec<_>>()
    ]))
}
pub(crate) fn restore(
    bytes: &[u8],
    mut versions: std::collections::BTreeMap<String, Version>,
) -> Result<Resource, PgError> {
    let v: Value = decode(bytes)?;
    let a = array(&v, 6)?;
    if n(&a[0])? != 1 {
        return Err(fault("codec::restore"));
    }
    let states = a[5].as_array().ok_or_else(|| fault("codec::restore"))?;
    if states.len() > 10_000 || states.len() != versions.len() {
        return Err(fault("codec::restore"));
    }
    let entries = states
        .iter()
        .map(|v| {
            let a = array(v, 2)?;
            Ok(StoredVersion {
                version: versions
                    .remove(s(&a[0])?)
                    .ok_or_else(|| fault("codec::restore"))?,
                state: read_state(&a[1])?,
            })
        })
        .collect::<Result<Vec<_>, PgError>>()?;
    let changed_at = if a[4].is_null() {
        None
    } else {
        Some(data(
            "codec::restore",
            Timepoint::try_from(a[4].as_i64().ok_or_else(|| fault("codec::restore"))?),
        )?)
    };
    data(
        "codec::restore",
        Resource::restore(ResourceSnapshot {
            tenant: data("codec::restore", TenantId::parse(s(&a[1])?))?,
            key: id(&a[2])?,
            kind: read_kind(&a[3])?,
            changed_at,
            versions: entries,
        }),
    )
}
