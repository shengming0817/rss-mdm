use super::*;
use rss_identity_core::profile::{Attribute, Profile};
use rss_identity_postgres::{ProfileStatus, ProfileView, TrustedProfile};
fn attribute<T: serde::Serialize>(v: &Attribute<T>) -> Value {
    match v {
        Attribute::Available { value } => json!({"status":"available","value":value}),
        Attribute::Missing => json!({"status":"missing"}),
        Attribute::Invalid => json!({"status":"invalid"}),
        Attribute::NotConfigured => json!({"status":"not_configured"}),
    }
}
fn fixed(v: &Profile) -> Value {
    json!({"displayName":attribute(&v.display_name),"username":attribute(&v.username),"email":attribute(&v.email),"emailVerified":attribute(&v.email_verified)})
}
fn document(v: &Profile) -> Value {
    let mut value = serde_json::Map::new();
    for (name, v) in [
        ("displayName", v.display_name.value()),
        ("username", v.username.value()),
        ("email", v.email.value()),
    ] {
        if let Some(v) = v {
            value.insert(name.into(), json!(v));
        }
    }
    if let Some(v) = v.email_verified.value() {
        value.insert("emailVerified".into(), json!(v));
    }
    if let Some(v) = v.extensions.value() {
        value.insert("extensions".into(), Value::Object(v.object().clone()));
    }
    Value::Object(value)
}
fn status(status: ProfileStatus) -> &'static str {
    match status {
        ProfileStatus::Available => "available",
        ProfileStatus::Missing => "missing",
        ProfileStatus::Expired => "expired",
        ProfileStatus::Unavailable => "unavailable",
    }
}
fn projected(
    definition: &model::Definition,
    view: Option<&ProfileView>,
    preview: bool,
) -> (&'static str, Option<Value>) {
    let Some(d) = &definition.value else {
        return ("unavailable", None);
    };
    let Some(view) = view else {
        return ("unavailable", None);
    };
    if view.status != ProfileStatus::Available {
        return (status(view.status), None);
    }
    if view
        .collected_at_micros
        .is_none_or(|t| t <= definition.collected_after_micros)
    {
        return ("pending_login", None);
    }
    let Some(profile) = &view.profile else {
        return ("unavailable", None);
    };
    let document = document(profile);
    let Some(value) = document.pointer(&d.pointer) else {
        let state = match d.pointer.split('/').nth(1) {
            Some("displayName") => missing_state(&profile.display_name),
            Some("username") => missing_state(&profile.username),
            Some("email") => missing_state(&profile.email),
            Some("emailVerified") => missing_state(&profile.email_verified),
            Some("extensions") => missing_state(&profile.extensions),
            _ => "missing",
        };
        return (state, None);
    };
    if !model::conforms(value, d) {
        return ("invalid", None);
    }
    if preview && d.sensitive {
        ("redacted", None)
    } else {
        ("available", Some(value.clone()))
    }
}
fn missing_state<T>(value: &Attribute<T>) -> &'static str {
    match value {
        Attribute::Invalid => "invalid",
        Attribute::NotConfigured => "not_configured",
        _ => "missing",
    }
}
fn visible(v: &DefinitionValue, own: bool, read: bool) -> bool {
    match v.visibility {
        Visibility::SelfOnly => own,
        Visibility::ProfilesRead => read,
        Visibility::Both => own || read,
    }
}
pub(super) fn response(
    principal: rss_identity_core::PrincipalId,
    query: ProfileQuery,
    definitions: &[model::Definition],
    profiles: &[TrustedProfile],
    own: bool,
    read: bool,
) -> Result<Value, Error> {
    let views = profiles
        .iter()
        .map(|v| v.view().map_err(identity_error))
        .collect::<Result<Vec<_>, _>>()?;
    let mut fields = Vec::new();
    let mut required = 0;
    let mut complete = 0;
    for definition in definitions {
        let Some(d) = &definition.value else {
            continue;
        };
        if !d.enabled || !visible(d, own, read) {
            continue;
        }
        let source = model::source(&d.source)?;
        let view = views.iter().find(|v| v.source == Some(source)).copied();
        let (state, value) = projected(definition, view, query.preview);
        if d.required {
            required += 1;
            if matches!(state, "available" | "redacted") {
                complete += 1;
            }
        }
        fields.push(json!({"fieldId":definition.field_id,"revision":definition.revision,"key":d.key,"displayName":d.display_name,"source":d.source,"valueType":d.value_type,"sensitive":d.sensitive,"displayUse":d.display_use,"required":d.required,"status":state,"value":value}));
    }
    let profiles=views.iter().map(|v|json!({"source":v.source.map(model::source_dto),"status":status(v.status),"snapshotId":v.snapshot_id,"observedAt":v.observed_at,"collectedAtMicros":v.collected_at_micros,"expiresAt":v.expires_at,"fixed":if v.status==ProfileStatus::Available {v.profile.as_ref().map(fixed)} else {None}})).collect::<Vec<_>>();
    Ok(
        json!({"principalId":principal.as_uuid(),"view":query.view,"profiles":profiles,"fields":fields,"completeness":{"required":required,"complete":complete,"missing":required-complete}}),
    )
}
