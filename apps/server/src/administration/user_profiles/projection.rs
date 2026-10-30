use super::*;
use rss_identity_core::profile::{Attribute as IdentityAttribute, Profile as IdentityProfile};
use rss_identity_postgres::{ProfileStatus as IdentityStatus, ProfileView, TrustedProfile};
fn attribute<T: Clone>(v: &IdentityAttribute<T>) -> Attribute<T> {
    match v {
        IdentityAttribute::Available { value } => Attribute::Available {
            value: value.clone(),
        },
        IdentityAttribute::Missing => Attribute::Missing,
        IdentityAttribute::Invalid => Attribute::Invalid,
        IdentityAttribute::NotConfigured => Attribute::NotConfigured,
    }
}
fn fixed(v: &IdentityProfile) -> Fixed {
    Fixed {
        display_name: attribute(&v.display_name),
        username: attribute(&v.username),
        email: attribute(&v.email),
        email_verified: attribute(&v.email_verified),
    }
}
fn document(v: &IdentityProfile) -> Value {
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
fn status(status: IdentityStatus) -> ProfileStatus {
    match status {
        IdentityStatus::Available => ProfileStatus::Available,
        IdentityStatus::Missing => ProfileStatus::Missing,
        IdentityStatus::Expired => ProfileStatus::Expired,
        IdentityStatus::Unavailable => ProfileStatus::Unavailable,
    }
}
fn projected(
    definition: &model::Definition,
    view: Option<&ProfileView>,
    preview: bool,
) -> (FieldStatus, Option<Value>) {
    let Some(d) = &definition.value else {
        return (FieldStatus::Unavailable, None);
    };
    let Some(view) = view else {
        return (FieldStatus::Unavailable, None);
    };
    if view.status != IdentityStatus::Available {
        return (
            match view.status {
                IdentityStatus::Available => FieldStatus::Available,
                IdentityStatus::Missing => FieldStatus::Missing,
                IdentityStatus::Expired => FieldStatus::Expired,
                IdentityStatus::Unavailable => FieldStatus::Unavailable,
            },
            None,
        );
    }
    if view
        .collected_at_micros
        .is_none_or(|t| t <= definition.collected_after_micros)
    {
        return (FieldStatus::PendingLogin, None);
    }
    let Some(profile) = &view.profile else {
        return (FieldStatus::Unavailable, None);
    };
    let document = document(profile);
    let Some(value) = document.pointer(&d.pointer) else {
        let state = match d.pointer.split('/').nth(1) {
            Some("displayName") => missing_state(&profile.display_name),
            Some("username") => missing_state(&profile.username),
            Some("email") => missing_state(&profile.email),
            Some("emailVerified") => missing_state(&profile.email_verified),
            Some("extensions") => missing_state(&profile.extensions),
            _ => FieldStatus::Missing,
        };
        return (state, None);
    };
    if value.is_null() {
        return (FieldStatus::Missing, None);
    }
    if !model::conforms(value, d) {
        return (FieldStatus::Invalid, None);
    }
    if preview && d.sensitive {
        (FieldStatus::Redacted, None)
    } else {
        (FieldStatus::Available, Some(value.clone()))
    }
}
fn missing_state<T>(value: &IdentityAttribute<T>) -> FieldStatus {
    match value {
        IdentityAttribute::Invalid => FieldStatus::Invalid,
        IdentityAttribute::NotConfigured => FieldStatus::NotConfigured,
        _ => FieldStatus::Missing,
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
) -> Result<Profile, Error> {
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
            if matches!(state, FieldStatus::Available | FieldStatus::Redacted) {
                complete += 1;
            }
        }
        fields.push(FieldView {
            field_id: definition.field_id,
            revision: definition.revision,
            key: d.key.clone(),
            display_name: d.display_name.clone(),
            source: d.source.clone(),
            value_type: d.value_type,
            sensitive: d.sensitive,
            display_use: d.display_use,
            required: d.required,
            status: state,
            value,
        });
    }
    let profiles = views
        .iter()
        .map(|v| ObservedProfile {
            source: v.source.map(model::source_dto),
            status: status(v.status),
            snapshot_id: v.snapshot_id,
            provider_config_version: v.provider_config_version,
            source_revision: v.source_revision,
            observed_at: v.observed_at,
            collected_at_micros: v.collected_at_micros,
            expires_at: v.expires_at,
            fixed: if !query.preview && v.status == IdentityStatus::Available {
                v.profile.as_ref().map(fixed)
            } else {
                None
            },
        })
        .collect();
    Ok(Profile {
        principal_id: principal.as_uuid(),
        view: query.view,
        profiles,
        fields,
        completeness: Completeness {
            required,
            complete,
            missing: required - complete,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn null_and_absence_are_missing_while_false_and_zero_remain_values() {
        let profile = IdentityProfile {
            display_name: IdentityAttribute::Missing,
            username: IdentityAttribute::Missing,
            email: IdentityAttribute::Missing,
            email_verified: IdentityAttribute::Missing,
            extensions: IdentityAttribute::Available {
                value: rss_identity_core::profile::Extensions::try_from(
                    json!({"null":null,"false":false,"zero":0}),
                )
                .unwrap(),
            },
        };
        let view = ProfileView {
            instance_id: String::new(),
            tenant_id: String::new(),
            principal_id: String::new(),
            source: Some(rss_identity_postgres::ProfileSource::IdentityLocal),
            status: IdentityStatus::Available,
            snapshot_id: Some(Uuid::new_v4()),
            provider_config_version: None,
            source_revision: Some(1),
            observed_at: Some(1),
            collected_at_micros: Some(1),
            expires_at: Some(100),
            profile: Some(profile),
        };
        let mut definition = model::Definition {
            field_id: Uuid::new_v4(),
            revision: 1,
            collected_after_micros: 0,
            value: Some(DefinitionValue {
                key: "test".into(),
                display_name: "Test".into(),
                source: ProfileSource::IdentityLocal,
                pointer: String::new(),
                value_type: ValueType::Boolean,
                max_length: None,
                max_items: None,
                minimum: None,
                maximum: None,
                enabled: true,
                sensitive: false,
                visibility: Visibility::Both,
                display_use: DisplayUse::Profile,
                required: true,
                use_existing_observation: true,
            }),
        };
        for (pointer, kind, state, value) in [
            (
                "/extensions/null",
                ValueType::String,
                FieldStatus::Missing,
                None,
            ),
            (
                "/extensions/absent",
                ValueType::String,
                FieldStatus::Missing,
                None,
            ),
            (
                "/extensions/false",
                ValueType::Boolean,
                FieldStatus::Available,
                Some(json!(false)),
            ),
            (
                "/extensions/zero",
                ValueType::Integer,
                FieldStatus::Available,
                Some(json!(0)),
            ),
            (
                "/extensions/false",
                ValueType::Integer,
                FieldStatus::Invalid,
                None,
            ),
        ] {
            let v = definition.value.as_mut().unwrap();
            v.pointer = pointer.into();
            v.value_type = kind;
            assert_eq!(projected(&definition, Some(&view), false), (state, value));
        }
    }
}
