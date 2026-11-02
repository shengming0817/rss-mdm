//! Pure configuration precedence. Qualification of managed inputs belongs to the real verifier.
use rss_mdm_agent_wire::{
    da::{Configuration, ConfigurationField, DeliveryPermission, SourceState},
    runtime::AccessConfiguration,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    ManagedMandatory,
    Da,
    SafeDefault,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FieldDecision {
    pub field: ConfigurationField,
    pub source: Source,
    pub locked: bool,
    pub backend_ignored: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resolution {
    pub configuration: Option<AccessConfiguration>,
    pub fields: Vec<FieldDecision>,
    pub blocked: Option<SourceState>,
}
impl Resolution {
    fn blocked(reason: SourceState) -> Self {
        Self {
            configuration: None,
            fields: Vec::new(),
            blocked: Some(reason),
        }
    }
}

/// Called only after issuer, scope, time and platform qualification. No HTTP DTO accepts
/// these inputs as trusted. Server account admission always uses the backend configuration.
pub fn resolve(
    backend: Option<&AccessConfiguration>,
    managed: &[&Configuration],
    state: SourceState,
    locked: &[ConfigurationField],
) -> Result<Resolution, crate::Error> {
    if managed.len() > 16 {
        return Err(crate::Error);
    }
    if !matches!(state, SourceState::Present | SourceState::Missing) {
        return Ok(Resolution::blocked(state));
    }
    if state == SourceState::Missing && !locked.is_empty() {
        return Ok(Resolution::blocked(SourceState::Missing));
    }
    let Some(backend) = backend else {
        if !managed.is_empty() || !locked.is_empty() {
            return Ok(Resolution::blocked(SourceState::Missing));
        }
        return Ok(Resolution {
            configuration: None,
            fields: [ConfigurationField::Mac, ConfigurationField::Windows]
                .into_iter()
                .map(|field| FieldDecision {
                    field,
                    source: Source::SafeDefault,
                    locked: false,
                    backend_ignored: false,
                })
                .collect(),
            blocked: None,
        });
    };
    backend.validate().map_err(|_| crate::Error)?;
    let mut output = backend.clone();
    let mut decisions = Vec::new();
    for field in [ConfigurationField::Mac, ConfigurationField::Windows] {
        let mut selected: Option<&Configuration> = None;
        for candidate in managed {
            candidate.validate().map_err(|_| crate::Error)?;
            if candidate.delivery != DeliveryPermission::ManagedMandatory {
                return Err(crate::Error);
            }
            if !candidate.managed_fields.contains(&field) {
                continue;
            }
            if let Some(previous) = selected {
                let conflict = match field {
                    ConfigurationField::Mac => previous.content.mac != candidate.content.mac,
                    ConfigurationField::Windows => {
                        previous.content.windows != candidate.content.windows
                    }
                };
                if conflict {
                    return Ok(Resolution::blocked(SourceState::Conflict));
                }
            }
            selected = Some(candidate);
        }
        if selected.is_none() && locked.contains(&field) {
            return Ok(Resolution::blocked(SourceState::Missing));
        }
        if let Some(selected) = selected {
            match field {
                ConfigurationField::Mac => output.mac = selected.content.mac.clone(),
                ConfigurationField::Windows => output.windows = selected.content.windows.clone(),
            }
        }
        decisions.push(FieldDecision {
            field,
            source: if selected.is_some() {
                Source::ManagedMandatory
            } else {
                Source::Da
            },
            locked: selected.is_some(),
            backend_ignored: selected.is_some(),
        });
    }
    if output.validate().is_err() {
        return Ok(Resolution::blocked(SourceState::Invalid));
    }
    Ok(Resolution {
        configuration: Some(output),
        fields: decisions,
        blocked: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_mdm_agent_wire::{
        da::{Audience, NativeExpectation},
        runtime::{AccessRole, AccessWindowsConfiguration, AccessWindowsKind},
    };
    use uuid::Uuid;
    fn backend() -> AccessConfiguration {
        AccessConfiguration {
            mac: None,
            windows: AccessWindowsConfiguration::Whfb,
            self_enrollment: false,
            enabled: true,
            role: Some(AccessRole::Standard),
        }
    }
    fn managed() -> Configuration {
        let mut content = backend();
        content.windows = AccessWindowsConfiguration::RssFactor {
            accounts: vec![AccessWindowsKind::Local],
        };
        content.role = Some(AccessRole::Administrator);
        content.self_enrollment = true;
        Configuration {
            service_id: Uuid::from_u128(1),
            tenant: Uuid::from_u128(2),
            id: Uuid::from_u128(3),
            version: Uuid::from_u128(4),
            revision: 1,
            trust_revision: 1,
            operation_id: Uuid::from_u128(5),
            audience: Audience::Tenant,
            delivery: DeliveryPermission::ManagedMandatory,
            managed_fields: vec![ConfigurationField::Windows],
            issued_at: 1,
            expires_at: 100,
            native: NativeExpectation::new(&content, vec![], None).unwrap(),
            content,
        }
    }
    #[test]
    fn managed_groups_cannot_override_server_authorization() {
        let backend = backend();
        let candidate = managed();
        let result = resolve(Some(&backend), &[&candidate], SourceState::Present, &[]).unwrap();
        let actual = result.configuration.unwrap();
        assert_eq!(actual.windows, candidate.content.windows);
        assert_eq!(actual.role, backend.role);
        assert!(!actual.self_enrollment);
        assert!(result.fields[1].locked && result.fields[1].backend_ignored);
        assert!(!result.fields[0].locked);
    }
    #[test]
    fn unavailable_or_conflicting_protected_sources_never_fall_back() {
        let backend = backend();
        let first = managed();
        let mut other = managed();
        other.content.windows = AccessWindowsConfiguration::Whfb;
        other.native = NativeExpectation::new(&other.content, vec![], None).unwrap();
        assert_eq!(
            resolve(Some(&backend), &[&first, &other], SourceState::Present, &[])
                .unwrap()
                .blocked,
            Some(SourceState::Conflict)
        );
        for state in [
            SourceState::Missing,
            SourceState::Invalid,
            SourceState::Expired,
            SourceState::ReadFailed,
            SourceState::Withdrawn,
            SourceState::Conflict,
        ] {
            assert_eq!(
                resolve(Some(&backend), &[], state, &[ConfigurationField::Windows])
                    .unwrap()
                    .blocked,
                Some(state)
            );
        }
        let defaults = resolve(None, &[], SourceState::Missing, &[]).unwrap();
        assert!(defaults.configuration.is_none());
        assert!(defaults.blocked.is_none());
        assert!(
            defaults
                .fields
                .iter()
                .all(|v| v.source == Source::SafeDefault && !v.locked)
        );
    }
}
