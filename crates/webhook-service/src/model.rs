use crate::Error;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum EventType {
    #[serde(rename = "device.registered")]
    Registered,
    #[serde(rename = "device.retired")]
    Retired,
    #[serde(rename = "policy.execution.terminal")]
    PolicyTerminal,
    #[serde(rename = "compliance.status.changed")]
    ComplianceChanged,
    #[serde(rename = "device.access.changed")]
    DeviceAccessChanged,
    #[serde(rename = "webhook.test")]
    Test,
}
impl EventType {
    pub const BUSINESS: [Self; 5] = [
        Self::Registered,
        Self::Retired,
        Self::PolicyTerminal,
        Self::ComplianceChanged,
        Self::DeviceAccessChanged,
    ];
    pub const fn permission(self) -> &'static str {
        match self {
            Self::Registered | Self::Retired | Self::Test => "inventory_read",
            Self::PolicyTerminal => "operation_read",
            Self::ComplianceChanged => "compliance_read",
            Self::DeviceAccessChanged => "account_write",
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Event {
    pub event_id: Uuid,
    pub event_type: EventType,
    pub version: u8,
    pub occurred_at: i64,
    pub tenant_id: Uuid,
    pub device_id: String,
    pub data: EventData,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum EventData {
    DeviceAccess {
        operation_id: Uuid,
        binding_id: Uuid,
        registration_id: Uuid,
        registration_generation: i64,
        instance_id: Uuid,
        principal_id: Uuid,
        previous_principal: Option<Uuid>,
        binding_generation: i64,
        factor_generation: i64,
        revision: i64,
        revoked: bool,
        phase: String,
    },
    Registration {
        registration_id: Uuid,
        generation: i64,
        channel: String,
        state: String,
    },
    Policy {
        run_id: Uuid,
        policy_version: Uuid,
        registration_id: Uuid,
        generation: i64,
        status: String,
    },
    Compliance {
        rule_id: Uuid,
        rule_version: i64,
        run_id: Uuid,
        status: String,
        reason: String,
    },
    Test,
}
impl Event {
    pub fn validate(&self) -> Result<(), Error> {
        if self.event_id.is_nil()
            || self.tenant_id.is_nil()
            || self.version != 1
            || self.occurred_at < 0
            || self.device_id.is_empty()
            || self.device_id.len() > 255
        {
            return Err(Error::Invalid);
        }
        let valid = match (&self.data, self.event_type) {
            (
                EventData::DeviceAccess {
                    operation_id,
                    binding_id,
                    registration_id,
                    registration_generation,
                    instance_id,
                    principal_id,
                    previous_principal,
                    binding_generation,
                    factor_generation,
                    revision,
                    phase,
                    ..
                },
                EventType::DeviceAccessChanged,
            ) => {
                [
                    operation_id,
                    binding_id,
                    registration_id,
                    instance_id,
                    principal_id,
                ]
                .iter()
                .all(|id| !id.is_nil())
                    && previous_principal.is_none_or(|id| !id.is_nil())
                    && [
                        *registration_generation,
                        *binding_generation,
                        *factor_generation,
                        *revision,
                    ]
                    .iter()
                    .all(|v| *v > 0)
                    && matches!(
                        phase.as_str(),
                        "accepted" | "pending" | "applied" | "failed" | "unknown" | "retired"
                    )
            }
            (
                EventData::Registration {
                    registration_id,
                    generation,
                    channel,
                    state,
                },
                kind,
            ) => {
                !registration_id.is_nil()
                    && *generation > 0
                    && matches!(channel.as_str(), "mdm" | "agent")
                    && match kind {
                        EventType::Registered => state == "active",
                        EventType::Retired => {
                            matches!(state.as_str(), "retired" | "revoked" | "superseded")
                        }
                        _ => false,
                    }
            }
            (
                EventData::Policy {
                    run_id,
                    policy_version,
                    registration_id,
                    generation,
                    status,
                },
                EventType::PolicyTerminal,
            ) => {
                !run_id.is_nil()
                    && !policy_version.is_nil()
                    && !registration_id.is_nil()
                    && *generation > 0
                    && matches!(
                        status.as_str(),
                        "succeeded" | "failed" | "cancelled" | "expired"
                    )
            }
            (
                EventData::Compliance {
                    rule_id,
                    rule_version,
                    run_id,
                    status,
                    reason,
                },
                EventType::ComplianceChanged,
            ) => {
                !rule_id.is_nil()
                    && *rule_version > 0
                    && !run_id.is_nil()
                    && matches!(
                        status.as_str(),
                        "compliant" | "non_compliant" | "unknown" | "not_applicable"
                    )
                    && matches!(
                        reason.as_str(),
                        "platform_not_applicable"
                            | "group_not_applicable"
                            | "platform_unknown"
                            | "group_unknown"
                            | "rule_satisfied"
                            | "rule_failed"
                            | "facts_unknown"
                    )
            }
            (EventData::Test, EventType::Test) => true,
            _ => false,
        };
        if valid { Ok(()) } else { Err(Error::Invalid) }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Selection {
    AllDevices,
    Devices { ids: Vec<String> },
    Groups { ids: Vec<Uuid> },
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    pub presentation: serde_json::Map<String, serde_json::Value>,
    pub endpoint: String,
    pub event_types: Vec<EventType>,
    pub selection: Selection,
    pub key_reference: String,
    pub network_reference: String,
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        let text = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && s.trim() == s && !s.chars().any(char::is_control)
        };
        if !crate::presentation::valid(&self.presentation, 65536)
            || !self
                .presentation
                .get("name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| text(name, 128))
            || !text(&self.key_reference, 128)
            || !text(&self.network_reference, 128)
            || self.endpoint.len() > 2048
            || self.event_types.is_empty()
            || self.event_types.len() > EventType::BUSINESS.len()
            || self.event_types.contains(&EventType::Test)
            || self
                .event_types
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.event_types.len()
        {
            return Err(Error::Invalid);
        }
        let u = url::Url::parse(&self.endpoint).map_err(|_| Error::Invalid)?;
        if u.scheme() != "https"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
            || u.query().is_some()
        {
            return Err(Error::Invalid);
        }
        match &self.selection {
            Selection::AllDevices => (),
            Selection::Devices { ids }
                if !ids.is_empty()
                    && ids.len() <= 256
                    && ids.iter().all(|i| text(i, 255))
                    && ids.iter().collect::<std::collections::BTreeSet<_>>().len() == ids.len() => {
            }
            Selection::Groups { ids }
                if !ids.is_empty()
                    && ids.len() <= 16
                    && ids.iter().all(|i| !i.is_nil())
                    && ids.iter().collect::<std::collections::BTreeSet<_>>().len() == ids.len() => {
            }
            _ => return Err(Error::Invalid),
        }
        Ok(())
    }
    pub fn same_delivery(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint
            && self.event_types == other.event_types
            && match (&self.selection, &other.selection) {
                (Selection::AllDevices, Selection::AllDevices) => true,
                (Selection::Devices { ids: a }, Selection::Devices { ids: b }) => {
                    a.iter().collect::<std::collections::BTreeSet<_>>() == b.iter().collect()
                }
                (Selection::Groups { ids: a }, Selection::Groups { ids: b }) => {
                    a.iter().collect::<std::collections::BTreeSet<_>>() == b.iter().collect()
                }
                _ => false,
            }
            && self.key_reference == other.key_reference
            && self.network_reference == other.network_reference
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: Uuid,
    pub revision: i64,
    pub target_version: i64,
    pub enabled: bool,
    pub deleted: bool,
    pub settings: Settings,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Settings {
        Settings {
            presentation: serde_json::json!({"name":"receiver"})
                .as_object()
                .unwrap()
                .clone(),
            endpoint: "https://receiver.example/hooks".into(),
            event_types: vec![EventType::Registered],
            selection: Selection::AllDevices,
            key_reference: "receiver-key".into(),
            network_reference: "receiver-network".into(),
        }
    }
    #[test]
    fn name_is_not_a_delivery_change() {
        let a = settings();
        let mut b = a.clone();
        b.presentation
            .insert("name".into(), serde_json::json!("renamed"));
        assert!(a.same_delivery(&b));
        b.presentation
            .insert("vendorHelp".into(), serde_json::json!({"text":"support"}));
        b.validate().unwrap();
        assert!(a.same_delivery(&b));
        let restored: Settings = serde_json::from_slice(&serde_json::to_vec(&b).unwrap()).unwrap();
        assert_eq!(restored.presentation, b.presentation);
        b.endpoint = "https://other.example/hooks".into();
        assert!(!a.same_delivery(&b));
    }
    #[test]
    fn resource_order_does_not_retire_a_target() {
        let mut a = settings();
        let mut b = a.clone();
        a.selection = Selection::Devices {
            ids: vec!["a".into(), "b".into()],
        };
        b.selection = Selection::Devices {
            ids: vec!["b".into(), "a".into()],
        };
        assert!(a.same_delivery(&b));
        let (x, y) = (Uuid::new_v4(), Uuid::new_v4());
        a.selection = Selection::Groups { ids: vec![x, y] };
        b.selection = Selection::Groups { ids: vec![y, x] };
        assert!(a.same_delivery(&b));
        b.selection = Selection::Groups { ids: vec![y, y] };
        assert!(b.validate().is_err());
        assert!(!a.same_delivery(&b));
    }
    #[test]
    fn subscription_rejects_insecure_credential_and_query_urls() {
        let mut s = settings();
        assert!(s.validate().is_ok());
        for endpoint in [
            "http://receiver.example",
            "https://u:p@receiver.example",
            "https://receiver.example/?secret=value",
            "https://receiver.example/#fragment",
        ] {
            s.endpoint = endpoint.into();
            assert!(s.validate().is_err());
        }
    }
    #[test]
    fn unknown_execution_is_not_terminal() {
        let e = Event {
            event_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            event_type: EventType::PolicyTerminal,
            version: 1,
            occurred_at: 0,
            device_id: "device".into(),
            data: EventData::Policy {
                run_id: Uuid::new_v4(),
                policy_version: Uuid::new_v4(),
                registration_id: Uuid::new_v4(),
                generation: 1,
                status: "unknown".into(),
            },
        };
        assert!(e.validate().is_err());
    }
}
