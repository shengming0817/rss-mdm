//! Public device control is closed; platform payloads remain execution-internal.
//! ref: apple/device-management mdm/commands/device.{lock,erase,restart}.yaml
use crate::{Create, Error, NativeTarget, Task, authorization::Permission};
use rss_mdm_inventory::ReportSource;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Restart,
    Lock,
    Wipe,
}
impl Kind {
    pub fn permission(self) -> Permission {
        match self {
            Self::Restart | Self::Lock => Permission::DeviceControl,
            Self::Wipe => Permission::DeviceWipe,
        }
    }
    pub fn dangerous(self) -> bool {
        self != Self::Restart
    }
    /// Conservative product matrix in addition to the platform's native schema.
    pub fn supports_apple(self, context: &rss_mdm_apple_mdm::applicability::Context) -> bool {
        use rss_mdm_apple_mdm::applicability::{Channel, Enrollment, Version};
        let Some(version) = context.version else {
            return false;
        };
        if context.channel != Channel::Device || context.enrollment != Enrollment::Device {
            return false;
        }
        let minimum = match self {
            Self::Restart => "10.13",
            Self::Lock => match context.apple_silicon {
                Some(true) => "11.5",
                Some(false) => "10.8",
                None => return false,
            },
            Self::Wipe if context.apple_silicon == Some(true) => "12.0.1",
            Self::Wipe => return false,
        };
        version >= Version::parse(minimum).expect("fixed minimum version")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistrationConfirmation {
    pub registration_id: Uuid,
    pub generation: i64,
}
impl RegistrationConfirmation {
    pub fn check(self, registration: Uuid, generation: i64) -> Result<(), Error> {
        if self.registration_id.is_nil() || self.generation < 1 {
            return Err(Error::Malformed);
        }
        if self.registration_id != registration || self.generation != generation {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum Action {
    Restart {},
    Lock {
        confirmed: bool,
        expected_registration_id: Uuid,
        expected_generation: i64,
        pin: String,
    },
    Wipe {
        confirmed: bool,
        expected_registration_id: Uuid,
        expected_generation: i64,
    },
}
impl std::fmt::Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceControlAction([REDACTED])")
    }
}
impl Action {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Restart {} => Kind::Restart,
            Self::Lock { .. } => Kind::Lock,
            Self::Wipe { .. } => Kind::Wipe,
        }
    }
    pub fn confirmation(&self) -> Result<Option<RegistrationConfirmation>, Error> {
        let (confirmed, registration_id, generation) = match self {
            Self::Restart {} => return Ok(None),
            Self::Lock {
                confirmed,
                expected_registration_id,
                expected_generation,
                pin,
            } => {
                if pin.len() != 6 || !pin.bytes().all(|v| v.is_ascii_digit()) {
                    return Err(Error::Malformed);
                }
                (*confirmed, *expected_registration_id, *expected_generation)
            }
            Self::Wipe {
                confirmed,
                expected_registration_id,
                expected_generation,
            } => (*confirmed, *expected_registration_id, *expected_generation),
        };
        if !confirmed || registration_id.is_nil() || generation < 1 {
            return Err(Error::Malformed);
        }
        Ok(Some(RegistrationConfirmation {
            registration_id,
            generation,
        }))
    }
    pub(crate) fn task(&self, source: ReportSource) -> Result<Task, Error> {
        use rss_mdm_apple_mdm::native::{
            input::{CommandInput, FieldValue, Fields},
            request::Request as A,
        };
        use rss_mdm_windows_mdm::native::{Execution, Request, Value, Verb};
        Ok(match source {
            ReportSource::MdmApple => {
                let (request_type, fields) = match self {
                    Self::Restart {} => ("RestartDevice", Fields::default()),
                    Self::Lock { pin, .. } => (
                        "DeviceLock",
                        Fields(std::collections::BTreeMap::from([(
                            "PIN".into(),
                            FieldValue::String(pin.clone()),
                        )])),
                    ),
                    Self::Wipe { .. } => (
                        "EraseDevice",
                        Fields(std::collections::BTreeMap::from([(
                            "ObliterationBehavior".into(),
                            FieldValue::String("DoNotObliterate".into()),
                        )])),
                    ),
                };
                Task::Macos {
                    request: A::Command {
                        command: CommandInput {
                            request_type: request_type.into(),
                            fields,
                        },
                    },
                }
            }
            ReportSource::MdmWindows => {
                let (node, value) = match self {
                    Self::Restart {} => ("./Device/Vendor/MSFT/Reboot/RebootNow", None),
                    Self::Wipe { .. } => (
                        "./Device/Vendor/MSFT/RemoteWipe/doWipe",
                        Some(Value::Text(String::new())),
                    ),
                    Self::Lock { .. } => return Err(Error::Unsupported),
                };
                Task::Windows {
                    request: Execution::SyncMl {
                        request: Request::Node {
                            node: node.into(),
                            instance: Vec::new(),
                            operation: Verb::Exec,
                            value,
                        },
                    },
                }
            }
            _ => return Err(Error::Unsupported),
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    pub operation_id: Uuid,
    pub deadline: i64,
    pub action: Action,
}
impl Input {
    pub fn validate(&self, now: i64) -> Result<(), Error> {
        if self.operation_id.is_nil()
            || self.deadline <= now
            || self.deadline.checked_mul(1_000_000).is_none()
        {
            return Err(Error::Malformed);
        }
        self.action.confirmation()?;
        Ok(())
    }
    pub(crate) fn native(&self, source: ReportSource) -> Result<Create, Error> {
        Ok(Create {
            operation_id: self.operation_id,
            deadline: self.deadline,
            input_version: "device-control-v1".into(),
            target: NativeTarget::Device,
            task: self.action.task(source)?,
        })
    }
}

/// Reapproval refreshes grants, never changes the original action, PIN or registration.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approval {
    pub request_id: Uuid,
    pub expected_revision: i64,
    pub confirmation: Option<ApprovalConfirmation>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalConfirmation {
    pub confirmed: bool,
    pub expected_registration_id: Uuid,
    pub expected_generation: i64,
}
impl Approval {
    pub fn registration(&self) -> Result<Option<RegistrationConfirmation>, Error> {
        self.confirmation
            .as_ref()
            .map(|v| {
                if !v.confirmed || v.expected_registration_id.is_nil() || v.expected_generation < 1
                {
                    return Err(Error::Malformed);
                }
                Ok(RegistrationConfirmation {
                    registration_id: v.expected_registration_id,
                    generation: v.expected_generation,
                })
            })
            .transpose()
    }
}

/// Validate the closed authority against the already authenticated sealed native input.
pub(crate) fn matches(kind: Kind, input: &Create) -> Result<bool, Error> {
    use rss_mdm_apple_mdm::native::{input::FieldValue, request::Request};
    let action = match kind {
        Kind::Restart => Action::Restart {},
        Kind::Wipe => Action::Wipe {
            confirmed: true,
            expected_registration_id: Uuid::nil(),
            expected_generation: 0,
        },
        Kind::Lock => {
            let Task::Macos {
                request: Request::Command { command },
            } = &input.task
            else {
                return Ok(false);
            };
            let Some(FieldValue::String(pin)) = command.fields.0.get("PIN") else {
                return Ok(false);
            };
            if pin.len() != 6 || !pin.bytes().all(|v| v.is_ascii_digit()) {
                return Ok(false);
            }
            Action::Lock {
                confirmed: true,
                expected_registration_id: Uuid::nil(),
                expected_generation: 0,
                pin: pin.clone(),
            }
        }
    };
    Ok(input.input_version == "device-control-v1"
        && input.target == NativeTarget::Device
        && serde_json::to_value(&input.task).map_err(|_| Error::Malformed)?
            == serde_json::to_value(action.task(input.task.source())?)
                .map_err(|_| Error::Malformed)?)
}

impl crate::ExecutionService {
    pub(crate) async fn validate_control_in(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        device: &str,
        registration: Uuid,
        generation: i64,
        input: &Create,
        action: Kind,
    ) -> crate::Result<()> {
        if !matches(action, input)? {
            return Err(Error::Unsupported.into());
        }
        let supported = match &input.task {
            Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::SyncMl { request },
            } => {
                let tenant = self.tenant.to_string();
                let capability = tx.with_connection(move |c| Box::pin(async move {
                    sqlx::query_as::<_, (String, i32)>("SELECT os_version,edition FROM mdm_commands.capabilities WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3")
                        .bind(tenant).bind(registration).bind(generation).fetch_optional(c).await
                })).await?;
                capability.is_some_and(|(version, edition)| {
                    crate::native::context(
                        &version,
                        edition as u32,
                        rss_mdm_windows_mdm::native::Scope::Device,
                        rss_mdm_registration_service::Purpose::Primary,
                    )
                    .is_ok_and(|context| request.compile(context, 1).is_ok())
                })
            }
            Task::Macos {
                request: rss_mdm_apple_mdm::native::request::Request::Command { command },
            } => {
                let provider = self.apple_results.clone();
                let target = crate::channels::AppleRegistration {
                    tenant: self.tenant.to_string(),
                    device: device.to_owned(),
                    registration,
                    generation,
                };
                let command = command.clone();
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        Ok(provider
                            .device_control_supported(c, target, action, command)
                            .await)
                    })
                })
                .await?
                .map_err(Error::from)?
            }
            _ => false,
        };
        if !supported {
            return Err(Error::Unsupported.into());
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/device_control_unit.rs"]
mod tests;
