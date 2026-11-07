//! Public device control is closed; platform payloads remain execution-internal.
//! ref: apple/device-management mdm/commands/device.{lock,erase,restart}.yaml
use crate::control::{Create, Error, NativeTarget, Task, authorization::Permission};
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
    /// Fixed native shape used by applicability reads and by the real submission.
    /// The lock PIN is added only by `Action::task` after input validation.
    pub fn native_shape(self, source: ReportSource) -> Result<Task, Error> {
        use rss_mdm_apple_mdm::native::{
            input::{CommandInput, FieldValue, Fields},
            request::Request,
        };
        use rss_mdm_windows_mdm::native::{Execution, Request as Windows, Value, Verb};
        match source {
            ReportSource::MdmApple => {
                let (request_type, fields) = match self {
                    Self::Restart => ("RestartDevice", Fields::default()),
                    Self::Lock => ("DeviceLock", Fields::default()),
                    Self::Wipe => (
                        "EraseDevice",
                        Fields(std::collections::BTreeMap::from([(
                            "ObliterationBehavior".into(),
                            FieldValue::String("DoNotObliterate".into()),
                        )])),
                    ),
                };
                Ok(Task::Macos {
                    request: Request::Command {
                        command: CommandInput {
                            request_type: request_type.into(),
                            fields,
                        },
                    },
                })
            }
            ReportSource::MdmWindows => {
                let (node, value) = match self {
                    Self::Restart => ("./Device/Vendor/MSFT/Reboot/RebootNow", None),
                    Self::Wipe => (
                        "./Device/Vendor/MSFT/RemoteWipe/doWipe",
                        Some(Value::Text(String::new())),
                    ),
                    Self::Lock => return Err(Error::Unsupported),
                };
                Ok(Task::Windows {
                    request: Execution::SyncMl {
                        request: Windows::Node {
                            node: node.into(),
                            instance: Vec::new(),
                            operation: Verb::Exec,
                            value,
                        },
                    },
                })
            }
            ReportSource::AgentBuiltin => Err(Error::Unsupported),
        }
    }
    pub fn permission(self) -> Permission {
        match self {
            Self::Restart | Self::Lock => Permission::DeviceControl,
            Self::Wipe => Permission::DeviceWipe,
        }
    }
    pub fn dangerous(self) -> bool {
        self != Self::Restart
    }
}

/// Current platform prerequisites, never a grant or proof of device execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applicability {
    Supported,
    Unsupported,
    Unknown,
}

/// A capability read has no operation identity, deadline, confirmation or secret.
#[derive(Clone, Copy)]
pub struct Check {
    pub registration: Uuid,
    pub generation: i64,
    pub source: ReportSource,
    pub action: Kind,
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

#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
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
        let mut task = self.kind().native_shape(source)?;
        if let (
            Self::Lock { pin, .. },
            Task::Macos {
                request: rss_mdm_apple_mdm::native::request::Request::Command { command },
            },
        ) = (self, &mut task)
        {
            command.fields.0.insert(
                "PIN".into(),
                rss_mdm_apple_mdm::native::input::FieldValue::String(pin.clone()),
            );
        }
        Ok(task)
    }
}

#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
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

/// Reauthorization refreshes grants, never changes the original action, PIN or registration.
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Reauthorization {
    pub request_id: Uuid,
    pub expected_revision: i64,
    pub confirmation: Option<DangerousActionConfirmation>,
}
#[derive(schemars::JsonSchema, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DangerousActionConfirmation {
    pub confirmed: bool,
    pub expected_registration_id: Uuid,
    pub expected_generation: i64,
}
impl Reauthorization {
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

/// Resolve the same unique enabled native source for reads and submissions.
/// The caller supplies its authorized, tenant-bound connection and current registration.
pub async fn source_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    registration: Uuid,
) -> crate::control::Result<ReportSource> {
    let sources = sqlx::query_scalar::<_, String>("SELECT source FROM mdm_access.report_sources WHERE tenant_id=$1::uuid AND registration=$2 AND enabled AND source IN('mdm.apple','mdm.windows') ORDER BY source")
        .bind(tenant.to_string()).bind(registration).fetch_all(c).await?;
    match sources.as_slice() {
        [source] if source == "mdm.apple" => Ok(ReportSource::MdmApple),
        [source] if source == "mdm.windows" => Ok(ReportSource::MdmWindows),
        _ => Err(Error::Conflict.into()),
    }
}

pub(crate) async fn applicability_on(
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    apple: std::sync::Arc<dyn crate::control::apple_facts::AppleResults>,
    windows: std::sync::Arc<dyn crate::control::windows_results::Store>,
    checks: &[Check],
) -> crate::control::Result<Vec<Applicability>> {
    use std::collections::BTreeMap;
    if checks.len() > 1000 {
        return Err(Error::Malformed.into());
    }
    let mut output = BTreeMap::new();
    let mut apples = Vec::new();
    let mut windows_checks = Vec::new();
    for (id, check) in checks.iter().enumerate() {
        match check.action.native_shape(check.source) {
            Ok(Task::Windows {
                request: rss_mdm_windows_mdm::native::Execution::SyncMl { request },
            }) => {
                windows_checks.push((id, check.registration, check.generation, request));
            }
            Ok(Task::Macos {
                request: rss_mdm_apple_mdm::native::request::Request::Command { command },
            }) => {
                apples.push(crate::control::apple_facts::AppleControlCheck {
                    id,
                    registration: check.registration,
                    generation: check.generation,
                    action: check.action,
                    command,
                });
            }
            Err(Error::Unsupported) => {
                output.insert(id, Applicability::Unsupported);
            }
            Err(e) => return Err(e.into()),
            Ok(_) => {
                return Err(Error::Unavailable(crate::control::Failure::CommandInvariant).into());
            }
        }
    }
    if !apples.is_empty() {
        output.extend(
            apple
                .control_applicability(c, &tenant.to_string(), &apples)
                .await?,
        );
    }
    if !windows_checks.is_empty() {
        output.extend(
            windows
                .control_applicability(c, tenant, windows_checks)
                .await?,
        );
    }
    if output.len() != checks.len() {
        return Err(Error::Unavailable(crate::control::Failure::CommandInvariant).into());
    }
    (0..checks.len())
        .map(|id| {
            output
                .remove(&id)
                .ok_or_else(|| Error::Unavailable(crate::control::Failure::CommandInvariant).into())
        })
        .collect()
}
impl crate::control::Service {
    pub(crate) async fn validate_control_in(
        &self,
        tx: &mut rss_transactional_messaging_postgres::PgTransaction<'_>,
        _device: &str,
        registration: Uuid,
        generation: i64,
        input: &Create,
        action: Kind,
    ) -> crate::control::Result<()> {
        if !matches(action, input)? {
            return Err(Error::Unsupported.into());
        }
        let tenant = tx.tenant_id();
        let checks = [Check {
            registration,
            generation,
            source: input.task.source(),
            action,
        }];
        let result = tx
            .with_connection_context(&mut (self, &checks), move |(service, checks), c| {
                Box::pin(async move {
                    Ok(applicability_on(
                        c,
                        tenant,
                        service.transactions.apple_results.clone(),
                        service.transactions.windows_results.clone(),
                        *checks,
                    )
                    .await)
                })
            })
            .await??;
        if result.as_slice() == [Applicability::Supported] {
            Ok(())
        } else {
            Err(Error::Unsupported.into())
        }
    }
}

impl crate::control::queries::Queries {
    /// Borrow the caller's authorized, tenant-bound read-only snapshot.
    pub async fn control_applicability_on(
        &self,
        c: &mut sqlx::PgConnection,
        checks: &[Check],
    ) -> crate::control::Result<Vec<Applicability>> {
        applicability_on(
            c,
            self.tenant,
            self.apple_results.clone(),
            self.windows_results.clone(),
            checks,
        )
        .await
    }
}
