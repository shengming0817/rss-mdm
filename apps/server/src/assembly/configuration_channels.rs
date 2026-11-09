//! Static adapters for Policy configuration's channel facts; no owner SQL lives here.
use rss_mdm_apple_channel::protocol_types::{self as apple, AppleProfiles as _, AppleResults as _};
use rss_mdm_policy_service::{
    Error, Failure,
    configuration::{self as cfg, channels::*},
    transaction::Fault,
};
use rss_request_context::TenantId;
use sqlx::PgConnection;
use std::sync::Arc;
use uuid::Uuid;
pub(crate) struct ConfigurationChannels {
    pub protection: Arc<rss_mdm_native_protection::Protector>,
}
fn apple_error(e: rss_mdm_apple_channel::Error) -> Error {
    super::policy_ports::error(super::apple_facts::error(e))
}
fn windows_error(e: rss_mdm_windows_channel::Error) -> Error {
    super::policy_ports::error(super::windows_results::error(e))
}
fn fault(e: Fault) -> Error {
    match e {
        Fault::Request(e) => e,
        Fault::Sql(_) | Fault::Storage(_) => Error::Unavailable(Failure::Database),
    }
}
impl ConfigurationChannels {
    fn apple(&self) -> rss_mdm_apple_channel::flow_store::Store {
        rss_mdm_apple_channel::flow_store::Store {
            protection: self.protection.clone(),
        }
    }
    fn windows(&self) -> rss_mdm_windows_channel::results::Results {
        rss_mdm_windows_channel::results::Results {
            protection: self.protection.clone(),
        }
    }
}
pub(crate) fn target(v: cfg::NativeTarget) -> Result<apple::Target, rss_mdm_apple_channel::Error> {
    match v {
        cfg::NativeTarget::Device => Ok(apple::Target::Device),
        cfg::NativeTarget::EnrolledUser => Err(rss_mdm_apple_channel::Error::Unsupported),
        cfg::NativeTarget::User { user_id } => Ok(apple::Target::User { user_id }),
    }
}
fn windows_receipt(
    v: rss_mdm_windows_channel::results::WindowsReceipt,
) -> cfg::queries::records::WindowsReceipt {
    let rss_mdm_windows_channel::results::WindowsReceipt {
        phase,
        ordinal,
        session,
        message,
        command,
        parent_command,
        item,
        kind,
        uri,
        status,
        value,
        accepted,
        received_at,
        result_accepted,
        result_received_at,
        frames,
        redacted,
    } = v;
    cfg::queries::records::WindowsReceipt {
        phase: match phase {
            rss_mdm_windows_channel::participants::AttemptPhase::Prepare => {
                cfg::model::AttemptPhase::Prepare
            }
            rss_mdm_windows_channel::participants::AttemptPhase::Execute => {
                cfg::model::AttemptPhase::Execute
            }
            rss_mdm_windows_channel::participants::AttemptPhase::Observe => {
                cfg::model::AttemptPhase::Observe
            }
        },
        ordinal,
        session,
        message,
        command,
        parent_command,
        item,
        kind,
        uri,
        status,
        value,
        accepted,
        received_at,
        result_accepted,
        result_received_at,
        frames: frames.into_iter().map(windows_frame).collect(),
        redacted,
    }
}
fn windows_frame(
    v: rss_mdm_windows_channel::results::WindowsFrame,
) -> cfg::queries::records::WindowsFrame {
    let rss_mdm_windows_channel::results::WindowsFrame {
        message,
        command,
        start_byte,
        end_byte,
        total_bytes,
        status,
        accepted,
        received_at,
    } = v;
    cfg::queries::records::WindowsFrame {
        message,
        command,
        start_byte,
        end_byte,
        total_bytes,
        status,
        accepted,
        received_at,
    }
}
impl Channels for ConfigurationChannels {
    fn observations<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        reads: Vec<ObservationRead>,
        values: bool,
    ) -> Pending<'a, std::collections::BTreeMap<Uuid, cfg::queries::records::NativeObservation>>
    {
        Box::pin(async move {
            use cfg::queries::records::NativeObservation;
            let mut windows = Vec::new();
            let mut apples = Vec::new();
            let mut properties = std::collections::BTreeMap::new();
            for r in reads {
                properties.insert(r.id, (r.status, r.profile));
                let sensitive = r.task.permissions()?.iter().any(|p| {
                    matches!(
                        p,
                        rss_mdm_authorization_service::Permission::DeviceDiagnostics
                            | rss_mdm_authorization_service::Permission::SecurityOperate
                            | rss_mdm_authorization_service::Permission::Credentials
                            | rss_mdm_authorization_service::Permission::AccountWrite
                    )
                });
                match r.task {
                    cfg::Task::Windows { request } => {
                        windows.push(rss_mdm_windows_channel::results::Read {
                            id: r.id,
                            device: r.device.clone(),

                            request,
                            values: values && !sensitive,
                        })
                    }
                    cfg::Task::Macos { request } => apples.push((r.id, request)),
                }
            }
            let mut output = std::collections::BTreeMap::new();
            for (id, e) in self
                .windows()
                .observations(c, tenant, &windows)
                .await
                .map_err(windows_error)?
            {
                let receipts = e.receipts.into_iter().map(windows_receipt).collect();
                output.insert(
                    id,
                    NativeObservation::Windows {
                        receipts,
                        progress: properties[&id].0,
                        effect: e.assessment.state,
                        reason: e.assessment.reason,
                    },
                );
            }
            for (id, e) in self
                .apple()
                .evidence_page(c, tenant.to_string(), apples, values)
                .await
                .map_err(apple_error)?
            {
                let (status, profile) = properties[&id];
                output.insert(
                    id,
                    match e {
                        apple::AppleEvidence::Declarations(facts) => {
                            NativeObservation::Declarations {
                                facts: facts.map(|f| *f),
                                progress: status,
                            }
                        }
                        apple::AppleEvidence::Observations(rows) => NativeObservation::Apple {
                            facts: rss_mdm_apple_mdm::native::evidence::summarize(rows, profile),
                            progress: status,
                            effect_confirmed: status == rss_device_command::Status::Applied,
                        },
                    },
                );
            }
            Ok(output)
        })
    }

    fn bind_command<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        binding: rss_mdm_registration_service::command_authority::CommandBinding,
        windows: bool,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            if windows {
                rss_mdm_windows_channel::command_binding::bind_on(c, tenant, binding)
                    .await
                    .map_err(windows_error)
            } else {
                rss_mdm_apple_channel::command_binding::bind_on(c, tenant, binding)
                    .await
                    .map_err(apple_error)
            }
        })
    }
    fn previous_permissions<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        device: &'a str,
        input: &'a cfg::Create,
        owner: String,
    ) -> Pending<'a, Vec<rss_mdm_authorization_service::Permission>> {
        Box::pin(async move {
            let mut required = input.task.permissions()?;
            let old = if let Some((identifier, _, _)) = input.profile_target() {
                self.apple()
                    .previous_profiles(
                        c,
                        tenant.to_string(),
                        device.into(),
                        input.target.user_key().into(),
                        identifier.into(),
                    )
                    .await
                    .map_err(apple_error)?
            } else if matches!(
                input.task,
                cfg::Task::Macos {
                    request: rss_mdm_apple_mdm::native::request::Request::Declarations { .. }
                }
            ) {
                self.apple()
                    .previous_declarations(
                        c,
                        tenant.to_string(),
                        device.into(),
                        input.target.user_key().into(),
                        owner,
                    )
                    .await
                    .map_err(apple_error)?
            } else {
                return Ok(required);
            };
            required.extend(operation_permissions(c, tenant, &self.protection, old).await?);
            required.sort();
            required.dedup();
            Ok(required)
        })
    }
    fn reserve_profile<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        r: Reservation,
    ) -> Pending<'a, ()> {
        Box::pin(async move {
            self.apple()
                .reserve_profile(
                    c,
                    apple::AppleRegistration {
                        tenant: tenant.to_string(),
                        device: r.device,
                    },
                    apple::AppleCommand {
                        operation: r.binding.operation,
                        owner: String::new(),
                        authorized_declarations: Vec::new(),
                        assets: Vec::new(),
                        deadline: r.deadline,
                        input_version: r.input_version,
                        target: target(r.target).map_err(apple_error)?,
                        request: r.request,
                    },
                )
                .await
                .map_err(apple_error)
        })
    }
    fn execute_was_sent<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        operation: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            let windows =
                rss_mdm_windows_channel::command_binding::execute_was_sent_on(c, tenant, operation)
                    .await
                    .map_err(windows_error)?;
            let apple =
                rss_mdm_apple_channel::command_binding::execute_was_sent_on(c, tenant, operation)
                    .await
                    .map_err(apple_error)?;
            Ok(windows || apple)
        })
    }
    fn withdrawal_published<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: String,
        operation: Uuid,
    ) -> Pending<'a, bool> {
        Box::pin(async move {
            self.apple()
                .withdrawal_published(c, tenant, operation)
                .await
                .map_err(apple_error)
        })
    }
}
impl WindowsEvidence for ConfigurationChannels {
    fn settlement<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        complete: bool,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::receipt::Settlement> {
        Box::pin(async move {
            self.windows()
                .settlement(c, tenant, id, complete)
                .await
                .map_err(windows_error)
        })
    }
    fn assessment<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: TenantId,
        id: Uuid,
        registration: String,
        request: rss_mdm_windows_mdm::native::Execution,
    ) -> Pending<'a, rss_mdm_windows_mdm::native::verification::EffectAssessment> {
        Box::pin(async move {
            self.windows()
                .observations(
                    c,
                    tenant,
                    &[rss_mdm_windows_channel::results::Read {
                        id,
                        device: registration.to_string(),

                        request,
                        values: false,
                    }],
                )
                .await
                .map_err(windows_error)?
                .remove(&id)
                .map(|e| e.assessment)
                .ok_or(Error::Conflict)
        })
    }
}

pub(super) async fn operation_permissions(
    c: &mut PgConnection,
    tenant: TenantId,
    protection: &rss_mdm_native_protection::Protector,
    old: Vec<Uuid>,
) -> Result<Vec<rss_mdm_authorization_service::Permission>, Error> {
    let mut required = Vec::new();
    let mut owned = Vec::with_capacity(old.len());
    for id in old {
        owned.push((id, super::native_ownership::on(c, tenant, id).await?));
    }
    for (id, owner) in owned {
        required.extend(match owner {
            super::native_ownership::Owner::Software => {
                rss_mdm_software_service::deployment::storage::load_on(c, tenant, protection, id)
                    .await
                    .map_err(super::policy_ports::software_fault)
                    .map_err(fault)?
                    .request
                    .task
                    .permissions()
                    .map_err(super::policy_ports::software_error)?
            }
            super::native_ownership::Owner::Registration => {
                rss_mdm_registration_service::installation::storage::load_on(
                    c, tenant, protection, id,
                )
                .await
                .map_err(|e| match e {
                    rss_mdm_registration_service::installation::Fault::Request(e) => {
                        registration_error(e)
                    }
                    _ => Error::Unavailable(Failure::Database),
                })?
                .request
                .task
                .permissions()
                .map_err(registration_error)?
            }

            super::native_ownership::Owner::Configuration => {
                cfg::storage::load_on(c, tenant, protection, id)
                    .await
                    .map_err(fault)?
                    .request
                    .task
                    .permissions()?
            }
            super::native_ownership::Owner::Recovery => {
                rss_mdm_recovery_credentials::native::storage::load_on(c, tenant, protection, id)
                    .await
                    .map_err(|_| Error::Unavailable(Failure::Database))?
                    .request
                    .task
                    .permissions()
                    .map_err(|_| Error::Forbidden)?
            }
            super::native_ownership::Owner::Device => {
                rss_mdm_device_service::control::storage::load_on(c, tenant, protection, id)
                    .await
                    .map_err(super::policy_ports::fault)
                    .map_err(fault)?
                    .request
                    .task
                    .permissions()
                    .map_err(super::policy_ports::error)?
            }
        });
    }
    required.sort();
    required.dedup();
    Ok(required)
}

fn registration_error(e: rss_mdm_registration_service::installation::Error) -> Error {
    use rss_mdm_registration_service::installation::Error as E;
    match e {
        E::CommitUnknown => Error::CommitUnknown,
        E::RollbackFailed => Error::RollbackFailed,
        E::Forbidden => Error::Forbidden,
        E::Unauthorized => Error::Unauthorized,
        E::Malformed => Error::Malformed,
        E::Conflict => Error::Conflict,
        E::NotFound | E::Execution(_) => Error::NotFound,
        E::Unsupported => Error::Unsupported,
        _ => Error::Unavailable(Failure::Database),
    }
}
