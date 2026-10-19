//! Credential policies share the existing schedule and durable Agent task lifecycle.
use crate::{
    action_contract::{ExecutionInput, ScheduledInput},
    authorization::{OperationAuthority, Permission},
    *,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::{Architecture, CredentialOperation as Operation};
use rss_mdm_recovery_credentials::{self as vault, storage as materials};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrozenCredential {
    pub input: ExecutionInput,
    pub operation: Operation,
    pub grants: BTreeMap<String, Vec<OperationAuthority>>,
}
impl ScheduledInput for FrozenCredential {
    fn execution_input(&self) -> &ExecutionInput {
        &self.input
    }
}
pub fn permission(operation: &Operation) -> Permission {
    match operation {
        Operation::RotateLocalAdministrator { .. } | Operation::VerifyLocalAdministrator { .. } => {
            Permission::AccountWrite
        }
        _ => Permission::SecurityOperate,
    }
}
impl FrozenCredential {
    pub fn permission(&self) -> Permission {
        permission(&self.operation)
    }
    pub async fn authorized_in(
        &self,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        now: i64,
    ) -> Result<bool> {
        let Some(grants) = self
            .grants
            .get(&target.device)
            .or_else(|| self.grants.get("*"))
        else {
            return Ok(false);
        };
        let grants = grants.clone();
        let permission = self.permission();
        tx.with_connection(move |c| {
            Box::pin(async move {
                for grant in grants {
                    if grant.valid(c, permission, now).await.map_err(|_| {
                        sqlx::Error::Protocol("credential authority unavailable".into())
                    })? {
                        return Ok(true);
                    }
                }
                Ok(false)
            })
        })
        .await
        .map_err(Into::into)
    }
}
pub fn capable(binding: &channels::AgentBinding, architecture: Architecture) -> bool {
    binding.platform == "windows"
        && binding.architecture
            == match architecture {
                Architecture::X86_64 => "x86_64",
                Architecture::Aarch64 => "aarch64",
            }
        && binding
            .capabilities
            .contains(&wire::Capability::CredentialsWindowsV1)
}
pub async fn eligible(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    target: &Target,
    architecture: Architecture,
) -> Result<bool> {
    Ok(service.recovery_credentials.is_some()
        && channels::agent_binding_in(tx, service.agent_store.clone(), target.registration)
            .await?
            .is_some_and(|b| capable(&b, architecture)))
}
fn operation(value: &Operation) -> wire::CredentialOperation {
    match value {
        Operation::CollectBitlocker => wire::CredentialOperation::CollectBitlocker,
        Operation::VerifyBitlocker { volume, protector } => {
            wire::CredentialOperation::VerifyBitlocker {
                volume: volume.clone(),
                protector: *protector,
            }
        }
        Operation::RotateBitlocker { volume, protector } => {
            wire::CredentialOperation::RotateBitlocker {
                volume: volume.clone(),
                protector: *protector,
            }
        }
        Operation::RotateLocalAdministrator { sid } => {
            wire::CredentialOperation::RotateLocalAdministrator { sid: sid.clone() }
        }
        Operation::VerifyLocalAdministrator { sid } => {
            wire::CredentialOperation::VerifyLocalAdministrator { sid: sid.clone() }
        }
    }
}
pub async fn task(
    policy: &sources::admission::ExecutionPolicy<FrozenCredential>,
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    target: &Target,
    issue: actions::storage::TaskIssue,
) -> Result<wire::TaskPayload> {
    let protection = service
        .recovery_credentials
        .as_ref()
        .ok_or(Error::Unsupported)?;
    let recipient = protection.active_recipient();
    recipient
        .require_current(crate::storage::now(tx).await?)
        .map_err(recovery_credentials::error)?;
    let recipient = wire::CredentialRecipient {
        key_id: recipient.id().into(),
        public_key: STANDARD.encode(
            recipient
                .public_key_der()
                .map_err(recovery_credentials::error)?,
        ),
    };
    let tenant = checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?;
    let target_owned = target.clone();
    let revisions = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(materials::revisions_in(
                    c,
                    tenant,
                    &target_owned.device,
                    target_owned.registration,
                    target_owned.generation,
                )
                .await)
            })
        })
        .await?
        .map_err(recovery_credentials::error)?;
    let mut expected = revisions
        .into_iter()
        .map(|(subject, revision)| {
            Ok(wire::CredentialVersion {
                subject: stored(serde_json::from_value(checked_input(
                    serde_json::to_value(subject),
                )?))?,
                revision,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    expected.sort_by(|a, b| a.subject.cmp(&b.subject));
    let run = actions::storage::load_run(tx, issue.run).await?;
    let operation = operation(&policy.frozen.operation);
    let recovery = if matches!(
        operation,
        wire::CredentialOperation::VerifyBitlocker { .. }
            | wire::CredentialOperation::VerifyLocalAdministrator { .. }
    ) {
        let registration = target.registration;
        let generation = target.generation;
        let guard = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(materials::agent_guard_in(c, tenant, registration, generation).await)
                })
            })
            .await?
            .map_err(recovery_credentials::error)?;
        if let Some((task_id, attempt_id)) = guard {
            let original = actions::storage::load_run(tx, task_id).await?;
            let actions::evidence::Material::Credential {
                task: original_task,
            } = actions::evidence::load_in(tx, task_id, attempt_id).await?
            else {
                return Err(Error::Conflict.into());
            };
            let matching = match (&operation, &original_task.operation) {
                (
                    wire::CredentialOperation::VerifyBitlocker { volume, protector },
                    wire::CredentialOperation::RotateBitlocker {
                        volume: v,
                        protector: p,
                    },
                ) => volume == v && protector == p,
                (
                    wire::CredentialOperation::VerifyLocalAdministrator { sid },
                    wire::CredentialOperation::RotateLocalAdministrator { sid: s },
                ) => sid == s,
                _ => false,
            };
            if !matching
                || original.target.device != target.device
                || original.target.registration != target.registration
                || original.target.generation != target.generation
                || original.state.attempt() != Some(attempt_id)
                || !matches!(original.state.execution, actions::state::Execution::Unknown)
            {
                return Err(Error::Conflict.into());
            }
            Some(wire::CredentialRecovery {
                task_id,
                attempt_id,
            })
        } else {
            None
        }
    } else {
        None
    };
    let spec = wire::CredentialTaskSpec {
        wire_version: wire::WIRE_VERSION,
        tenant_id: tenant,
        device_id: target.device.clone(),
        platform: wire::TaskPlatform::Windows,
        architecture: match policy.frozen.input.architecture {
            Architecture::X86_64 => wire::TaskArchitecture::X86_64,
            Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
        },
        registration_id: target.registration,
        generation: checked_input(target.generation.try_into())?,
        task_id: issue.run,
        attempt_id: issue.attempt,
        permit: issue.permit,
        expires_at: issue.expiry,
        deadline: run.deadline,
        authorization: wire::TaskAuthorization::Policy {
            policy_id: policy.owner,
            policy_version: policy.id,
        },
        definition_digest: checked_input(wire::CredentialTaskSpec::digest(
            &operation, &recipient, &expected, &recovery,
        ))?,
        operation,
        recipient,
        expected,
        recovery,
    };
    checked_input(spec.validate())?;
    Ok(wire::TaskPayload::Credential(Box::new(spec)))
}
fn subject(value: &wire::CredentialSubject) -> vault::Subject {
    match value {
        wire::CredentialSubject::Bitlocker { volume, protector } => vault::Subject::Bitlocker {
            volume: volume.clone(),
            protector: *protector,
        },
        wire::CredentialSubject::LocalAdministrator { sid } => {
            vault::Subject::LocalAdministrator { sid: sid.clone() }
        }
    }
}
fn allowed_subject(task: &wire::CredentialTaskSpec, value: &wire::CredentialSubject) -> bool {
    match (&task.operation, value) {
        (
            wire::CredentialOperation::VerifyBitlocker { volume, protector },
            wire::CredentialSubject::Bitlocker {
                volume: v,
                protector: p,
            },
        ) => volume == v && (task.recovery.is_some() || protector == p),
        (
            wire::CredentialOperation::CollectBitlocker,
            wire::CredentialSubject::Bitlocker { .. },
        ) => true,
        (
            wire::CredentialOperation::RotateBitlocker {
                volume,
                protector: old,
            },
            wire::CredentialSubject::Bitlocker {
                volume: v,
                protector: new,
            },
        ) => volume == v && old != new,
        (
            wire::CredentialOperation::RotateLocalAdministrator { sid }
            | wire::CredentialOperation::VerifyLocalAdministrator { sid },
            wire::CredentialSubject::LocalAdministrator { sid: s },
        ) => sid == s,
        _ => false,
    }
}
pub async fn escrow(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &actions::storage::Run,
    attempt: Uuid,
    value: &wire::CredentialEscrow,
) -> Result<()> {
    checked_input(value.validate())?;
    let actions::evidence::Material::Credential { task } =
        actions::evidence::load_in(tx, run.id, attempt).await?
    else {
        return Err(Error::Conflict.into());
    };
    if task.definition_digest != value.definition_digest
        || task.task_id != run.id
        || task.attempt_id != attempt
    {
        return Err(Error::Conflict.into());
    }
    let protection = service
        .recovery_credentials
        .as_ref()
        .ok_or(Error::Unsupported)?
        .clone();
    let value = value.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result = async {
                let recipient = protection.recipient(&task.recipient.key_id)?;
                for item in &value.materials {
                    if !allowed_subject(&task, &item.subject) {
                        return Err(vault::Error::Malformed);
                    }
                    let aad = task
                        .material_aad(&item.subject, item.expected_revision)
                        .map_err(|_| vault::Error::Conflict)?;
                    let secret = recipient.open_envelope(
                        &STANDARD
                            .decode(&item.wrapped_key)
                            .map_err(|_| vault::Error::Malformed)?,
                        item.nonce,
                        &STANDARD
                            .decode(&item.ciphertext)
                            .map_err(|_| vault::Error::Malformed)?,
                        &aad,
                    )?;
                    let binding = vault::Binding {
                        device: task.device_id.clone(),
                        registration: task.registration_id,
                        generation: task.generation as i64,
                        subject: subject(&item.subject),
                    };
                    let verifying = matches!(
                        task.operation,
                        wire::CredentialOperation::VerifyBitlocker { .. }
                            | wire::CredentialOperation::VerifyLocalAdministrator { .. }
                    );
                    let coordinates = if let Some(recovery) = &task.recovery {
                        if materials::agent_guard_in(
                            c,
                            task.tenant_id,
                            task.registration_id,
                            task.generation as i64,
                        )
                        .await?
                            != Some((recovery.task_id, recovery.attempt_id))
                        {
                            return Err(vault::Error::Conflict);
                        }
                        materials::recovery_secret_in(
                            c,
                            &protection.keys,
                            task.tenant_id,
                            &binding,
                            item.expected_revision,
                            recovery.task_id,
                            &secret,
                        )
                        .await?
                    } else if verifying {
                        materials::verify_existing_secret_in(
                            c,
                            &protection.keys,
                            task.tenant_id,
                            &binding,
                            item.expected_revision,
                            &secret,
                        )
                        .await?
                    } else {
                        let coordinates = materials::reserve_in(
                            c,
                            task.tenant_id,
                            &binding,
                            task.task_id,
                            item.expected_revision,
                        )
                        .await?;
                        if matches!(
                            task.operation,
                            wire::CredentialOperation::RotateLocalAdministrator { .. }
                        ) {
                            materials::unknown_in(c, task.tenant_id, task.task_id).await?;
                        }
                        materials::ingest_in(
                            c,
                            &protection.keys,
                            &coordinates,
                            task.task_id,
                            &secret,
                        )
                        .await?;
                        coordinates
                    };
                    materials::link_agent_in(c, task.task_id, task.attempt_id, &coordinates)
                        .await?;
                }
                Ok::<_, vault::Error>(())
            }
            .await;
            Ok(result)
        })
    })
    .await?
    .map_err(recovery_credentials::error)?;
    Ok(())
}
pub async fn finish(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &actions::storage::Run,
    attempt: Uuid,
    value: &wire::CredentialResult,
) -> Result<actions::state::Execution> {
    checked_input(value.validate())?;
    let actions::evidence::Material::Credential { task } =
        actions::evidence::load_in(tx, run.id, attempt).await?
    else {
        return Err(Error::Conflict.into());
    };
    if task.definition_digest != value.definition_digest {
        return Err(Error::Conflict.into());
    }
    if value.recovery.is_some() && task.recovery.is_none() {
        return Err(Error::Conflict.into());
    }
    let value = value.clone();
    let (success, uncertain, recovered) = tx
        .with_connection(move |c| {
            Box::pin(async move {
                let result = async {
                    let mut recovered = Vec::new();
                    let requires_verification =
                        !matches!(task.operation, wire::CredentialOperation::CollectBitlocker);
                    let mut success = value.complete
                        && value.failure.is_none()
                        && (!requires_verification
                            || value
                                .items
                                .iter()
                                .all(|i| i.outcome == wire::CredentialOutcome::Verified));
                    let escrowed = materials::agent_materials_in(
                        c,
                        task.tenant_id,
                        task.task_id,
                        task.attempt_id,
                    )
                    .await?;
                    if escrowed.len() > 512
                        || escrowed.iter().any(|m| {
                            !value
                                .items
                                .iter()
                                .any(|i| subject(&i.subject) == m.binding.subject)
                        })
                    {
                        return Err(vault::Error::Conflict);
                    }
                    for item in &value.items {
                        if !allowed_subject(&task, &item.subject) {
                            return Err(vault::Error::Malformed);
                        }
                        let good = matches!(
                            item.outcome,
                            wire::CredentialOutcome::Verified | wire::CredentialOutcome::Escrowed
                        );
                        if good {
                            let material = escrowed
                                .iter()
                                .find(|m| m.binding.subject == subject(&item.subject))
                                .ok_or(vault::Error::Conflict)?;
                            let coordinates = vault::Coordinates {
                                tenant: task.tenant_id,
                                material: material.id,
                                version: material.version,
                                binding: material.binding.clone(),
                            };
                            if item.outcome == wire::CredentialOutcome::Verified {
                                if let Some(recovery) = &task.recovery {
                                    if value.recovery.is_none()
                                        || materials::agent_guard_in(
                                            c,
                                            task.tenant_id,
                                            task.registration_id,
                                            task.generation as i64,
                                        )
                                        .await?
                                            != Some((recovery.task_id, recovery.attempt_id))
                                    {
                                        return Err(vault::Error::Conflict);
                                    }
                                    materials::reconcile_in(c, &coordinates, recovery.task_id)
                                        .await?;
                                } else {
                                    materials::verify_in(c, &coordinates, material.operation)
                                        .await?;
                                }
                            } else if requires_verification {
                                materials::unknown_in(c, task.tenant_id, material.operation)
                                    .await?;
                            } else {
                                materials::settled_in(c, &coordinates, material.operation).await?;
                            }
                        } else {
                            success = false;
                            materials::unknown_in(c, task.tenant_id, task.task_id).await?;
                        }
                    }
                    if let Some(recovery) = &task.recovery {
                        if value.recovery == Some(wire::CredentialRecoveryOutcome::NotAttempted) {
                            if !materials::agent_materials_in(
                                c,
                                task.tenant_id,
                                recovery.task_id,
                                recovery.attempt_id,
                            )
                            .await?
                            .is_empty()
                                || materials::agent_guard_in(
                                    c,
                                    task.tenant_id,
                                    task.registration_id,
                                    task.generation as i64,
                                )
                                .await?
                                    != Some((recovery.task_id, recovery.attempt_id))
                                || materials::finish_agent_in(c, task.tenant_id, recovery.task_id)
                                    .await?
                                    != Some(recovery.attempt_id)
                            {
                                return Err(vault::Error::Conflict);
                            }
                            recovered.push((
                                recovery.task_id,
                                recovery.attempt_id,
                                wire::CredentialRecoveryOutcome::NotAttempted,
                            ));
                        } else if success
                            && value.items.len() == 1
                            && value.items[0].outcome == wire::CredentialOutcome::Verified
                        {
                            let effect = value.recovery.ok_or(vault::Error::Conflict)?;
                            if let wire::CredentialOperation::VerifyBitlocker {
                                volume,
                                protector,
                            } = &task.operation
                            {
                                let old = wire::CredentialSubject::Bitlocker {
                                    volume: volume.clone(),
                                    protector: *protector,
                                };
                                let unchanged = value.items[0].subject == old;
                                if unchanged
                                    != (effect == wire::CredentialRecoveryOutcome::Unchanged)
                                {
                                    return Err(vault::Error::Conflict);
                                }
                                if !unchanged {
                                    let revision = task
                                        .expected
                                        .iter()
                                        .find(|v| v.subject == old)
                                        .map(|v| v.revision)
                                        .unwrap_or(0);
                                    materials::supersede_in(
                                        c,
                                        task.tenant_id,
                                        &vault::Binding {
                                            device: task.device_id.clone(),
                                            registration: task.registration_id,
                                            generation: task.generation as i64,
                                            subject: subject(&old),
                                        },
                                        revision,
                                    )
                                    .await?;
                                }
                            }
                            if materials::finish_agent_in(c, task.tenant_id, recovery.task_id)
                                .await?
                                != Some(recovery.attempt_id)
                            {
                                return Err(vault::Error::Conflict);
                            }
                            recovered.push((recovery.task_id, recovery.attempt_id, effect));
                        } else if value.recovery.is_some() {
                            return Err(vault::Error::Conflict);
                        }
                    }
                    if success
                        && value
                            .items
                            .iter()
                            .all(|i| i.outcome == wire::CredentialOutcome::Verified)
                        && let wire::CredentialOperation::RotateBitlocker { volume, protector } =
                            &task.operation
                    {
                        let previous = wire::CredentialSubject::Bitlocker {
                            volume: volume.clone(),
                            protector: *protector,
                        };
                        let revision = task
                            .expected
                            .iter()
                            .find(|v| v.subject == previous)
                            .map(|v| v.revision)
                            .unwrap_or(0);
                        materials::supersede_in(
                            c,
                            task.tenant_id,
                            &vault::Binding {
                                device: task.device_id.clone(),
                                registration: task.registration_id,
                                generation: task.generation as i64,
                                subject: subject(&previous),
                            },
                            revision,
                        )
                        .await?;
                    }
                    let no_effect = escrowed.is_empty()
                        && matches!(
                            value.failure,
                            Some(
                                wire::CredentialFailure::NoMaterials
                                    | wire::CredentialFailure::Unsupported
                                    | wire::CredentialFailure::PermissionDenied
                                    | wire::CredentialFailure::OwnerConflict
                                    | wire::CredentialFailure::TargetMissing
                            )
                        );
                    let uncertain = matches!(
                        value.failure,
                        Some(
                            wire::CredentialFailure::NativeFailure
                                | wire::CredentialFailure::RecoveryState
                        )
                    ) || value
                        .items
                        .iter()
                        .any(|i| i.outcome == wire::CredentialOutcome::Unknown)
                        || (requires_verification && !success && !no_effect);
                    if success || no_effect {
                        materials::finish_agent_in(c, task.tenant_id, task.task_id).await?;
                    }
                    Ok::<_, vault::Error>((success, uncertain, recovered))
                }
                .await;
                Ok(result)
            })
        })
        .await?
        .map_err(recovery_credentials::error)?;
    for (id, attempt, effect) in recovered {
        let mut original = actions::storage::load_run(tx, id).await?;
        if original.target.device != run.target.device
            || original.target.registration != run.target.registration
            || original.target.generation != run.target.generation
        {
            return Err(Error::Conflict.into());
        }
        if matches!(
            original.state.execution,
            actions::state::Execution::Unknown | actions::state::Execution::Running
        ) {
            original
                .state
                .result(attempt, effect == wire::CredentialRecoveryOutcome::Applied)?;
            original.result = Some(
                serde_json::json!({"effect":effect,"recoveredByTask":run.id,"recoveredByAttempt":run.state.attempt()}),
            );
            actions::storage::save_run(tx, &original).await?;
        }
    }
    let _ = service;
    Ok(if uncertain {
        actions::state::Execution::Unknown
    } else if success {
        actions::state::Execution::Succeeded
    } else {
        actions::state::Execution::Failed
    })
}

pub async fn start(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &actions::storage::Run,
    attempt: Uuid,
) -> Result<()> {
    let _ = service;
    let actions::evidence::Material::Credential { task } =
        actions::evidence::load_in(tx, run.id, attempt).await?
    else {
        return Err(Error::Conflict.into());
    };
    if matches!(
        task.operation,
        wire::CredentialOperation::RotateBitlocker { .. }
            | wire::CredentialOperation::RotateLocalAdministrator { .. }
    ) {
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(materials::start_agent_in(
                    c,
                    task.tenant_id,
                    task.registration_id,
                    task.generation as i64,
                    task.task_id,
                    task.attempt_id,
                )
                .await)
            })
        })
        .await?
        .map_err(recovery_credentials::error)?;
    }
    Ok(())
}
