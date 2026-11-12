//! Credential policies share the existing schedule and durable Agent task lifecycle.
use super::agent_facts;
use super::{authorization::Permission, policy::ExecutionInput, *};
use crate::{self as vault, storage as materials};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_agent_wire::runtime as wire;
use rss_mdm_policy::{Architecture, CredentialOperation as Operation};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FrozenCredential {
    pub input: ExecutionInput,
    pub operation: Operation,
}
pub fn permission(operation: &Operation) -> Permission {
    match operation {
        Operation::RotateRssLogin { .. }
        | Operation::VerifyRssLogin { .. }
        | Operation::RotateLocalAdministrator { .. }
        | Operation::VerifyLocalAdministrator { .. } => Permission::AccountWrite,
        _ => Permission::SecurityOperate,
    }
}
impl FrozenCredential {
    pub fn permission(&self) -> Permission {
        permission(&self.operation)
    }
    pub(crate) async fn authorized_in(
        &self,
        service: &crate::tasks::Transactions,
        tx: &mut PgTransaction<'_>,
        target: &Target,
        _now: i64,
    ) -> Result<bool> {
        if super::product::rss(&self.operation)
            && !agent_facts::agent_binding_in(tx, service.agent_store.clone(), target.device)
                .await?
                .is_some_and(|b| b.capabilities.contains(&wire::Capability::DeviceAccessV1))
        {
            return Ok(false);
        }
        match super::product::anchor(service, tx, &self.operation, target).await {
            Ok(_) => Ok(true),
            Err(super::transaction::Fault::Request(
                Error::Forbidden | Error::Conflict | Error::NotFound | Error::Unsupported,
            )) => Ok(false),
            Err(e) => Err(e),
        }
    }
}
pub fn capable(binding: &agent_facts::Binding, architecture: Architecture) -> bool {
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
pub(crate) async fn eligible(
    service: &crate::tasks::Transactions,
    tx: &mut PgTransaction<'_>,
    target: &Target,
    architecture: Architecture,
) -> Result<bool> {
    Ok(
        agent_facts::agent_binding_in(tx, service.agent_store.clone(), target.device)
            .await?
            .is_some_and(|b| capable(&b, architecture)),
    )
}
fn operation(value: &Operation) -> wire::CredentialOperation {
    match value {
        Operation::RotateRssLogin {
            binding,
            binding_generation,
            sid,
        } => wire::CredentialOperation::RotateRssLogin {
            binding: *binding,
            binding_generation: *binding_generation,
            sid: sid.clone(),
        },
        Operation::VerifyRssLogin {
            binding,
            binding_generation,
            sid,
        } => wire::CredentialOperation::VerifyRssLogin {
            binding: *binding,
            binding_generation: *binding_generation,
            sid: sid.clone(),
        },
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
pub(crate) async fn task(
    profile: rss_mdm_install_support::StorageProfile,
    policy: &super::policy::CredentialPolicy,
    service: &crate::tasks::Transactions,
    tx: &mut PgTransaction<'_>,
    target: &Target,
    issue: actions::storage::TaskIssue,
) -> Result<wire::TaskPayload> {
    let protection = service.recovery_credentials.as_ref();
    let recipient = protection.active_recipient();
    recipient
        .require_current(crate::tasks::storage::now(tx).await?)
        .map_err(Error::from)?;
    let recipient = wire::CredentialRecipient {
        key_id: recipient.id().into(),
        public_key: STANDARD.encode(recipient.public_key_der().map_err(Error::from)?),
    };
    let tenant = checked_input(Uuid::parse_str(&tx.tenant_id().to_string()))?;
    let run = actions::storage::load_run(profile, tx, issue.run).await?;
    let target_owned = run
        .material
        .as_ref()
        .map(|b| Target { device: b.device })
        .unwrap_or_else(|| target.clone());
    let product = service.product.clone();
    let revisions = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(materials::revisions_in(
                    super::product::custody(profile, product.as_deref()),
                    c,
                    tenant,
                    &target_owned.device,
                )
                .await)
            })
        })
        .await?
        .map_err(Error::from)?;
    let mut expected = revisions
        .into_iter()
        .filter(|(subject, _)| {
            run.material
                .as_ref()
                .is_none_or(|anchor| &anchor.subject == subject)
        })
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
    let operation = operation(&policy.frozen.operation);
    let recovery = if matches!(
        operation,
        wire::CredentialOperation::VerifyRssLogin { .. }
            | wire::CredentialOperation::VerifyBitlocker { .. }
            | wire::CredentialOperation::VerifyLocalAdministrator { .. }
    ) {
        let registration = run
            .material
            .as_ref()
            .map_or_else(|| target.device, |b| b.device);
        let product = service.product.clone();
        let guard = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(materials::agent_guard_in(
                        super::product::custody(profile, product.as_deref()),
                        c,
                        tenant,
                        registration,
                    )
                    .await)
                })
            })
            .await?
            .map_err(Error::from)?;
        if let Some((task_id, attempt_id)) = guard {
            let original = actions::storage::load_run(profile, tx, task_id).await?;
            let actions::evidence::Material::Credential {
                task: original_task,
            } = actions::evidence::load_in(service.agent_store.clone(), tx, task_id, attempt_id)
                .await?;
            let matching = match (&operation, &original_task.operation) {
                (
                    wire::CredentialOperation::VerifyRssLogin {
                        binding,
                        binding_generation,
                        sid,
                    },
                    wire::CredentialOperation::RotateRssLogin {
                        binding: b,
                        binding_generation: g,
                        sid: s,
                    },
                ) => binding == b && binding_generation == g && sid == s,
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
                || original.state.attempt() != Some(attempt_id)
                || !matches!(
                    original.state.execution,
                    rss_mdm_task_state::Execution::Unknown
                )
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
        device_id: target.device,
        platform: wire::TaskPlatform::Windows,
        architecture: match policy.frozen.input.architecture {
            Architecture::X86_64 => wire::TaskArchitecture::X86_64,
            Architecture::Aarch64 => wire::TaskArchitecture::Aarch64,
        },

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
pub(crate) fn subject(value: &wire::CredentialSubject) -> vault::Subject {
    match value {
        wire::CredentialSubject::RssLogin {
            binding,
            binding_generation,
            sid,
        } => vault::Subject::RssLogin {
            binding: *binding,
            binding_generation: *binding_generation,
            sid: sid.clone(),
        },
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
            wire::CredentialOperation::RotateRssLogin {
                binding,
                binding_generation,
                sid,
            }
            | wire::CredentialOperation::VerifyRssLogin {
                binding,
                binding_generation,
                sid,
            },
            wire::CredentialSubject::RssLogin {
                binding: b,
                binding_generation: g,
                sid: s,
            },
        ) => binding == b && binding_generation == g && sid == s,
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
pub(crate) async fn escrow(
    profile: rss_mdm_install_support::StorageProfile,
    service: &crate::tasks::Transactions,
    tx: &mut PgTransaction<'_>,
    run: &actions::storage::Run,
    attempt: Uuid,
    value: &wire::CredentialEscrow,
) -> Result<Vec<wire::CredentialReceipt>> {
    checked_input(value.validate())?;
    let actions::evidence::Material::Credential { task } =
        actions::evidence::load_in(service.agent_store.clone(), tx, run.id, attempt).await?;
    if task.definition_digest != value.definition_digest
        || task.task_id != run.id
        || task.attempt_id != attempt
    {
        return Err(Error::Conflict.into());
    }
    let protection = service.recovery_credentials.clone();
    let product = service.product.clone();
    let anchor = run.material.clone();
    let registration = anchor.as_ref().map_or_else(|| task.device_id, |a| a.device);
    let value = value.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result = async {
                let recipient = protection.recipient(&task.recipient.key_id)?;
                let mut receipts = Vec::new();
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
                    let binding = super::product::material(
                        anchor.as_ref(),
                        &Target {
                            device: task.device_id,
                        },
                        subject(&item.subject),
                    )?;
                    let verifying = matches!(
                        task.operation,
                        wire::CredentialOperation::VerifyRssLogin { .. }
                            | wire::CredentialOperation::VerifyBitlocker { .. }
                            | wire::CredentialOperation::VerifyLocalAdministrator { .. }
                    );
                    let coordinates = if let Some(recovery) = &task.recovery {
                        if materials::agent_guard_in(
                            super::product::custody(profile, product.as_deref()),
                            c,
                            task.tenant_id,
                            registration,
                        )
                        .await?
                            != Some((recovery.task_id, recovery.attempt_id))
                        {
                            return Err(vault::Error::Conflict);
                        }
                        materials::recovery_secret_in(
                            super::product::custody(profile, product.as_deref()),
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
                            super::product::custody(profile, product.as_deref()),
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
                            super::product::custody(profile, product.as_deref()),
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
                            materials::unknown_in(
                                super::product::custody(profile, product.as_deref()),
                                c,
                                task.tenant_id,
                                task.task_id,
                            )
                            .await?;
                        }
                        materials::ingest_in(
                            super::product::custody(profile, product.as_deref()),
                            c,
                            &protection.keys,
                            &coordinates,
                            task.task_id,
                            &secret,
                        )
                        .await?;
                        coordinates
                    };
                    materials::link_agent_in(
                        super::product::custody(profile, product.as_deref()),
                        c,
                        task.task_id,
                        task.attempt_id,
                        &coordinates,
                    )
                    .await?;
                    receipts.push(wire::CredentialReceipt {
                        subject: item.subject.clone(),
                        material: coordinates.material,
                        version: coordinates.version,
                    });
                }
                Ok::<_, vault::Error>(receipts)
            }
            .await;
            Ok(result)
        })
    })
    .await?
    .map_err(Error::from)
    .map_err(Into::into)
}
pub(crate) async fn finish(
    profile: rss_mdm_install_support::StorageProfile,
    service: &crate::tasks::Transactions,
    tx: &mut PgTransaction<'_>,
    run: &actions::storage::Run,
    attempt: Uuid,
    value: &wire::CredentialResult,
) -> Result<rss_mdm_task_state::Execution> {
    checked_input(value.validate())?;
    let actions::evidence::Material::Credential { task } =
        actions::evidence::load_in(service.agent_store.clone(), tx, run.id, attempt).await?;
    if task.definition_digest != value.definition_digest {
        return Err(Error::Conflict.into());
    }
    if value.recovery.is_some() && task.recovery.is_none() {
        return Err(Error::Conflict.into());
    }
    let product = service.product.clone();
    let anchor = run.material.clone();
    let registration = anchor.as_ref().map_or_else(|| task.device_id, |a| a.device);
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
                        super::product::custody(profile, product.as_deref()),
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
                                profile,
                                tenant: task.tenant_id,
                                material: material.id,
                                version: material.version,
                                binding: material.binding.clone(),
                            };
                            if item.outcome == wire::CredentialOutcome::Verified {
                                if let Some(recovery) = &task.recovery {
                                    if value.recovery.is_none()
                                        || materials::agent_guard_in(
                                            super::product::custody(profile, product.as_deref()),
                                            c,
                                            task.tenant_id,
                                            registration,
                                        )
                                        .await?
                                            != Some((recovery.task_id, recovery.attempt_id))
                                    {
                                        return Err(vault::Error::Conflict);
                                    }
                                    materials::reconcile_in(
                                        super::product::custody(profile, product.as_deref()),
                                        c,
                                        &coordinates,
                                        recovery.task_id,
                                    )
                                    .await?;
                                } else {
                                    materials::verify_in(
                                        super::product::custody(profile, product.as_deref()),
                                        c,
                                        &coordinates,
                                        material.operation,
                                    )
                                    .await?;
                                }
                            } else if requires_verification {
                                materials::unknown_in(
                                    super::product::custody(profile, product.as_deref()),
                                    c,
                                    task.tenant_id,
                                    material.operation,
                                )
                                .await?;
                            } else {
                                materials::settled_in(
                                    super::product::custody(profile, product.as_deref()),
                                    c,
                                    &coordinates,
                                    material.operation,
                                )
                                .await?;
                            }
                        } else {
                            success = false;
                            materials::unknown_in(
                                super::product::custody(profile, product.as_deref()),
                                c,
                                task.tenant_id,
                                task.task_id,
                            )
                            .await?;
                        }
                    }
                    if let Some(recovery) = &task.recovery {
                        if value.recovery == Some(wire::CredentialRecoveryOutcome::NotAttempted) {
                            if !materials::agent_materials_in(
                                super::product::custody(profile, product.as_deref()),
                                c,
                                task.tenant_id,
                                recovery.task_id,
                                recovery.attempt_id,
                            )
                            .await?
                            .is_empty()
                                || materials::agent_guard_in(
                                    super::product::custody(profile, product.as_deref()),
                                    c,
                                    task.tenant_id,
                                    registration,
                                )
                                .await?
                                    != Some((recovery.task_id, recovery.attempt_id))
                                || materials::finish_agent_in(
                                    super::product::custody(profile, product.as_deref()),
                                    c,
                                    task.tenant_id,
                                    recovery.task_id,
                                )
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
                                        super::product::custody(profile, product.as_deref()),
                                        c,
                                        task.tenant_id,
                                        &vault::Binding {
                                            device: task.device_id,

                                            subject: subject(&old),
                                        },
                                        revision,
                                    )
                                    .await?;
                                }
                            }
                            if materials::finish_agent_in(
                                super::product::custody(profile, product.as_deref()),
                                c,
                                task.tenant_id,
                                recovery.task_id,
                            )
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
                            super::product::custody(profile, product.as_deref()),
                            c,
                            task.tenant_id,
                            &vault::Binding {
                                device: task.device_id,

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
                        materials::finish_agent_in(
                            super::product::custody(profile, product.as_deref()),
                            c,
                            task.tenant_id,
                            task.task_id,
                        )
                        .await?;
                    }
                    Ok::<_, vault::Error>((success, uncertain, recovered))
                }
                .await;
                Ok(result)
            })
        })
        .await?
        .map_err(Error::from)?;
    for (id, attempt, effect) in recovered {
        let mut original = actions::storage::load_run(profile, tx, id).await?;
        if original.target.device != run.target.device {
            return Err(Error::Conflict.into());
        }
        if matches!(
            original.state.execution,
            rss_mdm_task_state::Execution::Unknown | rss_mdm_task_state::Execution::Running
        ) {
            original
                .state
                .result(attempt, effect == wire::CredentialRecoveryOutcome::Applied)?;
            original.result = Some(actions::result::RunResult::CredentialRecovery(
                actions::result::CredentialRecovery {
                    effect,
                    recovered_by_task: run.id,
                    recovered_by_attempt: run.state.attempt(),
                },
            ));
            actions::storage::save_run(profile, &service.reconcile_messaging, tx, &original)
                .await?;
        }
    }
    Ok(if uncertain {
        rss_mdm_task_state::Execution::Unknown
    } else if success {
        rss_mdm_task_state::Execution::Succeeded
    } else {
        rss_mdm_task_state::Execution::Failed
    })
}

pub(crate) async fn start(
    profile: rss_mdm_install_support::StorageProfile,
    service: &crate::tasks::Transactions,
    tx: &mut PgTransaction<'_>,
    run: &actions::storage::Run,
    attempt: Uuid,
) -> Result<()> {
    let actions::evidence::Material::Credential { task } =
        actions::evidence::load_in(service.agent_store.clone(), tx, run.id, attempt).await?;
    let product = service.product.clone();
    let registration = run
        .material
        .as_ref()
        .map_or_else(|| task.device_id, |a| a.device);
    if matches!(
        task.operation,
        wire::CredentialOperation::RotateRssLogin { .. }
            | wire::CredentialOperation::RotateBitlocker { .. }
            | wire::CredentialOperation::RotateLocalAdministrator { .. }
    ) {
        tx.with_connection(move |c| {
            Box::pin(async move {
                Ok(materials::start_agent_in(
                    super::product::custody(profile, product.as_deref()),
                    c,
                    task.tenant_id,
                    registration,
                    task.task_id,
                    task.attempt_id,
                )
                .await)
            })
        })
        .await?
        .map_err(Error::from)?;
    }
    Ok(())
}
