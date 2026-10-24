//! Windows initialization belongs to the access attempt; recovery custody remains with its owner.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_recovery_credentials::{self as vault, storage as materials};

fn subject(b: &access::Binding) -> Option<wire::CredentialSubject> {
    match &b.account {
        Some(wire::AccessAccount::Windows { sid }) => Some(wire::CredentialSubject::RssLogin {
            binding: b.id,
            binding_generation: b.generation,
            sid: sid.clone(),
        }),
        _ => None,
    }
}
pub(super) async fn plan(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    b: &access::Binding,
) -> Result<Option<wire::AccessWindowsPlan>> {
    if b.intent.platform() != wire::TaskPlatform::Windows || b.state == access::State::Revoked {
        return Ok(None);
    }
    let expected_subject = subject(b);
    if let Some(facts) = &b.applied_windows
        && facts.factor_generation == b.factor_generation
        && expected_subject.as_ref() == Some(&facts.recovery.subject)
    {
        let binding = vault::Binding {
            device: b.device.clone(),
            registration: b.registration,
            generation: b.registration_generation,
            subject: crate::credential_tasks::subject(&facts.recovery.subject),
        };
        let tenant = b.tenant;
        let current = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(materials::current_in(c, tenant, &binding).await) })
            })
            .await?
            .map_err(crate::recovery_credentials::error)?
            .ok_or(Error::Conflict)?;
        if current.validity != vault::Validity::Verified || !current.escrowed {
            return Err(Error::Conflict.into());
        }
        let mut facts = facts.clone();
        facts.recovery.material = current.id;
        facts.recovery.version = current.version;
        return Ok(Some(wire::AccessWindowsPlan::Preserve { facts }));
    }
    let protection = service
        .recovery_credentials
        .as_ref()
        .ok_or(Error::Unsupported)?;
    let recipient = protection.active_recipient();
    recipient
        .require_current(crate::storage::now(tx).await?)
        .map_err(crate::recovery_credentials::error)?;
    let recipient = wire::CredentialRecipient {
        key_id: recipient.id().into(),
        public_key: STANDARD.encode(
            recipient
                .public_key_der()
                .map_err(crate::recovery_credentials::error)?,
        ),
    };
    let binding = b.clone();
    let expected_revision = tx
        .with_connection(move |c| {
            Box::pin(async move {
                let rows = materials::revisions_in(
                    c,
                    binding.tenant,
                    &binding.device,
                    binding.registration,
                    binding.registration_generation,
                )
                .await;
                Ok(rows.map(|rows| {
                    expected_subject
                        .as_ref()
                        .and_then(|s| {
                            rows.into_iter()
                                .find(|(v, _)| v == &crate::credential_tasks::subject(s))
                                .map(|(_, r)| r)
                        })
                        .unwrap_or(0)
                }))
            })
        })
        .await?
        .map_err(crate::recovery_credentials::error)?;
    Ok(Some(wire::AccessWindowsPlan::Initialize {
        recipient,
        expected_revision,
    }))
}
async fn task(
    tx: &mut PgTransaction<'_>,
    run: Uuid,
    attempt: Uuid,
) -> Result<wire::AccessTaskSpec> {
    let crate::actions::evidence::Material::DeviceAccess { task } =
        crate::actions::evidence::load_in(tx, run, attempt).await?
    else {
        return Err(Error::Conflict.into());
    };
    if task.task_id != run || task.attempt_id != attempt || task.permit != wire::TaskPermit::Start {
        return Err(Error::Conflict.into());
    }
    Ok(*task)
}
pub(crate) async fn prepared(
    tx: &mut PgTransaction<'_>,
    run: &runs::Run,
    input: &wire::TaskEventRequest,
    value: &wire::AccessPrepared,
) -> Result<()> {
    let task = task(tx, run.id, input.attempt_id()).await?;
    if task.binding_id != value.binding_id
        || task.binding_generation != value.binding_generation
        || task.revision != value.revision
        || task.definition_digest != value.definition_digest
        || task.platform != wire::TaskPlatform::Windows
        || matches!(task.action, wire::AccessAction::Unbind { .. })
    {
        return Err(Error::Conflict.into());
    }
    if let wire::AccessAction::Apply { account, .. } = &task.action
        && account != &value.account
    {
        return Err(Error::Conflict.into());
    }
    let value = value.clone();
    tx.with_connection(move |c| {
        Box::pin(async move { Ok(access::storage::prepared_in(c, task.tenant_id, &value).await) })
    })
    .await??;
    Ok(())
}
pub(crate) async fn escrow(
    service: &ExecutionService,
    tx: &mut PgTransaction<'_>,
    run: &runs::Run,
    attempt: Uuid,
    value: &wire::CredentialEscrow,
) -> Result<Vec<wire::CredentialReceipt>> {
    checked_input(value.validate())?;
    let task = task(tx, run.id, attempt).await?;
    if value.materials.len() != 1 || value.definition_digest != task.definition_digest {
        return Err(Error::Conflict.into());
    }
    let Some(wire::AccessWindowsPlan::Initialize { recipient, .. }) = &task.windows else {
        return Err(Error::Conflict.into());
    };
    let item = value.materials[0].clone();
    let aad = checked_input(task.material_aad(&item.subject, item.expected_revision))?;
    let protection = service
        .recovery_credentials
        .as_ref()
        .ok_or(Error::Unsupported)?
        .clone();
    let secret = protection
        .recipient(&recipient.key_id)
        .map_err(crate::recovery_credentials::error)?
        .open_envelope(
            &checked_input(STANDARD.decode(&item.wrapped_key))?,
            item.nonce,
            &checked_input(STANDARD.decode(&item.ciphertext))?,
            &aad,
        )
        .map_err(crate::recovery_credentials::error)?;
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result = async {
                let b = access::storage::locked_in(c, task.tenant_id, task.binding_id).await?;
                if b.generation != task.binding_generation
                    || b.factor_generation != task.factor_generation
                    || b.revision != task.revision
                    || b.definition_digest()? != task.definition_digest
                    || subject(&b).as_ref() != Some(&item.subject)
                {
                    return Err(vault::Error::Conflict);
                }
                let binding = vault::Binding {
                    device: task.device_id.clone(),
                    registration: task.registration_id,
                    generation: task.generation as i64,
                    subject: crate::credential_tasks::subject(&item.subject),
                };
                let coordinates = materials::reserve_in(
                    c,
                    task.tenant_id,
                    &binding,
                    task.task_id,
                    item.expected_revision,
                )
                .await?;
                materials::ingest_in(c, &protection.keys, &coordinates, task.task_id, &secret)
                    .await?;
                materials::link_agent_in(c, task.task_id, task.attempt_id, &coordinates).await?;
                Ok(vec![wire::CredentialReceipt {
                    subject: item.subject,
                    material: coordinates.material,
                    version: coordinates.version,
                }])
            }
            .await;
            Ok(result)
        })
    })
    .await?
    .map_err(crate::recovery_credentials::error)
    .map_err(Into::into)
}
pub(crate) async fn finish(
    tx: &mut PgTransaction<'_>,
    run: &runs::Run,
    attempt: Uuid,
    report: &wire::AccessResult,
    project: bool,
) -> Result<()> {
    let task = task(tx, run.id, attempt).await?;
    if task.platform != wire::TaskPlatform::Windows {
        return Ok(());
    }
    let wire::AccessEffect::Applied {
        account,
        windows: Some(facts),
        ..
    } = &report.effect
    else {
        return Ok(());
    };
    if facts.factor_generation != task.factor_generation {
        return Err(Error::Conflict.into());
    }
    let wire::AccessAccount::Windows { sid } = account else {
        return Err(Error::Malformed.into());
    };
    if facts.recovery.subject
        != (wire::CredentialSubject::RssLogin {
            binding: task.binding_id,
            binding_generation: task.binding_generation,
            sid: sid.clone(),
        })
    {
        return Err(Error::Conflict.into());
    }
    let facts = facts.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result = async {
                let mut access =
                    access::storage::locked_observation_in(c, task.tenant_id, task.binding_id)
                        .await?;
                // A late receipt can settle custody, but cannot restore revoked access or authorize a later factor generation.
                if access.state == access::State::Revoked
                    || access.generation != task.binding_generation
                    || !rss_mdm_registration_service::lifecycle::work_allowed_in(
                        c,
                        &task.tenant_id.to_string(),
                        &task.device_id,
                    )
                    .await?
                {
                    return Ok(());
                }
                let binding = vault::Binding {
                    device: task.device_id,
                    registration: task.registration_id,
                    generation: task.generation as i64,
                    subject: crate::credential_tasks::subject(&facts.recovery.subject),
                };
                let coordinates = materials::coordinates_in(
                    c,
                    task.tenant_id,
                    &binding.device,
                    facts.recovery.material,
                    facts.recovery.version,
                )
                .await?;
                if coordinates.binding != binding {
                    return Err(vault::Error::Conflict);
                }
                match task.windows {
                    Some(wire::AccessWindowsPlan::Initialize { .. }) => {
                        let stored = materials::agent_materials_in(
                            c,
                            task.tenant_id,
                            task.task_id,
                            task.attempt_id,
                        )
                        .await?;
                        if stored.len() != 1
                            || stored[0].id != coordinates.material
                            || stored[0].version != coordinates.version
                        {
                            return Err(vault::Error::Conflict);
                        }
                        materials::verify_in(c, &coordinates, task.task_id).await?;
                    }
                    Some(wire::AccessWindowsPlan::Preserve { facts: expected })
                        if facts == expected =>
                    {
                        let current = materials::current_in(c, task.tenant_id, &binding)
                            .await?
                            .ok_or(vault::Error::Conflict)?;
                        if current.id != coordinates.material
                            || current.version != coordinates.version
                            || current.validity != vault::Validity::Verified
                            || !current.escrowed
                        {
                            return Err(vault::Error::Conflict);
                        }
                    }
                    _ => return Err(vault::Error::Conflict),
                }
                if !project {
                    access.applied_windows = Some(facts);
                    access::storage::save_in(c, &access, access.revision).await?;
                }
                Ok(())
            }
            .await;
            Ok(result)
        })
    })
    .await?
    .map_err(crate::recovery_credentials::error)?;
    Ok(())
}

/// Never terminalize an attempt with an escrowed but unverified local candidate.
pub(crate) async fn unresolved(
    tx: &mut PgTransaction<'_>,
    run: &runs::Run,
    attempt: Uuid,
    terminal: bool,
) -> Result<bool> {
    let task = task(tx, run.id, attempt).await?;
    if task.platform != wire::TaskPlatform::Windows {
        return Ok(false);
    }
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result = async {
                let b = access::storage::locked_observation_in(c, task.tenant_id, task.binding_id)
                    .await?;
                let withdrawn = b.state == access::State::Revoked
                    || b.generation != task.binding_generation
                    || !rss_mdm_registration_service::lifecycle::work_allowed_in(
                        c,
                        &task.tenant_id.to_string(),
                        &task.device_id,
                    )
                    .await?;
                let values =
                    materials::agent_materials_in(c, task.tenant_id, task.task_id, task.attempt_id)
                        .await?;
                if withdrawn {
                    if terminal {
                        for v in values {
                            let coordinates = vault::Coordinates {
                                tenant: task.tenant_id,
                                material: v.id,
                                version: v.version,
                                binding: v.binding,
                            };
                            materials::settled_in(c, &coordinates, v.operation).await?;
                        }
                    }
                    return Ok(false);
                }
                Ok(values
                    .iter()
                    .any(|v| v.validity != vault::Validity::Verified))
            }
            .await;
            Ok(result)
        })
    })
    .await?
    .map_err(crate::recovery_credentials::error)
    .map_err(Into::into)
}
