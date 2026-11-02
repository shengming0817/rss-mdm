//! Windows initialization belongs to the access attempt; recovery custody remains with its owner.
use super::*;
use crate::device_access as access;
use rss_mdm_agent_wire::runtime as wire;

pub(super) async fn plan(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    b: &access::Binding,
) -> Result<Option<wire::AccessWindowsPlan>> {
    if b.intent.platform() != wire::TaskPlatform::Windows {
        return Ok(None);
    }
    if matches!(
        b.configuration.windows,
        wire::AccessWindowsConfiguration::Whfb
    ) {
        let previous_key = match &b.applied_windows {
            Some(wire::AccessWindowsFacts::Whfb(f))
                if f.factor_generation != b.factor_generation =>
            {
                f.key_id
            }
            _ => None,
        };
        return Ok(Some(wire::AccessWindowsPlan::Whfb {
            retire: b.state == rss_mdm_device_access::State::Revoked,
            previous_key,
        }));
    }
    if b.state == rss_mdm_device_access::State::Revoked {
        return Ok(None);
    }
    let recovery = service.recovery.as_ref().ok_or(Error::Unsupported)?;
    let now = storage::now(tx).await?;
    tx.with_connection_context(&mut (recovery, b), |(recovery, binding), c| {
        Box::pin(async move { Ok(recovery.plan(c, binding, now).await) })
    })
    .await?
    .map(Some)
    .map_err(|e| Error::from(e).into())
}

async fn task(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    run: Uuid,
    attempt: Uuid,
) -> Result<wire::AccessTaskSpec> {
    let tenant = tx.tenant_id().to_string();
    let store = service.agent_store.clone();
    let payload = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(store.payload(c, tenant, run, attempt).await) })
        })
        .await??;
    let wire::TaskPayload::DeviceAccess(task) = payload else {
        return Err(Error::Conflict.into());
    };
    if task.task_id != run || task.attempt_id != attempt || task.permit != wire::TaskPermit::Start {
        return Err(Error::Conflict.into());
    }
    Ok(*task)
}
pub(crate) async fn prepared(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    run: &storage::Run,
    input: &wire::TaskEventRequest,
    value: &wire::AccessPrepared,
) -> Result<()> {
    let task = task(service, tx, run.id, input.attempt_id()).await?;
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
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    run: &storage::Run,
    attempt: Uuid,
    value: &wire::CredentialEscrow,
) -> Result<Vec<wire::CredentialReceipt>> {
    let task = task(service, tx, run.id, attempt).await?;
    let recovery = service.recovery.as_ref().ok_or(Error::Unsupported)?;
    tx.with_connection_context(
        &mut (recovery, &task, value),
        |(recovery, task, value), c| {
            Box::pin(async move { Ok(recovery.escrow(c, task, value).await) })
        },
    )
    .await?
    .map_err(|e| Error::from(e).into())
}
pub(crate) async fn finish(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    run: &storage::Run,
    attempt: Uuid,
    report: &wire::AccessResult,
    project: bool,
) -> Result<()> {
    let task = task(service, tx, run.id, attempt).await?;
    if task.platform != wire::TaskPlatform::Windows {
        return Ok(());
    }
    if let wire::AccessEffect::WhfbRetired { account, facts, .. } = &report.effect {
        if !matches!(
            task.windows,
            Some(wire::AccessWindowsPlan::Whfb { retire: true, .. })
        ) || facts.factor_generation != task.factor_generation
            || !matches!(&task.action, wire::AccessAction::Unbind { account: expected, .. } if expected == account)
        {
            return Err(Error::Conflict.into());
        }
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
    if facts.factor_generation() != task.factor_generation {
        return Err(Error::Conflict.into());
    }
    if let wire::AccessWindowsFacts::Whfb(facts) = facts {
        let Some(wire::AccessWindowsPlan::Whfb {
            retire: false,
            previous_key,
        }) = task.windows
        else {
            return Err(Error::Conflict.into());
        };
        if previous_key.is_some()
            && facts.key_id == previous_key
            && facts.registration == wire::AccessObservation::Present
        {
            return Err(Error::Conflict.into());
        }
        return Ok(());
    }
    let wire::AccessWindowsFacts::RssFactor(facts) = facts else {
        return Err(Error::Conflict.into());
    };
    let wire::AccessAccount::Windows { sid, .. } = account else {
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
    let recovery = service.recovery.as_ref().ok_or(Error::Unsupported)?.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result: std::result::Result<(), crate::Error> = async {
                let mut access =
                    access::storage::locked_observation_in(c, task.tenant_id, task.binding_id)
                        .await?;
                // A late receipt can settle custody, but cannot restore revoked access or authorize a later factor generation.
                if access.state == rss_mdm_device_access::State::Revoked
                    || access.generation != task.binding_generation
                    || !rss_mdm_registration_service::lifecycle::work_allowed_in(
                        rss_mdm_install_support::StorageProfile::Da,
                        c,
                        &task.tenant_id.to_string(),
                        &task.device_id,
                    )
                    .await?
                {
                    return Ok(());
                }
                recovery.settle(c, &task, &facts).await?;
                if !project {
                    access.applied_windows = Some(wire::AccessWindowsFacts::RssFactor(facts));
                    access::storage::save_in(c, &access, access.revision).await?;
                }
                Ok(())
            }
            .await;
            Ok(result)
        })
    })
    .await?
    .map_err(Error::from)?;
    Ok(())
}

/// Never terminalize an attempt with an escrowed but unverified local candidate.
pub(crate) async fn unresolved(
    service: &Transactions,
    tx: &mut PgTransaction<'_>,
    run: &storage::Run,
    attempt: Uuid,
    terminal: bool,
) -> Result<bool> {
    let task = task(service, tx, run.id, attempt).await?;
    if task.platform != wire::TaskPlatform::Windows
        || matches!(task.windows, Some(wire::AccessWindowsPlan::Whfb { .. }))
    {
        return Ok(false);
    }
    let recovery = service.recovery.as_ref().ok_or(Error::Unsupported)?.clone();
    tx.with_connection(move |c| {
        Box::pin(async move {
            let result: std::result::Result<bool, crate::Error> = async {
                let b = access::storage::locked_observation_in(c, task.tenant_id, task.binding_id)
                    .await?;
                let withdrawn = b.state == rss_mdm_device_access::State::Revoked
                    || b.generation != task.binding_generation
                    || !rss_mdm_registration_service::lifecycle::work_allowed_in(
                        rss_mdm_install_support::StorageProfile::Da,
                        c,
                        &task.tenant_id.to_string(),
                        &task.device_id,
                    )
                    .await?;
                recovery
                    .unresolved(
                        c,
                        &task,
                        if withdrawn {
                            crate::device_access::participants::BindingDisposition::Withdrawn
                        } else {
                            crate::device_access::participants::BindingDisposition::Current
                        },
                        terminal,
                    )
                    .await
            }
            .await;
            Ok(result)
        })
    })
    .await?
    .map_err(Error::from)
    .map_err(Into::into)
}
