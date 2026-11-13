use super::*;
use crate::{
    database::db,
    operations::{Actor, Operation},
};
use sha2::{Digest, Sha256};
use sqlx::{Row, postgres::PgRow};

fn uuid(row: &PgRow, name: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(&row.try_get::<String, _>(name).map_err(db)?).map_err(|_| Error::Storage)
}
fn digest(value: &impl Serialize) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("closed operation"))
    )
}
fn locator(proof: &VerifiedChannelCredential) -> String {
    proof.locator.iter().map(|v| format!("{v:02x}")).collect()
}
pub async fn lock_channel(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    channel: Channel,
) -> Result<(), Error> {
    lock_channels(profile, tx, tenant, &[(device.to_owned(), channel)]).await
}
pub async fn lock_channels(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    targets: &[(rss_mdm_agent_wire::DeviceId, Channel)],
) -> Result<(), Error> {
    let devices = targets
        .iter()
        .map(|(device, _)| *device)
        .collect::<Vec<_>>();
    crate::lifecycle::lock_devices_in(profile, c, tenant, &devices).await?;
    let keys = targets
        .iter()
        .map(|(d, c)| (d, c.as_str()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|(device, channel)| {
            serde_json::to_string(&(profile.name(), tenant, device, channel))
                .map_err(|_| Error::Malformed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(key,2348)) FROM unnest($1::text[]) WITH ORDINALITY locks(key,n) ORDER BY n").bind(keys).execute(c).await.map_err(db)?;
    Ok(())
}
/// Record a validated management exchange, Agent task poll or Agent report.
/// The channel owner must first accept the protocol request. This function rechecks
/// current authority under the device fence and participates in its transaction.
/// Every protocol context updates the same owning device.
/// Only server receipt time is recorded, independently of Inventory and device clocks.
pub async fn record_communication_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
) -> Result<(), Error> {
    if profile != principal.profile() {
        return Err(crate::Error::Forbidden);
    }

    revalidate_management(profile, c, principal).await?;
    let updated =
        sqlx::query(crate::storage_profile::sql(profile).device_store_record_communication_in_1)
            .bind(principal.tenant().to_string())
            .bind(principal.device().into_uuid())
            .bind(principal.require_channel()?.as_str())
            .execute(c)
            .await
            .map_err(db)?;
    if updated.rows_affected() != 1 {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

impl DeviceService {
    pub async fn revoke_inner(
        &self,
        admin: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        key: Uuid,
        audit: &RequestAudit,
    ) -> Result<RevocationReceipt, Error> {
        let profile = self.profile();

        if key.is_nil() {
            return Err(Error::Malformed);
        }
        if admin.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        admin.credentials(device)?;
        let digest = digest(&("credential_revoke", device));
        let operation = Operation {
            actor: Actor::from_authorized(admin),
            key,
            digest: &digest,
        };
        let budget = self.retirement_budget();
        let attempt = self
            .audit_store
            .write(
                rss_request_context::TenantId::parse(admin.tenant_id())
                    .map_err(|_| Error::Malformed)?,
                &budget.source_control(),
                (
                    &self.audit_store,
                    RevokeInputs {
                        retirement: self.access.retirement.as_ref(),
                        admin,
                        device,
                        key,
                        audit,
                        operation: &operation,
                        facts: Vec::new(),
                    },
                ),
                |(store, inputs), tx| {
                    Box::pin(async move {
                        let (receipt, replayed) = tx
                            .with_connection_context(inputs, |inputs, c| {
                                Box::pin(revoke_on(profile, c, inputs))
                            })
                            .await?;
                        for fact in &inputs.facts {
                            store.append(tx, fact).await.map_err(Error::from)?;
                        }
                        let fact = rss_mdm_audit_integration::Fact::business(
                            inputs.audit,
                            rss_mdm_audit_integration::operation::OperationOwner::Registration,
                            &format!(
                                "credential_revoke:{}:{}",
                                inputs.admin.principal_id(),
                                inputs.key
                            ),
                            200,
                            "success",
                            None,
                        )
                        .map_err(Error::from)?;
                        (if replayed {
                            Ok(())
                        } else {
                            store.append(tx, &fact).await
                        })
                        .map_err(Error::from)?;
                        if replayed {
                            inputs.audit.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            );
                        }
                        inputs.audit.mark_commit_started();
                        Ok(receipt)
                    })
                },
            )
            .await;
        crate::operations::settle(attempt, audit)
    }
    pub async fn authorize_report(
        &self,
        credential: &VerifiedChannelCredential,
        source: ReportSource,
    ) -> Result<(DevicePrincipal, Scope), Error> {
        let profile = self.profile();

        if credential.purpose != Purpose::Primary
            || source != credential.source
            || self.tenant != credential.tenant.to_string()
        {
            return Err(Error::Forbidden);
        }
        let tenant = credential.tenant.to_string();
        let mut tx = self.access.begin(&tenant).await?;
        // Probe the immutable locator, then lock only the device first. Replacement uses
        // the same order; post-lock reads recheck credential and source state.
        let row = sqlx::query(crate::storage_profile::sql(profile).device_store_authorize_report_1)
            .bind(&tenant)
            .bind(credential.channel.as_str())
            .bind(locator(credential))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(Error::Unauthorized)?;
        let device: rss_mdm_agent_wire::DeviceId = row
            .try_get::<Uuid, _>("id")
            .and_then(crate::database::device_id)
            .map_err(db)?;
        let row = sqlx::query(crate::storage_profile::sql(profile).device_store_authorize_report_2)
            .bind(&tenant)
            .bind(device.into_uuid())
            .bind(credential.channel.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(Error::Unauthorized)?;
        let child =
            sqlx::query(crate::storage_profile::sql(profile).device_store_authorize_report_3)
                .bind(&tenant)
                .bind(device.into_uuid())
                .bind(credential.channel.as_str())
                .bind(locator(credential))
                .bind(source.as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(Error::Forbidden)?;
        let principal = DevicePrincipal {
            profile,
            tenant: credential.tenant,
            device: row
                .try_get::<uuid::Uuid, _>("device")
                .and_then(crate::database::device_id)
                .map_err(db)?,
            kind: RegistrationKind::from_channel(channel(&row)?),
            installation: installation_in(profile, &mut tx).await?,
            purpose: Purpose::Primary,
            protocol_request: None,
            epoch: uuid(&row, "epoch")?,
            credential: uuid(&child, "id")?,
            enrolled_user: (source == ReportSource::MdmWindows
                && row
                    .try_get::<Option<String>, _>("windows_profile")
                    .map_err(db)?
                    .as_deref()
                    == Some("Full")),
        };
        let scope = scope(
            profile,
            credential.tenant,
            &device,
            source.as_str(),
            uuid(&child, "epoch")?,
        )?;
        tx.commit().await.map_err(db)?;
        Ok((principal, scope))
    }
    pub async fn current_scope(
        &self,
        proof: &AuthorizedPrincipal,
        device: &rss_mdm_agent_wire::DeviceId,
        coordinates: Coordinates,
    ) -> Result<Scope, Error> {
        let profile = self.profile();

        if proof.tenant_id() != self.tenant {
            return Err(Error::Forbidden);
        }
        // Recheck current MDM resource permission. Requested coordinates only choose a source.
        proof.require(
            rss_mdm_authorization_service::Permission::InventoryRead,
            Some(device),
        )?;
        let mut tx = self.access.begin(proof.tenant_id()).await?;
        let row = sqlx::query(crate::storage_profile::sql(profile).device_store_current_scope_1)
            .bind(proof.tenant_id())
            .bind(device.into_uuid())
            .bind(coordinates.source.channel().as_str())
            .bind(coordinates.source.as_str())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(Error::NotFound)?;
        let scope = scope(
            profile,
            TenantId::parse(proof.tenant_id()).map_err(|_| Error::Unauthorized)?,
            device,
            coordinates.source.as_str(),
            uuid(&row, "epoch")?,
        )?;
        tx.commit().await.map_err(db)?;
        Ok(scope)
    }
}
fn channel(row: &PgRow) -> Result<Channel, Error> {
    match row.try_get::<String, _>("channel").map_err(db)?.as_str() {
        "agent" => Ok(Channel::Agent),
        "mdm" => Ok(Channel::Mdm),
        _ => Err(Error::Storage),
    }
}
fn unique_or_db(error: sqlx::Error) -> Error {
    if error
        .as_database_error()
        .is_some_and(|e| e.is_unique_violation())
    {
        Error::Conflict
    } else {
        db(error)
    }
}
pub async fn retire_state_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    state: &str,
    events: Option<&dyn crate::EventSink>,
) -> Result<(), Error> {
    let previous = sqlx::query(crate::storage_profile::sql(profile).device_store_retire_state_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_store_retire_state_in_2)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(state)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_store_retire_state_in_3)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(state)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_store_retire_state_in_4)
        .bind(tenant)
        .bind(device.into_uuid())
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if let Some(row) = previous
        && row.try_get::<String, _>("state").map_err(db)? == "active"
        && matches!(state, "retired" | "revoked" | "superseded")
    {
        crate::webhook::device(
            events,
            tx,
            tenant,
            device,
            row.try_get::<Option<String>, _>("channel")
                .map_err(db)?
                .as_deref()
                .unwrap_or("da_device"),
            state,
        )
        .await?;
    }
    Ok(())
}

/// Borrow the Database transaction; the caller commits binding, certificate and audit together.
#[allow(
    clippy::too_many_arguments,
    reason = "borrowed device transaction carries separate authorization, channel evidence, command, receipt identities and retirement participant"
)]
pub async fn bind_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    admin: &AuthorizedPrincipal,
    credential: &VerifiedChannelCredential,
    command: &BindRegistration,
    device: rss_mdm_agent_wire::DeviceId,
    ids: [Uuid; 2],
) -> Result<RegistrationReceipt, Error> {
    if profile != admin.profile() {
        return Err(crate::Error::Forbidden);
    }

    if profile != credential.profile {
        return Err(crate::Error::Forbidden);
    }

    bind_authorized_in(
        profile,
        tx,
        admin.tenant_id(),
        credential,
        command,
        device,
        ids,
    )
    .await
}
#[allow(
    clippy::too_many_arguments,
    reason = "one shared device mutation for user and policy authority"
)]
pub(crate) async fn bind_authorized_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    credential: &VerifiedChannelCredential,
    command: &BindRegistration,
    device: rss_mdm_agent_wire::DeviceId,
    ids: [Uuid; 2],
) -> Result<RegistrationReceipt, Error> {
    if profile != credential.profile {
        return Err(crate::Error::Forbidden);
    }

    if credential.purpose != Purpose::Primary || credential.tenant.to_string() != tenant {
        return Err(Error::Forbidden);
    }
    lock_channel(profile, tx, tenant, &device, credential.channel).await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
        .bind(format!("request:{}:{}", tenant, command.request_id))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if sqlx::query_scalar::<_, bool>(
        crate::storage_profile::sql(profile).device_store_bind_authorized_in_1,
    )
    .bind(tenant)
    .bind(command.request_id.to_string())
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?
    {
        return Err(Error::Conflict);
    }
    let request_source: String =
        sqlx::query_scalar(crate::storage_profile::sql(profile).device_store_bind_authorized_in_2)
            .bind(tenant)
            .bind(command.request_id.to_string())
            .bind(device.into_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(Error::Forbidden)?;
    if request_source != command.source.as_str() || command.source != credential.source {
        return Err(Error::Forbidden);
    }
    lock_channel(profile, tx, tenant, &device, credential.channel).await?;
    crate::lifecycle::require_work_in(profile, tx, tenant, &device).await?;
    if sqlx::query_scalar::<_, bool>(
        crate::storage_profile::sql(profile).device_store_bind_authorized_in_4,
    )
    .bind(tenant)
    .bind(credential.channel.as_str())
    .bind(locator(credential))
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?
    {
        return Err(Error::Conflict);
    }
    let receipt = RegistrationReceipt {
        operation_id: command.operation_id,
        request_id: command.request_id,
        device,
        channel: credential.channel,
        credential: ids[0],
        epoch: ids[1],
    };
    sqlx::query(crate::storage_profile::sql(profile).device_store_bind_authorized_in_7)
        .bind(tenant)
        .bind(receipt.device.into_uuid())
        .bind(receipt.channel.as_str())
        .bind(command.request_id.to_string())
        .bind(receipt.epoch)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_store_bind_authorized_in_8)
        .bind(tenant)
        .bind(receipt.credential.to_string())
        .bind(receipt.device.into_uuid())
        .bind(receipt.channel.as_str())
        .bind(locator(credential))
        .bind(command.request_id)
        .execute(&mut *tx)
        .await
        .map_err(unique_or_db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_store_bind_authorized_in_9)
        .bind(tenant)
        .bind(receipt.device.into_uuid())
        .bind(command.source.as_str())
        .bind(receipt.epoch.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db)?;

    crate::webhook::device(
        Some(&crate::WebhookEvents),
        tx,
        tenant,
        &receipt.device,
        receipt.channel.as_str(),
        "active",
    )
    .await?;
    Ok(receipt)
}

/// Replace the exact current credential, preserving its device and protocol context.
pub async fn replace_mdm_credential_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    predecessor: Uuid,
    locator: &str,
) -> Result<(), Error> {
    let old: Option<Uuid> = sqlx::query_scalar(
        crate::storage_profile::sql(profile).device_store_replace_mdm_credential_in_1,
    )
    .bind(tenant)
    .bind(device.into_uuid())
    .bind(predecessor)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?;
    if old != Some(predecessor) {
        return Err(Error::Unauthorized);
    }
    rss_mdm_pki_service::certificates::revoke_credential_in(profile, tx, tenant, predecessor)
        .await
        .map_err(|_| Error::Storage)?;
    sqlx::query(crate::storage_profile::sql(profile).device_store_replace_mdm_credential_in_2)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(predecessor)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    sqlx::query(crate::storage_profile::sql(profile).device_store_replace_mdm_credential_in_3)
        .bind(tenant)
        .bind(Uuid::new_v4().to_string())
        .bind(device.into_uuid())
        .bind(locator)
        .bind(predecessor)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    Ok(())
}

pub async fn revalidate_source(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
    source: rss_mdm_inventory::ReportSource,
) -> Result<Scope, Error> {
    if profile != principal.profile() {
        return Err(crate::Error::Forbidden);
    }

    if principal.purpose() != Purpose::Primary || principal.channel() != Some(source.channel()) {
        return Err(Error::Forbidden);
    }
    let tenant = principal.tenant().to_string();
    let device = principal.device();
    crate::device::store::lock_channel(
        profile,
        tx,
        &tenant,
        principal.device(),
        principal.require_channel()?,
    )
    .await?;
    super::management::revalidate(profile, tx, principal).await?;
    let live = sqlx::query(crate::storage_profile::sql(profile).device_store_revalidate_source_1)
        .bind(&tenant)
        .bind(device.into_uuid())
        .bind(principal.require_channel()?.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    if live
        .try_get::<uuid::Uuid, _>("device")
        .and_then(crate::database::device_id)
        .map_err(db)?
        != *principal.device()
    {
        return Err(Error::Unauthorized);
    }
    sqlx::query(crate::storage_profile::sql(profile).device_store_revalidate_source_2)
        .bind(&tenant)
        .bind(device.into_uuid())
        .bind(principal.credential().to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::Unauthorized)?;
    // The device/channel fence above also serializes source retirement and credential rotation.
    // Revalidation only observes the epoch; sequence allocation takes its own row write lock.
    let row = sqlx::query(crate::storage_profile::sql(profile).device_store_revalidate_source_3)
        .bind(&tenant)
        .bind(device.into_uuid())
        .bind(source.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::Forbidden)?;
    crate::device::scope(
        profile,
        principal.tenant(),
        principal.device(),
        source.as_str(),
        Uuid::parse_str(&row.try_get::<String, _>("epoch").map_err(db)?)
            .map_err(|_| Error::Storage)?,
    )
    .map_err(Into::into)
}

struct RevokeInputs<'a> {
    retirement: &'a dyn crate::Retirement,
    admin: &'a AuthorizedPrincipal,
    device: &'a rss_mdm_agent_wire::DeviceId,
    key: Uuid,
    audit: &'a RequestAudit,
    operation: &'a Operation<'a>,
    facts: Vec<rss_mdm_audit_integration::Fact>,
}
async fn revoke_on(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    inputs: &mut RevokeInputs<'_>,
) -> Result<(RevocationReceipt, bool), Error> {
    let RevokeInputs {
        retirement,
        admin,
        device,
        key,
        audit,
        operation,
        facts,
    } = inputs;
    let device = *device;
    let admin = *admin;
    let audit = *audit;
    let operation = *operation;
    let key = *key;
    crate::lifecycle::lock_device_in(profile, tx, admin.tenant_id(), device).await?;
    if let Some(old) = crate::operations::replay(profile, tx, operation).await? {
        let receipt = serde_json::from_str(&old).map_err(|_| Error::Storage)?;
        admin.credentials(device)?;
        return Ok((receipt, true));
    }
    let row = sqlx::query(crate::storage_profile::sql(profile).device_store_revoke_on_1)
        .bind(admin.tenant_id())
        .bind(device.into_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(Error::Forbidden)?;
    let channel = channel(&row)?;
    lock_channel(profile, tx, admin.tenant_id(), device, channel).await?;
    let row = sqlx::query(crate::storage_profile::sql(profile).device_store_revoke_on_2)
        .bind(admin.tenant_id())
        .bind(device.into_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
    if row.try_get::<String, _>("state").map_err(db)? != "active" {
        return Err(Error::Conflict);
    }
    crate::lifecycle::retire(
        profile,
        tx,
        facts,
        admin.tenant_id(),
        device,
        "revoked",
        *retirement,
    )
    .await?;
    admin.credentials(device)?;
    let receipt = RevocationReceipt {
        operation_id: key,
        device: device.to_owned(),
    };
    audit.target_device(device);
    crate::operations::save(
        profile,
        tx,
        operation,
        &serde_json::to_string(&receipt).expect("closed receipt"),
        audit,
        false,
    )
    .await?;
    Ok((receipt, false))
}

/// Registry authority for a channel worker already operating under its owner's transaction.
pub async fn active_source_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::ReportSource,
) -> Result<bool, Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_store_active_source_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(source.as_str())
        .fetch_one(c)
        .await
        .map_err(db)
}

pub struct CollectionSource {
    pub device: rss_mdm_agent_wire::DeviceId,
    pub epoch: Uuid,
    pub sequence: i64,
}
/// Allocate a source sequence under the device channel lock on the caller's transaction.
pub async fn allocate_collection_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::ReportSource,
) -> Result<CollectionSource, Error> {
    lock_channel(profile, c, tenant, device, source.channel()).await?;
    // The channel advisory lock serializes device, credential replacement and revocation.
    // A collecting owner only mutates the report sequence and needs no UPDATE privilege on identity rows.
    let row =
        sqlx::query(crate::storage_profile::sql(profile).device_store_allocate_collection_in_1)
            .bind(tenant)
            .bind(device.into_uuid())
            .bind(source.as_str())
            .fetch_optional(&mut *c)
            .await
            .map_err(db)?
            .ok_or(Error::Conflict)?;
    let sequence = sqlx::query_scalar(
        crate::storage_profile::sql(profile).device_store_allocate_collection_in_2,
    )
    .bind(tenant)
    .bind(device.into_uuid())
    .bind(source.as_str())
    .fetch_one(c)
    .await
    .map_err(db)?;
    Ok(CollectionSource {
        device: device.to_owned(),
        epoch: row.try_get("epoch").map_err(db)?,
        sequence,
    })
}
pub async fn source_current_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::ReportSource,
    epoch: Uuid,
) -> Result<bool, Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_store_source_current_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(source.as_str())
        .bind(epoch)
        .fetch_one(c)
        .await
        .map_err(db)
}

/// Allocate a report sequence and contiguous correlation IDs on an already locked source.
#[allow(
    clippy::too_many_arguments,
    reason = "report allocation borrows the transaction and explicit product and device evidence"
)]
pub async fn allocate_report_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::ReportSource,
    epoch: &str,
    count: i64,
    maximum: i64,
) -> Result<Option<(i64, i64)>, sqlx::Error> {
    if count < 1 || maximum < count {
        return Err(sqlx::Error::Protocol("invalid report allocation".into()));
    }
    sqlx::query_as(crate::storage_profile::sql(profile).device_store_allocate_report_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(source.as_str())
        .bind(epoch)
        .bind(count)
        .bind(maximum - count + 1)
        .fetch_optional(c)
        .await
}
pub async fn allocate_task_report_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::Source,
) -> Result<(String, i64), sqlx::Error> {
    if !matches!(
        source,
        rss_mdm_inventory::Source::AgentScript
            | rss_mdm_inventory::Source::AgentOsquery
            | rss_mdm_inventory::Source::AgentNative
    ) {
        return Err(sqlx::Error::Protocol(
            "invalid enterprise report source".into(),
        ));
    }
    sqlx::query_as(crate::storage_profile::sql(profile).device_store_allocate_task_report_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(source.as_str())
        .fetch_one(c)
        .await
}
/// Allocate protocol identities independently of Inventory sources; caller revalidates first.
pub async fn allocate_commands_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
    count: i64,
) -> Result<u32, Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    if count < 1 || count > i64::from(u32::MAX) {
        return Err(Error::Malformed);
    }
    revalidate_management(profile, c, p).await?;
    let first: i64 = sqlx::query_scalar(
        crate::storage_profile::sql(profile).device_store_allocate_commands_in_1,
    )
    .bind(p.tenant().to_string())
    .bind(p.device().into_uuid())
    .bind(p.protocol_request())
    .bind(count)
    .fetch_one(c)
    .await
    .map_err(db)?;
    first.try_into().map_err(|_| Error::Storage)
}

#[allow(
    clippy::too_many_arguments,
    reason = "native renewal keeps independent device, generation and credential evidence"
)]
pub async fn activate_renewed_mdm_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    predecessor: Uuid,
    credential: &super::VerifiedChannelCredential,
) -> Result<(), Error> {
    if profile != credential.profile {
        return Err(crate::Error::Forbidden);
    }

    if credential.tenant.to_string() != tenant
        || credential.channel != super::Channel::Mdm
        || credential.source != rss_mdm_inventory::ReportSource::MdmWindows
    {
        return Err(Error::Unauthorized);
    }
    lock_channel(profile, c, tenant, device, credential.channel).await?;
    let current: bool = sqlx::query_scalar(
        crate::storage_profile::sql(profile).device_store_activate_renewed_mdm_in_1,
    )
    .bind(tenant)
    .bind(device.into_uuid())
    .bind(predecessor)
    .bind(credential.purpose.as_str())
    .fetch_one(&mut *c)
    .await
    .map_err(db)?;
    if !current {
        return Err(Error::Unauthorized);
    }
    replace_mdm_credential_in(
        profile,
        c,
        tenant,
        device,
        predecessor,
        &locator(credential),
    )
    .await
}

/// Current management authority; this does not authorize publishing an observation.
pub async fn management_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    credential: &VerifiedChannelCredential,
) -> Result<DevicePrincipal, Error> {
    if profile != credential.profile {
        return Err(crate::Error::Forbidden);
    }

    super::management::authenticate(profile, c, credential).await
}
/// Verify this exact credential and generation within a caller-owned read snapshot.
pub async fn read_management_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
) -> Result<(), Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    super::management::validate(profile, c, p).await
}

pub async fn revalidate_management(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    p: &DevicePrincipal,
) -> Result<(), Error> {
    if profile != p.profile() {
        return Err(crate::Error::Forbidden);
    }

    super::management::revalidate(profile, c, p).await
}

/// The same binding kernel consumes all closed native admission kinds.
#[allow(
    clippy::too_many_arguments,
    reason = "borrowed device transaction with live admission"
)]
pub async fn bind_native_in(
    profile: rss_mdm_install_support::StorageProfile,
    tx: &mut sqlx::PgConnection,
    admission: &crate::enrollment::native::Admission,
    credential: &VerifiedChannelCredential,
    ids: [Uuid; 2],
) -> Result<RegistrationReceipt, Error> {
    if profile != credential.profile {
        return Err(crate::Error::Forbidden);
    }

    admission.current(tx).await?;
    let d = admission.coordinates();
    bind_authorized_in(
        profile,
        tx,
        &d.tenant,
        credential,
        &BindRegistration {
            operation_id: d.operation,
            request_id: d.id,
            source: d.source,
        },
        d.device,
        ids,
    )
    .await
}

/// Bind an already authorized collection template to the current Agent source incarnation.
/// This validates device/credential liveness; the caller still owns template authority.
pub async fn revalidate_collection_source(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    principal: &DevicePrincipal,
    source: rss_mdm_inventory::Source,
) -> Result<Scope, Error> {
    if profile != principal.profile() {
        return Err(crate::Error::Forbidden);
    }

    use rss_mdm_inventory::Source;
    if principal.purpose() != Purpose::Primary
        || principal.channel() != Some(Channel::Agent)
        || !matches!(
            source,
            Source::AgentNative | Source::AgentScript | Source::AgentOsquery
        )
    {
        return Err(Error::Forbidden);
    }
    revalidate_management(profile, c, principal).await?;
    let epoch: Option<Uuid> = sqlx::query_scalar(
        crate::storage_profile::sql(profile).device_store_revalidate_collection_source_1,
    )
    .bind(principal.tenant().to_string())
    .bind(principal.device().into_uuid())
    .bind(source.as_str())
    .fetch_optional(c)
    .await
    .map_err(db)?;
    crate::device::scope(
        profile,
        principal.tenant(),
        principal.device(),
        source.as_str(),
        epoch.ok_or(Error::Forbidden)?,
    )
    .map_err(Into::into)
}

/// Effective Agent collection streams for a device; old device incarnations stay historical.
pub async fn live_collection_streams_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &rss_mdm_agent_wire::DeviceId,
) -> Result<Vec<(rss_mdm_agent_wire::DeviceId, String, Uuid)>, Error> {
    lock_channel(profile, c, &tenant.to_string(), device, Channel::Agent).await?;
    let rows = sqlx::query_as::<_, (Uuid, String, Uuid)>(
        crate::storage_profile::sql(profile).device_store_live_collection_streams_on_1,
    )
    .bind(tenant.to_string())
    .bind(device.into_uuid())
    .fetch_all(c)
    .await
    .map_err(db)?;
    if rows.len() > 64 {
        return Err(Error::Storage);
    }
    rows.into_iter()
        .map(|(id, source, epoch)| Ok((crate::database::device_id(id).map_err(db)?, source, epoch)))
        .collect()
}

/// A closed old source must never be reactivated merely because a credential expired.
/// The caller proves the historical stream's device membership from accepted product facts.
pub async fn collection_stream_retired_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: rss_request_context::TenantId,
    device: &rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::Source,
    epoch: Uuid,
) -> Result<bool, Error> {
    lock_channel(profile, c, &tenant.to_string(), device, Channel::Agent).await?;
    sqlx::query_scalar(
        crate::storage_profile::sql(profile).device_store_collection_stream_retired_on_1,
    )
    .bind(tenant.to_string())
    .bind(device.into_uuid())
    .bind(source.as_str())
    .bind(epoch)
    .fetch_one(c)
    .await
    .map_err(db)
}

/// Current report epoch for a channel owner borrowing an already authorized device transaction.
/// Caller holds the device/channel lifecycle lock; no new transaction or authority is created.
pub async fn report_epoch_in(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    source: rss_mdm_inventory::ReportSource,
) -> Result<Option<Uuid>, Error> {
    sqlx::query_scalar(crate::storage_profile::sql(profile).device_store_report_epoch_in_1)
        .bind(tenant)
        .bind(device.into_uuid())
        .bind(source.as_str())
        .fetch_optional(c)
        .await
        .map_err(db)
}

/// Keep existing Agent/native lock identities while admitting independent DA registrations.
pub async fn lock_registration(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut sqlx::PgConnection,
    tenant: &str,
    device: &rss_mdm_agent_wire::DeviceId,
    kind: RegistrationKind,
) -> Result<(), Error> {
    crate::lifecycle::lock_device_in(profile, c, tenant, device).await?;
    let key = serde_json::to_string(&(profile.name(), tenant, device, kind.lock_name()))
        .map_err(|_| Error::Malformed)?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2348))")
        .bind(key)
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
