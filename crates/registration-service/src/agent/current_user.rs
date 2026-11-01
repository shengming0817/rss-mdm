//! One current enterprise login per endpoint. Identity retains session authority.
//! ref: sqlx v0.8.6 sqlx-core/src/transaction.rs (caller-owned connection).
use super::*;
use crate::device::{DevicePrincipal, registration_user};
use rss_mdm_agent_wire::runtime::{
    CurrentUser, CurrentUserChange, CurrentUserState, SelfServiceUser,
};
use rss_mdm_authorization_service::session::{SessionAuthority, SessionReference};

/// Trusted persistence only; never accepted from an Agent or used to authenticate it.
pub struct Binding {
    pub revision: u64,
    pub reference: Option<SessionReference>,
    pub registration_valid: bool,
    pub confirmed_at: Option<i64>,
}
/// Read a single device from the caller's already authorized scope and transaction.
pub async fn binding_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Binding, Error> {
    bindings_on(profile, c, tenant, &[device.to_owned()])
        .await?
        .remove(device)
        .ok_or(Error::Corrupt)
}
/// Read only devices supplied by an already-authorized consumer, at most one provider batch.
pub async fn bindings_on(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<std::collections::BTreeMap<String, Binding>, Error> {
    if devices.len() > 1000 {
        return Err(Error::Malformed);
    }
    let rows = sqlx::query(crate::storage_profile::sql(profile).agent_current_user_bindings_on_1)
        .bind(tenant)
        .bind(devices)
        .fetch_all(&mut *c)
        .await
        .map_err(db)?;
    let mut result = devices
        .iter()
        .map(|id| {
            (
                id.clone(),
                Binding {
                    revision: 0,
                    reference: None,
                    registration_valid: false,
                    confirmed_at: None,
                },
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let fingerprints = rows
        .iter()
        .map(|row| row.try_get::<Option<Vec<u8>>, _>("fingerprint").map_err(db))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let valid = rss_mdm_pki_service::registry::current_certificates_in(
        profile,
        c,
        rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Corrupt)?,
        rss_mdm_agent_wire::pki::Purpose::Agent,
        &fingerprints,
    )
    .await
    .map_err(|_| Error::Storage)?;
    for row in rows {
        let reference: Option<SessionReference> = row
            .try_get::<Option<serde_json::Value>, _>("session_reference")
            .map_err(db)?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| Error::Corrupt)?;
        let fingerprint: Option<Vec<u8>> = row.try_get("fingerprint").map_err(db)?;
        let registration_valid = fingerprint.as_ref().is_some_and(|f| valid.contains(f));
        result.insert(
            row.try_get("device").map_err(db)?,
            Binding {
                revision: row
                    .try_get::<i64, _>("revision")
                    .map_err(db)?
                    .try_into()
                    .map_err(|_| Error::Corrupt)?,
                reference,
                registration_valid,
                confirmed_at: Some(row.try_get("confirmed_at").map_err(db)?),
            },
        );
    }
    Ok(result)
}

/// Recheck through the existing Identity authority without renewing idle or inventing presence.
pub async fn resolve(binding: &Binding, sessions: &SessionAuthority) -> Result<CurrentUser, Error> {
    let mut value = CurrentUser {
        revision: binding.revision,
        state: CurrentUserState::Unbound,
        user: None,
        confirmed_at: binding.confirmed_at,
    };
    if let Some(reference) = &binding.reference {
        value.state = CurrentUserState::Invalidated;
        if binding.registration_valid {
            match sessions.recheck(reference).await {
                Ok(facts) => {
                    facts.check_live().map_err(|_| Error::Unauthorized)?;
                    value.state = CurrentUserState::Active;
                    value.user = Some(SelfServiceUser {
                        tenant_id: Uuid::parse_str(&facts.account().tenant.to_string())
                            .map_err(|_| Error::Corrupt)?,
                        instance_id: facts.instance().as_uuid(),
                        principal_id: facts.account().principal.as_uuid(),
                    });
                }
                Err(
                    rss_mdm_authorization_service::Error::Unauthorized
                    | rss_mdm_authorization_service::Error::Forbidden,
                ) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(value)
}
impl Service {
    pub async fn current_user(
        &self,
        device: &DevicePrincipal,
        sessions: &SessionAuthority,
    ) -> Result<CurrentUser, Error> {
        let profile = self.profile();

        if device.tenant() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin(&self.tenant.to_string()).await?;
        crate::device::store::revalidate_management(profile, &mut tx, device).await?;
        let binding =
            binding_on(profile, &mut tx, &self.tenant.to_string(), device.device()).await?;
        // Await settlement: Drop only queues rollback and cannot fence the next authority call.
        tx.rollback().await.map_err(db)?;
        let value = resolve(&binding, sessions).await?;
        let mut tx = self.store.begin(&self.tenant.to_string()).await?;
        crate::device::store::revalidate_management(profile, &mut tx, device).await?;
        let current =
            binding_on(profile, &mut tx, &self.tenant.to_string(), device.device()).await?;
        tx.rollback().await.map_err(db)?;
        if current.revision != binding.revision
            || current.reference != binding.reference
            || current.registration_valid != binding.registration_valid
        {
            return Err(Error::Conflict);
        }
        Ok(value)
    }
    /// Login/switch receives a real enterprise proof; logout needs only the device and CAS.
    pub async fn change_current_user(
        &self,
        device: &DevicePrincipal,
        employee: Option<&AuthorizedPrincipal>,
        input: &CurrentUserChange,
        sessions: &SessionAuthority,
        audit: &RequestAudit,
    ) -> Result<CurrentUser, Error> {
        let profile = self.profile();

        input.validate().map_err(|_| Error::Malformed)?;
        if device.tenant() != self.tenant || audit.tenant() != self.tenant.to_string() {
            return Err(Error::Forbidden);
        }
        let reference = employee
            .map(|p| {
                if p.tenant_id() != self.tenant.to_string() {
                    return Err(Error::Forbidden);
                }
                p.bind_audit(audit)?;
                p.session()?.reference().map_err(|_| Error::Unauthorized)
            })
            .transpose()?;
        let user = employee.map(|p| p.user()).transpose()?;
        audit.operation(
            input.operation_id,
            "agent_current_user_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device.device());
        let digest = crate::enrollment::digest(&(
            "agent-current-user.v1",
            device.registration(),
            device.generation(),
            input,
            &reference,
        ));
        self.write(
            audit,
            (
                device,
                employee,
                input,
                reference,
                user,
                digest,
                sessions,
                audit.request_id(),
            ),
            |ctx, c| {
                Box::pin(async move {
                    let (device, employee, input, reference, user, digest, sessions, request_id) =
                        ctx;
                    sqlx::query("SELECT set_config('application_name',$1,true)")
                        .bind(format!("mdm-current-user:{request_id}"))
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                    write_stage(*request_id, "channel_revalidation");
                    crate::device::store::revalidate_management(profile, c, device).await?;
                    // Lock order is shared with ownership edits and first-login initialization.
                    write_stage(*request_id, "registration_user_lock");
                    registration_user::lock_on(
                        profile,
                        c,
                        &device.tenant().to_string(),
                        device.device(),
                    )
                    .await?;
                    // Device namespace keeps login/logout replay coherent across user switches.
                    let actor = format!("agent-user:{}", device.device());
                    let old = sqlx::query(
                        crate::storage_profile::sql(profile)
                            .agent_current_user_change_current_user_1,
                    )
                    .bind(device.tenant().to_string())
                    .bind(&actor)
                    .bind(input.operation_id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?;
                    if let Some(old) = old {
                        if old.try_get::<String, _>("digest").map_err(db)? != *digest
                            || old.try_get::<String, _>("instance").map_err(db)?
                                != device.registration().to_string()
                        {
                            return Err(Error::Conflict);
                        }
                        let value =
                            serde_json::from_str(&old.try_get::<String, _>("result").map_err(db)?)
                                .map_err(|_| Error::Corrupt)?;
                        return Ok(Change {
                            value,
                            replay: true,
                        });
                    }
                    let current =
                        binding_on(profile, c, &device.tenant().to_string(), device.device())
                            .await?;
                    if current.revision != input.expected_revision {
                        return Err(Error::Conflict);
                    }
                    if let Some(employee) = employee {
                        employee.check_live()?;
                    }
                    write_stage(*request_id, "identity_session_recheck");
                    if let Some(reference) = reference {
                        sessions.recheck(reference).await?;
                    }
                    if let Some(user) = user {
                        registration_user::initialize_on(profile, c, device.device(), user).await?;
                    }
                    let revision = current.revision + 1;
                    let now = now(c).await?;
                    write_stage(*request_id, "binding_upsert");
                    sqlx::query(
                        crate::storage_profile::sql(profile)
                            .agent_current_user_change_current_user_2,
                    )
                    .bind(device.tenant().to_string())
                    .bind(device.device())
                    .bind(revision as i64)
                    .bind(device.registration())
                    .bind(device.generation())
                    .bind(
                        reference
                            .as_ref()
                            .map(serde_json::to_value)
                            .transpose()
                            .map_err(|_| Error::Corrupt)?,
                    )
                    .bind(now)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                    let value = CurrentUser {
                        revision,
                        state: if user.is_some() {
                            CurrentUserState::Active
                        } else {
                            CurrentUserState::Unbound
                        },
                        user: user
                            .as_ref()
                            .map(|u| {
                                Ok::<_, Error>(SelfServiceUser {
                                    tenant_id: Uuid::parse_str(&u.tenant_id)
                                        .map_err(|_| Error::Corrupt)?,
                                    instance_id: Uuid::parse_str(&u.instance_id)
                                        .map_err(|_| Error::Corrupt)?,
                                    principal_id: Uuid::parse_str(&u.principal_id)
                                        .map_err(|_| Error::Corrupt)?,
                                })
                            })
                            .transpose()?,
                        confirmed_at: Some(now),
                    };
                    write_stage(*request_id, "operation_receipt");
                    sqlx::query(
                        crate::storage_profile::sql(profile)
                            .agent_current_user_change_current_user_3,
                    )
                    .bind(device.tenant().to_string())
                    .bind(actor)
                    .bind(device.registration().to_string())
                    .bind(input.operation_id)
                    .bind(&*digest)
                    .bind(serde_json::to_string(&value).map_err(|_| Error::Corrupt)?)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                    write_stage(*request_id, "channel_revalidation");
                    crate::device::store::revalidate_management(profile, c, device).await?;
                    write_stage(*request_id, "source_callback_complete");
                    Ok(Change {
                        value,
                        replay: false,
                    })
                })
            },
        )
        .await
    }
}

fn write_stage(request: uuid::Uuid, stage: &'static str) {
    eprintln!(
        "{}",
        serde_json::json!({"event":"mdm_current_user_write_stage","request_id":request,"stage":stage})
    );
}
