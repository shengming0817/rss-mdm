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
    c: &mut PgConnection,
    tenant: &str,
    device: &str,
) -> Result<Binding, Error> {
    bindings_on(c, tenant, &[device.to_owned()])
        .await?
        .remove(device)
        .ok_or(Error::Corrupt)
}
/// Read only devices supplied by an already-authorized consumer, at most one provider batch.
pub async fn bindings_on(
    c: &mut PgConnection,
    tenant: &str,
    devices: &[String],
) -> Result<std::collections::BTreeMap<String, Binding>, Error> {
    if devices.len() > 1000 {
        return Err(Error::Malformed);
    }
    let rows=sqlx::query("SELECT u.device,u.revision,u.session_reference,u.confirmed_at,(SELECT decode(k.locator,'hex') FROM mdm_access.registrations r JOIN mdm_access.credentials k ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) JOIN mdm_access.agent_issuances i ON(i.tenant_id,i.credential)=(k.tenant_id,k.id) WHERE r.tenant_id=u.tenant_id AND r.id=u.registration AND r.device=u.device AND r.generation=u.generation AND r.channel='agent' AND r.purpose='primary' AND r.state='active' AND k.state='active' AND i.not_before<=extract(epoch FROM statement_timestamp()) AND i.not_after>extract(epoch FROM statement_timestamp())) AS fingerprint FROM mdm_access.current_users u WHERE u.tenant_id=$1::uuid AND u.device=ANY($2)")
        .bind(tenant).bind(devices).fetch_all(&mut *c).await.map_err(db)?;
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
    for row in rows {
        let reference: Option<SessionReference> = row
            .try_get::<Option<serde_json::Value>, _>("session_reference")
            .map_err(db)?
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| Error::Corrupt)?;
        let fingerprint: Option<Vec<u8>> = row.try_get("fingerprint").map_err(db)?;
        let mut registration_valid = fingerprint.is_some();
        if reference.is_some()
            && let Some(fingerprint) = fingerprint
        {
            match rss_mdm_pki_service::registry::current_certificate_in(
                c,
                rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Corrupt)?,
                rss_mdm_agent_wire::pki::Purpose::Agent,
                &fingerprint,
            )
            .await
            {
                Ok(()) => {}
                Err(rss_mdm_pki_service::Error::Forbidden) => registration_valid = false,
                Err(_) => return Err(Error::Storage),
            }
        }
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
        if device.tenant() != self.tenant {
            return Err(Error::Forbidden);
        }
        let mut tx = self.store.begin(&self.tenant.to_string()).await?;
        crate::device::store::revalidate_management(&mut tx, device).await?;
        let binding = binding_on(&mut tx, &self.tenant.to_string(), device.device()).await?;
        // Await settlement: Drop only queues rollback and cannot fence the next authority call.
        tx.rollback().await.map_err(db)?;
        let value = resolve(&binding, sessions).await?;
        let mut tx = self.store.begin(&self.tenant.to_string()).await?;
        crate::device::store::revalidate_management(&mut tx, device).await?;
        let current = binding_on(&mut tx, &self.tenant.to_string(), device.device()).await?;
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
        audit.operation(input.operation_id, "agent_current_user_change");
        audit.target_device(device.device());
        let digest = crate::enrollment::digest(&(
            "agent-current-user.v1",
            device.registration(),
            device.generation(),
            input,
            &reference,
        ));
        self.write(audit,(device,employee,input,reference,user,digest,sessions),|ctx,c|Box::pin(async move {
            let (device,employee,input,reference,user,digest,sessions)=ctx;
            crate::device::store::revalidate_management(c,device).await?;
            // Lock order is shared with ownership edits and first-login initialization.
            registration_user::lock_on(c,&device.tenant().to_string(),device.device()).await?;
            // Device namespace keeps login/logout replay coherent across user switches.
            let actor=format!("agent-user:{}",device.device());
            let old=sqlx::query("SELECT digest,result,instance FROM mdm_access.registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$3")
                .bind(device.tenant().to_string()).bind(&actor).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)?;
            if let Some(old)=old {
                if old.try_get::<String,_>("digest").map_err(db)?!=*digest || old.try_get::<String,_>("instance").map_err(db)?!=device.registration().to_string() {return Err(Error::Conflict);}
                let value=serde_json::from_str(&old.try_get::<String,_>("result").map_err(db)?).map_err(|_|Error::Corrupt)?;
                return Ok(Change{value,replay:true,digest:digest.clone()});
            }
            let current=binding_on(c,&device.tenant().to_string(),device.device()).await?;
            if current.revision!=input.expected_revision {return Err(Error::Conflict);}
            if let Some(employee)=employee {employee.check_live()?;}
            if let Some(reference)=reference {sessions.recheck(reference).await?;}
            if let Some(user)=user {registration_user::initialize_on(c,device.device(),user).await?;}
            let revision=current.revision+1;
            let now=now(c).await?;
            sqlx::query("INSERT INTO mdm_access.current_users(tenant_id,device,revision,registration,generation,session_reference,confirmed_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,device) DO UPDATE SET revision=EXCLUDED.revision,registration=EXCLUDED.registration,generation=EXCLUDED.generation,session_reference=EXCLUDED.session_reference,confirmed_at=EXCLUDED.confirmed_at")
                .bind(device.tenant().to_string()).bind(device.device()).bind(revision as i64).bind(device.registration()).bind(device.generation()).bind(reference.as_ref().map(serde_json::to_value).transpose().map_err(|_|Error::Corrupt)?).bind(now).execute(&mut *c).await.map_err(db)?;
            let value=CurrentUser{revision,state:if user.is_some(){CurrentUserState::Active}else{CurrentUserState::Unbound},user:user.as_ref().map(|u|Ok::<_,Error>(SelfServiceUser{tenant_id:Uuid::parse_str(&u.tenant_id).map_err(|_|Error::Corrupt)?,instance_id:Uuid::parse_str(&u.instance_id).map_err(|_|Error::Corrupt)?,principal_id:Uuid::parse_str(&u.principal_id).map_err(|_|Error::Corrupt)?})).transpose()?,confirmed_at:Some(now)};
            sqlx::query("INSERT INTO mdm_access.registration_operations(tenant_id,actor,instance,operation_id,digest,result) VALUES($1::uuid,$2,$3,$4,$5,$6)")
                .bind(device.tenant().to_string()).bind(actor).bind(device.registration().to_string()).bind(input.operation_id).bind(&*digest).bind(serde_json::to_string(&value).map_err(|_|Error::Corrupt)?).execute(&mut *c).await.map_err(db)?;
            crate::device::store::revalidate_management(c,device).await?;
            Ok(Change{value,replay:false,digest:digest.clone()})
        })).await
    }
}
