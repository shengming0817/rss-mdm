//! Closed native admission: original browser authority or a revalidated account session.
//! Both use the existing request, grant, quota and registration owners.
use super::{
    Authorization, Receipt, digest,
    store::{request, uuid},
};
use crate::{
    Error,
    database::db,
    operations::{Actor, Operation},
};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{
    context::AuthorizedPrincipal,
    session::{RevalidatedSession, SessionAuthority, SessionReference},
};
use rss_mdm_inventory::ReportSource;
use sqlx::{PgConnection, Row, postgres::PgRow};
use std::sync::Arc;
use uuid::Uuid;
type Pending<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Error>> + Send + 'a>>;
/// Product-owned organization authority, required for every account issuance and admission.
/// Composition supplies the implementation; protocol callers cannot omit this gate.
pub trait AccountAuthority: Send + Sync {
    fn authorize_issue<'a>(
        &'a self,
        c: &'a mut PgConnection,
        proof: &'a AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
    ) -> Pending<'a>;
    fn current<'a>(&'a self, c: &'a mut PgConnection, coordinates: &'a Coordinates) -> Pending<'a>;
}

#[derive(Clone)]
pub struct Coordinates {
    pub tenant: String,
    pub id: Uuid,
    pub device: String,
    pub actor: String,
    pub instance: String,
    pub version: i64,
    pub expected_generation: i64,
    pub operation: Uuid,
    pub source: ReportSource,
}
/// Apple owner gates organization policy and the verified manufacturer request.
pub trait OrganizationAuthority: Send + Sync {
    fn authorize_issue<'a>(
        &'a self,
        c: &'a mut PgConnection,
        tenant: &'a str,
        organization: Uuid,
        profile: Uuid,
        machine: &'a rss_mdm_certificate::apple::ade::MachineInfo,
    ) -> Pending<'a>;
    fn current<'a>(&'a self, c: &'a mut PgConnection, data: &'a Coordinates) -> Pending<'a>;
}
/// The Windows owner must revalidate persisted organization policy in the consuming transaction.
pub trait EntraPolicyAuthority: Send + Sync {
    fn current<'a>(&'a self, c: &'a mut PgConnection, coordinates: &'a Coordinates) -> Pending<'a>;
}
pub trait AgentPolicyAuthority: Send + Sync {
    fn current<'a>(&'a self, c: &'a mut PgConnection, coordinates: &'a Coordinates) -> Pending<'a>;
}
enum Basis {
    AgentPolicy {
        authority: Arc<dyn AgentPolicyAuthority>,
    },
    Entra {
        proof: rss_mdm_authorization_service::entra::RevalidatedAccount,
        authority: Arc<dyn EntraPolicyAuthority>,
    },
    Organization {
        authority: Arc<dyn OrganizationAuthority>,
    },
    Password {
        credential: Uuid,
        proof: AuthorizedPrincipal,
    },
    Account {
        reference: SessionReference,
        proof: RevalidatedSession,
        authority: Arc<dyn AccountAuthority>,
    },
}
pub struct Admission {
    data: Coordinates,
    basis: Basis,
}
impl Admission {
    pub fn coordinates(&self) -> &Coordinates {
        &self.data
    }
    /// Revalidate an existing account continuation in its consuming transaction.
    pub async fn revalidate_account_in(&self, c: &mut PgConnection) -> Result<(), Error> {
        self.check_live()?;
        let Basis::Account {
            reference,
            proof,
            authority,
        } = &self.basis
        else {
            return Err(Error::Unauthorized);
        };
        let d = &self.data;
        if proof.account().tenant.to_string() != d.tenant
            || proof.account().principal.as_uuid().to_string() != d.actor
            || proof.instance().to_string() != d.instance
        {
            return Err(Error::Unauthorized);
        }
        crate::device::store::lock_channel(c, &d.tenant, &d.device, d.source.channel()).await?;
        authority.current(c, d).await?;
        let same:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2 AND authority_kind='apple_account' AND account_version=$3 AND account_reference=$4 AND expected_generation=$5 AND issuance_operation=$6 AND state<>'cancelled')")
            .bind(&d.tenant).bind(d.id).bind(d.version).bind(serde_json::to_value(reference).map_err(|_|Error::Corrupt)?).bind(d.expected_generation).bind(d.operation).fetch_one(c).await.map_err(db)?;
        if !same {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    pub fn password(
        tenant: String,
        auth: Authorization,
        proof: AuthorizedPrincipal,
    ) -> Result<Self, Error> {
        auth.authorize(&proof)?;
        if tenant != proof.tenant_id() {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            data: Coordinates {
                tenant,
                id: auth.id,
                device: auth.device,
                actor: auth.actor,
                instance: auth.instance,
                version: auth.version,
                expected_generation: auth.expected_generation,
                operation: auth.operation,
                source: auth.source,
            },
            basis: Basis::Password {
                credential: auth.credential_ref,
                proof,
            },
        })
    }
    pub fn is_account(&self) -> bool {
        matches!(self.basis, Basis::Account { .. })
    }
    pub fn is_organization(&self) -> bool {
        matches!(self.basis, Basis::Organization { .. })
    }
    pub fn check_live(&self) -> Result<(), Error> {
        match &self.basis {
            Basis::Organization { .. } | Basis::AgentPolicy { .. } => Ok(()),
            Basis::Entra { proof, .. } => proof.check_live().map_err(|_| Error::Unauthorized),
            Basis::Password { proof, .. } => proof.check_live().map_err(Into::into),
            Basis::Account { proof, .. } => proof.check_live().map_err(|_| Error::Unauthorized),
        }
    }
    pub fn bind_audit(&self, audit: &RequestAudit) -> Result<(), Error> {
        match &self.basis {
            Basis::Entra { proof, .. } => {
                rss_mdm_authorization_service::context::bind_native_audit(proof, audit)
                    .map_err(Into::into)
            }
            Basis::Organization { .. } | Basis::AgentPolicy { .. } => {
                if audit.tenant() != self.data.tenant {
                    return Err(Error::Unauthorized);
                }
                audit.identify_service(if matches!(self.basis, Basis::AgentPolicy { .. }) {
                    "service:agent-policy"
                } else {
                    "service:apple-ade"
                });
                Ok(())
            }
            Basis::Password { proof, .. } => proof.bind_audit(audit).map_err(Into::into),
            Basis::Account { proof, .. } => {
                rss_mdm_authorization_service::session::bind_revalidated_audit(proof, audit)
                    .map_err(Into::into)
            }
        }
    }
    pub async fn current(&self, c: &mut PgConnection) -> Result<PgRow, Error> {
        let row = self.current_request(c).await?;
        if row.try_get::<String, _>("state").map_err(db)? != "pending" {
            return Err(Error::Conflict);
        }
        Ok(row)
    }
    /// Binding and exact certificate replay share current authority checks.
    pub async fn current_request(&self, c: &mut PgConnection) -> Result<PgRow, Error> {
        self.check_live()?;
        crate::admission::lock_in(c, &self.data.tenant).await?;
        if self.is_account() {
            self.revalidate_account_in(c).await?;
        }
        let d = &self.data;
        if let Basis::Organization { authority } = &self.basis {
            authority.current(c, d).await?;
        }
        if let Basis::Entra { authority, .. } = &self.basis {
            authority.current(c, d).await?;
        }
        if let Basis::AgentPolicy { authority } = &self.basis {
            authority.current(c, d).await?;
        }
        let row = request(c, &d.tenant, d.id).await?;
        if row.try_get::<String, _>("state").map_err(db)? == "cancelled"
            || !row.try_get::<bool, _>("live").map_err(db)?
            || row.try_get::<String, _>("actor").map_err(db)? != d.actor
            || row.try_get::<String, _>("instance").map_err(db)? != d.instance
            || row.try_get::<i64, _>("expected_generation").map_err(db)? != d.expected_generation
            || uuid(&row, "issuance_operation")? != d.operation
            || row.try_get::<String, _>("device").map_err(db)? != d.device
            || row.try_get::<String, _>("source").map_err(db)? != d.source.as_str()
        {
            return Err(Error::Unauthorized);
        }
        let kind: String = row.try_get("authority_kind").map_err(db)?;
        match &self.basis {
            Basis::AgentPolicy { .. }
                if kind == "agent_policy"
                    && row.try_get::<i64, _>("password_version").map_err(db)? == d.version => {}
            Basis::Entra { .. }
                if kind == "windows_entra"
                    && !row.try_get::<bool, _>("self_service").map_err(db)?
                    && row.try_get::<i64, _>("organization_version").map_err(db)? == d.version => {}
            Basis::Organization { .. }
                if kind == "apple_ade"
                    && !row.try_get::<bool, _>("self_service").map_err(db)?
                    && row.try_get::<i64, _>("organization_version").map_err(db)? == d.version => {}
            Basis::Password { credential, .. }
                if kind == "password"
                    && uuid(&row, "credential_ref")? == *credential
                    && row.try_get::<i64, _>("password_version").map_err(db)? == d.version => {}
            Basis::Account { reference, .. }
                if kind == "apple_account"
                    && row.try_get::<bool, _>("self_service").map_err(db)?
                    && row.try_get::<i64, _>("account_version").map_err(db)? == d.version
                    && row
                        .try_get::<serde_json::Value, _>("account_reference")
                        .map_err(db)?
                        == serde_json::to_value(reference).map_err(|_| Error::Corrupt)? => {}
            _ => return Err(Error::Unauthorized),
        }
        Ok(row)
    }
    pub async fn mark_bound_in(&self, c: &mut PgConnection) -> Result<(), Error> {
        self.current(c).await?;
        sqlx::query(
            "UPDATE mdm_access.requests SET state='bound' WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(&self.data.tenant)
        .bind(self.data.id)
        .execute(c)
        .await
        .map_err(db)?;
        Ok(())
    }
}
/// Load the persisted account locator, then recheck Identity with no MDM row lock held.
pub async fn account(
    store: &crate::Store,
    sessions: &SessionAuthority,
    id: Uuid,
    authority: Arc<dyn AccountAuthority>,
    challenge: Option<&str>,
) -> Result<Admission, Error> {
    let tenant = sessions.tenant().to_string();
    let mut tx = store.begin(&tenant).await?;
    let row = request(&mut tx, &tenant, id).await?;
    if row.try_get::<String, _>("authority_kind").map_err(db)? != "apple_account"
        || row.try_get::<String, _>("state").map_err(db)? == "cancelled"
    {
        return Err(Error::Unauthorized);
    }
    if let Some(challenge) = challenge {
        let expected: String = row.try_get("account_challenge").map_err(db)?;
        if !super::equal(&expected, &challenge_digest(&tenant, id, challenge)) {
            return Err(Error::Unauthorized);
        }
    }
    let reference: SessionReference =
        serde_json::from_value(row.try_get("account_reference").map_err(db)?)
            .map_err(|_| Error::Corrupt)?;
    let data = Coordinates {
        tenant,
        id,
        device: row.try_get("device").map_err(db)?,
        actor: row.try_get("actor").map_err(db)?,
        instance: row.try_get("instance").map_err(db)?,
        version: row.try_get("account_version").map_err(db)?,
        expected_generation: row.try_get("expected_generation").map_err(db)?,
        operation: uuid(&row, "issuance_operation")?,
        source: ReportSource::MdmApple,
    };
    tx.rollback().await.map_err(db)?;
    let proof = sessions.recheck(&reference).await?;
    if proof.account().tenant.to_string() != data.tenant
        || proof.account().principal.as_uuid().to_string() != data.actor
        || proof.instance().to_string() != data.instance
    {
        return Err(Error::Unauthorized);
    }
    let admission = Admission {
        data,
        basis: Basis::Account {
            reference,
            proof,
            authority,
        },
    };
    let mut tx = store.begin(&admission.data.tenant).await?;
    admission.revalidate_account_in(&mut tx).await?;
    tx.rollback().await.map_err(db)?;
    Ok(admission)
}
pub fn challenge_digest(tenant: &str, id: Uuid, challenge: &str) -> String {
    digest(&("apple.account.scep/v1", tenant, id, challenge))
}
/// Acquire lifecycle serialization before the Apple owner takes flow/configuration locks.
pub async fn lock_account_issuance(
    c: &mut PgConnection,
    proof: &AuthorizedPrincipal,
    id: Uuid,
) -> Result<(), Error> {
    proof.check_live()?;
    let device = format!(
        "self:{}:{}:{}",
        proof.instance_id(),
        proof.principal_id(),
        id
    );
    crate::device::store::lock_channel(
        c,
        proof.tenant_id(),
        &device,
        rss_mdm_inventory::Channel::Mdm,
    )
    .await
}
/// The product organization authority and Identity jointly authorize account issuance.
#[allow(
    clippy::too_many_arguments,
    reason = "one existing lifecycle transaction with exact operation receipt"
)]
pub async fn issue_in(
    c: &mut PgConnection,
    proof: &AuthorizedPrincipal,
    authority: &dyn AccountAuthority,
    id: Uuid,
    operation: Uuid,
    challenge: &str,
    audit: &RequestAudit,
) -> Result<(Receipt, bool), Error> {
    crate::admission::lock_in(c, proof.tenant_id()).await?;
    lock_account_issuance(c, proof, id).await?;
    authority.authorize_issue(c, proof, id, operation).await?;
    let reference = proof
        .session()
        .reference()
        .map_err(|_| Error::Unauthorized)?;
    let hash = challenge_digest(proof.tenant_id(), id, challenge);
    let fingerprint = digest(&("apple.account.issue/v1", id, &reference, &hash));
    let op = Operation {
        actor: Actor::from_authorized(proof),
        key: operation,
        digest: &fingerprint,
    };
    crate::quotas::lock_on(c, proof.tenant_id()).await?;
    if let Some(old) = crate::operations::replay(c, &op).await? {
        return serde_json::from_str(&old)
            .map(|r| (r, true))
            .map_err(|_| Error::Corrupt);
    }
    crate::admission::require_request_in(
        c,
        proof.tenant_id(),
        id,
        crate::quotas::Channel::MacosMdm,
    )
    .await?;
    let existing=sqlx::query("SELECT q.state,q.authority_kind,q.expires_at>clock_timestamp() AS live,g.actor,g.instance FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=$1::uuid AND q.id=$2 FOR UPDATE OF q")
        .bind(proof.tenant_id()).bind(id).fetch_optional(&mut *c).await.map_err(db)?;
    let registration;
    if let Some(row) = existing {
        if row.try_get::<String, _>("authority_kind").map_err(db)? != "apple_account"
            || row.try_get::<String, _>("actor").map_err(db)? != proof.principal_id()
            || row.try_get::<String, _>("instance").map_err(db)? != proof.instance_id()
        {
            return Err(Error::Unauthorized);
        }
        let state: String = row.try_get("state").map_err(db)?;
        if state == "cancelled" {
            return Err(Error::Unauthorized);
        }
        registration = if state == "bound" {
            Some(super::store::active_registration(c, proof.tenant_id(), id).await?)
        } else {
            None
        };
        if state == "pending" && !row.try_get::<bool, _>("live").map_err(db)? {
            crate::quotas::admit_on(
                c,
                proof.tenant_id(),
                proof.instance_id(),
                proof.principal_id(),
                crate::quotas::Channel::MacosMdm,
            )
            .await?;
        }
        sqlx::query("UPDATE mdm_access.requests SET account_version=account_version+1,account_reference=$3,account_challenge=$4,expires_at=clock_timestamp()+interval '300 seconds' WHERE tenant_id=$1::uuid AND id=$2")
            .bind(proof.tenant_id()).bind(id).bind(serde_json::to_value(&reference).map_err(|_|Error::Corrupt)?).bind(&hash).execute(&mut *c).await.map_err(db)?;
    } else {
        crate::quotas::admit_on(
            c,
            proof.tenant_id(),
            proof.instance_id(),
            proof.principal_id(),
            crate::quotas::Channel::MacosMdm,
        )
        .await?;
        let device = format!(
            "self:{}:{}:{}",
            proof.instance_id(),
            proof.principal_id(),
            id
        );
        proof.self_enrollment(&device)?;
        let grant = Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2,$3,$4,$5,'enrollment','consumed',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t")
            .bind(proof.tenant_id()).bind(grant).bind(proof.principal_id()).bind(proof.instance_id()).bind(&device).execute(&mut *c).await.map_err(db)?;
        sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,authority_kind,grant_id,state,source,expected_generation,issuance_operation,expires_at,self_service,account_version,account_reference,account_challenge) VALUES($1::uuid,$2,'apple_account',$3,'pending','mdm.apple',0,$4,clock_timestamp()+interval '300 seconds',true,1,$5,$6)")
            .bind(proof.tenant_id()).bind(id).bind(grant).bind(operation).bind(serde_json::to_value(&reference).map_err(|_|Error::Corrupt)?).bind(&hash).execute(&mut *c).await.map_err(db)?;
        registration = None;
    }
    let expiry:i64=sqlx::query_scalar("SELECT floor(extract(epoch FROM expires_at))::bigint FROM mdm_access.requests WHERE tenant_id=$1::uuid AND id=$2").bind(proof.tenant_id()).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    let receipt = Receipt {
        operation_id: operation,
        enrollment_id: id,
        status: if registration.is_some() {
            "bound"
        } else {
            "pending"
        }
        .into(),
        expires_at: expiry,
        registration,
        source: ReportSource::MdmApple,
    };
    proof.check_live()?;
    crate::operations::save(
        c,
        &op,
        &serde_json::to_string(&receipt).map_err(|_| Error::Corrupt)?,
        audit,
    )
    .await?;
    Ok((receipt, false))
}

/// The organization proof is revalidated inside the same transaction as its request.
#[allow(
    clippy::too_many_arguments,
    reason = "one existing registration transaction with manufacturer evidence and mandatory organization authority"
)]
pub async fn issue_organization_in(
    c: &mut PgConnection,
    tenant: &str,
    organization: Uuid,
    profile: Uuid,
    machine: &rss_mdm_certificate::apple::ade::MachineInfo,
    id: Uuid,
    challenge: &str,
    authority: Arc<dyn OrganizationAuthority>,
) -> Result<Admission, Error> {
    if id.is_nil() || organization.is_nil() || profile.is_nil() {
        return Err(Error::Malformed);
    }
    crate::admission::require_new_in(c, tenant, crate::quotas::Channel::MacosMdm).await?;
    let device = format!("ade:{organization}:{id}");
    crate::device::store::lock_channel(c, tenant, &device, rss_mdm_inventory::Channel::Mdm).await?;
    authority
        .authorize_issue(c, tenant, organization, profile, machine)
        .await?;
    let grant = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2,'service:apple-ade','service',$3,'enrollment','consumed',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t")
        .bind(tenant).bind(grant).bind(&device).execute(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,authority_kind,grant_id,state,source,expected_generation,issuance_operation,expires_at,self_service,organization_version,organization_challenge) VALUES($1::uuid,$2,'apple_ade',$3,'pending','mdm.apple',0,$2,clock_timestamp()+interval '300 seconds',false,1,$4)")
        .bind(tenant).bind(id).bind(grant).bind(organization_challenge(tenant,id,challenge)).execute(c).await.map_err(db)?;
    Ok(Admission {
        data: Coordinates {
            tenant: tenant.into(),
            id,
            device,
            actor: "service:apple-ade".into(),
            instance: "service".into(),
            version: 1,
            expected_generation: 0,
            operation: id,
            source: ReportSource::MdmApple,
        },
        basis: Basis::Organization { authority },
    })
}
pub fn organization_challenge(tenant: &str, id: Uuid, challenge: &str) -> String {
    digest(&("apple.ade.scep/v1", tenant, id, challenge))
}
pub async fn organization(
    store: &crate::Store,
    tenant: &str,
    id: Uuid,
    authority: Arc<dyn OrganizationAuthority>,
    challenge: Option<&str>,
) -> Result<Admission, Error> {
    let mut tx = store.begin(tenant).await?;
    let row = request(&mut tx, tenant, id).await?;
    if row.try_get::<String, _>("authority_kind").map_err(db)? != "apple_ade" {
        return Err(Error::Unauthorized);
    }
    if let Some(challenge) = challenge
        && !super::equal(
            &row.try_get::<String, _>("organization_challenge")
                .map_err(db)?,
            &organization_challenge(tenant, id, challenge),
        )
    {
        return Err(Error::Unauthorized);
    }
    let data = Coordinates {
        tenant: tenant.into(),
        id,
        device: row.try_get("device").map_err(db)?,
        actor: row.try_get("actor").map_err(db)?,
        instance: row.try_get("instance").map_err(db)?,
        version: row.try_get("organization_version").map_err(db)?,
        expected_generation: row.try_get("expected_generation").map_err(db)?,
        operation: uuid(&row, "issuance_operation")?,
        source: ReportSource::MdmApple,
    };
    tx.rollback().await.map_err(db)?;
    Ok(Admission {
        data,
        basis: Basis::Organization { authority },
    })
}

/// Only a live Identity account plus the mandatory product policy can create native authority.
pub async fn entra_in(
    c: &mut PgConnection,
    proof: rss_mdm_authorization_service::entra::RevalidatedAccount,
    authority: Arc<dyn EntraPolicyAuthority>,
    id: Uuid,
    policy_version: i64,
    profile: super::WindowsProfile,
) -> Result<Admission, Error> {
    proof.check_live().map_err(|_| Error::Unauthorized)?;
    let claims = proof.claims().map_err(|_| Error::Unauthorized)?;
    let device_id = claims.device.ok_or(Error::Unauthorized)?;
    let device = format!("entra:{}:{}", claims.tenant, device_id);
    let tenant = proof.account().tenant.to_string();
    let actor = proof.account().principal.as_uuid().to_string();
    let instance = proof.instance().to_string();
    if id.is_nil() || policy_version <= 0 {
        return Err(Error::Malformed);
    }
    crate::admission::lock_in(c, &tenant).await?;
    // Organization authority uses the shared lifecycle without personal quota locks.
    crate::device::store::lock_channel(c, &tenant, &device, rss_mdm_inventory::Channel::Mdm)
        .await?;
    let old = sqlx::query("SELECT q.id FROM mdm_access.requests q JOIN mdm_access.grants g ON(g.tenant_id,g.id)=(q.tenant_id,q.grant_id) WHERE q.tenant_id=$1::uuid AND q.authority_kind='windows_entra' AND g.device=$2 AND q.state<>'cancelled' AND ((q.state='bound' AND EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE r.tenant_id=q.tenant_id AND r.request_id=q.id AND r.state='active' AND r.purpose='primary')) OR (q.state='pending' AND q.expires_at>clock_timestamp())) FOR UPDATE OF q")
        .bind(&tenant).bind(&device).fetch_optional(&mut *c).await.map_err(db)?;
    let (id, generation) = if let Some(old) = old {
        let id: Uuid = old.try_get("id").map_err(db)?;
        let row = request(c, &tenant, id).await?;
        if row.try_get::<String, _>("actor").map_err(db)? != actor
            || row.try_get::<String, _>("instance").map_err(db)? != instance
            || row.try_get::<i64, _>("organization_version").map_err(db)? != policy_version
            || row
                .try_get::<Option<String>, _>("windows_profile")
                .map_err(db)?
                .as_deref()
                != Some(profile.as_str())
        {
            return Err(Error::Conflict);
        }
        (
            id,
            row.try_get::<i64, _>("expected_generation").map_err(db)?,
        )
    } else {
        crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::WindowsMdm).await?;
        // Active enrollments use certificate renewal; a new native token cannot replace another owner.
        let generation: i64 = sqlx::query_scalar("SELECT coalesce(max(generation),0) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel='mdm' AND purpose='primary'")
            .bind(&tenant).bind(&device).fetch_one(&mut *c).await.map_err(db)?;
        let grant = Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2,$3,$4,$5,'enrollment','consumed',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t")
            .bind(&tenant).bind(grant).bind(&actor).bind(&instance).bind(&device).execute(&mut *c).await.map_err(db)?;
        sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,authority_kind,grant_id,state,source,expected_generation,issuance_operation,expires_at,self_service,organization_version,windows_profile) VALUES($1::uuid,$2,'windows_entra',$3,'pending','mdm.windows',$4,$2,clock_timestamp()+interval '300 seconds',false,$5,$6)")
            .bind(&tenant).bind(id).bind(grant).bind(generation).bind(policy_version).bind(profile.as_str()).execute(&mut *c).await.map_err(db)?;
        (id, generation)
    };
    let admission = Admission {
        data: Coordinates {
            tenant,
            id,
            device,
            actor,
            instance,
            version: policy_version,
            expected_generation: generation,
            operation: id,
            source: ReportSource::MdmWindows,
        },
        basis: Basis::Entra { proof, authority },
    };
    admission.current_request(c).await?;
    Ok(admission)
}
impl Admission {
    pub async fn recheck_entra(
        self,
        authority: &rss_mdm_authorization_service::entra::EntraAuthority,
    ) -> Result<Self, Error> {
        let Self { data, basis } = self;
        match basis {
            Basis::Entra {
                proof,
                authority: policy,
            } => Ok(Self {
                data,
                basis: Basis::Entra {
                    proof: rss_mdm_authorization_service::entra::recheck(authority, proof).await?,
                    authority: policy,
                },
            }),
            _ => Err(Error::Unauthorized),
        }
    }
}

/// A native password handoff can originate from an authenticated Agent task without a browser session.
pub async fn agent_policy(
    database: &crate::Store,
    tenant: &str,
    id: Uuid,
    secret: Option<&str>,
    authority: Arc<dyn AgentPolicyAuthority>,
) -> Result<Admission, Error> {
    let mut tx = database.begin(tenant).await?;
    let row = request(&mut tx, tenant, id).await?;
    if row.try_get::<String, _>("authority_kind").map_err(db)? != "agent_policy" {
        return Err(Error::Unauthorized);
    }
    let device: String = row.try_get("device").map_err(db)?;
    if let Some(secret) = secret {
        let password = super::Password::new(secret.to_owned())?;
        if password.digest(tenant, &device)?
            != row.try_get::<String, _>("password_digest").map_err(db)?
        {
            return Err(Error::Unauthorized);
        }
    }
    let admission = Admission {
        data: Coordinates {
            tenant: tenant.into(),
            id,
            device,
            actor: row.try_get("actor").map_err(db)?,
            instance: row.try_get("instance").map_err(db)?,
            version: row.try_get("password_version").map_err(db)?,
            expected_generation: row.try_get("expected_generation").map_err(db)?,
            operation: uuid(&row, "issuance_operation")?,
            source: ReportSource::parse(&row.try_get::<String, _>("source").map_err(db)?)
                .map_err(|_| Error::Corrupt)?,
        },
        basis: Basis::AgentPolicy { authority },
    };
    admission.current_request(&mut tx).await?;
    tx.rollback().await.map_err(db)?;
    Ok(admission)
}
