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
use uuid::Uuid;

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
enum Basis {
    Password {
        credential: Uuid,
        proof: AuthorizedPrincipal,
    },
    Account {
        reference: SessionReference,
        proof: RevalidatedSession,
    },
}
pub struct Admission {
    pub data: Coordinates,
    basis: Basis,
}
impl Admission {
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
    pub fn check_live(&self) -> Result<(), Error> {
        match &self.basis {
            Basis::Password { proof, .. } => proof.check_live().map_err(Into::into),
            Basis::Account { proof, .. } => proof.check_live().map_err(|_| Error::Unauthorized),
        }
    }
    pub fn bind_audit(&self, audit: &RequestAudit) -> Result<(), Error> {
        match &self.basis {
            Basis::Password { proof, .. } => proof.bind_audit(audit).map_err(Into::into),
            Basis::Account { proof, .. } => {
                rss_mdm_authorization_service::session::bind_revalidated_audit(proof, audit)
                    .map_err(Into::into)
            }
        }
    }
    pub async fn current(&self, c: &mut PgConnection) -> Result<PgRow, Error> {
        self.check_live()?;
        let d = &self.data;
        let row = request(c, &d.tenant, d.id).await?;
        if row.try_get::<String, _>("state").map_err(db)? != "pending"
            || !row.try_get::<bool, _>("live").map_err(db)?
            || row.try_get::<String, _>("actor").map_err(db)? != d.actor
            || row.try_get::<String, _>("instance").map_err(db)? != d.instance
            || row.try_get::<String, _>("device").map_err(db)? != d.device
            || row.try_get::<String, _>("source").map_err(db)? != d.source.as_str()
        {
            return Err(Error::Unauthorized);
        }
        let kind: String = row.try_get("authority_kind").map_err(db)?;
        match &self.basis {
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
    Ok(Admission {
        data,
        basis: Basis::Account { reference, proof },
    })
}
pub fn challenge_digest(tenant: &str, id: Uuid, challenge: &str) -> String {
    digest(&("apple.account.scep/v1", tenant, id, challenge))
}
/// Called only after the Apple bridge authenticated and checked its organization/account binding.
#[allow(
    clippy::too_many_arguments,
    reason = "one existing lifecycle transaction with exact operation receipt"
)]
pub async fn issue_in(
    c: &mut PgConnection,
    proof: &AuthorizedPrincipal,
    id: Uuid,
    operation: Uuid,
    challenge: &str,
    audit: &RequestAudit,
) -> Result<(Receipt, bool), Error> {
    proof.check_live()?;
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
        sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) VALUES($1::uuid,$2,$3,$4,$5,'enrollment','consumed',clock_timestamp(),clock_timestamp()+interval '300 seconds')")
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
