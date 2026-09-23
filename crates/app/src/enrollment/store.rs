use super::*;
use crate::identity::Principal;
use crate::{
    AccessStore, Failure,
    access::EnrollmentPermission,
    access_store::{Actor, Operation, db},
    audit::Audit,
    device::store::lock_channel,
};
use rss_mdm_inventory::Channel;
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};

pub(crate) fn actor(proof: &Principal) -> Actor<'_> {
    Actor {
        tenant: proof.tenant_id(),
        subject: proof.principal_id(),
        instance: proof.instance_id(),
    }
}
pub(crate) fn uuid(row: &PgRow, name: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(&row.try_get::<String, _>(name).map_err(db)?)
        .map_err(|_| Error::Unavailable(Failure::AccessStore))
}
fn authorization(row: PgRow) -> Result<Authorization, Error> {
    Ok(Authorization {
        id: uuid(&row, "id")?,
        device: row.try_get("device").map_err(db)?,
        actor: row.try_get("actor").map_err(db)?,
        instance: row.try_get("instance").map_err(db)?,
        credential_ref: uuid(&row, "credential_ref")?,
        version: row.try_get("password_version").map_err(db)?,
        expected_generation: row.try_get("expected_generation").map_err(db)?,
        operation: uuid(&row, "issuance_operation")?,
        state: row.try_get("state").map_err(db)?,
        channel: match row.try_get::<String, _>("channel").map_err(db)?.as_str() {
            "agent" => Channel::Agent,
            "mdm" => Channel::Mdm,
            _ => return Err(Error::Unavailable(Failure::AccessStore)),
        },
    })
}
pub(crate) async fn request(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &str,
    id: Uuid,
) -> Result<PgRow, Error> {
    // Cancelled legacy rows have no password or session and can never be resumed.
    sqlx::query("SELECT r.id::text,r.state,r.channel,r.password_digest,r.password_version,r.expected_generation,r.credential_ref::text,r.issuance_operation::text,floor(extract(epoch FROM r.expires_at))::bigint AS expiry,r.expires_at>clock_timestamp() AS live,g.actor,g.instance,g.device FROM mdm_access.requests r JOIN mdm_access.grants g ON (g.tenant_id,g.id)=(r.tenant_id,r.grant_id) WHERE r.tenant_id=$1::uuid AND r.id=$2::uuid AND r.issuance_operation IS NOT NULL FOR UPDATE OF r")
        .bind(tenant).bind(id.to_string()).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(Error::Forbidden)
}
impl AccessStore {
    pub(crate) async fn create_enrollment(
        &self,
        permission: EnrollmentPermission<'_>,
        password: &Password,
        channel: Channel,
        session: Uuid,
        key: Uuid,
        audit: &Audit,
    ) -> Result<Receipt, Error> {
        let proof = permission.proof();
        proof.enrollment(permission.device())?;
        let device = permission.device();
        let password_digest = password.digest(proof.tenant_id(), device)?;
        let digest = digest(&("enrollment_create", device, channel, &password_digest));
        let op = Operation {
            actor: actor(proof),
            key,
            digest: &digest,
        };
        let mut tx = self.begin(proof.tenant_id()).await?;
        if let Some(old) = Self::replay(&mut tx, &op).await? {
            proof.enrollment(permission.device())?;
            return serde_json::from_str(&old)
                .map_err(|_| Error::Unavailable(Failure::AccessStore));
        }
        lock_channel(&mut tx, proof.tenant_id(), device, channel).await?;
        let generation: i64 = sqlx::query_scalar("SELECT coalesce(max(generation),0) FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND channel=$3")
            .bind(proof.tenant_id()).bind(device).bind(channel.as_str()).fetch_one(&mut *tx).await.map_err(db)?;
        let id = Uuid::new_v4();
        let grant = Uuid::new_v4();
        sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,created_at,expires_at) SELECT $1::uuid,$2::uuid,$3,$4,$5,'enrollment','consumed',now,now+interval '300 seconds' FROM (SELECT clock_timestamp() AS now) t")
            .bind(proof.tenant_id()).bind(grant.to_string()).bind(proof.principal_id()).bind(proof.instance_id()).bind(device).execute(&mut *tx).await.map_err(db)?;
        let expires: i64 = sqlx::query_scalar("INSERT INTO mdm_access.requests(tenant_id,id,grant_id,state,channel,expected_generation,password_digest,password_version,credential_ref,expires_at,issuance_operation) VALUES($1::uuid,$2::uuid,$3::uuid,'pending',$4,$5,$6,1,$7::uuid,clock_timestamp()+interval '300 seconds',$8::uuid) RETURNING floor(extract(epoch FROM expires_at))::bigint")
            .bind(proof.tenant_id()).bind(id.to_string()).bind(grant.to_string()).bind(channel.as_str()).bind(generation).bind(password_digest).bind(session.to_string()).bind(Uuid::new_v4().to_string()).fetch_one(&mut *tx).await.map_err(db)?;
        let receipt = Receipt {
            operation_id: key,
            enrollment_id: id,
            status: "pending".into(),
            expires_at: expires,
            registration: None,
            channel,
        };
        proof.enrollment(permission.device())?;
        self.finish(
            tx,
            &op,
            &serde_json::to_string(&receipt).expect("closed receipt"),
            audit,
            Some(id),
        )
        .await?;
        Ok(receipt)
    }
    pub(crate) async fn enrollment_target(
        &self,
        proof: &Principal,
        id: Uuid,
    ) -> Result<String, Error> {
        let mut tx = self.begin(proof.tenant_id()).await?;
        let row = request(&mut tx, proof.tenant_id(), id).await?;
        same_actor(&row, proof)?;
        row.try_get("device").map_err(db)
    }
    pub(crate) async fn change_enrollment(
        &self,
        permission: EnrollmentPermission<'_>,
        id: Uuid,
        resume: Option<(&Password, Uuid)>,
        key: Uuid,
        audit: &Audit,
    ) -> Result<Receipt, Error> {
        let proof = permission.proof();
        proof.enrollment(permission.device())?;
        let password_digest = resume
            .map(|(p, _)| p.digest(proof.tenant_id(), permission.device()))
            .transpose()?;
        let action = if resume.is_some() {
            "enrollment_resume"
        } else {
            "enrollment_cancel"
        };
        let digest = digest(&(action, id, &password_digest));
        let op = Operation {
            actor: actor(proof),
            key,
            digest: &digest,
        };
        let mut tx = self.begin(proof.tenant_id()).await?;
        if let Some(old) = Self::replay(&mut tx, &op).await? {
            proof.enrollment(permission.device())?;
            return serde_json::from_str(&old)
                .map_err(|_| Error::Unavailable(Failure::AccessStore));
        }
        let row = request(&mut tx, proof.tenant_id(), id).await?;
        same_actor(&row, proof)?;
        if row.try_get::<String, _>("device").map_err(db)? != permission.device() {
            return Err(Error::Forbidden);
        }
        let state: String = row.try_get("state").map_err(db)?;
        if state == "cancelled" || state == "bound" && resume.is_none() {
            return Err(Error::Conflict);
        }
        let registration = if state == "bound" {
            Some(
                self.active_registration(&mut tx, proof.tenant_id(), id)
                    .await?,
            )
        } else {
            None
        };
        let expires = if let Some((_, reference)) = resume {
            if password_digest.as_deref()
                == Some(
                    row.try_get::<String, _>("password_digest")
                        .map_err(db)?
                        .as_str(),
                )
            {
                return Err(Error::Conflict);
            }
            sqlx::query_scalar("UPDATE mdm_access.requests SET password_digest=$3,password_version=password_version+1,credential_ref=$4::uuid,expires_at=clock_timestamp()+interval '300 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid RETURNING floor(extract(epoch FROM expires_at))::bigint")
                .bind(proof.tenant_id()).bind(id.to_string()).bind(password_digest).bind(reference.to_string()).fetch_one(&mut *tx).await.map_err(db)?
        } else {
            sqlx::query("UPDATE mdm_access.requests SET state='cancelled' WHERE tenant_id=$1::uuid AND id=$2::uuid")
                .bind(proof.tenant_id()).bind(id.to_string()).execute(&mut *tx).await.map_err(db)?;
            row.try_get("expiry").map_err(db)?
        };
        let receipt = Receipt {
            operation_id: key,
            enrollment_id: id,
            status: if resume.is_some() {
                state
            } else {
                "cancelled".into()
            },
            expires_at: expires,
            registration,
            channel: match row.try_get::<String, _>("channel").map_err(db)?.as_str() {
                "agent" => Channel::Agent,
                "mdm" => Channel::Mdm,
                _ => return Err(Error::Unavailable(Failure::AccessStore)),
            },
        };
        proof.enrollment(permission.device())?;
        self.finish(
            tx,
            &op,
            &serde_json::to_string(&receipt).expect("closed receipt"),
            audit,
            Some(id),
        )
        .await?;
        Ok(receipt)
    }
    pub(crate) async fn enrollment_authorization(
        &self,
        tenant: &str,
        id: Uuid,
        password: &Password,
    ) -> Result<Authorization, Error> {
        let mut tx = self.begin(tenant).await?;
        let row = request(&mut tx, tenant, id).await?;
        let device: String = row.try_get("device").map_err(db)?;
        let state: String = row.try_get("state").map_err(db)?;
        if state == "cancelled"
            || state != "bound" && !row.try_get::<bool, _>("live").map_err(db)?
            || !super::equal(
                &password.digest(tenant, &device)?,
                &row.try_get::<String, _>("password_digest").map_err(db)?,
            )
        {
            return Err(Error::Unauthorized);
        }
        authorization(row)
    }
    pub(crate) async fn active_registration(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
        id: Uuid,
    ) -> Result<Uuid, Error> {
        let row = sqlx::query("SELECT r.id::text FROM mdm_access.registrations r JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.request_id=$2::uuid AND r.state='active' AND c.state='active' FOR SHARE OF r,c")
            .bind(tenant).bind(id.to_string()).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(Error::Conflict)?;
        uuid(&row, "id")
    }
    pub(crate) async fn active_windows_enrollment(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: &str,
        id: Uuid,
    ) -> Result<Uuid, Error> {
        let row = sqlx::query("SELECT r.id::text,e.certificate,floor(extract(epoch FROM clock_timestamp()))::bigint AS now FROM mdm_access.registrations r JOIN mdm_access.credentials c ON (c.tenant_id,c.registration)=(r.tenant_id,r.id) JOIN mdm_access.enrollment_certificates e ON (e.tenant_id,e.request_id)=(r.tenant_id,r.request_id) WHERE r.tenant_id=$1::uuid AND r.request_id=$2::uuid AND r.channel='mdm' AND r.state='active' AND c.state='active' FOR SHARE OF r,c")
            .bind(tenant).bind(id.to_string()).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(Error::Conflict)?;
        use x509_cert::der::Decode;
        let certificate: Vec<u8> = row.try_get("certificate").map_err(db)?;
        let certificate =
            x509_cert::Certificate::from_der(&certificate).map_err(|_| Error::Conflict)?;
        crate::windows::certificate::leaf_usage(
            &certificate.tbs_certificate,
            row.try_get("now").map_err(db)?,
        )?;
        uuid(&row, "id")
    }
}
fn same_actor(row: &PgRow, proof: &Principal) -> Result<(), Error> {
    if row.try_get::<String, _>("actor").map_err(db)? != proof.principal_id()
        || row.try_get::<String, _>("instance").map_err(db)? != proof.instance_id()
    {
        return Err(Error::Forbidden);
    }
    Ok(())
}
