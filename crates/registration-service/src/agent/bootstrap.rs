//! Dedicated native bootstrap authority. Package delivery is not enrollment proof.
use super::*;
use rss_mdm_certificate::{HandshakePeer, bootstrap as certificate};
use rss_mdm_device_trust::DeviceTrust;
use rss_mdm_pki_service::scep;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};
/// Prepared by application composition from the purpose-specific PKI trust and webhook keys.
pub struct Configuration {
    pub trust: DeviceTrust,
    pub webhooks: scep::Verifier,
}
/// Public native certificate enrollment inputs. Secrets are generated per installation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployment {
    pub issuer: String,
    pub provisioner: String,
    pub scep_url: String,
    pub root: Vec<u8>,
    pub root_thumbprint: String,
}
impl Deployment {
    /// Select the exact issuer frozen by the caller's registry transaction fence.
    pub fn select(
        trust: rss_mdm_agent_wire::pki::Trust,
        endpoints: &std::collections::BTreeMap<String, String>,
        now: i64,
    ) -> Result<Self, Error> {
        let trust = DeviceTrust::new(trust, rss_mdm_agent_wire::pki::Purpose::AgentBootstrap, now)
            .map_err(|_| Error::Configuration)?;
        let issuer = trust.active().map_err(|_| Error::Configuration)?;
        let root =
            rss_mdm_device_trust::decode(&issuer.root, 32768).map_err(|_| Error::Configuration)?;
        let root_thumbprint = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &root)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        Ok(Self {
            scep_url: endpoints
                .get(&issuer.digest)
                .ok_or(Error::Configuration)?
                .clone(),
            issuer: issuer.digest,
            provisioner: issuer.provisioner,
            root,
            root_thumbprint,
        })
    }
}
impl Service {
    pub fn bootstrap_configuration(&self) -> Result<&Configuration, Failure> {
        self.bootstrap
            .as_deref()
            .ok_or_else(|| Error::Configuration.into())
    }
    pub async fn bootstrap_challenge(
        &self,
        verified: scep::VerifiedRequest,
        audit: &RequestAudit,
    ) -> Result<serde_json::Value, Failure> {
        let config = self.bootstrap_configuration()?;
        let input = verified.request();
        if input.x509_certificate.is_some() || input.scep_error_code.is_some() {
            return Err(Error::Unauthorized.into());
        }
        let csr = certificate::Csr::verify(
            &input
                .x509_certificate_request
                .der()
                .map_err(|_| Error::Malformed)?,
        )
        .map_err(|_| Error::Unauthorized)?;
        let active = config
            .trust
            .public()
            .map_err(|_| Error::Configuration)?
            .issuers
            .into_iter()
            .find(|issuer| issuer.digest == verified.issuer())
            .ok_or(Error::Unauthorized)?;
        let challenge = input.scep_challenge.as_ref().ok_or(Error::Unauthorized)?;
        let now = self.clock.unix_seconds()?;
        audit.operation(csr.attempt(), "agent_bootstrap_sign");
        self.write(audit, (self, &csr, &input, challenge, &active, now), |ctx,c| Box::pin(async move {
            let (s,csr,input,challenge,active,now)=*ctx;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))").bind(s.tenant.to_string()).execute(&mut *c).await.map_err(db)?;
            let retained:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_pki.issuers WHERE tenant_id=$1::uuid AND purpose='agent_bootstrap' AND digest=$2 AND state IN ('active','verify_only'))")
                .bind(s.tenant.to_string()).bind(&active.digest).fetch_one(&mut *c).await.map_err(db)?;
            if !retained {return Err(Error::Forbidden);}
            let row = row(c,s.tenant,csr.attempt()).await?;
            if !row.try_get::<bool,_>("active").map_err(db)?
                || row.try_get::<Uuid,_>("installation").map_err(db)? != csr.installation()
                || row.try_get::<i64,_>("deadline").map_err(db)? <= now
                || input.provisioner_name.as_deref() != Some(active.provisioner.as_str())
                || row.try_get::<String,_>("issuer").map_err(db)? != active.digest
                || row.try_get::<String,_>("provisioner").map_err(db)? != active.provisioner
                || row.try_get::<Vec<u8>,_>("challenge").map_err(db)?.as_slice() != Sha256::digest(challenge.as_bytes()).as_slice() { return Err(Error::Forbidden); }
            let state: String = row.try_get("state").map_err(db)?;
            let replay = state == "signing"
                && row.try_get::<Option<String>,_>("transaction_id").map_err(db)?.as_deref() == Some(input.transaction.as_str())
                && row.try_get::<Option<Vec<u8>>,_>("csr_digest").map_err(db)?.as_deref() == Some(csr.digest().as_slice())
                && row.try_get::<Option<Vec<u8>>,_>("spki").map_err(db)?.as_deref() == Some(csr.spki().as_slice());
            if state != "prepared" && !replay { return Err(Error::Forbidden); }
            let source = native::source(c,s.tenant,row.try_get("source").map_err(db)?).await?;
            s.native.bootstrap(c,&source).await?;
            let stored_deadline: i64 = row.try_get("deadline").map_err(db)?;
            let deadline = if replay { stored_deadline } else { stored_deadline.min(now + 1800) };
            if !replay { sqlx::query("UPDATE mdm_access.agent_bootstraps SET state='signing',transaction_id=$3,csr_digest=$4,spki=$5,deadline=$6 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(s.tenant.to_string()).bind(csr.attempt()).bind(&input.transaction).bind(csr.digest().as_slice()).bind(csr.spki().as_slice()).bind(deadline).execute(c).await.map_err(db)?; }
            Ok(Change { value: serde_json::json!({"allow":true,"data":{"subject":{"commonName":rss_mdm_certificate::apple::subject(csr.installation(),csr.attempt()),"organizationalUnit":[certificate::PURPOSE]},"notAfter":time::OffsetDateTime::from_unix_timestamp(deadline).map_err(|_|Error::Corrupt)?.format(&time::format_description::well_known::Rfc3339).map_err(|_|Error::Corrupt)?}}), replay, digest: digest(&(csr.attempt(),csr.digest(),&input.transaction))? })
        })).await.map_err(Into::into)
    }
    pub async fn bootstrap_notify(
        &self,
        verified: scep::VerifiedRequest,
        audit: &RequestAudit,
    ) -> Result<(), Failure> {
        let config = self.bootstrap_configuration()?;
        let input = verified.request();
        if input.scep_error_code.is_some() {
            return Err(Error::Unauthorized.into());
        }
        let der = input
            .x509_certificate
            .as_ref()
            .ok_or(Error::Unauthorized)?
            .der()
            .map_err(|_| Error::Malformed)?;
        let now = self.clock.unix_seconds()?;
        let chain = [der.as_slice().into()];
        let issuer = config
            .trust
            .verify(&chain, now)
            .map_err(|_| Error::Unauthorized)?;
        if issuer.digest != verified.issuer() {
            return Err(Error::Unauthorized.into());
        }
        let leaf = Certificate::from_der(&der).map_err(|_| Error::Malformed)?;
        let (installation, id) = certificate::parse_subject(&leaf.tbs_certificate.subject)
            .map_err(|_| Error::Unauthorized)?;
        let fingerprint: Vec<u8> = Sha256::digest(&der).to_vec();
        let spki = Sha256::digest(
            leaf.tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| Error::Malformed)?,
        )
        .to_vec();
        let end = leaf
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs() as i64;
        audit.operation(id, "agent_bootstrap_issued");
        self.write(audit,(self,id,installation,&issuer,&input,&der,&fingerprint,&spki,end), |ctx,c| Box::pin(async move {
            let (s,id,installation,issuer,input,der,fingerprint,spki,end)=*ctx;
            let row=row(c,s.tenant,id).await?;
            if row.try_get::<Uuid,_>("installation").map_err(db)? != installation
                || row.try_get::<String,_>("issuer").map_err(db)? != issuer.digest
                || row.try_get::<Option<String>,_>("transaction_id").map_err(db)?.as_deref()!=Some(input.transaction.as_str())
                || row.try_get::<Option<Vec<u8>>,_>("spki").map_err(db)?.as_ref()!=Some(spki)
                || end>row.try_get::<i64,_>("deadline").map_err(db)? { return Err(Error::Forbidden); }
            let state: String=row.try_get("state").map_err(db)?;
            let replay=state=="issued" || state=="consumed";
            if replay {
                if row.try_get::<Option<Vec<u8>>,_>("fingerprint").map_err(db)?.as_ref()!=Some(fingerprint) {return Err(Error::Conflict);}
            } else if state=="signing" {
                let source=native::source(c,s.tenant,row.try_get("source").map_err(db)?).await?;
                s.native.bootstrap(c,&source).await?;
                sqlx::query("UPDATE mdm_access.agent_bootstraps SET state='issued',fingerprint=$3,certificate=$4 WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(s.tenant.to_string()).bind(id).bind(fingerprint).bind(der).execute(c).await.map_err(db)?;
            } else {return Err(Error::Forbidden);}
            Ok(Change {value:(),replay,digest:digest(&(id,fingerprint))?})
        })).await.map_err(Into::into)
    }
    pub async fn native_grant(
        &self,
        peer: &HandshakePeer,
        input: &wire::NativeGrantRequest,
        audit: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        input.validate().map_err(|_| Error::Malformed)?;
        let config = self.bootstrap_configuration()?;
        config
            .trust
            .verify(peer.chain(), self.clock.unix_seconds()?)
            .map_err(|_| Error::Unauthorized)?;
        let bytes = peer.chain().first().ok_or(Error::Unauthorized)?;
        let leaf = Certificate::from_der(bytes).map_err(|_| Error::Unauthorized)?;
        let (installation, id) = certificate::parse_subject(&leaf.tbs_certificate.subject)
            .map_err(|_| Error::Unauthorized)?;
        if installation != input.installation_operation {
            return Err(Error::Forbidden.into());
        }
        if csr(&input.csr)?
            .uses_key(&leaf.tbs_certificate.subject_public_key_info)
            .map_err(|_| Error::Malformed)?
        {
            return Err(Error::Forbidden.into());
        }
        let fingerprint = Sha256::digest(bytes).to_vec();
        audit.operation(input.operation_id, "agent_native_grant");
        self.write(audit,(self,id,input,&fingerprint),|ctx,c|Box::pin(async move {
            let(s,id,input,fingerprint)=*ctx;
            let row=row(c,s.tenant,id).await?;
            if !row.try_get::<bool,_>("active").map_err(db)? || !matches!(row.try_get::<String,_>("state").map_err(db)?.as_str(),"issued"|"consumed")
                || row.try_get::<i64,_>("deadline").map_err(db)?<=s.clock.unix_seconds()?
                || row.try_get::<Option<Vec<u8>>,_>("fingerprint").map_err(db)?.as_ref()!=Some(fingerprint) {return Err(Error::Forbidden);}
            let mut proof: serde_json::Value=row.try_get("source").map_err(db)?;
            proof["runtime"]=serde_json::to_value(&input.runtime).map_err(|_|Error::Malformed)?;
            let source=native::source(c,s.tenant,proof).await?;
            let (value,replay)=s.native.grant(c,&source,input).await?;
            sqlx::query("UPDATE mdm_access.agent_bootstraps SET state='consumed' WHERE tenant_id=$1::uuid AND id=$2")
                .bind(s.tenant.to_string()).bind(id).execute(c).await.map_err(db)?;
            Ok(Change {value,replay,digest:digest(input)?})
        })).await.map_err(Into::into)
    }
}
async fn row(
    c: &mut PgConnection,
    tenant: rss_request_context::TenantId,
    id: Uuid,
) -> Result<PgRow, Error> {
    sqlx::query(
        "SELECT * FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND id=$2 FOR UPDATE",
    )
    .bind(tenant.to_string())
    .bind(id)
    .fetch_optional(c)
    .await
    .map_err(db)?
    .ok_or(Error::Unauthorized)
}
