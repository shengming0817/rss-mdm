//! Attach an original CA response to the frozen attempt; never sign an unresolved attempt again.
use crate::{
    Error,
    mutation::{Change, replay, save},
    registry::Registry,
    signing::Frozen,
};
use rss_mdm_agent_wire::pki::Purpose;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_certificate::windows::Csr;
use rss_mdm_device_trust::{decode, digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use x509_cert::der::{Decode, DecodePem, Encode};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recovery {
    pub operation: Uuid,
    pub attempt: Uuid,
    pub chain: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Receipt {
    pub attempt: Uuid,
    pub fingerprint: String,
}
impl Registry {
    pub async fn recover(
        &self,
        p: &AuthorizedPrincipal,
        input: &Recovery,
        a: &RequestAudit,
        now: i64,
    ) -> Result<Receipt, Error> {
        p.require_all_devices(Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        p.bind_audit(a).map_err(|_| Error::Forbidden)?;
        if input.operation.is_nil()
            || input.attempt.is_nil()
            || input.chain.is_empty()
            || input.chain.len() > 4
        {
            return Err(Error::Request);
        }
        let mut tx = self.begin(p.tenant_id()).await?;
        let binding: Vec<u8> = sqlx::query_scalar(
            "SELECT binding FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2",
        )
        .bind(p.tenant_id())
        .bind(input.attempt)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Error::Storage)?;
        tx.rollback().await.map_err(|_| Error::Storage)?;
        let frozen: Frozen = serde_json::from_slice(&binding).map_err(|_| Error::Storage)?;
        let purpose = match frozen.purpose.as_str() {
            "windows" => Purpose::Windows,
            _ => return Err(Error::Request),
        };
        let trust = self.trust(purpose)?;
        if trust.tenant.to_string() != p.tenant_id() {
            return Err(Error::Forbidden);
        }
        self.synchronize(now).await?;
        let trust = self.binding(purpose)?;
        let chain = input
            .chain
            .iter()
            .map(|s| decode(s, 32768).map_err(|_| Error::Request))
            .collect::<Result<Vec<_>, _>>()?;
        let csr = x509_cert::request::CertReq::from_pem(&frozen.csr)
            .map_err(|_| Error::Storage)?
            .to_der()
            .map_err(|_| Error::Storage)?;
        if frozen.version != 1 || Sha256::digest(&csr).as_slice() != frozen.csr_digest {
            return Err(Error::Storage);
        }
        let request = x509_cert::request::CertReq::from_der(&csr).map_err(|_| Error::Storage)?;
        for certificate in &chain {
            x509_cert::Certificate::from_der(certificate).map_err(|_| Error::Request)?;
        }
        let leaf = x509_cert::Certificate::from_der(&chain[0]).map_err(|_| Error::Request)?;
        trust
            .verify_history(&chain[0], &frozen.issuer)
            .map_err(|_| Error::Request)?;
        let t = &leaf.tbs_certificate;
        if t.subject_public_key_info != request.info.public_key
            || t.validity.not_before.to_unix_duration().as_secs() as i64 != frozen.start
            || t.validity.not_after.to_unix_duration().as_secs() as i64 != frozen.end
        {
            return Err(Error::Request);
        }
        Csr::verify(&csr).map_err(|_| Error::Storage)?;
        let registration = Uuid::parse_str(&frozen.subject).map_err(|_| Error::Storage)?;
        if !frozen.sans.is_empty() || t.subject.to_string() != format!("CN={registration}") {
            return Err(Error::Request);
        }
        let receipt = Receipt {
            attempt: input.attempt,
            fingerprint: digest(&chain[0]),
        };
        let request =
            Sha256::digest(serde_json::to_vec(input).map_err(|_| Error::Request)?).to_vec();
        let bytes = serde_json::to_vec(&chain).map_err(|_| Error::Request)?;
        a.operation(
            input.operation,
            "device_pki_signing_recover",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.mutation(
            rss_request_context::TenantId::parse(p.tenant_id()).map_err(|_| Error::Request)?,
            a,
            (p, input, binding, request, bytes, receipt),
            |ctx, c| {
                Box::pin(async move {
                    let (p, input, binding, hash, bytes, receipt) = ctx;
                    p.check_live().map_err(|_| Error::Forbidden)?;
                    rss_mdm_authorization_service::lock_on(c, p.tenant_id(), p.instance_id())
                        .await
                        .map_err(|_| Error::Storage)?;
                    rss_mdm_authorization_service::snapshot_on(c, p.tenant_id(), p.instance_id())
                        .await
                        .map_err(|_| Error::Storage)?
                        .require_all_devices(p, Permission::Credentials)
                        .map_err(|_| Error::Forbidden)?;
                    let phase = "signing_recover";
                    let old = replay(
                        c,
                        p.tenant_id(),
                        p.principal_id(),
                        p.instance_id(),
                        input.operation,
                        phase,
                        hash,
                    )
                    .await?;
                    if let Some(old) = old {
                        return Ok(Change {
                            value: serde_json::from_slice(&old).map_err(|_| Error::Storage)?,
                            replay: true,
                            key: format!("pki:{}:{phase}", input.operation),
                            fingerprint: hash.clone(),
                        });
                    }
                    adopt_in(c, p.tenant_id(), input.attempt, binding, bytes).await?;
                    save(
                        c,
                        (p.tenant_id(), p.principal_id(), p.instance_id()),
                        input.operation,
                        phase,
                        hash,
                        &serde_json::to_vec(receipt).map_err(|_| Error::Storage)?,
                    )
                    .await?;
                    Ok(Change {
                        value: Receipt {
                            attempt: receipt.attempt,
                            fingerprint: receipt.fingerprint.clone(),
                        },
                        replay: false,
                        key: format!("pki:{}:{phase}", input.operation),
                        fingerprint: hash.clone(),
                    })
                })
            },
        )
        .await
    }
}
pub async fn adopt_in(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    attempt: Uuid,
    binding: &[u8],
    chain: &[u8],
) -> Result<(), Error> {
    let row=sqlx::query("SELECT binding,state,chain FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2 FOR UPDATE")
        .bind(tenant).bind(attempt).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
    if row
        .try_get::<Vec<u8>, _>("binding")
        .map_err(|_| Error::Storage)?
        != binding
    {
        return Err(Error::Conflict);
    }
    if row
        .try_get::<String, _>("state")
        .map_err(|_| Error::Storage)?
        == "issued"
    {
        if row
            .try_get::<Vec<u8>, _>("chain")
            .map_err(|_| Error::Storage)?
            != chain
        {
            return Err(Error::Conflict);
        }
        return Ok(());
    }
    let frozen: Frozen = serde_json::from_slice(binding).map_err(|_| Error::Storage)?;
    let certificates: Vec<Vec<u8>> = serde_json::from_slice(chain).map_err(|_| Error::Request)?;
    crate::certificates::record_candidate_in(
        c,
        tenant,
        &frozen.purpose,
        None,
        &frozen.issuer,
        certificates.first().ok_or(Error::Request)?,
    )
    .await?;
    sqlx::query("UPDATE mdm_pki.signing SET state='issued',chain=$3 WHERE tenant_id=$1::uuid AND attempt=$2")
        .bind(tenant).bind(attempt).bind(chain).execute(c).await.map_err(|_|Error::Storage)?;
    Ok(())
}
