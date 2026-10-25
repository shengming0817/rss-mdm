//! Refresh signed publications and reconcile durable revoke jobs without holding business locks.
//! A successful /revoke response is never itself a published-revocation receipt.
use crate::{
    Error,
    mutation::Change,
    registry::{Registry, purpose},
};
use rss_mdm_agent_wire::pki::{Purpose, Trust};
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_device_trust::{DeviceTrust, crl, decode};
use rss_request_context::TenantId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use x509_cert::{Certificate, der::Decode};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub issuer: String,
    pub crl: String,
    pub root_crl: String,
}
/// One atomic purpose snapshot; no single-publication compatibility route.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationSet {
    pub operation: Uuid,
    pub purpose: Purpose,
    pub publications: Vec<Publication>,
}
/// Public certificate/publication deadlines and durable CA work; contains no key or endpoint.
#[derive(Serialize)]
pub struct Health {
    pub purpose: Purpose,
    pub issuer: String,
    pub issuer_not_after: i64,
    pub root_not_after: i64,
    pub crl_next_update: i64,
    pub root_crl_next_update: i64,
    pub unpublished_revocations: i64,
}
struct Job {
    attempt: Uuid,
    serial: String,
    failures: i32,
}
impl Registry {
    pub async fn health(&self) -> Result<Vec<Health>, Error> {
        let mut result = Vec::new();
        for binding in self.bindings() {
            let trust = binding.public().map_err(|_| Error::Storage)?;
            let mut tx = self.begin(&trust.tenant.to_string()).await?;
            for g in trust.issuers {
                let certificate = Certificate::from_der(
                    &decode(&g.certificate, 32768).map_err(|_| Error::Storage)?,
                )
                .map_err(|_| Error::Storage)?;
                let root =
                    Certificate::from_der(&decode(&g.root, 32768).map_err(|_| Error::Storage)?)
                        .map_err(|_| Error::Storage)?;
                let next = |encoded: &str| -> Result<i64, Error> {
                    let list = x509_cert::crl::CertificateList::from_der(
                        &decode(encoded, 16 * 1024 * 1024).map_err(|_| Error::Storage)?,
                    )
                    .map_err(|_| Error::Storage)?;
                    Ok(list
                        .tbs_cert_list
                        .next_update
                        .ok_or(Error::Storage)?
                        .to_unix_duration()
                        .as_secs() as i64)
                };
                let pending=sqlx::query_scalar("SELECT count(*) FROM mdm_pki.revocations WHERE tenant_id=$1 AND purpose=$2 AND issuer=$3 AND state<>'published'")
                    .bind(trust.tenant).bind(purpose(trust.purpose)).bind(&g.digest).fetch_one(&mut *tx).await.map_err(|_|Error::Storage)?;
                result.push(Health {
                    purpose: trust.purpose,
                    issuer: g.digest,
                    issuer_not_after: certificate
                        .tbs_certificate
                        .validity
                        .not_after
                        .to_unix_duration()
                        .as_secs() as i64,
                    root_not_after: root
                        .tbs_certificate
                        .validity
                        .not_after
                        .to_unix_duration()
                        .as_secs() as i64,
                    crl_next_update: next(&g.crl)?,
                    root_crl_next_update: next(&g.root_crl)?,
                    unpublished_revocations: pending,
                });
            }
            tx.rollback().await.map_err(|_| Error::Storage)?;
        }
        Ok(result)
    }
    /// Authenticated offline-root/legacy-issuer CRL publication follows the same validation path.
    pub async fn publish(
        &self,
        p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        input: &PublicationSet,
        a: &RequestAudit,
        now: i64,
    ) -> Result<(), Error> {
        p.require_all_devices(rss_mdm_authorization_service::Permission::Credentials)
            .map_err(|_| Error::Forbidden)?;
        p.bind_audit(a).map_err(|_| Error::Forbidden)?;
        if input.operation.is_nil()
            || self.trust(input.purpose)?.tenant.to_string() != p.tenant_id()
        {
            return Err(Error::Forbidden);
        }
        a.operation(
            input.operation,
            "device_pki_crl_publish",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.publish_set(
            &input.publications,
            input.purpose,
            input.operation,
            a,
            Some(p),
            now,
        )
        .await
    }
    async fn publish_set(
        &self,
        inputs: &[Publication],
        requested_purpose: Purpose,
        operation: Uuid,
        a: &RequestAudit,
        principal: Option<&rss_mdm_authorization_service::context::AuthorizedPrincipal>,
        now: i64,
    ) -> Result<(), Error> {
        if inputs.is_empty() || inputs.len() > 16 || operation.is_nil() {
            return Err(Error::Request);
        }
        let mut next = self.trust(requested_purpose)?;
        let mut publications = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut roots = std::collections::BTreeMap::new();
        for input in inputs {
            if !seen.insert(&input.issuer) {
                return Err(Error::Request);
            }
            let g = next
                .issuers
                .iter_mut()
                .find(|g| g.digest == input.issuer)
                .ok_or(Error::Request)?;
            let certificate =
                Certificate::from_der(&decode(&g.certificate, 32768).map_err(|_| Error::Request)?)
                    .map_err(|_| Error::Request)?;
            let published = crl(
                &decode(&input.crl, 16 * 1024 * 1024).map_err(|_| Error::Request)?,
                &certificate,
                now,
            )
            .map_err(|_| Error::Request)?;
            g.crl = input.crl.clone();
            let root = g.root.clone();
            if roots
                .insert(root.clone(), input.root_crl.clone())
                .is_some_and(|old| old != input.root_crl)
            {
                return Err(Error::Request);
            }
            // One offline root publication applies to every generation sharing that exact root.
            for sibling in next.issuers.iter_mut().filter(|g| g.root == root) {
                sibling.root_crl = input.root_crl.clone();
            }
            publications.push((input.issuer.clone(), published));
        }
        DeviceTrust::new(next.clone(), requested_purpose, now).map_err(|_| Error::Request)?;
        let tenant = next.tenant;
        let mut canonical = inputs.iter().collect::<Vec<_>>();
        canonical.sort_by(|a, b| a.issuer.cmp(&b.issuer));
        let fingerprint = Sha256::digest(
            serde_json::to_vec(&(
                "device-pki-publication/v1",
                requested_purpose,
                operation,
                canonical,
            ))
            .map_err(|_| Error::Request)?,
        )
        .to_vec();
        let result=self.mutation(TenantId::parse(&tenant.to_string()).map_err(|_|Error::Request)?,a,
            (principal,next.clone(),publications,fingerprint,now,operation),|ctx,c|Box::pin(async move {
                let (p,next,publications,fingerprint,now,operation)=ctx;
                if let Some(p)=p {
                    p.check_live().map_err(|_|Error::Forbidden)?;
                    rss_mdm_authorization_service::lock_on(c,p.tenant_id(),p.instance_id()).await.map_err(|_|Error::Storage)?;
                    rss_mdm_authorization_service::snapshot_on(c,p.tenant_id(),p.instance_id()).await.map_err(|_|Error::Storage)?
                        .require_all_devices(p,rss_mdm_authorization_service::Permission::Credentials).map_err(|_|Error::Forbidden)?;
                }
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))").bind(next.tenant.to_string()).execute(&mut *c).await.map_err(|_|Error::Storage)?;
                let bytes:Vec<u8>=sqlx::query_scalar("SELECT body FROM mdm_pki.trust WHERE tenant_id=$1 AND purpose=$2 FOR UPDATE")
                    .bind(next.tenant).bind(purpose(next.purpose)).fetch_one(&mut *c).await.map_err(|_|Error::Storage)?;
                let current:Trust=serde_json::from_slice(&bytes).map_err(|_|Error::Storage)?;
                if current.installation_digest()!=next.installation_digest(){return Err(Error::Conflict);}
                let actor=p.map(|p|p.principal_id()).unwrap_or("service:device-pki");
                let instance=p.map(|p|p.instance_id()).unwrap_or("");
                let replay=crate::mutation::replay(c,&next.tenant.to_string(),actor,instance,*operation,"crl_publish",fingerprint).await?.is_some();
                if replay { return Ok(Change{value:false, replay:true, key:format!("pki:{operation}:crl_publish")}); }
                let checked=DeviceTrust::restore(current.clone(),current.purpose,*now).map_err(|_|Error::Storage)?;
                checked.update(next.clone(),*now).map_err(|_|Error::Conflict)?;
                for (issuer,published) in publications {
                    let number=i64::try_from(published.number).map_err(|_|Error::Request)?;
                    sqlx::query("UPDATE mdm_pki.revocations SET state='published',crl_number=$4 WHERE tenant_id=$1 AND purpose=$2 AND issuer=$3 AND serial=ANY($5) AND state<>'published'")
                        .bind(next.tenant).bind(purpose(next.purpose)).bind(issuer.as_str()).bind(number).bind(&published.revoked).execute(&mut *c).await.map_err(|_|Error::Storage)?;
                }
                crate::registry::persist(c,next).await?;
                if !replay {crate::mutation::save(c,(&next.tenant.to_string(),actor,instance),*operation,"crl_publish",fingerprint,b"null").await?;}
                Ok(Change{value:true, replay, key:format!("pki:{operation}:crl_publish")})
            })).await;
        if matches!(result, Ok(true)) {
            self.binding(requested_purpose)?
                .update(next, now)
                .map_err(|_| Error::Storage)?;
        }
        result.map(|_| ())
    }
    /// Refresh all generations of a purpose together, so a CA outage can recover without restart.
    pub async fn sweep(
        &self,
        clock: impl Fn() -> Result<i64, Error> + Send + Sync,
    ) -> Result<(), Error> {
        self.synchronize(clock()?).await?;
        let mut failed = false;
        for binding in self.bindings() {
            let trust = binding.public().map_err(|_| Error::Storage)?;
            let mut inputs = Vec::new();
            let mut unavailable = false;
            for g in &trust.issuers {
                let client = match self.providers.get(trust.purpose, &g.digest) {
                    Ok(c) => c,
                    Err(_) if g.provisioner.is_empty() => continue,
                    Err(_) => {
                        unavailable = true;
                        continue;
                    }
                };
                match client.published_crl().await {
                    Ok(bytes) => inputs.push(Publication {
                        issuer: g.digest.clone(),
                        crl: base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            bytes,
                        ),
                        root_crl: g.root_crl.clone(),
                    }),
                    Err(_) => unavailable = true,
                }
            }
            if unavailable || inputs.is_empty() {
                failed |= unavailable;
                continue;
            }
            // A physical issuer can serve several purposes with identical CRL bytes.
            // Keep each purpose in its own durable operation scope.
            let canonical = serde_json::to_vec(&("device-pki-sweep/v1", trust.purpose, &inputs))
                .map_err(|_| Error::Storage)?;
            let operation = Uuid::from_bytes(
                Sha256::digest(canonical)[..16]
                    .try_into()
                    .map_err(|_| Error::Storage)?,
            );
            let publication_now = clock()?;
            let a = RequestAudit::new(
                trust.tenant.to_string(),
                "device_pki_crl_publish",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            a.identify_service("service:device-pki");
            a.operation(
                operation,
                "device_pki_crl_publish",
                rss_mdm_audit_integration::AuditIntent::Management,
            );
            let result = self
                .publish_set(&inputs, trust.purpose, operation, &a, None, publication_now)
                .await;
            a.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            if result.is_err() {
                failed = true;
                continue;
            }
            for provider in self.providers.entries().iter().filter(|p| {
                p.purpose == trust.purpose && trust.issuers.iter().any(|g| g.digest == p.issuer)
            }) {
                for _ in 0..8 {
                    let Some(job) = self.claim(&trust, provider, clock()?).await? else {
                        break;
                    };
                    let acknowledged = provider
                        .client
                        .revoke(job.attempt, &job.serial, clock()?)
                        .await
                        .is_ok();
                    if acknowledged {
                        self.submitted(&trust, provider, &job).await?;
                    }
                }
            }
        }
        if failed { Err(Error::Storage) } else { Ok(()) }
    }
    async fn claim(
        &self,
        trust: &Trust,
        provider: &crate::providers::Provider,
        now: i64,
    ) -> Result<Option<Job>, Error> {
        let a = RequestAudit::new(
            trust.tenant.to_string(),
            "device_pki_revoke_dispatch",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        a.identify_service("service:device-pki");
        let result=self.mutation(TenantId::parse(&trust.tenant.to_string()).map_err(|_|Error::Request)?,&a,
            (trust,provider,now,&a),|ctx,c|Box::pin(async move {
                let (trust,provider,now,a)=ctx;
                let row=sqlx::query("SELECT serial,attempt,failures FROM mdm_pki.revocations WHERE tenant_id=$1 AND purpose=$2 AND issuer=$3 AND state<>'published' AND next_attempt<=clock_timestamp() ORDER BY next_attempt,attempt LIMIT 1 FOR UPDATE SKIP LOCKED")
                    .bind(trust.tenant).bind(purpose(provider.purpose)).bind(&provider.issuer).fetch_optional(&mut *c).await.map_err(|_|Error::Storage)?;
                let Some(row)=row else{return Ok(Change{value:None, replay:true, key:String::new()});};
                let job=Job{attempt:row.try_get("attempt").map_err(|_|Error::Storage)?,serial:row.try_get("serial").map_err(|_|Error::Storage)?,failures:row.try_get("failures").map_err(|_|Error::Storage)?};
                a.operation(job.attempt,"device_pki_revoke_dispatch", rss_mdm_audit_integration::AuditIntent::Management);
                let seconds=(60_i64.saturating_mul(1_i64<<job.failures.min(9))).min(21600);
                sqlx::query("UPDATE mdm_pki.revocations SET failures=least(failures+1,32),next_attempt=clock_timestamp()+make_interval(secs=>$4) WHERE tenant_id=$1 AND purpose=$2 AND attempt=$3")
                    .bind(trust.tenant).bind(purpose(provider.purpose)).bind(job.attempt).bind(seconds as f64).execute(c).await.map_err(|_|Error::Storage)?;

                Ok(Change{key:format!("pki:{}:dispatch:{now}",job.attempt), value:Some(job), replay:false})
            })).await;
        a.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
    async fn submitted(
        &self,
        trust: &Trust,
        provider: &crate::providers::Provider,
        job: &Job,
    ) -> Result<(), Error> {
        let a = RequestAudit::new(
            trust.tenant.to_string(),
            "device_pki_revoke_submit",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        a.identify_service("service:device-pki");
        a.operation(
            job.attempt,
            "device_pki_revoke_submit",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let result=self.mutation(TenantId::parse(&trust.tenant.to_string()).map_err(|_|Error::Request)?,&a,(trust,provider,job),|ctx,c|Box::pin(async move {
            let (trust,provider,job)=ctx;
            let changed=sqlx::query("UPDATE mdm_pki.revocations SET state='submitted' WHERE tenant_id=$1 AND purpose=$2 AND attempt=$3 AND state='pending'")
                .bind(trust.tenant).bind(purpose(provider.purpose)).bind(job.attempt).execute(c).await.map_err(|_|Error::Storage)?.rows_affected();
            Ok(Change{value:(), replay:changed==0, key:if changed==0{String::new()}else{format!("pki:{}:submitted",job.attempt)}})
        })).await;
        a.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
/// A previously accepted complete snapshot has at least one common valid interval.
pub(crate) fn publication_time(trust: &Trust) -> Result<i64, Error> {
    let mut newest = 0;
    for g in &trust.issuers {
        for encoded in [&g.crl, &g.root_crl] {
            let der = decode(encoded, 16 * 1024 * 1024).map_err(|_| Error::Storage)?;
            let list =
                x509_cert::crl::CertificateList::from_der(&der).map_err(|_| Error::Storage)?;
            newest = newest.max(list.tbs_cert_list.this_update.to_unix_duration().as_secs() as i64);
        }
    }
    Ok(newest)
}
