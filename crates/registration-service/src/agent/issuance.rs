use super::*;
use rss_mdm_device_trust::agent::IssuedAgentCertificate;
pub(crate) struct Signing {
    pub attempt: Uuid,
    pub issuer: [u8; 32],
    pub grant: Uuid,
    pub csr: Vec<u8>,
    pub identity: String,
    pub deadline: i64,
    pub start: i64,
    pub end: i64,
}
enum Claim {
    New(Signing),
    Issued(wire::Candidate),
    Unknown(Uuid),
}
impl Service {
    pub async fn issue(
        &self,
        input: &wire::CertificateRequest,
        a: &RequestAudit,
    ) -> Result<wire::Candidate, Failure> {
        version(input.wire_version, input.operation_id)?;
        input.runtime.validate().map_err(|_| Error::Malformed)?;
        let verified = csr(&input.csr)?;
        let request_digest = digest(input)?;
        let spki = hex(verified.spki());
        let csr = STANDARD.decode(&input.csr).map_err(|_| Error::Malformed)?;
        // Authorization and candidate writes are phases; the HTTP result still needs settlement.
        a.require_request_settlement();
        a.operation(input.operation_id, "agent_certificate_authorize");
        let claim = self
            .write(a, (self, input, a, request_digest, spki, csr), |ctx, c| {
                Box::pin(async move {
                    let (service, input, a, digest, spki, csr) = ctx;
                    let tenant = service.tenant.to_string();
                    configurations::lock_for_grant(c, &tenant, input.grant_id).await?;
                    let grant = grant_row(c, &tenant, input.grant_id).await?;
                    check_secret(&tenant, &grant, &input.secret)?;
                    a.target(&grant.try_get::<String, _>("device").map_err(db)?);
                    if let Some(row) = sqlx::query(
                        r#"
SELECT * FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND grant_id=$2 FOR UPDATE
"#,
                    )
                    .bind(&tenant)
                    .bind(input.grant_id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    {
                        if row.try_get::<Uuid, _>("operation_id").map_err(db)? != input.operation_id
                            || row.try_get::<String, _>("request_digest").map_err(db)? != *digest
                            || row.try_get::<String, _>("spki").map_err(db)? != *spki
                        {
                            return Err(Error::Conflict);
                        }
                        service.grant_live(c, &grant).await?;
                        let value = if row.try_get::<String, _>("state").map_err(db)? == "issued" {
                            Claim::Issued(candidate(&grant, &row)?)
                        } else {
                            Claim::Unknown(row.try_get("id").map_err(db)?)
                        };
                        return Ok(Change {
                            value,
                            replay: true,
                            digest: digest.clone(),
                        });
                    }
                    service.grant_live(c, &grant).await?;
                    if grant
                        .try_get::<Option<Uuid>, _>("target_registration")
                        .map_err(db)?
                        .is_none()
                    {
                        crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::Agent)
                            .await?;
                    }
                    if let Some(authority) = grant
                        .try_get::<Option<serde_json::Value>, _>("native_authority")
                        .map_err(db)?
                        && authority["runtime"]
                            != serde_json::to_value(&input.runtime).map_err(|_| Error::Malformed)?
                    {
                        return Err(Error::Forbidden);
                    }
                    if let Some(binding) = grant
                        .try_get::<Option<serde_json::Value>, _>("configuration_binding")
                        .map_err(db)?
                        && binding["runtime"]
                            != serde_json::to_value(&input.runtime).map_err(|_| Error::Malformed)?
                    {
                        return Err(Error::Forbidden);
                    }
                    if row_platform(&grant)? != input.runtime.platform
                        || grant
                            .try_get::<Option<String>, _>("spki")
                            .map_err(db)?
                            .is_some_and(|v| v != *spki)
                    {
                        return Err(Error::Forbidden);
                    }
                    if grant.try_get::<String, _>("state").map_err(db)? != "available" {
                        return Err(Error::Conflict);
                    }
                    let device: String = grant.try_get("device").map_err(db)?;
                    a.target(&device);
                    let start = now(c).await?;
                    let end = service.issuer.end(start)?;
                    let identity = rss_mdm_certificate::agent::identity(
                        Uuid::parse_str(&tenant).map_err(|_| Error::Configuration)?,
                        &device,
                    )
                    .map_err(|_| Error::Configuration)?;
                    let attempt = Uuid::new_v4();
                    let issuer = service.trust().issuer_digest();
                    let signing = Signing {
                        attempt,
                        issuer,
                        grant: input.grant_id,
                        csr: csr.clone(),
                        identity: identity.clone(),
                        deadline: grant.try_get("expiry").map_err(db)?,
                        start,
                        end,
                    };
                    service
                        .issuer
                        .authorize_in(
                            c,
                            Uuid::parse_str(&tenant).map_err(|_| Error::Configuration)?,
                            &signing,
                        )
                        .await?;
                    sqlx::query(
                        r#"
INSERT INTO
mdm_access.agent_issuances(tenant_id,
id,
grant_id,
operation_id,
request_digest,
csr,
spki,
identity,
profile,
not_before,
not_after,
authority_digest,
signing_issuer,
state)
VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'signing')
"#,
                    )
                    .bind(&tenant)
                    .bind(attempt)
                    .bind(input.grant_id)
                    .bind(input.operation_id)
                    .bind(&*digest)
                    .bind(&*csr)
                    .bind(&*spki)
                    .bind(&identity)
                    .bind(serde_json::to_value(&input.runtime).map_err(|_| Error::Malformed)?)
                    .bind(start)
                    .bind(end)
                    .bind(service.issuer.authority_digest(issuer)?)
                    .bind(hex(issuer))
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                    sqlx::query(
                        r#"
UPDATE mdm_access.agent_grants SET state='consumed' WHERE tenant_id=$1::uuid AND id=$2
"#,
                    )
                    .bind(&tenant)
                    .bind(input.grant_id)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                    Ok(Change {
                        value: Claim::New(signing),
                        replay: false,
                        digest: digest.clone(),
                    })
                })
            })
            .await?;
        let signing = match claim {
            Claim::Issued(c) => return Ok(c),
            Claim::Unknown(id) => return Err(unknown(id)),
            Claim::New(s) => s,
        };
        let attempt = signing.attempt;
        let intent = self.issuer.persisted_intent(signing)?;
        let issued = match self
            .issuer
            .issue(
                intent,
                &rss_mdm_pki_service::signing::SigningStore::new(self.audit.clone()),
                Uuid::parse_str(&self.tenant.to_string()).map_err(|_| Error::Configuration)?,
            )
            .await
        {
            Ok(v) => v.certificate,
            Err(_) => {
                // The signing row already fences retries. Best-effort diagnostic transition cannot authorize a retry.
                let _ = self.record_unknown(input, attempt, a).await;
                return Err(unknown(attempt));
            }
        };
        self.save_certificate(
            input.grant_id,
            attempt,
            &issued,
            input.operation_id,
            a,
            None,
        )
        .await
        .map_err(|_| unknown(attempt))
    }
    async fn record_unknown(
        &self,
        input: &wire::CertificateRequest,
        id: Uuid,
        a: &RequestAudit,
    ) -> Result<(), Error> {
        a.operation(input.operation_id, "agent_certificate_unknown");
        self.write(a, (self, id), |ctx, c| {
            Box::pin(async move {
                let (service, id) = ctx;
                let n = sqlx::query(
                    r#"
UPDATE mdm_access.agent_issuances SET state='unknown' WHERE tenant_id=$1::uuid AND id=$2 AND
state='signing'
"#,
                )
                .bind(service.tenant.to_string())
                .bind(*id)
                .execute(c)
                .await
                .map_err(db)?
                .rows_affected();
                Ok(Change {
                    value: (),
                    replay: n == 0,
                    digest: digest(id)?,
                })
            })
        })
        .await
    }
    async fn save_certificate(
        &self,
        grant: Uuid,
        id: Uuid,
        certificate: &IssuedAgentCertificate,
        operation: Uuid,
        a: &RequestAudit,
        principal: Option<&AuthorizedPrincipal>,
    ) -> Result<wire::Candidate, Error> {
        a.operation(operation, "agent_certificate_result");
        let digest = if principal.is_some() {
            digest(&("agent_issuance_recovery", id, &certificate.chain))?
        } else {
            hex(certificate.csr_digest)
        };
        self.write(a, (self, grant, id, certificate, digest, principal, operation, a), |ctx, c| {
            Box::pin(async move {
                let (service, grant, id, certificate, digest, principal, operation, a) = ctx;
                let tenant = service.tenant.to_string();
                if let Some(p)=principal {
                    p.check_live()?;
                    rss_mdm_authorization_service::lock_on(c,&tenant,p.instance_id()).await?;
                }
                // A reused certificate is not a replay of a new administrator operation.
                let receipt = principal.map(|p| crate::operations::Operation {
                    actor: crate::operations::Actor::from_authorized(p),
                    key: *operation,
                    digest,
                });
                let previous = if let Some(op) = &receipt {
                    crate::operations::replay(c, op).await?
                } else {
                    None
                };
                let g = grant_row(c, &tenant, *grant).await?;
                if let Some(p)=principal {
                    rss_mdm_authorization_service::snapshot_on(c,&tenant,p.instance_id()).await?
                        .require(p,rss_mdm_authorization_service::Permission::Credentials,Some(&g.try_get::<String,_>("device").map_err(db)?)).map_err(|_|Error::Forbidden)?;
                }
                a.target(&g.try_get::<String, _>("device").map_err(db)?);
                if let Some(old) = previous {
                    return Ok(Change {
                        value: serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,
                        replay: true,
                        digest: digest.clone(),
                    });
                }
                let old = sqlx::query(
                    r#"
SELECT * FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND id=$2 AND grant_id=$3 FOR
UPDATE
"#,
                )
                .bind(&tenant)
                .bind(*id)
                .bind(*grant)
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
                if old.try_get::<String, _>("signing_issuer").map_err(db)?
                    != hex(certificate.metadata.issuer)
                {
                    return Err(Error::Forbidden);
                }
                if let Some(binding)=sqlx::query_scalar::<_,Vec<u8>>("SELECT binding FROM mdm_pki.signing WHERE tenant_id=$1::uuid AND attempt=$2")
                    .bind(&tenant).bind(*id).fetch_optional(&mut *c).await.map_err(db)? {
                    rss_mdm_pki_service::recovery::adopt_in(c,&tenant,*id,&binding,
                        &serde_json::to_vec(&certificate.chain).map_err(|_|Error::Corrupt)?).await.map_err(|_|Error::Conflict)?;
                }
                rss_mdm_pki_service::certificates::record_candidate_in(c,&tenant,"agent",g.try_get::<Option<Uuid>,_>("target_registration").map_err(db)?,
                    &hex(certificate.metadata.issuer),certificate.chain.first().ok_or(Error::Corrupt)?).await.map_err(|_|Error::Storage)?;
                if g.try_get::<String,_>("state").map_err(db)?=="revoked" {
                    rss_mdm_pki_service::certificates::enqueue_in(c,&tenant,"agent",&hex(certificate.metadata.issuer),
                        &rss_mdm_device_trust::serial(&certificate.metadata.serial)).await.map_err(|_|Error::Storage)?;
                }
                let replay = old.try_get::<String, _>("state").map_err(db)? == "issued";
                if replay
                    && old.try_get::<String, _>("fingerprint").map_err(db)?
                        != hex(certificate.metadata.fingerprint)
                {
                    return Err(Error::Conflict);
                }
                if !replay {
                    sqlx::query(
                        r#"
UPDATE mdm_access.agent_issuances SET
state='issued',certificate_chain=$3,metadata=$4,fingerprint=$5 WHERE tenant_id=$1::uuid AND
id=$2
"#,
                    )
                    .bind(&tenant)
                    .bind(*id)
                    .bind(
                        serde_json::to_value(
                            certificate
                                .chain
                                .iter()
                                .map(|v| STANDARD.encode(v))
                                .collect::<Vec<_>>(),
                        )
                        .map_err(|_| Error::Corrupt)?,
                    )
                    .bind(serde_json::to_value(&certificate.metadata).map_err(|_| Error::Corrupt)?)
                    .bind(hex(certificate.metadata.fingerprint))
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                }
                let row = sqlx::query(
                    r#"
SELECT * FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND id=$2
"#,
                )
                .bind(&tenant)
                .bind(*id)
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
                let value = candidate(&g, &row)?;
                if let Some(op) = &receipt {
                    crate::operations::save(c, op, &serde_json::to_string(&value).map_err(|_| Error::Corrupt)?, a).await?;
                }
                Ok(Change {
                    value,
                    replay: receipt.is_none() && replay,
                    digest: digest.clone(),
                })
            })
        })
        .await
    }
    pub async fn recover_issuance(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: &wire::RecoverIssuance,
        a: &RequestAudit,
    ) -> Result<wire::Candidate, Failure> {
        self.proof(p, a)?;
        version(input.wire_version, input.operation_id)?;
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let i = sqlx::query(
            r#"
SELECT * FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND id=$2
"#,
        )
        .bind(&tenant)
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let expected: String = i.try_get("signing_issuer").map_err(db)?;
        let bytes = (0..32)
            .map(|i| {
                u8::from_str_radix(expected.get(i * 2..i * 2 + 2).ok_or(Error::Corrupt)?, 16)
                    .map_err(|_| Error::Corrupt)
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let expected: [u8; 32] = bytes.try_into().map_err(|_| Error::Corrupt)?;
        let grant = i.try_get::<Uuid, _>("grant_id").map_err(db)?;
        let g = grant_row(&mut tx, &tenant, grant).await?;
        p.credentials(&g.try_get::<String, _>("device").map_err(db)?)?;
        let verified = VerifiedAgentCsr::verify(&i.try_get::<Vec<u8>, _>("csr").map_err(db)?)
            .map_err(|_| Error::Corrupt)?;
        if input.certificate_chain.is_empty() || input.certificate_chain.len() > 4 {
            return Err(Error::Malformed.into());
        }
        let chain = input
            .certificate_chain
            .iter()
            .map(|v| {
                if v.len() > 43692 {
                    Err(Error::Malformed)
                } else {
                    STANDARD.decode(v).map_err(|_| Error::Malformed)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let issued = self
            .trust()
            .recover_issued_for(
                expected,
                chain,
                &verified,
                &i.try_get::<String, _>("identity").map_err(db)?,
                i.try_get("not_before").map_err(db)?,
                i.try_get("not_after").map_err(db)?,
            )
            .map_err(|_| Error::Forbidden)?;
        tx.commit().await.map_err(db)?;
        self.save_certificate(grant, id, &issued, input.operation_id, a, Some(p))
            .await
            .map_err(Into::into)
    }
}
pub(super) fn row_platform(row: &PgRow) -> Result<runtime::TaskPlatform, Error> {
    match row.try_get::<String, _>("platform").map_err(db)?.as_str() {
        "windows" => Ok(runtime::TaskPlatform::Windows),
        "macos" => Ok(runtime::TaskPlatform::Macos),
        _ => Err(Error::Corrupt),
    }
}
fn candidate(grant: &PgRow, row: &PgRow) -> Result<wire::Candidate, Error> {
    Ok(wire::Candidate {
        wire_version: wire::API_VERSION,
        issuance_id: row.try_get("id").map_err(db)?,
        operation_id: row.try_get("operation_id").map_err(db)?,
        certificate_chain: serde_json::from_value(row.try_get("certificate_chain").map_err(db)?)
            .map_err(|_| Error::Corrupt)?,
        activate_before: grant.try_get("expiry").map_err(db)?,
    })
}
fn unknown(id: Uuid) -> Failure {
    Failure {
        code: wire::ErrorCode::IssuanceUnknown,
        issuance_id: Some(id),
        source: None,
    }
}
pub(super) async fn now(c: &mut PgConnection) -> Result<i64, Error> {
    sqlx::query_scalar(
        r#"
SELECT floor(extract(epoch FROM clock_timestamp()))::bigint
"#,
    )
    .fetch_one(c)
    .await
    .map_err(db)
}
