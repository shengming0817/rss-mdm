use super::*;
use rss_mdm_certificate::agent::IssuedAgentCertificate;
pub(crate) struct Signing {
    pub attempt: Uuid,
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
        a.operation(input.operation_id, "agent_certificate_authorize");
        let claim=self.write(a,(self,input,a,request_digest,spki,csr),|ctx,c| { Box::pin(async move {
            let (service,input,a,digest,spki,csr)=ctx;
let tenant=service.tenant.to_string();
let grant=grant_row(c,&tenant,input.grant_id).await?;
            check_secret(&tenant,&grant,&input.secret)?;
a.target(&grant.try_get::<String,_>("device").map_err(db)?);
            if let Some(row)=sqlx::query(r#"
SELECT * FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND grant_id=$2 FOR UPDATE
"#).bind(&tenant).bind(input.grant_id).fetch_optional(&mut *c).await.map_err(db)?{
                if row.try_get::<Uuid,_>("operation_id").map_err(db)?!=input.operation_id || row.try_get::<String,_>("request_digest").map_err(db)?!=*digest || row.try_get::<String,_>("spki").map_err(db)?!=*spki{
return Err(Error::Conflict)}
                service.grant_live(c,&grant).await?;
                let value=if row.try_get::<String,_>("state").map_err(db)?=="issued"{
Claim::Issued(candidate(&grant,&row)?)}
else{
Claim::Unknown(row.try_get("id").map_err(db)?)}
;
                return Ok(Change{
value,replay:true,digest:digest.clone()}
)
            }
            service.grant_live(c,&grant).await?;
            if let Some(authority)=grant.try_get::<Option<serde_json::Value>,_>("native_authority").map_err(db)? {
                if authority["runtime"]!=serde_json::to_value(&input.runtime).map_err(|_|Error::Malformed)?{
return Err(Error::Forbidden)}
            }
            if !service.policy.platforms.contains(&input.runtime.platform) || row_platform(&grant)?!=input.runtime.platform || grant.try_get::<Option<String>,_>("spki").map_err(db)?.is_some_and(|v|v!=*spki){
return Err(Error::Forbidden)}
            if grant.try_get::<String,_>("state").map_err(db)?!="available"{
return Err(Error::Conflict)}
            let device:String=grant.try_get("device").map_err(db)?;
            a.target(&device);
            let start=now(c).await?;
let end=service.issuer.end(start)?;
            let identity=rss_mdm_certificate::agent::identity(Uuid::parse_str(&tenant).map_err(|_|Error::Configuration)?,&device).map_err(|_|Error::Configuration)?;
            let attempt=Uuid::new_v4();
            sqlx::query(r#"
INSERT INTO
mdm_access.agent_issuances(tenant_id,id,grant_id,operation_id,request_digest,csr,spki,identity,profile,not_before,not_after,state)
VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'signing')
"#)
                .bind(&tenant).bind(attempt).bind(input.grant_id).bind(input.operation_id).bind(&*digest).bind(&*csr).bind(&*spki).bind(&identity).bind(serde_json::to_value(&input.runtime).map_err(|_|Error::Malformed)?).bind(start).bind(end).execute(&mut *c).await.map_err(db)?;
            sqlx::query(r#"
UPDATE mdm_access.agent_grants SET state='consumed' WHERE tenant_id=$1::uuid AND id=$2
"#).bind(&tenant).bind(input.grant_id).execute(&mut *c).await.map_err(db)?;
            Ok(Change{
value:Claim::New(Signing{
attempt,grant:input.grant_id,csr:csr.clone(),identity,deadline:grant.try_get("expiry").map_err(db)?,start,end}
),replay:false,digest:digest.clone()}
)
        }) }).await?;
        let signing = match claim {
            Claim::Issued(c) => return Ok(c),
            Claim::Unknown(id) => return Err(unknown(id)),
            Claim::New(s) => s,
        };
        let attempt = signing.attempt;
        let intent = self.issuer.persisted_intent(signing)?;
        let issued = match self.issuer.issue(intent).await {
            Ok(v) => v.certificate,
            Err(_) => {
                // The signing row already fences retries. Best-effort diagnostic transition cannot authorize a retry.
                let _ = self.record_unknown(input, attempt, a).await;
                return Err(unknown(attempt));
            }
        };
        self.save_certificate(input.grant_id, attempt, &issued, input.operation_id, a)
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
    ) -> Result<wire::Candidate, Error> {
        a.operation(operation, "agent_certificate_result");
        let digest = hex(certificate.csr_digest);
        self.write(a, (self, grant, id, certificate, digest), |ctx, c| {
            Box::pin(async move {
                let (service, grant, id, certificate, digest) = ctx;
                let tenant = service.tenant.to_string();
                let g = grant_row(c, &tenant, *grant).await?;
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
                .fetch_one(c)
                .await
                .map_err(db)?;
                Ok(Change {
                    value: candidate(&g, &row)?,
                    replay,
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
            .validate_issued(
                chain,
                &verified,
                &i.try_get::<String, _>("identity").map_err(db)?,
                i.try_get("not_before").map_err(db)?,
                i.try_get("not_after").map_err(db)?,
                self.now()?,
            )
            .map_err(|_| Error::Forbidden)?;
        tx.commit().await.map_err(db)?;
        self.save_certificate(grant, id, &issued, input.operation_id, a)
            .await
            .map_err(Into::into)
    }
}
fn row_platform(row: &PgRow) -> Result<runtime::TaskPlatform, Error> {
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
