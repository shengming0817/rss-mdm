use super::*;
use rss_mdm_device_trust::device_identity::IssuedDeviceCertificate;
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
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CertificateInput {
    pub wire_version: u8,
    pub operation_id: Uuid,
    pub grant_id: Uuid,
    pub secret: runtime::Secret,
    pub csr: String,
    pub runtime: Option<wire::RuntimeProfile>,
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
        if self.issuer.purpose() != rss_mdm_agent_wire::pki::Purpose::Agent {
            return Err(Error::Forbidden.into());
        }
        self.issue_request(
            &CertificateInput {
                wire_version: input.wire_version,
                operation_id: input.operation_id,
                grant_id: input.grant_id,
                secret: input.secret.clone(),
                csr: input.csr.clone(),
                runtime: Some(input.runtime.clone()),
            },
            a,
        )
        .await
    }
    pub(super) async fn issue_request(
        &self,
        input: &CertificateInput,
        a: &RequestAudit,
    ) -> Result<wire::Candidate, Failure> {
        let profile = self.profile();

        version(input.wire_version, input.operation_id)?;
        match (&input.runtime, self.issuer.purpose()) {
            (Some(runtime), rss_mdm_agent_wire::pki::Purpose::Agent) => {
                runtime.validate().map_err(|_| Error::Malformed)?
            }
            (None, rss_mdm_agent_wire::pki::Purpose::DaDevice) => {}
            _ => return Err(Error::Forbidden.into()),
        }
        if input.csr.len() > 43692 {
            return Err(Error::Malformed.into());
        }
        let verified = VerifiedDeviceCsr::verify(
            &STANDARD.decode(&input.csr).map_err(|_| Error::Malformed)?,
            self.issuer.purpose(),
        )
        .map_err(|_| Error::Malformed)?;
        let request_digest = digest(input)?;
        let spki = hex(verified.spki());
        let csr = STANDARD.decode(&input.csr).map_err(|_| Error::Malformed)?;
        // Authorization and candidate writes are phases; the HTTP result still needs settlement.
        a.require_final_request();
        a.operation(
            input.operation_id,
            "device_certificate_authorize",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let claim = self
            .write(a, (self, input, a, request_digest, spki, csr), |ctx, c| {
                Box::pin(async move {
                    let (service, input, a, digest, spki, csr) = ctx;
                    let tenant = service.tenant.to_string();
                    configurations::lock_for_grant(profile, c, &tenant, input.grant_id).await?;
                    let grant = grant_row(profile, c, &tenant, input.grant_id).await?;
                    check_secret(&tenant, &grant, &input.secret)?;
                    a.target(&grant.try_get::<String, _>("device").map_err(db)?);
                    if let Some(row) =
                        sqlx::query(crate::storage_profile::sql(profile).agent_issuance_issue_1)
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
                        });
                    }
                    service.grant_live(c, &grant).await?;
                    if service.issuer.purpose() == rss_mdm_agent_wire::pki::Purpose::Agent
                        && grant
                            .try_get::<Option<Uuid>, _>("target_registration")
                            .map_err(db)?
                            .is_none()
                    {
                        crate::admission::require_new_in(
                            profile,
                            c,
                            &tenant,
                            crate::quotas::Channel::Agent,
                        )
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
                    if input
                        .runtime
                        .as_ref()
                        .is_some_and(|r| row_platform(&grant).ok() != Some(r.platform))
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
                    let identity = rss_mdm_certificate::device_identity::identity(
                        service.issuer.purpose(),
                        service.service_id()?,
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
                    sqlx::query(crate::storage_profile::sql(profile).agent_issuance_issue_2)
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
                    sqlx::query(crate::storage_profile::sql(profile).agent_issuance_issue_3)
                        .bind(&tenant)
                        .bind(input.grant_id)
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                    Ok(Change {
                        value: Claim::New(signing),
                        replay: false,
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
                &rss_mdm_pki_service::signing::SigningStore::new(profile, self.audit.clone()),
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
        input: &CertificateInput,
        id: Uuid,
        a: &RequestAudit,
    ) -> Result<(), Error> {
        let profile = self.profile();

        a.operation(
            input.operation_id,
            "device_certificate_unknown",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(a, (self, id), |ctx, c| {
            Box::pin(async move {
                let (service, id) = ctx;
                let n = sqlx::query(
                    crate::storage_profile::sql(profile).agent_issuance_record_unknown_1,
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
                })
            })
        })
        .await
    }
    async fn save_certificate(
        &self,
        grant: Uuid,
        id: Uuid,
        certificate: &IssuedDeviceCertificate,
        operation: Uuid,
        a: &RequestAudit,
        principal: Option<&AuthorizedPrincipal>,
    ) -> Result<wire::Candidate, Error> {
        let profile = self.profile();

        a.operation(
            operation,
            "device_certificate_result",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let digest = if principal.is_some() {
            digest(&("certificate_issuance_recovery", id, &certificate.chain))?
        } else {
            hex(certificate.csr_digest)
        };
        self.write(
            a,
            (
                self,
                grant,
                id,
                certificate,
                digest,
                principal,
                operation,
                a,
            ),
            |ctx, c| {
                Box::pin(async move {
                    let (service, grant, id, certificate, digest, principal, operation, a) = ctx;
                    let tenant = service.tenant.to_string();
                    if let Some(p) = principal {
                        p.check_live()?;
                        rss_mdm_authorization_service::lock_on(
                            p.authority_profile(),
                            c,
                            &tenant,
                            p.instance_id(),
                        )
                        .await?;
                    }
                    // A reused certificate is not a replay of a new administrator operation.
                    let receipt = principal.map(|p| crate::operations::Operation {
                        actor: crate::operations::Actor::from_authorized(p),
                        key: *operation,
                        digest,
                    });
                    let previous = if let Some(op) = &receipt {
                        crate::operations::replay(profile, c, op).await?
                    } else {
                        None
                    };
                    let g = grant_row(profile, c, &tenant, *grant).await?;
                    if let Some(p) = principal {
                        rss_mdm_authorization_service::snapshot_on(
                            p.authority_profile(),
                            c,
                            &tenant,
                            p.instance_id(),
                        )
                        .await?
                        .require(
                            p,
                            rss_mdm_authorization_service::Permission::Credentials,
                            Some(&g.try_get::<String, _>("device").map_err(db)?),
                        )
                        .map_err(|_| Error::Forbidden)?;
                    }
                    a.target(&g.try_get::<String, _>("device").map_err(db)?);
                    let old = sqlx::query(
                        crate::storage_profile::sql(profile).agent_issuance_save_certificate_1,
                    )
                    .bind(&tenant)
                    .bind(*id)
                    .bind(*grant)
                    .fetch_one(&mut *c)
                    .await
                    .map_err(db)?;
                    if let Some(previous) = previous {
                        if serde_json::from_str::<Uuid>(&previous).map_err(|_| Error::Corrupt)?
                            != *id
                        {
                            return Err(Error::Corrupt);
                        }
                        return Ok(Change {
                            value: candidate(&g, &old)?,
                            replay: true,
                        });
                    }
                    if old.try_get::<String, _>("signing_issuer").map_err(db)?
                        != hex(certificate.metadata.issuer)
                    {
                        return Err(Error::Forbidden);
                    }
                    if let Some(binding) = sqlx::query_scalar::<_, Vec<u8>>(
                        crate::storage_profile::sql(profile).agent_issuance_save_certificate_4,
                    )
                    .bind(&tenant)
                    .bind(*id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    {
                        rss_mdm_pki_service::recovery::adopt_in(
                            profile,
                            c,
                            &tenant,
                            *id,
                            &binding,
                            &serde_json::to_vec(&certificate.chain).map_err(|_| Error::Corrupt)?,
                        )
                        .await
                        .map_err(|_| Error::Conflict)?;
                    }
                    rss_mdm_pki_service::certificates::record_candidate_in(
                        profile,
                        c,
                        &tenant,
                        rss_mdm_pki_service::registry::purpose(service.issuer.purpose()),
                        g.try_get::<Option<Uuid>, _>("target_registration")
                            .map_err(db)?,
                        &hex(certificate.metadata.issuer),
                        certificate.chain.first().ok_or(Error::Corrupt)?,
                    )
                    .await
                    .map_err(|_| Error::Storage)?;
                    if g.try_get::<String, _>("state").map_err(db)? == "revoked" {
                        rss_mdm_pki_service::certificates::enqueue_in(
                            profile,
                            c,
                            &tenant,
                            rss_mdm_pki_service::registry::purpose(service.issuer.purpose()),
                            &hex(certificate.metadata.issuer),
                            &rss_mdm_device_trust::serial(&certificate.metadata.serial),
                        )
                        .await
                        .map_err(|_| Error::Storage)?;
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
                            crate::storage_profile::sql(profile).agent_issuance_save_certificate_2,
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
                        .bind(
                            serde_json::to_value(&certificate.metadata)
                                .map_err(|_| Error::Corrupt)?,
                        )
                        .bind(hex(certificate.metadata.fingerprint))
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                    }
                    let row = sqlx::query(
                        crate::storage_profile::sql(profile).agent_issuance_save_certificate_3,
                    )
                    .bind(&tenant)
                    .bind(*id)
                    .fetch_one(&mut *c)
                    .await
                    .map_err(db)?;
                    let value = candidate(&g, &row)?;
                    if let Some(op) = &receipt {
                        // The immutable issuance owns the chain; the bounded receipt stores its identity only.
                        crate::operations::save_issuance_recovery(profile, c, op, *id, a).await?;
                    }
                    Ok(Change {
                        value,
                        replay: receipt.is_none() && replay,
                    })
                })
            },
        )
        .await
    }
    pub async fn recover_issuance(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        input: &wire::RecoverIssuance,
        a: &RequestAudit,
    ) -> Result<wire::Candidate, Failure> {
        let profile = self.profile();

        self.proof(p, a)?;
        version(input.wire_version, input.operation_id)?;
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let i = sqlx::query(crate::storage_profile::sql(profile).agent_issuance_recover_issuance_1)
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
        let g = grant_row(profile, &mut tx, &tenant, grant).await?;
        p.credentials(&g.try_get::<String, _>("device").map_err(db)?)?;
        let verified = VerifiedDeviceCsr::verify(
            &i.try_get::<Vec<u8>, _>("csr").map_err(db)?,
            self.issuer.purpose(),
        )
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
pub(super) fn candidate(grant: &PgRow, row: &PgRow) -> Result<wire::Candidate, Error> {
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
