use super::*;
impl Service {
    /// Create only a machine CSR request. A live enterprise session authorizes it separately.
    pub async fn request(
        &self,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        let profile = self.profile();

        version(input.wire_version, input.operation_id)?;
        let bound = hex(csr(&input.csr)?.spki());
        let d = digest(input)?;
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            input.operation_id,
            "agent_authorization_request",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(a, (self, input, bound, d), |ctx, c| {
            Box::pin(async move {
                let (service, input, bound, d) = ctx;
                let tenant = service.tenant.to_string();
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2630))")
                    .bind(format!("{tenant}:browser:{}", input.operation_id))
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                if let Some(id) = sqlx::query_scalar::<_, Uuid>(
                    crate::storage_profile::sql(profile).certificate_grants_request_1,
                )
                .bind(&tenant)
                .bind(input.operation_id)
                .fetch_optional(&mut *c)
                .await
                .map_err(db)?
                {
                    let row = grant_row(profile, c, &tenant, id).await?;
                    if row.try_get::<String, _>("request_digest").map_err(db)? != *d {
                        return Err(Error::Conflict);
                    }
                    check_secret(&tenant, &row, &input.secret)?;
                    return Ok(Change {
                        value: receipt(&row)?,
                        replay: true,
                    });
                }
                crate::admission::require_new_in(
                    profile,
                    c,
                    &tenant,
                    crate::quotas::Channel::Agent,
                )
                .await?;
                let values = settings::admit_on(profile, c, &tenant, input.platform).await?;
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2630))")
                    .bind(format!("{tenant}:pending"))
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                let pending: i64 = sqlx::query_scalar(
                    crate::storage_profile::sql(profile).certificate_grants_request_2,
                )
                .bind(&tenant)
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
                if pending >= 1000 {
                    return Err(Error::Capacity);
                }
                let id = Uuid::new_v4();
                sqlx::query(crate::storage_profile::sql(profile).certificate_grants_request_3)
                    .bind(&tenant)
                    .bind(id)
                    .bind(input.operation_id)
                    .bind(Uuid::new_v4().to_string())
                    .bind(platform(input.platform))
                    .bind(secret_digest(&tenant, id, &input.secret))
                    .bind(&*d)
                    .bind(&*bound)
                    .bind(f64::from(values.grant_seconds))
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                Ok(Change {
                    value: receipt(&grant_row(profile, c, &tenant, id).await?)?,
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    pub async fn authorize(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        let profile = self.profile();

        self.proof(p, a)?;
        version(wire::API_VERSION, operation)?;
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            operation,
            "agent_grant_authorize",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(a, (self, p, id, operation, a), |ctx, c| {
            Box::pin(async move {
                let (service, p, id, operation, a) = ctx;
                let tenant = service.tenant.to_string();
                let action = "authorize";
                let d = digest(&(action, *id, *operation))?;
                let op = crate::operations::Operation {
                    actor: crate::operations::Actor::from_authorized(p),
                    key: *operation,
                    digest: &d,
                };
                if let Some(old) = crate::operations::replay(profile, c, &op).await? {
                    return Ok(Change {
                        value: serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,
                        replay: true,
                    });
                }
                let row = grant_row(profile, c, &tenant, *id).await?;
                if row.try_get::<String, _>("source").map_err(db)? != "browser" {
                    return Err(Error::Forbidden);
                }
                let replay = row.try_get::<String, _>("state").map_err(db)? != "pending";
                if replay {
                    if row
                        .try_get::<Option<String>, _>("actor")
                        .map_err(db)?
                        .as_deref()
                        != Some(p.principal_id())
                        || row
                            .try_get::<Option<String>, _>("instance")
                            .map_err(db)?
                            .as_deref()
                            != Some(p.instance_id())
                    {
                        return Err(Error::Forbidden);
                    }
                } else {
                    if row.try_get::<i64, _>("expiry").map_err(db)? <= now(c).await? {
                        return Err(Error::Agent(wire::ErrorCode::GrantExpired));
                    }
                    crate::admission::require_new_in(
                        profile,
                        c,
                        &tenant,
                        crate::quotas::Channel::Agent,
                    )
                    .await?;
                    settings::admit_on(profile, c, &tenant, row_platform(&row)?).await?;
                    crate::quotas::admit_on(
                        profile,
                        c,
                        &tenant,
                        p.instance_id(),
                        p.principal_id(),
                        crate::quotas::Channel::Agent,
                    )
                    .await?;
                    p.check_live()?;
                    sqlx::query(
                        crate::storage_profile::sql(profile).certificate_grants_authorize_target_3,
                    )
                    .bind(&tenant)
                    .bind(*id)
                    .bind(p.principal_id())
                    .bind(p.instance_id())
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                }
                let current = grant_row(profile, c, &tenant, *id).await?;
                if !replay {
                    crate::device::registration_user::initialize_on(
                        profile,
                        c,
                        &current.try_get::<String, _>("device").map_err(db)?,
                        &p.user()?,
                    )
                    .await?;
                }
                let value = receipt(&current)?;
                crate::operations::save(
                    profile,
                    c,
                    &op,
                    &serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,
                    a,
                    false,
                )
                .await?;
                Ok(Change {
                    value,
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    pub async fn revoke(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        let profile = self.profile();

        self.proof(p, a)?;
        version(wire::API_VERSION, operation)?;
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            operation,
            "agent_grant_revoke",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(a, (self, p, id, operation, a), |ctx, c| {
            Box::pin(async move {
                let (service, p, id, operation, a) = ctx;
                let tenant = service.tenant.to_string();
                let action = "revoke";
                let d = digest(&(action, *id, *operation))?;
                let op = crate::operations::Operation {
                    actor: crate::operations::Actor::from_authorized(p),
                    key: *operation,
                    digest: &d,
                };
                if let Some(old) = crate::operations::replay(profile, c, &op).await? {
                    return Ok(Change {
                        value: serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,
                        replay: true,
                    });
                }
                let row = grant_row(profile, c, &tenant, *id).await?;
                if matches!(
                    row.try_get::<String, _>("source").map_err(db)?.as_str(),
                    "configuration" | "native"
                ) {
                    return Err(Error::Forbidden);
                }
                owned(p, &row)?;
                sqlx::query(crate::storage_profile::sql(profile).certificate_grants_revoke_2)
                    .bind(&tenant)
                    .bind(*id)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                let attempts: Vec<Uuid> = sqlx::query_scalar(
                    crate::storage_profile::sql(profile).certificate_grants_revoke_1,
                )
                .bind(&tenant)
                .bind(*id)
                .fetch_all(&mut *c)
                .await
                .map_err(db)?;
                for attempt in attempts {
                    rss_mdm_pki_service::certificates::revoke_attempt_in(
                        profile, c, &tenant, attempt,
                    )
                    .await
                    .map_err(|_| Error::Storage)?;
                }
                let value = receipt(&grant_row(profile, c, &tenant, *id).await?)?;
                crate::operations::save(
                    profile,
                    c,
                    &op,
                    &serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,
                    a,
                    false,
                )
                .await?;
                Ok(Change {
                    value,
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    pub async fn poll(&self, input: &wire::StatusRequest) -> Result<wire::Progress, Failure> {
        let profile = self.profile();

        version(input.wire_version, input.operation_id)?;
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let row = grant_row(profile, &mut tx, &tenant, input.grant_id).await?;
        check_secret(&tenant, &row, &input.secret)?;
        if row.try_get::<Uuid, _>("operation_id").map_err(db)? != input.operation_id {
            return Err(Error::Conflict.into());
        }
        let out = progress(profile, &mut tx, &tenant, &row).await?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }
    /// Read an existing renewal grant without requiring its predecessor credential.
    /// Missing operations and incorrect secrets share the same rejection; this cannot
    /// create or extend authorization, and subsequent issuance/activation retain their checks.
    pub async fn renewal_status(
        &self,
        input: &wire::RenewalStatusRequest,
    ) -> Result<wire::GrantReceipt, Failure> {
        let profile = self.profile();

        version(input.wire_version, input.operation_id)?;
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let row =
            sqlx::query(crate::storage_profile::sql(profile).certificate_grants_renewal_status_1)
                .bind(&tenant)
                .bind(input.operation_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(Error::Unauthorized)?;
        check_secret(&tenant, &row, &input.secret)?;
        let out = receipt(&row)?;
        tx.commit().await.map_err(db)?;
        Ok(out)
    }
    pub async fn recovery(
        &self,
        p: &AuthorizedPrincipal,
        device_id: &str,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        let profile = self.profile();

        self.proof(p, a)?;
        version(input.wire_version, input.operation_id)?;
        let bound = hex(csr(&input.csr)?.spki());
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::RegistrationRecovery,
            input.operation_id,
            "agent_recovery_grant",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let digest = digest(&(device_id, input))?;
        self.write(
            a,
            (self, p, device_id, input, a, bound, digest),
            |ctx, c| {
                Box::pin(async move {
                    let (service, p, device_id, input, a, bound, digest) = ctx;
                    let tenant = service.tenant.to_string();
                    let row = sqlx::query(
                        crate::storage_profile::sql(profile).certificate_grants_recovery_1,
                    )
                    .bind(&tenant)
                    .bind(*device_id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    .ok_or(Error::Forbidden)?;
                    let device: String = row.try_get("device").map_err(db)?;
                    p.credentials(&device)?;
                    if row.try_get::<String, _>("state").map_err(db)? != "active" {
                        return Err(Error::Forbidden);
                    }
                    a.target_device(&device);
                    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
                        crate::storage_profile::sql(profile).certificate_grants_recovery_2,
                    )
                    .bind(&tenant)
                    .bind(input.operation_id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    {
                        let old = grant_row(profile, c, &tenant, id).await?;
                        owned(p, &old)?;
                        if old.try_get::<String, _>("request_digest").map_err(db)? != *digest {
                            return Err(Error::Conflict);
                        }
                        return Ok(Change {
                            value: receipt(&old)?,
                            replay: true,
                        });
                    }
                    let seconds = settings::admit_on(profile, c, &tenant, input.platform)
                        .await?
                        .grant_seconds;
                    let id = Uuid::new_v4();
                    sqlx::query(crate::storage_profile::sql(profile).certificate_grants_recovery_3)
                        .bind(&tenant)
                        .bind(id)
                        .bind(input.operation_id)
                        .bind(p.principal_id())
                        .bind(p.instance_id())
                        .bind(&device)
                        .bind(platform(input.platform))
                        .bind(secret_digest(&tenant, id, &input.secret))
                        .bind(&*digest)
                        .bind(&*bound)
                        .bind(f64::from(seconds))
                        .bind(row.try_get::<Uuid, _>("id").map_err(db)?)
                        .execute(&mut *c)
                        .await
                        .map_err(db)?;
                    Ok(Change {
                        value: receipt(&grant_row(profile, c, &tenant, id).await?)?,
                        replay: false,
                    })
                })
            },
        )
        .await
        .map_err(Into::into)
    }
}
fn owned(p: &AuthorizedPrincipal, row: &PgRow) -> Result<(), Error> {
    if row
        .try_get::<Option<String>, _>("actor")
        .map_err(db)?
        .as_deref()
        == Some(p.principal_id())
        && row
            .try_get::<Option<String>, _>("instance")
            .map_err(db)?
            .as_deref()
            == Some(p.instance_id())
    {
        p.check_live().map_err(Into::into)
    } else {
        p.credentials(&row.try_get::<String, _>("device").map_err(db)?)
            .map_err(Into::into)
    }
}
async fn progress(
    profile: rss_mdm_install_support::StorageProfile,
    c: &mut PgConnection,
    tenant: &str,
    row: &PgRow,
) -> Result<wire::Progress, Error> {
    let issuance = sqlx::query(crate::storage_profile::sql(profile).certificate_grants_progress_1)
        .bind(tenant)
        .bind(row.try_get::<Uuid, _>("id").map_err(db)?)
        .fetch_optional(c)
        .await
        .map_err(db)?;
    let (id, unknown, activation) = match issuance {
        Some(i) => (
            Some(i.try_get("id").map_err(db)?),
            i.try_get::<String, _>("state").map_err(db)? != "issued",
            i.try_get::<Option<serde_json::Value>, _>("activation_result")
                .map_err(db)?
                .map(|v| {
                    serde_json::from_value::<ActivationResult>(v)
                        .map_err(|_| Error::Corrupt)?
                        .agent()
                })
                .transpose()
                .map_err(|_| Error::Corrupt)?,
        ),
        None => (None, false, None),
    };
    Ok(wire::Progress {
        grant: receipt(row)?,
        issuance_id: id,
        issuance_unknown: unknown,
        activation,
    })
}
impl Service {
    /// A manual renewal requires the still-current mTLS credential;
    /// Expired peers use administrator recovery.
    pub async fn renew(
        &self,
        peer: &rss_mdm_certificate::ClientCertificateEvidence,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        let profile = self.profile();

        version(input.wire_version, input.operation_id)?;
        let principal = self.authenticate(peer).await?;
        let bound = hex(csr(&input.csr)?.spki());
        let d = digest(&(principal.device(), principal.credential(), input))?;
        a.identify_device(&(principal.device()).to_string());
        a.target(principal.device());
        a.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            input.operation_id,
            "agent_renewal_grant",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        self.write(a, (self, principal, input, bound, d), |ctx, c| {
            Box::pin(async move {
                let (service, p, input, bound, d) = ctx;
                let tenant = service.tenant.to_string();
                crate::device::store::revalidate_source(
                    profile,
                    c,
                    p,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await?;
                let row =
                    sqlx::query(crate::storage_profile::sql(profile).certificate_grants_renew_1)
                        .bind(&tenant)
                        .bind(p.device())
                        .fetch_one(&mut *c)
                        .await
                        .map_err(db)?;
                if row.try_get::<String, _>("platform").map_err(db)? != platform(input.platform) {
                    return Err(Error::Forbidden);
                }
                if let Some(id) = sqlx::query_scalar::<_, Uuid>(
                    crate::storage_profile::sql(profile).certificate_grants_renew_2,
                )
                .bind(&tenant)
                .bind(input.operation_id)
                .fetch_optional(&mut *c)
                .await
                .map_err(db)?
                {
                    let g = grant_row(profile, c, &tenant, id).await?;
                    if g.try_get::<String, _>("request_digest").map_err(db)? != *d {
                        return Err(Error::Conflict);
                    }
                    check_secret(&tenant, &g, &input.secret)?;
                    return Ok(Change {
                        value: receipt(&g)?,
                        replay: true,
                    });
                }
                let seconds = settings::admit_on(profile, c, &tenant, input.platform)
                    .await?
                    .grant_seconds;
                let id = Uuid::new_v4();
                sqlx::query(crate::storage_profile::sql(profile).certificate_grants_renew_3)
                    .bind(&tenant)
                    .bind(id)
                    .bind(input.operation_id)
                    .bind(row.try_get::<String, _>("actor").map_err(db)?)
                    .bind(row.try_get::<String, _>("instance").map_err(db)?)
                    .bind(p.device())
                    .bind(platform(input.platform))
                    .bind(secret_digest(&tenant, id, &input.secret))
                    .bind(&*d)
                    .bind(&*bound)
                    .bind(f64::from(seconds))
                    .bind(p.credential())
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                Ok(Change {
                    value: receipt(&grant_row(profile, c, &tenant, id).await?)?,
                    replay: false,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
}
