use super::*;
impl Service {
    /// Create only a machine CSR request. A live enterprise session authorizes it separately.
    pub async fn request(
        &self,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        version(input.wire_version, input.operation_id)?;
        let bound = hex(csr(&input.csr)?.spki());
        let d = digest(input)?;
        a.operation(input.operation_id, "agent_authorization_request");
        self.write(a,(self,input,bound,d),|ctx,c|Box::pin(async move {
            let (service,input,bound,d)=ctx;let tenant=service.tenant.to_string();
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2630))")
                .bind(format!("{tenant}:browser:{}",input.operation_id)).execute(&mut *c).await.map_err(db)?;
            if let Some(id)=sqlx::query_scalar::<_,Uuid>("SELECT id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='browser' AND operation_id=$2")
                .bind(&tenant).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)? {
                let row=grant_row(c,&tenant,id).await?;
                if row.try_get::<String,_>("request_digest").map_err(db)?!=*d{return Err(Error::Conflict);}
                check_secret(&tenant,&row,&input.secret)?;
                return Ok(Change{value:receipt(&row)?,replay:true,digest:d.clone()});
            }
            crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::Agent).await?;
            let values=settings::admit_on(c,&tenant,input.platform).await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2630))").bind(format!("{tenant}:pending")).execute(&mut *c).await.map_err(db)?;
            let pending:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND state='pending' AND expires_at>clock_timestamp()")
                .bind(&tenant).fetch_one(&mut *c).await.map_err(db)?;
            if pending>=1000{return Err(Error::Capacity);}
            let id=Uuid::new_v4();
            sqlx::query("INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,device,platform,secret_digest,request_digest,spki,state,created_at,expires_at) VALUES($1::uuid,$2,$3,'browser',$4,$5,$6,$7,$8,'pending',statement_timestamp(),statement_timestamp()+make_interval(secs=>$9))")
                .bind(&tenant).bind(id).bind(input.operation_id).bind(Uuid::new_v4().to_string()).bind(platform(input.platform))
                .bind(secret_digest(&tenant,id,&input.secret)).bind(&*d).bind(&*bound).bind(f64::from(values.grant_seconds)).execute(&mut *c).await.map_err(db)?;
            Ok(Change{value:receipt(&grant_row(c,&tenant,id).await?)?,replay:false,digest:d.clone()})
        })).await.map_err(Into::into)
    }
    pub async fn authorize(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        self.authorize_target(p, id, operation, None, a).await
    }
    pub async fn authorize_reenrollment(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
        device: &str,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        self.authorize_target(p, id, operation, Some(device), a)
            .await
    }
    async fn authorize_target(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
        device: Option<&str>,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        self.proof(p, a)?;
        version(wire::API_VERSION, operation)?;
        a.operation(operation, "agent_grant_authorize");
        self.write(a, (self, p, id, operation, device, a), |ctx, c| {
            Box::pin(async move {
                let (service, p, id, operation, device, a) = ctx;
                let tenant = service.tenant.to_string();
                let action = "authorize";
                let d = digest(&(action, *id, *operation, *device))?;
                let op = crate::operations::Operation {
                    actor: crate::operations::Actor::from_authorized(p),
                    key: *operation,
                    digest: &d,
                };
                if let Some(old) = crate::operations::replay(c, &op).await? {
                    return Ok(Change {
                        value: serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,
                        replay: true,
                        digest: d,
                    });
                }
                let row = grant_row(c, &tenant, *id).await?;
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
                    crate::admission::require_new_in(c, &tenant, crate::quotas::Channel::Agent)
                        .await?;
                    settings::admit_on(c, &tenant, row_platform(&row)?).await?;
                    crate::quotas::admit_on(
                        c,
                        &tenant,
                        p.instance_id(),
                        p.principal_id(),
                        crate::quotas::Channel::Agent,
                    )
                    .await?;
                    if let Some(device) = device {
                        crate::lifecycle::authorize_reenrollment_in(c, p, device).await?;
                        let retired: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2) AND NOT EXISTS(SELECT 1 FROM mdm_access.registrations WHERE tenant_id=$1::uuid AND device=$2 AND state='active')")
                            .bind(&tenant).bind(*device).fetch_one(&mut *c).await.map_err(db)?;
                        if !retired {return Err(Error::Conflict);}
                        sqlx::query("UPDATE mdm_access.agent_grants SET device=$3 WHERE tenant_id=$1::uuid AND id=$2 AND state='pending'")
                            .bind(&tenant).bind(*id).bind(*device).execute(&mut *c).await.map_err(db)?;
                    }
                    p.check_live()?;
                    sqlx::query(
                        r#"
UPDATE mdm_access.agent_grants SET actor=$3,instance=$4,state='available' WHERE
tenant_id=$1::uuid AND id=$2
"#,
                    )
                    .bind(&tenant)
                    .bind(*id)
                    .bind(p.principal_id())
                    .bind(p.instance_id())
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                }
                let current = grant_row(c, &tenant, *id).await?;
                if !replay {
                    crate::device::registration_user::initialize_on(c, &current.try_get::<String,_>("device").map_err(db)?, &p.user()?).await?;
                }
                let value = receipt(&current)?;
                crate::operations::save(
                    c,
                    &op,
                    &serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,
                    a,
                )
                .await?;
                Ok(Change {
                    value,
                    replay: false,
                    digest: d,
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
        self.proof(p, a)?;
        version(wire::API_VERSION, operation)?;
        a.operation(operation, "agent_grant_revoke");
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
                if let Some(old) = crate::operations::replay(c, &op).await? {
                    return Ok(Change {
                        value: serde_json::from_str(&old).map_err(|_| Error::Corrupt)?,
                        replay: true,
                        digest: d,
                    });
                }
                let row = grant_row(c, &tenant, *id).await?;
                if matches!(row.try_get::<String,_>("source").map_err(db)?.as_str(),"configuration"|"native"){return Err(Error::Forbidden);}
                owned(p, &row)?;
                sqlx::query(
                    r#"
UPDATE mdm_access.agent_grants SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2
"#,
                )
                .bind(&tenant)
                .bind(*id)
                .execute(&mut *c)
                .await
                .map_err(db)?;
                let attempts:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND grant_id=$2")
                    .bind(&tenant).bind(*id).fetch_all(&mut *c).await.map_err(db)?;
                for attempt in attempts {rss_mdm_pki_service::certificates::revoke_attempt_in(c,&tenant,attempt).await.map_err(|_|Error::Storage)?;}
                let value = receipt(&grant_row(c, &tenant, *id).await?)?;
                crate::operations::save(
                    c,
                    &op,
                    &serde_json::to_string(&value).map_err(|_| Error::Corrupt)?,
                    a,
                )
                .await?;
                Ok(Change {
                    value,
                    replay: false,
                    digest: d,
                })
            })
        })
        .await
        .map_err(Into::into)
    }
    pub async fn poll(&self, input: &wire::StatusRequest) -> Result<wire::Progress, Failure> {
        version(input.wire_version, input.operation_id)?;
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let row = grant_row(&mut tx, &tenant, input.grant_id).await?;
        check_secret(&tenant, &row, &input.secret)?;
        if row.try_get::<Uuid, _>("operation_id").map_err(db)? != input.operation_id {
            return Err(Error::Conflict.into());
        }
        let out = progress(&mut tx, &tenant, &row).await?;
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
        version(input.wire_version, input.operation_id)?;
        let tenant = self.tenant.to_string();
        let mut tx = self.store.begin(&tenant).await?;
        let row = sqlx::query(
            "SELECT *, floor(extract(epoch FROM expires_at))::bigint AS expiry, expires_at>clock_timestamp() AS live FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='renewal' AND operation_id=$2",
        )
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
        registration: Uuid,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        self.proof(p, a)?;
        version(input.wire_version, input.operation_id)?;
        let bound = hex(csr(&input.csr)?.spki());
        a.operation(input.operation_id, "agent_recovery_grant");
        let digest = digest(&(registration, input))?;
        self.write(
            a,
            (self, p, registration, input, a, bound, digest),
            |ctx, c| {
                Box::pin(async move {
                    let (service, p, registration, input, a, bound, digest) = ctx;
                    let tenant = service.tenant.to_string();
                    let row = sqlx::query(
                        r#"
SELECT r.device,r.state,k.id FROM mdm_access.registrations r JOIN mdm_access.credentials k
ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND
r.channel='agent' AND k.state='active' FOR UPDATE OF r,k
"#,
                    )
                    .bind(&tenant)
                    .bind(*registration)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    .ok_or(Error::Forbidden)?;
                    let device: String = row.try_get("device").map_err(db)?;
                    p.credentials(&device)?;
                    if row.try_get::<String, _>("state").map_err(db)? != "active" {
                        return Err(Error::Forbidden);
                    }
                    a.target(&device);
                    if let Some(id) = sqlx::query_scalar::<_, Uuid>(
                        r#"
SELECT id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='recovery' AND
operation_id=$2
"#,
                    )
                    .bind(&tenant)
                    .bind(input.operation_id)
                    .fetch_optional(&mut *c)
                    .await
                    .map_err(db)?
                    {
                        let old = grant_row(c, &tenant, id).await?;
                        owned(p, &old)?;
                        if old.try_get::<String, _>("request_digest").map_err(db)? != *digest {
                            return Err(Error::Conflict);
                        }
                        return Ok(Change {
                            value: receipt(&old)?,
                            replay: true,
                            digest: digest.clone(),
                        });
                    }
                    let seconds = settings::admit_on(c, &tenant, input.platform)
                        .await?
                        .grant_seconds;
                    let id = Uuid::new_v4();
                    sqlx::query(
                        r#"
INSERT INTO
mdm_access.agent_grants(tenant_id,
id,
operation_id,
source,
actor,
instance,
device,
platform,
secret_digest,
request_digest,
spki,
state,
created_at,
expires_at,
target_registration,
predecessor)
VALUES($1::uuid,
$2,
$3,
'recovery',
$4,
$5,
$6,
$7,
$8,
$9,
$10,
'available',
statement_timestamp(),
statement_timestamp()+make_interval(secs=>$11),
$12,
$13)
"#,
                    )
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
                    .bind(*registration)
                    .bind(row.try_get::<Uuid, _>("id").map_err(db)?)
                    .execute(&mut *c)
                    .await
                    .map_err(db)?;
                    Ok(Change {
                        value: receipt(&grant_row(c, &tenant, id).await?)?,
                        replay: false,
                        digest: digest.clone(),
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
    c: &mut PgConnection,
    tenant: &str,
    row: &PgRow,
) -> Result<wire::Progress, Error> {
    let issuance = sqlx::query(
        r#"
SELECT id,state,activation_result FROM mdm_access.agent_issuances WHERE tenant_id=$1::uuid AND
grant_id=$2
"#,
    )
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
                .map(serde_json::from_value)
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
        version(input.wire_version, input.operation_id)?;
        let principal = self.authenticate(peer).await?;
        let bound = hex(csr(&input.csr)?.spki());
        let d = digest(&(principal.registration(), principal.credential(), input))?;
        a.identify_device(principal.registration());
        a.target(principal.device());
        a.operation(input.operation_id, "agent_renewal_grant");
        self.write(a, (self, principal, input, bound, d), |ctx, c| {
            Box::pin(async move {
                let (service, p, input, bound, d) = ctx;
                let tenant = service.tenant.to_string();
                crate::device::store::revalidate_source(
                    c,
                    p,
                    rss_mdm_inventory::ReportSource::AgentBuiltin,
                )
                .await?;
                let row = sqlx::query(
                    r#"
SELECT g.actor,g.instance,g.platform FROM mdm_access.registrations r JOIN
mdm_access.agent_grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.agent_grant_id) WHERE
r.tenant_id=$1::uuid AND r.id=$2
"#,
                )
                .bind(&tenant)
                .bind(p.registration())
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
                if row.try_get::<String, _>("platform").map_err(db)? != platform(input.platform) {
                    return Err(Error::Forbidden);
                }
                if let Some(id) = sqlx::query_scalar::<_, Uuid>(
                    r#"
SELECT id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='renewal' AND
operation_id=$2
"#,
                )
                .bind(&tenant)
                .bind(input.operation_id)
                .fetch_optional(&mut *c)
                .await
                .map_err(db)?
                {
                    let g = grant_row(c, &tenant, id).await?;
                    if g.try_get::<String, _>("request_digest").map_err(db)? != *d {
                        return Err(Error::Conflict);
                    }
                    check_secret(&tenant, &g, &input.secret)?;
                    return Ok(Change {
                        value: receipt(&g)?,
                        replay: true,
                        digest: d.clone(),
                    });
                }
                let seconds = settings::admit_on(c, &tenant, input.platform)
                    .await?
                    .grant_seconds;
                let id = Uuid::new_v4();
                sqlx::query(
                    r#"
INSERT INTO
mdm_access.agent_grants(tenant_id,
id,
operation_id,
source,
actor,
instance,
device,
platform,
secret_digest,
request_digest,
spki,
state,
created_at,
expires_at,
target_registration,
predecessor)
VALUES($1::uuid,
$2,
$3,
'renewal',
$4,
$5,
$6,
$7,
$8,
$9,
$10,
'available',
statement_timestamp(),
statement_timestamp()+make_interval(secs=>$11),
$12,
$13)
"#,
                )
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
                .bind(p.registration())
                .bind(p.credential())
                .execute(&mut *c)
                .await
                .map_err(db)?;
                Ok(Change {
                    value: receipt(&grant_row(c, &tenant, id).await?)?,
                    replay: false,
                    digest: d.clone(),
                })
            })
        })
        .await
        .map_err(Into::into)
    }
}
