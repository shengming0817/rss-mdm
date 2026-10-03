use super::*;
impl Service {
    pub async fn create(
        &self,
        p: &AuthorizedPrincipal,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        self.proof(p, a)?;
        self.create_inner(Some(p), input, a, false).await
    }
    pub async fn request(
        &self,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        self.create_inner(None, input, a, true).await
    }
    async fn create_inner(
        &self,
        p: Option<&AuthorizedPrincipal>,
        input: &wire::GrantRequest,
        a: &RequestAudit,
        pending: bool,
    ) -> Result<wire::GrantReceipt, Failure> {
        version(input.wire_version, input.operation_id)?;
        if !self.policy.platforms.contains(&input.platform) || (pending && input.csr.is_none()) {
            return Err(Error::Forbidden.into());
        }
        let bound = input
            .csr
            .as_deref()
            .map(csr)
            .transpose()?
            .map(|c| hex(c.spki()));
        let seconds = input.lifetime_seconds.unwrap_or(self.policy.grant_seconds);
        if seconds == 0 || seconds > self.policy.grant_seconds {
            return Err(Error::Malformed.into());
        }
        let source = if pending { "browser" } else { "download" };
        let digest = digest(input)?;
        a.operation(
            input.operation_id,
            if pending {
                "agent_authorization_request"
            } else {
                "agent_grant_create"
            },
        );
        self.write(a,(self,p,input,a,source,digest,bound,seconds),|ctx,c| { Box::pin(async move {
            let (service,p,input,_a,source,digest,bound,seconds)=ctx;
let tenant=service.tenant.to_string();
            sqlx::query(r#"
SELECT pg_advisory_xact_lock(hashtextextended($1,2630))
"#).bind(format!("{tenant}:{source}:{}",input.operation_id)).execute(&mut *c).await.map_err(db)?;
            if let Some(id)=sqlx::query_scalar::<_,Uuid>(r#"
SELECT id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source=$2 AND
operation_id=$3
"#).bind(&tenant).bind(*source).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)? {
                let row=grant_row(c,&tenant,id).await?;
                if row.try_get::<String,_>("request_digest").map_err(db)?!=*digest || p.is_some_and(|p|row.get::<Option<String>,_>("actor").as_deref()!=Some(p.principal_id()) || row.get::<Option<String>,_>("instance").as_deref()!=Some(p.instance_id())){
return Err(Error::Conflict)}
                check_secret(&tenant,&row,&input.secret)?;
                return Ok(Change{
value:receipt(&row)?,replay:true,digest:digest.clone()}
)
            }
            if let Some(p)=p {
 quota(c,&tenant,p.principal_id(),p.instance_id(),service.policy.user_device_limit).await?;
p.check_live()?;
 }
            // Anonymous pending requests are bounded per tenant independently of device quota.
            if p.is_none() {
                sqlx::query(r#"
SELECT pg_advisory_xact_lock(hashtextextended($1,2630))
"#).bind(format!("{tenant}:pending")).execute(&mut *c).await.map_err(db)?;
                let count:i64=sqlx::query_scalar(r#"
SELECT count(*) FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND state='pending' AND
expires_at>clock_timestamp()
"#).bind(&tenant).fetch_one(&mut *c).await.map_err(db)?;
                if count>=1000{
return Err(Error::Capacity)}
            }
            let id=Uuid::new_v4();
let device=Uuid::new_v4().to_string();
            sqlx::query(r#"
INSERT INTO
mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,expires_at)
VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp()+make_interval(secs=>$13))
"#)
                .bind(&tenant).bind(id).bind(input.operation_id).bind(*source).bind(p.map(|p|p.principal_id())).bind(p.map(|p|p.instance_id())).bind(device).bind(platform(input.platform)).bind(secret_digest(&tenant,id,&input.secret)).bind(&*digest).bind(&*bound).bind(if p.is_some(){
"available"}
else{
"pending"}
).bind(*seconds as f64).execute(&mut *c).await.map_err(db)?;
            Ok(Change{
value:receipt(&grant_row(c,&tenant,id).await?)?,replay:false,digest:digest.clone()}
)
        }) }).await.map_err(Into::into)
    }
    pub async fn approve(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
        operation: Uuid,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        self.proof(p, a)?;
        version(wire::API_VERSION, operation)?;
        a.operation(operation, "agent_grant_approve");
        self.write(a, (self, p, id, operation, a), |ctx, c| {
            Box::pin(async move {
                let (service, p, id, operation, a) = ctx;
                let tenant = service.tenant.to_string();
                let action = if a.snapshot().action == "agent_grant_approve" {
                    "approve"
                } else {
                    "revoke"
                };
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
                    if !row.try_get::<bool, _>("live").map_err(db)?
                        || !service
                            .policy
                            .platforms
                            .iter()
                            .any(|v| platform(*v) == row.get::<String, _>("platform"))
                    {
                        return Err(Error::Forbidden);
                    }
                    quota(
                        c,
                        &tenant,
                        p.principal_id(),
                        p.instance_id(),
                        service.policy.user_device_limit,
                    )
                    .await?;
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
                let action = if a.snapshot().action == "agent_grant_approve" {
                    "approve"
                } else {
                    "revoke"
                };
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
    pub async fn status(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<wire::Progress, Failure> {
        p.check_live()?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        let row = grant_row(&mut tx, p.tenant_id(), id).await?;
        owned(p, &row)?;
        let out = progress(&mut tx, p.tenant_id(), &row).await?;
        tx.commit().await.map_err(db)?;
        Ok(out)
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
    pub async fn recovery(
        &self,
        p: &AuthorizedPrincipal,
        registration: Uuid,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        self.proof(p, a)?;
        version(input.wire_version, input.operation_id)?;
        let bound = input
            .csr
            .as_deref()
            .map(csr)
            .transpose()?
            .map(|c| hex(c.spki()));
        let seconds = input.lifetime_seconds.unwrap_or(self.policy.grant_seconds);
        if seconds == 0 || seconds > self.policy.grant_seconds {
            return Err(Error::Malformed.into());
        }
        a.operation(input.operation_id, "agent_recovery_grant");
        let digest = digest(&(registration, input))?;
        self.write(a,(self,p,registration,input,a,bound,seconds,digest),|ctx,c| { Box::pin(async move {
            let (service,p,registration,input,a,bound,seconds,digest)=ctx;
let tenant=service.tenant.to_string();
            let row=sqlx::query(r#"
SELECT r.device,r.state,k.id FROM mdm_access.registrations r JOIN mdm_access.credentials k
ON(k.tenant_id,k.registration)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND
r.channel='agent' AND k.state='active' FOR UPDATE OF r,k
"#).bind(&tenant).bind(*registration).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Forbidden)?;
            let device:String=row.try_get("device").map_err(db)?;
p.credentials(&device)?;
            if row.try_get::<String,_>("state").map_err(db)?!="active"{
return Err(Error::Forbidden)}
            a.target(&device);
            if let Some(id)=sqlx::query_scalar::<_,Uuid>(r#"
SELECT id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='recovery' AND
operation_id=$2
"#).bind(&tenant).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)?{
                let old=grant_row(c,&tenant,id).await?;
owned(p,&old)?;
                if old.try_get::<String,_>("request_digest").map_err(db)?!=*digest{
return Err(Error::Conflict)}
                return Ok(Change{
value:receipt(&old)?,replay:true,digest:digest.clone()}
)
            }
            let id=Uuid::new_v4();
            sqlx::query(r#"
INSERT INTO
mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,expires_at,target_registration,predecessor)
VALUES($1::uuid,$2,$3,'recovery',$4,$5,$6,$7,$8,$9,$10,'available',clock_timestamp()+make_interval(secs=>$11),$12,$13)
"#)
                .bind(&tenant).bind(id).bind(input.operation_id).bind(p.principal_id()).bind(p.instance_id()).bind(&device).bind(platform(input.platform)).bind(secret_digest(&tenant,id,&input.secret)).bind(&*digest).bind(&*bound).bind(*seconds as f64).bind(*registration).bind(row.try_get::<Uuid,_>("id").map_err(db)?).execute(&mut *c).await.map_err(db)?;
            Ok(Change{
value:receipt(&grant_row(c,&tenant,id).await?)?,replay:false,digest:digest.clone()}
)
        }) }).await.map_err(Into::into)
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
async fn quota(
    c: &mut PgConnection,
    tenant: &str,
    actor: &str,
    instance: &str,
    limit: u32,
) -> Result<(), Error> {
    sqlx::query(
        r#"
SELECT pg_advisory_xact_lock(hashtextextended($1,2630))
"#,
    )
    .bind(format!("{tenant}:quota:{instance}:{actor}"))
    .execute(&mut *c)
    .await
    .map_err(db)?;
    let count: i64 = sqlx::query_scalar(
        r#"
SELECT count(*) FROM mdm_access.agent_grants g WHERE g.tenant_id=$1::uuid AND g.actor=$2 AND
g.instance=$3 AND g.source IN('download','browser') AND ((g.state IN('available','consumed') AND
g.expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM mdm_access.registrations r WHERE
r.tenant_id=g.tenant_id AND r.agent_grant_id=g.id)) OR EXISTS(SELECT 1 FROM
mdm_access.registrations r WHERE r.tenant_id=g.tenant_id AND r.agent_grant_id=g.id AND
r.state='active'))
"#,
    )
    .bind(tenant)
    .bind(actor)
    .bind(instance)
    .fetch_one(c)
    .await
    .map_err(db)?;
    if count >= i64::from(limit) {
        Err(Error::Capacity)
    } else {
        Ok(())
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
        peer: &rss_mdm_certificate::HandshakePeer,
        input: &wire::GrantRequest,
        a: &RequestAudit,
    ) -> Result<wire::GrantReceipt, Failure> {
        version(input.wire_version, input.operation_id)?;
        let principal = self.authenticate(peer).await?;
        let bound = hex(csr(input.csr.as_deref().ok_or(Error::Malformed)?)?.spki());
        let seconds = input.lifetime_seconds.unwrap_or(self.policy.grant_seconds);
        if seconds == 0 || seconds > self.policy.grant_seconds {
            return Err(Error::Malformed.into());
        }
        let d = digest(&(principal.registration(), principal.credential(), input))?;
        a.identify_device(principal.registration());
        a.target(principal.device());
        a.operation(input.operation_id, "agent_renewal_grant");
        self.write(a,(self,principal,input,bound,seconds,d),|ctx,c| { Box::pin(async move {
            let (service,p,input,bound,seconds,d)=ctx;
let tenant=service.tenant.to_string();
            crate::device::store::revalidate_source(c,p,rss_mdm_inventory::ReportSource::AgentBuiltin).await?;
            let row=sqlx::query(r#"
SELECT g.actor,g.instance,g.platform FROM mdm_access.registrations r JOIN
mdm_access.agent_grants g ON(g.tenant_id,g.id)=(r.tenant_id,r.agent_grant_id) WHERE
r.tenant_id=$1::uuid AND r.id=$2
"#).bind(&tenant).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
            if row.try_get::<String,_>("platform").map_err(db)?!=platform(input.platform){
return Err(Error::Forbidden)}
            if let Some(id)=sqlx::query_scalar::<_,Uuid>(r#"
SELECT id FROM mdm_access.agent_grants WHERE tenant_id=$1::uuid AND source='renewal' AND
operation_id=$2
"#).bind(&tenant).bind(input.operation_id).fetch_optional(&mut *c).await.map_err(db)?{
                let g=grant_row(c,&tenant,id).await?;
                if g.try_get::<String,_>("request_digest").map_err(db)?!=*d{
return Err(Error::Conflict)}
                check_secret(&tenant,&g,&input.secret)?;
return Ok(Change{
value:receipt(&g)?,replay:true,digest:d.clone()}
)
            }
            let id=Uuid::new_v4();
            sqlx::query(r#"
INSERT INTO
mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,spki,state,expires_at,target_registration,predecessor)
VALUES($1::uuid,$2,$3,'renewal',$4,$5,$6,$7,$8,$9,$10,'available',clock_timestamp()+make_interval(secs=>$11),$12,$13)
"#)
                .bind(&tenant).bind(id).bind(input.operation_id).bind(row.try_get::<String,_>("actor").map_err(db)?).bind(row.try_get::<String,_>("instance").map_err(db)?).bind(p.device()).bind(platform(input.platform)).bind(secret_digest(&tenant,id,&input.secret)).bind(&*d).bind(&*bound).bind(*seconds as f64).bind(p.registration()).bind(p.credential()).execute(&mut *c).await.map_err(db)?;
            Ok(Change{
value:receipt(&grant_row(c,&tenant,id).await?)?,replay:false,digest:d.clone()}
)
        }) }).await.map_err(Into::into)
    }
}
impl Service {
    pub async fn preview(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<wire::AuthorizationRequest, Failure> {
        p.check_live()?;
        if p.tenant_id() != self.tenant.to_string() {
            return Err(Error::Forbidden.into());
        }
        let mut tx = self.store.begin(p.tenant_id()).await?;
        let row = grant_row(&mut tx, p.tenant_id(), id).await?;
        if row.try_get::<String, _>("source").map_err(db)? != "browser" {
            return Err(Error::Forbidden.into());
        }
        if row.try_get::<String, _>("state").map_err(db)? != "pending" {
            owned(p, &row)?
        }
        let out = wire::AuthorizationRequest {
            grant: receipt(&row)?,
            public_key_fingerprint: row.try_get("spki").map_err(db)?,
        };
        tx.commit().await.map_err(db)?;
        Ok(out)
    }
}
