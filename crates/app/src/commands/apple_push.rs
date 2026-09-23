//! Durable APNs wake lease, separate from native command evidence.
use super::*;
use sqlx::Row;
pub(crate) struct Wake {
    pub id: Uuid,
    pub registration: Uuid,
    pub revision: i64,
    pub token: Vec<u8>,
    pub magic: String,
}
impl Commands {
    pub(crate) async fn apple_wake(
        &self,
        configuration: &[u8; 32],
    ) -> std::result::Result<Option<Wake>, Error> {
        let configuration = *configuration;
        let audit = Audit::new(self.tenant.to_string(), "apple_push");
        let result=self.transact(self,&audit,|service,tx|Box::pin(async move {
            let tenant=service.tenant.to_string();let instance=service.instance.clone();
            tx.with_connection(move|c|Box::pin(async move {Ok(crate::authorization::lock_on(c,&tenant,&instance).await)})).await??;
            let tenant=service.tenant.to_string();
            let rows=tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("SELECT a.registration::text,a.token,a.magic,a.token_revision FROM mdm_apple.devices a JOIN mdm_access.registrations r ON (r.tenant_id,r.id)=(a.tenant_id,a.registration) WHERE a.tenant_id=$1::uuid AND a.state='active' AND r.state='active' AND EXISTS(SELECT 1 FROM mdm_access.report_sources s WHERE (s.tenant_id,s.registration)=(a.tenant_id,a.registration) AND s.source='mdm.apple' AND s.enabled) AND (a.push_outcome IS DISTINCT FROM 'rejected' OR a.push_configuration IS DISTINCT FROM $2) AND a.next_push<=clock_timestamp() AND (a.push_lease_until IS NULL OR a.push_lease_until<clock_timestamp()) ORDER BY a.next_push,a.registration LIMIT 32 FOR UPDATE OF a SKIP LOCKED")
                    .bind(tenant).bind(configuration.as_slice()).fetch_all(c).await
            })).await?;
            for row in rows {
                let registration=corrupt(Uuid::parse_str(&row.try_get::<String,_>("registration")?))?;
                if !pending(tx,registration).await? {
                    let tenant=service.tenant.to_string();
                    tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_apple.devices SET next_push=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND registration=$2::uuid").bind(tenant).bind(registration.to_string()).execute(c).await?;Ok(())})).await?;
                    continue
                }
                let id=Uuid::new_v4();let tenant=service.tenant.to_string();
                tx.with_connection(move|c|Box::pin(async move {
                    sqlx::query("UPDATE mdm_apple.devices SET push_failures=CASE WHEN push_configuration IS DISTINCT FROM $4 THEN 0 ELSE push_failures END,push_configuration=$4,push_id=$3::uuid,push_lease_until=clock_timestamp()+interval '15 seconds',next_push=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND registration=$2::uuid")
                        .bind(tenant).bind(registration.to_string()).bind(id.to_string()).bind(configuration.as_slice()).execute(c).await?;Ok(())
                })).await?;
                return Ok(Some(Wake{id,registration,revision:row.try_get("token_revision")?,token:row.try_get("token")?,magic:row.try_get("magic")?}))
            }
            Ok(None)
        })).await;
        audit.finalize(None);
        result
    }
    pub(crate) async fn apple_pushed(
        &self,
        wake: &Wake,
        status: Option<u16>,
        outcome: crate::apple::push::Outcome,
    ) -> std::result::Result<(), Error> {
        let audit = Audit::new(self.tenant.to_string(), "apple_push");
        audit.registration(wake.registration);
        let result=self.transact((self,wake,status,outcome,&audit),&audit,|ctx,tx|Box::pin(async move {
            let (service,wake,status,outcome,audit)=*ctx;let tenant=service.tenant.to_string();let registration=wake.registration;let id=wake.id;let revision=wake.revision;
            let unregistered=outcome==crate::apple::push::Outcome::Unregistered;
            let outcome=match outcome {crate::apple::push::Outcome::Accepted=>"accepted",crate::apple::push::Outcome::Retryable=>"retryable",crate::apple::push::Outcome::Unregistered=>"unregistered",crate::apple::push::Outcome::Rejected=>"rejected"};
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("UPDATE mdm_apple.devices SET push_lease_until=NULL,push_status=$5,push_outcome=$6,next_push=clock_timestamp()+make_interval(secs => CASE WHEN $6='retryable' THEN greatest(CASE WHEN $5>=500 THEN 900 ELSE 30 END,30*(1<<least(push_failures,5))) ELSE 30 END),push_failures=CASE WHEN $6='retryable' THEN least(push_failures+1,6) ELSE 0 END,token=CASE WHEN $7 THEN NULL ELSE token END,magic=CASE WHEN $7 THEN NULL ELSE magic END,state=CASE WHEN $7 THEN 'pending_token' ELSE state END WHERE tenant_id=$1::uuid AND registration=$2::uuid AND push_id=$3::uuid AND token_revision=$4 AND state='active'")
                    .bind(tenant).bind(registration.to_string()).bind(id.to_string()).bind(revision).bind(status.map(i32::from)).bind(outcome).bind(unregistered).execute(c).await?;Ok(())
            })).await?;
            storage::audit(tx,audit,200).await?;Ok(())
        })).await;
        audit.finalize(None);
        result
    }
}
async fn pending(tx: &mut PgTransaction<'_>, registration: Uuid) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move {
        sqlx::query("SELECT o.request::text,o.approval::text,NULL::text AS collection,to_timestamp(0) AS due FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.gateway_accepted AND d.status IN ('published','received') AND (o.request->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) UNION ALL SELECT NULL,r.apple_approval::text,r.id::text,a.next_attempt FROM mdm_access.collection_runs r JOIN mdm_apple.attempts a ON (a.tenant_id,a.collection)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.registration=$2::uuid AND r.source='mdm.apple' AND r.sealed_at IS NULL AND r.apple_deadline>clock_timestamp() AND a.next_attempt<=clock_timestamp() ORDER BY due,collection LIMIT 64")
            .bind(tenant).bind(registration.to_string()).fetch_all(c).await
    })).await?;
    let tenant = tx.tenant_id().to_string();
    let renewal = tx.with_connection(move |c| Box::pin(async move {
        sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND registration=$2::uuid AND phase='renew' AND state IN ('pending','sent','not_now') AND next_attempt<=clock_timestamp() AND deadline>clock_timestamp())").bind(tenant).bind(registration.to_string()).fetch_one(c).await
    })).await?;
    if renewal {
        return Ok(true);
    }
    let now = storage::now(tx).await?;
    for row in rows {
        let request = row
            .try_get::<Option<String>, _>("request")?
            .map(|s| corrupt(serde_json::from_str::<Create>(&s)))
            .transpose()?;
        let permission = request.map_or(crate::authorization::Permission::InventoryCollect, |r| {
            r.task.permission()
        });
        let approval: crate::authorization::Approval =
            corrupt(serde_json::from_str(&row.try_get::<String, _>("approval")?))?;
        if tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(approval.valid(c, permission, now).await) })
            })
            .await??
        {
            return Ok(true);
        }
        if let Some(collection) = row.try_get::<Option<String>, _>("collection")? {
            let tenant = tx.tenant_id().to_string();
            tx.with_connection(move|c|Box::pin(async move { sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND collection=$2::uuid").bind(tenant).bind(collection).execute(c).await?; Ok(()) })).await?;
        }
    }
    Ok(false)
}
