//! Durable APNs wake lease, separate from native command evidence.
use super::channels::{PushOutcome, Wake};
use super::*;
use rss_mdm_audit_integration::Fact;
use sqlx::Row;
impl ExecutionService {
    pub async fn apple_wake(
        &self,
        configuration: &[u8; 32],
    ) -> std::result::Result<Option<Wake>, Error> {
        let configuration = *configuration;
        let tenant = self.tenant.to_string();
        let participant = self.apple_store.clone();
        let discovered = self
            .runtime
            .local_tx(self.tenant, deadline(), |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(
                            async move { Ok(participant.push_due(c, tenant, configuration).await) },
                        )
                    })
                    .await
                })
            })
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::CommandStorage)),
                |_| Err(Error::Unavailable(Failure::CommandStorage)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::CommandStorage)),
            )?
            .map_err(Error::from)?;
        if !discovered {
            return Ok(None);
        }
        let audit = RequestAudit::new(self.tenant.to_string(), "apple_push");
        audit.identify_service("apple-push");
        let result = crate::transaction::run(
            &self.audit_store,
            &self.runtime,
            self.tenant,
            &audit,
            (self, &audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, audit) = *ctx;
                    let tenant = service.tenant.to_string();
                    let instance = service.instance.clone();
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(crate::authorization::lock_on(c, &tenant, &instance).await)
                        })
                    })
                    .await??;
                    let tenant = service.tenant.to_string();
                    let participant = service.apple_store.clone();
                    let rows = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(participant.push_candidates(c, tenant, configuration).await)
                            })
                        })
                        .await?
                        .map_err(Error::from)?;
                    for row in rows {
                        let registration = row.registration;
                        if !pending(tx, service.apple_store.clone(), registration).await? {
                            let tenant = service.tenant.to_string();
                            let participant = service.apple_store.clone();
                            tx.with_connection(move |c| {
                                Box::pin(async move {
                                    Ok(participant.defer_push(c, tenant, registration).await)
                                })
                            })
                            .await?
                            .map_err(Error::from)?;
                            continue;
                        }
                        let id = Uuid::new_v4();
                        let tenant = service.tenant.to_string();
                        let participant = service.apple_store.clone();
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(participant
                                    .lease_push(c, tenant, id, registration, configuration)
                                    .await)
                            })
                        })
                        .await?
                        .map_err(Error::from)?;
                        audit.registration(registration);
                        audit.operation(id, "apple_push");
                        audit.target(&registration.to_string());
                        let revision = row.revision;
                        let fingerprint = checked_input(serde_json::to_vec(&(
                            registration,
                            revision,
                            configuration,
                        )))?;
                        let fact = Fact::business(
                            audit,
                            &format!("apple-push:{id}:lease"),
                            &fingerprint,
                            200,
                            "success",
                            None,
                        )?;
                        service.audit_store.append_in(tx, &fact, false).await?;
                        return Ok(Some(Wake {
                            id,
                            registration,
                            revision,
                            token: row.token,
                            magic: row.magic,
                        }));
                    }
                    Ok(None)
                })
            },
            crate::transaction::TransactionOwner::Execution,
        )
        .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
    pub async fn apple_pushed(
        &self,
        wake: &Wake,
        status: Option<u16>,
        outcome: PushOutcome,
    ) -> std::result::Result<(), Error> {
        let audit = RequestAudit::new(self.tenant.to_string(), "apple_push");
        audit.registration(wake.registration);
        audit.operation(wake.id, "apple_push");
        audit.target(&wake.registration.to_string());
        audit.identify_service("apple-push");
        let result=crate::transaction::run(&self.audit_store,&self.runtime,self.tenant,&audit,(self,wake,status,outcome,&audit),|ctx,tx|Box::pin(async move {
            let (service,wake,status,outcome,audit)=*ctx;let tenant=service.tenant.to_string();let registration=wake.registration;let id=wake.id;let revision=wake.revision;
            let outcome_name=outcome.as_str();
            let fingerprint=checked_input(serde_json::to_vec(&(registration,id,revision,status,outcome_name)))?;
            let fact=Fact::business(audit,&format!("apple-push:{id}:settle"),&fingerprint,200,"success",None)?
                .with_details(serde_json::json!({"outcome":outcome_name,"status":status,"tokenRevision":revision}))?;
            let participant=service.apple_store.clone();let wake=wake.clone();
            let changed=tx.with_connection(move|c|Box::pin(async move{Ok(participant.settle_push(c,tenant,wake,status,outcome).await)})).await?.map_err(Error::from)?;
            if changed == Some(1) { crate::worker_wake::notify_in(tx, crate::worker_wake::Work::Apple).await?; }
            match changed {
                Some(0|1)=>{service.audit_store.append_in(tx,&fact,changed==Some(0)).await?;},
                Some(_)=>return Err(Error::Conflict.into()),
                None=>{service.audit_store.append_request_in(tx,audit,200,"success").await?;},
            }
            Ok(())
        }),crate::transaction::TransactionOwner::Execution).await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
async fn pending(
    tx: &mut PgTransaction<'_>,
    participant: Arc<dyn super::channels::AppleStore>,
    registration: Uuid,
) -> Result<bool> {
    let tenant = tx.tenant_id().to_string();
    let store = participant.clone();
    let renewal = tx
        .with_connection(move |c| {
            Box::pin(async move { Ok(store.renewal_due(c, tenant, registration).await) })
        })
        .await?
        .map_err(Error::from)?;
    if renewal {
        return Ok(true);
    }
    let tenant = tx.tenant_id().to_string();
    let rows=tx.with_connection(move|c|Box::pin(async move{
 sqlx::query("SELECT o.request::text,o.approval::text FROM mdm_commands.operations o JOIN rss_device_command.commands d ON d.tenant_id=o.tenant_id AND d.command_id=o.id::text WHERE o.tenant_id=$1::uuid AND o.registration=$2::uuid AND o.gateway_accepted AND d.status IN ('published','received') AND (o.request->>'deadline')::bigint>extract(epoch FROM clock_timestamp()) ORDER BY o.id LIMIT 64").bind(tenant).bind(registration).fetch_all(c).await
 })).await?;
    let remaining = 64 - rows.len();
    let now = storage::now(tx).await?;
    for row in rows {
        let request: Create = stored(serde_json::from_str(&row.try_get::<String, _>("request")?))?;
        let approval: crate::execution::authority::ExecutionAuthority =
            stored(serde_json::from_str(&row.try_get::<String, _>("approval")?))?;
        if tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(approval.valid(c, request.task.permission(), now).await) })
            })
            .await??
        {
            return Ok(true);
        }
    }
    if remaining == 0 {
        return Ok(false);
    }
    let tenant = tx.tenant_id().to_string();
    let store = participant.clone();
    let collections = tx
        .with_connection(move |c| {
            Box::pin(async move {
                Ok(store
                    .pending_collections(c, tenant, registration, remaining)
                    .await)
            })
        })
        .await?
        .map_err(Error::from)?;
    // Collection admission already checked the administrator's authority. The accepted
    // run belongs to the organization and remains eligible after that session ends.
    if !collections.is_empty() {
        return Ok(true);
    }

    Ok(false)
}
