//! APNs leases and outcomes are committed by the Apple owner.
use crate::{Error, Failure, delivery::Delivery, protocol_types::*};
use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use uuid::Uuid;
impl Delivery {
    pub async fn wake(
        &self,
        execution: rss_transactional_messaging::fence::ExecutionBinding,
        configuration: &[u8; 32],
        channel: crate::push::Channel,
    ) -> Result<Option<Wake>, Error> {
        let configuration = *configuration;
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            execution,
            "apple_push",
            AuditIntent::Management,
        );
        audit.identify_service("apple-push");
        let result = self
            .run(&audit, (self, &audit, channel), |ctx, tx| {
                Box::pin(async move {
                    let (s, audit, channel) = ctx;
                    let channel = channel.clone();
                    let (s,audit)=(*s,*audit);
                    let tenant = tx.tenant_id().to_string();
                    let facts = s.facts.clone();
                    let Some(row) = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(facts.push_candidate(c, tenant, channel, configuration).await)
                            })
                        })
                        .await
                        .map_err(storage)?? else {return Ok(None)};
                    s.business.prepare_wake(tx, vec![row.device], audit).await?;
                    let needed = matches!(&row.disposition, PushDisposition::Ready { .. }) && s.wake_pending(tx,row.device,&row.user_key).await?;
                        let device = row.device;
                        let user_key = row.user_key.clone();
                        let tenant = tx.tenant_id().to_string();
                        let facts = s.facts.clone();
                        let (token, magic) = match row.disposition {
                            PushDisposition::Invalid { scope } => {
                                let revision = row.revision;
                                tx.with_connection(move |c| {
                                    Box::pin(async move {
                                        Ok(facts
                                            .reject_push(
                                                c, tenant, device, user_key, revision, scope,
                                            )
                                            .await)
                                    })
                                })
                                .await
                                .map_err(storage)??;
                                return Ok(None);
                            }
                            PushDisposition::Ready { token, magic } => (token, magic),
                            PushDisposition::Inactive => (Vec::new(), String::new()),
                        };
                        if !needed {
                            tx.with_connection(move |c| {
                                Box::pin(async move {
                                    Ok(facts.defer_push(c, tenant, device, user_key).await)
                                })
                            })
                            .await
                            .map_err(storage)??;
                            return Ok(None);
                        }
                        let id = Uuid::new_v4();
                        let value = device;
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(facts
                                    .lease_push(c, tenant, id, value, user_key, configuration)
                                    .await)
                            })
                        })
                        .await
                        .map_err(storage)??;
                        audit.target_device(&device);
                        audit.operation(id, "apple_push", AuditIntent::Management);
                        audit.target(&device.to_string());
                        s.audit
                            .append_in(
                                tx,
                                &Fact::observation(
                                    audit,
                                    &format!("apple-push:{id}:lease"),
                                    200,
                                    "success",
                                    None,
                                )?,
                            )
                            .await?;
                        Ok(Some(Wake {
                            execution,
                            id,
                            device: device.to_owned(),
                            revision: row.revision,
                            user_key: row.user_key,
                            token,
                            magic,
                        }))
                })
            })
            .await;
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
    async fn wake_pending(
        &self,
        tx: &mut PgTransaction<'_>,
        device: rss_mdm_agent_wire::DeviceId,

        user: &str,
    ) -> Result<bool, Error> {
        let value = device;
        if user.is_empty() {
            let facts = self.facts.clone();
            let business = self.business.clone();
            let tenant = tx.tenant_id().to_string();
            if tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(facts
                            .maintenance_due(business.as_ref(), c, tenant, value)
                            .await)
                    })
                })
                .await
                .map_err(storage)??
            {
                return Ok(true);
            }
        }
        let mut after = Uuid::nil();
        loop {
            let page = self.business.wake_commands(tx, device, after).await?;
            for (id, target) in page.commands {
                if target == user {
                    return Ok(true);
                }
                if user.is_empty() && !target.is_empty() {
                    let facts = self.facts.clone();
                    let tenant = tx.tenant_id().to_string();
                    if tx
                        .with_connection(move |c| {
                            Box::pin(
                                async move { Ok(facts.needs_prerequisites(c, tenant, id).await) },
                            )
                        })
                        .await
                        .map_err(storage)??
                    {
                        return Ok(true);
                    }
                }
            }
            match page.next {
                Some(next) => after = next,
                None => break,
            }
        }
        let facts = self.facts.clone();
        let tenant = tx.tenant_id().to_string();
        let user = user.to_owned();
        let rows = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(facts.pending_collections(c, tenant, device, user, 64).await) },
                )
            })
            .await
            .map_err(storage)??;
        Ok(!rows.is_empty())
    }
    pub async fn pushed(
        &self,
        wake: &Wake,
        status: Option<u16>,
        outcome: PushOutcome,
    ) -> Result<bool, Error> {
        let execution = wake.execution;
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            execution,
            "apple_push",
            AuditIntent::Management,
        );
        audit.target_device(&wake.device);
        audit.operation(wake.id, "apple_push", AuditIntent::Management);
        audit.target(&wake.device.to_string());
        audit.identify_service("apple-push");
        let result=self.run(&audit,(self,wake,&audit),|ctx,tx|Box::pin(async move {
   let (s,wake,audit)=*ctx;s.business.prepare_wake(tx,Vec::new(),audit).await?;
   let fact=Fact::observation(audit,&format!("apple-push:{}:settle",wake.id),200,"success",None)?.with_details(serde_json::json!({"outcome":outcome.as_str(),"status":status,"tokenRevision":wake.revision}))?;
   let facts=s.facts.clone();let tenant=tx.tenant_id().to_string();let wake=wake.clone();
   let changed=tx.with_connection(move|c|Box::pin(async move {let changed=facts.settle_push(c,tenant,wake,status,outcome).await; if matches!(changed,Ok(Some(1))) {crate::notify(c,"apple").await?;} Ok(changed)})).await.map_err(storage)??;
   match changed {Some(0)=>{},Some(1)=>s.audit.append_in(tx,&fact).await?,Some(_)=>return Err(Error::Conflict),None=>audit.require_final_request()}
   Ok(changed == Some(1))
  })).await;
        if result.is_ok() && audit.snapshot().final_request {
            let budget = rss_mdm_audit_integration::budget::AuditBudget::new(
                std::time::Duration::from_secs(2),
            );
            self.audit
                .settle_request(&audit, 200, "success", &budget.source_control())
                .await?;
        }
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result
    }
}
fn storage(_: PgError) -> Error {
    Error::Unavailable(Failure::Database)
}
