//! APNs leases and outcomes are committed by the Apple owner.
use crate::{Error, Failure, delivery::Delivery, protocol_types::*};
use rss_mdm_audit_integration::{AuditIntent, Fact, RequestAudit};
use rss_transactional_messaging_postgres::{PgError, PgTransaction};
use uuid::Uuid;
impl Delivery {
    pub async fn wake(&self, configuration: &[u8; 32]) -> Result<Option<Wake>, Error> {
        let configuration = *configuration;
        let facts = self.facts.clone();
        let tenant = self.tenant.to_string();
        let discovered = self
            .runtime
            .local_tx(
                self.tenant,
                rss_transactional_messaging::policy::OperationDeadline::from_remaining(
                    std::time::Duration::from_secs(6),
                ),
                |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |c| {
                            Box::pin(
                                async move { Ok(facts.push_due(c, tenant, configuration).await) },
                            )
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(Failure::Database)),
                |_| Err(Error::Unavailable(Failure::Database)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(Failure::Database)),
            )??;
        if !discovered {
            return Ok(None);
        }
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            self.tenant.to_string(),
            "apple_push",
            AuditIntent::Management,
        );
        audit.identify_service("apple-push");
        let result = self
            .run(&audit, (self, &audit), |ctx, tx| {
                Box::pin(async move {
                    let (s, audit) = *ctx;
                    let tenant = s.tenant.to_string();
                    let facts = s.facts.clone();
                    let rows = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(facts.push_candidates(c, tenant, configuration).await)
                            })
                        })
                        .await
                        .map_err(storage)??;
                    s.business
                        .prepare_wake(tx, rows.iter().map(|r| r.device.clone()).collect(), audit)
                        .await?;
                    let mut prepared = Vec::new();
                    for row in rows {
                        let needed = matches!(&row.disposition, PushDisposition::Ready { .. })
                            && s.wake_pending(tx, row.registration, row.generation, &row.user_key)
                                .await?;
                        prepared.push((row, needed));
                    }
                    for (row, needed) in prepared {
                        let registration = row.registration;
                        let user_key = row.user_key.clone();
                        let tenant = s.tenant.to_string();
                        let facts = s.facts.clone();
                        let (token, magic) = match row.disposition {
                            PushDisposition::Invalid { scope } => {
                                let revision = row.revision;
                                tx.with_connection(move |c| {
                                    Box::pin(async move {
                                        Ok(facts
                                            .reject_push(
                                                c,
                                                tenant,
                                                registration,
                                                user_key,
                                                revision,
                                                scope,
                                            )
                                            .await)
                                    })
                                })
                                .await
                                .map_err(storage)??;
                                continue;
                            }
                            PushDisposition::Ready { token, magic } => (token, magic),
                            PushDisposition::Inactive => (Vec::new(), String::new()),
                        };
                        if !needed {
                            tx.with_connection(move |c| {
                                Box::pin(async move {
                                    Ok(facts.defer_push(c, tenant, registration, user_key).await)
                                })
                            })
                            .await
                            .map_err(storage)??;
                            continue;
                        }
                        let id = Uuid::new_v4();
                        tx.with_connection(move |c| {
                            Box::pin(async move {
                                Ok(facts
                                    .lease_push(
                                        c,
                                        tenant,
                                        id,
                                        registration,
                                        user_key,
                                        configuration,
                                    )
                                    .await)
                            })
                        })
                        .await
                        .map_err(storage)??;
                        audit.registration(registration);
                        audit.operation(id, "apple_push", AuditIntent::Management);
                        audit.target(&registration.to_string());
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
                        return Ok(Some(Wake {
                            id,
                            registration,
                            revision: row.revision,
                            user_key: row.user_key,
                            token,
                            magic,
                        }));
                    }
                    Ok(None)
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
        registration: Uuid,
        generation: i64,
        user: &str,
    ) -> Result<bool, Error> {
        if user.is_empty() {
            let facts = self.facts.clone();
            let business = self.business.clone();
            let tenant = self.tenant.to_string();
            if tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        Ok(facts
                            .maintenance_due(business.as_ref(), c, tenant, registration)
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
            let page = self
                .business
                .wake_commands(tx, registration, generation, after)
                .await?;
            for (id, target) in page.commands {
                if target == user {
                    return Ok(true);
                }
                if user.is_empty() && !target.is_empty() {
                    let facts = self.facts.clone();
                    let tenant = self.tenant.to_string();
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
        let tenant = self.tenant.to_string();
        let user = user.to_owned();
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(facts
                        .pending_collections(c, tenant, registration, user, 64)
                        .await)
                })
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
    ) -> Result<(), Error> {
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Background,
            rss_mdm_audit_integration::StorageProfile::Mdm,
            self.tenant.to_string(),
            "apple_push",
            AuditIntent::Management,
        );
        audit.registration(wake.registration);
        audit.operation(wake.id, "apple_push", AuditIntent::Management);
        audit.target(&wake.registration.to_string());
        audit.identify_service("apple-push");
        let result=self.run(&audit,(self,wake,&audit),|ctx,tx|Box::pin(async move {
   let (s,wake,audit)=*ctx;s.business.prepare_wake(tx,Vec::new(),audit).await?;
   let fact=Fact::observation(audit,&format!("apple-push:{}:settle",wake.id),200,"success",None)?.with_details(serde_json::json!({"outcome":outcome.as_str(),"status":status,"tokenRevision":wake.revision}))?;
   let facts=s.facts.clone();let tenant=s.tenant.to_string();let wake=wake.clone();
   let changed=tx.with_connection(move|c|Box::pin(async move {let changed=facts.settle_push(c,tenant,wake,status,outcome).await; if matches!(changed,Ok(Some(1))) {crate::notify(c,"apple").await?;} Ok(changed)})).await.map_err(storage)??;
   match changed {Some(0)=>{},Some(1)=>s.audit.append_in(tx,&fact).await?,Some(_)=>return Err(Error::Conflict),None=>audit.require_final_request()}
   Ok(())
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
