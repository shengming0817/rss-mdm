use super::*;
use crate::operations::{Actor, Operation};
use rss_mdm_audit_integration::{Fact, RequestAudit, budget::AuditBudget};
use uuid::Uuid;
impl Quotas {
    pub async fn change(
        &self,
        p: &AuthorizedPrincipal,
        user: Option<&User>,
        change: &Change,
        key: Uuid,
        audit: &RequestAudit,
    ) -> Result<Configuration, Error> {
        let profile = self.profile();

        p.manage(Permission::RegistrationConfigurationWrite)?;
        let subject = subject(p, user)?;
        if key.is_nil()
            || change.expected_revision >= i64::MAX as u64
            || (user.is_none() && Channel::ALL.iter().any(|c| change.limits.get(*c).is_none()))
        {
            return Err(Error::Malformed);
        }
        p.bind_audit(audit)?;
        audit.owned_operation(
            rss_mdm_audit_integration::operation::OperationOwner::Registration,
            key,
            "registration_quota_change",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let digest = crate::enrollment::digest(&(
            "registration_quota.v1",
            &subject,
            change.expected_revision,
            &change.limits,
        ));
        let op = Operation {
            actor: Actor::from_authorized(p),
            key,
            digest: &digest,
        };
        let budget = AuditBudget::new(std::time::Duration::from_secs(6));
        let result = self
            .audit
            .write(
                rss_request_context::TenantId::parse(p.tenant_id())
                    .map_err(|_| Error::Malformed)?,
                &budget.source_control(),
                (&self.audit, p, &subject, change, &op, audit),
                |ctx, tx| {
                    Box::pin(async move {
                        let (store, p, subject, change, op, audit) = *ctx;
                        let (value, replayed) = tx
                            .with_connection_context(
                                &mut (p, subject, change, op, audit),
                                |ctx, c| {
                                    Box::pin(async move {
                                        let (p, subject, change, op, audit) = *ctx;
                                        lock_on(profile, c, p.tenant_id()).await?;
                                        if let Some(old) =
                                            crate::operations::replay(profile, c, op).await?
                                        {
                                            return Ok::<_, Error>((
                                                serde_json::from_str(&old)
                                                    .map_err(|_| Error::Corrupt)?,
                                                true,
                                            ));
                                        }
                                        let current =
                                            configuration_on(profile, c, p.tenant_id(), subject)
                                                .await?;
                                        if current.revision != change.expected_revision {
                                            return Err(Error::Conflict);
                                        }
                                        let revision = current.revision + 1;
                                        sqlx::query(
                                            crate::storage_profile::sql(profile)
                                                .quotas_management_change_1,
                                        )
                                        .bind(p.tenant_id())
                                        .bind(subject)
                                        .bind(revision as i64)
                                        .bind(change.limits.agent.map(i64::from))
                                        .bind(change.limits.windows_mdm.map(i64::from))
                                        .bind(change.limits.macos_mdm.map(i64::from))
                                        .execute(&mut *c)
                                        .await
                                        .map_err(db)?;
                                        p.manage(Permission::RegistrationConfigurationWrite)?;
                                        let value = Configuration {
                                            revision,
                                            limits: change.limits.clone(),
                                        };
                                        crate::operations::save(
                                            profile,
                                            c,
                                            op,
                                            &serde_json::to_string(&value)
                                                .map_err(|_| Error::Corrupt)?,
                                            audit,
                                            false,
                                        )
                                        .await?;
                                        Ok((value, false))
                                    })
                                },
                            )
                            .await?;
                        let fact = Fact::business(
                            audit,
                            rss_mdm_audit_integration::operation::OperationOwner::Registration,
                            &format!("registration-quota:{}:{}", p.principal_id(), op.key),
                            200,
                            "success",
                            None,
                        )?;
                        (if replayed {
                            Ok(())
                        } else {
                            store.append(tx, &fact).await
                        })
                        .map_err(Error::from)?;
                        if replayed {
                            audit.management_result(
                                rss_mdm_audit_integration::ManagementResult::Replayed,
                            );
                        }
                        audit.mark_commit_started();
                        Ok(value)
                    })
                },
            )
            .await;
        crate::operations::settle(result, audit)
    }
}
