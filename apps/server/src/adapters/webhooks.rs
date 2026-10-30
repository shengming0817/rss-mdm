//! Cross-owner Webhook sources; every read borrows the original transaction connection.
use rss_mdm_webhook_service::{self as webhooks, events, model::*};
use rss_request_context::TenantId;
use uuid::Uuid;
pub(crate) struct Sources {
    pub tenant: Uuid,
}
impl webhooks::management::Sources for Sources {
    fn group_member<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        tenant: TenantId,
        groups: &'a [Uuid],
        endpoint: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<bool, webhooks::Error>> {
        Box::pin(async move {
            if tenant.to_string() != self.tenant.to_string() {
                return Err(webhooks::Error::Denied);
            }
            rss_mdm_group_postgres::published_endpoint_member_on(c, tenant, groups, endpoint)
                .await
                .map_err(|_| webhooks::Error::Storage)?
                .map_err(|rejection| match rejection {
                    rss_mdm_group_postgres::Rejection::TenantMismatch => webhooks::Error::Denied,
                    _ => webhooks::Error::Invalid,
                })
        })
    }
    fn compliance_page<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        source: &'a events::CompliancePublication,
        after: Option<String>,
    ) -> futures::future::BoxFuture<
        'a,
        Result<rss_mdm_webhook_service::fanout::ChangePage, rss_mdm_webhook_service::Error>,
    > {
        Box::pin(async move {
            if source.tenant != self.tenant {
                return Err(rss_mdm_webhook_service::Error::Denied);
            }
            let tenant = TenantId::parse(&self.tenant.to_string())
                .map_err(|_| rss_mdm_webhook_service::Error::Invalid)?;
            let mut rows = rss_mdm_compliance_postgres::webhook_changes(
                c,
                tenant,
                source.run,
                source.previous,
                after,
                rss_mdm_webhook_service::PAGE + 1,
            )
            .await?;
            let more = rows.len() > rss_mdm_webhook_service::PAGE as usize;
            rows.truncate(rss_mdm_webhook_service::PAGE as usize);
            let next = if more {
                rows.last().map(|(device, _)| device.clone())
            } else {
                None
            };
            let events = rows
                .into_iter()
                .map(|(device, a)| {
                    Ok(Event {
                        event_id: events::identity(source.run, &format!("compliance:{device}")),
                        event_type: EventType::ComplianceChanged,
                        version: 1,
                        occurred_at: source.occurred_at,
                        tenant_id: source.tenant,
                        device_id: device,
                        data: EventData::Compliance {
                            rule_id: a.rule_id,
                            rule_version: a.rule_version,
                            run_id: source.run,
                            status: serde_json::from_value(serde_json::to_value(a.status)?)
                                .map_err(|_| rss_mdm_webhook_service::Error::Invalid)?,
                            reason: serde_json::from_value(serde_json::to_value(a.reason)?)
                                .map_err(|_| rss_mdm_webhook_service::Error::Invalid)?,
                        },
                    })
                })
                .collect::<Result<Vec<_>, rss_mdm_webhook_service::Error>>()?;
            Ok((events, next))
        })
    }
}
