use super::*;
pub(crate) struct Installation {
    pub tenants: Option<Arc<crate::administration::tenants::service::Service>>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub timeline: Arc<rss_mdm_timeline_service::Timeline>,
    pub tenant: rss_request_context::TenantId,
}
impl Reads for Installation {
    fn operation<'a>(
        &'a self,
        l: Lookup<'a>,
    ) -> futures::future::BoxFuture<'a, Result<Detail, Error>> {
        Box::pin(async move {
            let p = &l.auth.proof;
            if p.tenant_id() != self.tenant.to_string()
                || l.query
                    .actor
                    .as_deref()
                    .is_some_and(|v| v != p.principal_id())
                || l.query
                    .instance
                    .is_some_and(|v| v.to_string() != p.instance_id())
            {
                return Err(Error::Forbidden);
            }
            let id = l.operation;
            let mut original_result_url = None;
            let mut current_resource_url = None;
            let value = async {
                Ok::<_, Error>(match l.owner {
                    O::TenantAdministration => {
                        let value = self
                            .tenants
                            .as_ref()
                            .ok_or(Error::Unavailable(Failure::Runtime))?
                            .operation_receipt(p, id)
                            .await?;
                        let mut result = ReceiptSummary::new(id);
                        use crate::administration::tenants::ReceiptResult as R;
                        match value.result {
                            R::Tenant(v) => {
                                result.object = Some(v.tenant_id);
                                result.revision = Some(v.revision);
                            }
                            R::Administrator(v) => {
                                result.object = Some(v.tenant_id);
                                result.revision = Some(
                                    i64::try_from(v.rule_revision).map_err(|_| Error::Conflict)?,
                                );
                                result.accepted = Some(true);
                            }
                            R::Provisioning(v) => {
                                result.object = Some(v.tenant_id.to_string());
                                result.revision =
                                    Some(i64::try_from(v.revision).map_err(|_| Error::Conflict)?);
                                result.state = Some(enum_name(v.phase)?);
                            }
                        }
                        original_result_url =
                            Some(format!("/api/v1/tenant-administration/operations/{id}"));
                        current_resource_url = result
                            .object
                            .as_ref()
                            .map(|id| format!("/api/v1/tenant-administration/tenants/{id}"));
                        Some(result)
                    }
                    O::Authorization => {
                        rss_mdm_authorization_service::store::operation_receipt(&self.audit, p, id)
                            .await?
                    }
                    _ => return Err(Error::Malformed),
                })
            }
            .await;
            let value = match value {
                Ok(v) => v,
                Err(e) if e.is_not_found() => None,
                Err(e) => return Err(e),
            };
            let audit_evidence = if !l.query.include_audit {
                Evidence::NotRequested
            } else {
                match self
                    .timeline
                    .diagnostics(
                        p,
                        "installation_operation",
                        &rss_mdm_timeline_service::Query {
                            operation_id: Some(id),
                            owner: Some(l.owner),
                            cursor: l.query.cursor.clone(),
                            ..Default::default()
                        },
                    )
                    .await
                {
                    Ok(page) => {
                        l.audit
                            .intent(rss_mdm_audit_integration::AuditIntent::Sensitive(
                                rss_mdm_audit_integration::SensitiveAction::AuditHistoryRead,
                            ));
                        Evidence::Available(page)
                    }
                    Err(rss_mdm_timeline_service::Error::Conflict) => {
                        return Err(Error::QueryCursorInvalidated);
                    }
                    Err(rss_mdm_timeline_service::Error::Malformed) => {
                        return Err(Error::Malformed);
                    }
                    Err(rss_mdm_timeline_service::Error::Forbidden) => Evidence::Restricted,
                    Err(_) => Evidence::Unavailable,
                }
            };
            let (audit_evidence, request_evidence) =
                rss_mdm_management_http::operation_diagnostics::split_requests(audit_evidence);
            p.check_live()?;
            Ok(Detail {
                operation: OperationLocator {
                    product: p.profile(),
                    owner: l.owner,
                    operation_id: id,
                    actor: l.owner.actor_bound().then(|| p.principal_id().into()),
                    instance: l
                        .owner
                        .actor_bound()
                        .then(|| Uuid::parse_str(p.instance_id()).map_err(|_| Error::Forbidden))
                        .transpose()?,
                    target: None,
                    device: None,
                    registration: None,
                    generation: None,
                },
                original_result: value.map_or(Evidence::NotFound, Evidence::Available),
                audit_evidence,
                request_evidence,
                execution_evidence: Evidence::NoDurableEvidence,
                original_result_url,
                current_resource_url,
            })
        })
    }
}
