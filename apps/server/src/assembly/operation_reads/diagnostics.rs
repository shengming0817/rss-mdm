//! Exact namespace reads reuse execution metadata and safe owner projections.
use super::*;
use rss_mdm_audit_integration::operation::{OperationOwner as O, ReceiptSummary};
use rss_mdm_management_http::operation_diagnostics::LocatorQuery;

impl Operations {
    pub(crate) async fn diagnostic(
        &self,
        p: &AuthorizedPrincipal,
        owner: O,
        id: Uuid,
        q: &LocatorQuery,
    ) -> Result<(Option<ReceiptSummary>, Option<Evidence>), Error> {
        let device = q.device.as_deref().ok_or(Error::Malformed)?;
        if owner == O::DeviceControlRequest {
            return self
                .tasks
                .snapshot(p, (self, p), |(s, p), c, grant, now| {
                    Box::pin(async move {
                        grant.require(p, Permission::OperationRead, Some(device))?;
                        let Some((_, value)) = rss_mdm_device_service::control::storage::read_on(
                            c,
                            p.tenant_id(),
                            id,
                            p.principal_id(),
                        )
                        .await
                        .map_err(sql)?
                        else {
                            return Ok((None, None));
                        };
                        if value.get("accepted").is_some() {
                            return Err(Error::NotFound);
                        }
                        let changed: rss_mdm_device_service::control::ChangedReceipt =
                            serde_json::from_value(value)
                                .map_err(|_| Error::Unavailable(Failure::CommandInvariant))?;
                        let detail = s
                            .detail_owned_on(
                                c,
                                p,
                                grant,
                                now,
                                device,
                                changed.operation_id,
                                true,
                                super::super::native_ownership::Owner::Device,
                            )
                            .await?;
                        let mut receipt = ReceiptSummary::new(id);
                        receipt.object = Some(device.into());
                        receipt.revision = Some(changed.revision);
                        receipt.executions.push(changed.operation_id);
                        Ok((
                            Some(receipt),
                            Some(Evidence::Native {
                                detail: Box::new(detail),
                            }),
                        ))
                    })
                })
                .await;
        }
        self.tasks.snapshot(p,(self,p,q),|ctx,c,grant,now|Box::pin(async move{
            let(s,p,q)=*ctx;
            grant.require(p,Permission::OperationRead,Some(device))?;
            let native=match owner {
                O::DeviceControl=>Some(super::super::native_ownership::Owner::Device),
                O::SoftwareDeployment=>Some(super::super::native_ownership::Owner::Software),
                O::Installation=>Some(super::super::native_ownership::Owner::Registration),
                O::RecoveryCommand=>Some(super::super::native_ownership::Owner::Recovery),
                O::Configuration=>Some(super::super::native_ownership::Owner::Configuration),
                _=>None,
            };
            let collection_relation=rss_mdm_inventory_service::collection::execution::queries::relation_sql();
            let (relation,kind)=match owner {
                O::DeviceControl=> (rss_mdm_device_service::control::directory::RELATION_SQL,"command"),
                O::DeviceAction=> (rss_mdm_device_service::control::directory::RELATION_SQL,"action_run"),
                O::SoftwareDeployment=>(rss_mdm_software_service::deployment::directory::RELATION_SQL,"command"),
                O::SoftwareAction=>(rss_mdm_software_service::deployment::directory::RELATION_SQL,"action_run"),
                O::Installation=>(rss_mdm_registration_service::installation::queries::RELATION_SQL,"command"),
                O::RecoveryCommand=>(rss_mdm_recovery_credentials::native::queries::RELATION_SQL,"command"),
                O::Configuration=>("SELECT id,device,kind,registration,generation,source_kind,policy_version,policy,deadline,status,input_bytes FROM mdm_planning.configuration_execution_facts WHERE tenant_id=$1::uuid","command"),
                O::Script=>(rss_mdm_script_service::queries::RELATION_SQL,"action_run"),
                O::CollectionExecution=>(collection_relation.as_str(),"action_run"),
                O::EnrollmentTask=>(rss_mdm_registration_service::enrollment::tasks::queries::RELATION_SQL,"action_run"),
                O::DeviceAccessTask=>(rss_mdm_device_access_postgres::device_access::execution::queries::RELATION_SQL,"action_run"),
                O::CredentialTask=>(rss_mdm_recovery_credentials::tasks::queries::RELATION_SQL,"action_run"),
                _=>return Err(Error::Malformed),
            };
            let mut query=sqlx::QueryBuilder::new("WITH tenant_context AS (SELECT ");
            query.push_bind(p.tenant_id()).push("::uuid),owned AS (").push(relation).push(") SELECT policy,registration,generation FROM owned WHERE id=").push_bind(id).push(" AND device=").push_bind(device).push(" AND kind=").push_bind(kind);
            let row:Option<(Option<Uuid>,Uuid,i64)>=query.build_query_as().fetch_optional(&mut *c).await.map_err(sql)?;
            let Some((policy,registration,generation))=row else {return Ok((None,None));};
            if q.registration.is_some_and(|v|v!=registration) || q.generation.is_some_and(|v|v!=generation){return Err(Error::NotFound);}
            let tenant=s.tasks.tenant.to_string();
            let original=match owner {
                O::DeviceControl=>rss_mdm_device_service::control::storage::read_on(c,&tenant,id,p.principal_id()).await.map_err(sql)?,
                O::SoftwareDeployment=>rss_mdm_software_service::deployment::storage::read_on(c,&tenant,id,p.principal_id()).await.map_err(sql)?,
                O::Installation=>rss_mdm_registration_service::installation::storage::read_on(c,&tenant,id,p.principal_id()).await.map_err(sql)?,
                O::RecoveryCommand=>rss_mdm_recovery_credentials::native::storage::read_on(c,&tenant,id,p.principal_id()).await.map_err(sql)?,
                _=>None,
            };
            let original=Some(original.map_or_else(||{
                let mut r=ReceiptSummary::new(id);r.object=Some(device.into());r.accepted=Some(true);r.executions.push(id);r
            },|(_,v)|{
                let mut r=ReceiptSummary::new(id);
                r.object=Some(device.into());r.revision=v["revision"].as_i64();r.accepted=v["accepted"].as_bool();r.executions.push(id);r
            }));
            let evidence=if let Some(native)=native {
                Evidence::Native{detail:Box::new(s.detail_owned_on(c,p,grant,now,device,id,true,native).await?)}
            }else{match owner {
                O::DeviceAction=>Evidence::Device(rss_mdm_device_service::control::directory::run_summaries_on(c,s.tasks.tenant,vec![id]).await.map_err(execution_fault)?.remove(&id).ok_or(Error::NotFound)?),
                O::SoftwareAction=>Evidence::Software(rss_mdm_software_service::deployment::directory::run_summaries_on(c,s.tasks.tenant,vec![id]).await.map_err(software_fault)?.remove(&id).ok_or(Error::NotFound)?),
                O::Script=>Evidence::Script(Box::new(rss_mdm_script_service::queries::run_summaries_on(c,s.tasks.tenant,vec![id]).await.map_err(super::super::task_reads::script_fault)?.remove(&id).ok_or(Error::NotFound)?)),
                O::CollectionExecution=>Evidence::Collection(Box::new(rss_mdm_inventory_service::collection::execution::queries::run_summaries_on(c,s.tasks.tenant,vec![id]).await?.remove(&id).ok_or(Error::NotFound)?)),
                O::EnrollmentTask=>Evidence::Enrollment(rss_mdm_registration_service::enrollment::tasks::queries::detail_on(rss_mdm_install_support::StorageProfile::Mdm,c,&tenant,policy.ok_or(Error::Conflict)?,id,p,grant).await.map_err(super::super::task_reads::enrollment_fault)?),
                O::DeviceAccessTask=>Evidence::Access(rss_mdm_device_access_postgres::device_access::execution::queries::detail_on(c,&tenant,policy.ok_or(Error::Conflict)?,id,p,grant).await.map_err(super::super::task_reads::access_fault)?),
                O::CredentialTask=>Evidence::Credential(rss_mdm_recovery_credentials::tasks::queries::detail_on(rss_mdm_install_support::StorageProfile::Mdm,c,&tenant,policy.ok_or(Error::Conflict)?,id,p,grant).await.map_err(super::super::task_reads::credential_fault)?),
                _=>return Err(Error::Malformed),
            }};
            Ok((original,Some(evidence)))
        })).await
    }
}
