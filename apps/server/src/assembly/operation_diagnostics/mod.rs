//! Product composition of independently authorized original receipts and execution evidence.
use rss_mdm_audit_integration::{
    RequestAudit,
    operation::{OperationLocator, OperationOwner as O, ReceiptSummary},
};
use rss_mdm_authorization_service::{Permission, context::AuthorizedPrincipal};
use rss_mdm_management_http::{
    Error, Failure,
    operation_diagnostics::{Detail, Evidence, Lookup, Reads},
};
use std::sync::Arc;
use uuid::Uuid;
mod device_access;
mod installation;
mod links;
pub(crate) use installation::Installation;

type OperationSections = (
    Evidence<ReceiptSummary>,
    Evidence<rss_mdm_management_http::execution::operations::Evidence>,
);
pub(crate) struct Diagnostics {
    pub state: Arc<super::Assembly>,
    pub apple: Arc<rss_mdm_apple_channel::HttpState>,
    pub windows: Arc<rss_mdm_windows_channel::HttpState>,
    pub first_use: Arc<crate::administration::first_use::FirstUse>,
    pub profiles: Arc<crate::administration::user_profiles::Backend>,
    pub mail: Arc<rss_mdm_mail_service::authority::Authority>,
}
impl Reads for Diagnostics {
    fn operation<'a>(
        &'a self,
        lookup: Lookup<'a>,
    ) -> futures::future::BoxFuture<'a, Result<Detail, Error>> {
        Box::pin(self.read(lookup))
    }
}
impl Diagnostics {
    async fn read(&self, l: Lookup<'_>) -> Result<Detail, Error> {
        let p = l.auth.proof.as_ref();
        self.validate_locator(p, &l)?;
        let da_owner = p.profile() == rss_mdm_install_support::StorageProfile::Da
            || matches!(
                l.owner,
                O::DeviceAccess
                    | O::EnterpriseConfiguration
                    | O::DaPublication
                    | O::DaConfigurationExport
                    | O::AgentDelivery
            );
        let da_proof = if da_owner && p.profile() != rss_mdm_install_support::StorageProfile::Da {
            Some(self.da_proof(&l).await?)
        } else {
            None
        };
        let p = da_proof.as_ref().unwrap_or(p);
        let da_source = da_owner || l.owner == O::DeviceAccessTask;
        let operation = locator(p, &l, da_source)?;
        let (original_result, execution_evidence) =
            match self.result(p, &l, &operation, da_owner).await {
                Ok(value) => value,
                Err(e) if e.is_not_found() => (Evidence::NotFound, Evidence::NotFound),
                Err(Error::Unavailable(_)) => (Evidence::Unavailable, Evidence::Unavailable),
                Err(e) => return Err(e),
            };
        let audit_evidence = self.history(&l, p, da_source, &operation).await?;
        let (audit_evidence, request_evidence) =
            rss_mdm_management_http::operation_diagnostics::split_requests(audit_evidence);
        p.check_live()?;
        let (original_result_url, current_resource_url) =
            links::urls(l.owner, l.operation, l.query, &original_result);
        Ok(Detail {
            operation,
            original_result,
            audit_evidence,
            request_evidence,
            execution_evidence,
            original_result_url,
            current_resource_url,
        })
    }
    fn validate_locator(&self, p: &AuthorizedPrincipal, l: &Lookup<'_>) -> Result<(), Error> {
        p.check_live()?;
        let background = background_namespace(l);
        if background && l.query.instance.is_some() {
            return Err(Error::Malformed);
        }
        if p.tenant_id() != self.state.identity.tenant.to_string()
            || actor_bound(l.owner)
                && !background
                && !matches!(l.owner, O::RegistrationRecovery | O::Pki)
                && l.query
                    .actor
                    .as_deref()
                    .is_some_and(|v| v != p.principal_id())
            || actor_bound(l.owner)
                && !background
                && !matches!(l.owner, O::RegistrationRecovery | O::Pki)
                && l.query
                    .instance
                    .is_some_and(|v| v.to_string() != p.instance_id())
        {
            return Err(Error::Forbidden);
        }
        if l.owner == O::Pki
            && l.query.instance.is_none()
            && l.query
                .actor
                .as_deref()
                .is_some_and(|v| v != "service:device-pki" && v != p.principal_id())
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    async fn result(
        &self,
        p: &AuthorizedPrincipal,
        l: &Lookup<'_>,
        operation: &OperationLocator,
        da_owner: bool,
    ) -> Result<OperationSections, Error> {
        let execution_owner = matches!(
            l.owner,
            O::DeviceControlRequest
                | O::DeviceControl
                | O::DeviceAction
                | O::SoftwareDeployment
                | O::SoftwareAction
                | O::Installation
                | O::RecoveryCommand
                | O::Configuration
                | O::Script
                | O::CollectionExecution
                | O::EnrollmentTask
                | O::DeviceAccessTask
                | O::CredentialTask
        );
        Ok(
            if matches!(l.owner, O::AppleAccountEnrollment | O::Initialization) {
                let grant = rss_mdm_authorization_service::store::authorization_snapshot(
                    &self.state.access.authorization_store(),
                    p,
                )
                .await?;
                grant.require(p, Permission::RegistrationConfigurationRead, None)?;
                // These owners keep current configuration / installation progress, not a historical receipt by operation ID.
                (Evidence::NoDurableEvidence, Evidence::NoDurableEvidence)
            } else if l.owner == O::Retirement {
                self.retirement(p, l.operation).await?
            } else if matches!(l.owner, O::PkiSigning | O::PkiRevocation) {
                self.pki_task(p, l, da_owner).await?
            } else if da_owner && l.owner == O::CredentialTask {
                self.da_task(p, operation).await?
            } else if execution_owner || l.owner.invocation() {
                self.execution(l, operation).await?
            } else {
                self.receipt(p, l, da_owner).await?
            },
        )
    }
    async fn receipt(
        &self,
        p: &AuthorizedPrincipal,
        l: &Lookup<'_>,
        da_owner: bool,
    ) -> Result<OperationSections, Error> {
        let receipt = if da_owner {
            self.da_receipt(l, p).await
        } else {
            self.original(l.auth, l.audit, l.owner, l.operation, l.query)
                .await
        };
        let original = section(receipt)?;
        let execution = if da_owner && l.owner == O::DeviceAccess {
            self.da_execution(
                p,
                l.query.device.as_deref().ok_or(Error::Malformed)?,
                l.operation,
            )
            .await?
        } else {
            Evidence::NoDurableEvidence
        };
        Ok((original, execution))
    }
    async fn retirement(
        &self,
        p: &AuthorizedPrincipal,
        id: Uuid,
    ) -> Result<OperationSections, Error> {
        let original = section(
            self.state
                .associations
                .retirement_receipt(p, id)
                .await
                .map_err(Into::into),
        )?;
        let execution = section(
            self.state
                .associations
                .retirement(p, id)
                .await
                .map(|value| {
                    Some(
                        rss_mdm_management_http::execution::operations::Evidence::Retirement(
                            Box::new(value),
                        ),
                    )
                })
                .map_err(Into::into),
        )?;
        Ok((original, execution))
    }
    async fn pki_task(
        &self,
        p: &AuthorizedPrincipal,
        l: &Lookup<'_>,
        da_owner: bool,
    ) -> Result<OperationSections, Error> {
        let registry = if da_owner {
            self.state
                .da
                .as_ref()
                .and_then(|d| d.pki.as_ref())
                .ok_or(Error::Unavailable(Failure::Runtime))?
        } else {
            &self.state.pki
        };
        Ok(
            match registry
                .task_receipt(p, l.owner, l.operation)
                .await
                .map_err(|e| match e {
                    rss_mdm_pki_service::Error::Forbidden => Error::Forbidden,
                    rss_mdm_pki_service::Error::Request => Error::Malformed,
                    _ => Error::Unavailable(Failure::Database),
                }) {
                Ok(Some((original, execution))) => (
                    Evidence::Available(original),
                    Evidence::Available(
                        rss_mdm_management_http::execution::operations::Evidence::Pki(execution),
                    ),
                ),
                Ok(None) => (Evidence::NotFound, Evidence::NotFound),
                Err(Error::Unavailable(_)) => (Evidence::Unavailable, Evidence::Unavailable),
                Err(e) => return Err(e),
            },
        )
    }
    async fn execution(
        &self,
        l: &Lookup<'_>,
        operation: &OperationLocator,
    ) -> Result<OperationSections, Error> {
        let result = if l.owner.invocation() {
            if l.query.actor.is_none() || l.query.instance.is_some() {
                return Err(Error::Malformed);
            }
            self.state
                .operation_reads
                .invocation(l.auth, operation, l.query)
                .await
        } else {
            self.state
                .operation_reads
                .diagnostic(l.auth, l.owner, l.operation, l.query)
                .await
        };
        let result = result?;
        Ok((section(Ok(result.original))?, section(result.execution)?))
    }
    async fn history(
        &self,
        l: &Lookup<'_>,
        p: &AuthorizedPrincipal,
        da_source: bool,
        operation: &OperationLocator,
    ) -> Result<Evidence<rss_mdm_timeline_service::DiagnosticPage>, Error> {
        if !l.query.include_audit {
            return Ok(Evidence::NotRequested);
        }
        // Timeline authority is instance-bound. Never attach a same-UUID attempt from the
        // reader's current instance to an explicitly selected receipt in another instance.
        if operation
            .instance
            .is_some_and(|instance| instance.to_string() != p.instance_id())
        {
            return Ok(Evidence::Restricted);
        }
        // DeviceAccessTask keeps its existing MDM execution authority, but its facts are DA.
        let da_proof = if da_source && p.profile() != rss_mdm_install_support::StorageProfile::Da {
            match self.da_proof(l).await {
                Ok(proof) => Some(proof),
                Err(Error::Forbidden | Error::Unauthorized) => return Ok(Evidence::Restricted),
                Err(Error::Unavailable(_)) => return Ok(Evidence::Unavailable),
                Err(e) => return Err(e),
            }
        } else {
            None
        };
        let p = da_proof.as_ref().unwrap_or(p);
        if p.require(Permission::AuditRead, None).is_err() {
            return Ok(Evidence::Restricted);
        }
        let da_timeline = if da_source {
            let Some(da) = &self.state.da else {
                return Ok(Evidence::Unavailable);
            };
            Some(self.state.timeline.for_source(
                rss_mdm_install_support::StorageProfile::Da,
                da.audit.clone(),
            ))
        } else {
            None
        };
        let timeline = da_timeline.as_ref().unwrap_or(self.state.timeline.as_ref());
        let query = rss_mdm_timeline_service::Query {
            operation_id: Some(l.operation),
            owner: Some(l.owner),
            device: l.query.device.clone(),
            actor: operation.actor.clone(),
            target_id: l.query.target.clone(),
            registration_id: l.query.registration,
            generation: l.query.generation,
            cursor: l.query.cursor.clone(),
            ..Default::default()
        };
        match tokio::time::timeout(
            std::time::Duration::from_secs(1),
            timeline.diagnostics(p, "operation_detail", &query),
        )
        .await
        {
            Ok(Ok(page)) => {
                l.audit
                    .intent(rss_mdm_audit_integration::AuditIntent::Sensitive(
                        rss_mdm_audit_integration::SensitiveAction::AuditHistoryRead,
                    ));
                Ok(Evidence::Available(page))
            }
            Ok(Err(rss_mdm_timeline_service::Error::Forbidden)) => Ok(Evidence::Restricted),
            Ok(Err(rss_mdm_timeline_service::Error::Conflict)) => {
                Err(Error::QueryCursorInvalidated)
            }
            Ok(Err(rss_mdm_timeline_service::Error::Malformed)) => Err(Error::Malformed),
            _ => Ok(Evidence::Unavailable),
        }
    }
    #[expect(
        clippy::cognitive_complexity,
        reason = "the exhaustive static receipt-owner dispatch is intentionally kept auditable in one match"
    )]
    async fn original(
        &self,
        request: &rss_mdm_authorization_service::context::RequestAuth,
        a: &RequestAudit,
        owner: O,
        id: Uuid,
        q: &rss_mdm_management_http::operation_diagnostics::LocatorQuery,
    ) -> Result<Option<ReceiptSummary>, Error> {
        let p = &request.proof;
        let s = &self.state;
        match owner {
            O::DeviceManagement => s
                .associations
                .operation_receipt(
                    p,
                    id,
                    if q.actor.as_deref()
                        == Some(rss_mdm_device_service::ReceiptNamespace::AUTOMATIC_ACTOR)
                    {
                        rss_mdm_device_service::ReceiptNamespace::AutomaticAssociation
                    } else {
                        rss_mdm_device_service::ReceiptNamespace::CurrentPrincipal
                    },
                )
                .await
                .map_err(Into::into),
            O::Asset => s.assets.operation_receipt(p, id).await.map_err(Into::into),
            O::AgentConfiguration => {
                let value =
                    rss_mdm_registration_service::agent::configurations::configuration_operation(
                        &s.access.registration(),
                        p,
                        id,
                    )
                    .await
                    .map_err(|e| {
                        e.source
                            .map(Error::from)
                            .unwrap_or(Error::Unavailable(Failure::Database))
                    })?;
                Ok(value.map(|v| {
                    let mut r = ReceiptSummary::new(id);
                    r.object = Some(v.configuration.configuration_id.to_string());
                    r.accepted = Some(true);
                    r
                }))
            }
            O::RegistrationRecovery => {
                let identity = rss_mdm_registration_service::agent::queries::ReceiptIdentity {
                    actor: q.actor.clone().unwrap_or_else(|| p.principal_id().into()),
                    instance: q
                        .instance
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| p.instance_id().into()),
                };
                let value =
                    rss_mdm_registration_service::agent::queries::registration_recovery_operation(
                        &s.access.registration(),
                        request,
                        q.registration.ok_or(Error::Malformed)?,
                        id,
                        &identity,
                    )
                    .await?;
                value
                    .map(|v| {
                        let raw = serde_json::to_value(v)
                            .map_err(|_| Error::Unavailable(Failure::Database))?;
                        let mut r = summary(id, raw.clone());
                        r.object = raw["grantId"].as_str().map(str::to_owned);
                        r.accepted = Some(true);
                        Ok(r)
                    })
                    .transpose()
            }
            O::Registration => {
                rss_mdm_registration_service::operations::diagnostic_receipt(&s.audit_store, p, id)
                    .await
                    .map_err(Into::into)
            }
            O::Authorization => {
                rss_mdm_authorization_service::store::operation_receipt(&s.audit_store, p, id)
                    .await
                    .map_err(Into::into)
            }
            O::Filevault => rss_mdm_recovery_credentials::filevault_operation_receipt(
                &s.audit_store,
                p,
                q.device.as_deref().ok_or(Error::Malformed)?,
                id,
                q.registration.ok_or(Error::Malformed)?,
                q.generation.ok_or(Error::Malformed)?,
            )
            .await
            .map_err(Into::into),
            O::Resource => s
                .resources
                .operation_receipt(p, id)
                .await
                .map_err(Into::into),
            O::PolicyEventMember => s
                .events
                .member_receipt(p, q.device.as_deref().ok_or(Error::Malformed)?, id)
                .await
                .map_err(Into::into),
            O::ComplianceTask => s.compliance.task_receipt(p, id).await.map_err(Into::into),
            O::PolicyEvent => s
                .events
                .operation_receipt(p, q.device.as_deref().ok_or(Error::Malformed)?, id)
                .await
                .map_err(Into::into),
            O::Collection => s
                .assets
                .collection_receipt(
                    p,
                    q.device.as_deref().ok_or(Error::Malformed)?,
                    id,
                    q.registration,
                    q.generation,
                )
                .await
                .map_err(Into::into),
            O::Policy => {
                rss_mdm_policy_service::management::read::operation_receipt(&s.policies, p, id)
                    .await
                    .map_err(Into::into)
            }
            O::GroupTask => s.groups.task_receipt(p, id).await.map_err(Into::into),
            O::ScopeTask => s.scopes.task_receipt(p, id).await.map_err(Into::into),
            O::AssetQuery => s.assets.query_receipt(p, id).await.map_err(Into::into),
            O::PolicyWork => {
                rss_mdm_policy_service::management::read::work_receipt(&s.policies, p, id)
                    .await
                    .map_err(Into::into)
            }
            O::Group => s.groups.operation_receipt(p, id).await.map_err(Into::into),
            O::Scope => s.scopes.operation_receipt(p, id).await.map_err(Into::into),
            O::Compliance => s
                .compliance
                .operation_receipt(p, id)
                .await
                .map_err(Into::into),
            O::SoftwarePublication => s
                .publications
                .operation_receipt(p, id)
                .await
                .map_err(Into::into),
            O::SoftwareCatalog => {
                use rss_mdm_software_service::catalog::OperationReceipt as R;
                let Some(value) = rss_mdm_software_service::management::installers::operation(
                    &s.software_catalog,
                    p,
                    id,
                )
                .await?
                else {
                    return Ok(None);
                };
                let mut result = ReceiptSummary::new(id);
                match value {
                    R::Source(v) => {
                        result.revision =
                            Some(i64::try_from(v.lifecycle.revision).map_err(|_| Error::Conflict)?);
                        result.recorded_at = Some(v.lifecycle.at);
                        result.state = Some(enum_name(v.lifecycle.state)?);
                    }
                    R::Version(v) => {
                        result.object = Some(v.resource);
                        result.revision =
                            Some(i64::try_from(v.lifecycle.revision).map_err(|_| Error::Conflict)?);
                        result.recorded_at = Some(v.lifecycle.at);
                        result.state = Some(enum_name(v.lifecycle.state)?);
                    }
                    R::Import(v) => {
                        result.object = Some(v.resource);
                        result.revision =
                            Some(i64::try_from(v.storage_revision).map_err(|_| Error::Conflict)?);
                    }
                    R::Installer(v) => {
                        result.object = Some(v.package_id.to_string());
                        result.revision =
                            Some(i64::try_from(v.storage_revision).map_err(|_| Error::Conflict)?);
                    }
                    R::Withdrawal(v) => {
                        result.object = Some(v.withdrawn.to_string());
                        result.state = Some("withdrawn".into());
                    }
                }
                Ok(Some(result))
            }
            O::SoftwareSourceSnapshot => {
                let source = q.target.clone().ok_or(Error::Malformed)?;
                let v = rss_mdm_software_service::source_snapshots::operation(
                    &s.software_catalog,
                    p,
                    a,
                    source,
                    id,
                )
                .await?;
                let mut result = ReceiptSummary::new(id);
                result.object = Some(v.snapshot.source);
                result.revision = Some(v.snapshot.revision);
                result.recorded_at = Some(v.snapshot.imported_at);
                Ok(Some(result))
            }
            O::Content => {
                let resource = q.target.as_deref().ok_or(Error::Malformed)?;
                let access = s
                    .content_access
                    .as_ref()
                    .ok_or(Error::Unavailable(Failure::ContentStorage))?;
                let v =
                    rss_mdm_content_service::service::receipt(access, p, a, resource, id).await?;
                let mut result = ReceiptSummary::new(id);
                result.object = Some(v.resource);
                result.accepted = Some(v.committed);
                Ok(Some(result))
            }
            O::StorageConnection | O::StorageMigration => {
                let authority = rss_mdm_content_service::connections::authority::Authority {
                    tenant: s.identity.tenant,
                    protection: s.protection.clone(),
                    audit: s.audit_store.clone(),
                    content: s.content_writer.clone(),
                };
                let mut result = ReceiptSummary::new(id);
                if owner == O::StorageConnection {
                    let value = authority.operation(p, a, id).await?;
                    result.revision = Some(value.revision);
                    result.state = Some(value.state);
                    result.object = Some(value.profile);
                } else {
                    let value = authority.migration_operation(p, a, id).await?;
                    result.revision = Some(value.target_revision);
                    result.state = Some(enum_name(value.phase)?);
                    result.object = Some(value.target_generation.to_string());
                }
                Ok(Some(result))
            }
            O::Telemetry => {
                let budget = rss_mdm_audit_integration::budget::AuditBudget::new(
                    std::time::Duration::from_secs(5),
                );
                let result = s
                    .audit_store
                    .read(s.identity.tenant, &budget.control(), p, |p, tx| {
                        Box::pin(async move {
                            tx.with_connection_context(p, |p, c| {
                                Box::pin(async move {
                                    rss_mdm_authorization_service::lock_shared_on(
                                        p.authority_profile(),
                                        c,
                                        p.tenant_id(),
                                        p.instance_id(),
                                    )
                                    .await?;
                                    let grant = rss_mdm_authorization_service::snapshot_on(
                                        p.authority_profile(),
                                        c,
                                        p.tenant_id(),
                                        p.instance_id(),
                                    )
                                    .await?;
                                    rss_mdm_telemetry_service::maintenance::operation_receipt_on(
                                        c, p, &grant, id,
                                    )
                                    .await
                                    .map_err(rss_mdm_management_http::telemetry::error)
                                })
                            })
                            .await
                        })
                    })
                    .await;
                fn failure(
                    e: rss_mdm_audit_integration::TransactionError<Error>,
                ) -> Result<Option<ReceiptSummary>, Error> {
                    Err(match e {
                        rss_mdm_audit_integration::TransactionError::Operation(e) => e,
                        _ => Error::Unavailable(Failure::Database),
                    })
                }
                result.fold(Ok, failure, failure, failure, failure, failure)
            }
            O::AppleAde => rss_mdm_apple_channel::ade::diagnostic_receipt(&self.apple, p, id)
                .await
                .map_err(|e| Error::from(crate::Error::Apple(e))),
            O::AppleRuntimeMaterial => {
                let value =
                    rss_mdm_apple_channel::runtime_materials::operation_receipt(&self.apple, p, id)
                        .await
                        .map_err(|e| Error::from(crate::Error::Apple(e)))?;
                Ok(Some(summary(
                    id,
                    serde_json::to_value(value)
                        .map_err(|_| Error::Unavailable(Failure::Database))?,
                )))
            }
            O::WindowsWns => {
                use rss_mdm_windows_channel::wns_materials::Operation;
                let value =
                    rss_mdm_windows_channel::wns_materials::operation_receipt(&self.windows, p, id)
                        .await
                        .map_err(|e| Error::from(crate::Error::Windows(e)))?;
                let mut result = ReceiptSummary::new(id);
                match value {
                    Operation::Material(v) => {
                        result.revision = Some(v.revision);
                        result.object = Some(v.package_family_name);
                    }
                    Operation::Revocation(v) => {
                        result.revision = Some(v.revision);
                        result.state = Some("revoked".into());
                    }
                }
                Ok(Some(result))
            }
            O::Pki => s
                .pki
                .operation_receipt(
                    p,
                    id,
                    q.actor.as_deref().unwrap_or(p.principal_id()),
                    if q.actor.as_deref() == Some("service:device-pki") {
                        None
                    } else {
                        Some(q.instance.unwrap_or(
                            Uuid::parse_str(p.instance_id()).map_err(|_| Error::Malformed)?,
                        ))
                    },
                )
                .await
                .map_err(|e| match e {
                    rss_mdm_pki_service::Error::Forbidden => Error::Forbidden,
                    rss_mdm_pki_service::Error::Request => Error::Malformed,
                    rss_mdm_pki_service::Error::NotFound => Error::NotFound,
                    _ => Error::Unavailable(Failure::Database),
                }),
            O::Webhook => {
                let value = s
                    .webhooks
                    .execute(
                        p.clone(),
                        a.clone(),
                        rss_mdm_webhook_service::management::Command::OperationReceipt(id),
                    )
                    .await?;
                if let rss_mdm_webhook_service::management::Reply::OperationReceipt(value) = value {
                    Ok(Some(value))
                } else {
                    Err(Error::Unavailable(Failure::Database))
                }
            }
            O::Smtp => {
                let v = self.mail.operation(p, a, id).await?;
                Ok(Some(summary(
                    id,
                    serde_json::to_value(v).map_err(|_| Error::Unavailable(Failure::Database))?,
                )))
            }
            O::TaskTrust => {
                let v = s.task_trust.task_trust_operation(p, a, id).await?;
                Ok(Some(summary(
                    id,
                    serde_json::to_value(v).map_err(|_| Error::Unavailable(Failure::Database))?,
                )))
            }
            O::FirstUse => {
                let v = self.first_use.operation(p, a, id).await?;
                Ok(Some(summary(
                    id,
                    serde_json::to_value(v.saved)
                        .map_err(|_| Error::Unavailable(Failure::Database))?,
                )))
            }
            O::UserProfile => {
                let v = self.profiles.operation(p, a, id).await?;
                let mut result = ReceiptSummary::new(id);
                result.object = Some(v.definition.field_id.to_string());
                result.revision = Some(v.definition.revision);
                result.enabled = v.definition.value.map(|v| v.enabled);
                Ok(Some(result))
            }
            O::CertificateArchive => {
                let v = s.certificate_archive.operation(p, id).await?;
                let mut result = ReceiptSummary::new(id);
                result.object = v.entry_id.map(|v| v.to_string());
                result.revision = Some(v.revision);
                Ok(Some(result))
            }
            O::Retirement
            | O::PkiSigning
            | O::PkiRevocation
            | O::ScriptInvocation
            | O::SoftwareInvocation
            | O::EnrollmentInvocation
            | O::DeviceControl
            | O::DeviceAction
            | O::DeviceControlRequest
            | O::Installation
            | O::EnrollmentTask
            | O::Configuration
            | O::CollectionExecution
            | O::Script
            | O::SoftwareDeployment
            | O::SoftwareAction
            | O::RecoveryCommand
            | O::CredentialTask
            | O::DeviceAccess
            | O::EnterpriseConfiguration
            | O::DaPublication
            | O::DaConfigurationExport
            | O::AgentDelivery
            | O::DeviceAccessTask
            | O::TenantAdministration
            | O::Initialization
            | O::AppleAccountEnrollment => Err(Error::Malformed),
        }
    }
}
/// Only scalar historical coordinates from typed owner responses; no payload or diagnostic text.
fn summary(id: Uuid, v: serde_json::Value) -> ReceiptSummary {
    let mut s = ReceiptSummary::new(id);
    s.object = v
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    s.revision = v.get("revision").and_then(serde_json::Value::as_i64);
    s.state = v
        .get("state")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    s.accepted = v.get("accepted").and_then(serde_json::Value::as_bool);
    s.enabled = v.get("enabled").and_then(serde_json::Value::as_bool);
    s
}

fn actor_bound(owner: O) -> bool {
    owner.actor_bound()
}

fn enum_name(value: impl serde::Serialize) -> Result<String, Error> {
    serde_json::to_value(value)
        .map_err(|_| Error::Unavailable(Failure::Database))?
        .as_str()
        .map(str::to_owned)
        .ok_or(Error::Conflict)
}

/// Preserve independent evidence while keeping authentication, authority and bad locators fail-closed.
fn section<T>(value: Result<Option<T>, Error>) -> Result<Evidence<T>, Error> {
    match value {
        Ok(Some(value)) => Ok(Evidence::Available(value)),
        Ok(None) => Ok(Evidence::NotFound),
        Err(e) if e.is_not_found() => Ok(Evidence::NotFound),
        Err(e)
            if e.status().is_server_error()
                && e.status() != axum::http::StatusCode::NOT_IMPLEMENTED =>
        {
            Ok(Evidence::Unavailable)
        }
        Err(e) => Err(e),
    }
}

fn locator(
    p: &AuthorizedPrincipal,
    l: &Lookup<'_>,
    da_source: bool,
) -> Result<OperationLocator, Error> {
    Ok(OperationLocator {
        product: if da_source {
            rss_mdm_install_support::StorageProfile::Da
        } else {
            p.profile()
        },
        owner: l.owner,
        operation_id: l.operation,
        actor: (actor_bound(l.owner) || l.owner.invocation()).then(|| {
            l.query
                .actor
                .clone()
                .unwrap_or_else(|| p.principal_id().to_owned())
        }),
        instance: if background_namespace(l) {
            if l.query.instance.is_some() {
                return Err(Error::Malformed);
            }
            None
        } else if actor_bound(l.owner) {
            Some(
                l.query
                    .instance
                    .unwrap_or(Uuid::parse_str(p.instance_id()).map_err(|_| Error::Forbidden)?),
            )
        } else {
            None
        },
        target: l.query.target.clone(),
        device: l.query.device.clone(),
        registration: l.query.registration,
        generation: l.query.generation,
    })
}

fn background_namespace(l: &Lookup<'_>) -> bool {
    matches!(
        (l.owner, l.query.actor.as_deref()),
        (O::Pki, Some("service:device-pki"))
            | (
                O::DeviceManagement,
                Some(rss_mdm_device_service::ReceiptNamespace::AUTOMATIC_ACTOR)
            )
    )
}
