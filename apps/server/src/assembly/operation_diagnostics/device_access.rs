use super::*;
impl Diagnostics {
    pub(super) async fn da_proof(&self, l: &Lookup<'_>) -> Result<AuthorizedPrincipal, Error> {
        let da = self
            .state
            .da
            .as_ref()
            .ok_or(Error::Unavailable(Failure::Runtime))?;
        // Reauthenticate the presented credential through the existing authority owner.
        // A product proof is never cast from MDM into DA.
        let (principal, _) = self
            .state
            .identity
            .browser()
            .authenticate_request(
                l.headers,
                rss_identity_http_axum::SessionActivity::Passive,
                &da.authorization,
                l.address,
                true,
            )
            .await
            .map_err(|r| {
                if r.status() == axum::http::StatusCode::FORBIDDEN {
                    Error::Forbidden
                } else if r.status().is_server_error() {
                    Error::Unavailable(Failure::IdentityStorage)
                } else {
                    Error::Unauthorized
                }
            })?;
        let p = AuthorizedPrincipal::from_identity(&da.authorization, principal)?
            .load_authorization(&da.authorization)
            .await?;
        if p.tenant_id() != l.auth.proof.tenant_id()
            || p.instance_id() != l.auth.proof.instance_id()
            || p.principal_id() != l.auth.proof.principal_id()
        {
            return Err(Error::Forbidden);
        }
        Ok(p)
    }
    pub(super) async fn da_task(
        &self,
        p: &AuthorizedPrincipal,
        locator: &OperationLocator,
    ) -> Result<
        (
            Evidence<ReceiptSummary>,
            Evidence<rss_mdm_management_http::execution::operations::Evidence>,
        ),
        Error,
    > {
        let da = self
            .state
            .da
            .as_ref()
            .ok_or(Error::Unavailable(Failure::Runtime))?;
        let budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(5));
        let attempt = da
            .audit
            .read(
                self.state.identity.tenant,
                &budget.control(),
                (p, locator),
                |ctx, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(ctx, |(p, locator), c| {
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
                                let value =
                                    rss_mdm_recovery_credentials::tasks::queries::diagnostic_on(
                                        c, p, &grant, locator,
                                    )
                                    .await
                                    .map_err(super::super::task_reads::credential_fault)?;
                                p.check_live()?;
                                Ok::<_, Error>(value)
                            })
                        })
                        .await
                    })
                },
            )
            .await;
        let failure = |e: rss_mdm_audit_integration::TransactionError<Error>| {
            Err(match e {
                rss_mdm_audit_integration::TransactionError::Operation(e) => e,
                _ => Error::Unavailable(Failure::Database),
            })
        };
        let value = attempt.fold(Ok, failure, failure, failure, failure, failure)?;
        Ok(match value {
            Some(value) => {
                let mut result = ReceiptSummary::new(locator.operation_id);
                result.object = locator.device.clone();
                result.accepted = Some(true);
                result.executions.push(locator.operation_id);
                (
                    Evidence::Available(result),
                    Evidence::Available(
                        rss_mdm_management_http::execution::operations::Evidence::Credential(value),
                    ),
                )
            }
            None => (Evidence::NotFound, Evidence::NotFound),
        })
    }
    pub(super) async fn da_execution(
        &self,
        p: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
    ) -> Result<Evidence<rss_mdm_management_http::execution::operations::Evidence>, Error> {
        let da = self
            .state
            .da
            .as_ref()
            .ok_or(Error::Unavailable(Failure::Runtime))?;
        match da
            .runtime
            .business
            .offboarding_progress(p, device, id)
            .await
        {
            Ok(value) => Ok(Evidence::Available(
                rss_mdm_management_http::execution::operations::Evidence::Offboarding(
                    rss_mdm_device_access_postgres::device_access::lifecycle::DiagnosticProgress {
                        identity: value.operation.identity,
                        devices: value.devices,
                        complete: value.complete,
                    },
                ),
            )),
            Err(rss_mdm_device_access_postgres::Error::NotFound) => Ok(Evidence::NoDurableEvidence),
            Err(e) => match da_error(e) {
                Error::Unavailable(_) => Ok(Evidence::Unavailable),
                error => Err(error),
            },
        }
    }
    pub(super) async fn da_receipt(
        &self,
        l: &Lookup<'_>,
        p: &AuthorizedPrincipal,
    ) -> Result<Option<ReceiptSummary>, Error> {
        let da = self
            .state
            .da
            .as_ref()
            .ok_or(Error::Unavailable(Failure::Runtime))?;
        let service = &da.runtime.business;
        let id = l.operation;
        let mut result = ReceiptSummary::new(id);
        match l.owner {
            O::EnterpriseConfiguration => {
                use rss_mdm_device_access_postgres::enterprise::Record;
                let v = service
                    .enterprise_operation(p, id)
                    .await
                    .map_err(da_error)?;
                match v {
                    Record::RelyingParty(v) => {
                        result.object = Some(v.id);
                        result.revision = Some(v.revision);
                        result.enabled = Some(v.enabled);
                    }
                    Record::Subject(v) => {
                        result.object = Some(v.person.principal.to_string());
                        result.revision = Some(v.revision);
                        result.enabled = Some(v.enabled);
                    }
                    Record::WindowsKey(v) => {
                        result.object = Some(v.id.to_string());
                        result.revision = Some(v.version);
                    }
                }
            }
            O::DaPublication => {
                let v = service
                    .publication_operation(p, id)
                    .await
                    .map_err(da_error)?;
                result = summary(
                    id,
                    serde_json::to_value(v).map_err(|_| Error::Unavailable(Failure::Database))?,
                );
            }
            O::DaConfigurationExport => {
                let signing = da
                    .runtime
                    .configurations
                    .as_ref()
                    .ok_or(Error::Unavailable(Failure::Runtime))?;
                let value = service
                    .configuration_operation(signing, p, id)
                    .await
                    .map_err(da_error)?
                    .decode()
                    .map_err(|_| Error::Unavailable(Failure::Database))?;
                result.object = Some(value.id.to_string());
                result.accepted = Some(true);
                result.recorded_at = Some(value.issued_at);
            }
            O::AgentDelivery => {
                result.revision = Some(service.delivery_operation(p, id).await.map_err(da_error)?)
            }
            O::DeviceAccess => {
                let device = l.query.device.as_deref().ok_or(Error::Malformed)?;
                let v = service
                    .device_access_operation(p, device, id)
                    .await
                    .map_err(da_error)?;
                result = summary(
                    id,
                    serde_json::to_value(v).map_err(|_| Error::Unavailable(Failure::Database))?,
                );
            }
            O::Registration => {
                return rss_mdm_registration_service::operations::diagnostic_receipt(
                    &da.audit, p, id,
                )
                .await
                .map_err(Into::into);
            }
            O::Authorization => {
                return rss_mdm_authorization_service::store::operation_receipt(&da.audit, p, id)
                    .await
                    .map_err(Into::into);
            }
            O::Filevault => {
                return rss_mdm_recovery_credentials::filevault_operation_receipt(
                    &da.audit,
                    p,
                    l.query.device.as_deref().ok_or(Error::Malformed)?,
                    id,
                )
                .await
                .map_err(Into::into);
            }
            O::Pki => {
                return da
                    .pki
                    .as_ref()
                    .ok_or(Error::Unavailable(Failure::Runtime))?
                    .operation_receipt(
                        p,
                        id,
                        l.query.actor.as_deref().unwrap_or(p.principal_id()),
                        if l.query.actor.as_deref() == Some("service:device-pki") {
                            None
                        } else {
                            Some(l.query.instance.unwrap_or(
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
                    });
            }
            _ => return Err(Error::Malformed),
        }
        p.check_live()?;
        Ok(Some(result))
    }
}
fn da_error(e: rss_mdm_device_access_postgres::Error) -> Error {
    use rss_mdm_device_access_postgres::Error as E;
    match e {
        E::NotFound => Error::NotFound,
        E::Unauthorized => Error::Unauthorized,
        E::Forbidden => Error::Forbidden,
        E::Malformed => Error::Malformed,
        E::Conflict => Error::Conflict,
        _ => Error::Unavailable(Failure::Database),
    }
}
