//! 只读目录组合原领域公开读接口；不复制领域状态或秘密。
use crate::Error;
use model::*;
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::AuthorizedPrincipal;
pub(crate) mod http;
pub(crate) mod model;
use std::{collections::BTreeMap, sync::Arc};
#[derive(Clone)]
pub(crate) struct Directory {
    pub management_tenant: rss_request_context::TenantId,
    pub identity: rss_identity_postgres::Authority,
    pub federation: Option<rss_identity_postgres::Federation>,
    pub tenant_administration: Option<Arc<crate::administration::tenants::service::Service>>,
    pub user_profiles: Arc<crate::administration::user_profiles::Backend>,
    pub audit: Arc<rss_mdm_audit_integration::AuditStore>,
    pub clock: Arc<dyn crate::clock::Clock>,
    pub protection: Arc<rss_mdm_native_protection::Protector>,
    pub pki: Arc<rss_mdm_pki_service::registry::Registry>,
    pub software_runtime: Arc<rss_transactional_messaging_postgres::PgRuntime>,
    pub registration: Option<Arc<rss_mdm_registration_service::agent::Service>>,
    pub webhooks: Arc<rss_mdm_webhook_service::management::Service>,
    pub windows: Arc<rss_mdm_windows_channel::Store>,
    pub windows_runtime: Arc<rss_mdm_windows_channel::HttpState>,
    pub content: Option<Arc<rss_mdm_content_service::Store>>,
    pub task_trust: Arc<rss_mdm_task_trust::Service>,
    pub recovery: Option<Arc<rss_mdm_recovery_credentials::Protection>>,
    pub apple_store: Arc<rss_mdm_apple_channel::Store>,
    pub apple: Arc<rss_mdm_apple_channel::HttpState>,
}
fn route(id: &str, tenant: &str) -> Option<String> {
    let path = match id {
        "apns-key" | "apns-cert" => "/api/v1/apple/materials/apns",
        "profile-key" | "profile-cert" => "/api/v1/apple/materials/profile",
        "managed-key" => "/api/v1/apple/materials/managed_account",
        "s3-key" | "storage" => "/api/v1/storage/connections",
        "registration" => "/api/v1/agent-enrollment-settings",
        "smtp" => "/api/v1/smtp",
        "user-attributes" => "/api/v1/user-attribute-definitions",
        "wns" => "/api/v1/windows/wns",
        "task-key" => "/api/v1/task-signing/trust",
        "agent-package" => "/api/v1/agent-packages",
        "webhook-own" => "/api/v1/webhooks/materials",
        "organization" => "/api/v1/tenant-administration/tenants",
        _ => return None,
    };
    Some(if path.starts_with("/api/v1/tenant-administration/") {
        path.to_owned()
    } else {
        format!(
            "/api/v1/tenants/{tenant}/{}",
            path.strip_prefix("/api/v1/").expect("business route")
        )
    })
}
fn configured(projection: &mut Projection, count: usize) {
    projection.configured_count = Some(count);
    projection.status = if count == 0 {
        Status::Unconfigured
    } else {
        Status::Configured
    };
    projection.reason = None;
}
fn unavailable(projection: &mut Projection, error: Error) -> Result<(), Error> {
    if super::permission_denied(&error) {
        return Err(error);
    }
    projection.status = Status::Unavailable;
    projection.reason = Some("owner_read_unavailable");
    Ok(())
}
impl Directory {
    pub(crate) async fn project(
        &self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        continuation: &rss_mdm_authorization_service::credential::RequestCredential,
        items: Vec<Item>,
        cutoff: rss_request_context::Deadline,
    ) -> Result<Vec<Entry>, Error> {
        let business = proof.tenant_id() != self.management_tenant.to_string();
        proof.bind_audit(&audit)?;
        audit.set_action(
            "settings_catalog_read",
            rss_mdm_audit_integration::AuditIntent::Routine,
        );
        let mut cache = BTreeMap::<String, Projection>::new();
        let mut result = Vec::new();
        let mut organizations: Option<serde_json::Value> = None;
        for item in items {
            proof.check_live()?;
            let href = route(item.id, proof.tenant_id());
            if let Some(cached) = href.as_ref().and_then(|key| cache.get(key)) {
                result.push(Entry {
                    item,
                    projection: cached.clone(),
                });
                continue;
            }
            let mut projection = Projection::unknown(href.as_deref());
            self.host_projection(&proof, business, item.id, &mut projection)
                .await?;
            if business {
                self.business_projection(
                    &proof,
                    &audit,
                    continuation,
                    item.id,
                    &mut organizations,
                    cutoff,
                    &mut projection,
                )
                .await?;
            }
            self.configure_action(&proof, item.id, &mut projection);
            if let Some(href) = href {
                cache.insert(href, projection.clone());
            }
            result.push(Entry { item, projection });
        }
        proof.check_live()?;
        Ok(result)
    }

    async fn host_projection(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        business: bool,
        id: &str,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        match id {
            "entry" | "postgres" | "instance" | "native" | "operation" => {
                projection.status = Status::Loaded;
                projection.reason = Some("current_process_loaded_not_external_qualification");
            }
            "organization" if !business => self.tenant_registry(proof, projection).await?,
            "audit" | "ledger" => {
                projection.status = if id == "audit" || self.audit.uses_ledger() {
                    Status::Loaded
                } else {
                    Status::Unconfigured
                };
                projection.reason = Some(if self.audit.uses_ledger() {
                    "fixed_installation_key_no_same_chain_rotation"
                } else {
                    "explicit_plain_installation_integrity_mode"
                });
            }
            "dbpassword" => {
                projection.status = Status::Loaded;
                projection.reason =
                    Some("current_database_sessions_not_future_credential_validity");
            }
            "ca-root" | "ca-pass" | "provisioner" | "scep-decrypter" | "ca-webhook" => {
                self.ca_custody(proof, id, projection).await?
            }
            "windows-key" => {
                projection.status = if self.windows_runtime.windows.is_some() {
                    Status::Loaded
                } else {
                    Status::Unconfigured
                };
                projection.reason = Some("current_process_loaded_not_device_confirmation");
            }
            "oidc-state" => {
                projection.status = if self.federation.is_some() {
                    Status::Loaded
                } else {
                    Status::Unconfigured
                };
                projection.reason = Some("current_process_loaded_not_provider_login");
            }
            _ => (),
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "projection borrows the original subject, continuation, audit and cumulative deadline"
    )]
    async fn business_projection(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        audit: &RequestAudit,
        continuation: &rss_mdm_authorization_service::credential::RequestCredential,
        id: &str,
        organizations: &mut Option<serde_json::Value>,
        cutoff: rss_request_context::Deadline,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        match id {
            "user-attributes" => self.user_attributes(proof, audit, projection).await?,
            "recovery-key" | "recovery-rsa" => {
                self.recovery_material(proof, id, projection).await?
            }
            "oidc" => {
                self.identity_providers(proof, continuation, projection, cutoff)
                    .await?
            }
            "ade-key" | "ade-token" | "apple-account" => {
                self.apple_organizations(proof, id, organizations, projection)
                    .await?
            }
            "agent-package" => self.agent_packages(proof, projection).await?,
            "s3-key" | "storage" => self.content_storage(proof, audit, projection).await?,
            "apns-key" | "apns-cert" | "profile-key" | "profile-cert" | "managed-key" => {
                self.apple_materials(proof, id, projection).await?
            }
            "registration" => self.agent_registration(proof, projection).await?,
            "smtp" => self.mail(proof, audit, projection).await?,
            "wns" => self.windows_push(proof, projection).await?,
            "task-key" => self.task_signing(proof, audit, projection).await?,
            "trust" | "crl" => self.pki_trust(proof, projection).await?,
            "webhook-own" => self.webhook_materials(proof, audit, projection).await?,
            _ => (),
        }
        Ok(())
    }

    fn configure_action(&self, proof: &AuthorizedPrincipal, id: &str, projection: &mut Projection) {
        use rss_mdm_authorization_service::Permission;
        let write = match id {
            "s3-key" | "storage" => Some(Permission::StorageConfigurationWrite),
            "apns-key" | "apns-cert" | "profile-key" | "profile-cert" | "managed-key"
            | "task-key" | "wns" | "smtp" => Some(Permission::RegistrationConfigurationWrite),
            "registration" => Some(Permission::AgentEnrollmentWrite),
            "ade-key" | "ade-token" | "apple-account" => {
                Some(Permission::RegistrationConfigurationWrite)
            }
            "agent-package" => Some(Permission::SoftwareWrite),
            "webhook-own" => Some(Permission::WebhookWrite),
            "oidc" => Some(Permission::IdentityProvidersManage),
            "user-attributes" => Some(Permission::UserAttributeDefinitionsWrite),
            _ => None,
        };
        let recent = self
            .clock
            .unix_seconds()
            .ok()
            .is_some_and(|now| proof.recently_authenticated(now, 300).unwrap_or(false));
        if (recent || id == "user-attributes")
            && write.is_some_and(|permission| proof.require(permission, None).is_ok())
            && let Some(entry) = projection.actions.first()
        {
            projection.actions.push(model::Action {
                name: "configure",
                href: entry.href.clone(),
            });
        }
    }

    async fn user_attributes(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        audit: &RequestAudit,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        match self.user_profiles.configured_count(proof, audit).await {
            Ok(count) => {
                configured(projection, count);
                projection.ready = true;
            }
            Err(error) => unavailable(projection, error)?,
        }
        Ok(())
    }

    async fn tenant_registry(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        if let Some(service) = &self.tenant_administration {
            match service.summary(proof).await {
                Ok(value) => {
                    configured(
                        projection,
                        value["count"].as_u64().ok_or(Error::Malformed)? as usize,
                    );
                }
                Err(crate::Error::Forbidden | crate::Error::Unauthorized) => {
                    return Err(Error::Forbidden);
                }
                Err(_) => {
                    projection.status = Status::Unavailable;
                    projection.reason = Some("tenant_registry_read_unavailable");
                }
            }
        } else {
            configured(projection, 0);
        }
        Ok(())
    }

    async fn ca_custody(
        &self,
        proof: &AuthorizedPrincipal,
        id: &str,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        projection.reason = Some("external_ca_custody_requires_deployment_operator_observation");
        let mut count = 0;
        for trust in self
            .pki
            .trusts(proof.binding())
            .await
            .map_err(|_| Error::Unavailable(crate::Failure::Database))?
        {
            if matches!(id, "scep-decrypter" | "ca-webhook")
                && !matches!(
                    trust.purpose,
                    rss_mdm_agent_wire::pki::Purpose::Apple
                        | rss_mdm_agent_wire::pki::Purpose::AgentBootstrap
                )
            {
                continue;
            }
            count += trust.issuers.len();
        }
        projection.configured_count = Some(count);
        if count == 0 {
            projection.status = Status::Unconfigured;
        }
        Ok(())
    }

    async fn recovery_material(
        &self,
        proof: &AuthorizedPrincipal,
        id: &str,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        let Some(protection) = &self.recovery else {
            configured(projection, 0);
            return Ok(());
        };
        let tenant = uuid::Uuid::parse_str(proof.tenant_id()).map_err(|_| Error::Malformed)?;
        let budget =
            rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(6));
        let selected = self
            .audit
            .read(
                proof.binding().tenant(),
                &budget.control(),
                tenant,
                |tenant, tx| {
                    Box::pin(async move {
                        tx.with_connection_context(tenant, |tenant, c| {
                            Box::pin(async move {
                                match rss_mdm_recovery_credentials::Protection::selected_id_on(
                                    rss_mdm_install_support::StorageProfile::Mdm,
                                    c,
                                    *tenant,
                                )
                                .await
                                {
                                    Ok(value) => Ok(Some(value)),
                                    Err(rss_mdm_recovery_credentials::Error::Configuration) => {
                                        Ok(None)
                                    }
                                    Err(_) => Err(Error::Unavailable(crate::Failure::Database)),
                                }
                            })
                        })
                        .await
                    })
                },
            )
            .await
            .fold(
                Ok,
                |_| Err(Error::Unavailable(crate::Failure::Database)),
                |_| Err(Error::Unavailable(crate::Failure::Database)),
                |_| Err(Error::RollbackFailed),
                |_| Err(Error::CommitUnknown),
                |_| Err(Error::Unavailable(crate::Failure::Database)),
            )?;
        let Some(selected) = selected else {
            configured(projection, 0);
            return Ok(());
        };
        configured(projection, 1);
        projection.ready = protection.recipient(&selected).is_ok_and(|recipient| {
            id != "recovery-rsa"
                || self
                    .clock
                    .unix_seconds()
                    .is_ok_and(|now| recipient.require_current(now).is_ok())
        });
        projection.status = if projection.ready {
            Status::Loaded
        } else {
            Status::Unavailable
        };
        projection.reason = Some("current_material_not_device_escrow_confirmation");
        Ok(())
    }

    async fn identity_providers(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        continuation: &rss_mdm_authorization_service::credential::RequestCredential,
        projection: &mut Projection,
        cutoff: rss_request_context::Deadline,
    ) -> Result<(), Error> {
        if let Some(federation) = &self.federation {
            use rss_mdm_authorization_service::credential::RequestCredential;
            let credential = continuation.duplicate()?;
            let session = match credential {
                RequestCredential::Cookie(secret) => {
                    self.identity
                        .inspect_session(
                            proof.binding(),
                            secret,
                            rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                                cutoff,
                                &crate::lifecycle::RuntimeTimer,
                            ),
                        )
                        .await
                }
                RequestCredential::Bearer(secret) => {
                    self.identity
                        .inspect_bearer(
                            proof.binding(),
                            secret,
                            rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                                cutoff,
                                &crate::lifecycle::RuntimeTimer,
                            ),
                        )
                        .await
                }
                RequestCredential::ApiKey(_) => return Err(Error::Forbidden),
            }
            .map_err(crate::identity::failure)?;
            if session.account() != proof.session()?.account()
                || session.view().id != proof.session()?.view().id
            {
                return Err(Error::Forbidden);
            }
            projection.actions.push(model::Action {
                name: "inspect",
                href: format!("/api/v1/identity/tenants/{}/providers", proof.tenant_id()),
            });
            match federation
                .list_providers(
                    session,
                    rss_transactional_messaging::policy::OperationDeadline::from_cutoff(
                        cutoff,
                        &crate::lifecycle::RuntimeTimer,
                    ),
                )
                .await
            {
                Ok(providers) => {
                    configured(projection, providers.len());
                    projection.ready = providers.iter().any(|p| p.enabled);
                }
                Err(rss_identity_postgres::AuthorityError::Rejected) => {
                    return Err(Error::Forbidden);
                }
                Err(_) => {
                    projection.status = Status::Unavailable;
                    projection.reason = Some("identity_read_unavailable");
                }
            }
        } else {
            configured(projection, 0);
        }
        Ok(())
    }

    async fn apple_organizations(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        id: &str,
        organizations: &mut Option<serde_json::Value>,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        if organizations.is_none() {
            let apple = self.apple.apple(proof.binding()).await.ok();
            *organizations = Some(
                match rss_mdm_apple_channel::management_query::summary(
                    &self.apple_store,
                    apple.as_deref(),
                    &crate::clock::InventoryClock(self.clock.clone()),
                    proof,
                )
                .await
                {
                    Ok(value) => value,
                    Err(
                        rss_mdm_apple_channel::Error::Forbidden
                        | rss_mdm_apple_channel::Error::Unauthorized,
                    ) => return Err(Error::Forbidden),
                    Err(_) => serde_json::json!({"unavailable":true,"items":[]}),
                },
            );
        }
        if organizations
            .as_ref()
            .is_some_and(|v| v["unavailable"] == true)
        {
            projection.status = Status::Unavailable;
            projection.reason = Some("apple_owner_read_unavailable");
            return Ok(());
        }
        let summary = &organizations.as_ref().ok_or(Error::Malformed)?[if id == "apple-account" {
            "account"
        } else {
            "ade"
        }];
        let count = summary["count"].as_u64().ok_or(Error::Malformed)? as usize;
        configured(projection, count);
        let unavailable = if id == "ade-key" {
            0
        } else {
            summary["unavailable"].as_u64().ok_or(Error::Malformed)?
        };
        let pending = if id == "ade-key" {
            0
        } else {
            summary["pending"].as_u64().ok_or(Error::Malformed)?
        };
        if unavailable > 0 {
            projection.status = Status::Unavailable;
        } else if pending > 0 {
            projection.status = Status::Pending;
        }
        projection.reason = Some("external_organization_and_device_confirmation_separate");
        projection.ready = if id == "ade-key" {
            count > 0
        } else {
            summary["ready"] == true
                && (id == "apple-account" || (unavailable == 0 && pending == 0))
        };
        projection.actions.push(model::Action {
            name: "inspect",
            href: format!("/api/v1/tenants/{}/apple/organizations", proof.tenant_id()),
        });
        Ok(())
    }

    async fn agent_packages(
        &self,
        proof: &AuthorizedPrincipal,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        match rss_mdm_software_service::agent_packages::list(
            &self.software_runtime,
            proof.binding(),
        )
        .await
        {
            Ok(packages) => {
                configured(projection, packages.len());
                projection.ready = !packages.is_empty();
                projection.reason = Some("published_packages_not_device_installation_confirmation");
            }
            Err(error) => unavailable(projection, error.into())?,
        }
        Ok(())
    }

    async fn content_storage(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        audit: &RequestAudit,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        let authority = rss_mdm_content_service::connections::authority::Authority {
            protection: self.protection.clone(),
            audit: self.audit.clone(),
            content: self.content.clone(),
        };
        let observed = async {
            let loaded = match &self.content {
                Some(store) => store
                    .active_s3_revision(proof.binding())
                    .await
                    .map_err(Error::from)?,
                None => None,
            };
            let directory = authority.read(proof, audit).await.map_err(Error::from)?;
            Ok::<_, Error>((loaded, directory))
        }
        .await;
        match observed {
            Ok((loaded, directory)) => {
                projection.revision = Some(directory.revision);
                projection.desired_revision = directory.active_revision;
                configured(projection, directory.version_count as usize);
                let now = self.clock.unix_seconds().ok();
                projection.applied_revision = loaded;
                if let Some(loaded) = loaded {
                    let valid = directory.applied.as_ref().is_some_and(|v| {
                        v.revision == loaded
                            && !v.revoked
                            && v.expires_at
                                .is_none_or(|expires| now.is_some_and(|t| t < expires))
                    });
                    projection.ready = valid && Some(loaded) == directory.active_revision;
                    projection.status = if !valid {
                        Status::Unavailable
                    } else if Some(loaded) == directory.active_revision {
                        Status::Loaded
                    } else {
                        Status::Pending
                    };
                    projection.reason = Some(if !valid {
                        "applied_material_unusable"
                    } else {
                        "current_process_loaded_not_provider_requalification"
                    });
                } else if directory.active_revision.is_some() {
                    projection.status = Status::Pending;
                    projection.reason = Some("host_application_observation_required");
                }
            }
            Err(error) => unavailable(projection, error)?,
        }
        Ok(())
    }

    async fn apple_materials(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        id: &str,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        use rss_mdm_apple_channel::runtime_materials::{Purpose, directory};
        let purpose = match id {
            "apns-key" | "apns-cert" => Purpose::Apns,
            "profile-key" | "profile-cert" => Purpose::Profile,
            _ => Purpose::ManagedAccount,
        };
        let loaded_materials = self
            .apple
            .apple(proof.binding())
            .await
            .ok()
            .map(|apple| apple.material_selection());
        let loaded_versions: Vec<i64> = loaded_materials
            .as_ref()
            .map(|v| match purpose {
                Purpose::Apns => v.apns.into_iter().collect(),
                Purpose::Profile => v.profile.into_iter().collect(),
                Purpose::ManagedAccount => v.accounts.values().copied().collect(),
            })
            .unwrap_or_default();
        match directory(
            &self.apple_store,
            proof.binding().tenant(),
            proof,
            purpose,
            &loaded_versions,
        )
        .await
        {
            Ok(value) => {
                projection.revision = Some(value.revision);
                projection.desired_revision = value.desired_revision;
                configured(
                    projection,
                    usize::try_from(value.version_count).map_err(|_| Error::Malformed)?,
                );
                if purpose == Purpose::ManagedAccount {
                    let desired = &value.account_bindings;
                    let loaded = loaded_materials
                        .as_ref()
                        .map(|materials| &materials.accounts);
                    projection.desired_revision = None;
                    projection.applied_revision = None;
                    projection.status = account_material_status(
                        &value,
                        desired,
                        loaded,
                        self.clock.unix_seconds().ok(),
                    )?;
                    projection.ready = matches!(projection.status, Status::Loaded);
                    projection.reason = Some(match projection.status {
                        Status::Unavailable => "bound_account_material_unusable",
                        Status::Pending => "host_application_observation_required",
                        _ => "current_process_loaded_not_device_confirmation",
                    });
                } else {
                    let loaded = loaded_materials
                        .as_ref()
                        .and_then(|materials| match purpose {
                            Purpose::Apns => materials.apns,
                            Purpose::Profile => materials.profile,
                            Purpose::ManagedAccount => None,
                        });
                    projection.applied_revision = loaded;
                    if let Some(revision) = loaded {
                        let selected = value.materials.get(&revision);
                        let now = self.clock.unix_seconds().ok();
                        let usable = selected.is_some_and(|v| {
                            !v.revoked
                                && v.expires_at
                                    .is_some_and(|expires| now.is_some_and(|t| t < expires))
                        });
                        projection.ready = usable && Some(revision) == projection.desired_revision;
                        projection.status = if !usable {
                            Status::Unavailable
                        } else if Some(revision) == projection.desired_revision {
                            Status::Loaded
                        } else {
                            Status::Pending
                        };
                        projection.reason = Some(if usable {
                            "current_process_loaded_not_device_confirmation"
                        } else {
                            "applied_material_unusable"
                        });
                    } else if projection.desired_revision.is_some() {
                        projection.status = Status::Pending;
                        projection.reason = Some("host_application_observation_required");
                    }
                }
            }
            Err(rss_mdm_apple_channel::Error::Forbidden) => {
                return Err(Error::Forbidden);
            }
            Err(_) => {
                projection.status = Status::Unavailable;
                projection.reason = Some("apple_material_read_unavailable");
            }
        }
        Ok(())
    }

    async fn agent_registration(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        if let Some(service) = &self.registration {
            match service.settings(proof).await {
                Ok(settings) => {
                    configured(projection, settings.values.platforms.len());
                    projection.revision = i64::try_from(settings.revision).ok();
                    projection.ready = !settings.values.platforms.is_empty();
                }
                Err(error) => {
                    use rss_mdm_agent_wire::enroll::ErrorCode;
                    if matches!(
                        error.code,
                        ErrorCode::PermissionDenied | ErrorCode::InvalidIdentity
                    ) {
                        return Err(Error::Forbidden);
                    }
                    projection.status = Status::Unavailable;
                    projection.reason = Some("registration_read_unavailable");
                }
            }
        } else {
            configured(projection, 0);
        }
        Ok(())
    }

    async fn mail(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        audit: &RequestAudit,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        let service = rss_mdm_mail_service::authority::Authority {
            protection: self.protection.clone(),
            audit: self.audit.clone(),
        };
        match service.read(proof, audit).await {
            Ok(value) => {
                configured(projection, value.version_count as usize);
                projection.revision = Some(value.revision);
                projection.applied_revision = value.selected_revision;
                if value.selected_revision.is_none() && value.latest.is_some() {
                    projection.status = if value.latest.as_ref().ok_or(Error::Malformed)?.state
                        == rss_mdm_mail_service::store::State::Pending
                    {
                        Status::Pending
                    } else {
                        Status::Unavailable
                    };
                }
                projection.ready = value.selected_revision.is_some_and(|selected| {
                    value.current.as_ref().is_some_and(|v| {
                        v.revision == selected
                            && v.state == rss_mdm_mail_service::store::State::Accepted
                    })
                });
                projection.reason = Some("smtp_acceptance_is_not_recipient_delivery");
            }
            Err(error) => unavailable(projection, error.into())?,
        }
        Ok(())
    }

    async fn windows_push(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        let applied = self
            .windows_runtime
            .windows(proof.binding())
            .await
            .ok()
            .and_then(|windows| {
                windows
                    .push
                    .as_ref()
                    .and_then(|push| push.material_revision())
            });
        match rss_mdm_windows_channel::wns_materials::snapshot(&self.windows, proof, applied).await
        {
            Ok(values) => {
                configured(projection, values.version_count as usize);
                projection.revision = Some(values.revision);
                projection.desired_revision = values.desired_revision;
                projection.applied_revision = applied;
                if let Some(applied) = projection.applied_revision {
                    let valid = values.applied.as_ref().is_some_and(|v| {
                        v.revision == applied
                            && v.selected
                            && !v.revoked
                            && v.qualified_at.is_some()
                    });
                    projection.ready = valid && Some(applied) == values.desired_revision;
                    projection.status = if valid {
                        Status::Loaded
                    } else {
                        Status::Unavailable
                    };
                } else if values.version_count > 0 {
                    projection.status = Status::Pending;
                }
                projection.reason = Some("oauth_qualification_is_not_device_delivery");
            }
            Err(rss_mdm_windows_channel::Error::Forbidden) => {
                return Err(Error::Forbidden);
            }
            Err(_) => {
                projection.status = Status::Unavailable;
                projection.reason = Some("windows_material_read_unavailable");
            }
        }
        Ok(())
    }

    async fn task_signing(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        audit: &RequestAudit,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        match rss_mdm_task_trust::service::read_task_trust(
            rss_mdm_install_support::StorageProfile::Mdm,
            rss_mdm_task_trust::Use::AgentTask,
            &self.audit,
            proof.binding().tenant(),
            proof,
            audit,
            None,
        )
        .await
        {
            Ok(trust) => {
                configured(projection, trust.keys.len());
                projection.revision = i64::try_from(trust.revision).ok();
                projection.ready = self
                    .task_trust
                    .signing_material(proof.binding())
                    .await
                    .map_err(Error::from)?
                    .as_ref()
                    .is_some_and(|(id, revision)| {
                        if *revision != trust.revision {
                            return false;
                        }
                        trust.keys.iter().any(|k| {
                            k.id == *id
                                && k.state == rss_mdm_agent_wire::task_trust::KeyState::Active
                        })
                    });
                projection.reason = Some("device_acknowledgements_gate_activation");
            }
            Err(error) => unavailable(projection, error.into())?,
        }
        Ok(())
    }

    async fn pki_trust(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        let trusts = self
            .pki
            .trusts(proof.binding())
            .await
            .map_err(|_| Error::Unavailable(crate::Failure::Database))?;
        configured(projection, trusts.len());
        projection.reason = Some("device_distribution_and_crl_publication_are_separate");
        for trust in trusts {
            if trust.tenant.to_string() != proof.tenant_id() {
                return Err(Error::Forbidden);
            }
            projection.actions.push(model::Action {
                name: "inspect",
                href: format!(
                    "/api/v1/tenants/{}/pki/{}/trust",
                    proof.tenant_id(),
                    rss_mdm_pki_service::registry::purpose(trust.purpose)
                ),
            });
        }
        Ok(())
    }

    async fn webhook_materials(
        &self,
        proof: &Arc<AuthorizedPrincipal>,
        audit: &RequestAudit,
        projection: &mut Projection,
    ) -> Result<(), Error> {
        use rss_mdm_webhook_service::management::Command;
        match self
            .webhooks
            .execute(proof.clone(), audit.clone(), Command::Materials)
            .await
        {
            Ok(value) => {
                let value = value.materials().map_err(Error::from)?;
                let heads = &value.keys.heads;
                let materials = &value.keys.materials;
                configured(projection, heads.len());
                if heads.iter().any(|head| head.active_revision.is_none()) {
                    projection.status = Status::Pending;
                }
                if heads.iter().any(|head| {
                    materials.iter().any(|material| {
                        material.reference == head.reference
                            && Some(material.revision) == head.active_revision
                            && material.revoked
                    })
                }) {
                    projection.status = Status::Unavailable;
                }
                projection.ready = !heads.is_empty()
                    && heads.iter().all(|head| {
                        materials.iter().any(|m| {
                            m.reference == head.reference
                                && Some(m.revision) == head.active_revision
                                && !m.revoked
                                && m.confirmed
                        })
                    });
                projection.reason =
                    Some("receiver_key_possession_is_not_business_delivery_confirmation");
                projection.actions.push(model::Action {
                    name: "subscriptions",
                    href: format!(
                        "/api/v1/tenants/{}/webhooks/subscriptions",
                        proof.tenant_id()
                    ),
                });
            }
            Err(error) => unavailable(projection, error.into())?,
        }
        Ok(())
    }
}

fn account_material_status(
    value: &rss_mdm_apple_channel::runtime_materials::Directory,
    desired: &BTreeMap<String, i64>,
    loaded: Option<&BTreeMap<String, i64>>,
    now: Option<i64>,
) -> Result<Status, Error> {
    let materials = &value.materials;
    let usable = |revision: &i64| {
        materials.get(revision).is_some_and(|v| {
            !v.revoked
                && v.expires_at
                    .is_some_and(|expires| now.is_some_and(|now| now < expires))
        })
    };
    if desired.values().any(|r| !usable(r))
        || loaded.is_some_and(|m| m.values().any(|r| !usable(r)))
    {
        return Ok(Status::Unavailable);
    }
    Ok(if loaded == Some(desired) && !desired.is_empty() {
        Status::Loaded
    } else if !desired.is_empty() || loaded.is_some_and(|m| !m.is_empty()) {
        Status::Pending
    } else if value.version_count == 0 {
        Status::Unconfigured
    } else {
        Status::Configured
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_bindings_require_exact_loaded_set_and_current_materials() {
        use rss_mdm_apple_channel::runtime_materials::{
            Directory, PublicVersion, RuntimeObservation,
        };
        let version = |revision, expires_at| PublicVersion {
            revision,
            key_id: uuid::Uuid::nil(),
            public_key_digest: "public".into(),
            csr: "csr".into(),
            certificate_chain_pem: None,
            certificate_digest: None,
            topic: None,
            expires_at: Some(expires_at),
            revoked: false,
        };
        let mut value = Directory {
            revision: 2,
            desired_revision: None,
            version_count: 2,
            materials: BTreeMap::from([(1, version(1, 100)), (2, version(2, 200))]),
            runtime_observation: RuntimeObservation::Separate,
            account_bindings: BTreeMap::new(),
        };
        let selected = BTreeMap::from([("org.example".into(), 1), ("second".into(), 2)]);
        assert!(matches!(
            account_material_status(&value, &selected, Some(&selected), Some(99)).unwrap(),
            Status::Loaded
        ));
        assert!(matches!(
            account_material_status(&value, &selected, None, Some(99)).unwrap(),
            Status::Pending
        ));
        assert!(matches!(
            account_material_status(&value, &selected, Some(&selected), Some(100)).unwrap(),
            Status::Unavailable
        ));
        value.materials.get_mut(&1).unwrap().revoked = true;
        assert!(matches!(
            account_material_status(&value, &selected, Some(&selected), Some(99)).unwrap(),
            Status::Unavailable
        ));
    }
}
