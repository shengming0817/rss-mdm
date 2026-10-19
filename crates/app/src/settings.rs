//! 只读目录组合原领域公开读接口；不复制领域状态或秘密。
use rss_mdm_audit_integration::RequestAudit;
use rss_mdm_authorization_service::context::{AuthorizedPrincipal, RequestAuth};
use rss_mdm_management_http::{
    Error,
    settings::{Entry, Item, Projection, Source, Status},
};
use std::{collections::BTreeMap, sync::Arc};
pub(crate) struct Directory {
    pub state: Arc<crate::api::Assembly>,
    pub apple: Arc<rss_mdm_apple_channel::HttpState>,
}
fn route(id: &str) -> Option<&'static str> {
    Some(match id {
        "apns-key" | "apns-cert" => "/api/v1/apple/materials/apns",
        "profile-key" | "profile-cert" => "/api/v1/apple/materials/profile",
        "managed-key" => "/api/v1/apple/materials/managed_account",
        "s3-key" | "storage" => "/api/v1/storage/connections",
        "registration" => "/api/v1/agent-enrollment-settings",
        "smtp" => "/api/v1/smtp",
        "wns" => "/api/v1/windows/wns",
        "task-key" => "/api/v1/task-signing/trust",
        "agent-package" => "/api/v1/agent-packages",
        "webhook-own" => "/api/v1/webhooks/materials",
        "organization" => "/api/v1/tenant-administration/tenants",
        "host-config" => "/api/v1/tenant-administration/provisionings",
        _ => return None,
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
    if matches!(error, Error::Forbidden | Error::Unauthorized) {
        return Err(error);
    }
    projection.status = Status::Unavailable;
    projection.reason = Some("owner_read_unavailable");
    Ok(())
}
impl Source for Directory {
    fn project<'a>(
        &'a self,
        proof: Arc<AuthorizedPrincipal>,
        audit: RequestAudit,
        continuation: rss_mdm_management_http::http_operation::RequestContinuation,
        items: Vec<Item>,
    ) -> futures::future::BoxFuture<'a, Result<Vec<Entry>, Error>> {
        Box::pin(async move {
            let business = proof.tenant_id() == self.state.identity.tenant.to_string();
            if !business && proof.tenant_id() != self.state.identity.management_tenant.to_string() {
                return Err(Error::Forbidden);
            }
            proof.bind_audit(&audit)?;
            audit.set_action("settings_catalog_read");
            let mut cache = BTreeMap::<&str, Projection>::new();
            let mut result = Vec::new();
            let mut organizations: Option<serde_json::Value> = None;
            for item in items {
                proof.check_live()?;
                let href = route(item.id);
                if let Some(cached) = href.and_then(|key| cache.get(key)) {
                    result.push(Entry {
                        item,
                        projection: cached.clone(),
                    });
                    continue;
                }
                let mut projection = Projection::unknown(href);
                match item.id {
                    "entry" | "postgres" | "instance" | "native" | "operation" => {
                        projection.status = Status::Loaded;
                        projection.reason =
                            Some("current_process_loaded_not_external_qualification");
                    }
                    "organization" | "host-config" if !business => {
                        if let Some(service) = &self.state.identity.tenant_administration {
                            match service.directory(&proof, item.id == "host-config").await {
                                Ok(value) => {
                                    let values =
                                        value["items"].as_array().ok_or(Error::Malformed)?;
                                    configured(&mut projection, values.len());
                                    if item.id == "host-config" {
                                        if values.iter().any(|v| !v["result"]["blocked"].is_null())
                                        {
                                            projection.status = Status::Unavailable;
                                        } else if values
                                            .iter()
                                            .any(|v| v["result"]["phase"] != "enabled")
                                        {
                                            projection.status = Status::Pending;
                                        }
                                        projection.reason = Some(
                                            "operation_observations_not_current_process_health",
                                        );
                                    }
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
                            configured(&mut projection, 0);
                        }
                    }
                    "audit" | "ledger" => {
                        projection.status =
                            if item.id == "audit" || self.state.audit_store.uses_ledger() {
                                Status::Loaded
                            } else {
                                Status::Unconfigured
                            };
                        projection.reason = Some(if self.state.audit_store.uses_ledger() {
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
                        projection.reason =
                            Some("external_ca_custody_requires_deployment_operator_observation");
                        let mut count = 0;
                        for binding in self.state.pki.bindings() {
                            let trust = binding.public().map_err(|_| Error::Conflict)?;
                            if matches!(item.id, "scep-decrypter" | "ca-webhook")
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
                    }
                    "windows-key" => {
                        projection.status = if self.state.windows.is_some() {
                            Status::Loaded
                        } else {
                            Status::Unconfigured
                        };
                        projection.reason = Some("current_process_loaded_not_device_confirmation");
                    }
                    "recovery-key" | "recovery-rsa" if business => {
                        if let Some(protection) = self.state.execution.recovery_credentials() {
                            configured(&mut projection, 1);
                            projection.status = if item.id == "recovery-rsa"
                                && self.state.clock.unix_seconds().ok().is_none_or(|now| {
                                    protection.active_recipient().require_current(now).is_err()
                                }) {
                                Status::Unavailable
                            } else {
                                Status::Loaded
                            };
                            projection.reason =
                                Some("deployment_application_not_device_escrow_confirmation");
                        } else {
                            configured(&mut projection, 0);
                        }
                    }
                    "oidc" if business => {
                        if let Some(federation) = &self.state.identity.federation {
                            use rss_mdm_authorization_service::credential::RequestCredential;
                            let credential = continuation.secret().duplicate()?;
                            let session = match credential {
                                RequestCredential::Cookie(secret) => {
                                    self.state
                                        .identity
                                        .authority
                                        .inspect_session(
                                            self.state.identity.tenant,
                                            secret,
                                            crate::identity::deadline(),
                                        )
                                        .await
                                }
                                RequestCredential::Bearer(secret) => {
                                    self.state
                                        .identity
                                        .authority
                                        .inspect_bearer(
                                            self.state.identity.tenant,
                                            secret,
                                            crate::identity::deadline(),
                                        )
                                        .await
                                }
                                RequestCredential::ApiKey(_) => return Err(Error::Forbidden),
                            }
                            .map_err(|_| Error::Unauthorized)?;
                            if session.account() != proof.session()?.account()
                                || session.view().id != proof.session()?.view().id
                            {
                                return Err(Error::Forbidden);
                            }
                            projection
                                .actions
                                .push(rss_mdm_management_http::settings::Action {
                                    name: "inspect",
                                    href: format!(
                                        "/api/v1/identity/tenants/{}/providers",
                                        proof.tenant_id()
                                    ),
                                });
                            match federation
                                .list_providers(session, crate::identity::deadline())
                                .await
                            {
                                Ok(providers) => configured(&mut projection, providers.len()),
                                Err(rss_identity_postgres::AuthorityError::Rejected) => {
                                    return Err(Error::Forbidden);
                                }
                                Err(_) => {
                                    projection.status = Status::Unavailable;
                                    projection.reason = Some("identity_read_unavailable");
                                }
                            }
                        } else {
                            configured(&mut projection, 0);
                        }
                    }
                    "oidc-state" => {
                        projection.status = if self.state.identity.federation.is_some() {
                            Status::Loaded
                        } else {
                            Status::Unconfigured
                        };
                        projection.reason = Some("current_process_loaded_not_provider_login");
                    }
                    "ade-key" | "ade-token" | "apple-account" if business => {
                        if organizations.is_none() {
                            organizations = Some(
                                match rss_mdm_apple_channel::account_enrollment::directory(
                                    &self.apple,
                                    &proof,
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
                            result.push(Entry { item, projection });
                            continue;
                        }
                        let values = organizations
                            .as_ref()
                            .and_then(|v| v["items"].as_array())
                            .ok_or(Error::Malformed)?;
                        let mut count = 0;
                        let mut unavailable = 0;
                        let mut pending = 0;
                        for value in values {
                            let value = if item.id == "apple-account" {
                                &value["accountEnrollment"]
                            } else {
                                &value["ade"]
                            };
                            if value.is_null() {
                                continue;
                            }
                            count += 1;
                            if item.id == "ade-token" {
                                match value["tokenState"].as_str() {
                                    Some("expired" | "invalid") => unavailable += 1,
                                    Some("verified") => (),
                                    _ => pending += 1,
                                }
                            } else if item.id == "apple-account"
                                && value["enabled"] == true
                                && value["signingKeyConfigured"] != true
                            {
                                unavailable += 1;
                            }
                        }
                        configured(&mut projection, count);
                        if unavailable > 0 {
                            projection.status = Status::Unavailable;
                        } else if pending > 0 {
                            projection.status = Status::Pending;
                        }
                        projection.reason =
                            Some("external_organization_and_device_confirmation_separate");
                        projection
                            .actions
                            .push(rss_mdm_management_http::settings::Action {
                                name: "inspect",
                                href: "/api/v1/apple/organizations".into(),
                            });
                    }
                    "agent-package" if business => {
                        let access = crate::api::software_access(&self.state);
                        match rss_mdm_software_service::agent_packages::list(&access).await {
                            Ok(packages) => {
                                configured(&mut projection, packages.len());
                                projection.reason =
                                    Some("published_packages_not_device_installation_confirmation");
                            }
                            Err(error) => unavailable(&mut projection, error.into())?,
                        }
                    }
                    "s3-key" | "storage" if business => {
                        let authority =
                            rss_mdm_content_service::connections::authority::Authority {
                                tenant: self.state.identity.tenant,
                                protection: self.state.protection.clone(),
                                audit: self.state.audit_store.clone(),
                            };
                        match authority.read(&proof, &audit).await {
                            Ok(directory) => {
                                projection.revision = Some(directory.revision);
                                projection.desired_revision = directory.desired_revision;
                                configured(&mut projection, directory.versions.len());
                                let now = self.state.clock.unix_seconds().ok();
                                let loaded =
                                    self.state.content_writer.as_ref().and_then(
                                        |store| match &store.config.storage {
                                            rss_mdm_content_service::Storage::S3(value) => {
                                                i64::try_from(value.revision).ok()
                                            }
                                            _ => None,
                                        },
                                    );
                                projection.applied_revision = loaded;
                                if let Some(loaded) = loaded {
                                    let valid = directory.versions.iter().any(|v| {
                                        v.revision == loaded
                                            && v.selected
                                            && !v.revoked
                                            && v.expires_at.is_none_or(|expires| {
                                                now.is_some_and(|t| t < expires)
                                            })
                                    });
                                    projection.status = if !valid {
                                        Status::Unavailable
                                    } else if Some(loaded) == directory.desired_revision {
                                        Status::Loaded
                                    } else {
                                        Status::Pending
                                    };
                                    projection.reason = Some(if !valid {
                                        "applied_material_unusable"
                                    } else {
                                        "current_process_loaded_not_provider_requalification"
                                    });
                                } else if directory.desired_revision.is_some() {
                                    projection.status = Status::Pending;
                                    projection.reason =
                                        Some("host_application_observation_required");
                                }
                            }
                            Err(error) => unavailable(&mut projection, error.into())?,
                        }
                    }
                    "apns-key" | "apns-cert" | "profile-key" | "profile-cert" | "managed-key"
                        if business =>
                    {
                        use rss_mdm_apple_channel::runtime_materials::{Purpose, directory};
                        let purpose = match item.id {
                            "apns-key" | "apns-cert" => Purpose::Apns,
                            "profile-key" | "profile-cert" => Purpose::Profile,
                            _ => Purpose::ManagedAccount,
                        };
                        match directory(
                            &self.apple,
                            &RequestAuth {
                                proof: proof.clone(),
                            },
                            purpose,
                        )
                        .await
                        {
                            Ok(value) => {
                                projection.revision = value["revision"].as_i64();
                                projection.desired_revision = value["desiredRevision"].as_i64();
                                configured(
                                    &mut projection,
                                    value["versions"].as_array().map_or(0, Vec::len),
                                );
                                if purpose == Purpose::ManagedAccount {
                                    let desired: BTreeMap<String, i64> =
                                        serde_json::from_value(value["accountBindings"].clone())
                                            .map_err(|_| Error::Malformed)?;
                                    let loaded = self
                                        .state
                                        .apple
                                        .as_ref()
                                        .map(|apple| &apple.config.materials.accounts);
                                    projection.desired_revision = None;
                                    projection.applied_revision = None;
                                    projection.status = account_material_status(
                                        &value,
                                        &desired,
                                        loaded,
                                        self.state.clock.unix_seconds().ok(),
                                    )?;
                                    projection.reason = Some(match projection.status {
                                        Status::Unavailable => "bound_account_material_unusable",
                                        Status::Pending => "host_application_observation_required",
                                        _ => "current_process_loaded_not_device_confirmation",
                                    });
                                } else {
                                    let loaded =
                                        self.state.apple.as_ref().and_then(|apple| match purpose {
                                            Purpose::Apns => Some(apple.config.materials.apns),
                                            Purpose::Profile => {
                                                Some(apple.config.materials.profile)
                                            }
                                            Purpose::ManagedAccount => None,
                                        });
                                    projection.applied_revision = loaded;
                                    if let Some(revision) = loaded {
                                        let selected =
                                            value["versions"].as_array().and_then(|versions| {
                                                versions.iter().find(|v| {
                                                    v["revision"].as_i64() == Some(revision)
                                                })
                                            });
                                        let now = self.state.clock.unix_seconds().ok();
                                        let usable = selected.is_some_and(|v| {
                                            v["revoked"].as_bool() == Some(false)
                                                && v["expiresAt"].as_i64().is_some_and(|expires| {
                                                    now.is_some_and(|t| t < expires)
                                                })
                                        });
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
                                        projection.reason =
                                            Some("host_application_observation_required");
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
                    }
                    "registration" if business => {
                        if let Some(service) = &self.state.agent_enrollment {
                            match service.settings(&proof).await {
                                Ok(settings) => {
                                    configured(&mut projection, settings.values.platforms.len());
                                    projection.revision = i64::try_from(settings.revision).ok();
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
                            configured(&mut projection, 0);
                        }
                    }
                    "smtp" if business => {
                        let service = rss_mdm_mail_service::authority::Authority {
                            tenant: self.state.identity.tenant,
                            protection: self.state.protection.clone(),
                            audit: self.state.audit_store.clone(),
                        };
                        match service.read(&proof, &audit).await {
                            Ok(value) => {
                                configured(&mut projection, value.versions.len());
                                projection.revision = Some(value.revision);
                                projection.applied_revision = value.selected_revision;
                                if value.selected_revision.is_none() && !value.versions.is_empty() {
                                    projection.status = if value.versions[0].state
                                        == rss_mdm_mail_service::store::State::Pending
                                    {
                                        Status::Pending
                                    } else {
                                        Status::Unavailable
                                    };
                                }
                                projection.reason =
                                    Some("smtp_acceptance_is_not_recipient_delivery");
                            }
                            Err(error) => unavailable(&mut projection, error.into())?,
                        }
                    }
                    "wns" if business => {
                        match rss_mdm_windows_channel::wns_materials::snapshot(
                            &self.state.access.windows_store(),
                            &proof,
                        )
                        .await
                        {
                            Ok(values) => {
                                configured(&mut projection, values.versions.len());
                                projection.revision = Some(values.revision);
                                projection.desired_revision = values.desired_revision;
                                projection.applied_revision = self
                                    .state
                                    .windows
                                    .as_ref()
                                    .and_then(|w| w.config.push.as_ref().map(|p| p.revision));
                                if let Some(applied) = projection.applied_revision {
                                    let valid = values.versions.iter().any(|v| {
                                        v.revision == applied
                                            && v.selected
                                            && !v.revoked
                                            && v.qualified_at.is_some()
                                    });
                                    projection.status = if valid {
                                        Status::Loaded
                                    } else {
                                        Status::Unavailable
                                    };
                                } else if !values.versions.is_empty() {
                                    projection.status = Status::Pending;
                                }
                                projection.reason =
                                    Some("oauth_qualification_is_not_device_delivery");
                            }
                            Err(rss_mdm_windows_channel::Error::Forbidden) => {
                                return Err(Error::Forbidden);
                            }
                            Err(_) => {
                                projection.status = Status::Unavailable;
                                projection.reason = Some("windows_material_read_unavailable");
                            }
                        }
                    }
                    "task-key" if business => {
                        match self.state.execution.task_trust(&proof, &audit).await {
                            Ok(trust) => {
                                configured(&mut projection, trust.keys.len());
                                projection.revision = i64::try_from(trust.revision).ok();
                                projection.reason = Some("device_acknowledgements_gate_activation");
                            }
                            Err(error) => unavailable(&mut projection, error.into())?,
                        }
                    }
                    "trust" | "crl" if business => {
                        let trusts = self.state.pki.bindings();
                        configured(&mut projection, trusts.len());
                        projection.reason =
                            Some("device_distribution_and_crl_publication_are_separate");
                        for binding in trusts {
                            let trust = binding.public().map_err(|_| Error::Conflict)?;
                            if trust.tenant.to_string() != proof.tenant_id() {
                                return Err(Error::Forbidden);
                            }
                            projection
                                .actions
                                .push(rss_mdm_management_http::settings::Action {
                                    name: "inspect",
                                    href: format!(
                                        "/api/v1/pki/{}/trust",
                                        rss_mdm_pki_service::registry::purpose(trust.purpose)
                                    ),
                                });
                        }
                    }
                    "webhook-own" if business => {
                        use rss_mdm_management_http::webhooks::{Command, Source};
                        match self
                            .state
                            .webhooks
                            .execute(proof.clone(), audit.clone(), Command::Materials)
                            .await
                        {
                            Ok(value) => {
                                let heads =
                                    value["keys"]["heads"].as_array().ok_or(Error::Malformed)?;
                                let materials = value["keys"]["materials"]
                                    .as_array()
                                    .ok_or(Error::Malformed)?;
                                configured(&mut projection, heads.len());
                                if heads.iter().any(|head| head["activeRevision"].is_null()) {
                                    projection.status = Status::Pending;
                                }
                                if heads.iter().any(|head| {
                                    materials.iter().any(|material| {
                                        material["reference"] == head["reference"]
                                            && material["revision"] == head["activeRevision"]
                                            && material["revoked"] == true
                                    })
                                }) {
                                    projection.status = Status::Unavailable;
                                }
                                projection.reason = Some(
                                    "receiver_key_possession_is_not_business_delivery_confirmation",
                                );
                                projection.actions.push(
                                    rss_mdm_management_http::settings::Action {
                                        name: "subscriptions",
                                        href: "/api/v1/webhooks/subscriptions".into(),
                                    },
                                );
                            }
                            Err(error) => unavailable(&mut projection, error)?,
                        }
                    }
                    _ => (),
                }
                use rss_mdm_authorization_service::Permission;
                let write = match item.id {
                    "s3-key" | "storage" => Some(Permission::StorageConfigurationWrite),
                    "apns-key" | "apns-cert" | "profile-key" | "profile-cert" | "managed-key"
                    | "task-key" | "wns" | "smtp" => {
                        Some(Permission::RegistrationConfigurationWrite)
                    }
                    "registration" => Some(Permission::AgentEnrollmentWrite),
                    "ade-key" | "ade-token" | "apple-account" => {
                        Some(Permission::RegistrationConfigurationWrite)
                    }
                    "agent-package" => Some(Permission::SoftwareWrite),
                    "webhook-own" => Some(Permission::WebhookWrite),
                    "oidc" => Some(Permission::IdentityProvidersManage),
                    _ => None,
                };
                let recent = proof.session().ok().is_some_and(|session| {
                    self.state.clock.unix_seconds().ok().is_some_and(|now| {
                        session.view().auth_time <= now && now - session.view().auth_time <= 300
                    })
                });
                if recent
                    && write.is_some_and(|permission| proof.require(permission, None).is_ok())
                    && let Some(entry) = projection.actions.first()
                {
                    projection
                        .actions
                        .push(rss_mdm_management_http::settings::Action {
                            name: "configure",
                            href: entry.href.clone(),
                        });
                }
                if let Some(href) = href {
                    cache.insert(href, projection.clone());
                }
                result.push(Entry { item, projection });
            }
            proof.check_live()?;
            Ok(result)
        })
    }
}

fn account_material_status(
    value: &serde_json::Value,
    desired: &BTreeMap<String, i64>,
    loaded: Option<&BTreeMap<String, i64>>,
    now: Option<i64>,
) -> Result<Status, Error> {
    let versions = value["versions"].as_array().ok_or(Error::Malformed)?;
    let usable = |revision: &i64| {
        versions
            .iter()
            .find(|v| v["revision"].as_i64() == Some(*revision))
            .is_some_and(|v| {
                v["revoked"] == false
                    && v["expiresAt"]
                        .as_i64()
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
    } else if versions.is_empty() {
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
        let mut value = serde_json::json!({"versions":[{"revision":1,"expiresAt":100,"revoked":false},{"revision":2,"expiresAt":200,"revoked":false}]});
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
        value["versions"][0]["revoked"] = serde_json::json!(true);
        assert!(matches!(
            account_material_status(&value, &selected, Some(&selected), Some(99)).unwrap(),
            Status::Unavailable
        ));
    }
}
