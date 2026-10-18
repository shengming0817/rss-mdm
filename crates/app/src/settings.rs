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
        "webhook-own" => "/api/v1/webhooks/subscriptions",
        "organization" | "host-config" => "/api/v1/tenant-administration/provisionings",
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
                    "oidc-state" if business => {
                        projection.status = if self.state.identity.federation.is_some() {
                            Status::Loaded
                        } else {
                            Status::Unconfigured
                        };
                        projection.reason = Some("current_process_loaded_not_provider_login");
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
                                let loaded =
                                    self.state.apple.as_ref().and_then(|apple| match purpose {
                                        Purpose::Apns => Some(apple.config.materials.apns),
                                        Purpose::Profile => Some(apple.config.materials.profile),
                                        Purpose::ManagedAccount => None,
                                    });
                                projection.applied_revision = loaded;
                                if let Some(revision) = loaded {
                                    let selected =
                                        value["versions"].as_array().and_then(|versions| {
                                            versions
                                                .iter()
                                                .find(|v| v["revision"].as_i64() == Some(revision))
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
                            .execute(proof.clone(), audit.clone(), Command::Subscriptions(None))
                            .await
                        {
                            Ok(value) => {
                                // 订阅存在不等于对端已经信任当前签名版本。
                                configured(
                                    &mut projection,
                                    value["items"].as_array().ok_or(Error::Malformed)?.len(),
                                );
                                projection.reason = Some("remote_signing_confirmation_required");
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
