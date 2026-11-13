//! Native bootstrap is a child command under the frozen installation authority.
//! ref: Microsoft ClientCertificateInstall CSP; Apple com.apple.security.scep payload.
use super::{authority::Authority, *};
use crate::agent::bootstrap::Deployment;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
fn task(
    d: &Deployment,
    platform: rss_mdm_policy::Platform,
    installation: Uuid,
    id: Uuid,
    secret: &str,
) -> std::result::Result<Task, Error> {
    match platform {
        rss_mdm_policy::Platform::Windows => {
            use rss_mdm_windows_mdm::native::{Execution, Request, Value, Verb};
            let root = "./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/*";
            let node = |suffix: &str, value: Option<Value>, operation: Verb| Request::Node {
                node: format!("{root}{suffix}"),
                instance: vec![id.to_string()],
                operation,
                value,
            };
            let mut operations = vec![node("", None, Verb::Add)];
            for (name, value) in [
                ("ServerURL", Value::Text(d.scep_url.clone())),
                ("Challenge", Value::Text(STANDARD.encode(secret.as_bytes()))),
                (
                    "SubjectName",
                    Value::Text(rss_mdm_certificate::bootstrap::subject(installation, id)),
                ),
                ("KeyLength", Value::Integer(2048)),
                ("KeyUsage", Value::Integer(128)),
                ("KeyProtection", Value::Integer(3)),
                ("HashAlgorithm", Value::Text("SHA-2".into())),
                ("EKUMapping", Value::Text("1.3.6.1.5.5.7.3.2".into())),
                ("CAThumbprint", Value::Text(d.root_thumbprint.clone())),
            ] {
                operations.push(node(&format!("/Install/{name}"), Some(value), Verb::Add));
            }
            operations.push(node("/Install/Enroll", None, Verb::Exec));
            Ok(Task::Windows {
                request: Execution::SyncMl {
                    request: Request::Atomic { operations },
                },
            })
        }
        rss_mdm_policy::Platform::Macos => {
            use plist::Value;
            use rss_mdm_apple_mdm::{
                native::{
                    input::Fields,
                    profiles::{PayloadInput, ProfileInput},
                    request::Request,
                },
                protocol::dictionary,
            };
            let subject = Value::Array(vec![
                Value::Array(vec![Value::Array(vec![
                    "CN".into(),
                    rss_mdm_certificate::apple::subject(installation, id).into(),
                ])]),
                Value::Array(vec![Value::Array(vec![
                    "OU".into(),
                    rss_mdm_certificate::bootstrap::PURPOSE.into(),
                ])]),
            ]);
            let content = dictionary([
                ("URL", d.scep_url.clone().into()),
                ("Name", d.provisioner.clone().into()),
                ("Challenge", secret.into()),
                ("Subject", subject),
                ("Key Type", "RSA".into()),
                ("Keysize", 2048.into()),
                ("Key Usage", 1.into()),
                ("KeyIsExtractable", false.into()),
                // macOS otherwise restricts this SCEP key to Apple processes. This
                // dedicated, short-lived bootstrap identity is never a runtime MDM key.
                ("AllowAllAppsAccess", true.into()),
            ]);
            let fields = Fields::from_plist(&dictionary([("PayloadContent", content.into())]))
                .map_err(|_| Error::Malformed)?;
            let identifier = format!("com.rss-mdm.agent.bootstrap.{id}");
            Ok(Task::Macos {
                request: Request::InstallProfile {
                    profile: ProfileInput {
                        identifier: identifier.clone(),
                        uuid: id,
                        metadata: Fields::default(),
                        payloads: vec![PayloadInput {
                            schema: "mdm/profiles/com.apple.security.scep.yaml".into(),
                            identifier: format!("{identifier}.identity"),
                            uuid: Uuid::new_v4(),
                            metadata: Fields::default(),
                            fields,
                        }],
                    },
                },
            })
        }
    }
}

/// The cleanup authority permits exactly this bootstrap object's native removal.
pub(crate) fn cleanup_task(platform: rss_mdm_policy::Platform, id: Uuid) -> Task {
    match platform {
        rss_mdm_policy::Platform::Windows => Task::Windows {
            request: rss_mdm_windows_mdm::native::Execution::SyncMl {
                request: rss_mdm_windows_mdm::native::Request::Atomic {
                    operations: vec![rss_mdm_windows_mdm::native::Request::Node {
                        node: "./Device/Vendor/MSFT/ClientCertificateInstall/SCEP/*".into(),
                        instance: vec![id.to_string()],
                        operation: rss_mdm_windows_mdm::native::Verb::Delete,
                        value: None,
                    }],
                },
            },
        },
        rss_mdm_policy::Platform::Macos => Task::Macos {
            request: rss_mdm_apple_mdm::native::request::Request::RemoveProfile {
                identifier: format!("com.rss-mdm.agent.bootstrap.{id}"),
                uuid: id,
            },
        },
    }
}

impl Transactions {
    pub async fn queue_bootstrap_in(
        &self,
        tx: &mut PgTransaction<'_>,
        installation: Uuid,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.validate_in(tx)?;
        let tenant = self.tenant;
        let reader = self.materials.installations.clone();
        let frozen = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(reader.authorized_on(c, tenant, installation).await) })
            })
            .await??;
        // The installation reader retains Registration's endpoint fence through settlement.
        // It serializes the absent bootstrap row as well as the original native command.
        let existing=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_as::<_,(serde_json::Value,Uuid)>("SELECT installation_facts,delivery FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND installation=$2 AND active FOR UPDATE").bind(tenant.to_string()).bind(installation).fetch_optional(c).await
        })).await?;
        if let Some((facts, delivery)) = existing {
            let previous: Installation = stored(serde_json::from_value(facts))?;
            if previous != frozen {
                return Err(Error::Conflict.into());
            }
            // The bootstrap and its native command were committed by the same original transaction.
            let op = storage::load(tx, &self.protection, delivery).await?;
            if op.authority.installation() != &frozen {
                return Err(Error::Unavailable(Failure::CommandInvariant).into());
            }
            return Ok(());
        }
        let endpoints = self
            .materials
            .endpoints
            .as_ref()
            .ok_or(Error::Unsupported)?;
        let trust = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    Ok(rss_mdm_pki_service::registry::trust_on(
                        rss_mdm_install_support::StorageProfile::Mdm,
                        c,
                        tenant,
                        rss_mdm_agent_wire::pki::Purpose::AgentBootstrap,
                    )
                    .await)
                })
            })
            .await??;
        let deployment = Deployment::select(trust, endpoints, storage::now(tx).await?)
            .map_err(|_| Error::Unsupported)?;
        let id = Uuid::new_v4();
        let delivery = Uuid::new_v4();
        let mut random = [0u8; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| Error::Malformed)?;
        let secret = zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(random));
        let task = task(&deployment, frozen.platform, installation, id, &secret)?;
        let registration = frozen.device;
        let source = frozen.source;
        let release = frozen.release;
        let deadline = frozen.deadline;
        let issuer = deployment.issuer.clone();
        let provisioner = deployment.provisioner.clone();
        let challenge = Sha256::digest(secret.as_bytes()).to_vec();
        let download_origin = frozen.download_origin.clone();
        let facts = checked_input(serde_json::to_value(&frozen))?;
        tx.with_connection(move|c|Box::pin(async move {
            let credential:Uuid=sqlx::query_scalar("SELECT id FROM mdm_access.credentials WHERE tenant_id = CAST($1 AS uuid) AND device = $2 AND channel = 'mdm' AND purpose = 'primary' AND state = 'active'").bind(tenant.to_string()).bind(registration.into_uuid()).fetch_one(&mut *c).await?;
            let proof=serde_json::json!({"installation":installation,"device":registration,"credential":credential,"source":source,"runtime":null,"bootstrap":id});
            sqlx::query("INSERT INTO mdm_access.agent_bootstraps(tenant_id,id,installation,installation_facts,delivery,source,release,issuer,provisioner,challenge,deadline,download_origin,state) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'prepared')").bind(tenant.to_string()).bind(id).bind(installation).bind(facts).bind(delivery).bind(proof).bind(release).bind(issuer).bind(provisioner).bind(challenge).bind(deadline).bind(download_origin).execute(c).await?;Ok(())
        })).await?;
        let input = Create {
            operation_id: delivery,
            deadline,
            input_version: frozen.input_version.clone(),
            target: NativeTarget::Device,
            task,
        };
        let required = input.task.permissions()?;
        let device = frozen.device;
        let fingerprint = protection::fingerprint(
            &self.protection,
            tenant,
            &device,
            "agent-bootstrap-command/v1",
            &(&input, installation, id),
        )?;
        let authority = Authority::Bootstrap {
            installation: frozen,
            bootstrap: id,
            required,
        };
        self.queue_bootstrap_command_in(
            tx,
            &device,
            &input,
            authority,
            fingerprint,
            audit,
            "agent-bootstrap-policy",
        )
        .await
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "explicit owner participants and caller authority retain the borrowed connection and exact operation identity"
    )]
    async fn queue_bootstrap_command_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        input: &Create,
        authority: Authority,
        fingerprint: Vec<u8>,
        audit: &RequestAudit,
        service: &str,
    ) -> Result<()> {
        let fact = audit.transaction_copy();
        fact.identify_service(service);
        fact.operation(
            input.operation_id,
            "command_accept",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        fact.target_device(device);
        let result = self
            .queue_authorized_in(tx, device, input, authority, fingerprint, &fact)
            .await;
        fact.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result.map(|_| ())
    }
    /// An unresolved signing attempt never becomes a new bootstrap attempt.
    pub async fn recover_bootstrap_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.validate_in(tx)?;
        let now = storage::now(tx).await?;
        let tenant = tx.tenant_id();
        let device = device.to_owned();
        let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as::<_,(Uuid,Uuid)>("SELECT id,installation FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND (installation_facts->>'device')::uuid=$2 AND active AND state='issued' AND deadline<=$3 AND (installation_facts->>'deadline')::bigint>$3 ORDER BY installation").bind(tenant.to_string()).bind(device.into_uuid()).bind(now).fetch_all(c).await})).await?;
        for (id, installation) in rows {
            let reader = self.materials.installations.clone();
            let current = tx
                .with_connection(move |c| {
                    Box::pin(async move { Ok(reader.authorized_on(c, tenant, installation).await) })
                })
                .await?;
            match current {
                Ok(_) => (),
                Err(
                    crate::Error::Forbidden | crate::Error::Unauthorized | crate::Error::Conflict,
                ) => continue,
                Err(e) => return Err(e.into()),
            }
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_access.agent_bootstraps SET active=false WHERE tenant_id=$1::uuid AND id=$2 AND active AND state='issued' AND deadline<=$3").bind(tenant.to_string()).bind(id).bind(now).execute(c).await?;Ok(())})).await?;
            self.queue_bootstrap_in(tx, installation, audit).await?;
        }
        Ok(())
    }
    pub async fn cleanup_bootstrap_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &rss_mdm_agent_wire::DeviceId,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.validate_in(tx)?;
        let now = storage::now(tx).await?;
        let tenant = tx.tenant_id();
        let device = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_access.agent_bootstraps SET cleanup_complete=true WHERE tenant_id=$1::uuid AND cleanup IS NOT NULL AND NOT cleanup_complete AND mdm_registration_tasks.installation_status(cleanup)='applied'").bind(tenant.to_string()).execute(c).await?;Ok(())})).await?;
        let rows=tx.with_connection(move|c|Box::pin(async move {sqlx::query_as::<_,(Uuid,serde_json::Value)>("SELECT b.id, b.installation_facts FROM mdm_access.agent_bootstraps AS b WHERE b.tenant_id = CAST($1 AS uuid) AND (b.installation_facts ->> 'device')::uuid = $2 AND NOT b.cleanup_complete AND b.cleanup_retry_at <= $3 AND (b.cleanup IS NULL OR mdm_registration_tasks.installation_status(b.cleanup) IN ('rejected', 'cancelled', 'timed_out', 'superseded') OR EXISTS (SELECT 1 FROM mdm_registration_tasks.operations AS o WHERE o.tenant_id = b.tenant_id AND o.id = b.cleanup AND CAST(o.input_context ->> 'deadline' AS bigint) <= $3)) AND b.state IN ('issued', 'consumed') AND EXISTS (SELECT 1 FROM mdm_access.devices AS r WHERE r.tenant_id = b.tenant_id AND r.id = CAST(b.source ->> 'device' AS uuid) AND r.state = 'active') FOR UPDATE OF b").bind(tenant.to_string()).bind(device.into_uuid()).bind(now).fetch_all(c).await})).await?;
        for (id, value) in rows {
            let installation: Installation = stored(serde_json::from_value(value))?;
            let reader = self.materials.installations.clone();
            let parent = installation.id;
            let deadline = installation.deadline;
            let cleanup=tx.with_connection(move|c|Box::pin(async move {Ok(async {
                let activated:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mdm_access.certificate_grants AS g INNER JOIN mdm_access.devices AS r ON (r.tenant_id, r.certificate_grant_id) = (g.tenant_id, g.id) WHERE g.tenant_id = CAST($1 AS uuid) AND g.native_authority ->> 'installation' = CAST($2 AS text))").bind(tenant.to_string()).bind(parent).fetch_one(&mut *c).await.map_err(|_|crate::Error::Storage)?;
                Ok::<_,crate::Error>(activated || deadline<=now || reader.delivery_ended_on(c,tenant,parent).await?)
            }.await)})).await??;
            if !cleanup {
                continue;
            }
            let delivery = Uuid::new_v4();
            let input = Create {
                operation_id: delivery,
                deadline: now + 300,
                input_version: installation.input_version.clone(),
                target: NativeTarget::Device,
                task: cleanup_task(installation.platform, id),
            };
            let device = installation.device;
            let required = input.task.permissions()?;
            let fingerprint = protection::fingerprint(
                &self.protection,
                tenant,
                &device,
                "agent-bootstrap-cleanup/v1",
                &(&input, installation.id, id),
            )?;
            tx.with_connection(move|c|Box::pin(async move {sqlx::query("UPDATE mdm_access.agent_bootstraps SET cleanup=$3,cleanup_retry_at=$4 WHERE tenant_id=$1::uuid AND id=$2 AND NOT cleanup_complete").bind(tenant.to_string()).bind(id).bind(delivery).bind(now+300).execute(c).await?;Ok(())})).await?;
            let authority = Authority::Cleanup {
                installation,
                bootstrap: id,
                operation: delivery,
                required,
            };
            self.queue_bootstrap_command_in(
                tx,
                &device,
                &input,
                authority,
                fingerprint,
                audit,
                "agent-bootstrap-cleanup",
            )
            .await?;
        }
        Ok(())
    }
}
