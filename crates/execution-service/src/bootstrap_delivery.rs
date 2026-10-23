//! Native bootstrap is a child command under the frozen installation authority.
//! ref: Microsoft ClientCertificateInstall CSP; Apple com.apple.security.scep payload.
use crate::{
    authority::{AgentInstallStage, ExecutionAuthority},
    *,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::rand::{SecureRandom, SystemRandom};
use rss_mdm_registration_service::agent::bootstrap::Deployment;
use sha2::{Digest, Sha256};
impl ExecutionService {
    pub(crate) async fn queue_bootstrap_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        installation: Uuid,
        audit: &RequestAudit,
    ) -> Result<()> {
        self.inputs.admit_agent_installation_in(tx).await?;
        let endpoints = self.inputs.bootstrap.as_ref().ok_or(Error::Unsupported)?;
        let tenant = tx.tenant_id();
        // Freeze the active DB generation under the same fence used by activation and retirement.
        let body:Vec<u8>=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2639))").bind(tenant.to_string()).execute(&mut *c).await?;
            sqlx::query_scalar("SELECT body FROM mdm_pki.trust WHERE tenant_id=$1::uuid AND purpose='agent_bootstrap'").bind(tenant.to_string()).fetch_one(c).await
        })).await?;
        let trust: rss_mdm_agent_wire::pki::Trust =
            serde_json::from_slice(&body).map_err(|_| Error::Malformed)?;
        if trust.tenant.to_string() != tenant.to_string()
            || trust.purpose != rss_mdm_agent_wire::pki::Purpose::AgentBootstrap
        {
            return Err(Error::Forbidden.into());
        }
        let deployment = Deployment::select(trust, endpoints, storage::now(tx).await?)
            .map_err(|_| Error::Unsupported)?;
        let op = storage::load(tx, &self.protection, installation).await?;
        let package = op.authority.agent_package().ok_or(Error::Forbidden)?;
        let ExecutionAuthority::AgentInstall {
            download_origin, ..
        } = &op.authority
        else {
            return Err(Error::Forbidden.into());
        };
        let download_origin = download_origin.clone();
        let id = Uuid::new_v4();
        let delivery = Uuid::new_v4();
        let mut random = [0u8; 32];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| Error::Malformed)?;
        let secret = zeroize::Zeroizing::new(URL_SAFE_NO_PAD.encode(random));
        let task = task(
            &deployment,
            package.target.parts().0,
            installation,
            id,
            &secret,
        )?;
        let tenant = tx.tenant_id();
        let registration = op.registration;
        let generation = op.registration_generation;
        let source = op.request.task.source();
        let release = package.release.release_id;
        let deadline = op.request.deadline;
        let issuer = deployment.issuer.clone();
        let provisioner = deployment.provisioner.clone();
        let challenge = Sha256::digest(secret.as_bytes()).to_vec();
        tx.with_connection(move|c|Box::pin(async move {
            let credential:Uuid=sqlx::query_scalar("SELECT id FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND registration=$2 AND channel='mdm' AND state='active'")
                .bind(tenant.to_string()).bind(registration).fetch_one(&mut *c).await?;
            let proof=serde_json::json!({"installation":installation,"registration":registration,"credential":credential,"generation":generation,"source":source,"runtime":null,"bootstrap":id});
            sqlx::query("INSERT INTO mdm_access.agent_bootstraps(tenant_id,id,installation,delivery,source,release,issuer,provisioner,challenge,deadline,download_origin,state) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'prepared')")
                .bind(tenant.to_string()).bind(id).bind(installation).bind(delivery).bind(proof).bind(release).bind(issuer).bind(provisioner).bind(challenge).bind(deadline).bind(download_origin).execute(c).await?;
            Ok(())
        })).await?;
        let input = Create {
            operation_id: delivery,
            deadline,
            input_version: op.request.input_version,
            target: NativeTarget::Device,
            task,
        };
        let mut authority = op.authority;
        let ExecutionAuthority::AgentInstall {
            stage, required, ..
        } = &mut authority
        else {
            return Err(Error::Forbidden.into());
        };
        *stage = AgentInstallStage::Bootstrap;
        *required = input.task.permissions()?;
        let fact = audit.transaction_copy();
        fact.identify_service("agent-bootstrap-policy");
        fact.operation(delivery, "command_accept");
        fact.target_device(device);
        let fingerprint = crate::protection::fingerprint(
            &self.protection,
            tenant,
            device,
            "agent-bootstrap-command/v1",
            &(&input, installation, id),
        )?;
        let result = self
            .queue_authorized_in(tx, device, &input, authority, fingerprint, &fact)
            .await;
        fact.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result.map(|_| ())
    }
}
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
                ("AllowAllAppsAccess", false.into()),
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

impl ExecutionService {
    /// Retry only a known issued, expired identity; an unknown signing attempt stays fenced.
    pub(crate) async fn recover_bootstrap_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<()> {
        let now = self.installation_authorization_time(storage::now(tx).await?);
        let tenant = tx.tenant_id();
        let name = device.to_owned();
        let rows = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_as::<_,(Uuid,Uuid)>("SELECT b.id,b.installation FROM mdm_access.agent_bootstraps b JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(b.tenant_id,b.installation) JOIN mdm_access.registrations r ON(r.tenant_id,r.id,r.generation)=(o.tenant_id,o.registration,o.registration_generation) WHERE b.tenant_id=$1::uuid AND o.device=$2 AND b.active AND b.state='issued' AND b.deadline<=$3 AND (o.input_context->>'deadline')::bigint>$3 AND r.state='active' AND mdm_commands.installation_status(o.id) IN('published','received','applied') FOR UPDATE OF b")
                .bind(tenant.to_string()).bind(name).bind(now).fetch_all(c).await
        })).await?;
        for (id, installation) in rows {
            let op = storage::load(tx, &self.protection, installation).await?;
            if !storage::authority_valid(&self.source, &self.protection, tx, &op, now).await? {
                continue;
            }
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query("UPDATE mdm_access.agent_bootstraps SET active=false WHERE tenant_id=$1::uuid AND id=$2 AND active AND state='issued' AND deadline<=$3")
                    .bind(tenant.to_string()).bind(id).bind(now).execute(c).await?;
                Ok(())
            })).await?;
            self.queue_bootstrap_in(tx, device, installation, audit)
                .await?;
        }
        Ok(())
    }
    pub(crate) async fn cleanup_bootstrap_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        audit: &RequestAudit,
    ) -> Result<()> {
        let now = self.installation_authorization_time(storage::now(tx).await?);
        let tenant = tx.tenant_id();
        let name = device.to_owned();
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("UPDATE mdm_access.agent_bootstraps SET cleanup_complete=true WHERE tenant_id=$1::uuid AND cleanup IS NOT NULL AND NOT cleanup_complete AND mdm_commands.installation_status(cleanup)='applied'").bind(tenant.to_string()).execute(c).await?;Ok(())
        })).await?;
        let rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_as::<_,(Uuid,Uuid)>("SELECT b.id,b.installation FROM mdm_access.agent_bootstraps b JOIN mdm_commands.operations o ON(o.tenant_id,o.id)=(b.tenant_id,b.installation) WHERE b.tenant_id=$1::uuid AND o.device=$2 AND NOT b.cleanup_complete AND b.cleanup_retry_at<=$3 AND (b.cleanup IS NULL OR EXISTS(SELECT 1 FROM mdm_commands.operations cleanup WHERE cleanup.tenant_id=b.tenant_id AND cleanup.id=b.cleanup AND (mdm_commands.installation_status(cleanup.id) IN('rejected','cancelled','expired') OR (cleanup.input_context->>'deadline')::bigint<=$3))) AND b.state IN('issued','consumed') AND EXISTS(SELECT 1 FROM mdm_access.registrations native WHERE native.tenant_id=o.tenant_id AND native.id=o.registration AND native.generation=o.registration_generation AND native.state='active') AND EXISTS(SELECT 1 FROM mdm_access.agent_grants g JOIN mdm_access.registrations r ON(r.tenant_id,r.agent_grant_id)=(g.tenant_id,g.id) WHERE g.tenant_id=b.tenant_id AND g.native_authority->>'installation'=b.installation::text ) FOR UPDATE OF b")
                .bind(tenant.to_string()).bind(name).bind(now).fetch_all(c).await
        })).await?;
        for (id, installation) in rows {
            let op = storage::load(tx, &self.protection, installation).await?;
            let delivery = Uuid::new_v4();
            let task = cleanup_task(
                op.authority
                    .agent_package()
                    .ok_or(Error::Forbidden)?
                    .target
                    .parts()
                    .0,
                id,
            );
            let input = Create {
                operation_id: delivery,
                deadline: now + 300,
                input_version: op.request.input_version,
                target: NativeTarget::Device,
                task,
            };
            let mut authority = op.authority;
            let ExecutionAuthority::AgentInstall {
                stage, required, ..
            } = &mut authority
            else {
                return Err(Error::Forbidden.into());
            };
            *stage = AgentInstallStage::Cleanup { bootstrap: id };
            *required = input.task.permissions()?;
            let fingerprint = crate::protection::fingerprint(
                &self.protection,
                tenant,
                device,
                "agent-bootstrap-cleanup/v1",
                &(&input, installation, id),
            )?;
            let fact = audit.transaction_copy();
            fact.identify_service("agent-bootstrap-cleanup");
            fact.operation(delivery, "command_accept");
            fact.target_device(device);
            let result = self
                .queue_authorized_in(tx, device, &input, authority, fingerprint, &fact)
                .await;
            fact.finalize(
                result
                    .as_ref()
                    .err()
                    .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
            );
            result?;
            tx.with_connection(move|c|Box::pin(async move {
                sqlx::query("UPDATE mdm_access.agent_bootstraps SET cleanup=$3,cleanup_retry_at=$4 WHERE tenant_id=$1::uuid AND id=$2 AND NOT cleanup_complete").bind(tenant.to_string()).bind(id).bind(delivery).bind(now+300).execute(c).await?;Ok(())
            })).await?;
        }
        Ok(())
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
