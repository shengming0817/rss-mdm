//! Real signed native operation, immutable Content bytes and final production HTTP mount.
use super::*;
use crate::host_t2_support as host;
use rss_mdm_content_service as content;

async fn prepare(
    c: &Context,
    id: Uuid,
    lifetime: Option<i64>,
) -> Result<(rss_mdm_resource::Version, owner::storage::Operation)> {
    let (_, target, _, scope, _) = endpoints(c).await?;
    let resource = software(c, "native-download").await?;
    let (policy, _) = policy(
        c,
        &resource,
        scope,
        rss_mdm_policy::SoftwareChannel::Mdm,
        vec![stage(scope)],
    )
    .await?;
    let fixture = open(c).await?;
    assert!(accepted(&accept(c, &fixture, policy, &target, id).await?));
    let fingerprint: Vec<u8> = sqlx::query_scalar("SELECT dispatch_fingerprint FROM mdm_software_deployment.action_runs WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    fixture
        .software
        .service
        .accept_action_dispatch(c.execution(), id, fingerprint)
        .await?;
    if let Some(seconds) = lifetime {
        let mut tx = command::seed_transaction(c).await?;
        let cutoff = now() + seconds;
        let state = rss_mdm_task_state::RunState::new(cutoff, now())?;
        sqlx::query("UPDATE mdm_software_deployment.action_runs SET deadline=$3,state=$4 WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(id).bind(cutoff).bind(serde_json::to_value(state)?).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    let execution = c.execution();
    owner::transaction::inspect(
        &fixture.resources.storage.runtime,
        execution,
        fixture.software.service.as_ref(),
        move |service, tx| {
            Box::pin(async move {
                owner::actions::recovery::recover_one(execution, service, tx, id).await
            })
        },
    )
    .await?;
    let mut tx = command::seed_transaction(c).await?;
    let operation =
        owner::storage::load_on(&mut tx, c.tenant, &fixture.resources.protection, id).await?;
    tx.commit().await?;
    let audit = || {
        RequestAudit::unresolved(
            rss_mdm_audit_integration::Origin::Request,
            rss_mdm_install_support::StorageProfile::Mdm,
            "download-proof",
            AuditIntent::Routine,
        )
    };
    let url = url(&operation);
    let token = url
        .query_pairs()
        .find(|(k, _)| k == "token")
        .unwrap()
        .1
        .into_owned();
    assert!(
        matches!(
            fixture
                .software
                .service
                .software_installation_artifact(id, &token, &audit())
                .await,
            Err(owner::Error::Forbidden)
        ),
        "queued command must not authorize bytes"
    );
    let mut tx = command::seed_transaction(c).await?;
    sqlx::query("UPDATE rss_device_command.commands SET status='published',published_at=queued_at,version=version+1 WHERE tenant_id=$1::uuid AND command_id=$2").bind(c.tenant.to_string()).bind(id.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    assert!(
        matches!(
            fixture
                .software
                .service
                .software_installation_artifact(id, &token, &audit())
                .await,
            Err(owner::Error::Forbidden)
        ),
        "published without native dispatch must not authorize bytes"
    );
    // Minimum already-dispatched protocol fact; signing, authority and content readers stay real.
    let mut tx = command::seed_transaction(c).await?;
    let credential: Uuid = sqlx::query_scalar(
        "SELECT id FROM mdm_access.credentials WHERE tenant_id=$1::uuid AND device=$2",
    )
    .bind(c.tenant.to_string())
    .bind(target.device.into_uuid())
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO mdm_windows.attempts(protocol_epoch,tenant_id,id,operation,device,ordinal,credential,session,message,phase,request) VALUES($1,$2::uuid,$3,$4,$5,1,$6,1,1,'execute',$7)").bind(Uuid::new_v4()).bind(c.tenant.to_string()).bind(Uuid::new_v4()).bind(id).bind(target.device.into_uuid()).bind(credential).bind(vec![0u8;68]).execute(&mut *tx).await?;
    tx.commit().await?;
    // Discovery cannot overwrite a scope already bound by its caller, even within one tenant.
    use rss_transactional_messaging::fence::{Epoch, ExecutionBinding, StorageIdentity};
    for binding in [
        ExecutionBinding::new(c.execution().storage(), c.tenant, Epoch::new(2)?),
        ExecutionBinding::new(
            StorageIdentity::new([3; 16], [4; 16])?,
            c.tenant,
            Epoch::new(1)?,
        ),
    ] {
        let audit = RequestAudit::new(
            rss_mdm_audit_integration::Origin::Request,
            rss_mdm_install_support::StorageProfile::Mdm,
            binding,
            "download-proof",
            AuditIntent::Routine,
        );
        assert!(
            fixture
                .software
                .service
                .software_installation_artifact(id, &token, &audit)
                .await
                .is_err()
        );
        assert_eq!(audit.binding()?, binding);
    }
    fixture.close().await?;
    Ok((resource, operation))
}
fn url(operation: &owner::storage::Operation) -> url::Url {
    let owner::Task::Windows {
        request: rss_mdm_windows_mdm::native::Execution::Msi { job },
    } = &operation.request.task
    else {
        panic!("MSI fixture")
    };
    url::Url::parse(&job.content_urls[0]).unwrap()
}

#[tokio::test]
#[ignore = "T2: final App consumes issued software URL and enforces current native authority and verified bytes"]
async fn final_router_serves_only_current_signed_native_content() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let operation_id = Uuid::new_v4();
    let (resource, operation) = prepare(&c, operation_id, None).await?;
    let expiring = Context::open("shared", &[]).await?;
    let (_, expired) = prepare(&expiring, Uuid::new_v4(), Some(10)).await?;
    let issued = url(&operation);
    let directory = tempfile::tempdir()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let mut configuration =
        host::configuration(&c.inputs, "shared", listener.local_addr()?, Uuid::new_v4()).await?;
    configuration["software_distribution"]["mdm_enabled"] = json!(true);
    configuration["content"] = json!({"storage":{"kind":"volume","directory":directory.path()},"imports":{},"max_artifact_bytes":33554432,"max_temporary_bytes":67108864,"max_uploads":4,"transfer_seconds":60,"retention_seconds":3600,"max_bundle_entries":4096,"max_expansion_ratio":100});
    let config: crate::config::Config = serde_json::from_value(configuration.clone())?;
    let store = crate::assembly::content::open(&config, material::protection(&c)?)
        .await?
        .unwrap();
    let id = Uuid::new_v4();
    let binding = content::Binding {
        purpose: content::Purpose::Resource(content::ResourceBinding {
            inspection: None,
            storage_class: content::StorageClass::Artifact,
            resource: resource.resource().as_str().into(),
            version: "1".into(),
            variant: "msi".into(),
            platform: rss_mdm_resource::Platform::Windows,
            architecture: rss_mdm_resource::Architecture::X86_64,
            resource_digest: resource.digest().bytes(),
            source: None,
            origin: None,
        }),
        reference: "app-msi".into(),
        length: 3,
        sha256: rss_mdm_resource::Digest::of(b"msi").bytes(),
        actor: "download-proof".into(),
    };
    store
        .begin(c.execution(), id, binding, now(), store.upload_budget()?)
        .await?;
    store
        .append(
            c.execution(),
            "download-proof",
            id,
            0,
            now(),
            &b"msi"[..],
            store.upload_budget()?,
        )
        .await?;
    assert!(
        store
            .finish(
                c.execution(),
                "download-proof",
                id,
                now(),
                store.upload_budget()?
            )
            .await?
            .complete
    );
    store.close().await;
    let management = config.identity.management_tenant;
    sqlx::query(
        "INSERT INTO identity_authority.guard(tenant_id) VALUES($1::uuid) ON CONFLICT DO NOTHING",
    )
    .bind(management.to_string())
    .execute(&c.operator)
    .await?;
    drop(listener);
    let result = {
        let c = &c;
        let directory = &directory;
        let expired = &expired;
        let operation = &operation;
        let issued = &issued;
        host::run(configuration, |client, base| async move {
            let path = format!("{}?{}", issued.path(), issued.query().unwrap());
            let download = format!("{base}{path}");
            let response = client.get(&download).send().await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.headers()["cache-control"], "private, no-store");
            Uuid::parse_str(response.headers()["x-request-id"].to_str()?)?;
            assert_eq!(response.bytes().await?.as_ref(), b"msi");
            let response = client
                .get(&download)
                .header("range", "bytes=1-2")
                .send()
                .await?;
            assert_eq!(response.status(), 206);
            assert_eq!(response.headers()["content-range"], "bytes 1-2/3");
            assert_eq!(response.bytes().await?.as_ref(), b"si");
            host::reject(
                client
                    .get(format!("{base}{}?token={}", issued.path(), "0".repeat(64)))
                    .send()
                    .await?,
                403,
                "permission_denied",
            )
            .await?;
            host::reject(
                client
                    .get(download.replace(&operation_id.to_string(), &Uuid::new_v4().to_string()))
                    .send()
                    .await?,
                403,
                "permission_denied",
            )
            .await?;
            host::reject(
                client
                    .get(&download)
                    .header("host", "foreign.example.test")
                    .send()
                    .await?,
                400,
                "malformed_request",
            )
            .await?;
            // A valid token cannot survive current registration revocation.
            let mut tx = command::seed_transaction(&c).await?;
            sqlx::query(
                "UPDATE mdm_access.devices SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2",
            )
            .bind(c.tenant.to_string())
            .bind(operation.device.into_uuid())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            host::reject(
                client.get(&download).send().await?,
                403,
                "permission_denied",
            )
            .await?;
            let mut tx = command::seed_transaction(&c).await?;
            sqlx::query(
                "UPDATE mdm_access.devices SET state='active' WHERE tenant_id=$1::uuid AND id=$2",
            )
            .bind(c.tenant.to_string())
            .bind(operation.device.into_uuid())
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            assert_eq!(
                client.get(&download).send().await?.bytes().await?.as_ref(),
                b"msi"
            );
            // Expiration is evaluated from the original persisted request, without a fake clock.
            let wait = expired.request.deadline.saturating_sub(now());
            if wait > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(wait as u64)).await;
            }
            let expired_url = url(&expired);
            host::reject(
                client
                    .get(format!(
                        "{base}{}?{}",
                        expired_url.path(),
                        expired_url.query().unwrap()
                    ))
                    .send()
                    .await?,
                403,
                "permission_denied",
            )
            .await?;
            // Corrupt actual stored bytes; no successful response may start streaming them.
            let tenant_directory = directory.path().join(c.tenant.to_string());
            let chunk = std::fs::read_dir(tenant_directory)?
                .filter_map(Result::ok)
                .map(|e| e.path())
                .find(|p| std::fs::read(p).is_ok_and(|v| v == b"msi"))
                .expect("sealed chunk");
            std::fs::write(&chunk, b"bad")?;
            let failed = client.get(&download).send().await?;
            assert!(failed.status().is_server_error());
            assert_ne!(failed.bytes().await?.as_ref(), b"bad");
            std::fs::write(&chunk, b"msi")?;
            assert_eq!(
                client.get(&download).send().await?.bytes().await?.as_ref(),
                b"msi"
            );
            // Equal opaque IDs in two tenants must not select either tenant's signed operation.
            let foreign = Context::open("shared", &[]).await?;
            let (_, foreign_operation) = prepare(&foreign, operation_id, None).await?;
            assert_ne!(url(&foreign_operation).query(), issued.query());
            host::reject(
                client.get(&download).send().await?,
                403,
                "permission_denied",
            )
            .await?;
            foreign.close().await;
            Ok(())
        })
        .await
    };
    expiring.close().await;
    c.close().await;
    result
}
