use super::*;
use anyhow::{Result, ensure};
use sqlx::Executor;
use std::str::FromStr;

mod runtime;

#[tokio::test]
#[ignore = "make t2: complete predecessor upgrade in a disposable database"]
async fn complete_predecessor_withdraws_old_authority_and_preserves_started_evidence() -> Result<()>
{
    use serde_json::{Value, json};
    use uuid::Uuid;

    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
        epoch: 1,
        tenants: vec![
            "11111111-1111-4111-8111-111111111111".into(),
            "22222222-2222-4222-8222-222222222222".into(),
        ],
    };
    let mut owner = PgConnection::connect_with(&options).await?;
    migrate_units(&mut owner, &installation, &baseline_units()).await?;
    let policy = Uuid::from_u128(1);
    let version = Uuid::from_u128(2);
    let registration = Uuid::from_u128(3);
    let grant = Uuid::from_u128(4);
    let pending = Uuid::from_u128(5);
    let running = Uuid::from_u128(6);
    let attempt = Uuid::from_u128(7);
    let previous_attempt = Uuid::from_u128(8);
    let device = "predecessor-device";
    let deadline = 10_000;
    let old_definition = json!({"scope":Uuid::from_u128(9),"action":{"kind":"software","intent":"available_install"},"selfService":{"published":true,"allowAi":true,"riskLevel":2}});
    let old_context = json!({"revision":1,"osVersion":[14,0,0,0],"systemBroker":true,"interactiveUser":null,"sourceCredentials":[],"msixSideload":false,"msixUnsigned":false});
    let pending_state = json!({"delivery":{"kind":"queued"},"execution":"not_started","cancellation":"none","deadline":deadline,"startedAt":null});
    let running_state = json!({"delivery":{"kind":"received","attempt":attempt,"leaseUntil":200},"execution":"running","cancellation":"none","deadline":deadline,"startedAt":100});
    let frozen = json!({"kind":"software","action":{"delivery":{"kind":"direct"},"resource":"predecessor-app","version":"v1","variants":{"macos_aarch64":"default"},"resource_digest":vec![17;32],"admission_operation":Uuid::from_u128(10),"intent":"available_install","schedule":{"kind":"check_in"},"run_lifetime_seconds":3600}});
    let execution_target = json!({"kind":"user","identity":"502","sessionId":Uuid::from_u128(13)});
    let historical_step = |target: Value| {
        let invocation = json!({"runAs":"logged_in_user","arguments":[],"environment":{},"timeoutSeconds":60,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
        json!({"action":{"package":"Predecessor.User","version":"1","reboot":"report","downgrade":"deny","signatures":[],"behavior":{"kind":"brew","installer":"package","scope":"user","install":invocation,"upgradeInvocation":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"file","scope":"user","path":"bin/predecessor","version":"1","sha256":vec![19;32]}}},"target":target,"export":{"kind":"direct"},"artifacts":[{"key":"0/package","length":1024,"sha256":vec![20;32]}]})
    };
    let steps = json!([historical_step(execution_target.clone())]);
    let _: Vec<rss_mdm_agent_wire::runtime::SoftwareTaskStep> =
        serde_json::from_value(steps.clone())?;
    let material = json!({"kind":"software","platform":"macos","intent":"install","definitionDigest":vec![18;32],"steps":steps});

    // This is a SQL transformation fixture: the installer copies opaque historical
    // signed envelopes and projects their evidence coordinates without verifying
    // or decoding a retired task DTO. The runtime namespace upgrades complete
    // product-owned material and finishes the original live attempt.
    let envelope = |tenant: Uuid, permit: &str, target: Value| json!({"keyId":"predecessor-key","signature":"opaque-original-signature","payload":{"wireVersion":1,"tenantId":tenant,"deviceId":device,"registrationId":registration,"generation":1,"taskId":running,"attemptId":attempt,"permit":permit,"expiresAt":deadline,"platform":"macos","architecture":"aarch64","executionContext":old_context,"definitionDigest":vec![18;32],"steps":[historical_step(target)],"intent":"install","startMode":"user_initiated"}});
    let invocation = |tenant: Uuid, run: Uuid| json!({"authorization":{"kind":"self_service","requestId":run,"actor":{"instanceId":installation.instance_id,"tenantId":tenant,"principalId":Uuid::from_u128(11)},"source":"human","policyId":policy,"policyRevision":1,"policyVersion":version,"allowAi":true,"riskLevel":2,"confirmed":false},"parameters":{},"grant":{"operation":"script_execute","historical":"not-authority"}});
    for tenant in &installation.tenants {
        let tenant = Uuid::parse_str(tenant)?;
        let mut tx = owner.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO mdm_policy.policies(tenant_id,id,revision,current_version,version_number,enabled,definition,author,updated_at) VALUES($1,$2,1,$3,1,true,$4,'{}',1)")
            .bind(tenant).bind(policy).bind(version).bind(&old_definition).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,resource,resource_version,frozen,fingerprint) VALUES($1,$2,$3,1,'software','predecessor-app','v1',$4,$5)")
            .bind(tenant).bind(version).bind(policy).bind(&frozen).bind(vec![0u8;32]).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_access.devices(tenant_id,id) VALUES($1,$2)")
            .bind(tenant)
            .bind(device)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO mdm_access.agent_grants(tenant_id,id,operation_id,source,actor,instance,device,platform,secret_digest,request_digest,state,expires_at) VALUES($1,$2,$2,'download','fixture',$3,$4,'macos',repeat('0',64),repeat('0',64),'consumed',clock_timestamp()+interval '1 day')")
            .bind(tenant).bind(grant).bind(&installation.instance_id).bind(device).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_access.registrations(tenant_id,id,purpose,epoch,device,channel,generation,agent_grant_id,state) VALUES($1,$2,'primary',$2,$3,'agent',1,$4,'active')")
            .bind(tenant).bind(registration).bind(device).bind(grant).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_agent.bindings(tenant_id,registration,wire_version,capabilities,platform,architecture,execution_context) VALUES($1,$2,1,'[\"inventory.collect.v1\",\"software.pkg.system.v1\"]','macos','aarch64',$3)")
            .bind(tenant).bind(registration).bind(&old_context).execute(&mut *tx).await?;
        for (run, state) in [(pending, &pending_state), (running, &running_state)] {
            sqlx::query("INSERT INTO mdm_commands.action_runs(tenant_id,id,policy_version,device,registration,generation,occurrence,created_at,available_at,deadline,state,gateway_accepted,dispatch_fingerprint,invocation) VALUES($1,$2,$3,$4,$5,1,$6,1,1,$7,$8,true,$9,$10)")
                .bind(tenant).bind(run).bind(version).bind(device).bind(registration).bind(run.to_string()).bind(deadline).bind(state).bind(vec![0u8;32]).bind(invocation(tenant,run)).execute(&mut *tx).await?;
        }
        // A replaced claim must not choose the wrong effect target when backfilled.
        let mut replaced = envelope(
            tenant,
            "offer",
            json!({"kind":"user","identity":"501","sessionId":Uuid::from_u128(12)}),
        );
        replaced["payload"]["attemptId"] = json!(previous_attempt);
        sqlx::query("INSERT INTO mdm_commands.action_attempts(tenant_id,id,run,registration,claimed_at,offer) VALUES($1,$2,$3,$4,50,$5)")
            .bind(tenant).bind(previous_attempt).bind(running).bind(registration).bind(replaced).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_commands.action_attempts(tenant_id,id,run,registration,claimed_at,offer,permit) VALUES($1,$2,$3,$4,90,$5,$6)")
            .bind(tenant).bind(attempt).bind(running).bind(registration).bind(envelope(tenant,"offer",execution_target.clone())).bind(envelope(tenant,"start",execution_target.clone())).execute(&mut *tx).await?;
        tx.commit().await?;
    }

    let original_ledger: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    for field in ["instance_id", "target", "tenants", "epoch", "audit_mode"] {
        let mut input = installation.configuration();
        input[field] = match field {
            "instance_id" => json!("55555555-5555-4555-8555-555555555555"),
            "target" => json!(vec![3; 16]),
            "tenants" => json!(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
            "epoch" => json!(2),
            _ => json!("ledger"),
        };
        let mismatch: Installation = serde_json::from_value(input)?;
        ensure!(migrate_on(&mut owner, &mismatch).await.is_err());
        let actual_ledger: Vec<(String, String, bool)> =
            sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
                .fetch_all(&mut owner)
                .await?;
        ensure!(actual_ledger == original_ledger);
        ensure!(!sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='mdm_commands' AND table_name='action_runs' AND column_name='software_effect')").fetch_one(&mut owner).await?);
        for tenant in &installation.tenants {
            let mut tx = owner.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(tenant)
                .execute(&mut *tx)
                .await?;
            let actual_definition: Value = sqlx::query_scalar(
                "SELECT definition FROM mdm_policy.policies WHERE tenant_id=$1::uuid AND id=$2",
            )
            .bind(tenant)
            .bind(policy)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(actual_definition == old_definition);
            let states: Vec<Value> = sqlx::query_scalar(
                "SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid ORDER BY id",
            )
            .bind(tenant)
            .fetch_all(&mut *tx)
            .await?;
            ensure!(states == vec![pending_state.clone(), running_state.clone()]);
            tx.rollback().await?;
        }
    }
    // An interrupted predecessor is rejected before any new schema or data mutation.
    owner
        .execute("UPDATE public.mdm_migrations SET complete=false WHERE name='audit-v1'")
        .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(!sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='mdm_commands' AND table_name='action_runs' AND column_name='software_effect')").fetch_one(&mut owner).await?);
    owner
        .execute("UPDATE public.mdm_migrations SET complete=true WHERE name='audit-v1'")
        .await?;
    migrate_on(&mut owner, &installation).await?;
    let mut snapshots = Vec::new();
    for tenant in &installation.tenants {
        let tenant = Uuid::parse_str(tenant)?;
        let mut tx = owner.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        let (revision, enabled, mut definition): (i64, bool, Value) = sqlx::query_as("SELECT revision,enabled,definition FROM mdm_policy.policies WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(policy).fetch_one(&mut *tx).await?;
        ensure!(revision == 2 && enabled);
        ensure!(definition["selfService"].get("access") == Some(&Value::Null));
        ensure!(definition["selfService"]["published"] == false);
        definition["selfService"]
            .as_object_mut()
            .unwrap()
            .remove("access");
        definition["selfService"]["published"] = json!(true);
        ensure!(definition == old_definition);
        for (run, original_state) in [(pending, &pending_state), (running, &running_state)] {
            let (state, normalized, archive, effect): (Value, Value, Value, Option<Value>) = sqlx::query_as("SELECT state,invocation,invocation_archive,software_effect FROM mdm_commands.action_runs WHERE tenant_id=$1 AND id=$2")
                .bind(tenant).bind(run).fetch_one(&mut *tx).await?;
            ensure!(archive == invocation(tenant, run));
            ensure!(normalized["basis"] == json!({"kind":"withdrawn"}));
            ensure!(normalized["execution_target"] == json!({"kind":"device"}));
            ensure!(normalized["authorization"].get("actor").is_none());
            ensure!(
                normalized["authorization"]["subject"]
                    == json!({"kind":"user","user":archive["authorization"]["actor"]})
            );
            ensure!(normalized["parameters"] == archive["parameters"]);
            ensure!(normalized.get("grant").is_none());
            let mut expected = original_state.clone();
            if run == pending {
                expected["cancellation"] = json!("confirmed");
                ensure!(effect.is_none());
            } else {
                ensure!(
                    effect
                        == Some(
                            json!({"generation":1,"resource":"predecessor-app","version":"v1","digest":vec![17;32],"intent":"install","target":{"kind":"user","identity":"502"}})
                        )
                );
            }
            ensure!(state == expected);
        }
        let (offer, permit, actual_material): (Value, Value, Value) = sqlx::query_as("SELECT offer,permit,execution_material FROM mdm_commands.action_attempts WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(attempt).fetch_one(&mut *tx).await?;
        ensure!(offer == envelope(tenant, "offer", execution_target.clone()));
        ensure!(permit == envelope(tenant, "start", execution_target.clone()));
        ensure!(actual_material == material);
        let (previous_offer, previous_permit, previous_material): (Value, Option<Value>, Option<Value>) = sqlx::query_as("SELECT offer,permit,execution_material FROM mdm_commands.action_attempts WHERE tenant_id=$1 AND id=$2")
            .bind(tenant).bind(previous_attempt).fetch_one(&mut *tx).await?;
        let mut expected_previous = envelope(
            tenant,
            "offer",
            json!({"kind":"user","identity":"501","sessionId":Uuid::from_u128(12)}),
        );
        expected_previous["payload"]["attemptId"] = json!(previous_attempt);
        ensure!(previous_offer == expected_previous);
        ensure!(previous_permit.is_none() && previous_material.is_none());
        let mut context: Value = sqlx::query_scalar("SELECT execution_context FROM mdm_agent.bindings WHERE tenant_id=$1 AND registration=$2")
            .bind(tenant).bind(registration).fetch_one(&mut *tx).await?;
        ensure!(context["userHelper"] == false);
        context.as_object_mut().unwrap().remove("userHelper");
        ensure!(context == old_context);
        snapshots.push(upgrade_snapshot(&mut tx).await?);
        tx.commit().await?;
    }
    let ledger: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(ledger.len() == units().len() && ledger.iter().all(|row| row.2));
    migrate_on(&mut owner, &installation).await?;
    for (tenant, before) in installation.tenants.iter().zip(snapshots) {
        let mut tx = owner.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        ensure!(upgrade_snapshot(&mut tx).await? == before);
        tx.commit().await?;
    }
    let replayed_ledger: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(replayed_ledger == ledger);
    owner.close().await?;
    Ok(())
}

async fn upgrade_snapshot(conn: &mut PgConnection) -> Result<serde_json::Value> {
    Ok(sqlx::query_scalar(
        "SELECT jsonb_build_object('policies',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM mdm_policy.policies p),'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM mdm_commands.action_runs r),'attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM mdm_commands.action_attempts a),'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY registration) FROM mdm_agent.bindings b))",
    ).fetch_one(conn).await?)
}

#[tokio::test]
#[ignore = "make t2: fresh installation and rejected ledger in a disposable database"]
async fn fresh_installation_replay_and_mismatch_rejection() -> Result<()> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
        epoch: 1,
        tenants: vec!["11111111-1111-4111-8111-111111111111".into()],
    };
    let mut owner = PgConnection::connect_with(&options).await?;
    migrate_on(&mut owner, &installation).await?;
    let before: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(before.len() == units().len() && before.iter().all(|r| r.2));
    migrate_on(&mut owner, &installation).await?;
    for field in ["instance_id", "target", "tenants", "audit_mode"] {
        let mut changed = installation.configuration();
        changed[field] = match field {
            "instance_id" => serde_json::json!("55555555-5555-4555-8555-555555555555"),
            "audit_mode" => serde_json::json!("ledger"),
            "target" => serde_json::json!(vec![3; 16]),
            _ => serde_json::json!(["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]),
        };
        let changed: Installation = serde_json::from_value(changed)?;
        ensure!(migrate_on(&mut owner, &changed).await.is_err());
    }
    for (grant, revoke) in [
        (
            "GRANT SELECT ON identity_authority.accounts TO mdm_identity_audit",
            "REVOKE SELECT ON identity_authority.accounts FROM mdm_identity_audit",
        ),
        (
            "GRANT INSERT ON rss_audit.records TO mdm_identity_audit",
            "REVOKE INSERT ON rss_audit.records FROM mdm_identity_audit",
        ),
        (
            "GRANT DELETE ON identity_authority.accounts TO mdm_identity_runtime",
            "REVOKE DELETE ON identity_authority.accounts FROM mdm_identity_runtime",
        ),
        (
            "GRANT SELECT ON identity_authority.sessions TO mdm_identity_maintenance",
            "REVOKE SELECT ON identity_authority.sessions FROM mdm_identity_maintenance",
        ),
    ] {
        sqlx::raw_sql(grant).execute(&mut owner).await?;
        ensure!(migrate_on(&mut owner, &installation).await.is_err());
        sqlx::raw_sql(revoke).execute(&mut owner).await?;
    }
    migrate_on(&mut owner, &installation).await?;
    owner.execute("CREATE TABLE public.installation_evidence(value text); INSERT INTO public.installation_evidence VALUES('preserve')").await?;
    // Agent V6 SQL at base ab3f923a5b9a95951829430113af6db34db29c7c; the installer must not upgrade this ledger.
    let old_agent_digest = "d83c754a01ae788f6ac846df16586838b89ac7651c5a2f5b3225a69dda3ecbf9";
    let current_agent = before
        .iter()
        .find(|row| row.0 == "agent-channel-schema-v1")
        .unwrap();
    ensure!(current_agent.1 != old_agent_digest);
    sqlx::query("UPDATE public.mdm_migrations SET digest=$1 WHERE name='agent-channel-schema-v1'")
        .bind(old_agent_digest)
        .execute(&mut owner)
        .await?;
    let old_ledger: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    let rejected_ledger: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(old_ledger == rejected_ledger);
    ensure!(
        sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
            .fetch_one(&mut owner)
            .await?
            == "preserve"
    );
    // Restore only this disposable fixture before exercising the remaining admission cases.
    sqlx::query("UPDATE public.mdm_migrations SET digest=$1 WHERE name='agent-channel-schema-v1'")
        .bind(&current_agent.1)
        .execute(&mut owner)
        .await?;
    for statement in [
        "UPDATE public.mdm_migrations SET digest=repeat('0',64) WHERE name='transactional-messaging-v1'",
        "UPDATE public.mdm_migrations SET complete=false WHERE name='transactional-messaging-v1'",
    ] {
        sqlx::raw_sql(statement).execute(&mut owner).await?;
        ensure!(migrate_on(&mut owner, &installation).await.is_err());
        ensure!(
            sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
                .fetch_one(&mut owner)
                .await?
                == "preserve"
        );
        // Only this disposable test repairs its injected damage; the installer never does.
        let original = before
            .iter()
            .find(|r| r.0 == "transactional-messaging-v1")
            .unwrap();
        sqlx::query("UPDATE public.mdm_migrations SET digest=$1,complete=true WHERE name=$2")
            .bind(&original.1)
            .bind(&original.0)
            .execute(&mut owner)
            .await?;
    }
    // An otherwise complete ledger missing inventory owner units must not regain prefix-upgrade support.
    owner
        .execute("DELETE FROM public.mdm_migrations WHERE name IN ('inventory-v2','inventory-service-schema-v1')")
        .await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut owner)
            .await?
            == before.len() as i64 - 2
    );
    ensure!(
        sqlx::query_scalar::<_, String>("SELECT value FROM public.installation_evidence")
            .fetch_one(&mut owner)
            .await?
            == "preserve"
    );
    for (name, digest, complete) in &before {
        if name == "inventory-v2" || name == "inventory-service-schema-v1" {
            sqlx::query("INSERT INTO public.mdm_migrations VALUES($1,$2,$3)")
                .bind(name)
                .bind(digest)
                .bind(complete)
                .execute(&mut owner)
                .await?;
        }
    }
    owner.execute("INSERT INTO public.mdm_migrations VALUES('unrecognized-installation',repeat('a',64),true)").await?;
    ensure!(migrate_on(&mut owner, &installation).await.is_err());
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations")
            .fetch_one(&mut owner)
            .await?
            == before.len() as i64 + 1
    );
    owner.close().await?;
    Ok(())
}

#[test]
fn installation_accepts_empty_current_or_explicit_complete_predecessor_ledger() {
    let current = units();
    let ledger = current
        .iter()
        .map(|(name, sql)| (name.to_string(), format!("{:x}", Sha256::digest(sql)), true))
        .collect::<Vec<_>>();
    assert!(accepted_ledger(&[], &current));
    assert!(accepted_ledger(&ledger, &current));
    for prefix in 1..ledger.len() {
        assert_eq!(
            accepted_ledger(&ledger[..prefix], &current),
            prefix == baseline_units().len() || prefix == current.len() - 1
        );
    }
    let mut altered = ledger.clone();
    altered[0].1 = "0".repeat(64);
    assert!(!accepted_ledger(&altered, &current));
    let mut incomplete = ledger.clone();
    incomplete[0].2 = false;
    assert!(!accepted_ledger(&incomplete, &current));
    let mut duplicate = ledger;
    duplicate[0] = duplicate[1].clone();
    assert!(!accepted_ledger(&duplicate, &current));
}

#[test]
fn installation_validates_tenant_coordinates_within_the_declared_limit() {
    let mut installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
        epoch: 1,
        tenants: (1..=1024)
            .map(|n| uuid::Uuid::from_u128(n).to_string())
            .collect(),
    };
    assert!(installation.validate().is_ok());
    installation
        .tenants
        .push(uuid::Uuid::from_u128(1025).to_string());
    assert!(installation.validate().is_err());
    installation.tenants = vec![uuid::Uuid::from_u128(1).to_string(); 2];
    assert!(installation.validate().is_err());
    installation.tenants.clear();
    assert!(installation.validate().is_err());
}

#[tokio::test]
#[ignore = "MODULE=installation.migration: previous released ledger adds enrollment evidence"]
async fn previous_release_adds_enrollment_progress_without_rewriting_units() -> Result<()> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let installation = Installation {
        audit_mode: AuditMode::Plain,
        instance_id: crate::test_support::identity::INSTANCE.into(),
        target: [1; 16],
        lineage: [2; 16],
        epoch: 1,
        tenants: vec!["11111111-1111-4111-8111-111111111111".into()],
    };
    let mut owner = PgConnection::connect_with(&options).await?;
    let current = units();
    let previous = current
        .iter()
        .copied()
        .filter(|(name, _)| *name != "enrollment-progress-v1")
        .collect::<Vec<_>>();
    migrate_units(&mut owner, &installation, &previous).await?;
    let old: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    migrate_on(&mut owner, &installation).await?;
    let migrated: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations ORDER BY name")
            .fetch_all(&mut owner)
            .await?;
    ensure!(migrated.len() == old.len() + 1 && old.iter().all(|unit| migrated.contains(unit)));
    let nullable:bool=sqlx::query_scalar("SELECT NOT attnotnull FROM pg_attribute WHERE attrelid='mdm_access.registrations'::regclass AND attname='first_authenticated_at'").fetch_one(&mut owner).await?;
    ensure!(nullable);
    migrate_on(&mut owner, &installation).await?;
    owner.close().await?;
    Ok(())
}
