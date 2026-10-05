//! Upgrade behavior through current product admission, recovery and result intake.
use crate::test_support::software::write;
use crate::test_support::*;
use crate::test_support::{agent_execution as scripts, software_execution as software};
use sqlx::{
    Connection, Executor, PgConnection,
    postgres::{PgConnectOptions, PgSslMode},
};
use std::str::FromStr;
use uuid::Uuid;

async fn owner() -> Result<PgConnection> {
    let options = PgConnectOptions::from_str(&std::env::var("MDM_OWNER_URL")?)?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(std::env::var("PG_CA_FILE")?);
    let mut conn = PgConnection::connect_with(&options).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut conn)
        .await?;
    Ok(conn)
}

/// Only this disposable database rewinds the transition. All resource, authorization,
/// scope, registration and complete predecessor units retain their production contents.
async fn upgrade(conn: &mut PgConnection) -> Result<()> {
    let configuration: Value =
        sqlx::query_scalar("SELECT configuration FROM public.mdm_installation")
            .fetch_one(&mut *conn)
            .await?;
    let installation: super::Installation = serde_json::from_value(configuration)?;
    // Account enrollment and ADE were not present in this released predecessor. Rewind their
    // structure too; deleting ledger entries alone would describe an impossible schema.
    conn.execute(
        r#"
        DROP FUNCTION mdm_apple.account_current(uuid,uuid,bigint,uuid,text);
        DROP TABLE mdm_apple.ade_enrollments, mdm_apple.ade_sync_devices, mdm_apple.ade_operations,
          mdm_apple.ade_devices, mdm_apple.ade_profiles, mdm_apple.ade_servers;
        DROP TABLE mdm_apple.account_flows, mdm_apple.account_bindings, mdm_apple.account_configuration,
          mdm_apple.organizations;
        ALTER TABLE mdm_apple.scep_attempts RENAME COLUMN authorization_version TO password_version;
        ALTER TABLE mdm_access.requests DROP CONSTRAINT enrollment_shape;
        ALTER TABLE mdm_access.requests DROP COLUMN account_version, DROP COLUMN account_reference, DROP COLUMN account_challenge,
          DROP COLUMN organization_version, DROP COLUMN organization_challenge;
        ALTER TABLE mdm_access.requests DROP CONSTRAINT requests_authority_kind_check;
        ALTER TABLE mdm_access.requests ADD CONSTRAINT requests_authority_kind_check CHECK(authority_kind IN ('password','parent_certificate'));
        ALTER TABLE mdm_access.requests ADD CONSTRAINT enrollment_shape CHECK (
          state='cancelled' OR (expected_generation IS NOT NULL AND expires_at IS NOT NULL AND issuance_operation IS NOT NULL AND (
          (authority_kind='password' AND grant_id IS NOT NULL AND parent_id IS NULL AND password_digest IS NOT NULL AND password_version>0 AND credential_ref IS NOT NULL) OR
          (authority_kind='parent_certificate' AND grant_id IS NULL AND source='mdm.windows' AND parent_id IS NOT NULL AND parent_generation IS NOT NULL AND parent_generation>0 AND parent_credential IS NOT NULL AND password_digest IS NULL AND password_version=0 AND credential_ref IS NULL)
          )));
        ALTER TABLE mdm_commands.action_attempts DROP COLUMN execution_material;
        ALTER TABLE mdm_commands.action_runs DROP COLUMN software_effect,DROP COLUMN invocation_archive;
        ALTER TABLE mdm_access.registrations DROP COLUMN first_authenticated_at;
        ALTER TABLE mdm_access.agent_grants DROP COLUMN configuration_id, DROP COLUMN configuration_binding;
        ALTER TABLE mdm_access.agent_grants DROP CONSTRAINT agent_grants_source_check;
        ALTER TABLE mdm_access.agent_grants ADD CONSTRAINT agent_grants_source_check CHECK(source IN('download','browser','native','recovery','renewal'));
        DROP TABLE mdm_access.agent_configurations, mdm_access.agent_enrollment_settings;
        DROP SCHEMA mdm_agent_packages CASCADE;
        DELETE FROM public.mdm_migrations WHERE name IN ('self-service-access-v1','enrollment-progress-v1','apple-account-authority-v1','apple-account-channel-v1',
          'registration-agent-configurations-v1','software-agent-packages-v1','apple-organizations-v1','apple-ade-authority-v1','apple-ade-channel-v1');
        "#,
    )
    .await?;
    let actual: Vec<(String, String, bool)> =
        sqlx::query_as("SELECT name,digest,complete FROM public.mdm_migrations")
            .fetch_all(&mut *conn)
            .await?;
    ensure!(super::accepted_ledger(&actual, &super::units()));
    ensure!(actual.len() == super::baseline_units().len());
    super::migrate_on(conn, &installation).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(case_tenant())
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn wait_recovered(conn: &mut PgConnection, policy: Uuid) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let recovered: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2)")
                .bind(case_tenant()).bind(policy).fetch_one(&mut *conn).await?;
            if recovered { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=installation.upgrade_runtime"]
async fn background_queued_and_retired_offers_keep_their_original_policy_and_remote_runs()
-> Result<()> {
    let mut f = scripts::Fixture::new().await?;
    f.register().await?;
    scripts::claim_request(&f.router, Uuid::new_v4()).await?;
    f.scope(
        scripts::case_task_scope(),
        json!([{"kind":"device","id":scripts::case_device_id()}]),
    )
    .await?;
    // Action-only material keeps the migration delivery proof independent of Inventory.
    let resource = Uuid::new_v4();
    let bytes = b"#!/bin/sh\nprintf '{\"version\":\"1.2\",\"healthy\":true}\\n'\n";
    let script = json!({"profile":"posix_sh","runAs":"system","encoding":"utf8","parameters":{"type":"object","properties":{},"required":[],"additionalProperties":false},"bindings":{},"output":{"type":"object","properties":{"version":{"type":"string"},"healthy":{"type":"boolean"}},"required":["version","healthy"],"additionalProperties":false},"purpose":{"kind":"action"},"timeoutSeconds":60,"outputBytes":4096,"maxRows":1});
    scripts::resource(
        &mut f.author,
        &f.router,
        resource,
        0,
        json!({"action":"create","kind":"script"}),
    )
    .await?;
    scripts::resource(&mut f.author,&f.router,resource,1,json!({"action":"version","version":"v1","kind":"script","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"script","artifact":{"reference":"upgrade-background-script","length":bytes.len(),"sha256":rss_mdm_resource::Digest::of(bytes).bytes()},"definition":script}}]})).await?;
    ensure!(scripts::upload(&f.author, &f.router, resource, bytes).await? == StatusCode::CREATED);
    scripts::resource(
        &mut f.author,
        &f.router,
        resource,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let stack = scripts::worker(&f.base).await?;
    let mut tasks = Vec::new();
    for remote in [false, false, true, true] {
        let id = Uuid::new_v4();
        let mut definition = scripts::policy_definition(resource, scripts::case_task_scope());
        definition["action"]["schedule"] = json!({"trigger":{"kind":"registration"},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null});
        scripts::post(&mut f.author,&f.router,&format!("/api/v1/policies/{id}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":definition}})).await?;
        let mut task = scripts::claim(&f.router).await?;
        if remote {
            task = scripts::historical_remote(&f, &task, Uuid::new_v4()).await?;
        }
        tasks.push(task);
    }
    crate::test_support::stop_worker(stack).await?;
    let mut conn = owner().await?;
    let mut original = Vec::new();
    let mut retired_replays = Vec::new();
    for (index, task) in tasks.iter().enumerate() {
        let run = Uuid::parse_str(task["payload"]["taskId"].as_str().unwrap())?;
        let attempt = Uuid::parse_str(task["payload"]["attemptId"].as_str().unwrap())?;
        let row:(String,Option<Uuid>,Option<Uuid>)=sqlx::query_as("SELECT occurrence,policy_version,remote_operation FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_tenant()).bind(run).fetch_one(&mut conn).await?;
        original.push((run, row));
        if index % 2 == 0 {
            // Restore the pre-Offer fixture state, including absence of attempt and receipt.
            sqlx::query("UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{delivery}','{\"kind\":\"queued\"}') WHERE tenant_id=$1::uuid AND id=$2")
                .bind(case_tenant()).bind(run).execute(&mut conn).await?;
            sqlx::query(
                "DELETE FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2",
            )
            .bind(case_tenant())
            .bind(attempt)
            .execute(&mut conn)
            .await?;
            sqlx::query("DELETE FROM mdm_commands.action_receipts WHERE tenant_id=$1::uuid AND response->'task'->'payload'->>'taskId'=$2")
                .bind(case_tenant()).bind(run.to_string()).execute(&mut conn).await?;
        } else {
            let mut retired = task.clone();
            // The reconstructed signature is opaque audit material, never Start authority.
            retired["payload"]
                .as_object_mut()
                .unwrap()
                .remove("executionTarget");
            ensure!(
                serde_json::from_value::<rss_mdm_agent_wire::runtime::SignedTask>(retired.clone())
                    .is_err()
            );
            sqlx::query("UPDATE mdm_commands.action_attempts SET offer=$3 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(case_tenant()).bind(attempt).bind(&retired).execute(&mut conn).await?;
            let receipt:Uuid=sqlx::query_scalar("UPDATE mdm_commands.action_receipts SET response=jsonb_set(response,'{task}',$3) WHERE tenant_id=$1::uuid AND response->'task'->'payload'->>'taskId'=$2 RETURNING id")
                .bind(case_tenant()).bind(run.to_string()).bind(retired).fetch_one(&mut conn).await?;
            retired_replays.push(receipt);
        }
    }
    upgrade(&mut conn).await?;
    for receipt in retired_replays {
        let response = scripts::claim_request(&f.router, receipt).await?;
        ensure!(
            response.0 == StatusCode::CONFLICT,
            "retired receipt must reject its raw attempt before decoding retired payload: {response:?}"
        );
    }
    for (run, coordinates) in &original {
        let row:(String,Option<Uuid>,Option<Uuid>,Value)=sqlx::query_as("SELECT occurrence,policy_version,remote_operation,state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2")
            .bind(case_tenant()).bind(run).fetch_one(&mut conn).await?;
        ensure!((&row.0, row.1, row.2) == (&coordinates.0, coordinates.1, coordinates.2));
        ensure!(row.3["delivery"]["kind"] == "queued" && row.3["cancellation"] == "none");
    }
    let stack = scripts::worker(&f.base).await?;
    let mut seen = std::collections::BTreeSet::new();
    for _ in original
        .iter()
        .filter(|(_, coordinates)| coordinates.2.is_none())
    {
        let task = scripts::claim(&f.router).await?;
        let run = Uuid::parse_str(task["payload"]["taskId"].as_str().unwrap())?;
        ensure!(
            original.iter().any(|(id, _)| *id == run) && seen.insert(run),
            "upgrade must reclaim the existing occurrence: {task}"
        );
        scripts::complete(&f.router, &task).await?;
    }
    for (run, coordinates) in &original {
        let state: Value = sqlx::query_scalar(
            "SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(case_tenant())
        .bind(run)
        .fetch_one(&mut conn)
        .await?;
        if let Some(remote) = coordinates.2 {
            f.execution.recover_remote_fixture(remote).await?;
            let state: Value = sqlx::query_scalar(
                "SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
            )
            .bind(case_tenant())
            .bind(run)
            .fetch_one(&mut conn)
            .await?;
            ensure!(state["cancellation"] == "confirmed");
        } else {
            ensure!(state["execution"] == "succeeded");
        }
    }
    let versions: Vec<_> = original.iter().filter_map(|(_, row)| row.1).collect();
    let operations: Vec<_> = original.iter().filter_map(|(_, row)| row.2).collect();
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND (policy_version=ANY($2) OR remote_operation=ANY($3))")
        .bind(case_tenant()).bind(versions).bind(operations).fetch_one(&mut conn).await?;
    ensure!(
        count == original.len() as i64,
        "upgrade must not create replacement business Runs"
    );
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Withdrawal {
    None,
    Scope,
    Approval,
    ApprovalBeforeRecovery,
    Registration,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=installation.upgrade_runtime"]
async fn started_user_software_finishes_the_original_attempt_before_helper_refresh() -> Result<()> {
    started_software(Withdrawal::None).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=installation.upgrade_runtime"]
async fn upgraded_started_software_still_observes_scope_withdrawal() -> Result<()> {
    started_software(Withdrawal::Scope).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=installation.upgrade_runtime"]
async fn upgraded_started_software_still_observes_approval_withdrawal() -> Result<()> {
    started_software(Withdrawal::Approval).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=installation.upgrade_runtime"]
async fn started_self_service_software_rejects_withdrawn_approval_before_recovery_marks_cancellation()
-> Result<()> {
    started_software(Withdrawal::ApprovalBeforeRecovery).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=installation.upgrade_runtime"]
async fn upgraded_started_software_still_observes_registration_revocation() -> Result<()> {
    started_software(Withdrawal::Registration).await
}

#[allow(
    clippy::cognitive_complexity,
    reason = "shared integration scenario keeps ordered upgrade and independent withdrawal assertions visible"
)]
async fn started_software(withdrawal: Withdrawal) -> Result<()> {
    let mut local = software::context(software::Platform::Windows);
    local["interactiveUser"] =
        json!({"identity":"S-1-5-21-1-2-3-1001","sessionId":Uuid::new_v4(),"administrator":false});
    let mut f = software::Fixture::with_profiles(
        software::Platform::Windows,
        json!([
            "inventory.collect.v1",
            "software.msi.system.v1",
            "software.msi.user.v1"
        ]),
        local.clone(),
    )
    .await?;
    let resource = Uuid::new_v4();
    let bytes = b"controlled predecessor user MSI";
    let invocation = json!({"runAs":"logged_in_user","arguments":[],"environment":{},"timeoutSeconds":300,"outputBytes":4096,"exitCodes":{"success":[0],"reboot":[]}});
    let definition = json!({"source":f.source_snapshot,"package":"Private.PredecessorUser","version":"1","artifacts":{"package":{"reference":"predecessor-user-msi","length":bytes.len(),"sha256":rss_mdm_resource::Digest::of(bytes).bytes()}},"reboot":"report","downgrade":"deny","dependencies":[],"behavior":{"kind":"msi","installer":"package","scope":"user","install":invocation,"upgrade":"in_place","uninstall":null,"detect":{"kind":"msi_product","productCode":"{CCCCCCCC-DDDD-EEEE-FFFF-AAAAAAAAAAAA}","version":"1"},"upgradeInvocation":invocation},"signatures":[],"provenance":{"kind":"private"},"export":{"kind":"disabled"}});
    let path = format!("/api/v1/resources/{resource}");
    write(
        &mut f.author,
        &f.router,
        &path,
        0,
        json!({"action":"create","kind":"software"}),
    )
    .await?;
    write(&mut f.author,&f.router,&path,1,json!({"action":"version","version":"v1","kind":"software","variants":[{"platform":"windows","architecture":"x86_64","key":"default","declaration":{"kind":"software","definition":definition}}]})).await?;
    software::upload_windows(&f.author, &f.router, resource, bytes).await?;
    write(
        &mut f.author,
        &f.router,
        &path,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let approval_path = format!("/api/v1/software/resources/{resource}/versions/v1");
    let approval = write(
        &mut f.author,
        &f.router,
        &approval_path,
        0,
        json!({"action":"approve","evidence":["predecessor-user-install"]}),
    )
    .await?;
    let policy = Uuid::new_v4();
    let self_service = matches!(withdrawal, Withdrawal::ApprovalBeforeRecovery);
    let mut definition = software::authored(
        resource,
        f.scope,
        if self_service {
            "available_install"
        } else {
            "required_install"
        },
        &approval["admission"]["operation"],
    );
    definition["action"]["resource"]["variants"] = json!({"windows_x86_64":"default"});
    if self_service {
        definition["selfService"] = json!({"access":{"kind":"device"},"published":true,"displayName":"User software","description":"","prerequisites":"","sideEffects":"Install","category":"Apps","keywords":[]});
    }
    let published = write(
        &mut f.author,
        &f.router,
        &format!("/api/v1/policies/{policy}"),
        0,
        json!({"action":"put","enabled":true,"definition":definition}),
    )
    .await?;
    let stack = software::worker(&f.base, f.content.clone()).await?;
    if self_service {
        let requested=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/self-service/invocations",Some(&f.credential),Some(json!({"operationId":Uuid::new_v4(),"policyId":policy,"policyRevision":published["revision"],"policyVersion":published["versionId"],"source":"human","confirmed":true,"parameters":{}}))).await?;
        ensure!(
            requested.0 == StatusCode::ACCEPTED,
            "self-service invocation: {requested:?}"
        );
    }
    let task=tokio::time::timeout(Duration::from_secs(30),async {
        loop {
            let poll=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(&f.credential),Some(json!({"wireVersion":1,"executionContext":local,"profiles":["posix_sh"],"operationId":Uuid::new_v4()}))).await?;
            ensure!(poll.0==StatusCode::OK,"claim: {poll:?}");
            if !poll.1["task"].is_null() { return Ok::<_,anyhow::Error>(poll.1["task"].clone()); }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await??;
    ensure!(task["payload"]["steps"][0]["target"]["kind"] == "user");
    if self_service {
        ensure!(task["payload"]["authorization"]["kind"] == "self_service");
    }
    ensure!(
        software::event_with(&f.router, &f.credential, &task, json!({"kind":"received"}))
            .await?
            .0
            == StatusCode::OK
    );
    let start =
        software::event_with(&f.router, &f.credential, &task, json!({"kind":"start"})).await?;
    ensure!(start.0 == StatusCode::OK, "start: {start:?}");
    let result = software::result_event(&task, "install", Some(0), "present", false)?;
    crate::test_support::stop_worker(stack).await?;
    let run = Uuid::parse_str(task["payload"]["taskId"].as_str().unwrap())?;
    let attempt = Uuid::parse_str(task["payload"]["attemptId"].as_str().unwrap())?;
    let registration = Uuid::parse_str(task["payload"]["registrationId"].as_str().unwrap())?;
    let mut conn = owner().await?;
    if !self_service {
        // Reconstruct historical wire shapes with complete product-owned steps.
        // Signatures are opaque audit bytes, not valid signatures over these edited payloads.
        let retire = |mut envelope: Value| {
            envelope["payload"]
                .as_object_mut()
                .unwrap()
                .remove("authorization");
            envelope["payload"]["executionContext"]
                .as_object_mut()
                .unwrap()
                .remove("userHelper");
            envelope
        };
        let old_offer = retire(task.clone());
        let old_permit = retire(start.1["permit"].clone());
        ensure!(
            serde_json::from_value::<rss_mdm_agent_wire::runtime::SignedTask>(old_permit.clone())
                .is_err()
        );
        sqlx::query("UPDATE mdm_commands.action_attempts SET offer=$3,permit=$4 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(attempt).bind(&old_offer).bind(&old_permit).execute(&mut conn).await?;
        sqlx::query("UPDATE mdm_agent.bindings SET execution_context=execution_context-'userHelper' WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(case_tenant()).bind(registration).execute(&mut conn).await?;
        sqlx::query(
            "DELETE FROM mdm_commands.policy_recovery WHERE tenant_id=$1::uuid AND policy=$2",
        )
        .bind(case_tenant())
        .bind(policy)
        .execute(&mut conn)
        .await?;
        upgrade(&mut conn).await?;
        let (offer,permit,material):(Value,Value,Value)=sqlx::query_as("SELECT offer,permit,execution_material FROM mdm_commands.action_attempts WHERE tenant_id=$1::uuid AND id=$2")
        .bind(case_tenant()).bind(attempt).fetch_one(&mut conn).await?;
        ensure!(
            offer == old_offer
                && permit == old_permit
                && material["steps"] == task["payload"]["steps"]
        );
        let steps: Vec<rss_mdm_agent_wire::runtime::SoftwareTaskStep> =
            serde_json::from_value(material["steps"].clone())?;
        ensure!(!steps.is_empty());
        local["userHelper"] = json!(false);
    }
    match withdrawal {
        Withdrawal::None => (),
        Withdrawal::Scope => {
            let automation = start_automation(&f.base).await?;
            let changed=write(&mut f.author,&f.router,&format!("/api/v1/scopes/{}",f.scope),1,json!({"action":"put","definition":{"targets":[],"limitations":null,"exclusions":[]}})).await?;
            await_task(
                &mut f.author,
                &f.router,
                &format!(
                    "/api/v1/scopes/{}/tasks/{}",
                    f.scope,
                    changed["task"].as_str().unwrap()
                ),
            )
            .await?;
            crate::test_support::stop_worker(automation).await?;
        }
        Withdrawal::Approval | Withdrawal::ApprovalBeforeRecovery => {
            write(
                &mut f.author,
                &f.router,
                &approval_path,
                1,
                json!({"action":"withdraw","evidence":["real-revocation"]}),
            )
            .await?;
        }
        Withdrawal::Registration => {
            sqlx::query("UPDATE mdm_access.registrations SET state='revoked' WHERE tenant_id=$1::uuid AND id=$2")
                .bind(case_tenant()).bind(registration).execute(&mut conn).await?;
        }
    }
    if matches!(withdrawal, Withdrawal::ApprovalBeforeRecovery) {
        let before: Value = sqlx::query_scalar(
            "SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(case_tenant())
        .bind(run)
        .fetch_one(&mut conn)
        .await?;
        ensure!(
            before["execution"] == "running" && before["cancellation"] == "none",
            "worker must not mask the result-admission boundary"
        );
        let response=agent_call(&f.router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{run}/events"),Some(&f.credential),Some(json!({"wireVersion":1,"executionContext":local,"operationId":Uuid::new_v4(),"attemptId":attempt,"event":result}))).await?;
        let (state, effect): (Value, Value) = sqlx::query_as(
            "SELECT state,result FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(case_tenant())
        .bind(run)
        .fetch_one(&mut conn)
        .await?;
        ensure!(
            response.0 == StatusCode::OK
                && state["execution"] == "unknown"
                && effect["effect"] == "unknown",
            "withdrawn approval cannot verify a result before recovery: {response:?} {state} {effect}"
        );
        ensure!(state["delivery"]["attempt"] == task["payload"]["attemptId"]);
        return Ok(());
    }
    let stack = software::worker(&f.base, f.content.clone()).await?;
    wait_recovered(&mut conn, policy).await?;
    let before: Value = sqlx::query_scalar(
        "SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(run)
    .fetch_one(&mut conn)
    .await?;
    let helper:bool=sqlx::query_scalar("SELECT (execution_context->>'userHelper')::boolean FROM mdm_agent.bindings WHERE tenant_id=$1::uuid AND registration=$2")
        .bind(case_tenant()).bind(registration).fetch_one(&mut conn).await?;
    ensure!(
        !helper,
        "result must be tested before the Agent refreshes helper capability"
    );
    if matches!(withdrawal, Withdrawal::None) {
        ensure!(
            before["execution"] == "running" && before["cancellation"] == "none",
            "fresh-start prerequisites must not cancel the predecessor attempt: {before}"
        );
    } else {
        ensure!(
            before["cancellation"] != "none",
            "actual business withdrawal must still cancel: {before}"
        );
    }
    if matches!(withdrawal, Withdrawal::None) {
        for field in ["target", "definitionDigest"] {
            let mut invalid = result.clone();
            if field == "target" {
                invalid["steps"][0]["target"]["identity"] = json!("S-1-5-21-1-2-3-1002");
            } else {
                invalid["definitionDigest"] = json!(vec![91; 32]);
            }
            let rejected=agent_call(&f.router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{run}/events"),Some(&f.credential),Some(json!({"wireVersion":1,"executionContext":local,"operationId":Uuid::new_v4(),"attemptId":attempt,"event":invalid}))).await?;
            ensure!(
                rejected.0 == StatusCode::BAD_REQUEST,
                "wrong {field} must fail retained-material association: {rejected:?}"
            );
            let unchanged: Value = sqlx::query_scalar(
                "SELECT state FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
            )
            .bind(case_tenant())
            .bind(run)
            .fetch_one(&mut conn)
            .await?;
            ensure!(
                unchanged == before,
                "rejected evidence must not change the running attempt"
            );
        }
    }
    let response=agent_call(&f.router,Method::POST,&format!("/api/v1/agent/runtime/tasks/{run}/events"),Some(&f.credential),Some(json!({"wireVersion":1,"executionContext":local,"operationId":Uuid::new_v4(),"attemptId":attempt,"event":result}))).await?;
    let (state, effect): (Value, Option<Value>) = sqlx::query_as(
        "SELECT state,result FROM mdm_commands.action_runs WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(case_tenant())
    .bind(run)
    .fetch_one(&mut conn)
    .await?;
    if matches!(withdrawal, Withdrawal::None) {
        ensure!(
            response.0 == StatusCode::OK
                && state["execution"] == "succeeded"
                && effect.as_ref().is_some_and(|v| v["effect"] == "verified"),
            "original attempt must finish from retained material: {response:?} {state} {effect:?}"
        );
    } else {
        ensure!(
            state["execution"] != "succeeded"
                && effect.as_ref().is_none_or(|v| v["effect"] != "verified")
        );
        if matches!(withdrawal, Withdrawal::Registration) {
            ensure!(response.0 == StatusCode::UNAUTHORIZED);
        } else {
            ensure!(
                response.0 == StatusCode::OK,
                "safe result intake: {response:?}"
            );
        }
    }
    ensure!(state["delivery"]["attempt"] == task["payload"]["attemptId"]);
    crate::test_support::stop_worker(stack).await?;
    Ok(())
}
