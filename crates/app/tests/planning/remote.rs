//! Removed creation, immutable historical owners and started receipt settlement.
use crate::test_support::agent_execution::*;
use crate::test_support::*;
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "MODULE=planning.remote: HTTP entry retirement and PG history"]
async fn creation_is_removed_and_existing_remote_history_still_settles() -> Result<()> {
    let mut f = Fixture::new().await?;
    f.register().await?;
    claim_request(&f.router, Uuid::new_v4()).await?;
    let (resource, _, _) = f.resource().await?;
    f.scope(
        case_task_scope(),
        json!([{"kind":"device","id":case_device_id()}]),
    )
    .await?;
    let mut grants = f.grants.clone();
    grants.extend(crate::test_support::identity::device_grants(
        None,
        &["operation_read", "operation_cancel"],
    )?);
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, grants).await?;
    let before = pg(&format!(
        "SELECT jsonb_build_array((SELECT count(*) FROM mdm_planning.remote_operations WHERE tenant_id='{t}'),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{t}'))",
        t = case_tenant()
    ))?;
    for kind in [
        "execute",
        "collect_native",
        "apply_configuration",
        "software",
    ] {
        let id = Uuid::new_v4();
        let response=f.author.call(&f.router,Method::POST,"/api/v1/remote-operations",Some(json!({"operationId":id,"resource":policy_definition(resource,case_task_scope())["action"]["resource"],"targets":{"kind":"devices","devices":[case_device_id()]},"action":{"kind":kind},"deadline":crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?+300}))).await?;
        ensure!(
            response.0 == StatusCode::METHOD_NOT_ALLOWED,
            "retired action {kind}: {response:?}"
        );
    }
    ensure!(
        pg(&format!(
            "SELECT jsonb_build_array((SELECT count(*) FROM mdm_planning.remote_operations WHERE tenant_id='{t}'),(SELECT count(*) FROM mdm_commands.action_runs WHERE tenant_id='{t}'))",
            t = case_tenant()
        ))? == before
    );
    let worker = worker(&f.base).await?;
    publish(&mut f.author, &f.router, resource).await?;
    let pending = claim(&f.router).await?;
    publish(&mut f.author, &f.router, resource).await?;
    let started = claim(&f.router).await?;
    task_event(&f.router, &started, json!({"kind":"received"})).await?;
    task_event(&f.router, &started, json!({"kind":"start"})).await?;
    crate::test_support::stop_worker(worker).await?;
    let pending_parent = Uuid::new_v4();
    let started_parent = Uuid::new_v4();
    let pending = historical_remote(&f, &pending, pending_parent).await?;
    let started = historical_remote(&f, &started, started_parent).await?;
    let run = Uuid::parse_str(started["payload"]["task"]["taskId"].as_str().unwrap())?;
    let mut c =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let original:Value=sqlx::query_scalar("SELECT jsonb_build_object('state',state,'offer',(SELECT offer FROM mdm_commands.action_attempts WHERE tenant_id=r.tenant_id AND run=r.id LIMIT 1),'permit',(SELECT permit FROM mdm_commands.action_attempts WHERE tenant_id=r.tenant_id AND run=r.id LIMIT 1)) FROM mdm_commands.action_runs r WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(run).fetch_one(&mut c).await?;
    f.execution.recover_remote_fixture(pending_parent).await?;
    f.execution.recover_remote_fixture(started_parent).await?;
    let start = task_event_request(
        &f.router,
        &pending,
        Uuid::new_v4(),
        &mut json!({"kind":"start"}),
    )
    .await?;
    ensure!(
        start.0 == StatusCode::FORBIDDEN,
        "retired offer regained Start: {start:?}"
    );
    let unchanged:Value=sqlx::query_scalar("SELECT jsonb_build_object('state',state,'offer',(SELECT offer FROM mdm_commands.action_attempts WHERE tenant_id=r.tenant_id AND run=r.id LIMIT 1),'permit',(SELECT permit FROM mdm_commands.action_attempts WHERE tenant_id=r.tenant_id AND run=r.id LIMIT 1)) FROM mdm_commands.action_runs r WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(run).fetch_one(&mut c).await?;
    ensure!(
        unchanged == original,
        "retirement rewrote started execution evidence"
    );
    task_event(&f.router,&started,json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}})).await?;
    let detail = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/remote-operations/{started_parent}"),
            None,
        )
        .await?;
    ensure!(
        detail.0 == StatusCode::OK
            && detail.1["sourceRetired"] == true
            && detail.1["targetExpansionStopped"] == false
            && detail.1["items"][0]["result"]["exitCode"] == 0,
        "historical result: {detail:?}"
    );
    let summary = f
        .author
        .call(&f.router, Method::GET, "/api/v1/remote-operations", None)
        .await?;
    ensure!(
        summary.0 == StatusCode::OK
            && summary.1["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|v| v["sourceRetired"] == true)
    );
    // Unstaged snapshots remain exact history; recovery cannot expand them.
    let unstaged = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_planning.remote_operations(tenant_id,id,resource,resource_version,frozen,snapshot,created_at,deadline,author) SELECT tenant_id,$2,resource,resource_version,frozen,snapshot,created_at,deadline,author FROM mdm_planning.remote_operations WHERE tenant_id=$1::uuid AND id=$3").bind(case_tenant()).bind(unstaged).bind(started_parent).execute(&mut c).await?;
    f.execution.recover_remote_fixture(unstaged).await?;
    let detail = f
        .author
        .call(
            &f.router,
            Method::GET,
            &format!("/api/v1/remote-operations/{unstaged}"),
            None,
        )
        .await?;
    ensure!(
        detail.1["phase"] == "retired"
            && detail.1["targetExpansionStopped"] == true
            && detail.1["items"].as_array().unwrap().is_empty()
    );
    let rights:(bool,bool,bool)=sqlx::query_as("SELECT has_table_privilege('mdm_command_runtime','mdm_planning.remote_operations','INSERT'),has_table_privilege('mdm_command_runtime','mdm_planning.remote_operation_targets','INSERT'),has_column_privilege('mdm_command_runtime','mdm_planning.remote_operations','staged','UPDATE')").fetch_one(&mut c).await?;
    ensure!(
        rights == (false, false, false),
        "runtime can recreate retired sources: {rights:?}"
    );
    c.close().await?;
    Ok(())
}
