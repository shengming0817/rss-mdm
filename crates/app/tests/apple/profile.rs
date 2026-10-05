//! Device creation rejects native configuration; apple.policy owns the profile lifecycle.
use super::*;
use lifecycle::command;
use sqlx::Connection;
#[tokio::test]
#[ignore = "MODULE=apple.profile: closed device contract over HTTP and PG"]
async fn profile_lifecycle_requires_its_policy_owner() -> Result<()> {
    let mut f = Fixture::start().await?;
    let (_peer, device) = f.ready_local_peer().await?;
    for task in [
        profile_task(Uuid::new_v4(), true),
        ddm::task(vec![ddm::subscription("retired")], vec![]),
    ] {
        let id = Uuid::new_v4();
        let response = f.browser.call(&f.router, Method::POST, &format!("/api/v1/devices/{}/operations", case_device()),
            Some(json!({"operationId":id,"deadline":f.app.clock.unix_seconds()?+300,"inputVersion":"1","target":{"kind":"device"},"task":task}))).await?;
        ensure!(
            response.0 == StatusCode::BAD_REQUEST,
            "retired native input: {response:?}"
        );
        ensure!(
            f.browser
                .call(
                    &f.router,
                    Method::GET,
                    &format!("/api/v1/devices/{}/operations/{id}", case_device()),
                    None
                )
                .await?
                .0
                == StatusCode::NOT_FOUND
        );
    }
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.profile: native error requires complete contrary evidence to retire reservations"]
async fn failed_install_partial_manifest_keeps_ownership_until_proven_absent() -> Result<()> {
    let mut f = Fixture::start().await?;
    f.policy_grants().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let owner = f.policy_worker().await?;
    let profile = Uuid::new_v4();
    let (policy, failed) = f
        .configuration_policy(profile_task(profile, true), None, "retain")
        .await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let next = peer.manage("Error", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    let mut partial = profile_manifest(profile, "com.apple.security.firewall");
    partial.as_array_mut().unwrap()[0]
        .as_dictionary_mut()
        .unwrap()
        .insert("PayloadContent".into(), plist::Value::Array(vec![]));
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", partial)),
    )
    .await?;
    ensure!(f.operation(failed).await?["commandStatus"] == "published");
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let guarded:bool=sqlx::query_scalar("SELECT observed_at IS NULL AND retired_at IS NULL FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2").bind(case_tenant()).bind(failed).fetch_one(&mut pg).await?;
    ensure!(
        guarded,
        "partial manifest released failed install reservation"
    );
    // Retain releases the logical claim without pretending the uncertain native effect is absent.
    f.policy_post(
        &format!("/api/v1/policies/{policy}"),
        1,
        json!({"action":"disable"}),
    )
    .await?;
    f.policy_claims_released(policy).await?;
    let guarded: bool = sqlx::query_scalar("SELECT observed_at IS NULL AND retired_at IS NULL FROM mdm_apple.profiles WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(case_tenant()).bind(failed).fetch_one(&mut pg).await?;
    ensure!(guarded, "Policy exit released uncertain native ownership");
    pg.close().await?;
    f.profile_query_due(failed).await?;
    let (observe, _) = peer.next("ProfileList").await?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some(("ProfileList", plist::Value::Array(vec![]))),
    )
    .await?;
    ensure!(f.operation(failed).await?["commandStatus"] == "rejected");
    let replacement_profile = Uuid::new_v4();
    let (_, replacement) = f
        .configuration_policy(profile_task(replacement_profile, false), None, "retain")
        .await?;
    let (execute, _) = peer.next("InstallProfile").await?;
    let next = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    peer.manage(
        "Acknowledged",
        Some(observe),
        Some((
            "ProfileList",
            profile_manifest(replacement_profile, "com.apple.security.firewall"),
        )),
    )
    .await?;
    ensure!(f.operation(replacement).await?["commandStatus"] == "applied");
    ensure!(owner.shutdown().join().await?.is_clean());
    drop(device);
    f.close().await
}

#[tokio::test]
#[ignore = "MODULE=apple.profile: attempt, guards, command and audit share the original transaction"]
async fn profile_confirmation_rolls_back_with_execution_and_audit() -> Result<()> {
    let mut f = Fixture::start().await?;
    f.policy_grants().await?;
    let (peer, device) = f.ready_local_peer().await?;
    let owner = f.policy_worker().await?;
    let profile = Uuid::new_v4();
    let (_, operation) = f
        .configuration_policy(profile_task(profile, true), None, "retain")
        .await?;
    // The Policy runtime has published the command; receipt processing uses the independent execution runtime.
    ensure!(owner.shutdown().join().await?.is_clean());
    let (execute, _) = peer.next("InstallProfile").await?;
    let next = peer.manage("Acknowledged", Some(execute), None).await?;
    let (observe, _) = command(&next, "ProfileList")?;
    let mut pg =
        sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?)
            .await?;
    let operation_key = operation.to_string();
    let observe_key = observe.to_string();
    let audit_count = |records: Vec<crate::audit_test_support::Record>| {
        records
            .iter()
            .filter(|r| {
                r.operation() == Some(operation_key.as_str())
                    || r.operation() == Some(observe_key.as_str())
            })
            .count()
    };
    let before = audit_count(crate::audit_test_support::read(&mut pg).await?);
    let response = protocol::dictionary([
        ("Status", "Acknowledged".into()),
        (
            "UDID",
            crate::test_support::case::name("rss-t2-apple").into(),
        ),
        ("CommandUUID", observe.to_string().into()),
        (
            "ProfileList",
            profile_manifest(profile, "com.apple.security.firewall"),
        ),
    ]);
    // The commit fault is consumed after channel confirmation, reducer and audit SQL have run.
    f.app
        .execution
        .inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    ensure!(peer.send("/mdm", response.clone()).await?.0 == StatusCode::SERVICE_UNAVAILABLE);
    let state:(bool,bool)=sqlx::query_as("SELECT a.response IS NULL AND a.state='sent' AND NOT a.accepted,p.observed_at IS NULL AND p.retired_at IS NULL FROM mdm_apple.attempts a JOIN mdm_apple.profiles p ON(p.tenant_id,p.operation)=(a.tenant_id,a.operation) WHERE a.tenant_id=$1::uuid AND a.id=$2")
        .bind(case_tenant()).bind(observe).fetch_one(&mut pg).await?;
    ensure!(
        state == (true, true),
        "attempt or guards escaped rollback: {state:?}"
    );
    ensure!(
        audit_count(crate::audit_test_support::read(&mut pg).await?) == before,
        "audit escaped rollback"
    );
    ensure!(
        f.operation(operation).await?["commandStatus"] == "received",
        "command escaped rollback"
    );
    ensure!(peer.send("/mdm", response.clone()).await?.0 == StatusCode::OK);
    let detail = f.operation(operation).await?;
    ensure!(
        detail["commandStatus"] == "applied" && detail["observation"]["result"] == "matched",
        "recovery: {detail}"
    );
    let stable = peer.send("/mdm", response.clone()).await?;
    ensure!(
        peer.send("/mdm", response).await? == stable,
        "replay changed response"
    );
    pg.close().await?;
    drop(device);
    f.close().await
}
