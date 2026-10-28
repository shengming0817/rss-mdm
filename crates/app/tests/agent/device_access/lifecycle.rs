use super::*;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: explicit reinstatement fences old offboarding attempts"]
async fn reinstatement_does_not_reopen_old_offboarding() -> Result<()> {
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let delivery_worker = crate::test_support::software_execution::worker(&f.base, f.execution.clone()).await?;
        let outcome = async {

        let id=enterprise::ready(&mut f).await?;let person=f.author_id.clone();
        let list=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{}/device-access",execution::case_device_id()),None).await?;
        ensure!(list.0==StatusCode::OK,"bindings {list:?}");
        let policy=pg(&format!("SELECT document->>'policy' FROM mdm_access.device_access_bindings WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?.trim().to_owned();
        // A distinct current administrator performs offboarding; self-offboarding is rejected.
        f.author = crate::test_support::authority::Authority::prepared_browser("admin")?;f.access_authenticator=None;
        let operator=prepared_subject(&f.author)?;
        let mut grants=f.grants.clone();
        grants.push(crate::authorization::Grant{operation:crate::authorization::Permission::IdentityAccountsManage,scope:crate::authorization::Scope::Tenant});
        crate::test_support::identity::seed_grants(case_tenant(),&operator,grants.clone()).await?;
        f.author = crate::test_support::authority::Authority::prepared_browser("admin")?;
        let path=format!("/api/v1/devices/{}/device-access/bindings/{id}",execution::case_device_id());
        let successor_login=format!("successor-{}",Uuid::new_v4());
        let successor=f.author.call(&f.router,Method::POST,&format!("/api/v1/identity/tenants/{}/accounts",case_tenant()),Some(json!({"login":successor_login,"password":crate::test_support::identity::PASSWORD}))).await?;
        ensure!(successor.0==StatusCode::CREATED,"successor creation {successor:?}");
        let successor_id=successor.1["principalId"].as_str().context("successor principal")?;
        let mut successor_grants=f.grants.clone();successor_grants.push(crate::authorization::Grant{operation:crate::authorization::Permission::IdentityAccountsManage,scope:crate::authorization::Scope::Tenant});
        crate::test_support::identity::seed_grants(case_tenant(),successor_id,successor_grants).await?;
        let operation=Uuid::new_v4();let offboard=json!({"operationId":operation,"expectedRevision":1,"action":{"kind":"offboard","disposition":"keep"}});
        let result=f.access_call(Method::PUT,&path,Some(offboard.clone())).await?;ensure!(result.0==StatusCode::OK,"offboard {result:?}");
        f.author.cookies.remove("__Host-identity-operation");ensure!(f.author.call(&f.router,Method::PUT,&path,Some(offboard)).await?==result);
        let status_path=format!("/api/v1/devices/{}/device-access/operations/{operation}/offboarding",execution::case_device_id());
        let observe_path=format!("{status_path}/identity");
        let observed=f.author.call(&f.router,Method::POST,&observe_path,Some(json!({"kind":"reconcile"}))).await?;
        ensure!(observed.0==StatusCode::OK && observed.1["operation"]["identity"]=="pending" && observed.1.get("nextCursor").is_none(),"direct active account observation {observed:?}");
        ensure!(f.author.call(&f.router,Method::POST,&format!("{observe_path}?limit=1"),Some(json!({"kind":"reconcile"}))).await?.0==StatusCode::BAD_REQUEST);
        let without_accounts=grants.iter().filter(|grant|grant.operation!=crate::authorization::Permission::IdentityAccountsManage).cloned().collect();
        crate::test_support::identity::change_grants(case_tenant(),&operator,without_accounts).await?;
        let denied=f.author.call(&f.router,Method::POST,&observe_path,Some(json!({"kind":"reconcile"}))).await?;
        ensure!(denied.0==StatusCode::FORBIDDEN,"account read permission required {denied:?}");
        ensure!(f.author.call(&f.router,Method::GET,&status_path,None).await?.1["operation"]["identity"]=="pending");
        crate::test_support::identity::change_grants(case_tenant(),&operator,grants.clone()).await?;
        let person_account=format!("/api/v1/identity/tenants/{}/accounts/{person}/enabled",case_tenant());
        ensure!(f.author.call(&f.router,Method::POST,&person_account,Some(json!({"enabled":false}))).await?.0==StatusCode::OK);
        let observed=f.author.call(&f.router,Method::POST,&observe_path,Some(json!({"kind":"reconcile"}))).await?;
        ensure!(observed.0==StatusCode::OK && observed.1["operation"]["identity"]=="confirmed" && observed.1.get("nextCursor").is_none(),"inactive target observation {observed:?}");
        ensure!(f.author.call(&f.router,Method::POST,&person_account,Some(json!({"enabled":true}))).await?.0==StatusCode::OK);
        crate::test_support::identity::change_grants(case_tenant(),&operator,vec![]).await?;
        ensure!(!f.author.call(&f.router,Method::GET,&status_path,None).await?.0.is_success());
        let mut next=Browser::default();
        ensure!(next.call(&f.router,Method::POST,&format!("/api/v1/identity/tenants/{}/login",case_tenant()),Some(json!({"login":successor_login,"password":crate::test_support::identity::PASSWORD}))).await?.0==StatusCode::OK);
        f.author=next;f.access_authenticator=None;
        let pending=f.author.call(&f.router,Method::GET,&status_path,None).await?;ensure!(pending.0==StatusCode::OK&&pending.1["complete"]==false,"offline offboarding {pending:?}");
        let restored=f.access_call(Method::PUT,&path,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":2,"action":{"kind":"reinstate","instance":INSTANCE,"principal":person,"policy":policy,"account":{"kind":"existing","account":{"platform":"windows","sid":"S-1-5-21-100-200-300-1001","authority":{"kind":"local"}}}}}))).await?;
        ensure!(restored.0==StatusCode::OK,"reinstate {restored:?}");
        let stale=f.author.call(&f.router,Method::POST,&format!("{status_path}/identity"),Some(json!({"kind":"execute"}))).await?;
        ensure!(!stale.0.is_success(),"old offboarding reopened");
        Ok(())
        }.await;
        let stopped = crate::test_support::runtime::stop_worker(delivery_worker).await;
        outcome.and(stopped)

    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: DA recovery requires atomic step-up and preserves its disclosure receipt"]
async fn recovery_disclosure_consumes_one_proof_and_rechecks_current_binding() -> Result<()> {
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let delivery_worker = crate::test_support::software_execution::worker(&f.base, f.execution.clone()).await?;
        let outcome = async {

        f.grants.extend(crate::test_support::identity::device_grants(None,&["credentials"])?);
        let binding=enterprise::ready(&mut f).await?;
        let device=execution::case_device_id();
        let list=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{device}/recovery-credentials"),None).await?;
        ensure!(list.0==StatusCode::OK,"materials {list:?}");
        let material=list.1["items"].as_array().context("materials array")?.iter().find(|m|m["binding"]["subject"]["kind"]=="rss_login").context("DA material")?;
        let id=material["id"].as_str().context("material id")?;let version=material["version"].as_i64().context("version")?;
        let ordinary=format!("/api/v1/devices/{device}/recovery-credentials/{id}/versions/{version}/secret");
        ensure!(!f.author.call(&f.router,Method::GET,&ordinary,None).await?.0.is_success());
        let path=format!("/api/v1/devices/{device}/device-access/materials/{id}/versions/{version}");let body=json!({"operationId":Uuid::new_v4()});
        ensure!(f.author.call(&f.router,Method::POST,&format!("{path}/secret"),Some(body.clone())).await?.0==StatusCode::UNAUTHORIZED);
        ensure!(f.access_authorize(&path,Some(body.clone())).await?.is_none());
        let secret_path=format!("{path}/secret");
        let (a,b)=concurrent_access_calls(&f.router,f.author.clone(),f.author.clone(),Method::POST,&secret_path,body.clone()).await?;
        ensure!(a.0==StatusCode::OK&&b==a,"disclosure statuses {} {}",a.0,b.0);ensure!(a.1["secret"].as_str().is_some_and(|s|!s.is_empty()));
        f.author.cookies.remove("__Host-identity-operation");ensure!(f.author.call(&f.router,Method::POST,&secret_path,Some(body.clone())).await?==a);
        let unbound=f.access_call(Method::PUT,&format!("/api/v1/devices/{device}/device-access/bindings/{binding}"),Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"action":{"kind":"unbind","disposition":"keep"}}))).await?;
        ensure!(unbound.0==StatusCode::OK,"unbind {unbound:?}");
        ensure!(!f.author.call(&f.router,Method::POST,&secret_path,Some(body)).await?.0.is_success());
        Ok(())
        }.await;
        let stopped = crate::test_support::runtime::stop_worker(delivery_worker).await;
        outcome.and(stopped)

    }).await
}
