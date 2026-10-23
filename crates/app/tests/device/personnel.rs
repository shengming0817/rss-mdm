use super::*;
use crate::test_support::{authority::Authority, http::Browser, identity};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    http::{Method, StatusCode},
};
use serde_json::Value;

async fn ok(
    browser: &mut Browser,
    router: &Router,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    let (status, value) = browser.call(router, method, path, body).await?;
    ensure!(
        (status == StatusCode::OK || status == StatusCode::CREATED),
        "personnel request {path}: {status}"
    );
    Ok(value)
}

#[tokio::test]
#[ignore = "MODULE=device.views: real Identity personnel, authorized full-set search and visibility-bound cursors"]
async fn authorized_names_and_local_login_are_projected_before_paging() -> Result<()> {
    let mut authority = Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let (access, service, admin, mut pg) = setup().await?;
        let mut grants = identity::device_grants(None, &["inventory_read", "enrollment"])?;
        grants.extend([crate::authorization::Permission::InventorySensitiveRead, crate::authorization::Permission::UserProfilesRead, crate::authorization::Permission::IdentityAccountsManage].map(|operation|crate::authorization::Grant{operation,scope:crate::authorization::Scope::Tenant}));
        identity::set_grants(case_a(), admin.principal_id(), grants.clone()).await?;
        let service=Arc::new(service);
        let sessions=Arc::new(rss_mdm_authorization_service::session::SessionAuthority::new(authority.identity.authority.clone(),authority.identity.tenant));
        let router = authority.router(Router::new().nest("/api/v1", rss_mdm_management_http::device_views::routes(
            sessions.clone(), authority.identity.authority.clone(), None,
        ).with_state(service.clone())))?;
        let mut browser = authority.browser("admin")?;
        let accounts = format!("/api/v1/identity/tenants/{}/accounts", case_a());
        let login = crate::test_support::case::login("directory-person");
        let target = ok(&mut browser, &router, Method::POST, &accounts,
            Some(json!({"login":login,"password":identity::PASSWORD}))).await?;
        let principal = target["principalId"].as_str().context("new account")?;
        let viewer=ok(&mut browser,&router,Method::POST,&accounts,Some(json!({"login":crate::test_support::case::login("directory-reader"),"password":identity::PASSWORD}))).await?;
        let viewer_id=viewer["principalId"].as_str().context("directory reader")?;
        identity::set_grants(case_a(),viewer_id,grants.clone()).await?;
        let mut reader=Browser::default();
        ensure!(reader.login_password(&router,"directory-reader",identity::PASSWORD).await?==StatusCode::OK);
        let local = format!("{accounts}/{principal}/profile");
        ok(&mut browser, &router, Method::PUT, &local, Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"value":{"displayName":"Directory Person","username":"source-alias","email":null,"extensions":{},"maxAgeSeconds":14400}}))).await?;
        let first = crate::test_support::case::name("aaa-personnel");
        let last = crate::test_support::case::name("zzz-personnel");
        seed(first, "mdm", "personnel-first")?;
        seed(last, "mdm", "personnel-last")?;
        let registration = DeviceService::new(access.registration(), case_a().into(), authority.audit.clone());
        registration.assign_registration_user(&admin, last, &rss_mdm_registration_service::device::registration_user::RegistrationUserChange {
            expected_revision:0,
            user:Some(crate::authorization::User {tenant_id:case_a().into(),instance_id:identity::INSTANCE.into(),principal_id:principal.into()}),
        },Uuid::new_v4(),&RequestAudit::new(case_a().into(),"registration_user_change")).await?;

        // Minimal unrelated accounts force the existing account API's second page. No login,
        // session, profile or searchable device fact is fabricated for these accounts.
        sqlx::query("INSERT INTO identity_authority.accounts(tenant_id,principal_id) SELECT $1::uuid,('00000000-0000-0000-0000-'||lpad(to_hex(n),12,'0'))::uuid FROM generate_series(1,101) n")
            .bind(case_a()).execute(&mut pg).await?;
        sqlx::query("INSERT INTO identity_authority.memberships(tenant_id,principal_id) SELECT tenant_id,principal_id FROM identity_authority.accounts WHERE tenant_id=$1::uuid ON CONFLICT DO NOTHING")
            .bind(case_a()).execute(&mut pg).await?;
        let page = ok(&mut reader,&router,Method::GET,&format!("/api/v1/device-views?limit=1&search={login}"),None).await?;
        ensure!(page["statistics"]["deviceViewCount"]==1 && page["items"][0]["endpoints"][0]["id"]==last);
        let display = &page["items"][0]["endpoints"][0]["registrationUser"]["display"];
        ensure!(display["login"]==login && display["profiles"]==json!([]), "never-logged-in account lost its login");
        let mut person = Browser::default();
        ensure!(person.login_password(&router,"directory-person",identity::PASSWORD).await?==StatusCode::OK);
        let path = format!("/api/v1/device-views/endpoint/{last}");
        let detail = ok(&mut reader,&router,Method::GET,&path,None).await?;
        ensure!(detail["endpoints"][0]["registrationUser"]["display"]["profiles"][0]["displayName"]=="Directory Person");
        ensure!(detail["endpoints"][0]["registrationUser"]["display"]["profiles"][0]["username"]=="source-alias");
        let found=ok(&mut reader,&router,Method::GET,"/api/v1/device-views?limit=1&search=dIrEcToRy%20pErSoN",None).await?;
        ensure!(found["statistics"]["deviceViewCount"]==1, "name search ran after pagination");
        // Middleware proof predates revocation, while both product reads start afterwards.
        // Keep Enrollment and Identity read permissions so only the sensitive fence can hide names.
        let credential=rss_mdm_authorization_service::credential::RequestCredential::Cookie(rss_identity_core::session::SessionSecret::parse(reader.cookies["__Host-identity-session"].clone())?);
        let stale=sessions.authenticate(access.authorization(),credential.duplicate()?).await?;
        stale.require(crate::authorization::Permission::InventorySensitiveRead,None)?;
        identity::set_grants(case_a(),viewer_id,grants.iter().filter(|g|g.operation!=crate::authorization::Permission::InventorySensitiveRead).cloned().collect()).await?;
        let people=people(&authority)?;
        let hidden=service.view(&stale,&ViewRef::Endpoint(last.into()),&people).await?;
        ensure!(hidden["endpoints"][0]["registrationUser"]["user"]["principalId"]==principal);
        ensure!(hidden["endpoints"][0]["registrationUser"]["display"].is_null(),"stale proof disclosed revoked personnel");
        let directory=service.views(&stale,&query(64),&people).await?;
        ensure!(directory["statistics"]["deviceViewCount"]==2);
        ensure!(directory["items"].as_array().context("directory items")?.iter().flat_map(|v|v["endpoints"].as_array().into_iter().flatten()).all(|e|e["registrationUser"]["display"].is_null()));
        for term in ["Directory Person",login] {
            let mut search=query(1);search.search=Some(term.into());
            let hidden=service.views(&stale,&search,&people).await?;
            ensure!(hidden["statistics"]["deviceViewCount"]==0 && hidden["items"]==json!([]),"stale proof made revoked personnel searchable");
        }
        identity::set_grants(case_a(),viewer_id,grants.clone()).await?;
        let page=ok(&mut reader,&router,Method::GET,"/api/v1/device-views?limit=1",None).await?;
        let cursor=page["nextCursor"].as_str().context("two devices")?;
        // The current Identity revision fences personnel pagination.
        sqlx::query("UPDATE identity_authority.accounts SET enabled=false WHERE tenant_id=$1::uuid AND principal_id='00000000-0000-0000-0000-000000000001'").bind(case_a()).execute(&mut pg).await?;
        ensure!(reader.call(&router,Method::GET,&format!("/api/v1/device-views?limit=1&cursor={cursor}"),None).await?.0==StatusCode::CONFLICT);
        let page=ok(&mut reader,&router,Method::GET,"/api/v1/device-views?limit=1",None).await?;
        let cursor=page["nextCursor"].as_str().context("refreshed personnel cursor")?;
        ok(&mut browser,&router,Method::PUT,&local,Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"value":{"displayName":"Renamed Person","username":null,"email":null,"extensions":{},"maxAgeSeconds":14400}}))).await?;
        person=Browser::default();
        ensure!(person.login_password(&router,"directory-person",identity::PASSWORD).await?==StatusCode::OK);
        ensure!(reader.call(&router,Method::GET,&format!("/api/v1/device-views?limit=1&cursor={cursor}"),None).await?.0==StatusCode::CONFLICT);

        for removed in ["user_profiles_read", "identity_accounts_manage", "inventory_sensitive_read"] {
            let remaining=grants.iter().filter(|g| serde_json::to_value(g.operation).ok()!=Some(json!(removed))).cloned().collect();
            identity::set_grants(case_a(),viewer_id,remaining).await?;
            let detail=ok(&mut reader,&router,Method::GET,&path,None).await?;
            let display=&detail["endpoints"][0]["registrationUser"]["display"];
            match removed {
                "user_profiles_read" => ensure!(display["profiles"]==json!([]) && display["login"]==login),
                "identity_accounts_manage" => ensure!(display["login"].is_null() && display["profiles"][0]["displayName"]=="Renamed Person"),
                _ => ensure!(display.is_null()),
            }
        }
        identity::set_grants(case_a(),viewer_id,grants).await?;
        sqlx::query("UPDATE identity_authority.profile_observations SET observed_at=1,expires_at=2 WHERE tenant_id=$1::uuid AND principal_id=$2::uuid").bind(case_a()).bind(principal).execute(&mut pg).await?;
        let detail=ok(&mut reader,&router,Method::GET,&path,None).await?;
        let profile=&detail["endpoints"][0]["registrationUser"]["display"]["profiles"][0];
        ensure!(profile["status"]=="expired" && profile["displayName"].is_null() && profile["username"].is_null());
        ensure!(ok(&mut reader,&router,Method::GET,"/api/v1/device-views?search=renamed",None).await?["statistics"]["deviceViewCount"]==0);
        ok(&mut browser,&router,Method::POST,&format!("{accounts}/{principal}/enabled"),Some(json!({"enabled":false}))).await?;
        ensure!(ok(&mut reader,&router,Method::GET,&path,None).await?["endpoints"][0]["registrationUser"]["display"].is_null());
        // Source-page responses retain their own DTO; personnel enriches endpoints only.
        access.close().await;
        Ok(())
    }).await
}
