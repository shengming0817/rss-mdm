use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

#[tokio::test]
#[ignore = "MODULE=device-access.http: FileVault device mTLS upload does not require task execution or an employee session"]
async fn cms_upload_has_independent_authorization_and_exact_audit_replay() -> Result<()> {
    use openssl::{
        cms::{CMSOptions, CmsContentInfo},
        stack::Stack,
        symm::Cipher,
        x509::X509,
    };
    let mut f = fixture().await?;
    let requests = crate::test_support::runtime::NativeRequests::new();
    f.resources.resource(requests.clone());
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        let registration=f.register_profile(json!(["inventory.collect.v1"])).await?;
        let protection=f.execution.recovery_credentials().context("recovery fixture")?;
        let custody=Arc::new(rss_mdm_recovery_credentials::FilevaultService::new(f.authority.pool.clone(),f.authority.audit.clone(),protection.clone()));
        let runtime=rss_mdm_agent_channel::boundary::wrap(
            rss_mdm_agent_channel::filevault::routes(f.enrollment.clone(),Some(custody.clone())),
            rss_mdm_agent_channel::boundary::Envelope{admission:Arc::new(tokio::sync::Semaphore::new(32)),requests:Arc::new(tokio::sync::Semaphore::new(32)),
                host:"mdm.example.test:9445".into(),clock:monotonic(),audit_store:f.authority.audit.clone(),tenant:case_tenant().into()});
        f.router=f.router.clone().merge(requests.wrap(Router::new().nest("/api/v1/agent/runtime",runtime.into_axum())));
        let routes=rss_mdm_management_http::recovery_credentials::filevault_routes(Some(custody));
        f.router=f.router.clone().merge(f.authority.protect(rss_mdm_http_contract::Router::new().nest("/api/v1",routes))?);
        let path="/api/v1/agent/runtime/filevault/configuration";
        let initial=agent_call(&f.router,Method::GET,path,Some(execution::case_credential()),None).await?;
        ensure!(initial.0==StatusCode::OK && initial.1["enabled"]==false,"initial configuration: {initial:?}");
        let missing=agent_call(&f.router,Method::GET,path,None,None).await?;ensure!(!missing.0.is_success());
        let managed=format!("/api/v1/devices/{}/recovery-credentials/filevault/configuration",execution::case_device_id());
        let denied_before=crate::audit_test_support::audit_count(|r|r.source()=="mdm.request" && r.status()==403).await?;
        ensure!(f.author.call(&f.router,Method::GET,&managed,None).await?.0==StatusCode::FORBIDDEN);
        ensure!(crate::audit_test_support::audit_count(|r|r.source()=="mdm.request" && r.status()==403).await?==denied_before,
            "ordinary FileVault configuration read acquired management audit");
        let denied=f.author.call(&f.router,Method::POST,&managed,Some(json!({"operationId":Uuid::new_v4(),
            "registration":registration["registrationId"],"generation":registration["generation"],"expectedRevision":0,
            "enabled":true,"recipientId":protection.active_recipient().id()}))).await?;
        ensure!(denied.0==StatusCode::FORBIDDEN,"FileVault mutation denial {denied:?}");
        ensure!(crate::audit_test_support::audit_count(|r|r.source()=="mdm.request" && r.status()==403 && r.result()=="denied").await?==denied_before+1,
            "FileVault mutation lost ingress audit");
        f.grants.extend(crate::test_support::identity::device_grants(None,&["security_operate"])?);
        crate::test_support::identity::seed_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        ensure!(f.author.login_password(&f.router,"other",crate::test_support::identity::PASSWORD).await?==StatusCode::OK);
        let configuration=f.author.call(&f.router,Method::POST,
            &format!("/api/v1/devices/{}/recovery-credentials/filevault/configuration",execution::case_device_id()),
            Some(json!({"operationId":Uuid::new_v4(),"registration":registration["registrationId"],"generation":registration["generation"],"expectedRevision":0,"enabled":true,"recipientId":protection.active_recipient().id()}))).await?;
        ensure!(configuration.0==StatusCode::OK,"configure: {configuration:?}");
        let mut recipients=Stack::new()?;recipients.push(X509::from_der(&protection.active_recipient().certificate_der()?)?)?;
        let cms=CmsContentInfo::encrypt(&recipients,b"ABCD-EFGH-IJKL-MNOP-QRST-UVWX",Cipher::aes_256_cbc(),CMSOptions::BINARY)?.to_der()?;
        let operation=Uuid::new_v4();
        let upload=json!({"operationId":operation,"custodyId":configuration.1["custodyId"],"custodyEpoch":configuration.1["custodyEpoch"],
            "configurationRevision":configuration.1["revision"],"expectedRevision":0,"recipientId":protection.active_recipient().id(),"cmsDigest":format!("{:x}",Sha256::digest(&cms)),"cms":STANDARD.encode(cms)});
        let uri="/api/v1/agent/runtime/filevault/escrows";
        let first=agent_call(&f.router,Method::POST,uri,Some(execution::case_credential()),Some(upload.clone())).await?;
        ensure!(first.0==StatusCode::OK && first.1["escrowed"]==true,"upload status: {}",first.0);
        let replay=agent_call(&f.router,Method::POST,uri,Some(execution::case_credential()),Some(upload.clone())).await?;
        ensure!(replay==first,"exact replay must not produce a new material or audit conflict");
        let status=agent_call(&f.router,Method::GET,&format!("/api/v1/agent/runtime/filevault/operations/{operation}"),Some(execution::case_credential()),None).await?;
        ensure!(status==first);
        let mut changed=upload;changed["configurationRevision"]=json!(999);
        let conflict=agent_call(&f.router,Method::POST,uri,Some(execution::case_credential()),Some(changed)).await?;
        ensure!(conflict.0==StatusCode::CONFLICT);
        ensure!(!first.1.to_string().contains("ABCD-EFGH"));
        let managed=format!("/api/v1/devices/{}/recovery-credentials/filevault/configuration",execution::case_device_id());
        let mut fresh_manager=Browser::default();
        ensure!(fresh_manager.login_password(&f.router,"other",crate::test_support::identity::PASSWORD).await?==StatusCode::OK);
        let read=fresh_manager.call(&f.router,Method::GET,&managed,None).await?;
        ensure!(read.0==StatusCode::OK && read.1["enabled"]==true);
        let disable=json!({"operationId":Uuid::new_v4(),"registration":registration["registrationId"],"generation":registration["generation"],"expectedRevision":0,"enabled":false,"recipientId":protection.active_recipient().id()});
        ensure!(fresh_manager.call(&f.router,Method::POST,&managed,Some(disable.clone())).await?.0==StatusCode::CONFLICT);
        let current=fresh_manager.call(&f.router,Method::GET,&managed,None).await?;
        let mut disable=disable;disable["expectedRevision"]=current.1["revision"].clone();
        let changed=fresh_manager.call(&f.router,Method::POST,&managed,Some(disable)).await?;
        ensure!(changed.0==StatusCode::OK && changed.1["enabled"]==false);

        Ok(())
    }).await
}
