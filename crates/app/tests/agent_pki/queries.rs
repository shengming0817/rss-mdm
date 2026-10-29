use super::*;
use crate::test_support::{Method, StatusCode, http::Browser};
use anyhow::ensure;

pub(super) async fn snapshot(
    pool: &sqlx::PgPool,
    tenant: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant)
        .execute(&mut *tx)
        .await?;
    let mut result = vec![];
    for table in [
        "mdm_pki.trust",
        "mdm_pki.rotations",
        "mdm_pki.signing",
        "mdm_pki.revocations",
        "mdm_pki.operations",
        "mdm_pki.acknowledgements",
        "mdm_access.agent_grants",
        "mdm_access.agent_issuances",
        "mdm_access.credentials",
        "mdm_access.registration_operations",
        "rss_audit.records",
    ] {
        let mut sql = sqlx::QueryBuilder::new(
            "SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) FROM ",
        );
        sql.push(table)
            .push(" t WHERE tenant_id=")
            .push_bind(tenant.to_owned())
            .push("::uuid");
        result.push(sql.build_query_scalar().fetch_one(&mut *tx).await?);
    }
    tx.rollback().await?;
    Ok(result)
}
#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn rotation_reads_are_durable_and_authorized() -> anyhow::Result<()> {
    use rss_mdm_agent_wire::pki::{Mode, Purpose, Trust};
    let (mut authority, pki, router) = management().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async{
        let mut browser=authority.browser("admin")?;
        let path="/api/v1/pki/agent/rotations/latest";
        ensure!(browser.call(&router,Method::GET,path,None).await?==(StatusCode::OK,serde_json::Value::Null));
        let trust=pki.trust(Purpose::Agent)?;
        let next:Trust=serde_json::from_slice(&std::fs::read(PathBuf::from(std::env::var("MDM_AGENT_PKI_CANDIDATE_FIXTURES")?).join("agent-trust.json"))?)?;
        let mut proposal=trust.clone();proposal.revision+=1;let mut added=next.issuers[0].clone();added.mode=Mode::Prepared;proposal.issuers.push(added);
        let id=Uuid::new_v4();
        ensure!(browser.call(&router,Method::POST,"/api/v1/pki/rotations",Some(serde_json::json!({"id":id,"purpose":"agent","expected_revision":trust.revision,"candidate":proposal}))).await?.0==StatusCode::OK);
        let original_admin=admin(case_a(),"admin-a").await?;
        let history=rss_mdm_pki_service::registry::Registry::new(authority.pool.clone(),authority.audit.clone(),vec![],Arc::new(rss_mdm_pki_service::providers::Providers::new(vec![])?));
        let durable=history.rotation(&original_admin,Purpose::Agent,Some(id),now()).await?.unwrap();
        ensure!(durable.id==id&&durable.distribution_revision==trust.revision+1);
        ensure!(matches!(durable.preconditions.as_slice(),[rss_mdm_pki_service::rotation::Precondition::ProviderNotConfigured]));
        let before=snapshot(&authority.pool,case_a()).await?;
        let(status,view)=browser.call(&router,Method::GET,path,None).await?;
        ensure!(status==StatusCode::OK&&view["id"]==id.to_string()&&view["state"]=="distributing");
        ensure!(view["distributionRevision"]==trust.revision+1&&view["trustRevision"]==trust.revision+1);
        ensure!(view["providerVerification"]=="not_evaluated"&&view["operations"].as_array().unwrap().len()==1);
        let detail=format!("/api/v1/pki/agent/rotations/{id}");
        ensure!(browser.call(&router,Method::GET,&detail,None).await?.1["id"]==id.to_string());
        ensure!(browser.call(&router,Method::GET,&format!("{detail}/blockers?limit=1"),None).await?.0==StatusCode::OK);
        ensure!(browser.call(&router,Method::GET,&format!("{detail}/blockers?limit=0"),None).await?.0==StatusCode::BAD_REQUEST);
        ensure!(before==snapshot(&authority.pool,case_a()).await?,"read mutated PKI, registration or audit");
        let mut anonymous=Browser::default();ensure!(anonymous.call(&router,Method::GET,path,None).await?.0==StatusCode::UNAUTHORIZED);
        let mut other=authority.browser("other")?;
        crate::test_support::http::change_device_grants(&mut other,"some-device",&["credentials"]).await?;
        ensure!(other.call(&router,Method::GET,path,None).await?.0==StatusCode::FORBIDDEN);
        ensure!(browser.call(&router,Method::GET,"/api/v1/pki/invalid/rotations/latest",None).await?.0==StatusCode::BAD_REQUEST);
        let(result,_)=browser.call(&router,Method::POST,"/api/v1/pki/agent/rotations",Some(serde_json::json!({"id":id,"expected_revision":trust.revision+1,"action":"activate"}))).await?;ensure!(result==StatusCode::OK);
        let view=browser.call(&router,Method::GET,&detail,None).await?.1;
        ensure!(view["state"]=="activated"&&view["distributionRevision"]==trust.revision+1&&view["trustRevision"]==trust.revision+2);
        ensure!(browser.call(&router,Method::POST,"/api/v1/pki/agent/rotations",Some(serde_json::json!({"id":id,"expected_revision":trust.revision+2,"action":"retire"}))).await?.0==StatusCode::OK);
        ensure!(browser.call(&router,Method::GET,path,None).await?.1["state"]=="retired");
        Ok(())
    }).await
}
#[tokio::test]
#[ignore = "make t2 MODULE=agent.pki"]
async fn recovery_queries_bind_objects_submitters_and_live_authority() -> anyhow::Result<()> {
    use rss_mdm_registration_service::agent::queries::{REQUESTS, ReceiptIdentity};
    let mut authority = crate::test_support::authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources
        .finish(async {
            let s = service(
                deployment(),
                authority.pool.clone(),
                authority.audit.clone(),
            )
            .await?;
            let p = admin(case_a(), "admin-a").await?;
            let g = grant()?;
            let granted = authorize_request(&s, &p, &g, &audit()).await?;
            let candidate = s.issue(&signing(&g, granted.grant_id)?, &audit()).await?;
            let device = s.request_details(&p, granted.grant_id).await?.device;
            let input = wire::RecoverIssuance {
                wire_version: 1,
                operation_id: Uuid::new_v4(),
                certificate_chain: candidate.certificate_chain.clone(),
            };
            s.recover_issuance(&p, candidate.issuance_id, &input, &audit())
                .await?;
            let mut other = authority.browser("other")?;
            crate::test_support::http::change_device_grants(&mut other, &device, &["credentials"])
                .await?;
            let b = admin(case_a(), "other-a").await?;
            // The read supports the receipt table's full identity. Seed an exact original
            // receipt under a different source instance; do not change the existing write
            // audit identity, which rejects reusing the same business operation across actors.
            let other_instance=format!("{}:original",b.instance_id());
            let mut tx=authority.pool.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(case_a()).execute(&mut *tx).await?;
            let copied=sqlx::query("INSERT INTO mdm_access.registration_operations(tenant_id,actor,instance,operation_id,digest,result,agent_issuance_recovery) SELECT tenant_id,$3,$4,operation_id,digest,result,agent_issuance_recovery FROM mdm_access.registration_operations WHERE tenant_id=$1::uuid AND actor=$2 AND operation_id=$5 AND agent_issuance_recovery=$6")
                .bind(case_a()).bind(p.principal_id()).bind(b.principal_id()).bind(&other_instance).bind(input.operation_id).bind(candidate.issuance_id).execute(&mut *tx).await?;
            ensure!(copied.rows_affected()==1);
            tx.commit().await?;
            let before = snapshot(&authority.pool, case_a()).await?;
            let router = authority.router({
 rss_mdm_http_contract::route_module! { struct RecoveryQueriesBindObjectsSubmittersAndLiveAuthorityModule1 for [Browser] { api_v1 at "/api/v1" } }
 RecoveryQueriesBindObjectsSubmittersAndLiveAuthorityModule1 { api_v1: rss_mdm_management_http::agent_enrollment::routes(Some(s.clone())) }.assemble()
})?;
            let receipt_path = format!(
                "/api/v1/agent-issuances/{}/recovery-operations/{}",
                candidate.issuance_id, input.operation_id
            );
            ensure!(
                other
                    .call(&router, Method::GET, &receipt_path, None)
                    .await?
                    .0
                    == StatusCode::BAD_REQUEST
            );
            let identity = ReceiptIdentity {
                actor: p.principal_id().into(),
                instance: p.instance_id().into(),
            };
            for (actor,instance) in [(p.principal_id(),p.instance_id()),(b.principal_id(),other_instance.as_str())] {
                let path = format!("{receipt_path}?actor={actor}&instance={instance}");
                let (status, value) = other.call(&router, Method::GET, &path, None).await?;
                ensure!(
                    status == StatusCode::OK && value == serde_json::to_value(&candidate)?,
                    "cross-admin exact recovery read failed"
                );
            }
            let missing=format!("/api/v1/agent-issuances/{}/recovery-operations/{}?actor={}&instance={}",Uuid::new_v4(),input.operation_id,p.principal_id(),p.instance_id());
            ensure!(other.call(&router,Method::GET,&missing,None).await?.0==StatusCode::NOT_FOUND);
            let wrong = ReceiptIdentity {
                actor: identity.actor.clone(),
                instance: "wrong".into(),
            };
            ensure!(
                s.issuance_recovery_operation(
                    &b,
                    candidate.issuance_id,
                    input.operation_id,
                    &wrong
                )
                .await
                .is_err()
            );
            ensure!(
                s.issuance_recovery_operation(&b, candidate.issuance_id, Uuid::new_v4(), &identity)
                    .await?
                    .is_none()
            );
            let listing = format!(
                "/api/v1/agent-issuances/{}/recovery-operations?limit=1",
                candidate.issuance_id
            );
            let first = other.call(&router, Method::GET, &listing, None).await?;
            ensure!(first.0 == StatusCode::OK && first.1["items"].as_array().unwrap().len() == 1);
            let cursor = first.1["nextCursor"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("missing second receipt page"))?;
            let second = other
                .call(
                    &router,
                    Method::GET,
                    &format!("{listing}&cursor={cursor}"),
                    None,
                )
                .await?;
            ensure!(
                second.0 == StatusCode::OK
                    && second.1["items"][0]["actor"] != first.1["items"][0]["actor"]
                    && second.1["nextCursor"].is_null()
            );
            let (status, detail) = other
                .call(
                    &router,
                    Method::GET,
                    &format!("/api/v1/agent-requests/{}", granted.grant_id),
                    None,
                )
                .await?;
            ensure!(
                status == StatusCode::OK
                    && detail["issuance"] == candidate.issuance_id.to_string()
                    && detail["activated"] == false
            );
            let page = s
                .request_directory(&b, &device, &REQUESTS.parse("limit=1")?)
                .await?;
            ensure!(!page.items.is_empty());
            ensure!(
                before == snapshot(&authority.pool, case_a()).await?,
                "GET changed original grants, issuance, operations or audit"
            );
            ensure!(
                s.request_directory(&b, "outside-device", &REQUESTS.parse("")?)
                    .await
                    .is_err()
            );
            let (reached, resume) = s.pause_query_before_authority();
            let read = s.request_details(&b, granted.grant_id);
            let revoke = async {
                tokio::time::timeout(Duration::from_secs(5), reached).await??;
                crate::test_support::identity::change_grants(case_a(), b.principal_id(), vec![])
                    .await?;
                resume.notify_one();
                Ok::<_, anyhow::Error>(())
            };
            let (result, changed) = tokio::join!(read, revoke);
            changed?;
            ensure!(
                result.is_err(),
                "revoked authority escaped the data snapshot"
            );
            Ok(())
        })
        .await
}
