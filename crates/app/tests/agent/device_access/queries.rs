use super::*;
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: binding query fields, stable pagination and authorization/data fencing"]
async fn binding_directory_uses_checked_queries_and_signed_continuations() -> Result<()> {
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
        let delivery_worker = crate::test_support::software_execution::worker(&f.base, f.execution.clone()).await?;
        let outcome = async {

 let id=enterprise::ready(&mut f).await?;
 let device=execution::case_device_id();
 let path=format!("/api/v1/devices/{device}/device-access");
 let detail=f.author.call(&f.router,Method::GET,&format!("{path}/bindings/{id}"),None).await?;
 ensure!(detail.0==StatusCode::OK&&detail.1["id"]==id.to_string());
 // Historical bindings may share a person/account; unrelated live uniqueness remains intact.
 let mut c=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
 sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_tenant()).execute(&mut c).await?;
 let caller_tenant:Option<String>=sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)").fetch_one(&mut c).await?;
 sqlx::query("INSERT INTO mdm_access.device_access_bindings SELECT tenant_id,x.id,device,registration,registration_generation,instance,principal,generation,revision,'revoked',account,jsonb_set(jsonb_set(document,'{id}',to_jsonb(x.id)),'{state}','\"revoked\"') FROM mdm_access.device_access_bindings CROSS JOIN (SELECT gen_random_uuid() id FROM generate_series(1,2)) x WHERE tenant_id=$1::uuid AND mdm_access.device_access_bindings.id=$2").bind(case_tenant()).bind(id).execute(&mut c).await?;
 let restored_tenant:Option<String>=sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)").fetch_one(&mut c).await?;
 ensure!(caller_tenant.unwrap_or_default()==restored_tenant.unwrap_or_default(),"trigger leaked the source tenant to its caller");
 let query="sort=-revision&fields=id,revision&limit=1";
 let first=f.author.call(&f.router,Method::GET,&format!("{path}?{query}"),None).await?;
 ensure!(first.0==StatusCode::OK,"page {first:?}");
 let cursor=first.1["nextCursor"].as_str().context("continuation")?;
 ensure!(first.1["items"][0].as_object().unwrap().len()==2);
 let second=f.author.call(&f.router,Method::GET,&format!("{path}?{query}&cursor={cursor}"),None).await?;
 ensure!(second.0==StatusCode::OK&&second.1["items"][0]["id"]!=first.1["items"][0]["id"]);
 let next=second.1["nextCursor"].as_str().context("second continuation")?;
 let last=f.author.call(&f.router,Method::GET,&format!("{path}?{query}&cursor={next}"),None).await?;
 ensure!(last.0==StatusCode::OK&&last.1["items"].as_array().unwrap().len()==1&&last.1["nextCursor"].is_null());
 let filtered=f.author.call(&f.router,Method::GET,&format!("{path}?filter=serverState==active&fields=id"),None).await?;
 ensure!(filtered.0==StatusCode::OK&&filtered.1["items"]==json!([{"id":id}]));
 for bad in ["after=00000000-0000-0000-0000-000000000001","limit=0","limit=101","limit=1&limit=2","fields=secret","sort=desired","filter=unknown==x"]{
 ensure!(f.author.call(&f.router,Method::GET,&format!("{path}?{bad}"),None).await?.0==StatusCode::BAD_REQUEST,"accepted {bad}");
 }
 ensure!(f.author.call(&f.router,Method::GET,&format!("{path}?fields=id&cursor={cursor}"),None).await?.0==StatusCode::CONFLICT);
 let tampered=format!("A{}",&cursor[1..]);
 ensure!(f.author.call(&f.router,Method::GET,&format!("{path}?{query}&cursor={tampered}"),None).await?.0==StatusCode::CONFLICT);
 sqlx::query("UPDATE mdm_access.device_access_bindings SET revision=revision+1,document=jsonb_set(document,'{revision}',to_jsonb(revision+1)) WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).execute(&mut c).await?;
 ensure!(f.author.call(&f.router,Method::GET,&format!("{path}?{query}&cursor={cursor}"),None).await?.0==StatusCode::CONFLICT);
 let fresh=f.author.call(&f.router,Method::GET,&format!("{path}?{query}"),None).await?;
 let cursor=fresh.1["nextCursor"].as_str().context("fresh cursor")?;
 crate::test_support::identity::change_grants(case_tenant(),&f.author_id,vec![]).await?;
 ensure!(f.author.call(&f.router,Method::GET,&format!("{path}?{query}&cursor={cursor}"),None).await?.0==StatusCode::FORBIDDEN);
 c.close().await?;
 Ok(())
        }.await;
        let stopped = crate::test_support::runtime::stop_worker(delivery_worker).await;
        outcome.and(stopped)

 }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: native discovery has a bounded signed scan and rejects management query aliases"]
async fn native_discovery_uses_signed_window_continuation() -> Result<()> {
    let mut f = fixture().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async{
 let (policy,_)=setup_platform(&mut f,false,true).await?;
 ensure!(claim(&f,&windows_context()).await?.0==StatusCode::OK);
 let original=f.author.call(&f.router,Method::GET,&format!("/api/v1/policies/{policy}"),None).await?;
 let other=Uuid::new_v4();
 execution::post(&mut f.author,&f.router,&format!("/api/v1/policies/{other}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":original.1["definition"]}})).await?;
 let first=directory(&f,true,"?limit=1").await?;
 ensure!(first.0==StatusCode::OK&&first.1["policies"].as_array().unwrap().len()==1,"native first {first:?}");
 let cursor=first.1["nextCursor"].as_str().context("native cursor")?;
 let second=directory(&f,true,&format!("?limit=1&cursor={cursor}")).await?;
 ensure!(second.0==StatusCode::OK&&second.1["policies"].as_array().unwrap().len()==1&&second.1["policies"][0]["policy"]!=first.1["policies"][0]["policy"]&&second.1["nextCursor"].is_null(),"native second {second:?}");
 for bad in ["?after=00000000-0000-0000-0000-000000000001","?limit=0","?limit=101","?filter=id==x","?fields=id"]{ensure!(directory(&f,true,bad).await?.0==StatusCode::BAD_REQUEST);}
 let tampered=format!("A{}",&cursor[1..]);
 ensure!(!directory(&f,true,&format!("?cursor={tampered}")).await?.0.is_success());
 Ok(())
 }).await
}
