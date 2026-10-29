use super::*;
use sqlx::Connection;
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=device-access.http: binding query fields, stable pagination and authorization/data fencing"]
async fn binding_directory_uses_checked_queries_and_signed_continuations() -> Result<()> {
    let mut f = crate::test_support::current_user::Fixture::new().await?;
    let routes = rss_mdm_management_http::device_access::routes(
        rss_mdm_query::cursor::CursorCodec::new(&[37; 32])?,
        None,
        Some(f.enrollment.clone()),
        f.execution.clone(),
        f.authority.identity.browser(),
    );
    f.router = f.router.merge(
        f.authority
            .protect(rss_mdm_http_contract::Router::new().nest("/api/v1", routes))?,
    );
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
 let registration = f.register_profile(json!(["inventory.collect.v1"])).await?;
 let device=execution::case_device_id();
 f.grants.extend(identity::device_grants(None, &["account_write"])?);
 identity::seed_grants(case_tenant(), &f.author_id, f.grants.clone()).await?;
 let id=Uuid::new_v4();
 let path=format!("/api/v1/devices/{device}/device-access");
 let mut c=sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
 sqlx::query("SELECT set_config('rss.tenant_id',$1,false)").bind(case_tenant()).execute(&mut c).await?;
 let caller_tenant:Option<String>=sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)").fetch_one(&mut c).await?;
 let account = wire::AccessAccount::Macos { generated_uid: Uuid::new_v4() };
 let active = rss_mdm_registration_service::device_access::Binding {
    operation_id: Uuid::new_v4(), account_disposition: wire::AccessAccountDisposition::Keep,
    id, tenant: Uuid::parse_str(case_tenant())?, device: device.into(),
    registration: serde_json::from_value(registration["registrationId"].clone())?, registration_generation: 1,
    person: rss_mdm_registration_service::device_access::Person { instance: Uuid::parse_str(INSTANCE)?, principal: Uuid::parse_str(&f.author_id)? },
    origin: rss_mdm_registration_service::device_access::Origin::SelfEnrollment,
    generation: 1, factor_generation: 1, revision: 1, state: rss_mdm_registration_service::device_access::State::Active,
    intent: rss_mdm_registration_service::device_access::AccountIntent::Existing { account: account.clone() }, account: Some(account.clone()),
    policy: Uuid::new_v4(), policy_version: Uuid::new_v4(),
    configuration: wire::AccessConfiguration { mac: Some(Default::default()), windows: wire::AccessWindowsConfiguration::RssFactor { accounts: vec![wire::AccessWindowsKind::Local] }, self_enrollment: true, enabled: true, role: None },
    received_revision: Some(1), applied_revision: Some(1),
    effect: Some(wire::AccessEffect::Applied { account, role: wire::AccessRole::Standard, mac: None, windows: None }),
    applied_windows: None, created_by_rss: false,
 };
 let mut records=Vec::new();
 for index in 0..3 {
    let mut binding=active.clone();
    if index>0 { binding.id=Uuid::new_v4(); binding.state=rss_mdm_registration_service::device_access::State::Revoked; }
    binding.validate()?;
    records.push(serde_json::to_value(binding)?);
 }
 let inserted=sqlx::query("INSERT INTO mdm_access.device_access_bindings(tenant_id,id,device,registration,registration_generation,instance,principal,generation,revision,state,account,document) SELECT (d->>'tenant')::uuid,(d->>'id')::uuid,d->>'device',(d->>'registration')::uuid,(d->>'registrationGeneration')::bigint,(d->'person'->>'instance')::uuid,(d->'person'->>'principal')::uuid,(d->>'generation')::bigint,(d->>'revision')::bigint,d->>'state',d->'account',d FROM jsonb_array_elements($1) x(d)")
    .bind(json!(records)).execute(&mut c).await?;
 ensure!(inserted.rows_affected()==3);
 let restored_tenant:Option<String>=sqlx::query_scalar("SELECT current_setting('rss.tenant_id',true)").fetch_one(&mut c).await?;
 ensure!(caller_tenant==restored_tenant,"trigger leaked the source tenant to its caller");
 let detail=f.author.call(&f.router,Method::GET,&format!("{path}/bindings/{id}"),None).await?;
 ensure!(detail.0==StatusCode::OK&&detail.1["id"]==id.to_string());
 let mut isolated=f.authority.pool.begin().await?;
 sqlx::query("SELECT set_config('rss.tenant_id',$1,true)").bind(Uuid::new_v4().to_string()).execute(&mut *isolated).await?;
 let foreign:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_access.device_access_bindings WHERE id=$1").bind(id).fetch_one(&mut *isolated).await?;
 ensure!(foreign==0,"binding leaked across RLS tenant");isolated.rollback().await?;
 let peer=case::name("directory-peer");
 inventory::seed_source(peer,"agent","agent.builtin","fixture")?;
 let wrong=f.author.call(&f.router,Method::GET,&format!("/api/v1/devices/{peer}/device-access/bindings/{id}"),None).await?;
 ensure!(!wrong.0.is_success(),"binding leaked across device");
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
 let (reached,resume)=f.authority.registration.pause_query_before_authority();
 let next_path=format!("{path}?{query}&cursor={cursor}");
 let read=f.author.call(&f.router,Method::GET,&next_path,None);
 let update=async {
  tokio::time::timeout(Duration::from_secs(3),reached).await??;
 sqlx::query("UPDATE mdm_access.device_access_bindings SET revision=revision+1,document=jsonb_set(document,'{revision}',to_jsonb(revision+1)) WHERE tenant_id=$1::uuid AND id=$2").bind(case_tenant()).bind(id).execute(&mut c).await?;
  resume.notify_one();Ok::<_,anyhow::Error>(())
 };
 let (continued,updated)=tokio::join!(read,update);updated?;
 ensure!(continued?.0==StatusCode::OK,"registration data update invalidated snapshot response");
 let fresh=f.author.call(&f.router,Method::GET,&format!("{path}?{query}"),None).await?;
 let cursor=fresh.1["nextCursor"].as_str().context("fresh cursor")?;
 crate::test_support::identity::change_grants(case_tenant(),&f.author_id,vec![]).await?;
 ensure!(f.author.call(&f.router,Method::GET,&format!("{path}?{query}&cursor={cursor}"),None).await?.0==StatusCode::FORBIDDEN);
 c.close().await?;
 Ok(())
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
