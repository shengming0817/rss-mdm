//! Real HTTP and PostgreSQL evidence for direct authorized disclosure and material integrity.
use crate::test_support::{http::*, process::*, runtime::*, *};
use anyhow::Context;
use rss_mdm_recovery_credentials::{Binding, Coordinates, Credentials, KeyRing, Subject, storage};
use sqlx::Row;
use uuid::Uuid;
use zeroize::Zeroizing;

fn keys(active: &str, old: bool) -> Arc<KeyRing> {
    let mut values = vec![("next".into(), Zeroizing::new(vec![82; 32]))];
    if old {
        values.push(("first".into(), Zeroizing::new(vec![41; 32])))
    }
    Arc::new(KeyRing::new(active.into(), values).unwrap())
}
async fn begin(pool: &sqlx::PgPool) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
async fn seed(
    pool: &sqlx::PgPool,
    keys: &KeyRing,
    device: &str,
    secret: &str,
) -> Result<Coordinates> {
    let (registration, _) = inventory::seed_source(device, "agent", "agent.builtin", "fixture")?;
    let mut tx = begin(pool).await?;
    let binding = Binding {
        device: device.into(),
        registration,
        generation: 1,
        subject: Subject::LocalAdministrator {
            sid: "S-1-5-21-100-200-300-500".into(),
        },
    };
    let operation = Uuid::new_v4();
    let coordinates = storage::reserve_in(
        &mut tx,
        Uuid::parse_str(case_tenant())?,
        &binding,
        operation,
        0,
    )
    .await?;
    storage::ingest_in(&mut tx, keys, &coordinates, operation, secret.as_bytes()).await?;
    storage::verify_in(&mut tx, &coordinates, operation).await?;
    tx.commit().await?;
    Ok(coordinates)
}
fn route(
    authority: &authority::Authority,
    keys: Arc<KeyRing>,
    admission: Arc<dyn rss_mdm_registration_service::device_access::Admission>,
) -> Result<Router> {
    authority.router(
        {
 rss_mdm_http_contract::route_module! { struct RouteModule1 for [Browser] { api_v1 [optional] at "/api/v1", authority } }
 RouteModule1 { api_v1: rss_mdm_management_http::recovery_credentials::routes(
                    Some(Arc::new(Credentials::new(
                        authority.pool.clone(),
                        authority.audit.clone(),
                        keys,
                        None,
                        admission,
                    ))),
                    rss_mdm_query::cursor::CursorCodec::new(&[31; 32])?,
                ),
authority: authority.authorization() }.assemble()
},
    )
}
fn secret_url(device: &str, c: &Coordinates) -> String {
    format!(
        "/api/v1/devices/{device}/recovery-credentials/{}/versions/{}/secret",
        c.material, c.version
    )
}

#[tokio::test]
#[ignore = "MODULE=recovery-credentials.http: RSS binding isolation, concurrent rotation and applied-version fencing"]
async fn rss_login_rotation_is_account_bound_and_keeps_old_material_until_application() -> Result<()>
{
    use rss_mdm_agent_wire::runtime::{
        AccessAccount, AccessConfiguration, AccessEffect, AccessRole,
    };
    use rss_mdm_registration_service::device_access as access;
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources
        .finish(async {
            let keys = keys("first", true);
            let device = case::name("rss-login-recovery");
            let (registration, _) =
                inventory::seed_source(device, "agent", "agent.builtin", "fixture")?;
            let tenant = Uuid::parse_str(case_tenant())?;
            let id = Uuid::new_v4();
            let sid = "S-1-5-21-100-200-300-1001".to_owned();
            let account = AccessAccount::Windows {
                sid: sid.clone(),
                authority: rss_mdm_agent_wire::runtime::AccessWindowsAuthority::Local,
            };
            let b = access::Binding {
                operation_id: Uuid::new_v4(),
                account_disposition: rss_mdm_agent_wire::runtime::AccessAccountDisposition::Keep,
                id,
                tenant,
                device: device.into(),
                registration,
                registration_generation: 1,
                person: access::Person {
                    instance: Uuid::new_v4(),
                    principal: Uuid::new_v4(),
                },
                origin: access::Origin::SelfEnrollment,
                generation: 1,
                factor_generation: 1,
                revision: 1,
                state: access::State::Active,
                intent: access::AccountIntent::Existing {
                    account: account.clone(),
                },
                account: Some(account.clone()),
                policy: Uuid::new_v4(),
                policy_version: Uuid::new_v4(),
                configuration: AccessConfiguration {
                    mac: Some(Default::default()),
                    windows: rss_mdm_agent_wire::runtime::AccessWindowsConfiguration::RssFactor {
                        accounts: vec![rss_mdm_agent_wire::runtime::AccessWindowsKind::Local],
                    },
                    self_enrollment: true,
                    enabled: true,
                    role: None,
                },
                received_revision: Some(1),
                applied_revision: Some(1),
                applied_windows: None,
                effect: Some(AccessEffect::Applied {
                    windows: Some(rss_mdm_agent_wire::runtime::AccessWindowsFacts::RssFactor(
                        rss_mdm_agent_wire::runtime::AccessRssFacts {
                            factor_generation: 1,
                            recovery: rss_mdm_agent_wire::runtime::CredentialReceipt {
                                subject: rss_mdm_agent_wire::runtime::CredentialSubject::RssLogin {
                                    binding: id,
                                    binding_generation: 1,
                                    sid: sid.clone(),
                                },
                                material: Uuid::new_v4(),
                                version: 1,
                            },
                        },
                    )),
                    account,
                    role: AccessRole::Standard,
                    mac: None,
                }),
                created_by_rss: false,
            };
            let mut tx = begin(&authority.pool).await?;
            access::storage::insert_in(&mut tx, &b).await?;
            tx.commit().await?;
            let binding = Binding {
                device: device.into(),
                registration,
                generation: 1,
                subject: Subject::RssLogin {
                    binding: id,
                    binding_generation: 1,
                    sid,
                },
            };
            let first_operation = Uuid::new_v4();
            let secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            let mut tx = begin(&authority.pool).await?;
            let first = storage::reserve_in(&mut tx, tenant, &binding, first_operation, 0).await?;
            storage::ingest_in(&mut tx, &keys, &first, first_operation, secret.as_bytes()).await?;
            storage::verify_in(&mut tx, &first, first_operation).await?;
            tx.commit().await?;
            let reserve = |operation| {
                let authority = &authority;
                let binding = binding.clone();
                async move {
                    let mut tx = begin(&authority.pool).await?;
                    let result = storage::reserve_in(&mut tx, tenant, &binding, operation, 1).await;
                    match result {
                        Ok(c) => {
                            tx.commit().await?;
                            Ok::<_, anyhow::Error>(Some((operation, c)))
                        }
                        Err(rss_mdm_recovery_credentials::Error::Conflict) => {
                            tx.rollback().await?;
                            Ok(None)
                        }
                        Err(e) => Err(e.into()),
                    }
                }
            };
            let (a, z) = tokio::join!(reserve(Uuid::new_v4()), reserve(Uuid::new_v4()));
            let (a, z) = (a?, z?);
            ensure!(
                a.is_some() != z.is_some(),
                "both concurrent rotations were admitted"
            );
            let (operation, next) = a.or(z).context("one rotation admitted")?;
            let mut tx = begin(&authority.pool).await?;
            let again = storage::reserve_in(&mut tx, tenant, &binding, operation, 1).await?;
            ensure!(again.version == next.version);
            let next_secret = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
            storage::ingest_in(&mut tx, &keys, &next, operation, next_secret.as_bytes()).await?;
            let current: Option<i64> = sqlx::query_scalar(
                "SELECT current_version FROM mdm_recovery.entries WHERE tenant_id=$1 AND id=$2",
            )
            .bind(tenant)
            .bind(first.material)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(
                current == Some(1),
                "escrow promoted unconfirmed device effect"
            );
            storage::verify_in(&mut tx, &next, operation).await?;
            let current: Option<i64> = sqlx::query_scalar(
                "SELECT current_version FROM mdm_recovery.entries WHERE tenant_id=$1 AND id=$2",
            )
            .bind(tenant)
            .bind(first.material)
            .fetch_one(&mut *tx)
            .await?;
            ensure!(current == Some(2));
            tx.commit().await?;
            let mut tx = begin(&authority.pool).await?;
            let mut changed = access::storage::locked_in(&mut tx, tenant, id).await?;
            changed.generation = 2;
            changed.revision = 2;
            changed.state = access::State::Revoked;
            changed.configuration.enabled = false;
            access::storage::save_in(&mut tx, &changed, 1).await?;
            tx.commit().await?;
            let mut tx = begin(&authority.pool).await?;
            ensure!(storage::active_in(&mut tx, tenant, &binding).await.is_err());
            tx.rollback().await?;
            let mut tx = begin(&authority.pool).await?;
            ensure!(
                storage::active_in(&mut tx, Uuid::new_v4(), &binding)
                    .await
                    .is_err()
            );
            tx.rollback().await?;
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "make t2 MODULE=recovery-credentials.http"]
async fn login_and_device_permission_are_sufficient_over_real_http() -> Result<()> {
    let mut authority = authority::Authority::open().await?;
    let config: Config = serde_json::from_value(authority.base.clone())?;
    let mut resources = std::mem::take(&mut authority.resources);
    let opened = crate::test_support::agent_runtime::Execution::open(
        &mut authority,
        &config,
        None,
        BTreeMap::new(),
        None,
        None,
        vec![31; 32],
        &mut resources,
    )
    .await;
    let execution = match opened {
        Ok(value) => value.service,
        Err(error) => return resources.finish(async { Err(error) }).await,
    };
    authority.resources = resources;
    let resources = std::mem::take(&mut authority.resources);
    resources
        .finish(async {
            let ring = keys("first", true);
            let router = route(&authority, ring.clone(), execution.clone())?;
            let device = case::name("recovery-device");
            let secret = "recovery-http-canary-2789";
            let coordinates = seed(&authority.pool, &ring, device, secret).await?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address = listener.local_addr()?;
            let app = router.clone();
            let _server =
                planning_http::Server(tokio::spawn(
                    async move { axum::serve(listener, app).await },
                ));
            let network = Some((
                Client::builder().no_proxy().build()?,
                format!("http://{address}"),
            ));
            let mut admin = authority.browser("admin")?;
            admin.network = network.clone();
            let actor = prepared_subject(&admin)?;
            identity::seed_grants(
                case_tenant(),
                &actor,
                identity::device_grants(
                    Some(device),
                    &["inventory_read", "credentials", "account_write"],
                )?,
            )
            .await?;
            identity::age_prepared_admin_session()?;
            let url = secret_url(device, &coordinates);
            let (status, value) = admin.call(&router, Method::GET, &url, None).await?;
            ensure!(
                status == StatusCode::OK,
                "direct credential read: {status} {value}"
            );
            ensure!(value["secret"] == secret);
            let (_, metadata) = admin
                .call(
                    &router,
                    Method::GET,
                    &format!("/api/v1/devices/{device}/recovery-credentials"),
                    None,
                )
                .await?;
            ensure!(!metadata.to_string().contains(secret));
            let mut anonymous = Browser {
                network: network.clone(),
                ..Default::default()
            };
            ensure!(
                anonymous.call(&router, Method::GET, &url, None).await?.0
                    == StatusCode::UNAUTHORIZED
            );
            let mut other = authority.browser("other")?;
            other.network = network;
            ensure!(other.call(&router, Method::GET, &url, None).await?.0 == StatusCode::FORBIDDEN);
            authority.audit.inject_next_fault(
                rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
            );
            let (status, failed) = admin.call(&router, Method::GET, &url, None).await?;
            ensure!(!status.is_success() && !failed.to_string().contains(secret));
            identity::change_grants(
                case_tenant(),
                &actor,
                identity::device_grants(Some("another-device"), &["credentials"])?,
            )
            .await?;
            ensure!(admin.call(&router, Method::GET, &url, None).await?.0 == StatusCode::FORBIDDEN);
            identity::change_grants(case_tenant(), &actor, vec![]).await?;
            ensure!(admin.call(&router, Method::GET, &url, None).await?.0 == StatusCode::FORBIDDEN);
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "make t2 MODULE=recovery-credentials.http"]
async fn encrypted_versions_replay_rewrap_and_registration_retirement() -> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(crate::device::test_support::options("mdm_access")?)
        .await?;
    let mut resources = Resources::default();
    resources.resource(PoolResource(pool.clone()));
    resources.finish(async{
        let first=keys("first",true);let device=case::name("recovery-storage");let secret="storage-recovery-canary-2789";
        let coordinates=seed(&pool,&first,device,secret).await?;
        let mut tx=begin(&pool).await?;
        let row=sqlx::query("SELECT operation,sealed FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=1").bind(coordinates.tenant).bind(coordinates.material).fetch_one(&mut *tx).await?;
        let operation:Uuid=row.try_get("operation")?;let sealed:Vec<u8>=row.try_get("sealed")?;
        ensure!(!sealed.windows(secret.len()).any(|v|v==secret.as_bytes()));
        let replay=storage::reserve_in(&mut tx,coordinates.tenant,&coordinates.binding,operation,0).await?;
        ensure!(replay.version==coordinates.version);
        storage::ingest_in(&mut tx,&first,&coordinates,operation,secret.as_bytes()).await?;
        ensure!(storage::ingest_in(&mut tx,&first,&coordinates,operation,b"different").await.is_err());
        storage::validate_keys_in(&mut tx,coordinates.tenant,&first).await?;
        let next=keys("next",true);let prepared=storage::prepare_rewrap_in(&mut tx,coordinates.tenant,&next).await?;ensure!(storage::rewrap_in(&mut tx,prepared,&next).await?==1);
        tx.commit().await?;
        let restarted=keys("next",false);let mut tx=begin(&pool).await?;
        ensure!(storage::secret_in(&mut tx,&restarted,&coordinates).await?.expose()==secret.as_bytes());
        let mut wrong=coordinates.clone();wrong.binding.device="another-device".into();
        ensure!(storage::secret_in(&mut tx,&restarted,&wrong).await.is_err());
        storage::retire_in(&mut tx,case_tenant(),coordinates.binding.registration).await?;
        ensure!(storage::secret_in(&mut tx,&restarted,&coordinates).await.is_err());
        tx.commit().await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=recovery-credentials.http"]
async fn postgres_backup_restores_material_only_with_the_correct_key() -> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(crate::device::test_support::options("mdm_access")?)
        .await?;
    let mut resources = Resources::default();
    resources.resource(PoolResource(pool.clone()));
    resources.finish(async{
        let ring=keys("first",true);let device=case::name("recovery-backup");
        let secret="backup-recovery-canary-2789";let c=seed(&pool,&ring,device,secret).await?;
        let config:Value=serde_json::from_slice(&std::fs::read(std::env::var("BACKEND_PG_CONFIG")?)?)?;
        let container=config["container"].as_str().context("PG container")?;
        let dump=command(&["exec","-i",container,"pg_dump","-U","postgres","-d",config["database"].as_str().context("PG database")?,"--data-only","--schema=mdm_recovery","--disable-triggers","--no-owner","--no-privileges"],None)?;
        ensure!(!dump.contains(secret));
        pg("TRUNCATE mdm_recovery.disclosures,mdm_recovery.rss_login_uses,mdm_recovery.agent_materials,mdm_recovery.native_actions,mdm_recovery.agent_guards,mdm_recovery.versions,mdm_recovery.entries")?;
        command(&["exec","-i",container,"psql","-Xq","-U","postgres","-d",config["database"].as_str().context("PG database")?,"-v","ON_ERROR_STOP=1"],Some(&dump))?;
        let mut tx=begin(&pool).await?;
        storage::validate_keys_in(&mut tx,c.tenant,&ring).await?;
        ensure!(storage::secret_in(&mut tx,&ring,&c).await?.expose()==secret.as_bytes());
        let wrong=KeyRing::new("first".into(),vec![("first".into(),Zeroizing::new(vec![99;32]))])?;
        ensure!(storage::validate_keys_in(&mut tx,c.tenant,&wrong).await.is_err());
        ensure!(storage::secret_in(&mut tx,&wrong,&c).await.is_err());
        tx.rollback().await?;
        Ok(())
    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=recovery-credentials.http"]
async fn unknown_candidates_block_rotation_and_retention_preserves_unresolved_material()
-> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(crate::device::test_support::options("mdm_access")?)
        .await?;
    let mut resources = Resources::default();
    resources.resource(PoolResource(pool.clone()));
    resources.finish(async{
        let ring=keys("first",true);let device=case::name("recovery-retention");
        let first=seed(&pool,&ring,device,"first-managed-password").await?;
        let mut tx=begin(&pool).await?;
        let operation=Uuid::new_v4();
        let second=storage::reserve_in(&mut tx,first.tenant,&first.binding,operation,1).await?;
        storage::ingest_in(&mut tx,&ring,&second,operation,b"second-managed-password").await?;
        storage::unknown_in(&mut tx,first.tenant,operation).await?;
        ensure!(storage::reserve_in(&mut tx,first.tenant,&first.binding,Uuid::new_v4(),2).await.is_err());
        storage::verify_in(&mut tx,&second,operation).await?;
        sqlx::query("UPDATE mdm_recovery.versions SET invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-7772400 WHERE tenant_id=$1 AND entry=$2 AND version=1").bind(first.tenant).bind(first.material).execute(&mut *tx).await?;
        ensure!(storage::expired_in(&mut tx,first.tenant).await?.is_empty());
        sqlx::query("UPDATE mdm_recovery.versions SET invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-7779600 WHERE tenant_id=$1 AND entry=$2 AND version=1").bind(first.tenant).bind(first.material).execute(&mut *tx).await?;
        ensure!(storage::expired_in(&mut tx,first.tenant).await?.iter().any(|m|m.id==first.material&&m.version==1));
        storage::clear_expired_in(&mut tx,first.tenant,first.material,1).await?;
        let erased:bool=sqlx::query_scalar("SELECT sealed IS NULL AND key_id IS NULL FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=1").bind(first.tenant).bind(first.material).fetch_one(&mut *tx).await?;
        ensure!(erased);
        ensure!(storage::secret_in(&mut tx,&ring,&second).await?.expose()==b"second-managed-password");
        let uncertain=Uuid::new_v4();
        let third=storage::reserve_in(&mut tx,first.tenant,&first.binding,uncertain,2).await?;
        storage::ingest_in(&mut tx,&ring,&third,uncertain,b"unresolved-password").await?;
        storage::retire_in(&mut tx,case_tenant(),first.binding.registration).await?;
        sqlx::query("UPDATE mdm_recovery.versions SET invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-7776001 WHERE tenant_id=$1 AND entry=$2 AND version=3").bind(first.tenant).bind(first.material).execute(&mut *tx).await?;
        ensure!(!storage::expired_in(&mut tx,first.tenant).await?.iter().any(|m|m.version==3));
        let retained:bool=sqlx::query_scalar("SELECT sealed IS NOT NULL AND pending FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=3").bind(first.tenant).bind(first.material).fetch_one(&mut *tx).await?;
        ensure!(retained);
        tx.commit().await?;Ok(())
    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=recovery-credentials.http"]
async fn retention_sweep_skips_protected_registrations_and_advances_past_blocked_copies()
-> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(crate::device::test_support::options("mdm_access")?)
        .await?;
    let mut resources = Resources::default();
    resources.resource(PoolResource(pool.clone()));
    resources.finish(async {
        let ring=keys("first",true);
        let a=seed(&pool,&ring,case::name("retention-held"),"first-password").await?;
        let b=seed(&pool,&ring,case::name("retention-free"),"other-password").await?;
        let mut tx=begin(&pool).await?;
        for revision in 1..=100 {
            let operation=Uuid::new_v4();
            let candidate=storage::reserve_in(&mut tx,a.tenant,&a.binding,operation,revision).await?;
            storage::ingest_in(&mut tx,&ring,&candidate,operation,b"retained-history-password").await?;
            storage::verify_in(&mut tx,&candidate,operation).await?;
        }
        let unresolved=Uuid::new_v4();
        let pending=storage::reserve_in(&mut tx,a.tenant,&a.binding,unresolved,101).await?;
        storage::ingest_in(&mut tx,&ring,&pending,unresolved,b"unknown-password").await?;
        storage::unknown_in(&mut tx,a.tenant,unresolved).await?;
        storage::retire_in(&mut tx,case_tenant(),b.binding.registration).await?;
        sqlx::query("UPDATE mdm_recovery.versions SET invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-8000000 WHERE tenant_id=$1 AND entry=$2 AND invalidated_at IS NOT NULL").bind(a.tenant).bind(a.material).execute(&mut *tx).await?;
        sqlx::query("UPDATE mdm_recovery.versions SET invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-7776001 WHERE tenant_id=$1 AND entry=$2").bind(b.tenant).bind(b.material).execute(&mut *tx).await?;
        let eligible=storage::expired_in(&mut tx,a.tenant).await?;
        ensure!(eligible.iter().any(|m|m.id==b.material));
        ensure!(eligible.iter().all(|m|m.id!=a.material));
        storage::verify_in(&mut tx,&pending,unresolved).await?;
        let batch=storage::expired_in(&mut tx,a.tenant).await?;
        ensure!(batch.len()==100 && batch.iter().all(|m|m.id==a.material));
        for m in batch {storage::cleanup_visited_in(&mut tx,a.tenant,m.id,m.version).await?;}
        ensure!(storage::expired_in(&mut tx,a.tenant).await?.iter().any(|m|m.id==b.material),"blocked copies starved later registration");
        tx.rollback().await?;Ok(())
    }).await
}

#[tokio::test]
#[ignore = "make t2 MODULE=recovery-credentials.http"]
async fn unescrowed_agent_mutation_protects_retired_material_from_expiry() -> Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(crate::device::test_support::options("mdm_access")?)
        .await?;
    let mut resources = Resources::default();
    resources.resource(PoolResource(pool.clone()));
    resources.finish(async{
        let ring=keys("first",true);
        let original=seed(&pool,&ring,case::name("guard-retention"),"possibly-still-current-password").await?;
        let mut tx=begin(&pool).await?;
        storage::start_agent_in(&mut tx,original.tenant,original.binding.registration,original.binding.generation,Uuid::new_v4(),Uuid::new_v4()).await?;
        storage::retire_in(&mut tx,case_tenant(),original.binding.registration).await?;
        sqlx::query("UPDATE mdm_recovery.versions SET invalidated_at=floor(extract(epoch FROM clock_timestamp()))::bigint-7776001 WHERE tenant_id=$1 AND entry=$2").bind(original.tenant).bind(original.material).execute(&mut *tx).await?;
        ensure!(!storage::expired_in(&mut tx,original.tenant).await?.iter().any(|v|v.id==original.material));
        storage::clear_expired_in(&mut tx,original.tenant,original.material,original.version).await?;
        let retained:bool=sqlx::query_scalar("SELECT sealed IS NOT NULL AND key_id IS NOT NULL AND NOT pending FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=$3").bind(original.tenant).bind(original.material).bind(original.version).fetch_one(&mut *tx).await?;
        ensure!(retained);tx.rollback().await?;Ok(())
    }).await
}

#[tokio::test]
#[ignore = "MODULE=recovery-credentials.http: publication and authorization lock order under concurrent HTTP access"]
async fn disclosure_and_revocation_wait_for_publication_before_authorization() -> Result<()> {
    use sqlx::Connection;
    let mut authority = authority::Authority::open().await?;
    let config: Config = serde_json::from_value(authority.base.clone())?;
    let mut resources = std::mem::take(&mut authority.resources);
    let opened = crate::test_support::agent_runtime::Execution::open(
        &mut authority,
        &config,
        None,
        BTreeMap::new(),
        None,
        None,
        vec![31; 32],
        &mut resources,
    )
    .await;
    let execution = match opened {
        Ok(value) => value.service,
        Err(error) => return resources.finish(async { Err(error) }).await,
    };
    authority.resources = resources;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let ring = keys("first", true);
        let router = route(&authority, ring.clone(), execution.clone())?;
        let device = case::name("recovery-lock-order");
        let secret = "recovery-lock-order-canary";
        let coordinates = seed(&authority.pool, &ring, device, secret).await?;
        let mut browser = authority.browser("admin")?;
        let actor = prepared_subject(&browser)?;
        identity::seed_grants(case_tenant(), &actor, identity::device_grants(Some(device), &["credentials", "account_write"])?).await?;
        let mut observer = sqlx::PgConnection::connect_with(&crate::device::test_support::options("postgres")?).await?;
        for (method, path) in [(Method::GET, secret_url(device, &coordinates)), (Method::POST, secret_url(device, &coordinates).replace("/secret", "/revoke"))] {
            let mut hold = observer.begin().await?;
            crate::Database::configure_transaction(&mut hold, case_tenant()).await?;
            rss_mdm_inventory_postgres::lock_watermark_in(&mut hold, rss_request_context::TenantId::parse(case_tenant())?).await?;
            let release = async {
                let observed = tokio::time::timeout(Duration::from_secs(3), async {
                    loop {
                        let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename='mdm_access' AND pg_backend_pid()=ANY(pg_blocking_pids(pid)) AND query LIKE '%mdm.lock_asset_watermark%')").fetch_one(&mut *hold).await?;
                        if waiting { break; }
                        sqlx::query("SELECT pg_stat_clear_snapshot()").execute(&mut *hold).await?;
                        tokio::task::yield_now().await;
                    }
                    let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,2363))").bind(format!("{}:{}", case_tenant(), INSTANCE)).fetch_one(&mut *hold).await?;
                    ensure!(free, "credential request held authorization while waiting for publication");
                    Ok::<_, anyhow::Error>(())
                }).await;
                hold.rollback().await?;
                observed.context("credential request must actually wait for publication")??;
                Ok::<_, anyhow::Error>(())
            };
            let (response, released) = tokio::join!(browser.call(&router, method.clone(), &path, None), release);
            released?;
            let (status, value) = response?;
            ensure!(status == StatusCode::OK, "credential lock order request: {status}");
            if method == Method::GET { ensure!(value["secret"] == secret); }
            else { ensure!(value["validity"] == "revoked"); }
        }
        ensure!(browser.call(&router, Method::GET, &secret_url(device, &coordinates), None).await?.0 == StatusCode::NOT_FOUND);
        observer.close().await?;
        Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "MODULE=recovery-credentials.http: metadata query, composite cursor, device and revision binding"]
async fn metadata_directory_projects_pages_and_invalidates_changed_sources() -> Result<()> {
    let mut authority = authority::Authority::open().await?;
    let config: Config = serde_json::from_value(authority.base.clone())?;
    let mut resources = std::mem::take(&mut authority.resources);
    let opened = crate::test_support::agent_runtime::Execution::open(
        &mut authority,
        &config,
        None,
        BTreeMap::new(),
        None,
        None,
        vec![31; 32],
        &mut resources,
    )
    .await;
    let execution = match opened {
        Ok(value) => value.service,
        Err(error) => return resources.finish(async { Err(error) }).await,
    };
    authority.resources = resources;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async{
 let ring=keys("first",true);
 let router=route(&authority,ring.clone(),execution.clone())?;
 let device=case::name("query-recovery");
 let secret="recovery-directory-private-value";
 let first=seed(&authority.pool,&ring,device,secret).await?;
 let mut tx=begin(&authority.pool).await?;
 let operation=Uuid::new_v4();
 let second=storage::reserve_in(&mut tx,first.tenant,&first.binding,operation,1).await?;
 storage::ingest_in(&mut tx,&ring,&second,operation,secret.as_bytes()).await?;
 storage::verify_in(&mut tx,&second,operation).await?;
 tx.commit().await?;
 let mut admin=authority.browser("admin")?;
 let principal=prepared_subject(&admin)?;
 identity::seed_grants(case_tenant(),&principal,identity::device_grants(None,&["inventory_read","credentials","account_write"])?).await?;
 let path=format!("/api/v1/devices/{device}/recovery-credentials");
 let query="sort=-version&fields=id,version&limit=1";
 let one=admin.call(&router,Method::GET,&format!("{path}?{query}"),None).await?;
 ensure!(one.0==StatusCode::OK&&one.1["items"]==json!([{"id":second.material,"version":2}]),"first {one:?}");
 ensure!(!one.1.to_string().contains(secret));
 let cursor=one.1["nextCursor"].as_str().context("material cursor")?;
 let two=admin.call(&router,Method::GET,&format!("{path}?{query}&cursor={cursor}"),None).await?;
 ensure!(two.0==StatusCode::OK&&two.1["items"]==json!([{"id":first.material,"version":1}])&&two.1["nextCursor"].is_null());
 let current=admin.call(&router,Method::GET,&format!("{path}?filter=current==true&fields=id,version"),None).await?;
 ensure!(current.0==StatusCode::OK&&current.1["items"]==json!([{"id":second.material,"version":2}]));
 for bad in ["fields=secret","fields=sealed","sort=binding","afterId=x&afterVersion=1","limit=101","filter=validity==invalid"]{
 ensure!(admin.call(&router,Method::GET,&format!("{path}?{bad}"),None).await?.0==StatusCode::BAD_REQUEST,"accepted {bad}");
 }
 ensure!(admin.call(&router,Method::GET,&format!("/api/v1/devices/another-device/recovery-credentials?{query}&cursor={cursor}"),None).await?.0==StatusCode::CONFLICT);
 ensure!(admin.call(&router,Method::GET,&format!("{path}?fields=id&cursor={cursor}"),None).await?.0==StatusCode::CONFLICT);
 let revoked=admin.call(&router,Method::POST,&format!("{path}/{}/versions/2/revoke",second.material),None).await?;
 ensure!(revoked.0==StatusCode::OK,"revoke {revoked:?}");
 ensure!(admin.call(&router,Method::GET,&format!("{path}?{query}&cursor={cursor}"),None).await?.0==StatusCode::OK);
 Ok(())
 }).await
}

mod filevault;
