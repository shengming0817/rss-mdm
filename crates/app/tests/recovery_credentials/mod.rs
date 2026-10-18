//! Real HTTP and PostgreSQL evidence for direct authorized disclosure and material integrity.
use crate::test_support::*;
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
async fn begin(
    authority: &authority::Authority,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = authority.access.archive_pool().begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(case_tenant())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}
async fn seed(
    authority: &authority::Authority,
    keys: &KeyRing,
    device: &str,
    secret: &str,
) -> Result<Coordinates> {
    let (registration, _) = inventory::seed_source(device, "agent", "agent.builtin", "fixture")?;
    let mut tx = begin(authority).await?;
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
fn route(authority: &authority::Authority, keys: Arc<KeyRing>) -> Result<Router> {
    authority.router(
        Router::new()
            .nest(
                "/api/v1",
                rss_mdm_management_http::recovery_credentials::routes(Some(Arc::new(
                    Credentials::new(
                        authority.access.archive_pool(),
                        authority.audit.clone(),
                        keys,
                    ),
                ))),
            )
            .merge(authority.authorization()),
    )
}
fn secret_url(device: &str, c: &Coordinates) -> String {
    format!(
        "/api/v1/devices/{device}/recovery-credentials/{}/versions/{}/secret",
        c.material, c.version
    )
}

#[tokio::test]
#[ignore = "make t2 MODULE=recovery-credentials.http"]
async fn login_and_device_permission_are_sufficient_over_real_http() -> Result<()> {
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources
        .finish(async {
            let ring = keys("first", true);
            let router = route(&authority, ring.clone())?;
            let device = case::name("recovery-device");
            let secret = "recovery-http-canary-2789";
            let coordinates = seed(&authority, &ring, &device, secret).await?;
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
            let actor = browser_subject(&admin, &router).await?;
            identity::set_grants(
                case_tenant(),
                &actor,
                identity::device_grants(
                    Some(&device),
                    &["inventory_read", "credentials", "account_write"],
                )?,
            )
            .await?;
            identity::age_prepared_admin_session()?;
            let url = secret_url(&device, &coordinates);
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
            authority
                .audit
                .inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
            let (status, failed) = admin.call(&router, Method::GET, &url, None).await?;
            ensure!(!status.is_success() && !failed.to_string().contains(secret));
            identity::set_grants(
                case_tenant(),
                &actor,
                identity::device_grants(Some("another-device"), &["credentials"])?,
            )
            .await?;
            ensure!(admin.call(&router, Method::GET, &url, None).await?.0 == StatusCode::FORBIDDEN);
            identity::set_grants(case_tenant(), &actor, vec![]).await?;
            ensure!(admin.call(&router, Method::GET, &url, None).await?.0 == StatusCode::FORBIDDEN);
            Ok(())
        })
        .await
}

#[tokio::test]
#[ignore = "make t2 MODULE=recovery-credentials.http"]
async fn encrypted_versions_replay_rewrap_and_registration_retirement() -> Result<()> {
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async{
        let first=keys("first",true);let device=case::name("recovery-storage");let secret="storage-recovery-canary-2789";
        let coordinates=seed(&authority,&first,&device,secret).await?;
        let mut tx=begin(&authority).await?;
        let row=sqlx::query("SELECT operation,sealed FROM mdm_recovery.versions WHERE tenant_id=$1 AND entry=$2 AND version=1").bind(coordinates.tenant).bind(coordinates.material).fetch_one(&mut *tx).await?;
        let operation:Uuid=row.try_get("operation")?;let sealed:Vec<u8>=row.try_get("sealed")?;
        ensure!(!sealed.windows(secret.len()).any(|v|v==secret.as_bytes()));
        let replay=storage::reserve_in(&mut tx,coordinates.tenant,&coordinates.binding,operation,0).await?;
        ensure!(replay.version==coordinates.version);
        storage::ingest_in(&mut tx,&first,&coordinates,operation,secret.as_bytes()).await?;
        ensure!(storage::ingest_in(&mut tx,&first,&coordinates,operation,b"different").await.is_err());
        storage::validate_keys_in(&mut tx,coordinates.tenant,&first).await?;
        let next=keys("next",true);ensure!(storage::rewrap_in(&mut tx,coordinates.tenant,&next).await?==1);
        tx.commit().await?;
        let restarted=keys("next",false);let mut tx=begin(&authority).await?;
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
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async{
        let ring=keys("first",true);let device=case::name("recovery-backup");
        let secret="backup-recovery-canary-2789";let c=seed(&authority,&ring,&device,secret).await?;
        let config:Config=serde_json::from_value(authority.base.clone())?;
        let container=std::env::var("MDM_TEST_PG_CONTAINER")?;
        let dump=command(&["exec","-i",&container,"pg_dump","-U","postgres","-d",&config.access_database.name,"--data-only","--schema=mdm_recovery","--disable-triggers","--no-owner","--no-privileges"],None)?;
        ensure!(!dump.contains(secret));
        pg("TRUNCATE mdm_recovery.agent_materials,mdm_recovery.native_actions,mdm_recovery.agent_guards,mdm_recovery.versions,mdm_recovery.entries")?;
        command(&["exec","-i",&container,"psql","-Xq","-U","postgres","-d",&config.access_database.name,"-v","ON_ERROR_STOP=1"],Some(&dump))?;
        let mut tx=begin(&authority).await?;
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
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async{
        let ring=keys("first",true);let device=case::name("recovery-retention");
        let first=seed(&authority,&ring,&device,"first-managed-password").await?;
        let mut tx=begin(&authority).await?;
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
    let mut authority = authority::Authority::open().await?;
    let resources = std::mem::take(&mut authority.resources);
    resources.finish(async {
        let ring=keys("first",true);
        let a=seed(&authority,&ring,&case::name("retention-held"),"first-password").await?;
        let b=seed(&authority,&ring,&case::name("retention-free"),"other-password").await?;
        let mut tx=begin(&authority).await?;
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
