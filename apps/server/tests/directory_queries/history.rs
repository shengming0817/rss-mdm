//! Historical selectors consume immutable accepted evidence, independently of current projection.
use super::*;
use crate::{command_runtime_t2_support::seed_transaction, planning_t2_support as planning};
use rss_mdm_install_support::StorageProfile::Mdm;
use rss_mdm_inventory::{
    CollectedValue, CollectionDefinition, CollectionField, CollectionProgress, CollectionScope,
    FieldKey, NativeValue, Scalar, Source,
};
use rss_mdm_inventory_postgres::{CollectionCompletion, seal_collection_in};

pub(super) struct Fixtures {
    device: String,
    duplicate: String,
    no_evidence: String,
}
const U1: &str = "0a1b2c3d-0000-4000-8000-000000000001";
const U2: &str = "0a1b2c3d-0000-4000-8000-000000000002";

pub(super) async fn seed(
    c: &Context,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
) -> Result<Fixtures> {
    let device = planning::endpoint(c).await?.members[0].device.clone();
    let duplicate = planning::endpoint(c).await?.members[0].device.clone();
    let no_evidence = planning::endpoint(c).await?.members[0].device.clone();
    for (target, serial, uuid) in [
        (&device, "Directory-S1", U1),
        (&device, "Directory-S2", U2),
        (&duplicate, "Directory-S1", U1),
    ] {
        seal(c, target, Source::MdmWindows, serial, uuid, true).await?;
    }
    seal(c, &no_evidence, Source::MdmWindows, "Untrusted", U1, false).await?;
    native_registered_at(c, p).await?;
    Ok(Fixtures {
        device,
        duplicate,
        no_evidence,
    })
}

pub(in crate::assembly) struct PreparedCollection {
    scope: rss_observation::Scope,
    run: String,
    sequence: u64,
    progress: CollectionProgress,
}
pub(in crate::assembly) async fn prepare(
    c: &Context,
    device: &str,
    source: Source,
    serial: &str,
    uuid: &str,
) -> Result<PreparedCollection> {
    let mut tx = seed_transaction(c).await?;
    let fields = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .filter(|f| {
            matches!(
                f.key.as_str(),
                "device.serial_number" | "device.hardware_uuid"
            )
        })
        .collect::<Vec<_>>();
    for field in &fields {
        rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, field).await?;
    }
    let definition = CollectionDefinition::new(
        "directory-history",
        "1",
        source,
        fields
            .into_iter()
            .map(|definition| CollectionField {
                definition,
                scope: CollectionScope::Device,
            })
            .collect(),
    )?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, c.tenant, &definition).await?;
    let (epoch,sequence):(Uuid,i64)=sqlx::query_as("UPDATE mdm_access.report_sources SET next_sequence=next_sequence+1 WHERE tenant_id=$1::uuid AND device=$2 AND source=$3 RETURNING epoch,next_sequence")
        .bind(c.tenant.to_string()).bind(device).bind(source.as_str()).fetch_one(&mut *tx).await?;
    let scope = rss_mdm_registration_service::device::scope_dataset(
        Mdm,
        c.tenant,
        device,
        source.as_str(),
        epoch,
        "directory-history",
    )?;
    let progress = CollectionProgress::native(
        definition,
        [
            (
                FieldKey::parse("device.serial_number")?,
                NativeValue::Value(CollectedValue::Value(Scalar::String(serial.into()))),
            ),
            (
                FieldKey::parse("device.hardware_uuid")?,
                NativeValue::Value(CollectedValue::Value(Scalar::String(uuid.into()))),
            ),
        ]
        .into(),
        1,
    )?;
    let run = Uuid::new_v4().to_string();
    tx.commit().await?;
    Ok(PreparedCollection {
        scope,
        run,
        sequence: sequence.try_into()?,
        progress,
    })
}
pub(in crate::assembly) async fn seal(
    c: &Context,
    device: &str,
    source: Source,
    serial: &str,
    uuid: &str,
    trusted: bool,
) -> Result<()> {
    prepare(c, device, source, serial, uuid)
        .await?
        .accept(c, trusted)
        .await
}
impl PreparedCollection {
    pub(in crate::assembly) async fn accept(&self, c: &Context, trusted: bool) -> Result<()> {
        let Self {
            scope,
            run,
            sequence,
            progress,
        } = self;
        let mut tx = seed_transaction(c).await?;
        let completion = || CollectionCompletion {
            trusted,
            scope,
            run,
            sequence: *sequence,
            observed_at: 1,
            progress,
        };
        let first = seal_collection_in(&mut tx, completion()).await?;
        let replay = seal_collection_in(&mut tx, completion()).await?;
        assert_eq!(first.encode(), replay.encode());
        let present:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.device_hardware_evidence WHERE tenant_id=$1::uuid AND scope=$2 AND run=$3)").bind(c.tenant.to_string()).bind(scope.encode()?).bind(&run).fetch_one(&mut *tx).await?;
        assert_eq!(present, trusted);
        // An altered acceptance cannot upgrade trust or replace immutable result coordinates.
        let mut changed = completion();
        changed.trusted = !trusted;
        assert!(seal_collection_in(&mut tx, changed).await.is_err());
        let mut changed = completion();
        changed.observed_at = 2;
        assert!(seal_collection_in(&mut tx, changed).await.is_err());
        tx.commit().await?;
        // Rollback removes both reception and locator evidence.
        let rollback = Uuid::new_v4().to_string();
        let mut tx = seed_transaction(c).await?;
        seal_collection_in(
            &mut tx,
            CollectionCompletion {
                run: &rollback,
                ..completion()
            },
        )
        .await?;
        tx.rollback().await?;
        let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm.collection_results WHERE tenant_id=$1::uuid AND run=$2) OR EXISTS(SELECT FROM mdm.device_hardware_evidence WHERE tenant_id=$1::uuid AND run=$2)").bind(c.tenant.to_string()).bind(&rollback).fetch_one(&c.operator).await?;
        assert!(!exists);
        Ok(())
    }
}

pub(super) async fn exercise(
    c: &Context,
    http: &Http,
    ordinary: &Http,
    f: &Fixtures,
) -> Result<()> {
    let filter = format!(
        "serialNumber==Directory-S1;hardwareUuid=={}",
        U1.to_uppercase()
    );
    let (status, page) = http
        .get("/api/v1/devices", &[("filter", &filter), ("sort", "id")])
        .await?;
    assert_eq!(status, 200, "{page}");
    let expected = [f.device.clone(), f.duplicate.clone()]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    let (status, stats) = http
        .get("/api/v1/devices/statistics", &[("filter", &filter)])
        .await?;
    assert_eq!(status, 200, "{stats}");
    assert_eq!(stats["statistics"]["total"], 2);
    for filter in [
        format!("serialNumber==Directory-S1;hardwareUuid=={U2}"),
        "serialNumber==Untrusted".into(),
    ] {
        let (status, page) = http.get("/api/v1/devices", &[("filter", &filter)]).await?;
        assert_eq!(status, 200, "{page}");
        assert_eq!(page["items"], json!([]));
    }
    let filter = format!("serialNumber==absent,id=={}", f.no_evidence);
    assert_eq!(
        http.selected("/api/v1/devices", &filter).await?["id"],
        f.no_evidence
    );
    for query in [
        [("filter", "serialNumber=icontains=Directory")],
        [("sort", "serialNumber")],
    ] {
        assert_eq!(http.get("/api/v1/devices", &query).await?.0, 400);
    }
    let (status, time_page) = http
        .get(
            "/api/v1/devices",
            &[
                ("filter", "registeredAt=isnotnull=true"),
                ("sort", "registeredAt"),
                ("limit", "1"),
            ],
        )
        .await?;
    assert_eq!(status, 200, "{time_page}");
    assert!(
        time_page["items"][0]["registeredAt"]
            .as_i64()
            .is_some_and(|t| t > 0)
    );
    let cursor = time_page["nextCursor"]
        .as_str()
        .context("registeredAt stable pagination")?;
    let (status, next) = http
        .get(
            "/api/v1/devices",
            &[
                ("filter", "registeredAt=isnotnull=true"),
                ("sort", "registeredAt"),
                ("limit", "1"),
                ("cursor", cursor),
            ],
        )
        .await?;
    assert_eq!(status, 200, "{next}");
    assert_ne!(time_page["items"][0]["id"], next["items"][0]["id"]);
    assert!(next["nextCursor"].is_null());
    assert!(
        http.selected(
            "/api/v1/devices",
            &format!("id=={};registeredAt=isnull=true", f.no_evidence)
        )
        .await?["registeredAt"]
            .is_null()
    );
    let access = c.inputs.pool("shared", "mdm_access").await?;
    let mut tx = access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(Uuid::new_v4().to_string())
        .execute(&mut *tx)
        .await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm.device_hardware_evidence WHERE tenant_id=$1::uuid",
    )
    .bind(c.tenant.to_string())
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 0);
    tx.rollback().await?;
    access.close().await;
    // Hardware remains subject to device scope and the Inventory field owner's search contract.
    let limited = c.account(&[P::InventoryRead]).await?;
    let mut tx = seed_transaction(c).await?;
    sqlx::query("UPDATE mdm_access.authorization_rules SET revision=revision+1,document=jsonb_set(document,'{grants}',$3) WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(limited.rule).bind(json!([{"operation":"inventory_read","scope":{"kind":"device","id":f.device}}])).execute(&mut *tx).await?;
    tx.commit().await?;
    let access::credential::RequestCredential::Cookie(cookie) = limited.credential()? else {
        anyhow::bail!("cookie")
    };
    let limited = Http {
        client: http.client.clone(),
        address: http.address,
        cookie: format!("__Host-identity-session={}", cookie.expose()),
        csrf: cookie.csrf(),
    };
    assert_eq!(
        limited
            .selected("/api/v1/devices", "serialNumber==Directory-S1")
            .await?["id"],
        f.device
    );
    let (status, count) = limited
        .get(
            "/api/v1/devices/statistics",
            &[("filter", "serialNumber==Directory-S1")],
        )
        .await?;
    assert_eq!(status, 200, "{count}");
    assert_eq!(count["statistics"]["total"], 1);
    // Core hardware sensitivity is immutable; tests do not invent a mutable security classification.
    let mut field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.serial_number")
        .unwrap();
    field.version = 2;
    field.searchable = false;
    let mut tx = seed_transaction(c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 1, &field).await?);
    tx.commit().await?;
    for path in ["/api/v1/devices", "/api/v1/devices/statistics"] {
        assert_eq!(
            ordinary
                .get(path, &[("filter", "serialNumber==Directory-S1")])
                .await?
                .0,
            400
        );
    }
    field.version = 3;
    field.searchable = true;
    let mut tx = seed_transaction(c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 2, &field).await?);
    tx.commit().await?;
    let (_, count) = http.get("/api/v1/devices/statistics", &[]).await?;
    let total = count["statistics"]["total"]
        .as_u64()
        .context("device count")?;
    let mut cursor = None;
    let mut ids = std::collections::BTreeSet::new();
    loop {
        let mut query = vec![
            ("sort", "inventoryAvailable"),
            ("fields", "id"),
            ("limit", "1"),
        ];
        if let Some(token) = cursor.as_deref() {
            query.push(("cursor", token));
        }
        let (status, page) = http.get("/api/v1/devices", &query).await?;
        assert_eq!(status, 200, "{page}");
        for item in page["items"].as_array().unwrap() {
            assert!(item.get("inventoryAvailable").is_none());
            assert!(ids.insert(item["id"].as_str().unwrap().to_owned()));
        }
        cursor = page["nextCursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
        assert!(ids.len() as u64 <= total);
    }
    assert_eq!(ids.len() as u64, total);
    // Ordinary Inventory retention cannot erase accepted hardware locations.
    let mut tx = seed_transaction(c).await?;
    sqlx::query("DELETE FROM mdm.collection_results WHERE tenant_id=$1::uuid AND run IN(SELECT run FROM mdm.device_hardware_evidence WHERE tenant_id=$1::uuid AND device=$2)").bind(c.tenant.to_string()).bind(&f.device).execute(&mut *tx).await?;
    tx.commit().await?;
    assert_eq!(
        http.selected(
            "/api/v1/devices",
            &format!(
                "id=={};serialNumber==Directory-S2;hardwareUuid=={U2}",
                f.device
            )
        )
        .await?["id"],
        f.device
    );
    Ok(())
}

async fn native_registered_at(
    c: &Context,
    p: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
) -> Result<()> {
    use rss_mdm_inventory::ReportSource;
    use rss_mdm_registration_service::device::{self, Purpose};
    for source in [ReportSource::MdmWindows, ReportSource::MdmApple] {
        let request = Uuid::new_v4();
        let grant = Uuid::new_v4();
        let device = Uuid::new_v4().to_string();
        let credential = device::ChannelMount::new(Mdm, c.tenant, source, Purpose::Primary)
            .credential(if source == ReportSource::MdmWindows {
                [41; 32]
            } else {
                [42; 32]
            })?;
        let command = device::BindRegistration {
            operation_id: Uuid::new_v4(),
            request_id: request,
            source,
        };
        let mut tx = seed_transaction(c).await?;
        sqlx::query("INSERT INTO mdm_access.grants(tenant_id,id,actor,instance,device,purpose,state,expires_at) VALUES($1::uuid,$2,'directory-history',$3,$4,'enrollment','consumed',clock_timestamp()+interval '4 minutes')").bind(c.tenant.to_string()).bind(grant).bind(p.instance_id()).bind(&device).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_access.requests(tenant_id,id,source,state,grant_id,device,expires_at,issuance_operation,password_digest,password_version,windows_profile) VALUES($1::uuid,$2,$3,'pending',$4,$5,clock_timestamp()+interval '4 minutes',$6,repeat('a',64),1,$7)").bind(c.tenant.to_string()).bind(request).bind(source.as_str()).bind(grant).bind(&device).bind(command.operation_id).bind(if source==ReportSource::MdmWindows{Some("Device")}else{None}).execute(&mut *tx).await?;
        // Bind then abort: successful acceptance and its timestamp have one transaction boundary.
        sqlx::query("SAVEPOINT registration")
            .execute(&mut *tx)
            .await?;
        let before: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *tx)
                .await?;
        let receipt = device::store::bind_in(
            Mdm,
            &mut tx,
            p,
            &credential,
            &command,
            device.clone(),
            [Uuid::new_v4(), Uuid::new_v4()],
        )
        .await?;
        let timestamp: i64 = sqlx::query_scalar(
            "SELECT registered_at FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(c.tenant.to_string())
        .bind(&receipt.device)
        .fetch_one(&mut *tx)
        .await?;
        assert!(timestamp >= before);
        sqlx::query("ROLLBACK TO SAVEPOINT registration")
            .execute(&mut *tx)
            .await?;
        let absent: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS(SELECT FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2)",
        )
        .bind(c.tenant.to_string())
        .bind(&device)
        .fetch_one(&mut *tx)
        .await?;
        assert!(absent);
        let receipt = device::store::bind_in(
            Mdm,
            &mut tx,
            p,
            &credential,
            &command,
            device.clone(),
            [Uuid::new_v4(), Uuid::new_v4()],
        )
        .await?;
        let timestamp: i64 = sqlx::query_scalar(
            "SELECT registered_at FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(c.tenant.to_string())
        .bind(&receipt.device)
        .fetch_one(&mut *tx)
        .await?;
        assert!(
            device::store::bind_in(
                Mdm,
                &mut tx,
                p,
                &credential,
                &command,
                device.clone(),
                [Uuid::new_v4(), Uuid::new_v4()]
            )
            .await
            .is_err()
        );
        let after: i64 = sqlx::query_scalar(
            "SELECT registered_at FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(c.tenant.to_string())
        .bind(&receipt.device)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(timestamp, after);
        tx.commit().await?;
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let mut tx = seed_transaction(c).await?;
        device::store::replace_mdm_credential_in(
            Mdm,
            &mut tx,
            &c.tenant.to_string(),
            &receipt.device,
            receipt.credential,
            &format!("{:064x}", Uuid::new_v4().as_u128()),
        )
        .await?;
        let renewed: i64 = sqlx::query_scalar(
            "SELECT registered_at FROM mdm_access.devices WHERE tenant_id=$1::uuid AND id=$2",
        )
        .bind(c.tenant.to_string())
        .bind(&receipt.device)
        .fetch_one(&mut *tx)
        .await?;
        assert_eq!(renewed, timestamp);
        // Keep the other source's legal locator distinct.
        tx.commit().await?;
    }
    Ok(())
}
