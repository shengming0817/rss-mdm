//! Actual read-role query observations for several historical operations of one version.
use crate::authority_t2_support::Context;
use anyhow::Result;
use rss_mdm_native_protection::{ProtectionContext, Protector};
use rss_mdm_policy_service::{application::Application, configuration};
use std::sync::{Arc, Mutex};
use tracing_subscriber::prelude::*;
use uuid::Uuid;

#[derive(Clone, Default)]
struct Reads(Arc<Mutex<Vec<(String, u64)>>>);
#[derive(Default)]
struct Measurement {
    stage: String,
    rows: u64,
    statement: String,
}
impl tracing::field::Visit for Measurement {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "stage" => self.stage = value.into(),
            "db.statement" => self.statement = value.into(),
            _ => {}
        }
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "rows" {
            self.rows = value
        }
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "db.statement" {
            self.statement = format!("{value:?}")
        }
    }
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Reads {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let mut value = Measurement::default();
        event.record(&mut value);
        if value.stage == "configuration.authority" {
            self.0.lock().unwrap().push((value.stage, value.rows));
        }
        if event.metadata().target() == "sqlx::query"
            && value.statement.contains("mdm_policy.versions")
        {
            self.0.lock().unwrap().push(("version-query".into(), 1));
        }
    }
}
async fn historical(c: &Context, key: &Protector, original: Uuid) -> Result<Vec<Uuid>> {
    #[derive(serde::Serialize)]
    struct Identity<'a> {
        operation: Uuid,
        device: &'a str,
        registration: Uuid,
        generation: i64,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Metadata<'a> {
        platform: &'a str,
        deadline: i64,
        input_version: &'a str,
        target: &'a configuration::NativeTarget,
    }
    let mut tx = crate::command_runtime_t2_support::seed_transaction(c).await?;
    let operation = configuration::storage::load_on(&mut tx, c.tenant, key, original).await?;
    let mut ids = vec![original];
    for _ in 0..7 {
        let id = Uuid::new_v4();
        let mut input = operation.request.clone();
        input.operation_id = id;
        let meta = Metadata {
            platform: "windows",
            deadline: input.deadline,
            input_version: &input.input_version,
            target: &input.target,
        };
        let owner = serde_json::to_string(&Identity {
            operation: id,
            device: &operation.device,
            registration: operation.registration,
            generation: operation.registration_generation,
        })?;
        let field = serde_json::to_string(&("native.operation.input/v1", &meta))?;
        let sealed = key.seal_bytes(
            &serde_json::to_vec(&input)?,
            &ProtectionContext::new(c.tenant, &owner, &field, 1)?.derive(),
        )?;
        let digest = input
            .digest(key, c.tenant, &operation.device)?
            .as_bytes()
            .to_vec();
        sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,version) SELECT tenant_id,$3,device_id,generation,authority_epoch,$4,deadline,queued_at,outbox_domain,$5,$4,'published',queued_at,2 FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2")
            .bind(c.tenant.to_string()).bind(original.to_string()).bind(id.to_string()).bind(&digest).bind(format!("dispatch.{id}")).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_planning.configuration_operations(tenant_id,id,device,request,input_context,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,gateway_accepted,policy_version) SELECT tenant_id,$3,device,$4,$5,$6,registration,registration_generation,generation,epoch,authority,$6,true,policy_version FROM mdm_planning.configuration_operations WHERE tenant_id=$1::uuid AND id=$2")
            .bind(c.tenant.to_string()).bind(original).bind(id).bind(sealed).bind(serde_json::to_value(meta)?).bind(digest).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO mdm_windows.native_commands(tenant_id,id,registration,registration_generation) VALUES($1::uuid,$2,$3,$4)").bind(c.tenant.to_string()).bind(id).bind(operation.registration).bind(operation.registration_generation).execute(&mut *tx).await?;
        ids.push(id);
    }
    tx.commit().await?;
    Ok(ids)
}
pub async fn prove_batch(
    c: &Context,
    app: &Application,
    read_pool: &sqlx::PgPool,
    key: &Protector,
    id: Uuid,
) -> Result<()> {
    use rss_mdm_authorization_service::{self as access, Permission};
    use tracing::instrument::WithSubscriber;
    let ids = historical(c, key, id).await?;
    let account = c.account(&[Permission::OperationRead]).await?;
    let proof = c.authenticate(&account).await?;
    let measurements = Reads::default();
    let subscriber = tracing_subscriber::registry().with(measurements.clone());
    let mut tx = read_pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let grant = access::snapshot_on(
        rss_mdm_install_support::StorageProfile::Mdm,
        &mut tx,
        proof.tenant_id(),
        proof.instance_id(),
    )
    .await?;
    let result = app
        .configuration
        .as_ref()
        .expect("MDM configuration")
        .classify_on(
            &mut tx,
            &proof,
            &grant,
            ids.clone(),
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .with_subscriber(subscriber)
        .await?;
    tx.rollback().await?;
    assert_eq!(result.len(), ids.len());
    assert!(result.values().all(|v| matches!(
        v,
        configuration::queries::records::Authorization::Authorized
    )));
    let values = measurements.0.lock().unwrap();
    let versions = values
        .iter()
        .filter(|v| v.0 == "configuration.authority")
        .map(|v| v.1)
        .collect::<Vec<_>>();
    assert_eq!(
        versions,
        vec![1],
        "the version's protected input must be read once before decoding"
    );
    // One claim query, one size query and one bounded payload query, independent of eight operations.
    let queries = values.iter().filter(|v| v.0 == "version-query").count();
    assert_eq!(
        queries, 2,
        "version fetches must be independent of operation count: {values:?}"
    );
    Ok(())
}
