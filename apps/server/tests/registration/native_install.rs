//! Exercise the policy coordinator, frozen native request and bootstrap as one committed command.
use super::super::software_t2::{Fixture, support as software};
use super::*;
use connections::PRIMARY;

pub(super) async fn cold_command() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let n = identity::seed(&c, "windows").await?;
    let materials = support::materials(&c, &n, Uuid::new_v4(), Uuid::new_v4()).await?;
    let pki = support::pki(&c, &n, &materials, PRIMARY, &[]).await?;
    let endpoints = BTreeMap::from([(
        format!("{:x}", Sha256::digest(&n.root)),
        "https://localhost/scep".to_string(),
    )]);
    let host = command::Prepared::open(&c, |config| {
        config["agent_pki"] = json!({"mode":"step_ca","endpoint":{"origin":PRIMARY}});
    })
    .await?;
    let fixture = Fixture::with_endpoints(&c, host, Some(endpoints)).await?;
    let (package, policy, _, _) = support::install_policy(&c, &n).await?;
    software::native_observation(&c, n.device, vec![package.detection_identity()]).await?;
    let target = owner::Target { device: n.device };
    let deferred = software::accept(&c, &fixture, policy, &target, Uuid::new_v4()).await?;
    anyhow::ensure!(
        !matches!(deferred, w::PolicyEventDecision::Accepted { .. }),
        "unexpected command without an available origin"
    );
    fixture.resources.channels.installation(pki)?;
    let decision = software::accept(&c, &fixture, policy, &target, Uuid::new_v4()).await?;
    let w::PolicyEventDecision::Accepted { operations } = decision else {
        anyhow::bail!("cold installation decision {decision:?}")
    };
    let [w::PolicyEventOperation::Native { id }] = operations.as_slice() else {
        anyhow::bail!("expected one native installation")
    };
    assert_frozen(&c, &fixture, *id).await?;
    let changed = support::pki(&c, &n, &materials, "https://localhost", &[]).await?;
    let changed = support::service_with_pki(
        &c,
        fixture.software.authority.clone(),
        fixture.resources.protection.clone(),
        changed,
    )?;
    connections::protect_frozen(&c, &changed).await?;
    fixture.close().await?;
    c.close().await;
    Ok(())
}

async fn assert_frozen(c: &Context, fixture: &Fixture, id: Uuid) -> Result<()> {
    let op = owner::transaction::inspect(
        &fixture.resources.storage.runtime,
        c.execution(),
        (fixture.resources.protection.clone(), id),
        |args, tx| Box::pin(async move { owner::storage::load(tx, &args.0, args.1).await }),
    )
    .await?;
    let owner::authority::Authority::AgentInstall {
        download_origin,
        package,
        ..
    } = op.authority
    else {
        anyhow::bail!("expected frozen installation")
    };
    assert_eq!(download_origin, PRIMARY);
    assert_eq!(
        serde_json::to_value(op.request.task)?,
        serde_json::to_value(package.native_task(id, PRIMARY)?)?
    );
    let origin:String=sqlx::query_scalar("SELECT download_origin FROM mdm_access.agent_bootstraps WHERE tenant_id=$1::uuid AND installation=$2").bind(c.tenant.to_string()).bind(id).fetch_one(&c.operator).await?;
    assert_eq!(origin, PRIMARY);
    Ok(())
}
