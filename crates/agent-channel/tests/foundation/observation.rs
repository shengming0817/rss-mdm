use super::*;
use rss_observation::{
    Access, Authority, JournalReadGrant, LifecycleGrant, ObservationStore, Policy, VerifiedBatch,
};
use rss_projection::{BatchLimit, Control, GenerationStart, ReplayBound, RunLimit, Stop};
struct ReportAuthority {
    scope: rss_observation::Scope,
    coverage: rss_observation::Coverage,
}
impl Authority for ReportAuthority {
    fn authorize(&self, access: Access<'_>) -> std::result::Result<(), rss_observation::Error> {
        let allowed = match access {
            Access::Read { scope } | Access::Activate { scope } => scope == &self.scope,
            Access::Submit { scope, coverage } => {
                scope == &self.scope && coverage == &self.coverage
            }
            Access::ReadJournal { tenant } => tenant == self.scope.tenant(),
        };
        if allowed {
            Ok(())
        } else {
            Err(rss_observation::ErrorKind::Unauthorized.into())
        }
    }
}
impl rss_observation::Clock for context::Timer {
    fn now(&self) -> std::time::Instant {
        rss_request_context::Clock::now(self)
    }
}
pub async fn enrollment(c: &Context, p: &registration::DevicePrincipal) -> Result<()> {
    use rss_mdm_inventory::builtin;
    let definition = rss_mdm_inventory::CollectionDefinition::new(
        builtin::MDM_ENROLLMENT.as_str(),
        "1",
        rss_mdm_inventory::Source::AgentBuiltin,
        builtin::fields()
            .into_iter()
            .filter(|f| f.key == builtin::MDM_ENROLLMENT)
            .map(|definition| rss_mdm_inventory::CollectionField {
                definition,
                scope: rss_mdm_inventory::CollectionScope::Device,
            })
            .collect(),
    )?;
    let wire_definition = w::CollectionDefinition::new(
        builtin::MDM_ENROLLMENT.as_str(),
        "1",
        w::Source::AgentBuiltin,
        definition
            .fields()
            .map(|f| rss_mdm_inventory_service::collection::wire::to_wire_field(f))
            .collect::<std::result::Result<Vec<_>, _>>()?,
    )?;
    let report = w::ReportRequest::new(
        Uuid::new_v4(),
        1,
        now(),
        wire_definition,
        serde_json::from_value(
            json!({"kind":"snapshot","values":[{"field":builtin::MDM_ENROLLMENT.as_str(),"value":{"kind":"value","value":{"kind":"string","value":"unenrolled"}}}]}),
        )?,
    )?;
    let batch = rss_mdm_agent_channel::report_batch(&report)?;
    let scope = registration::device::scope_dataset(
        DA,
        c.tenant,
        p.registration(),
        "agent.builtin",
        p.epoch(),
        builtin::MDM_ENROLLMENT.as_str(),
    )?;
    let mut tx = c.seed().await?;
    rss_mdm_inventory_postgres::register_collection_in(&mut tx, c.tenant, &definition).await?;
    tx.commit().await?;
    let mut tx = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    assert!(
        rss_mdm_inventory_service::collection::agent::accept_in(
            DA, &mut tx, p, &scope, &batch, &report
        )
        .await?
        .1
    );
    assert!(
        !rss_mdm_inventory_service::collection::agent::accept_in(
            DA, &mut tx, p, &scope, &batch, &report
        )
        .await?
        .1
    );
    let run = rss_mdm_inventory_service::collection::store::read_on(
        DA,
        &mut tx,
        &c.tenant.to_string(),
        Uuid::parse_str(batch.id().as_str())?,
    )
    .await?;
    let reference = run.batch().expect("durable sealed report").clone();
    tx.commit().await?;
    let clock = rss_mdm_inventory_service::inventory_runtime::Clock::new(Arc::new(context::Timer));
    let deadline = rss_request_context::Deadline::at(
        rss_observation::Clock::now(&clock) + Duration::from_secs(20),
    );
    let observation = Arc::new(
        rss_observation_postgres::PgStore::new(
            c.inputs.database("da_runtime").pool().await?,
            clock.clone(),
            deadline,
        )
        .await?,
    );
    let authority = ReportAuthority {
        scope: scope.clone(),
        coverage: reference.coverage().clone(),
    };
    observation
        .activate(
            &LifecycleGrant::verify(&authority, scope.clone())?,
            None,
            &Policy::new(86400, 3600, 3600)?,
            deadline,
        )
        .await?;
    observation
        .receive(
            &VerifiedBatch::verify(&authority, scope.clone(), reference)?,
            deadline,
        )
        .await?;
    let projection_scope = rss_mdm_inventory_postgres::projection_scope(c.tenant);
    let source = Arc::new(rss_observation_postgres::PgSource::new(
        observation.clone(),
        JournalReadGrant::verify(&authority, c.tenant)?,
        projection_scope.source().clone(),
    )?);
    let token = tokio_util::sync::CancellationToken::new();
    let control = Control::new(&clock, clock.cutoff(), &token);
    let projection = rss_projection_postgres::PgStore::new(
        c.inputs.database("da_runtime").pool().await?,
        &control,
    )
    .await?;
    let identity = rss_mdm_inventory_postgres::definition();
    projection
        .initialize(
            &projection_scope,
            &identity,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let claim = projection
        .takeover(&projection_scope, &identity, &control)
        .await?;
    let execution = projection.projection(
        claim,
        rss_mdm_inventory_postgres::Inventory::new(source.clone()),
    )?;
    let report = rss_projection::run(
        source.as_ref(),
        &execution,
        &control,
        RunLimit::new(BatchLimit::new(64)?, 256)?,
    )
    .await
    .into_result()?;
    assert_eq!(report.stop, Stop::CaughtUp);
    assert_eq!(report.applied, 1);
    let mut tx = c.access.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(c.tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let observed = rss_mdm_inventory_service::assets::channel::detail_in(
        DA,
        &mut tx,
        c.tenant,
        p.registration(),
        p.generation(),
        rss_mdm_inventory::ReportSource::AgentBuiltin,
    )
    .await?;
    assert!(
        matches!(observed,rss_mdm_inventory::channel::Observation::Ready(fact) if fact.state=="unenrolled")
    );
    tx.rollback().await?;
    let _ = projection.close(&control).await;
    observation.close(deadline).await?;
    Ok(())
}
