//! Real management admission, Scope publication and one protected Policy claim per step.
use super::{Context, P, planning};
use crate::authority_t2_support::Account;
use crate::policy_management_t2_support::Fixture;
use anyhow::{Context as _, Result, ensure};
use rss_mdm_policy_service::{
    management::{Change, View, rerun::Rerun},
    operation::Operation,
    worker::PolicyWork,
};
use rss_reconcile::{Completion, Control, DriftKind, DurableStore, ReconcileStep, Scope, Timer};
use serde_json::{Value, json};
use std::{collections::BTreeSet, sync::Arc, time::Duration};
use uuid::Uuid;

struct Worker {
    work: Arc<PolicyWork>,
    pool: sqlx::PgPool,
}
impl Worker {
    async fn open(c: &Context, f: &Fixture) -> Result<Self> {
        let resources = &f.resources;
        let app = crate::assembly::policy::application(
            &resources.resources.background,
            &f.owner,
            c.execution(),
            &[7; 32],
            Arc::new(crate::clock::SystemClock),
            resources.resources.protection.clone(),
            None,
        )
        .await?;
        let events = crate::assembly::policy::events(
            c.execution(),
            app.clone(),
            resources.materials.clone(),
            resources.software.materials.clone(),
            resources.registration.materials.clone(),
            vec![],
        )
        .await?;
        let pool = c.inputs.pool(&c.profile, "mdm_scheduler_runtime").await?;
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = Control::new(&timer, timer.now() + Duration::from_secs(6), &cancel);
        let schedule = rss_mdm_work_page::scheduler::Scheduler::new(pool.clone(), &control).await?;
        Ok(Self {
            work: PolicyWork::new(
                c.database.archive_pool(),
                c.execution().storage(),
                app,
                events,
                schedule,
            ),
            pool,
        })
    }

    /// Hold unrelated claims so the test can interleave a real publication, restart or revocation.
    async fn step(&self, c: &Context, entities: BTreeSet<String>) -> Result<()> {
        let scope = Scope::new(c.tenant, "mdm.policy")?;
        let timer = rss_mdm_policy_service::clock::Timer::new();
        let cancel = tokio_util::sync::CancellationToken::new();
        let control = Control::new(&timer, timer.now() + Duration::from_secs(180), &cancel);
        let batch = self
            .work
            .claim_due(&scope, 512, 1024, Duration::from_secs(180), &control)
            .await?;
        let mut found = BTreeSet::new();
        for claim in batch.claims {
            let entity = claim.target().entity().to_owned();
            if !entities.contains(&entity) {
                self.work.release(&claim, &control).await?;
                continue;
            }
            found.insert(entity.clone());
            let ReconcileStep::Ready(diff) = self.work.observe(&claim, &control).await? else {
                anyhow::bail!("unexpected deferred observation {entity}");
            };
            let completion = if diff.drift() == DriftKind::Converged {
                Completion::Converged
            } else {
                match self
                    .work
                    .apply(&claim, diff, &control)
                    .await
                    .with_context(|| format!("apply {entity}"))?
                {
                    ReconcileStep::Deferred(delay) => Completion::Reobserve(delay),
                    ReconcileStep::Ready(()) => {
                        let ReconcileStep::Ready(next) =
                            self.work.observe(&claim, &control).await?
                        else {
                            anyhow::bail!("deferred verification {entity}");
                        };
                        if next.drift() == DriftKind::Converged {
                            Completion::Converged
                        } else {
                            Completion::Reobserve(Duration::from_millis(1))
                        }
                    }
                }
            };
            self.work.finish(&claim, completion, &control).await?;
        }
        ensure!(
            found == entities,
            "missing claims {:?}",
            entities.difference(&found)
        );
        Ok(())
    }
    async fn close(self) {
        drop(self.work);
        self.pool.close().await;
    }
}
fn jobs(ids: impl IntoIterator<Item = Uuid>) -> BTreeSet<String> {
    ids.into_iter().map(|id| format!("job:{id}")).collect()
}
async fn manager(c: &Context) -> Result<Account> {
    c.account(&[
        P::PolicyRead,
        P::PolicyWrite,
        P::InventoryRead,
        P::DeviceUnmanage,
    ])
    .await
}
async fn submit(c: &Context, f: &Fixture, account: &Account, definition: Value) -> Result<View> {
    let p = c.authenticate(account).await?;
    Ok(f.policies
        .change(
            &p,
            Uuid::new_v4(),
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                input: Change::Put {
                    definition: serde_json::from_value(definition)?,
                    enabled: true,
                },
            },
            &c.request(&p)?,
        )
        .await?)
}
async fn policy(c: &Context, f: &Fixture, account: &Account, size: usize) -> Result<View> {
    let mut targets = vec![];
    for _ in 0..size {
        let object = planning::endpoint(c).await?;
        targets.push(json!({"kind":"device","id":object.members[0].device}));
    }
    submit(
        c,
        f,
        account,
        json!({"scope":{"targets":targets,"limitations":null,"exclusions":[]},
        "action":{"kind":"unmanage_device","runLifetimeSeconds":300}}),
    )
    .await
}
async fn publish(c: &Context, v: &View) -> Result<Uuid> {
    let s = crate::scope_t2::open(c).await?;
    let scope = v.scopes[0].id;
    let run = v.scopes[0].task.context("accepted Scope calculation")?;
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(6));
    let cut = rss_mdm_inventory_service::assets::cut::capture(&c.audit, c.tenant, &budget).await?;
    for _ in 0..512 {
        crate::scope_t2::advance(c.execution(), &s, run, &cut, false).await?;
        let published:bool=sqlx::query_scalar("SELECT resolution IS NOT DISTINCT FROM $3 FROM mdm_scope.scopes WHERE tenant_id=$1 AND id=$2")
            .bind(Uuid::from_bytes(c.tenant.octets())).bind(scope).bind(run).fetch_one(&c.operator).await?;
        if published {
            s.runtime.close().await;
            return Ok(run);
        }
    }
    anyhow::bail!("scope {scope} did not publish");
}
async fn now(c: &Context) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&c.operator)
            .await?,
    )
}
async fn rerun(
    c: &Context,
    f: &Fixture,
    account: &Account,
    v: &View,
    deadline: i64,
) -> Result<(Operation<Rerun>, Uuid)> {
    let op = Operation {
        operation_id: Uuid::new_v4(),
        expected_revision: v.revision as u64,
        input: Rerun { deadline },
    };
    let p = c.authenticate(account).await?;
    let audit = c.request(&p)?;
    let receipt = f.policies.rerun(&p, v.id, &op, &audit).await?;
    audit.finalize(None);
    assert_eq!(
        (
            receipt.operation_id,
            receipt.version_id,
            receipt.policy_id,
            receipt.deadline
        ),
        (op.operation_id, v.version_id, v.id, deadline)
    );
    let work=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_page' AND input->'occurrence'->>'trigger'=$2")
        .bind(c.tenant.to_string()).bind(op.operation_id.to_string()).fetch_one(&c.operator).await?;
    Ok((op, work))
}
async fn children(c: &Context, id: Uuid) -> Result<Vec<Uuid>> {
    Ok(sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='policy_lifecycle' AND input->>'occurrence'=$2 ORDER BY id")
        .bind(c.tenant.to_string()).bind(format!("explicit:{id}")).fetch_all(&c.operator).await?)
}
async fn refresh_members(c: &Context, publication: Uuid) -> Result<BTreeSet<Uuid>> {
    Ok(sqlx::query_scalar("SELECT (input->'occurrence'->>'trigger')::uuid FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_page' AND input->>'publication'=$2")
        .bind(c.tenant.to_string()).bind(publication.to_string()).fetch_all(&c.operator).await?.into_iter().collect())
}
async fn outcome(c: &Context, task: Uuid) -> Result<Value> {
    Ok(sqlx::query_scalar("SELECT retirement_result FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2 AND completed AND (failure IS NULL OR failure='superseded')")
        .bind(c.tenant.to_string()).bind(task).fetch_one(&c.operator).await?)
}

#[tokio::test]
#[ignore = "T2: every admitted retirement rerun survives the former latest-64 boundary and reconciles to the exact device operation"]
async fn every_receipt_reaches_its_device_even_as_new_triggers_arrive() -> Result<()> {
    let c = Context::open("policy_reruns", &[]).await?;
    let f = Fixture::open(&c).await?;
    let account = manager(&c).await?;
    let v = policy(&c, &f, &account, 1).await?;
    let publication = publish(&c, &v).await?;
    let worker = Worker::open(&c, &f).await?;
    let expires = now(&c).await? + 600;
    let mut accepted = vec![];
    for i in 0..65 {
        let end = if i == 64 { expires + 60 } else { expires };
        accepted.push(rerun(&c, &f, &account, &v, end).await?);
    }
    worker.step(&c, jobs([publication, accepted[0].1])).await?;
    assert_eq!(
        refresh_members(&c, publication).await?,
        accepted[..64].iter().map(|r| r.0.operation_id).collect()
    );
    for _ in 0..65 {
        accepted.push(rerun(&c, &f, &account, &v, expires + 1).await?);
    }
    let resume:Uuid=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_refresh' AND input->'page'->>'publication'=$2")
        .bind(c.tenant.to_string()).bind(publication.to_string()).fetch_one(&c.operator).await?;
    worker
        .step(&c, jobs(accepted[1..].iter().map(|r| r.1).chain([resume])))
        .await?;
    assert_eq!(
        refresh_members(&c, publication).await?,
        accepted[..65].iter().map(|r| r.0.operation_id).collect()
    );
    // Each original request reached a device before any other request could retire it.
    let mut device_work = vec![];
    for (op, parent) in &accepted {
        assert_eq!(outcome(&c, *parent).await?["eligible"], 1);
        let child = children(&c, op.operation_id).await?;
        ensure!(
            child.len() == 1,
            "expected one child for {}",
            op.operation_id
        );
        device_work.push(child[0]);
    }
    worker.step(&c, jobs([device_work[0]])).await?;
    let device = match v.definition.scope.targets.first().context("target")? {
        rss_mdm_scope::Reference::Device(d) => *d,
        _ => anyhow::bail!("expected device"),
    };
    let operation: Uuid =
        serde_json::from_value(outcome(&c, device_work[0]).await?["operation"].clone())?;
    // Both parents are admitted while registrations are live, but only run after the first Device operation revokes them.
    let (late, late_parent) = rerun(&c, &f, &account, &v, expires).await?;
    let overlapping = submit(&c, &f, &account, serde_json::to_value(&v.definition)?).await?;
    publish(&c, &overlapping).await?;
    let (overlap, overlap_parent) = rerun(&c, &f, &account, &overlapping, expires).await?;
    let proof = c.authenticate(&account).await?;
    let associations = rss_mdm_device_service::Associations::new(c.audit.clone(), &[7; 32])?;
    Box::pin(associations.force_retirement(
        &proof,
        operation,
        &rss_mdm_device_service::lifecycle_management::ForceRevoke {
            operation_id: Uuid::new_v4(),
            reason: "finish retirement before the queued reruns".into(),
        },
        &c.request(&proof)?,
    ))
    .await?;
    crate::assembly::execution_owners_t2::retirement::device_step(
        &c,
        &f.resources.service,
        operation,
    )
    .await?;
    let revoked:bool=sqlx::query_scalar("SELECT d.state='revoked' AND ch.stage='complete' FROM mdm_access.devices d JOIN mdm_devices.retirement_channels ch ON (ch.tenant_id,ch.device)=(d.tenant_id,d.id) WHERE d.tenant_id=$1::uuid AND ch.operation=$2")
        .bind(c.tenant.to_string()).bind(operation).fetch_one(&c.operator).await?;
    assert!(revoked);
    worker.step(&c, jobs([late_parent, overlap_parent])).await?;
    for op in [late, overlap] {
        let child = children(&c, op.operation_id).await?;
        ensure!(
            child.len() == 1,
            "retained Scope evidence must recognize the completed Device intent"
        );
        worker.step(&c, jobs(child.iter().copied())).await?;
        let result = outcome(&c, child[0]).await?;
        assert_eq!(result, json!({"state":"reused","operation":operation}));
    }
    let linked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_devices.retirement_policies WHERE tenant_id=$1::uuid AND operation=$2 AND policy=$3 AND version=$4)")
        .bind(c.tenant.to_string()).bind(operation).bind(overlapping.id).bind(overlapping.version_id).fetch_one(&c.operator).await?;
    assert!(linked);
    worker
        .step(&c, jobs(device_work[1..].iter().copied()))
        .await?;
    let first = outcome(&c, device_work[0]).await?;
    assert_eq!(first["state"], "accepted");
    let operation = Uuid::parse_str(
        first["operation"]
            .as_str()
            .context("Device operation UUID")?,
    )?;
    let exact:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM mdm_devices.retirements r JOIN mdm_devices.retirement_channels ch ON (ch.tenant_id,ch.operation)=(r.tenant_id,r.id) WHERE r.tenant_id=$1::uuid AND r.id=$2 AND r.policy=$3 AND r.version=$4 AND r.occurrence=$5 AND r.object_id=$6 AND ch.device=$6 AND ch.channel='mdm')")
        .bind(c.tenant.to_string()).bind(operation).bind(v.id).bind(v.version_id)
        .bind(format!("explicit:{}",accepted[0].0.operation_id)).bind(device.into_uuid()).fetch_one(&c.operator).await?;
    assert!(
        exact,
        "receipts must reconcile to the Device owner's original retirement"
    );
    for ((op, _), child) in accepted.iter().zip(device_work) {
        let p = c.authenticate(&account).await?;
        let receipt = f.policies.rerun(&p, v.id, op, &c.request(&p)?).await?;
        assert_eq!(
            (receipt.operation_id, receipt.version_id, receipt.deadline),
            (op.operation_id, v.version_id, op.input.deadline)
        );
        let result = outcome(&c, child).await?;
        assert_eq!(result["operation"], first["operation"]);
        let receipt = rss_mdm_policy_service::management::read::operation_receipt(
            &f.policies,
            &p,
            op.operation_id,
        )
        .await?
        .context("original trigger diagnostic")?;
        assert_eq!(receipt.executions.len(), 1);
        let summary = rss_mdm_policy_service::management::read::work_receipt(
            &f.policies,
            &p,
            receipt.executions[0],
            Some(device),
        )
        .await?
        .context("authorized per-device result")?;
        assert_eq!(summary.state.as_deref(), result["state"].as_str());
        assert!(summary.executions.contains(&child) && summary.executions.contains(&operation));
    }
    let p = c.authenticate(&account).await?;
    let mut changed = accepted[0].0.clone();
    changed.input.deadline -= 1;
    ensure!(matches!(
        f.policies.rerun(&p, v.id, &changed, &c.request(&p)?).await,
        Err(rss_mdm_policy_service::Error::Conflict)
    ));
    worker.close().await;
    f.close().await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: retirement resumes after 64 eligible devices and keeps each exact object and operation"]
async fn one_occurrence_resumes_after_a_committed_device_page() -> Result<()> {
    let c = Context::open("policy_reruns", &[]).await?;
    let f = Fixture::open(&c).await?;
    let account = manager(&c).await?;
    let v = policy(&c, &f, &account, 65).await?;
    publish(&c, &v).await?;
    let (op, parent) = rerun(&c, &f, &account, &v, now(&c).await? + 600).await?;
    let worker = Worker::open(&c, &f).await?;
    let (_, interrupted) = rerun(&c, &f, &account, &v, now(&c).await? + 600).await?;
    worker.step(&c, jobs([parent, interrupted])).await?;
    let initial = children(&c, op.operation_id).await?;
    assert_eq!(initial.len(), 64);
    let checkpoint:Uuid=sqlx::query_scalar("SELECT cursor_id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2 AND NOT completed")
        .bind(c.tenant.to_string()).bind(parent).fetch_one(&c.operator).await?;
    assert!(!checkpoint.is_nil());
    worker.close().await;
    f.close().await?;
    let fresh = Fixture::open(&c).await?;
    let worker = Worker::open(&c, &fresh).await?;
    worker.step(&c, jobs([parent])).await?;
    let device_work = children(&c, op.operation_id).await?;
    assert_eq!(device_work.len(), 65);
    assert!(initial.iter().all(|id| device_work.contains(id)));
    assert_eq!(outcome(&c, parent).await?["eligible"], 65);
    worker.step(&c, jobs(device_work)).await?;
    let matched:i64=sqlx::query_scalar("SELECT count(DISTINCT r.id) FROM mdm_policy.work w JOIN mdm_devices.retirements r ON r.tenant_id=w.tenant_id AND r.id=(w.retirement_result->>'operation')::uuid WHERE w.tenant_id=$1::uuid AND w.input->>'occurrence'=$2 AND w.completed AND r.target=w.input->'object' AND r.occurrence=$2 AND r.version=$3")
        .bind(c.tenant.to_string()).bind(format!("explicit:{}",op.operation_id)).bind(v.version_id).fetch_one(&c.operator).await?;
    assert_eq!(matched, 65);
    let p = c.authenticate(&account).await?;
    fresh
        .policies
        .change(
            &p,
            v.id,
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: v.revision as u64,
                input: Change::Disable,
            },
            &c.request(&p)?,
        )
        .await?;
    worker.step(&c, jobs([interrupted])).await?;
    let partial = outcome(&c, interrupted).await?;
    assert_eq!(partial["state"], "superseded");
    assert_eq!(partial["eligible"], 64);
    worker.close().await;
    fresh.close().await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: calendar and explicit retirement obey the frozen window, expiry, later Scope removal and version"]
async fn calendar_window_and_queued_reruns_recheck_current_authority() -> Result<()> {
    let c = Context::open("policy_reruns", &[]).await?;
    let f = Fixture::open(&c).await?;
    let account = manager(&c).await?;
    let worker = Worker::open(&c, &f).await?;
    let object = planning::endpoint(&c).await?;
    let scope = json!({"targets":[{"kind":"device","id":object.members[0].device}],"limitations":null,"exclusions":[]});
    Box::pin(calendar_authority(&c, &f, &account, &worker, &scope)).await?;
    Box::pin(future_window(&c, &f, &account, &worker, &scope)).await?;
    worker.close().await;
    f.close().await?;
    c.close().await;
    Ok(())
}

async fn revise(
    c: &Context,
    f: &Fixture,
    account: &Account,
    current: &View,
    definition: rss_mdm_policy::Definition<rss_mdm_scope::ScopeDefinition>,
) -> Result<View> {
    let proof = c.authenticate(account).await?;
    let op = Operation {
        operation_id: Uuid::new_v4(),
        expected_revision: current.revision as u64,
        input: Change::Put {
            definition: Box::new(definition),
            enabled: true,
        },
    };
    Ok(Box::pin(
        f.policies
            .change(&proof, current.id, &op, &c.request(&proof)?),
    )
    .await?)
}

// All three transitions refer to the same queued device work and published Scope.
#[expect(
    clippy::cognitive_complexity,
    reason = "assert the causal order of an exact device's withdrawal, readmission and version replacement"
)]
async fn calendar_authority(
    c: &Context,
    f: &Fixture,
    account: &Account,
    worker: &Worker,
    scope: &Value,
) -> Result<()> {
    let t = now(c).await?;
    let calendar=submit(c,f,account,json!({"scope":scope,"action":{"kind":"unmanage_device","runLifetimeSeconds":300,"schedule":{"trigger":{"kind":"once","at":t},"notBefore":0,"jitterSeconds":0}}})).await?;
    publish(c, &calendar).await?;
    worker.step(c, ["schedules".to_owned()].into()).await?;
    let page:Uuid=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_page' AND input->'occurrence'->>'kind'='calendar' AND (input->'occurrence'->>'at')::bigint=$2")
        .bind(c.tenant.to_string()).bind(t).fetch_one(&c.operator).await?;
    let (old, parent) = rerun(c, f, account, &calendar, t + 600).await?;
    let (withdrawn, withdrawn_page) = rerun(c, f, account, &calendar, t + 600).await?;
    worker.step(c, jobs([page, parent, withdrawn_page])).await?;
    assert_eq!(outcome(c, page).await?["eligible"], 1);
    let revoked = children(c, withdrawn.operation_id).await?[0];
    let stale = children(c, old.operation_id).await?[0];
    Box::pin(queued_expiry(c, f, account, worker, &calendar)).await?;
    let mut definition = calendar.definition.clone();
    definition.scope.limitations = Some(Default::default());
    let revised = revise(c, f, account, &calendar, definition).await?;
    assert_eq!(revised.version_id, calendar.version_id);
    publish(c, &revised).await?;
    worker.step(c, jobs([revoked])).await?;
    assert_eq!(outcome(c, revoked).await?["state"], "ineligible");
    let restored = revise(c, f, account, &revised, calendar.definition.clone()).await?;
    let generation = publish(c, &restored).await?;
    worker.step(c, jobs([generation])).await?;
    let retry:Uuid=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_page' AND input->'occurrence'->>'trigger'=$2 AND id<>$3")
        .bind(c.tenant.to_string()).bind(withdrawn.operation_id.to_string()).bind(withdrawn_page).fetch_one(&c.operator).await?;
    worker.step(c, jobs([retry])).await?;
    let replacement = children(c, withdrawn.operation_id)
        .await?
        .into_iter()
        .find(|id| *id != revoked)
        .context("newly eligible object")?;
    worker.step(c, jobs([replacement])).await?;
    assert_eq!(outcome(c, replacement).await?["state"], "accepted");
    let mut new_version = restored.definition.clone();
    if let rss_mdm_policy::Action::UnmanageDevice {
        run_lifetime_seconds,
        ..
    } = &mut new_version.action
    {
        *run_lifetime_seconds += 60;
    }
    let next = revise(c, f, account, &restored, new_version).await?;
    assert_ne!(next.version_id, calendar.version_id);
    worker.step(c, jobs([stale])).await?;
    assert_eq!(outcome(c, stale).await?["state"], "superseded");
    let p = c.authenticate(account).await?;
    assert_eq!(
        f.policies
            .rerun(&p, calendar.id, &old, &c.request(&p)?)
            .await?
            .version_id,
        calendar.version_id
    );

    let effects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND policy=$2",
    )
    .bind(c.tenant.to_string())
    .bind(calendar.id)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(effects, 1);
    Ok(())
}
async fn queued_expiry(
    c: &Context,
    f: &Fixture,
    account: &Account,
    worker: &Worker,
    calendar: &View,
) -> Result<()> {
    let expiry = now(c).await? + 5;
    let (short, short_page) = rerun(c, f, account, calendar, expiry).await?;
    worker.step(c, jobs([short_page])).await?;
    let short_children = children(c, short.operation_id).await?;
    assert_eq!(short_children.len(), 1);
    while now(c).await? < expiry {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    worker.step(c, jobs(short_children.iter().copied())).await?;
    assert_eq!(outcome(c, short_children[0]).await?["state"], "expired");
    let p = c.authenticate(account).await?;
    assert_eq!(
        f.policies
            .rerun(&p, calendar.id, &short, &c.request(&p)?)
            .await?
            .deadline,
        expiry
    );
    Ok(())
}
#[expect(
    clippy::cognitive_complexity,
    reason = "check pending and exhausted admissions from the same wall-clock window"
)]
async fn future_window(
    c: &Context,
    f: &Fixture,
    account: &Account,
    worker: &Worker,
    scope: &Value,
) -> Result<()> {
    let minute = (now(c).await? / 60 + 10) % 1440;
    let delayed=submit(c,f,account,json!({"scope":scope,"action":{"kind":"unmanage_device","runLifetimeSeconds":300,
        "schedule":{"trigger":{"kind":"manual"},"notBefore":0,"jitterSeconds":0,"window":{"zone":"UTC","weekdays":[1,2,3,4,5,6,7],"startMinute":minute,"endMinute":(minute+1)%1440}}}})).await?;
    let (future, future_page) = rerun(c, f, account, &delayed, now(c).await? + 3600).await?;
    let (_, expires) = rerun(c, f, account, &delayed, now(c).await? + 45).await?;
    worker.step(c, jobs([future_page, expires])).await?;
    assert_eq!(outcome(c, expires).await?["state"], "expired");
    let p = c.authenticate(account).await?;
    assert_eq!(
        rss_mdm_policy_service::management::read::work_receipt(&f.policies, &p, expires, None)
            .await?
            .context("expired work receipt")?
            .state
            .as_deref(),
        Some("expired")
    );
    let deferred:bool=sqlx::query_scalar("SELECT NOT w.completed AND t.next_run>clock_timestamp() FROM mdm_policy.work w JOIN rss_reconcile.targets t ON t.tenant_id=w.tenant_id AND t.reconciler='mdm.policy' AND t.entity='job:'||w.id::text WHERE w.tenant_id=$1::uuid AND w.id=$2")
        .bind(c.tenant.to_string()).bind(future_page).fetch_one(&c.operator).await?;
    assert!(deferred);
    assert!(children(c, future.operation_id).await?.is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "T2: the original trigger summarizes a later Scope acceptance and never projects it onto another device"]
async fn original_trigger_reports_later_scope_acceptance_after_its_own_scan_expires() -> Result<()>
{
    let c = Context::open("policy_reruns", &[]).await?;
    let f = Fixture::open(&c).await?;
    let account = manager(&c).await?;
    let v = policy(&c, &f, &account, 1).await?;
    let worker = Worker::open(&c, &f).await?;
    let mut latest_expiry = 0;
    for _ in 0..130 {
        latest_expiry = now(&c).await? + 4;
        rerun(&c, &f, &account, &v, latest_expiry).await?;
    }
    while now(&c).await? < latest_expiry {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let expires = now(&c).await? + 15;
    let (op, parent) = rerun(&c, &f, &account, &v, expires).await?;
    worker.step(&c, jobs([parent])).await?;
    assert!(children(&c, op.operation_id).await?.is_empty());
    let publication = publish(&c, &v).await?;
    worker.step(&c, jobs([publication])).await?;
    assert_eq!(
        refresh_members(&c, publication).await?,
        [op.operation_id].into()
    );
    let continuations:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_refresh' AND input#>>'{page,publication}'=$2")
        .bind(c.tenant.to_string()).bind(publication.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(
        continuations, 0,
        "expired requests must consume no slots on the first business page"
    );
    let refresh:Uuid=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND input->>'publication'=$2 AND input#>>'{occurrence,trigger}'=$3")
        .bind(c.tenant.to_string()).bind(publication.to_string()).bind(op.operation_id.to_string()).fetch_one(&c.operator).await?;
    worker.step(&c, jobs([refresh])).await?;
    let child = children(&c, op.operation_id).await?;
    ensure!(child.len() == 1);
    worker.step(&c, jobs(child.iter().copied())).await?;
    let device_result = outcome(&c, child[0]).await?;
    assert_eq!(device_result["state"], "accepted");
    while now(&c).await? < expires {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    worker.step(&c, jobs([parent])).await?;
    assert_eq!(outcome(&c, parent).await?["state"], "expired");
    let other = planning::endpoint(&c).await?.members[0].device;
    let proof = c.authenticate(&account).await?;
    let summary =
        rss_mdm_policy_service::management::read::work_receipt(&f.policies, &proof, parent, None)
            .await?
            .context("original trigger")?;
    assert_eq!(summary.state.as_deref(), Some("has_accepted_devices"));
    assert!(summary.executions.contains(&refresh));
    assert!(
        summary
            .stages
            .iter()
            .any(|stage| stage.phase == "assignment_scan"
                && stage.state.as_deref() == Some("expired"))
    );
    let absent = rss_mdm_policy_service::management::read::work_receipt(
        &f.policies,
        &proof,
        parent,
        Some(other),
    )
    .await?
    .context("device lookup")?;
    assert_eq!(absent.state.as_deref(), Some("no_device_evidence"));
    assert!(absent.executions.is_empty() && absent.accepted.is_none());
    worker.close().await;
    f.close().await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: calendar work discovered on time cannot dispatch past the configured misfire tolerance"]
async fn queued_calendar_page_expires_at_original_lateness_cutoff() -> Result<()> {
    let c = Context::open("policy_reruns", &[]).await?;
    let f = Fixture::open(&c).await?;
    let account = manager(&c).await?;
    let worker = Worker::open(&c, &f).await?;
    let device = planning::endpoint(&c).await?.members[0].device;
    let at = now(&c).await?;
    let definition = json!({"scope":{"targets":[{"kind":"device","id":device}],"exclusions":[],"limitations":null},
        "action":{"kind":"unmanage_device","runLifetimeSeconds":300,"schedule":{"trigger":{"kind":"once","at":at},"notBefore":0,"jitterSeconds":0,
        "misfire":{"kind":"skip","maxLatenessSeconds":10}}}});
    let view = submit(&c, &f, &account, definition.clone()).await?;
    let timely = submit(&c, &f, &account, definition).await?;
    worker.step(&c, ["schedules".to_owned()].into()).await?;
    let page = calendar_page(&c, view.version_id).await?;
    let timely_page = calendar_page(&c, timely.version_id).await?;
    publish(&c, &view).await?;
    publish(&c, &timely).await?;
    worker.step(&c, jobs([timely_page])).await?;
    assert_eq!(outcome(&c, timely_page).await?["state"], "dispatched");
    let child:Uuid=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='policy_lifecycle' AND input->>'version'=$2")
        .bind(c.tenant.to_string()).bind(timely.version_id.to_string()).fetch_one(&c.operator).await?;
    while now(&c).await? <= at + 10 {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    worker.step(&c, jobs([page, child])).await?;
    assert_eq!(outcome(&c, page).await?["state"], "expired");
    assert_eq!(outcome(&c, child).await?["state"], "accepted");
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='policy_lifecycle' AND input->>'version'=$2")
        .bind(c.tenant.to_string()).bind(view.version_id.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(count, 0);
    worker.close().await;
    f.close().await?;
    c.close().await;
    Ok(())
}

async fn calendar_page(c: &Context, version: Uuid) -> Result<Uuid> {
    Ok(sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_page' AND input->>'version'=$2 AND input->>'publication' IS NULL")
        .bind(c.tenant.to_string()).bind(version.to_string()).fetch_one(&c.operator).await?)
}
