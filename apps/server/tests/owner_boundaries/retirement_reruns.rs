//! Real management admission, Scope publication and one protected Policy claim per step.
use super::{AuthorizedPrincipal, Context, P, planning};
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
async fn principal(c: &Context) -> Result<AuthorizedPrincipal> {
    let account = c
        .account(&[
            P::PolicyRead,
            P::PolicyWrite,
            P::InventoryRead,
            P::DeviceUnmanage,
        ])
        .await?;
    c.authenticate(&account).await
}
async fn submit(
    c: &Context,
    f: &Fixture,
    p: &AuthorizedPrincipal,
    definition: Value,
) -> Result<View> {
    Ok(f.policies
        .change(
            p,
            Uuid::new_v4(),
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                input: Change::Put {
                    definition: serde_json::from_value(definition)?,
                    enabled: true,
                },
            },
            &c.request(p)?,
        )
        .await?)
}
async fn policy(c: &Context, f: &Fixture, p: &AuthorizedPrincipal, size: usize) -> Result<View> {
    let mut targets = vec![];
    for _ in 0..size {
        let object = planning::endpoint(c).await?;
        targets.push(json!({"kind":"device","id":object.members[0].device}));
    }
    submit(
        c,
        f,
        p,
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
    p: &AuthorizedPrincipal,
    v: &View,
    deadline: i64,
) -> Result<(Operation<Rerun>, Uuid)> {
    let op = Operation {
        operation_id: Uuid::new_v4(),
        expected_revision: v.revision as u64,
        input: Rerun { deadline },
    };
    let receipt = f.policies.rerun(p, v.id, &op, &c.request(p)?).await?;
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
async fn outcome(c: &Context, task: Uuid) -> Result<Value> {
    Ok(sqlx::query_scalar("SELECT retirement_result FROM mdm_policy.work WHERE tenant_id=$1::uuid AND id=$2 AND completed AND failure IS NULL")
        .bind(c.tenant.to_string()).bind(task).fetch_one(&c.operator).await?)
}

#[tokio::test]
#[ignore = "T2: every admitted retirement rerun survives the former latest-64 boundary and reconciles to the exact device operation"]
async fn every_receipt_reaches_its_device_even_as_new_triggers_arrive() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let f = Fixture::open(&c).await?;
    let p = principal(&c).await?;
    let v = policy(&c, &f, &p, 1).await?;
    let publication = publish(&c, &v).await?;
    let worker = Worker::open(&c, &f).await?;
    let expires = now(&c).await? + 600;
    let mut accepted = vec![];
    for _ in 0..65 {
        accepted.push(rerun(&c, &f, &p, &v, expires).await?);
    }
    worker.step(&c, jobs([publication, accepted[0].1])).await?;
    accepted.push(rerun(&c, &f, &p, &v, expires).await?);
    let resume:Uuid=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_refresh' AND input->'page'->>'publication'=$2")
        .bind(c.tenant.to_string()).bind(publication.to_string()).fetch_one(&c.operator).await?;
    worker
        .step(&c, jobs(accepted[1..].iter().map(|r| r.1).chain([resume])))
        .await?;
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
    worker
        .step(&c, jobs(device_work[1..].iter().copied()))
        .await?;
    let first = outcome(&c, device_work[0]).await?;
    assert_eq!(first["state"], "accepted");
    for ((op, _), child) in accepted.iter().zip(device_work) {
        let receipt = f.policies.rerun(&p, v.id, op, &c.request(&p)?).await?;
        assert_eq!(
            (receipt.operation_id, receipt.version_id, receipt.deadline),
            (op.operation_id, v.version_id, expires)
        );
        assert_eq!(outcome(&c, child).await?, first);
    }
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
    let c = Context::open("shared", &[]).await?;
    let f = Fixture::open(&c).await?;
    let p = principal(&c).await?;
    let v = policy(&c, &f, &p, 65).await?;
    publish(&c, &v).await?;
    let (op, parent) = rerun(&c, &f, &p, &v, now(&c).await? + 600).await?;
    let worker = Worker::open(&c, &f).await?;
    worker.step(&c, jobs([parent])).await?;
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
    worker.close().await;
    fresh.close().await?;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: calendar and explicit retirement obey the frozen window, expiry, later Scope removal and version"]
async fn calendar_window_and_queued_reruns_recheck_current_authority() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let f = Fixture::open(&c).await?;
    let p = principal(&c).await?;
    let object = planning::endpoint(&c).await?;
    let scope = json!({"targets":[{"kind":"device","id":object.members[0].device}],"limitations":null,"exclusions":[]});
    let t = now(&c).await?;
    let calendar=submit(&c,&f,&p,json!({"scope":scope,"action":{"kind":"unmanage_device","runLifetimeSeconds":300,"schedule":{"trigger":{"kind":"once","at":t},"notBefore":0,"jitterSeconds":0}}})).await?;
    publish(&c, &calendar).await?;
    let worker = Worker::open(&c, &f).await?;
    worker.step(&c, ["schedules".to_owned()].into()).await?;
    let page:Uuid=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_page' AND input->'occurrence'->>'kind'='calendar' AND (input->'occurrence'->>'at')::bigint=$2")
        .bind(c.tenant.to_string()).bind(t).fetch_one(&c.operator).await?;
    let (old, parent) = rerun(&c, &f, &p, &calendar, t + 600).await?;
    let (withdrawn, withdrawn_page) = rerun(&c, &f, &p, &calendar, t + 600).await?;
    worker
        .step(&c, jobs([page, parent, withdrawn_page]))
        .await?;
    assert_eq!(outcome(&c, page).await?["eligible"], 1);
    let revoked = children(&c, withdrawn.operation_id).await?[0];
    let stale = children(&c, old.operation_id).await?[0];
    let expiry = now(&c).await? + 5;
    let (short, short_page) = rerun(&c, &f, &p, &calendar, expiry).await?;
    worker.step(&c, jobs([short_page])).await?;
    let short_children = children(&c, short.operation_id).await?;
    assert_eq!(short_children.len(), 1);
    while now(&c).await? < expiry {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    worker
        .step(&c, jobs(short_children.iter().copied()))
        .await?;
    assert_eq!(outcome(&c, short_children[0]).await?["state"], "expired");
    assert_eq!(
        f.policies
            .rerun(&p, calendar.id, &short, &c.request(&p)?)
            .await?
            .deadline,
        expiry
    );
    let mut definition = calendar.definition.clone();
    definition.scope.limitations = Some(Default::default());
    let revised = f
        .policies
        .change(
            &p,
            calendar.id,
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: calendar.revision as u64,
                input: Change::Put {
                    definition: Box::new(definition),
                    enabled: true,
                },
            },
            &c.request(&p)?,
        )
        .await?;
    assert_eq!(revised.version_id, calendar.version_id);
    publish(&c, &revised).await?;
    worker.step(&c, jobs([revoked])).await?;
    assert_eq!(outcome(&c, revoked).await?["state"], "ineligible");
    let restored = f
        .policies
        .change(
            &p,
            calendar.id,
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: revised.revision as u64,
                input: Change::Put {
                    definition: Box::new(calendar.definition.clone()),
                    enabled: true,
                },
            },
            &c.request(&p)?,
        )
        .await?;
    let generation = publish(&c, &restored).await?;
    worker.step(&c, jobs([generation])).await?;
    let retry:Uuid=sqlx::query_scalar("SELECT id FROM mdm_policy.work WHERE tenant_id=$1::uuid AND kind='retirement_page' AND input->'occurrence'->>'trigger'=$2 AND id<>$3")
        .bind(c.tenant.to_string()).bind(withdrawn.operation_id.to_string()).bind(withdrawn_page).fetch_one(&c.operator).await?;
    worker.step(&c, jobs([retry])).await?;
    let replacement = children(&c, withdrawn.operation_id)
        .await?
        .into_iter()
        .find(|id| *id != revoked)
        .context("newly eligible object")?;
    worker.step(&c, jobs([replacement])).await?;
    assert_eq!(outcome(&c, replacement).await?["state"], "accepted");
    let mut new_version = restored.definition.clone();
    if let rss_mdm_policy::Action::UnmanageDevice {
        run_lifetime_seconds,
        ..
    } = &mut new_version.action
    {
        *run_lifetime_seconds += 60;
    }
    let next = f
        .policies
        .change(
            &p,
            calendar.id,
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: restored.revision as u64,
                input: Change::Put {
                    definition: Box::new(new_version),
                    enabled: true,
                },
            },
            &c.request(&p)?,
        )
        .await?;
    assert_ne!(next.version_id, calendar.version_id);
    worker.step(&c, jobs([stale])).await?;
    assert_eq!(outcome(&c, stale).await?["state"], "superseded");
    assert_eq!(
        f.policies
            .rerun(&p, calendar.id, &old, &c.request(&p)?)
            .await?
            .version_id,
        calendar.version_id
    );

    let minute = (now(&c).await? / 60 + 10) % 1440;
    let delayed=submit(&c,&f,&p,json!({"scope":scope,"action":{"kind":"unmanage_device","runLifetimeSeconds":300,
        "schedule":{"trigger":{"kind":"manual"},"notBefore":0,"jitterSeconds":0,"window":{"zone":"UTC","weekdays":[1,2,3,4,5,6,7],"startMinute":minute,"endMinute":(minute+1)%1440}}}})).await?;
    let (future, future_page) = rerun(&c, &f, &p, &delayed, now(&c).await? + 3600).await?;
    let (_, expires) = rerun(&c, &f, &p, &delayed, now(&c).await? + 45).await?;
    worker.step(&c, jobs([future_page, expires])).await?;
    assert_eq!(outcome(&c, expires).await?["state"], "expired");
    let deferred:bool=sqlx::query_scalar("SELECT NOT w.completed AND t.next_run>clock_timestamp() FROM mdm_policy.work w JOIN rss_reconcile.targets t ON t.tenant_id=w.tenant_id AND t.reconciler='mdm.policy' AND t.entity='job:'||w.id::text WHERE w.tenant_id=$1::uuid AND w.id=$2")
        .bind(c.tenant.to_string()).bind(future_page).fetch_one(&c.operator).await?;
    assert!(deferred);
    assert!(children(&c, future.operation_id).await?.is_empty());
    let effects: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_devices.retirements WHERE tenant_id=$1::uuid AND policy=$2",
    )
    .bind(c.tenant.to_string())
    .bind(calendar.id)
    .fetch_one(&c.operator)
    .await?;
    assert_eq!(effects, 1);
    worker.close().await;
    f.close().await?;
    c.close().await;
    Ok(())
}
