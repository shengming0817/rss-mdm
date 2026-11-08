//! Policy is the sole configuration CAS; Scope work and retained history are independent.
use crate::{
    authority_t2_support::Context, planning_t2_support as planning,
    policy_management_t2_support::Fixture,
};
use anyhow::Result;
use rss_mdm_authorization_service::Permission as P;
use rss_mdm_policy_service::{
    management::{Change, View, scopes::Recompute},
    operation::Operation,
};
use serde_json::json;
use uuid::Uuid;
fn put(view: &View) -> Operation<Change> {
    Operation {
        operation_id: Uuid::new_v4(),
        expected_revision: view.revision as u64,
        input: Change::Put {
            definition: Box::new(view.definition.clone()),
            enabled: false,
        },
    }
}
#[tokio::test]
#[ignore = "T2: Policy saves owned Scopes atomically, replays the original composition, and retires without deleting history"]
async fn policy_owns_scope_cas_receipt_and_retirement() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::PolicyRead,
            P::PolicyWrite,
            P::InventoryRead,
            P::DeviceUnmanage,
        ])
        .await?;
    let p = c.authenticate(&account).await?;
    let object = planning::endpoint(&c).await?;
    let f = Fixture::open(&c).await?;
    let first=f.create(&c,&p,serde_json::from_value(json!({"targets":[{"kind":"device","id":object.members[0].device}],"limitations":null,"exclusions":[]}))?).await?;
    let scope = first.scopes[0].id;
    let owner = rss_mdm_scope::ScopeOwner {
        policy: first.id,
        stage: None,
    };
    assert_eq!((first.revision, first.scopes[0].revision), (1, 1));
    assert!(first.scopes[0].task.is_some());
    let unchanged = f
        .policies
        .change(&p, first.id, &put(&first), &c.request(&p)?)
        .await?;
    assert_eq!(
        (
            unchanged.revision,
            unchanged.version,
            unchanged.scopes[0].revision
        ),
        (2, first.version, 1)
    );
    assert_eq!(unchanged.scopes[0].task, first.scopes[0].task);
    let draft = rss_mdm_policy_service::management::scopes::Qualification {
        expected_revision: 2,
        definition: Box::new(unchanged.definition.clone()),
        scope_result: None,
    };
    f.policies.qualify(&p, first.id, &draft).await?;
    let mut change = put(&unchanged);
    if let Change::Put { definition, .. } = &mut change.input {
        definition.scope.limitations = Some(Default::default());
    }
    let changed = f
        .policies
        .change(&p, first.id, &change, &c.request(&p)?)
        .await?;
    assert_eq!(
        (
            changed.revision,
            changed.version,
            changed.scopes[0].revision
        ),
        (3, first.version, 2)
    );
    assert_eq!(changed.scopes[0].id, scope);
    assert!(
        matches!(
            f.policies.qualify(&p, first.id, &draft).await,
            Err(rss_mdm_policy_service::Error::Conflict)
        ),
        "a preview completed after another save must fail its final qualification"
    );
    assert!(changed.scopes[0].task.is_some());
    assert!(matches!(
        f.policies
            .change(&p, first.id, &put(&unchanged), &c.request(&p)?)
            .await,
        Err(rss_mdm_policy_service::Error::Conflict)
    ));
    // A failed reference validation leaves neither authored state nor durable work behind.
    let before = counts(&c, first.id).await?;
    let mut invalid = put(&changed);
    if let Change::Put { definition, .. } = &mut invalid.input {
        definition
            .scope
            .targets
            .insert(rss_mdm_scope::Reference::Device("missing-device".into()));
    }
    assert!(
        f.policies
            .change(&p, first.id, &invalid, &c.request(&p)?)
            .await
            .is_err()
    );
    assert_eq!(counts(&c, first.id).await?, before);
    let request = Recompute {
        operation_id: Uuid::new_v4(),
        expected_revision: 3,
    };
    let recomputed = f
        .policies
        .scope_recompute(&p, &c.request(&p)?, owner, &request)
        .await?;
    assert_eq!(recomputed.revision, 2);
    let archived = f
        .policies
        .change(
            &p,
            first.id,
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 3,
                input: Change::Archive,
            },
            &c.request(&p)?,
        )
        .await?;
    assert_eq!(archived.revision, 4);
    assert!(archived.scopes[0].retired);
    assert_eq!(archived.scopes[0].revision, 2);
    let row:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM mdm_scope.scope_sources WHERE tenant_id=$1::uuid AND scope=$2),(SELECT count(*) FROM mdm_scope.scope_versions WHERE tenant_id=$1::uuid AND id=$2)").bind(c.tenant.to_string()).bind(scope).fetch_one(&c.operator).await?;
    assert_eq!(row, (0, 2));
    let replay = f
        .policies
        .change(&p, first.id, &change, &c.request(&p)?)
        .await?;
    assert_eq!(
        serde_json::to_value(replay)?,
        serde_json::to_value(changed)?
    );
    assert_eq!(
        f.policies
            .scope_recompute(&p, &c.request(&p)?, owner, &request)
            .await?
            .task,
        recomputed.task
    );
    assert!(
        f.policies
            .scope_recompute(
                &p,
                &c.request(&p)?,
                owner,
                &Recompute {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 4
                }
            )
            .await
            .is_err()
    );
    assert!(
        f.policies
            .scope_read(
                &p,
                &c.request(&p)?,
                rss_mdm_scope::ScopeOwner {
                    policy: Uuid::new_v4(),
                    stage: None
                }
            )
            .await
            .is_err()
    );
    // Replay does not preserve a revoked authority grant.
    sqlx::query("UPDATE mdm_access.authorization_rules SET revision=revision+1,document=NULL WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(account.rule).execute(&c.operator).await?;
    assert!(
        f.policies
            .change(&p, first.id, &change, &c.request(&p)?)
            .await
            .is_err()
    );
    f.close().await?;
    c.close().await;
    Ok(())
}
async fn counts(c: &Context, policy: Uuid) -> Result<(i64, i64, i64)> {
    Ok(sqlx::query_as("SELECT p.revision,(SELECT count(*) FROM mdm_scope.scope_versions v JOIN mdm_scope.scopes s USING(tenant_id,id) WHERE s.tenant_id=p.tenant_id AND s.policy_id=p.id),(SELECT count(*) FROM mdm_scope.tasks t JOIN mdm_scope.scopes s ON(s.tenant_id,s.id)=(t.tenant_id,t.scope) WHERE s.tenant_id=p.tenant_id AND s.policy_id=p.id) FROM mdm_policy.policies p WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(policy).fetch_one(&c.operator).await?)
}

#[tokio::test]
#[ignore = "T2: stable rollout stage identities preserve owned Scopes across reorder and retire removed stages"]
async fn stage_identity_is_owned_and_reorder_does_not_republish() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::PolicyRead,
            P::PolicyWrite,
            P::InventoryRead,
            P::SoftwareDeploy,
            P::ResourceRead,
        ])
        .await?;
    let p = c.authenticate(&account).await?;
    let resource = crate::assembly::seed_software(&c, "owned-rollout").await?;
    let f = Fixture::open(&c).await?;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let id = Uuid::new_v4();
    let scope = json!({"targets":[],"limitations":null,"exclusions":[]});
    let definition = serde_json::from_value(
        json!({"scope":scope,"action":{"kind":"software","resource":{"kind":"software","id":resource.resource().as_str(),"version":resource.label().as_str(),"variants":{"windows_x86_64":"msi"}},"channel":"agent","delivery":{"kind":"direct"},"intent":"required_install","runLifetimeSeconds":300,"rollout":{"stages":[{"id":a,"scope":scope,"opensAt":0},{"id":b,"scope":scope,"opensAt":1}]}}}),
    )?;
    let first = f
        .policies
        .change(
            &p,
            id,
            &Operation {
                operation_id: Uuid::new_v4(),
                expected_revision: 0,
                input: Change::Put {
                    definition,
                    enabled: false,
                },
            },
            &c.request(&p)?,
        )
        .await?;
    assert_eq!(first.scopes.len(), 3);
    let mut request = put(&first);
    if let Change::Put { definition, .. } = &mut request.input {
        if let rss_mdm_policy::Action::Software { rollout, .. } = &mut definition.action {
            rollout.stages.swap(0, 1);
            for (index, stage) in rollout.stages.iter_mut().enumerate() {
                stage.opens_at = index as i64;
            }
        }
    }
    let second = f.policies.change(&p, id, &request, &c.request(&p)?).await?;
    assert_eq!(second.version_id, first.version_id);
    for child in &first.scopes {
        let same = second
            .scopes
            .iter()
            .find(|c| c.stage == child.stage)
            .unwrap();
        assert_eq!(
            (same.id, same.revision, same.task),
            (child.id, child.revision, child.task)
        );
    }
    let before = counts(&c, id).await?;
    let last = second.scopes.iter().max_by_key(|s| s.id).unwrap().stage;
    let invalid = second
        .definition
        .clone()
        .try_map_scopes(|stage, mut definition| {
            definition.limitations = Some(Default::default());
            if stage == last {
                definition.targets.insert(rss_mdm_scope::Reference::Device(
                    "absent-stage-device".into(),
                ));
            }
            Ok::<_, anyhow::Error>(definition)
        })?;
    assert!(
        f.policies
            .change(
                &p,
                id,
                &Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: second.revision as u64,
                    input: Change::Put {
                        definition: Box::new(invalid),
                        enabled: false
                    }
                },
                &c.request(&p)?
            )
            .await
            .is_err()
    );
    assert_eq!(
        counts(&c, id).await?,
        before,
        "a later child failure rolls back earlier child writes"
    );
    let mut request = put(&second);
    if let Change::Put { definition, .. } = &mut request.input {
        if let rss_mdm_policy::Action::Software { rollout, .. } = &mut definition.action {
            rollout.stages.retain(|s| s.id == b);
        }
    }
    let third = f.policies.change(&p, id, &request, &c.request(&p)?).await?;
    assert_eq!(third.version_id, first.version_id);
    let retired = f
        .policies
        .scope_read(
            &p,
            &c.request(&p)?,
            rss_mdm_scope::ScopeOwner {
                policy: id,
                stage: Some(a),
            },
        )
        .await?;
    assert!(retired.retired);
    assert_eq!(retired.revision, 1);
    let mut request = put(&third);
    if let Change::Put { definition, .. } = &mut request.input {
        if let rss_mdm_policy::Action::Software { rollout, .. } = &mut definition.action {
            rollout.stages.clear();
        }
    }
    let unbatched = f.policies.change(&p, id, &request, &c.request(&p)?).await?;
    assert_eq!(unbatched.scopes.len(), 1);
    assert_eq!(unbatched.version_id, first.version_id);
    f.close().await?;
    c.close().await;
    Ok(())
}
