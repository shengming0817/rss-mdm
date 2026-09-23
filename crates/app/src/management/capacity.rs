//! Actual product Scope capacity over real PostgreSQL history and member snapshots.
#![allow(
    clippy::disallowed_methods,
    reason = "capacity measurements use elapsed wall time"
)]
use super::*;
use rss_mdm_group_postgres as g;

async fn wait_capacity(m: &Management, task: Uuid, scope: Uuid) -> Value {
    tokio::time::timeout(Duration::from_secs(1800), async {
        let mut last = 0;
        loop {
            let value = execute(
                m,
                &Command::TaskRead {
                    id: task,
                    target: scope.to_string(),
                    family: automation::TaskKind::Scope,
                },
            )
            .await
            .unwrap();
            if value["status"] == "completed"
                || value["status"] == "failed"
                || value["status"] == "superseded"
            {
                return value;
            }
            let processed = value["processed"].as_u64().unwrap();
            if processed >= last + 100_000 {
                eprintln!("scope capacity processed={processed}");
                last = processed;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("capacity Scope failed to settle within its fixture deadline")
}

#[tokio::test]
#[ignore = "actual million-device PostgreSQL capacity acceptance"]
async fn million_scope_pages_and_overflow_use_product_worker() {
    // Bulk synthetic identities are fixture setup, not a device/T3 claim or a
    // production writer proof. The calculation below uses the production runner.
    let t = tenant();
    sql(&format!(
        "INSERT INTO mdm.asset_clock VALUES('{t}',1); INSERT INTO mdm.asset_changes VALUES('{t}',1,'device','{{}}',ARRAY[]::text[],true); INSERT INTO mdm_management.asset_dispatch(tenant_id,consumed,watermark) VALUES('{t}',1,1);"
    ));
    for start in (0..1_000_000).step_by(1000) {
        sql(&format!(
            r#"
            INSERT INTO mdm_access.asset_authority_history(tenant_id,kind,identity,device,registration,revision,document)
            SELECT '{t}',k,concat(k,n),'device-'||lpad(n::text,7,'0'),md5(n::text)::uuid,1,
              CASE k WHEN 'registration' THEN '{{"state":"active"}}'::jsonb
                     WHEN 'credential' THEN '{{"state":"active"}}'::jsonb
                     ELSE '{{"enabled":true}}'::jsonb END
            FROM generate_series({start},{end}) n CROSS JOIN unnest(ARRAY['registration','credential','source']) k;
        "#,
            end = start + 999
        ));
        if start % 100_000 == 0 {
            eprintln!("scope capacity seeded={}", start + 1000);
        }
    }
    seed_device("device-1000000");
    sql(&format!(
        "UPDATE mdm.asset_changes SET forwarded=true; UPDATE mdm_management.asset_dispatch SET consumed=(SELECT revision FROM mdm.asset_clock WHERE tenant_id='{t}'),watermark=(SELECT revision FROM mdm.asset_clock WHERE tenant_id='{t}');"
    ));
    let m = Arc::new(management(t).await);
    let group = Uuid::new_v4();
    execute(
        &m,
        &Command::Group {
            id: group,
            change: operation(
                0,
                GroupChange::Create {
                    name: "capacity-source".into(),
                    description: String::new(),
                    criteria: None,
                },
            ),
        },
    )
    .await
    .unwrap();
    let group_id = g::GroupId::parse(&group.to_string()).unwrap();
    let mut revision = g::Revision::new(1).unwrap();
    let mut member_version = 0;
    let mut max_tx = Duration::ZERO;
    macro_rules! group_tx {
        ($context:expr, |$ctx:ident,$tx:ident| $body:expr) => {{
            let start = std::time::Instant::now();
            let result = m
                .runtime
                .local_tx_with_context(t, deadline(), $context, |$ctx, $tx| {
                    Box::pin(async move { $body })
                })
                .await
                .fold(
                    |v| v.unwrap(),
                    |e| panic!("{e:?}"),
                    |e| panic!("{e:?}"),
                    |e| panic!("{e:?}"),
                    |e| panic!("{e:?}"),
                    |e| panic!("{e:?}"),
                );
            max_tx = max_tx.max(start.elapsed());
            result
        }};
    }
    let started = std::time::Instant::now();
    let scope = Uuid::new_v4();
    let mut previous_removed = 0;
    for (iteration, removed) in [0, 0, 1, 10_000, 1_000_000].into_iter().enumerate() {
        let range = if iteration == 0 {
            0..1_000_000
        } else {
            previous_removed..removed
        };
        for start in range.clone().step_by(1000) {
            let ids = (start..(start + 1000).min(range.end))
                .map(|n| format!("device-{n:07}"))
                .collect();
            let request = g::BuildRequest {
                id: g::OperationId::parse(&Uuid::new_v4().to_string()).unwrap(),
                group: group_id,
                expected: revision,
                rule_version: None,
                patch: Some(if iteration == 0 {
                    g::MemberPatch {
                        add: ids,
                        remove: vec![],
                    }
                } else {
                    g::MemberPatch {
                        add: vec![],
                        remove: ids,
                    }
                }),
                input_version: "assets:1".into(),
                as_of: Timepoint::try_from(10).unwrap(),
            };
            group_tx!((&m.groups, &request), |ctx, tx| ctx
                .0
                .begin_build_in(tx, ctx.1)
                .await);
            group_tx!(&m.groups, |s, tx| s.advance_static_in(tx, request.id).await);
            assert!(
                group_tx!(&m.groups, |s, tx| s
                    .advance_difference_in(tx, request.id)
                    .await)
                .build
                .ready
            );
            let receipt = group_tx!(&m.groups, |s, tx| {
                tx.prepare_outbox_partitions(&[s.partition(&group_id.to_string())?])
                    .await?;
                s.publish_build_in(tx, request.id).await
            });
            revision = receipt.group.revision;
            member_version = receipt.group.member_version;
        }
        group_tx!(&m.policies, |s, tx| s
            .advance_reference_in(tx, &format!("group-members.{group}"), member_version as u64)
            .await);
        let result = execute(
            &m,
            &Command::Scope {
                id: scope,
                change: operation(
                    iteration as u64,
                    ScopeChange::Put {
                        definition: super::scope(group),
                    },
                ),
            },
        )
        .await
        .unwrap();
        let task = Uuid::parse_str(result["task"].as_str().unwrap()).unwrap();
        let running = RunningAutomation::start(m.clone()).await;
        let round = std::time::Instant::now();
        let complete = wait_capacity(&m, task, scope).await;
        assert_eq!(complete["status"], "completed", "{complete}");
        assert_eq!(complete["members"], 1_000_000 - removed);
        let mut cursor = None;
        let mut read = 0;
        loop {
            let page = execute(
                &m,
                &Command::ScopePage {
                    scope,
                    result: task,
                    projection: pages::ScopePageKind::Members,
                    query: pages::PageQuery {
                        limit: 1000,
                        cursor,
                    },
                },
            )
            .await
            .unwrap();
            let items = page["page"]["items"].as_array().unwrap();
            assert!(items.len() <= 1000);
            read += items.len();
            cursor = page["nextCursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(read, 1_000_000 - removed);
        running.stop().await;
        if iteration == 0 {
            let overflow = Uuid::new_v4();
            let result = execute(
                &m,
                &Command::Scope {
                    id: overflow,
                    change: operation(
                        0,
                        ScopeChange::Put {
                            definition: ScopeDefinition {
                                targets: [
                                    Reference::Group(group),
                                    Reference::Device("device-1000000".into()),
                                ]
                                .into(),
                                limitations: None,
                                exclusions: Default::default(),
                            },
                        },
                    ),
                },
            )
            .await
            .unwrap();
            let running = RunningAutomation::start(m.clone()).await;
            let rejected = wait_capacity(
                &m,
                Uuid::parse_str(result["task"].as_str().unwrap()).unwrap(),
                overflow,
            )
            .await;
            assert_eq!(rejected["failure"], "capacity_exceeded", "{rejected}");
            running.stop().await;
        }
        println!(
            "{}",
            json!({"scenario":"million_scope","iteration":iteration,"members":read,"elapsed_seconds":round.elapsed().as_secs_f64(),"max_group_transaction_seconds":max_tx.as_secs_f64()})
        );
        previous_removed = removed;
    }
    println!(
        "{}",
        json!({"scenario":"million_scope_total","elapsed_seconds":started.elapsed().as_secs_f64()})
    );
    m.runtime.close().await;
}
