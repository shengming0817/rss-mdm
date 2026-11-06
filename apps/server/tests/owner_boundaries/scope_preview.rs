//! Scope draft samples consume the same Group, Device and authorization owners as publication.
use super::*;
use rss_mdm_inventory::Channel;
use rss_mdm_scope::{Reference, ScopeDefinition};
use rss_mdm_scope_service::preview::{Request, StopReason};
use std::collections::BTreeSet;

async fn members(
    owners: &Owners,
    c: &Context,
    p: &AuthorizedPrincipal,
    id: Uuid,
    objects: Vec<rss_mdm_inventory_service::objects::ObjectRef>,
) -> Result<()> {
    let result = owners
        .groups
        .execute(
            &group::Command::Group {
                id,
                change: Box::new(group::operation::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 1,
                    input: group::GroupChange::Members {
                        add: objects,
                        remove: vec![],
                    },
                }),
            },
            &c.request(p)?,
            p,
        )
        .await?;
    if let Some(task) = result["task"].as_str() {
        owners.settle(c, Uuid::parse_str(task)?).await?;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "T2: Scope drafts combine complete sources without any saved definition, publication or task"]
async fn draft_algebra_is_read_only_and_enforces_live_permissions() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::ScopeRead,
            P::ScopeWrite,
            P::InventoryRead,
            P::GroupRead,
            P::GroupWrite,
        ])
        .await?;
    let p = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let scopes = crate::scope_t2::open(&c).await?;
    let a = planning::endpoint(&c).await?;
    let b = planning::endpoint(&c).await?;
    let id = owners.create(&c, &p, None).await?;
    members(
        &owners,
        &c,
        &p,
        id,
        vec![a.object.clone(), b.object.clone()],
    )
    .await?;
    let mut request = Request {
        definition: ScopeDefinition {
            targets: BTreeSet::from([Reference::Group(id)]),
            limitations: None,
            exclusions: BTreeSet::from([Reference::Device(b.members[0].device.clone())]),
        },
        channel: Channel::Mdm,
        editing: None,
    };
    let before = super::preview::business_state(&c).await?;
    let result = scopes.preview(&p, &request, &c.request(&p)?).await?;
    assert_eq!(result.items, vec![a.object.clone()]);
    assert!(result.scan_complete && !result.has_unknown);
    assert_eq!(result.stop_reason, StopReason::Complete);
    assert_eq!(
        result.input_fingerprint,
        rss_mdm_query::cursor::fingerprint(&request)?
    );
    assert_eq!(super::preview::business_state(&c).await?, before);
    request.definition.limitations = Some(BTreeSet::new());
    let result = scopes.preview(&p, &request, &c.request(&p)?).await?;
    assert!(result.items.is_empty() && result.scan_complete);
    request.definition.limitations = Some(BTreeSet::from([Reference::Device(
        a.members[0].device.clone(),
    )]));
    let result = scopes.preview(&p, &request, &c.request(&p)?).await?;
    assert_eq!(result.items, vec![a.object.clone()]);
    request.channel = Channel::Agent;
    let result = scopes.preview(&p, &request, &c.request(&p)?).await?;
    assert!(result.scan_complete && result.items.is_empty());
    request.channel = Channel::Mdm;
    let reader = c.account(&[P::ScopeRead, P::InventoryRead]).await?;
    let reader = c.authenticate(&reader).await?;
    assert!(matches!(
        scopes
            .preview(&reader, &request, &c.request(&reader)?)
            .await,
        Err(rss_mdm_scope_service::Error::Forbidden)
    ));
    let no_inventory = c.account(&[P::ScopeRead, P::GroupRead]).await?;
    let no_inventory = c.authenticate(&no_inventory).await?;
    assert!(matches!(
        scopes
            .preview(&no_inventory, &request, &c.request(&no_inventory)?)
            .await,
        Err(rss_mdm_scope_service::Error::Forbidden)
    ));
    let da_access = c
        .access()
        .for_product(rss_mdm_audit_integration::StorageProfile::Da);
    let da = rss_mdm_authorization_service::session::SessionAuthority::new(
        c.authority.clone(),
        c.tenant,
    )
    .authenticate(&da_access, account.credential()?)
    .await?;
    da.manage(P::ScopeRead)?;
    let da_audit = rss_mdm_audit_integration::RequestAudit::new(
        rss_mdm_audit_integration::StorageProfile::Da,
        c.tenant.to_string(),
        "management_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    da.bind_audit(&da_audit)?;
    assert!(matches!(
        scopes.preview(&da, &request, &da_audit).await,
        Err(rss_mdm_scope_service::Error::Forbidden)
    ));
    // The same previously authenticated principal cannot retain a revoked grant.
    sqlx::query("UPDATE mdm_access.authorization_rules SET document=NULL,revision=revision+1 WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string()).bind(account.rule).execute(&c.operator).await?;
    assert!(scopes.preview(&p, &request, &c.request(&p)?).await.is_err());
    drop(scopes);
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: HTTP preview has a typed contract and an editing CAS; missing sources cannot become empty samples"]
async fn http_preview_and_recompute_use_the_formal_contract() -> Result<()> {
    use rss_mdm_authorization_service::context::RequestAuth;
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[P::ScopeRead, P::ScopeWrite, P::InventoryRead, P::GroupRead])
        .await?;
    let p = Arc::new(c.authenticate(&account).await?);
    let scopes = crate::scope_t2::open(&c).await?;
    let owners = Owners::open(&c).await?;
    let object = planning::endpoint(&c).await?;
    let old = planning::published(&c, &object).await?;
    let app = rss_mdm_management_http::planning::routes()
        .into_axum()
        .with_state(Arc::new(
            rss_mdm_management_http::planning::http::HttpState {
                scopes: scopes.clone(),
                groups: owners.groups.clone(),
            },
        ))
        .layer(axum::Extension(RequestAuth {
            proof: p.clone(),
            sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
                c.authority.clone(),
                c.tenant,
            ),
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(8),
        }))
        .layer(axum::middleware::from_fn({
            let proof = p.clone();
            let tenant = c.tenant;
            move |mut request: axum::extract::Request, next: axum::middleware::Next| {
                let proof = proof.clone();
                async move {
                    let audit = rss_mdm_audit_integration::RequestAudit::new(
                        rss_mdm_audit_integration::StorageProfile::Mdm,
                        tenant.to_string(),
                        "management_read",
                        rss_mdm_audit_integration::AuditIntent::Routine,
                    );
                    proof.bind_audit(&audit).unwrap();
                    request.extensions_mut().insert(audit.clone());
                    let response = next.run(request).await;
                    audit.finalize(None);
                    response
                }
            }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::new();
    let body = json!({"definition":old.input.definition,"channel":"mdm","editing":{"scopeId":old.scope,"expectedRevision":1}});
    let response = client
        .post(format!("{base}/scopes/previews"))
        .json(&body)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let response: serde_json::Value = response.json().await?;
    assert_eq!(response["items"], json!([object.object]));
    assert_eq!(response["scanComplete"], true);
    assert!(response.get("total").is_none() && response.get("task").is_none());
    let mut stale = body.clone();
    stale["editing"]["expectedRevision"] = json!(2);
    assert_eq!(
        client
            .post(format!("{base}/scopes/previews"))
            .json(&stale)
            .send()
            .await?
            .status(),
        409
    );
    let mut missing = body.clone();
    missing["definition"]["targets"] = json!([{"kind":"group","id":Uuid::new_v4()}]);
    assert_eq!(
        client
            .post(format!("{base}/scopes/previews"))
            .json(&missing)
            .send()
            .await?
            .status(),
        404
    );
    let change =
        json!({"operationId":Uuid::new_v4(),"expectedRevision":1,"input":{"action":"recompute"}});
    let response = client
        .post(format!("{base}/scopes/{}", old.scope))
        .json(&change)
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let receipt: serde_json::Value = response.json().await?;
    assert_eq!(receipt["revision"], 1);
    assert!(receipt["task"].is_string());
    let replay: serde_json::Value = client
        .post(format!("{base}/scopes/{}", old.scope))
        .json(&change)
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(replay, receipt);
    server.abort();
    let _ = server.await;
    drop(scopes);
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: a sealed unknown exclusion and an unfinished dynamic source never become a successful empty range"]
async fn unknown_and_unfinished_sources_are_distinct_from_empty() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::ScopeRead,
            P::InventoryRead,
            P::GroupRead,
            P::GroupWrite,
            P::GroupRecompute,
        ])
        .await?;
    let p = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let scopes = crate::scope_t2::open(&c).await?;
    let object = planning::endpoint(&c).await?;
    let field = rss_mdm_inventory::builtin::fields()
        .into_iter()
        .find(|f| f.key.as_str() == "device.os.name")
        .unwrap();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    assert!(rss_mdm_inventory_postgres::publish_field_in(&mut tx, c.tenant, 0, &field).await?);
    tx.commit().await?;
    let mut targets = BTreeSet::from([Reference::Device(object.members[0].device.clone())]);
    for _ in 0..16 {
        let endpoint = planning::endpoint(&c).await?;
        targets.insert(Reference::Device(endpoint.members[0].device.clone()));
    }
    let condition = serde_json::from_value(
        json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"predicate","field":"device.os.name","op":"eq","value":{"kind":"string","value":"Windows"}}}),
    )?;
    let group = owners.create(&c, &p, Some(condition)).await?;
    let run = super::preview::publish(&owners, &c, &p, group).await?;
    let mut request = Request {
        definition: ScopeDefinition {
            targets: BTreeSet::from([Reference::Device(object.members[0].device.clone())]),
            limitations: None,
            exclusions: BTreeSet::from([Reference::Group(group)]),
        },
        channel: Channel::Mdm,
        editing: None,
    };
    let response = scopes.preview(&p, &request, &c.request(&p)?).await?;
    assert!(response.items.is_empty() && response.scan_complete && response.has_unknown);
    // A byte-budget stop with no confirmed sample is partial, not an empty result.
    sqlx::query("UPDATE mdm_group.member_rows SET evidence=evidence||convert_to(repeat(' ',1048576-octet_length(evidence)),'UTF8'),evidence_digest=sha256(evidence||convert_to(repeat(' ',1048576-octet_length(evidence)),'UTF8')) WHERE tenant_id=$1::uuid AND run_id=$2")
        .bind(c.tenant.to_string()).bind(run).execute(&c.operator).await?;
    request.definition.targets = targets;
    let partial = scopes.preview(&p, &request, &c.request(&p)?).await?;
    assert!(partial.items.is_empty() && !partial.scan_complete);
    assert_eq!(partial.stop_reason, StopReason::WorkBudget);
    sqlx::query("UPDATE mdm_group.groups SET member_set=NULL WHERE tenant_id=$1::uuid AND id=$2")
        .bind(c.tenant.to_string())
        .bind(group)
        .execute(&c.operator)
        .await?;
    assert!(matches!(
        scopes.preview(&p, &request, &c.request(&p)?).await,
        Err(rss_mdm_scope_service::Error::Conflict)
    ));
    drop(scopes);
    drop(owners);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: frozen endpoint reverse lookup excludes later moves and enforces bytes before decoding"]
async fn frozen_membership_does_not_follow_current_heads() -> Result<()> {
    use rss_mdm_inventory_service::objects::ObjectReader;
    let c = Context::open("shared", &[]).await?;
    let object = planning::endpoint(&c).await?;
    let published = planning::published(&c, &object).await?;
    let snapshot = Uuid::new_v4();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_devices.object_cuts(tenant_id,id,asset_cut,through) VALUES($1::uuid,$2,$3,1)")
        .bind(c.tenant.to_string()).bind(snapshot).bind(published.cut.to_json()).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO mdm_devices.object_versions(tenant_id,object,revision,input,devices) VALUES($1::uuid,$2,1,$3,$4),($1::uuid,$2,2,NULL,'{}')")
        .bind(c.tenant.to_string()).bind(object.object.key()).bind(serde_json::to_value(&object)?).bind(vec![object.members[0].device.clone()]).execute(&mut *tx).await?;
    tx.commit().await?;
    let reader = rss_mdm_device_service::planning::PlanningObjects;
    let mut connection = c.operator.acquire().await?;
    let value = reader
        .memberships_at(
            &mut connection,
            c.tenant,
            snapshot,
            &object.members[0].device,
            Channel::Mdm,
            16 * 1024,
        )
        .await?
        .unwrap();
    assert_eq!(value.0, vec![object.clone()]);
    assert!(value.1 > 0);
    assert!(
        reader
            .memberships_at(
                &mut connection,
                c.tenant,
                snapshot,
                &object.members[0].device,
                Channel::Mdm,
                1
            )
            .await?
            .is_none()
    );
    assert!(
        reader
            .memberships_at(
                &mut connection,
                c.tenant,
                Uuid::new_v4(),
                &object.members[0].device,
                Channel::Mdm,
                16 * 1024
            )
            .await
            .is_err()
    );
    let deleted_cut = Uuid::new_v4();
    sqlx::query("INSERT INTO mdm_devices.object_cuts(tenant_id,id,asset_cut,through) VALUES($1::uuid,$2,$3,2)")
        .bind(c.tenant.to_string()).bind(deleted_cut).bind(published.cut.to_json()).execute(&mut *connection).await?;
    let deleted = reader
        .memberships_at(
            &mut connection,
            c.tenant,
            deleted_cut,
            &object.members[0].device,
            Channel::Mdm,
            16 * 1024,
        )
        .await?
        .unwrap();
    assert!(
        deleted.0.is_empty(),
        "a tombstone inside the cut must not resurrect the old membership"
    );
    drop(connection);
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: draft and publication agree on absence in a complete frozen Group set"]
async fn frozen_set_absence_matches_formal_scope_publication() -> Result<()> {
    use rss_mdm_scope_service::{Command, ScopeChange, operation::Operation, pages};
    let c = Context::open("shared", &[]).await?;
    let account = c
        .account(&[
            P::ScopeRead,
            P::ScopeWrite,
            P::InventoryRead,
            P::GroupRead,
            P::GroupWrite,
            P::GroupRecompute,
        ])
        .await?;
    let p = c.authenticate(&account).await?;
    let owners = Owners::open(&c).await?;
    let scopes = crate::scope_t2::open(&c).await?;
    planning::endpoint(&c).await?;
    let empty = owners.create(&c, &p, None).await?;
    let condition = serde_json::from_value(
        json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"group","groupId":empty,"op":"member_of"}}),
    )?;
    let group = owners.create(&c, &p, Some(condition)).await?;
    super::preview::publish(&owners, &c, &p, group).await?;
    let new = planning::endpoint(&c).await?;
    let draft = Request {
        definition: ScopeDefinition {
            targets: BTreeSet::from([Reference::Device(new.members[0].device.clone())]),
            limitations: None,
            exclusions: BTreeSet::from([Reference::Group(group)]),
        },
        channel: Channel::Mdm,
        editing: None,
    };
    let preview = scopes.preview(&p, &draft, &c.request(&p)?).await?;
    assert_eq!(preview.items, vec![new.object.clone()]);
    assert!(preview.scan_complete && !preview.has_unknown);
    let id = Uuid::new_v4();
    let receipt = scopes
        .execute(
            &Command::Scope {
                id,
                change: Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: 0,
                    input: ScopeChange::Put {
                        definition: draft.definition.clone(),
                    },
                },
            },
            &c.request(&p)?,
            &p,
        )
        .await?;
    let task = Uuid::parse_str(receipt["task"].as_str().unwrap())?;
    for _ in 0..20 {
        crate::scope_t2::advance(&scopes, task, &preview.asset_cut, false).await?;
    }
    let page = scopes
        .page(
            &p,
            &pages::PageRequest {
                scope: id,
                result: task,
                projection: pages::ScopePageKind::Members,
                query: pages::ResultQuery::parse("channel=mdm")?,
            },
            &c.request(&p)?,
        )
        .await?;
    assert_eq!(
        page["page"]["items"],
        json!([{"object":new.object,"available":true}])
    );
    drop(scopes);
    drop(owners);
    c.close().await;
    Ok(())
}
