//! Direct blockers use real owner transactions and runtime roles. HTTP consumes the same
//! authenticated principal as the service; these cases do not replace session/TLS proofs.
mod fields;
mod publication;
use super::{
    owner_boundaries_t2::{Owners, scope},
    software_t2::support,
};
use crate::{authority_t2_support::Context, planning_t2_support as planning};
use anyhow::Result;
use rss_mdm_authorization_service::{
    Permission as P,
    context::{AuthorizedPrincipal, RequestAuth},
};
use rss_mdm_resource as r;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

struct Http {
    base: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Http {
    async fn open(router: axum::Router, c: &Context, p: Arc<AuthorizedPrincipal>) -> Result<Self> {
        let router = router
            .layer(axum::Extension(c.request(&p)?))
            .layer(axum::Extension(RequestAuth {
                proof: p,
                sessions: rss_mdm_authorization_service::session::SessionAuthority::new(
                    c.authority.clone(),
                    c.tenant,
                ),
                deadline: c.access().now() + std::time::Duration::from_secs(8),
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Ok(Self { base, task })
    }
    async fn get(&self, path: &str) -> Result<(u16, Value)> {
        let response = reqwest::get(format!("{}{path}", self.base)).await?;
        let status = response.status().as_u16();
        let value = response.json().await?;
        Ok((status, value))
    }
    async fn pages(&self, path: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let uri = format!(
                "{path}?limit=1{}",
                cursor
                    .as_ref()
                    .map_or(String::new(), |c| format!("&cursor={c}"))
            );
            let (status, value) = self.get(&uri).await?;
            assert_eq!(status, 200, "{value}");
            assert!(value.get("total").is_none());
            assert!(value.get("canDelete").is_none());
            let items = value["items"].as_array().expect("domain Page");
            assert!(items.len() <= 1);
            out.extend(items.iter().cloned());
            cursor = value["nextCursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
            assert!(out.len() < 20, "continuation must terminate");
        }
        Ok(out)
    }
}
async fn catalog(
    c: &Context,
) -> Result<(
    crate::owner_storage::OwnerRuntime,
    Arc<rss_mdm_resource_service::ResourceCatalog>,
)> {
    let owner = planning::owner(c, "mdm_resource_runtime").await?;
    let service = super::resource::catalog(
        owner.audit.clone(),
        owner.runtime.clone(),
        c.tenant,
        Arc::new(crate::clock::SystemClock),
        vec![7; 32],
    )
    .await?;
    Ok((owner, service))
}
async fn version(c: &Context, v: r::Version) -> Result<()> {
    let owner = planning::owner(c, "mdm_resource_runtime").await?;
    let store = rss_mdm_resource_postgres::ResourceStore::new(
        owner.runtime.clone(),
        c.tenant,
        crate::authority_t2_support::deadline(),
    )
    .await?;
    for (revision, command) in [
        (0, rss_mdm_resource_postgres::Command::Create(v.kind())),
        (1, rss_mdm_resource_postgres::Command::Insert(v.clone())),
    ] {
        store
            .execute(
                &rss_mdm_resource_postgres::Request {
                    id: r::Id::new(Uuid::new_v4().to_string())?,
                    resource: v.resource().clone(),
                    expected_storage_revision: revision,
                    as_of: rss_contract::Timepoint::try_from(support::now())?,
                    command,
                },
                crate::authority_t2_support::deadline(),
            )
            .await?;
    }
    owner.runtime.close().await;
    Ok(())
}
async fn archive(
    service: &rss_mdm_resource_service::ResourceCatalog,
    c: &Context,
    p: &AuthorizedPrincipal,
    id: &str,
    version: &str,
    revision: u64,
) -> std::result::Result<Value, rss_mdm_resource_service::Error> {
    service
        .execute(
            &rss_mdm_resource_service::Command::Resource {
                id: id.into(),
                change: rss_mdm_resource_service::Operation {
                    operation_id: Uuid::new_v4(),
                    expected_revision: revision,
                    input: rss_mdm_resource_service::Change::Archive {
                        version: version.into(),
                    },
                },
            },
            &c.request(p).unwrap(),
            p,
        )
        .await
}

#[tokio::test]
#[ignore = "T2: authenticated HTTP pages expose all retained resource blockers under target-only permission, with fresh grants and exact runtime privileges"]
async fn resource_http_retention_permissions_and_continuations() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let account = c.account(&[P::ResourceRead]).await?;
    let proof = Arc::new(c.authenticate(&account).await?);
    let resource = support::software_with_export(
        &c,
        "blocker-software",
        r::SoftwareExport::Winget {
            locale: "en-US".into(),
            name: "App".into(),
            publisher: "Acme".into(),
            description: "App".into(),
            license: "Proprietary".into(),
        },
    )
    .await?;
    let target = scope(&c, &[]).await?;
    let (policy, historical) = support::policy(
        &c,
        &resource,
        target,
        rss_mdm_policy::SoftwareChannel::Agent,
        vec![support::stage(target)],
    )
    .await?;
    let current = Uuid::new_v4();
    let mut tx = crate::command_runtime_t2_support::seed_transaction(&c).await?;
    sqlx::query("INSERT INTO mdm_policy.versions(tenant_id,id,policy,number,action_kind,frozen,fingerprint,resource,resource_version) SELECT tenant_id,$3,policy,2,action_kind,frozen,fingerprint,resource,resource_version FROM mdm_policy.versions WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(historical).bind(current).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE mdm_policy.policies SET state='archived',current_version=$3,version_number=2,revision=2 WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(c.tenant.to_string())
    .bind(policy)
    .bind(current)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE mdm_software.versions SET lifecycle=jsonb_set(lifecycle,'{state}','\"withdrawn\"') WHERE tenant_id=$1::uuid AND resource='blocker-software'").bind(c.tenant.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    publication::withdrawn(&c, &resource).await?;
    let (owner, service) = catalog(&c).await?;
    let http = Http::open(
        rss_mdm_management_http::resource_catalog::http::routes()
            .into_axum()
            .with_state(Arc::new(
                rss_mdm_management_http::resource_catalog::http::HttpState {
                    catalog: service.clone(),
                    content: None,
                },
            )),
        &c,
        proof.clone(),
    )
    .await?;
    let path = "/resources/blocker-software/versions/1/references";
    let rows = http.pages(path).await?;
    assert_eq!(rows.len(), 4);
    assert!(rows.iter().any(|r| r["id"] == policy.to_string()
        && r["version"] == current.to_string()
        && r["retention"] == "current_version"));
    assert!(
        rows.iter()
            .any(|r| r["version"] == historical.to_string()
                && r["retention"] == "historical_version")
    );
    assert!(rows.iter().any(|r| r["id"] == "retained-publication"));
    assert!(rows.iter().all(|r| r["release"] == "retained_immutable"));
    for row in &rows {
        assert_eq!(row.as_object().unwrap().len(), 6);
    }
    assert_eq!(
        http.get("/resources/blocker-software/versions/missing/references")
            .await?
            .0,
        404
    );
    assert_eq!(
        http.get(&format!("{path}?kind=policy_version")).await?.0,
        400
    );
    let (_, first) = http.get(&format!("{path}?limit=1")).await?;
    let token = first["nextCursor"].as_str().unwrap();
    assert_ne!(
        http.get(&format!("{path}?limit=2&cursor={token}")).await?.0,
        200
    );
    let other_account = c.account(&[P::ResourceRead]).await?;
    let other_proof = c.authenticate(&other_account).await?;
    assert!(matches!(
        service
            .references(
                &other_proof,
                "blocker-software",
                "1",
                &rss_mdm_resource_service::references::SCHEMA
                    .parse(&format!("limit=1&cursor={token}"))?
                    .0
            )
            .await,
        Err(rss_mdm_resource_service::Error::ResourceCursorInvalidated)
    ));
    support::software(&c, "other-target").await?;
    assert_ne!(
        http.get(&format!(
            "/resources/other-target/versions/1/references?limit=1&cursor={token}"
        ))
        .await?
        .0,
        200
    );
    let other = Context::open("shared", &[]).await?;
    let foreign = other.account(&[P::ResourceRead]).await?;
    let foreign = other.authenticate(&foreign).await?;
    assert!(matches!(
        service
            .references(
                &foreign,
                "blocker-software",
                "1",
                &rss_mdm_resource_service::references::SCHEMA.parse("")?.0
            )
            .await,
        Err(rss_mdm_resource_service::Error::Forbidden)
    ));
    other.close().await;
    let writer = c.account(&[P::ResourceRead, P::ResourceWrite]).await?;
    let writer = c.authenticate(&writer).await?;
    assert!(matches!(
        archive(&service, &c, &writer, "blocker-software", "1", 2).await,
        Err(rss_mdm_resource_service::Error::Referenced)
    ));
    assert!(matches!(
        archive(&service, &c, &writer, "blocker-software", "1", 0).await,
        Err(rss_mdm_resource_service::Error::Conflict)
    ));
    // A page is read-only: no command receipt was emitted by any read.
    let receipts:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_resource.requests WHERE tenant_id=$1::uuid AND owner='blocker-software'").bind(c.tenant.to_string()).fetch_one(&c.operator).await?;
    assert_eq!(receipts, 2);
    let pool = c.inputs.pool("shared", "mdm_resource_runtime").await?;
    let can_read:bool=sqlx::query_scalar("SELECT has_column_privilege(current_user,'mdm_software_composition.subjects','record','SELECT') AND NOT has_column_privilege(current_user,'mdm_software_composition.subjects','document','SELECT')").fetch_one(&pool).await?;
    assert!(can_read);
    pool.close().await;
    sqlx::query("UPDATE mdm_access.authorization_rules SET revision=revision+1,document=NULL WHERE tenant_id=$1::uuid AND id=$2").bind(c.tenant.to_string()).bind(account.rule).execute(&c.operator).await?;
    assert_eq!(
        http.get(&format!("{path}?limit=1&cursor={token}")).await?.0,
        403
    );
    drop(http);
    drop(service);
    owner.runtime.close().await;
    c.close().await;
    Ok(())
}

#[tokio::test]
#[ignore = "T2: Group direct identities carry Scope owner coordinates; impacts keep their own gate"]
async fn group_and_scope_target_authority_and_delete_gates() -> Result<()> {
    let c = Context::open("shared", &[]).await?;
    let writer = c
        .account(&[P::InventoryRead, P::GroupRead, P::GroupWrite])
        .await?;
    let writer = c.authenticate(&writer).await?;
    let owners = Owners::open(&c).await?;
    let root = owners.create(&c, &writer, None).await?;
    let child=owners.create(&c,&writer,Some(serde_json::from_value(json!({"selector":{"kind":"device"},"quantifier":"one","criteria":{"kind":"group","groupId":root,"op":"member_of"}}))?)).await?;
    for (revision, stale) in [(2, true), (1, false)] {
        let result = owners
            .groups
            .execute(
                &rss_mdm_group_service::Command::Group {
                    id: root,
                    change: Box::new(rss_mdm_group_service::operation::Operation {
                        operation_id: Uuid::new_v4(),
                        expected_revision: revision,
                        input: rss_mdm_group_service::GroupChange::Delete,
                    }),
                },
                &c.request(&writer)?,
                &writer,
            )
            .await;
        if stale {
            assert!(matches!(
                result,
                Err(rss_mdm_group_service::Error::Conflict)
            ));
        } else {
            assert!(matches!(
                result,
                Err(rss_mdm_group_service::Error::Referenced)
            ));
        }
    }
    let scoped = scope(&c, &[root]).await?;
    let account = c.account(&[P::GroupRead, P::PolicyRead]).await?;
    let reader = Arc::new(c.authenticate(&account).await?);
    let http = Http::open(
        rss_mdm_management_http::planning::routes()
            .into_axum()
            .with_state(Arc::new(
                rss_mdm_management_http::planning::http::HttpState {
                    groups: owners.groups.clone(),
                },
            )),
        &c,
        reader,
    )
    .await?;
    let rows = http.pages(&format!("/groups/{root}/references")).await?;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|r| r["id"] == child.to_string()));
    assert!(rows.iter().any(|r| r["id"] == scoped.to_string()));
    assert_eq!(http.get(&format!("/groups/{root}/impacts")).await?.0, 403);
    let row = rows.iter().find(|r| r["id"] == scoped.to_string()).unwrap();
    assert!(row["policy"].is_string());
    assert!(row["stage"].is_null());
    drop(http);
    drop(owners);
    c.close().await;
    Ok(())
}
