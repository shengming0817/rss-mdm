//! Authenticated management metadata; public package discovery keeps its protocol admission.
use super::*;
use rss_mdm_query::directory::{Field, Kind, Query, Schema};
use serde_json::{Value, json};
pub static SCHEMA: Schema = Schema {
    id: "agent_packages",
    keys: &["releaseId"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("releaseId", Kind::Uuid),
        Field::scalar("state", Kind::Enum(&["published", "withdrawn"])),
        Field::scalar("platform", Kind::Enum(&["windows", "macos"])),
        Field::scalar("architecture", Kind::Enum(&["x86_64", "aarch64"])),
        Field::scalar(
            "format",
            Kind::Enum(&["windows_exe", "windows_msi", "windows_msix", "macos_pkg"]),
        ),
        Field::scalar("version", Kind::Text),
        Field::output("tenantId"),
        Field::output("target"),
        Field::output("filename"),
        Field::output("length"),
        Field::output("installerSha256"),
    ],
};
fn column(name: &str) -> &'static str {
    match name {
        "releaseId" => "id::text COLLATE \"C\"",
        "state" => "state COLLATE \"C\"",
        "platform" => "platform COLLATE \"C\"",
        "architecture" => "architecture COLLATE \"C\"",
        "format" => "format COLLATE \"C\"",
        "version" => "product_version COLLATE \"C\"",
        _ => unreachable!("checked package field"),
    }
}
fn validate(row: &Value, tenant: TenantId) -> Result<(), Error> {
    let p: w::Package = serde_json::from_value(row["_package"].clone()).map_err(|_| storage())?;
    if p.tenant_id.to_string() != tenant.to_string() || row["_id"] != json!(p.release_id) {
        return Err(storage());
    }
    Ok(())
}
async fn rows<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: &Query,
) -> Result<(Vec<Row>, String), Error> {
    q.require_schema(&SCHEMA).map_err(management::query_error)?;
    p.manage(Permission::AgentEnrollmentRead)?;
    audit.set_action(
        "agent_package_read",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    transaction::inspect(&app.runtime,app.tenant,(app,p,audit,q),|ctx,tx|Box::pin(async move{
  let(app,p,_audit,q)=ctx;let current=transaction::current(tx,p).await?;current.require(p,Permission::AgentEnrollmentRead,None)?;
  let binding=q.binding(&(p.tenant_id(),p.instance_id(),current.query_binding(p)?)).map_err(management::query_error)?;let after=q.after(&app.cursor,&binding).map_err(management::query_error)?;
  let mut sql=sqlx::QueryBuilder::new("SELECT document || jsonb_build_object('_package',document,'_id',id,'state',state,'platform',platform,'architecture',architecture) FROM mdm_agent_packages.releases WHERE tenant_id=");sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
  rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(management::query_error)?;
  let mut rows:Vec<Value>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_scalar().fetch_all(c).await})).await?;
  for row in &mut rows{validate(row,app.tenant)?;let fields=row.as_object_mut().ok_or_else(storage)?;fields.remove("_package");fields.remove("_id");}
  let rows=rows.into_iter().map(serde_json::from_value).collect::<std::result::Result<Vec<Row>,_>>().map_err(|_|storage())?;
  p.check_live()?;Ok((rows,binding))
 }),TransactionOwner::SoftwareCatalog).await
}
pub async fn get<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
) -> Result<Row, Error> {
    // The same directory projection defines metadata identity, including withdrawn releases.
    let q = SCHEMA
        .parse(&format!("filter=releaseId=={id}&limit=1"))
        .map_err(management::query_error)?;
    rows(app, p, audit, &q)
        .await?
        .0
        .into_iter()
        .next()
        .ok_or(Error::ResourceMissing)
}

#[derive(Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    #[serde(flatten)]
    pub package: w::Package,
    pub state: ReleaseState,
    pub platform: rss_mdm_agent_wire::runtime::TaskPlatform,
    pub architecture: rss_mdm_agent_wire::runtime::TaskArchitecture,
}
#[derive(Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseState {
    Published,
    Withdrawn,
}
pub async fn list<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: Query,
) -> Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Row>>, Error> {
    let (rows, binding) = rows(app, p, audit, &q).await?;
    q.page_typed(rows, &app.cursor, &binding)
        .map_err(management::query_error)
}
