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
            Kind::Enum(&["windows_exe", "windows_msi", "macos_pkg"]),
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
pub async fn list<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    q: Query,
) -> Result<Value, Error> {
    q.require_schema(&SCHEMA).map_err(management::query_error)?;
    p.manage(Permission::AgentEnrollmentRead)?;
    audit.set_action("agent_package_read");
    transaction::inspect(&app.runtime,app.tenant,(app,p,audit,q),|ctx,tx|Box::pin(async move{
  let(app,p,audit,q)=ctx;let current=transaction::current(tx,p).await?;current.require(p,Permission::AgentEnrollmentRead,None)?;
  let binding=q.binding(&(p.tenant_id(),p.instance_id(),current.query_binding(p)?)).map_err(management::query_error)?;let after=q.after(&app.cursor,&binding).map_err(management::query_error)?;
  let mut sql=sqlx::QueryBuilder::new("SELECT document || jsonb_build_object('_package',document,'_id',id,'state',state,'platform',platform,'architecture',architecture) FROM mdm_agent_packages.releases WHERE tenant_id=");sql.push_bind(tx.tenant_id().to_string()).push("::uuid");
  rss_mdm_query_postgres::append(&mut sql,q,after.as_ref(),column).map_err(management::query_error)?;
  let rows:Vec<Value>=tx.with_connection(move|c|Box::pin(async move{sql.build_query_scalar().fetch_all(c).await})).await?;
  for row in &rows{validate(row,app.tenant)?;}
  p.check_live()?;audit.require_request_settlement();Ok(json!(q.page(rows,&app.cursor,&binding).map_err(management::query_error)?))
 }),TransactionOwner::SoftwareCatalog).await
}
pub async fn get<C: ManagementContentPort>(
    app: &management::catalog::Access<C>,
    p: &AuthorizedPrincipal,
    audit: &RequestAudit,
    id: Uuid,
) -> Result<Value, Error> {
    // The same directory projection defines metadata identity, including withdrawn releases.
    let q = SCHEMA
        .parse(&format!("filter=releaseId=={id}&limit=1"))
        .map_err(management::query_error)?;
    let page = list(app, p, audit, q).await?;
    page["items"]
        .as_array()
        .and_then(|v| v.first())
        .cloned()
        .ok_or(Error::ResourceMissing)
}
