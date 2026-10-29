use super::*;
use crate::authorization::context::AuthorizedPrincipal;
use rss_mdm_authorization_service::Permission;
use rss_mdm_query::{
    cursor::CursorCodec,
    directory::{Field, Kind, Query, Schema},
};

pub static SCHEMA: Schema = Schema {
    id: "scopes",
    keys: &["id"],
    default_limit: 64,
    max_limit: 1000,
    fields: &[
        Field::scalar("id", Kind::Uuid),
        Field::scalar("revision", Kind::Integer),
        Field::scalar("deleted", Kind::Boolean),
        Field::scalar("calculationRevision", Kind::Integer),
        Field::scalar("resolutionRevision", Kind::Integer),
        Field::output("resolution"),
        Field::filter_only("ready", Kind::Boolean),
    ],
};
pub fn parse(raw: &str) -> rss_mdm_query::Result<Query> {
    let mut q = SCHEMA.parse(raw)?;
    q.default_filter("deleted", "false")?;
    Ok(q)
}
impl Scopes {
    pub async fn scope_directory(
        &self,
        proof: &AuthorizedPrincipal,
        q: &Query,
        audit: &RequestAudit,
    ) -> std::result::Result<rss_mdm_query::Page<rss_mdm_query::directory::Projection<Row>>, Error>
    {
        q.require_schema(&SCHEMA).map_err(crate::query_error)?;
        proof.manage(Permission::ScopeRead)?;
        crate::transaction::inspect(
            &self.runtime,
            self.tenant,
            (self, proof, q, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (s, p, q, _audit) = *ctx;
                    let current = crate::action_admission::current(tx, p).await?;
                    current.require(p, Permission::ScopeRead, None)?;
                    let binding = q
                        .binding(&(p.tenant_id(), p.instance_id(), current.query_binding(p)?))
                        .map_err(crate::query_error)?;
                    let codec = CursorCodec::from_key(s.cursor_key.clone());
                    let after = q.after(&codec, &binding).map_err(crate::query_error)?;
                    let rows = s.store.directory_in(tx, q, after.as_ref()).await?;
                    p.check_live()?;
                    let rows = rows
                        .into_iter()
                        .map(serde_json::from_value::<Row>)
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(|_| Error::Unavailable(crate::Failure::Storage))?;
                    Ok(q.page_typed(rows, &codec, &binding)
                        .map_err(crate::query_error)?)
                })
            },
        )
        .await
    }
}

#[derive(schemars::JsonSchema, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Row {
    pub id: Uuid,
    pub revision: i64,
    pub deleted: bool,
    pub calculation_revision: i64,
    pub resolution: Option<Uuid>,
    pub resolution_revision: i64,
}
