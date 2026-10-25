use crate::assets;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskKind {
    Group,
    Scope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JobInput {
    GroupDefinition {
        edit: Box<rss_mdm_inventory_service::groups::DefinitionEdit>,
    },
    PolicyReconcile {
        policy: Uuid,
    },
    Compliance {
        input: Box<crate::compliance::Input>,
    },
    AssetQuery {
        query: Box<assets::Query>,
        scope: assets::ReadScope,
        watermark: i64,
        as_of: i64,
    },
    Group {
        group: Uuid,
        base_revision: i64,
        watermark: i64,
        publish: bool,
        automatic: bool,
    },
    Scope {
        scope: Uuid,
    },
}
impl JobInput {
    pub(crate) fn audit_partition(
        &self,
        tenant: rss_request_context::TenantId,
    ) -> Result<
        rss_transactional_messaging::message::PartitionIdentity,
        rss_mdm_audit_integration::Error,
    > {
        let kind = match self {
            Self::Group { .. } | Self::GroupDefinition { .. } => "group",
            Self::Scope { .. } => "scope",
            Self::PolicyReconcile { .. } => "policy",
            _ => "mdm",
        };
        rss_mdm_audit_integration::source_partition(tenant, kind, &self.target())
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::GroupDefinition { .. } => "group_definition",
            Self::Compliance { .. } => "compliance",
            Self::AssetQuery { .. } => "asset_query",
            Self::Group { publish: true, .. } => "group",
            Self::Group { publish: false, .. } => "group_preview",
            Self::Scope { .. } => "scope",
            Self::PolicyReconcile { .. } => "policy_reconcile",
        }
    }
    pub fn target(&self) -> String {
        match self {
            Self::Compliance { input } => input.rule.to_string(),
            Self::AssetQuery { scope, .. } => scope.subject.clone(),
            Self::Group { group, .. } => group.to_string(),
            Self::GroupDefinition { edit } => edit.group.to_string(),
            Self::Scope { scope } => scope.to_string(),
            Self::PolicyReconcile { policy } => policy.to_string(),
        }
    }
}
