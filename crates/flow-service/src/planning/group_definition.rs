//! Resumable validation of one Group definition using the existing Automation job.
//! ref: kubernetes/apimachinery v0.34.0 pkg/apis/meta/v1/types.go (edit versus observation coordinates).
use super::*;
use rss_mdm_inventory_service::groups::{DefinitionEdit, Groups};

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Cursor {
    graph_revision: u64,
    ready: bool,
}
impl Planning {
    fn group_editor(&self) -> Groups {
        Groups {
            objects: self.objects.clone(),
            tenant: self.tenant,
            groups: self.groups.clone(),
            cursor_key: self.cursor_key.clone(),
            audit_store: self.audit_store.clone(),
            runtime: self.runtime.clone(),
            reconcile_messaging: self.reconcile_messaging.clone(),
            clock: Arc::new(crate::clock::InventoryClock(self.clock.clone())),
        }
    }
    pub(crate) async fn advance_group_definition_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        edit: &DefinitionEdit,
        cursor: Option<String>,
    ) -> Result<()> {
        let editor = self.group_editor();
        let (context, roots) = match editor
            .definition_references_in(tx, edit.group, &edit.change)
            .await
        {
            Ok(value) => value,
            Err(rss_mdm_inventory_service::transaction::Fault::Request(
                rss_mdm_inventory_service::Error::Conflict,
            )) => {
                return crate::automation::jobs::finish_job_in(
                    tx,
                    &self.audit_store,
                    task,
                    Some("owner_conflict"),
                )
                .await;
            }
            Err(error) => return Err(error.into()),
        };
        let revision = checked(self.sources.reference_in(tx, "group-graph").await?)?.unwrap_or(0);
        let previous: Option<Cursor> = cursor
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Error::Malformed)?;
        let restart = previous
            .as_ref()
            .is_none_or(|c| c.graph_revision != revision);
        if !restart && previous.as_ref().is_some_and(|c| c.ready) {
            editor
                .publish_change_in(
                    tx,
                    edit.group,
                    &edit.change,
                    checked_input(Timepoint::try_from(edit.at))?,
                    self,
                )
                .await?;
            return crate::automation::jobs::finish_job_in(tx, &self.audit_store, task, None).await;
        }
        if restart {
            let tenant = self.tenant.to_string();
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query("DELETE FROM mdm_planning.group_definition_walk WHERE tenant_id=$1::uuid AND task_id=$2")
                    .bind(tenant).bind(task).execute(c).await?;
                Ok(())
            })).await?;
            self.seed_definition_nodes(tx, task, revision, roots)
                .await?;
        }
        let tenant = self.tenant.to_string();
        let nodes: Vec<Uuid> = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT node_id FROM mdm_planning.group_definition_walk WHERE tenant_id=$1::uuid AND task_id=$2 AND graph_revision=$3 AND NOT visited ORDER BY node_id LIMIT 16")
                .bind(tenant).bind(task).bind(revision as i64).fetch_all(c).await
        })).await?;
        for node in &nodes {
            if *node == edit.group {
                return Err(Error::Malformed.into());
            }
            let children = editor.reference_edges_in(tx, *node, context).await?;
            if children.contains(&edit.group) {
                return Err(Error::Malformed.into());
            }
            self.seed_definition_nodes(tx, task, revision, children)
                .await?;
            let tenant = self.tenant.to_string();
            let node = *node;
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query("UPDATE mdm_planning.group_definition_walk SET visited=true WHERE tenant_id=$1::uuid AND task_id=$2 AND node_id=$3 AND graph_revision=$4")
                    .bind(tenant).bind(task).bind(node).bind(revision as i64).execute(c).await?; Ok(())
            })).await?;
        }
        let tenant = self.tenant.to_string();
        let pending: bool = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_planning.group_definition_walk WHERE tenant_id=$1::uuid AND task_id=$2 AND graph_revision=$3 AND NOT visited)")
                .bind(tenant).bind(task).bind(revision as i64).fetch_one(c).await
        })).await?;
        let cursor = checked_input(serde_json::to_string(&Cursor {
            graph_revision: revision,
            ready: !pending,
        }))?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_automation.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2")
                .bind(tenant).bind(task).bind(cursor).execute(c).await?; Ok(())
        })).await?;
        Ok(())
    }
    async fn seed_definition_nodes(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        revision: u64,
        nodes: Vec<Uuid>,
    ) -> Result<()> {
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_planning.group_definition_walk(tenant_id,task_id,node_id,graph_revision) SELECT $1::uuid,$2,n,$3 FROM unnest($4::uuid[]) n ON CONFLICT(tenant_id,task_id,node_id) DO UPDATE SET graph_revision=excluded.graph_revision,visited=false WHERE mdm_planning.group_definition_walk.graph_revision<>excluded.graph_revision")
                .bind(tenant).bind(task).bind(revision as i64).bind(nodes).execute(c).await?; Ok(())
        })).await?;
        Ok(())
    }
}
