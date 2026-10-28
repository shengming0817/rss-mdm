//! Resumable validation of one Group definition using the existing Automation job.
//! ref: kubernetes/apimachinery v0.34.0 pkg/apis/meta/v1/types.go (edit versus observation coordinates).
use super::*;

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Cursor {
    graph_revision: u64,
    ready: bool,
}
impl Groups {
    pub(crate) async fn advance_group_definition_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        edit: &DefinitionEdit,
        cursor: Option<String>,
    ) -> Result<()> {
        let editor = self;
        let (context, roots) = match editor
            .definition_references_in(tx, edit.group, &edit.change)
            .await
        {
            Ok(value) => value,
            Err(crate::transaction::Fault::Request(crate::Error::Conflict)) => {
                return self.finish_task_in(tx, task, Some("owner_conflict")).await;
            }
            Err(error) => return Err(error),
        };
        let revision = group_checked(self.groups.graph_revision_in(tx).await?)?;
        let previous: Option<Cursor> = cursor
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| Error::Unavailable(Failure::AssetsStorage))?;
        let restart = previous
            .as_ref()
            .is_none_or(|c| c.graph_revision != revision);
        if !restart && previous.as_ref().is_some_and(|c| c.ready) {
            editor
                .publish_change_in(
                    tx,
                    edit.group,
                    &edit.change,
                    stored(Timepoint::try_from(edit.at))?,
                    &edit.authority,
                )
                .await?;
            return self.finish_task_in(tx, task, None).await;
        }
        if restart {
            group_checked(self.groups.clear_definition_walk_in(tx, task).await?)?;
            self.seed_definition_nodes(tx, task, revision, roots)
                .await?;
        }
        let nodes = group_checked(
            self.groups
                .definition_walk_page_in(tx, task, revision)
                .await?,
        )?;
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
            group_checked(
                self.groups
                    .visit_definition_node_in(tx, task, revision, *node)
                    .await?,
            )?;
        }
        let pending = !group_checked(
            self.groups
                .definition_walk_page_in(tx, task, revision)
                .await?,
        )?
        .is_empty();
        let cursor = checked_input(serde_json::to_string(&Cursor {
            graph_revision: revision,
            ready: !pending,
        }))?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_assets.group_tasks SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2")
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
        group_checked(
            self.groups
                .seed_definition_walk_in(tx, task, revision, nodes)
                .await?,
        )?;
        Ok(())
    }
}
