//! Compliance owns task facts and terminal audit; RSS owns claims and retries.
use super::*;
pub type TaskState = pg::tasks::Task<Input>;
impl Compliance {
    fn check_task_transaction(&self, tx: &PgTransaction<'_>) -> Result<()> {
        self.runtime.validate_transaction(tx)?;
        if tx.tenant_id() != self.tenant() {
            return Err(Error::Forbidden.into());
        }
        Ok(())
    }
    pub async fn read_task_in(&self, tx: &mut PgTransaction<'_>, id: Uuid) -> Result<TaskState> {
        self.check_task_transaction(tx)?;
        let t = self.tenant();
        let state = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::tasks::read::<Input>(c, t, id).await })
            })
            .await?
            .ok_or(Error::NotFound)?;
        stored(state.input.validate())?;
        Ok(state)
    }
    pub(super) async fn enqueue_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        input: &Input,
    ) -> Result<()> {
        self.check_task_transaction(tx)?;
        checked_input(input.validate())?;
        let t = self.tenant();
        let input = input.clone();
        tx.with_connection(move |c| {
            Box::pin(async move {
                pg::tasks::enqueue(c, t, id, input.rule, input.revision, &input).await
            })
        })
        .await?;
        self.reconcile_messaging
            .wake_in(
                tx,
                &target(t, id),
                &rss_reconcile::ResourceSet::empty(t),
                (),
                |_, _| Box::pin(async { Ok(()) }),
            )
            .await?;
        crate::wake::task(tx, "compliance").await?;
        Ok(())
    }
    pub(super) async fn task_cursor_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        cursor: Option<String>,
    ) -> Result<()> {
        self.check_task_transaction(tx)?;
        let t = self.tenant();
        tx.with_connection(move |c| {
            Box::pin(async move { pg::tasks::cursor(c, t, id, cursor.as_deref()).await })
        })
        .await?;
        Ok(())
    }
    pub(super) async fn task_detail_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        detail: crate::tasks::TaskDiagnostic,
    ) -> Result<()> {
        self.check_task_transaction(tx)?;
        let t = self.tenant();
        let detail = json(&detail)?;
        tx.with_connection(move |c| {
            Box::pin(async move { pg::tasks::detail(c, t, id, detail).await })
        })
        .await?;
        Ok(())
    }
    pub(super) async fn finish_task_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: Uuid,
        failure: Option<&str>,
    ) -> Result<()> {
        self.check_task_transaction(tx)?;
        let state = self.read_task_in(tx, id).await?;
        let t = self.tenant();
        let reason = failure.map(str::to_owned);
        let changed = tx
            .with_connection(move |c| {
                Box::pin(async move { pg::tasks::finish(c, t, id, reason.as_deref()).await })
            })
            .await?;
        self.clear_evaluation(tx, id).await?;
        if !changed {
            return Ok(());
        }
        let action = match failure {
            None => "automation_completed",
            Some("superseded") => "automation_superseded",
            Some(_) => "automation_failed",
        };
        let audit = RequestAudit::new(
            t.to_string(),
            action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.identify_service("service:compliance");
        audit.target(&state.input.rule.to_string());
        audit.operation(
            id,
            action,
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        let fact = rss_mdm_audit_integration::Fact::business(
            &audit,
            &format!("compliance:{id}:terminal"),
            200,
            if failure.is_some() {
                "failed"
            } else {
                "success"
            },
            None,
        )
        .map_err(Error::from)?;
        let result = self
            .audit_store
            .append_in(tx, &fact)
            .await
            .map_err(Error::from);
        audit.finalize(
            result
                .as_ref()
                .err()
                .map(|_| rss_mdm_audit_integration::FailureReason::Transaction),
        );
        result?;
        Ok(())
    }
    pub(super) async fn history_in(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        bounds: HistoryBounds,
        after: Option<HistoryPosition>,
        limit: usize,
    ) -> Result<Vec<HistoryRow>> {
        self.check_task_transaction(tx)?;
        if !(1..=usize::from(rss_mdm_query::MAX_PAGE_LIMIT)).contains(&limit) {
            return Err(Error::Malformed.into());
        }
        let t = self.tenant();
        let device = device.to_owned();
        let rows = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    pg::tasks::history(
                        c,
                        t,
                        &device,
                        (bounds.from, bounds.until),
                        after.map(|a| (a.evaluated_at, a.task)),
                        limit,
                    )
                    .await
                })
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| HistoryRow {
                position: HistoryPosition {
                    task: r.task,
                    evaluated_at: r.evaluated_at,
                },
                document: r.document,
                failure: r.failure,
            })
            .collect())
    }
}
pub fn target(t: TenantId, id: Uuid) -> rss_reconcile::Target {
    rss_reconcile::Target::new(
        rss_reconcile::Scope::new(t, "mdm.compliance").expect("constant scope"),
        format!("task:{id}"),
    )
    .expect("UUID target")
}
