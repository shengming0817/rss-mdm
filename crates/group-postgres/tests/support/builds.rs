//! Consumer-owned transactions. No scheduler/claim implementation is copied here.
use super::support::{FixturePage, at, deadline, op, tenant};
use rss_mdm_group_postgres::*;
use rss_transactional_messaging::transaction::LocalTxAttempt;
use rss_transactional_messaging_postgres::{PgError, PgRuntime};
pub fn settle<T>(
    attempt: LocalTxAttempt<Result<T, Rejection>, PgError>,
    id: OperationId,
) -> Result<T, Error> {
    attempt.fold(
        |v| v.map_err(Error::Rejected),
        |e| Err(Error::NotStarted(e)),
        |e| Err(Error::RolledBack(e)),
        |e| Err(Error::RollbackFailed(e)),
        |source| {
            Err(Error::CommitUnknown {
                operation: Some(id),
                source,
            })
        },
        |e| Err(Error::Fenced(e)),
    )
}
pub fn request(receipt: &Receipt, patch: Option<MemberPatch>) -> BuildRequest {
    BuildRequest {
        id: op(),
        group: receipt.group.id,
        expected: receipt.group.revision,
        rule_version: receipt.group.rule_version.clone(),
        patch,
        input_version: "fixture-frozen".into(),
        as_of: at(),
    }
}
pub async fn begin(
    runtime: &PgRuntime,
    s: &GroupStore,
    r: &BuildRequest,
) -> Result<MemberBuild, Error> {
    settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (s, r), |ctx, tx| {
                Box::pin(async move { ctx.0.begin_build_in(tx, ctx.1).await })
            })
            .await,
        r.id,
    )
}
pub async fn prepare(
    runtime: &PgRuntime,
    s: &GroupStore,
    r: &BuildRequest,
    page: &FixturePage,
) -> Result<MemberBuild, Error> {
    let id = r.id;
    let count = page.objects.len();
    let build = begin(runtime, s, r).await?;
    if !build.input_sealed {
        if r.patch.is_some() {
            settle(
                runtime
                    .local_tx_with_context(tenant(), deadline(), s, move |s, tx| {
                        Box::pin(async move { s.advance_static_in(tx, id).await })
                    })
                    .await,
                r.id,
            )?;
        } else {
            if !page.objects.is_empty() {
                settle(
                    runtime
                        .local_tx_with_context(tenant(), deadline(), (s, r, page), |ctx, tx| {
                            Box::pin(async move {
                                ctx.0
                                    .append_build_page_in(
                                        tx,
                                        ctx.1.id,
                                        &core::PageInput {
                                            tenant: tenant(),
                                            id: "fixture",
                                            version: &ctx.1.input_version,
                                            dictionary_version: "dictionary-1",
                                            coverage: &ctx.2.coverage,
                                            objects: &ctx.2.objects,
                                            after: None,
                                        },
                                    )
                                    .await
                            })
                        })
                        .await,
                    r.id,
                )?;
            }
            settle(
                runtime
                    .local_tx_with_context(tenant(), deadline(), s, move |s, tx| {
                        Box::pin(async move { s.seal_build_in(tx, id, count).await })
                    })
                    .await,
                r.id,
            )?;
        }
    }
    loop {
        let step = settle(
            runtime
                .local_tx_with_context(tenant(), deadline(), s, move |s, tx| {
                    Box::pin(async move { s.advance_difference_in(tx, id).await })
                })
                .await,
            r.id,
        )?;
        if step.build.ready {
            return Ok(step.build);
        }
    }
}
pub async fn publish(
    runtime: &PgRuntime,
    s: &GroupStore,
    r: &BuildRequest,
) -> Result<Receipt, Error> {
    settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), (s, r), |ctx, tx| {
                Box::pin(async move {
                    tx.prepare_outbox_partitions(&[ctx.0.partition(&ctx.1.group.to_string())?])
                        .await?;
                    ctx.0.publish_build_in(tx, ctx.1.id).await
                })
            })
            .await,
        r.id,
    )
}
pub async fn members(
    runtime: &PgRuntime,
    s: &GroupStore,
    id: OperationId,
) -> Result<Vec<String>, Error> {
    settle(
        runtime
            .local_tx_with_context(tenant(), deadline(), s, move |s, tx| {
                Box::pin(async move { s.build_members_in(tx, id, None, 1000).await })
            })
            .await,
        id,
    )
}
