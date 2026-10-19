//! 同址灾难恢复：只接受空目标数据库，保留原安装、密钥和内容身份。
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub directory: PathBuf,
    pub operation_id: Uuid,
    pub backup_manifest_sha256: String,
    /// 目标集群须已恢复受限角色及其原凭据，管理员仅用于原样还原归档。
    pub administrator: crate::config::Database,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Reserved,
    Database,
    Contents,
    Complete,
}
#[derive(Serialize, Deserialize)]
struct Progress {
    operation: Uuid,
    manifest: String,
    stage: Stage,
}
pub async fn run(input: Request) -> Result<Receipt> {
    if !cfg!(target_os = "linux") || input.operation_id.is_nil() {
        return Err(Error::Input);
    }
    let journal = Journal::open(&input.directory)?;
    journal.secret(
        "recovery-request.json",
        &serde_json::to_vec(&input).map_err(|_| Error::Input)?,
    )?;
    let bundle = backup::verify(&journal, &input.backup_manifest_sha256)?;
    let mut saved: Saved = journal.load("restore-source.json")?.ok_or(Error::Corrupt)?;
    if saved.receipt.phase != Phase::BackedUp
        || saved.receipt.operation_id != bundle.operation
        || saved.operator.directory != input.directory
        || saved.owner.host != input.administrator.host
        || saved.owner.port != input.administrator.port
        || saved.owner.name != input.administrator.name
    {
        return Err(Error::Conflict);
    }
    saved.receipt.backup_manifest_sha256 = Some(input.backup_manifest_sha256.clone());
    let mut progress: Progress = journal.load("recovery.json")?.unwrap_or(Progress {
        operation: input.operation_id,
        manifest: input.backup_manifest_sha256.clone(),
        stage: Stage::Reserved,
    });
    if progress.operation != input.operation_id || progress.manifest != input.backup_manifest_sha256
    {
        return Err(Error::Conflict);
    }
    journal.save("recovery.json", &progress)?;
    if progress.stage == Stage::Complete {
        let restored: Saved = journal.load("transfer.json")?.ok_or(Error::Corrupt)?;
        if restored.receipt.phase != Phase::Transferred {
            return Err(Error::Corrupt);
        }
        return Ok(restored.receipt);
    }
    super::super::backup::recovery_administrator(&input.administrator).await?;
    if progress.stage == Stage::Reserved {
        let mut c =
            PgConnection::connect_with(&input.administrator.options().map_err(|_| Error::Input)?)
                .await
                .map_err(|_| Error::Storage)?;
        super::super::backup::connection_fence(&mut c, &journal, true).await?;
        stopped(&mut c).await?;
        sqlx::query("SELECT pg_advisory_lock(2823,4)")
            .execute(&mut c)
            .await
            .map_err(|_| Error::Storage)?;
        let reserved: bool =
            sqlx::query_scalar("SELECT to_regclass('public.mdm_restore_operation') IS NOT NULL")
                .fetch_one(&mut c)
                .await
                .map_err(|_| Error::Storage)?;
        if !reserved {
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN('r','p','v','m','S','f')").fetch_one(&mut c).await.map_err(|_|Error::Storage)?;
            if count != 0 {
                return Err(Error::Conflict);
            }
            let mut tx = c.begin().await.map_err(|_| Error::Storage)?;
            sqlx::raw_sql("CREATE TABLE public.mdm_restore_operation(singleton boolean PRIMARY KEY CHECK(singleton),operation uuid NOT NULL,manifest text NOT NULL); REVOKE ALL ON public.mdm_restore_operation FROM PUBLIC").execute(&mut *tx).await.map_err(|_|Error::Storage)?;
            sqlx::query("INSERT INTO public.mdm_restore_operation VALUES(true,$1,$2)")
                .bind(input.operation_id)
                .bind(&input.backup_manifest_sha256)
                .execute(&mut *tx)
                .await
                .map_err(|_| Error::Storage)?;
            tx.commit().await.map_err(|_| Error::Storage)?;
        }
        let marker: (Uuid, String) = sqlx::query_as(
            "SELECT operation,manifest FROM public.mdm_restore_operation WHERE singleton",
        )
        .fetch_one(&mut c)
        .await
        .map_err(|_| Error::Storage)?;
        if marker != (input.operation_id, input.backup_manifest_sha256.clone()) {
            return Err(Error::Conflict);
        }
        let committed: bool =
            sqlx::query_scalar("SELECT to_regclass('public.mdm_installation') IS NOT NULL")
                .fetch_one(&mut c)
                .await
                .map_err(|_| Error::Storage)?;
        if !committed {
            backup::restore_database(&journal, &input.administrator).await?;
        }
        exact_source(&mut c).await?;
        crate::migration::verify_identity(&mut c, &saved.installation)
            .await
            .map_err(|_| Error::Conflict)?;
        c.close().await.map_err(|_| Error::Storage)?;
        progress.stage = Stage::Database;
        journal.save("recovery.json", &progress)?;
    }
    if progress.stage == Stage::Database {
        let mut c = PgConnection::connect_with(&saved.owner.options().map_err(|_| Error::Input)?)
            .await
            .map_err(|_| Error::Storage)?;
        super::super::backup::connection_fence(&mut c, &journal, true).await?;
        stopped(&mut c).await?;
        for host in &saved.hosts {
            if let Some(volume) = &host.input.deployment.content_volume {
                backup::restore_volume(&journal, host.id, volume)?;
            }
            storage::restore(&mut c, &journal, host.id, &host.source).await?;
        }
        let expected: Vec<ledger::Head> = journal
            .load("ledger-checkpoints.json")?
            .ok_or(Error::Corrupt)?;
        for head in expected {
            let runtime = saved
                .hosts
                .iter()
                .find(|h| h.source["identity"]["tenant_id"].as_str() == Some(&head.tenant))
                .unwrap_or(&saved.hosts[0]);
            let actual = ledger::verify_operator(
                &runtime.source,
                std::slice::from_ref(&head.tenant),
                &input.administrator,
            )
            .await?;
            if serde_json::to_value(&actual[0]).map_err(|_| Error::Corrupt)?
                != serde_json::to_value(&head).map_err(|_| Error::Corrupt)?
            {
                return Err(Error::Corrupt);
            }
        }
        c.close().await.map_err(|_| Error::Storage)?;
        // 数据和原链均通过后才允许新权威迁入、真实认证及宿主重启。
        journal.save("transfer.json", &saved)?;
        progress.stage = Stage::Contents;
        journal.save("recovery.json", &progress)?;
    }
    let current: Saved = journal.load("transfer.json")?.ok_or(Error::Corrupt)?;
    let receipt = resume(current, &journal).await?;
    progress.stage = Stage::Complete;
    journal.save("recovery.json", &progress)?;
    Ok(receipt)
}
