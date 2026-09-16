use super::*;
use anyhow::{Result, ensure};
use sqlx::Executor;
use std::str::FromStr;

#[tokio::test]
#[ignore = "make t2: populated develop schema upgrade in a dedicated disposable database"]
async fn populated_windows_and_backend_upgrade() -> Result<()> {
    let options = |name: &str| -> Result<PgConnectOptions> {
        Ok(PgConnectOptions::from_str(&std::env::var(name)?)?
            .database("mdm_upgrade")
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert(std::env::var("PG_CA_FILE")?))
    };
    let mut owner = PgConnection::connect_with(&options("MDM_OWNER_URL")?).await?;
    owner.execute("CREATE TABLE public.mdm_migrations(name text PRIMARY KEY,digest text NOT NULL,complete boolean NOT NULL DEFAULT false)").await?;
    for (name, sql) in units().into_iter().take(8) {
        sqlx::raw_sql(sql).execute(&mut owner).await?;
        sqlx::query("INSERT INTO public.mdm_migrations VALUES($1,$2,true)")
            .bind(name)
            .bind(format!("{:x}", Sha256::digest(sql)))
            .execute(&mut owner)
            .await?;
    }
    let mut admin = PgConnection::connect_with(&options("MDM_ADMIN_URL")?).await?;
    admin.execute(r#"
INSERT INTO mdm_access.grants(tenant_id,id,actor,client,device,purpose,state,expires_at)
 VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','00000000-0000-4000-8000-000000000001','legacy','mdm','legacy','enrollment','consumed',clock_timestamp()+interval '200 seconds');
INSERT INTO mdm_access.requests(tenant_id,id,grant_id)
 VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000001');
INSERT INTO mdm_access.devices VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','legacy');
INSERT INTO mdm_access.registrations VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','00000000-0000-4000-8000-000000000003','legacy','mdm',1,'00000000-0000-4000-8000-000000000002','active');
INSERT INTO mdm_access.credentials VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','00000000-0000-4000-8000-000000000004','00000000-0000-4000-8000-000000000003','mdm',repeat('a',64),'active');
INSERT INTO mdm_access.audit(tenant_id,id,request_id,action,result,status) VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','00000000-0000-4000-8000-000000000005','00000000-0000-4000-8000-000000000006','windows_management','success',200);
INSERT INTO mdm.inventory VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','mdm.observation.v1','inventory-v1','legacy','legacy','device.model','Legacy-model','legacy',1,2);
INSERT INTO mdm_access.management_sessions SELECT 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','00000000-0000-4000-8000-000000000003',state,1,'00000000-0000-4000-8000-000000000004',state,1,true,'correlation',decode(repeat('00',16),'hex'),clock_timestamp()+interval '1 hour' FROM unnest(ARRAY['challenge','complete']) AS state;
INSERT INTO mdm_access.management_messages SELECT tenant_id,registration,session_id,1,repeat('a',64),decode('01','hex') FROM mdm_access.management_sessions;
"#).await?;
    async fn history(conn: &mut PgConnection) -> Result<String> {
        Ok(sqlx::query_scalar("SELECT jsonb_build_array((SELECT jsonb_agg(to_jsonb(t)) FROM mdm_access.registrations t),(SELECT jsonb_agg(to_jsonb(t)) FROM mdm_access.credentials t),(SELECT jsonb_agg(to_jsonb(t)) FROM mdm_access.audit t),(SELECT jsonb_agg(to_jsonb(t)) FROM mdm.inventory t),(SELECT jsonb_agg(to_jsonb(t)) FROM mdm_access.requests t),(SELECT jsonb_agg(to_jsonb(t)) FROM mdm_access.grants t))::text").fetch_one(conn).await?)
    }
    let before = history(&mut admin).await?;
    ensure!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mdm_access.management_sessions WHERE expires_at>clock_timestamp()"
        )
        .fetch_one(&mut admin)
        .await?
            == 2
    );
    // Preserve the older 8→9 scenario, then freeze the actual develop baseline before N10/N11.
    let (name, sql) = units()[8];
    sqlx::raw_sql(sql).execute(&mut owner).await?;
    sqlx::query("INSERT INTO public.mdm_migrations VALUES($1,$2,true)")
        .bind(name)
        .bind(format!("{:x}", Sha256::digest(sql)))
        .execute(&mut owner)
        .await?;
    ensure!(
        before == history(&mut admin).await?,
        "upgrade changed durable history"
    );
    ensure!(sqlx::query_scalar::<_, bool>("SELECT NOT EXISTS(SELECT 1 FROM mdm_access.management_sessions) AND NOT EXISTS(SELECT 1 FROM mdm_access.management_messages)").fetch_one(&mut admin).await?, "upgrade retained old protocol state");
    ensure!(sqlx::query_scalar::<_, bool>("SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class WHERE oid IN ('mdm_access.management_sessions'::regclass,'mdm_access.management_messages'::regclass,'mdm_access.collection_runs'::regclass)").fetch_one(&mut admin).await?);
    ensure!(sqlx::query_scalar::<_, bool>("SELECT has_column_privilege('mdm_access','mdm_access.management_sessions','run_id','UPDATE') AND NOT has_table_privilege('mdm_api','mdm_access.collection_runs','SELECT')").fetch_one(&mut admin).await?);
    let index: String = sqlx::query_scalar("SELECT pg_get_expr(indpred,indrelid) FROM pg_index WHERE indexrelid='mdm_access.one_advancing_management_session'::regclass").fetch_one(&mut admin).await?;
    ensure!(index.contains("challenge") && index.contains("collecting"));
    let state: String = sqlx::query_scalar("SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='mdm_access.management_sessions'::regclass AND conname='management_sessions_state_check'").fetch_one(&mut admin).await?;
    ensure!(
        state.contains("collecting") && state.contains("complete") && state.contains("superseded")
    );
    admin.execute(r#"
INSERT INTO mdm_access.collection_runs(tenant_id,id,registration,source,epoch,scope,sequence,session_id,request_message,first_command,request,started_at,attempts,result,reason,batch,digest,sealed_at,delivery_pending)
VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','00000000-0000-4000-8000-000000000007','00000000-0000-4000-8000-000000000003','mdm.windows','00000000-0000-4000-8000-000000000008','device',0,'current',1,1024,decode('01','hex'),10,'{}','snapshot','complete',decode('02','hex'),repeat('b',64),11,true);
INSERT INTO mdm_access.management_sessions(tenant_id,registration,session_id,generation,credential,state,last_message,client_authenticated,correlation,nonce,expires_at,run_id)
VALUES('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','00000000-0000-4000-8000-000000000003','current',1,'00000000-0000-4000-8000-000000000004','complete',1,true,'current',decode(repeat('00',16),'hex'),clock_timestamp()+interval '1 hour','00000000-0000-4000-8000-000000000007');
INSERT INTO mdm_access.management_messages SELECT tenant_id,registration,session_id,1,repeat('c',64),decode('03','hex') FROM mdm_access.management_sessions;
"#).await?;
    let tables:Vec<String>=sqlx::query_scalar("SELECT quote_ident(n.nspname)||'.'||quote_ident(c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname NOT IN ('pg_catalog','information_schema','public') AND n.nspname NOT LIKE 'pg_toast%' ORDER BY 1").fetch_all(&mut admin).await?;
    async fn rows(conn: &mut PgConnection, tables: &[String]) -> Result<Vec<String>> {
        let mut records = Vec::new();
        // Identifiers come exclusively from server quote_ident over its catalog, never user input.
        for table in tables {
            // Compare every pre-existing field; the new audit projection is checked separately.
            let row = if table == "mdm_access.audit" {
                "to_jsonb(t) - 'software'"
            } else {
                "to_jsonb(t)"
            };
            records.push(sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT coalesce(jsonb_agg({row} ORDER BY ({row})::text),'[]')::text FROM {table} t"
            ))).fetch_one(&mut *conn).await?);
        }
        Ok(records)
    }
    let current = rows(&mut admin, &tables).await?;
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations WHERE complete")
            .fetch_one(&mut admin)
            .await?
            == 9
    );
    migrate_on(&mut owner).await?;
    migrate_on(&mut owner).await?;
    ensure!(
        current == rows(&mut admin, &tables).await?,
        "9→14 upgrade changed existing durable/protocol data"
    );
    ensure!(
        sqlx::query_scalar::<_, bool>(
            "SELECT count(*)=1 AND bool_and(software IS NULL) FROM mdm_access.audit"
        )
        .fetch_one(&mut admin)
        .await?,
        "upgrade invented software facts for legacy audit"
    );
    ensure!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.mdm_migrations WHERE complete")
            .fetch_one(&mut admin)
            .await?
            == 14
    );
    owner.close().await?;
    admin.close().await?;
    Ok(())
}
