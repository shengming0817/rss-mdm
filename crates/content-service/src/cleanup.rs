//! Qualification, exact provider deletion, and settlement are distinct durable operations.
use super::*;
use journal::{Manifest, commit, decode};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
use uuid::Uuid;
#[derive(Clone)]
pub struct Garbage {
    store: Store,
    manifest: Manifest,
    pub digest: [u8; 32],
    pub class: StorageClass,
    length: u64,
    _admission: Arc<crate::gate::Permit>,
}
impl Garbage {
    pub(crate) async fn lock_in(&self, tx: &mut PgTransaction<'_>) -> Result<bool, Error> {
        let tenant = tx.tenant_id().to_string();
        let digest = self.digest;
        let c = journal::class(self.class);
        let length = self.length;
        let artifact = Artifact::new(
            rss_mdm_resource::Id::new("gc").map_err(|_| invariant())?,
            length,
            rss_mdm_resource::Digest::from_bytes(digest),
        )
        .map_err(|_| invariant())?;
        let document = self.store.sign(
            &self.store.manifest_key(self.class, &artifact),
            &self.manifest,
        )?;

        tx.with_connection(move|conn|Box::pin(async move{
   let state:Option<String>=sqlx::query_scalar("SELECT state FROM mdm_content.manifests WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4 AND document=$5 FOR UPDATE").bind(&tenant).bind(c).bind(digest.as_slice()).bind(length as i64).bind(document).fetch_optional(&mut *conn).await?;
   if state.as_deref()==Some("deleted") || state.is_none(){return Ok(false)}
   let busy:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content.pins WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4 AND expires>extract(epoch FROM clock_timestamp())) OR EXISTS(SELECT 1 FROM mdm_content.uploads WHERE tenant_id=$1::uuid AND expires>extract(epoch FROM clock_timestamp()) AND document->'value'->'upload'->'binding'->'sha256'=$5)")
    .bind(&tenant).bind(c).bind(digest.as_slice()).bind(length as i64).bind(serde_json::json!(digest)).fetch_one(&mut *conn).await?;
   Ok(!busy)
  })).await.map_err(|_|storage())
    }
    pub(crate) async fn deleting_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), Error> {
        let tenant = tx.tenant_id().to_string();
        let generation = self.store.generation;
        let digest = self.digest;
        let c = journal::class(self.class);
        let length = self.length;
        tx.with_connection(move|conn|Box::pin(async move{sqlx::query("SELECT set_config('rss.content_generation',$1,true)").bind(generation.to_string()).execute(&mut *conn).await?;sqlx::query("UPDATE mdm_content.manifests SET state='deleting' WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4 AND state<>'deleted'").bind(tenant).bind(c).bind(digest.as_slice()).bind(length as i64).execute(conn).await?;Ok(())})).await.map_err(|_|storage())
    }
    pub async fn remove(self) -> Result<(), Error> {
        let artifact = Artifact::new(
            rss_mdm_resource::Id::new("gc").map_err(|_| invariant())?,
            self.length,
            rss_mdm_resource::Digest::from_bytes(self.digest),
        )
        .map_err(|_| invariant())?;
        let document = self.store.sign(
            &self.store.manifest_key(self.class, &artifact),
            &self.manifest,
        )?;
        let mut tx = self.store.tx().await?;
        let deleting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_content.manifests WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4 AND state='deleting' AND document=$5)")
         .bind(self.store.tenant.to_string()).bind(journal::class(self.class)).bind(self.digest.as_slice()).bind(self.length as i64).bind(&document).fetch_one(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        if !deleting {
            return Err(Error::Conflict);
        }
        commit(tx).await?;
        let deadline = self.store.deadline()?;
        for p in &self.manifest.pieces {
            let mut tx = self.store.tx().await?;
            let deleted:bool=sqlx::query_scalar("SELECT state='deleted' FROM mdm_content.objects WHERE tenant_id=$1::uuid AND generation=$2 AND id=$3")
                .bind(self.store.tenant.to_string()).bind(self.store.generation).bind(p.id).fetch_one(&mut *tx).await.map_err(|_|storage())?;
            commit(tx).await?;
            if deleted {
                continue;
            }

            if !self
                .store
                .backend
                .delete(
                    &self.store.coordinate(p).await?,
                    deadline,
                    self._admission.clone(),
                )
                .await?
            {
                return Err(Error::CommitUnknown);
            }
            let mut tx = self.store.tx().await?;
            sqlx::query(
                "UPDATE mdm_content.objects SET state='deleted' WHERE generation=current_setting('rss.content_generation')::uuid AND tenant_id=$1::uuid AND id=$2",
            )
            .bind(self.store.tenant.to_string())
            .bind(p.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
            commit(tx).await?;
        }
        let mut tx = self.store.tx().await?;
        sqlx::query("UPDATE mdm_content.manifests SET state='deleted' WHERE tenant_id=$1::uuid AND class=$2 AND sha256=$3 AND length=$4 AND state='deleting' AND document=$5").bind(self.store.tenant.to_string()).bind(journal::class(self.class)).bind(self.digest.as_slice()).bind(self.length as i64).bind(document).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        commit(tx).await
    }
}
impl Store {
    pub(super) async fn clean_orphans(
        &self,
        now: i64,
        admission: Arc<crate::gate::Permit>,
    ) -> Result<(), Error> {
        let deadline = self.deadline()?;
        let mut tx = self.tx().await?;
        sqlx::query(
            "DELETE FROM mdm_content.pins WHERE expires<=extract(epoch FROM clock_timestamp())",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        let rows=sqlx::query("SELECT o.id,o.location,o.content FROM mdm_content.objects o WHERE o.generation=current_setting('rss.content_generation')::uuid AND o.state<>'deleted' AND o.expires<=$1 AND NOT EXISTS(SELECT 1 FROM mdm_content.uploads u WHERE u.id=o.owner AND (u.held_until>$1 OR (u.expires>$1 AND (u.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id)) OR o.location->'value'->'coordinate'='null'::jsonb)))) AND NOT EXISTS(SELECT 1 FROM mdm_content.manifests m WHERE m.state<>'deleted' AND m.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id))) ORDER BY o.id LIMIT 128 FOR UPDATE OF o")
   .bind(now).fetch_all(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        for row in &rows {
            let id: Uuid = row
                .try_get("id")
                .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
            sqlx::query("UPDATE mdm_content.objects SET state='deleting' WHERE generation=current_setting('rss.content_generation')::uuid AND id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
        }
        commit(tx).await?;
        for row in rows {
            self.check_deadline(deadline)?;
            let id: Uuid = row
                .try_get("id")
                .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
            let content = decode(
                row.try_get("content")
                    .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?,
            )?;
            let mut location = crate::location::Location::open(
                &self.protection,
                self.tenant,
                self.generation,
                id,
                content,
                row.try_get("location").map_err(|_| storage())?,
            )?;
            let coordinate = match location.coordinate.clone() {
                Some(c) => Some(c),
                None => {
                    self.backend
                        .recover(&location.intent, content, deadline)
                        .await?
                }
            };
            if let Some(c) = coordinate {
                // Save recovered exact versions before deleting; an ambiguous delete can be retried safely.
                location.coordinate = Some(c.clone());
                let mut tx = self.tx().await?;
                sqlx::query("UPDATE mdm_content.objects SET location=$2 WHERE id=$1 AND generation=current_setting('rss.content_generation')::uuid")
                    .bind(id)
                    .bind(location.seal(&self.protection,self.tenant)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
                commit(tx).await?;
                if self.backend.delete(&c, deadline, admission.clone()).await? {
                    let mut tx = self.tx().await?;
                    sqlx::query("UPDATE mdm_content.objects SET state='deleted' WHERE generation=current_setting('rss.content_generation')::uuid AND id=$1")
                        .bind(id)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
                    commit(tx).await?;
                }
            }
            // Unresolved recovery is never evidence that a write did not happen.
        }
        let mut tx = self.tx().await?;
        sqlx::query("DELETE FROM mdm_content.uploads u WHERE u.expires<=$1 AND u.held_until<=$1 AND (u.epoch IS NULL OR (u.document->'value'->'upload'->>'offset')::bigint<(u.document->'value'->'upload'->'binding'->>'length')::bigint) AND NOT EXISTS(SELECT 1 FROM mdm_content.objects o WHERE o.generation=current_setting('rss.content_generation')::uuid AND o.owner=u.id AND o.state<>'deleted' AND NOT EXISTS(SELECT 1 FROM mdm_content.manifests m WHERE m.state<>'deleted' AND m.document->'value'->'pieces' @> jsonb_build_array(jsonb_build_object('id',o.id))))").bind(now).execute(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        commit(tx).await
    }
    async fn garbage_in(&self, now: i64) -> Result<Vec<Garbage>, Error> {
        if now < 0 {
            return Err(Error::Malformed);
        }
        let admission = self.admit(crate::gate::Kind::Mutation).await?;
        self.clean_orphans(now, admission.clone()).await?;
        let mut tx = self.tx().await?;
        let rows=sqlx::query("SELECT class,sha256,length,document FROM mdm_content.manifests WHERE ((state='ready' AND expires<=$1) OR state='deleting') AND NOT EXISTS(SELECT 1 FROM mdm_content.pins p WHERE p.class=mdm_content.manifests.class AND p.sha256=mdm_content.manifests.sha256 AND p.length=mdm_content.manifests.length AND p.expires>extract(epoch FROM clock_timestamp())) ORDER BY class,sha256 LIMIT 128").bind(now).fetch_all(&mut *tx).await.map_err(|e|journal::pg_error(concat!(file!(), ":", line!()),e))?;
        let mut out = Vec::new();
        for row in rows {
            let c: String = row
                .try_get("class")
                .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?;
            let c: StorageClass = decode(serde_json::json!(c))?;
            let length = row
                .try_get::<i64, _>("length")
                .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?
                as u64;
            let digest: [u8; 32] = row
                .try_get::<Vec<u8>, _>("sha256")
                .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?
                .try_into()
                .map_err(|_| invariant())?;
            let a = Artifact::new(
                rss_mdm_resource::Id::new("gc").map_err(|_| invariant())?,
                length,
                rss_mdm_resource::Digest::from_bytes(digest),
            )
            .map_err(|_| invariant())?;
            out.push(Garbage {
                store: self.clone(),
                manifest: self.unsign(
                    &self.manifest_key(c, &a),
                    row.try_get("document")
                        .map_err(|e| journal::pg_error(concat!(file!(), ":", line!()), e))?,
                )?,
                digest,
                class: c,
                length,
                _admission: admission.clone(),
            });
        }
        commit(tx).await?;
        Ok(out)
    }
}

impl Store {
    pub async fn garbage(&self, now: i64) -> Result<Vec<Garbage>, Error> {
        self.current().await?.garbage_in(now).await
    }
}
