//! Derived membership publication is distinct-set insertion, never summing partial counts.
use super::*;
use rss_mdm_inventory::Scalar;
use sqlx::Row;
impl AssetService {
    pub(super) async fn software_evidence(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        job: &Job,
        progress: &mut ObjectProgress,
        array: &ArrayInput,
        ordinal: usize,
        value: Scalar,
    ) -> Result<()> {
        let item = evidence::item(array.source, array.platform, &value)?;
        let matched =
            evidence::resolve(&job.configuration, &job.predicates, array, ordinal, &item)?;
        progress.coverage_unknown |=
            matches!(matched.identity, Identity::Conflict { .. }) || !item.installation_known;
        progress.unknown |= progress.coverage_unknown;
        let confirmed = array.confirmed && item.installed;
        let selected = progress.matched
            && evidence::selected(
                &job.query.software,
                job.software_predicate.as_ref(),
                &matched,
                &item,
            )?;
        let mut dimensions = progress.dimensions.clone();
        for (dimension, field) in [
            (Dimension::Version, "version"),
            (Dimension::Component, "component"),
            (Dimension::Publisher, "publisher"),
            (Dimension::Platform, "platform"),
        ] {
            dimensions.insert(
                dimension,
                item.fields.get(field).cloned().into_iter().collect(),
            );
        }
        let evidence = InstallationEvidence {
            endpoint: array.endpoint.clone(),
            source: array.source,
            evidence: array.evidence.clone(),
            array_version: array.value.version.clone(),
            ordinal,
            value,
            rules: matched.rules,
            confirmed,
        };
        let id = digest(&(
            &evidence.endpoint,
            evidence.source,
            &evidence.evidence,
            &evidence.array_version,
            ordinal,
        ))?;
        let document = checked_input(serde_json::to_value(evidence))?;
        let identity = checked_input(serde_json::to_value(matched.identity))?;
        let dimensions = checked_input(serde_json::to_value(dimensions))?;
        let bytes = document.to_string().len()
            + identity.to_string().len()
            + dimensions.to_string().len()
            + 1024;
        if identity.to_string().len() > 65536
            || document.to_string().len() > 1024 * 1024
            || dimensions.to_string().len() > 65536
        {
            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
        }
        let tenant = self.tenant.to_string();
        let object = progress.object.object.key();
        let admitted = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_assets.software_buckets(tenant_id,run,id,standard,identity) VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
                .bind(&tenant).bind(task).bind(&matched.key).bind(matched.standard).bind(identity).execute(&mut *c).await?;
            let added = sqlx::query("INSERT INTO mdm_assets.software_evidence(tenant_id,run,bucket,object,id,selected,confirmed,document,dimensions) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING")
                .bind(&tenant).bind(task).bind(matched.key).bind(object).bind(id).bind(selected).bind(confirmed).bind(document).bind(dimensions).execute(&mut *c).await?.rows_affected();
            if added == 0 { return Ok(true); }
            Ok(sqlx::query("UPDATE mdm_assets.software_progress SET items=items+1,bytes=bytes+$3 WHERE tenant_id=$1::uuid AND run=$2 AND items<10000000 AND bytes+$3<=1073741824")
                .bind(tenant).bind(task).bind(bytes as i64).execute(c).await?.rows_affected() == 1)
        })).await?;
        if !admitted {
            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
        }
        Ok(())
    }

    pub(super) async fn publish_software_object(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        job: &Job,
        progress: &mut ObjectProgress,
    ) -> Result<bool> {
        let object = progress.object.object.key();
        let result = ObjectResult {
            matched: progress.matched,
            unknown: progress.unknown,
            object: progress.object.object.clone(),
            groups: progress.groups.clone(),
            quality: progress.quality.clone(),
        };
        let document = checked_input(serde_json::to_value(result))?;
        let bytes = document.to_string().len();
        if bytes > 16 * 1024 * 1024 {
            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
        }
        let tenant = self.tenant.to_string();
        let key = object.clone();
        let admitted = tx.with_connection(move |c| Box::pin(async move {
            let added = sqlx::query("INSERT INTO mdm_assets.software_objects(tenant_id,run,object,document) VALUES($1::uuid,$2,$3,$4) ON CONFLICT DO NOTHING")
                .bind(&tenant).bind(task).bind(key).bind(document).execute(&mut *c).await?.rows_affected();
            if added == 0 { return Ok(true); }
            Ok(sqlx::query("UPDATE mdm_assets.software_progress SET bytes=bytes+$3 WHERE tenant_id=$1::uuid AND run=$2 AND bytes+$3<=1073741824")
                .bind(tenant).bind(task).bind(bytes as i64).execute(c).await?.rows_affected() == 1)
        })).await?;
        if !admitted {
            return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
        }
        let tenant = self.tenant.to_string();
        let key = object.clone();
        let after = progress.published_after.clone();
        let rows = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT e.bucket,b.standard,bool_or(e.selected) AS selected FROM mdm_assets.software_evidence e JOIN mdm_assets.software_buckets b ON(b.tenant_id,b.run,b.id)=(e.tenant_id,e.run,e.bucket) WHERE e.tenant_id=$1::uuid AND e.run=$2 AND e.object=$3 AND e.confirmed AND e.bucket COLLATE \"C\">coalesce($4,'') COLLATE \"C\" GROUP BY e.bucket,b.standard ORDER BY e.bucket COLLATE \"C\" LIMIT 129")
                .bind(tenant).bind(task).bind(key).bind(after).fetch_all(c).await
        })).await?;
        let more = rows.len() > 128;
        let mut members = Vec::new();
        for row in rows.into_iter().take(128) {
            let bucket: String = row.try_get("bucket")?;
            let standard: Option<Uuid> = row.try_get("standard")?;
            let decision = standard
                .and_then(|id| job.configuration.standards.iter().find(|r| r.id == id))
                .and_then(|r| r.definition.as_ref())
                .map(|s| filter::compliance(s.assessments.get(job.query.context), &progress.groups))
                .unwrap_or(Compliance::Disabled);
            let compliance = stored(serde_json::to_value(decision))?;
            members.push(serde_json::json!({"bucket":bucket,"selected":row.try_get::<bool,_>("selected")?,"compliance":compliance}));
            progress.published_after = Some(bucket);
        }
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("INSERT INTO mdm_assets.software_members(tenant_id,run,bucket,object,selected,compliance) SELECT $1::uuid,$2,x.bucket,$3,x.selected,x.compliance FROM jsonb_to_recordset($4) AS x(bucket text,selected boolean,compliance text) ON CONFLICT(tenant_id,run,bucket,object) DO NOTHING")
                .bind(tenant).bind(task).bind(object).bind(serde_json::json!(members)).execute(c).await?; Ok(())
        })).await?;
        if more {
            return Ok(false);
        }
        let tenant = self.tenant.to_string();
        let matched = i64::from(progress.matched);
        let unknown = i64::from(progress.unknown);
        let uncertain = i64::from(progress.coverage_unknown);
        let admitted = tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("UPDATE mdm_assets.software_progress SET uncertain=uncertain+$3 WHERE tenant_id=$1::uuid AND run=$2").bind(&tenant).bind(task).bind(uncertain).execute(&mut *c).await?;
            Ok(sqlx::query("UPDATE mdm_assets.asset_query_runs SET total=total+1,matched=matched+$3,unknown=unknown+$4 WHERE tenant_id=$1::uuid AND id=$2 AND total<1000000")
                .bind(tenant).bind(task).bind(matched).bind(unknown).execute(c).await?.rows_affected() == 1)
        })).await?;
        if !admitted {
            return Err(Error::Unavailable(Failure::AssetObjectLimit).into());
        }
        Ok(true)
    }
}
