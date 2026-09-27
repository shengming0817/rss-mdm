use crate::{
    storage::{data, stored_shape},
    store::input,
    *,
};
use rss_transactional_messaging_postgres::PgTransaction;
use sqlx::Row;
impl GroupStore {
    pub(crate) async fn delta_difference_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        build: &MemberBuild,
        previous: Option<OperationId>,
    ) -> InTransaction<DifferenceStep> {
        let tenant = self.tenant.to_string();
        let after = build.difference_cursor.clone();
        let rows=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("SELECT object_id,matched FROM mdm_group.member_rows WHERE tenant_id=$1::uuid AND run_id=$2::uuid AND object_id>coalesce($3,'') COLLATE \"C\" ORDER BY object_id LIMIT 1000").bind(tenant).bind(id.to_string()).bind(after).fetch_all(c).await
        })).await?;
        let more = rows.len() == 1000;
        let devices = rows
            .iter()
            .map(|r| r.try_get::<String, _>("object_id"))
            .collect::<Result<Vec<_>, _>>()?;
        let old = crate::history::metadata(
            tx,
            previous.ok_or_else(stored_shape)?,
            None,
            Some(devices.clone()),
            1000,
            true,
        )
        .await?
        .into_iter()
        .map(|r| r.try_get::<String, _>("object_id"))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
        let mut changed = Vec::new();
        let mut values = Vec::new();
        for row in rows {
            let device: String = row.try_get("object_id")?;
            let value: bool = row.try_get("matched")?;
            if value != old.contains(&device) {
                changed.push(device);
                values.push(value);
            }
        }
        let added = values.iter().filter(|v| **v).count() as i64;
        let removed = values.len() as i64 - added;
        let tenant = self.tenant.to_string();
        let group = build.request.group.to_string();
        let revision = build.request.base_calculation + 1;
        let last = devices.last().cloned();
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.member_changes(tenant_id,run_id,object_id,group_id,revision,added) SELECT $1::uuid,$2::uuid,d,$3::uuid,$4,v FROM unnest($5::text[],$6::boolean[]) a(d,v)").bind(&tenant).bind(id.to_string()).bind(group).bind(revision).bind(changed).bind(values).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_group.member_runs SET diff_cursor=$3,added=added+$4,removed=removed+$5,phase=$6 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(last).bind(added).bind(removed).bind(if more{"diff"}else{"ready"}).execute(c).await?;Ok(())
        })).await?;
        Ok(Ok(DifferenceStep {
            build: input!(self.build_in(tx, id).await?),
            devices,
        }))
    }
    pub(crate) async fn seal_missing_delta_in(
        &self,
        tx: &mut PgTransaction<'_>,
        id: OperationId,
        build: &MemberBuild,
    ) -> InTransaction<()> {
        let Some(devices) = build.request.changed_devices.clone() else {
            return Ok(Ok(()));
        };
        let tenant = self.tenant.to_string();
        let missing=tx.with_connection(move|c|Box::pin(async move {
            sqlx::query_scalar::<_,String>("SELECT d FROM unnest($3::text[]) d WHERE NOT EXISTS(SELECT 1 FROM mdm_group.member_rows r WHERE r.tenant_id=$1::uuid AND r.run_id=$2::uuid AND r.object_id=d) ORDER BY d COLLATE \"C\"").bind(tenant).bind(id.to_string()).bind(devices).fetch_all(c).await
        })).await?;
        if missing.is_empty() {
            return Ok(Ok(()));
        }
        let previous = input!(self.current_member_set_in(tx, build.request.group).await?)
            .ok_or_else(stored_shape)?;
        let prior =
            crate::history::metadata(tx, previous, None, Some(missing.clone()), 1000, false)
                .await?;
        let prior_matches = prior
            .iter()
            .map(|r| r.try_get::<bool, _>("matched"))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|v| *v)
            .count() as i64;
        let new_objects = missing.len() as i64 - prior.len() as i64;
        let count = missing.len() as i64;
        let mut evidence = Vec::new();
        for device in &missing {
            evidence.push(data(serde_json::to_vec(&DecisionRecord {
                device: device.clone(),
                origin: DecisionOrigin::Rule,
                decision: DecisionValue::NoMatch,
                explanations: vec![],
                provenance: vec![],
            }))?);
        }
        let hashes = evidence
            .iter()
            .map(|v| crate::storage::digest(v))
            .collect::<Vec<_>>();
        let tenant = self.tenant.to_string();
        tx.with_connection(move|c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_group.member_rows SELECT $1::uuid,$2::uuid,d,false,e,h FROM unnest($3::text[],$4::bytea[],$5::bytea[]) a(d,e,h)").bind(&tenant).bind(id.to_string()).bind(missing).bind(evidence).bind(hashes).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_group.member_runs SET object_count=object_count+$3,member_count=member_count-$4,processed_count=processed_count+$5 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(id.to_string()).bind(new_objects).bind(prior_matches).bind(count).execute(c).await?;Ok(())
        })).await?;
        Ok(Ok(()))
    }
}
