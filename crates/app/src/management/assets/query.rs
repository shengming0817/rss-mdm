//! Asset queries are immutable asynchronous results, prepared under RSS claims.
use super::super::automation::JobInput;
use super::*;
use rss_mdm_group_postgres::core as g;
use rss_mdm_inventory::State;
impl Management {
    pub(super) fn validate_query(&self, q: &Query) -> Result<()> {
        if q.select.len() > FieldKey::ALL.len()
            || q.select.iter().collect::<BTreeSet<_>>().len() != q.select.len()
        {
            return Err(Error::Malformed.into());
        }
        if let Some(criteria) = &q.criteria {
            rule(self.tenant, Uuid::nil(), criteria)?;
        }
        Ok(())
    }
    pub(super) async fn asset_query(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        scope: &ReadScope,
        q: &Query,
        at: Timepoint,
    ) -> Result<Response> {
        self.validate_query(q)?;
        let tenant = self.tenant;
        let watermark = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    rss_mdm_inventory_postgres::watermark_in(c, tenant)
                        .await
                        .map_err(|_| sqlx::Error::Protocol("asset watermark unavailable".into()))
                })
            })
            .await?;
        self.enqueue_job_in(
            tx,
            task,
            &JobInput::AssetQuery {
                query: q.clone(),
                scope: scope.clone(),
                watermark,
                as_of: at.unix_seconds(),
            },
        )
        .await?;
        let tenant = self.tenant.to_string();
        tx.with_connection(move |c|Box::pin(async move {
            sqlx::query("INSERT INTO mdm_management.asset_query_runs(tenant_id,id) VALUES($1::uuid,$2::uuid)").bind(tenant).bind(task.to_string()).execute(c).await?;Ok(())
        })).await?;
        Ok(Response::Accepted {
            task,
            status_url: format!("/api/v2/device-queries/{task}"),
        })
    }
    pub(in crate::management) async fn advance_asset_query_in(
        &self,
        tx: &mut PgTransaction<'_>,
        task: Uuid,
        job: &JobInput,
        after: Option<String>,
    ) -> Result<()> {
        let JobInput::AssetQuery {
            query: q,
            scope,
            watermark,
            as_of,
        } = job
        else {
            return Err(Error::Unavailable(Failure::ManagementStorage).into());
        };
        let watermark = *watermark;
        let at = input(Timepoint::try_from(*as_of))?;
        let rule = q
            .criteria
            .as_ref()
            .map(|c| rule(self.tenant, task, c))
            .transpose()?;
        let mut limit = 128;
        let (page, decisions) = loop {
            let page = match self
                .asset_page_in(tx, watermark, after.clone(), limit, scope)
                .await
            {
                Err(super::super::Fault::Request(Error::Unavailable(
                    Failure::AssetBytesLimit | Failure::AssetSourceLimit,
                ))) if limit > 1 => {
                    limit = (limit / 2).max(1);
                    continue;
                }
                result => result?,
            };
            let snapshot = criteria::page(self.tenant, &page.devices)?;
            let key = after
                .as_ref()
                .map(|s| input(g::ObjectKey::new(self.tenant, s)))
                .transpose()?;
            let decisions = if let Some(rule) = &rule {
                match rule.evaluate_page(
                    &g::PageInput {
                        tenant: self.tenant,
                        id: "assets",
                        version: &format!("assets:{watermark}"),
                        dictionary_version: rss_mdm_inventory::DICTIONARY,
                        coverage: &snapshot.coverage,
                        objects: &snapshot.objects,
                        after: key.as_ref(),
                    },
                    at,
                ) {
                    Ok(result) => result
                        .objects
                        .into_iter()
                        .map(|o| o.decision)
                        .collect::<Vec<_>>(),
                    Err(g::Error::LimitExceeded(_)) if limit > 1 => {
                        limit = (limit / 2).max(1);
                        continue;
                    }
                    Err(g::Error::LimitExceeded(_)) => {
                        return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
                    }
                    Err(_) => return Err(Error::Malformed.into()),
                }
            } else {
                vec![g::Decision::Match; page.devices.len()]
            };
            break (page, decisions);
        };
        let total = page.devices.len() as i64;
        let unknown = decisions
            .iter()
            .filter(|d| **d == g::Decision::Unknown)
            .count() as i64;
        let last = page.devices.last().map(|d| d.device.clone()).or(after);
        let done = page.next.is_none();
        let mut ids = Vec::new();
        let mut keys = Vec::new();
        let mut documents = Vec::new();
        let mut digests = Vec::new();
        let mut facets = BTreeMap::<(&str, String), i64>::new();
        for (mut device, decision) in page.devices.into_iter().zip(decisions) {
            if decision != g::Decision::Match {
                continue;
            }
            for channel in &device.channels {
                *facets.entry(("channels", channel.clone())).or_default() += 1;
            }
            if let State::Known(Scalar::String(os)) = &device.fields[&FieldKey::OsVersion].state {
                *facets.entry(("os_versions", os.clone())).or_default() += 1;
            }
            for field in device.fields.values() {
                *facets
                    .entry(("asset_states", state_name(&field.state).into()))
                    .or_default() += 1;
            }
            let key = q.sort.as_ref().map_or_else(Vec::new, |sort| {
                query_sort::key(
                    device.fields.get(&sort.field).map(|f| &f.state),
                    sort.descending,
                )
            });
            if !q.select.is_empty() {
                device.fields.retain(|f, _| q.select.contains(f));
                device.revisions.retain(|f, _| q.select.contains(f));
            }
            let bytes = input(serde_json::to_vec(&device))?;
            if bytes.len() > 1024 * 1024 {
                return Err(Error::Unavailable(Failure::AssetBytesLimit).into());
            }
            ids.push(device.device);
            keys.push(key);
            digests.push(Sha256::digest(&bytes).to_vec());
            documents.push(bytes);
        }
        let tenant = self.tenant.to_string();
        let matched = ids.len() as i64;
        let mut kinds = Vec::new();
        let mut labels = Vec::new();
        let mut counts = Vec::new();
        for ((kind, label), count) in facets {
            kinds.push(kind.to_owned());
            labels.push(label);
            counts.push(count);
        }
        let accepted=tx.with_connection(move |c|Box::pin(async move {
            let updated=sqlx::query("UPDATE mdm_management.asset_query_runs SET total=total+$3,matched=matched+$4,unknown=unknown+$5 WHERE tenant_id=$1::uuid AND id=$2::uuid AND total+$3<=1000000")
                .bind(&tenant).bind(task.to_string()).bind(total).bind(matched).bind(unknown).execute(&mut *c).await?.rows_affected();
            if updated!=1 {return Ok(false);}
            sqlx::query("INSERT INTO mdm_management.asset_query_results SELECT $1::uuid,$2::uuid,d,k,b,h FROM unnest($3::text[],$4::bytea[],$5::bytea[],$6::bytea[]) AS p(d,k,b,h)")
                .bind(&tenant).bind(task.to_string()).bind(ids).bind(keys).bind(documents).bind(digests).execute(&mut *c).await?;
            sqlx::query("INSERT INTO mdm_management.asset_query_facets SELECT $1::uuid,$2::uuid,k,l,n FROM unnest($3::text[],$4::text[],$5::bigint[]) AS p(k,l,n) ON CONFLICT(tenant_id,run,kind,label) DO UPDATE SET total=mdm_management.asset_query_facets.total+excluded.total")
                .bind(&tenant).bind(task.to_string()).bind(kinds).bind(labels).bind(counts).execute(&mut *c).await?;
            sqlx::query("UPDATE mdm_management.automation_jobs SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(tenant).bind(task.to_string()).bind(last).execute(c).await?;Ok(true)
        })).await?;
        if !accepted {
            return Err(Error::Unavailable(Failure::AssetObjectLimit).into());
        }
        if done {
            self.finish_job_in(tx, task, None).await?;
        }
        Ok(())
    }
}
fn state_name(state: &State) -> &'static str {
    match state {
        State::Known(_) => "known",
        State::Null => "null",
        State::Missing => "missing",
        State::Deleted => "deleted",
        State::Conflict => "conflict",
        State::Unsupported => "unsupported",
    }
}
