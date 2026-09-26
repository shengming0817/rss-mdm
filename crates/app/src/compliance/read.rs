use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_compliance::{Current, Status};
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCursor {
    tenant: String,
    device: String,
    subject: String,
    from: Option<i64>,
    until: Option<i64>,
    after: Uuid,
}

impl Compliance {
    async fn device(&self, tx: &mut PgTransaction<'_>, device: &str) -> Result<()> {
        let t = self.tenant().to_string();
        let d = device.to_owned();
        if !tx
            .with_connection(move |c| {
                Box::pin(async move { crate::device::read::exists(c, t, d).await })
            })
            .await?
        {
            return Err(Error::NotFound.into());
        }
        Ok(())
    }
    pub(super) async fn current(&self, tx: &mut PgTransaction<'_>, device: &str) -> Result<Value> {
        self.device(tx, device).await?;
        let t = self.tenant();
        // Serialize with ingress while checking heads so a response has one linearization point.
        tx.with_connection(move |c| {
            Box::pin(async move { rss_mdm_inventory_postgres::lock_watermark_in(c, t).await })
        })
        .await?;
        let rules = tx
            .with_connection(move |c| Box::pin(async move { pg::rules(c, t, None, 101).await }))
            .await?;
        if rules.len() > 100 {
            return Err(Error::Unavailable(Failure::ComplianceStorage).into());
        }
        let mut items = Vec::new();
        let mut statuses = Vec::new();
        for rule in rules.iter().filter(|r| r.enabled) {
            let mut previous = None;
            let mut current = None;
            if let Some(task) = rule.current_run {
                let d = device.to_owned();
                let value = tx
                    .with_connection(move |c| {
                        Box::pin(async move { pg::result_at(c, t, task, &d).await })
                    })
                    .await?;
                let (job, done, failure, _, _) = crate::automation::jobs::read_in(tx, task).await?;
                if let crate::automation::JobInput::Compliance { input } = job {
                    if done
                        && failure.is_none()
                        && rule.desired == Some(task)
                        && self.fresh(tx, rule, &input).await?
                    {
                        current = value.clone();
                    }
                } else {
                    return Err(Error::Unavailable(Failure::ComplianceStorage).into());
                }
                previous = value;
            }
            let status = match &current {
                Some(v) => Current::from(stored(serde_json::from_value::<Status>(
                    v["status"].clone(),
                ))?),
                None => Current::Pending,
            };
            statuses.push(status);
            items.push(json!({"ruleId":rule.id,"ruleVersion":rule.revision,"status":status,"current":current,"previous":if status==Current::Pending{previous}else{None}}));
        }
        Ok(
            json!({"device":device,"status":rss_mdm_compliance::aggregate(statuses),"reason":if items.is_empty(){Some("no_rules")}else{None},"rules":items}),
        )
    }
    pub(super) async fn history(
        &self,
        tx: &mut PgTransaction<'_>,
        device: &str,
        subject: &str,
        page: &HistoryPage,
    ) -> Result<Value> {
        self.device(tx, device).await?;
        let limit = page.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) || page.from.zip(page.until).is_some_and(|(a, b)| a > b) {
            return Err(Error::Malformed.into());
        }
        let t = self.tenant().to_string();
        let secret: Vec<u8> = tx
            .with_connection(move |c| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT secret FROM mdm_flow.cursor_keys WHERE tenant_id=$1::uuid",
                    )
                    .bind(t)
                    .fetch_one(c)
                    .await
                })
            })
            .await?;
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret);
        let cursor = if let Some(token) = &page.cursor {
            if token.len() > 4096 {
                return Err(Error::Malformed.into());
            }
            let bytes = checked_input(URL_SAFE_NO_PAD.decode(token))?;
            if bytes.len() <= 32 {
                return Err(Error::Malformed.into());
            }
            let (payload, sig) = bytes.split_at(bytes.len() - 32);
            ring::hmac::verify(&key, payload, sig).map_err(|_| Error::Malformed)?;
            let c: HistoryCursor = checked_input(serde_json::from_slice(payload))?;
            if c.tenant != self.tenant().to_string()
                || c.device != device
                || c.subject != subject
                || c.from != page.from
                || c.until != page.until
            {
                return Err(Error::Malformed.into());
            }
            Some(c.after)
        } else {
            None
        };
        let t = self.tenant().to_string();
        let d = device.to_owned();
        let from = page.from;
        let until = page.until;
        let rows=tx.with_connection(move|c|Box::pin(async move{
   if let Some(id)=cursor {let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_compliance.results WHERE tenant_id=$1::uuid AND device=$2 AND task=$3::uuid AND ($4::bigint IS NULL OR evaluated_at>=$4) AND ($5::bigint IS NULL OR evaluated_at<=$5))").bind(&t).bind(&d).bind(id.to_string()).bind(from).bind(until).fetch_one(&mut *c).await?;if !exists{return Err(sqlx::Error::Protocol("invalid compliance history anchor".into()))}}
   sqlx::query("SELECT e.task::text,e.document::text,j.completed,j.failure FROM mdm_compliance.results e JOIN mdm_automation.automation_jobs j ON (j.tenant_id,j.id)=(e.tenant_id,e.task) WHERE e.tenant_id=$1::uuid AND e.device=$2 AND j.completed AND ($3::bigint IS NULL OR e.evaluated_at>=$3) AND ($4::bigint IS NULL OR e.evaluated_at<=$4) AND ($5::uuid IS NULL OR (e.evaluated_at,e.task)<(SELECT evaluated_at,task FROM mdm_compliance.results WHERE tenant_id=$1::uuid AND device=$2 AND task=$5::uuid)) ORDER BY e.evaluated_at DESC,e.task DESC LIMIT $6")
    .bind(t).bind(d).bind(from).bind(until).bind(cursor.map(|v|v.to_string())).bind((limit+1) as i64).fetch_all(c).await
  })).await?;
        let more = rows.len() > limit;
        let mut items = Vec::new();
        let mut next = None;
        for r in rows.into_iter().take(limit) {
            let task: String = r.try_get("task")?;
            let failure: Option<String> = r.try_get("failure")?;
            let mut value: Value = stored(serde_json::from_str(r.try_get("document")?))?;
            value["task"] = json!(task);
            value["disposition"] = json!(match failure.as_deref() {
                None => "published",
                Some("superseded") => "superseded",
                Some(_) => "failed",
            });
            items.push(value);
            next = Some(task);
        }
        let next = if more {
            if let Some(next) = next {
                let c = HistoryCursor {
                    tenant: self.tenant().to_string(),
                    device: device.into(),
                    subject: subject.into(),
                    from: page.from,
                    until: page.until,
                    after: stored(Uuid::parse_str(&next))?,
                };
                let mut bytes = json_bytes(&c)?;
                let tag = ring::hmac::sign(&key, &bytes);
                bytes.extend_from_slice(tag.as_ref());
                Some(URL_SAFE_NO_PAD.encode(bytes))
            } else {
                None
            }
        } else {
            None
        };
        Ok(json!({"items":items,"nextCursor":next}))
    }
}

fn json_bytes(v: &impl serde::Serialize) -> Result<Vec<u8>> {
    checked_input(serde_json::to_vec(v))
}
