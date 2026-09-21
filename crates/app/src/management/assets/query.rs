use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_mdm_group_postgres::core as g;
use rss_mdm_inventory::State;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    fingerprint: String,
    last: String,
}
impl Management {
    pub(super) fn validate_query(&self, q: &Query) -> Result<()> {
        if q.limit == 0
            || q.limit > 100
            || q.select.len() > FieldKey::ALL.len()
            || q.select.iter().collect::<BTreeSet<_>>().len() != q.select.len()
        {
            return Err(Error::Malformed.into());
        }
        if let Some(c) = &q.criteria {
            rule(self.tenant, Uuid::nil(), c)?;
        }
        if q.cursor.as_ref().is_some_and(|s| s.len() > 4096) {
            return Err(Error::Malformed.into());
        }
        Ok(())
    }
    pub(super) async fn asset_query(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ReadScope,
        q: &Query,
        at: Timepoint,
    ) -> Result<Response> {
        self.validate_query(q)?;
        let devices = self.load_assets(tx, scope).await?;
        let snapshot = criteria::snapshot(self.tenant, &devices)?;
        let decisions = if let Some(c) = &q.criteria {
            input(rule(self.tenant, Uuid::nil(), c)?.evaluate(&snapshot, at))?
                .objects
                .into_iter()
                .map(|o| (o.key.id().to_owned(), o.decision))
                .collect::<BTreeMap<_, _>>()
        } else {
            devices
                .iter()
                .map(|d| (d.device.clone(), g::Decision::Match))
                .collect()
        };
        let unknown = decisions
            .values()
            .filter(|d| **d == g::Decision::Unknown)
            .count();
        let total = devices.len();
        let mut matches: Vec<_> = devices
            .into_iter()
            .filter(|d| decisions.get(&d.device) == Some(&g::Decision::Match))
            .collect();
        if let Some(sort) = &q.sort {
            matches.sort_by(|a, b| compare(a, b, sort).then_with(|| a.device.cmp(&b.device)));
        }
        let mut definition = q.clone();
        definition.cursor = None;
        let fingerprint = digest(&(
            self.tenant.to_string(),
            scope,
            &definition,
            &snapshot.version,
        ))?;
        let start = if let Some(token) = &q.cursor {
            let bytes = input(URL_SAFE_NO_PAD.decode(token))?;
            if bytes.len() < 32 {
                return Err(Error::Conflict.into());
            }
            let (payload, signature) = bytes.split_at(bytes.len() - 32);
            ring::hmac::verify(&self.asset_cursor_key, payload, signature)
                .map_err(|_| Error::Conflict)?;
            let cursor: Cursor = serde_json::from_slice(payload).map_err(|_| Error::Conflict)?;
            if cursor.fingerprint != fingerprint {
                return Err(Error::Conflict.into());
            }
            matches
                .iter()
                .position(|d| d.device == cursor.last)
                .ok_or(Error::Conflict)?
                + 1
        } else {
            0
        };
        let mut summary = Summary {
            matched: matches.len(),
            unknown,
            total,
            os_versions: BTreeMap::new(),
            channels: BTreeMap::new(),
            states: BTreeMap::new(),
        };
        for device in &matches {
            for channel in &device.channels {
                *summary.channels.entry(channel.clone()).or_default() += 1;
            }
            if let State::Known(Scalar::String(os)) = &device.fields[&FieldKey::OsVersion].state {
                *summary.os_versions.entry(os.clone()).or_default() += 1;
            }
            for fact in device.fields.values() {
                *summary
                    .states
                    .entry(state_name(&fact.state).into())
                    .or_default() += 1;
            }
        }
        let more = start + q.limit < matches.len();
        let mut items: Vec<_> = matches.into_iter().skip(start).take(q.limit).collect();
        let next_cursor = if more {
            let mut payload = input(serde_json::to_vec(&Cursor {
                fingerprint,
                last: items.last().ok_or(Error::Malformed)?.device.clone(),
            }))?;
            let signature = ring::hmac::sign(&self.asset_cursor_key, &payload);
            payload.extend(signature.as_ref());
            Some(URL_SAFE_NO_PAD.encode(payload))
        } else {
            None
        };
        if !q.select.is_empty() {
            for device in &mut items {
                device.fields.retain(|f, _| q.select.contains(f));
                device.revisions.retain(|f, _| q.select.contains(f));
            }
        }
        Ok(Response::Page {
            items,
            next_cursor,
            snapshot: snapshot.version,
            summary,
        })
    }
}
fn compare(a: &DeviceView, b: &DeviceView, sort: &Sort) -> std::cmp::Ordering {
    let value = |d: &DeviceView| match &d.fields[&sort.field].state {
        State::Known(v) => Some(v.clone()),
        _ => None,
    };
    match (value(a), value(b)) {
        (Some(a), Some(b)) => {
            let order = a.cmp(&b);
            if sort.descending {
                order.reverse()
            } else {
                order
            }
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}
fn state_name(s: &State) -> &'static str {
    match s {
        State::Known(_) => "known",
        State::Null => "null",
        State::Missing => "missing",
        State::Deleted => "deleted",
        State::Conflict => "conflict",
        State::Unsupported => "unsupported",
    }
}
