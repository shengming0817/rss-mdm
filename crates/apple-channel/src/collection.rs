use crate::{Error, database::db, device::DevicePrincipal};
use rss_mdm_apple_mdm::protocol as wire;
use rss_mdm_inventory_service::collection::{Attempts, store};
use rss_mdm_registration_service::enrollment::store::uuid;
use sqlx::{PgConnection, Row};
use uuid::Uuid;
// Keep transaction, protection, audit sink and authenticated wire evidence explicit.
#[allow(clippy::too_many_arguments)]
pub async fn receive(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    facts: &mut Vec<rss_mdm_audit_integration::Fact>,
    p: &DevicePrincipal,
    id: Uuid,
    status: wire::Status,
    d: &plist::Dictionary,
    bytes: &[u8],
) -> Result<bool, Error> {
    use crate::attempt::{self, Owner, Reception};
    let tenant = p.tenant().to_string();
    let attempt = match attempt::lock(c, protection, p, id, Owner::Collection, bytes).await? {
        None => return Ok(false),
        Some(Reception::Replay) => return Ok(true),
        Some(Reception::Ready(attempt)) => attempt,
    };
    let collection = attempt.collection.ok_or(Error::Malformed)?;
    if !rss_mdm_inventory_service::apple_collection::current(c, &tenant, collection).await? {
        attempt.settle(c, status, false).await?;
        return Ok(true);
    }
    if matches!(
        attempt.phase.as_str(),
        "collect_device" | "collect_security"
    ) {
        let valid = status != wire::Status::Acknowledged
            || if attempt.phase == "collect_device" {
                rss_mdm_apple_mdm::applicability::Context::from_reports(
                    d,
                    None,
                    rss_mdm_apple_mdm::applicability::Channel::Device,
                )
                .is_ok()
            } else {
                crate::collection_context::security_valid(c, protection, p, collection, d).await?
            };
        attempt.settle(c, status, valid).await?;
        if status == wire::Status::Acknowledged && valid {
            facts.extend(prepare_native(c, protection, &tenant, collection).await?);
        } else if status != wire::Status::NotNow {
            let mut run = store::load_on(c, &tenant, collection).await?;
            let template =
                rss_mdm_inventory_service::collection::native::template(c, &tenant, collection)
                    .await?
                    .ok_or(Error::Malformed)?;
            let now =
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(&mut *c)
                    .await
                    .map_err(db)?;
            run.attempts = rss_mdm_inventory_service::collection::native::result(
                &template,
                run.attempts.definition().clone(),
                &serde_json::Value::Null,
                now,
                false,
            )?;
            facts.extend(store::seal(c, &mut run, "complete").await?);
        }
        return Ok(true);
    }
    let native_valid = attempt.valid;
    attempt.settle(c, status, native_valid).await?;
    if status != wire::Status::NotNow {
        let mut run = store::load_on(c, &tenant, id).await?;
        let now = sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
        let template = rss_mdm_inventory_service::collection::native::template(c, &tenant, id)
            .await?
            .ok_or(Error::Malformed)?;
        {
            let normalized = crate::collection_values::normalize(template.spec().adapter, d);
            let valid = normalized.is_ok();
            let value = normalized.unwrap_or(serde_json::Value::Null);
            let success = native_valid
                && valid
                && status == wire::Status::Acknowledged
                && bytes.len() <= template.spec().output_bytes as usize;
            let frozen: serde_json::Value = sqlx::query_scalar(
                "SELECT context FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND id=$2",
            )
            .bind(&tenant)
            .bind(id)
            .fetch_one(&mut *c)
            .await
            .map_err(db)?;
            let context = serde_json::from_value(frozen).map_err(|_| Error::Malformed)?;
            let rights: i32 = sqlx::query_scalar("SELECT access_rights FROM mdm_apple.devices WHERE tenant_id=$1::uuid AND registration=$2")
                .bind(&tenant).bind(p.registration()).fetch_one(&mut *c).await.map_err(db)?;
            let rights = crate::native::rights(rights);
            let target = rss_mdm_apple_mdm::native::Target {
                context: &context,
                access_rights: &rights,
            };
            let root = match template.spec().adapter {
                rss_mdm_resource::NativeAdapter::AppleDeviceInformation => Some("QueryResponses"),
                rss_mdm_resource::NativeAdapter::AppleSecurity => Some("SecurityInfo"),
                _ => None,
            };
            let unsupported = template
                .spec()
                .mappings
                .iter()
                .filter_map(|(field, m)| {
                    let root = root?;
                    rss_mdm_apple_mdm::native::Command::response_field_supported(
                        template.spec().adapter.apple_command()?,
                        &[root, m.query.apple_key()?],
                        &target,
                    )
                    .is_err()
                    .then(|| rss_mdm_inventory::FieldKey::parse(field))
                    .transpose()
                    .ok()
                    .flatten()
                })
                .collect();
            run.attempts = rss_mdm_inventory_service::collection::native::result_with_unsupported(
                &template,
                run.attempts.definition().clone(),
                &value,
                now,
                success,
                &unsupported,
            )?;
            facts.extend(store::seal(c, &mut run, "complete").await?);
            return Ok(true);
        }
    }
    Ok(true)
}
pub async fn send(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    p: &DevicePrincipal,
    user_key: &str,
) -> Result<Vec<u8>, Error> {
    let tenant = p.tenant().to_string();
    let rows=sqlx::query("SELECT id::text,collection,request FROM mdm_apple.attempts WHERE tenant_id=$1::uuid AND registration=$2::uuid AND generation=$3 AND NOT EXISTS(SELECT 1 FROM mdm_commands.action_runs r WHERE r.tenant_id=mdm_apple.attempts.tenant_id AND r.id=mdm_apple.attempts.collection AND r.source_kind='remote_operation') AND user_key=$4 AND phase IN ('collect','collect_device','collect_security') AND state IN ('pending','sent','not_now') AND next_attempt<=clock_timestamp() AND deadline>clock_timestamp() ORDER BY collection_sequence LIMIT 32 FOR UPDATE")
        .bind(&tenant).bind(p.registration().to_string()).bind(p.generation()).bind(user_key).fetch_all(&mut *c).await.map_err(db)?;
    for row in rows {
        let id = uuid(&row, "id")?;
        let collection: Uuid = row.try_get("collection").map_err(db)?;
        if !rss_mdm_inventory_service::apple_collection::current(c, &tenant, collection).await? {
            sqlx::query("UPDATE mdm_apple.attempts SET next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid").bind(&tenant).bind(id.to_string()).execute(&mut *c).await.map_err(db)?;
            crate::notify(c, "apple").await.map_err(db)?;
            continue;
        }
        sqlx::query("UPDATE mdm_apple.attempts SET state='sent',next_attempt=clock_timestamp()+interval '30 seconds' WHERE tenant_id=$1::uuid AND id=$2::uuid")
            .bind(&tenant).bind(id.to_string()).execute(&mut *c).await.map_err(db)?;
        crate::notify(c, "apple").await.map_err(db)?;
        rss_mdm_execution_service::actions::native_collection::sent(c, &tenant, collection).await?;
        let sealed: Vec<u8> = row.try_get("request").map_err(db)?;
        return crate::protection::open(
            protection,
            &tenant,
            p.registration(),
            p.generation(),
            id,
            crate::protection::Part::Request,
            &sealed,
        )
        .map(|v| v.expose().to_vec());
    }
    Ok(Vec::new())
}

pub async fn prepare_native(
    c: &mut PgConnection,
    protection: &rss_mdm_native_protection::Protector,
    tenant: &str,
    id: Uuid,
) -> Result<Vec<rss_mdm_audit_integration::Fact>, Error> {
    use rss_mdm_resource::{NativeAdapter, TemplateScope};
    let template = rss_mdm_inventory_service::collection::native::template(c, tenant, id)
        .await?
        .ok_or(Error::Malformed)?;
    let row=sqlx::query("SELECT c.registration,r.generation,c.sequence,c.deadline::text AS deadline,d.access_rights FROM mdm_access.collection_runs c JOIN mdm_access.registrations r ON(r.tenant_id,r.id)=(c.tenant_id,c.registration) JOIN mdm_apple.devices d ON(d.tenant_id,d.registration)=(r.tenant_id,r.id) WHERE c.tenant_id=$1::uuid AND c.id=$2 AND c.sealed_at IS NULL AND d.state='active'").bind(tenant).bind(id).fetch_one(&mut *c).await.map_err(db)?;
    let required = template
        .spec()
        .adapter
        .apple_rights()
        .ok_or(Error::Malformed)?
        | 1040;
    let user_key = match &template.spec().scope {
        TemplateScope::Device => "",
        TemplateScope::User { identity } => identity.as_str(),
        _ => return Err(Error::Malformed),
    };
    if row.try_get::<i32, _>("access_rights").map_err(db)? & required != required {
        let mut run = store::load_on(c, tenant, id).await?;
        let now: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(db)?;
        let values = run
            .attempts
            .definition()
            .fields()
            .map(|f| {
                (
                    f.key,
                    rss_mdm_inventory::NativeValue::Value(
                        rss_mdm_inventory::CollectedValue::Unsupported,
                    ),
                )
            })
            .collect();
        run.attempts = Attempts::native(run.attempts.definition().clone(), values, now)
            .map_err(|_| Error::Malformed)?;
        return Ok(store::seal(c, &mut run, "complete")
            .await?
            .into_iter()
            .collect());
    }
    let Some(context) = crate::collection_context::prepare(
        c,
        protection,
        tenant,
        id,
        row.try_get("registration").map_err(db)?,
        row.try_get("generation").map_err(db)?,
        row.try_get("sequence").map_err(db)?,
        &row.try_get::<String, _>("deadline").map_err(db)?,
        user_key,
    )
    .await?
    else {
        return Ok(Vec::new());
    };
    let rights = crate::native::rights(row.try_get("access_rights").map_err(db)?);
    let target = rss_mdm_apple_mdm::native::Target {
        context: &context,
        access_rights: &rights,
    };
    let command = match template.spec().adapter {
        NativeAdapter::AppleDeviceInformation => wire::dictionary([
            ("RequestType", "DeviceInformation".into()),
            (
                "Queries",
                plist::Value::Array(
                    template
                        .spec()
                        .mappings
                        .values()
                        .map(|m| {
                            m.query
                                .apple_key()
                                .expect("validated Apple query")
                                .to_owned()
                        })
                        .filter(|query| {
                            rss_mdm_apple_mdm::native::Command::response_field_supported(
                                "DeviceInformation",
                                &["QueryResponses", query],
                                &target,
                            )
                            .is_ok()
                        })
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .map(plist::Value::String)
                        .collect(),
                ),
            ),
        ]),
        NativeAdapter::AppleInstalledApplications => {
            wire::dictionary([("RequestType", "InstalledApplicationList".into())])
        }
        NativeAdapter::AppleSecurity | NativeAdapter::AppleUsers => wire::dictionary([(
            "RequestType",
            template
                .spec()
                .adapter
                .apple_command()
                .ok_or(Error::Malformed)?
                .into(),
        )]),
        NativeAdapter::AppleProfiles | NativeAdapter::AppleCertificates => wire::dictionary([
            (
                "RequestType",
                template
                    .spec()
                    .adapter
                    .apple_command()
                    .ok_or(Error::Malformed)?
                    .into(),
            ),
            ("ManagedOnly", true.into()),
        ]),
        _ => return Err(Error::Malformed),
    };
    let mut fields = command.clone();
    fields.remove("RequestType");
    let input = rss_mdm_apple_mdm::native::input::CommandInput {
        request_type: template
            .spec()
            .adapter
            .apple_command()
            .ok_or(Error::Malformed)?
            .into(),
        fields: rss_mdm_apple_mdm::native::input::Fields::from_plist(&fields)
            .map_err(|_| Error::Malformed)?,
    };
    let rights = crate::native::rights(row.try_get("access_rights").map_err(db)?);
    let target = rss_mdm_apple_mdm::native::Target {
        context: &context,
        access_rights: &rights,
    };
    let environment = rss_mdm_resource::CollectionEnvironment {
        os_version: context.version.map(String::from),
        ..Default::default()
    };
    let applicability = template.spec().applicability.allows(
        &environment,
        "primary",
        &[template.spec().adapter.capability().into()].into(),
    );
    let command = match input.compile(&target).and_then(|command| {
        if applicability {
            Ok(command)
        } else {
            Err(rss_mdm_apple_mdm::native::Error::Unsupported)
        }
    }) {
        Ok(command) => command,
        Err(_) => {
            let mut run = store::load_on(c, tenant, id).await?;
            let now =
                sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
                    .fetch_one(&mut *c)
                    .await
                    .map_err(db)?;
            let values = run
                .attempts
                .definition()
                .fields()
                .map(|f| {
                    (
                        f.key,
                        rss_mdm_inventory::NativeValue::Value(
                            rss_mdm_inventory::CollectedValue::Unsupported,
                        ),
                    )
                })
                .collect();
            run.attempts = Attempts::native(run.attempts.definition().clone(), values, now)
                .map_err(|_| Error::Malformed)?;
            return Ok(store::seal(c, &mut run, "complete")
                .await?
                .into_iter()
                .collect());
        }
    };
    let request = command.encode(id).map_err(|_| Error::Malformed)?;
    let request = crate::protection::seal(
        protection,
        tenant,
        row.try_get("registration").map_err(db)?,
        row.try_get("generation").map_err(db)?,
        id,
        crate::protection::Part::Request,
        &request,
    )?;
    sqlx::query("INSERT INTO mdm_apple.attempts(tenant_id,id,registration,generation,collection,phase,request,state,collection_sequence,deadline,user_key,context) VALUES($1::uuid,$2,$3,$4,$2,'collect',$5,'pending',$6,$7::text::timestamptz,$8,$9)")
        .bind(tenant).bind(id).bind(row.try_get::<Uuid,_>("registration").map_err(db)?).bind(row.try_get::<i64,_>("generation").map_err(db)?).bind(request).bind(row.try_get::<i64,_>("sequence").map_err(db)?).bind(row.try_get::<String,_>("deadline").map_err(db)?).bind(user_key).bind(serde_json::to_value(context).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
    crate::notify(c, "apple").await.map_err(db)?;
    Ok(Vec::new())
}
