use super::*;
use crate::account_enrollment::management::operation as operation_id;
use axum::{
    Extension, Json,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::IntoResponse,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rss_mdm_audit_integration::{Fact, RequestAudit};
use rss_mdm_authorization_service::{
    Permission,
    context::{AuthorizedPrincipal, RequestAuth},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configure {
    expected_revision: i64,
    enabled: bool,
    server_uuid: Uuid,
    org_id: String,
    rotate_key: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Token {
        #[serde(rename = "expectedRevision")]
        expected_revision: i64,
        p7m: Zeroizing<String>,
    },
    Sync {
        full: bool,
    },
    Profile {
        id: Uuid,
        #[serde(rename = "expectedRevision")]
        expected_revision: i64,
        configuration: Setup,
    },
    Assign {
        profile: Uuid,
        revision: i64,
        devices: Vec<String>,
    },
    Clear {
        devices: Vec<String>,
    },
    Reconcile {
        operation: Uuid,
    },
    Resolve {
        operation: Uuid,
        #[serde(rename = "remoteProfile")]
        remote_profile: Uuid,
    },
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Setup {
    pub name: String,
    pub mandatory: bool,
    pub removable: bool,
    pub skip: Vec<String>,
}
impl Setup {
    pub(super) fn validate(&self) -> Result<(), Error> {
        const PANES: &[&str] = &[
            "AppleID",
            "Appearance",
            "AppStore",
            "Biometric",
            "Diagnostics",
            "FileVault",
            "EnableLockdownMode",
            "iCloudDiagnostics",
            "iCloudStorage",
            "Location",
            "Payment",
            "Passcode",
            "Privacy",
            "Restore",
            "ScreenTime",
            "Siri",
            "TOS",
            "Welcome",
            "TermsOfAddress",
            "UnlockWithWatch",
            "Accessibility",
            "Intelligence",
        ];
        if self.name.is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
            || (!self.removable && !self.mandatory)
            || self.skip.len() > PANES.len()
            || self.skip.iter().any(|p| !PANES.contains(&p.as_str()))
            || self
                .skip
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.skip.len()
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub(super) fn apple(&self, url: String) -> Value {
        json!({"profile_name":self.name,"url":url,"is_mandatory":self.mandatory,"is_mdm_removable":self.removable,"is_supervised":true,"skip_setup_items":self.skip,"await_device_configured":false,"auto_advance_setup":false})
    }
}
fn proof(auth: &RequestAuth, write: bool) -> Result<&AuthorizedPrincipal, Error> {
    auth.proof.manage(if write {
        Permission::RegistrationConfigurationWrite
    } else {
        Permission::RegistrationConfigurationRead
    })?;
    Ok(&auth.proof)
}
pub async fn configure(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    Json(input): Json<Configure>,
) -> Result<Json<Value>, Error> {
    if id.is_nil()
        || input.server_uuid.is_nil()
        || input.expected_revision < 0
        || input.expected_revision == i64::MAX
        || input.org_id.is_empty()
        || input.org_id.len() > 256
        || input.org_id.chars().any(char::is_control)
    {
        return Err(Error::Malformed);
    }
    let p = proof(&auth, true)?;
    let key = tokio::task::spawn_blocking({
        let time = now(&app)?;
        move || rss_mdm_certificate::apple::ade::generate_key(time)
    })
    .await
    .map_err(|_| Error::Conflict)??;
    let op = operation_id(&headers)?;
    p.bind_audit(&audit)?;
    audit.operation(
        op,
        "apple_ade_configuration",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let digest = rss_mdm_registration_service::enrollment::digest(&(
        id,
        p.principal_id(),
        p.instance_id(),
        &input,
    ));
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let result=app.audit_store.write(app.identity.tenant(),&budget.source_control(),(&app,&p,&audit,&input,&key,id,op,&digest),|ctx,tx|Box::pin(async move{
        let (app,p,audit,input,key,id,op,digest)=*ctx;
        let value=tx.with_connection_context(&mut (app,p,input,key,id,op,digest),|ctx,c|Box::pin(async move{
            let(app,p,input,key,id,op,digest)=*ctx;
            lock(c,p.tenant_id(),id).await?;
            if let Some(value)=replay(c,p.tenant_id(),op,digest).await?{return Ok((value,true));}
            crate::organizations::ensure_in(c,p.tenant_id(),id).await?;
            let row=sqlx::query("SELECT * FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2 FOR UPDATE").bind(p.tenant_id()).bind(id).fetch_optional(&mut *c).await.map_err(db)?;
            let current=row.as_ref().map(|r|r.try_get::<i64,_>("revision").map_err(db)).transpose()?.unwrap_or(0);
            if current!=input.expected_revision{return Err(Error::Conflict);}
            if let Some(r)=&row
                && (r.try_get::<Uuid,_>("server_uuid").map_err(db)?!=input.server_uuid || r.try_get::<String,_>("org_id").map_err(db)?!=input.org_id){
                return Err(Error::Conflict);
            }
            let key_id=Uuid::new_v4();
            let sealed=app.protection.seal_bytes(&key.private_key,&aad(p.tenant_id(),id,&key_id.to_string(),"apple.ade.key")?).map_err(|_|Error::Conflict)?;
            sqlx::query("INSERT INTO mdm_apple.ade_servers(tenant_id,organization,revision,enabled,server_uuid,org_id,key_id,certificate,private_key) VALUES($1::uuid,$2,1,$3,$4,$5,$6,$7,$8) ON CONFLICT(tenant_id,organization) DO UPDATE SET revision=mdm_apple.ade_servers.revision+1,enabled=excluded.enabled,key_id=CASE WHEN $9 THEN excluded.key_id ELSE mdm_apple.ade_servers.key_id END,certificate=CASE WHEN $9 THEN excluded.certificate ELSE mdm_apple.ade_servers.certificate END,private_key=CASE WHEN $9 THEN excluded.private_key ELSE mdm_apple.ade_servers.private_key END")
                .bind(p.tenant_id()).bind(id).bind(input.enabled).bind(input.server_uuid).bind(&input.org_id).bind(key_id).bind(&key.certificate).bind(sealed).bind(input.rotate_key).execute(&mut *c).await.map_err(db)?;
            let value=json!({"operationId":op,"state":"succeeded","revision":current+1});
            save(c,p.tenant_id(),id,op,"configuration",digest,p.principal_id(),p.instance_id(),current+1,0,&json!({}),"succeeded",Some(&value),false,now(app)?).await?;
            p.check_live()?;Ok((value,false))
        })).await?;
        append(app,tx,audit,op,value.1).await?;
        Ok(value.0)
    })).await;
    crate::operations::settle(result, &audit).map(Json)
}
pub async fn public_key(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, Error> {
    let p = proof(&auth, false)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    let bytes:Vec<u8>=sqlx::query_scalar("SELECT certificate FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2").bind(p.tenant_id()).bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::NotFound)?;
    Ok((
        [
            ("content-type", "application/x-pem-file"),
            ("cache-control", "no-store"),
            (
                "content-disposition",
                "attachment; filename=RSS-ADE-public.pem",
            ),
        ],
        bytes,
    )
        .into_response())
}
pub async fn operation(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Extension(audit): Extension<RequestAudit>,
    Json(input): Json<Command>,
) -> Result<Json<Value>, Error> {
    let p = proof(&auth, true)?;
    let op = operation_id(&headers)?;
    p.bind_audit(&audit)?;
    audit.operation(
        op,
        "apple_ade_operation",
        rss_mdm_audit_integration::AuditIntent::Management,
    );
    let canonical = Zeroizing::new(
        serde_json::to_vec(&(p.principal_id(), p.instance_id(), &input))
            .map_err(|_| Error::Malformed)?,
    );
    let digest = app
        .protection
        .mac(
            &canonical,
            &aad(p.tenant_id(), id, "operation", "apple.ade.request")?,
        )
        .map_err(|_| Error::Conflict)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    // Exact committed replay is answered before any external read or key-dependent token decode.
    let mut tx = app.access.begin(p.tenant_id()).await?;
    if let Some(value) = replay(&mut tx, p.tenant_id(), op, &digest).await? {
        return Ok(Json(value));
    }
    let row = server(&mut tx, p.tenant_id(), id).await?;
    tx.rollback().await.map_err(db)?;
    let revision: i64 = row.try_get("revision").map_err(db)?;
    let token_revision: i64 = row.try_get("token_revision").map_err(db)?;
    let imported = if let Command::Token {
        expected_revision,
        p7m,
    } = &input
    {
        if *expected_revision != revision {
            return Err(Error::Conflict);
        }
        let encrypted = Zeroizing::new(
            STANDARD
                .decode(p7m.as_str())
                .map_err(|_| Error::Malformed)?,
        );
        let key_id: Uuid = row.try_get("key_id").map_err(db)?;
        let key: Vec<u8> = row.try_get("private_key").map_err(db)?;
        let key = app
            .protection
            .open_bytes(
                &key,
                &aad(p.tenant_id(), id, &key_id.to_string(), "apple.ade.key")?,
            )
            .map_err(|_| Error::Conflict)?;
        let plain = rss_mdm_certificate::apple::ade::decrypt_token(
            &encrypted,
            &row.try_get::<Vec<u8>, _>("certificate").map_err(db)?,
            key.expose(),
        )?;
        let token = client::Token::parse(&plain, now(&app)?)?;
        let expires = token.expires()?;
        let mut client = remote_client(&app, token)?;
        let account = client
            .request(reqwest::Method::GET, "/account", None)
            .await
            .map_err(remote)?;
        if account
            .get("server_uuid")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            != Some(row.try_get("server_uuid").map_err(db)?)
            || account.get("org_id").and_then(Value::as_str)
                != Some(row.try_get::<String, _>("org_id").map_err(db)?.as_str())
        {
            return Err(Error::Forbidden);
        }
        let sealed = app
            .protection
            .seal_bytes(
                &plain,
                &aad(
                    p.tenant_id(),
                    id,
                    &(token_revision + 1).to_string(),
                    "apple.ade.token",
                )?,
            )
            .map_err(|_| Error::Conflict)?;
        Some((sealed, expires))
    } else {
        None
    };
    let request = match &input {
        Command::Token { .. } => json!({"kind":"token"}),
        _ => serde_json::to_value(&input).map_err(|_| Error::Malformed)?,
    };
    let budget =
        rss_mdm_audit_integration::budget::AuditBudget::new(std::time::Duration::from_secs(10));
    let result=app.audit_store.write(app.identity.tenant(),&budget.source_control(),(&app,&p,&audit,&input,&request,&imported,id,op,revision,token_revision,&digest),|ctx,tx|Box::pin(async move{
        let(app,p,audit,input,request,imported,id,op,revision,token_revision,digest)=*ctx;
        let (value,replayed)=tx.with_connection_context(&mut(app,p,input,request,imported,id,op,revision,token_revision,digest),|ctx,c|Box::pin(async move{
            let(app,p,input,request,imported,id,op,revision,token_revision,digest)=*ctx;
            lock(c,p.tenant_id(),id).await?;
            if let Some(v)=replay(c,p.tenant_id(),op,digest).await?{return Ok((v,true));}
            let row=server(c,p.tenant_id(),id).await?;
            if row.try_get::<i64,_>("revision").map_err(db)?!=revision || row.try_get::<i64,_>("token_revision").map_err(db)?!=token_revision{return Err(Error::Conflict);}
            // One external effect per organization prevents snapshot/assignment races.
            // Unknown effects require an explicit read-only resolution before another write.
            if !matches!(input,Command::Token{..}|Command::Resolve{..}|Command::Reconcile{..}) {
                let busy:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND state IN('pending','running','unknown'))").bind(p.tenant_id()).bind(id).fetch_one(&mut *c).await.map_err(db)?;
                if busy{return Err(Error::Conflict);}
            }
            let(kind,state,full)=match input {
                Command::Token{..}=>{
                    let(sealed,expires)=imported.as_ref().ok_or(Error::Conflict)?;
                    sqlx::query("UPDATE mdm_apple.ade_servers SET token=$3,token_revision=token_revision+1,token_expires=$4,verified=true,token_invalid=false,next_sync=0 WHERE tenant_id=$1::uuid AND organization=$2")
                        .bind(p.tenant_id()).bind(id).bind(sealed).bind(expires).execute(&mut *c).await.map_err(db)?;
                    ("token","succeeded",false)
                }
                Command::Sync{full}=>{
                    super::token(&row,app,p.tenant_id(),id)?;
                    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND kind='sync' AND state IN('pending','running'))").bind(p.tenant_id()).bind(id).fetch_one(&mut *c).await.map_err(db)?;
                    if exists{return Err(Error::Conflict);}("sync","pending",*full || row.try_get::<Option<String>,_>("cursor").map_err(db)?.is_none())
                }
                Command::Profile{id:profile,expected_revision,configuration}=>{
                    super::token(&row,app,p.tenant_id(),id)?;configuration.validate()?;
                    if profile.is_nil() || *expected_revision<0 || *expected_revision==i64::MAX{return Err(Error::Malformed);}
                    let current:Option<i64>=sqlx::query_scalar("SELECT revision FROM mdm_apple.ade_profiles WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 FOR UPDATE").bind(p.tenant_id()).bind(id).bind(profile).fetch_optional(&mut *c).await.map_err(db)?;
                    if current.unwrap_or(0)!=*expected_revision{return Err(Error::Conflict);}
                    sqlx::query("INSERT INTO mdm_apple.ade_profiles(tenant_id,organization,id,revision,configuration) VALUES($1::uuid,$2,$3,1,$4) ON CONFLICT(tenant_id,organization,id) DO UPDATE SET revision=mdm_apple.ade_profiles.revision+1,configuration=excluded.configuration,remote_uuid=NULL")
                        .bind(p.tenant_id()).bind(id).bind(profile).bind(serde_json::to_value(configuration).map_err(|_|Error::Malformed)?).execute(&mut *c).await.map_err(db)?;
                    ("profile","pending",false)
                }
                Command::Assign{profile,revision,devices}=>{
                    super::token(&row,app,p.tenant_id(),id)?;validate_devices(devices)?;
                    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.ade_profiles WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND revision=$4 AND remote_uuid IS NOT NULL)").bind(p.tenant_id()).bind(id).bind(profile).bind(revision).fetch_one(&mut *c).await.map_err(db)?;
                    if !exists{return Err(Error::Conflict);}check_devices(c,p.tenant_id(),id,devices).await?;("assign","pending",false)
                }
                Command::Clear{devices}=>{super::token(&row,app,p.tenant_id(),id)?;validate_devices(devices)?;check_devices(c,p.tenant_id(),id,devices).await?;("clear","pending",false)}
                Command::Reconcile{operation}=>{
                    super::token(&row,app,p.tenant_id(),id)?;
                    let kind:Option<String>=sqlx::query_scalar("SELECT kind FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 AND state='unknown' AND kind IN('assign','clear') FOR UPDATE").bind(p.tenant_id()).bind(id).bind(operation).fetch_optional(&mut *c).await.map_err(db)?;
                    if kind.is_none(){return Err(Error::Conflict);}
                    recovery_idle(c,p.tenant_id(),id).await?;
                    ("reconcile","pending",false)
                }
                Command::Resolve{operation,remote_profile}=>{
                    super::token(&row,app,p.tenant_id(),id)?;recovery_idle(c,p.tenant_id(),id).await?;
                    if remote_profile.is_nil(){return Err(Error::Malformed);}
                    let old=sqlx::query("SELECT kind,state FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3 FOR UPDATE").bind(p.tenant_id()).bind(id).bind(operation).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::NotFound)?;
                    if old.try_get::<String,_>("kind").map_err(db)?!="profile" || old.try_get::<String,_>("state").map_err(db)?!="unknown"{return Err(Error::Conflict);}
                    ("resolve","pending",false)
                }
            };
            let value=json!({"operationId":op,"state":state});
            save(c,p.tenant_id(),id,op,kind,digest,p.principal_id(),p.instance_id(),revision,token_revision,request,state,Some(&value),full,now(app)?).await?;
            if kind=="sync" && !full {sqlx::query("UPDATE mdm_apple.ade_operations SET cursor=$3 WHERE tenant_id=$1::uuid AND id=$2").bind(p.tenant_id()).bind(op).bind(row.try_get::<Option<String>,_>("cursor").map_err(db)?).execute(&mut *c).await.map_err(db)?;}
            p.check_live()?;crate::notify(c,"apple").await.map_err(db)?;Ok((value,false))
        })).await?;
        append(app,tx,audit,op,replayed).await?;Ok(value)
    })).await;
    crate::operations::settle(result, &audit).map(Json)
}
pub(super) fn remote_client(
    app: &HttpState,
    token: client::Token,
) -> Result<client::Client, Error> {
    let client = client::Client::new(token)?;
    #[cfg(feature = "integration")]
    if let Some(f) = &app.apple()?.ade_fixture {
        return Ok(client.fixture(f.client.clone(), f.origin.clone()));
    }
    let _ = app;
    Ok(client)
}
pub(super) fn remote(error: client::RemoteError) -> Error {
    match error {
        client::RemoteError::Unauthorized => Error::Unauthorized,
        client::RemoteError::Unknown
        | client::RemoteError::Throttled
        | client::RemoteError::Invalid => Error::Unavailable(Failure::AppleAde),
        _ => Error::Conflict,
    }
}
pub(super) async fn lock(c: &mut sqlx::PgConnection, tenant: &str, id: Uuid) -> Result<(), Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,2673))")
        .bind(format!("apple-ade:{tenant}:{id}"))
        .execute(c)
        .await
        .map_err(db)?;
    Ok(())
}
pub(super) async fn replay(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    op: Uuid,
    digest: &str,
) -> Result<Option<Value>, Error> {
    let row = sqlx::query(
        "SELECT digest,receipt FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND id=$2",
    )
    .bind(tenant)
    .bind(op)
    .fetch_optional(c)
    .await
    .map_err(db)?;
    row.map(|r| {
        if r.try_get::<String, _>("digest").map_err(db)? != digest {
            return Err(Error::Conflict);
        }
        r.try_get::<Value, _>("receipt").map_err(db)
    })
    .transpose()
}
#[allow(
    clippy::too_many_arguments,
    reason = "one ADE operation journal, bound to its protocol owner"
)]
pub(super) async fn save(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    organization: Uuid,
    id: Uuid,
    kind: &str,
    digest: &str,
    actor: &str,
    instance: &str,
    revision: i64,
    token_revision: i64,
    request: &Value,
    state: &str,
    result: Option<&Value>,
    full: bool,
    now: i64,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO mdm_apple.ade_operations(tenant_id,organization,id,kind,digest,actor,instance,server_revision,token_revision,request,state,result,full_sync,created_at,receipt) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)").bind(tenant).bind(organization).bind(id).bind(kind).bind(digest).bind(actor).bind(instance).bind(revision).bind(token_revision).bind(request).bind(state).bind(result).bind(full).bind(now).bind(result.cloned().unwrap_or_else(||json!({"operationId":id,"state":state}))).execute(c).await.map_err(db)?;
    Ok(())
}
async fn append(
    app: &HttpState,
    tx: &mut rss_mdm_audit_integration::SourceTransaction<'_, '_>,
    audit: &RequestAudit,
    op: Uuid,
    replayed: bool,
) -> Result<(), Error> {
    let fact = Fact::business(audit, &format!("apple-ade:{op}"), 200, "success", Some(op))?;
    (if replayed {
        Ok(())
    } else {
        app.audit_store.append(tx, &fact).await
    })
    .map_err(Error::from)?;
    audit.mark_commit_started();
    Ok(())
}
fn validate_devices(devices: &[String]) -> Result<(), Error> {
    if devices.is_empty()
        || devices.len() > 1000
        || devices
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        || devices
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != devices.len()
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
async fn check_devices(
    c: &mut sqlx::PgConnection,
    tenant: &str,
    id: Uuid,
    devices: &[String],
) -> Result<(), Error> {
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM mdm_apple.ade_devices d JOIN mdm_apple.ade_servers s ON(s.tenant_id,s.organization)=(d.tenant_id,d.organization) WHERE d.tenant_id=$1::uuid AND d.organization=$2 AND d.serial=ANY($3) AND NOT d.deleted AND s.synced_at>floor(extract(epoch FROM clock_timestamp()))::bigint-604800").bind(tenant).bind(id).bind(devices).fetch_one(c).await.map_err(db)?;
    if count != devices.len() as i64 {
        return Err(Error::Conflict);
    }
    Ok(())
}
pub async fn status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, Error> {
    let p = proof(&auth, false)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    let row = sqlx::query(
        "SELECT * FROM mdm_apple.ade_servers WHERE tenant_id=$1::uuid AND organization=$2",
    )
    .bind(p.tenant_id())
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db)?
    .ok_or(Error::NotFound)?;
    Ok(Json(status_row(&row, now(&app)?)?))
}
pub(crate) fn status_row(r: &sqlx::postgres::PgRow, now: i64) -> Result<Value, Error> {
    let expires: Option<i64> = r.try_get("token_expires").map_err(db)?;
    let state = if expires.is_none() {
        "missing"
    } else if expires.is_some_and(|v| v <= now) {
        "expired"
    } else if r.try_get::<bool, _>("token_invalid").map_err(db)? {
        "invalid"
    } else if r.try_get::<bool, _>("verified").map_err(db)? {
        "verified"
    } else {
        "unverified"
    };
    Ok(
        json!({"organizationId":r.try_get::<Uuid,_>("organization").map_err(db)?,"revision":r.try_get::<i64,_>("revision").map_err(db)?,"enabled":r.try_get::<bool,_>("enabled").map_err(db)?,"serverUuid":r.try_get::<Uuid,_>("server_uuid").map_err(db)?,"orgId":r.try_get::<String,_>("org_id").map_err(db)?,"keyId":r.try_get::<Uuid,_>("key_id").map_err(db)?,"tokenRevision":r.try_get::<i64,_>("token_revision").map_err(db)?,"tokenExpiresAt":expires,"tokenState":state,"syncedAt":r.try_get::<Option<i64>,_>("synced_at").map_err(db)?,"externalDeviceVerification":"not_observed"}),
    )
}
pub async fn operation_status(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path((id, op)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, Error> {
    let p = proof(&auth, false)?;
    let mut tx = app.access.begin_read(p.tenant_id()).await?;
    let row=sqlx::query("SELECT kind,state,result FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND id=$3").bind(p.tenant_id()).bind(id).bind(op).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(Error::NotFound)?;
    Ok(Json(
        json!({"operationId":op,"kind":row.try_get::<String,_>("kind").map_err(db)?,"state":row.try_get::<String,_>("state").map_err(db)?,"result":row.try_get::<Option<Value>,_>("result").map_err(db)?}),
    ))
}
pub async fn devices(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
    RawQuery(raw): RawQuery,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Value>>, Error> {
    (async {
        crate::management_query::page(
            &app,
            &auth.proof,
            crate::management_query::Collection::Devices(id),
            raw.as_deref().unwrap_or(""),
        )
        .await
        .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}
pub async fn profiles(
    State(app): State<Arc<HttpState>>,
    Extension(auth): Extension<RequestAuth>,
    Path(id): Path<Uuid>,
    RawQuery(raw): RawQuery,
) -> Result<rss_mdm_http_contract::CollectionResponse<Json<Value>>, Error> {
    (async {
        crate::management_query::page(
            &app,
            &auth.proof,
            crate::management_query::Collection::Profiles(id),
            raw.as_deref().unwrap_or(""),
        )
        .await
        .map(Json)
    })
    .await
    .map(rss_mdm_http_contract::CollectionResponse)
}

async fn recovery_idle(c: &mut sqlx::PgConnection, tenant: &str, id: Uuid) -> Result<(), Error> {
    let busy:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_apple.ade_operations WHERE tenant_id=$1::uuid AND organization=$2 AND state IN('pending','running'))").bind(tenant).bind(id).fetch_one(c).await.map_err(db)?;
    if busy {
        return Err(Error::Conflict);
    }
    Ok(())
}
