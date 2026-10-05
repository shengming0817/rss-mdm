use super::*;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Accept {
    pub terms_version: String,
    pub accepted: bool,
}
pub async fn terms(
    axum::extract::State(app): axum::extract::State<Arc<HttpState>>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, Error> {
    let entra = owner(&app)?;
    let subject = entra.verify(bearer(&headers)?).await?;
    let claims = subject.claims().map_err(|_| Error::Unauthorized)?;
    let mut tx = app.access.begin_read(&entra.tenant.to_string()).await?;
    let settings = settings_in(&mut tx, &entra.tenant.to_string(), false).await?;
    settings.policy.permits(claims.user)?;
    subject.check_live().map_err(|_| Error::Unauthorized)?;
    Ok(axum::Json(
        serde_json::json!({"revision":settings.revision,"termsVersion":settings.policy.terms_version}),
    ))
}
pub async fn accept(
    axum::extract::State(app): axum::extract::State<Arc<HttpState>>,
    headers: axum::http::HeaderMap,
    axum::Extension(a): axum::Extension<RequestAudit>,
    axum::Json(input): axum::Json<Accept>,
) -> Result<axum::Json<serde_json::Value>, Error> {
    let entra = owner(&app)?;
    let subject = entra.verify(bearer(&headers)?).await?;
    let claims = subject.claims().map_err(|_| Error::Unauthorized)?;
    if !input.accepted {
        return Ok(axum::Json(serde_json::json!({"isAccepted":false})));
    }
    let secret = crate::enrollment::random();
    let digest = hash(&secret);
    let id = Uuid::new_v4();
    a.identify_service("service:windows-entra-terms");
    a.operation(id, "windows_entra_consent");
    a.target(&format!("entra:{}:{}", claims.tenant, claims.user));
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
    let control = budget.control();
    let result=app.audit_store.write(entra.tenant,&control,(&app,&subject,&input,&digest,&a,id,entra),|(app,subject,input,digest,a,id,entra),tx|Box::pin(async move {
        let (app,subject,input,digest,a,id,entra)=(*app,*subject,*input,*digest,*a,*id,*entra);
        tx.with_connection_context(&mut (subject,input,digest,entra),|(subject,input,digest,entra),c|Box::pin(async move {
            let (subject,input,digest,entra)=(*subject,*input,*digest,*entra);
            let claims=subject.claims().map_err(|_|Error::Unauthorized)?;
            let settings=settings_in(c,&entra.tenant.to_string(),true).await?;
            settings.policy.permits(claims.user)?;
            if input.terms_version!=settings.policy.terms_version {return Err(Error::Conflict);}
            sqlx::query("DELETE FROM mdm_windows.entra_consents WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp() AND digest IN(SELECT digest FROM mdm_windows.entra_consents WHERE tenant_id=$1::uuid AND expires_at<clock_timestamp() ORDER BY expires_at LIMIT 128)").bind(entra.tenant.to_string()).execute(&mut *c).await.map_err(db)?;
            sqlx::query("INSERT INTO mdm_windows.entra_consents(tenant_id,digest,entra_tenant,entra_user,revision,expires_at) VALUES($1::uuid,$2,$3,$4,$5,clock_timestamp()+interval '300 seconds')")
                .bind(entra.tenant.to_string()).bind(digest.as_str()).bind(claims.tenant).bind(claims.user).bind(settings.revision).execute(c).await.map_err(db)?;
            subject.check_live().map_err(|_|Error::Unauthorized)
        })).await?;
        let fact=Fact::business(a,&format!("windows-entra-consent:{id}"),digest.as_bytes(),200,"success",None).map_err(Error::from)?;
        app.audit_store.append(tx,&fact,false).await.map_err(Error::from)?;a.mark_commit_started();Ok(())
    })).await;
    crate::operations::settle(result, &a)?;
    Ok(axum::Json(
        serde_json::json!({"isAccepted":true,"opaqueBlob":secret,"expiresIn":300}),
    ))
}
pub(super) async fn consent(
    c: &mut PgConnection,
    entra: &Entra,
    subject: &VerifiedExternalSubject,
    settings: &Settings,
    opaque: Option<&str>,
) -> Result<(), Error> {
    settings
        .policy
        .permits(subject.claims().map_err(|_| Error::Unauthorized)?.user)?;
    let Some(opaque) = opaque else {
        return if settings.policy.allow_background {
            Ok(())
        } else {
            Err(Error::Forbidden)
        };
    };
    if opaque.is_empty() || opaque.len() > 256 {
        return Err(Error::Unauthorized);
    }
    let claims = subject.claims().map_err(|_| Error::Unauthorized)?;
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mdm_windows.entra_consents WHERE tenant_id=$1::uuid AND digest=$2 AND entra_tenant=$3 AND entra_user=$4 AND revision=$5 AND expires_at>clock_timestamp())")
        .bind(entra.tenant.to_string()).bind(hash(opaque)).bind(claims.tenant).bind(claims.user).bind(settings.revision).fetch_one(c).await.map_err(db)?;
    if !valid {
        return Err(Error::Forbidden);
    }
    Ok(())
}
