use super::*;
struct Gate {
    tenant: String,
    user: Uuid,
    revision: i64,
}
impl EntraPolicyAuthority for Gate {
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        d: &'a Coordinates,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), rss_mdm_registration_service::Error>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if d.tenant != self.tenant || d.version != self.revision {
                return Err(rss_mdm_registration_service::Error::Forbidden);
            }
            let settings = settings_in(c, &self.tenant, true).await.map_err(|error| {
                use crate::Failure;
                use rss_mdm_registration_service::Error as R;
                match error {
                    Error::Malformed | Error::CertificateRequest => R::Malformed,
                    Error::Unauthorized => R::Unauthorized,
                    Error::Forbidden => R::Forbidden,
                    Error::Conflict => R::Conflict,
                    Error::CommitUnknown => R::CommitUnknown,
                    Error::RollbackFailed => R::RollbackFailed,
                    Error::Unavailable(Failure::RequestDeadline) => R::Deadline,
                    Error::Unavailable(Failure::Capacity) => R::Capacity,
                    Error::Unavailable(_) => R::Storage,
                    Error::NotFound | Error::Missing(_) => R::NotFound,
                    Error::Configuration(_) | Error::Unsupported => R::Configuration,
                }
            })?;
            if settings.revision != self.revision {
                return Err(rss_mdm_registration_service::Error::Forbidden);
            }
            settings
                .policy
                .permits(self.user)
                .map_err(|_| rss_mdm_registration_service::Error::Forbidden)
        })
    }
}
/// Policy and consent gate precede JIT. The resulting account enters the closed lifecycle basis.
pub(super) async fn admit(
    app: &HttpState,
    token: Zeroizing<String>,
    opaque: Option<&str>,
    csr: &[u8],
    profile: WindowsProfile,
    a: &RequestAudit,
) -> Result<Admission, Error> {
    let entra = owner(app)?;
    let subject = entra.verify(token).await?;
    let claims = subject.claims().map_err(|_| Error::Unauthorized)?;
    let device = claims.device.ok_or(Error::Unauthorized)?;
    let user = claims.user;
    let external_tenant = claims.tenant;
    let tenant = entra.tenant.to_string();
    let mut tx = app.access.begin_read(&tenant).await?;
    let settings = settings_in(&mut tx, &tenant, false).await?;
    consent(&mut tx, entra, &subject, &settings, opaque).await?;
    tx.rollback().await.map_err(db)?;
    // No MDM locks held while Identity may create/revalidate the canonical account.
    let proof = identity::resolve(&entra.authority, subject).await?;
    rss_mdm_authorization_service::context::bind_native_audit(&proof, a)?;
    a.target(&format!("entra:{external_tenant}:{device}"));
    let proposed = Uuid::new_v4();
    let digest = crate::enrollment::digest(&(
        "windows-entra-admit",
        external_tenant,
        user,
        device,
        csr,
        profile,
    ));
    let policy: Arc<dyn EntraPolicyAuthority> = Arc::new(Gate {
        tenant,
        user,
        revision: settings.revision,
    });
    let budget = rss_mdm_audit_integration::budget::AuditBudget::new(Duration::from_secs(2));
    let control = budget.control();
    let result=app.audit_store.write(entra.tenant,&control,(app,Some(proof),policy,&settings,opaque,&digest,a),|(app,proof,policy,settings,opaque,digest,a),tx|Box::pin(async move {
        let (app,settings,opaque,digest,a)=(*app,*settings,*opaque,*digest,*a);
        let (admission,replayed)=tx.with_connection_context(&mut (proof,policy,settings,opaque,digest),|(proof,policy,settings,opaque,digest),c|Box::pin(async move {
            let (settings,opaque,digest)=(*settings,*opaque,*digest);
            let proof:RevalidatedAccount=proof.take().ok_or(Error::Conflict)?;
            let admission=rss_mdm_registration_service::enrollment::native::entra_in(c,proof,policy.clone(),proposed,settings.revision,profile).await?;
            let d=admission.coordinates();
            if let Some(opaque)=opaque {
                let changed=sqlx::query("UPDATE mdm_windows.entra_consents SET request_id=$3,request_digest=$4 WHERE tenant_id=$1::uuid AND digest=$2 AND revision=$5 AND expires_at>clock_timestamp() AND (request_id IS NULL OR (request_id=$3 AND request_digest=$4))")
                    .bind(&d.tenant).bind(hash(opaque)).bind(d.id).bind(digest.as_str()).bind(settings.revision).execute(&mut *c).await.map_err(db)?.rows_affected();
                if changed!=1 {return Err(Error::Forbidden);}
            } else if !settings.policy.allow_background {return Err(Error::Forbidden);}
            let old:Option<String>=sqlx::query_scalar("SELECT request_digest FROM mdm_windows.entra_admissions WHERE tenant_id=$1::uuid AND request_id=$2").bind(&d.tenant).bind(d.id).fetch_optional(&mut *c).await.map_err(db)?;
            let replayed=old.is_some();
            if let Some(old)=old {if old!=*digest {return Err(Error::Conflict);}} else {
                sqlx::query("INSERT INTO mdm_windows.entra_admissions(tenant_id,request_id,request_digest) VALUES($1::uuid,$2,$3)").bind(&d.tenant).bind(d.id).bind(digest.as_str()).execute(&mut *c).await.map_err(db)?;
            }
            admission.check_live()?;
            Ok::<_,Error>((admission,replayed))
        })).await?;
        let id=admission.coordinates().id;
        a.operation(id,"enrollment_issue");
        let fact=Fact::business(a,&format!("windows-entra-admit:{id}"),digest.as_bytes(),200,"success",Some(id)).map_err(Error::from)?;
        app.audit_store.append(tx,&fact,replayed).await.map_err(Error::from)?;a.mark_commit_started();Ok(admission)
    })).await;
    crate::operations::settle(result, a)
}
