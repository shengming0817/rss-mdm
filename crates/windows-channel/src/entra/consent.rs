use super::*;
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
