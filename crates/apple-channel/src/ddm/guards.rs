//! Native Legacy Profile conflicts and correlated absence proof.
use super::*;
async fn guarded(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    user: &str,
) -> Result<Vec<(Uuid, bool, Publication)>, Error> {
    let rows=sqlx::query("SELECT operation,snapshot,retired_at IS NOT NULL AS withdrawn FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND legacy_released_at IS NULL ORDER BY operation")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(user).fetch_all(c).await.map_err(db)?;
    let mut values = Vec::new();
    for row in rows {
        let id = row.try_get("operation").map_err(db)?;
        let sealed: Vec<u8> = row.try_get("snapshot").map_err(db)?;
        let plain = key
            .open_bytes(&sealed, &aad(p, user, id, "apple.ddm.publication")?)
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
        let publication: Publication = serde_json::from_slice(plain.expose())
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
        if !publication.legacy.is_empty() {
            values.push((id, row.try_get("withdrawn").map_err(db)?, publication));
        }
    }
    Ok(values)
}
pub(crate) async fn profile_conflict(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    user: &str,
    root: &str,
    objects: Option<&[native::profiles::ProfileObject]>,
) -> Result<bool, Error> {
    for (_, _, publication) in guarded(c, key, p, user).await? {
        for profile in publication.legacy {
            if profile
                .objects
                .first()
                .is_some_and(|o| o.identifier == root)
                || objects.is_some_and(|objects| {
                    native::profiles::collides(objects, &profile.objects, true)
                })
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
pub(crate) async fn profile_observation_guards(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    user: &str,
) -> Result<Vec<Uuid>, Error> {
    Ok(guarded(c, key, p, user)
        .await?
        .into_iter()
        .filter_map(|(id, withdrawn, _)| withdrawn.then_some(id))
        .collect())
}
/// Only a fresh independently correlated complete native read may release a withdrawn guard.
pub(crate) async fn release_profiles(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    user: &str,
    report: &plist::Dictionary,
    observed_guards: &[Uuid],
) -> Result<bool, Error> {
    let mut remaining = false;
    for (id, withdrawn, publication) in guarded(c, key, p, user).await? {
        if !withdrawn {
            continue;
        }
        // This native query cannot prove absence after a later withdrawal.
        if !observed_guards.contains(&id) {
            remaining = true;
            continue;
        }
        let absent = publication.legacy.iter().all(|profile| {
            profile.objects.first().is_some_and(|root| {
                matches!(
                    rss_mdm_apple_mdm::profile::presence(report, &root.identifier, root.uuid),
                    Ok(false)
                )
            })
        });
        if absent {
            for profile in &publication.legacy {
                let root = profile.objects.first().ok_or(Error::Malformed)?;
                sqlx::query("UPDATE mdm_apple.profiles SET retired_at=coalesce(retired_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND identifier=$5 AND profile=$6")
                    .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(user).bind(&root.identifier).bind(root.uuid).execute(&mut *c).await.map_err(db)?;
            }
            sqlx::query("UPDATE mdm_apple.declarations SET legacy_released_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND operation=$2 AND retired_at IS NOT NULL AND legacy_released_at IS NULL")
                .bind(p.tenant().to_string()).bind(id).execute(&mut *c).await.map_err(db)?;
        } else {
            remaining = true;
        }
    }
    Ok(!remaining)
}
