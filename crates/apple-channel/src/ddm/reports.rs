//! Protected report evidence and commutative native interpretation.
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Accumulated {
    state: native::ddm::ProjectionState,
    received_at: i64,
}
fn publication_set(publication: &Publication, scope: &str) -> Result<DeclarationSet, Error> {
    let target = native::Target {
        context: &publication.context,
        access_rights: &[],
    };
    DeclarationSet::new(
        scope,
        publication
            .inputs
            .iter()
            .map(|i| i.compile(&publication.version, &target))
            .collect::<Result<_, _>>()
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?,
    )
    .map_err(|_| Error::Unavailable(Failure::AppleStorage))
}
fn accumulated(
    key: &Protector,
    sealed: &[u8],
    aad: &rss_mdm_native_protection::DerivedAad,
) -> Result<Accumulated, Error> {
    let plain = key
        .open_bytes(sealed, aad)
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    serde_json::from_slice(plain.expose()).map_err(|_| Error::Unavailable(Failure::AppleStorage))
}
impl Exchange {
    pub(super) async fn status(
        &self,
        c: &mut PgConnection,
        p: &DevicePrincipal,
        publications: &[(Uuid, String, Publication)],
    ) -> Result<channels::AppleDdmReply, Error> {
        let bytes = self.data.as_deref().ok_or(Error::Malformed)?;
        let fallback;
        let publication = if let Some((_, _, publication)) = publications.last() {
            publication
        } else {
            let row=sqlx::query("SELECT operation,snapshot FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 ORDER BY published_at DESC,operation DESC LIMIT 1")
                .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(&self.user).fetch_optional(&mut *c).await.map_err(db)?.ok_or(Error::Unauthorized)?;
            let id = row.try_get("operation").map_err(db)?;
            let sealed: Vec<u8> = row.try_get("snapshot").map_err(db)?;
            let plain = self
                .apple
                .protection
                .open_bytes(&sealed, &aad(p, &self.user, id, "apple.ddm.publication")?)
                .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
            fallback = serde_json::from_slice::<Publication>(plain.expose())
                .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
            &fallback
        };
        let target = native::Target {
            context: &publication.context,
            access_rights: &[],
        };
        let set = compile(publications, &scope(p, &self.user)?).map_err(|_| Error::Conflict)?;
        native::ddm::StatusReport::decode(bytes, &target).map_err(|_| Error::Malformed)?;
        let evidence = native::ddm::ReportEvidence {
            report: bytes.to_vec(),
            context: publication.context.clone(),
            subscriptions: subscriptions(publications)?,
            declarations_token: set.tokens()["SyncTokens"]["DeclarationsToken"]
                .as_str()
                .ok_or(Error::Malformed)?
                .into(),
        };
        let digest = self
            .apple
            .protection
            .mac(
                &serde_json::to_vec(&(
                    bytes,
                    &evidence.declarations_token,
                    &evidence.subscriptions,
                ))
                .map_err(|_| Error::Malformed)?,
                &aad(p, &self.user, Uuid::nil(), "apple.ddm.report-replay")?,
            )
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
        let id = Uuid::new_v4();
        let sealed = seal(
            &self.apple.protection,
            p,
            &self.user,
            id,
            "apple.ddm.report",
            &serde_json::to_vec(&evidence).map_err(|_| Error::Malformed)?,
        )?;
        let inserted = sqlx::query("INSERT INTO mdm_apple.status_reports(tenant_id,id,registration,generation,user_key,digest,evidence) VALUES($1::uuid,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,registration,generation,user_key,digest) DO NOTHING")
            .bind(p.tenant().to_string()).bind(id).bind(p.registration()).bind(p.generation()).bind(&self.user).bind(digest.as_slice()).bind(sealed).execute(&mut *c).await.map_err(db)?.rows_affected() == 1;
        if inserted {
            let received_at:i64=sqlx::query_scalar("SELECT received_at FROM mdm_apple.status_reports WHERE tenant_id=$1::uuid AND id=$2").bind(p.tenant().to_string()).bind(id).fetch_one(&mut *c).await.map_err(db)?;
            // Raw history and bounded accumulated claims commit together in the host transaction.
            for (operation, _, publication) in publications {
                let sealed:Option<Vec<u8>>=sqlx::query_scalar("SELECT projection FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2 AND retired_at IS NULL").bind(p.tenant().to_string()).bind(operation).fetch_one(&mut *c).await.map_err(db)?;
                let protection = aad(p, &self.user, *operation, "apple.ddm.projection")?;
                let state = sealed
                    .map(|bytes| accumulated(&self.apple.protection, &bytes, &protection))
                    .transpose()?
                    .map(|s| s.state)
                    .unwrap_or_default();
                let expected = publication_set(publication, &scope(p, &self.user)?)?;
                let target = native::Target {
                    context: &publication.context,
                    access_rights: &[],
                };
                let mut projection = native::ddm::Projection::restore(&expected, &target, state)
                    .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
                projection
                    .observe(&evidence)
                    .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
                let bytes = serde_json::to_vec(&Accumulated {
                    state: projection.checkpoint(),
                    received_at,
                })
                .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
                let sealed = self
                    .apple
                    .protection
                    .seal_bytes(&bytes, &protection)
                    .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
                sqlx::query("UPDATE mdm_apple.declarations SET projection=$3 WHERE tenant_id=$1::uuid AND operation=$2 AND retired_at IS NULL").bind(p.tenant().to_string()).bind(operation).bind(sealed).execute(&mut *c).await.map_err(db)?;
            }
        }
        let mut synchronized = Vec::new();
        for (id, _, publication) in publications {
            if let Some(value) = observation(
                c,
                &self.apple.protection,
                &p.tenant().to_string(),
                *id,
                false,
            )
            .await?
            {
                if value.status.synchronized {
                    synchronized.push(*id);
                }
                // A valid, active exact-version native declaration may take over its
                // identical managed Profile. The DDM guard remains until native absence.
                let statuses = &value.status.declarations;
                for profile in &publication.legacy {
                    if statuses.iter().any(|d| {
                        d["identifier"] == profile.declaration
                            && d["native"]["valid"] == "valid"
                            && d["native"]["active"] == true
                    }) {
                        let root = profile.objects.first().ok_or(Error::Malformed)?;
                        sqlx::query("UPDATE mdm_apple.profiles SET retired_at=coalesce(retired_at,floor(extract(epoch FROM clock_timestamp()))::bigint) WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND identifier=$5 AND profile=$6")
                            .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(&self.user).bind(&root.identifier).bind(root.uuid).execute(&mut *c).await.map_err(db)?;
                    }
                }
            }
        }
        Ok(channels::AppleDdmReply {
            status: 200,
            bytes: Vec::new(),
            synchronized,
        })
    }
}
fn subscriptions(
    publications: &[(Uuid, String, Publication)],
) -> Result<std::collections::BTreeSet<String>, Error> {
    let mut names = std::collections::BTreeSet::new();
    for (_, _, publication) in publications {
        for declaration in &publication.inputs {
            if declaration.declaration_type
                != "com.apple.configuration.management.status-subscriptions"
            {
                continue;
            }
            let fields = declaration
                .payload
                .to_plist()
                .map_err(|_| Error::Malformed)?;
            for value in fields
                .get("StatusItems")
                .and_then(plist::Value::as_array)
                .ok_or(Error::Malformed)?
            {
                let name = value
                    .as_dictionary()
                    .and_then(|v| v.get("Name"))
                    .and_then(plist::Value::as_string)
                    .ok_or(Error::Malformed)?;
                names.insert(name.to_owned());
            }
        }
    }
    Ok(names)
}
pub(crate) async fn observation(
    c: &mut PgConnection,
    key: &Protector,
    tenant: &str,
    operation: Uuid,
    native_values: bool,
) -> Result<Option<native::evidence::DeclarationEvidence>, Error> {
    let row=sqlx::query("SELECT registration,generation,user_key,snapshot,projection,retired_at FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2")
        .bind(tenant).bind(operation).fetch_optional(&mut *c).await.map_err(db)?;
    let Some(row) = row else { return Ok(None) };
    let registration = row.try_get("registration").map_err(db)?;
    let generation = row.try_get("generation").map_err(db)?;
    let user: String = row.try_get("user_key").map_err(db)?;
    let sealed: Vec<u8> = row.try_get("snapshot").map_err(db)?;
    let plain = key
        .open_bytes(
            &sealed,
            &aad_parts(
                tenant,
                registration,
                generation,
                &user,
                operation,
                "apple.ddm.publication",
            )?,
        )
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    let publication: Publication = serde_json::from_slice(plain.expose())
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    let target = native::Target {
        context: &publication.context,
        access_rights: &[],
    };
    let set = publication_set(
        &publication,
        &serde_json::to_string(&(tenant, registration, generation, &user))
            .map_err(|_| Error::Malformed)?,
    )?;
    let retired: Option<i64> = row.try_get("retired_at").map_err(db)?;
    let sealed: Option<Vec<u8>> = row.try_get("projection").map_err(db)?;
    let accumulated = if retired.is_none() {
        sealed
            .map(|bytes| {
                accumulated(
                    key,
                    &bytes,
                    &aad_parts(
                        tenant,
                        registration,
                        generation,
                        &user,
                        operation,
                        "apple.ddm.projection",
                    )?,
                )
            })
            .transpose()?
    } else {
        None
    };
    let received_at = accumulated.as_ref().map(|s| s.received_at);
    let projection = native::ddm::Projection::restore(
        &set,
        &target,
        accumulated.map(|s| s.state).unwrap_or_default(),
    )
    .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    let mut status = projection
        .finish()
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    if !native_values {
        status.items.clear();
        status.errors.clear();
        for row in &mut status.declarations {
            row["native"]["reasons"] = serde_json::json!([]);
        }
    }
    Ok(Some(native::evidence::DeclarationEvidence {
        input_version: publication.input_version,
        expected: set.manifest()["Declarations"].clone(),
        publication: if retired.is_some() {
            native::evidence::PublicationState::Withdrawn
        } else {
            native::evidence::PublicationState::Published
        },
        received_at,
        status,
    }))
}

/// Logical desired ownership can leave after withdrawal without fabricating an OS effect.
pub(crate) async fn withdrawal_published(
    c: &mut PgConnection,
    key: &Protector,
    tenant: &str,
    operation: Uuid,
) -> Result<bool, Error> {
    let row = sqlx::query("SELECT registration,generation,user_key,snapshot FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND operation=$2 AND retired_at IS NULL")
        .bind(tenant).bind(operation).fetch_optional(c).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let bytes: Vec<u8> = row.try_get("snapshot").map_err(db)?;
    let plain = key
        .open_bytes(
            &bytes,
            &aad_parts(
                tenant,
                row.try_get("registration").map_err(db)?,
                row.try_get("generation").map_err(db)?,
                &row.try_get::<String, _>("user_key").map_err(db)?,
                operation,
                "apple.ddm.publication",
            )?,
        )
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    let publication: Publication = serde_json::from_slice(plain.expose())
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
    Ok(publication.inputs.is_empty())
}
