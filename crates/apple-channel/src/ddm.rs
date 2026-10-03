//! Native DDM synchronization borrows the existing execution transaction.
//! ref: apple/device-management mdm/checkin/declarativemanagement.yaml@09f249a.
use crate::{Error, Failure, database::db, device::DevicePrincipal, execution::channels};
use rss_mdm_apple_mdm::{
    applicability::Context,
    native::{
        self,
        ddm::{DeclarationInput, DeclarationKind, DeclarationSet},
    },
};
use rss_mdm_native_protection::{ProtectionContext, Protector};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, Row};
use uuid::Uuid;
// Online work is bounded independently of retained evidence history.
const MAX_PUBLICATIONS: usize = 16;
mod assets;
mod guards;
mod reports;
pub use assets::asset;
pub(crate) use guards::{profile_conflict, profile_observation_guards, release_profiles};
pub(crate) use reports::{observation, withdrawal_published};

#[derive(Serialize, Deserialize)]
struct Publication {
    input_version: String,
    version: String,
    owner: String,
    inputs: Vec<DeclarationInput>,
    assets: Vec<native::ddm::AssetBinding>,
    context: Context,
    legacy: Vec<native::ddm::LegacyProfile>,
}
fn aad_parts(
    tenant: &str,
    registration: Uuid,
    generation: i64,
    user: &str,
    id: Uuid,
    purpose: &str,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    let owner = serde_json::to_string(&(registration, generation, user, id))
        .map_err(|_| Error::Malformed)?;
    let tenant = rss_request_context::TenantId::parse(tenant).map_err(|_| Error::Malformed)?;
    ProtectionContext::new(tenant, &owner, purpose, 1)
        .map(|v| v.derive())
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))
}
fn aad(
    p: &DevicePrincipal,
    user: &str,
    id: Uuid,
    purpose: &str,
) -> Result<rss_mdm_native_protection::DerivedAad, Error> {
    aad_parts(
        &p.tenant().to_string(),
        p.registration(),
        p.generation(),
        user,
        id,
        purpose,
    )
}
fn seal(
    key: &Protector,
    p: &DevicePrincipal,
    user: &str,
    id: Uuid,
    purpose: &str,
    bytes: &[u8],
) -> Result<Vec<u8>, Error> {
    key.seal_bytes(bytes, &aad(p, user, id, purpose)?)
        .map_err(|_| Error::Unavailable(Failure::AppleStorage))
}
fn scope(p: &DevicePrincipal, user: &str) -> Result<String, Error> {
    serde_json::to_string(&(
        p.tenant().to_string(),
        p.registration(),
        p.generation(),
        user,
    ))
    .map_err(|_| Error::Malformed)
}
async fn publications(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    user: &str,
) -> Result<Vec<(Uuid, String, Publication)>, Error> {
    let rows=sqlx::query("SELECT operation,owner,snapshot FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND retired_at IS NULL ORDER BY operation LIMIT 17")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(user).fetch_all(c).await.map_err(db)?;
    if rows.len() > MAX_PUBLICATIONS {
        return Err(Error::Conflict);
    }
    let mut out = Vec::new();
    for row in rows {
        let id = row.try_get("operation").map_err(db)?;
        let sealed: Vec<u8> = row.try_get("snapshot").map_err(db)?;
        let plain = key
            .open_bytes(&sealed, &aad(p, user, id, "apple.ddm.publication")?)
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
        let value = serde_json::from_slice(plain.expose())
            .map_err(|_| Error::Unavailable(Failure::AppleStorage))?;
        let owner: String = row.try_get("owner").map_err(db)?;
        let value: Publication = value;
        if value.owner != owner {
            return Err(Error::Unavailable(Failure::AppleStorage));
        }
        out.push((id, owner, value));
    }
    Ok(out)
}
fn compile(
    publications: &[(Uuid, String, Publication)],
    scope: &str,
) -> Result<DeclarationSet, native::Error> {
    let mut declarations = Vec::new();
    for (_, _, publication) in publications {
        let target = native::Target {
            context: &publication.context,
            access_rights: &[],
        };
        for input in &publication.inputs {
            declarations.push(input.compile(&publication.version, &target)?);
        }
    }
    DeclarationSet::new(scope, declarations)
}
pub(crate) async fn candidates(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    user: &str,
) -> Result<Vec<Uuid>, Error> {
    sqlx::query_scalar("SELECT operation FROM mdm_apple.declarations WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND retired_at IS NULL ORDER BY operation")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(user).fetch_all(c).await.map_err(db)
}
async fn retain(
    c: &mut PgConnection,
    p: &DevicePrincipal,
    user: &str,
    authorized: &[Uuid],
) -> Result<(), Error> {
    sqlx::query("UPDATE mdm_apple.declarations SET retired_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND retired_at IS NULL AND NOT(operation=ANY($5))")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(user).bind(authorized).execute(c).await.map_err(db)?;
    Ok(())
}
pub(crate) async fn publish(
    c: &mut PgConnection,
    apple: &crate::Apple,
    p: &DevicePrincipal,
    command: &channels::AppleCommand,
    context: &Context,
) -> Result<Result<serde_json::Value, native::Error>, Error> {
    let native::request::Request::Declarations { declarations, .. } = &command.request else {
        return Err(Error::Malformed);
    };
    let user = command.target.user_key();
    retain(c, p, user, &command.authorized_declarations).await?;
    let mut old = publications(c, &apple.protection, p, user).await?;
    if old.iter().any(|(id, _, _)| *id == command.operation) {
        return Ok(compile(&old, &scope(p, user)?).map(|set| set.tokens()));
    }
    old.retain(|(_, owner, _)| owner != &command.owner);
    let base = format!(
        "{}/native/apple/ddm/assets/{}",
        apple.config.management.origin.trim_end_matches('/'),
        command.operation
    );
    let inputs = match native::ddm::bind_assets(
        declarations,
        &command.assets,
        &base,
        &native::Target {
            context,
            access_rights: &[],
        },
    ) {
        Ok(value) => value,
        Err(error) => return Ok(Err(error)),
    };
    let legacy = match native::ddm::legacy_profiles(
        &inputs,
        &command.assets,
        &native::Target {
            context,
            access_rights: &[],
        },
    ) {
        Ok(value) => value,
        Err(error) => return Ok(Err(error)),
    };
    if !crate::profiles::ddm_admission(c, &apple.protection, p, user, &legacy).await? {
        return Ok(Err(native::Error::Constraint));
    }
    // A publication owns a closed native graph; another actor's withdrawal must
    // never leave references dangling in this frozen intent.
    let declarations = match inputs
        .iter()
        .map(|input| {
            input.compile(
                &command.input_version,
                &native::Target {
                    context,
                    access_rights: &[],
                },
            )
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(value) => value,
        Err(error) => return Ok(Err(error)),
    };
    if let Err(error) = DeclarationSet::new(&scope(p, user)?, declarations) {
        return Ok(Err(error));
    }
    old.push((
        command.operation,
        command.owner.clone(),
        Publication {
            input_version: command.input_version.clone(),
            version: command.operation.to_string(),
            owner: command.owner.clone(),
            inputs,
            assets: command.assets.clone(),
            context: context.clone(),
            legacy,
        },
    ));
    if old.len() > MAX_PUBLICATIONS {
        return Ok(Err(native::Error::Constraint));
    }
    let new = &old.last().ok_or(Error::Malformed)?.2;
    for (_, _, other) in &old[..old.len() - 1] {
        if new.legacy.iter().any(|a| {
            other
                .legacy
                .iter()
                .any(|b| native::profiles::collides(&a.objects, &b.objects, true))
        }) {
            return Ok(Err(native::Error::Constraint));
        }
    }
    let set = match compile(&old, &scope(p, user)?) {
        Ok(set) => set,
        Err(error) => return Ok(Err(error)),
    };
    let bytes =
        serde_json::to_vec(&old.last().ok_or(Error::Malformed)?.2).map_err(|_| Error::Malformed)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Ok(Err(native::Error::Limit));
    }
    let sealed = seal(
        &apple.protection,
        p,
        user,
        command.operation,
        "apple.ddm.publication",
        &bytes,
    )?;
    sqlx::query("UPDATE mdm_apple.declarations SET retired_at=floor(extract(epoch FROM clock_timestamp()))::bigint WHERE tenant_id=$1::uuid AND registration=$2 AND generation=$3 AND user_key=$4 AND owner=$5 AND retired_at IS NULL")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(p.generation()).bind(user).bind(&command.owner).execute(&mut *c).await.map_err(db)?;
    sqlx::query("INSERT INTO mdm_apple.declarations(tenant_id,operation,registration,generation,user_key,owner,snapshot,legacy_released_at) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,CASE WHEN $8 THEN floor(extract(epoch FROM clock_timestamp()))::bigint END)")
        .bind(p.tenant().to_string()).bind(command.operation).bind(p.registration()).bind(p.generation()).bind(user).bind(&command.owner).bind(sealed).bind(new.legacy.is_empty()).execute(&mut *c).await.map_err(db)?;
    Ok(Ok(set.tokens()))
}
struct Exchange {
    apple: std::sync::Arc<crate::Apple>,
    udid: String,
    user: String,
    endpoint: String,
    data: Option<Vec<u8>>,
}
pub fn prepare(
    apple: std::sync::Arc<crate::Apple>,
    dictionary: &plist::Dictionary,
) -> Result<Box<dyn channels::AppleDdmExchange>, Error> {
    let crate::protocol::CheckIn::DeclarativeManagement {
        udid,
        user,
        endpoint,
        data,
    } = crate::protocol::checkin(dictionary)?
    else {
        return Err(Error::Malformed);
    };
    Ok(Box::new(Exchange {
        apple,
        udid: udid.into(),
        user: user.map(|u| u.to_string()).unwrap_or_default(),
        endpoint: endpoint.into(),
        data: data.map(ToOwned::to_owned),
    }))
}
impl channels::AppleDdmExchange for Exchange {
    fn user_key(&self) -> &str {
        &self.user
    }
    fn current<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> channels::Pending<'a, ()> {
        Box::pin(async move {
            crate::flow_store::current(c, p, &self.udid, &self.user)
                .await
                .map_err(Into::into)
        })
    }
    fn candidates<'a>(
        &'a self,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
    ) -> channels::Pending<'a, Vec<Uuid>> {
        Box::pin(async move { candidates(c, p, &self.user).await.map_err(Into::into) })
    }
    fn respond<'a>(
        self: Box<Self>,
        c: &'a mut PgConnection,
        p: &'a DevicePrincipal,
        authorized: Vec<Uuid>,
    ) -> channels::Pending<'a, channels::AppleDdmReply> {
        Box::pin(async move { self.response(c, p, &authorized).await.map_err(Into::into) })
    }
}
impl Exchange {
    async fn response(
        &self,
        c: &mut PgConnection,
        p: &DevicePrincipal,
        authorized: &[Uuid],
    ) -> Result<channels::AppleDdmReply, Error> {
        // Loss of current authority exits publication ownership in this same transaction.
        retain(c, p, &self.user, authorized).await?;
        let publications = publications(c, &self.apple.protection, p, &self.user).await?;
        let set = compile(&publications, &scope(p, &self.user)?).map_err(|_| Error::Conflict)?;
        let value = match self.endpoint.as_str() {
            "tokens" => Some(set.tokens()),
            "declaration-items" => Some(set.manifest()),
            "status" => {
                return self.status(c, p, &publications).await;
            }
            path => {
                let mut parts = path.split('/');
                if parts.next() != Some("declaration") {
                    return Err(Error::Malformed);
                }
                let kind = match parts.next() {
                    Some("activation") => DeclarationKind::Activation,
                    Some("configuration") => DeclarationKind::Configuration,
                    Some("asset") => DeclarationKind::Asset,
                    Some("management") => DeclarationKind::Management,
                    _ => return Err(Error::Malformed),
                };
                let id = parts.next().ok_or(Error::Malformed)?;
                if parts.next().is_some() {
                    return Err(Error::Malformed);
                }
                set.declaration(kind, id)
            }
        };
        Ok(channels::AppleDdmReply {
            status: if value.is_some() { 200 } else { 404 },
            synchronized: Vec::new(),
            bytes: value
                .map(|v| serde_json::to_vec(&v).map_err(|_| Error::Malformed))
                .transpose()?
                .unwrap_or_default(),
        })
    }
}
