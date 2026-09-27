//! Product-owned immutable native configuration content.
use super::*;
use rss_mdm_resource as r;
async fn authored_version(
    tx: &mut PgTransaction<'_>,
    resource: &str,
    version: &str,
    enabled: bool,
) -> Result<r::Version> {
    use sha2::{Digest, Sha256};
    let id = |s: &str| checked_input(r::Id::new(s));
    let bytes = serde_json::to_vec(&serde_json::json!({"enabled":enabled}))
        .map_err(|_| Error::Malformed)?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let v = checked_input(r::Version::new(
        tx.tenant_id(),
        id(resource)?,
        id(version)?,
        r::Kind::Configuration,
        vec![
            r::Variant::new(
                r::Platform::Windows,
                r::Architecture::X86_64,
                id("domain-firewall")?,
                r::Declaration::Configuration {
                    artifact: checked_input(r::Artifact::new(
                        id("inline-domain-firewall")?,
                        bytes.len() as u64,
                        r::Digest::from_bytes(digest),
                    ))?,
                    schema: id("windows-firewall-domain-v1")?,
                    apply: id("replace")?,
                    detect: id("device-firewall-status")?,
                    remove: None,
                },
            ),
            r::Variant::new(
                r::Platform::MacOS,
                r::Architecture::X86_64,
                id("firewall-profile")?,
                r::Declaration::Configuration {
                    artifact: checked_input(r::Artifact::new(
                        id("inline-firewall-profile")?,
                        bytes.len() as u64,
                        r::Digest::from_bytes(digest),
                    ))?,
                    schema: id("apple-firewall-profile-v1")?,
                    apply: id("install-profile")?,
                    detect: id("profile-list")?,
                    remove: Some(id("remove-profile")?),
                },
            ),
            r::Variant::new(
                r::Platform::MacOS,
                r::Architecture::Aarch64,
                id("firewall-profile")?,
                r::Declaration::Configuration {
                    artifact: checked_input(r::Artifact::new(
                        id("inline-firewall-profile")?,
                        bytes.len() as u64,
                        r::Digest::from_bytes(digest),
                    ))?,
                    schema: id("apple-firewall-profile-v1")?,
                    apply: id("install-profile")?,
                    detect: id("profile-list")?,
                    remove: Some(id("remove-profile")?),
                },
            ),
        ],
    ))?;
    let tenant = tx.tenant_id().to_string();
    let resource = resource.to_owned();
    let version = version.to_owned();
    let digest = v.digest().bytes().to_vec();
    tx.with_connection(move|c|Box::pin(async move{sqlx::query("INSERT INTO mdm_planning.firewall_resources VALUES($1::uuid,$2,$3,$4,$5) ON CONFLICT DO NOTHING").bind(tenant).bind(resource).bind(version).bind(enabled).bind(digest).execute(c).await?;Ok(())})).await?;
    Ok(v)
}

pub(crate) struct FirewallAuthor;
impl crate::resource_catalog::ConfigurationAuthor for FirewallAuthor {
    fn read_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        resource: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<std::collections::BTreeMap<String, bool>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let tenant = tx.tenant_id().to_string();
            let resource = resource.to_owned();
            Ok(tx.with_connection(move|c|Box::pin(async move{sqlx::query_as::<_,(String,bool)>("SELECT version,enabled FROM mdm_planning.firewall_resources WHERE tenant_id=$1::uuid AND resource=$2").bind(tenant).bind(resource).fetch_all(c).await})).await?.into_iter().collect())
        })
    }

    fn version_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        resource: &'a str,
        version: &'a str,
        enabled: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<r::Version>> + Send + 'a>> {
        Box::pin(authored_version(tx, resource, version, enabled))
    }
}
