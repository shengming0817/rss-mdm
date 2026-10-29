use super::*;
impl Inputs {
    pub(super) async fn software_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        version: &resource::Version,
    ) -> Result<FrozenSoftwareAction> {
        self.validate_in(tx)?;
        let PublicationInput::Software {
            channel,
            binding: selection,
            delivery,
            intent,
            schedule,
            lifetime: run_lifetime_seconds,
        } = input
        else {
            return Err(Error::Malformed.into());
        };
        let binding = selection.identity();
        if version.kind() != resource::Kind::Software {
            return Err(Error::Malformed.into());
        }
        let targets = selection
            .variants
            .iter()
            .map(|(target, key)| {
                let (platform, architecture) = target.parts();
                (
                    crate::sources::software::target(platform, architecture),
                    key.clone(),
                )
            })
            .collect::<Vec<_>>();
        self.materials
            .software
            .freeze_in(
                tx,
                rss_mdm_software_service::preparation::FreezeRequest {
                    resource: binding.id(),
                    version: binding.version(),
                    digest: version.digest().bytes(),
                    uninstall: matches!(intent, SoftwareIntent::ExplicitUninstall),
                    targets: &targets,
                },
            )
            .await?;
        let mut native_packages = std::collections::BTreeMap::new();
        if *channel == rss_mdm_policy::SoftwareChannel::Mdm {
            for (target, key) in &selection.variants {
                let (platform, architecture) = crate::agent_install::resource_target(*target);
                let variant = version
                    .resolve(
                        platform,
                        architecture,
                        &resource::Id::new(key).map_err(|_| Error::Malformed)?,
                    )
                    .map_err(|_| Error::Malformed)?;
                let resource::Declaration::Software { definition } = variant.declaration() else {
                    return Err(Error::Malformed.into());
                };
                native_packages.insert(
                    *target,
                    crate::native_software::Package::compile(
                        definition,
                        self.materials.product_origin.clone(),
                    )?,
                );
            }
        }
        let action = FrozenSoftwareAction {
            native_packages,
            channel: *channel,
            delivery: (*delivery).clone(),
            resource_digest: version.digest().bytes(),
            resource: binding.id().to_owned(),
            version: binding.version().to_owned(),
            variants: selection.variants.clone(),
            intent: *intent,
            schedule: (*schedule).clone(),
            run_lifetime_seconds: *run_lifetime_seconds,
        };
        Ok(action)
    }
}
