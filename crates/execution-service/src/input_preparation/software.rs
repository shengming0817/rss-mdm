use super::*;
impl Inputs {
    pub(super) async fn software_in(
        &self,
        tx: &mut PgTransaction<'_>,
        input: &PublicationInput<'_>,
        version: &resource::Version,
    ) -> Result<FrozenSoftwareAction> {
        let PublicationInput::Software {
            binding: selection,
            delivery,
            intent,
            admission: admission_operation,
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
        self.software
            .freeze_in(
                tx,
                rss_mdm_software_service::preparation::FreezeRequest {
                    resource: binding.id(),
                    version: binding.version(),
                    digest: version.digest().bytes(),
                    admission: *admission_operation,
                    uninstall: matches!(intent, SoftwareIntent::ExplicitUninstall),
                    targets: &targets,
                },
            )
            .await?;
        let action = FrozenSoftwareAction {
            delivery: (*delivery).clone(),
            resource_digest: version.digest().bytes(),
            resource: binding.id().to_owned(),
            version: binding.version().to_owned(),
            variants: selection.variants.clone(),
            admission_operation: *admission_operation,
            intent: *intent,
            schedule: (*schedule).clone(),
            run_lifetime_seconds: *run_lifetime_seconds,
        };
        Ok(action)
    }
}
