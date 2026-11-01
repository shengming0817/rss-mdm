use super::*;
use rss_mdm_agent_wire::runtime as wire;
impl Service {
    pub async fn record_access_recovery_use(
        &self,
        device: &rss_mdm_registration_service::DevicePrincipal,
        input: &wire::AccessRecoveryUse,
        audit: &RequestAudit,
    ) -> std::result::Result<(), Error> {
        let profile = self.profile();

        if device.tenant() != self.transactions.tenant {
            return Err(Error::Forbidden);
        }
        input.validate().map_err(|_| Error::Malformed)?;
        audit.operation(
            input.operation_id,
            "device_access_recovery_use",
            rss_mdm_audit_integration::AuditIntent::Management,
        );
        audit.target_device(device.device());
        transaction::run(
            &self.transactions.audit_store,
            &self.transactions.runtime,
            self.transactions.tenant,
            audit,
            (self, device, input, audit),
            |ctx, tx| {
                Box::pin(async move {
                    let (service, device, input, audit) = *ctx;

                    super::actions::agent::lock_device(profile, tx, device.device()).await?;
                    super::transaction::prepare_audit_in(
                        &service.transactions.audit_store,
                        tx,
                        audit,
                        &[],
                    )
                    .await?;
                    let p = device.clone();
                    let value = input.clone();
                    let replay = tx
                        .with_connection(move |c| {
                            Box::pin(async move {
                                Ok(crate::storage::rss_use_in(
                                    crate::Custody::new(profile, None),
                                    c,
                                    &p,
                                    &value,
                                )
                                .await)
                            })
                        })
                        .await?
                        .map_err(Error::from)?;

                    let fact = rss_mdm_audit_integration::Fact::business(
                        audit,
                        &format!(
                            "rss-login-use:{}:{}",
                            device.registration(),
                            input.operation_id
                        ),
                        200,
                        "success",
                        None,
                    )?;
                    (if replay {
                        Ok(())
                    } else {
                        service.transactions.audit_store.append_in(tx, &fact).await
                    })?;
                    Ok(())
                })
            },
        )
        .await
    }
}
