//! Retained command state for query consumers.
//! ref: rss e1b5d6b device-command-postgres/src/{store,persistence}.rs (public SQL ports).
use super::*;

impl ExecutionService {
    /// Prepare a published Windows restart without admission receipts, relay work or workers.
    #[cfg(feature = "integration")]
    pub async fn seed_published_restart_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
    ) -> Result<()> {
        self.seed_restart_in(
            tx,
            proof,
            device,
            id,
            rss_mdm_inventory::ReportSource::MdmWindows,
            dc::Event::Published,
        )
        .await
    }

    /// Retained Apple prerequisite history, already cancelled and never dispatched.
    #[cfg(feature = "integration")]
    pub async fn seed_cancelled_apple_restart_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
    ) -> Result<()> {
        self.seed_restart_in(
            tx,
            proof,
            device,
            id,
            rss_mdm_inventory::ReportSource::MdmApple,
            dc::Event::Cancel,
        )
        .await
    }

    async fn seed_restart_in(
        &self,
        tx: &mut PgTransaction<'_>,
        proof: &AuthorizedPrincipal,
        device: &str,
        id: Uuid,
        source: rss_mdm_inventory::ReportSource,
        event: dc::Event,
    ) -> Result<()> {
        let now = self.store.now(tx).await? / 1_000_000;
        let request = crate::device_control::Input {
            operation_id: id,
            action: crate::device_control::Action::Restart {},
            deadline: now + 300,
        };
        let input = request.native(source)?;
        let authority = ExecutionAuthority::for_control(
            proof.authorization()?,
            proof,
            device,
            crate::device_control::Kind::Restart,
            None,
        )?;
        let (registration, registration_generation) = storage::current_registration(
            tx,
            device,
            rss_mdm_registration_service::Purpose::Primary,
        )
        .await?;
        let (scope, coordinate) =
            storage::authority(self, tx, device, registration, registration_generation).await?;
        let spec = dc::CommandSpec::new(
            scope,
            checked_input(dc::CommandId::parse(&id.to_string()))?,
            coordinate,
            input.digest(&self.protection, self.tenant, device)?,
            input.deadline * 1_000_000,
        );
        let mut command = checked_input(dc::Command::queue(spec, now * 1_000_000))?;
        let outcome = checked_input(command.transition(event, coordinate, now * 1_000_000))?;
        if outcome != dc::Outcome::Advanced {
            return Err(Error::Conflict.into());
        }
        let record = command.record();
        let status = record.status.as_str();
        let published_at = record.published_at;
        let terminal_at = record.terminal_at;
        let message = dispatch(self.tenant, device, &input, coordinate, now)?;
        let dispatch_fingerprint = message.fingerprint().as_bytes().to_vec();
        let (metadata, sealed) = crate::input_storage::seal(
            &self.protection,
            self.tenant,
            &crate::input_storage::Identity {
                operation: id,
                device,
                registration,
                generation: registration_generation,
            },
            &input,
        )?;
        let tenant = self.tenant.to_string();
        let device = device.to_owned();
        let command_device = scope.device().as_uuid();
        let expected = record.spec.expected().as_bytes().to_vec();
        let fingerprint = Sha256::digest(checked_input(serde_json::to_vec(&request))?).to_vec();
        let authority = checked_input(serde_json::to_value(authority))?;
        tx.with_connection(move |c| Box::pin(async move {
            sqlx::query("SELECT rss_device_command.enqueue($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
                .bind(&tenant).bind(command_device.to_string()).bind(id.to_string()).bind(coordinate.generation()).bind(coordinate.epoch()).bind(expected).bind((now+300)*1_000_000).bind(now*1_000_000)
                .bind(format!("dispatch.{id}")).bind(&dispatch_fingerprint).bind(messaging_domain().as_str()).execute(&mut *c).await?;
            let saved: bool = sqlx::query_scalar("SELECT rss_device_command.save($1::uuid,$2::uuid,$3,1,$4,$5,NULL,$6)")
                .bind(&tenant).bind(command_device.to_string()).bind(id.to_string()).bind(status).bind(published_at).bind(terminal_at).fetch_one(&mut *c).await?;
            if !saved { return Err(sqlx::Error::Protocol("fixture command occupied".into())); }
            sqlx::query("INSERT INTO mdm_commands.operations(tenant_id,id,device,request,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,source_kind,input_context) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'direct',$12)")
                .bind(&tenant).bind(id).bind(device).bind(sealed).bind(fingerprint).bind(registration).bind(registration_generation).bind(coordinate.generation()).bind(coordinate.epoch()).bind(authority).bind(dispatch_fingerprint).bind(metadata).execute(&mut *c).await?;
            sqlx::query("SELECT mdm_commands.observe_query_commands($1::uuid,$2::text[],$3::bigint[])").bind(tenant).bind(vec![id.to_string()]).bind(vec![2_i64]).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
}

impl ExecutionService {
    /// Retained configuration history with distinct authenticated command identities.
    #[cfg(feature = "integration")]
    pub async fn seed_configuration_history_in(
        &self,
        tx: &mut PgTransaction<'_>,
        template: Uuid,
        ids: &[Uuid],
    ) -> Result<()> {
        let mut op = storage::load(tx, &self.protection, template).await?;
        if !matches!(
            op.authority,
            ExecutionAuthority::Policy { remove: true, .. }
        ) {
            return Err(Error::Malformed.into());
        }
        for &id in ids {
            op.request.operation_id = id;
            let (metadata, sealed) = crate::input_storage::seal(
                &self.protection,
                self.tenant,
                &crate::input_storage::Identity {
                    operation: id,
                    device: &op.device,
                    registration: op.registration,
                    generation: op.registration_generation,
                },
                &op.request,
            )?;
            let tenant = self.tenant.to_string();
            let command_device = op.scope.device().as_uuid().to_string();
            let generation = op.coordinate.generation();
            let epoch = op.coordinate.epoch();
            let expected = op
                .request
                .digest(&self.protection, self.tenant, &op.device)?
                .as_bytes()
                .to_vec();
            let deadline = op.request.deadline * 1_000_000;
            let now = self.store.now(tx).await?;
            tx.with_connection(move |c| Box::pin(async move {
                sqlx::query("SELECT rss_device_command.enqueue($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
                    .bind(&tenant).bind(&command_device).bind(id.to_string()).bind(generation).bind(epoch).bind(&expected).bind(deadline).bind(now).bind(format!("dispatch.{id}")).bind(&expected).bind(messaging_domain().as_str()).execute(&mut *c).await?;
                let saved:bool=sqlx::query_scalar("SELECT rss_device_command.save($1::uuid,$2::uuid,$3,1,'cancelled',NULL,NULL,$4)")
                    .bind(&tenant).bind(command_device).bind(id.to_string()).bind(now).fetch_one(&mut *c).await?;
                if !saved { return Err(sqlx::Error::Protocol("fixture command occupied".into())); }
                sqlx::query("INSERT INTO mdm_commands.operations(tenant_id,id,device,request,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,source_kind,policy_version,input_context) SELECT tenant_id,$3,device,$4,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,source_kind,policy_version,$5 FROM mdm_commands.operations WHERE tenant_id=$1::uuid AND id=$2")
                    .bind(tenant).bind(template).bind(id).bind(sealed).bind(metadata).execute(c).await?;
                Ok(())
            })).await?;
        }
        Ok(())
    }
}
