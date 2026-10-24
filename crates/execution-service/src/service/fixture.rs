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
        let now = self.store.now(tx).await? / 1_000_000;
        let request = crate::device_control::Input {
            operation_id: id,
            action: crate::device_control::Action::Restart {},
            deadline: now + 300,
        };
        let input = request.native(rss_mdm_inventory::ReportSource::MdmWindows)?;
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
        let outcome =
            checked_input(command.transition(dc::Event::Published, coordinate, now * 1_000_000))?;
        if outcome != dc::Outcome::Advanced {
            return Err(Error::Conflict.into());
        }
        let record = command.record();
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
                .bind(&tenant).bind(command_device).bind(id.to_string()).bind(coordinate.generation()).bind(coordinate.epoch()).bind(expected).bind((now+300)*1_000_000).bind(now*1_000_000)
                .bind(format!("dispatch.{id}")).bind(&dispatch_fingerprint).bind(messaging_domain().as_str()).execute(&mut *c).await?;
            let saved: bool = sqlx::query_scalar("SELECT rss_device_command.save($1::uuid,$2::uuid,$3,1,'published',$4,NULL,NULL)")
                .bind(&tenant).bind(command_device).bind(id.to_string()).bind(now*1_000_000).fetch_one(&mut *c).await?;
            if !saved { return Err(sqlx::Error::Protocol("fixture command occupied".into()).into()); }
            sqlx::query("INSERT INTO mdm_commands.operations(tenant_id,id,device,request,fingerprint,registration,registration_generation,generation,epoch,authority,dispatch_fingerprint,source_kind,input_context) VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'direct',$12)")
                .bind(&tenant).bind(id).bind(device).bind(sealed).bind(fingerprint).bind(registration).bind(registration_generation).bind(coordinate.generation()).bind(coordinate.epoch()).bind(authority).bind(dispatch_fingerprint).bind(metadata).execute(&mut *c).await?;
            sqlx::query("SELECT mdm_commands.observe_query_commands($1::uuid,$2::text[],$3::bigint[])").bind(tenant).bind(vec![id.to_string()]).bind(vec![2_i64]).execute(c).await?;
            Ok(())
        })).await?;
        Ok(())
    }
}
