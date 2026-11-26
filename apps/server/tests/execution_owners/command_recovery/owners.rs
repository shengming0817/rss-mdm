//! Each native owner selects and settles its own operations on the shared RSS device store.
use super::*;
use rss_mdm_agent_wire::DeviceId;
use rss_mdm_native_protection::ProtectionContext;
use rss_mdm_recovery_credentials::native as credentials;
use rss_mdm_registration_service::installation;
use rss_mdm_software_service::deployment;

#[derive(Clone, Copy)]
enum Owner {
    Software,
    Installation,
    Credentials,
}

impl Owner {
    fn schema(self) -> &'static str {
        match self {
            Self::Software => "mdm_software_deployment",
            Self::Installation => "mdm_registration_tasks",
            Self::Credentials => "mdm_recovery_tasks",
        }
    }
    fn domain(self) -> rss_transactional_messaging::message::MessagingDomain {
        match self {
            Self::Software => deployment::messaging_domain(),
            Self::Installation => installation::messaging_domain(),
            Self::Credentials => credentials::messaging_domain(),
        }
    }
    fn scope(self, c: &Context) -> rss_reconcile::Scope {
        match self {
            Self::Software => deployment::recovery_scope(c.tenant),
            Self::Installation => installation::recovery_scope(c.tenant),
            Self::Credentials => credentials::recovery_scope(c.tenant),
        }
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    platform: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<rss_mdm_registration_service::Purpose>,
    deadline: i64,
    input_version: &'static str,
    target: Value,
}
struct Page {
    owner: Owner,
    device: DeviceId,
    command_device: Uuid,
    ids: [Uuid; 2],
}

async fn seed(h: &Harness, owner: Owner, policy: Uuid, version: Uuid) -> Result<Page> {
    let is_credential = matches!(owner, Owner::Credentials);
    let (protocol, platform) = if is_credential {
        ("apple", "macos")
    } else {
        ("windows", "windows")
    };
    let device = crate::native_identity_t2_support::seed(&h.c, protocol)
        .await?
        .device;
    let page = Page {
        owner,
        device,
        command_device: Uuid::new_v4(),
        ids: [Uuid::new_v4(), Uuid::new_v4()],
    };
    let tenant = h.c.tenant.to_string();
    let metadata = Metadata {
        platform,
        purpose: (!is_credential).then_some(rss_mdm_registration_service::Purpose::Primary),
        deadline: now() - 10,
        input_version: "1",
        target: json!({"kind":"device"}),
    };
    let grant =
        h.c.account(&[rss_mdm_authorization_service::Permission::SecurityOperate])
            .await?;
    let proof = h.c.authenticate(&grant).await?;
    let mut tx = command::seed_transaction(&h.c).await?;
    sqlx::query("INSERT INTO mdm_access.command_authorities(tenant_id,device,command_device,generation,epoch) VALUES($1::uuid,$2,$3,1,1)")
        .bind(&tenant).bind(device.into_uuid()).bind(page.command_device).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1::uuid,$2,1,1)")
        .bind(&tenant).bind(page.command_device).execute(&mut *tx).await?;
    sqlx::query(sqlx::AssertSqlSafe(format!("INSERT INTO {}.device_recovery(tenant_id,device,authority_epoch,expected_epoch,recovery_after) VALUES($1::uuid,$2,1,$3,$4)",owner.schema())))
        .bind(&tenant).bind(device.into_uuid()).bind(h.c.execution().epoch().get()).bind(Uuid::nil().to_string()).execute(&mut *tx).await?;
    for (index, id) in page.ids.into_iter().enumerate() {
        let sealed = page.sealed(h, id, &metadata)?;
        let authority = page.authority(&proof, id, policy, version)?;
        sqlx::query("INSERT INTO rss_device_command.commands(tenant_id,command_id,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,outbox_message_id,outbox_fingerprint,status,published_at,terminal_at,version) VALUES($1::uuid,$2,$3,1,1,$4,2000000,1000000,$5,$2,$4,$6,1000000,$7, $8)")
            .bind(&tenant).bind(id.to_string()).bind(page.command_device).bind([1u8;32].as_slice()).bind(owner.domain().as_str())
            .bind(if index==0 {"published"} else {"cancelled"}).bind((index==1).then_some(1000001_i64)).bind(if index==0 {2_i64} else {3}).execute(&mut *tx).await?;
        let software = matches!(owner, Owner::Software);
        let (column, param) = if software {
            (",policy_version", ",$8")
        } else {
            ("", "")
        };
        let insert = format!(
            "INSERT INTO {}.operations(expected_epoch,tenant_id,id,device,request,input_context,fingerprint,generation,epoch,authority,dispatch_fingerprint{column}) VALUES(current_setting('rss.execution_epoch')::bigint,$1::uuid,$2,$3,$4,$5,$6,1,1,$7,$6{param})",
            owner.schema()
        );
        let mut insert = sqlx::query(sqlx::AssertSqlSafe(insert))
            .bind(&tenant)
            .bind(id)
            .bind(device.into_uuid())
            .bind(sealed)
            .bind(serde_json::to_value(&metadata)?)
            .bind([1u8; 32].as_slice())
            .bind(authority);
        if software {
            insert = insert.bind(version);
        }
        insert.execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(page)
}

impl Page {
    fn authority(
        &self,
        proof: &rss_mdm_authorization_service::context::AuthorizedPrincipal,
        id: Uuid,
        policy: Uuid,
        version: Uuid,
    ) -> Result<Value> {
        Ok(match self.owner {
            Owner::Software => serde_json::to_value(deployment::authority::Authority::Software {
                origin: rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
                retirement: None,
                target: rss_mdm_policy::SoftwareTarget::WindowsX86_64,
                tenant: proof.tenant_id().to_string(),
                version,
                device: self.device,
                operation: id,
                required: vec![],
            })?,
            Owner::Installation => {
                serde_json::to_value(installation::authority::Authority::Bootstrap {
                    installation: installation::Installation {
                        id,
                        policy,
                        version,
                        device: self.device,
                        platform: rss_mdm_policy::Platform::Windows,
                        source: rss_mdm_inventory::ReportSource::MdmWindows,
                        release: Uuid::new_v4(),
                        deadline: metadata.deadline,
                        input_version: "1".into(),
                        download_origin: "https://localhost".into(),
                        origin: rss_mdm_audit_integration::activity::ActivityOrigin::Policy,
                    },
                    bootstrap: Uuid::new_v4(),
                    required: vec![],
                })?
            }
            Owner::Credentials => {
                serde_json::to_value(credentials::authority::Authority::admitted(
                    proof.authorization()?,
                    proof,
                    &self.device,
                    id,
                    vec![rss_mdm_authorization_service::Permission::SecurityOperate],
                )?)?
            }
        })
    }
    fn sealed(&self, h: &Harness, id: Uuid, metadata: &Metadata) -> Result<Vec<u8>> {
        let request = if matches!(self.owner, Owner::Credentials) {
            json!({"kind":"command","command":{"requestType":"SetRecoveryLock","fields":{"NewPassword":{"type":"string","value":"fixture-password"}}}})
        } else {
            json!({"kind":"msi","job":{"product":"{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}","version":"1.2","contentUrls":["https://localhost/test.msi"],"sha256":vec![1u8;32],"operation":id,"scope":"device","enforcement":{"commandLine":"/quiet","timeoutMinutes":5,"retryCount":1,"retryIntervalMinutes":1,"downloadFromAad":false}}})
        };
        let input = json!({"operationId":id,"inputVersion":metadata.input_version,"deadline":metadata.deadline,"target":metadata.target,"task":{"platform":metadata.platform,"request":request}});
        #[derive(serde::Serialize)]
        struct Identity {
            operation: Uuid,
            device: DeviceId,
        }
        let identity = serde_json::to_string(&Identity {
            operation: id,
            device: self.device,
        })?;
        let field = serde_json::to_string(&("native.operation.input/v1", &metadata))?;
        Ok(h.a.resources.protection.seal_bytes(
            &serde_json::to_vec(&input)?,
            &ProtectionContext::new(h.c.tenant, &identity, &field, 1)?.derive(),
        )?)
    }
    async fn apply<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
        &self,
        h: &Harness,
        worker: &R,
    ) -> Result<Option<rss_reconcile::ErrorKind>> {
        on_claim(
            h,
            self.owner.scope(&h.c),
            &self.device,
            async |claim, control, _| {
                let ReconcileStep::Ready(diff) = worker.observe(claim, control).await? else {
                    anyhow::bail!("deferred observation")
                };
                let result = worker.apply(claim, diff, control).await;
                match result {
                    Ok(ReconcileStep::Ready(())) => Ok(None),
                    Err(error) => Ok(Some(error.kind())),
                    _ => anyhow::bail!("unexpected contention"),
                }
            },
        )
        .await
    }
    async fn cursor(&self, h: &Harness) -> Result<Option<String>> {
        Ok(sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT recovery_after FROM {}.device_recovery WHERE tenant_id=$1::uuid AND device=$2",
            self.owner.schema()
        )))
        .bind(h.c.tenant.to_string())
        .bind(self.device.into_uuid())
        .fetch_one(&h.c.operator)
        .await?)
    }
    async fn assert_rejected<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
        &self,
        h: &Harness,
        worker: &R,
    ) -> Result<()> {
        assert_eq!(
            self.apply(h, worker).await?,
            Some(rss_reconcile::ErrorKind::Permanent)
        );
        assert_eq!(self.cursor(h).await?, Some(Uuid::nil().to_string()));
        assert!(
            command::recovery_fact(&h.c, self.ids[0], 3)
                .await?
                .is_none()
        );
        Ok(())
    }
    async fn wrong_device<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
        &self,
        h: &Harness,
        worker: &R,
    ) -> Result<()> {
        let tenant = h.c.tenant.to_string();
        let foreign = Uuid::new_v4();
        let mut tx = command::seed_transaction(&h.c).await?;
        sqlx::query("INSERT INTO rss_device_command.authorities(tenant_id,device_id,generation,authority_epoch) VALUES($1::uuid,$2,1,1)").bind(&tenant).bind(foreign).execute(&mut *tx).await?;
        sqlx::query("UPDATE rss_device_command.commands SET device_id=$3 WHERE tenant_id=$1::uuid AND command_id=$2").bind(&tenant).bind(self.ids[1].to_string()).bind(foreign).execute(&mut *tx).await?;
        tx.commit().await?;
        self.assert_rejected(h, worker).await?;
        let mut tx = command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE rss_device_command.commands SET device_id=$3 WHERE tenant_id=$1::uuid AND command_id=$2").bind(&tenant).bind(self.ids[1].to_string()).bind(self.command_device).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn missing<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
        &self,
        h: &Harness,
        worker: &R,
    ) -> Result<()> {
        let tenant = h.c.tenant.to_string();
        let alias = format!("unselected:{}", self.ids[1]);
        let mut tx = command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE rss_device_command.commands SET command_id=$3,outbox_domain='another.owner.v1' WHERE tenant_id=$1::uuid AND command_id=$2")
            .bind(&tenant).bind(self.ids[1].to_string()).bind(&alias).execute(&mut *tx).await?;
        tx.commit().await?;
        self.assert_rejected(h, worker).await?;
        Ok(())
    }
    async fn orphan<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
        &self,
        h: &Harness,
        worker: &R,
    ) -> Result<()> {
        let tenant = h.c.tenant.to_string();
        let alias = format!("unselected:{}", self.ids[1]);
        let mut tx = command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE rss_device_command.commands SET command_id=$2,outbox_domain=$4 WHERE tenant_id=$1::uuid AND command_id=$3")
            .bind(&tenant).bind(self.ids[1].to_string()).bind(&alias).bind(self.owner.domain().as_str()).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO rss_device_command.commands SELECT tenant_id,$3,device_id,generation,authority_epoch,expected_digest,deadline,queued_at,outbox_domain,$3,outbox_fingerprint,status,version,published_at,received_at,terminal_at FROM rss_device_command.commands WHERE tenant_id=$1::uuid AND command_id=$2")
            .bind(&tenant).bind(self.ids[1].to_string()).bind(&alias).execute(&mut *tx).await?;
        tx.commit().await?;
        self.assert_rejected(h, worker).await?;
        let mut tx = command::seed_transaction(&h.c).await?;
        sqlx::query("UPDATE rss_device_command.commands SET outbox_domain='another.owner.v1' WHERE tenant_id=$1::uuid AND command_id=$2")
            .bind(&tenant).bind(&alias).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    async fn settle<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
        &self,
        h: &Harness,
        worker: &R,
    ) -> Result<()> {
        let tenant = h.c.tenant.to_string();
        assert_eq!(self.apply(h, worker).await?, None);
        for (id, status) in self.ids.into_iter().zip(["timed_out", "cancelled"]) {
            let versions:(String,i64,i64)=sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT c.status,c.version,o.observed_command_version FROM {}.operations o JOIN rss_device_command.commands c ON (c.tenant_id,c.command_id)=(o.tenant_id,o.id::text) WHERE o.tenant_id=$1::uuid AND o.id=$2",self.owner.schema()))).bind(&tenant).bind(id).fetch_one(&h.c.operator).await?;
            assert_eq!(versions, (status.into(), 3, 3));
            assert_eq!(
                command::recovery_fact(&h.c, id, 3)
                    .await?
                    .expect("owner audit")["details"]["after"],
                status
            );
        }
        assert_eq!(self.cursor(h).await?, None);
        Ok(())
    }
    async fn verify<R: Reconciler<rss_reconcile_postgres::PgClaim, State = bool>>(
        &self,
        h: &Harness,
        worker: &R,
    ) -> Result<()> {
        let tenant = h.c.tenant.to_string();
        self.wrong_device(h, worker).await?;
        self.missing(h, worker).await?;
        self.orphan(h, worker).await?;
        self.settle(h, worker).await?;
        // Run the observed empty page through exactly the same production apply path.
        let mut tx = command::seed_transaction(&h.c).await?;
        sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE {}.device_recovery SET recovery_after=$3 WHERE tenant_id=$1::uuid AND device=$2", self.owner.schema())))
            .bind(&tenant).bind(self.device.into_uuid()).bind(self.ids[1].to_string()).execute(&mut *tx).await?;
        tx.commit().await?;
        assert_eq!(self.apply(h, worker).await?, None);
        assert_eq!(self.cursor(h).await?, None);
        Ok(())
    }
}

#[tokio::test]
#[ignore = "T2: software, installation and credential recovery settle their own mixed pages and reject a wrong device atomically"]
async fn native_owners_settle_their_selected_commands() -> Result<()> {
    with_harness(async |h| {
        let software =
            crate::assembly::software_t2::support::software(&h.c, "recovery-page").await?;
        let (policy, version) = crate::assembly::software_t2::support::policy(
            &h.c,
            &software,
            h.scope,
            rss_mdm_policy::SoftwareChannel::Mdm,
            vec![crate::assembly::software_t2::support::stage(h.scope)],
        )
        .await?;
        seed(h, Owner::Software, policy, version)
            .await?
            .verify(h, h.a.software.service.as_ref())
            .await?;
        seed(h, Owner::Installation, policy, version)
            .await?
            .verify(h, h.a.registration.native.as_ref())
            .await?;
        let s = &h.a.resources;
        let assembly = crate::assembly::credential_execution::assemble(
            s.storage.discovery_pool.clone(),
            &s.config,
            &s.background,
            s.storage.runtime.clone(),
            h.c.execution(),
            s.storage.audit.clone(),
            s.protection.clone(),
            crate::assembly::credential_owners_t2::protection(&h.c, "old")?,
            s.source.clone(),
            s.storage.reconcile.clone(),
            s.storage.worker_budget.clone(),
        )
        .await?;
        seed(h, Owner::Credentials, policy, version)
            .await?
            .verify(h, assembly.native.as_ref())
            .await?;
        drop(assembly);
        Ok(())
    })
    .await
}
