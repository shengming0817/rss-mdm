use anyhow::Context;
#[path = "windows_assets.rs"]
mod windows_assets;
use crate::test_support::agent_execution::*;
use crate::test_support::*;
use ring::signature::KeyPair;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn credential_offer_start_escrow_and_result_keep_secrets_out_of_task_history() -> Result<()> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use openssl::{encrypt::Encrypter, hash::MessageDigest, pkey::PKey, rsa::Padding};
    use rss_mdm_agent_wire::runtime as wire;
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async{
        let context=crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::Windows);
        let registration=crate::test_support::agent::seed_profile(&fixture.base,fixture.execution.clone(),case_credential(),case_device_id(),json!({"capabilities":["inventory.collect.v1","task.execute.v1","credentials.windows.v1"],"platform":"windows","architecture":"x86_64","executionContext":context})).await?;
        let device=registration["deviceId"].as_str().unwrap();
        fixture.grants.extend(identity::device_grants(Some(device),&["security_operate","credentials"])?);
        identity::set_grants(case_tenant(),&fixture.author_id,fixture.grants.clone()).await?;
        fixture.scope(case_task_scope(),json!([{"kind":"device","id":device}])).await?;
        let policy=Uuid::new_v4();
        post(&mut fixture.author,&fixture.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":case_task_scope(),"action":{"kind":"credential","operation":{"kind":"collect_bitlocker"},"architecture":"x86_64","schedule":{"trigger":{"kind":"check_in","minimumSeconds":60},"misfire":{"kind":"coalesce_one"},"notBefore":0,"until":null,"jitterSeconds":0,"window":null},"frequency":"once_per_version","runLifetimeSeconds":300}}}})).await?;
        let offered=tokio::time::timeout(Duration::from_secs(30),async{
            loop{
                let (status,value)=agent_call(&fixture.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"executionContext":context,"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":[]}))).await?;
                ensure!(status==StatusCode::OK,"credential claim: {status} {value}");
                if !value["task"].is_null(){break Ok::<_,anyhow::Error>(value["task"].clone())}
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        let signed:wire::SignedTask=serde_json::from_value(offered.clone())?;
        ensure!(matches!(signed.payload,wire::TaskPayload::Credential(_)));
        let task=signed.payload.task_id();let attempt=signed.payload.attempt_id();
        let path=format!("/api/v1/agent/runtime/tasks/{task}/events");
        for event in [json!({"kind":"received"}),json!({"kind":"start"})]{
            let (status,value)=agent_call(&fixture.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":attempt,"executionContext":context,"event":event}))).await?;
            ensure!(status==StatusCode::OK,"credential start: {status} {value}");
        }
        let wire::TaskPayload::Credential(spec)=signed.payload else{unreachable!()};
        let mut materials=Vec::new();let mut secrets=Vec::new();
        for index in 0..2u8{
            let subject=wire::CredentialSubject::Bitlocker{volume:format!("\\\\?\\Volume{{{}}}\\",Uuid::new_v4()),protector:Uuid::new_v4()};
            let secret=std::iter::repeat_n(if index==0{"111111"}else{"222222"},8).collect::<Vec<_>>().join("-");
            let aad=spec.material_aad(&subject,0)?;let key=[index+7;32];let nonce=[index+1;12];
            let public=PKey::public_key_from_der(&STANDARD.decode(&spec.recipient.public_key)?)?;
            let mut encrypt=Encrypter::new(&public)?;encrypt.set_rsa_padding(Padding::PKCS1_OAEP)?;encrypt.set_rsa_oaep_md(MessageDigest::sha256())?;encrypt.set_rsa_mgf1_md(MessageDigest::sha256())?;
            let mut wrapped=vec![0;encrypt.encrypt_len(&key)?];let length=encrypt.encrypt(&key,&mut wrapped)?;wrapped.truncate(length);
            let aead=ring::aead::LessSafeKey::new(ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM,&key).map_err(|_|anyhow::anyhow!("test key"))?);
            let mut ciphertext=secret.as_bytes().to_vec();aead.seal_in_place_append_tag(ring::aead::Nonce::assume_unique_for_key(nonce),ring::aead::Aad::from(aad),&mut ciphertext).map_err(|_|anyhow::anyhow!("test encryption"))?;
            materials.push(wire::CredentialEnvelope{subject,expected_revision:0,wrapped_key:STANDARD.encode(wrapped),nonce,ciphertext:STANDARD.encode(ciphertext)});secrets.push(secret);
        }
        let mut tampered=materials.clone();tampered[1].subject=wire::CredentialSubject::Bitlocker{volume:format!("\\\\?\\Volume{{{}}}\\",Uuid::new_v4()),protector:Uuid::new_v4()};
        let event=wire::TaskEvent::CredentialEscrow(wire::CredentialEscrow{definition_digest:spec.definition_digest,materials:tampered});
        let rejected=agent_call(&fixture.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":attempt,"executionContext":context,"event":event}))).await?;
        ensure!(!rejected.0.is_success());
        ensure!(pg(&format!("SELECT count(*) FROM mdm_recovery.versions WHERE tenant_id='{}' AND operation='{task}'",case_tenant()))?.trim()=="0");
        let event=wire::TaskEvent::CredentialEscrow(wire::CredentialEscrow{definition_digest:spec.definition_digest,materials:materials.clone()});
        let input=json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":attempt,"executionContext":context,"event":event});
        let first=agent_call(&fixture.router,Method::POST,&path,Some(case_credential()),Some(input.clone())).await?;
        ensure!(first.0==StatusCode::OK,"escrow: {first:?}");
        ensure!(agent_call(&fixture.router,Method::POST,&path,Some(case_credential()),Some(input)).await?==first);
        let event=wire::TaskEvent::CredentialResult(wire::CredentialResult{definition_digest:spec.definition_digest,complete:true,failure:None,items:materials.iter().map(|m|wire::CredentialItemResult{subject:m.subject.clone(),outcome:wire::CredentialOutcome::Verified}).collect()});
        let complete=agent_call(&fixture.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":attempt,"executionContext":context,"event":event}))).await?;
        ensure!(complete.0==StatusCode::OK,"credential completion: {complete:?}");
        let history=pg(&format!("SELECT coalesce(result::text,'') FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{task}'",case_tenant()))?;
        for secret in secrets{ensure!(!history.contains(&secret));}
        ensure!(pg(&format!("SELECT count(*) FROM mdm_recovery.versions WHERE tenant_id='{}' AND operation='{task}' AND validity='verified'",case_tenant()))?.trim()=="2");
        Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn registration_capability_and_wire_gate() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let router = fixture.router;
    let registration=crate::test_support::agent::seed_profile(&fixture.base,fixture.execution.clone(),case_inventory_credential(),case::name("inventory-peer"),json!({"capabilities":["inventory.collect.v1"],"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)})).await?;
    ensure!(registration["capabilities"] == json!(["inventory.collect.v1"]));
    let taskless = agent_call(
        &router,
        Method::POST,
        "/api/v1/agent/runtime/tasks/claim",
        Some(case_inventory_credential()),
        Some(json!({"wireVersion":1,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"],"operationId":Uuid::new_v4()})),
    )
    .await?;
    ensure!(
        taskless.0 == StatusCode::FORBIDDEN,
        "inventory-only registration entered task API: {taskless:?}"
    );
    let registration=crate::test_support::agent::seed_profile(&fixture.base,fixture.execution.clone(),case_credential(),case_device_id(),json!({"capabilities":["inventory.collect.v1","task.execute.v1"],"platform":"macos","architecture":"aarch64","executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs)})).await?;
    ensure!(registration["capabilities"] == json!(["inventory.collect.v1", "task.execute.v1"]));
    // Legacy URL and major cannot enter task intake.
    let old = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/agent/v2/tasks/claim")
                .header("host", "mdm.example.test")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(old.status() == StatusCode::NOT_FOUND);
    let operation = Uuid::new_v4();
    let valid = json!({"wireVersion":1,"operationId":operation,"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"environment":{"edition":null,"tools":{},"nativeEngines":{}},"profiles":["posix_sh","bash","power_shell7","osquery"]});
    {
        let version = 2;
        let mut retired = valid.clone();
        retired["wireVersion"] = json!(version);
        ensure!(
            agent_call(
                &router,
                Method::POST,
                "/api/v1/agent/runtime/tasks/claim",
                Some(case_credential()),
                Some(retired)
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    ensure!(
        agent_call(
            &router,
            Method::POST,
            "/api/v1/agent/runtime/tasks/claim",
            Some(case_credential()),
            Some(valid)
        )
        .await?
        .0 == StatusCode::OK
    );
    Ok(())
    }).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn offer_start_result_replay_and_inventory_projection() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    let registration = fixture.register().await?;
    let (id, _bytes, _definition) = fixture.resource().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    let base = fixture.base;
    let router = fixture.router;
    let execution = fixture.execution;
    let mut author = fixture.author;
    let key = fixture.key;
    let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
    let policy_id = publish(&mut author, &router, id).await?;
    let first = claim_request(&router, Uuid::new_v4()).await?;
    ensure!(first.0 == StatusCode::OK, "lazy acceptance: {first:?}");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE v.policy='{policy_id}'"))?.trim()=="1");
    tokio::time::timeout(Duration::from_secs(15),async {loop {
        if pg(&format!("SELECT gateway_accepted FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON v.id=r.policy_version WHERE v.policy='{policy_id}'"))?.trim()=="t" {break Ok::<_,anyhow::Error>(());}
        tokio::time::sleep(Duration::from_millis(50)).await;
    }}).await??;
    if !first.1["task"].is_null() {
        pg(&format!(
            "UPDATE mdm_commands.action_runs SET state=jsonb_set(state,'{{delivery,leaseUntil}}','0') WHERE tenant_id='{}' AND id='{}'",
            case_tenant(),
            first.1["task"]["payload"]["task"]["taskId"]
                .as_str()
                .unwrap()
        ))?;
    }
    let claim_operation = Uuid::new_v4();
    execution.inject_fault(rss_transactional_messaging_postgres::PgTransactionFault::CommitPending);
    ensure!(
        claim_request(&router, claim_operation).await?.0 == StatusCode::SERVICE_UNAVAILABLE,
        "claim commit-pending fault was not surfaced"
    );
    let claim_response = claim_request(&router, claim_operation).await?;
    ensure!(claim_response.0 == StatusCode::OK && !claim_response.1["task"].is_null());
    ensure!(
        claim_response == claim_request(&router, claim_operation).await?,
        "claim retry receipt changed"
    );
    let task = claim_response.1["task"].clone();
    let signed: rss_mdm_agent_wire::runtime::SignedTask = serde_json::from_value(task.clone())?;
    let context = crate::test_support::task_signature::TaskVerification {
        key_id: "t2",
        public_key: key.public_key().as_ref(),
        tenant_id: Uuid::parse_str(case_tenant())?,
        device_id: case_device_id(),
        platform: rss_mdm_agent_wire::runtime::TaskPlatform::Macos,
        architecture: rss_mdm_agent_wire::runtime::TaskArchitecture::Aarch64,
        registration_id: Uuid::parse_str(registration["registrationId"].as_str().unwrap())?,
        generation: registration["generation"].as_u64().unwrap(),
        task_id: signed.payload.task_id(),
        attempt_id: signed.payload.attempt_id(),
        permit: rss_mdm_agent_wire::runtime::TaskPermit::Offer,
        now,
    };
    crate::test_support::task_signature::verify(&signed, &context)?;
    let attempt = signed.payload.attempt_id();
    let reserved = pg(&format!(
        "SELECT sequence FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}' AND result='pending' AND sealed_at IS NULL",
        case_tenant()
    ))?;
    ensure!(
        !reserved.trim().is_empty(),
        "collection was not frozen before Offer"
    );
    let event_operation = Uuid::new_v4();
    {
        let version = 2;
        let retired = json!({"wireVersion":version,"operationId":event_operation,"attemptId":task["payload"]["task"]["attemptId"],"executionContext":crate::test_support::software_execution::context(crate::test_support::software_execution::Platform::MacOs),"event":{"kind":"received"}});
        ensure!(
            agent_call(
                &router,
                Method::POST,
                &format!(
                    "/api/v1/agent/runtime/tasks/{}/events",
                    task["payload"]["task"]["taskId"].as_str().unwrap()
                ),
                Some(case_credential()),
                Some(retired)
            )
            .await?
            .0 == StatusCode::BAD_REQUEST
        );
    }
    task_event(&router, &task, json!({"kind":"received"})).await?;
    let permit = task_event(&router, &task, json!({"kind":"start"})).await?;
    let ack: rss_mdm_agent_wire::runtime::TaskEventAck = serde_json::from_value(permit)?;
    crate::test_support::task_signature::verify(
        &ack.into_permit().unwrap(),
        &crate::test_support::task_signature::TaskVerification {
            permit: rss_mdm_agent_wire::runtime::TaskPermit::Start,
            ..context
        },
    )?;
    let result_operation = Uuid::new_v4();
    let mut result = json!({"kind":"result","exitCode":0,"quality":"complete","output":{"version":"1.2","healthy":true}});
    execution.inject_fault(
        rss_transactional_messaging_postgres::PgTransactionFault::CommitUnknownAfterAck,
    );
    ensure!(
        task_event_request(&router, &task, result_operation, &mut result)
            .await?
            .0
            == StatusCode::SERVICE_UNAVAILABLE,
        "result commit-unknown fault was not surfaced"
    );
    let accepted = task_event_request(&router, &task, result_operation, &mut result).await?;
    ensure!(accepted.0 == StatusCode::OK);
    ensure!(
        accepted == task_event_request(&router, &task, result_operation, &mut result).await?,
        "result retry receipt changed"
    );
    let mut conflict = result.clone();
    conflict["output"]["version"] = json!("different");
    ensure!(
        task_event_request(&router, &task, result_operation, &mut conflict)
            .await?
            .0
            == StatusCode::CONFLICT,
        "result operation accepted conflicting payload"
    );
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM mdm_commands.action_receipts WHERE id='{result_operation}'"
        ))?
        .trim()
            == "1"
    );
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{}' AND registration='{}' AND source='agent.script' AND delivery_pending", case_tenant(), registration["registrationId"].as_str().unwrap()))?.trim()=="1");
    ensure!(
        pg(&format!(
            "SELECT count(*) FROM rss_device_command.commands WHERE command_id='{}'",
            signed.payload.task_id()
        ))?
        .trim()
            == "0"
    );
    ensure!(
        pg(&format!(
            "SELECT sequence FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}' AND result='snapshot'",
            case_tenant()
        ))? == reserved,
        "result changed collection ordering"
    );
    let runtime = agent_runtime(&base).await?;
    let inventory = crate::inventory_runtime::test_support::start(runtime.clone()).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if pg(
                &format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.script' AND state='known'", case_tenant(), registration["registrationId"].as_str().unwrap()),
            )?
            .trim()
                == "2"
            {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let (_, detail) = author
        .call(
            &router,
            Method::GET,
            &format!(
                "/api/v1/devices/{DEVICE_ID}/inventory",
                DEVICE_ID = case_device_id()
            ),
            None,
        )
        .await?;
    ensure!(
        detail["asset"]["device"]["fields"]["custom.corporate_agent.healthy"]["state"]["value"]["value"]
            == true,
        "detail: {detail}"
    );
    crate::test_support::stop_worker(inventory).await?;
    runtime.close_fixture().await?;
    crate::test_support::stop_worker(stack).await?;
    Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn chunked_results_require_complete_output_and_preserve_attempt_identity() -> Result<()> {
    use rss_mdm_agent_wire::runtime as wire;
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    fixture.register().await?;
    let (resource, _, _) = fixture.resource_with_output_limit(524288).await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    let policy = publish(&mut fixture.author, &fixture.router, resource).await?;
    let task = claim(&fixture.router).await?;
    task_event(&fixture.router, &task, json!({"kind":"received"})).await?;
    task_event(&fixture.router, &task, json!({"kind":"start"})).await?;
    let result = wire::TaskResult::new(
        Some(0),
        wire::OutputQuality::Complete,
        json!({"version":"1.2","healthy":true,"padding":"x".repeat(400000)}),
        wire::TaskDiagnostics::new("".into(), "".into(), 1, 1, None)?,
        2,
    )?;
    let (reference, chunks) = wire::ChunkedTaskResult::split(result)?;
    ensure!(chunks.len() == 2);
    let mut final_event = serde_json::to_value(wire::TaskEvent::ChunkedResult(reference))?;
    ensure!(
        task_event_request(&fixture.router, &task, Uuid::new_v4(), &mut final_event)
            .await?
            .0
            == StatusCode::BAD_REQUEST,
        "missing output was accepted"
    );
    let operation = Uuid::new_v4();
    let mut first = serde_json::to_value(wire::TaskEvent::OutputChunk(chunks[0].clone()))?;
    let response = task_event_request(&fixture.router, &task, operation, &mut first).await?;
    ensure!(response.0 == StatusCode::OK);
    ensure!(response == task_event_request(&fixture.router, &task, operation, &mut first).await?);
    let bad = wire::OutputChunk::new(
        chunks[0].manifest().clone(),
        0,
        &vec![b'z'; wire::OUTPUT_CHUNK_BYTES],
    )?;
    let mut conflict = serde_json::to_value(wire::TaskEvent::OutputChunk(bad))?;
    ensure!(
        task_event_request(&fixture.router, &task, Uuid::new_v4(), &mut conflict)
            .await?
            .0
            == StatusCode::CONFLICT
    );
    task_event(
        &fixture.router,
        &task,
        serde_json::to_value(wire::TaskEvent::OutputChunk(chunks[1].clone()))?,
    )
    .await?;
    task_event(&fixture.router, &task, final_event).await?;
    let attempt = task["payload"]["task"]["attemptId"].as_str().unwrap();
    ensure!(pg(&format!("SELECT count(*) FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}' AND result='snapshot'",case_tenant()))?.trim()=="1");
    ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.output_chunks WHERE tenant_id='{}' AND attempt='{attempt}'",case_tenant()))?.trim()=="2");
    let task_id = task["payload"]["task"]["taskId"].as_str().unwrap();
    let detail = fixture.author.call(&fixture.router, Method::GET, &format!("/api/v1/policies/{policy}/runs/{task_id}"), None).await?;
    ensure!(detail.0 == StatusCode::OK && detail.1["taskId"] == task_id);
    ensure!(detail.1["result"]["output"]["version"] == "1.2" && detail.1["result"]["output"]["healthy"] == true);
    crate::test_support::stop_worker(stack).await?;
    Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn collection_structure_budget_precedes_partial_field_acceptance() -> Result<()> {
    use rss_mdm_agent_wire::runtime as wire;
    let mut fixture = Fixture::new().await?;
    let resources = std::mem::take(&mut fixture.resources);
    resources.finish(async {
    fixture.register().await?;
    fixture
        .scope(
            case_task_scope(),
            json!([{"kind":"device","id":case_device_id()}]),
        )
        .await?;
    let stack = worker(&fixture.base).await?;
    for mode in ["direct", "chunked", "truncated", "partial"] {
        let (resource, _, _) = fixture.resource_with_output_limit(524288).await?;
        publish(&mut fixture.author, &fixture.router, resource).await?;
        let task = claim(&fixture.router).await?;
        task_event(&fixture.router, &task, json!({"kind":"received"})).await?;
        task_event(&fixture.router, &task, json!({"kind":"start"})).await?;
        let output = if mode == "partial" {
            json!({"healthy":true})
        } else if mode == "truncated" {
            json!({"version":"1.2","healthy":true})
        } else {
            json!({"version":"1.2","healthy":true,"items":[{"id":"a"},{"id":"b"}]})
        };
        let (quality, failure) = if mode == "truncated" {
            (
                wire::OutputQuality::Truncated,
                Some(wire::TaskFailure::OutputLimit),
            )
        } else {
            (wire::OutputQuality::Complete, None)
        };
        let result = wire::TaskResult::new(
            Some(0),
            quality,
            output,
            wire::TaskDiagnostics::new("".into(), "".into(), 1, 1, failure)?,
            2,
        )?;
        let event = if mode == "chunked" {
            let (reference, chunks) = wire::ChunkedTaskResult::split(result)?;
            for chunk in chunks {
                task_event(
                    &fixture.router,
                    &task,
                    serde_json::to_value(wire::TaskEvent::OutputChunk(chunk))?,
                )
                .await?;
            }
            wire::TaskEvent::ChunkedResult(reference)
        } else {
            wire::TaskEvent::Result(result)
        };
        // A budget violation is a terminal failed collection, never a trusted partial
        // snapshot or an endlessly retried transport rejection.
        task_event(&fixture.router, &task, serde_json::to_value(event)?).await?;
        let attempt = task["payload"]["task"]["attemptId"].as_str().unwrap();
        let expected = if mode == "partial" {
            "partial"
        } else {
            "failed"
        };
        ensure!(pg(&format!("SELECT result FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}'",case_tenant()))?.trim()==expected,"invalid collection outcome: {mode}");
        if mode == "partial" {
            let fields: Value = serde_json::from_str(pg(&format!("SELECT attempts::jsonb->'fields' FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{attempt}'", case_tenant()))?.trim())?;
            ensure!(fields["custom.corporate_agent.healthy"]["quality"] == "success");
            ensure!(fields["custom.corporate_agent.version"]["quality"] == "missing");
        }
        if mode != "partial" {
            let id = task["payload"]["task"]["taskId"].as_str().unwrap();
            ensure!(pg(&format!("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?.trim()=="failed");
            ensure!(pg(&format!("SELECT result->>'trusted' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{id}'",case_tenant()))?.trim()=="false");
        }
    }
    crate::test_support::stop_worker(stack).await?;
    Ok(())
    }).await
}

/// Synthetic protocol fixture: proves server HTTP/PG semantics, not Windows execution.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn native_inventory_only_partial_empty_chunked_and_revoked() -> Result<()> {
    native_inventory_case(
        "windows",
        Some("device.software.installations"),
        rss_mdm_agent_wire::runtime::NativeQueryStatus::Complete,
        &[0, 1, 2, 3],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn native_unmapped_evidence_requires_sensitive_permission() -> Result<()> {
    native_inventory_case(
        "windows",
        None,
        rss_mdm_agent_wire::runtime::NativeQueryStatus::Complete,
        &[0, 1, 2, 3],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn native_all_query_failures_preserve_execution_completion() -> Result<()> {
    native_inventory_case(
        "windows",
        None,
        rss_mdm_agent_wire::runtime::NativeQueryStatus::Denied,
        &[0],
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery"]
async fn macos_native_mapping_and_context_recheck() -> Result<()> {
    native_inventory_case(
        "macos",
        Some("device.software.receipts"),
        rss_mdm_agent_wire::runtime::NativeQueryStatus::Complete,
        &[0, 1, 2, 3],
    )
    .await
}

#[allow(
    clippy::cognitive_complexity,
    reason = "shared HTTP scenario retains distinct authorization, quality and transport assertions"
)]
async fn native_inventory_case(
    platform: &str,
    mapped_software: Option<&str>,
    status: rss_mdm_agent_wire::runtime::NativeQueryStatus,
    stages: &[i32],
) -> Result<()> {
    use rss_mdm_agent_wire::runtime as w;
    use rss_mdm_resource as r;
    use sha2::{Digest, Sha256};
    let macos = platform == "macos";
    let map_software = mapped_software.is_some();
    let all_failed = status != w::NativeQueryStatus::Complete;
    let software_field = if macos {
        "device.software.receipts"
    } else {
        "device.software.installations"
    };
    let large_raw = !macos && map_software;
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    f.grants
        .retain(|g| g.operation != crate::authorization::Permission::ScriptExecute);
    f.grants
        .extend(crate::test_support::identity::device_grants(
            None,
            &["inventory_collect", "operation_read"],
        )?);
    f.grants.push(crate::authorization::Grant {
        operation: crate::authorization::Permission::InventorySensitiveRead,
        scope: crate::authorization::Scope::Tenant,
    });
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let context = crate::test_support::software_execution::context(if macos {
        crate::test_support::software_execution::Platform::MacOs
    } else {
        crate::test_support::software_execution::Platform::Windows
    });
    let registration=crate::test_support::agent::seed_profile(&f.base,f.execution.clone(),case_credential(),case_device_id(),json!({"capabilities":["inventory.collect.v1","inventory.native.v1"],"platform":platform,"architecture":"x86_64","executionContext":context})).await?;
    let device = registration["deviceId"].as_str().unwrap().to_owned();
    f.scope(case_task_scope(), json!([{"kind":"device","id":device}]))
        .await?;
    let mut specs = Vec::new();
    for id in if macos {
        [
            "macos.agent.memory",
            "macos.agent.network",
            "macos.agent.receipts",
        ]
    } else {
        [
            "windows.agent.memory",
            "windows.agent.network",
            "windows.agent.software",
        ]
    } {
        let r::blueprints::Definition::AgentCollection { template } = r::blueprints::get(
            id,
            if id == "windows.agent.software" {
                "2"
            } else {
                "1"
            },
        )
        .unwrap()
        .definition
        else {
            unreachable!()
        };
        specs.push(template.spec().clone());
    }
    if !macos {
        let r::blueprints::Definition::AgentCollection { template } =
            r::blueprints::get("windows.agent.identity", "2")
                .unwrap()
                .definition
        else {
            unreachable!()
        };
        specs.push(template.spec().clone());
    }
    if !large_raw {
    for (id, name) in if macos {
        [("sys_security","macos.agent.gatekeeper"),("sys_accounts","macos.agent.accounts"),("sys_certificates","macos.agent.certificates_system"),("sys_updates","macos.agent.updates_available_local")]
    } else {
        [("sys_security","windows.agent.defender"),("sys_accounts","windows.agent.accounts"),("sys_certificates","windows.agent.certificates_device_my"),("sys_updates","windows.agent.updates_available_local")]
    } {
        let r::blueprints::Definition::AgentCollection {template}=r::blueprints::get(name,"1").unwrap().definition else {unreachable!()};
        let mut spec=template.spec().clone();let mut plan=spec.plan.spec().clone();
        let query=plan.queries.remove("facts").unwrap();plan.queries.insert(id.into(),query);
        spec.plan=w::NativeCollectionPlan::new(plan)?;
        for mapping in spec.mappings.values_mut() {mapping.query=id.into();}
        specs.push(spec);
    }
    }
    let mut ps = specs[0].plan.spec().clone();
    let mut mappings = specs[0].mappings.clone();
    for spec in &specs[1..] {
        ps.queries.extend(spec.plan.spec().queries.clone());
        mappings.extend(spec.mappings.clone());
    }
    if !map_software {
        mappings.remove(software_field);
    }
    if !large_raw {
        ps.budget.output_bytes=w::NATIVE_SYSTEM_MAX_BYTES;
        for q in ps.queries.values_mut() {q.budget.output_bytes=q.budget.output_bytes.min(w::NATIVE_SYSTEM_MAX_BYTES);}
    }
    let definition = r::AgentCollectionDefinition::new(r::AgentCollectionSpec {
                applicability: specs.last().unwrap().applicability.clone(),
        plan: w::NativeCollectionPlan::new(ps)?,
        mappings,
    })?;
    let resource_id = Uuid::new_v4();
    let bytes = definition.canonical();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        0,
        json!({"action":"create","kind":"agent_collection"}),
    )
    .await?;
    resource(&mut f.author,&f.router,resource_id,1,json!({"action":"version","version":"v1","kind":"agent_collection","variants":[{"platform":platform,"architecture":"x86_64","key":"default","declaration":{"kind":"agent_collection","artifact":{"reference":"native.json","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(
        upload_for(
            &f.author,
            &f.router,
            resource_id,
            &bytes,
            platform,
            "x86_64"
        )
        .await?
            == StatusCode::CREATED
    );
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let worker = worker(&f.base).await?;
    let runtime = agent_runtime(&f.base).await?;
    let inventory = crate::inventory_runtime::test_support::start(runtime.clone()).await?;
    let claim_input = |engines: Value| json!({"wireVersion":1,"operationId":Uuid::new_v4(),"profiles":[],"environment":{"edition":null,"tools":{},"nativeEngines":engines},"executionContext":context});
    let policy_input = || json!({"scope":case_task_scope(),"action":{"kind":"agent_collection","resource":{"id":resource_id,"version":"v1","platform":platform,"architecture":"x86_64","variant":"default"},"runLifetimeSeconds":300}});
    let mut prior_network = String::new();
    let mut prior_software = String::new();
    let mut prior_updates = Value::Null;
    for &stage in stages {
        let policy = Uuid::new_v4();
        if !map_software && stage == 0 {
        let ordinary = f
            .grants
            .iter()
            .filter(|g| g.operation != crate::authorization::Permission::InventorySensitiveRead)
            .cloned()
            .collect();
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, ordinary).await?;
        let denied = f.author.call(&f.router, Method::POST, &format!("/api/v1/policies/{policy}"), Some(json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_input()}}))).await?;
        ensure!(
            denied.0 == StatusCode::FORBIDDEN,
            "raw evidence publication bypass: {denied:?}"
        );
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
            .await?;
        }
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":policy_input()}})).await?;
        if large_raw && stage == 0 {
        let unsupported = agent_call(
            &f.router,
            Method::POST,
            "/api/v1/agent/runtime/tasks/claim",
            Some(case_credential()),
            Some(claim_input(json!({}))),
        )
        .await?;
        ensure!(
            unsupported.0 == StatusCode::OK && unsupported.1["task"].is_null(),
            "unsupported native claim: {unsupported:?}"
        );
        }
        let task = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let response = agent_call(
                    &f.router,
                    Method::POST,
                    "/api/v1/agent/runtime/tasks/claim",
                    Some(case_credential()),
                    Some(claim_input(if macos {
                        json!({"macos.hardware":1,"macos.pkg_receipts":1,"macos.security":1,"macos.accounts":1,"macos.certificates":1,"macos.updates":1})
                    } else {
                        json!({"windows.wmi":1,"windows.registry":1,"windows.network":1,"windows.software":1,"windows.security":1,"windows.accounts":1,"windows.certificates":1,"windows.updates":1})
                    })),
                )
                .await?;
                ensure!(response.0 == StatusCode::OK, "native claim: {response:?}");
                if !response.1["task"].is_null() {
                    break Ok::<_, anyhow::Error>(serde_json::from_value::<w::SignedTask>(
                        response.1["task"].clone(),
                    )?);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let w::TaskPayload::Collection(spec) = &task.payload else {
            anyhow::bail!("native policy issued another task family");
        };
        let path = format!("/api/v1/agent/runtime/tasks/{}/events", spec.task_id);
        let event = |operation, event: Value| json!({"wireVersion":1,"operationId":operation,"attemptId":spec.attempt_id,"executionContext":context,"event":event});
        let received = agent_call(
            &f.router,
            Method::POST,
            &path,
            Some(case_credential()),
            Some(event(Uuid::new_v4(), json!({"kind":"received"}))),
        )
        .await?;
        ensure!(received.0 == StatusCode::OK);
        if stage == 3 {
            let grants = f
                .grants
                .iter()
                .filter(|g| {
                    g.operation
                        != if map_software {
                            crate::authorization::Permission::InventoryCollect
                        } else {
                            crate::authorization::Permission::InventorySensitiveRead
                        }
                })
                .cloned()
                .collect();
            if !macos {
                crate::test_support::identity::set_grants(case_tenant(), &f.author_id, grants)
                    .await?;
            }
            let mut start = event(Uuid::new_v4(), json!({"kind":"start"}));
            if macos {
                start["executionContext"]["revision"] =
                    json!(context["revision"].as_u64().unwrap() + 1);
            }
            let denied = agent_call(
                &f.router,
                Method::POST,
                &path,
                Some(case_credential()),
                Some(start),
            )
            .await?;
            ensure!(
                denied.0 == StatusCode::FORBIDDEN,
                "revoked native Start: {denied:?}"
            );
            break;
        }
        let started = agent_call(
            &f.router,
            Method::POST,
            &path,
            Some(case_credential()),
            Some(event(Uuid::new_v4(), json!({"kind":"start"}))),
        )
        .await?;
        ensure!(started.0 == StatusCode::OK, "native Start: {started:?}");
        let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        let mut queries = std::collections::BTreeMap::new();
        for (id, q) in &spec.plan.spec().queries {
            let rows = if id.starts_with("sys_") {
                if stage>=2 {vec![]} else {vec![serde_json::from_value(match id.as_str() {
                    "sys_security"=>if macos {json!({"presence":"present","configured":"enabled","running":"unknown","version":"1"})}else{json!({"presence":"present","configured":"enabled","running":"disabled","mode":"passive","health":"passive","signature_version":"1"})},
                    "sys_accounts"=>if macos {json!({"id":"00000000-0000-0000-0000-000000000501","uid":501,"name":"sensitive-account","account_type":"local","enabled":"enabled"})}else{json!({"id":"S-1-5-21-1-2-3-1001","name":"sensitive-account","account_type":"local","enabled":"enabled"})},
                    "sys_certificates"=>json!({"id":"a".repeat(64),"subject":"CN=sensitive-certificate","issuer":"CN=CA","not_before":1,"not_after":2000000000,"scope":"device","owner":"","store":if macos {"system"}else{"my"}}),
                    "sys_updates"=>json!({"id":if stage==0 {"update-1"}else{"must-not-replace"},"title":if stage==0 {"Update"}else{"Truncated update"},"version":"1","origin":"configured","state":"available"}),
                    _=>unreachable!(),
                })?]}
            } else if !macos && let Some(rows) = windows_assets::rows(id, stage) {
                rows
            } else if id == "memory" {
                vec![
                    [(
                        if macos {
                            "total_bytes"
                        } else {
                            "TotalPhysicalMemory"
                        }
                        .into(),
                        json!((8192 + stage).to_string()),
                    )]
                    .into(),
                ]
            } else if stage == 2 || stage >= 4 {
                vec![]
            } else if id == "software" || id == "receipts" {
                (0..if stage == 0 { 2 } else { 1 })
                    .map(|i| {
                        [
                            ("id".into(), json!(format!("app-{i}"))),
                            ("native_id".into(), json!(format!("native-{i}"))),
                            (
                                "name".into(),
                                json!(if stage == 0 {
                                    "private-software"
                                } else {
                                    "partial-software"
                                }),
                            ),
                            ("version".into(), json!("1.0")),
                            ("publisher".into(), json!("Acme")),
                            ("scope".into(), json!(if macos { "device" } else { "user" })),
                            (
                                "owner".into(),
                                json!(if macos {
                                    String::new()
                                } else {
                                    format!("S-1-5-21-1-2-3-{}", 1001 + i)
                                }),
                            ),
                            (
                                "origin".into(),
                                json!(if macos { "pkg_receipt" } else { "registry" }),
                            ),
                            ("location".into(), json!("C:\\Apps")),
                        ]
                        .into()
                    })
                    .collect()
            } else if stage == 0 && large_raw {
                (0..24)
                    .map(|i| {
                        [
                            ("id".into(), json!(format!("nic{i}"))),
                            ("name".into(), json!("private-native-evidence")),
                            ("addresses".into(), json!(vec!["x".repeat(220); 64])),
                        ]
                        .into()
                    })
                    .collect()
            } else {
                vec![
                    [
                        ("id".into(), json!("nic0")),
                        ("name".into(), json!("changed-truncated")),
                        ("addresses".into(), json!(["192.0.2.99"])),
                    ]
                    .into(),
                ]
            };
            queries.insert(
                id.clone(),
                w::NativeQueryResult {
                    scan: (id=="sys_updates").then(||w::NativeScanEvidence {mode:w::UpdateScanMode::Local,source:Some("configured".into()),started_at:Some(now-10),finished_at:Some(now-5)}),
                    query_digest: q.digest(),
                    collected_at: now,
                    status: if all_failed { status } else if stage == 1 && (id == "network" || id == "receipts" || id.starts_with("sys_")) {
                        w::NativeQueryStatus::Truncated
                    } else { w::NativeQueryStatus::Complete },
                    enumeration_complete: !(stage == 1 && id == "network"),
                    row_count: rows.len() as u32,
                    rows,
                    users: (id == "software").then(|| {
                        let expected: std::collections::BTreeSet<_> = [
                            "S-1-5-21-1-2-3-1001".to_owned(),
                            "S-1-5-21-1-2-3-1002".to_owned(),
                        ]
                        .into();
                        w::NativeUserCoverage {
                            enumeration_complete: true,
                            observed: expected.clone(),
                            completed: if stage == 1 {
                                ["S-1-5-21-1-2-3-1001".to_owned()].into()
                            } else {
                                expected.clone()
                            },
                            expected,
                        }
                    }),
                },
            );
        }
        let result = w::NativeCollectionResult {
            plan_digest: spec.plan_digest,
            collected_at: now,
            queries,
        };
        let body = serde_json::to_vec(&result)?;
        let manifest = w::OutputManifest::new(body.len() as u32, Sha256::digest(&body).into())?;
        let terminal = serde_json::to_value(w::TaskEvent::ChunkedCollectionResult {
            manifest: manifest.clone(),
        })?;
        if large_raw && stage == 0 {
        let missing = agent_call(
            &f.router,
            Method::POST,
            &path,
            Some(case_credential()),
            Some(event(Uuid::new_v4(), terminal.clone())),
        )
        .await?;
        ensure!(
            missing.0 == StatusCode::BAD_REQUEST,
            "missing native chunks: {missing:?}"
        );
            ensure!(body.len() > 256 * 1024);
        }
        let terminal = if large_raw && stage == 1 {
            for (i, chunk) in body.chunks(w::OUTPUT_CHUNK_BYTES).enumerate() {
                let chunk = w::TaskEvent::OutputChunk(w::OutputChunk::new(manifest.clone(), i as u16, chunk)?);
                let response = agent_call(&f.router, Method::POST, &path, Some(case_credential()), Some(event(Uuid::new_v4(), serde_json::to_value(chunk)?))).await?;
                ensure!(response.0 == StatusCode::OK);
            }
            terminal
        } else { serde_json::to_value(w::TaskEvent::CollectionResult(result.clone()))? };
        let operation = Uuid::new_v4();
        let input = event(operation, terminal);
        let accepted = agent_call(
            &f.router,
            Method::POST,
            &path,
            Some(case_credential()),
            Some(input.clone()),
        )
        .await?;
        ensure!(accepted.0 == StatusCode::OK, "native result: {accepted:?}");
        ensure!(
            accepted
                == agent_call(
                    &f.router,
                    Method::POST,
                    &path,
                    Some(case_credential()),
                    Some(input)
                )
                .await?
        );
        ensure!(pg(&format!("SELECT state->>'execution' FROM mdm_commands.action_runs WHERE tenant_id='{}' AND id='{}'", case_tenant(), spec.task_id))?.trim() == "succeeded", "legal finished package did not complete execution");
        if all_failed {
            ensure!(pg(&format!("SELECT result FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{}'", case_tenant(), spec.attempt_id))?.trim() == "failed");
            tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    if pg(&format!("SELECT NOT delivery_pending FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{}'", case_tenant(), spec.attempt_id))?.trim() == "t" { break Ok::<_, anyhow::Error>(()); }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }).await??;
            ensure!(pg(&format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native'", case_tenant(), spec.registration_id))?.trim() == "0");
        } else {
            tokio::time::timeout(Duration::from_secs(20),async{
            loop{let rows=pg(&format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native' AND field='device.memory.bytes' AND value::jsonb->>'value'='{}'",case_tenant(),spec.registration_id,8192+stage))?;if rows.trim()=="1"{break Ok::<_,anyhow::Error>(());}tokio::time::sleep(Duration::from_millis(50)).await;}
        }).await??;
            let network = pg(&format!(
                "SELECT value::text FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native' AND field='device.network.interfaces'",
                case_tenant(),
                spec.registration_id
            ))?;
            if stage == 0 {
                prior_network = network.clone();
            } else if stage == 1 {
                ensure!(
                    network == prior_network,
                    "truncated result replaced complete inventory"
                );
                ensure!(pg(&format!("SELECT attempts::jsonb#>>'{{fields,device.network.interfaces,quality}}' FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{}'",case_tenant(),spec.attempt_id))?.trim()=="failed");
            } else {
                let v: Value = serde_json::from_str(network.trim())?;
                ensure!(v["value"] == json!([]));
            }
            if !large_raw && stage<=2 {
                let certificates:Value=serde_json::from_str(pg(&format!("SELECT value::text FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND field='device.certificates.metadata' AND source='agent.native'",case_tenant(),spec.registration_id))?.trim())?;
                ensure!(certificates["value"].as_array().unwrap().len()==if stage==2 {0}else{1},"certificate partial/empty replacement failed: {certificates}");
                let updates:Value=serde_json::from_str(pg(&format!("SELECT value::text FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND field='device.updates.available' AND source='agent.native'",case_tenant(),spec.registration_id))?.trim())?;
                ensure!(updates["value"].as_array().unwrap().len()==if stage==2 {0}else{1});
                if stage==0 {prior_updates=updates.clone();}
                if stage==1 {ensure!(updates==prior_updates,"truncated update replaced prior complete discovery");}
                if stage==0 {
                    let security=if macos {"device.security.macos.gatekeeper_observation"}else{"device.security.windows.defender.observation"};
                    let evidence=pg(&format!("SELECT value::text FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND field='{security}'",case_tenant(),spec.registration_id))?;
                    ensure!(evidence.contains(if macos {"unknown"}else{"passive"}),"security observation not projected: {evidence}");
                }

            }
            if !macos && map_software {
                windows_assets::verify_identity(spec.registration_id, spec.attempt_id, stage)?;
                let response = f
                    .author
                    .call(
                        &f.router,
                        Method::GET,
                        &format!("/api/v1/devices/{device}/inventory"),
                        None,
                    )
                    .await?;
                ensure!(response.0 == StatusCode::OK, "asset query: {response:?}");
                ensure!(
                    response.1["asset"]["device"]["fields"]["device.os.edition"]["state"]["value"]
                        ["value"]
                        == "Professional"
                );
            }
            if map_software {
                let software = pg(&format!(
                    "SELECT value::text FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native' AND field='{software_field}'",
                    case_tenant(),
                    spec.registration_id
                ))?;
                if stage == 0 {
                    let value: Value = serde_json::from_str(software.trim())?;
                    if macos {
                        ensure!(
                            value["value"]
                                .as_array()
                                .is_some_and(|rows| rows.len() == 2)
                        );
                    } else {
                        windows_assets::verify_software(&value)?;
                    }
                    prior_software = software;
                } else if stage == 1 || stage >= 4 {
                    ensure!(
                        software == prior_software,
                        "incomplete user coverage replaced the whole software list"
                    );
                } else {
                    let value: Value = serde_json::from_str(software.trim())?;
                    ensure!(
                        value["value"] == json!([]),
                        "complete empty software list was not published"
                    );
                }
            }
        }
        if !map_software {
            ensure!(pg(&format!("SELECT count(*) FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND source='agent.native' AND field='{software_field}'", case_tenant(), spec.registration_id))?.trim() == "0");
        }
        if stage != 0 { continue; }
        let detail_path = format!("/api/v1/policies/{policy}/runs/{}", spec.task_id);
        let detail = f
            .author
            .call(&f.router, Method::GET, &detail_path, None)
            .await?;
        ensure!(
            detail.0 == StatusCode::OK
                && detail.1["result"]["native"] == serde_json::to_value(&result)?,
            "native evidence recovery failed: {}",
            detail.0
        );
        if !all_failed && !large_raw {
        let certificate_scope=json!({"kind":"native_certificates","platform":platform,"owner":null,"store":if macos {"system"}else{"my"}});
        let account_scope=json!({"kind":"native_accounts","platform":platform,"identities":[]});
        let mut sensitive_paths=Vec::new();
        for (scope,field,secret) in [(certificate_scope,"device.certificates.metadata","sensitive-certificate"),(account_scope,if macos {"device.accounts.macos.identities"}else{"device.accounts.windows.identities"},"sensitive-account")] {
            let params=url::form_urlencoded::Serializer::new(String::new()).append_pair("scope",&scope.to_string()).finish();
            let path=format!("/api/v1/devices/{device}/inventory-lists/{field}?{params}");
            let visible=f.author.call(&f.router,Method::GET,&path,None).await?;
            ensure!(visible.0==StatusCode::OK && visible.1.to_string().contains(secret),"positive sensitive field read failed: {visible:?}");
            sensitive_paths.push((path,secret));
        }
        let ordinary = f
            .grants
            .iter()
            .filter(|g| g.operation != crate::authorization::Permission::InventorySensitiveRead)
            .cloned()
            .collect();
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, ordinary).await?;
        for (path,secret) in sensitive_paths {
            let hidden=f.author.call(&f.router,Method::GET,&path,None).await?;
            ensure!(hidden.0==StatusCode::FORBIDDEN && !hidden.1.to_string().contains(secret),"sensitive field read leaked or failed unexpectedly: {hidden:?}");
        }
        let denied = f
            .author
            .call(&f.router, Method::GET, &detail_path, None)
            .await?;
        ensure!(
            denied.0 == StatusCode::FORBIDDEN && !denied.1.to_string().contains("private-software"),
            "raw evidence read bypass: {denied:?}"
        );
        let limited = f
            .grants
            .iter()
            .filter(|g| g.operation != crate::authorization::Permission::InventoryRead)
            .cloned()
            .collect();
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, limited).await?;
        ensure!(
            f.author
                .call(&f.router, Method::GET, &detail_path, None)
                .await?
                .0
                == StatusCode::FORBIDDEN
        );
        let summary = f
            .author
            .call(
                &f.router,
                Method::GET,
                &format!("/api/v1/policies/{policy}/runs"),
                None,
            )
            .await?;
        ensure!(summary.0 == StatusCode::OK, "native summary: {summary:?}");
        let item = summary.1["items"].as_array().unwrap().iter().find(|item| item["taskId"] == spec.task_id.to_string()).expect("target run absent from summary");
        ensure!(
            item["result"].get("native").is_none()
                && !summary.1.to_string().contains("private-native-evidence")
                && !summary.1.to_string().contains("changed-truncated")
        );
        crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
            .await?;
        }
        ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.action_runs r JOIN mdm_policy.versions v ON(v.tenant_id,v.id)=(r.tenant_id,r.policy_version) WHERE r.tenant_id='{}' AND v.action_kind='execution'",case_tenant()))?.trim()=="0");
    }
    crate::test_support::stop_worker(inventory).await?;
    runtime.close_fixture().await?;
    crate::test_support::stop_worker(worker).await?;
    Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery: signed user binding and scoped application/Brew projection"]
async fn macos_user_applications_and_brew_keep_other_users_after_complete_empty() -> Result<()> {
    use rss_mdm_agent_wire::runtime as w;
    use rss_mdm_resource as r;
    use sha2::{Digest, Sha256};
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
    f.grants
        .extend(crate::test_support::identity::device_grants(
            None,
            &["inventory_collect", "operation_read"],
        )?);
    f.grants.push(crate::authorization::Grant {
        operation: crate::authorization::Permission::InventorySensitiveRead,
        scope: crate::authorization::Scope::Tenant,
    });
    crate::test_support::identity::set_grants(case_tenant(), &f.author_id, f.grants.clone())
        .await?;
    let mut context = crate::test_support::software_execution::context(
        crate::test_support::software_execution::Platform::MacOs,
    );
    context["interactiveUser"] =
        json!({"generatedUid":"00000000-0000-0000-0000-000000000501","identity":"501","sessionId":Uuid::new_v4(),"administrator":false});
    let registration = crate::test_support::agent::seed_profile(&f.base, f.execution.clone(), case_credential(), case_device_id(), json!({"capabilities":["inventory.collect.v1","inventory.native.v1"],"platform":"macos","architecture":"aarch64","executionContext":context})).await?;
    let device = registration["deviceId"].as_str().unwrap().to_owned();
    f.scope(case_task_scope(), json!([{"kind":"device","id":device}]))
        .await?;
    let mut specs = Vec::new();
    for (name, version) in [
        ("macos.agent.applications_user", "1"),
        ("macos.agent.brew_arm_formula", "2"),
    ] {
        let r::blueprints::Definition::AgentCollection { template } =
            r::blueprints::get(name, version).unwrap().definition
        else {
            unreachable!()
        };
        specs.push(template.spec().clone());
    }
    let mut plan = specs[0].plan.spec().clone();
    plan.queries.extend(specs[1].plan.spec().queries.clone());
    let mut mappings = specs[0].mappings.clone();
    mappings.extend(specs[1].mappings.clone());
    let definition = r::AgentCollectionDefinition::new(r::AgentCollectionSpec {
                applicability: Default::default(),
        plan: w::NativeCollectionPlan::new(plan)?,
        mappings,
    })?;
    let resource_id = Uuid::new_v4();
    let bytes = definition.canonical();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        0,
        json!({"action":"create","kind":"agent_collection"}),
    )
    .await?;
    resource(&mut f.author,&f.router,resource_id,1,json!({"action":"version","version":"v1","kind":"agent_collection","variants":[{"platform":"macos","architecture":"aarch64","key":"default","declaration":{"kind":"agent_collection","artifact":{"reference":"native.json","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
    ensure!(
        upload_for(
            &f.author,
            &f.router,
            resource_id,
            &bytes,
            "macos",
            "aarch64"
        )
        .await?
            == StatusCode::CREATED
    );
    resource(
        &mut f.author,
        &f.router,
        resource_id,
        2,
        json!({"action":"activate","version":"v1"}),
    )
    .await?;
    let worker = worker(&f.base).await?;
    let runtime = agent_runtime(&f.base).await?;
    let inventory = crate::inventory_runtime::test_support::start(runtime.clone()).await?;
    let mut datasets = Vec::new();
    for (stage, uid) in [(0, "501"), (1, "502"), (2, "501")] {
        context["revision"] = json!(stage + 2);
        context["interactiveUser"] =
            json!({"generatedUid":format!("00000000-0000-0000-0000-{:012}",uid.parse::<u32>().unwrap()),"identity":uid,"sessionId":Uuid::new_v4(),"administrator":false});
        let policy = Uuid::new_v4();
        post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":case_task_scope(),"action":{"kind":"agent_collection","resource":{"id":resource_id,"version":"v1","platform":"macos","architecture":"aarch64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
        let task = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let response = agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"profiles":[],"environment":{"edition":null,"tools":{},"nativeEngines":{"macos.applications":1,"macos.brew":2}},"executionContext":context}))).await?;
                ensure!(response.0 == StatusCode::OK, "scoped claim: {response:?}");
                if !response.1["task"].is_null() { break Ok::<_,anyhow::Error>(serde_json::from_value::<w::SignedTask>(response.1["task"].clone())?); }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }).await??;
        let w::TaskPayload::Collection(spec) = &task.payload else {
            anyhow::bail!("wrong task family")
        };
        ensure!(
            matches!(&spec.execution.target, w::SoftwareExecutionTarget::User { identity, .. } if identity == uid)
        );
        let verification = crate::test_support::task_signature::TaskVerification {
            key_id: "t2", public_key: f.key.public_key().as_ref(),
            tenant_id: Uuid::parse_str(case_tenant())?, device_id: registration["deviceId"].as_str().unwrap(),
            platform: w::TaskPlatform::Macos, architecture: w::TaskArchitecture::Aarch64,
            registration_id: serde_json::from_value(registration["registrationId"].clone())?,
            generation: registration["generation"].as_u64().unwrap(),
            task_id: spec.task_id, attempt_id: spec.attempt_id, permit: w::TaskPermit::Offer,
            now: crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?,
        };
        crate::test_support::task_signature::verify(&task, &verification)?;
        let path = format!("/api/v1/agent/runtime/tasks/{}/events", spec.task_id);
        for event in [json!({"kind":"received"}), json!({"kind":"start"})] {
            let is_start = event["kind"] == "start";
            let response = agent_call(&f.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":spec.attempt_id,"executionContext":context,"event":event}))).await?;
            ensure!(response.0 == StatusCode::OK, "scoped start: {response:?}");
            if is_start {
                let ack: w::TaskEventAck = serde_json::from_value(response.1)?;
                crate::test_support::task_signature::verify(&ack.into_permit().unwrap(), &crate::test_support::task_signature::TaskVerification { permit: w::TaskPermit::Start, ..verification })?;
            }
        }
        let now = crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
        let mut queries = std::collections::BTreeMap::new();
        for (id, query) in &spec.plan.spec().queries {
            let application = matches!(
                query.definition,
                w::NativeQueryDefinition::MacosApplications { .. }
            );
            let mut row = json!({"id":"instance","native_id":"native","name":"Scoped app","version":"1","publisher":"Acme","scope":"user","owner":uid,"origin":if application {"application"} else {"homebrew"},"location":"/controlled/fixture"});
            if application {
                row["signature_status"] = json!("signed");
            } else {
                row["prefix"] = json!("/opt/homebrew");
                row["tap"] = json!("homebrew/core");
                row["package_kind"] = json!("formula");
            }
            let rows = if stage == 2 {
                vec![]
            } else {
                vec![serde_json::from_value(row)?]
            };
            queries.insert(
                id.clone(),
                w::NativeQueryResult {
                    scan: None,
                    query_digest: query.digest(),
                    collected_at: now,
                    status: w::NativeQueryStatus::Complete,
                    enumeration_complete: true,
                    row_count: rows.len() as u32,
                    rows,
                    users: None,
                },
            );
        }
        let event = w::TaskEvent::CollectionResult(w::NativeCollectionResult {
            plan_digest: spec.plan_digest,
            collected_at: now,
            queries,
        });
        let response = agent_call(&f.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":spec.attempt_id,"executionContext":context,"event":event}))).await?;
        ensure!(response.0 == StatusCode::OK, "scoped result: {response:?}");
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let count = pg(&format!(
                    "SELECT count(*) FROM mdm.inventory WHERE tenant_id='{}' AND batch_id='{}'",
                    case_tenant(),
                    spec.attempt_id
                ))?;
                if count.trim() == "2" {
                    break Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        for (field, scope) in [
            (
                "device.software.installations",
                json!({"kind":"macos_applications","root":"user","uid":uid.parse::<u32>()?}),
            ),
            (
                "device.software.packages",
                json!({"kind":"macos_brew","uid":uid.parse::<u32>()?,"prefix":"/opt/homebrew","package":"formula","taps":[]}),
            ),
        ] {
            let parameters = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("scope", &scope.to_string())
                .finish();
            let response = f
                .author
                .call(
                    &f.router,
                    Method::GET,
                    &format!(
                        "/api/v1/devices/{device}/collections/{}/fields/{field}/items?{parameters}",
                        spec.attempt_id
                    ),
                    None,
                )
                .await?;
            ensure!(
                response.0 == StatusCode::OK,
                "scoped item pagination: {response:?}"
            );
        }
        datasets.push(pg(&format!("SELECT attempts::jsonb#>>'{{definition,dataset}}' FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{}'",case_tenant(),spec.attempt_id))?);
    }
    ensure!(datasets[0] == datasets[2] && datasets[0] != datasets[1]);
    let rows: Value = serde_json::from_str(pg(&format!(
        "SELECT jsonb_agg(jsonb_build_object('field',field,'scope',field_scope::jsonb,'value',value::jsonb->'value')) FROM mdm.inventory WHERE tenant_id='{}' AND source='agent.native' AND field IN ('device.software.installations','device.software.packages')",
        case_tenant()
    ))?.trim())?;
    let rows = rows.as_array().context("scoped software facts")?;
    ensure!(
        rows.len() == 4,
        "expected both fields for both users: {rows:?}"
    );
    for uid in [501, 502] {
        for (field, scope) in [
            (
                "device.software.installations",
                json!({"kind":"macos_applications","root":"user","uid":uid}),
            ),
            (
                "device.software.packages",
                json!({"kind":"macos_brew","uid":uid,"prefix":"/opt/homebrew","package":"formula","taps":[]}),
            ),
        ] {
            let matching: Vec<_> = rows
                .iter()
                .filter(|row| row["field"] == field && row["scope"] == scope)
                .collect();
            ensure!(
                matching.len() == 1,
                "missing or duplicate {field}/{scope}: {rows:?}"
            );
            let values = matching[0]["value"]
                .as_array()
                .context("trusted software list")?;
            ensure!(
                values.len() == if uid == 501 { 0 } else { 1 },
                "incorrect replacement for {field}/{scope}: {values:?}"
            );
            if uid == 502 {
                ensure!(
                    values[0]["value"]["owner"]["value"] == "502"
                        && values[0]["value"]["name"]["value"] == "Scoped app",
                    "other user's fact changed: {values:?}"
                );
            }
        }
    }
    crate::test_support::stop_worker(inventory).await?;
    runtime.close_fixture().await?;
    crate::test_support::stop_worker(worker).await?;
    Ok(())
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery: Windows certificate store and signed SID isolation"]
async fn windows_certificate_scopes_preserve_other_users_and_stores() -> Result<()> {
    certificate_scope_case(false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "make t2 MODULE=execution.agent.delivery: macOS certificate store and GeneratedUID isolation"]
async fn macos_certificate_scopes_preserve_other_users_and_stores() -> Result<()> {
    certificate_scope_case(true).await
}
async fn certificate_scope_case(macos: bool) -> Result<()> {
    use rss_mdm_agent_wire::runtime as w;
    use rss_mdm_resource as r;
    use sha2::{Digest, Sha256};
    let platform = if macos { "macos" } else { "windows" };
    let mut f = Fixture::new().await?;
    let resources = std::mem::take(&mut f.resources);
    resources.finish(async {
        f.grants.extend(crate::test_support::identity::device_grants(None,&["inventory_collect","operation_read"])?);
        f.grants.push(crate::authorization::Grant {operation:crate::authorization::Permission::InventorySensitiveRead,scope:crate::authorization::Scope::Tenant});
        crate::test_support::identity::set_grants(case_tenant(),&f.author_id,f.grants.clone()).await?;
        let mut context=crate::test_support::software_execution::context(if macos {crate::test_support::software_execution::Platform::MacOs}else{crate::test_support::software_execution::Platform::Windows});
        let registration=crate::test_support::agent::seed_profile(&f.base,f.execution.clone(),case_credential(),case_device_id(),json!({"capabilities":["inventory.collect.v1","inventory.native.v1"],"platform":platform,"architecture":"x86_64","executionContext":context})).await?;
        let device=registration["deviceId"].as_str().unwrap().to_owned();
        f.scope(case_task_scope(),json!([{"kind":"device","id":device}])).await?;
        let worker=worker(&f.base).await?;
        let runtime=agent_runtime(&f.base).await?;
        let inventory=crate::inventory_runtime::test_support::start(runtime.clone()).await?;
        // Machine store; two users; another store; failed and empty attempts in user A's store.
        // macOS has one user login store, so its additional store is System Roots.
        let mut scopes=Vec::new();
        let mut published=std::collections::BTreeMap::new();
        let mut prior_user=String::new();
        for stage in 0..6 {
            let user=matches!(stage,1|2|4|5) || (!macos && stage==3);
            let n=if stage==2 {502}else{501};
            let uid=n.to_string();let sid=format!("S-1-5-21-1-2-3-{n}");let guid=format!("00000000-0000-0000-0000-{n:012}");
            context["revision"]=json!(stage+2);
            context["interactiveUser"]=json!({"identity":if macos {&uid}else{&sid},"generatedUid":if macos {Some(&guid)}else{None},"sessionId":Uuid::new_v4(),"administrator":false});
            let blueprint=if macos {if user {"macos.agent.certificates_login"}else if stage==3 {"macos.agent.certificates_system_roots"}else{"macos.agent.certificates_system"}}else if stage==0 {"windows.agent.certificates_device_my"}else if stage==3 {"windows.agent.certificates_user_root"}else{"windows.agent.certificates_user_my"};
            let r::blueprints::Definition::AgentCollection {template:definition}=r::blueprints::get(blueprint,"1").unwrap().definition else {unreachable!()};
            let engines=definition.spec().plan.requirements();
            let resource_id=if let Some(id)=published.get(blueprint) {*id} else {
            let resource_id=Uuid::new_v4();let bytes=definition.canonical();let digest:[u8;32]=Sha256::digest(&bytes).into();
            resource(&mut f.author,&f.router,resource_id,0,json!({"action":"create","kind":"agent_collection"})).await?;
            resource(&mut f.author,&f.router,resource_id,1,json!({"action":"version","version":"v1","kind":"agent_collection","variants":[{"platform":platform,"architecture":"x86_64","key":"default","declaration":{"kind":"agent_collection","artifact":{"reference":"native.json","length":bytes.len(),"sha256":digest},"definition":definition}}]})).await?;
            ensure!(upload_for(&f.author,&f.router,resource_id,&bytes,platform,"x86_64").await?==StatusCode::CREATED);
            resource(&mut f.author,&f.router,resource_id,2,json!({"action":"activate","version":"v1"})).await?;
            published.insert(blueprint,resource_id);resource_id
            };
            let policy=Uuid::new_v4();
            post(&mut f.author,&f.router,&format!("/api/v1/policies/{policy}"),json!({"operationId":Uuid::new_v4(),"expectedRevision":0,"input":{"action":"put","enabled":true,"definition":{"scope":case_task_scope(),"action":{"kind":"agent_collection","resource":{"id":resource_id,"version":"v1","platform":platform,"architecture":"x86_64","variant":"default"},"runLifetimeSeconds":300}}}})).await?;
            let task=tokio::time::timeout(Duration::from_secs(30),async {
                loop {
                    let response=agent_call(&f.router,Method::POST,"/api/v1/agent/runtime/tasks/claim",Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"profiles":[],"environment":{"edition":null,"tools":{},"nativeEngines":engines},"executionContext":context}))).await?;
                    ensure!(response.0==StatusCode::OK,"certificate claim: {response:?}");
                    if !response.1["task"].is_null() {break Ok::<_,anyhow::Error>(serde_json::from_value::<w::SignedTask>(response.1["task"].clone())?);}
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }).await??;
            let w::TaskPayload::Collection(spec)=&task.payload else {anyhow::bail!("wrong task")};
            ensure!(spec.execution.generated_uid==if macos && user {Some(guid.clone())}else{None});
            let verification=crate::test_support::task_signature::TaskVerification {key_id:"t2",public_key:f.key.public_key().as_ref(),tenant_id:Uuid::parse_str(case_tenant())?,device_id:&device,platform:if macos {w::TaskPlatform::Macos}else{w::TaskPlatform::Windows},architecture:w::TaskArchitecture::X86_64,registration_id:serde_json::from_value(registration["registrationId"].clone())?,generation:registration["generation"].as_u64().unwrap(),task_id:spec.task_id,attempt_id:spec.attempt_id,permit:w::TaskPermit::Offer,now:crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?};
            crate::test_support::task_signature::verify(&task,&verification)?;
            let path=format!("/api/v1/agent/runtime/tasks/{}/events",spec.task_id);
            for kind in ["received","start"] {
                let response=agent_call(&f.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":spec.attempt_id,"executionContext":context,"event":{"kind":kind}}))).await?;
                ensure!(response.0==StatusCode::OK,"certificate start: {response:?}");
                if kind=="start" {let ack:w::TaskEventAck=serde_json::from_value(response.1)?;crate::test_support::task_signature::verify(&ack.into_permit().unwrap(),&crate::test_support::task_signature::TaskVerification {permit:w::TaskPermit::Start,..verification})?;}
            }
            if stage==0 {
                let secret=br#"{"private_key":"must-never-persist"}"#;
                let manifest=w::OutputManifest::new(secret.len() as u32,Sha256::digest(secret).into())?;
                let chunk=w::OutputChunk::new(manifest.clone(),0,secret)?;
                let rejected=agent_call(&f.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":spec.attempt_id,"executionContext":context,"event":w::TaskEvent::OutputChunk(chunk)}))).await?;
                ensure!(rejected.0==StatusCode::BAD_REQUEST,"System raw chunk accepted: {rejected:?}");
                ensure!(pg(&format!("SELECT count(*) FROM mdm_commands.output_chunks WHERE tenant_id='{}' AND attempt='{}'",case_tenant(),spec.attempt_id))?.trim()=="0","rejected secret chunk persisted");
                let rejected=agent_call(&f.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":spec.attempt_id,"executionContext":context,"event":w::TaskEvent::ChunkedCollectionResult {manifest}}))).await?;
                ensure!(rejected.0==StatusCode::BAD_REQUEST);
            }
            let q=&spec.plan.spec().queries["facts"];
            let w::NativeQueryDefinition::System {query}=&q.definition else {unreachable!()};let store=query.certificate_store().unwrap();
            let owner=if user {if macos {guid.clone()}else{sid.clone()}}else{String::new()};
            let now=crate::clock::Clock::unix_seconds(&crate::clock::SystemClock)?;
            let rows=if stage==5 {vec![]}else{vec![serde_json::from_value(json!({"id":"a".repeat(64),"subject":"CN=private-certificate","issuer":"CN=CA","not_before":1,"not_after":2000000000,"scope":if user {"user"}else{"device"},"owner":owner,"store":store}))?]};
            let answer=w::NativeQueryResult {scan:None,query_digest:q.digest(),collected_at:now,status:if stage==4 {w::NativeQueryStatus::Partial}else{w::NativeQueryStatus::Complete},enumeration_complete:stage!=4,row_count:rows.len() as u32,rows,users:None};
            let event=w::TaskEvent::CollectionResult(w::NativeCollectionResult {plan_digest:spec.plan_digest,collected_at:now,queries:[("facts".into(),answer)].into()});
            if stage==1 {
                let mut tampered=serde_json::to_value(&event)?;
                tampered["queries"]["facts"]["rows"][0]["owner"]=json!(if macos {"00000000-0000-0000-0000-000000000999"}else{"S-1-5-21-1-2-3-999"});
                let denied=agent_call(&f.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":spec.attempt_id,"executionContext":context,"event":tampered}))).await?;
                ensure!(denied.0==StatusCode::BAD_REQUEST,"wrong certificate owner accepted: {denied:?}");
            }
            let response=agent_call(&f.router,Method::POST,&path,Some(case_credential()),Some(json!({"wireVersion":1,"operationId":Uuid::new_v4(),"attemptId":spec.attempt_id,"executionContext":context,"event":event}))).await?;
            ensure!(response.0==StatusCode::OK,"certificate result: {response:?}");
            tokio::time::timeout(Duration::from_secs(20),async {loop {
                if pg(&format!("SELECT NOT delivery_pending FROM mdm_access.collection_runs WHERE tenant_id='{}' AND id='{}'",case_tenant(),spec.attempt_id))?.trim()=="t" {break Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(50)).await;
            }}).await??;
            let scope=json!({"kind":"native_certificates","platform":platform,"store":store,"owner":if !user {Value::Null}else if macos {json!({"kind":"macos","uid":n,"generated_uid":guid})}else{json!({"kind":"windows","sid":sid})}});
            let escaped=scope.to_string().replace('\'',"''");
            let saved=pg(&format!("SELECT value::text FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND field='device.certificates.metadata' AND field_scope::jsonb='{}'::jsonb",case_tenant(),spec.registration_id,escaped))?;
            let parsed:Value=serde_json::from_str(saved.trim())?;
            ensure!(parsed["value"].as_array().unwrap().len()==if stage==5 {0}else{1},"wrong store replacement: {parsed}");
            if stage==1 {prior_user=saved.clone();}
            if stage==4 {ensure!(saved==prior_user,"partial replaced previous certificate");}
            if stage<4 {scopes.push(scope);}
        }
        let facts:Value=serde_json::from_str(pg(&format!("SELECT jsonb_agg(jsonb_build_object('scope',field_scope::jsonb,'value',value::jsonb)) FROM mdm.inventory WHERE tenant_id='{}' AND registration='{}' AND field='device.certificates.metadata'",case_tenant(),registration["registrationId"].as_str().unwrap()))?.trim())?;
        let facts=facts.as_array().context("certificate facts")?;ensure!(facts.len()==4);
        for (i,scope) in scopes.iter().enumerate() {
            let fact=facts.iter().find(|f|f["scope"]==*scope).context("missing store")?;
            ensure!(fact["value"]["value"].as_array().unwrap().len()==if i==1 {0}else{1},"unrelated certificate scope replaced");
        }
        crate::test_support::stop_worker(inventory).await?;runtime.close_fixture().await?;crate::test_support::stop_worker(worker).await?;
        Ok(())
    }).await
}
