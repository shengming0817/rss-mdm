use super::*;
fn operation() -> Operation {
    let id = Uuid::new_v4();
    let tenant = TenantId::parse(&Uuid::new_v4().to_string()).unwrap();
    let request = crate::device_control::Input {
        operation_id: id,
        deadline: 100,
        action: crate::device_control::Action::Restart {},
    }
    .native(rss_mdm_inventory::ReportSource::MdmWindows)
    .unwrap();
    Operation {
        id,
        device: "device".into(),
        request,
        authority: ExecutionAuthority::DeviceControl {
            action: crate::device_control::Kind::Restart,
            confirmation: None,
            required: vec![authorization::Permission::DeviceControl],
            actor: authorization::Actor::ApiKey {
                instance: Uuid::new_v4().to_string(),
                tenant: tenant.to_string(),
                id: Uuid::new_v4(),
            },
        },
        revision: 1,
        dispatch_failure: None,
        scope: dc::Scope::new(
            tenant,
            dc::DeviceId::parse(&Uuid::new_v4().to_string()).unwrap(),
        ),
        coordinate: dc::Coordinate::new(1, 1).unwrap(),
        registration: Uuid::new_v4(),
        registration_generation: 1,
    }
}
#[test]
fn authorization_and_operator_eligibility_are_independent() {
    let op = operation();
    let registration = Some((op.registration, 1));
    assert_eq!(
        decide(&op, true, registration, true).unwrap(),
        Authorization::Authorized
    );
    assert_eq!(
        reauthorization(&op, dc::Status::Queued, 1, registration, true, false).unwrap(),
        Reauthorization::Unavailable {
            reason: ReauthorizationReason::PermissionDenied
        }
    );
    assert_eq!(
        decide(&op, false, registration, true).unwrap(),
        Authorization::Blocked {
            reason: BlockReason::LifecycleBlocked
        }
    );
    // Refreshing the actor cannot bypass a lifecycle or source fence.
    assert!(matches!(
        reauthorization(&op, dc::Status::Queued, 1, registration, true, true).unwrap(),
        Reauthorization::Available { .. }
    ));
    assert_eq!(
        decide(&op, true, registration, false).unwrap(),
        Authorization::Blocked {
            reason: BlockReason::SourceInvalid
        }
    );
}
#[test]
fn expiry_receipt_terminal_and_registration_cannot_be_reauthorized() {
    let op = operation();
    let registration = Some((op.registration, 1));
    for (status, now, current, reason) in [
        (
            dc::Status::Queued,
            100,
            registration,
            ReauthorizationReason::Expired,
        ),
        (
            dc::Status::Received,
            1,
            registration,
            ReauthorizationReason::AlreadyReceived,
        ),
        (
            dc::Status::Cancelled,
            1,
            registration,
            ReauthorizationReason::Terminal,
        ),
        (
            dc::Status::Queued,
            1,
            Some((op.registration, 2)),
            ReauthorizationReason::RegistrationChanged,
        ),
        (
            dc::Status::Queued,
            1,
            None,
            ReauthorizationReason::RegistrationChanged,
        ),
    ] {
        assert_eq!(
            reauthorization(&op, status, now, current, true, true).unwrap(),
            Reauthorization::Unavailable { reason }
        );
    }
    assert_eq!(
        decide(&op, true, Some((op.registration, 2)), true).unwrap(),
        Authorization::Blocked {
            reason: BlockReason::RegistrationChanged
        }
    );
}

#[test]
fn authorization_contract_exposes_filters_without_a_second_sort_contract() {
    let schema = &crate::directory::SCHEMA;
    assert!(
        schema
            .parse("filter=authorization.state==blocked;authorization.reason==registration_changed")
            .is_ok()
    );
    assert!(
        schema
            .statistics("filter=reauthorization.state==available")
            .is_ok()
    );
    assert!(schema.parse("sort=authorization.state").is_err());
    assert!(schema.parse("fields=authorization.state").is_err());
    assert!(
        schema
            .parse("filter=authorization.state==approved")
            .is_err()
    );
    assert!(serde_json::from_value::<Authorization>(serde_json::json!("blocked")).is_err());
}

#[test]
fn legal_source_documents_cross_batches_without_a_total_candidate_cap() {
    let sizes = [8 * 1024 * 1024, 8 * 1024 * 1024, 8 * 1024 * 1024];
    let first = crate::transaction::input_prefix(sizes).unwrap();
    assert_eq!(first, 2);
    assert_eq!(
        crate::transaction::input_prefix(sizes[first..].iter().copied()).unwrap(),
        1
    );
    assert!(crate::transaction::input_prefix([16 * 1024 * 1024 + 1]).is_err());
    assert_eq!(
        crate::transaction::input_prefix(std::iter::repeat_n(1, 1001)).unwrap(),
        1000
    );
}
