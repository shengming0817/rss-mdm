use super::*;

fn previous() -> Applied {
    Applied {
        host_id: uuid::Uuid::new_v4(),
        operation_id: uuid::Uuid::new_v4(),
        revision: 4,
        material_digest: "a".repeat(64),
        process_generation: uuid::Uuid::new_v4(),
        tenant_id: uuid::Uuid::new_v4().to_string(),
        instance_id: uuid::Uuid::new_v4().to_string(),
    }
}
fn binding(value: &Applied) -> Binding {
    Binding {
        host_id: value.host_id,
        operation_id: value.operation_id,
        revision: value.revision,
        material_digest: value.material_digest.clone(),
    }
}
#[test]
fn replay_and_successor_preserve_host_identity_and_operation() {
    let previous = previous();
    let mut next = binding(&previous);
    let admit = |next: &Binding| {
        admit_successor(&previous, next, &previous.tenant_id, &previous.instance_id)
    };
    assert!(admit(&next).is_ok());
    next.material_digest = "b".repeat(64);
    assert!(admit(&next).is_err());
    next.revision += 1;
    assert!(admit(&next).is_err());
    next.operation_id = uuid::Uuid::new_v4();
    assert!(admit(&next).is_ok());
    next.revision = previous.revision - 1;
    assert!(admit(&next).is_err());
    next = binding(&previous);
    next.host_id = uuid::Uuid::new_v4();
    assert!(admit(&next).is_err());
    assert!(
        admit_successor(
            &previous,
            &binding(&previous),
            "other",
            &previous.instance_id
        )
        .is_err()
    );
}
#[test]
fn health_requires_the_exact_input_and_a_real_process_generation() {
    let mut value = previous();
    let expected = binding(&value);
    assert!(matches(
        &value,
        &expected,
        &value.tenant_id,
        &value.instance_id
    ));
    value.process_generation = uuid::Uuid::nil();
    assert!(!matches(
        &value,
        &expected,
        &value.tenant_id,
        &value.instance_id
    ));
    value.process_generation = uuid::Uuid::new_v4();
    value.revision += 1;
    assert!(!matches(
        &value,
        &expected,
        &value.tenant_id,
        &value.instance_id
    ));
}
#[test]
fn deployment_requires_an_immutable_image() {
    assert!(image(&format!("sha256:{}", "a".repeat(64))).is_ok());
    assert!(image(&format!("registry.example/mdm@sha256:{}", "b".repeat(64))).is_ok());
    for value in [
        "mdm:latest",
        "mdm:v1",
        "sha256:abc",
        "--help",
        "mdm@sha256:",
    ] {
        assert!(image(value).is_err());
    }
}
