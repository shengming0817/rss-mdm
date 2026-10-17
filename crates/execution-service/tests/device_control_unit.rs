use super::*;
use serde_json::json;

#[test]
fn public_control_rejects_generic_and_unknown_inputs() {
    for value in [
        json!({"operationId":Uuid::new_v4(),"deadline":100,"task":{"platform":"macos"}}),
        json!({"operationId":Uuid::new_v4(),"deadline":100,"action":{"kind":"execute"}}),
        json!({"operationId":Uuid::new_v4(),"deadline":100,"action":{"kind":"restart","fields":{}}}),
        json!({"operationId":Uuid::new_v4(),"deadline":100,"action":{"kind":"restart"},"target":{"kind":"user"}}),
    ] {
        assert!(serde_json::from_value::<Input>(value).is_err());
    }
}

#[test]
fn dangerous_control_requires_confirmation_and_valid_pin() {
    let registration = Uuid::new_v4();
    for (confirmed, pin) in [(false, "123456"), (true, "12345"), (true, "abcdef")] {
        let input: Input = serde_json::from_value(json!({"operationId":Uuid::new_v4(),"deadline":100,
            "action":{"kind":"lock","confirmed":confirmed,"expectedRegistrationId":registration,"expectedGeneration":1,"pin":pin}})).unwrap();
        assert!(input.validate(1).is_err());
    }
    let input: Input = serde_json::from_value(json!({"operationId":Uuid::new_v4(),"deadline":100,
        "action":{"kind":"lock","confirmed":true,"expectedRegistrationId":registration,"expectedGeneration":1,"pin":"123456"}})).unwrap();
    let confirmation = input.action.confirmation().unwrap().unwrap();
    assert!(confirmation.check(registration, 1).is_ok());
    assert!(matches!(
        confirmation.check(registration, 2),
        Err(Error::Conflict)
    ));
    assert!(!format!("{:?}", input.action).contains("123456"));
}

#[test]
fn fixed_native_mapping_cannot_wrap_arbitrary_commands() {
    let input = Input {
        operation_id: Uuid::new_v4(),
        deadline: 100,
        action: Action::Wipe {
            confirmed: true,
            expected_registration_id: Uuid::new_v4(),
            expected_generation: 1,
        },
    };
    let mut native = input.native(ReportSource::MdmApple).unwrap();
    assert!(matches(Kind::Wipe, &native).unwrap());
    let Task::Macos {
        request: rss_mdm_apple_mdm::native::request::Request::Command { command },
    } = &mut native.task
    else {
        panic!()
    };
    command.fields.0.clear();
    assert!(!matches(Kind::Wipe, &native).unwrap());
    assert!(
        Action::Lock {
            confirmed: true,
            expected_registration_id: Uuid::new_v4(),
            expected_generation: 1,
            pin: "123456".into()
        }
        .task(ReportSource::MdmWindows)
        .is_err()
    );
}

#[test]
fn apple_matrix_requires_known_safe_hardware_and_version() {
    use rss_mdm_apple_mdm::applicability::{Channel, Context, Enrollment, Version};
    let mut context = Context {
        version: Some(Version::parse("12.0.1").unwrap()),
        channel: Channel::Device,
        enrollment: Enrollment::Device,
        supervised: None,
        automated_enrollment: None,
        user_authorized: None,
        apple_silicon: Some(true),
    };
    assert!(Kind::Wipe.supports_apple(&context));
    context.apple_silicon = Some(false);
    assert!(!Kind::Wipe.supports_apple(&context));
    assert!(Kind::Lock.supports_apple(&context));
    context.apple_silicon = None;
    assert!(!Kind::Lock.supports_apple(&context));
    context.apple_silicon = Some(true);
    context.version = Some(Version::parse("11.4").unwrap());
    assert!(!Kind::Lock.supports_apple(&context));
    assert!(!Kind::Wipe.supports_apple(&context));
    context.enrollment = Enrollment::User;
    assert!(!Kind::Restart.supports_apple(&context));
}
