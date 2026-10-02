//! Native notifications are immutable registration evidence, independent of operation effects.
//! ref: MS-MDM 2.2.7.2 native Alert lifecycle.
use crate::{Error, Failure, RequestAudit, device::DevicePrincipal};
use rss_mdm_audit_integration::Fact;
use rss_mdm_native_protection::Protector;
use rss_mdm_windows_mdm::syncml::{Alert, Command, Message};

pub(crate) fn facts(
    key: &Protector,
    p: &DevicePrincipal,
    message: &Message,
    bytes: &[u8],
    audit: &RequestAudit,
) -> Result<Vec<Fact>, Error> {
    let mut facts = Vec::new();
    for command in &message.commands {
        let Command::Alert { id, alert } = command else {
            continue;
        };
        let (code, kind, count) = match alert {
            Alert::Generic { items } => (1226, "csp_notification", items.len()),
            Alert::LoginStatus { .. } => (1224, "reported_login_state", 1),
            Alert::SessionAbort => (1223, "session_aborted", 0),
            _ => continue,
        };
        let identity = (
            p.registration(),
            p.generation(),
            p.credential(),
            message.header.session_id,
            message.header.message_id,
            *id,
        );
        let digest = key
            .mac(
                bytes,
                &crate::protection::native_aad(
                    p.tenant(),
                    "windows.native-notification",
                    &identity,
                )?,
            )
            .map_err(|_| Error::Unavailable(Failure::Protocol))?;
        let items = match alert {
            Alert::Generic {items} => items.iter().map(|item| serde_json::json!({
                "source":item.source,"format":item.meta.as_ref().and_then(|meta|meta.format.as_ref()),
                "nativeType":item.meta.as_ref().and_then(|meta|meta.media_type.as_ref()),
            })).collect::<Vec<_>>(),
            _ => vec![],
        };
        let fact=Fact::business(audit,&format!("windows-notification:{}:{}:{}:{}:{}",p.registration(),p.generation(),message.header.session_id,message.header.message_id,id),&digest,200,"success",None)
            .and_then(|fact|fact.with_details(serde_json::json!({"nativeCode":code,"kind":kind,"items":count,"nativeItems":items,"effect":"unverified"})))
            .map_err(Error::from)?;
        facts.push(fact);
    }
    Ok(facts)
}
