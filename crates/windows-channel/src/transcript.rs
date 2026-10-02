//! The committed wire transcript is the only source of session response history.
use crate::{Error, Failure, database::db, device::DevicePrincipal, large_object::Assembly};
use rss_mdm_native_protection::Protector;
use rss_mdm_windows_mdm::{CodecLimits, syncml as s};
use sqlx::{PgConnection, Row};

pub(crate) struct History {
    pub expected: Option<s::Expected>,
    pub assembly: Assembly,
    pub limits: CodecLimits,
}
fn corrupt() -> Error {
    Error::Unavailable(Failure::Protocol)
}
pub(crate) async fn load(
    c: &mut PgConnection,
    key: &Protector,
    p: &DevicePrincipal,
    raw: &s::Message,
) -> Result<History, Error> {
    let bounds = CodecLimits::default();
    let rows = sqlx::query("SELECT message_id,request,response,package_state FROM mdm_access.management_messages WHERE tenant_id=$1::uuid AND registration=$2 AND session_id=$3 ORDER BY message_id LIMIT $4")
        .bind(p.tenant().to_string()).bind(p.registration()).bind(raw.header.session_id.to_string())
        .bind((bounds.session_messages + 1) as i64).fetch_all(c).await.map_err(db)?;
    if rows.len() > bounds.session_messages || rows.len() + 1 != raw.header.message_id as usize {
        return Err(corrupt());
    }
    let mut history = History {
        expected: None,
        assembly: Assembly::default(),
        limits: bounds.clone(),
    };
    for (index, row) in rows.iter().enumerate() {
        let id: i64 = row.try_get("message_id").map_err(db)?;
        if id != index as i64 + 1 {
            return Err(corrupt());
        }
        let binding = (
            p.registration(),
            p.generation(),
            p.credential(),
            raw.header.session_id.to_string(),
            id,
        );
        let decode = |part: &str, column: &str| -> Result<s::Message, Error> {
            let cipher: Vec<u8> = row.try_get(column).map_err(db)?;
            let aad = crate::protection::native_aad(p.tenant(), part, &binding)?;
            let plain = key.open_bytes(&cipher, &aad).map_err(|_| corrupt())?;
            let message = s::decode(plain.expose(), &bounds).map_err(|_| corrupt())?;
            if i64::from(message.header.message_id) != id
                || message.header.session_id != raw.header.session_id
            {
                return Err(corrupt());
            }
            Ok(message)
        };
        let incoming = decode("windows.management.incoming", "request")?;
        let outgoing = decode("windows.management.response", "response")?;
        if incoming.header.source != raw.header.source
            || incoming.header.target != raw.header.target
            || outgoing.header.target != raw.header.source
            || outgoing.header.source != raw.header.target
        {
            return Err(corrupt());
        }
        // Only a committed, non-aborted authenticated packet participates in object recovery.
        if row.try_get::<String, _>("package_state").map_err(db)? != "aborted"
            && let Some(expected) = history.expected.as_ref()
        {
            history
                .assembly
                .feed(&incoming, expected, &bounds)
                .map_err(|_| corrupt())?;
        }
        negotiate(&mut history.limits, &incoming);
        let (_, sent) = s::encode_request(&outgoing, &bounds).map_err(|_| corrupt())?;
        if let Some(expected) = history.expected.as_mut() {
            expected.record_sent(sent, &bounds).map_err(|_| corrupt())?;
        } else {
            history.expected = Some(
                s::Expected::new(sent, raw.header.message_id, &bounds).map_err(|_| corrupt())?,
            );
        }
    }
    negotiate(&mut history.limits, raw);
    Ok(history)
}
fn negotiate(limits: &mut CodecLimits, message: &s::Message) {
    if let Some(meta) = &message.header.meta {
        if let Some(size) = meta.max_message_size {
            limits.syncml_bytes = limits.syncml_bytes.min(size as usize);
        }
        if let Some(size) = meta.max_object_size {
            limits.object_bytes = limits.object_bytes.min(size as usize);
        }
    }
}
