//! Additional real native status and OsVersion paths using the canonical Router.
use super::*;
use rss_mdm_windows_mdm::{CodecLimits, Secret, syncml as s};

pub(crate) async fn post(
    peer: &reqwest::Client,
    url: &str,
    message: &s::Message,
) -> anyhow::Result<reqwest::Response> {
    // Respect the production per-peer admission rate across the expanded exchanges.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Ok(peer
        .post(url)
        .header("content-type", "application/vnd.syncml.dm+xml")
        .body(s::encode(message, &CodecLimits::default())?)
        .send()
        .await?)
}
pub(crate) struct ReadExchange {
    pub(crate) first: s::Message,
    pub(crate) gets: Vec<(u32, String)>,
    pub(crate) ack: s::Message,
}
pub(crate) async fn begin(
    peer: &reqwest::Client,
    url: &str,
    initial: &s::Message,
    ack: &s::Message,
    session: u32,
    task_uri: Option<&str>,
) -> anyhow::Result<ReadExchange> {
    use base64::Engine;
    let mut first = initial.clone();
    first.header.session_id = session;
    ensure!(post(peer, url, &first).await?.status() == StatusCode::OK);
    let mut ack = ack.clone();
    ack.header.session_id = session;
    if let s::Command::Status(status) = &mut ack.commands[0] {
        status.challenge.as_mut().unwrap().nonce = Some(Secret(
            base64::engine::general_purpose::STANDARD.encode([session as u8; 16]),
        ));
    }
    let response = post(peer, url, &ack).await?;
    ensure!(response.status() == StatusCode::OK);
    let message = s::decode(&response.bytes().await?, &CodecLimits::default())?;
    let gets = message
        .commands
        .iter()
        .filter_map(|c| match c {
            s::Command::Get { id, items, .. } => Some((*id, items[0].target.clone().unwrap())),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut expected = vec![
        "./DevInfo/Mod",
        "./DevDetail/SwV",
        "./DevDetail/SwV",
        "./Vendor/MSFT/DeviceStatus/OS/Edition",
    ];
    expected.extend(task_uri);
    ensure!(gets.iter().map(|(_, uri)| uri.as_str()).collect::<Vec<_>>() == expected);
    ensure!(message.commands.len() == gets.len() + 1);
    ensure!(
        message
            .commands
            .iter()
            .map(s::Command::id)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == message.commands.len()
    );
    Ok(ReadExchange { first, gets, ack })
}
pub(crate) fn report(
    first: &s::Message,
    gets: &[(u32, String)],
    version: &str,
    status: u16,
) -> s::Message {
    let native_status = |id, command_ref, code, command| {
        s::Command::Status(s::Status {
            id,
            message_ref: 2,
            command_ref,
            command,
            target_refs: vec![],
            source_refs: vec![],
            code,
            items: vec![],
            challenge: None,
            credential: None,
        })
    };
    let mut packet = s::Message {
        header: s::Header {
            message_id: 3,
            credential: None,
            ..first.header.clone()
        },
        commands: vec![native_status(1, 0, 200, s::CommandName::SyncHdr)],
        final_message: true,
    };
    for (index, (id, uri)) in gets.iter().enumerate() {
        packet.commands.push(native_status(
            index as u32 * 2 + 2,
            *id,
            status,
            s::CommandName::Get,
        ));
        if status == 200 {
            packet.commands.push(s::Command::Results(s::Results {
                id: index as u32 * 2 + 3,
                message_ref: Some(2),
                command_ref: Some(*id),
                command: Some(s::CommandName::Get),
                meta: None,
                items: vec![s::Item {
                    source: Some(uri.clone()),
                    target: None,
                    meta: None,
                    data: Some(Secret(
                        if uri.ends_with("/Mod") {
                            "Model-extra"
                        } else if uri.ends_with("/Edition") {
                            "48"
                        } else {
                            version
                        }
                        .into(),
                    )),
                }],
            }));
        }
    }
    packet
}
