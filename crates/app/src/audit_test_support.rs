//! Test assertions decode the component's canonical records, including their source identity.
use rss_audit_core::DecodedAuditV1;
use serde_json::Value;

pub(crate) struct Record {
    pub decoded: DecodedAuditV1,
    pub payload: Value,
}
impl Record {
    fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let decoded = rss_audit_core::decode_untrusted(bytes)?;
        let payload = serde_json::from_slice(decoded.event().context().payload().as_bytes())?;
        Ok(Self { decoded, payload })
    }
    pub fn action(&self) -> &str {
        self.decoded.event().facts().action().as_str()
    }
    pub fn target(&self) -> &str {
        self.decoded.event().facts().resource().id().as_str()
    }
    pub fn actor(&self) -> Option<&str> {
        (self.decoded.event().facts().actor().kind().as_str() != "unidentified")
            .then(|| self.decoded.event().facts().actor().id().as_str())
    }
    pub fn operation(&self) -> Option<&str> {
        self.decoded
            .event()
            .context()
            .coordinates()
            .operation_id()
            .map(|v| v.as_str())
    }
    pub fn request(&self) -> Option<&str> {
        self.decoded
            .event()
            .context()
            .coordinates()
            .request_id()
            .map(|v| v.as_str())
    }
    pub fn source(&self) -> &str {
        self.decoded
            .event()
            .identity()
            .source()
            .source_id()
            .as_str()
    }
    pub fn result(&self) -> &str {
        self.payload["result"].as_str().expect("product result")
    }
    pub fn status(&self) -> u16 {
        u16::try_from(self.payload["status"].as_u64().expect("HTTP status"))
            .expect("HTTP status width")
    }
}
pub(crate) async fn read(connection: &mut sqlx::PgConnection) -> anyhow::Result<Vec<Record>> {
    let rows: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT canonical FROM rss_audit.records ORDER BY tenant_id,position")
            .fetch_all(connection)
            .await?;
    rows.iter().map(|row| Record::decode(row)).collect()
}
pub(crate) fn decode_hex(lines: &str) -> anyhow::Result<Vec<Record>> {
    lines
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            anyhow::ensure!(line.len() % 2 == 0, "canonical hex length");
            let bytes = (0..line.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&line[i..i + 2], 16))
                .collect::<Result<Vec<_>, _>>()?;
            Record::decode(&bytes)
        })
        .collect()
}
