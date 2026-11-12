use rss_transactional_messaging_postgres::PgTransaction;
/// Application composition sums the concrete owners under the existing device lock.
pub trait DeviceCapacity: Send + Sync {
    fn available_in<'a>(
        &'a self,
        tx: &'a mut PgTransaction<'_>,
        device: &'a rss_mdm_agent_wire::DeviceId,
        now: i64,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<bool, super::Error>> + Send + 'a>>;
}
