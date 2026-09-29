pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> Option<i64>;
}
