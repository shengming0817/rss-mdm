//! One invocation's captured journal horizon; persistent projection generation stays live.
use crate::storage::Clock;
use rss_observation_postgres::PgSource;
use rss_projection::{BatchLimit, Error, ErrorKind, Event, Position, Source, SourceScope};
use std::sync::Arc;
pub struct Window {
    pub source: Arc<PgSource<Clock>>,
    pub through: Option<Position>,
}
impl Source for Window {
    async fn high_water(&self, scope: &SourceScope) -> Result<Option<Position>, Error> {
        if scope != self.source.scope() {
            return Err(Error::new(ErrorKind::ScopeMismatch));
        }
        Ok(self.through)
    }
    async fn read(
        &self,
        scope: &SourceScope,
        after: Option<Position>,
        limit: BatchLimit,
    ) -> Result<Vec<Event>, Error> {
        self.high_water(scope).await?;
        if self.through.is_none() || after >= self.through {
            return Ok(vec![]);
        }
        let mut events = self.source.read(scope, after, limit).await?;
        events.retain(|event| Some(event.position()) <= self.through);
        Ok(events)
    }
}
