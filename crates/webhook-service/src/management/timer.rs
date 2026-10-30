use std::sync::Arc;
use rss_request_context::{Clock,Deadline,ExecutionTimer};
trait Driver: Send+Sync {
    fn now(&self)->std::time::Instant;
    fn sleep(&self,deadline:Deadline)->futures::future::BoxFuture<'_,()>;
}
impl<T:ExecutionTimer> Driver for T {
    fn now(&self)->std::time::Instant {Clock::now(self)}
    fn sleep(&self,deadline:Deadline)->futures::future::BoxFuture<'_,()> {Box::pin(self.sleep_until(deadline))}
}
#[derive(Clone)]
pub(super) struct Timer(Arc<dyn Driver>);
impl Timer {pub(super) fn new<T:ExecutionTimer+'static>(timer:T)->Self {Self(Arc::new(timer))}}
impl Clock for Timer {fn now(&self)->std::time::Instant {self.0.now()}}
impl ExecutionTimer for Timer {async fn sleep_until(&self,deadline:Deadline) {self.0.sleep(deadline).await;}}
