//! Local fixture composition and verification support; not a production MDM server.
pub mod app;
pub mod failure;
pub mod fixture;
mod storage;
pub use storage::{BUDGET, Clock, options};
mod window;
