//! Credential-free public contracts shared by agent adapters and the trusted engine.

pub mod ids;
pub mod json;
pub mod protocol;
pub mod service;

pub use protocol::*;
pub use service::{AgentService, Body, Response};

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
