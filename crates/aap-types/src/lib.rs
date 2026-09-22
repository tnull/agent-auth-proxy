//! Credential-free public contracts shared by agent adapters and the trusted engine.

pub mod ids;
pub mod json;
pub mod mcp;
pub mod profile;
pub mod protocol;
pub mod proxy;
pub mod service;
pub mod stream;
pub mod wire;

pub use protocol::*;
pub use service::{AgentService, Body, Response};

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
