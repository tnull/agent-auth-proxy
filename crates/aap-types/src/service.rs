//! Runtime-neutral, session-scoped service surface for all agent adapters.

use crate::{BoxFuture, protocol::*};

pub type Body = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, Error>;
pub type Response = http::Response<Body>;

/// This handle is created by the trusted host, never from a caller-supplied ID.
/// Implementations must enforce shared session quotas across every frontend.
pub trait AgentService: Send + Sync {
    fn execute(&self, request: ExecuteRequest) -> BoxFuture<'_, Result<Response>>;
    /// Register one destination-bound stream attachment without starting its
    /// upstream connection. Unsupported adapters fail closed by default.
    fn open_stream(
        &self,
        _request: crate::stream::Open,
    ) -> BoxFuture<'_, Result<crate::stream::service::Admission>> {
        Box::pin(async { Err(ErrorCode::AuthProfileUnsupported.into()) })
    }
    /// Trusted adapter seam: resolve a unique enrolled profile and use the same
    /// authorized pipeline. Not exposed as a separate local JSON/MCP operation.
    fn forward(&self, _request: crate::proxy::ForwardRequest) -> BoxFuture<'_, Result<Response>> {
        Box::pin(async { Err(ErrorCode::AuthProfileUnsupported.into()) })
    }
    fn search_items(&self, request: SearchItems) -> BoxFuture<'_, Result<SearchResult>>;
    fn get_login(&self, request: GetLogin) -> BoxFuture<'_, Result<Login>>;
    fn auth_status(&self, request: AuthContext) -> BoxFuture<'_, Result<AuthStatus>>;
    fn logout(&self, request: AuthContext) -> BoxFuture<'_, Result<Logout>>;
    fn request_status(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>>;
    fn cancel(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>>;

    /// Authorize a TLS CONNECT authority before issuing an interception leaf.
    /// Each request inside the connection must still pass through the engine's
    /// authorized forwarding/execution pipeline.
    fn admit_connect(&self, authority: String) -> BoxFuture<'_, Result<()>>;
}
