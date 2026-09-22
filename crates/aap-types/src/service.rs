//! Runtime-neutral, session-scoped service surface for all agent adapters.

use crate::{BoxFuture, protocol::*};

pub type Body = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, Error>;
pub type Response = http::Response<Body>;

/// This handle is created by the trusted host, never from a caller-supplied ID.
/// Implementations must enforce shared session quotas across every frontend.
pub trait AgentService: Send + Sync {
    fn execute(&self, request: ExecuteRequest) -> BoxFuture<'_, Result<Response>>;
    fn search_items(&self, request: SearchItems) -> BoxFuture<'_, Result<SearchResult>>;
    fn get_login(&self, request: GetLogin) -> BoxFuture<'_, Result<Login>>;
    fn auth_status(&self, request: AuthContext) -> BoxFuture<'_, Result<AuthStatus>>;
    fn logout(&self, request: AuthContext) -> BoxFuture<'_, Result<Logout>>;
    fn request_status(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>>;
    fn cancel(&self, request_id: String) -> BoxFuture<'_, Result<OperationStatus>>;

    /// Authorize a TLS CONNECT authority before issuing an interception leaf.
    /// Each request inside the connection must still pass through `execute`.
    fn admit_connect(&self, authority: String) -> BoxFuture<'_, Result<()>>;
}
