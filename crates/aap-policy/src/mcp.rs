use crate::{Authentication, Catalog, ResourceProfile};
use aap_types::{
    ErrorCode, Result,
    mcp::{MAX_REQUEST, MAX_RESPONSE, Tool, validate_tools},
};
use std::collections::BTreeSet;

impl ResourceProfile {
    pub(crate) fn validate_mcp(&self, tools: &[Tool], header: &str) -> Result<()> {
        validate_tools(tools)?;
        if matches!(header, "content-type" | "accept" | "mcp-protocol-version")
            || !(1..=2).contains(&self.routes.len())
            || !self.routes.iter().any(|route| route.method == "POST")
            || self.routes.iter().any(|route| {
                !matches!(route.method.as_str(), "POST" | "DELETE")
                    || route.path != self.routes[0].path
                    || route.query.is_some()
                    || route.streaming
                    || route.max_request_bytes > MAX_REQUEST
                    || route.max_response_bytes > MAX_RESPONSE
                    || route.allowed_headers.iter().any(|name| {
                        !matches!(
                            name.as_str(),
                            "content-type" | "accept" | "mcp-protocol-version"
                        )
                    })
            })
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(())
    }
}

impl Catalog {
    pub(crate) fn validate_mcp_bindings(&self, profiles: &[ResourceProfile]) -> Result<()> {
        let mcp_profiles: BTreeSet<_> = profiles
            .iter()
            .filter(|profile| matches!(profile.auth, Authentication::Mcp { .. }))
            .map(|profile| profile.id.as_str())
            .collect();
        let endpoints: BTreeSet<_> = profiles
            .iter()
            .filter(|profile| mcp_profiles.contains(profile.id.as_str()))
            .map(|profile| (profile.origin.as_str(), profile.routes[0].path.as_str()))
            .collect();
        for other in profiles
            .iter()
            .filter(|profile| !mcp_profiles.contains(profile.id.as_str()))
        {
            if other
                .routes
                .iter()
                .any(|route| endpoints.contains(&(other.origin.as_str(), route.path.as_str())))
            {
                return Err(ErrorCode::RequestInvalid.into());
            }
        }
        // A native item enrolled for MCP cannot be reused through a raw route,
        // even at another origin/path. Separate aliases/records are trusted
        // choices, not discovered by comparing or fingerprinting secret values.
        let key =
            |item: &'_ crate::Item| (item.credential.store.clone(), item.credential.key.clone());
        let mcp_keys: BTreeSet<_> = self
            .items
            .iter()
            .filter(|item| mcp_profiles.contains(item.profile.as_str()))
            .map(key)
            .collect();
        if self
            .items
            .iter()
            .filter(|item| !mcp_profiles.contains(item.profile.as_str()))
            .any(|item| mcp_keys.contains(&key(item)))
        {
            return Err(ErrorCode::RequestInvalid.into());
        }
        Ok(())
    }
}
