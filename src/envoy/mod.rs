//! Envoy Proxy integration suite for SATGuardian Edge WAF.
//! Provides native ext_authz HTTP/gRPC filter services and configuration helpers.

pub mod ext_authz;

pub use ext_authz::{create_envoy_authz_router, EnvoyAuthzState};
#[cfg(unix)]
pub use ext_authz::serve_uds;

