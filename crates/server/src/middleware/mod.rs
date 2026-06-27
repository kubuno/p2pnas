use axum::{extract::Request, middleware::Next, response::Response};
use uuid::Uuid;

use crate::errors::P2pError;

/// The authenticated user, extracted from headers the core proxy injects.
#[derive(Debug, Clone)]
pub struct P2pUser {
    pub id:    Uuid,
    pub role:  String,
    pub email: String,
}

impl P2pUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

/// Trust the `X-Kubuno-User-*` headers injected by the core proxy and stash the
/// user in the request extensions.
pub async fn require_auth(mut req: Request, next: Next) -> Result<Response, P2pError> {
    let id = req
        .headers()
        .get("x-kubuno-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(P2pError::Unauthorized)?;
    let role = req
        .headers()
        .get("x-kubuno-user-role")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("user")
        .to_string();
    let email = req
        .headers()
        .get("x-kubuno-user-email")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    req.extensions_mut().insert(P2pUser { id, role, email });
    Ok(next.run(req).await)
}

/// Gate admin-only routes (runs after `require_auth`).
pub async fn require_admin(req: Request, next: Next) -> Result<Response, P2pError> {
    let is_admin = req
        .extensions()
        .get::<P2pUser>()
        .map(|u| u.is_admin())
        .unwrap_or(false);
    if !is_admin {
        return Err(P2pError::Forbidden);
    }
    Ok(next.run(req).await)
}
