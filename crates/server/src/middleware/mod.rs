use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::{errors::P2pError, state::AppState};

/// Constant-time byte-slice equality. Comparing a shared secret with `!=` returns
/// as soon as the first differing byte is found, which leaks — through response
/// timing — how long a common prefix the attacker guessed, letting the secret be
/// reconstructed byte by byte. This compares every byte regardless. The length
/// check leaks only the secret's length (a server-side constant), never content.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Gate the `/ipc/*` surface: those routes carry no user, so the shared internal
/// secret is the ONLY thing standing between them and anyone who can reach the
/// module's port. An empty configured secret is refused as well — a blank value
/// would otherwise let a request with a blank header through.
pub async fn require_ipc_secret(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, P2pError> {
    let expected = state.settings.core.internal_secret.as_str();
    let provided = req
        .headers()
        .get("x-internal-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if expected.is_empty() || !constant_time_eq(provided.as_bytes(), expected.as_bytes()) {
        return Err(P2pError::Unauthorized);
    }
    Ok(next.run(req).await)
}

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

/// This module's id, used as the token audience: a token minted by the core for
/// another module does not validate here.
const MODULE_ID: &str = "p2pnas";

/// Authenticate the caller from the signed `X-Kubuno-Auth` token the core mints
/// with this module's internal secret (see `kubuno-modauth`), and stash the user
/// in the request extensions.
///
/// The plain `X-Kubuno-User-*` headers are no longer trusted: any process able
/// to reach this module’s loopback port (`:3123`) could set them to impersonate
/// any user — administrators included, which here means seizing another user's
/// files and every peer/quota control. The token binds the identity to the
/// module secret and carries a short expiry, so a forged or replayed header is
/// rejected. This is especially load-bearing for p2pnas, whose whole point is to
/// hold data on behalf of users who must never see each other's files.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, P2pError> {
    let token = req
        .headers()
        .get(kubuno_modauth::TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(P2pError::Unauthorized)?;

    let user = kubuno_modauth::verify(
        state.settings.core.internal_secret.as_bytes(),
        token,
        MODULE_ID,
    )
    .map_err(|_| P2pError::Unauthorized)?;

    req.extensions_mut().insert(P2pUser {
        id:    user.id,
        role:  user.role,
        email: user.email,
    });
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
