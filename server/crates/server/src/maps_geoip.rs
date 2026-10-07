//! Thin client for the **maps** module's GeoIP service. p2pnas doesn't ship a
//! GeoIP database — maps owns that — so we resolve a peer's country by calling
//! maps through the core proxy. The call carries a user context (it runs inside
//! an authenticated request such as upload), so the standard `/api/v1/maps/...`
//! proxy is used rather than an internal endpoint.

use serde::Deserialize;
use uuid::Uuid;

use crate::state::AppState;

/// Outcome of a GeoIP lookup, distinguishing "maps is unavailable" (so the caller
/// can surface a clear "geo option needs the maps module" message) from "resolved
/// but unknown country".
pub enum GeoOutcome {
    /// maps answered: Some(country) or None (IP not in the database).
    Resolved(Option<String>),
    /// maps is not installed / not active / unreachable.
    Unavailable,
}

#[derive(Deserialize)]
struct GeoipResponse {
    available: bool,
    country:   Option<String>,
}

/// Resolve `ip`'s ISO country via maps (through the core proxy, as `user`).
pub async fn country(st: &AppState, user: Uuid, ip: &str) -> GeoOutcome {
    let url = format!("{}/api/v1/maps/geoip", st.settings.core.url.trim_end_matches('/'));
    let resp = st
        .http
        .get(&url)
        .query(&[("ip", ip)])
        .header("X-Internal-Secret", st.settings.core.internal_secret.as_str())
        .header("X-Kubuno-User-Id", user.to_string())
        .send()
        .await;
    match resp {
        Ok(r) if r.status().is_success() => match r.json::<GeoipResponse>().await {
            Ok(body) if body.available => GeoOutcome::Resolved(body.country),
            // maps reachable but no database loaded → treat as unavailable so the
            // jurisdiction constraint isn't silently bypassed.
            Ok(_) => GeoOutcome::Unavailable,
            Err(_) => GeoOutcome::Unavailable,
        },
        // 404 = maps not registered with the core (module disabled / not installed).
        _ => GeoOutcome::Unavailable,
    }
}
