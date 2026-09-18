//! Instance-wide settings of the p2pnas module, as the administrator left them
//! in the console.
//!
//! Declared by `module.toml`'s `[[settings]]`, stored in `core.settings`, and
//! read back here through `/internal/modules/p2pnas/settings` — a module owns its
//! own schema and cannot read the core's tables, and a background worker (the
//! repair loop) has no user token for the public config route. The module is
//! named in the URL so the read works whether the instance shares one master
//! secret or a derived one per module.
//!
//! Every field here is read by code that acts on it: a knob that changes nothing
//! is worse than an absent one. What is deliberately NOT here:
//!
//! - `DATA_SHARDS` / `PARITY_SHARDS` (`p2pnas_core::erasure`) and
//!   `DEFAULT_CHUNK_SIZE` (`p2pnas_core::chunker`). They are not policy, they are
//!   the ENCODING of the bytes already on disk: a chunk written as 10+4 can only
//!   be reassembled as 10+4. Changing either at runtime would leave every
//!   existing file unreadable, silently, with no way back. They stay compiled in.
//!
//! Sizes are exposed and stored in BYTES, the unit the comparison sites use, so
//! there is no hidden conversion between the console and the check.

use serde_json::Value;

/// One GiB, the unit the byte-sized knobs are naturally read in.
const GIB: i64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceConfig {
    /// Quota, in BYTES, granted to a user who has no `p2pnas.user_quota` row
    /// yet. `0` = none, which is the historical behaviour (every account has to
    /// be allocated by hand before it can store anything).
    pub default_quota_bytes: i64,
    /// Ceiling, in BYTES, on a single upload. Enforced per request in
    /// `handlers::files::upload`; the router's `DefaultBodyLimit` is a separate,
    /// larger transport ceiling that this value may only sit under.
    pub max_upload_bytes: i64,
    /// Delay between two automatic repair passes, in seconds.
    pub repair_interval_secs: u64,
    /// Consecutive failed liveness probes before a peer is marked `down` and
    /// excluded from new placements.
    pub peer_down_threshold: i32,
    /// ISO country codes shards may be placed in. EMPTY means "not set here",
    /// NOT "everything allowed": the caller then falls back to `config.toml`'s
    /// `discovery.geoip_allow`, so a blank field can never quietly lift a
    /// jurisdiction constraint the operator wrote in the file.
    pub jurisdiction_allow: Vec<String>,
    /// Retention / reciprocity thresholds, in DAYS of owner absence, before this
    /// host acts on the data it stores for that owner. These are the network's
    /// backbone (an instance-wide setting); each is stretched per-owner by how
    /// reliable that owner has been (see `retention`), which is the "margin".
    ///   grace   — stop placing new shards on/for them; nothing is removed yet.
    ///   reclaim — shed the PARITY shards we host for them (data still fully
    ///             reconstructs the file, so this is reversible).
    ///   evict   — remove everything we host for them.
    pub retention_grace_days:   i64,
    pub retention_reclaim_days: i64,
    pub retention_evict_days:   i64,
}

impl Default for InstanceConfig {
    fn default() -> Self {
        Self {
            // No implicit allocation: same behaviour p2pnas has always had.
            default_quota_bytes:  0,
            // Mirrors `router::MAX_UPLOAD` (2 GiB).
            max_upload_bytes:     2 * GIB,
            // Mirrors the interval the repair loop used to hard-code.
            repair_interval_secs: 600,
            // Mirrors the `DOWN_THRESHOLD` constant `repair.rs` used to hold.
            peer_down_threshold:  5,
            jurisdiction_allow:   Vec::new(),
            // Generous by default: a fortnight of grace, six weeks before parity
            // is shed, half a year before full eviction — and reliable owners get
            // more still. Absence is not assumed to be bad faith.
            retention_grace_days:   14,
            retention_reclaim_days: 45,
            retention_evict_days:   180,
        }
    }
}

impl InstanceConfig {
    /// Maps the core's `{key: value}` object onto the struct. Every read falls
    /// back to the compiled default rather than to a permissive value: a missing,
    /// malformed or out-of-range entry is treated as a mistake and ignored, never
    /// as "no limit".
    pub fn from_settings(settings: &Value) -> Self {
        let d = Self::default();

        // Bounds duplicate module.toml's min/max on purpose: the console enforces
        // them, but a value written before a bound existed must not slip through.
        let default_quota_bytes  = int_in(settings, "default_quota_bytes", 0, 1024 * GIB)
            .unwrap_or(d.default_quota_bytes);
        let max_upload_bytes     = int_in(settings, "max_upload_bytes", 1024 * 1024, 2 * GIB)
            .unwrap_or(d.max_upload_bytes);
        let repair_interval_secs = int_in(settings, "repair_interval_secs", 60, 86_400)
            .map(|n| n as u64)
            .unwrap_or(d.repair_interval_secs);
        let peer_down_threshold  = int_in(settings, "peer_down_threshold", 1, 100)
            .map(|n| n as i32)
            .unwrap_or(d.peer_down_threshold);

        let jurisdiction_allow = settings
            .get("jurisdiction_allow")
            .and_then(Value::as_str)
            .map(parse_country_list)
            .unwrap_or(d.jurisdiction_allow);

        // Read each threshold within [1, 3650] days, then enforce ordering
        // (grace ≤ reclaim ≤ evict) so a misconfiguration can never make eviction
        // happen before grace.
        let retention_grace_days = int_in(settings, "retention_grace_days", 1, 3650)
            .unwrap_or(d.retention_grace_days);
        let retention_reclaim_days = int_in(settings, "retention_reclaim_days", 1, 3650)
            .unwrap_or(d.retention_reclaim_days)
            .max(retention_grace_days);
        let retention_evict_days = int_in(settings, "retention_evict_days", 1, 3650)
            .unwrap_or(d.retention_evict_days)
            .max(retention_reclaim_days);

        Self {
            default_quota_bytes,
            max_upload_bytes,
            repair_interval_secs,
            peer_down_threshold,
            jurisdiction_allow,
            retention_grace_days,
            retention_reclaim_days,
            retention_evict_days,
        }
    }
}

/// An integer setting, accepted only inside `[lo, hi]`. `None` for anything
/// missing, unparseable or out of range — the caller then keeps its compiled
/// default rather than a value nobody meant.
fn int_in(settings: &Value, key: &str, lo: i64, hi: i64) -> Option<i64> {
    settings
        .get(key)
        // A console that echoes a text field can send "600" for 600.
        .and_then(|v| match v {
            Value::Number(n) => n.as_i64(),
            Value::String(s) => s.trim().parse::<i64>().ok(),
            _ => None,
        })
        .filter(|n| (lo..=hi).contains(n))
}

/// Turns the textarea (one entry per line) into the country list the placement
/// filter compares against `p2pnas.peers.country`.
///
/// Entries are upper-cased and de-duplicated, and NOTHING is dropped for looking
/// wrong: an unrecognised entry simply matches no peer, which makes the list
/// STRICTER. Silently discarding it could empty the list and hand the decision
/// back to `config.toml` — the one outcome that would loosen the constraint.
fn parse_country_list(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        let code = line.trim().to_ascii_uppercase();
        if code.is_empty() || out.contains(&code) {
            continue;
        }
        out.push(code);
    }
    out
}

/// Reads the instance settings from the core. Any failure yields `None`, so the
/// caller keeps the values it already had rather than reverting to defaults
/// because the core was briefly unreachable.
pub async fn fetch(http: &reqwest::Client, core_url: &str, secret: &str) -> Option<InstanceConfig> {
    let url = format!("{core_url}/internal/modules/p2pnas/settings");
    let resp = http
        .get(&url)
        .header("X-Internal-Secret", secret)
        .send()
        .await
        .map_err(|e| tracing::warn!(error = %e, "Lecture des réglages d'instance p2pnas"))
        .ok()?;

    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "Réglages d'instance p2pnas refusés par le core");
        return None;
    }

    let body: Value = resp
        .json()
        .await
        .map_err(|e| tracing::warn!(error = %e, "Réglages d'instance p2pnas : réponse illisible"))
        .ok()?;

    Some(InstanceConfig::from_settings(body.get("settings")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_keys_keep_the_compiled_defaults() {
        let c = InstanceConfig::from_settings(&json!({}));
        assert_eq!(c, InstanceConfig::default());
        assert_eq!(c.default_quota_bytes, 0);
        assert_eq!(c.repair_interval_secs, 600);
        assert_eq!(c.peer_down_threshold, 5);
        assert_eq!(c.max_upload_bytes, 2 * GIB);
        assert!(c.jurisdiction_allow.is_empty());
    }

    #[test]
    fn retention_defaults_and_ordering() {
        let d = InstanceConfig::default();
        assert_eq!((d.retention_grace_days, d.retention_reclaim_days, d.retention_evict_days), (14, 45, 180));

        // A misconfiguration that puts evict before reclaim before grace is
        // clamped back into order, so eviction can never precede grace.
        let c = InstanceConfig::from_settings(&json!({
            "retention_grace_days":   90,
            "retention_reclaim_days": 10,
            "retention_evict_days":   5,
        }));
        assert!(c.retention_grace_days <= c.retention_reclaim_days);
        assert!(c.retention_reclaim_days <= c.retention_evict_days);
        assert_eq!(c.retention_grace_days, 90);
        assert_eq!(c.retention_reclaim_days, 90);
        assert_eq!(c.retention_evict_days, 90);
    }

    #[test]
    fn values_are_read() {
        let c = InstanceConfig::from_settings(&json!({
            "default_quota_bytes":  5_368_709_120i64,
            "max_upload_bytes":     104_857_600i64,
            "repair_interval_secs": 300,
            "peer_down_threshold":  3,
            "jurisdiction_allow":   "FR\nBE\n",
        }));
        assert_eq!(c.default_quota_bytes, 5_368_709_120);
        assert_eq!(c.max_upload_bytes, 104_857_600);
        assert_eq!(c.repair_interval_secs, 300);
        assert_eq!(c.peer_down_threshold, 3);
        assert_eq!(c.jurisdiction_allow, vec!["FR".to_string(), "BE".to_string()]);
    }

    #[test]
    fn strings_are_accepted_for_ints() {
        let c = InstanceConfig::from_settings(&json!({ "repair_interval_secs": " 900 " }));
        assert_eq!(c.repair_interval_secs, 900);
    }

    #[test]
    fn out_of_range_values_fall_back() {
        // Below the floor, above the ceiling, negative, and not a number at all.
        assert_eq!(
            InstanceConfig::from_settings(&json!({ "repair_interval_secs": 5 })).repair_interval_secs,
            600
        );
        assert_eq!(
            InstanceConfig::from_settings(&json!({ "repair_interval_secs": 999_999 })).repair_interval_secs,
            600
        );
        assert_eq!(
            InstanceConfig::from_settings(&json!({ "peer_down_threshold": 0 })).peer_down_threshold,
            5
        );
        assert_eq!(
            InstanceConfig::from_settings(&json!({ "default_quota_bytes": -1 })).default_quota_bytes,
            0
        );
        // An upload ceiling above the transport limit is refused, not clamped up.
        assert_eq!(
            InstanceConfig::from_settings(&json!({ "max_upload_bytes": 9 * GIB })).max_upload_bytes,
            2 * GIB
        );
        assert_eq!(
            InstanceConfig::from_settings(&json!({ "max_upload_bytes": "beaucoup" })).max_upload_bytes,
            2 * GIB
        );
    }

    #[test]
    fn country_list_is_normalised_and_deduplicated() {
        let c = InstanceConfig::from_settings(&json!({
            "jurisdiction_allow": "  fr \n\nBE\nfr\n  \nch",
        }));
        assert_eq!(
            c.jurisdiction_allow,
            vec!["FR".to_string(), "BE".to_string(), "CH".to_string()]
        );
    }

    #[test]
    fn blank_country_list_means_unset_not_permissive() {
        // Empty here → the caller keeps config.toml's list (see `distribute_shards`).
        let c = InstanceConfig::from_settings(&json!({ "jurisdiction_allow": "  \n \n" }));
        assert!(c.jurisdiction_allow.is_empty());
    }
}
