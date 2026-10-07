//! Latency-, reliability- and failure-zone-aware shard placement.
//!
//! Given the measured round-trip latency, the failure zone and the reliability
//! score of each candidate peer, decide where a chunk's `total` shards go. Three
//! objectives are balanced:
//!
//! - **Durability**: every *location* (the owner's own store included) holds at
//!   most `parity` shards, AND every *failure zone* holds at most `parity` shards.
//!   Losing any single location — or any single zone — therefore leaves at least
//!   `total - parity` (= DATA_SHARDS) shards reachable and the chunk
//!   reconstructable.
//! - **Reliability**: at comparable latency, a peer that has been answering
//!   reliably is preferred over a flaky one (`peers.reliability_score`, 0..100).
//! - **Locality**: among locations under their caps, shards prefer the lowest
//!   latency (the owner is latency 0), so normal reads gather nearby shards.
//!
//! The zone cap is what a per-peer cap alone cannot give: the greedy favours low
//! latency, and low latency means "same LAN / same building / same ISP" — often
//! the same power strip and the same box. Without a zone cap the neighbour's
//! outage can take several shards at once, which RS 10+4 does not survive.
//!
//! A greedy minimises
//! `normalized_rtt + α·current_count + β·(1 − reliability/100)` per shard: the
//! count term spreads load (and thus latency-clusters), the rtt term pulls toward
//! near peers, the reliability term breaks ties toward dependable hosts.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// Weight of the reliability penalty in the greedy score. The rtt term spans
/// 0..1 (normalized) and the concentration term spans 0..1 (α·parity), so 0.5
/// lets reliability outweigh a *moderate* latency difference — a peer at half
/// score reliability loses against an equally-distant healthy peer — without ever
/// letting it outweigh a peer that is an order of magnitude nearer.
const RELIABILITY_WEIGHT: f64 = 0.5;

/// A placement decision for one shard: `None` keeps it on the owner (self,
/// latency 0); `Some(i)` sends it to `peers[i]`.
pub type Placement = Option<usize>;

/// One candidate remote location for a shard.
#[derive(Clone, Debug)]
pub struct PeerCandidate {
    /// Measured round-trip latency in milliseconds.
    pub rtt_ms:      f64,
    /// Correlated-failure zone. Peers sharing a zone are assumed to fail
    /// together (same subnet ⇒ usually same site, same uplink, same power).
    /// `None` means "unknown": the peer is then treated as its own zone, which
    /// degrades to the plain per-peer cap rather than lumping every unknown peer
    /// into one artificial zone.
    pub zone:        Option<String>,
    /// `peers.reliability_score`, 0..100 (100 = always answered so far).
    pub reliability: f64,
}

impl PeerCandidate {
    /// A candidate with no zone information and full reliability — the values
    /// that reproduce the historical latency-only behaviour.
    pub fn new(rtt_ms: f64) -> Self {
        PeerCandidate { rtt_ms, zone: None, reliability: 100.0 }
    }
}

/// Derive a coarse failure zone from a peer address (`ip`, `ip:port` or
/// `[v6]:port`): the /24 for IPv4, the /64 for IPv6.
///
/// This is a heuristic, not a truth: two hosts in the same /24 are almost always
/// behind the same uplink, while two hosts in different /24s may still share a
/// datacentre. It is the strongest signal available without an operator-supplied
/// label, and it is exactly the case the greedy would otherwise fall into (all
/// the nearest peers being LAN neighbours). An explicit `peers.zone` label always
/// wins over this derivation.
pub fn zone_of_addr(addr: &str) -> Option<String> {
    match ip_of_addr(addr)? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
        }
        IpAddr::V6(v6) => {
            // An IPv4-mapped address is really IPv4: use the v4 zone so the two
            // spellings of the same host cannot land in two different zones.
            if let Some(v4) = v6.to_ipv4_mapped() {
                let o = v4.octets();
                return Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]));
            }
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3]))
        }
    }
}

/// Extract the IP from `ip`, `ip:port` or `[v6]:port`; `None` for a hostname.
fn ip_of_addr(addr: &str) -> Option<IpAddr> {
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    let host = match addr.strip_prefix('[') {
        Some(rest) => rest.split(']').next()?,
        None => addr.rsplit_once(':').map(|(h, _)| h)?,
    };
    host.parse::<IpAddr>().ok()
}

/// Plan placement for `total` shards over the owner + `peer_rtt` (ms) peers.
///
/// Latency-only compatibility shim: no zone information, every peer assumed
/// fully reliable. Prefer [`plan_placement_zoned`], which also spreads across
/// failure zones.
pub fn plan_placement(peer_rtt: &[f64], total: usize, parity: usize) -> Vec<Placement> {
    let peers: Vec<PeerCandidate> = peer_rtt.iter().copied().map(PeerCandidate::new).collect();
    plan_placement_zoned(&peers, None, total, parity)
}

/// Plan placement for `total` shards over the owner + `peers`.
///
/// `self_zone` is the owner's own failure zone, when known: pass `Some(z)` to
/// have the owner share a zone budget with the peers in `z`, `None` to treat the
/// owner as its own zone (the safe default — the owner's disk is already bounded
/// by the per-location cap, and grouping it with its LAN neighbours would push
/// most shards back onto that same disk when no distant peer exists).
///
/// **Graceful degradation.** When every location is blocked by its *zone* cap,
/// the cap is relaxed (per-peer cap only) rather than failing or hoarding the
/// surplus locally: a second shard on an already-loaded remote zone is still
/// strictly better for durability than a second shard on our own disk, which is
/// itself a single point of failure. Only when every peer has reached its
/// per-peer cap does the surplus stay local, as before.
pub fn plan_placement_zoned(
    peers: &[PeerCandidate],
    self_zone: Option<&str>,
    total: usize,
    parity: usize,
) -> Vec<Placement> {
    let max_rtt = peers.iter().map(|p| p.rtt_ms).fold(1.0_f64, f64::max);
    let alpha = 1.0 / parity.max(1) as f64; // concentration weight

    // Zone key per peer. Unknown zone → a key nothing else can collide with, so
    // an unlabelled peer only ever constrains itself.
    let zone_key: Vec<String> = peers
        .iter()
        .enumerate()
        .map(|(i, p)| match p.zone.as_deref().filter(|z| !z.is_empty()) {
            Some(z) => format!("zone:{z}"),
            None => format!("unzoned-peer:{i}"),
        })
        .collect();
    let self_key = match self_zone.filter(|z| !z.is_empty()) {
        Some(z) => format!("zone:{z}"),
        None => "zone:@self".to_string(),
    };

    let mut zone_count: HashMap<&str, usize> = HashMap::new();
    let mut peer_count = vec![0usize; peers.len()];
    let mut self_count = 0usize;
    let mut out = Vec::with_capacity(total);

    for _ in 0..total {
        // Two passes: honour the zone caps first, relax them only if that leaves
        // nowhere to go (see "Graceful degradation" above).
        let mut choice: Option<Placement> = None;
        for honor_zones in [true, false] {
            let mut best: Option<Placement> = None;
            let mut best_score = f64::INFINITY;

            // Self (rtt 0, reliability of our own disk taken as full): its score
            // is the concentration term only.
            let self_zone_ok =
                !honor_zones || zone_count.get(self_key.as_str()).copied().unwrap_or(0) < parity;
            if self_count < parity && self_zone_ok {
                best = Some(None);
                best_score = alpha * self_count as f64;
            }

            for (i, p) in peers.iter().enumerate() {
                if peer_count[i] >= parity {
                    continue;
                }
                if honor_zones && zone_count.get(zone_key[i].as_str()).copied().unwrap_or(0) >= parity {
                    continue;
                }
                let unreliability = 1.0 - p.reliability.clamp(0.0, 100.0) / 100.0;
                let score = p.rtt_ms / max_rtt
                    + alpha * peer_count[i] as f64
                    + RELIABILITY_WEIGHT * unreliability;
                if score < best_score {
                    best_score = score;
                    best = Some(Some(i));
                }
            }

            if best.is_some() {
                choice = best;
                break;
            }
        }

        // Outer `None` = nothing placeable anywhere → overflow stays local, which
        // flattens to the same `None` as "self was the best choice".
        let placement: Placement = choice.flatten();
        match placement {
            Some(i) => {
                peer_count[i] += 1;
                *zone_count.entry(zone_key[i].as_str()).or_default() += 1;
            }
            None => {
                self_count += 1;
                *zone_count.entry(self_key.as_str()).or_default() += 1;
            }
        }
        out.push(placement);
    }
    out
}

/// Jurisdiction check: with an empty allow-list everything passes; otherwise a
/// peer must have a known country that is on the list (unknown → rejected).
pub fn jurisdiction_allowed(allow: &[String], country: Option<&str>) -> bool {
    allow.is_empty() || country.is_some_and(|c| allow.iter().any(|a| a == c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(rtt: f64, zone: &str, reliability: f64) -> PeerCandidate {
        PeerCandidate { rtt_ms: rtt, zone: Some(zone.to_string()), reliability }
    }

    fn count(plan: &[Placement], peer: usize) -> usize {
        plan.iter().filter(|x| **x == Some(peer)).count()
    }

    #[test]
    fn jurisdiction_filter() {
        // No allow-list → anything passes (even unknown country).
        assert!(jurisdiction_allowed(&[], None));
        assert!(jurisdiction_allowed(&[], Some("US")));
        let allow = vec!["FR".to_string(), "BE".to_string()];
        assert!(jurisdiction_allowed(&allow, Some("FR")));
        assert!(!jurisdiction_allowed(&allow, Some("US")));
        // Unknown country is rejected when a list is set (conservative).
        assert!(!jurisdiction_allowed(&allow, None));
    }

    #[test]
    fn respects_cap_and_prefers_near() {
        // 14 shards, parity 4, 3 peers with rising latency.
        let rtt = [10.0, 30.0, 250.0];
        let p = plan_placement(&rtt, 14, 4);
        assert_eq!(p.len(), 14);
        // No location exceeds the parity cap (self counted as None).
        let self_n = p.iter().filter(|x| x.is_none()).count();
        assert!(self_n <= 4, "self holds {self_n} > parity");
        for i in 0..3 {
            let n = count(&p, i);
            assert!(n <= 4, "peer {i} holds {n} > parity");
        }
        // The nearest peer should hold at least as many as the farthest.
        assert!(count(&p, 0) >= count(&p, 2), "near peer should hold >= far peer");
    }

    #[test]
    fn overflow_to_self_when_too_few_peers() {
        // 1 peer can hold at most `parity`; the rest overflow to self.
        let p = plan_placement(&[20.0], 14, 4);
        assert_eq!(count(&p, 0), 4);
        assert_eq!(p.iter().filter(|x| x.is_none()).count(), 10);
    }

    #[test]
    fn zone_derivation() {
        assert_eq!(zone_of_addr("192.168.1.42:7490"), Some("192.168.1.0/24".into()));
        assert_eq!(zone_of_addr("192.168.1.99"), Some("192.168.1.0/24".into()));
        assert_eq!(zone_of_addr("[2001:db8:1:2:3:4:5:6]:7490"), Some("2001:db8:1:2::/64".into()));
        assert_eq!(zone_of_addr("2001:db8:1:2:3:4:5:6"), Some("2001:db8:1:2::/64".into()));
        // An IPv4-mapped v6 address must land in the SAME zone as its v4 form.
        assert_eq!(zone_of_addr("::ffff:192.168.1.7"), zone_of_addr("192.168.1.7"));
        // A hostname carries no zone signal.
        assert_eq!(zone_of_addr("peer.example.org:7490"), None);
    }

    #[test]
    fn zone_cap_beats_latency() {
        // Three near neighbours in ONE zone (the "same house" case) plus one
        // distant peer in another. Latency alone would pile everything on the
        // near zone; the zone cap must hold it to `parity`. 12 shards = exactly
        // the capacity of the 3 zones (self + LAN + far), so no relaxation.
        let peers = vec![
            candidate(5.0, "192.168.1.0/24", 100.0),
            candidate(6.0, "192.168.1.0/24", 100.0),
            candidate(7.0, "192.168.1.0/24", 100.0),
            candidate(200.0, "203.0.113.0/24", 100.0),
        ];
        let p = plan_placement_zoned(&peers, None, 12, 4);
        let lan: usize = (0..3).map(|i| count(&p, i)).sum();
        assert_eq!(lan, 4, "the LAN zone must be capped at parity, got {lan}");
        // The distant zone and the owner absorb the rest, each under its own cap.
        assert_eq!(count(&p, 3), 4);
        assert_eq!(p.iter().filter(|x| x.is_none()).count(), 4);
    }

    #[test]
    fn reliability_breaks_ties_at_equal_latency() {
        // Same latency, same (empty) zone pressure: the dependable peer must win.
        let peers = vec![candidate(5.0, "a", 100.0), candidate(5.0, "b", 20.0)];
        let p = plan_placement_zoned(&peers, None, 6, 4);
        assert!(
            count(&p, 0) > count(&p, 1),
            "reliable peer holds {}, flaky peer holds {} — reliability did not break the tie",
            count(&p, 0),
            count(&p, 1)
        );
    }

    #[test]
    fn degrades_gracefully_when_zones_are_scarce() {
        // Only ONE zone available: the zone cap cannot be honoured for 14 shards.
        // The surplus must still go remote (up to each peer's own cap) instead of
        // collapsing onto the owner's single disk.
        let peers = vec![candidate(10.0, "same", 100.0), candidate(20.0, "same", 100.0)];
        let p = plan_placement_zoned(&peers, None, 14, 4);
        assert_eq!(p.len(), 14);
        let remote = p.iter().filter(|x| x.is_some()).count();
        assert_eq!(remote, 8, "both peers should be filled to their per-peer cap");
        assert_eq!(count(&p, 0), 4);
        assert_eq!(count(&p, 1), 4);
    }

    #[test]
    fn self_zone_shares_the_budget_when_declared() {
        // Declaring the owner inside the LAN zone makes owner + LAN neighbour
        // share ONE budget of `parity`; the distant peer then picks up the slack.
        let peers = vec![candidate(5.0, "lan", 100.0), candidate(300.0, "far", 100.0)];
        let shared = plan_placement_zoned(&peers, Some("lan"), 8, 4);
        let lan = count(&shared, 0) + shared.iter().filter(|x| x.is_none()).count();
        assert_eq!(lan, 4, "owner + LAN neighbour share one budget, got {lan}");
        assert_eq!(count(&shared, 1), 4, "the surplus must go to the distant zone");

        // Without the declaration the owner is its own zone, so the same eight
        // shards never leave the LAN — that is exactly the risk the label fixes.
        let split = plan_placement_zoned(&peers, None, 8, 4);
        assert_eq!(count(&split, 1), 0);
    }

    #[test]
    fn no_zone_ever_exceeds_the_cap_when_zones_are_plentiful() {
        let peers: Vec<PeerCandidate> =
            (0..6).map(|i| candidate(10.0 * (i + 1) as f64, &format!("z{i}"), 100.0)).collect();
        let p = plan_placement_zoned(&peers, None, 14, 4);
        let mut per_zone: HashMap<String, usize> = HashMap::new();
        for slot in &p {
            let key = match slot {
                Some(i) => format!("z{i}"),
                None => "self".to_string(),
            };
            *per_zone.entry(key).or_default() += 1;
        }
        for (zone, n) in &per_zone {
            assert!(*n <= 4, "zone {zone} holds {n} > parity");
        }
    }
}
