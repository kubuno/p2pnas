//! Latency-aware shard placement.
//!
//! Given the measured round-trip latency to each candidate peer, decide where a
//! chunk's `total` shards go. Two objectives are balanced:
//!
//! - **Durability**: every location (the owner's own store included) holds at
//!   most `parity` shards, so losing any single location — including the owner's
//!   disk — leaves at least `total - parity` (= DATA_SHARDS) shards reachable and
//!   the chunk reconstructable.
//! - **Locality**: among locations under their cap, shards prefer the lowest
//!   latency (the owner is latency 0), so normal reads gather nearby shards.
//!
//! A greedy minimises `normalized_rtt + α·current_count` per shard; the count
//! term spreads load (and thus latency-clusters), the rtt term pulls toward near
//! peers. When every location is already at `parity`, the overflow stays local.

/// A placement decision for one shard: `None` keeps it on the owner (self,
/// latency 0); `Some(i)` sends it to `peers[i]`.
pub type Placement = Option<usize>;

/// Plan placement for `total` shards over the owner + `peer_rtt` (ms) peers.
pub fn plan_placement(peer_rtt: &[f64], total: usize, parity: usize) -> Vec<Placement> {
    let max_rtt = peer_rtt.iter().copied().fold(1.0_f64, f64::max);
    let alpha = 1.0 / parity.max(1) as f64; // concentration weight
    let mut peer_count = vec![0usize; peer_rtt.len()];
    let mut self_count = 0usize;
    let mut out = Vec::with_capacity(total);

    for _ in 0..total {
        // Pick the under-cap location with the lowest score. `None` = self (rtt 0).
        // Self's score is its concentration term only (rtt 0); if it's at cap, the
        // threshold stays +inf so a peer (or self-overflow) is taken instead.
        let mut best: Placement = None;
        let mut best_score = if self_count < parity { alpha * self_count as f64 } else { f64::INFINITY };

        for (i, &rtt) in peer_rtt.iter().enumerate() {
            if peer_count[i] >= parity {
                continue;
            }
            let score = rtt / max_rtt + alpha * peer_count[i] as f64;
            if score < best_score {
                best_score = score;
                best = Some(i);
            }
        }

        match best {
            Some(i) => peer_count[i] += 1,
            // self chosen, or every location at cap → overflow stays local.
            None => self_count += 1,
        }
        out.push(best);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
            let n = p.iter().filter(|x| **x == Some(i)).count();
            assert!(n <= 4, "peer {i} holds {n} > parity");
        }
        // The nearest peer should hold at least as many as the farthest.
        let near = p.iter().filter(|x| **x == Some(0)).count();
        let far = p.iter().filter(|x| **x == Some(2)).count();
        assert!(near >= far, "near peer {near} should hold >= far peer {far}");
    }

    #[test]
    fn overflow_to_self_when_too_few_peers() {
        // 1 peer can hold at most `parity`; the rest overflow to self.
        let p = plan_placement(&[20.0], 14, 4);
        let peer_n = p.iter().filter(|x| **x == Some(0)).count();
        assert_eq!(peer_n, 4);
        assert_eq!(p.iter().filter(|x| x.is_none()).count(), 10);
    }
}
