//! Self-healing repair pass. Scans every file's shard placement, detects shards
//! that are durably gone, and — as long as at least `DATA_SHARDS` of a chunk's 14
//! shards are still reachable — reconstructs the chunk and re-replicates the lost
//! shards onto healthy locations (this node or a reachable peer).
//!
//! This is what turns the round-robin *spread* (phase 3b) into genuine durability:
//! a chunk placed so that no location holds more than `PARITY_SHARDS` shards stays
//! recoverable across a single failure, and a repair pass restores the redundancy
//! before a second failure can take it below the reconstruction threshold.
//!
//! Three rules shape what the pass actually does, and each exists because the
//! naive version of it was wrong:
//!
//! - **Local scrubbing.** A local shard used to be judged healthy by a bare
//!   `exists()`, so silent bit rot on our own disk was only ever discovered when a
//!   user tried to read the file — while remote shards were hash-audited on every
//!   pass. A rotating sample of the local shards is now byte-verified against the
//!   manifest hash; a corrupt one is treated as lost and rebuilt from parity.
//! - **Grace period.** "Missing" used to mean "its host did not answer this
//!   second", which turned every personal machine switched off for the night into
//!   a full re-replication of everything it held. A shard is only re-replicated
//!   once its host is *durably* absent (`peers.status = 'down'`, reached after
//!   `peer_down_threshold` consecutive failed probes) — unless the chunk's live
//!   margin has become critical, where safety outranks the bandwidth economy.
//! - **Priority.** Chunks are repaired least-margin-first, so the ones closest to
//!   unrecoverable spend the shortest time exposed.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::json;

use p2pnas_core::erasure::{DATA_SHARDS, PARITY_SHARDS, TOTAL_SHARDS};
use p2pnas_p2p::P2pMessage;
use p2pnas_store::{ChunkRow, ShardRow};

use crate::state::AppState;

/// How many live shards a chunk must hold ABOVE `DATA_SHARDS` for the grace
/// period to be granted at all. At or below this margin a single further loss
/// makes the chunk unrecoverable, so shards whose host is merely offline are
/// re-replicated immediately: durability outranks the bandwidth economy.
///
/// With 10+4, a margin of 2 means: 12 live shards or more → wait for the host to
/// be declared `down`; 11 or fewer → repair now. Small networks (few distinct
/// locations, so many shards per host) therefore keep repairing eagerly, which is
/// the right call — they have no durability slack to spend.
const CRITICAL_MARGIN: usize = 2;

/// Target duration of one full local scrub cycle: every local shard is byte-
/// verified against its manifest hash about once a week. Only a `1/buckets`
/// sample is read per pass, so scrubbing never turns a 10-minute repair pass into
/// a full disk re-read.
const SCRUB_CYCLE_SECS: u64 = 7 * 24 * 60 * 60;

/// Upper bound on the degraded chunks buffered for the priority pass. Sorting by
/// margin needs the candidates in memory; holding *every* chunk of the node would
/// be unbounded, so only the degraded ones are kept, and only up to this many —
/// past that the least endangered are dropped and picked up by the next pass
/// (repair is idempotent and periodic, so deferring costs a pass, never data).
const MAX_PENDING_REPAIRS: usize = 4096;

/// Reliability attributed to our own store when comparing placement targets. Our
/// disk is the one location whose availability we control, so it ranks with the
/// best peers rather than being penalised by an absent score.
const LOCAL_RELIABILITY: f64 = 100.0;

#[derive(Default, Serialize)]
pub struct RepairReport {
    pub files_scanned:       usize,
    pub chunks_scanned:      usize,
    pub chunks_healthy:      usize,
    pub chunks_repaired:     usize,
    pub shards_replaced:     usize,
    pub chunks_unrepairable: usize,
    pub peers_total:         usize,
    pub peers_reachable:     usize,
    /// Local shards byte-verified against the manifest hash in this pass's scrub
    /// sample.
    pub shards_scrubbed:     usize,
    /// Local shards the scrub found corrupt (bit rot) — rebuilt like a loss.
    pub shards_corrupt:      usize,
    /// Shards left in place although unreachable, because their host is not
    /// `down` yet and the chunk still has margin to spare.
    pub shards_in_grace:     usize,
    /// Degraded chunks left to the next pass because the priority buffer was full.
    pub chunks_deferred:     usize,
}

/// What this pass knows about the peers, gathered once before the file sweep.
#[derive(Default)]
struct PeerView {
    /// peer_id → addr for the peers that answered a Ping just now. These are the
    /// only valid fetch sources and placement targets.
    reachable:   HashMap<String, String>,
    /// Peers whose `status` is `down` (durably absent, threshold crossed).
    down:        HashSet<String>,
    /// Every peer_id present in the table — a shard location outside this set
    /// belongs to a peer that no longer exists for us.
    known:       HashSet<String>,
    /// peer_id → EWMA reliability score (0..100), used to break placement ties.
    reliability: HashMap<String, f64>,
}

/// What the pass believes about one shard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ShardState {
    /// Present and intact: verified locally (scrub sample) or hash-audited on a
    /// peer that answered.
    Live,
    /// Its host said nothing this pass but has not crossed the down threshold —
    /// presumed still holding the shard (a laptop closed for the night).
    Grace,
    /// Durably gone: host marked `down` or unknown, local file absent/corrupt, or
    /// a host that DID answer failed the content audit.
    Lost,
}

/// The repair decision for one chunk.
struct ChunkPlan {
    /// Shards verified present right now (what reconstruction can rely on).
    live:     usize,
    /// Shards left alone thanks to the grace rule.
    deferred: usize,
    /// Shard indices to re-replicate in this pass.
    missing:  Vec<usize>,
}

/// A degraded chunk held between the assessment sweep and the priority repair.
struct Degraded {
    chunk:    ChunkRow,
    shard_at: Vec<Option<ShardRow>>,
    states:   Vec<Option<ShardState>>,
    missing:  Vec<usize>,
    /// `live - DATA_SHARDS`: how many further losses this chunk can absorb. The
    /// repair order is this value ascending.
    margin:   usize,
}

/// Orders pending repairs by margin ALONE, so a max-heap's top is the LEAST
/// endangered chunk — exactly the one to drop when the buffer overflows.
struct ByMargin(Degraded);

impl PartialEq for ByMargin {
    fn eq(&self, other: &Self) -> bool {
        self.0.margin == other.0.margin
    }
}
impl Eq for ByMargin {}
impl Ord for ByMargin {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.margin.cmp(&other.0.margin)
    }
}
impl PartialOrd for ByMargin {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Which local shards get byte-verified in this pass.
///
/// The sample is derived from the clock and the fragment id instead of a stored
/// cursor: it needs no schema, survives restarts, and still covers every shard
/// exactly once per cycle (each fragment sits in exactly one bucket, and the
/// buckets are visited in turn).
#[derive(Clone, Copy)]
struct ScrubPlan {
    bucket:  u64,
    buckets: u64,
}

impl ScrubPlan {
    fn new(now_secs: u64, interval_secs: u64) -> Self {
        let interval = interval_secs.max(1);
        // Number of passes in a full cycle (≥ 1: a repair interval longer than the
        // cycle simply scrubs everything each time).
        let buckets = (SCRUB_CYCLE_SECS / interval).max(1);
        Self { bucket: (now_secs / interval) % buckets, buckets }
    }

    fn due(&self, fragment_id: &str) -> bool {
        fnv1a(fragment_id.as_bytes()) % self.buckets == self.bucket
    }
}

/// FNV-1a: a stable, dependency-free spread of fragment ids over scrub buckets.
/// Not cryptographic — nothing here depends on it being hard to predict.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Run a full node-wide repair pass. Best-effort: any error on a single file or
/// chunk is logged and skipped so one bad file never aborts the whole sweep.
pub async fn repair_all(st: &AppState) -> RepairReport {
    let mut rep = RepairReport::default();

    // 1. Peer snapshot + liveness probe. The status and reliability columns are
    //    read in the SAME query as the addresses: the repair decisions below need
    //    "is this peer durably down?", not just "did it answer this second".
    let rows: Vec<(String, String, String, f64)> = match sqlx::query_as(
        "SELECT peer_id, addr, status, reliability_score FROM p2pnas.peers WHERE peer_id <> $1",
    )
    .bind(&st.identity.peer_id)
    .fetch_all(&st.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // Without the peer table we cannot tell a peer that is off for the
            // night from one that is gone for good. Skipping the pass costs one
            // interval; guessing would cost a node-wide re-replication.
            tracing::error!(error = %e, "peer table read failed — skipping repair pass");
            return rep;
        }
    };
    rep.peers_total = rows.len();

    // Probe all peers CONCURRENTLY (one node with many offline peers must not
    // serialize 8×timeout). The slow network part runs in parallel; the fast DB
    // bookkeeping (which takes row locks) is then done sequentially, so concurrent
    // repair passes can't contend on the same peer rows for the whole probe time.
    let mut set = tokio::task::JoinSet::new();
    for (pid, addr, _, _) in &rows {
        let (id, port, pid, addr) = (st.identity.peer_id.clone(), st.settings.server.port, pid.clone(), addr.clone());
        set.spawn(async move {
            let probe = p2pnas_p2p::ping_observed(&addr, &id, port).await.ok();
            (pid, addr, probe)
        });
    }
    let mut probes = Vec::with_capacity(rows.len());
    while let Some(r) = set.join_next().await {
        if let Ok(x) = r {
            probes.push(x);
        }
    }

    let mut view = PeerView::default();
    for (pid, _, status, score) in &rows {
        view.known.insert(pid.clone());
        view.reliability.insert(pid.clone(), *score);
        if status.as_str() == "down" {
            view.down.insert(pid.clone());
        }
    }

    let mut observed: HashMap<String, usize> = HashMap::new(); // public IP → vote count
    for (pid, addr, probe) in probes {
        let rtt = probe.as_ref().map(|(r, _)| *r);
        if let Some((_, Some(ip))) = &probe {
            *observed.entry(ip.clone()).or_default() += 1;
        }
        let just_down = record_peer_health(st, &pid, rtt).await;
        if just_down {
            tracing::warn!(peer_id = %pid, "peer marked down after repeated failures");
            view.down.insert(pid.clone());
            let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('peer_down', $1)")
                .bind(json!({ "peer_id": pid, "addr": addr }))
                .execute(&st.db)
                .await;
        }
        if rtt.is_some() {
            // It answered: whatever the stored status said, it is back.
            view.down.remove(&pid);
            view.reachable.insert(pid, addr);
        }
    }
    rep.peers_reachable = view.reachable.len();
    detect_self_ip_change(st, observed).await;

    // 2. Every file across all users. The sweep only ASSESSES; the actual repairs
    //    run afterwards, most endangered chunk first (see `MAX_PENDING_REPAIRS`).
    let scrub = ScrubPlan::new(unix_secs(), st.instance().repair_interval_secs);
    let man = st.manifest.clone();
    let files = match tokio::task::spawn_blocking(move || p2pnas_store::service::list_all(&man)).await {
        Ok(Ok(f)) => f,
        _ => return rep,
    };

    let mut pending: BinaryHeap<ByMargin> = BinaryHeap::new();
    for file in files {
        rep.files_scanned += 1;
        let man = st.manifest.clone();
        let (uid, fid) = (file.user_id.clone(), file.file_id.clone());
        let plan = match tokio::task::spawn_blocking(move || p2pnas_store::service::pull_plan(&man, &uid, &fid)).await {
            Ok(Ok((_, chunks))) => chunks,
            _ => continue,
        };
        for (chunk, shards) in plan {
            rep.chunks_scanned += 1;
            // Bound before the `if let`: the assessment future holds `&mut rep`
            // until the end of an `if let` scrutinee's temporary scope, which
            // would clash with the borrow `push_pending` needs.
            let degraded = assess_chunk(st, &view, &scrub, chunk, shards, &mut rep).await;
            if let Some(d) = degraded {
                push_pending(&mut pending, d, &mut rep);
            }
        }
    }

    // 3. Repair, smallest margin first: the chunks one loss away from being
    //    unrecoverable get their redundancy back before the comfortable ones.
    for ByMargin(d) in pending.into_sorted_vec() {
        repair_chunk(st, &view, d, &mut rep).await;
    }
    rep
}

/// Buffer a degraded chunk for the priority pass, keeping the most endangered
/// ones when the buffer is full.
fn push_pending(pending: &mut BinaryHeap<ByMargin>, d: Degraded, rep: &mut RepairReport) {
    if pending.len() < MAX_PENDING_REPAIRS {
        pending.push(ByMargin(d));
        return;
    }
    // Full: swap out the least endangered chunk if this one is worse. Either way
    // exactly one chunk is postponed to the next pass.
    if pending.peek().is_some_and(|worst| worst.0.margin > d.margin) {
        pending.pop();
        pending.push(ByMargin(d));
    }
    rep.chunks_deferred += 1;
}

/// Classify every shard of a chunk and decide whether it needs repairing.
/// Returns `None` when the chunk is healthy or beyond repair (both accounted for
/// in the report here).
async fn assess_chunk(
    st: &AppState,
    view: &PeerView,
    scrub: &ScrubPlan,
    chunk: ChunkRow,
    shards: Vec<ShardRow>,
    rep: &mut RepairReport,
) -> Option<Degraded> {
    // Index the shard rows (push always writes all 14).
    let mut shard_at: Vec<Option<ShardRow>> = (0..TOTAL_SHARDS).map(|_| None).collect();
    for s in shards {
        let i = s.shard_index as usize;
        if i < TOTAL_SHARDS {
            shard_at[i] = Some(s);
        }
    }

    let mut states: Vec<Option<ShardState>> = vec![None; TOTAL_SHARDS];
    for i in 0..TOTAL_SHARDS {
        if let Some(s) = &shard_at[i] {
            states[i] = Some(classify_shard(st, view, scrub, s, rep).await);
        }
    }

    let plan = plan_chunk(&states);
    rep.shards_in_grace += plan.deferred;
    if plan.missing.is_empty() {
        rep.chunks_healthy += 1;
        return None;
    }
    if plan.live < DATA_SHARDS {
        rep.chunks_unrepairable += 1;
        emit_unrepairable(st, &chunk, plan.live).await;
        tracing::warn!(chunk = %chunk.chunk_id, live = plan.live, "chunk unrepairable: too few shards reachable");
        return None;
    }
    Some(Degraded {
        margin: plan.live - DATA_SHARDS,
        chunk,
        shard_at,
        states,
        missing: plan.missing,
    })
}

/// Decide, from the per-shard states, what to re-replicate now.
///
/// A shard whose host is merely silent is NOT a loss: personal machines are off
/// every night, and re-replicating everything they hold — only for their copies
/// to come back as orphans in the morning — is a daily full re-replication of the
/// network. Such shards wait for their host to be declared `down`.
///
/// The exception is the whole reason the grace period is safe: as soon as the
/// count of *verified live* shards drops within `CRITICAL_MARGIN` of
/// `DATA_SHARDS`, the chunk is one incident away from being unrecoverable, and
/// every absent shard — graced or not — is rebuilt immediately.
fn plan_chunk(states: &[Option<ShardState>]) -> ChunkPlan {
    let live = states.iter().filter(|s| **s == Some(ShardState::Live)).count();
    let critical = live < DATA_SHARDS + CRITICAL_MARGIN;

    let mut missing = Vec::new();
    let mut deferred = 0usize;
    for (i, s) in states.iter().enumerate() {
        match s {
            Some(ShardState::Lost) => missing.push(i),
            Some(ShardState::Grace) if critical => missing.push(i),
            Some(ShardState::Grace) => deferred += 1,
            _ => {}
        }
    }
    ChunkPlan { live, deferred, missing }
}

/// Repair one degraded chunk: reconstruct from the survivors and re-place the
/// shards listed as missing.
async fn repair_chunk(st: &AppState, view: &PeerView, d: Degraded, rep: &mut RepairReport) {
    // Fetch DATA_SHARDS live shards (enough to reconstruct the cipher).
    let mut present: Vec<Option<Vec<u8>>> = (0..TOTAL_SHARDS).map(|_| None).collect();
    let mut got = 0usize;
    // Iterating over the slot rather than the index keeps clippy happy and makes
    // the pairing with `states`/`shard_at` explicit.
    for (i, slot) in present.iter_mut().enumerate() {
        if got >= DATA_SHARDS {
            break;
        }
        if d.states[i] == Some(ShardState::Live) {
            if let Some(s) = &d.shard_at[i] {
                if let Some(bytes) = fetch_shard(st, &view.reachable, s).await {
                    *slot = Some(bytes);
                    got += 1;
                }
            }
        }
    }
    if got < DATA_SHARDS {
        rep.chunks_unrepairable += 1;
        tracing::warn!(chunk = %d.chunk.chunk_id, got, "chunk unrepairable: shard fetch fell short");
        return;
    }

    // Deterministically regenerate all 14 shards from the survivors.
    let cipher_len = d.chunk.cipher_len as usize;
    let all = match tokio::task::spawn_blocking(move || {
        p2pnas_store::service::regen_chunk_shards(&present, cipher_len)
    })
    .await
    {
        Ok(Ok(v)) => v,
        _ => {
            rep.chunks_unrepairable += 1;
            tracing::warn!(chunk = %d.chunk.chunk_id, "chunk regeneration failed");
            return;
        }
    };

    // Count shards-per-location among the copies that STAY (live ones, plus the
    // graced ones still sitting on an offline host), so re-placement keeps the
    // single-failure invariant (≤ PARITY_SHARDS per location) where it can.
    let mut loc_count: HashMap<String, usize> = HashMap::new();
    for i in 0..TOTAL_SHARDS {
        if matches!(d.states[i], Some(ShardState::Live) | Some(ShardState::Grace)) {
            if let Some(s) = &d.shard_at[i] {
                *loc_count.entry(s.location.clone()).or_default() += 1;
            }
        }
    }

    let mut repaired_any = false;
    for &i in &d.missing {
        let frag = d.shard_at[i].as_ref().map(|s| s.fragment_id.clone()).unwrap_or_default();
        let Some(bytes) = all.get(i).cloned() else { continue };
        let target = choose_target(&loc_count, &view.reachable, &view.reliability);
        if place_shard(st, &view.reachable, &target, &frag, i as i32, &bytes).await {
            let (man, frag2, loc) = (st.manifest.clone(), frag.clone(), target.clone());
            let _ = tokio::task::spawn_blocking(move || p2pnas_store::service::set_location(&man, &frag2, &loc)).await;
            *loc_count.entry(target).or_default() += 1;
            rep.shards_replaced += 1;
            repaired_any = true;
        }
    }
    if repaired_any {
        rep.chunks_repaired += 1;
    }
}

/// Pick where a rebuilt shard goes. Candidates: this node + every reachable peer.
///
/// Ranked, in this order:
/// 1. locations still under the concentration cap (`PARITY_SHARDS` shards of this
///    chunk) — losing one location must never take the chunk below
///    `DATA_SHARDS`, so this is a hard preference, not a tie-break;
/// 2. the fewest shards of this chunk already there (spread);
/// 3. the highest reliability score — the EWMA `record_peer_health` maintains.
///    At comparable load, a host that has been answering for weeks is a better
///    home than one that keeps flapping, and re-placing onto a flaky host is how
///    a repair pass ends up repairing its own repairs.
///
/// The last tie-break is the location name, purely so the choice is deterministic.
fn choose_target(
    loc_count: &HashMap<String, usize>,
    reachable: &HashMap<String, String>,
    reliability: &HashMap<String, f64>,
) -> String {
    let mut candidates: Vec<String> = vec!["local".to_string()];
    candidates.extend(reachable.keys().cloned());

    let rank = |c: &String| {
        let n = loc_count.get(c).copied().unwrap_or(0);
        let r = if c.as_str() == "local" {
            LOCAL_RELIABILITY
        } else {
            reliability.get(c).copied().unwrap_or(0.0)
        };
        (n >= PARITY_SHARDS, n, r)
    };

    candidates
        .iter()
        .min_by(|a, b| {
            let (ra, rb) = (rank(a), rank(b));
            ra.0.cmp(&rb.0)
                .then(ra.1.cmp(&rb.1))
                .then(rb.2.total_cmp(&ra.2)) // higher score first
                .then(a.cmp(b))
        })
        .cloned()
        .unwrap_or_else(|| "local".to_string())
}

/// Is a shard present AND intact where the manifest says it lives — and if not,
/// is it durably gone or merely unreachable for now?
///
/// Remote shards are proof-of-storage audited (content hash compared to the
/// manifest), so a peer that silently corrupted/dropped the data — which a bare
/// `HasShard` would not catch — is a loss, not a grace case: it answered, and what
/// it holds is unusable.
///
/// Local shards are sampled by the scrub plan: the sampled ones are read and
/// hash-checked (bit rot detection), the others fall back to a presence test,
/// which is what keeps a pass cheap.
async fn classify_shard(
    st: &AppState,
    view: &PeerView,
    scrub: &ScrubPlan,
    s: &ShardRow,
    rep: &mut RepairReport,
) -> ShardState {
    if s.location == "local" {
        if scrub.due(&s.fragment_id) {
            rep.shards_scrubbed += 1;
            let (store, frag, hash) = (st.store.clone(), s.fragment_id.clone(), s.hash.clone());
            let ok = tokio::task::spawn_blocking(move || {
                p2pnas_store::service::read_local_verified(&store, &frag, &hash).is_some()
            })
            .await
            .unwrap_or(false);
            if ok {
                return ShardState::Live;
            }
            // Absent OR corrupt. Only the corruption case is newsworthy — a
            // missing file is already covered by the ordinary presence path.
            if st.store.exists(&s.fragment_id) {
                rep.shards_corrupt += 1;
                tracing::warn!(fragment_id = %s.fragment_id, "local shard corrupt (bit rot) — rebuilding from parity");
                emit_shard_corrupt(st, s).await;
            }
            return ShardState::Lost;
        }
        // Unsampled pass: presence only. A locally missing file is a real loss —
        // our own disk is never "temporarily unreachable".
        return if st.store.exists(&s.fragment_id) { ShardState::Live } else { ShardState::Lost };
    }

    if let Some(addr) = view.reachable.get(&s.location) {
        return match p2pnas_p2p::audit_shard(addr, &s.fragment_id).await {
            // Empty manifest hash = legacy shard → fall back to mere presence.
            Ok(h) if !h.is_empty() && (s.hash.is_empty() || h == s.hash) => ShardState::Live,
            _ => ShardState::Lost,
        };
    }
    // Silent host. Durably down, or unknown to us (removed from the peer table) →
    // its copies can never be counted on again. Otherwise: grace.
    if view.down.contains(&s.location) || !view.known.contains(&s.location) {
        ShardState::Lost
    } else {
        ShardState::Grace
    }
}

/// Fetch a shard's bytes (local read or P2P GetShard), verified against the
/// manifest hash.
///
/// The integrity check lives HERE, not just at the call sites, because this
/// function feeds the repair path — the one place that RE-ENCODES and rewrites
/// all 14 shards. Reed-Solomon in erasure mode is not error-correcting: a single
/// present-but-tampered shard silently poisons the reconstructed cipher, the
/// regenerated shards no longer match their stored hashes, and the file becomes
/// permanently unreadable. A malicious peer hosting one shard could thus destroy
/// a file by answering `GetShard` with flipped bytes. Verifying before the bytes
/// are ever used turns "corrupt" back into "lost", which erasure handles.
/// (Legacy rows with an empty hash skip the check, as elsewhere.)
pub(crate) async fn fetch_shard(st: &AppState, reachable: &HashMap<String, String>, s: &ShardRow) -> Option<Vec<u8>> {
    let bytes = if s.location == "local" {
        let (store, frag) = (st.store.clone(), s.fragment_id.clone());
        tokio::task::spawn_blocking(move || p2pnas_store::service::read_local(&store, &frag)).await.ok().flatten()?
    } else if let Some(addr) = reachable.get(&s.location) {
        match p2pnas_p2p::request(addr, &P2pMessage::GetShard { fragment_id: s.fragment_id.clone() }).await {
            Ok(P2pMessage::ShardData { data, .. }) => data,
            _ => return None,
        }
    } else {
        return None;
    };
    if !p2pnas_store::service::verify_hash(&bytes, &s.hash) {
        tracing::warn!(
            fragment_id = %s.fragment_id,
            location = %s.location,
            "shard failed integrity check during repair fetch — treating as lost"
        );
        return None;
    }
    Some(bytes)
}

/// Drop a shard from a location ("local" or a reachable peer_id) after it has been
/// re-placed elsewhere (used by the locality rebalance to free the old copy).
pub(crate) async fn drop_shard(st: &AppState, reachable: &HashMap<String, String>, location: &str, frag: &str) {
    if location == "local" {
        let (store, f) = (st.store.clone(), frag.to_string());
        let _ = tokio::task::spawn_blocking(move || store.delete(&f)).await;
    } else if let Some(addr) = reachable.get(location) {
        let _ = crate::p2p::signed_request(
            &st.identity,
            st.settings.server.port,
            addr,
            &P2pMessage::DeleteShard { fragment_id: frag.to_string(), owner_peer_id: st.identity.peer_id.clone() },
        )
        .await;
    }
}

/// Place a shard on a target location ("local" or a reachable peer_id).
/// `shard_index` travels with the shard so the host can record whether it is data
/// or parity (used later by the retention sweep to shed parity first).
pub(crate) async fn place_shard(st: &AppState, reachable: &HashMap<String, String>, target: &str, frag: &str, shard_index: i32, bytes: &[u8]) -> bool {
    if target == "local" {
        let (store, frag2, data) = (st.store.clone(), frag.to_string(), bytes.to_vec());
        return tokio::task::spawn_blocking(move || p2pnas_store::service::write_local(&store, &frag2, &data))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false);
    }
    let Some(addr) = reachable.get(target) else { return false };
    let msg = P2pMessage::StoreShard {
        fragment_id:   frag.to_string(),
        owner_peer_id: st.identity.peer_id.clone(),
        shard_index,
        data:          bytes.to_vec(),
    };
    matches!(
        crate::p2p::signed_request(&st.identity, st.settings.server.port, addr, &msg).await,
        Ok(P2pMessage::Ack { .. })
    )
}

/// Update a peer's reliability after a liveness probe (EWMA toward 100 or 0), its
/// measured round-trip latency (EWMA, ms), and its consecutive-failure / status
/// flag. `rtt` is Some(ms) when the peer answered, None when it didn't. Returns
/// true if the peer just went from active → down (so the caller can repair).
async fn record_peer_health(st: &AppState, peer_id: &str, rtt: Option<f64>) -> bool {
    if let Some(rtt_ms) = rtt {
        let _ = sqlx::query(
            "UPDATE p2pnas.peers
             SET reliability_score = LEAST(100.0, reliability_score * 0.8 + 20.0),
                 rtt_ms = CASE WHEN rtt_ms IS NULL THEN $2 ELSE rtt_ms * 0.7 + $2 * 0.3 END,
                 consecutive_failures = 0, status = 'active', last_seen = now()
             WHERE peer_id = $1",
        )
        .bind(peer_id)
        .bind(rtt_ms)
        .execute(&st.db)
        .await;
        return false;
    }
    // Consecutive failed probes tolerated before the peer is marked `down` (and
    // excluded from new placements until it answers again). Administrable: a
    // flaky home connection wants a higher figure than a datacentre fleet.
    let threshold = st.instance().peer_down_threshold;

    // Failure: decay score, bump the failure counter, flip to 'down' at the
    // threshold.
    //
    // The self-join reads `prev` from the statement's pre-update snapshot, so
    // RETURNING hands back the status BEFORE and AFTER in one round trip. The
    // transition is what the caller acts on, and comparing statuses is the only
    // way to detect it that survives the threshold being edited: a peer that had
    // accumulated four failures under a threshold of five, then lowered to two,
    // still goes active → down exactly once — a rule counting failures against
    // the current threshold would miss that crossing entirely.
    let row: Option<(String, String)> = sqlx::query_as(
        "UPDATE p2pnas.peers p
         SET reliability_score = GREATEST(0.0, p.reliability_score * 0.8),
             consecutive_failures = p.consecutive_failures + 1,
             status = CASE WHEN p.consecutive_failures + 1 >= $2 THEN 'down' ELSE p.status END
         FROM p2pnas.peers prev
         WHERE p.peer_id = $1 AND prev.peer_id = p.peer_id
         RETURNING prev.status, p.status",
    )
    .bind(peer_id)
    .bind(threshold)
    .fetch_optional(&st.db)
    .await
    .map_err(|e| tracing::error!(error = %e, peer_id, "mise à jour de la santé du pair"))
    .ok()
    .flatten();
    matches!(row, Some((before, after)) if before != "down" && after == "down")
}

/// Compare the consensus public IP (majority of what peers observed) to the last
/// known one. On a change, record it, emit an `ip_changed` event, and enqueue a
/// locality rebalance so data can be re-homed nearer the node's new location.
async fn detect_self_ip_change(st: &AppState, observed: HashMap<String, usize>) {
    let Some((ip, _)) = observed.into_iter().max_by_key(|(_, n)| *n) else { return };
    let prev: Option<String> = sqlx::query_scalar("SELECT public_ip FROM p2pnas.node_local WHERE id = 1")
        .fetch_one(&st.db)
        .await
        .ok()
        .flatten();
    if prev.as_deref() == Some(ip.as_str()) {
        return; // unchanged
    }
    let _ = sqlx::query("UPDATE p2pnas.node_local SET public_ip = $1, updated_at = now() WHERE id = 1")
        .bind(&ip)
        .execute(&st.db)
        .await;
    if let Some(old) = prev {
        // Always record the change; only auto-trigger a rebalance if we haven't
        // re-homed recently (hysteresis against a flapping IP).
        let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('ip_changed', $1)")
            .bind(json!({ "old": old, "new": ip }))
            .execute(&st.db)
            .await;
        let recent: Option<bool> = sqlx::query_scalar(
            "SELECT last_rebalance_at > now() - interval '30 minutes' FROM p2pnas.node_local WHERE id = 1",
        )
        .fetch_one(&st.db)
        .await
        .ok()
        .flatten();
        if recent == Some(true) {
            tracing::info!(old = %old, new = %ip, "public IP changed but rebalanced recently — skipping (cooldown)");
        } else {
            tracing::info!(old = %old, new = %ip, "public IP changed — enqueueing locality rebalance");
            crate::jobs::enqueue(&st.db, "rebalance_locality", json!({ "reason": "ip_changed" })).await;
        }
    }
}

/// Log a data-loss-risk event for a chunk that can no longer be reconstructed.
async fn emit_unrepairable(st: &AppState, chunk: &ChunkRow, reachable_count: usize) {
    let _ = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('chunk_unrepairable', $1)")
        .bind(json!({
            "chunk_id": chunk.chunk_id,
            "file_id": chunk.file_id,
            "reachable_shards": reachable_count,
            "needed": DATA_SHARDS,
        }))
        .execute(&st.db)
        .await;
}

/// Log a silent-corruption event: the local copy of a shard no longer matches its
/// manifest hash. Rare and diagnostic (a failing disk shows up as a burst of
/// these), so it is worth a row of its own.
async fn emit_shard_corrupt(st: &AppState, s: &ShardRow) {
    if let Err(e) = sqlx::query("INSERT INTO p2pnas.events (kind, payload) VALUES ('shard_corrupt', $1)")
        .bind(json!({ "fragment_id": s.fragment_id, "chunk_id": s.chunk_id, "location": "local" }))
        .execute(&st.db)
        .await
    {
        tracing::error!(error = %e, fragment_id = %s.fragment_id, "recording shard_corrupt event");
    }
}

/// The minimum number of distinct locations needed for single-failure durability
/// (so no location must hold more than `PARITY_SHARDS` shards). Exposed for the
/// upload path's durability warning.
pub fn min_locations_for_durability() -> usize {
    TOTAL_SHARDS.div_ceil(PARITY_SHARDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` live shards, `g` graced, `l` lost, rest empty (padded to TOTAL_SHARDS).
    fn states(n: usize, g: usize, l: usize) -> Vec<Option<ShardState>> {
        let mut v: Vec<Option<ShardState>> = Vec::with_capacity(TOTAL_SHARDS);
        v.extend((0..n).map(|_| Some(ShardState::Live)));
        v.extend((0..g).map(|_| Some(ShardState::Grace)));
        v.extend((0..l).map(|_| Some(ShardState::Lost)));
        v.resize(TOTAL_SHARDS, None);
        v
    }

    #[test]
    fn a_peer_off_for_the_night_does_not_trigger_re_replication() {
        // 12 live + 2 on a host that is silent but not `down`: margin 2, nothing
        // to do — this is the nightly-shutdown case the grace rule exists for.
        let p = plan_chunk(&states(12, 2, 0));
        assert_eq!(p.live, 12);
        assert_eq!(p.deferred, 2);
        assert!(p.missing.is_empty());
    }

    #[test]
    fn a_durably_down_host_is_repaired() {
        let p = plan_chunk(&states(12, 0, 2));
        assert_eq!(p.missing, vec![12, 13]);
        assert_eq!(p.deferred, 0);
    }

    #[test]
    fn critical_margin_overrides_the_grace_period() {
        // 11 live is within CRITICAL_MARGIN (2) of DATA_SHARDS (10): one more
        // failure and the chunk is gone, so graced shards are rebuilt now.
        let p = plan_chunk(&states(11, 3, 0));
        assert_eq!(p.live, 11);
        assert_eq!(p.deferred, 0);
        assert_eq!(p.missing.len(), 3);

        // One more live shard (12) and the economy applies again.
        let p = plan_chunk(&states(12, 2, 0));
        assert!(p.missing.is_empty());
    }

    #[test]
    fn lost_and_graced_are_merged_when_critical() {
        let p = plan_chunk(&states(10, 2, 2));
        assert_eq!(p.live, 10);
        assert_eq!(p.missing.len(), 4); // 2 lost + 2 graced, all urgent
    }

    #[test]
    fn healthy_chunk_plans_nothing() {
        let p = plan_chunk(&states(14, 0, 0));
        assert!(p.missing.is_empty());
        assert_eq!(p.deferred, 0);
    }

    fn peers(ids: &[&str]) -> HashMap<String, String> {
        ids.iter().map(|p| ((*p).to_string(), format!("{p}:9000"))).collect()
    }

    #[test]
    fn target_prefers_the_more_reliable_host_at_equal_load() {
        let reachable = peers(&["a", "b"]);
        let reliability: HashMap<String, f64> =
            [("a".to_string(), 30.0), ("b".to_string(), 95.0)].into_iter().collect();
        // Both peers hold 1 shard, local holds 1 too → reliability decides, and
        // "local" scores LOCAL_RELIABILITY so it stays a first-class candidate.
        let loc: HashMap<String, usize> =
            [("a".to_string(), 1), ("b".to_string(), 1), ("local".to_string(), 2)].into_iter().collect();
        assert_eq!(choose_target(&loc, &reachable, &reliability), "b");
    }

    #[test]
    fn load_still_outranks_reliability() {
        let reachable = peers(&["a", "b"]);
        let reliability: HashMap<String, f64> =
            [("a".to_string(), 10.0), ("b".to_string(), 100.0)].into_iter().collect();
        // b is far more reliable but already holds 2 shards of this chunk: spread
        // wins, because durability comes from distinct locations.
        let loc: HashMap<String, usize> =
            [("a".to_string(), 0), ("b".to_string(), 2), ("local".to_string(), 3)].into_iter().collect();
        assert_eq!(choose_target(&loc, &reachable, &reliability), "a");
    }

    #[test]
    fn concentration_cap_beats_everything() {
        let reachable = peers(&["a"]);
        let reliability: HashMap<String, f64> = [("a".to_string(), 100.0)].into_iter().collect();
        // "a" is at the parity cap even though it is empty-handed elsewhere and
        // perfectly reliable; local (below the cap) must be chosen.
        let loc: HashMap<String, usize> =
            [("a".to_string(), PARITY_SHARDS), ("local".to_string(), 1)].into_iter().collect();
        assert_eq!(choose_target(&loc, &reachable, &reliability), "local");

        // Everything at the cap → overflow to the least loaded (here local).
        let loc: HashMap<String, usize> =
            [("a".to_string(), PARITY_SHARDS + 2), ("local".to_string(), PARITY_SHARDS)].into_iter().collect();
        assert_eq!(choose_target(&loc, &reachable, &reliability), "local");
    }

    #[test]
    fn target_falls_back_to_local_without_peers() {
        assert_eq!(choose_target(&HashMap::new(), &HashMap::new(), &HashMap::new()), "local");
    }

    #[test]
    fn scrub_covers_every_shard_exactly_once_per_cycle() {
        let interval = 600; // the default repair interval: 144 passes a day
        let buckets = SCRUB_CYCLE_SECS / interval;
        let frags: Vec<String> = (0..500).map(|i| format!("frag-{i:04x}")).collect();

        let mut seen = vec![0usize; frags.len()];
        for pass in 0..buckets {
            let plan = ScrubPlan::new(pass * interval, interval);
            for (i, f) in frags.iter().enumerate() {
                if plan.due(f) {
                    seen[i] += 1;
                }
            }
        }
        assert!(seen.iter().all(|n| *n == 1), "every shard is scrubbed once per cycle");
    }

    #[test]
    fn scrub_sample_is_a_small_fraction_of_a_pass() {
        let plan = ScrubPlan::new(unix_secs(), 600);
        let due = (0..10_000).filter(|i| plan.due(&format!("frag-{i:05x}"))).count();
        // 1008 passes a week → well under 1% of the local shards per pass.
        assert!(due < 300, "scrub sample too large: {due}/10000");
    }

    #[test]
    fn scrub_never_divides_by_zero() {
        // A repair interval longer than the whole cycle degenerates to one bucket
        // (everything scrubbed every pass) instead of panicking.
        let plan = ScrubPlan::new(0, SCRUB_CYCLE_SECS * 4);
        assert_eq!(plan.buckets, 1);
        assert!(plan.due("anything"));
        let plan = ScrubPlan::new(0, 0);
        assert!(plan.buckets >= 1);
    }

    fn degraded(margin: usize) -> Degraded {
        Degraded {
            chunk:    ChunkRow {
                chunk_id:      format!("c{margin}"),
                file_id:       "f".into(),
                idx:           0,
                nonce:         Vec::new(),
                is_compressed: false,
                plaintext_len: 0,
                cipher_len:    0,
                shard_len:     0,
            },
            shard_at: Vec::new(),
            states:   Vec::new(),
            missing:  Vec::new(),
            margin,
        }
    }

    #[test]
    fn repairs_run_least_margin_first() {
        let mut rep = RepairReport::default();
        let mut heap = BinaryHeap::new();
        for m in [3usize, 0, 2, 1] {
            push_pending(&mut heap, degraded(m), &mut rep);
        }
        let order: Vec<usize> = heap.into_sorted_vec().into_iter().map(|b| b.0.margin).collect();
        assert_eq!(order, vec![0, 1, 2, 3]);
        assert_eq!(rep.chunks_deferred, 0);
    }

    #[test]
    fn overflowing_buffer_keeps_the_most_endangered() {
        let mut rep = RepairReport::default();
        let mut heap = BinaryHeap::new();
        // Fill past the cap with comfortable chunks, then add urgent ones.
        for _ in 0..MAX_PENDING_REPAIRS {
            push_pending(&mut heap, degraded(4), &mut rep);
        }
        push_pending(&mut heap, degraded(0), &mut rep);
        push_pending(&mut heap, degraded(1), &mut rep);
        assert_eq!(heap.len(), MAX_PENDING_REPAIRS);
        // Two chunks were postponed, and the two urgent ones made it in.
        assert_eq!(rep.chunks_deferred, 2);
        let margins: Vec<usize> = heap.into_sorted_vec().into_iter().map(|b| b.0.margin).collect();
        assert_eq!(margins[0], 0);
        assert_eq!(margins[1], 1);
    }
}
