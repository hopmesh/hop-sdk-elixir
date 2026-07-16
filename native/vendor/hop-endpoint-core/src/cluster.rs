//! Endpoint cluster coordination (DESIGN.md §40): self-forming, over-Hop dedup for endpoint
//! replicas that share one identity but no shared datastore.
//!
//! Multiple endpoint workers on customer hardware (horizontally scaled, same endpoint identity, no
//! shared DB, no known side-channel) each receive their own copy of an addressed message and would
//! each run the handler, so the side effect and the addressed response happen twice. This module
//! lets replicas reduce duplicate processing, with the coordination state
//! replicated *among the members over an `hps://` cluster topic* rather than a shared store. Because
//! it rides Hop, it works wherever the replicas can mesh at all.
//!
//! This is the transport-agnostic core: it owns the replicated state and decides what to gossip, but
//! ships nothing itself. [`Endpoint`](crate::Endpoint) pipes [`ClusterMsg`]s over an `hps://`
//! broadcast (see `endpoint.rs`), and persistence hands the durable [`ClaimKey`] set back on restart.
//!
//! **Phase 1: membership + a durable, gossiped `HANDLED` set.** When a member finishes a request it
//! records and gossips `Handled(key)`; a member drops any request whose key is already `HANDLED`.
//! Delivery is delay-tolerant, so the copies of one message usually reach the workers *apart in
//! time*; the later copy sees the earlier's `HANDLED` and is suppressed.
//!
//! **Phase 2: rendezvous ownership ([`Cluster::rank_for`]).** Every replica computes the same owner
//! for a key by HRW hashing over the live membership, so only the owner processes it and the standbys
//! hold (the [`Endpoint`](crate::Endpoint) gate). If the owner is silent, ranked standbys take over
//! one at a time (in `endpoint.rs`); if it ages out, the successor becomes owner automatically. That
//! reduces duplicates while membership views agree. The optional visibility threshold is a
//! conservative failover heuristic, not consensus or an at-most-once guarantee.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

/// A cluster coordination key: a stable per-message id that every copy of a message computes
/// identically, so two replicas holding the same message agree on the same key. For a
/// `ServiceRequest` it is `blake3(from ++ request_id)` (see [`claim_key`]); the sender-assigned
/// `request_id` is stable across the duplicate copies the mesh sprays.
pub type ClaimKey = [u8; 32];

/// A per-worker instance id, random per process. The replicas share the endpoint identity (same
/// keypair, so they can all open the statically-sealed requests), so identity can't tell them
/// apart; this can. A member ignores gossip stamped with its own id and counts distinct peers by it.
pub type MemberId = [u8; 16];

/// Derive the stable coordination key for an addressed request from its sender and request id.
pub fn claim_key(from: &[u8; 32], request_id: &[u8; 32]) -> ClaimKey {
    let mut h = blake3::Hasher::new();
    h.update(b"hop.cluster.key.v1");
    h.update(from);
    h.update(request_id);
    *h.finalize().as_bytes()
}

/// Rendezvous (highest-random-weight) score of `member` for `key`; the highest score owns the key.
/// Deterministic across replicas, so they agree on ownership from the membership set alone.
fn hrw(member: &MemberId, key: &ClaimKey) -> u64 {
    let mut h = blake3::Hasher::new();
    h.update(b"hop.cluster.hrw.v1");
    h.update(member);
    h.update(key);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.finalize().as_bytes()[..8]);
    u64::from_le_bytes(b)
}

/// Messages gossiped on the cluster topic. Serialized with postcard, then content-sealed by the
/// node under the cluster topic's derived key before it rides an `hps://` broadcast, so only fellow
/// replicas (holders of the cluster secret) can read or write them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterMsg {
    /// Liveness beacon: "member is alive as of `at_ms`" (its own clock; informational only, the
    /// receiver times out on *its* clock to stay skew-proof).
    Presence { member: MemberId, at_ms: u64 },
    /// Durable dedup fact: "member handled these keys". Batched so a rejoining member catches up in
    /// one message and so a burst of completions is one publish, not one-per-key.
    Handled {
        member: MemberId,
        keys: Vec<ClaimKey>,
    },
}

/// A member is considered alive for this long after its last beacon.
pub const MEMBER_TTL_MS: u64 = 30_000;
/// How often to emit a liveness beacon.
pub const PRESENCE_INTERVAL_MS: u64 = 10_000;
/// Cap on retained `HANDLED` keys (oldest evicted). Bounds memory and gossip size; a key older than
/// the cap can no longer dedup, which only risks a stale-duplicate long after the fact.
pub const HANDLED_CAP: usize = 100_000;

/// The replicated coordination state for one endpoint replica.
pub struct Cluster {
    me: MemberId,
    /// peer member id -> last-seen (our clock). Never contains `me`.
    members: HashMap<MemberId, u64>,
    /// handled keys (any member). Value is unused today but reserved for lease/term in Phase 2.
    handled: HashMap<ClaimKey, ()>,
    /// insertion order, for bounded eviction.
    order: VecDeque<ClaimKey>,
    /// keys handled locally since the last gossip flush, awaiting a `Handled` broadcast.
    pending: Vec<ClaimKey>,
    last_presence_ms: u64,
    started: bool,
    /// Min recently visible members (incl. self) required to act. 0 disables the threshold.
    quorum: usize,
}

impl Cluster {
    /// A fresh cluster view for member `me` (random per process).
    pub fn new(me: MemberId) -> Self {
        Self {
            me,
            members: HashMap::new(),
            handled: HashMap::new(),
            order: VecDeque::new(),
            pending: Vec::new(),
            last_presence_ms: 0,
            started: false,
            quorum: 0,
        }
    }

    /// Require at least `min_live_members` (incl. self) recently visible before this replica acts.
    /// `0` disables the threshold. Visibility is TTL-based and can be stale or asymmetric, so this is
    /// a conservative failover control, not a consensus quorum or at-most-once guarantee.
    pub fn set_quorum(&mut self, min_live_members: usize) {
        self.quorum = min_live_members;
    }

    /// Whether this replica currently sees enough of the cluster to act safely (`member_count >=
    /// quorum`). Always true when quorum is unset. When false the caller HOLDS every request rather
    /// than risk a double-process against a member it can't currently see.
    pub fn has_quorum(&self, now_ms: u64) -> bool {
        self.member_count(now_ms) >= self.quorum
    }

    /// Whether the conservative visibility threshold is enabled.
    pub fn quorum_enabled(&self) -> bool {
        self.quorum != 0
    }

    /// This replica's member id.
    pub fn me(&self) -> MemberId {
        self.me
    }

    /// Seed the durable `HANDLED` set from persistence at startup. Loaded keys are NOT re-gossiped
    /// (they are already known cluster-wide from when they were first handled); they only make this
    /// replica dedup correctly across a restart.
    pub fn load_handled(&mut self, keys: impl IntoIterator<Item = ClaimKey>) {
        for k in keys {
            self.insert_handled(k);
        }
    }

    /// Has any member handled this key? A `true` means "drop it, someone has it".
    pub fn is_handled(&self, key: &ClaimKey) -> bool {
        self.handled.contains_key(key)
    }

    /// Record that THIS replica handled `key`. Returns `true` if newly recorded (the caller should
    /// persist it; it will also be gossiped on the next [`tick`](Self::tick)). `false` means it was
    /// already handled, so the caller lost the race and must not process (or double-persist).
    pub fn mark_handled(&mut self, key: ClaimKey) -> bool {
        if self.handled.contains_key(&key) {
            return false;
        }
        self.insert_handled(key);
        self.pending.push(key);
        true
    }

    /// Apply an inbound gossip message. Returns keys learned for the FIRST time, so the caller can
    /// persist exactly the new ones. Gossip from our own `me` is ignored (broadcasts flood back).
    pub fn on_gossip(&mut self, msg: &ClusterMsg, now_ms: u64) -> Vec<ClaimKey> {
        match msg {
            ClusterMsg::Presence { member, .. } => {
                if *member != self.me {
                    self.members.insert(*member, now_ms);
                }
                Vec::new()
            }
            ClusterMsg::Handled { member, keys } => {
                if *member == self.me {
                    return Vec::new();
                }
                self.members.insert(*member, now_ms); // a Handled is itself proof of life
                let mut learned = Vec::new();
                for k in keys {
                    if !self.handled.contains_key(k) {
                        self.insert_handled(*k);
                        learned.push(*k);
                    }
                }
                learned
            }
        }
    }

    /// Outbound gossip due now: a liveness beacon on the interval, plus a `Handled` batch of any
    /// keys handled since the last flush. The caller serializes each and `hps_publish`es it. The
    /// first tick always beacons so members appear promptly.
    pub fn tick(&mut self, now_ms: u64) -> Vec<ClusterMsg> {
        let mut out = Vec::new();
        if !self.started || now_ms.saturating_sub(self.last_presence_ms) >= PRESENCE_INTERVAL_MS {
            out.push(ClusterMsg::Presence {
                member: self.me,
                at_ms: now_ms,
            });
            self.last_presence_ms = now_ms;
            self.started = true;
        }
        if !self.pending.is_empty() {
            out.push(ClusterMsg::Handled {
                member: self.me,
                keys: std::mem::take(&mut self.pending),
            });
        }
        out
    }

    /// Live members including self (peers whose last beacon is within [`MEMBER_TTL_MS`]).
    pub fn member_count(&self, now_ms: u64) -> usize {
        1 + self
            .members
            .values()
            .filter(|&&t| now_ms.saturating_sub(t) < MEMBER_TTL_MS)
            .count()
    }

    /// This replica's **rank** for `key` among the live membership (0 = owner). Rendezvous / highest-
    /// random-weight (HRW) hashing: every replica computes the same descending order of members by
    /// `hrw(member, key)`, so they agree on who owns a given message with NO coordination. The owner
    /// processes it; higher ranks are hot standbys that take over in order if the owner is silent.
    /// Ties (astronomically unlikely) break by member id. Phase 2 (DESIGN.md §40).
    pub fn rank_for(&self, key: &ClaimKey, now_ms: u64) -> usize {
        let mine = hrw(&self.me, key);
        let mut higher = 0;
        for (m, &t) in &self.members {
            if now_ms.saturating_sub(t) < MEMBER_TTL_MS {
                let w = hrw(m, key);
                if w > mine || (w == mine && *m > self.me) {
                    higher += 1;
                }
            }
        }
        higher
    }

    /// Whether THIS replica is the current owner of `key` (rank 0).
    pub fn is_owner(&self, key: &ClaimKey, now_ms: u64) -> bool {
        self.rank_for(key, now_ms) == 0
    }

    /// Number of keys currently retained in the dedup set (for tests/metrics).
    pub fn handled_len(&self) -> usize {
        self.handled.len()
    }

    fn insert_handled(&mut self, key: ClaimKey) {
        if self.handled.insert(key, ()).is_none() {
            self.order.push_back(key);
            while self.order.len() > HANDLED_CAP {
                if let Some(old) = self.order.pop_front() {
                    self.handled.remove(&old);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> ClaimKey {
        [n; 32]
    }

    #[test]
    fn claim_key_is_stable_and_binds_both_fields() {
        let from = [1u8; 32];
        let rid = [2u8; 32];
        assert_eq!(claim_key(&from, &rid), claim_key(&from, &rid), "stable");
        assert_ne!(
            claim_key(&from, &rid),
            claim_key(&[9u8; 32], &rid),
            "from binds"
        );
        assert_ne!(
            claim_key(&from, &rid),
            claim_key(&from, &[9u8; 32]),
            "rid binds"
        );
    }

    #[test]
    fn a_handles_gossips_and_b_dedups() {
        let mut a = Cluster::new([0xAA; 16]);
        let mut b = Cluster::new([0xBB; 16]);
        let k = key(7);

        // A finishes the request first.
        assert!(a.mark_handled(k), "A records it fresh");
        assert!(!b.is_handled(&k), "B has not heard yet");

        // A's next tick emits the Handled gossip; B applies it.
        let gossip = a.tick(1_000);
        let handled = gossip
            .iter()
            .find(|m| matches!(m, ClusterMsg::Handled { .. }))
            .expect("A gossips Handled");
        let learned = b.on_gossip(handled, 1_000);
        assert_eq!(learned, vec![k], "B persists exactly the new key");

        // B's later copy of the same message is now suppressed.
        assert!(b.is_handled(&k), "B dedups the later copy");
        // And B re-marking is a no-op (it lost the race).
        assert!(!b.mark_handled(k), "B does not double-handle");
    }

    #[test]
    fn own_gossip_is_ignored() {
        let mut a = Cluster::new([0xAA; 16]);
        a.mark_handled(key(1));
        let g = a.tick(1_000);
        // Feeding A its own broadcast back (floods return to sender) must learn nothing and not
        // inflate the member count with itself.
        for m in &g {
            assert!(a.on_gossip(m, 1_000).is_empty(), "no self-learning");
        }
        assert_eq!(a.member_count(1_000), 1, "self is not a peer");
    }

    #[test]
    fn membership_counts_live_peers_and_times_them_out() {
        let mut a = Cluster::new([0xAA; 16]);
        a.on_gossip(
            &ClusterMsg::Presence {
                member: [0xBB; 16],
                at_ms: 0,
            },
            1_000,
        );
        a.on_gossip(
            &ClusterMsg::Presence {
                member: [0xCC; 16],
                at_ms: 0,
            },
            1_000,
        );
        assert_eq!(a.member_count(1_000), 3, "self + 2 peers");
        // After the TTL with no fresh beacon, the peers age out.
        assert_eq!(
            a.member_count(1_000 + MEMBER_TTL_MS + 1),
            1,
            "stale peers drop"
        );
    }

    #[test]
    fn first_tick_always_beacons() {
        let mut a = Cluster::new([0xAA; 16]);
        let g = a.tick(0);
        assert!(
            g.iter().any(|m| matches!(m, ClusterMsg::Presence { .. })),
            "a fresh cluster beacons on its first tick even at t=0"
        );
        // A second tick right away does not re-beacon (interval not elapsed).
        assert!(!a
            .tick(1)
            .iter()
            .any(|m| matches!(m, ClusterMsg::Presence { .. })));
    }

    #[test]
    fn handled_set_is_bounded() {
        let mut a = Cluster::new([0xAA; 16]);
        for i in 0..(HANDLED_CAP + 500) {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_le_bytes());
            a.mark_handled(k);
        }
        assert_eq!(a.handled_len(), HANDLED_CAP, "eviction caps the set");
        // The oldest key was evicted; a very recent one is retained.
        let mut recent = [0u8; 32];
        recent[..8].copy_from_slice(&((HANDLED_CAP + 499) as u64).to_le_bytes());
        assert!(a.is_handled(&recent));
    }

    #[test]
    fn loaded_keys_dedup_but_are_not_regossiped() {
        // A restart reloads the durable set; those keys must dedup, but must NOT be re-broadcast
        // (they were already gossiped when first handled) or a restart would gossip-storm.
        let mut a = Cluster::new([0xAA; 16]);
        a.load_handled([key(1), key(2), key(3)]);
        assert!(a.is_handled(&key(2)));
        let g = a.tick(1_000);
        assert!(
            !g.iter().any(|m| matches!(m, ClusterMsg::Handled { .. })),
            "loaded keys are not re-gossiped"
        );
    }

    #[test]
    fn rendezvous_ownership_is_agreed_and_balanced() {
        // Two replicas that see each other agree, per key, on exactly one owner (rank 0) + one rank 1,
        // with NO coordination, and HRW spreads ownership across both.
        let a_id = [0xA1; 16];
        let b_id = [0xB2; 16];
        let mut a = Cluster::new(a_id);
        let mut b = Cluster::new(b_id);
        a.on_gossip(
            &ClusterMsg::Presence {
                member: b_id,
                at_ms: 0,
            },
            1_000,
        );
        b.on_gossip(
            &ClusterMsg::Presence {
                member: a_id,
                at_ms: 0,
            },
            1_000,
        );

        let (mut a_owns, mut b_owns) = (0, 0);
        for n in 0u8..60 {
            let k = [n; 32];
            let ra = a.rank_for(&k, 1_000);
            let rb = b.rank_for(&k, 1_000);
            assert_eq!(
                ra + rb,
                1,
                "exactly one owner + one standby, and the replicas agree"
            );
            if ra == 0 {
                a_owns += 1;
            } else {
                b_owns += 1;
            }
        }
        assert!(
            a_owns > 0 && b_owns > 0,
            "HRW spreads ownership ({a_owns} vs {b_owns})"
        );
    }

    #[test]
    fn ownership_fails_over_when_the_owner_ages_out() {
        // While a peer owns a key we are its standby (rank 1); once it stops beaconing and ages out,
        // rendezvous recomputes over the remaining membership and we become the owner.
        let me = [0x11; 16];
        let peer = [0x22; 16];
        let mut c = Cluster::new(me);
        c.on_gossip(
            &ClusterMsg::Presence {
                member: peer,
                at_ms: 0,
            },
            1_000,
        );
        let k = (0u8..=255)
            .map(|n| [n; 32])
            .find(|k| c.rank_for(k, 1_000) == 1)
            .expect("some key the peer owns");
        assert!(!c.is_owner(&k, 1_000), "the peer owns it while live");
        assert!(
            c.is_owner(&k, 1_000 + MEMBER_TTL_MS + 1),
            "we take over once the owner ages out"
        );
    }

    #[test]
    fn quorum_gates_acting_on_the_visible_membership() {
        let mut c = Cluster::new([1u8; 16]);
        c.set_quorum(2);
        assert!(!c.has_quorum(1_000), "alone (1 live) is below quorum 2");
        c.on_gossip(
            &ClusterMsg::Presence {
                member: [2u8; 16],
                at_ms: 0,
            },
            1_000,
        );
        assert!(c.has_quorum(1_000), "self + 1 peer meets quorum 2");
        assert!(
            !c.has_quorum(1_000 + MEMBER_TTL_MS + 1),
            "the peer aged out, back below quorum"
        );
        c.set_quorum(0);
        assert!(
            c.has_quorum(1_000 + MEMBER_TTL_MS + 1),
            "quorum 0 disables the check (AP)"
        );
    }
}
