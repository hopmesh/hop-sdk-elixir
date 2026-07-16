//! [`Endpoint`]: a `hop_core::Node` plus endpoint clustering, built only on the node's PUBLIC API.
//!
//! `Endpoint<S>` owns a `Node<S>` and `Deref`s to it, so every node call still works unchanged; it
//! adds a handful of shadowing methods that fold in the cluster coordinator ([`crate::cluster`]):
//!
//! - `cluster_join` registers the derived, pre-shared-key `hps://` cluster topic on the node
//!   (`hps_register_keyed`) and reloads the durable HANDLED set from the store.
//! - `tick` advances the node, then drains inbound cluster gossip and emits due gossip.
//! - `take_service_requests` / `take_http_requests` shadow the node's: they surface only the requests
//!   this replica OWNS (rendezvous rank 0), hold the rest, and drop sibling-handled ones (phase 2).
//! - `send_service_response` / `cluster_mark_done` mark completion so siblings drop their copies.
//! - `take_hps_messages` returns only the app's (non-cluster) `hps://` messages.
//!
//! No `hop-core` internals are touched: the gate is a post-filter, gossip rides `hps_publish` /
//! `take_hps_messages`, and the HANDLED set persists through the store's KV. DESIGN.md §40.

use std::ops::{Deref, DerefMut};

use rand_core::{OsRng, RngCore};

use hop_core::bundle::BundleId;
use hop_core::crypto::PubKeyBytes;
use hop_core::node::{HpsMessage, HttpReqItem, Node, ServiceReqItem};
use hop_core::store::Store;
use hop_core::Result;

use crate::cluster::{claim_key, ClaimKey, Cluster, ClusterMsg};

/// Store-KV prefix under which the durable HANDLED set is persisted (one entry per key, value = the
/// raw 32-byte [`ClaimKey`]), so a restarted replica still dedups.
const HANDLED_PREFIX: &str = "hop.cluster.handled.";

/// The `hps://` topic path the cluster gossips on, derived from the secret so outsiders cannot even
/// guess where to publish (defence in depth; the derived content key is the real gate).
fn cluster_topic_path(secret: &[u8; 32]) -> String {
    let d = blake3::derive_key("hop.cluster.path.v1", secret);
    let mut s = String::from("_hop.cluster/");
    push_hex(&mut s, &d[..8]);
    s
}

/// The symmetric content key every replica derives identically from the shared cluster secret.
fn content_key(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("hop.cluster.content.v1", secret)
}

/// The KV key for one persisted HANDLED [`ClaimKey`] (prefix + lowercase hex).
fn handled_kv(k: &ClaimKey) -> String {
    let mut s = String::with_capacity(HANDLED_PREFIX.len() + 64);
    s.push_str(HANDLED_PREFIX);
    push_hex(&mut s, k);
    s
}

fn push_hex(s: &mut String, bytes: &[u8]) {
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
}

/// Grace per rank step: a held request surfaces at `first_seen + rank * OWNER_GRACE_MS`. Rank 0 (the
/// owner) surfaces immediately; each standby waits one more grace, so a silent owner hands off to its
/// successors one at a time instead of all of them piling in at once.
const OWNER_GRACE_MS: u64 = 8_000;

/// A request held back because this replica is not (yet) the one that should process it.
struct Held<T> {
    item: T,
    key: ClaimKey,
    first_seen: u64,
}

/// The rendezvous-ownership gate (DESIGN.md §40, phase 2). Stages `incoming` into `held`, then
/// returns the requests this replica should process NOW: the ones it owns (rank 0), plus any standby
/// whose grace elapsed while the owner stayed silent and no visibility threshold is enabled. Requests
/// a sibling already handled are dropped; the rest stay held for a later poll.
fn gate<T>(
    cluster: &Cluster,
    held: &mut Vec<Held<T>>,
    incoming: Vec<T>,
    key_of: impl Fn(&T) -> ClaimKey,
    now_ms: u64,
) -> Vec<T> {
    for item in incoming {
        let key = key_of(&item);
        if cluster.is_handled(&key) || held.iter().any(|h| h.key == key) {
            continue;
        }
        held.push(Held {
            item,
            key,
            first_seen: now_ms,
        });
    }
    // A visibility threshold is conservative: hold below it, and disable timed standby takeover while
    // it is enabled. Recently visible membership can be stale, so it is not a consensus quorum.
    if !cluster.has_quorum(now_ms) {
        held.retain(|h| !cluster.is_handled(&h.key));
        return Vec::new();
    }
    let mut surface = Vec::new();
    let mut keep = Vec::new();
    for h in std::mem::take(held) {
        if cluster.is_handled(&h.key) {
            continue; // a sibling replica already handled it
        }
        let rank = cluster.rank_for(&h.key, now_ms) as u64;
        if rank == 0
            || (!cluster.quorum_enabled()
                && now_ms.saturating_sub(h.first_seen) >= rank * OWNER_GRACE_MS)
        {
            surface.push(h.item);
        } else {
            keep.push(h);
        }
    }
    *held = keep;
    surface
}

/// A `hop_core::Node` with endpoint clustering. `Deref`s to the node, so `subscribe`, `handle`,
/// `drain_outgoing`, addressing, etc. are used exactly as before; the methods defined here shadow
/// the node's to fold in the cluster coordinator.
pub struct Endpoint<S: Store> {
    node: Node<S>,
    cluster: Option<Cluster>,
    /// The derived cluster topic path (present iff joined).
    cluster_path: Option<String>,
    /// Non-cluster `hps://` messages, separated out for the app on the way through.
    passthrough_hps: Vec<HpsMessage>,
    /// Requests held because a sibling replica owns them (phase 2 rendezvous ownership).
    held_svc: Vec<Held<ServiceReqItem>>,
    held_http: Vec<Held<HttpReqItem>>,
}

impl<S: Store> Deref for Endpoint<S> {
    type Target = Node<S>;
    fn deref(&self) -> &Node<S> {
        &self.node
    }
}

impl<S: Store> DerefMut for Endpoint<S> {
    fn deref_mut(&mut self) -> &mut Node<S> {
        &mut self.node
    }
}

impl<S: Store> Endpoint<S> {
    /// Wrap a node as an endpoint. Not yet clustered until [`cluster_join`](Self::cluster_join).
    pub fn new(node: Node<S>) -> Self {
        Self {
            node,
            cluster: None,
            cluster_path: None,
            passthrough_hps: Vec::new(),
            held_svc: Vec::new(),
            held_http: Vec::new(),
        }
    }

    /// Borrow the underlying node (for calls this wrapper does not shadow).
    pub fn node(&self) -> &Node<S> {
        &self.node
    }

    /// Mutably borrow the underlying node.
    pub fn node_mut(&mut self) -> &mut Node<S> {
        &mut self.node
    }

    /// Unwrap back to the plain node.
    pub fn into_inner(self) -> Node<S> {
        self.node
    }

    /// Join the endpoint cluster from a human passphrase (an env var / config value): the 32-byte
    /// cluster secret is derived from it, so every replica configured with the same passphrase joins
    /// the same cluster. Convenience over [`cluster_join`](Self::cluster_join).
    pub fn cluster_join_passphrase(&mut self, passphrase: &[u8]) {
        self.cluster_join(blake3::derive_key("hop.cluster.passphrase.v1", passphrase));
    }

    /// Join the endpoint cluster keyed by `secret` (every replica of one endpoint passes the same
    /// secret). Registers the derived pre-shared-key cluster topic on the node and reloads the
    /// durable HANDLED set, so dedup applies from the next poll on. A fresh random member id
    /// distinguishes this process from its siblings (which all share the endpoint identity).
    pub fn cluster_join(&mut self, secret: [u8; 32]) {
        let mut member = [0u8; 16];
        OsRng.fill_bytes(&mut member);
        let path = cluster_topic_path(&secret);
        self.node.hps_register_keyed(&path, content_key(&secret));
        let mut cluster = Cluster::new(member);
        let loaded: Vec<ClaimKey> = self
            .node
            .store
            .list_kv(HANDLED_PREFIX)
            .into_iter()
            .filter_map(|(_, v)| <[u8; 32]>::try_from(v.as_slice()).ok())
            .collect();
        cluster.load_handled(loaded);
        self.cluster = Some(cluster);
        self.cluster_path = Some(path);
    }

    /// True once [`cluster_join`](Self::cluster_join) has run.
    pub fn cluster_joined(&self) -> bool {
        self.cluster.is_some()
    }

    /// Live replica count (self + peers beaconing within the membership TTL); `1` if not clustered.
    pub fn cluster_members(&self) -> usize {
        match &self.cluster {
            Some(c) => c.member_count(self.node.now_ms()),
            None => 1,
        }
    }

    /// Require at least `min_live_members` (incl. self) recently visible before this replica acts.
    /// While enabled, timed standby takeover is disabled. This TTL-based threshold reduces ordinary
    /// failover races but is not consensus or an at-most-once guarantee. `0` disables it.
    pub fn cluster_quorum(&mut self, min_live_members: usize) {
        if let Some(c) = &mut self.cluster {
            c.set_quorum(min_live_members);
        }
    }

    /// Whether request `(from, id)` would be dropped as already handled by a sibling replica.
    pub fn cluster_would_drop(&self, from: &PubKeyBytes, id: &BundleId) -> bool {
        match &self.cluster {
            Some(c) => c.is_handled(&claim_key(from, id)),
            None => false,
        }
    }

    /// Explicit completion for a fire-and-forget handler (no response to infer it from): mark the
    /// request handled and gossip it so siblings drop their copies.
    pub fn cluster_mark_done(&mut self, from: &PubKeyBytes, id: &BundleId) {
        self.mark_handled(from, id);
    }

    /// Advance the node, then apply inbound cluster gossip and emit any due gossip. Shadows
    /// `Node::tick`, so an endpoint driven the usual way clusters automatically.
    pub fn tick(&mut self, now_ms: u64) {
        self.node.tick(now_ms);
        self.pump_cluster(now_ms);
    }

    /// Drain custom service requests this replica should process now: the ones it owns (rendezvous
    /// rank 0), plus any it holds for a silent owner past the grace, with sibling-handled ones
    /// dropped. Shadows `Node::take_service_requests`, so every caller gets clustering unchanged.
    pub fn take_service_requests(&mut self) -> Vec<ServiceReqItem> {
        let now = self.node.now_ms();
        self.pump_cluster(now);
        let incoming = self.node.take_service_requests();
        let cluster = match &self.cluster {
            Some(c) => c,
            None => return incoming, // unclustered: transparent passthrough
        };
        gate(
            cluster,
            &mut self.held_svc,
            incoming,
            |r| claim_key(&r.from, &r.id),
            now,
        )
    }

    /// Send a response AND record the request handled (responding is completion), so sibling
    /// replicas drop their copies. Shadows `Node::send_service_response`.
    pub fn send_service_response(
        &mut self,
        to: PubKeyBytes,
        for_id: BundleId,
        status: u16,
        body: Vec<u8>,
    ) -> Result<BundleId> {
        let id = self.node.send_service_response(to, for_id, status, body)?;
        self.mark_handled(&to, &for_id);
        Ok(id)
    }

    /// Drain HTTP-over-mesh requests this replica should proxy now (same rendezvous-ownership gate as
    /// `take_service_requests`), so a clustered origin endpoint proxies each request once. Shadows
    /// `Node::take_http_requests`.
    pub fn take_http_requests(&mut self) -> Vec<HttpReqItem> {
        let now = self.node.now_ms();
        self.pump_cluster(now);
        let incoming = self.node.take_http_requests();
        let cluster = match &self.cluster {
            Some(c) => c,
            None => return incoming,
        };
        gate(
            cluster,
            &mut self.held_http,
            incoming,
            |r| claim_key(&r.from, &r.id),
            now,
        )
    }

    /// Send an HTTP-over-mesh response AND mark the request handled, so sibling replicas drop their
    /// copies (the proxied origin call fires once). Shadows `Node::send_http_response`.
    pub fn send_http_response(
        &mut self,
        to: PubKeyBytes,
        for_id: BundleId,
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<BundleId> {
        let id = self
            .node
            .send_http_response(to, for_id, status, headers, body)?;
        self.mark_handled(&to, &for_id);
        Ok(id)
    }

    /// Drain the app's `hps://` messages (cluster-internal gossip is filtered out). Shadows
    /// `Node::take_hps_messages`.
    pub fn take_hps_messages(&mut self) -> Vec<HpsMessage> {
        if self.cluster.is_none() {
            return self.node.take_hps_messages();
        }
        self.pump_cluster(self.node.now_ms());
        std::mem::take(&mut self.passthrough_hps)
    }

    fn mark_handled(&mut self, from: &PubKeyBytes, id: &BundleId) {
        let key = claim_key(from, id);
        let newly = match &mut self.cluster {
            Some(c) => c.mark_handled(key),
            None => false,
        };
        if newly {
            self.node.store.put_kv(&handled_kv(&key), key.to_vec());
        }
    }

    /// Drain inbound `hps://` messages, route cluster gossip into the coordinator (persisting newly
    /// learned keys) and set the rest aside for the app, then publish any due outbound gossip.
    fn pump_cluster(&mut self, now_ms: u64) {
        let path = match &self.cluster_path {
            Some(p) => p.clone(),
            None => return,
        };
        let msgs = self.node.take_hps_messages();
        let mut learned: Vec<ClaimKey> = Vec::new();
        let mut passthrough: Vec<HpsMessage> = Vec::new();
        let mut outbound: Vec<ClusterMsg> = Vec::new();
        if let Some(cluster) = self.cluster.as_mut() {
            for m in msgs {
                if m.path == path {
                    if let Ok(cm) = postcard::from_bytes::<ClusterMsg>(&m.body) {
                        learned.extend(cluster.on_gossip(&cm, now_ms));
                    }
                } else {
                    passthrough.push(m);
                }
            }
            outbound = cluster.tick(now_ms);
        }
        self.passthrough_hps.append(&mut passthrough);
        for k in learned {
            self.node.store.put_kv(&handled_kv(&k), k.to_vec());
        }
        for cm in outbound {
            if let Ok(bytes) = postcard::to_allocvec(&cm) {
                let _ = self.node.hps_publish(&path, &bytes);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hop_core::link::{BearerEvent, LinkId, Role};
    use hop_core::prelude::Identity;
    use hop_core::store::MemoryStore;
    use std::collections::HashMap;

    /// Minimal in-memory fabric over `Endpoint`s (which deref to `Node`), mirroring hop-core's
    /// `Wire2`: route each endpoint's outgoing bytes to the peer on the matching link id.
    struct Wire {
        routes: HashMap<(usize, LinkId), (usize, LinkId)>,
    }
    impl Wire {
        fn new() -> Self {
            Self {
                routes: HashMap::new(),
            }
        }
        fn connect(
            &mut self,
            eps: &mut [Endpoint<MemoryStore>],
            a: usize,
            la: LinkId,
            b: usize,
            lb: LinkId,
        ) {
            self.routes.insert((a, la), (b, lb));
            self.routes.insert((b, lb), (a, la));
            eps[a].handle(BearerEvent::Connected(la, Role::Initiator));
            eps[b].handle(BearerEvent::Connected(lb, Role::Responder));
            self.pump(eps);
        }
        fn pump(&mut self, eps: &mut [Endpoint<MemoryStore>]) {
            for _ in 0..1000 {
                let mut any = false;
                for i in 0..eps.len() {
                    for (link, bytes) in eps[i].drain_outgoing() {
                        any = true;
                        if let Some(&(j, jl)) = self.routes.get(&(i, link)) {
                            eps[j].handle(BearerEvent::Data(jl, bytes));
                        }
                    }
                }
                if !any {
                    break;
                }
            }
        }
    }

    fn ep(secret: Option<&[u8; 32]>) -> Endpoint<MemoryStore> {
        let id = match secret {
            Some(s) => Identity::from_secret_bytes(s),
            None => Identity::generate(),
        };
        Endpoint::new(Node::with_store(id, MemoryStore::new()))
    }

    /// Tick every endpoint + pump a few rounds so membership (Presence gossip) converges: each
    /// replica learns the others before rendezvous ownership is computed.
    fn converge(net: &mut Wire, eps: &mut [Endpoint<MemoryStore>], t: u64) {
        for r in 0..4u64 {
            for e in eps.iter_mut() {
                e.tick(t + r);
            }
            net.pump(eps);
        }
    }

    #[test]
    fn only_the_owner_surfaces_a_request_the_standby_holds_then_drops() {
        // Both replicas share ONE identity and receive the SAME request. Rendezvous ownership makes
        // exactly one (the owner) surface it while the other holds it; when the owner handles + gossips
        // HANDLED, the standby drops its held copy. Exactly-once, no shared store. DESIGN.md §40 phase 2.
        let e = [42u8; 32];
        let mut eps = [ep(Some(&e)), ep(Some(&e)), ep(None)]; // A, B, sender S
        assert_eq!(eps[0].address(), eps[1].address());
        let csecret = [7u8; 32];
        eps[0].cluster_join(csecret);
        eps[1].cluster_join(csecret);
        for e in eps.iter_mut() {
            e.set_time(1_000);
        }

        let mut net = Wire::new();
        net.connect(&mut eps, 0, 10, 1, 10); // A <-> B: cluster gossip
        net.connect(&mut eps, 2, 1, 0, 1); // S -> A
        net.connect(&mut eps, 2, 2, 1, 2); // S -> B  (both receive the request)
        converge(&mut net, &mut eps, 1_000);
        assert!(
            eps[0].cluster_members() >= 2 && eps[1].cluster_members() >= 2,
            "membership converged"
        );

        let a_addr = eps[0].address();
        let req_id = eps[2]
            .send_service_request(a_addr, "app.order".into(), "create".into(), b"{}".to_vec())
            .unwrap();
        net.pump(&mut eps);

        let a = eps[0].take_service_requests();
        let b = eps[1].take_service_requests();
        assert_eq!(
            a.len() + b.len(),
            1,
            "exactly the owner surfaces the request"
        );

        // Whichever surfaced it is the owner; it handles + gossips, and the standby drops its held copy.
        let (owner, standby, from, id) = if a.len() == 1 {
            (0usize, 1usize, a[0].from, a[0].id)
        } else {
            (1usize, 0usize, b[0].from, b[0].id)
        };
        assert_eq!(id, req_id);
        eps[owner]
            .send_service_response(from, id, 0, b"ok".to_vec())
            .unwrap();
        eps[owner].tick(1_500);
        net.pump(&mut eps);
        eps[standby].tick(1_500);
        assert!(
            eps[standby].take_service_requests().is_empty(),
            "the standby drops the request its owner already handled"
        );
    }

    #[test]
    fn a_silent_owner_fails_over_to_the_standby_after_the_grace() {
        // Both receive the request; the owner surfaces it but stays SILENT (never handles). The
        // standby holds it, then takes over once its grace (rank * OWNER_GRACE_MS) elapses with no
        // HANDLED gossip, so a stuck/lost owner never black-holes the request. DESIGN.md §40 phase 2.
        let e = [42u8; 32];
        let mut eps = [ep(Some(&e)), ep(Some(&e)), ep(None)]; // A, B, sender S
        let csecret = [7u8; 32];
        eps[0].cluster_join(csecret);
        eps[1].cluster_join(csecret);
        for e in eps.iter_mut() {
            e.set_time(1_000);
        }

        let mut net = Wire::new();
        net.connect(&mut eps, 0, 10, 1, 10); // A <-> B: cluster gossip
        net.connect(&mut eps, 2, 1, 0, 1); // S -> A
        net.connect(&mut eps, 2, 2, 1, 2); // S -> B
        converge(&mut net, &mut eps, 1_000);

        let a_addr = eps[0].address();
        let req_id = eps[2]
            .send_service_request(a_addr, "app.order".into(), "create".into(), b"{}".to_vec())
            .unwrap();
        net.pump(&mut eps);

        let a = eps[0].take_service_requests();
        let b = eps[1].take_service_requests();
        assert_eq!(a.len() + b.len(), 1, "exactly the owner surfaces it");
        let standby = if a.is_empty() { 0usize } else { 1usize };

        // The owner is silent. The standby is still holding the request now...
        assert!(
            eps[standby].take_service_requests().is_empty(),
            "the standby holds while the owner is presumed working"
        );
        // ...but once the grace elapses with no HANDLED, it takes over (a single successor, staggered).
        eps[standby].set_time(1_000 + OWNER_GRACE_MS + 100);
        let taken = eps[standby].take_service_requests();
        assert_eq!(
            taken.len(),
            1,
            "the standby takes over the silent owner's request"
        );
        assert_eq!(taken[0].id, req_id);
    }

    #[test]
    fn visibility_threshold_holds_until_members_are_visible() {
        // Two replicas require visibility of 2 members. Before discovery each holds the request.
        // Once they exchange presence, deterministic ownership surfaces one copy.
        let e = [42u8; 32];
        let mut eps = [ep(Some(&e)), ep(Some(&e)), ep(None)]; // A, B, sender S
        let cs = [7u8; 32];
        eps[0].cluster_join(cs);
        eps[1].cluster_join(cs);
        eps[0].cluster_quorum(2);
        eps[1].cluster_quorum(2);
        for e in eps.iter_mut() {
            e.set_time(1_000);
        }

        let mut net = Wire::new();
        net.connect(&mut eps, 2, 1, 0, 1); // S -> A
        net.connect(&mut eps, 2, 2, 1, 2); // S -> B  (A and B are NOT linked: a partition)

        let a_addr = eps[0].address();
        let req_id = eps[2]
            .send_service_request(a_addr, "app.order".into(), "create".into(), b"{}".to_vec())
            .unwrap();
        net.pump(&mut eps);

        // Partitioned: neither sees the other, so both hold (no double-process), but both received it.
        assert_eq!(eps[0].cluster_members(), 1);
        assert!(
            eps[0].take_service_requests().is_empty(),
            "A holds: no quorum"
        );
        assert!(
            eps[1].take_service_requests().is_empty(),
            "B holds: no quorum"
        );
        assert!(
            eps[0].store.seen(&req_id) && eps[1].store.seen(&req_id),
            "both received it"
        );

        // Heal the partition: A <-> B link + converge. Now each sees 2 members = quorum, and exactly
        // one (the owner) surfaces the held request.
        net.connect(&mut eps, 0, 10, 1, 10);
        converge(&mut net, &mut eps, 2_000);
        let a = eps[0].take_service_requests();
        let b = eps[1].take_service_requests();
        assert_eq!(
            a.len() + b.len(),
            1,
            "after coordinating, exactly one processes it"
        );
        assert_eq!(a.iter().chain(b.iter()).next().unwrap().id, req_id);
    }

    #[test]
    fn visibility_threshold_disables_standby_takeover_with_stale_membership() {
        let a_id = [0xA1; 16];
        let b_id = [0xB2; 16];
        let mut a = Cluster::new(a_id);
        let mut b = Cluster::new(b_id);
        a.on_gossip(
            &ClusterMsg::Presence {
                member: b_id,
                at_ms: 1_000,
            },
            1_000,
        );
        b.on_gossip(
            &ClusterMsg::Presence {
                member: a_id,
                at_ms: 1_000,
            },
            1_000,
        );
        a.set_quorum(2);
        b.set_quorum(2);

        let key = (0u8..=u8::MAX)
            .map(|n| [n; 32])
            .find(|k| a.rank_for(k, 1_000) == 0 && b.rank_for(k, 1_000) == 1)
            .expect("HRW assigns at least one sampled key to A");
        let mut held_a = Vec::new();
        let mut held_b = Vec::new();
        assert_eq!(gate(&a, &mut held_a, vec![1u8], |_| key, 1_000), vec![1]);
        assert!(gate(&b, &mut held_b, vec![1u8], |_| key, 1_000).is_empty());

        // The link is now partitioned, but B still counts A until the TTL. The old timed takeover
        // surfaced the duplicate here. Threshold mode must keep holding it instead.
        assert!(gate(
            &b,
            &mut held_b,
            Vec::new(),
            |_| key,
            1_000 + OWNER_GRACE_MS + 1,
        )
        .is_empty());
        assert!(gate(
            &b,
            &mut held_b,
            Vec::new(),
            |_| key,
            1_000 + crate::cluster::MEMBER_TTL_MS + 1,
        )
        .is_empty());
    }

    #[test]
    fn unclustered_endpoint_is_a_transparent_passthrough() {
        // Without cluster_join, the endpoint behaves exactly like the bare node.
        let mut eps = [ep(None), ep(None)];
        let mut net = Wire::new();
        net.connect(&mut eps, 0, 1, 1, 1);
        let to = eps[1].address();
        let req_id = eps[0]
            .send_service_request(to, "s".into(), "m".into(), b"x".to_vec())
            .unwrap();
        net.pump(&mut eps);
        let reqs = eps[1].take_service_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].id, req_id);
        assert_eq!(eps[1].cluster_members(), 1, "solo when unclustered");
        assert!(!eps[1].cluster_would_drop(&reqs[0].from, &reqs[0].id));
    }
}
