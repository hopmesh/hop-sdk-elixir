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

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use hop_core::bundle::BundleId;
use hop_core::crypto::PubKeyBytes;
use hop_core::node::{HpsMessage, HttpReqItem, Node, ServiceReqItem};
use hop_core::store::Store;
use hop_core::Result;

use crate::cluster::{claim_key, ClaimKey, Cluster, ClusterMsg, MemberId, HANDLED_TTL_MS};

/// Store-KV prefix under which the durable HANDLED set is persisted, so a restarted replica still
/// dedups. The claim is stored in both the key and value so startup can reject mismatched rows.
const HANDLED_PREFIX: &str = "hop.cluster.handled.";
const MEMBER_PREFIX: &str = "hop.cluster.member.";
const HANDLED_STARTUP_PAGE: usize = 128;
const HANDLED_STARTUP_MAX_ROWS: usize = 1_024;
const HANDLED_STARTUP_MAX_BYTES: usize = 256 * 1024;
const HANDLED_MAINTENANCE_PAGE: usize = 64;
const HANDLED_MAINTENANCE_MAX_BYTES: usize = 64 * 1024;
const HANDLED_MAINTENANCE_INTERVAL_MS: u64 = 1_000;
const HANDLED_MAX_ROW_BYTES: usize = 1_024;

#[derive(Serialize, Deserialize)]
struct PersistedHandled {
    key: ClaimKey,
    expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandledMaintenanceStats {
    pub malformed_deleted: u64,
    pub expired_deleted: u64,
    pub cap_deleted: u64,
}

struct HandledMaintenance {
    after: Option<String>,
}

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

fn member_kv(secret: &[u8; 32]) -> String {
    let derived = blake3::derive_key("hop.cluster.member-slot.v1", secret);
    let mut key = String::with_capacity(MEMBER_PREFIX.len() + 32);
    key.push_str(MEMBER_PREFIX);
    push_hex(&mut key, &derived[..16]);
    key
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
const HELD_MAX_ITEMS: usize = 512;
const HELD_MAX_BYTES: usize = 32 * 1024 * 1024;
const HELD_MAX_ITEM_BYTES: usize = 18 * 1024 * 1024;
const HELD_MAX_ITEMS_PER_SENDER: usize = 32;
const HELD_MAX_BYTES_PER_SENDER: usize = 18 * 1024 * 1024;
const HELD_LIFETIME_MS: u64 = 5 * 60 * 1_000;
const PASSTHROUGH_HPS_MAX_ITEMS: usize = 256;
const PASSTHROUGH_HPS_MAX_BYTES: usize = 16 * 1024 * 1024;

/// A request held back because this replica is not (yet) the one that should process it.
struct Held<T> {
    item: T,
    key: ClaimKey,
    id: BundleId,
    sender: PubKeyBytes,
    bytes: usize,
    first_seen: u64,
    expires_at: u64,
}

#[derive(Clone, Copy, Default)]
struct HeldSenderUsage {
    items: usize,
    bytes: usize,
}

#[derive(Default)]
struct HeldBudget {
    items: usize,
    bytes: usize,
    senders: HashMap<PubKeyBytes, HeldSenderUsage>,
}

impl HeldBudget {
    fn admit(&mut self, sender: PubKeyBytes, bytes: usize) -> bool {
        let sender_usage = self.senders.get(&sender).copied().unwrap_or_default();
        if bytes > HELD_MAX_ITEM_BYTES
            || self.items >= HELD_MAX_ITEMS
            || self.bytes.saturating_add(bytes) > HELD_MAX_BYTES
            || sender_usage.items >= HELD_MAX_ITEMS_PER_SENDER
            || sender_usage.bytes.saturating_add(bytes) > HELD_MAX_BYTES_PER_SENDER
        {
            return false;
        }
        self.items += 1;
        self.bytes += bytes;
        self.senders.insert(
            sender,
            HeldSenderUsage {
                items: sender_usage.items + 1,
                bytes: sender_usage.bytes + bytes,
            },
        );
        true
    }

    fn release(&mut self, sender: PubKeyBytes, bytes: usize) {
        self.items = self.items.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(bytes);
        if let Some(usage) = self.senders.get_mut(&sender) {
            usage.items = usage.items.saturating_sub(1);
            usage.bytes = usage.bytes.saturating_sub(bytes);
            if usage.items == 0 {
                self.senders.remove(&sender);
            }
        }
    }
}

struct GateResult<T> {
    surface: Vec<T>,
    completed: Vec<BundleId>,
    rejected: Vec<T>,
}

/// The rendezvous-ownership gate (DESIGN.md §40, phase 2). Stages `incoming` into `held`, then
/// returns the requests this replica should process NOW: the ones it owns (rank 0), plus any standby
/// whose grace elapsed while the owner stayed silent and no visibility threshold is enabled. Requests
/// a sibling already handled are dropped; the rest stay held for a later poll.
#[allow(clippy::too_many_arguments)] // Service and HTTP queues share this gate through four accessors.
fn gate<T>(
    cluster: &Cluster,
    held: &mut Vec<Held<T>>,
    budget: &mut HeldBudget,
    incoming: Vec<T>,
    history_ready: bool,
    key_of: impl Fn(&T) -> ClaimKey,
    id_of: impl Fn(&T) -> BundleId,
    sender_of: impl Fn(&T) -> PubKeyBytes,
    bytes_of: impl Fn(&T) -> usize,
    now_ms: u64,
) -> GateResult<T> {
    let mut completed = Vec::new();
    let mut rejected = Vec::new();
    let mut keep = Vec::new();
    for h in std::mem::take(held) {
        if cluster.is_handled(&h.key) {
            budget.release(h.sender, h.bytes);
            completed.push(h.id);
        } else if h.expires_at <= now_ms {
            budget.release(h.sender, h.bytes);
            rejected.push(h.item);
        } else {
            keep.push(h);
        }
    }
    *held = keep;

    for item in incoming {
        let key = key_of(&item);
        let id = id_of(&item);
        if cluster.is_handled(&key) {
            completed.push(id);
            continue;
        }
        if held.iter().any(|h| h.key == key) {
            continue;
        }
        let sender = sender_of(&item);
        let bytes = bytes_of(&item);
        if !budget.admit(sender, bytes) {
            rejected.push(item);
            continue;
        }
        held.push(Held {
            item,
            key,
            id,
            sender,
            bytes,
            first_seen: now_ms,
            expires_at: now_ms.saturating_add(HELD_LIFETIME_MS),
        });
    }
    let mut surface = Vec::new();
    let mut keep = Vec::new();
    for h in std::mem::take(held) {
        if cluster.is_handled(&h.key) {
            budget.release(h.sender, h.bytes);
            completed.push(h.id);
            continue; // a sibling replica already handled it
        }
        if h.expires_at <= now_ms {
            budget.release(h.sender, h.bytes);
            rejected.push(h.item);
            continue;
        }
        // Persisted dedup history must be loaded before any request can surface after restart. A
        // visibility threshold is likewise conservative: hold below it, and disable timed standby
        // takeover while it is enabled. Recently visible membership can be stale, so it is not
        // consensus.
        if !history_ready || !cluster.has_quorum(now_ms) {
            keep.push(h);
            continue;
        }
        let rank = cluster.rank_for(&h.key, now_ms) as u64;
        if rank == 0
            || (!cluster.quorum_enabled()
                && now_ms.saturating_sub(h.first_seen) >= rank * OWNER_GRACE_MS)
        {
            budget.release(h.sender, h.bytes);
            completed.push(h.id);
            surface.push(h.item);
        } else {
            keep.push(h);
        }
    }
    *held = keep;
    GateResult {
        surface,
        completed,
        rejected,
    }
}

fn load_persisted_handled<S: Store>(
    node: &mut Node<S>,
    cluster: &mut Cluster,
    key: String,
    value: Vec<u8>,
    now_ms: u64,
    stats: &mut HandledMaintenanceStats,
) {
    if key.len().saturating_add(value.len()) > HANDLED_MAX_ROW_BYTES {
        node.store.remove_kv(&key);
        stats.malformed_deleted = stats.malformed_deleted.saturating_add(1);
        return;
    }
    let record = postcard::from_bytes::<PersistedHandled>(&value).ok();
    match record {
        Some(record) if key == handled_kv(&record.key) && record.expires_at_ms > now_ms => {
            cluster.load_handled([(record.key, record.expires_at_ms)]);
        }
        Some(record) if key == handled_kv(&record.key) => {
            node.store.remove_kv(&key);
            stats.expired_deleted = stats.expired_deleted.saturating_add(1);
        }
        _ => {
            node.store.remove_kv(&key);
            stats.malformed_deleted = stats.malformed_deleted.saturating_add(1);
        }
    }
    for removed in cluster.take_removed() {
        node.store.remove_kv(&handled_kv(&removed));
        stats.cap_deleted = stats.cap_deleted.saturating_add(1);
    }
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
    passthrough_hps_bytes: usize,
    /// Requests held because a sibling replica owns them (phase 2 rendezvous ownership).
    held_svc: Vec<Held<ServiceReqItem>>,
    held_http: Vec<Held<HttpReqItem>>,
    held_budget: HeldBudget,
    handled_maintenance: Option<HandledMaintenance>,
    handled_maintenance_next_ms: u64,
    handled_maintenance_stats: HandledMaintenanceStats,
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
            passthrough_hps_bytes: 0,
            held_svc: Vec::new(),
            held_http: Vec::new(),
            held_budget: HeldBudget::default(),
            handled_maintenance: None,
            handled_maintenance_next_ms: 0,
            handled_maintenance_stats: HandledMaintenanceStats::default(),
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
    pub fn cluster_join_passphrase(&mut self, passphrase: &[u8]) -> bool {
        self.cluster_join(blake3::derive_key("hop.cluster.passphrase.v1", passphrase))
    }

    /// Join using a stable, operator-assigned replica label. This is the safe path for daemons whose
    /// local store is not durable: the same cluster passphrase and replica label derive the same
    /// member id after restart. Sibling replicas must use distinct labels.
    pub fn cluster_join_passphrase_for_replica(
        &mut self,
        passphrase: &[u8],
        replica: &[u8],
    ) -> bool {
        if replica.is_empty() {
            return false;
        }
        let secret = blake3::derive_key("hop.cluster.passphrase.v1", passphrase);
        let mut hasher = blake3::Hasher::new_derive_key("hop.cluster.replica-member.v1");
        hasher.update(&secret);
        hasher.update(replica);
        let derived = hasher.finalize();
        let mut member = [0u8; 16];
        member.copy_from_slice(&derived.as_bytes()[..16]);
        self.cluster_join_inner(secret, Some(member))
    }

    /// Join the endpoint cluster keyed by `secret` (every replica of one endpoint passes the same
    /// secret). Registers the derived pre-shared-key cluster topic on the node and reloads the
    /// durable HANDLED set, so dedup applies from the next poll on. Each replica persists one member
    /// id in its local store and reuses it across process restart; sibling replicas have separate
    /// local stores even though they share the endpoint identity.
    pub fn cluster_join(&mut self, secret: [u8; 32]) -> bool {
        self.cluster_join_inner(secret, None)
    }

    fn cluster_join_inner(&mut self, secret: [u8; 32], configured: Option<MemberId>) -> bool {
        let member_key = member_kv(&secret);
        let persisted = self
            .node
            .store
            .get_kv(&member_key)
            .and_then(|value| <MemberId>::try_from(value.as_slice()).ok());
        let member = match configured.or(persisted) {
            Some(member) => member,
            None => {
                let mut member = [0u8; 16];
                OsRng.fill_bytes(&mut member);
                member
            }
        };
        if persisted != Some(member)
            && self
                .node
                .store
                .put_kv_critical(&member_key, member.to_vec())
                .is_err()
        {
            return false;
        }
        let path = cluster_topic_path(&secret);
        self.node.hps_register_keyed(&path, content_key(&secret));
        let mut cluster = Cluster::new(member);
        let now_ms = self.node.now_ms();
        let mut after: Option<String> = None;
        let mut startup_rows = 0usize;
        let mut startup_bytes = 0usize;
        let mut maintenance = None;
        'startup: loop {
            let page_after = after.clone();
            let page = self.node.store.list_kv_page(
                HANDLED_PREFIX,
                after.as_deref(),
                HANDLED_STARTUP_PAGE,
            );
            if page.is_empty() {
                break;
            }
            let next = page.last().map(|(key, _)| key.clone());
            for (key, value) in page {
                let row_bytes = key.len().saturating_add(value.len());
                if startup_rows >= HANDLED_STARTUP_MAX_ROWS
                    || startup_bytes.saturating_add(row_bytes) > HANDLED_STARTUP_MAX_BYTES
                {
                    maintenance = Some(HandledMaintenance {
                        after: after.clone(),
                    });
                    break 'startup;
                }
                startup_rows += 1;
                startup_bytes += row_bytes;
                after = Some(key.clone());
                load_persisted_handled(
                    &mut self.node,
                    &mut cluster,
                    key,
                    value,
                    now_ms,
                    &mut self.handled_maintenance_stats,
                );
            }
            if next == page_after {
                break;
            }
            after = next;
        }
        self.cluster = Some(cluster);
        self.cluster_path = Some(path);
        self.handled_maintenance = maintenance;
        self.handled_maintenance_next_ms = now_ms.saturating_add(HANDLED_MAINTENANCE_INTERVAL_MS);
        true
    }

    /// True once [`cluster_join`](Self::cluster_join) has run.
    pub fn cluster_joined(&self) -> bool {
        self.cluster.is_some()
    }

    pub fn cluster_member_id(&self) -> Option<MemberId> {
        self.cluster.as_ref().map(Cluster::me)
    }

    pub fn handled_maintenance_pending(&self) -> bool {
        self.handled_maintenance.is_some()
    }

    pub fn handled_maintenance_stats(&self) -> HandledMaintenanceStats {
        self.handled_maintenance_stats
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
        let history_ready = !self.handled_maintenance_pending();
        let cluster = match &self.cluster {
            Some(c) => c,
            None => return self.node.take_service_requests(), // unclustered: transparent passthrough
        };
        let incoming = self.node.take_service_requests_deferred();
        let result = gate(
            cluster,
            &mut self.held_svc,
            &mut self.held_budget,
            incoming,
            history_ready,
            |r| claim_key(&r.from, &r.id),
            |r| r.id,
            |r| r.from,
            |r| {
                r.service
                    .len()
                    .saturating_add(r.method.len())
                    .saturating_add(r.args.len())
                    .saturating_add(72)
            },
            now,
        );
        let mut completed = std::collections::HashSet::new();
        for id in result.completed {
            if self.node.complete_app_delivery(&id) {
                completed.insert(id);
            } else {
                self.node.reject_app_delivery(&id);
            }
        }
        for rejected in result.rejected {
            self.node.reject_app_delivery(&rejected.id);
            if self
                .node
                .send_service_response(
                    rejected.from,
                    rejected.id,
                    503,
                    b"hop-endpoint: held request capacity exceeded".to_vec(),
                )
                .is_ok()
            {
                self.mark_handled(&rejected.from, &rejected.id);
            }
        }
        result
            .surface
            .into_iter()
            .filter(|item| completed.contains(&item.id))
            .collect()
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
        let history_ready = !self.handled_maintenance_pending();
        let cluster = match &self.cluster {
            Some(c) => c,
            None => return self.node.take_http_requests(),
        };
        let incoming = self.node.take_http_requests_deferred();
        let result = gate(
            cluster,
            &mut self.held_http,
            &mut self.held_budget,
            incoming,
            history_ready,
            |r| claim_key(&r.from, &r.id),
            |r| r.id,
            |r| r.from,
            |r| {
                let headers = r.headers.iter().fold(0usize, |total, (name, value)| {
                    total.saturating_add(name.len()).saturating_add(value.len())
                });
                r.host
                    .len()
                    .saturating_add(r.method.len())
                    .saturating_add(r.url.len())
                    .saturating_add(headers)
                    .saturating_add(r.body.len())
                    .saturating_add(80)
            },
            now,
        );
        let mut completed = std::collections::HashSet::new();
        for id in result.completed {
            if self.node.complete_app_delivery(&id) {
                completed.insert(id);
            } else {
                self.node.reject_app_delivery(&id);
            }
        }
        for rejected in result.rejected {
            self.node.reject_app_delivery(&rejected.id);
            if self
                .node
                .send_http_response(
                    rejected.from,
                    rejected.id,
                    503,
                    vec![("content-type".into(), "text/plain".into())],
                    b"hop-endpoint: held request capacity exceeded".to_vec(),
                )
                .is_ok()
            {
                self.mark_handled(&rejected.from, &rejected.id);
            }
        }
        result
            .surface
            .into_iter()
            .filter(|item| completed.contains(&item.id))
            .collect()
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
        self.passthrough_hps_bytes = 0;
        std::mem::take(&mut self.passthrough_hps)
    }

    fn mark_handled(&mut self, from: &PubKeyBytes, id: &BundleId) {
        let key = claim_key(from, id);
        let now_ms = self.node.now_ms();
        let newly = match &mut self.cluster {
            Some(c) => c.mark_handled(key, now_ms),
            None => false,
        };
        if newly {
            self.persist_handled(key, now_ms.saturating_add(HANDLED_TTL_MS));
        }
        self.delete_removed_handled();
    }

    /// Drain inbound `hps://` messages, route cluster gossip into the coordinator (persisting newly
    /// learned keys) and set the rest aside for the app, then publish any due outbound gossip.
    fn pump_cluster(&mut self, now_ms: u64) {
        self.maintain_handled_history(now_ms);
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
        for message in passthrough {
            let bytes = message
                .path
                .len()
                .saturating_add(message.body.len())
                .saturating_add(64);
            if bytes <= PASSTHROUGH_HPS_MAX_BYTES
                && self.passthrough_hps.len() < PASSTHROUGH_HPS_MAX_ITEMS
                && self.passthrough_hps_bytes.saturating_add(bytes) <= PASSTHROUGH_HPS_MAX_BYTES
            {
                self.passthrough_hps_bytes += bytes;
                self.passthrough_hps.push(message);
            }
        }
        for k in learned {
            self.persist_handled(k, now_ms.saturating_add(HANDLED_TTL_MS));
        }
        self.delete_removed_handled();
        for cm in outbound {
            if let Ok(bytes) = postcard::to_allocvec(&cm) {
                let _ = self.node.hps_publish(&path, &bytes);
            }
        }
    }

    fn persist_handled(&mut self, key: ClaimKey, expires_at_ms: u64) {
        if let Ok(value) = postcard::to_allocvec(&PersistedHandled { key, expires_at_ms }) {
            self.node.store.put_kv(&handled_kv(&key), value);
        }
    }

    fn maintain_handled_history(&mut self, now_ms: u64) {
        if now_ms < self.handled_maintenance_next_ms {
            return;
        }
        let Some(mut maintenance) = self.handled_maintenance.take() else {
            return;
        };
        self.handled_maintenance_next_ms = now_ms.saturating_add(HANDLED_MAINTENANCE_INTERVAL_MS);
        let page = self.node.store.list_kv_page(
            HANDLED_PREFIX,
            maintenance.after.as_deref(),
            HANDLED_MAINTENANCE_PAGE,
        );
        if page.is_empty() {
            return;
        }
        let page_len = page.len();
        let mut work_bytes = 0usize;
        let mut deferred = false;
        for (key, value) in page {
            let row_bytes = key.len().saturating_add(value.len());
            if row_bytes <= HANDLED_MAX_ROW_BYTES
                && work_bytes.saturating_add(row_bytes) > HANDLED_MAINTENANCE_MAX_BYTES
            {
                deferred = true;
                break;
            }
            work_bytes = work_bytes.saturating_add(row_bytes.min(HANDLED_MAX_ROW_BYTES));
            maintenance.after = Some(key.clone());
            if let Some(cluster) = self.cluster.as_mut() {
                load_persisted_handled(
                    &mut self.node,
                    cluster,
                    key,
                    value,
                    now_ms,
                    &mut self.handled_maintenance_stats,
                );
            }
        }
        if deferred || page_len == HANDLED_MAINTENANCE_PAGE {
            self.handled_maintenance = Some(maintenance);
        }
    }

    fn delete_removed_handled(&mut self) {
        let removed = match self.cluster.as_mut() {
            Some(cluster) => cluster.take_removed(),
            None => Vec::new(),
        };
        for key in removed {
            self.node.store.remove_kv(&handled_kv(&key));
            self.handled_maintenance_stats.cap_deleted =
                self.handled_maintenance_stats.cap_deleted.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::HANDLED_CAP;
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

    fn gate_byte(
        cluster: &Cluster,
        held: &mut Vec<Held<u8>>,
        budget: &mut HeldBudget,
        incoming: Vec<u8>,
        key: ClaimKey,
        now_ms: u64,
    ) -> GateResult<u8> {
        gate(
            cluster,
            held,
            budget,
            incoming,
            true,
            |_| key,
            |item| [*item; 32],
            |_| [3u8; 32],
            |_| 1,
            now_ms,
        )
    }

    fn numbered_key(n: u64) -> ClaimKey {
        let mut key = [0u8; 32];
        key[..8].copy_from_slice(&n.to_le_bytes());
        key
    }

    fn numbered_sender(n: u64) -> PubKeyBytes {
        let mut sender = [0u8; 32];
        sender[..8].copy_from_slice(&n.to_le_bytes());
        sender[31] = 1;
        sender
    }

    fn gate_numbers(
        cluster: &Cluster,
        held: &mut Vec<Held<u64>>,
        budget: &mut HeldBudget,
        incoming: Vec<u64>,
        sender_of: impl Fn(&u64) -> PubKeyBytes,
        bytes_of: impl Fn(&u64) -> usize,
        now_ms: u64,
    ) -> GateResult<u64> {
        gate(
            cluster,
            held,
            budget,
            incoming,
            true,
            |item| numbered_key(*item),
            |item| numbered_key(*item),
            sender_of,
            bytes_of,
            now_ms,
        )
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
    fn requests_stay_held_until_persisted_handled_history_is_ready() {
        let cluster = Cluster::new([1u8; 16]);
        let key = [2u8; 32];
        let mut held = Vec::new();
        let mut budget = HeldBudget::default();
        let blocked = gate(
            &cluster,
            &mut held,
            &mut budget,
            vec![7u8],
            false,
            |_| key,
            |item| [*item; 32],
            |_| [3u8; 32],
            |_| 1,
            1_000,
        );
        assert!(blocked.surface.is_empty());
        assert_eq!(held.len(), 1);

        let ready = gate(
            &cluster,
            &mut held,
            &mut budget,
            Vec::new(),
            true,
            |_| key,
            |item| [*item; 32],
            |_| [3u8; 32],
            |_| 1,
            1_001,
        );
        assert_eq!(ready.surface, vec![7]);
        assert!(held.is_empty());
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
        assert_eq!(eps[0].held_svc.len(), 1);
        assert_eq!(eps[1].held_svc.len(), 1);
        assert!(
            !eps[0].store.seen(&req_id) && !eps[1].store.seen(&req_id),
            "below-quorum held work is not ACKed or consumed as delivered"
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
        let mut budget_a = HeldBudget::default();
        let mut budget_b = HeldBudget::default();
        assert_eq!(
            gate_byte(&a, &mut held_a, &mut budget_a, vec![1], key, 1_000).surface,
            vec![1]
        );
        assert!(
            gate_byte(&b, &mut held_b, &mut budget_b, vec![1], key, 1_000)
                .surface
                .is_empty()
        );

        // The link is now partitioned, but B still counts A until the TTL. The old timed takeover
        // surfaced the duplicate here. Threshold mode must keep holding it instead.
        assert!(gate_byte(
            &b,
            &mut held_b,
            &mut budget_b,
            Vec::new(),
            key,
            1_000 + OWNER_GRACE_MS + 1,
        )
        .surface
        .is_empty());
        assert!(gate_byte(
            &b,
            &mut held_b,
            &mut budget_b,
            Vec::new(),
            key,
            1_000 + crate::cluster::MEMBER_TTL_MS + 1,
        )
        .surface
        .is_empty());
    }

    #[test]
    fn below_quorum_flood_stays_within_the_global_held_cap() {
        let mut cluster = Cluster::new([0xA1; 16]);
        cluster.set_quorum(2);
        let mut held = Vec::new();
        let mut budget = HeldBudget::default();
        let mut rejected = 0;

        for batch in 0..3u64 {
            let start = batch * HELD_MAX_ITEMS as u64;
            let result = gate_numbers(
                &cluster,
                &mut held,
                &mut budget,
                (start..start + HELD_MAX_ITEMS as u64).collect(),
                |item| numbered_sender(*item),
                |_| 1,
                1_000,
            );
            assert!(
                result.surface.is_empty(),
                "no request surfaces below quorum"
            );
            rejected += result.rejected.len();
        }

        assert_eq!(held.len(), HELD_MAX_ITEMS);
        assert_eq!(budget.items, HELD_MAX_ITEMS);
        assert_eq!(budget.bytes, HELD_MAX_ITEMS);
        assert_eq!(rejected, HELD_MAX_ITEMS * 2);
    }

    #[test]
    fn one_sender_cannot_consume_another_senders_held_capacity() {
        let mut cluster = Cluster::new([0xA1; 16]);
        cluster.set_quorum(2);
        let mut held = Vec::new();
        let mut budget = HeldBudget::default();

        let noisy = gate_numbers(
            &cluster,
            &mut held,
            &mut budget,
            (0..=HELD_MAX_ITEMS_PER_SENDER as u64).collect(),
            |_| numbered_sender(1),
            |_| 1,
            1_000,
        );
        assert_eq!(noisy.rejected.len(), 1);
        assert_eq!(held.len(), HELD_MAX_ITEMS_PER_SENDER);

        let other = gate_numbers(
            &cluster,
            &mut held,
            &mut budget,
            vec![10_000],
            |_| numbered_sender(2),
            |_| 1,
            1_000,
        );
        assert!(other.rejected.is_empty());
        assert_eq!(held.len(), HELD_MAX_ITEMS_PER_SENDER + 1);
    }

    #[test]
    fn held_bytes_items_and_absolute_lifetime_are_enforced() {
        let mut cluster = Cluster::new([0xA1; 16]);
        cluster.set_quorum(2);
        let mut held = Vec::new();
        let mut budget = HeldBudget::default();

        let oversized = gate_numbers(
            &cluster,
            &mut held,
            &mut budget,
            vec![0],
            |_| numbered_sender(0),
            |_| HELD_MAX_ITEM_BYTES + 1,
            1_000,
        );
        assert_eq!(oversized.rejected, vec![0]);
        assert_eq!(budget.items, 0);

        let half = HELD_MAX_BYTES / 2;
        let admitted = gate_numbers(
            &cluster,
            &mut held,
            &mut budget,
            vec![1, 2],
            |item| numbered_sender(*item),
            |_| half,
            1_000,
        );
        assert!(admitted.rejected.is_empty());
        assert_eq!(budget.bytes, HELD_MAX_BYTES);

        let full = gate_numbers(
            &cluster,
            &mut held,
            &mut budget,
            vec![3],
            |_| numbered_sender(3),
            |_| 1,
            1_000,
        );
        assert_eq!(full.rejected, vec![3]);

        let after_expiry = gate_numbers(
            &cluster,
            &mut held,
            &mut budget,
            vec![4],
            |_| numbered_sender(4),
            |_| 1,
            1_000 + HELD_LIFETIME_MS,
        );
        assert_eq!(after_expiry.rejected.len(), 2, "both old items expired");
        assert_eq!(held.len(), 1, "new work uses the released capacity");
        assert_eq!(budget.items, 1);
        assert_eq!(budget.bytes, 1);
    }

    #[test]
    fn held_work_is_retryable_after_an_endpoint_restart() {
        let endpoint_secret = [42u8; 32];
        let cluster_secret = [7u8; 32];
        let mut eps = [ep(Some(&endpoint_secret)), ep(None)];
        eps[0].cluster_join(cluster_secret);
        eps[0].cluster_quorum(2);
        eps[0].set_time(1_000);
        eps[1].set_time(1_000);
        let mut net = Wire::new();
        net.connect(&mut eps, 1, 1, 0, 1);

        let endpoint_address = eps[0].address();
        let request_id = eps[1]
            .send_service_request(
                endpoint_address,
                "app.retry".into(),
                "run".into(),
                b"work".to_vec(),
            )
            .unwrap();
        let original = eps[1]
            .store
            .get(&request_id)
            .expect("sender retains request");
        net.pump(&mut eps);
        assert!(eps[0].take_service_requests().is_empty());
        assert_eq!(eps[0].held_svc.len(), 1);
        assert!(!eps[0].store.seen(&request_id));

        let store = eps[0].store.clone();
        let identity = Identity::from_secret_bytes(&eps[0].identity_secret());
        let mut restarted = Endpoint::new(Node::with_store(identity, store));
        restarted.set_time(2_000);
        restarted.cluster_join(cluster_secret);
        restarted.cluster_quorum(2);
        restarted.ingest(original);

        assert!(restarted.take_service_requests().is_empty());
        assert_eq!(restarted.held_svc.len(), 1, "the retry is admitted again");
        assert!(!restarted.store.seen(&request_id));
    }

    #[test]
    fn handled_claim_survives_restart_then_expires_from_memory_and_kv() {
        let endpoint_secret = [42u8; 32];
        let cluster_secret = [7u8; 32];
        let from = numbered_sender(11);
        let request_id = numbered_key(12);
        let claim = claim_key(&from, &request_id);
        let mut endpoint = ep(Some(&endpoint_secret));
        endpoint.set_time(1_000);
        endpoint.cluster_join(cluster_secret);
        let member = endpoint.cluster_member_id().unwrap();
        endpoint.cluster_mark_done(&from, &request_id);

        let row = endpoint
            .store
            .get_kv(&handled_kv(&claim))
            .expect("handled claim persisted");
        let persisted: PersistedHandled = postcard::from_bytes(&row).unwrap();
        assert_eq!(persisted.expires_at_ms, 1_000 + HANDLED_TTL_MS);

        let store = endpoint.store.clone();
        let identity = Identity::from_secret_bytes(&endpoint.identity_secret());
        let mut restarted = Endpoint::new(Node::with_store(identity, store));
        restarted.set_time(1_001);
        restarted.cluster_join(cluster_secret);
        assert_eq!(
            restarted.cluster_member_id(),
            Some(member),
            "the local replica reuses one durable member id across restart"
        );
        assert!(restarted.cluster_would_drop(&from, &request_id));

        restarted.tick(persisted.expires_at_ms);
        assert!(!restarted.cluster_would_drop(&from, &request_id));
        assert!(restarted.store.get_kv(&handled_kv(&claim)).is_none());
    }

    #[test]
    fn configured_replica_label_is_stable_without_a_durable_store() {
        let mut first = ep(None);
        assert!(first.cluster_join_passphrase_for_replica(b"cluster", b"replica-a"));
        let first_member = first.cluster_member_id();

        let mut restarted = ep(None);
        assert!(restarted.cluster_join_passphrase_for_replica(b"cluster", b"replica-a"));
        assert_eq!(restarted.cluster_member_id(), first_member);

        let mut sibling = ep(None);
        assert!(sibling.cluster_join_passphrase_for_replica(b"cluster", b"replica-b"));
        assert_ne!(sibling.cluster_member_id(), first_member);

        let mut invalid = ep(None);
        assert!(!invalid.cluster_join_passphrase_for_replica(b"cluster", b""));
        assert!(!invalid.cluster_joined());
    }

    #[test]
    fn hostile_persisted_handled_history_is_paged_validated_and_capped() {
        let now_ms = 1_000;
        let expires_at_ms = now_ms + HANDLED_TTL_MS;
        let mut store = MemoryStore::new();
        for n in 0..(HANDLED_CAP + 500) as u64 {
            let key = numbered_key(n);
            store.put_kv(
                &handled_kv(&key),
                postcard::to_allocvec(&PersistedHandled { key, expires_at_ms }).unwrap(),
            );
        }

        let expired = numbered_key((HANDLED_CAP + 600) as u64);
        let expired_kv = handled_kv(&expired);
        store.put_kv(
            &expired_kv,
            postcard::to_allocvec(&PersistedHandled {
                key: expired,
                expires_at_ms: now_ms,
            })
            .unwrap(),
        );
        let mismatched_slot = numbered_key((HANDLED_CAP + 601) as u64);
        let mismatched_kv = handled_kv(&mismatched_slot);
        store.put_kv(
            &mismatched_kv,
            postcard::to_allocvec(&PersistedHandled {
                key: numbered_key((HANDLED_CAP + 602) as u64),
                expires_at_ms,
            })
            .unwrap(),
        );
        let malformed_kv = format!("{HANDLED_PREFIX}malformed");
        store.put_kv(&malformed_kv, vec![0xff, 0x00]);

        let mut endpoint = Endpoint::new(Node::with_store(Identity::generate(), store));
        endpoint.set_time(now_ms);
        endpoint.cluster_join([7u8; 32]);

        assert!(
            endpoint.handled_maintenance_pending(),
            "startup stops at its row/work budget and schedules the remainder"
        );
        assert!(endpoint.cluster.as_ref().unwrap().handled_len() <= HANDLED_STARTUP_MAX_ROWS);
        for step in 1..=256u64 {
            if !endpoint.handled_maintenance_pending() {
                break;
            }
            endpoint.tick(now_ms + step * HANDLED_MAINTENANCE_INTERVAL_MS);
        }
        assert!(
            !endpoint.handled_maintenance_pending(),
            "bounded maintenance eventually completes without extending startup"
        );
        assert_eq!(
            endpoint.cluster.as_ref().unwrap().handled_len(),
            HANDLED_CAP
        );
        let rows = endpoint.store.list_kv(HANDLED_PREFIX);
        assert_eq!(rows.len(), HANDLED_CAP, "durable history is capped too");
        assert!(endpoint.store.get_kv(&expired_kv).is_none());
        assert!(endpoint.store.get_kv(&mismatched_kv).is_none());
        assert!(endpoint.store.get_kv(&malformed_kv).is_none());
        let stats = endpoint.handled_maintenance_stats();
        assert!(stats.expired_deleted >= 1, "expired deletion is observable");
        assert!(
            stats.malformed_deleted >= 2,
            "mismatched and malformed deletion is observable"
        );
        assert!(stats.cap_deleted >= 500, "cap pruning is observable");
        for (kv, value) in rows {
            let record: PersistedHandled = postcard::from_bytes(&value).unwrap();
            assert_eq!(kv, handled_kv(&record.key));
            assert!(record.expires_at_ms > now_ms);
        }
    }

    #[test]
    fn unclustered_endpoint_is_a_transparent_passthrough() {
        // Without cluster_join, the endpoint behaves exactly like the bare node.
        let mut eps = [ep(None), ep(None)];
        let mut net = Wire::new();
        net.connect(&mut eps, 0, 1, 1, 1);
        eps[0].set_time(1);
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
