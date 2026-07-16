//! # hop-ffi
//!
//! The cross-platform binding surface (DESIGN.md §12): a thin, UniFFI-exported
//! wrapper around [`hop_core::node::Node`]. The host app links this (as a
//! `cdylib`/`staticlib`), runs the BLE bearer natively, and drives the node loop
//! through [`HopNode`] — feeding connection/data events in, draining outgoing
//! bytes out, and reading the inbox.
//!
//! Native bindings (Swift/Kotlin) are generated from this crate with the
//! `uniffi-bindgen` CLI; the exported types below are what those bindings expose.
//! Everything here is also callable from Rust, so the loop is testable end to end
//! without a device (see the tests).

use std::sync::{Arc, Mutex};

use hop_core::prelude::*;
use hop_endpoint_core::Endpoint;

// core-ffi-sdk-r2-02: the SQLite store is compiled iff the `full` feature is on (that is the feature
// that actually pulls in `dep:hop-store-sqlite`). The old gate keyed the alias off `not(minimal)`,
// which is TRUE for a bare `--no-default-features` build where `full` is ALSO off, so it referenced a
// crate that Cargo never linked and failed to compile in isolation. `full` is the single real axis;
// `minimal` is a coherence marker (see the compile guard below), so gating on `full`/`not(full)` makes
// the two builds exactly exhaustive.
/// The store backing a [`HopNode`] (core-ffi-03). The full build persists to SQLite; the constrained
/// embedded build swaps in hop-core's in-memory store, so an ESP32 `libhop.a` carries no SQLite (and
/// no UniFFI). Every `HopNode` method is written against this alias, so the two builds share one body.
#[cfg(feature = "full")]
type HopStore = hop_store_sqlite::SqliteStore;
#[cfg(not(feature = "full"))]
type HopStore = hop_core::store::MemoryStore;

// core-ffi-sdk-r2-02: make the two build axes coherent. `full` (the axis that actually pulls in
// `dep:hop-store-sqlite` + `dep:uniffi`) selects the full surface; its absence selects the embedded
// surface (in-memory store, C ABI only). So a bare `--no-default-features` build is a VALID embedded
// build that compiles, `--features minimal` is the same thing named explicitly, and `bundled`
// (default) / `sqlcipher` give the full surface. `full` and `minimal` are contradictory intents
// (SQLite+UniFFI vs. drop-both), so reject that combination loudly instead of silently ignoring
// `minimal`.
#[cfg(all(feature = "full", feature = "minimal"))]
compile_error!(
    "hop: `full` and `minimal` are contradictory build surfaces; enable at most one. `minimal` drops \
     SQLite + UniFFI for a constrained target; `full` (via `bundled`/`sqlcipher`) keeps them. A bare \
     `--no-default-features` build (neither) is the embedded surface."
);

/// libhop — the stable C ABI (cbindgen → `include/hop.h`): the universal client SDK + bearer seam,
/// for every non-UniFFI target (C/C++, ESP32, …). Wraps the SAME `HopNode` as the UniFFI surface.
pub mod cabi;

// core-ffi-03: UniFFI scaffolding is compiled only for the full build. The `minimal` build exposes
// ONLY the C ABI (`cabi.rs`), which is all a constrained/embedded client binds.
#[cfg(feature = "full")]
uniffi::setup_scaffolding!();

/// Build an identity from saved secret bytes, or a fresh one if absent/invalid.
fn identity_from(secret: &[u8]) -> Identity {
    match <[u8; 32]>::try_from(secret) {
        Ok(b) => Identity::from_secret_bytes(&b),
        Err(_) => Identity::generate(),
    }
}

/// Render an address as base58 (compact, copy/paste/QR-friendly).
#[cfg_attr(feature = "full", uniffi::export)]
pub fn address_base58(address: Vec<u8>) -> String {
    bs58::encode(address).into_string()
}

/// Decode a base58 address back to bytes (empty on invalid input).
#[cfg_attr(feature = "full", uniffi::export)]
pub fn address_from_base58(text: String) -> Vec<u8> {
    bs58::decode(text).into_vec().unwrap_or_default()
}

/// Hex of a short (8-byte) trace hop for display.
fn hex8(b: &[u8; 8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The 8-byte short form of a full address — matches what trace hops carry, so the app
/// can index its known addresses by this and resolve trace hops to display names (§27).
#[cfg_attr(feature = "full", uniffi::export)]
pub fn short_address(address: Vec<u8>) -> Vec<u8> {
    match to32(&address) {
        Ok(a) => short_addr(&a).to_vec(),
        Err(_) => Vec::new(),
    }
}

/// The built-in identity service name (`hop.identify`) — call it on a peer to learn its
/// display name + kind (DESIGN.md §29).
#[cfg_attr(feature = "full", uniffi::export)]
pub fn service_identify() -> String {
    SERVICE_IDENTIFY.to_string()
}

/// Decode a `hop.identify` response body into an [`IdentityInfo`]. Returns `None` if the
/// bytes aren't a valid identity record (e.g. the response was for a different service).
#[cfg_attr(feature = "full", uniffi::export)]
pub fn decode_identity(body: Vec<u8>) -> Option<IdentityInfo> {
    let rec: IdentityRecord = postcard::from_bytes(&body).ok()?;
    Some(IdentityInfo {
        address: rec.address.to_vec(),
        name: rec.name.unwrap_or_default(),
        kind: match rec.kind {
            NodeKind::Device => "device",
            NodeKind::Relay => "relay",
            NodeKind::Gateway => "gateway",
            NodeKind::Endpoint => "endpoint",
        }
        .to_string(),
    })
}

/// Human label for a trace hop's carrying app (DESIGN.md §27). Only public infra
/// nodes self-identify ("Hop Relay"); end-user devices stamp the generic fabric app
/// so a trace never advertises which app a device runs (privacy, §27).
fn label_app(app: &ShortApp) -> String {
    if *app == short_app(&relay_app_id()) {
        "Hop Relay".to_string()
    } else if *app == short_app(&FABRIC_APP) {
        "device".to_string()
    } else {
        hex8(app)
    }
}

/// Opaque bytes to ship over the bearer on a given connection.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct OutPacket {
    pub link: u64,
    pub bytes: Vec<u8>,
}

/// A decrypted message delivered to this node.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct InboxMessage {
    /// Sender's hop address (Ed25519 public key).
    pub from: Vec<u8>,
    pub content_type: String,
    pub body: Vec<u8>,
    /// How many hops it travelled to reach us (A→B path length).
    pub hops: u8,
    /// Sender's clock (ms) when the message was created — signed by the sender.
    /// Subtract from local receive time for an end-to-end latency estimate.
    pub created_at: u64,
    /// Provenance: one hop per node that forwarded this message, in order (DESIGN.md
    /// §27). Empty for a direct (0-relay) delivery. Each hop carries the forwarder's
    /// 8-byte short address (resolve it against your address book to a display name via
    /// `short_address`) plus a label for the carrying app.
    pub trace: Vec<TraceHopInfo>,
}

/// One forwarding hop in a message's provenance trace (DESIGN.md §27).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct TraceHopInfo {
    /// The forwarder's 8-byte short address. Compare to `short_address(full)` of a known
    /// peer/relay/contact to resolve it to a display name; show hex if unknown.
    pub node: Vec<u8>,
    /// Carrying-app label: "Hop Relay" for infra, "device" for end-user nodes, else hex.
    pub app_label: String,
}

/// A node's identity, decoded from a `hop.identify` response (DESIGN.md §29).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct IdentityInfo {
    /// The node's full hop address.
    pub address: Vec<u8>,
    /// Display name, if the node set one. Empty string = unset → show the short address
    /// (devices are unnamed by default; relays report their region domain).
    pub name: String,
    /// "device" | "relay" | "gateway".
    pub kind: String,
}

/// A custom (non-`hop.`) service request addressed to this node for the app to fulfill.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct ServiceReq {
    pub from: Vec<u8>,
    /// Request id — pass back to `send_service_response` as `for_request_id`.
    pub request_id: Vec<u8>,
    pub service: String,
    pub method: String,
    pub args: Vec<u8>,
}

/// A service response sealed back to this node as a caller.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct ServiceResp {
    pub from: Vec<u8>,
    pub for_request_id: Vec<u8>,
    pub status: u16,
    pub body: Vec<u8>,
}

/// A service advert discovered via gossip (direct or relayed). The `publisher` is
/// the address to message — its sealing key is derived from it. Apps build presence
/// and contacts on this (e.g. a "presence" service whose `title` is a display name).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct ServiceHit {
    /// Publisher's hop address (Ed25519 public key) — message this to reach them.
    pub publisher: Vec<u8>,
    pub service: String,
    pub title: String,
    pub summary: String,
    pub tags: Vec<String>,
    /// Hops away through the mesh (1 = direct neighbour, ≥2 = via relays; 0 = unknown).
    pub hops: u8,
    /// Publisher clock (ms) when this advert was created — lets the app pick the
    /// freshest record per publisher (e.g. current foreground/background state).
    pub created_at: u64,
}

/// An egress HTTP request a gateway should fulfill (Use Case A, §9).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct HttpReq {
    /// Requester's address (seal the response back to this).
    pub from: Vec<u8>,
    /// The request bundle id (pass back as `for_request_id`).
    pub request_id: Vec<u8>,
    /// The authorized target domain (the endpoint validates this against its own origin).
    pub host: String,
    pub method: String,
    pub url: String,
    pub body: Vec<u8>,
    pub max_resp: u32,
}

/// An HTTP response sealed back to the requester.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct HttpResp {
    pub from: Vec<u8>,
    pub for_request_id: Vec<u8>,
    pub status: u16,
    /// The response's content-type (e.g. `text/html`), so a WebView renders it correctly.
    /// Empty if the responder didn't set one.
    pub content_type: String,
    pub body: Vec<u8>,
}

/// A finished HNS resolution (DESIGN.md §30). `address` empty = the domain served no valid
/// reach record (a resolution error, e.g. `hops://thisdoesnotexist.com`).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct HnsRecord {
    pub domain: String,
    pub address: Vec<u8>,
}

/// A live HNS cache entry for the debug view (DESIGN.md §30). `address` empty = a cached
/// negative; `ttl_secs` is the remaining lifetime, ticking down to expiry.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct HnsCacheEntry {
    pub domain: String,
    pub address: Vec<u8>,
    pub ttl_secs: u32,
}

/// A verified reachability record (see `HopNode::sign_reach_record` + `verify_reach_record`).
/// `valid` false = the signature failed or the record expired; the other fields are then meaningless.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct ReachInfo {
    pub valid: bool,
    /// The reachable Hop address (32 bytes) the record self-certifies.
    pub address: Vec<u8>,
    /// The endpoint spec, e.g. `wss://myaddress.com/_hop` or `1.2.3.4:9944`.
    pub endpoint: String,
    pub issued_at: u64,
    pub ttl_secs: u32,
}

/// Verify a self-certifying reachability record (from `HopNode::sign_reach_record`, a
/// `/.well-known/hop` body, or gossip). `now_secs` = current Unix time to enforce expiry, or 0 to
/// skip the expiry check. Returns `valid=true` iff the signature is by the address the record names
/// and (when checked) it is unexpired. No trust anchor is consulted; the record certifies itself.
#[cfg_attr(feature = "full", uniffi::export)]
pub fn verify_reach_record(bytes: Vec<u8>, now_secs: u64) -> ReachInfo {
    let now = if now_secs == 0 { None } else { Some(now_secs) };
    match hop_core::reach::ReachRecord::verify(&bytes, now) {
        Some(r) => ReachInfo {
            valid: true,
            address: r.claim.address.to_vec(),
            endpoint: r.claim.endpoint,
            issued_at: r.claim.issued_at,
            ttl_secs: r.claim.ttl_secs,
        },
        None => ReachInfo {
            valid: false,
            address: Vec::new(),
            endpoint: String::new(),
            issued_at: 0,
            ttl_secs: 0,
        },
    }
}

/// Outcome of starting an HNS resolution (DESIGN.md §30).
#[cfg_attr(feature = "full", derive(uniffi::Enum))]
pub enum HnsLookupResult {
    /// Served from a fresh cache entry. `address` empty = a cached negative.
    Cached { address: Vec<u8> },
    /// A lookup was kicked off; the result arrives via `take_hns_results`. If this device
    /// is internet-connected the host must service `take_dns_lookups`.
    Pending,
    /// This device has no internet, so it can't fetch the domain's `/.well-known/hop`, and there
    /// is no relayed resolution. Hand it the address directly instead (`hops://<address>`).
    NeedsResolver,
}

/// The kind of `hps://` topic hosted at a path (DESIGN.md §32).
#[cfg_attr(feature = "full", derive(uniffi::Enum))]
pub enum HpsKind {
    /// Anyone with the content key reads AND writes; each post signed by its writer.
    Channel,
    /// Only the owner broadcasts (signed by the service key); subscribers read.
    Service,
}

/// Who may obtain a topic's keys (DESIGN.md §32).
#[cfg_attr(feature = "full", derive(uniffi::Enum))]
pub enum HpsAccess {
    /// Keys handed to anyone who asks (anonymous membership).
    Open,
    /// Requester asks; the host approves before keys are handed off.
    RequestToJoin,
    /// Host invites a destination; the destination accepts, then receives keys.
    Invite,
}

/// Whether a topic announces itself for discovery (DESIGN.md §32).
#[cfg_attr(feature = "full", derive(uniffi::Enum))]
pub enum HpsVisibility {
    /// Reachable only by known address+path or an invite.
    Private,
    /// Host broadcasts an (app-encrypted) discovery advert so same-app peers can browse it.
    Discoverable,
}

/// A received `hps://` message, after decryption + sender verification (DESIGN.md §32).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct HpsMessage {
    pub path: String,
    /// The verified sender's address (for a channel, the writer; for a service, the host).
    pub sender: Vec<u8>,
    pub body: Vec<u8>,
}

/// An invite we (member) received and may accept (DESIGN.md §32 Invite mode).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct HpsInvite {
    pub path: String,
    pub host: Vec<u8>,
    pub kind: HpsKind,
}

/// A discoverable topic surfaced by `browse_discoverable` (same-app only).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct HpsTopicInfo {
    pub host: Vec<u8>,
    pub path: String,
    pub kind: HpsKind,
    pub title: String,
    pub summary: String,
    pub access: HpsAccess,
}

/// A topic we host or follow — for rebuilding the app's channel list after a restart.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct HpsMyTopic {
    pub host: Vec<u8>,
    pub path: String,
    pub kind: HpsKind,
    pub hosting: bool,
    pub access: HpsAccess,
}

fn kind_to_core(k: &HpsKind) -> hop_core::hps::ServiceKind {
    match k {
        HpsKind::Channel => hop_core::hps::ServiceKind::Channel,
        HpsKind::Service => hop_core::hps::ServiceKind::Service,
    }
}
fn kind_from_core(k: hop_core::hps::ServiceKind) -> HpsKind {
    match k {
        hop_core::hps::ServiceKind::Channel => HpsKind::Channel,
        hop_core::hps::ServiceKind::Service => HpsKind::Service,
    }
}
fn access_to_core(a: &HpsAccess) -> hop_core::hps::AccessMode {
    match a {
        HpsAccess::Open => hop_core::hps::AccessMode::Open,
        HpsAccess::RequestToJoin => hop_core::hps::AccessMode::RequestToJoin,
        HpsAccess::Invite => hop_core::hps::AccessMode::Invite,
    }
}
fn access_from_core(a: hop_core::hps::AccessMode) -> HpsAccess {
    match a {
        hop_core::hps::AccessMode::Open => HpsAccess::Open,
        hop_core::hps::AccessMode::RequestToJoin => HpsAccess::RequestToJoin,
        hop_core::hps::AccessMode::Invite => HpsAccess::Invite,
    }
}
fn vis_to_core(v: &HpsVisibility) -> hop_core::hps::Visibility {
    match v {
        HpsVisibility::Private => hop_core::hps::Visibility::Private,
        HpsVisibility::Discoverable => hop_core::hps::Visibility::Discoverable,
    }
}

/// A live link to a directly-connected peer: its address + the bearer link id. The
/// host maps the link id to a transport (e.g. < 10000 = Bluetooth, ≥ 10000 = Wi-Fi).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct PeerLink {
    pub address: Vec<u8>,
    pub link: u64,
}

/// Delivery status of a message we sent (Sending / Sent N / Delivered).
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct MessageStatus {
    /// Distinct peers we've handed a copy to ("Sent N").
    pub relayed: u32,
    /// The destination confirmed receipt back across the network.
    pub delivered: bool,
    /// Forward path length the destination observed (hops to delivery; 0 until delivered).
    pub delivery_hops: u8,
    /// **Forward-path** (A→B) latency in ms the destination observed and reported in its ACK —
    /// how long the message took to *reach* the recipient, NOT the round trip. 0 until delivered.
    pub delivery_ms: u32,
}

/// An item in the relay queue: ours awaiting send, or a peer's awaiting relay.
#[cfg_attr(feature = "full", derive(uniffi::Record))]
pub struct QueueItem {
    pub id: Vec<u8>,
    /// True = our own message (pinned). False = relaying for a peer (decays).
    pub own: bool,
    /// Destination address (empty if internet-egress).
    pub to: Vec<u8>,
    pub priority: u8,
    pub hops: u8,
}

/// Errors crossing the FFI boundary.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "full", derive(uniffi::Error))]
pub enum FfiError {
    #[error("invalid key length (want 32 bytes)")]
    BadKey,
    #[error("hop error: {0}")]
    Hop(String),
}

fn to32(v: &[u8]) -> std::result::Result<[u8; 32], FfiError> {
    v.try_into().map_err(|_| FfiError::BadKey)
}

/// A running Hop node the host drives. Thread-safe (interior `Mutex`), handed to
/// the foreign side as a reference-counted object.
#[cfg_attr(feature = "full", derive(uniffi::Object))]
pub struct HopNode {
    inner: Mutex<Endpoint<HopStore>>,
    /// True iff this node has durable storage. `open` sets it false only when the db path was
    /// unusable even after quarantine, so the host can tell the difference between persistent
    /// and silently-ephemeral (F-26). `new`/`with_secret` are ephemeral by construction.
    persistent: bool,
    /// How many persisted records failed to decode on startup (F-03) — non-zero means an
    /// upgrade changed a struct layout and dropped state; the host should surface it.
    rehydrate_dropped: u32,
}

/// Open the persistent store, or if the file is unusable, quarantine it and retry once so a
/// corrupt/read-only db becomes a clean fresh start rather than permanent per-launch amnesia.
/// Returns `(store, persistent)`; only falls back to in-memory if even a fresh file won't open.
/// See F-26 — the old code did `open(path).or_else(in_memory)`, so a bad path silently ran
/// ephemeral forever with no signal to the host. (core-ffi-03: SQLite-only, so it is compiled only
/// for the `full` build; the embedded build has no SQLite.)
#[cfg(feature = "full")]
fn open_store_persistent(db_path: &str, key: &[u8]) -> (HopStore, bool) {
    use hop_store_sqlite::SqliteStore;
    // F-25: an empty key opens plain; a 32-byte key opens SQLCipher-encrypted (under the store's
    // `sqlcipher` feature).
    if let Ok(s) = SqliteStore::open_keyed(db_path, key) {
        return (s, true);
    }

    // stores-05 / android-01: a KEYED open of an EXISTING db failed. Never quarantine-wipe here — a
    // transient wrong key (e.g. a config path that forgot to pass the key, then a keyed restart) must
    // not destroy sessions/prekeys/queued sends. Two sub-cases:
    if !key.is_empty() && std::path::Path::new(db_path).exists() {
        // (a) The existing file is an unencrypted db and we now hold a key -> migrate it in place
        //     (plaintext -> SQLCipher) so at-rest encryption turns on WITHOUT data loss.
        #[cfg(feature = "sqlcipher")]
        if SqliteStore::opens_as_plaintext(db_path) {
            match SqliteStore::migrate_plaintext_to_keyed(db_path, key) {
                Ok(s) => {
                    eprintln!(
                        "hop: migrated plaintext db at {db_path} to SQLCipher (state preserved)"
                    );
                    return (s, true);
                }
                Err(e) => eprintln!("hop: WARNING plaintext->SQLCipher migration failed: {e}"),
            }
        }
        // (b) Wrong key / genuine corruption on an existing keyed db. FAIL CLOSED: run ephemeral this
        //     session and LEAVE THE FILE INTACT so a later correct-key open recovers it. is_persistent()
        //     is false, which the host must surface (do not silently churn state).
        eprintln!(
            "hop: WARNING keyed open of existing db {db_path} failed (wrong key or corruption); \
             running EPHEMERAL this session and PRESERVING the file. is_persistent() is false."
        );
        return (
            SqliteStore::open_in_memory().expect("in-memory sqlite"),
            false,
        );
    }

    // Empty-key (plain) path, or the file does not exist: a genuinely unusable/corrupt PLAIN db has no
    // key ambiguity, so quarantine it aside and start fresh (F-26). No secret state is encrypted here.
    let quarantine = format!("{db_path}.corrupt");
    let _ = std::fs::remove_file(&quarantine);
    if std::fs::rename(db_path, &quarantine).is_ok() {
        if let Ok(s) = SqliteStore::open_keyed(db_path, key) {
            eprintln!(
                "hop: quarantined unusable db to {quarantine}; started a fresh persistent store"
            );
            return (s, true);
        }
    }
    eprintln!(
        "hop: WARNING db path {db_path} is unusable even after quarantine; running EPHEMERAL \
         (state will NOT survive restart). is_persistent() is false."
    );
    (
        SqliteStore::open_in_memory().expect("in-memory sqlite"),
        false,
    )
}

/// Shared body of the `open` / `open_keyed` UniFFI constructors (F-25). A free function because UniFFI
/// doesn't allow a private associated fn inside an exported impl. (core-ffi-03: SQLite-backed, so it is
/// compiled only for the full build.)
#[cfg(feature = "full")]
fn open_node_inner(db_path: &str, secret: &[u8], app_secret: &[u8], key: &[u8]) -> Arc<HopNode> {
    let (store, persistent) = open_store_persistent(db_path, key);
    let mut node = Node::with_store(identity_from(secret), store);
    if let Ok(s) = <[u8; 32]>::try_from(app_secret) {
        node.set_app_keys(hop_core::app::AppKeys::from_secret(s));
    }
    // Surface any state silently lost to a struct-layout change across an upgrade (F-03).
    let report = node.take_rehydrate_report();
    if !report.is_empty() {
        eprintln!(
            "hop: rehydrate dropped {} persisted record(s) across an upgrade: {:?}",
            report.total(),
            report.dropped
        );
    }
    Arc::new(HopNode {
        inner: Mutex::new(Endpoint::new(node)),
        persistent,
        rehydrate_dropped: report.total(),
    })
}

impl HopNode {
    /// Poison-tolerant lock on the inner node (core-ffi-01). If a prior call panicked while holding
    /// the lock (e.g. a panic reached across the C ABI, or a UniFFI call that unwound), the standard
    /// `.lock().unwrap()` would panic on EVERY subsequent call, permanently bricking the node object
    /// until the app restarts. The node's own state is a plain in-memory structure with no cross-call
    /// invariant that a mid-mutation panic could leave in an unsafe-to-observe state, so recovering the
    /// guard is the right call: one bad call degrades to a dropped operation, not a dead node.
    fn node(&self) -> std::sync::MutexGuard<'_, Endpoint<HopStore>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // Endpoint cluster coordination (DESIGN.md §40). Kept OUT of the `uniffi::export` block (fixed
    // arrays are not a UniFFI type; the mobile client SDKs do not cluster), reachable via the C ABI.
    // These delegate to the `Endpoint` wrapper; `tick` / service polling already cluster through it.

    /// Join the endpoint cluster keyed by `secret`. Dedup then applies transparently: a request a
    /// sibling replica already handled is dropped before it is surfaced to the app.
    pub fn cluster_join(&self, secret: [u8; 32]) {
        self.node().cluster_join(secret);
    }

    /// Join the endpoint cluster from a passphrase (the 32-byte secret is derived from it), so every
    /// replica configured with the same string joins the same cluster, across languages and the
    /// standalone service (which reads it from `HOP_CLUSTER_SECRET`).
    pub fn cluster_join_passphrase(&self, passphrase: &[u8]) {
        self.node().cluster_join_passphrase(passphrase);
    }

    /// Explicit completion for a fire-and-forget handler: mark `(from, id)` handled + gossip it.
    pub fn cluster_mark_done(&self, from: [u8; 32], id: [u8; 32]) {
        self.node().cluster_mark_done(&from, &id);
    }

    /// Whether request `(from, id)` would be dropped as already handled by a sibling replica.
    pub fn cluster_would_drop(&self, from: [u8; 32], id: [u8; 32]) -> bool {
        self.node().cluster_would_drop(&from, &id)
    }

    /// Live replica count (self + peers within the membership TTL); 1 if not clustered.
    pub fn cluster_members(&self) -> u32 {
        self.node().cluster_members() as u32
    }

    /// Require at least `min_live_members` recently visible before processing. This TTL-based
    /// threshold is a conservative failover heuristic, not consensus or an at-most-once guarantee.
    pub fn cluster_quorum(&self, min_live_members: u32) {
        self.node().cluster_quorum(min_live_members as usize);
    }
}

/// A fresh EPHEMERAL store (core-ffi-03). The full build uses an in-memory SQLite; the embedded build
/// uses hop-core's in-memory store, so no SQLite is linked at all.
fn fresh_ephemeral_store() -> HopStore {
    #[cfg(feature = "full")]
    {
        hop_store_sqlite::SqliteStore::open_in_memory().expect("in-memory sqlite")
    }
    #[cfg(not(feature = "full"))]
    {
        hop_core::store::MemoryStore::new()
    }
}

#[cfg_attr(feature = "full", uniffi::export)]
impl HopNode {
    /// Create a node with a fresh identity and ephemeral in-memory storage.
    #[cfg_attr(feature = "full", uniffi::constructor)]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Endpoint::new(Node::with_store(
                Identity::generate(),
                fresh_ephemeral_store(),
            ))),
            persistent: false,
            rehydrate_dropped: 0,
        })
    }

    /// Restore a node from a saved identity secret with ephemeral storage. Pass
    /// empty/invalid bytes to get a fresh identity.
    #[cfg_attr(feature = "full", uniffi::constructor)]
    pub fn with_secret(secret: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Endpoint::new(Node::with_store(
                identity_from(&secret),
                fresh_ephemeral_store(),
            ))),
            persistent: false,
            rehydrate_dropped: 0,
        })
    }

    /// Open a node with **persistent** storage at `db_path` (messages survive
    /// restarts; bounded — older relayed messages are evicted to make room), a
    /// saved identity secret, and a 32-byte **app secret** that isolates this app's
    /// `hps://` channels/services from other apps (DESIGN.md §32). Pass empty/short
    /// app-secret bytes to stay on the open shared fabric. If the path can't be opened it is
    /// quarantined and reopened fresh; only if that also fails does it run ephemeral, and then
    /// [`HopNode::is_persistent`] returns false so the host can tell (F-26).
    #[cfg_attr(feature = "full", uniffi::constructor)]
    pub fn open(db_path: String, secret: Vec<u8>, app_secret: Vec<u8>) -> Arc<Self> {
        Self::open_keyed(db_path, secret, app_secret, Vec::new())
    }

    /// Like [`HopNode::open`], but ENCRYPTS the store at rest with a raw 32-byte `key` the host derives
    /// and stores in the platform Keychain/Keystore (F-25). Real encryption requires the store's
    /// `sqlcipher` cargo feature; without it the key is accepted but the db stays plain. An empty key
    /// behaves exactly like `open`.
    ///
    /// core-ffi-03: on the `minimal` embedded build there is no SQLite, so `db_path`/`key` are accepted
    /// for ABI compatibility but the node runs EPHEMERAL (in-memory); `is_persistent()` reports false so
    /// the host knows. An ESP32 host that wants durability supplies its own store via a future seam.
    #[cfg_attr(feature = "full", uniffi::constructor)]
    pub fn open_keyed(
        db_path: String,
        secret: Vec<u8>,
        app_secret: Vec<u8>,
        key: Vec<u8>,
    ) -> Arc<Self> {
        #[cfg(feature = "full")]
        {
            open_node_inner(&db_path, &secret, &app_secret, &key)
        }
        #[cfg(not(feature = "full"))]
        {
            let _ = (&db_path, &key); // no persistence on a constrained target — run ephemeral
            let mut node = Node::with_store(identity_from(&secret), fresh_ephemeral_store());
            if let Ok(s) = <[u8; 32]>::try_from(app_secret.as_slice()) {
                node.set_app_keys(hop_core::app::AppKeys::from_secret(s));
            }
            Arc::new(Self {
                inner: Mutex::new(Endpoint::new(node)),
                persistent: false,
                rehydrate_dropped: 0,
            })
        }
    }

    /// Whether this node has durable storage. `false` means the db path was unusable and state
    /// will NOT survive a restart; the host should surface a warning rather than assume the
    /// database is the ground truth (F-26).
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }

    /// How many persisted records failed to decode on startup (F-03). Non-zero means an upgrade
    /// changed a struct's on-disk layout and dropped that state; the host should tell the user
    /// (e.g. queued sends or sessions were lost) instead of it vanishing silently.
    pub fn rehydrate_dropped(&self) -> u32 {
        self.rehydrate_dropped
    }

    // Note: there is intentionally no `set_app` here. End-user devices must NOT stamp
    // their app id into trace hops — that would advertise which app a device runs to
    // every relay on the path (DESIGN.md §27 privacy). Devices stay on FABRIC_APP;
    // only infra relays self-identify (hop-relayd calls Node::set_app(relay_app_id())).

    /// Export this node's identity secret to persist (store it in the Keychain).
    pub fn secret(&self) -> Vec<u8> {
        self.node().identity_secret().to_vec()
    }

    /// This node's hop address (Ed25519 public key).
    pub fn address(&self) -> Vec<u8> {
        self.node().address().to_vec()
    }

    /// A bearer connection came up; `initiator` = we dialed it (BLE central).
    pub fn connected(&self, link: u64, initiator: bool) {
        let role = if initiator {
            Role::Initiator
        } else {
            Role::Responder
        };
        self.node().handle(BearerEvent::Connected(link, role));
    }

    /// A bearer connection dropped.
    pub fn disconnected(&self, link: u64) {
        self.node().handle(BearerEvent::Disconnected(link));
    }

    /// Bytes arrived on a connection.
    pub fn received(&self, link: u64, bytes: Vec<u8>) {
        self.node().handle(BearerEvent::Data(link, bytes));
    }

    /// Bytes the host must send over the bearer (then clears them).
    pub fn drain_outgoing(&self) -> Vec<OutPacket> {
        self.node()
            .drain_outgoing()
            .into_iter()
            .map(|(link, bytes)| OutPacket { link, bytes })
            .collect()
    }

    /// Advance time: expire adverts, retransmit unacked bundles, prune dedup.
    pub fn tick(&self, now_ms: u64) {
        self.node().tick(now_ms);
    }

    /// Subscribe the directory to a service topic.
    pub fn subscribe(&self, topic: String) {
        self.node().subscribe(topic);
    }

    /// Send a peer message to `dst` (an address — sealing key is derived from it).
    /// **Untraceable by default** (DESIGN.md §39): no cleartext src/dst, the bundle floods
    /// and is recognized only by `dst`. Still forward-secret + sender-authenticated. Returns
    /// the bundle id. Set `request_ack` for a private delivery confirmation.
    pub fn send_message(
        &self,
        dst: Vec<u8>,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let dst = to32(&dst)?;
        let id = self
            .node()
            .send_message(dst, content_type, body, request_ack)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Send a peer message to `dst` with full §27 provenance — cleartext src/dst, route
    /// learning, relay-vaccinating ACKs. The **opt-in traced** path; prefer [`Self::send_message`]
    /// (untraceable) unless the user has explicitly chosen a traceable send.
    pub fn send_message_traced(
        &self,
        dst: Vec<u8>,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let dst = to32(&dst)?;
        let id = self
            .node()
            .send_message_traced(dst, content_type, body, request_ack)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Publish a signed service advert that gossips across the mesh (even multiple
    /// hops away). Returns the advert id. Apps build presence on this — e.g. publish
    /// a "presence" service whose `title` is the user's display name. `ttlMs` bounds
    /// how long the record lives before it must be refreshed.
    pub fn publish_service(
        &self,
        service: String,
        title: String,
        summary: String,
        tags: Vec<String>,
        ttl_ms: u32,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let id = self
            .node()
            .publish_service(service, title, summary, tags, ttl_ms)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Browse a service namespace (optionally filtered by tag) for adverts discovered
    /// across the mesh, with hop distance. Pass an empty `tag` for no filter.
    pub fn browse(&self, service: String, tag: String) -> Vec<ServiceHit> {
        let tag = if tag.is_empty() { None } else { Some(tag) };
        self.node()
            .browse(&service, tag.as_deref())
            .into_iter()
            .filter_map(|a| match a.body.kind {
                AdvertKind::Service {
                    service,
                    title,
                    summary,
                    tags,
                } => Some(ServiceHit {
                    publisher: a.body.publisher.to_vec(),
                    service,
                    title,
                    summary,
                    tags,
                    hops: a.hops,
                    created_at: a.body.created_at,
                }),
                _ => None,
            })
            .collect()
    }

    /// Delivery status of a message we sent, by its bundle id.
    pub fn message_status(&self, id: Vec<u8>) -> MessageStatus {
        let blank = MessageStatus {
            relayed: 0,
            delivered: false,
            delivery_hops: 0,
            delivery_ms: 0,
        };
        let id = match to32(&id) {
            Ok(i) => i,
            Err(_) => return blank,
        };
        match self.node().message_status(&id) {
            Some((relayed, delivered, delivery_hops, delivery_ms)) => MessageStatus {
                relayed,
                delivered,
                delivery_hops,
                delivery_ms,
            },
            None => blank,
        }
    }

    /// Clear the relay queue: drop our undelivered messages (stop retransmitting) and any
    /// bundles held for peers. Does not touch chat history or sessions.
    pub fn clear_queue(&self) {
        self.node().clear_queue();
    }

    /// The relay queue: our messages awaiting send (pinned) + peers' awaiting relay.
    pub fn queue(&self) -> Vec<QueueItem> {
        self.node()
            .queue()
            .into_iter()
            .map(|q| QueueItem {
                id: q.id.to_vec(),
                own: q.own,
                to: q.to.map(|a| a.to_vec()).unwrap_or_default(),
                priority: q.priority,
                hops: q.hops,
            })
            .collect()
    }

    /// Whether messaging `address` is forward-secret (a ratchet session exists)
    /// rather than static-sealed (DESIGN.md §25). Drives a lock indicator in the UI.
    pub fn is_secured(&self, address: Vec<u8>) -> bool {
        match to32(&address) {
            Ok(a) => self.node().has_session(&a),
            Err(_) => false,
        }
    }

    /// Addresses of currently-connected, authenticated peers.
    pub fn peers(&self) -> Vec<Vec<u8>> {
        self.node().peers().iter().map(|a| a.to_vec()).collect()
    }

    /// Whether this node has learned a live route toward `address` from observed
    /// deliveries (DESIGN.md §27). Drives a "known route" indicator in the UI.
    pub fn knows_route(&self, address: Vec<u8>) -> bool {
        match to32(&address) {
            Ok(a) => self.node().knows_route(&a),
            Err(_) => false,
        }
    }

    /// Live links `(address, link id)` — the host maps link ids to transports to show
    /// the route to each direct neighbour.
    pub fn peer_links(&self) -> Vec<PeerLink> {
        self.node()
            .peer_links()
            .into_iter()
            .map(|(address, link)| PeerLink {
                address: address.to_vec(),
                link,
            })
            .collect()
    }

    /// Send a message to a directly-connected peer (sealed with the key learned at
    /// handshake). Returns the bundle id; errors if not connected to that address.
    pub fn send_to(
        &self,
        address: Vec<u8>,
        content_type: String,
        body: Vec<u8>,
        request_ack: bool,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let address = to32(&address)?;
        match self
            .node()
            .send_to(&address, content_type, body, request_ack)
            .map_err(|e| FfiError::Hop(e.to_string()))?
        {
            Some(id) => Ok(id.to_vec()),
            None => Err(FfiError::Hop("peer not connected".into())),
        }
    }

    /// Drain decrypted messages addressed to this node since the last call. Handles
    /// both static-sealed and forward-secret session messages uniformly.
    pub fn take_inbox(&self) -> Vec<InboxMessage> {
        let mut node = self.node();
        let bundles = node.take_inbox();
        bundles
            .iter()
            .filter_map(|b| match node.read_message(b) {
                Ok(Some(m)) => Some(InboxMessage {
                    from: m.from.to_vec(),
                    content_type: m.content_type,
                    body: m.body,
                    hops: b.env.hops,
                    created_at: b.inner.created_at,
                    // Structured hops so the app can resolve each forwarder to a name.
                    trace: b
                        .trace()
                        .iter()
                        .map(|h| TraceHopInfo {
                            node: h.node.to_vec(),
                            app_label: label_app(&h.app),
                        })
                        .collect(),
                }),
                _ => None,
            })
            .collect()
    }

    /// Publish this node's prekey so peers can open forward-secret sessions to it
    /// (DESIGN.md §25). Call at startup and re-publish periodically. Returns the
    /// advert id.
    pub fn publish_prekey(&self) -> std::result::Result<Vec<u8>, FfiError> {
        let id = self
            .node()
            .publish_prekey()
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Number of locally-sent bundles still awaiting an ACK.
    pub fn pending_count(&self) -> u32 {
        self.node().pending_count() as u32
    }

    /// Send a `hops://` request sealed and addressed to a specific endpoint's Hop address
    /// (DESIGN.md §30). `host` is the authorized domain (the endpoint validates it and
    /// refuses anything else); `url` is the path+query only. Returns the request bundle id;
    /// the response arrives via [`take_http_responses`].
    pub fn send_hops_request(
        &self,
        endpoint: Vec<u8>,
        host: String,
        method: String,
        url: String,
        body: Vec<u8>,
        max_resp: u32,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let ep = to32(&endpoint)?;
        let id = self
            .node()
            .send_hops_request(ep, host, method, url, vec![], body, max_resp)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    // ---- HNS: the Hop Name System (DESIGN.md §30) ----------------------------------------

    /// Declare whether this device can reach the public internet (and thus public DNS). When
    /// on, the host must service `take_dns_lookups` so the node can resolve HNS on its own
    /// without any relay round-trip.
    pub fn set_internet(&self, on: bool) {
        self.node().set_internet(on);
    }

    /// Whether this device is marked internet-connected.
    pub fn is_internet(&self) -> bool {
        self.node().is_internet()
    }

    /// Resolve `domain` to its hops endpoint address (DESIGN.md §30). See [`HnsLookupResult`].
    pub fn resolve_hns(&self, domain: String) -> HnsLookupResult {
        match self.node().resolve_hns(&domain) {
            HnsLookup::Cached(Some(addr)) => HnsLookupResult::Cached {
                address: addr.to_vec(),
            },
            HnsLookup::Cached(None) => HnsLookupResult::Cached { address: vec![] },
            HnsLookup::Pending => HnsLookupResult::Pending,
            HnsLookup::NeedsResolver => HnsLookupResult::NeedsResolver,
        }
    }

    /// Domains the node needs the host to resolve (DESIGN.md §30). For each, do a plain HTTPS GET
    /// of `https://<domain>/.well-known/hop` (the TLS certificate proves the domain), pull the
    /// reach record out of that JSON body, and hand its bytes to `provide_reach_record`. Core
    /// verifies the reach record against the address it carries; the host never decides the address.
    pub fn take_dns_lookups(&self) -> Vec<String> {
        self.node().take_dns_lookups()
    }

    /// Feed back the reach-record bytes fetched from a domain's `/.well-known/hop`. Core verifies
    /// the self-certifying record and caches the address only if it verifies (DESIGN.md §30).
    pub fn provide_reach_record(&self, domain: String, record: Vec<u8>) {
        self.node().provide_reach_record(&domain, record);
    }

    /// A snapshot of the live HNS cache (for the debug view): each cached domain, its address
    /// (empty = negative), and the remaining TTL in seconds (ticks down to expiry).
    pub fn hns_cache(&self) -> Vec<HnsCacheEntry> {
        self.node()
            .hns_cache_snapshot()
            .into_iter()
            .map(|(domain, addr, remaining_ms)| HnsCacheEntry {
                domain,
                address: addr.map(|a| a.to_vec()).unwrap_or_default(),
                ttl_secs: (remaining_ms / 1000) as u32,
            })
            .collect()
    }

    /// Finished HNS resolutions (positive or negative), clearing the queue.
    pub fn take_hns_results(&self) -> Vec<HnsRecord> {
        self.node()
            .take_hns_results()
            .into_iter()
            .map(|r| HnsRecord {
                domain: r.domain,
                address: r.address.map(|a| a.to_vec()).unwrap_or_default(),
            })
            .collect()
    }

    /// Sign a self-certifying reachability record for this node's address, binding it to `endpoint`
    /// (e.g. `wss://myaddress.com/_hop`) for `ttl_secs`. Serve the bytes at `/.well-known/hop` or
    /// gossip them; verify with the free `verify_reach_record`. No DNS needed: the record is
    /// signed by the address it names (DESIGN.md §30 endpoint discovery).
    pub fn sign_reach_record(&self, endpoint: String, ttl_secs: u32) -> Vec<u8> {
        self.node().sign_reach_record(endpoint, ttl_secs).to_bytes()
    }

    // ---- hps:// pub/sub: services & channels (DESIGN.md §32) ------------------------------

    /// Register (host) an `hps://` topic at `path`, minting + persisting its keys. `access`
    /// governs key handoff and `visibility` whether it's advertised for discovery (DESIGN.md
    /// §32). Returns the service's public key for a `Service`, or empty for a `Channel`.
    pub fn register_service(
        &self,
        path: String,
        kind: HpsKind,
        access: HpsAccess,
        visibility: HpsVisibility,
    ) -> Vec<u8> {
        self.node()
            .register_service(
                &path,
                kind_to_core(&kind),
                access_to_core(&access),
                vis_to_core(&visibility),
            )
            .map(|pk| pk.to_vec())
            .unwrap_or_default()
    }

    /// Host → destination: invite an address to a topic we host (Invite mode). Returns the
    /// invite bundle id.
    pub fn hps_invite(
        &self,
        path: String,
        dest: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let dest = to32(&dest)?;
        let id = self
            .node()
            .hps_invite(&path, dest)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Member → host: accept an invite we received; the host then seals us the keys.
    pub fn hps_accept_invite(
        &self,
        host: Vec<u8>,
        path: String,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let host = to32(&host)?;
        let id = self
            .node()
            .hps_accept_invite(host, &path)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Decline a received invite — drops it from durable storage so it won't reappear on restart.
    pub fn hps_decline_invite(
        &self,
        host: Vec<u8>,
        path: String,
    ) -> std::result::Result<(), FfiError> {
        let host = to32(&host)?;
        self.node().hps_decline_invite(host, &path);
        Ok(())
    }

    /// Drain invites we've received (DESIGN.md §32 Invite mode), clearing them.
    pub fn take_hps_invites(&self) -> Vec<HpsInvite> {
        self.node()
            .take_hps_invites()
            .into_iter()
            .map(|i| HpsInvite {
                path: i.path,
                host: i.host.to_vec(),
                kind: kind_from_core(i.kind),
            })
            .collect()
    }

    /// Member → host: leave a topic (stop being re-keyed). Returns the leave bundle id, if any.
    pub fn hps_leave(&self, path: String) -> std::result::Result<Vec<u8>, FfiError> {
        let id = self
            .node()
            .hps_leave(&path)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.map(|b| b.to_vec()).unwrap_or_default())
    }

    /// Host: pending join requests for a RequestToJoin topic (each is a requester address).
    pub fn hps_pending(&self, path: String) -> Vec<Vec<u8>> {
        self.node()
            .hps_pending(&path)
            .into_iter()
            .map(|a| a.to_vec())
            .collect()
    }

    /// Host: approve a pending requester, sealing them the keys. Returns the keys bundle id.
    pub fn hps_approve(
        &self,
        path: String,
        requester: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let requester = to32(&requester)?;
        let id = self
            .node()
            .hps_approve(&path, requester)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Host: deny/drop a pending requester (no keys).
    pub fn hps_deny(&self, path: String, requester: Vec<u8>) -> std::result::Result<(), FfiError> {
        let requester = to32(&requester)?;
        self.node().hps_deny(&path, requester);
        Ok(())
    }

    /// Host: selective forward rotation (revocation). Re-keys retained members except `remove`;
    /// removed members keep the dead key. `new_path` empty = keep the same path. Returns the
    /// rekey bundle ids.
    pub fn hps_rekey(
        &self,
        path: String,
        new_path: String,
        remove: Vec<Vec<u8>>,
    ) -> std::result::Result<Vec<Vec<u8>>, FfiError> {
        let mut removed = Vec::with_capacity(remove.len());
        for r in &remove {
            removed.push(to32(r)?);
        }
        let np = if new_path.trim().is_empty() {
            None
        } else {
            Some(new_path.as_str())
        };
        let ids = self
            .node()
            .hps_rekey(&path, np, &removed)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(ids.into_iter().map(|b| b.to_vec()).collect())
    }

    /// Host: unique acking addresses for a topic (its reach / delivery sense, DESIGN.md §32).
    pub fn hps_reach(&self, path: String) -> u32 {
        self.node().hps_reach(&path) as u32
    }

    /// Host: the retained-member set (addresses) for a topic.
    pub fn hps_members(&self, path: String) -> Vec<Vec<u8>> {
        self.node()
            .hps_members(&path)
            .into_iter()
            .map(|a| a.to_vec())
            .collect()
    }

    /// Topics this node hosts or follows — the app calls this at startup to rebuild its channel
    /// list, since the node persists topics but the app's in-memory list doesn't.
    pub fn hps_my_topics(&self) -> Vec<HpsMyTopic> {
        self.node()
            .hps_my_topics()
            .into_iter()
            .map(|t| HpsMyTopic {
                host: t.host.to_vec(),
                path: t.path,
                kind: kind_from_core(t.kind),
                hosting: t.hosting,
                access: access_from_core(t.access),
            })
            .collect()
    }

    /// Same-app discoverable topics visible on the mesh (decrypted descriptors + host address).
    pub fn browse_discoverable(&self) -> Vec<HpsTopicInfo> {
        self.node()
            .browse_discoverable(None)
            .into_iter()
            .map(|(host, m)| HpsTopicInfo {
                host: host.to_vec(),
                path: m.path,
                kind: kind_from_core(m.kind),
                title: m.title,
                summary: m.summary,
                access: access_from_core(m.access),
            })
            .collect()
    }

    /// Subscribe to `hps://{host}/{path}`: send a sealed request to `host`, which (for an open
    /// topic) replies with the topic keys. Messages then arrive via `take_hps_messages`. Returns
    /// the subscribe request's bundle id.
    pub fn hps_subscribe(
        &self,
        host: Vec<u8>,
        path: String,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let host = to32(&host)?;
        let id = self
            .node()
            .hps_subscribe(host, &path)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Publish to a topic we host or (for a channel) belong to. Floods to all subscribers,
    /// signed by the service key (service) or our own identity (channel). Returns the bundle id.
    pub fn hps_publish(
        &self,
        path: String,
        body: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let id = self
            .node()
            .hps_publish(&path, &body)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Drain received `hps://` messages (already decrypted + sender-verified), clearing them.
    pub fn take_hps_messages(&self) -> Vec<HpsMessage> {
        self.node()
            .take_hps_messages()
            .into_iter()
            .map(|m| HpsMessage {
                path: m.path,
                sender: m.sender.to_vec(),
                body: m.body,
            })
            .collect()
    }

    /// Seal an HTTP response back to a requester (gateway side).
    pub fn send_http_response(
        &self,
        to: Vec<u8>,
        for_request_id: Vec<u8>,
        status: u16,
        body: Vec<u8>,
    ) -> std::result::Result<(), FfiError> {
        let to = to32(&to)?;
        let for_id = to32(&for_request_id)?;
        self.node()
            .send_http_response(to, for_id, status, vec![], body)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(())
    }

    /// Drain egress HTTP requests addressed to this node as a gateway.
    pub fn take_http_requests(&self) -> Vec<HttpReq> {
        self.node()
            .take_http_requests()
            .into_iter()
            .map(|r| HttpReq {
                from: r.from.to_vec(),
                request_id: r.id.to_vec(),
                host: r.host,
                method: r.method,
                url: r.url,
                body: r.body,
                max_resp: r.max_resp,
            })
            .collect()
    }

    /// Drain HTTP responses sealed back to this node as a requester.
    pub fn take_http_responses(&self) -> Vec<HttpResp> {
        self.node()
            .take_http_responses()
            .into_iter()
            .map(|r| HttpResp {
                from: r.from.to_vec(),
                for_request_id: r.for_id.to_vec(),
                status: r.status,
                content_type: r
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default(),
                body: r.body,
            })
            .collect()
    }

    // --- service calls (DESIGN.md §29) ----------------------------------------

    /// Set this node's display name, returned by the built-in `hop.identify` service.
    /// Pass an empty string to clear it (then identify reports no name → peers show the
    /// short address).
    pub fn set_name(&self, name: String) {
        let name = if name.is_empty() { None } else { Some(name) };
        self.node().set_name(name);
    }

    /// This node's display name (empty string if unset).
    pub fn name(&self) -> String {
        self.node().name().unwrap_or_default().to_string()
    }

    /// Call a service/command on `dst` (DESIGN.md §29). For the built-in identity
    /// service pass `service_identify()` as `service`; the reply arrives via
    /// `take_service_responses` (decode an identify reply with `decode_identity`).
    /// Returns the request id.
    pub fn send_service_request(
        &self,
        dst: Vec<u8>,
        service: String,
        method: String,
        args: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let dst = to32(&dst)?;
        let id = self
            .node()
            .send_service_request(dst, service, method, args)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Seal a response to a custom service request back to its caller (app side). Use
    /// the [`ServiceReq`]'s `from` as `to` and its `request_id` as `for_request_id`.
    pub fn send_service_response(
        &self,
        to: Vec<u8>,
        for_request_id: Vec<u8>,
        status: u16,
        body: Vec<u8>,
    ) -> std::result::Result<Vec<u8>, FfiError> {
        let to = to32(&to)?;
        let for_id = to32(&for_request_id)?;
        let id = self
            .node()
            .send_service_response(to, for_id, status, body)
            .map_err(|e| FfiError::Hop(e.to_string()))?;
        Ok(id.to_vec())
    }

    /// Drain custom service requests addressed to this node (built-in `hop.` services
    /// are answered by the node and never appear here).
    pub fn take_service_requests(&self) -> Vec<ServiceReq> {
        self.node()
            .take_service_requests()
            .into_iter()
            .map(|r| ServiceReq {
                from: r.from.to_vec(),
                request_id: r.id.to_vec(),
                service: r.service,
                method: r.method,
                args: r.args,
            })
            .collect()
    }

    /// Drain service responses sealed back to this node as a caller.
    pub fn take_service_responses(&self) -> Vec<ServiceResp> {
        self.node()
            .take_service_responses()
            .into_iter()
            .map(|r| ServiceResp {
                from: r.from.to_vec(),
                for_request_id: r.for_id.to_vec(),
                status: r.status,
                body: r.body,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pump both nodes over a single symmetric link (id 1) until quiescent.
    fn pump(a: &HopNode, b: &HopNode) {
        for _ in 0..1000 {
            let oa = a.drain_outgoing();
            let ob = b.drain_outgoing();
            if oa.is_empty() && ob.is_empty() {
                break;
            }
            for p in oa {
                b.received(p.link, p.bytes);
            }
            for p in ob {
                a.received(p.link, p.bytes);
            }
        }
    }

    #[test]
    fn identity_secret_round_trips_address() {
        let a = HopNode::new();
        let addr = a.address();
        let sec = a.secret();
        assert_eq!(sec.len(), 32, "secret is the 32-byte Ed25519 seed");
        // Restoring from the saved secret MUST reproduce the same address.
        let b = HopNode::with_secret(sec.clone());
        assert_eq!(
            b.address(),
            addr,
            "restored identity keeps the same address"
        );
        // And the persistent constructor must do the same.
        let c = HopNode::open(":memory:".into(), sec, Vec::new());
        assert_eq!(
            c.address(),
            addr,
            "persistent restore keeps the same address"
        );
    }

    // F-25/F-26 (cabi-r3): open_store_persistent chooses among three data-loss-adjacent recovery arms
    // on a keyed-open failure. The underlying store OPERATIONS are proven in hop-store-sqlite; what was
    // untested at the FFI layer is the BRANCH SELECTION - which arm fires and whether is_persistent()
    // reports the truth. Picking wrong loses sessions/prekeys/queued sends or falsely claims durability.
    // These tests pin each arm.
    fn recovery_tmp(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("hop_cabi_r3_{name}_{}.db", std::process::id()));
        let s = p.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&s);
        let _ = std::fs::remove_file(format!("{s}.corrupt"));
        s
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn keyed_open_of_a_plaintext_db_migrates_in_place_and_stays_persistent() {
        use hop_store_sqlite::SqliteStore;
        let path = recovery_tmp("migrate");
        // Start with a PLAINTEXT db (empty key).
        drop(SqliteStore::open_keyed(&path, &[]).expect("create plaintext db"));
        assert!(
            SqliteStore::opens_as_plaintext(&path),
            "db starts as plaintext"
        );
        // Open persistently WITH a key: the migration arm must fire - persistent stays true, the file is
        // encrypted in place, nothing is quarantined, and the key reopens it.
        let key = [7u8; 32];
        let (_s, persistent) = open_store_persistent(&path, &key);
        assert!(
            persistent,
            "migration arm: is_persistent stays true (no false ephemeral)"
        );
        assert!(
            !SqliteStore::opens_as_plaintext(&path),
            "the db is now SQLCipher-encrypted"
        );
        assert!(
            !std::path::Path::new(&format!("{path}.corrupt")).exists(),
            "migration must NOT quarantine"
        );
        assert!(
            SqliteStore::open_keyed(&path, &key).is_ok(),
            "reopens with the migration key"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn wrong_key_on_a_keyed_db_fails_closed_and_preserves_the_file() {
        use hop_store_sqlite::SqliteStore;
        let path = recovery_tmp("failclosed");
        let key_a = [1u8; 32];
        drop(SqliteStore::open_keyed(&path, &key_a).expect("create keyed db"));
        // Open with the WRONG key: the fail-closed arm must fire - ephemeral (is_persistent=false), the
        // encrypted file PRESERVED (not wiped, not quarantined), so the right key recovers it later.
        let key_b = [2u8; 32];
        let (_s, persistent) = open_store_persistent(&path, &key_b);
        assert!(
            !persistent,
            "wrong key runs ephemeral (is_persistent=false), never churns state"
        );
        assert!(
            std::path::Path::new(&path).exists(),
            "the encrypted file is preserved"
        );
        assert!(
            !std::path::Path::new(&format!("{path}.corrupt")).exists(),
            "a wrong key must NOT quarantine (a transient wrong key must be recoverable)"
        );
        assert!(
            SqliteStore::open_keyed(&path, &key_a).is_ok(),
            "the correct key still recovers the db after a wrong-key session"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_corrupt_plain_db_is_quarantined_and_a_fresh_store_starts() {
        use hop_store_sqlite::SqliteStore;
        let path = recovery_tmp("quarantine");
        let quar = format!("{path}.corrupt");
        // A genuinely unusable PLAIN db (garbage bytes, no key ambiguity).
        std::fs::write(&path, b"this is not a sqlite database at all, just garbage").unwrap();
        // Empty-key path: the quarantine arm must fire - move the bad file aside and start FRESH
        // persistent (is_persistent=true), leaving a .corrupt copy for forensics.
        let (_s, persistent) = open_store_persistent(&path, &[]);
        assert!(
            persistent,
            "quarantine-then-fresh keeps persistence (is_persistent=true)"
        );
        assert!(
            std::path::Path::new(&quar).exists(),
            "the corrupt db was quarantined to .corrupt"
        );
        assert!(
            SqliteStore::opens_as_plaintext(&path),
            "a fresh usable plain db now lives at the path"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&quar);
    }

    #[test]
    fn two_nodes_handshake_and_message_over_ffi() {
        let a = HopNode::new();
        let b = HopNode::new();

        // Publish prekeys (as a real device does at startup) so a forward-secret session can
        // form — content is never static-sealed; it defers until a prekey is known (DESIGN.md §25).
        a.publish_prekey().unwrap();
        b.publish_prekey().unwrap();

        a.connected(1, true);
        b.connected(1, false);
        pump(&a, &b);

        a.send_message(
            b.address(),
            "text/plain".into(),
            b"hi over ffi".to_vec(),
            false,
        )
        .unwrap();
        pump(&a, &b);
        pump(&a, &b);

        let inbox = b.take_inbox();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].body, b"hi over ffi");
        assert_eq!(inbox[0].from, a.address());
    }

    #[test]
    fn rejects_bad_key_length() {
        let a = HopNode::new();
        let err = a.send_message(vec![0u8; 10], "t".into(), vec![], false);
        assert!(matches!(err, Err(FfiError::BadKey)));
    }

    // cov/cabi: the FFI surface below is the UniFFI-exported `HopNode` method body + the free
    // helpers. cabi.rs proves the C-ABI shims; these prove the Rust methods those shims (and the
    // Swift/Kotlin bindings) call - every error/return branch, each type mapper, and the drains
    // that only populate their record mappers when a real message crosses. Untested here before,
    // so a regression in a mapper (wrong field, dropped variant) surfaced only on-device.

    /// Handshake two nodes over one symmetric link (id 1) WITHOUT gossiping prekeys. Enough for
    /// hps/http/service sends (they seal to a static address); only §39 `send_message` needs a
    /// ratchet. Mirrors hop-core's `Wire2::connect` (handshake only).
    fn link(a: &HopNode, b: &HopNode) {
        a.tick(1_000);
        b.tick(1_000);
        a.connected(1, true);
        b.connected(1, false);
        pump(a, b);
    }

    #[test]
    fn free_functions_and_type_mappers_round_trip() {
        // base58 address: encode -> decode round trip; invalid input decodes to empty.
        let addr = HopNode::new().address();
        let b58 = address_base58(addr.clone());
        assert!(!b58.is_empty());
        assert_eq!(address_from_base58(b58), addr);
        assert!(address_from_base58("!!!not base58!!!".into()).is_empty());

        // short_address: 32-byte -> 8-byte short form; a wrong-length address -> empty.
        assert_eq!(short_address(addr).len(), 8);
        assert!(short_address(vec![0u8; 10]).is_empty());

        // service_identify is the built-in identity service name.
        assert_eq!(service_identify(), "hop.identify");

        // hex8 renders 8 bytes as 16 lowercase hex chars.
        assert_eq!(hex8(&[0x0a, 0xff, 0, 1, 2, 3, 4, 5]), "0aff000102030405");

        // label_app: relay app -> "Hop Relay", fabric app -> "device", anything else -> hex.
        assert_eq!(label_app(&short_app(&relay_app_id())), "Hop Relay");
        assert_eq!(label_app(&short_app(&FABRIC_APP)), "device");
        let other = label_app(&short_app(&app_id("com.example.other")));
        assert_eq!(other.len(), 16, "an unknown app renders as 8-byte hex");
        assert_ne!(other, "Hop Relay");
        assert_ne!(other, "device");

        // identity_from: a valid 32-byte secret is deterministic; a wrong-length one falls back to
        // a fresh identity (both arms exercised).
        let s = [9u8; 32];
        assert_eq!(identity_from(&s).address(), identity_from(&s).address());
        let _ = identity_from(&[1, 2, 3]);

        // hps enum <-> core mappers, both directions, every variant.
        use hop_core::hps::{AccessMode, ServiceKind, Visibility};
        assert!(matches!(
            kind_to_core(&HpsKind::Channel),
            ServiceKind::Channel
        ));
        assert!(matches!(
            kind_to_core(&HpsKind::Service),
            ServiceKind::Service
        ));
        assert!(matches!(
            kind_from_core(ServiceKind::Channel),
            HpsKind::Channel
        ));
        assert!(matches!(
            kind_from_core(ServiceKind::Service),
            HpsKind::Service
        ));
        assert!(matches!(access_to_core(&HpsAccess::Open), AccessMode::Open));
        assert!(matches!(
            access_to_core(&HpsAccess::RequestToJoin),
            AccessMode::RequestToJoin
        ));
        assert!(matches!(
            access_to_core(&HpsAccess::Invite),
            AccessMode::Invite
        ));
        assert!(matches!(
            access_from_core(AccessMode::Open),
            HpsAccess::Open
        ));
        assert!(matches!(
            access_from_core(AccessMode::RequestToJoin),
            HpsAccess::RequestToJoin
        ));
        assert!(matches!(
            access_from_core(AccessMode::Invite),
            HpsAccess::Invite
        ));
        assert!(matches!(
            vis_to_core(&HpsVisibility::Private),
            Visibility::Private
        ));
        assert!(matches!(
            vis_to_core(&HpsVisibility::Discoverable),
            Visibility::Discoverable
        ));

        // decode_identity rejects bytes that aren't a valid identity record.
        assert!(decode_identity(vec![0xff, 0xff, 0xff]).is_none());
    }

    #[test]
    fn node_scalar_getters_error_paths_and_local_mutators() {
        // One app-scoped node drives the whole scalar/host-side surface. `peer` is a real 32-byte
        // address for the "good key" arms so seals to it never fail on an invalid curve point.
        let node = HopNode::open(":memory:".into(), Vec::new(), vec![7u8; 32]);
        let peer = HopNode::new().address();

        // send_message_traced: wrong-length dst -> BadKey; good dst -> Ok(id) (defers, no prekey).
        assert!(matches!(
            node.send_message_traced(vec![0u8; 10], "t".into(), vec![], false),
            Err(FfiError::BadKey)
        ));
        let tid = node
            .send_message_traced(peer.clone(), "text/plain".into(), b"hi".to_vec(), false)
            .unwrap();
        assert_eq!(tid.len(), 32);

        // publish_service + browse: our own advert is browsable; the tag-filter branch runs too.
        node.publish_service(
            "presence".into(),
            "Alice".into(),
            "here".into(),
            vec!["tag1".into()],
            60_000,
        )
        .unwrap();
        let hits = node.browse("presence".into(), String::new());
        assert!(
            hits.iter()
                .any(|h| h.service == "presence" && h.title == "Alice"),
            "own service advert is browsable"
        );
        let _ = node.browse("presence".into(), "tag1".into());

        // message_status: a wrong-length id -> blank; the just-sent traced id -> tracked/undelivered.
        let blank = node.message_status(vec![1u8; 10]);
        assert!(!blank.delivered && blank.relayed == 0);
        assert!(!node.message_status(tid).delivered);

        // is_secured / knows_route: wrong-length -> false; an unknown-but-valid key -> false.
        assert!(!node.is_secured(vec![0u8; 10]));
        assert!(!node.is_secured(peer.clone()));
        assert!(!node.knows_route(vec![0u8; 10]));
        assert!(!node.knows_route(peer.clone()));

        // peers / peer_links empty on an unconnected node; pending_count runs.
        assert!(node.peers().is_empty());
        assert!(node.peer_links().is_empty());
        let _ = node.pending_count();

        // send_hops_request: wrong-length endpoint -> BadKey; good -> Ok(id).
        assert!(matches!(
            node.send_hops_request(
                vec![0u8; 10],
                "h".into(),
                "GET".into(),
                "/".into(),
                vec![],
                1000
            ),
            Err(FfiError::BadKey)
        ));
        node.send_hops_request(
            peer.clone(),
            "example.com".into(),
            "GET".into(),
            "/x".into(),
            vec![],
            64_000,
        )
        .unwrap();

        // queue / clear_queue: the hops request above is an own (pinned) Device-addressed bundle in
        // the store, so it surfaces in the queue with a non-empty destination (queue record mapper).
        let q = node.queue();
        assert!(
            q.iter().any(|i| i.own && !i.to.is_empty()),
            "our own queued bundle is pinned"
        );
        node.clear_queue();
        assert!(
            node.queue().is_empty(),
            "clear_queue drops our undelivered bundles"
        );

        // register_service: a Channel has no service pubkey; a Service exposes one. Covers the
        // kind/access/visibility -> core mappers across variants (incl. the Discoverable advert).
        assert!(
            node.register_service(
                "room".into(),
                HpsKind::Channel,
                HpsAccess::Open,
                HpsVisibility::Private,
            )
            .is_empty(),
            "a channel has no service pubkey"
        );
        assert!(
            !node
                .register_service(
                    "feed".into(),
                    HpsKind::Service,
                    HpsAccess::RequestToJoin,
                    HpsVisibility::Discoverable,
                )
                .is_empty(),
            "a service exposes its pubkey"
        );

        // hps_my_topics reflects both hosted topics (record mapper).
        let mine = node.hps_my_topics();
        assert!(mine.iter().any(|t| t.path == "room" && t.hosting));
        assert!(mine.iter().any(|t| t.path == "feed"));

        // invite (we host "room"): wrong-length dest -> BadKey; good -> Ok(id).
        assert!(matches!(
            node.hps_invite("room".into(), vec![0u8; 10]),
            Err(FfiError::BadKey)
        ));
        node.hps_invite("room".into(), peer.clone()).unwrap();

        // accept/decline: wrong-length host -> BadKey; a good host sends regardless of a match.
        assert!(matches!(
            node.hps_accept_invite(vec![0u8; 10], "room".into()),
            Err(FfiError::BadKey)
        ));
        node.hps_accept_invite(peer.clone(), "room".into()).unwrap();
        assert!(matches!(
            node.hps_decline_invite(vec![0u8; 10], "room".into()),
            Err(FfiError::BadKey)
        ));
        node.hps_decline_invite(peer.clone(), "room".into())
            .unwrap();

        // subscribe: wrong-length host -> BadKey; good -> Ok(id).
        assert!(matches!(
            node.hps_subscribe(vec![0u8; 10], "room".into()),
            Err(FfiError::BadKey)
        ));
        node.hps_subscribe(peer.clone(), "room".into()).unwrap();

        // pending/approve/deny (host side): approve/deny reject a wrong-length requester.
        assert!(node.hps_pending("feed".into()).is_empty());
        assert!(matches!(
            node.hps_approve("feed".into(), vec![0u8; 10]),
            Err(FfiError::BadKey)
        ));
        assert!(matches!(
            node.hps_deny("feed".into(), vec![0u8; 10]),
            Err(FfiError::BadKey)
        ));
        node.hps_deny("feed".into(), peer.clone()).unwrap();

        // reach / members are zero/empty on a just-registered topic.
        assert_eq!(node.hps_reach("room".into()), 0);
        assert!(node.hps_members("room".into()).is_empty());

        // rekey: a wrong-length member entry -> BadKey; then both new_path branches (keep / move).
        assert!(matches!(
            node.hps_rekey("room".into(), String::new(), vec![vec![0u8; 10]]),
            Err(FfiError::BadKey)
        ));
        node.hps_rekey("room".into(), String::new(), vec![])
            .unwrap(); // keep-path branch
        node.hps_rekey("room".into(), "room2".into(), vec![])
            .unwrap(); // move-path branch

        // publish: to a hosted topic -> Ok; to an unknown path -> Err.
        node.hps_publish("feed".into(), b"news".to_vec()).unwrap();
        assert!(node
            .hps_publish("nonexistent".into(), b"x".to_vec())
            .is_err());

        // leave a path we host (not a subscription) -> Ok(empty bundle id).
        assert!(node.hps_leave("feed".into()).unwrap().is_empty());

        // empty drains still exercise their bodies; browse_discoverable runs.
        assert!(node.take_hps_invites().is_empty());
        assert!(node.take_hps_messages().is_empty());
        let _ = node.browse_discoverable();

        // http response: wrong-length `to` or `for_request_id` -> BadKey; good -> Ok(()).
        assert!(matches!(
            node.send_http_response(vec![0u8; 10], vec![1u8; 32], 200, vec![]),
            Err(FfiError::BadKey)
        ));
        assert!(matches!(
            node.send_http_response(peer.clone(), vec![1u8; 10], 200, vec![]),
            Err(FfiError::BadKey)
        ));
        node.send_http_response(peer, vec![1u8; 32], 200, b"ok".to_vec())
            .unwrap();
        assert!(node.take_http_requests().is_empty());
        assert!(node.take_http_responses().is_empty());

        // name: unset -> ""; set -> reflected; cleared -> "".
        assert_eq!(node.name(), "");
        node.set_name("alice".into());
        assert_eq!(node.name(), "alice");
        node.set_name(String::new());
        assert_eq!(node.name(), "");
    }

    #[test]
    fn hns_resolution_flow_populates_cache_and_results() {
        let node = HopNode::open(":memory:".into(), Vec::new(), Vec::new());

        // Offline: reach records are fetched over the domain's own TLS well-known, which only this
        // device can do, so with no internet resolution can't start yet -> NeedsResolver.
        assert!(matches!(
            node.resolve_hns("example.com".into()),
            HnsLookupResult::NeedsResolver
        ));

        // With internet on, the node resolves itself: the domain surfaces as a DNS lookup.
        node.set_internet(true);
        assert!(node.is_internet());
        assert!(matches!(
            node.resolve_hns("example.com".into()),
            HnsLookupResult::Pending
        ));
        assert!(
            node.take_dns_lookups()
                .iter()
                .any(|d| d.contains("example.com")),
            "an internet-connected node queues the DNS lookup itself"
        );

        // Feed back unverifiable reach-record bytes -> a cached negative + a finished (empty) result.
        node.provide_reach_record("example.com".into(), vec![0u8; 8]);
        let results = node.take_hns_results();
        assert_eq!(results.len(), 1, "one finished resolution");
        assert!(results[0].address.is_empty(), "a negative resolution");
        assert!(
            node.hns_cache()
                .iter()
                .any(|e| e.domain.contains("example.com") && e.address.is_empty()),
            "the negative is cached and surfaced with an empty address"
        );

        // Now cached: resolve serves the cached negative straight back.
        assert!(matches!(
            node.resolve_hns("example.com".into()),
            HnsLookupResult::Cached { address } if address.is_empty()
        ));
    }

    #[test]
    fn hps_invite_channel_delivers_and_populates_host_and_member_views() {
        // Two nodes on the SAME app secret so hps join proofs verify across the link.
        let a = HopNode::open(":memory:".into(), Vec::new(), vec![6u8; 32]); // host
        let b = HopNode::open(":memory:".into(), Vec::new(), vec![6u8; 32]); // member
        link(&a, &b);
        let b_addr = b.address();

        // Host a Discoverable Invite channel; discoverable so browse_discoverable has something.
        a.register_service(
            "vip".into(),
            HpsKind::Channel,
            HpsAccess::Invite,
            HpsVisibility::Discoverable,
        );
        pump(&a, &b);
        pump(&a, &b);
        assert!(
            b.browse_discoverable().iter().any(|t| t.path == "vip"),
            "the member sees the discoverable topic (browse_discoverable mapper)"
        );

        // Host invites the member; the member drains the invite (invite record mapper).
        a.hps_invite("vip".into(), b_addr.clone()).unwrap();
        pump(&a, &b);
        let invites = b.take_hps_invites();
        assert_eq!(invites.len(), 1);
        assert_eq!(invites[0].path, "vip");

        // Member accepts; the host seals keys and records the member.
        b.hps_accept_invite(a.address(), "vip".into()).unwrap();
        pump(&a, &b);
        assert!(
            a.hps_members("vip".into()).contains(&b_addr),
            "the accepted member is recorded on the host (members mapper)"
        );

        // Host publishes; the member receives it (take_hps_messages record mapper).
        a.hps_publish("vip".into(), b"hello vip".to_vec()).unwrap();
        pump(&a, &b);
        let msgs = b.take_hps_messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, b"hello vip");

        // The member's own topic list now includes the followed topic (member-side mapper).
        assert!(b.hps_my_topics().iter().any(|t| t.path == "vip"));
        let _ = a.hps_reach("vip".into());
    }

    #[test]
    fn hps_request_to_join_approval_keys_the_member() {
        // The host-approves path (hps_approve's Ok arm + hps_pending's non-empty mapper): a
        // RequestToJoin topic queues a subscribe request; the member can't read until approved.
        let a = HopNode::open(":memory:".into(), Vec::new(), vec![8u8; 32]); // host
        let b = HopNode::open(":memory:".into(), Vec::new(), vec![8u8; 32]); // requester
        link(&a, &b);
        let b_addr = b.address();

        a.register_service(
            "lobby".into(),
            HpsKind::Channel,
            HpsAccess::RequestToJoin,
            HpsVisibility::Private,
        );
        b.hps_subscribe(a.address(), "lobby".into()).unwrap();
        pump(&a, &b);

        // Queued for approval, not auto-keyed.
        assert!(
            a.hps_pending("lobby".into()).contains(&b_addr),
            "the requester is queued pending host approval"
        );

        // Approve; the host seals the keys, then a publish reaches the now-member.
        a.hps_approve("lobby".into(), b_addr).unwrap();
        pump(&a, &b);
        a.hps_publish("lobby".into(), b"welcome".to_vec()).unwrap();
        pump(&a, &b);
        let msgs = b.take_hps_messages();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, b"welcome");
    }

    #[test]
    fn hops_http_request_and_response_drains_populate() {
        let a = HopNode::new();
        let b = HopNode::new();
        link(&a, &b);

        let req_id = a
            .send_hops_request(
                b.address(),
                "example.hopme.sh".into(),
                "GET".into(),
                "/hello".into(),
                vec![],
                64_000,
            )
            .unwrap();
        pump(&a, &b);

        // Endpoint side: the request surfaces for the operator (take_http_requests mapper).
        let reqs = b.take_http_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].host, "example.hopme.sh");
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].url, "/hello");
        let (from, rid) = (reqs[0].from.clone(), reqs[0].request_id.clone());

        b.send_http_response(from, rid, 200, b"world".to_vec())
            .unwrap();
        pump(&a, &b);

        // Client side: the response arrives, correlated by id (take_http_responses mapper).
        let resps = a.take_http_responses();
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0].for_request_id, req_id);
        assert_eq!(resps[0].status, 200);
        assert_eq!(resps[0].body, b"world");
    }

    #[test]
    fn identify_service_round_trips_and_decodes_to_identity_info() {
        let a = HopNode::new();
        let b = HopNode::new();
        link(&a, &b);
        // The handshake alone authenticates the peer, so peer views are populated here.
        assert!(!a.peers().is_empty(), "handshake made B a known peer");
        assert_eq!(
            a.peer_links().len(),
            a.peers().len(),
            "one live link per authenticated peer (peer_links mapper)"
        );

        b.set_name("Bob's Phone".into());
        a.send_service_request(b.address(), service_identify(), String::new(), vec![])
            .unwrap();
        pump(&a, &b);

        // The built-in service is auto-answered; nothing surfaces to B's app.
        assert!(b.take_service_requests().is_empty());
        let resps = a.take_service_responses();
        assert_eq!(resps.len(), 1);
        let info = decode_identity(resps[0].body.clone()).expect("a valid identity record decodes");
        assert_eq!(info.name, "Bob's Phone");
        assert_eq!(info.kind, "device");
        assert_eq!(info.address, b.address());
    }

    #[test]
    fn abi_cluster_dedup_propagates_between_replicas() {
        // Two HopNodes with the SAME identity (endpoint replicas) cluster over the ABI: A marking a
        // request handled propagates to B via the cluster topic, so B would drop that same request.
        // Proves HopNode delegates to the Endpoint layer end to end (join + gossip + gate).
        let secret = vec![5u8; 32];
        let a = HopNode::with_secret(secret.clone());
        let b = HopNode::with_secret(secret);
        assert_eq!(a.address(), b.address(), "replicas share the identity");
        let cs = [7u8; 32];
        a.cluster_join(cs);
        b.cluster_join(cs);
        link(&a, &b); // establish the A <-> B link (link id 1) the gossip rides

        let from = [1u8; 32];
        let id = [2u8; 32];
        assert!(!b.cluster_would_drop(from, id), "B has not learned it yet");

        a.cluster_mark_done(from, id);
        a.tick(2_000);
        pump(&a, &b);
        b.tick(2_000); // B drains + applies the inbound gossip

        assert!(
            b.cluster_would_drop(from, id),
            "B learned A's HANDLED via the ABI cluster path"
        );
        assert!(b.cluster_members() >= 2, "the replicas see each other");
        assert!(
            !b.cluster_would_drop(from, [9u8; 32]),
            "unrelated request not dropped"
        );
    }
}
