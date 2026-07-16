//! libhop — the stable C ABI for hop-core: the universal client SDK.
//!
//! This is the ONE contract every non-Rust client binds: mobile bearer libs (Swift/Kotlin via the
//! generated `hop.h`), C/C++ tools, and embedded FULL clients — e.g. an ESP32 that opens a node,
//! secures sessions, and pushes sensor data to a `hops://` service. cbindgen generates
//! `include/hop.h` from this module (see `cbindgen.toml`).
//!
//! It is the poll-model byte seam — link up / bytes in / link down / drain out, keyed by `LinkId`
//! (u64) + `HopLinkRole` — PLUS the full client surface (open, identity, subscribe, send). Nothing
//! transport-specific crosses it: no BLE, no beacon, no service id — pure bytes + ids. The optional
//! UniFFI layer (the rest of this crate) wraps the SAME `HopNode`, so mobile gets ergonomic bindings
//! while every other target binds this C ABI.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_void, CStr};
use std::os::raw::c_char;
use std::sync::Arc;

use crate::HopNode;

/// Which side opened a bearer link (the Noise role). Mirrors hop-core's internal `Role`.
#[repr(C)]
pub enum HopLinkRole {
    /// We dialed out (BLE central / TCP connect / Wi-Fi inviter) → Noise initiator.
    Dialer = 0,
    /// A peer connected in (peripheral / listener / invitee) → Noise responder.
    Acceptor = 1,
}

// ---- internal helpers (not exported) ----------------------------------------------------------

unsafe fn node_ref<'a>(node: *const HopNode) -> Option<&'a HopNode> {
    if node.is_null() {
        None
    } else {
        Some(&*node)
    }
}
unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

/// Build a NUL-terminated C string for a sink callback, STRIPPING any interior NUL bytes rather than
/// collapsing the whole value to empty (audit LOW: the sinks used `CString::new(s).unwrap_or_default()`,
/// which on an interior NUL silently dropped the entire content-type / service / method / endpoint to
/// `""`). None of those fields legitimately contains a NUL, so filtering is lossless for valid input and
/// preserves as much as possible for a hostile one, instead of a silent total loss.
fn c_string_lossy(s: String) -> std::ffi::CString {
    match std::ffi::CString::new(s) {
        Ok(c) => c,
        Err(e) => {
            let filtered: Vec<u8> = e.into_vec().into_iter().filter(|&b| b != 0).collect();
            std::ffi::CString::new(filtered).unwrap_or_default()
        }
    }
}
unsafe fn slice<'a>(p: *const u8, len: usize) -> &'a [u8] {
    if p.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p, len)
    }
}

// ---- lifecycle --------------------------------------------------------------------------------

/// The libhop C-ABI version. Bump on any signature or semantic change to an exported `hop_*`
/// function. A wrapper should assert `hop_abi_version() == HOP_ABI_VERSION` at load so a wrapper
/// built against a newer header fails loudly instead of drifting silently (F-28). This is the
/// *ABI* version and is independent of the *wire* format version (bundle.rs `BUNDLE_VERSION`).
pub const HOP_ABI_VERSION: u32 = 3;

/// Returns the ABI version this shared library implements (see [`HOP_ABI_VERSION`]).
#[no_mangle]
pub extern "C" fn hop_abi_version() -> u32 {
    HOP_ABI_VERSION
}

/// Run a constructor closure, converting a panic into a NULL return so it never unwinds across
/// the `extern "C"` boundary (which is undefined behavior). See F-26.
fn catch_ctor(f: impl FnOnce() -> *const HopNode) -> *const HopNode {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(std::ptr::null())
}

/// Run a closure, swallowing any panic so it can never unwind across the `extern "C"` boundary
/// (which is UB and aborts the whole host process) (core-ffi-01). A panic in hop-core reached via
/// hostile/malformed network bytes (`hop_bytes_received`) must degrade to a dropped operation, not
/// take down every C-ABI consumer (ESP32, C tools, JNA/Swift wrappers). The node's lock is
/// poison-tolerant, so a panic mid-call does not brick the node either. Returns `r` on panic.
fn catch<R>(default: R, f: impl FnOnce() -> R) -> R {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(default)
}

/// Open a node with persistent storage at `db_path` (UTF-8 C string), a saved 32-byte identity
/// `secret` (pass NULL/0 for a fresh identity), and a 32-byte `app_secret` (NULL/0 = open fabric).
/// Returns an owning handle to free with `hop_node_free`, or NULL on a NULL/non-UTF-8 `db_path`.
///
/// If the db path exists but can't be opened it is quarantined and reopened fresh; only if that
/// also fails does the node run with EPHEMERAL storage (call `hop_node_is_persistent` to detect
/// this) rather than silently, and rather than NULL (F-26).
#[no_mangle]
pub unsafe extern "C" fn hop_node_open(
    db_path: *const c_char,
    secret: *const u8,
    secret_len: usize,
    app_secret: *const u8,
    app_secret_len: usize,
) -> *const HopNode {
    let Some(path) = cstr(db_path) else {
        return std::ptr::null();
    };
    let path = path.to_string();
    let secret = slice(secret, secret_len).to_vec();
    let app = slice(app_secret, app_secret_len).to_vec();
    catch_ctor(|| Arc::into_raw(HopNode::open(path, secret, app)))
}

/// Like `hop_node_open`, but ENCRYPTS the store at rest with a raw `key` (typically 32 bytes) the host
/// derives and stores in the platform Keychain/Keystore (F-25). Real encryption requires libhop to be
/// built with the store's `sqlcipher` feature; otherwise the key is accepted but the db stays plain.
/// A NULL/empty key behaves like `hop_node_open`. NULL/non-UTF-8 `db_path` ⇒ NULL.
#[no_mangle]
pub unsafe extern "C" fn hop_node_open_keyed(
    db_path: *const c_char,
    secret: *const u8,
    secret_len: usize,
    app_secret: *const u8,
    app_secret_len: usize,
    key: *const u8,
    key_len: usize,
) -> *const HopNode {
    let Some(path) = cstr(db_path) else {
        return std::ptr::null();
    };
    let path = path.to_string();
    let secret = slice(secret, secret_len).to_vec();
    let app = slice(app_secret, app_secret_len).to_vec();
    let key = slice(key, key_len).to_vec();
    catch_ctor(|| Arc::into_raw(HopNode::open_keyed(path, secret, app, key)))
}

/// Create a node with a fresh identity and ephemeral (in-memory) storage. Free with `hop_node_free`.
#[no_mangle]
pub unsafe extern "C" fn hop_node_new() -> *const HopNode {
    catch_ctor(|| Arc::into_raw(HopNode::new()))
}

/// Open a node from a saved 32-byte identity `secret` with ephemeral (in-memory) storage. Pass
/// NULL/0 for a fresh identity. Free with `hop_node_free`.
#[no_mangle]
pub unsafe extern "C" fn hop_node_with_secret(
    secret: *const u8,
    secret_len: usize,
) -> *const HopNode {
    let secret = slice(secret, secret_len).to_vec();
    catch_ctor(|| Arc::into_raw(HopNode::with_secret(secret)))
}

/// Whether this node has durable storage. Returns false when the db path was unusable and the
/// node is running ephemerally (state will not survive a restart) — the host should surface this
/// rather than treat the database as ground truth (F-26). NULL handle ⇒ false.
#[no_mangle]
pub unsafe extern "C" fn hop_node_is_persistent(node: *const HopNode) -> bool {
    node_ref(node).map(|n| n.is_persistent()).unwrap_or(false)
}

/// How many persisted records failed to decode on startup (F-03). Non-zero ⇒ an upgrade changed
/// a struct's on-disk layout and dropped that state; surface it to the user. NULL handle ⇒ 0.
#[no_mangle]
pub unsafe extern "C" fn hop_node_rehydrate_dropped(node: *const HopNode) -> u32 {
    node_ref(node).map(|n| n.rehydrate_dropped()).unwrap_or(0)
}

/// Free a node handle returned by any constructor. Safe to pass NULL.
///
/// Ownership: this consumes the one strong reference each constructor returned. The caller must
/// ensure no other thread is calling into the same handle concurrently with free (the ABI does
/// not expose a retain/clone), and must not use the pointer afterward.
#[no_mangle]
pub unsafe extern "C" fn hop_node_free(node: *const HopNode) {
    if !node.is_null() {
        drop(Arc::from_raw(node));
    }
}

// ---- identity ---------------------------------------------------------------------------------

/// Write this node's 32-byte address into `out` (must have room for 32 bytes). False on NULL.
#[no_mangle]
pub unsafe extern "C" fn hop_node_address(node: *const HopNode, out: *mut u8) -> bool {
    catch(false, || {
        let (Some(node), false) = (node_ref(node), out.is_null()) else {
            return false;
        };
        let addr = node.address();
        std::ptr::copy_nonoverlapping(addr.as_ptr(), out, addr.len().min(32));
        true
    })
}

/// Write this node's 32-byte identity secret into `out` (room for 32 bytes) so the host can persist
/// it (e.g. in the Keychain) and restore the node later with `hop_node_with_secret`/`hop_node_open`.
/// Returns the number of bytes written (32), or 0 on NULL.
#[no_mangle]
pub unsafe extern "C" fn hop_node_secret(node: *const HopNode, out: *mut u8) -> usize {
    catch(0, || {
        let (Some(node), false) = (node_ref(node), out.is_null()) else {
            return 0;
        };
        let s = node.secret();
        let n = s.len().min(32);
        std::ptr::copy_nonoverlapping(s.as_ptr(), out, n);
        n
    })
}

/// Set the display name this node reports via presence / `hop.identify` (DESIGN.md §29).
#[no_mangle]
pub unsafe extern "C" fn hop_node_set_name(node: *const HopNode, name: *const c_char) {
    catch((), || {
        if let (Some(node), Some(name)) = (node_ref(node), cstr(name)) {
            node.set_name(name.to_string());
        }
    })
}

// ---- clock ------------------------------------------------------------------------------------

/// Advance time: expire adverts, retransmit unacked bundles, prune dedup. Call ~1 Hz.
#[no_mangle]
pub unsafe extern "C" fn hop_node_tick(node: *const HopNode, now_ms: u64) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            node.tick(now_ms);
        }
    })
}

// ---- bearer seam: inbound (bearer -> core) ----------------------------------------------------

/// A bearer link came up. `role` = which side dialed (the Noise initiator/responder selector),
/// using the [`HopLinkRole`] discriminants (0 = Dialer, 1 = Acceptor).
///
/// core-ffi-05: `role` is taken as a plain `u32`, not the `HopLinkRole` enum by value. A C caller
/// passing an out-of-range int would otherwise materialize an invalid Rust enum (instant UB) before
/// any validation runs. Here only `0` selects Dialer; any other value is treated as Acceptor, so a
/// bad int can never be UB.
#[no_mangle]
pub unsafe extern "C" fn hop_link_up(node: *const HopNode, link: u64, role: u32) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            let is_dialer = role == HopLinkRole::Dialer as u32;
            node.connected(link, is_dialer);
        }
    })
}

/// One frame of opaque bytes arrived on `link`.
#[no_mangle]
pub unsafe extern "C" fn hop_bytes_received(
    node: *const HopNode,
    link: u64,
    data: *const u8,
    len: usize,
) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            node.received(link, slice(data, len).to_vec());
        }
    })
}

/// A bearer link dropped.
#[no_mangle]
pub unsafe extern "C" fn hop_link_down(node: *const HopNode, link: u64) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            node.disconnected(link);
        }
    })
}

// ---- bearer seam: outbound (core -> bearer, POLLED) -------------------------------------------

/// Drain queued outbound packets. Synchronously invokes `sink(ctx, link, bytes_ptr, bytes_len)`
/// once per packet during this call — this is the POLL model; core never pushes asynchronously.
/// The byte pointer is valid only for the duration of each `sink` call; copy what you keep.
#[no_mangle]
pub unsafe extern "C" fn hop_drain_outgoing(
    node: *const HopNode,
    sink: Option<extern "C" fn(ctx: *mut c_void, link: u64, bytes: *const u8, len: usize)>,
    ctx: *mut c_void,
) {
    let (Some(node), Some(sink)) = (node_ref(node), sink) else {
        return;
    };
    // core-ffi-01: the node-side drain may panic; contain it so it can't unwind across the ABI. The
    // sink is a foreign fn: if IT panics that's the host's contract to uphold, outside our reach.
    let packets = catch(Vec::new(), || node.drain_outgoing());
    for pkt in packets {
        sink(ctx, pkt.link, pkt.bytes.as_ptr(), pkt.bytes.len());
    }
}

// ---- client API (full client, e.g. ESP32) -----------------------------------------------------

/// Subscribe the directory to a service `topic` (UTF-8 C string).
#[no_mangle]
pub unsafe extern "C" fn hop_subscribe(node: *const HopNode, topic: *const c_char) {
    catch((), || {
        if let (Some(node), Some(topic)) = (node_ref(node), cstr(topic)) {
            node.subscribe(topic.to_string());
        }
    })
}

/// Publish this node's prekey advert (DESIGN.md §25) so peers can seal forward-secret messages to
/// us; it gossips on link-up. Call once after opening (and after the first `hop_node_tick` sets a
/// real clock, else the advert is judged expired). Returns true on success.
#[no_mangle]
pub unsafe extern "C" fn hop_publish_prekey(node: *const HopNode) -> bool {
    catch(
        false,
        || matches!(node_ref(node), Some(node) if node.publish_prekey().is_ok()),
    )
}

/// Drain newly-received messages (poll model). Invokes
/// `sink(ctx, from32, content_type_cstr, body_ptr, body_len, hops, created_at_ms)` once per message
/// during this call. `from` points at 32 address bytes; `content_type` is a NUL-terminated UTF-8
/// string; `body` is `body_len` bytes — all valid only for the duration of each `sink` call.
#[no_mangle]
pub unsafe extern "C" fn hop_poll_inbox(
    node: *const HopNode,
    sink: Option<
        extern "C" fn(
            ctx: *mut c_void,
            from: *const u8,
            content_type: *const c_char,
            body: *const u8,
            body_len: usize,
            hops: u8,
            created_at: u64,
        ),
    >,
    ctx: *mut c_void,
) {
    let (Some(node), Some(sink)) = (node_ref(node), sink) else {
        return;
    };
    let inbox = catch(Vec::new(), || node.take_inbox());
    for m in inbox {
        let ct = c_string_lossy(m.content_type);
        sink(
            ctx,
            m.from.as_ptr(),
            ct.as_ptr(),
            m.body.as_ptr(),
            m.body.len(),
            m.hops,
            m.created_at,
        );
    }
}

/// Send to a DIRECTLY-CONNECTED peer `dst` (32 bytes), sealed with the key learned at handshake
/// (the directed §27 path; prefer `hop_send_message` unless you specifically want a directed send).
/// On success writes the 32-byte bundle id to `out_id` (may be NULL) and returns true; false if not
/// connected to that peer or on error.
#[no_mangle]
pub unsafe extern "C" fn hop_send_to(
    node: *const HopNode,
    dst: *const u8,
    content_type: *const c_char,
    body: *const u8,
    body_len: usize,
    request_ack: bool,
    out_id: *mut u8,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        let Some(ct) = cstr(content_type) else {
            return false;
        };
        if dst.is_null() {
            return false;
        }
        match node.send_to(
            slice(dst, 32).to_vec(),
            ct.to_string(),
            slice(body, body_len).to_vec(),
            request_ack,
        ) {
            Ok(id) => {
                if !out_id.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_ptr(), out_id, id.len().min(32));
                }
                true
            }
            Err(_) => false,
        }
    })
}

/// Delivery status of a message we sent, by its 32-byte bundle `id`. Writes each field to its
/// (nullable) out-param: `relayed` = distinct peers handed a copy; `delivered` = destination
/// confirmed; `hops`/`ms` = the FORWARD-path (A→B) length + latency the destination reported (§39
/// private ACK), 0 until delivered. Returns false on NULL node/id.
#[no_mangle]
pub unsafe extern "C" fn hop_message_status(
    node: *const HopNode,
    id: *const u8,
    out_relayed: *mut u32,
    out_delivered: *mut bool,
    out_hops: *mut u8,
    out_ms: *mut u32,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        if id.is_null() {
            return false;
        }
        let st = node.message_status(slice(id, 32).to_vec());
        if !out_relayed.is_null() {
            *out_relayed = st.relayed;
        }
        if !out_delivered.is_null() {
            *out_delivered = st.delivered;
        }
        if !out_hops.is_null() {
            *out_hops = st.delivery_hops;
        }
        if !out_ms.is_null() {
            *out_ms = st.delivery_ms;
        }
        true
    })
}

/// True iff messaging `addr` (32 bytes) is forward-secret — a ratchet session exists (DESIGN.md §25)
/// rather than a static seal. Drives a lock indicator. False on NULL.
#[no_mangle]
pub unsafe extern "C" fn hop_is_secured(node: *const HopNode, addr: *const u8) -> bool {
    catch(
        false,
        || matches!((node_ref(node), addr.is_null()), (Some(node), false) if node.is_secured(slice(addr, 32).to_vec())),
    )
}

// ---- hops:// request/response (a FULL round trip — HDP in BOTH directions) --------------------
//
// Distinct from `hop_send_message` (a one-way HDP datagram whose only "response" is the network
// delivery-ACK): a hops:// service request expects a sealed RESPONSE back over the network. The
// caller fires a request and later drains the reply; the host drains requests and seals responses.
// This is what makes an ESP32 a full hops:// client (e.g. POST weather → get an ack/result body).

/// Send a hops:// service request to `dst` (32 bytes): invoke `method` on `service` with `args`.
/// The reply arrives later via `hop_poll_service_responses`. Writes the 32-byte request id to
/// `out_id` (may be NULL) and returns true.
#[no_mangle]
pub unsafe extern "C" fn hop_send_service_request(
    node: *const HopNode,
    dst: *const u8,
    service: *const c_char,
    method: *const c_char,
    args: *const u8,
    args_len: usize,
    out_id: *mut u8,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        let (Some(service), Some(method)) = (cstr(service), cstr(method)) else {
            return false;
        };
        if dst.is_null() {
            return false;
        }
        match node.send_service_request(
            slice(dst, 32).to_vec(),
            service.to_string(),
            method.to_string(),
            slice(args, args_len).to_vec(),
        ) {
            Ok(id) => {
                if !out_id.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_ptr(), out_id, id.len().min(32));
                }
                true
            }
            Err(_) => false,
        }
    })
}

/// Seal a hops:// response back to a request's caller (host side). `to` = the request's `from`;
/// `for_request_id` = its `request_id`. Returns true on success.
#[no_mangle]
pub unsafe extern "C" fn hop_send_service_response(
    node: *const HopNode,
    to: *const u8,
    for_request_id: *const u8,
    status: u16,
    body: *const u8,
    body_len: usize,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        if to.is_null() || for_request_id.is_null() {
            return false;
        }
        node.send_service_response(
            slice(to, 32).to_vec(),
            slice(for_request_id, 32).to_vec(),
            status,
            slice(body, body_len).to_vec(),
        )
        .is_ok()
    })
}

// ---- endpoint cluster coordination (DESIGN.md §40) --------------------------------------------
//
// Self-clustering endpoint replicas (same identity, no shared datastore) dedup addressed requests
// among themselves over an `hps://` cluster topic (implemented in the `hop-endpoint-core` crate).
// The gate is TRANSPARENT: after hop_cluster_join, a request a sibling already handled is dropped
// before hop_poll_service_requests surfaces it, so every SDK gets dedup by adding one join call.
// Additive to the ABI (no existing signature changed), so HOP_ABI_VERSION is unchanged.

/// Join the endpoint cluster keyed by the 32-byte `secret` (all replicas of one endpoint pass the
/// same secret). `hop_send_service_response` marks a request complete for the siblings automatically;
/// a fire-and-forget handler calls `hop_cluster_mark_done`. No-op if `secret` is null.
#[no_mangle]
pub unsafe extern "C" fn hop_cluster_join(node: *const HopNode, secret: *const u8) {
    catch((), || {
        if let (Some(node), false) = (node_ref(node), secret.is_null()) {
            let mut s = [0u8; 32];
            s.copy_from_slice(slice(secret, 32));
            node.cluster_join(s);
        }
    })
}

/// Join the endpoint cluster from a passphrase (the 32-byte secret is derived from it): every replica
/// given the same string joins the same cluster, across languages and the standalone service. This is
/// the ergonomic entry point; `hop_cluster_join` takes a raw 32-byte secret. No-op if `pass` is null.
#[no_mangle]
pub unsafe extern "C" fn hop_cluster_join_passphrase(
    node: *const HopNode,
    pass: *const u8,
    pass_len: usize,
) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            node.cluster_join_passphrase(slice(pass, pass_len));
        }
    })
}

/// Explicit completion for a fire-and-forget handler (one that sends no response): mark request
/// `(from32, request_id32)` handled and gossip it so sibling replicas drop their copies.
#[no_mangle]
pub unsafe extern "C" fn hop_cluster_mark_done(
    node: *const HopNode,
    from: *const u8,
    request_id: *const u8,
) {
    catch((), || {
        if let (Some(node), false, false) = (node_ref(node), from.is_null(), request_id.is_null()) {
            let mut f = [0u8; 32];
            let mut i = [0u8; 32];
            f.copy_from_slice(slice(from, 32));
            i.copy_from_slice(slice(request_id, 32));
            node.cluster_mark_done(f, i);
        }
    })
}

/// Whether request `(from32, request_id32)` would be dropped as already handled by a sibling replica
/// (introspection; the poll path applies this automatically). False if `node` is null or unclustered.
#[no_mangle]
pub unsafe extern "C" fn hop_cluster_would_drop(
    node: *const HopNode,
    from: *const u8,
    request_id: *const u8,
) -> bool {
    catch(false, || {
        let (Some(node), false, false) = (node_ref(node), from.is_null(), request_id.is_null())
        else {
            return false;
        };
        let mut f = [0u8; 32];
        let mut i = [0u8; 32];
        f.copy_from_slice(slice(from, 32));
        i.copy_from_slice(slice(request_id, 32));
        node.cluster_would_drop(f, i)
    })
}

/// Live replica count (self + peers within the membership TTL); 1 if not clustered, 0 if `node` null.
#[no_mangle]
pub unsafe extern "C" fn hop_cluster_members(node: *const HopNode) -> u32 {
    catch(0, || {
        node_ref(node).map(|n| n.cluster_members()).unwrap_or(0)
    })
}

/// Require at least `min_live_members` recently visible before processing. This TTL-based threshold
/// is a conservative failover heuristic, not consensus or an at-most-once guarantee. `0` disables it.
#[no_mangle]
pub unsafe extern "C" fn hop_cluster_set_quorum(node: *const HopNode, min_live_members: u32) {
    catch((), || {
        if let Some(node) = node_ref(node) {
            node.cluster_quorum(min_live_members);
        }
    })
}

/// Drain hops:// service requests addressed to this node (host side). Invokes
/// `sink(ctx, from32, request_id32, service_cstr, method_cstr, args_ptr, args_len)` per request.
#[no_mangle]
pub unsafe extern "C" fn hop_poll_service_requests(
    node: *const HopNode,
    sink: Option<
        extern "C" fn(
            ctx: *mut c_void,
            from: *const u8,
            request_id: *const u8,
            service: *const c_char,
            method: *const c_char,
            args: *const u8,
            args_len: usize,
        ),
    >,
    ctx: *mut c_void,
) {
    let (Some(node), Some(sink)) = (node_ref(node), sink) else {
        return;
    };
    // core-ffi-01: the node-side drain may panic; contain it so it can't unwind across the ABI (the
    // sink is a foreign fn: if IT panics that is the host's contract, outside our reach).
    let requests = catch(Vec::new(), || node.take_service_requests());
    for r in requests {
        let svc = c_string_lossy(r.service);
        let mth = c_string_lossy(r.method);
        sink(
            ctx,
            r.from.as_ptr(),
            r.request_id.as_ptr(),
            svc.as_ptr(),
            mth.as_ptr(),
            r.args.as_ptr(),
            r.args.len(),
        );
    }
}

/// Drain hops:// service responses sealed back to this node (caller side). Invokes
/// `sink(ctx, from32, for_request_id32, status, body_ptr, body_len)` per response.
#[no_mangle]
pub unsafe extern "C" fn hop_poll_service_responses(
    node: *const HopNode,
    sink: Option<
        extern "C" fn(
            ctx: *mut c_void,
            from: *const u8,
            for_request_id: *const u8,
            status: u16,
            body: *const u8,
            body_len: usize,
        ),
    >,
    ctx: *mut c_void,
) {
    let (Some(node), Some(sink)) = (node_ref(node), sink) else {
        return;
    };
    // core-ffi-01: contain a panic in the node-side drain (see hop_poll_service_requests).
    let responses = catch(Vec::new(), || node.take_service_responses());
    for r in responses {
        sink(
            ctx,
            r.from.as_ptr(),
            r.for_request_id.as_ptr(),
            r.status,
            r.body.as_ptr(),
            r.body.len(),
        );
    }
}

// ---- address encoding helpers (base58) --------------------------------------------------------

/// Encode a 32-byte `addr` as base58 into the C buffer `out` (`out_cap` bytes incl. NUL). Returns
/// the string length (excluding NUL), or 0 on NULL / insufficient capacity.
#[no_mangle]
pub unsafe extern "C" fn hop_address_to_base58(
    addr: *const u8,
    out: *mut c_char,
    out_cap: usize,
) -> usize {
    if addr.is_null() || out.is_null() || out_cap == 0 {
        return 0;
    }
    let s = bs58::encode(slice(addr, 32)).into_string();
    let b = s.as_bytes();
    if b.len() + 1 > out_cap {
        return 0;
    }
    std::ptr::copy_nonoverlapping(b.as_ptr(), out as *mut u8, b.len());
    *out.add(b.len()) = 0; // NUL-terminate
    b.len()
}

/// Decode a base58 address C string `text` into `out32` (32 bytes). Returns true iff it decoded to
/// exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn hop_address_from_base58(text: *const c_char, out32: *mut u8) -> bool {
    let Some(text) = cstr(text) else {
        return false;
    };
    if out32.is_null() {
        return false;
    }
    match bs58::decode(text).into_vec() {
        Ok(v) if v.len() == 32 => {
            std::ptr::copy_nonoverlapping(v.as_ptr(), out32, 32);
            true
        }
        _ => false,
    }
}

/// Send a message to the 32-byte address `dst` — untraceable by default (DESIGN.md §39).
/// `content_type` is a UTF-8 C string (e.g. "text/plain"); `body`/`body_len` is the payload. If
/// `request_ack`, a private delivery confirmation is requested. On success writes the 32-byte
/// bundle id into `out_id` (room for 32 bytes, may be NULL to ignore) and returns true.
#[no_mangle]
pub unsafe extern "C" fn hop_send_message(
    node: *const HopNode,
    dst: *const u8,
    content_type: *const c_char,
    body: *const u8,
    body_len: usize,
    request_ack: bool,
    out_id: *mut u8,
) -> bool {
    catch(false, || {
        let Some(node) = node_ref(node) else {
            return false;
        };
        let Some(ct) = cstr(content_type) else {
            return false;
        };
        if dst.is_null() {
            return false;
        }
        match node.send_message(
            slice(dst, 32).to_vec(),
            ct.to_string(),
            slice(body, body_len).to_vec(),
            request_ack,
        ) {
            Ok(id) => {
                if !out_id.is_null() {
                    std::ptr::copy_nonoverlapping(id.as_ptr(), out_id, id.len().min(32));
                }
                true
            }
            Err(_) => false,
        }
    })
}

// ---- reachability records: self-certifying endpoint discovery (DESIGN.md §30) ----------------

/// Sign a self-certifying reachability record for THIS node's address, binding it to `endpoint`
/// (UTF-8 C string, e.g. "wss://myaddress.com/_hop") for `ttl_secs`. Invokes `sink(ctx, bytes, len)`
/// once with the signed record bytes (serve at /.well-known/hop or gossip). No-op on NULL args.
#[no_mangle]
pub unsafe extern "C" fn hop_sign_reach_record(
    node: *const HopNode,
    endpoint: *const c_char,
    ttl_secs: u32,
    sink: Option<extern "C" fn(ctx: *mut c_void, bytes: *const u8, len: usize)>,
    ctx: *mut c_void,
) {
    let (Some(node), Some(endpoint), Some(sink)) = (node_ref(node), cstr(endpoint), sink) else {
        return;
    };
    let bytes = catch(Vec::new(), || {
        node.sign_reach_record(endpoint.to_string(), ttl_secs)
    });
    sink(ctx, bytes.as_ptr(), bytes.len());
}

/// Verify a reachability record. `now_secs` = current Unix time to enforce expiry (0 skips the expiry
/// check). Returns true iff valid; on a valid record invokes `sink(ctx, address32, endpoint_cstr,
/// issued_at, ttl_secs)` once. Self-certifying: the record is checked against the address it names,
/// no external anchor. `bytes`/`len` is the record from `hop_sign_reach_record`.
#[no_mangle]
pub unsafe extern "C" fn hop_verify_reach_record(
    bytes: *const u8,
    len: usize,
    now_secs: u64,
    sink: Option<
        extern "C" fn(
            ctx: *mut c_void,
            address: *const u8,
            endpoint: *const c_char,
            issued_at: u64,
            ttl_secs: u32,
        ),
    >,
    ctx: *mut c_void,
) -> bool {
    let now = if now_secs == 0 { None } else { Some(now_secs) };
    let rec = catch(None, || {
        hop_core::reach::ReachRecord::verify(slice(bytes, len), now)
    });
    match rec {
        Some(r) => {
            if let Some(sink) = sink {
                let ep = c_string_lossy(r.claim.endpoint);
                sink(
                    ctx,
                    r.claim.address.as_ptr(),
                    ep.as_ptr(),
                    r.claim.issued_at,
                    r.claim.ttl_secs,
                );
            }
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    //! quality-net-08: direct tests of the C ABI entry points (they had none; only the higher-level
    //! Rust API and the foreign wrappers were exercised). These call the `extern "C"` functions the
    //! way a C/Swift/Kotlin host does - through raw pointers - so a regression in the ABI seam itself
    //! (not just the Rust core) is caught here rather than only on-device.
    use super::*;

    #[test]
    fn c_string_lossy_strips_interior_nuls_instead_of_emptying() {
        // audit LOW: a value with an interior NUL must be preserved (minus the NUL), not silently
        // collapsed to "" the way CString::new(..).unwrap_or_default() did.
        assert_eq!(
            c_string_lossy("text/plain".into()).to_bytes(),
            b"text/plain"
        );
        assert_eq!(
            c_string_lossy("a\0b\0c".into()).to_bytes(),
            b"abc",
            "interior NULs are stripped, not emptied"
        );
        assert_eq!(c_string_lossy(String::new()).to_bytes(), b"");
    }

    #[test]
    fn abi_version_matches_the_constant() {
        assert_eq!(hop_abi_version(), HOP_ABI_VERSION);
    }

    #[test]
    fn null_handles_are_safe_and_falsey() {
        // Every accessor must tolerate a NULL handle (a host that failed a ctor) without UB.
        unsafe {
            let mut buf = [0u8; 32];
            assert!(!hop_node_address(std::ptr::null(), buf.as_mut_ptr()));
            assert_eq!(hop_node_secret(std::ptr::null(), buf.as_mut_ptr()), 0);
            assert!(!hop_node_is_persistent(std::ptr::null()));
            assert_eq!(hop_node_rehydrate_dropped(std::ptr::null()), 0);
            hop_node_free(std::ptr::null()); // documented no-op on NULL
        }
    }

    #[test]
    fn new_node_yields_a_nonzero_address_then_frees() {
        unsafe {
            let node = hop_node_new();
            assert!(!node.is_null(), "ctor returns a handle");
            let mut addr = [0u8; 32];
            assert!(hop_node_address(node, addr.as_mut_ptr()));
            assert_ne!(addr, [0u8; 32], "a real Ed25519 address, not zeros");
            hop_node_free(node);
        }
    }

    #[test]
    fn with_secret_is_deterministic_across_the_abi() {
        // The whole point of hop_node_secret + hop_node_with_secret: a host persists the secret and
        // restores the SAME identity. Prove the address round-trips through the C ABI.
        unsafe {
            let seed = [7u8; 32];
            let a = hop_node_with_secret(seed.as_ptr(), seed.len());
            let b = hop_node_with_secret(seed.as_ptr(), seed.len());
            let (mut aa, mut ba) = ([0u8; 32], [0u8; 32]);
            assert!(hop_node_address(a, aa.as_mut_ptr()));
            assert!(hop_node_address(b, ba.as_mut_ptr()));
            assert_eq!(aa, ba, "same secret -> same identity through the ABI");

            // And the secret read back out re-creates the same identity.
            let mut secret_out = [0u8; 32];
            assert_eq!(hop_node_secret(a, secret_out.as_mut_ptr()), 32);
            let c = hop_node_with_secret(secret_out.as_ptr(), secret_out.len());
            let mut ca = [0u8; 32];
            assert!(hop_node_address(c, ca.as_mut_ptr()));
            assert_eq!(ca, aa, "secret read back re-creates the identity");

            hop_node_free(a);
            hop_node_free(b);
            hop_node_free(c);
        }
    }

    // core-ffi-sdk-r2-01: panic-containment regression. Every hop_* body that calls into the node is
    // wrapped in `catch(default, ...)` so a panic reached via crafted/hostile state degrades to a
    // dropped op instead of unwinding across `extern "C"` (UB that aborts the whole host). These tests
    // prove the mechanism the wraps depend on: a panicking closure yields the default and DOES NOT
    // escape. Before the fix, hop_send_to / hop_message_status / hop_is_secured / the service
    // send+poll fns / hop_publish_prekey / hop_subscribe / hop_node_address|secret|set_name had no
    // such guard.

    #[test]
    fn catch_contains_an_unwinding_panic_and_returns_the_default() {
        // The bool-returning fns (hop_send_to, hop_is_secured, hop_message_status, the service
        // send fns, hop_publish_prekey, hop_node_address) default to false on panic.
        let r = catch(false, || -> bool { panic!("boom from a core path") });
        assert!(!r, "a panic yields the `false` default, not an unwind");

        // The usize-returning hop_node_secret defaults to 0.
        let n = catch(0usize, || -> usize { panic!("boom") });
        assert_eq!(
            n, 0,
            "hop_node_secret's default on panic is 0 bytes written"
        );

        // The Vec-returning drains (hop_poll_service_requests/responses) default to empty.
        let v = catch(Vec::<u8>::new(), || -> Vec<u8> { panic!("boom") });
        assert!(
            v.is_empty(),
            "a drain panic yields an empty batch, not an unwind"
        );

        // The unit-returning fns (hop_subscribe, hop_node_set_name) simply swallow it.
        catch((), || panic!("boom"));
    }

    #[test]
    fn catch_is_transparent_when_no_panic_occurs() {
        // Wrapping must NOT change the happy-path result: the fix is pure containment, no behavior
        // change on the normal path (adversarial self-check: no black-holing of a good return).
        assert!(catch(false, || true));
        assert_eq!(catch(0usize, || 7usize), 7);
        assert_eq!(catch(Vec::new(), || vec![1u8, 2, 3]), vec![1, 2, 3]);
    }

    // ---- test harness: wire two in-process nodes together through the C ABI ------------------
    //
    // A C/Swift/Kotlin host feeds bearer bytes in via `hop_bytes_received` and pumps them out via
    // `hop_drain_outgoing`. This harness plays the bearer for TWO nodes: it drains one node's
    // outgoing packets and hands each straight to the other node's `hop_bytes_received`, keyed by a
    // shared link id. That exercises the full inbound+outbound byte seam end to end, exactly as the
    // real transport would, but without a network or device.

    /// Context a sink writes into: collects (link, bytes) drained from a node.
    struct DrainCollector {
        packets: Vec<(u64, Vec<u8>)>,
    }

    extern "C" fn drain_sink(ctx: *mut c_void, link: u64, bytes: *const u8, len: usize) {
        unsafe {
            let c = &mut *(ctx as *mut DrainCollector);
            c.packets.push((link, slice(bytes, len).to_vec()));
        }
    }

    /// Drain every outgoing packet a node has queued, as a host would.
    unsafe fn drain(node: *const HopNode) -> Vec<(u64, Vec<u8>)> {
        let mut c = DrainCollector {
            packets: Vec::new(),
        };
        hop_drain_outgoing(node, Some(drain_sink), &mut c as *mut _ as *mut c_void);
        c.packets
    }

    /// Pump bytes between two nodes until the wire goes quiet. `link_a` is the link id node A uses
    /// for this bearer; `link_b` is node B's. Bytes A drains on `link_a` arrive at B on `link_b`,
    /// and vice-versa. Returns after no node has anything left to send (or a safety cap).
    unsafe fn pump(a: *const HopNode, link_a: u64, b: *const HopNode, link_b: u64) {
        for _ in 0..1000 {
            let mut any = false;
            for (_l, bytes) in drain(a) {
                any = true;
                hop_bytes_received(b, link_b, bytes.as_ptr(), bytes.len());
            }
            for (_l, bytes) in drain(b) {
                any = true;
                hop_bytes_received(a, link_a, bytes.as_ptr(), bytes.len());
            }
            if !any {
                break;
            }
        }
    }

    /// Bring up a bearer link between two fresh nodes (A dials, B accepts), pump the handshake, and
    /// gossip prekeys so `hop_send_message` can open a forward-secret session. Returns the two
    /// addresses. Uses distinct link ids per node so the harness never conflates directions.
    unsafe fn connect(a: *const HopNode, b: *const HopNode) -> ([u8; 32], [u8; 32]) {
        const LA: u64 = 11;
        const LB: u64 = 22;
        // Give both a real clock so prekey adverts aren't judged expired.
        hop_node_tick(a, 1_000);
        hop_node_tick(b, 1_000);
        hop_link_up(a, LA, HopLinkRole::Dialer as u32);
        hop_link_up(b, LB, HopLinkRole::Acceptor as u32);
        pump(a, LA, b, LB);
        assert!(hop_publish_prekey(a), "A publishes its prekey");
        assert!(hop_publish_prekey(b), "B publishes its prekey");
        pump(a, LA, b, LB);
        let (mut aa, mut ba) = ([0u8; 32], [0u8; 32]);
        assert!(hop_node_address(a, aa.as_mut_ptr()));
        assert!(hop_node_address(b, ba.as_mut_ptr()));
        (aa, ba)
    }

    /// Like [`connect`] but WITHOUT gossiping prekeys: brings up the bearer link and pumps the
    /// handshake so the two nodes are authenticated peers, yet neither knows the other's prekey. A
    /// `hop_send_message` here has no session material to ratchet against, so it MUST defer (never
    /// static-seal) until a prekey arrives. Uses the SAME link ids as `connect` so `pump(a, 11, b, 22)`
    /// works unchanged.
    unsafe fn link_only(a: *const HopNode, b: *const HopNode) -> ([u8; 32], [u8; 32]) {
        const LA: u64 = 11;
        const LB: u64 = 22;
        hop_node_tick(a, 1_000);
        hop_node_tick(b, 1_000);
        hop_link_up(a, LA, HopLinkRole::Dialer as u32);
        hop_link_up(b, LB, HopLinkRole::Acceptor as u32);
        pump(a, LA, b, LB);
        let (mut aa, mut ba) = ([0u8; 32], [0u8; 32]);
        assert!(hop_node_address(a, aa.as_mut_ptr()));
        assert!(hop_node_address(b, ba.as_mut_ptr()));
        (aa, ba)
    }

    /// Inbox collector for `hop_poll_inbox`.
    struct InboxCollector {
        msgs: Vec<(Vec<u8>, String, Vec<u8>, u8)>,
    }
    extern "C" fn inbox_sink(
        ctx: *mut c_void,
        from: *const u8,
        content_type: *const c_char,
        body: *const u8,
        body_len: usize,
        hops: u8,
        _created_at: u64,
    ) {
        unsafe {
            let c = &mut *(ctx as *mut InboxCollector);
            let ct = CStr::from_ptr(content_type).to_string_lossy().into_owned();
            c.msgs.push((
                slice(from, 32).to_vec(),
                ct,
                slice(body, body_len).to_vec(),
                hops,
            ));
        }
    }
    unsafe fn poll_inbox(node: *const HopNode) -> Vec<(Vec<u8>, String, Vec<u8>, u8)> {
        let mut c = InboxCollector { msgs: Vec::new() };
        hop_poll_inbox(node, Some(inbox_sink), &mut c as *mut _ as *mut c_void);
        c.msgs
    }

    #[test]
    fn node_open_persists_and_restores_the_same_identity_from_disk() {
        // hop_node_open is the disk-backed ctor a real host uses. Prove it (a) returns a persistent
        // node, (b) survives a free + reopen at the same path, restoring the SAME identity from the
        // saved secret, all through the C string / raw-pointer surface. NULL/non-UTF-8 path -> NULL.
        unsafe {
            // NULL path is rejected with a NULL handle (documented sentinel), not a crash.
            assert!(
                hop_node_open(std::ptr::null(), std::ptr::null(), 0, std::ptr::null(), 0).is_null()
            );

            let dir = std::env::temp_dir().join(format!("hop-abi-open-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let db = dir.join("node.db");
            let c_path = std::ffi::CString::new(db.to_str().unwrap()).unwrap();

            let n1 = hop_node_open(c_path.as_ptr(), std::ptr::null(), 0, std::ptr::null(), 0);
            assert!(!n1.is_null(), "open returns a handle");
            assert!(
                hop_node_is_persistent(n1),
                "a real db path is persistent storage"
            );
            let mut addr1 = [0u8; 32];
            assert!(hop_node_address(n1, addr1.as_mut_ptr()));
            let mut secret = [0u8; 32];
            assert_eq!(hop_node_secret(n1, secret.as_mut_ptr()), 32);
            hop_node_free(n1);

            // Reopen the SAME path with the saved secret: identity must be restored.
            let n2 = hop_node_open(
                c_path.as_ptr(),
                secret.as_ptr(),
                secret.len(),
                std::ptr::null(),
                0,
            );
            assert!(!n2.is_null());
            let mut addr2 = [0u8; 32];
            assert!(hop_node_address(n2, addr2.as_mut_ptr()));
            assert_eq!(addr1, addr2, "identity restored from the persisted secret");
            assert_eq!(
                hop_node_rehydrate_dropped(n2),
                0,
                "a clean reopen drops no persisted records"
            );
            hop_node_free(n2);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn node_open_keyed_encrypts_at_rest_and_still_round_trips_identity() {
        // hop_node_open_keyed is the SQLCipher-at-rest ctor (F-25): same identity guarantees as
        // hop_node_open, plus a raw key. Prove the keyed open yields a persistent node whose identity
        // round-trips across a reopen with the same key. NULL path -> NULL sentinel.
        unsafe {
            assert!(hop_node_open_keyed(
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0
            )
            .is_null());

            let dir = std::env::temp_dir().join(format!("hop-abi-keyed-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let db = dir.join("node.db");
            let c_path = std::ffi::CString::new(db.to_str().unwrap()).unwrap();
            let key = [0x5Au8; 32];
            let secret = [3u8; 32];

            let n1 = hop_node_open_keyed(
                c_path.as_ptr(),
                secret.as_ptr(),
                secret.len(),
                std::ptr::null(),
                0,
                key.as_ptr(),
                key.len(),
            );
            assert!(!n1.is_null());
            assert!(hop_node_is_persistent(n1));
            let mut addr1 = [0u8; 32];
            assert!(hop_node_address(n1, addr1.as_mut_ptr()));
            hop_node_free(n1);

            let n2 = hop_node_open_keyed(
                c_path.as_ptr(),
                secret.as_ptr(),
                secret.len(),
                std::ptr::null(),
                0,
                key.as_ptr(),
                key.len(),
            );
            assert!(!n2.is_null());
            let mut addr2 = [0u8; 32];
            assert!(hop_node_address(n2, addr2.as_mut_ptr()));
            assert_eq!(addr1, addr2, "keyed reopen restores the same identity");
            hop_node_free(n2);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn is_secured_flips_true_only_after_a_forward_secret_send_over_the_abi() {
        // hop_is_secured is the lock indicator the UI shows: true iff a ratchet session exists to the
        // peer (a real forward-secret conversation), not merely a link. Prove it is false before any
        // message and flips true once A actually sends a forward-secret message to B through the ABI.
        unsafe {
            let a = hop_node_new();
            let b = hop_node_new();
            let (_aa, ba) = connect(a, b);
            // A link + gossiped prekeys is NOT yet a session: no lock until a real send.
            assert!(
                !hop_is_secured(a, ba.as_ptr()),
                "not secured until a forward-secret message is sent"
            );

            let ct = std::ffi::CString::new("text/plain").unwrap();
            let body = b"open a session";
            assert!(hop_send_message(
                a,
                ba.as_ptr(),
                ct.as_ptr(),
                body.as_ptr(),
                body.len(),
                false,
                std::ptr::null_mut(),
            ));
            assert!(
                hop_is_secured(a, ba.as_ptr()),
                "A now holds a ratchet session to B: the lock shows"
            );
            // The lock claim is only honest if the content ACTUALLY rode that session end to end. Pump
            // it to B and prove B decrypts the exact body: a forward-secret delivery, not a bare
            // handshake side effect. (Without this the test could pass on any session-establishing
            // artifact and the "forward-secret message" claim would outrun what it verified.)
            pump(a, 11, b, 22);
            let inbox = poll_inbox(b);
            assert_eq!(inbox.len(), 1, "exactly one message arrived at B");
            assert_eq!(
                inbox[0].2.as_slice(),
                &body[..],
                "B decrypted the forward-secret body: the message rode the ratchet, not a static seal"
            );
            hop_node_free(a);
            hop_node_free(b);
        }
    }

    #[test]
    fn send_without_a_known_prekey_defers_never_static_seals_then_flushes_ratcheted() {
        // The critical §25 invariant at the C ABI: content is ALWAYS forward-secret. A
        // hop_send_message to a peer whose prekey we do NOT yet hold must NOT static-seal or ship
        // anything in the clear; it defers ("Securing…") until the prekey arrives, then sends
        // ratcheted. Every other ABI test pre-connects via `connect` (which gossips prekeys on both
        // sides), so this deferral path had no ABI coverage. Drive it entirely through the raw ABI.
        unsafe {
            let a = hop_node_new();
            let b = hop_node_new();
            // Linked + authenticated, but NO prekey gossiped: A cannot ratchet to B yet.
            let (_aa, ba) = link_only(a, b);
            assert!(
                !hop_is_secured(a, ba.as_ptr()),
                "no session before any send (and no prekey to open one)"
            );

            let ct = std::ffi::CString::new("text/plain").unwrap();
            let body = b"defer me until the prekey lands";
            let mut handle = [0u8; 32];
            assert!(
                hop_send_message(
                    a,
                    ba.as_ptr(),
                    ct.as_ptr(),
                    body.as_ptr(),
                    body.len(),
                    true,
                    handle.as_mut_ptr(),
                ),
                "the send is ACCEPTED (deferred) even without a prekey, returning a stable handle"
            );
            assert_ne!(handle, [0u8; 32], "a real deferral handle was written");

            // (a) Nothing went out statically/unencrypted. Pump the wire: B's inbox is EMPTY (no
            // static-sealed content leaked) and A still has NO ratchet session to B.
            pump(a, 11, b, 22);
            assert!(
                poll_inbox(b).is_empty(),
                "a deferred send must NOT static-seal: nothing reaches B before the prekey"
            );
            assert!(
                !hop_is_secured(a, ba.as_ptr()),
                "still no forward-secret session: the content was deferred, not sealed"
            );
            // The deferred message reports not-yet-delivered.
            let mut delivered = true;
            assert!(hop_message_status(
                a,
                handle.as_ptr(),
                std::ptr::null_mut(),
                &mut delivered,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ));
            assert!(
                !delivered,
                "the deferred send is tracked as not-yet-delivered"
            );

            // (b) Now B publishes + gossips its prekey. A must flush the deferred content RATCHETED:
            // the session flips secured only now (proving forward secrecy), and B decrypts the exact
            // body. Publishing the prekey requires a real clock on B (adverts aren't judged expired).
            hop_node_tick(b, 1_000);
            assert!(hop_publish_prekey(b), "B publishes its prekey");
            pump(a, 11, b, 22); // gossip the prekey to A, which flushes the deferred send
            pump(a, 11, b, 22); // shuttle the now-ratcheted content to B

            assert!(
                hop_is_secured(a, ba.as_ptr()),
                "is_secured flips true ONLY after the deferred content was sent forward-secret"
            );
            let inbox = poll_inbox(b);
            assert_eq!(
                inbox.len(),
                1,
                "the once-deferred message finally arrived at B"
            );
            assert_eq!(
                inbox[0].2.as_slice(),
                &body[..],
                "B decrypted the exact deferred body: it flushed ratcheted, never static-sealed"
            );

            hop_node_free(a);
            hop_node_free(b);
        }
    }

    #[test]
    fn send_message_crosses_two_nodes_and_arrives_in_the_peer_inbox() {
        // The end-to-end reason libhop exists: node A sends, node B receives the plaintext. Drive it
        // entirely through the C ABI (send + drain + received + poll_inbox) so a regression anywhere
        // on the byte seam is caught. Assert the delivered from-address, content-type, and body.
        unsafe {
            let a = hop_node_new();
            let b = hop_node_new();
            let (aa, ba) = connect(a, b);

            let ct = std::ffi::CString::new("text/plain").unwrap();
            let body = b"hello over the abi";
            let mut id = [0u8; 32];
            assert!(
                hop_send_message(
                    a,
                    ba.as_ptr(),
                    ct.as_ptr(),
                    body.as_ptr(),
                    body.len(),
                    true,
                    id.as_mut_ptr(),
                ),
                "send_message returns true and writes a bundle id"
            );
            assert_ne!(id, [0u8; 32], "a real bundle id was written");

            pump(a, 11, b, 22);
            let inbox = poll_inbox(b);
            assert_eq!(inbox.len(), 1, "exactly one message arrived at B");
            let (from, cty, got_body, _hops) = &inbox[0];
            assert_eq!(from.as_slice(), &aa[..], "from == A's address");
            assert_eq!(cty, "text/plain");
            assert_eq!(got_body.as_slice(), &body[..], "body arrives intact");

            // Draining the inbox is destructive: a second poll is empty.
            assert!(poll_inbox(b).is_empty(), "inbox drained on first poll");
            hop_node_free(a);
            hop_node_free(b);
        }
    }

    #[test]
    fn message_status_transitions_to_delivered_after_a_private_ack() {
        // hop_send_message with request_ack asks the recipient for a §39 private delivery
        // confirmation. Before the ACK returns, message_status reports delivered=false; after the
        // round trip is pumped, it must flip to delivered=true. This is the send-receipt the UI
        // shows, driven purely through the ABI.
        unsafe {
            let a = hop_node_new();
            let b = hop_node_new();
            let (_aa, ba) = connect(a, b);

            let ct = std::ffi::CString::new("text/plain").unwrap();
            let body = b"ack me";
            let mut id = [0u8; 32];
            assert!(hop_send_message(
                a,
                ba.as_ptr(),
                ct.as_ptr(),
                body.as_ptr(),
                body.len(),
                true,
                id.as_mut_ptr(),
            ));

            // Immediately: not yet delivered.
            let mut delivered = true;
            assert!(hop_message_status(
                a,
                id.as_ptr(),
                std::ptr::null_mut(),
                &mut delivered,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ));
            assert!(!delivered, "not delivered before the ACK round trip");

            // Pump the message to B, let B poll (which triggers the private ACK), pump the ACK back.
            pump(a, 11, b, 22);
            let _ = poll_inbox(b);
            pump(a, 11, b, 22);

            let mut delivered2 = false;
            let mut hops = 0u8;
            assert!(hop_message_status(
                a,
                id.as_ptr(),
                std::ptr::null_mut(),
                &mut delivered2,
                &mut hops,
                std::ptr::null_mut(),
            ));
            assert!(delivered2, "delivered flips true after the private ACK");
            hop_node_free(a);
            hop_node_free(b);
        }
    }

    // ---- service request/response full round trip (hops://) ----------------------------------

    // (from, request_id, service, method, args)
    type SvcReqRow = (Vec<u8>, Vec<u8>, String, String, Vec<u8>);
    // (from, for_request_id, status, body)
    type SvcRespRow = (Vec<u8>, Vec<u8>, u16, Vec<u8>);

    struct SvcReqCollector {
        reqs: Vec<SvcReqRow>,
    }
    #[allow(clippy::too_many_arguments)]
    extern "C" fn svc_req_sink(
        ctx: *mut c_void,
        from: *const u8,
        request_id: *const u8,
        service: *const c_char,
        method: *const c_char,
        args: *const u8,
        args_len: usize,
    ) {
        unsafe {
            let c = &mut *(ctx as *mut SvcReqCollector);
            c.reqs.push((
                slice(from, 32).to_vec(),
                slice(request_id, 32).to_vec(),
                CStr::from_ptr(service).to_string_lossy().into_owned(),
                CStr::from_ptr(method).to_string_lossy().into_owned(),
                slice(args, args_len).to_vec(),
            ));
        }
    }
    unsafe fn poll_requests(node: *const HopNode) -> Vec<SvcReqRow> {
        let mut c = SvcReqCollector { reqs: Vec::new() };
        hop_poll_service_requests(node, Some(svc_req_sink), &mut c as *mut _ as *mut c_void);
        c.reqs
    }

    struct SvcRespCollector {
        resps: Vec<SvcRespRow>,
    }
    extern "C" fn svc_resp_sink(
        ctx: *mut c_void,
        from: *const u8,
        for_request_id: *const u8,
        status: u16,
        body: *const u8,
        body_len: usize,
    ) {
        unsafe {
            let c = &mut *(ctx as *mut SvcRespCollector);
            c.resps.push((
                slice(from, 32).to_vec(),
                slice(for_request_id, 32).to_vec(),
                status,
                slice(body, body_len).to_vec(),
            ));
        }
    }
    unsafe fn poll_responses(node: *const HopNode) -> Vec<SvcRespRow> {
        let mut c = SvcRespCollector { resps: Vec::new() };
        hop_poll_service_responses(node, Some(svc_resp_sink), &mut c as *mut _ as *mut c_void);
        c.resps
    }

    #[test]
    fn hops_service_request_response_round_trips_through_the_abi() {
        // The full hops:// round trip that makes an ESP32 a real client: caller A fires a service
        // request; host B drains it, seals a response; caller A drains the response. Assert the ids
        // line up (response.for_request_id == request.request_id), the service/method/args survive,
        // and the status + body come back. All through the extern "C" surface.
        unsafe {
            let a = hop_node_new();
            let b = hop_node_new();
            let (aa, ba) = connect(a, b);

            let service = std::ffi::CString::new("weather").unwrap();
            let method = std::ffi::CString::new("report").unwrap();
            let args = b"temp=21";
            let mut req_id = [0u8; 32];
            assert!(
                hop_send_service_request(
                    a,
                    ba.as_ptr(),
                    service.as_ptr(),
                    method.as_ptr(),
                    args.as_ptr(),
                    args.len(),
                    req_id.as_mut_ptr(),
                ),
                "service request fires and writes a request id"
            );
            assert_ne!(req_id, [0u8; 32]);

            pump(a, 11, b, 22);
            let reqs = poll_requests(b);
            assert_eq!(reqs.len(), 1, "B drains exactly one request");
            let (from, got_req_id, svc, mth, got_args) = &reqs[0];
            assert_eq!(from.as_slice(), &aa[..], "request came from A");
            assert_eq!(got_req_id.as_slice(), &req_id[..], "request id matches");
            assert_eq!(svc, "weather");
            assert_eq!(mth, "report");
            assert_eq!(got_args.as_slice(), &args[..], "args survive the codec");

            // B seals a response back.
            let resp_body = b"stored";
            assert!(
                hop_send_service_response(
                    b,
                    from.as_ptr(),
                    got_req_id.as_ptr(),
                    200,
                    resp_body.as_ptr(),
                    resp_body.len(),
                ),
                "response seals and queues"
            );
            pump(a, 11, b, 22);

            let resps = poll_responses(a);
            assert_eq!(resps.len(), 1, "A drains exactly one response");
            let (rfrom, for_id, status, body) = &resps[0];
            assert_eq!(rfrom.as_slice(), &ba[..], "response came from B");
            assert_eq!(
                for_id.as_slice(),
                &req_id[..],
                "for_request_id ties the response to the original request"
            );
            assert_eq!(*status, 200u16, "status code round-trips");
            assert_eq!(body.as_slice(), &resp_body[..], "response body round-trips");
            hop_node_free(a);
            hop_node_free(b);
        }
    }

    // ---- base58 address codec ----------------------------------------------------------------

    #[test]
    fn base58_address_round_trips_and_rejects_garbage() {
        unsafe {
            // A node's real address must survive encode -> decode unchanged.
            let node = hop_node_new();
            let mut addr = [0u8; 32];
            assert!(hop_node_address(node, addr.as_mut_ptr()));

            let mut buf = [0i8; 64];
            let n = hop_address_to_base58(addr.as_ptr(), buf.as_mut_ptr(), buf.len());
            assert!(n > 0, "encoded to a non-empty base58 string");
            // NUL-terminated at the reported length.
            assert_eq!(buf[n], 0, "output is NUL-terminated at the reported length");

            let mut decoded = [0u8; 32];
            assert!(hop_address_from_base58(buf.as_ptr(), decoded.as_mut_ptr()));
            assert_eq!(decoded, addr, "base58 round-trips the address exactly");

            // Too-small buffer must refuse (return 0), not overflow.
            let mut tiny = [0i8; 4];
            assert_eq!(
                hop_address_to_base58(addr.as_ptr(), tiny.as_mut_ptr(), tiny.len()),
                0,
                "insufficient capacity returns 0, never overruns"
            );

            // Non-base58 / wrong-length garbage must be rejected.
            let bad = std::ffi::CString::new("0OIl+not+base58").unwrap();
            assert!(
                !hop_address_from_base58(bad.as_ptr(), decoded.as_mut_ptr()),
                "invalid base58 is rejected"
            );
            let short = std::ffi::CString::new("aaa").unwrap(); // decodes to < 32 bytes
            assert!(
                !hop_address_from_base58(short.as_ptr(), decoded.as_mut_ptr()),
                "a valid-base58 but wrong-length string is rejected"
            );

            // NULL inputs are handled without UB.
            assert_eq!(
                hop_address_to_base58(std::ptr::null(), buf.as_mut_ptr(), buf.len()),
                0
            );
            assert!(!hop_address_from_base58(
                std::ptr::null(),
                decoded.as_mut_ptr()
            ));
            hop_node_free(node);
        }
    }

    #[test]
    fn link_down_ends_the_directed_send_path() {
        // hop_send_to (the directed §27 path) only works to a peer we're DIRECTLY linked to. Prove
        // it succeeds while the link is up, then that hop_link_down removes the peer link so the very
        // same send now returns a clean false. Drives link_up + link_down through the ABI.
        unsafe {
            let a = hop_node_new();
            let b = hop_node_new();
            let (_aa, ba) = connect(a, b);
            let ct = std::ffi::CString::new("text/plain").unwrap();
            let body = b"x";
            assert!(
                hop_send_to(
                    a,
                    ba.as_ptr(),
                    ct.as_ptr(),
                    body.as_ptr(),
                    body.len(),
                    false,
                    std::ptr::null_mut(),
                ),
                "send_to a directly-linked peer succeeds while the link is up"
            );

            hop_link_down(a, 11);
            // No live peer link remains, so a directed send_to must now fail cleanly.
            assert!(
                !hop_send_to(
                    a,
                    ba.as_ptr(),
                    ct.as_ptr(),
                    body.as_ptr(),
                    body.len(),
                    false,
                    std::ptr::null_mut(),
                ),
                "send_to a peer whose link dropped is a clean false"
            );
            hop_node_free(a);
            hop_node_free(b);
        }
    }

    #[test]
    fn send_to_directly_connected_peer_delivers() {
        // hop_send_to is the directed §27 path: it only works to a peer we're directly linked to.
        // Prove it succeeds across a live ABI link and the message lands in the peer's inbox.
        unsafe {
            let a = hop_node_new();
            let b = hop_node_new();
            let (aa, ba) = connect(a, b);

            let ct = std::ffi::CString::new("text/plain").unwrap();
            let body = b"directed hello";
            let mut id = [0u8; 32];
            assert!(
                hop_send_to(
                    a,
                    ba.as_ptr(),
                    ct.as_ptr(),
                    body.as_ptr(),
                    body.len(),
                    false,
                    id.as_mut_ptr(),
                ),
                "send_to a directly-connected peer succeeds"
            );
            assert_ne!(id, [0u8; 32]);
            pump(a, 11, b, 22);
            let inbox = poll_inbox(b);
            assert_eq!(inbox.len(), 1);
            assert_eq!(inbox[0].0.as_slice(), &aa[..]);
            assert_eq!(inbox[0].2.as_slice(), &body[..]);
            hop_node_free(a);
            hop_node_free(b);
        }
    }

    #[test]
    fn garbage_bytes_on_a_link_are_swallowed_not_unwound() {
        // hop_bytes_received is the single most hostile entry: it takes raw network bytes. Feeding
        // random garbage on an up link (and on a link that was never brought up) must never panic or
        // unwind across the ABI, and must leave the node still usable afterwards.
        unsafe {
            let node = hop_node_new();
            hop_link_up(node, 5, HopLinkRole::Acceptor as u32);
            let junk = [0xABu8; 128];
            hop_bytes_received(node, 5, junk.as_ptr(), junk.len());
            // A never-up link id, too.
            hop_bytes_received(node, 999, junk.as_ptr(), junk.len());
            // Zero-length frame.
            hop_bytes_received(node, 5, std::ptr::null(), 0);

            // The node still answers accessors afterwards: no brick, no poisoned lock.
            let mut addr = [0u8; 32];
            assert!(
                hop_node_address(node, addr.as_mut_ptr()),
                "node still usable after hostile bytes"
            );
            assert_ne!(addr, [0u8; 32]);
            hop_node_free(node);
        }
    }

    #[test]
    fn null_and_garbage_inputs_return_sentinels_across_the_send_surface() {
        // Every send/query entry point must reject NULL node / NULL required pointers with its
        // documented sentinel (false / 0), never dereference NULL, never unwind.
        unsafe {
            let ct = std::ffi::CString::new("text/plain").unwrap();
            let dst = [1u8; 32];
            let body = b"x";
            // NULL node on each send path.
            assert!(!hop_send_message(
                std::ptr::null(),
                dst.as_ptr(),
                ct.as_ptr(),
                body.as_ptr(),
                body.len(),
                false,
                std::ptr::null_mut()
            ));
            assert!(!hop_send_to(
                std::ptr::null(),
                dst.as_ptr(),
                ct.as_ptr(),
                body.as_ptr(),
                body.len(),
                false,
                std::ptr::null_mut()
            ));
            assert!(!hop_publish_prekey(std::ptr::null()));
            assert!(!hop_is_secured(std::ptr::null(), dst.as_ptr()));
            assert!(!hop_message_status(
                std::ptr::null(),
                dst.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ));

            // Live node, but NULL required pointers -> documented false, no deref.
            let node = hop_node_new();
            assert!(
                !hop_send_message(
                    node,
                    std::ptr::null(),
                    ct.as_ptr(),
                    body.as_ptr(),
                    body.len(),
                    false,
                    std::ptr::null_mut()
                ),
                "NULL dst rejected"
            );
            assert!(
                !hop_send_message(
                    node,
                    dst.as_ptr(),
                    std::ptr::null(),
                    body.as_ptr(),
                    body.len(),
                    false,
                    std::ptr::null_mut()
                ),
                "NULL content_type rejected"
            );
            assert!(
                !hop_is_secured(node, std::ptr::null()),
                "NULL addr rejected"
            );
            assert!(
                !hop_message_status(
                    node,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                "NULL id rejected"
            );
            assert!(
                !hop_send_service_request(
                    node,
                    std::ptr::null(),
                    ct.as_ptr(),
                    ct.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut()
                ),
                "NULL dst on service request rejected"
            );
            assert!(
                !hop_send_service_response(
                    node,
                    std::ptr::null(),
                    std::ptr::null(),
                    200,
                    std::ptr::null(),
                    0
                ),
                "NULL to/request_id on service response rejected"
            );
            hop_node_free(node);
        }
    }

    #[test]
    fn drain_and_poll_are_noops_with_a_null_sink_or_null_node() {
        // The poll-model drains must tolerate a NULL sink and a NULL node without UB (a host that
        // passes a bad callback, or drains a node that failed to open).
        unsafe {
            let node = hop_node_new();
            hop_drain_outgoing(node, None, std::ptr::null_mut());
            hop_poll_inbox(node, None, std::ptr::null_mut());
            hop_poll_service_requests(node, None, std::ptr::null_mut());
            hop_poll_service_responses(node, None, std::ptr::null_mut());
            // NULL node with a real-looking sink is also safe.
            hop_drain_outgoing(std::ptr::null(), Some(drain_sink), std::ptr::null_mut());
            // Node still fine.
            let mut addr = [0u8; 32];
            assert!(hop_node_address(node, addr.as_mut_ptr()));
            hop_node_free(node);
        }
    }

    #[test]
    fn subscribe_and_set_name_are_tolerant_and_effect_free_of_panics() {
        // These unit-returning entry points have no return to assert, so drive their observable
        // safety: NULL node, NULL string, and a valid call must all run without unwinding, and the
        // node must remain usable (subscribe/set_name touch node state under the lock).
        unsafe {
            let topic = std::ffi::CString::new("hops.chat").unwrap();
            let name = std::ffi::CString::new("esp32-01").unwrap();
            // NULL node: no-op.
            hop_subscribe(std::ptr::null(), topic.as_ptr());
            hop_node_set_name(std::ptr::null(), name.as_ptr());

            let node = hop_node_new();
            // NULL string args: no-op, no deref.
            hop_subscribe(node, std::ptr::null());
            hop_node_set_name(node, std::ptr::null());
            // Valid calls run clean.
            hop_subscribe(node, topic.as_ptr());
            hop_node_set_name(node, name.as_ptr());
            // Node still answers after mutating its state under the lock.
            let mut addr = [0u8; 32];
            assert!(hop_node_address(node, addr.as_mut_ptr()));
            assert_ne!(addr, [0u8; 32]);
            hop_node_free(node);
        }
    }

    #[test]
    fn link_role_out_of_range_is_treated_as_acceptor_not_ub() {
        // core-ffi-05: hop_link_up takes role as a plain u32. A C caller passing an out-of-range int
        // (here 7) must NOT materialize an invalid enum (UB); only 0 selects Dialer, anything else is
        // Acceptor. Prove a garbage role still yields a working link that completes a handshake.
        unsafe {
            let a = hop_node_new();
            let b = hop_node_new();
            hop_node_tick(a, 1_000);
            hop_node_tick(b, 1_000);
            // A dials (0). B accepts via a GARBAGE role int (7) -> must behave as Acceptor.
            hop_link_up(a, 11, 0);
            hop_link_up(b, 22, 7);
            pump(a, 11, b, 22);
            assert!(hop_publish_prekey(a));
            assert!(hop_publish_prekey(b));
            pump(a, 11, b, 22);
            let mut ba = [0u8; 32];
            assert!(hop_node_address(b, ba.as_mut_ptr()));
            // If the garbage role int had corrupted the handshake, no session forms and this send
            // never reaches B. Delivery to B's inbox proves the link came up as an Acceptor.
            let ct = std::ffi::CString::new("t").unwrap();
            let body = b"role-check";
            assert!(hop_send_message(
                a,
                ba.as_ptr(),
                ct.as_ptr(),
                body.as_ptr(),
                body.len(),
                false,
                std::ptr::null_mut(),
            ));
            pump(a, 11, b, 22);
            let inbox = poll_inbox(b);
            assert_eq!(
                inbox.len(),
                1,
                "garbage role int behaved as Acceptor and the message delivered"
            );
            assert_eq!(inbox[0].2.as_slice(), &body[..]);
            hop_node_free(a);
            hop_node_free(b);
        }
    }

    // ---- reachability records through the ABI ----
    struct BytesOut {
        bytes: Vec<u8>,
    }
    extern "C" fn reach_sign_sink(ctx: *mut c_void, bytes: *const u8, len: usize) {
        unsafe {
            (*(ctx as *mut BytesOut)).bytes = slice(bytes, len).to_vec();
        }
    }
    struct ReachOut {
        address: Vec<u8>,
        endpoint: String,
        ttl_secs: u32,
    }
    extern "C" fn reach_verify_sink(
        ctx: *mut c_void,
        address: *const u8,
        endpoint: *const c_char,
        _issued_at: u64,
        ttl_secs: u32,
    ) {
        unsafe {
            let o = &mut *(ctx as *mut ReachOut);
            o.address = slice(address, 32).to_vec();
            o.endpoint = CStr::from_ptr(endpoint).to_string_lossy().into_owned();
            o.ttl_secs = ttl_secs;
        }
    }

    #[test]
    fn reach_record_signs_and_verifies_through_the_abi() {
        unsafe {
            let node = hop_node_new();
            hop_node_tick(node, 1_700_000_000_000); // ms clock => issued_at 1_700_000_000s
            let mut addr = [0u8; 32];
            assert!(hop_node_address(node, addr.as_mut_ptr()));

            let ep = std::ffi::CString::new("wss://myaddress.com/_hop").unwrap();
            let mut signed = BytesOut { bytes: Vec::new() };
            hop_sign_reach_record(
                node,
                ep.as_ptr(),
                3600,
                Some(reach_sign_sink),
                &mut signed as *mut _ as *mut c_void,
            );
            assert!(!signed.bytes.is_empty(), "sign produced a record");

            let mut v = ReachOut {
                address: vec![],
                endpoint: String::new(),
                ttl_secs: 0,
            };
            let ok = hop_verify_reach_record(
                signed.bytes.as_ptr(),
                signed.bytes.len(),
                1_700_000_100, // within the 3600s ttl
                Some(reach_verify_sink),
                &mut v as *mut _ as *mut c_void,
            );
            assert!(ok, "a valid record verifies through the ABI");
            assert_eq!(v.address, addr, "self-certifies THIS node's address");
            assert_eq!(v.endpoint, "wss://myaddress.com/_hop");
            assert_eq!(v.ttl_secs, 3600);

            // Tamper one byte: verification must fail (self-certifying, no anchor bypass).
            let mut bad = signed.bytes.clone();
            let last = bad.len() - 1;
            bad[last] ^= 0xff;
            assert!(
                !hop_verify_reach_record(bad.as_ptr(), bad.len(), 0, None, std::ptr::null_mut()),
                "a tampered record is rejected"
            );

            hop_node_free(node);
        }
    }

    #[test]
    fn wrapped_send_paths_run_clean_on_the_happy_path() {
        // Drive the newly-wrapped fns through a live node to confirm the catch wrapper didn't alter
        // their normal return (a `catch` mistakenly returning the default would surface here).
        unsafe {
            let node = hop_node_new();
            assert!(
                hop_publish_prekey(node),
                "prekey publishes cleanly through the wrap"
            );

            let ct = std::ffi::CString::new("text/plain").unwrap();
            let dst = [9u8; 32];
            let body = b"hi";
            let mut out_id = [0u8; 32];
            // Not connected to `dst`, so send_to must return false (its documented failure), NOT
            // panic and NOT the catch-default masking a real send. Either way: no unwind.
            let sent = hop_send_to(
                node,
                dst.as_ptr(),
                ct.as_ptr(),
                body.as_ptr(),
                body.len(),
                false,
                out_id.as_mut_ptr(),
            );
            assert!(!sent, "send_to to an unconnected peer is a clean false");

            // is_secured on an unknown peer is a clean false.
            assert!(!hop_is_secured(node, dst.as_ptr()));

            // message_status for an unknown id returns true (fields written) with delivered=false.
            let mut relayed = 1u32;
            let mut delivered = true;
            let ok = hop_message_status(
                node,
                out_id.as_ptr(),
                &mut relayed,
                &mut delivered,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            assert!(ok);
            assert!(!delivered, "an unknown bundle id is not delivered");
            assert_eq!(relayed, 0);

            hop_node_free(node);
        }
    }
}
