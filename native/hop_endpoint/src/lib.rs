//! Rustler NIF: binds the `hop` crate's public `HopNode` Rust API (the same object the C ABI wraps,
//! with its panic guards) into the BEAM. The ergonomics + pump loop + bearer live in Elixir
//! (lib/hop/endpoint.ex); this layer is a thin, one-to-one bridge. Bytes cross as Erlang binaries.
use hop::HopNode;
use rustler::{Binary, Env, NewBinary, NifResult, ResourceArc};
use std::sync::Arc;

struct NodeRes(Arc<HopNode>);

#[rustler::resource_impl]
impl rustler::Resource for NodeRes {}

fn mkbin<'a>(env: Env<'a>, data: &[u8]) -> Binary<'a> {
    let mut b = NewBinary::new(env, data.len());
    b.as_mut_slice().copy_from_slice(data);
    b.into()
}

#[rustler::nif]
fn open_ephemeral() -> ResourceArc<NodeRes> {
    ResourceArc::new(NodeRes(HopNode::new()))
}

#[rustler::nif]
fn open_with_secret(secret: Binary) -> ResourceArc<NodeRes> {
    ResourceArc::new(NodeRes(HopNode::with_secret(secret.as_slice().to_vec())))
}

#[rustler::nif]
fn address<'a>(env: Env<'a>, node: ResourceArc<NodeRes>) -> Binary<'a> {
    mkbin(env, &node.0.address())
}

#[rustler::nif]
fn tick(node: ResourceArc<NodeRes>, now_ms: u64) {
    node.0.tick(now_ms);
}

#[rustler::nif]
fn connected(node: ResourceArc<NodeRes>, link: u64, initiator: bool) {
    node.0.connected(link, initiator);
}

#[rustler::nif]
fn disconnected(node: ResourceArc<NodeRes>, link: u64) {
    node.0.disconnected(link);
}

#[rustler::nif]
fn received(node: ResourceArc<NodeRes>, link: u64, data: Binary) {
    node.0.received(link, data.as_slice().to_vec());
}

#[rustler::nif]
fn drain_outgoing<'a>(env: Env<'a>, node: ResourceArc<NodeRes>) -> Vec<(u64, Binary<'a>)> {
    node.0
        .drain_outgoing()
        .into_iter()
        .map(|p| (p.link, mkbin(env, &p.bytes)))
        .collect()
}

#[rustler::nif]
fn subscribe(node: ResourceArc<NodeRes>, topic: String) {
    node.0.subscribe(topic);
}

#[rustler::nif]
fn publish_prekey(node: ResourceArc<NodeRes>) -> bool {
    node.0.publish_prekey().is_ok()
}

// Endpoint clustering (DESIGN.md §40): join a cluster and dedup applies transparently to the poll.
#[rustler::nif]
fn cluster_join_passphrase(node: ResourceArc<NodeRes>, passphrase: Binary) {
    node.0.cluster_join_passphrase(passphrase.as_slice());
}

#[rustler::nif]
fn cluster_members(node: ResourceArc<NodeRes>) -> u32 {
    node.0.cluster_members()
}

// Require at least `min_live_members` live cluster members visible before this replica processes a
// request using a TTL-based visibility threshold; this is not consensus or at-most-once.
#[rustler::nif]
fn cluster_quorum(node: ResourceArc<NodeRes>, min_live_members: u32) {
    node.0.cluster_quorum(min_live_members);
}

#[rustler::nif]
fn send_service_request<'a>(
    env: Env<'a>,
    node: ResourceArc<NodeRes>,
    dst: Binary,
    service: String,
    method: String,
    args: Binary,
) -> NifResult<Binary<'a>> {
    match node.0.send_service_request(
        dst.as_slice().to_vec(),
        service,
        method,
        args.as_slice().to_vec(),
    ) {
        Ok(id) => Ok(mkbin(env, &id)),
        Err(e) => Err(rustler::Error::Term(Box::new(format!("{e:?}")))),
    }
}

#[rustler::nif]
fn send_service_response(
    node: ResourceArc<NodeRes>,
    to: Binary,
    for_request_id: Binary,
    status: u16,
    body: Binary,
) -> bool {
    node.0
        .send_service_response(
            to.as_slice().to_vec(),
            for_request_id.as_slice().to_vec(),
            status,
            body.as_slice().to_vec(),
        )
        .is_ok()
}

#[rustler::nif]
fn take_service_requests<'a>(
    env: Env<'a>,
    node: ResourceArc<NodeRes>,
) -> Vec<(Binary<'a>, Binary<'a>, String, String, Binary<'a>)> {
    node.0
        .take_service_requests()
        .into_iter()
        .map(|r| {
            (
                mkbin(env, &r.from),
                mkbin(env, &r.request_id),
                r.service,
                r.method,
                mkbin(env, &r.args),
            )
        })
        .collect()
}

#[rustler::nif]
fn take_service_responses<'a>(
    env: Env<'a>,
    node: ResourceArc<NodeRes>,
) -> Vec<(Binary<'a>, Binary<'a>, u16, Binary<'a>)> {
    node.0
        .take_service_responses()
        .into_iter()
        .map(|r| {
            (
                mkbin(env, &r.from),
                mkbin(env, &r.for_request_id),
                r.status,
                mkbin(env, &r.body),
            )
        })
        .collect()
}

#[rustler::nif]
fn to_b58(addr: Binary) -> String {
    hop::address_base58(addr.as_slice().to_vec())
}

#[rustler::nif]
fn from_b58<'a>(env: Env<'a>, text: String) -> Binary<'a> {
    mkbin(env, &hop::address_from_base58(text))
}

#[rustler::nif]
fn sign_reach_record<'a>(
    env: Env<'a>,
    node: ResourceArc<NodeRes>,
    endpoint: String,
    ttl_secs: u32,
) -> Binary<'a> {
    mkbin(env, &node.0.sign_reach_record(endpoint, ttl_secs))
}

// Returns {valid, address, endpoint, issued_at, ttl_secs}. valid=false => the record is bad/expired.
#[rustler::nif]
fn verify_reach_record<'a>(
    env: Env<'a>,
    bytes: Binary,
    now_secs: u64,
) -> (bool, Binary<'a>, String, u64, u32) {
    let info = hop::verify_reach_record(bytes.as_slice().to_vec(), now_secs);
    (
        info.valid,
        mkbin(env, &info.address),
        info.endpoint,
        info.issued_at,
        info.ttl_secs,
    )
}

rustler::init!("Elixir.Hop.Native");
