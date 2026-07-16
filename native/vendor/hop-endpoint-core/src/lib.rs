//! The Hop **endpoint** layer: what a server-side endpoint needs on top of the pure protocol
//! (`hop-core`), starting with self-forming **clustering** so horizontally-scaled replicas (one
//! shared identity, no shared datastore, only the mesh between them) dedup addressed requests
//! among themselves.
//!
//! [`Endpoint`] wraps a [`hop_core::node::Node`] (and `Deref`s to it) and adds the cluster
//! coordinator built ENTIRELY on the node's public `hps://` + service API, so `hop-core` stays pure
//! protocol and carries nothing cluster-specific. The ABI crate and the standalone endpoint service
//! both build on this one implementation; see DESIGN.md §40.

pub mod cluster;
pub mod endpoint;

pub use cluster::{claim_key, ClaimKey, Cluster, ClusterMsg, MemberId};
pub use endpoint::Endpoint;
