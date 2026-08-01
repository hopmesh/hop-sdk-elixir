# Changelog

Notable changes, generated from [conventional commits](https://www.conventionalcommits.org) by
git-cliff. Do not edit by hand.
## Unreleased

### Bug Fixes
- bump corpus + all wire-version consumers to v10 (e68d804)
- close adversarial protocol gaps (cad3deb)
- cover Destination::Vaccine in every workspace crate (relay/relayd/hop-sim) + workspace fmt/clippy (e611c4d)

### CI
- bump create-github-app-token to v3.2.0 across all mirrored components (efc9f6c)

### Chore
- invert the license tiers, FSL moves from core to services (14d7fec)
- purge em-dashes and en-dashes from source (d222435)
- drop the root license, license per-component (FSL-1.1-ALv2) (#146) (be2a5a7)

### Dependencies
- land the grouped rust-dependencies bump (sha2, ed25519/x25519-dalek, chacha20poly1305, snow, rusqlite, p256, uniffi, tungstenite) (#89) (2038ce9)

### Documentation
- regenerate from conventional commits (2741000)
- regenerate from conventional commits (b96e019)
- regenerate from conventional commits (330c8c6)
- regenerate from conventional commits (096180b)
- regenerate from conventional commits (102ae67)
- regenerate from conventional commits (1572ae2)
- regenerate from conventional commits (a355901)
- branded, marketable READMEs for every sub-repo (9c2a477)
- stop mentioning DNSSEC (no longer part of the design) (179a278)
- record remediation results (8f69d08)

### Features
- finish inbound (import), drop export_pr (41c095e)
- auto-generate monorepo + per-library changelogs (git-cliff) (8c64c37)
- phase 3 hold-until-coordinated quorum (CP; never double-process) (#159) (ab0f376)
- cluster bindings across all six SDKs (+ passphrase ABI entry) (#154) (afb1632)
- self-clustering endpoints (phase 1 dedup) as a hop-endpoint-core layer over the mesh (#153) (487e4d2)
- self-certifying reachability records (core + ABI) for DNS-free endpoint discovery (#126) (7c31123)

### Other
- wire the relay pool end to end, and stop the wire guard false-firing (35946e0)
- one-time prekeys for async first contact (wire v11) (d6ebce3)
- CLA gate on contributions (preserve commercial relicensing of core) (5a9aa7d)
- SECURITY.md per component + enable-security in the bootstrap script (a1492e9)
- copyright holder is Hop Mesh, LLC (7d8c514)
- CHANGE_REQUEST sync-back + document merge/conversation + confidentiality (9e1dec2)
- make the TLS-served reach record the only name path (drop DNSSEC-over-DoH) (#139) (8998288)
- SQLCipher encryption at rest, keyed through the whole SDK stack (777cdb9)

### Testing
- cover the FFI/UniFFI HopNode surface + free helpers (crate 56.5% -> 96%) (#59) (af90faa)

