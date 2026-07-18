<p align="center">
  <img alt="Hop" src="https://hopme.sh/hop-mark.svg" width="200">
</p>

<h1 align="center">hop_endpoint</h1>

<p align="center">
  <b>Receive Hop messages in your Elixir service.</b><br>
  A Phoenix/Plug-shaped endpoint on the <a href="https://hopme.sh">Hop</a> mesh, over <code>hop-core</code> via a Rustler NIF.
</p>

<p align="center">
  <a href="https://hex.pm/packages/hop_endpoint"><img src="https://img.shields.io/hexpm/v/hop_endpoint?color=7a5299&label=hex" alt="hex"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-3ddc84" alt="license">
  <img src="https://img.shields.io/badge/elixir-%E2%89%A51.15-6ea8fe" alt="elixir >=1.15">
</p>

---

Hop is a **delay-tolerant mesh**: end-to-end encrypted datagrams that hop device to device, over BLE,
Wi-Fi, and the internet, until they reach the person or service you meant. Held, never dropped.

`hop` is the **server side**: your Elixir service becomes a first-class address on the mesh, so senders
hand messages straight to it. Self-host is a dependency, not an ops project. No inbound port to open to
the world, no bearer tokens to rotate, no message queue to run: the sender identity is authenticated by
the ratchet, and delivery is durable and store-and-forward.

## Install

Add it to `mix.exs`:

```elixir
def deps do
  [{:hop_endpoint, "~> 0.0"}]
end
```

The native side is a **Rustler NIF** that compiles `hop-core`, the Rust protocol core, into your app on
the first `mix` build, so you need a Rust toolchain present. The Hex archive includes the exact four
Rust crates needed by the NIF under `native/vendor` plus `native/Cargo.lock`; no path escapes the Hex
package and no monorepo checkout is required. Those protocol sources retain their FSL license while the
Elixir wrapper is Apache-2.0. `:ssl`, `:public_key`, and `:crypto` power the WSS bearer and discovery,
with no third-party WebSocket deps.

## Quick start

```elixir
{:ok, ep} = Hop.Endpoint.start_link([])

Hop.Endpoint.on(ep, "acme/orders", fn req, reply ->
  # req.from is a VERIFIED identity, not a spoofable header
  order = Jason.decode!(req.args)
  reply.(201, Jason.encode!(%{ok: true, order: order}))   # uint16 status + body
end)

{:ok, _} = Hop.TcpBearer.listen(ep, 9944)   # reachable by any device
IO.puts(Hop.Endpoint.address(ep))           # publish this (or its name); senders reach you by it
```

**The DX looks like HTTP; the semantics are better.** Inbound is a durable, store-and-forward consume; a
reply is a new addressed message that may arrive later, even after a restart. It works when the peer is
offline, and there is no auth layer to bolt on, the identity is cryptographic. `Hop.Endpoint` is a
`GenServer` that owns the node and runs the poll-model pump on a timer.

## Reachable by name

Make an endpoint reachable at `myaddress.com` with no new port, on a WSS bearer over Erlang's built-in
`:ssl`. `attach` wires the WSS bearer (`/_hop`) and the discovery route (`/.well-known/hop`) in one call:

```elixir
{:ok, _} = Hop.Endpoint.attach(ep, 443, [certfile: cert, keyfile: key], "wss://myaddress.com/_hop")
```

A client reaches it by name, verified end to end:

```elixir
address = Hop.Endpoint.dial_by_name(client, "https://myaddress.com")
{:ok, 201, body} = Hop.Endpoint.request(client, address, "acme/orders", "create", order)
```

TLS proves the domain, a signed **reach record** proves the address, and the Noise handshake confirms it.
Spoof the `A` record or MITM the lookup and the attacker still can't forge the cert or complete the
handshake as the address, and a request sealed to that address is unreadable to anyone else.

## How it maps to the core

The endpoint is a `hop-core` node in host-a-mailbox mode. Elixir reaches it through a Rustler NIF that
binds the same `HopNode` Rust object the C ABI wraps (panic guards intact), with zero core changes:

| Endpoint                       | hop-core operation                                          |
| ------------------------------ | ----------------------------------------------------------- |
| `Hop.Endpoint.on(svc, fun)`    | subscribe + poll service requests                           |
| `reply.(status, body)`         | send service response (status is a `uint16`)                |
| `Hop.Endpoint.request(...)`    | send service request + poll service responses               |
| the Internet bearer            | link up / bytes received / drain outgoing                   |

`Hop.TcpBearer` moves opaque frames over `:gen_tcp` with `packet: 4`; core does the Noise handshake and
all crypto over those bytes.

## Examples

Elixir and Erlang come from mise (`.mise.toml` pins them). Rustler compiles the native crate on the first
run:

```sh
mise trust
mise exec -- mix deps.get
mise exec -- mix test                           # round trips + reach record + WSS discovery, all pass
mise exec -- mix run examples/raw_roundtrip.exs # raw round trip through the NIF (Hop.Native)
mise exec -- mix run examples/echo.exs          # the DX in-process
mise exec -- mix run examples/tcp.exs           # the same round trip over a real TCP bearer
mise exec -- mix run examples/discovery.exs     # the full reachable-by-name chain (HTTPS + WSS)
```

Two-process shape (a standalone server plus a client that dials it):

```sh
mise exec -- mix run examples/server.exs                          # prints its address, listens on 9944
mise exec -- mix run examples/client.exs <address> localhost 9944
```

## Status

Prototype. Built and working: `on` / `reply` / `request`, the GenServer pump, the TCP / WSS bearers,
base58 addressing, reach-record `attach` / `dial_by_name` discovery, and sibling-replica clustering. HNS
name publish/resolve and multi-tenant hosting are on the roadmap (each an SDK-level follow-up, not a core
change).

## The Hop family

`hop_endpoint` is one of several SDKs over the same protocol core. Same surface, your language:
[node](https://github.com/hopmesh/hop-sdk-node) ·
[python](https://github.com/hopmesh/hop-sdk-python) ·
[go](https://github.com/hopmesh/hop-sdk-go) ·
[ruby](https://github.com/hopmesh/hop-sdk-ruby) ·
[crystal](https://github.com/hopmesh/hop-sdk-crystal) ·
[elixir](https://github.com/hopmesh/hop-sdk-elixir).
The protocol core is [libhop](https://github.com/hopmesh/libhop) / [hop-core](https://github.com/hopmesh/hop-core).

## License

[Apache-2.0](./LICENSE.md), embed it freely. Only the protocol core (`hop-core`) is FSL-1.1-ALv2,
source-available and converting to Apache-2.0 after two years.
