# hop (Elixir endpoint SDK, prototype)

Receive Hop messages in Elixir with a Phoenix/Plug-shaped surface, over `hop-core` via a Rustler NIF.
Same idea as `sdk/node`: your service becomes directly reachable on the mesh, so senders hand messages
straight to it without a relay in the middle.

```elixir
{:ok, ep} = Hop.Endpoint.start_link([])

Hop.Endpoint.on(ep, "acme/orders", fn req, reply ->
  # req.from is a cryptographically VERIFIED identity, not a spoofable header
  order = Jason.decode!(req.args)
  reply.(201, Jason.encode!(%{ok: true, order: order}))   # uint16 status + body
end)

{:ok, _} = Hop.TcpBearer.listen(ep, 9944)   # reachable by any device
IO.puts(Hop.Endpoint.address(ep))           # publish this (or its HNS name)
```

## How it is wired

- `native/hop_endpoint` is a **Rustler NIF** that binds the `hop` crate's public `HopNode` Rust API,
  the same object the C ABI wraps, with its panic guards. Bytes cross as Erlang binaries.
- `Hop.Endpoint` is a `GenServer`: it owns the node, runs the poll-model pump on a timer, dispatches
  inbound `hops://` requests to your handlers, and resolves `request/5` callers when responses return.
- `Hop.TcpBearer` is the Internet bearer: opaque frames over TCP using Erlang's `packet: 4` framing.
  core does the Noise handshake and all crypto over those bytes.

**The DX is HTTP-shaped; the semantics are not.** Inbound is a durable store-and-forward consume; a
reply is a new addressed message that may arrive later. It is a queue consumer, not a synchronous
route, that is what makes it offline-tolerant.

## Run it

Elixir + Erlang come from mise (`.mise.toml` pins them). Build `libhop`'s workspace once; the Rustler
compiler builds the NIF crate on first `mix` run:

```sh
cd sdk/elixir
mise trust
mise exec -- mix deps.get
mise exec -- mix test                             # round trips + reach record + WSS discovery, must pass
mise exec -- mix run examples/raw_roundtrip.exs   # raw C ABI round trip (Hop.Native)
mise exec -- mix run examples/echo.exs            # the DX in-process
mise exec -- mix run examples/tcp.exs             # the same round trip over a real TCP bearer
mise exec -- mix run examples/discovery.exs       # WSS + WebPKI + reach-record discovery (in-process cert)
```

Two-process shape (a standalone server + a client that dials it):

```sh
mise exec -- mix run examples/server.exs                          # prints its address, listens on 9944
mise exec -- mix run examples/client.exs <address> localhost 9944
```

## Reachable by name (WSS + discovery)

Make an endpoint reachable at `myaddress.com` with **no new port and no DNSSEC**, using a WSS bearer
over Erlang's built-in `:ssl` (no WS hex deps):

```elixir
{:ok, _} = Hop.Endpoint.attach(ep, 443, [certfile: cert, keyfile: key], "wss://myaddress.com/_hop")
```

```elixir
address = Hop.Endpoint.dial_by_name(client, "https://myaddress.com")
{:ok, 201, body} = Hop.Endpoint.request(client, address, "acme/orders", "create", order)
```

Trust, no DNSSEC: `dial_by_name` fetches `/.well-known/hop` (TLS proves the domain), verifies the
self-certifying reach record (signed by the address), dials the WSS, and the Noise handshake confirms
the address. `test/discovery_test.exs` proves the full chain against a self-signed HTTPS server.

## Prototype scope

Built and working: `hop.on` / `reply` / `request`, the GenServer pump, TCP + WSS bearers, base58
addressing, reach records + `attach`/`dial_by_name` discovery. Follow-ups (each additive, none a core
change): the no-domain gossip case, delegated endpoint keys, multi-tenant hosting. Not yet a required
CI job. Design: `docs/endpoint-sdk.md`.
