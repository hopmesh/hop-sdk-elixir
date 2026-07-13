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
mise exec -- mix test                    # hops:// round trip over a real TCP bearer, must pass
mise exec -- mix run examples/echo.exs   # the DX end to end
```

## Prototype scope

Built and working: `hop.on` / `reply` / `request`, the GenServer pump, the TCP bearer, base58
addressing. Stubbed follow-ups (each additive, none a core change): HNS publish/resolve, delegated
endpoint keys, multi-tenant hosting. Not yet a required CI job. Design: `docs/endpoint-sdk.md`.
