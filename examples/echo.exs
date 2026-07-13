# The Phoenix/Plug-shaped DX, running on real hop-core, in-process. A server endpoint registers a
# receiver; a client calls it and gets a reply. Delivery is delay-tolerant underneath.
#   mise exec -- mix run examples/echo.exs
{:ok, server} = Hop.Endpoint.start_link([])
{:ok, client} = Hop.Endpoint.start_link([])

# --- this is the whole server: mount a receiver, reply with a status + body ---
Hop.Endpoint.on(server, "acme/orders", fn req, reply ->
  IO.puts(
    "  [server] #{req.service}/#{req.method} from #{String.slice(req.from, 0, 10)} body=#{req.args}"
  )

  order = Jason.decode!(req.args)
  reply.(200, Jason.encode!(%{ok: true, id: 42, item: order["item"]}))
end)

# wire the two endpoints together (in-process bearer; swap for TCP to make it reachable by any device)
Hop.Endpoint.register_link(server, 11, :dialer, fn buf ->
  Hop.Endpoint.deliver(client, 22, buf)
end)

Hop.Endpoint.register_link(client, 22, :acceptor, fn buf ->
  Hop.Endpoint.deliver(server, 11, buf)
end)

addr = Hop.Endpoint.address(server)
IO.puts("server address: #{addr}")
IO.puts("client address: #{Hop.Endpoint.address(client)}")

# --- client calls the service, like an HTTP request, but forward-secret + delay-tolerant ---
{:ok, status, body} =
  Hop.Endpoint.request(client, addr, "acme/orders", "create", Jason.encode!(%{item: "widget"}))

IO.puts("  [client] <- #{status} #{body}")

parsed = Jason.decode!(body)
passed = status == 200 and parsed["ok"] == true and parsed["item"] == "widget"
Hop.Endpoint.close(server)
Hop.Endpoint.close(client)

IO.puts(
  if passed,
    do: "\nPASS: Endpoint.on(service) + reply.(status, body) over real hop-core.",
    else: "\nFAIL"
)

System.halt(if passed, do: 0, else: 1)
