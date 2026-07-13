# Proves the Internet bearer: a server endpoint LISTENS on a TCP port, a client endpoint DIALS it over
# a real socket, and the hops:// round trip completes over TCP with real Noise. One process, real
# loopback sockets (see server.exs + client.exs for the two-process deployment shape).
#   mise exec -- mix run examples/tcp.exs
{:ok, server} = Hop.Endpoint.start_link([])

Hop.Endpoint.on(server, "acme/orders", fn req, reply ->
  IO.puts("  [server] #{req.service}/#{req.method} over TCP: #{req.args}")
  reply.(201, Jason.encode!(%{ok: true, item: Jason.decode!(req.args)["item"]}))
end)

{:ok, _} = Hop.TcpBearer.listen(server, 9946)
addr = Hop.Endpoint.address(server)
IO.puts("server listening on tcp://localhost:9946  addr=#{String.slice(addr, 0, 12)}")

{:ok, client} = Hop.Endpoint.start_link([])
{:ok, _} = Hop.TcpBearer.dial(client, "localhost", 9946)

{:ok, status, body} =
  Hop.Endpoint.request(client, addr, "acme/orders", "create", Jason.encode!(%{item: "widget"}))

IO.puts("  [client] <- #{status} #{body}")

parsed = Jason.decode!(body)
passed = status == 201 and parsed["ok"] == true and parsed["item"] == "widget"
Hop.Endpoint.close(server)
Hop.Endpoint.close(client)

IO.puts(
  if passed, do: "\nPASS: hops:// round trip over a real TCP Internet bearer.", else: "\nFAIL"
)

System.halt(if passed, do: 0, else: 1)
