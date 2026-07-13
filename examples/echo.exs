# The Elixir DX on real hop-core, over a TCP bearer. Run with:
#   mise exec -- mix run examples/echo.exs
{:ok, server} = Hop.Endpoint.start_link([])

Hop.Endpoint.on(server, "acme/orders", fn req, reply ->
  IO.puts("  [server] #{req.service}/#{req.method} from #{String.slice(req.from, 0, 10)}: #{req.args}")
  reply.(201, "ok:" <> req.args)
end)

{:ok, _} = Hop.TcpBearer.listen(server, 9946)
addr = Hop.Endpoint.address(server)
IO.puts("server listening on tcp://localhost:9946  addr=#{String.slice(addr, 0, 12)}")

{:ok, client} = Hop.Endpoint.start_link([])
{:ok, _} = Hop.TcpBearer.dial(client, "localhost", 9946)

{:ok, status, body} = Hop.Endpoint.request(client, addr, "acme/orders", "create", "widget")
IO.puts("  [client] <- #{status} #{body}")
if status == 201 and body == "ok:widget", do: IO.puts("\nPASS"), else: IO.puts("\nFAIL")
