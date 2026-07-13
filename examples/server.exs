# A standalone, self-hostable Hop endpoint (the two-process deployment shape). Run this, then run
# client.exs with the address it prints. In production HNS would resolve a name to this host/port/key,
# and you would persist the key so the address is stable across restarts.
#   PORT=9944 mise exec -- mix run examples/server.exs
port = String.to_integer(System.get_env("PORT", "9944"))

{:ok, server} = Hop.Endpoint.start_link([])

Hop.Endpoint.on(server, "acme/orders", fn req, reply ->
  # req.from is the cryptographically VERIFIED sender, not a spoofable header. No auth middleware.
  IO.puts(
    "[server] #{req.service}/#{req.method} from #{String.slice(req.from, 0, 12)}: #{req.args}"
  )

  reply.(201, Jason.encode!(%{ok: true, received: Jason.decode!(req.args)}))
end)

{:ok, _} = Hop.TcpBearer.listen(server, port)
IO.puts("hop endpoint listening on tcp://0.0.0.0:#{port}")
IO.puts("address: #{Hop.Endpoint.address(server)}")

IO.puts(
  "\ntry it:\n  mise exec -- mix run examples/client.exs #{Hop.Endpoint.address(server)} localhost #{port}"
)

# keep the endpoint (and its pump) alive
Process.sleep(:infinity)
