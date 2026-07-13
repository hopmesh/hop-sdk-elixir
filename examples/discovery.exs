# Proves the full DNS-free discovery chain: a client resolves a domain by name, the TLS cert proves the
# domain (WebPKI), the served reach record self-certifies the address, and the WSS handshake confirms
# it, then a hops:// round trip runs over the WebSocket. One process, a real self-signed HTTPS server
# (production uses a real cert; here we accept the in-process self-signed one with insecure_tls).
#   mise exec -- mix run examples/discovery.exs
port = 8443
public_url = "wss://localhost:#{port}/_hop"

# self-signed cert for localhost, generated IN-PROCESS (no openssl CLI); production has a real WebPKI cert
ssl_opts = Hop.DevTls.ssl_opts()

# --- the server: an HTTPS server (wss /_hop + GET /.well-known/hop), wired in ONE call ---
{:ok, server} = Hop.Endpoint.start_link([])

Hop.Endpoint.on(server, "acme/orders", fn req, reply ->
  IO.puts(
    "  [server] #{req.service}/#{req.method} from #{String.slice(req.from, 0, 10)}: #{req.args}"
  )

  reply.(201, req.args)
end)

{:ok, _lsock} = Hop.Endpoint.attach(server, port, ssl_opts, public_url)

IO.puts(
  "endpoint on https://localhost:#{port} (well-known + wss)  addr=#{String.slice(Hop.Endpoint.address(server), 0, 12)}"
)

# --- the client: resolve by NAME, verifying the record, then round-trip over WSS ---
{:ok, client} = Hop.Endpoint.start_link([])
address = Hop.Endpoint.dial_by_name(client, "https://localhost:#{port}", insecure_tls: true)

IO.puts(
  "  [client] resolved the domain -> #{String.slice(address, 0, 12)} (reach record verified)"
)

{:ok, status, body} = Hop.Endpoint.request(client, address, "acme/orders", "create", "widget")
IO.puts("  [client] <- #{status} #{body}")

passed = status == 201 and body == "widget"
Hop.Endpoint.close(server)
Hop.Endpoint.close(client)

IO.puts(
  if passed, do: "\nPASS: name -> verified address -> WSS hops:// round trip.", else: "\nFAIL"
)

System.halt(if passed, do: 0, else: 1)
