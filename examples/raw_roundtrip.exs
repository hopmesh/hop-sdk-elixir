# Derisking proof: the hops:// service round trip through the raw Hop.Native NIFs, mirroring the C ABI.
# Two nodes, a byte-pipe bearer, a request in, 200 + body back out.
#   mise exec -- mix run examples/raw_roundtrip.exs
alias Hop.Native, as: N

la = 11
lb = 22

pump = fn pump, a, b ->
  out_a = N.drain_outgoing(a)
  Enum.each(out_a, fn {_l, buf} -> N.received(b, lb, buf) end)
  out_b = N.drain_outgoing(b)
  Enum.each(out_b, fn {_l, buf} -> N.received(a, la, buf) end)
  if out_a != [] or out_b != [], do: pump.(pump, a, b), else: :ok
end

a = N.open_ephemeral()
b = N.open_ephemeral()

N.tick(a, 1000)
N.tick(b, 1000)
N.connected(a, la, true)
N.connected(b, lb, false)
pump.(pump, a, b)
N.publish_prekey(a)
N.publish_prekey(b)
pump.(pump, a, b)

b_addr = N.address(b)
req_id = N.send_service_request(a, b_addr, "weather", "report", "temp=21")
pump.(pump, a, b)

[{frm, rid, service, method, args} | _] = N.take_service_requests(b)
IO.puts("B received: #{service}/#{method} = #{args} from #{String.slice(N.to_b58(frm), 0, 12)}")

N.send_service_response(b, frm, rid, 200, "stored")
pump.(pump, a, b)

[{_rf, for_id, status, body} | _] = N.take_service_responses(a)
IO.puts("A got response: #{status} #{body}  ties to reqId: #{for_id == req_id}")

passed = service == "weather" and status == 200 and body == "stored" and for_id == req_id

IO.puts(
  if passed, do: "\nPASS: full hops:// round trip through hop-core from Elixir.", else: "\nFAIL"
)

System.halt(if passed, do: 0, else: 1)
