defmodule Hop.DiscoveryTest do
  use ExUnit.Case, async: false
  import Bitwise

  test "reach record sign/verify + tamper-reject" do
    {:ok, e} = Hop.Endpoint.start_link([])
    rec = Hop.Endpoint.sign_reach(e, "wss://myaddress.com/_hop", 3600)

    {valid, address, endpoint, _i, _t} =
      Hop.Native.verify_reach_record(rec, System.system_time(:second))

    assert valid
    assert endpoint == "wss://myaddress.com/_hop"
    assert Hop.Native.to_b58(address) == Hop.Endpoint.address(e)

    n = byte_size(rec)
    bad = :binary.part(rec, 0, n - 1) <> <<bxor(:binary.at(rec, n - 1), 0xFF)>>
    {valid2, _, _, _, _} = Hop.Native.verify_reach_record(bad, System.system_time(:second))
    refute valid2
    Hop.Endpoint.close(e)
  end

  test "dial_by_name resolves + verifies + rounds trip over WSS" do
    port = 8447
    public_url = "wss://localhost:#{port}/_hop"

    {:ok, server} = Hop.Endpoint.start_link([])
    Hop.Endpoint.on(server, "acme/orders", fn req, reply -> reply.(201, req.args) end)
    {:ok, _lsock} = Hop.Endpoint.attach(server, port, Hop.DevTls.ssl_opts(), public_url)

    {:ok, client} = Hop.Endpoint.start_link([])
    address = Hop.Endpoint.dial_by_name(client, "https://localhost:#{port}", insecure_tls: true)
    assert address == Hop.Endpoint.address(server)

    assert {:ok, 201, "widget"} =
             Hop.Endpoint.request(client, address, "acme/orders", "create", "widget")

    Hop.Endpoint.close(server)
    Hop.Endpoint.close(client)
  end
end
