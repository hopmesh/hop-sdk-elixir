defmodule Hop.EndpointTest do
  use ExUnit.Case, async: false

  test "hops:// request/response round trip over a real TCP bearer" do
    port = 9955
    {:ok, server} = Hop.Endpoint.start_link([])
    Hop.Endpoint.on(server, "acme/orders", fn req, reply -> reply.(201, "got:" <> req.args) end)
    {:ok, _} = Hop.TcpBearer.listen(server, port)
    addr = Hop.Endpoint.address(server)
    assert is_binary(addr) and byte_size(addr) > 30

    {:ok, client} = Hop.Endpoint.start_link([])
    {:ok, _} = Hop.TcpBearer.dial(client, "localhost", port)

    assert {:ok, 201, "got:temp=21"} =
             Hop.Endpoint.request(client, addr, "acme/orders", "create", "temp=21")
  end
end
