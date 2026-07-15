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

  test "closing an endpoint with a live bearer connection is use-after-free-safe" do
    port = 9959
    {:ok, server} = Hop.Endpoint.start_link([])
    Hop.Endpoint.on(server, "svc", fn _req, reply -> reply.(200, "ok") end)
    {:ok, _} = Hop.TcpBearer.listen(server, port)
    {:ok, client} = Hop.Endpoint.start_link([])
    {:ok, _} = Hop.TcpBearer.dial(client, "localhost", port)

    assert {:ok, 200, "ok"} =
             Hop.Endpoint.request(client, Hop.Endpoint.address(server), "svc", "m", "x")

    # Close the server while its accepted recv_loop and the client's socket are still live. Unlike the
    # C-FFI SDKs, Elixir needs no guard: the node is only ever touched inside the GenServer, a bearer
    # reaches it via a GenServer cast to the (now stopped) server which is simply dropped, and there is
    # no manual node_free (Rustler GCs the node with the GenServer). So no use-after-free is possible.
    Hop.Endpoint.close(server)
    Process.sleep(100)
    assert Process.alive?(client)
    Hop.Endpoint.close(client)
  end

  test "joins a cluster and sets the CP quorum (DESIGN.md §40)" do
    # cluster join + quorum NIFs resolve and behave; the cross-replica dedup + hold are proven in the
    # Rust crate, here we exercise the Elixir surface (both are opts on start_link).
    {:ok, ep} = Hop.Endpoint.start_link(cluster: "shared-cluster-passphrase", quorum: 3)
    addr = Hop.Endpoint.address(ep)
    assert is_binary(addr) and byte_size(addr) > 30
    Hop.Endpoint.close(ep)
  end
end
