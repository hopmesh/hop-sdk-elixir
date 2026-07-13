defmodule Hop.TcpBearer do
  @moduledoc """
  The Internet bearer for an Elixir endpoint: opaque Hop frames over TCP, core does the Noise. Uses
  Erlang's built-in `packet: 4` length framing, so each send/recv is a whole frame. HNS would resolve
  a name to host/port/key; here you pass them directly.
  """
  @opts [:binary, packet: 4, active: false, reuseaddr: true]

  @doc "Listen for inbound Hop connections; each accepted socket is one bearer link (we are acceptor)."
  def listen(endpoint, port, host \\ {0, 0, 0, 0}) do
    {:ok, lsock} = :gen_tcp.listen(port, [{:ip, host} | @opts])
    spawn_link(fn -> accept_loop(endpoint, lsock) end)
    {:ok, lsock}
  end

  @doc "Dial a reachable endpoint (we are the Noise initiator)."
  def dial(endpoint, host, port) do
    {:ok, sock} = :gen_tcp.connect(to_charlist(host), port, @opts)
    link = new_link()

    :ok =
      Hop.Endpoint.register_link(endpoint, link, :dialer, fn bytes ->
        :gen_tcp.send(sock, bytes)
      end)

    spawn_link(fn -> recv_loop(endpoint, sock, link) end)
    {:ok, sock}
  end

  defp accept_loop(endpoint, lsock) do
    {:ok, sock} = :gen_tcp.accept(lsock)
    link = new_link()

    :ok =
      Hop.Endpoint.register_link(endpoint, link, :acceptor, fn bytes ->
        :gen_tcp.send(sock, bytes)
      end)

    spawn_link(fn -> recv_loop(endpoint, sock, link) end)
    accept_loop(endpoint, lsock)
  end

  defp recv_loop(endpoint, sock, link) do
    case :gen_tcp.recv(sock, 0) do
      {:ok, frame} ->
        Hop.Endpoint.deliver(endpoint, link, frame)
        recv_loop(endpoint, sock, link)

      {:error, _} ->
        Hop.Endpoint.link_down(endpoint, link)
    end
  end

  defp new_link, do: 40_000 + System.unique_integer([:positive, :monotonic])
end
