defmodule Hop.WssSecurityTest do
  use ExUnit.Case, async: false
  import Bitwise

  setup do
    {:ok, endpoint} = Hop.Endpoint.start_link([])
    {:ok, listener} = Hop.Endpoint.attach(endpoint, 0, Hop.DevTls.ssl_opts(), "wss://unused/_hop")
    {:ok, {_address, port}} = :ssl.sockname(listener)

    on_exit(fn ->
      if Process.alive?(endpoint), do: Hop.Endpoint.close(endpoint)
      :ssl.close(listener)
    end)

    %{endpoint: endpoint, listener: listener, port: port}
  end

  test "single and fragmented messages over 1 MiB close before their declared bodies", %{
    port: port
  } do
    max = Hop.WssBearer.limits().max_message_bytes

    single = upgrade(port)
    :ok = :ssl.send(single, frame_header(true, 0x2, max + 1))
    assert_closed(single)

    fragmented = upgrade(port)
    half = div(max, 2)
    :ok = :ssl.send(fragmented, frame(false, 0x2, :binary.copy(<<0x41>>, half + 1)))
    :ok = :ssl.send(fragmented, frame_header(true, 0x0, half))
    assert_closed(fragmented)

    recovered = upgrade(port)
    :ok = :ssl.send(recovered, frame(true, 0x8, <<>>))
    :ssl.close(recovered)
  end

  test "oversized headers and a malformed first request do not poison recovery", %{port: port} do
    max = Hop.WssBearer.limits().max_header_bytes
    oversized = tls_connect(port)

    :ok =
      :ssl.send(oversized, [
        "GET /_hop HTTP/1.1\r\nHost: localhost\r\nX-Fill: ",
        :binary.copy("x", max),
        "\r\n\r\n"
      ])

    assert_closed(oversized)

    malformed = tls_connect(port)
    :ok = :ssl.send(malformed, "malformed\r\n\r\n")
    assert_closed(malformed)

    recovered = upgrade(port)
    :ok = :ssl.send(recovered, frame(true, 0x8, <<>>))
    :ssl.close(recovered)
  end

  test "a stalled TLS client cannot serialize the accept loop", %{port: port} do
    {:ok, stalled} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)

    recovered = upgrade(port)
    :ok = :ssl.send(recovered, frame(true, 0x8, <<>>))
    :ssl.close(recovered)
    :gen_tcp.close(stalled)

    again = upgrade(port)
    :ok = :ssl.send(again, frame(true, 0x8, <<>>))
    :ssl.close(again)
  end

  test "slow trickle headers cannot reset the absolute five-second handshake budget", %{
    port: port
  } do
    slow = tls_connect(port)
    :ok = :ssl.send(slow, "GET /_hop HTTP/1.1\r\nHost: localhost\r\n")

    for _ <- 1..6 do
      Process.sleep(900)
      :ssl.send(slow, "X-Slow: x\r\n")
    end

    assert_strictly_closed(slow)
    recovered = upgrade(port)
    :ok = :ssl.send(recovered, frame(true, 0x8, <<>>))
    :ssl.close(recovered)
  end

  test "endpoint close tears down an admitted WebSocket", %{endpoint: endpoint, port: port} do
    sock = upgrade(port)
    :ok = Hop.Endpoint.close(endpoint)
    assert_strictly_closed(sock)
  end

  test "pending admission rejects cap plus one and duplicate cleanup releases once" do
    limit = Hop.WssBearer.limits().max_pending_connections
    admission = Hop.WssBearer.admission_for_test(limit)

    tokens =
      for _ <- 1..limit do
        assert {:ok, token} = Hop.WssBearer.admission_try_for_test(admission)
        token
      end

    assert :full = Hop.WssBearer.admission_try_for_test(admission)
    Hop.WssBearer.admission_release_for_test(admission, hd(tokens))
    Hop.WssBearer.admission_release_for_test(admission, hd(tokens))
    assert {:ok, replacement} = Hop.WssBearer.admission_try_for_test(admission)
    assert :full = Hop.WssBearer.admission_try_for_test(admission)

    Hop.WssBearer.admission_release_for_test(admission, replacement)
    Enum.each(tl(tokens), &Hop.WssBearer.admission_release_for_test(admission, &1))
    send(admission, :stop)
  end

  defp tls_connect(port) do
    {:ok, sock} =
      :ssl.connect(
        ~c"localhost",
        port,
        [:binary, active: false, verify: :verify_none],
        2_000
      )

    sock
  end

  defp upgrade(port) do
    sock = tls_connect(port)
    key = Base.encode64(:crypto.strong_rand_bytes(16))

    :ok =
      :ssl.send(sock, [
        "GET /_hop HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n",
        "Connection: Upgrade\r\nSec-WebSocket-Key: ",
        key,
        "\r\nSec-WebSocket-Version: 13\r\n\r\n"
      ])

    :ok = :ssl.setopts(sock, packet: :line, packet_size: Hop.WssBearer.limits().max_header_bytes)
    assert {:ok, status} = :ssl.recv(sock, 0, 2_000)
    assert String.contains?(status, "101")
    drain_headers(sock)
    :ok = :ssl.setopts(sock, packet: :raw)
    sock
  end

  defp drain_headers(sock) do
    assert {:ok, line} = :ssl.recv(sock, 0, 2_000)
    unless String.trim_trailing(line, "\r\n") == "", do: drain_headers(sock)
  end

  defp assert_closed(sock) do
    assert {:error, reason} = :ssl.recv(sock, 0, 2_000)
    assert reason in [:closed, :timeout] or match?({:tls_alert, {:close_notify, _}}, reason)
    :ssl.close(sock)
  end

  defp assert_strictly_closed(sock) do
    assert {:error, reason} = :ssl.recv(sock, 0, 2_000)
    refute reason == :timeout
    :ssl.close(sock)
  end

  defp frame(final, opcode, payload),
    do: frame_header(final, opcode, byte_size(payload)) <> payload

  defp frame_header(final, opcode, length) do
    first = if(final, do: 0x80, else: 0x00) ||| opcode

    cond do
      length < 126 -> <<first, length>>
      length < 65_536 -> <<first, 126, length::16>>
      true -> <<first, 127, length::64>>
    end
  end
end
