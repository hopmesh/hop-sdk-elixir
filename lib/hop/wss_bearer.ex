defmodule Hop.WssBearer do
  @moduledoc """
  The WSS Internet bearer for an Elixir endpoint, over Erlang's built-in `:ssl` (no WS hex deps): a
  minimal RFC 6455 WebSocket (Upgrade handshake + binary framing). The HTTP handshake is read in
  `packet: :line` mode, then the socket switches to `:raw` for frames, so a header read never
  over-consumes into frame bytes. One WS message per drained packet; core does the Noise + crypto.
  The server also answers GET /.well-known/hop on the same port, so attach wires both.
  """
  import Bitwise

  @guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

  # ---- server ----
  def listen(endpoint, port, ssl_opts, public_url, ttl_secs \\ 3600) do
    {:ok, lsock} = :ssl.listen(port, [:binary, {:active, false}, {:reuseaddr, true} | ssl_opts])
    spawn_link(fn -> accept_loop(endpoint, lsock, public_url, ttl_secs) end)
    {:ok, lsock}
  end

  defp accept_loop(endpoint, lsock, public_url, ttl_secs) do
    case :ssl.transport_accept(lsock) do
      {:ok, tsock} ->
        case :ssl.handshake(tsock) do
          {:ok, sock} -> spawn(fn -> serve_conn(endpoint, sock, public_url, ttl_secs) end)
          _ -> :ok
        end

        accept_loop(endpoint, lsock, public_url, ttl_secs)

      _ ->
        :ok
    end
  end

  defp serve_conn(endpoint, sock, public_url, ttl_secs) do
    :ssl.setopts(sock, packet: :line)
    {{_method, path}, headers} = read_http(sock, nil, %{})

    cond do
      path == "/.well-known/hop" ->
        body = Hop.Discovery.well_known_body(endpoint, public_url, ttl_secs)

        :ssl.send(sock, [
          "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ",
          Integer.to_string(byte_size(body)),
          "\r\nconnection: close\r\n\r\n",
          body
        ])

        :ssl.close(sock)

      path == "/_hop" and String.downcase(Map.get(headers, "upgrade", "")) == "websocket" ->
        accept = accept_key(Map.fetch!(headers, "sec-websocket-key"))

        :ssl.send(
          sock,
          "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: #{accept}\r\n\r\n"
        )

        :ssl.setopts(sock, packet: :raw)
        run_link(endpoint, sock, :acceptor, false)

      true ->
        :ssl.send(sock, "HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n")
        :ssl.close(sock)
    end
  rescue
    _ -> (:ssl.close(sock); :ok)
  end

  defp read_http(sock, req_line, headers) do
    {:ok, raw} = :ssl.recv(sock, 0)
    line = String.trim_trailing(raw, "\r\n")

    cond do
      line == "" -> {parse_req_line(req_line), headers}
      req_line == nil -> read_http(sock, line, headers)
      true ->
        [k, v] = String.split(line, ":", parts: 2)
        read_http(sock, req_line, Map.put(headers, k |> String.trim() |> String.downcase(), String.trim(v)))
    end
  end

  defp parse_req_line(line) do
    [method, path | _] = String.split(line, " ")
    {method, path}
  end

  # ---- client ----
  def dial(endpoint, wss_url, ssl_opts) do
    %URI{host: host, port: port, path: path} = URI.parse(wss_url)
    {:ok, sock} = :ssl.connect(String.to_charlist(host), port || 443, [:binary, {:active, false} | ssl_opts])
    key = Base.encode64(:crypto.strong_rand_bytes(16))

    :ssl.send(sock, [
      "GET ",
      path || "/_hop",
      " HTTP/1.1\r\nHost: ",
      host,
      "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ",
      key,
      "\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ])

    :ssl.setopts(sock, packet: :line)
    {:ok, status} = :ssl.recv(sock, 0)
    unless String.contains?(status, "101"), do: raise("WS upgrade failed: #{String.trim(status)}")
    drain_headers(sock)
    :ssl.setopts(sock, packet: :raw)
    spawn(fn -> run_link(endpoint, sock, :dialer, true) end)
    {:ok, sock}
  end

  defp drain_headers(sock) do
    {:ok, line} = :ssl.recv(sock, 0)
    if String.trim_trailing(line, "\r\n") == "", do: :ok, else: drain_headers(sock)
  end

  # ---- link + framing ----
  defp run_link(endpoint, sock, role, mask?) do
    link = System.unique_integer([:positive, :monotonic]) + 60_000
    Hop.Endpoint.register_link(endpoint, link, role, fn buf -> :ssl.send(sock, encode_frame(buf, mask?)) end)
    loop_frames(endpoint, sock, link)
  end

  defp loop_frames(endpoint, sock, link) do
    case read_frame(sock) do
      {:ok, opcode, payload} when opcode in [0x2, 0x0] ->
        Hop.Endpoint.deliver(endpoint, link, payload)
        loop_frames(endpoint, sock, link)

      {:ok, 0x8, _} ->
        Hop.Endpoint.link_down(endpoint, link)
        :ssl.close(sock)

      {:ok, _other, _} ->
        loop_frames(endpoint, sock, link)

      {:error, _} ->
        Hop.Endpoint.link_down(endpoint, link)
        :ssl.close(sock)
    end
  end

  defp accept_key(key), do: Base.encode64(:crypto.hash(:sha, key <> @guid))

  defp encode_frame(payload, mask?) do
    n = byte_size(payload)

    {lb, ext} =
      cond do
        n < 126 -> {n, <<>>}
        n < 65_536 -> {126, <<n::16>>}
        true -> {127, <<n::64>>}
      end

    mbit = if mask?, do: 1, else: 0
    header = <<1::1, 0::3, 2::4, mbit::1, lb::7, ext::binary>>

    if mask? do
      mk = :crypto.strong_rand_bytes(4)
      header <> mk <> apply_mask(payload, mk)
    else
      header <> payload
    end
  end

  defp read_frame(sock) do
    case :ssl.recv(sock, 2) do
      {:ok, <<b0, b1>>} ->
        opcode = b0 &&& 0x0F
        masked = (b1 &&& 0x80) != 0
        len = decode_len(sock, b1 &&& 0x7F)
        mask = if masked, do: recv_n(sock, 4), else: nil
        payload = if len == 0, do: <<>>, else: recv_n(sock, len)
        payload = if mask, do: apply_mask(payload, mask), else: payload
        {:ok, opcode, payload}

      {:error, e} ->
        {:error, e}
    end
  end

  defp decode_len(_sock, n) when n < 126, do: n

  defp decode_len(sock, 126) do
    <<n::16>> = recv_n(sock, 2)
    n
  end

  defp decode_len(sock, 127) do
    <<n::64>> = recv_n(sock, 8)
    n
  end

  defp recv_n(sock, n) do
    {:ok, data} = :ssl.recv(sock, n)
    data
  end

  defp apply_mask(data, mask), do: apply_mask(data, mask, 0, <<>>)
  defp apply_mask(<<>>, _mask, _i, acc), do: acc

  defp apply_mask(<<b, rest::binary>>, mask, i, acc) do
    apply_mask(rest, mask, i + 1, <<acc::binary, bxor(b, :binary.at(mask, rem(i, 4)))>>)
  end
end
