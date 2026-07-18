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
  @max_message_bytes 1 <<< 20
  @max_header_bytes 16 <<< 10
  @max_pending_connections 64
  @handshake_workers 4
  @handshake_timeout_ms 5_000
  @read_timeout_ms 15_000

  def limits do
    %{
      max_message_bytes: @max_message_bytes,
      max_header_bytes: @max_header_bytes,
      max_pending_connections: @max_pending_connections,
      handshake_workers: @handshake_workers,
      handshake_timeout_ms: @handshake_timeout_ms,
      read_timeout_ms: @read_timeout_ms
    }
  end

  # ---- server ----
  def listen(endpoint, port, ssl_opts, public_url, ttl_secs \\ 3600) do
    {:ok, lsock} =
      :ssl.listen(
        port,
        [
          :binary,
          {:active, false},
          {:reuseaddr, true},
          {:backlog, @max_pending_connections}
          | ssl_opts
        ]
      )

    admission =
      spawn(fn -> admission_loop(%{}, @handshake_workers, @max_pending_connections) end)

    for _ <- 1..@handshake_workers do
      spawn(fn -> accept_loop(endpoint, lsock, public_url, ttl_secs, admission) end)
    end

    spawn(fn ->
      ref = Process.monitor(endpoint)

      receive do
        {:DOWN, ^ref, :process, ^endpoint, _reason} ->
          :ssl.close(lsock)
          send(admission, :stop)
      end
    end)

    {:ok, lsock}
  end

  defp admission_loop(tokens, acceptors, limit) do
    receive do
      {:admit, from, ref, owner} ->
        if map_size(tokens) < limit do
          send(from, {ref, {:ok, ref}})
          admission_loop(Map.put(tokens, ref, owner), acceptors, limit)
        else
          send(from, {ref, :full})
          admission_loop(tokens, acceptors, limit)
        end

      {:track, token, owner} ->
        tokens = if Map.has_key?(tokens, token), do: Map.put(tokens, token, owner), else: tokens
        admission_loop(tokens, acceptors, limit)

      {:release, token} ->
        admission_loop(Map.delete(tokens, token), acceptors, limit)

      :acceptor_done when acceptors <= 1 ->
        :ok

      :acceptor_done ->
        admission_loop(tokens, acceptors - 1, limit)

      :stop ->
        for {_token, owner} <- tokens, is_pid(owner), do: Process.exit(owner, :kill)
        :ok
    end
  end

  defp admit(admission, owner) do
    ref = make_ref()
    send(admission, {:admit, self(), ref, owner})

    receive do
      {^ref, result} -> result
    after
      @handshake_timeout_ms ->
        release(admission, ref)
        :full
    end
  end

  defp track(admission, token, owner), do: send(admission, {:track, token, owner})
  defp release(admission, token), do: send(admission, {:release, token})

  @doc false
  def admission_for_test(limit) do
    spawn(fn -> admission_loop(%{}, 1, limit) end)
  end

  @doc false
  def admission_try_for_test(admission), do: admit(admission, nil)

  @doc false
  def admission_release_for_test(admission, token), do: release(admission, token)

  defp accept_loop(endpoint, lsock, public_url, ttl_secs, admission) do
    case :ssl.transport_accept(lsock) do
      {:ok, tsock} ->
        deadline = handshake_deadline()

        case admit(admission, self()) do
          {:ok, token} ->
            handoff =
              try do
                case :ssl.handshake(tsock, remaining_ms(deadline)) do
                  {:ok, sock} ->
                    handoff_conn(
                      endpoint,
                      sock,
                      public_url,
                      ttl_secs,
                      admission,
                      token,
                      deadline
                    )

                  _ ->
                    false
                end
              rescue
                _ -> false
              end

            unless handoff do
              :ssl.close(tsock)
              release(admission, token)
            end

          :full ->
            :ssl.close(tsock)
        end

        accept_loop(endpoint, lsock, public_url, ttl_secs, admission)

      _ ->
        send(admission, :acceptor_done)
    end
  end

  defp handoff_conn(endpoint, sock, public_url, ttl_secs, admission, token, deadline) do
    owner =
      spawn(fn ->
        receive do
          {:serve, ^sock} ->
            try do
              serve_conn(endpoint, sock, public_url, ttl_secs, deadline)
            after
              :ssl.close(sock)
              release(admission, token)
            end
        end
      end)

    spawn(fn -> watch_owner(endpoint, owner, admission, token) end)

    case :ssl.controlling_process(sock, owner) do
      :ok ->
        track(admission, token, owner)
        send(owner, {:serve, sock})
        true

      _ ->
        Process.exit(owner, :kill)
        false
    end
  end

  defp watch_owner(endpoint, owner, admission, token) do
    endpoint_ref = Process.monitor(endpoint)
    owner_ref = Process.monitor(owner)

    receive do
      {:DOWN, ^endpoint_ref, :process, ^endpoint, _reason} ->
        Process.exit(owner, :kill)
        release(admission, token)

      {:DOWN, ^owner_ref, :process, ^owner, _reason} ->
        Process.demonitor(endpoint_ref, [:flush])
    end
  end

  defp serve_conn(endpoint, sock, public_url, ttl_secs, deadline) do
    :ssl.setopts(sock, packet: :line, packet_size: @max_header_bytes)
    {{_method, path}, headers} = read_http(sock, nil, %{}, 0, deadline)

    cond do
      path == "/.well-known/hop" ->
        body = Hop.Discovery.well_known_body(endpoint, public_url, ttl_secs)

        :ssl.send(sock, [
          "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ",
          Integer.to_string(byte_size(body)),
          "\r\nconnection: close\r\n\r\n",
          body
        ])

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
    end
  rescue
    _ -> :ok
  end

  defp read_http(sock, req_line, headers, bytes, deadline) do
    {:ok, raw} = :ssl.recv(sock, 0, remaining_ms(deadline))
    bytes = bytes + byte_size(raw)
    if bytes > @max_header_bytes, do: raise("HTTP headers exceed 16 KiB")
    line = String.trim_trailing(raw, "\r\n")

    cond do
      line == "" ->
        {parse_req_line(req_line), headers}

      req_line == nil ->
        read_http(sock, line, headers, bytes, deadline)

      true ->
        [k, v] = String.split(line, ":", parts: 2)

        read_http(
          sock,
          req_line,
          Map.put(headers, k |> String.trim() |> String.downcase(), String.trim(v)),
          bytes,
          deadline
        )
    end
  end

  defp parse_req_line(line) do
    [method, path | _] = String.split(line, " ")
    {method, path}
  end

  # ---- client ----
  def dial(endpoint, wss_url, ssl_opts) do
    %URI{host: host, port: port, path: path} = URI.parse(wss_url)
    deadline = handshake_deadline()

    {:ok, sock} =
      :ssl.connect(
        String.to_charlist(host),
        port || 443,
        [:binary, {:active, false} | ssl_opts],
        remaining_ms(deadline)
      )

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

    :ssl.setopts(sock, packet: :line, packet_size: @max_header_bytes)
    {:ok, status} = :ssl.recv(sock, 0, remaining_ms(deadline))
    unless String.contains?(status, "101"), do: raise("WS upgrade failed: #{String.trim(status)}")
    drain_headers(sock, byte_size(status), deadline)
    :ssl.setopts(sock, packet: :raw)

    owner =
      spawn(fn -> receive do: ({:run, ^sock} -> run_link(endpoint, sock, :dialer, true)) end)

    :ok = :ssl.controlling_process(sock, owner)
    send(owner, {:run, sock})
    {:ok, sock}
  end

  defp drain_headers(sock, bytes, deadline) do
    {:ok, line} = :ssl.recv(sock, 0, remaining_ms(deadline))
    bytes = bytes + byte_size(line)
    if bytes > @max_header_bytes, do: raise("HTTP headers exceed 16 KiB")

    if String.trim_trailing(line, "\r\n") == "",
      do: :ok,
      else: drain_headers(sock, bytes, deadline)
  end

  defp handshake_deadline,
    do: System.monotonic_time(:millisecond) + @handshake_timeout_ms

  defp remaining_ms(deadline) do
    case deadline - System.monotonic_time(:millisecond) do
      remaining when remaining > 0 -> remaining
      _ -> 0
    end
  end

  # ---- link + framing ----
  defp run_link(endpoint, sock, role, mask?) do
    link = System.unique_integer([:positive, :monotonic]) + 60_000

    Hop.Endpoint.register_link(endpoint, link, role, fn buf ->
      if byte_size(buf) <= @max_message_bytes,
        do: :ssl.send(sock, encode_frame(buf, mask?)),
        else: :ssl.close(sock)
    end)

    try do
      loop_messages(endpoint, sock, link)
    after
      Hop.Endpoint.link_down(endpoint, link)
      :ssl.close(sock)
    end
  end

  defp loop_messages(endpoint, sock, link) do
    case read_message(sock) do
      {:ok, 0x2, payload} ->
        Hop.Endpoint.deliver(endpoint, link, payload)
        loop_messages(endpoint, sock, link)

      {:ok, 0x8, _} ->
        :ok

      {:ok, _other, _} ->
        loop_messages(endpoint, sock, link)

      {:error, _} ->
        :ok
    end
  end

  defp accept_key(key), do: Base.encode64(:crypto.hash(:sha, key <> @guid))

  defp encode_frame(payload, mask?) do
    n = byte_size(payload)
    if n > @max_message_bytes, do: raise("WebSocket message exceeds 1 MiB")

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

  defp read_message(sock) do
    deadline = System.monotonic_time(:millisecond) + @read_timeout_ms

    try do
      {final, opcode, payload} = read_frame_part(sock, @max_message_bytes, deadline)

      cond do
        opcode >= 0x8 -> {:ok, opcode, payload}
        opcode != 0x2 -> {:error, :expected_binary}
        final -> {:ok, opcode, payload}
        true -> read_continuations(sock, deadline, byte_size(payload), [payload])
      end
    rescue
      e -> {:error, e}
    end
  end

  defp read_continuations(sock, deadline, total, chunks) do
    {final, opcode, payload} = read_frame_part(sock, @max_message_bytes - total, deadline)
    if opcode != 0x0, do: raise("expected a WebSocket continuation frame")
    total = total + byte_size(payload)
    chunks = [payload | chunks]

    if final,
      do: {:ok, 0x2, chunks |> Enum.reverse() |> IO.iodata_to_binary()},
      else: read_continuations(sock, deadline, total, chunks)
  end

  defp read_frame_part(sock, remaining, deadline) do
    <<b0, b1>> = recv_n(sock, 2, deadline)
    if (b0 &&& 0x70) != 0, do: raise("WebSocket extensions are not supported")

    final = (b0 &&& 0x80) != 0
    opcode = b0 &&& 0x0F
    masked = (b1 &&& 0x80) != 0
    len = decode_len(sock, b1 &&& 0x7F, deadline)
    if len > remaining or len > @max_message_bytes, do: raise("WebSocket message exceeds 1 MiB")
    if opcode >= 0x8 and (not final or len > 125), do: raise("invalid WebSocket control frame")

    mask = if masked, do: recv_n(sock, 4, deadline), else: nil
    payload = if len == 0, do: <<>>, else: recv_n(sock, len, deadline)
    payload = if mask, do: apply_mask(payload, mask), else: payload
    {final, opcode, payload}
  end

  defp decode_len(_sock, n, _deadline) when n < 126, do: n

  defp decode_len(sock, 126, deadline) do
    <<n::16>> = recv_n(sock, 2, deadline)
    n
  end

  defp decode_len(sock, 127, deadline) do
    <<n::64>> = recv_n(sock, 8, deadline)
    n
  end

  defp recv_n(sock, n, deadline) do
    timeout = deadline - System.monotonic_time(:millisecond)
    if timeout <= 0, do: raise("WebSocket read deadline exceeded")

    case :ssl.recv(sock, n, timeout) do
      {:ok, data} -> data
      {:error, reason} -> raise("WebSocket read failed: #{inspect(reason)}")
    end
  end

  defp apply_mask(data, mask) do
    repeats = div(byte_size(data) + 3, 4)
    stream = :binary.part(:binary.copy(mask, repeats), 0, byte_size(data))
    :crypto.exor(data, stream)
  end
end
