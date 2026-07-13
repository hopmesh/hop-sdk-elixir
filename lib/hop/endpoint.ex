defmodule Hop.Request do
  @moduledoc "An inbound service request. `from` is the cryptographically verified sender identity."
  defstruct [:from, :from_bytes, :service, :method, :args]

  @type t :: %__MODULE__{
          from: String.t(),
          from_bytes: binary(),
          service: String.t(),
          method: String.t(),
          args: binary()
        }
end

defmodule Hop.Endpoint do
  @moduledoc """
  Receive Hop messages in Elixir with a Phoenix/Plug-shaped surface, over hop-core (via Rustler).

      {:ok, ep} = Hop.Endpoint.start_link([])
      Hop.Endpoint.on(ep, "acme/orders", fn req, reply ->
        # req.from is a VERIFIED identity, not a spoofable header
        reply.(201, Jason.encode!(%{ok: true}))
      end)
      {:ok, _} = Hop.TcpBearer.listen(ep, 9944)   # reachable by any device

  Semantics: inbound is a durable store-and-forward consume, and a reply is a new addressed message
  that may arrive later. The DX is HTTP-shaped; delivery is delay-tolerant. core is poll-model, so
  this GenServer runs a pump on a timer.
  """
  use GenServer
  alias Hop.Native

  # ---- public API ----
  def start_link(opts \\ []), do: GenServer.start_link(__MODULE__, opts, name: opts[:name])

  @doc "Register a receiver for a hops:// service. `fun` is `(%Hop.Request{}, reply_fun) -> any`."
  def on(pid, service, fun), do: GenServer.call(pid, {:on, service, fun})

  @doc "This endpoint's base58 address (publish this, or its HNS name)."
  def address(pid), do: GenServer.call(pid, :address)

  @doc "Call a service on a remote endpoint. Blocks until the response returns (delay-tolerant)."
  def request(pid, dst, service, method, args \\ "", timeout \\ 15_000) do
    GenServer.call(pid, {:request, dst, service, method, args, timeout}, timeout + 1_000)
  end

  def close(pid), do: GenServer.stop(pid)

  @doc "Sign a self-certifying reachability record for this endpoint's address bound to `endpoint`."
  def sign_reach(pid, endpoint, ttl_secs \\ 3600),
    do: GenServer.call(pid, {:sign_reach, endpoint, ttl_secs})

  @doc """
  Wire this endpoint into an HTTPS server IN ONE CALL: the WSS bearer at /_hop and the /.well-known/hop
  discovery responder, on `port` with `ssl_opts` (an `:ssl` server config). `public_url` is where
  senders reach it, e.g. "wss://myaddress.com/_hop". Returns the listen socket.
  """
  def attach(pid, port, ssl_opts, public_url, ttl_secs \\ 3600) do
    Hop.WssBearer.listen(pid, port, ssl_opts, public_url, ttl_secs)
  end

  @doc """
  Resolve a base HTTPS URL to a verified endpoint, dial its WSS, and return the reachable address
  (then use request/6). `insecure_tls: true` only for a dev/self-signed cert.
  """
  def dial_by_name(pid, base_url, opts \\ []) do
    {address, wss_url} = Hop.Discovery.resolve(base_url, opts)

    ssl_opts =
      if Keyword.get(opts, :insecure_tls, false),
        do: [verify: :verify_none],
        else: [verify: :verify_peer, cacerts: :public_key.cacerts_get()]

    {:ok, _sock} = Hop.WssBearer.dial(pid, wss_url, ssl_opts)
    address
  end

  # ---- bearer seam (used by Hop.TcpBearer) ----
  def register_link(pid, link, role, send_fun),
    do: GenServer.call(pid, {:register_link, link, role, send_fun})

  def deliver(pid, link, bytes), do: GenServer.cast(pid, {:deliver, link, bytes})
  def link_down(pid, link), do: GenServer.cast(pid, {:link_down, link})

  # ---- GenServer ----
  @impl true
  def init(opts) do
    node =
      case opts[:key] do
        nil -> Native.open_ephemeral()
        key -> Native.open_with_secret(key)
      end

    Native.tick(node, now())
    Native.publish_prekey(node)
    {:ok, _} = :timer.send_interval(opts[:tick_ms] || 50, :pump)
    {:ok, %{node: node, handlers: %{}, links: %{}, pending: %{}}}
  end

  @impl true
  def handle_call({:on, service, fun}, _from, st) do
    Native.subscribe(st.node, service)
    {:reply, :ok, %{st | handlers: Map.put(st.handlers, service, fun)}}
  end

  def handle_call(:address, _from, st), do: {:reply, Native.to_b58(Native.address(st.node)), st}

  def handle_call({:sign_reach, endpoint, ttl}, _from, st),
    do: {:reply, Native.sign_reach_record(st.node, endpoint, ttl), st}

  def handle_call({:register_link, link, role, send_fun}, _from, st) do
    Native.connected(st.node, link, role == :dialer)
    {:reply, :ok, %{st | links: Map.put(st.links, link, send_fun)}}
  end

  def handle_call({:request, dst, service, method, args, timeout}, from, st) do
    case try_send_request(st.node, dst, service, method, args) do
      {:ok, req_id} ->
        # Stamp the waiter with the CALLER's own deadline (monotonic, so an NTP step can't prune it
        # early), so the pump prunes it exactly when the caller's GenServer.call timeout has fired -
        # never before (audit LOW: a fixed 300s TTL dropped a still-valid waiter of a >300s-timeout
        # caller, and a leaked entry would grow st.pending unboundedly).
        deadline = System.monotonic_time(:millisecond) + timeout + 1_000
        {:noreply, %{st | pending: Map.put(st.pending, req_id, {from, deadline})}}

      {:error, reason} ->
        # A send that raises in the NIF must fail ONLY this caller, not crash the endpoint GenServer
        # and take down every other in-flight caller with it (audit LOW: fault-isolation break).
        {:reply, {:error, reason}, st}
    end
  end

  @impl true
  def handle_cast({:deliver, link, bytes}, st) do
    Native.received(st.node, link, bytes)
    {:noreply, st}
  end

  def handle_cast({:link_down, link}, st) do
    Native.disconnected(st.node, link)
    {:noreply, %{st | links: Map.delete(st.links, link)}}
  end

  @impl true
  def handle_info(:pump, st) do
    Native.tick(st.node, now())

    # outbound frames -> the owning bearer
    for {link, bytes} <- Native.drain_outgoing(st.node) do
      case st.links[link] do
        nil -> :ok
        send_fun -> send_fun.(bytes)
      end
    end

    # inbound requests -> handlers
    for {from, req_id, service, method, args} <- Native.take_service_requests(st.node) do
      case st.handlers[service] do
        nil ->
          :ok

        fun ->
          req = %Hop.Request{
            from: Native.to_b58(from),
            from_bytes: from,
            service: service,
            method: method,
            args: args
          }

          reply = fn status, body ->
            Native.send_service_response(st.node, from, req_id, status, to_bin(body))
          end

          fun.(req, reply)
      end
    end

    # inbound responses -> resolve pending callers
    st =
      Enum.reduce(Native.take_service_responses(st.node), st, fn {_from, for_id, status, body},
                                                                 acc ->
        case acc.pending[for_id] do
          nil ->
            acc

          {caller, _ts} ->
            GenServer.reply(caller, {:ok, status, body})
            %{acc | pending: Map.delete(acc.pending, for_id)}
        end
      end)

    # Prune waiters past their caller's deadline (audit LOW: bounds st.pending so a timed-out caller's
    # entry can't leak it), using monotonic time so the deadline comparison is NTP-immune.
    now_mono = System.monotonic_time(:millisecond)
    pending = for {rid, {c, dl}} <- st.pending, dl > now_mono, into: %{}, do: {rid, {c, dl}}

    {:noreply, %{st | pending: pending}}
  end

  @impl true
  def terminate(_reason, st) do
    # Unblock any in-flight callers on close so they fail fast instead of waiting out their call timeout.
    for {_rid, {caller, _ts}} <- st.pending, do: GenServer.reply(caller, {:error, :closed})
    :ok
  end

  # ---- helpers ----
  # Send a service request, converting a raising NIF error (e.g. an unsealable dst) into a value so one
  # caller's bad input can't crash the endpoint GenServer and every other in-flight caller with it.
  defp try_send_request(node, dst, service, method, args) do
    {:ok, Native.send_service_request(node, to_addr(dst), service, method, to_bin(args))}
  rescue
    e -> {:error, Exception.message(e)}
  end

  defp now, do: System.system_time(:millisecond)
  defp to_bin(b) when is_binary(b), do: b
  defp to_bin(other), do: :erlang.term_to_binary(other)
  defp to_addr(a) when byte_size(a) == 32, do: a
  defp to_addr(a) when is_binary(a), do: Native.from_b58(a)
end
