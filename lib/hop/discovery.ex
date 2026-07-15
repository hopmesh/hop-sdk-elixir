defmodule Hop.Discovery do
  @moduledoc """
  Discovery: bind a name to a Hop address using the domain's TLS cert (WebPKI) plus a
  self-certifying reachability record served at /.well-known/hop. See docs/endpoint-sdk.md.
  """
  @well_known_path "/.well-known/hop"

  @doc "The /.well-known/hop JSON body for an endpoint reachable at `public_url`."
  def well_known_body(endpoint, public_url, ttl_secs \\ 3600) do
    record = Hop.Endpoint.sign_reach(endpoint, public_url, ttl_secs)

    Jason.encode!(%{
      "address" => Hop.Endpoint.address(endpoint),
      "endpoint" => public_url,
      "reach" => Base.encode64(record)
    })
  end

  @doc """
  Fetch + verify `base_url`'s well-known. Returns `{address_base58, wss_url}`, or raises if the record
  is missing, malformed, or fails verification. `insecure_tls: true` only for a dev/self-signed cert.
  """
  def resolve(base_url, opts \\ []) do
    %URI{host: host, port: port} = URI.parse(base_url)
    body = https_get(host, port || 443, @well_known_path, Keyword.get(opts, :insecure_tls, false))
    j = Jason.decode!(body)
    rec = Base.decode64!(j["reach"])

    {valid, address, endpoint, _issued, _ttl} =
      Hop.Native.verify_reach_record(rec, System.system_time(:second))

    unless valid, do: raise("reach record failed verification (bad signature or expired)")
    {Hop.Native.to_b58(address), endpoint}
  end

  defp https_get(host, port, path, insecure) do
    ssl_opts =
      if insecure,
        do: [verify: :verify_none],
        else: [verify: :verify_peer, cacerts: :public_key.cacerts_get()]

    {:ok, sock} =
      :ssl.connect(String.to_charlist(host), port, [:binary, {:active, false} | ssl_opts])

    :ssl.send(sock, "GET #{path} HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n\r\n")
    body = recv_all(sock, "") |> extract_body()
    :ssl.close(sock)
    body
  end

  defp recv_all(sock, acc) do
    case :ssl.recv(sock, 0) do
      {:ok, data} -> recv_all(sock, acc <> data)
      {:error, _} -> acc
    end
  end

  defp extract_body(response) do
    case String.split(response, "\r\n\r\n", parts: 2) do
      [_head, body] -> body
      [_] -> ""
    end
  end
end
