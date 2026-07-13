# Calls a self-hosted Hop endpoint over TCP. The address would normally come from an HNS lookup; here
# you paste the one server.exs printed.
#   mise exec -- mix run examples/client.exs <server-address> [host] [port]
{address, host, port} =
  case System.argv() do
    [address | rest] ->
      host = Enum.at(rest, 0, "localhost")
      port = rest |> Enum.at(1, "9944") |> String.to_integer()
      {address, host, port}

    _ ->
      IO.puts(:stderr, "usage: mix run examples/client.exs <server-address> [host] [port]")
      System.halt(2)
  end

{:ok, client} = Hop.Endpoint.start_link([])
{:ok, _} = Hop.TcpBearer.dial(client, host, port)

case Hop.Endpoint.request(
       client,
       address,
       "acme/orders",
       "create",
       Jason.encode!(%{item: "widget", qty: 3})
     ) do
  {:ok, status, body} ->
    IO.puts("<- #{status} #{body}")
    Hop.Endpoint.close(client)

  other ->
    IO.puts(:stderr, "request failed: #{inspect(other)}")
    System.halt(1)
end
