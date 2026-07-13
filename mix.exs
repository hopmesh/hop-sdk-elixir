defmodule Hop.MixProject do
  use Mix.Project

  def project do
    [
      app: :hop,
      version: "0.0.1",
      elixir: "~> 1.15",
      deps: deps(),
      description:
        "Receive Hop messages in Elixir: an embeddable endpoint over hop-core via Rustler."
    ]
  end

  # :ssl (with :public_key + :crypto) powers the WSS bearer + discovery; no third-party WS deps.
  def application, do: [extra_applications: [:logger, :ssl, :public_key, :inets]]

  defp deps, do: [{:rustler, "~> 0.36.0"}, {:jason, "~> 1.4"}]
end
