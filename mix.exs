defmodule Hop.MixProject do
  use Mix.Project

  def project do
    [
      app: :hop_endpoint,
      version: "0.0.1",
      elixir: "~> 1.15",
      deps: deps(),
      source_url: "https://github.com/hopmesh/hop-sdk-elixir",
      package: package(),
      description:
        "Receive Hop messages in Elixir: an embeddable endpoint over hop-core via Rustler.",
      docs: [main: "readme", extras: ["README.md"]]
    ]
  end

  # :ssl (with :public_key + :crypto) powers the WSS bearer + discovery; no third-party WS deps.
  def application, do: [extra_applications: [:logger, :ssl, :public_key, :inets]]

  defp deps, do: [{:rustler, "~> 0.36.0"}, {:jason, "~> 1.4"}]

  defp package do
    [
      name: "hop_endpoint",
      # The Elixir wrapper is Apache-2.0. The checksum-covered vendored protocol crates retain FSL.
      licenses: ["Apache-2.0", "FSL-1.1-ALv2"],
      links: %{
        "GitHub" => "https://github.com/hopmesh/hop-sdk-elixir",
        "Homepage" => "https://hopme.sh"
      },
      files: [
        "lib",
        "native/hop_endpoint/src",
        "native/hop_endpoint/Cargo.toml",
        "native/hop_endpoint/LICENSE.md",
        "native/Cargo.toml",
        "native/Cargo.lock",
        "native/vendor/hop-core/src",
        "native/vendor/hop-core/Cargo.toml",
        "native/vendor/hop-core/LICENSE.md",
        "native/vendor/hop-endpoint-core/src",
        "native/vendor/hop-endpoint-core/Cargo.toml",
        "native/vendor/hop-endpoint-core/LICENSE.md",
        "native/vendor/hop-store-sqlite/src",
        "native/vendor/hop-store-sqlite/Cargo.toml",
        "native/vendor/hop-store-sqlite/LICENSE.md",
        "native/vendor/libhop/src",
        "native/vendor/libhop/Cargo.toml",
        "native/vendor/libhop/LICENSE.md",
        "mix.exs",
        "README.md",
        "LICENSE.md"
      ]
    ]
  end
end
