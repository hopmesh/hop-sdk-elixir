defmodule Hop.DevTls do
  @moduledoc """
  DEV/TEST ONLY: an in-process self-signed cert for the discovery example + test (no `openssl` CLI, no
  hex deps). Uses Erlang's `:public_key`/`:crypto` (OTP stdlib) for the RSA key + PKCS#1 signature, and
  hand-encodes a minimal self-signed v3 certificate DER. Never use a self-signed cert in production;
  there a real WebPKI cert proves the domain.
  """
  import Bitwise

  # Hardcoded OID DER (avoids a general OID encoder): rsaEncryption, sha256WithRSAEncryption, commonName.
  @oid_rsa <<0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01>>
  @oid_sha256_rsa <<0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B>>
  @oid_cn <<0x06, 0x03, 0x55, 0x04, 0x03>>

  @doc "`:ssl` server opts backed by a fresh in-process self-signed cert (RSA-2048, CN=<cn>, 1h)."
  def ssl_opts(cn \\ "localhost") do
    rsa = :public_key.generate_key({:rsa, 2048, 65_537})
    n = elem(rsa, 2)
    e = elem(rsa, 3)

    spki =
      seq([
        seq([@oid_rsa, null()]),
        bitstring(:public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, n, e}))
      ])

    sig_alg = seq([@oid_sha256_rsa, null()])
    # CN=<cn>
    name = seq([set([seq([@oid_cn, utf8(cn)])])])
    now = DateTime.utc_now()

    validity =
      seq([utctime(DateTime.add(now, -60, :second)), utctime(DateTime.add(now, 3600, :second))])

    # v3, serial 1, self-signed (issuer == subject)
    tbs = seq([ctx0(int(<<2>>)), int(<<1>>), sig_alg, name, validity, name, spki])
    sig = :public_key.sign(tbs, :sha256, rsa)
    cert = seq([tbs, sig_alg, bitstring(sig)])

    [cert: cert, key: {:RSAPrivateKey, :public_key.der_encode(:RSAPrivateKey, rsa)}]
  end

  # ---- minimal DER (ASN.1) writers ----
  defp der(tag, content), do: <<tag>> <> der_len(byte_size(content)) <> content

  defp der_len(n) when n < 128, do: <<n>>

  defp der_len(n) do
    bytes = :binary.encode_unsigned(n)
    <<0x80 ||| byte_size(bytes)>> <> bytes
  end

  defp int(bin) do
    bin = if :binary.first(bin) >= 128, do: <<0>> <> bin, else: bin
    der(0x02, bin)
  end

  defp seq(items), do: der(0x30, IO.iodata_to_binary(items))
  defp set(items), do: der(0x31, IO.iodata_to_binary(items))
  defp null, do: der(0x05, <<>>)
  defp utf8(s), do: der(0x0C, s)
  defp ctx0(content), do: der(0xA0, content)
  defp bitstring(bin), do: der(0x03, <<0>> <> bin)
  defp utctime(dt), do: der(0x17, Calendar.strftime(dt, "%y%m%d%H%M%SZ"))
end
