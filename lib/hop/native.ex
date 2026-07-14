defmodule Hop.Native do
  @moduledoc """
  Rustler NIF bindings to the `hop` crate's `HopNode` (native/hop_endpoint). Thin and one-to-one;
  the ergonomics live in `Hop.Endpoint`. All addresses/bytes cross as binaries. Not called directly
  by app code.
  """
  use Rustler, otp_app: :hop, crate: "hop_endpoint", mode: :debug

  # Stubs replaced by the NIF at load; each raises if the shared library failed to load.
  def open_ephemeral, do: err()
  def open_with_secret(_secret), do: err()
  def address(_node), do: err()
  def tick(_node, _now_ms), do: err()
  def connected(_node, _link, _initiator), do: err()
  def disconnected(_node, _link), do: err()
  def received(_node, _link, _data), do: err()
  def drain_outgoing(_node), do: err()
  def subscribe(_node, _topic), do: err()
  def publish_prekey(_node), do: err()
  def cluster_join_passphrase(_node, _passphrase), do: err()
  def cluster_members(_node), do: err()
  def send_service_request(_node, _dst, _service, _method, _args), do: err()
  def send_service_response(_node, _to, _for_id, _status, _body), do: err()
  def take_service_requests(_node), do: err()
  def take_service_responses(_node), do: err()
  def to_b58(_addr), do: err()
  def from_b58(_text), do: err()
  def sign_reach_record(_node, _endpoint, _ttl_secs), do: err()
  # -> {valid, address, endpoint, issued_at, ttl_secs}
  def verify_reach_record(_bytes, _now_secs), do: err()

  defp err, do: :erlang.nif_error(:nif_not_loaded)
end
