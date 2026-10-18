# Provenance

Vendored snapshot of the zquic working tree used by zhttp's HTTP/3 stack.

- Source: `../zquic` (zquic 0.9.18 tree, commit 31046aa plus the local
  Darwin/OpenSSL-compatibility fixes present in that checkout)
- Vendored: 2026-10-18
- License: Apache-2.0 (see LICENSE in this directory)
- Refresh:

  ~~~sh
  rsync -a --exclude .git --exclude .zig-cache --exclude zig-out \
    ../zquic/ vendor/zquic/
  ~~~

zhttp uses these zquic surfaces: `PacketCrypto`,
`Connection.SuperConnection` packet scheduling and loss timers, the
`setLostPacketObserver` callback with retained plaintext,
`TransportParameters`, `Tls13KeySchedule`, and the QUIC frame codec.

## zhttp hardening patch

zhttp applies defensive patches not present in the source checkout above:

In `src/core/packet.zig`:

- `Initial` packet headers parse the token length and token bytes; previously
  the token was left as null, which prevented server-side Retry validation.
- `RetryPacket.validateConnectionIds` now implements the RFC 9000
  Section 17.2.5.1 client rule: the Retry DCID equals the client's Initial
  SCID, and the Retry SCID becomes the client's next destination CID. The old
  code compared the Retry DCID with the original destination CID.
- New `computeRetryIntegrityTag` and `RetryPacket.validateClientRetry`
  verify the RFC 9001 Section 5.8 tag over
  `ODCID length || ODCID || Retry-without-tag`, reject an empty token, and
  accept a conformant Retry end to end.

In `src/core/packet_crypto.zig`:

- New `PacketCrypto.initial_token` makes Initial headers carry a varint-length
  token. A null or empty token still emits the single `0x00` byte used by
  server packets and pre-Retry clients.
- New `PacketCrypto.resetInitialPacketNumberState` restarts the Initial
  packet number space when a client accepts a Retry.
- `createProtectedRawPacket` encrypts directly into the final packet
  allocation instead of building intermediate protected-packet and ciphertext
  buffers. The header bytes and wire format are unchanged.

In `src/core/packet_space.zig` / `src/core/connection.zig`:

- Ack-eliciting plaintext is optionally retained in `SentPacket` and freed on
  ACK, loss, discard, or space teardown.
- `PacketSpace.onPacketSentWithOwnedPayload` stores a caller-owned plaintext
  allocation directly in `SentPacket` (no duplicate); the ownership contract
  is unconditional, so the slice is stored or freed before an error returns.
- `SuperConnection.queueOutgoingRawPacketOwned` and
  `sendProtectedRawPacketOwnedPlaintext` transfer ownership of the protected
  packet and plaintext buffers. The older `queueOutgoingRawPacket` and
  `sendProtectedRawPacket` copies remain for callers that only have borrowed
  slices.
- `SuperConnection.setLostPacketObserver` forwards time- and packet-threshold
  losses to a callback before the retained payload is freed. zhttp installs
  this observer with `context = self`; the callback copies
  `{level, packet number, plaintext}` into the transport's bounded queue and
  service resends it through `sendProtectedRawPacket`. zquic is the single
  loss detector/retransmission owner; ACK generation remains in the transport.
- `SuperConnection.pto_probes_enabled` stays at its default `true`. zhttp no
  longer suppresses PTO probes: a tail loss needs a probe ACK so loss
  detection can surface the original packet.
- `OwnedRawPacket` carries encryption level, plaintext length, ack-eliciting,
  and in-flight bytes so zhttp can enforce the congestion window and requeue
  blocked packets. `queueOutgoingRawPacketOwnedWithMetadata`,
  `queueOutgoingRawPacketsFront`, `bytesInFlight`, and `queuedInFlightBytes`
  are additive APIs; wire bytes are unchanged.
- `PacketSpace.processAck` now advances `largest_acked_packet` and
  `largest_acked_time` for every valid ACK range, including packet numbers that
  loss detection already removed from `sent_packets`. Without this, a single
  premature time-threshold loss froze `largest_acked` and made every later send
  look lost by packet threshold. This is a correctness fix, not a new API.

In `src/core/quic_frames.zig`:

- ACK range count is bounded by the remaining packet bytes before allocation.
- Length-prefixed frames validate the declared length against the remaining
  bytes before allocating.
- STREAM and DATAGRAM frames without a LEN field consume the rest of the
  packet instead of leaving trailing bytes to be misparsed as frames.

Re-apply or upstream this patch after refreshing the snapshot. Regression
coverage lives in `src/h3/native/fuzz_test.zig` under the QUIC frame tests,
`src/h3/native/retry_client_test.zig` for client Retry handling, and
`src/h3/native/recovery_observe_test.zig` plus
`src/h3/native/recovery_owner_test.zig` for zquic-driven lost-payload resends.
