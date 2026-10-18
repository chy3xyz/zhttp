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
`Connection.SuperConnection` packet scheduling and loss timers,
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

In `src/core/packet_space.zig` / `src/core/connection.zig`:

- Ack-eliciting plaintext is optionally retained in `SentPacket` and freed on
  ACK, loss, discard, or space teardown.
- `SuperConnection.setLostPacketObserver` forwards time- and packet-threshold
  losses to a callback before the retained payload is freed. This is
  observation only; zhttp's transport still owns retransmission.
- `SuperConnection.pto_probes_enabled` (default true) lets zhttp suppress
  zquic's duplicate PTO PING/CRYPTO probes while its transport retransmitter
  is still the single sender.

In `src/core/quic_frames.zig`:

- ACK range count is bounded by the remaining packet bytes before allocation.
- Length-prefixed frames validate the declared length against the remaining
  bytes before allocating.
- STREAM and DATAGRAM frames without a LEN field consume the rest of the
  packet instead of leaving trailing bytes to be misparsed as frames.

Re-apply or upstream this patch after refreshing the snapshot. Regression
coverage lives in `src/h3/native/fuzz_test.zig` under the QUIC frame tests and
in `src/h3/native/retry_client_test.zig` for client Retry handling.
