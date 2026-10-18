# Context

## Glossary

### Action

The verb portion of a Google AIP-136 custom method URL — the segment that follows the final `:` in the path (`POST /users/123:archive` → action is `archive`).

An Action is *not* a path segment or a path parameter; it is a third routing axis alongside HTTP method and path. The Router matches Actions exactly: a Route declaring action `archive` does not match a URL with no action, and vice versa.

AIP-136 requires custom methods to be invoked via POST. Declaring an Action on a Route with any HTTP method other than POST is a comptime error.

Action names match `[A-Za-z][A-Za-z0-9]*` (AIP `camelCase`). A trailing `:tail` whose `tail` does not satisfy this rule is **not** an Action — the `:tail` stays as literal content of the last segment, and `Request.action` remains `null`.

Surfaced on `Request.action: ?[]const u8`. The field is set whenever the URL contains a trailing `:verb` that satisfies the name rule, regardless of whether routing succeeds — fall-through handlers (e.g. 404) can read it.

### Action Separator

The `:` character at the end of a path that introduces an Action. Recognized only when it is not the first character of its segment — that distinguishes it from the `:` that introduces a path parameter (`:id`).

A segment may contain at most one Action Separator, and only the last segment of a path may contain one.

### Route Pattern

The comptime string used to declare a Route's path (e.g. `"/users/:id:archive"`). Three segment forms:

- **Literal** — exact-match path segment (`users`)
- **Param** — single-segment capture, segment begins with `:` (`:id`)
- **Catch-all** — captures the remainder of the path, segment begins with `*`, must be last (`*rest`)

Any segment that is not a catch-all may carry a trailing Action suffix (`:verb`). Catch-all segments cannot.

## HTTP/3 and QUIC

Everything H3 lives under `src/h3/`. The native stack is
documented in [docs/modules/h3.md](docs/modules/h3.md); read that before touching
any of it. The files that matter:

- `src/h3/native/transport.zig` — UDP socket, CID routing, zquic
  connection wrapper, CRYPTO/STREAM dispatch, packet I/O.
- `src/h3/native/ack.zig` / `reassembly.zig` / `recovery.zig` / `stats.zig` —
  ACK ranges, STREAM reassembly, retained-packet state, and counters.
- `src/h3/native/qtls.zig` — OpenSSL's QUIC-TLS callbacks: handshake
  bytes and traffic secrets in both directions.
- `src/h3/native/http3.zig` — HTTP/3 framing, control/QPACK streams,
  requests, responses, and the streaming response reader.
- `src/h3/native/qpack.zig` — RFC 9204 static table, literals, and
  Huffman string decoding.
- `src/h3/Adapter.zig` — Router/middleware `Connection.Handler` bridge.
- `src/h3/Server.zig` / `src/h3/Client.zig` — the composed API and the
  server's event loop.
- `src/h3/native/*_test.zig` / `fuzz_test.zig` — loopback, unit, and fuzz
  coverage, including the TLS bridge on its own.

### Transport Split

zquic owns packet protection, packet-number spaces, loss timers, stream IDs,
and frame serialization. `recovery.zig` keeps the plaintext of every
ack-eliciting packet until its ACK arrives, and the transport resends due
packets under a new packet number after an SRTT-derived timeout, so
CRYPTO/STREAM loss does not need zquic to carry a frame-level history. OpenSSL owns the TLS 1.3 handshake. This
repository owns the seam: coalesced-datagram splitting, per-level CRYPTO
reassembly, RFC 9001 key installation from OpenSSL's secrets, HTTP/3 framing,
and QPACK.

### Recovery Ownership

ACK/loss/retransmission is currently split: transport keeps `SentPacket`
plaintext and resends on a 2xSRTT timer, while zquic records packet spaces and
runs `pollLossRecovery` (PTO probes). An ACK is applied in both layers. The
intended direction is zquic-owned recovery: retain ack-eliciting payloads next
to the PN spaces, expose lost payloads through a callback, and build ACKs from
received packet numbers. The first safe step is now in place: zquic retains the
plaintext and `SuperConnection.setLostPacketObserver` reports lost packets
while the transport still owns retransmission. `pollLossRecovery` now uses
zquic's wall-clock domain, fixing a mismatch that had made its deadline
unreachable; zquic's duplicate PTO probes are suppressed until it becomes the
single sender. Remaining work is switching ACK generation and retransmission to
that single owner.

### Closing Period

`transport.Connection.close` schedules a CONNECTION_CLOSE at the highest
level whose keys exist and flushes it. The server does not yet keep a closing
period alive to answer retransmissions; it drops the connection after the close
packet is written.

### Control Stream and QPACK Streams

Every endpoint opens one control stream and a QPACK encoder/decoder pair when
the handshake completes. The control stream starts with stream type 0x00 and a
SETTINGS frame; the QPACK streams start with 0x02 and 0x03. SETTINGS advertises
a 4096-byte decoder dynamic table and zero blocked streams. Peer SETTINGS are
parsed (duplicate/reserved IDs -> 0x0109), peer QPACK streams are validated and
critical-stream FIN -> 0x0104. The decoder applies peer insert/capacity/
duplicate instructions and resolves pre-/post-base dynamic references; a
required insert that has not arrived is QPACK_DECOMPRESSION_FAILED (0x0201)
because blocked streams are not queued. Our encoder remains static-only and
does not yet emit decoder-stream acknowledgments.

### Connection ID (CID) Routing

`Listener.connections` maps the client's original DCID and the
server's SCID to the connection. Long headers carry the ID length; short (1-RTT)
headers use the 8-byte CID this stack always chooses. Every accepted connection
gets both entries together.

### Initial Keys

The Initial packet number space is keyed from the client's original DCID:
`installRfc9001ClientInitialKeys` on the client and
`installRfc9001ServerInitialKeys` on the server. The client's first Initial
datagram is padded to at least 1200 bytes.

### Server Event Loop

`Server.run` is a single-threaded loop: poll the socket, drain up to 32
datagrams, service every connection (TLS progress, queued CRYPTO/STREAM data,
ACKs, writes), service every HTTP/3 session, reap closed sessions and
connections, then back off for one millisecond only when the poll was idle.
There is no per-connection thread.

### Resource Ownership

- Listener owns accepted Connections and their CID map keys.
- Registry owns the Session for each accepted Connection.
- Reaping order is Session first, then Connection: Session.deinit clears
  conn.handler while the Connection is still valid.
- Session owns StreamState; completed streams are queued, removed outside the
  stream-map iterator, and remembered in a bitset so late frames cannot
  recreate them.
- Connection owns stream_send, stream_flow, sent_packets, and its own
  closed-stream bitset. FIN removes the send entry; both FINs remove the flow
  entry.
- Recovery is still split between this layer and zquic; that ownership is the
  next architectural cleanup.

### Transport Parameters

Each endpoint encodes `TransportParameters` from zquic with
`initial_max_data`/stream limits of 16 MiB and 100 streams. The transport
enforces the peer's send windows, sends `MAX_DATA`/`MAX_STREAM_DATA` as data
arrives, and issues `MAX_STREAMS` as peer-initiated streams close. The server
sets `original_destination_connection_id` and
`initial_source_connection_id`; the client sets only its own source CID.
Both sides advertise a zero-capacity QPACK dynamic table.

### Retry and Address Validation

`Server.Options.retry` makes the listener challenge a tokenless Initial with
an HMAC-authenticated Retry before allocating a Connection or Session. The
token is bound to the client address, retry SCID, client SCID, and original
DCID, with a 30-second lifetime. After Retry, Initial keys derive from the
Retry SCID while the transport parameters carry both
`original_destination_connection_id` and `retry_source_connection_id`. The
built-in client answers Retry by replaying the same ClientHello under fresh
Initial keys, and aioquic interoperates in both directions.

### 0-RTT

Not implemented. `ClientTls` has no resumption/ticket surface yet.

