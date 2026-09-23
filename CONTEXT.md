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

Everything H3 lives under `src/h3/`, and the API plus the sharp edges of driving
ngtcp2/nghttp3 by hand are written up in [docs/modules/h3.md](docs/modules/h3.md)
— read that before touching any of it. The files that matter:

- `src/h3/quic.zig` — QUIC transport: connections, TLS sessions, packet paths, connection-ID routing, the closing period, the server socket.
- `src/h3/http3.zig` — HTTP/3 framing: nghttp3 sessions, the endpoint's own control and QPACK streams, requests and responses.
- `src/h3/Server.zig` / `src/h3/Client.zig` — the composed API and the server's event loop.
- `src/h3/quic_test.zig` — a real client against a real server over loopback; it is the regression net for all of the above.

### Closing Period

RFC 9000's closing state: after sending CONNECTION_CLOSE an endpoint keeps the
connection only to answer whatever the peer still sends with the same frame. The
server enters it when a connection has been idle for
`Server.Options.idle_timeout_ns`, keeps the buffered close packet in
`quic.Connection.close_buf`, and answers from `Server.readDatagram`. The normal
write path is unusable there — ngtcp2 returns `NGTCP2_ERR_CLOSING`.

### Control Stream and QPACK Streams

The three unidirectional streams that every HTTP/3 endpoint opens for itself: one
control stream and a QPACK encoder/decoder pair. They are opened on the QUIC
connection and bound to the nghttp3 session (`bindControlStream`,
`bindQpackStreams`) before any request is submitted. The peer's three are
recognized by nghttp3 itself from their stream-type prefix.

### Connection ID (CID) Routing

`Listener.connections` maps *every* connection ID a connection owns to it: the
server's own SCID, the client's original DCID (which the client keeps using until
it has seen a reply) and each CID ngtcp2 later issues through
`get_new_connection_id`. Long headers carry the ID length, short (1-RTT) headers
do not — that is what `quic.cid_length` is for. Tearing a connection down removes
all of its entries together.

### Initial Keys

The packet protection keys for the Initial packet number space. ngtcp2 requires
the application to install them from `recv_client_initial` ("generate initial
keys and IVs for both transmission and reception"), which
`ngtcp2_crypto_recv_client_initial_cb` does.

### Path Storage

`ngtcp2_path_storage`: the address buffers a network path needs. Every `path`
argument handed to ngtcp2's write functions must point at buffers of its own, so
paths are never bare `ngtcp2_path` values here; `quic.initPath` fills one.

### Server Event Loop

`Server.run` is a single-threaded loop: one datagram per turn (read without
blocking), then every connection is serviced — its own H3 streams, pending
requests, queued writes and QUIC timers — and idle or finished connections are
reaped. There is no per-connection thread.

### Transport Parameters

What a QUIC endpoint advertises to its peer. `ngtcp2_transport_params_default`
zeroes every field, so each limit the peer needs has to be set explicitly —
notably `initial_max_stream_data_uni`, without which the peer's control and QPACK
streams (all unidirectional) cannot carry a single byte. The server also echoes
the client's original DCID back in `original_dcid` (RFC 9000).

### 0-RTT

Not implemented. `quic.connect` accepts an `early_data` argument and ignores it,
so a resumed session is never used.

