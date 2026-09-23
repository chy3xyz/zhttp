# zhttp

An HTTP/1.1, HTTP/2, and HTTP/3 library for Zig 0.17, built on the `std.Io` async model.

## Features

- **HTTP Server** — HTTP/1.1, HTTP/2, and HTTP/3, keep-alive, chunked transfer encoding, connection limits, slowloris protection
- **HTTP Client** — HTTP/1.1, HTTP/2, and HTTP/3, configurable timeouts, response size limits
- **HTTP/2** — ALPN negotiation, h2c (cleartext), HPACK compression, stream multiplexing, flow control, server push, trailers
- **HTTP/3** — opt-in via `-Dh3=true`: QUIC via ngtcp2, HTTP/3 framing via nghttp3, connection ID rotation, Alt-Svc advertisement
- **Router** — path parameters (`:id`), catch-all segments (`*rest`), AIP-136 custom methods (`:archive`), comptime dispatch, custom 404 handlers
- **WebSocket** — RFC 6455 upgrade, text/binary frames, fragmentation reassembly, per-route handlers
- **Streaming Responses** — chunked encoding, Server-Sent Events, zero-copy file serving
- **Middleware** — CORS, security headers, rate limiting, and gzip compression via composable `wrap` functions
- **HTTPS / TLS** — server and client TLS via [OpenSSL](https://github.com/openssl/openssl)
- **CONNECT Proxy** — SSRF protection with private IP blocking and host/port allowlists
- **Cookies** — RFC 6265 cookie parsing and Set-Cookie generation with Secure, HttpOnly, SameSite, Max-Age, Domain, Path
- **High Performance** — SIMD-accelerated ASCII lowercasing & CR/LF scanning (@Vector 16-byte SIMD), zero-allocation request parsing, lock-free CLOSE-WAIT sweeper
- **RFC 2616 / RFC 9113 / RFC 9114 Compliant** — HTTP date parsing, path traversal protection, TRACE support (off by default)

## Quick Start

```zig
const std = @import("std");
const zhttp = @import("zhttp");

pub fn main(init: std.process.Init) !void {
    var server = zhttp.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, handler);

    server.run(init.io) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("Error: port 8080 is already in use\n", .{});
            std.process.exit(1);
        },
    };
}

fn handler(_: std.mem.Allocator, _: std.Io, request: *const zhttp.Request) zhttp.Response {
    if (std.mem.eql(u8, request.uri, "/")) {
        return zhttp.Response.init(.ok, "text/plain", "Hello from zhttp!");
    }
    return zhttp.Response.init(.not_found, "text/plain", "Not Found");
}
```

Handlers receive a per-request arena allocator, an `std.Io` instance, and the parsed request. Return a `Response` value — the server handles serialization and cleanup.

## Using as a Dependency

```sh
zig fetch --save git+https://github.com/chy3xyz/zhttp.git
```

Then in your `build.zig`:

```zig
const zhttp_dep = b.dependency("zhttp", .{ .target = target });
const zhttp_mod = zhttp_dep.module("zhttp");
exe.root_module.addImport("zhttp", zhttp_mod);
```

HTTP/3 is off by default; add `.h3 = true` to `b.dependency` to build it in.

## Routing

The `Router` dispatches requests by method and path at comptime. Path parameters are stored on the request and accessed via `request.params`.

```zig
const std = @import("std");
const httpz = @import("httpz");

pub fn main(init: std.process.Init) !void {
    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, comptime httpz.Router.handler(&.{
        .{ .method = .GET, .path = "/", .handler = handleHome },
        .{ .method = .GET, .path = "/hello/:name", .handler = handleHello },
    }));

    server.run(init.io) catch |err| switch (err) {
        error.AddressInUse => std.process.exit(1),
    };
}

fn handleHome(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "text/plain", "Welcome!");
}

fn handleHello(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    const name = request.params.get("name") orelse "world";
    _ = name; // use name to build a response
    return httpz.Response.init(.ok, "text/plain", "Hello!");
}
```

`GET /hello/alice` matches the `:name` parameter — retrieve it with `request.params.get("name")`.

Use `Router.handlerWithFallback` to provide a custom 404 handler instead of the default.

### Custom Methods (AIP-136)

For actions that don't fit cleanly into the standard HTTP verbs — archiving a user, cancelling an order, translating a message — the Router supports [Google AIP-136](https://google.aip.dev/136) custom methods. Append `:verb` to the last segment of the path; the verb becomes a third routing axis alongside method and path:

```zig
comptime httpz.Router.handler(&.{
    .{ .method = .GET,  .path = "/users/:id",          .handler = getUser },
    .{ .method = .POST, .path = "/users/:id:archive",  .handler = archiveUser },
    .{ .method = .POST, .path = "/users/:id:transfer", .handler = transferUser },
    .{ .method = .POST, .path = "/users:batchGet",     .handler = batchGetUsers },
});
```

- `GET /users/42` → `getUser`
- `POST /users/42:archive` → `archiveUser` (`request.params.get("id")` is `"42"`)
- `POST /users:batchGet` → `batchGetUsers` (collection-level action)

The parsed action is exposed on `request.action: ?[]const u8` — useful for logging, or for a fall-through 404 handler that reports the unknown verb:

```zig
fn archiveUser(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    std.debug.print("action={s} id={s}\n", .{ request.action.?, request.params.get("id").? });
    return httpz.Response.init(.ok, "text/plain", "archived");
}
```

#### Rules

- **Exact match.** A route with action `archive` does not match a URL without one, and vice versa. `POST /users/:id` and `POST /users/:id:archive` are distinct routes that can coexist.
- **POST only.** AIP-136 requires custom methods to be invoked via POST. Declaring an action with any method other than `.POST` is a comptime error.
- **Action name format.** Must match `[A-Za-z][A-Za-z0-9]*` (AIP `camelCase`: `archive`, `batchGet`, `listMessages`). Invalid names in patterns are a comptime error; invalid names in incoming URLs are treated as literal path content (so `/items/SKU-123:foo-bar` still matches `/items/:sku` with `sku = "SKU-123:foo-bar"`).
- **Not on catch-all segments.** `/foo/*rest:action` is a comptime error — catch-alls swallow everything by design.

## Middleware

`wrap` works on both route handlers and plain handlers — use it per-route or globally:

```zig
const std = @import("std");
const httpz = @import("httpz");

const cors = httpz.middleware.cors.init(.{ .origin = "https://myapp.com" });
const compress = httpz.middleware.compression;

pub fn main(init: std.process.Init) !void {
    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, comptime httpz.Router.handler(&.{
        // Compression on a single route
        .{ .method = .GET, .path = "/data", .handler = compress.wrap(handleData) },
        // CORS + compression composed together
        .{ .method = .GET, .path = "/api", .handler = cors.wrap(compress.wrap(handleData)) },
    }));

    server.run(init.io) catch |err| switch (err) {
        error.AddressInUse => std.process.exit(1),
    };
}

fn handleData(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "application/json", "{\"ok\":true}");
}
```

To apply middleware globally without the Router:

```zig
var server = httpz.Server.init(config, compress.wrap(handler));
```

### Passing State to Handlers

Middleware can attach typed state to `request.context` for downstream handlers. The context is keyed by type, so multiple middleware can each store their own state without clobbering each other.

```zig
const GeoInfo = struct { lat: f64, lon: f64 };
const AuthInfo = struct { user_id: []const u8 };

fn geoMiddleware(comptime inner: httpz.Handler) httpz.Handler {
    return struct {
        fn handle(allocator: std.mem.Allocator, io: std.Io, req: *const httpz.Request) httpz.Response {
            var geo = GeoInfo{ .lat = 45.0, .lon = -73.0 }; // looked up from req IP
            var ctx_req = req.*;
            ctx_req.context.put(GeoInfo, &geo);
            return inner(allocator, io, &ctx_req);
        }
    }.handle;
}

fn authMiddleware(comptime inner: httpz.Handler) httpz.Handler {
    return struct {
        fn handle(allocator: std.mem.Allocator, io: std.Io, req: *const httpz.Request) httpz.Response {
            var auth = AuthInfo{ .user_id = "alice" }; // parsed from header
            var ctx_req = req.*;
            ctx_req.context.put(AuthInfo, &auth);
            return inner(allocator, io, &ctx_req);
        }
    }.handle;
}

fn handleDashboard(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    // Both are available — middleware don't clobber each other
    const geo = request.context.get(GeoInfo) orelse return httpz.Response.init(.internal_server_error, "text/plain", "No geo");
    const auth = request.context.get(AuthInfo) orelse return httpz.Response.init(.unauthorized, "text/plain", "No auth");
    _ = geo;
    _ = auth;
    return httpz.Response.init(.ok, "text/plain", "OK");
}
```

Context values live on each middleware's stack frame and are valid for the handler's lifetime. Up to 8 entries are supported (matching the `Params` limit).

### CORS Options

```zig
httpz.middleware.cors.init(.{
    .origin = "*",                                            // Access-Control-Allow-Origin
    .methods = "GET, POST, PUT, DELETE, OPTIONS, PATCH",      // Access-Control-Allow-Methods
    .headers = "Content-Type, Authorization",                 // Access-Control-Allow-Headers
    .max_age = "86400",                                       // Access-Control-Max-Age (seconds)
});
```

### Security Headers Middleware

Applies standard security hardening headers to HTTP responses:

```zig
const sec = httpz.middleware.security_headers;

// In your handler or middleware chain:
sec.apply(&response, .{
    .x_content_type_options = "nosniff",
    .x_frame_options = "DENY",
    .hsts = "max-age=31536000; includeSubDomains",
    .content_security_policy = "default-src 'self'",
});
```

### Rate Limiter Middleware

Token-bucket rate limiter per IP or custom key:

```zig
var limiter = httpz.middleware.rate_limit.RateLimiter.init(allocator, io, 100, 10); // max 100 tokens, 10 tokens/sec refill
defer limiter.deinit();

// Returns false and sets 429 status when limit exceeded:
if (!try limiter.enforce(client_ip, &response)) return response;
```

### Compression Options

Configure minimum body size threshold before applying Gzip compression:

```zig
const compress = httpz.middleware.compression;

// Only compress responses >= 1024 bytes (1 KB):
const handler = compress.wrapWithOptions(innerHandler, .{ .min_size_bytes = 1024 });
```

## Request & Response Helpers

### JSON Helper

```zig
// Parse JSON request body
const payload = try request.json(MyStruct, allocator);
defer payload.deinit();

// Send JSON response
return try httpz.Response.json(allocator, .{ .success = true, .data = "hello" }, .ok);
```

### Query Parameters & Header Helpers

```zig
// Query parameter: GET /search?q=zig&page=2
const query_str = request.query("q") orelse "";

// Header inspection:
if (request.isJson()) { ... }
if (request.isForm()) { ... }
if (request.isMultipart()) { ... }

// Auth token helpers:
const token = request.bearerToken(); // extracts token from "Authorization: Bearer <token>"

var buf: [64]u8 = undefined;
if (request.basicAuth(&buf)) |creds| {
    // creds.username, creds.password
} else {
    return httpz.Response.requireBasicAuth("Admin Realm");
}
```

## Cookies

`httpz.Cookie` provides RFC 6265 cookie parsing from requests and `Set-Cookie` header generation for responses.

### Reading Cookies

```zig
fn handler(allocator: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    // Look up a single cookie by name
    const session = httpz.Cookie.get(request, "session_id") orelse
        return httpz.Response.init(.unauthorized, "text/plain", "No session");

    // Iterate all cookies
    var iter = httpz.Cookie.iterator(request);
    while (iter.next()) |cookie| {
        std.debug.print("{s} = {s}\n", .{ cookie.name, cookie.value });
    }

    _ = session;
    _ = allocator;
    return httpz.Response.init(.ok, "text/plain", "OK");
}
```

### Setting Cookies

```zig
fn login(allocator: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "text/plain", "Logged in");

    // Session cookie — expires when browser closes
    httpz.Cookie.set(&resp, allocator, .{
        .name = "session_id",
        .value = "abc123",
        .path = "/",
        .http_only = true,
        .secure = true,
        .same_site = .lax,
    }) catch {};

    // Persistent cookie — 30 day expiry
    httpz.Cookie.set(&resp, allocator, .{
        .name = "preferences",
        .value = "dark_mode",
        .path = "/",
        .max_age = 86400 * 30,
    }) catch {};

    return resp;
}
```

### Deleting Cookies

```zig
fn logout(allocator: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "text/plain", "Logged out");

    // Domain and Path must match the original cookie
    httpz.Cookie.remove(&resp, allocator, .{
        .name = "session_id",
        .path = "/",
    }) catch {};

    return resp;
}
```

The allocator is used to format `Set-Cookie` header values. Use a per-request arena so the memory lives until the response is serialized.

## Streaming Responses

Set `stream_fn` on a response to stream the body directly to the network writer. The server serializes headers first, then calls your function.

### Chunked Encoding

```zig
fn handleStream(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok, .chunked = true };
    resp.headers.append("Content-Type", "text/plain") catch {};
    resp.stream_fn = streamFn;
    return resp;
}

fn streamFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var buf: [32]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "line {d}\n", .{i}) catch return;
        writer.writeAll(line) catch return;
    }
}
```

### Server-Sent Events

```zig
fn handleEvents(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok };
    resp.headers.append("Content-Type", "text/event-stream") catch {};
    resp.headers.append("Cache-Control", "no-cache") catch {};
    resp.auto_content_length = false;
    resp.stream_fn = sseStreamFn;
    return resp;
}

fn sseStreamFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "data: event {d}\n\n", .{i}) catch return;
        writer.writeAll(msg) catch return;
        writer.flush() catch return;
    }
}
```

Use `stream_context` to pass state to the stream function (Zig has no closures).

## WebSocket

Return a 101 upgrade response and provide a WebSocket handler. The handler owns the connection loop.

### Per-route (with Router)

```zig
.{ .method = .GET, .path = "/ws", .handler = handleWsUpgrade, .ws = .{ .handler = wsHandler } },
```

```zig
fn handleWsUpgrade(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    return httpz.WebSocket.upgradeResponse(request) orelse
        httpz.Response.init(.bad_request, "text/plain", "WebSocket upgrade required");
}

fn wsHandler(conn: *httpz.WebSocket.Conn, _: *const httpz.Request) void {
    while (true) {
        const msg = conn.recv() catch break orelse break;
        switch (msg.opcode) {
            .text => conn.send(msg.payload) catch break,
            .binary => conn.sendBinary(msg.payload) catch break,
            else => {},
        }
    }
}
```

### Global (without Router)

Set `websocket_handler` in the server config:

```zig
var server = httpz.Server.init(.{
    .port = 8080,
    .address = "127.0.0.1",
    .websocket_handler = wsHandler,
}, handler);
```

Then return `WebSocket.upgradeResponse(request)` from your handler to trigger the upgrade.

The `Conn` API: `recv() !?Message`, `send([]const u8) !void`, `sendBinary([]const u8) !void`, `close(u16, []const u8) !void`.

## File Serving

`Response.sendFile` streams a file from disk using zero-copy I/O when available:

```zig
fn handleFile(allocator: std.mem.Allocator, io: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.sendFile(allocator, io, "/var/www/index.html", "text/html", 10 * 1024 * 1024);
}
```

The last argument is the maximum allowed file size in bytes (0 for unlimited). Returns 404 if the file doesn't exist, 413 if it exceeds the limit. The file is streamed with the allocator and `Io` it is given, and released once it has been sent.

## HTTPS / TLS

### Server

```zig
const tls = httpz.tls;

var auth = tls.config.CertKeyPair.fromFilePath(allocator, io, cert_dir, "cert.pem", "key.pem") catch return error.InvalidCertificate;
defer auth.deinit(allocator);

var server = httpz.Server.init(.{
    .port = 4433,
    .address = "127.0.0.1",
    .tls_config = .{
        .auth = &auth,
    },
}, handler);
```

### Client

```zig
var client = zhttp.Client.init(allocator, .{
    .host = "example.com",
    .port = 443,
    .tls_config = .{
        .host = "example.com",
        .root_ca = .system,
    },
});
```

#### Mutual TLS (mTLS) with Client Certificate & Key

For APIs requiring client certificate authentication (e.g. WeChat Pay `zwechat`, payment gateways, microservices):

```zig
var client_auth = try zhttp.tls.config.CertKeyPair.fromFilePath(allocator, io, cert_dir, "apiclient_cert.pem", "apiclient_key.pem");
defer client_auth.deinit(allocator);

var client = zhttp.Client.init(allocator, .{
    .host = "api.mch.weixin.qq.com",
    .port = 443,
    .tls_config = .{
        .host = "api.mch.weixin.qq.com",
        .root_ca = .system,
        .auth = &client_auth, // or .cert = &client_auth
    },
});
```

## HTTP/2

HTTP/2 is supported transparently — handlers use the same `Request` and `Response` API regardless of protocol version.

### Automatic Negotiation

Over TLS, the server and client negotiate HTTP/2 via ALPN. No configuration is needed — if the peer supports `h2`, it is used automatically.

### h2c (Cleartext HTTP/2)

On the server side, h2c is detected automatically via the HTTP/2 connection preface.

On the client side, enable h2c with `h2_prior_knowledge`:

```zig
var client = httpz.Client.init(allocator, .{
    .host = "localhost",
    .port = 8080,
    .h2_prior_knowledge = true,
});
```

### Server Push

Handlers can push up to 4 additional resources per response. The server sends a `PUSH_PROMISE` and then serves the pushed resource on a reserved stream.

```zig
fn handler(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "text/html", "<html>...</html>");
    resp.addPush("/style.css");
    resp.addPush("/app.js");
    return resp;
}
```

Push is only sent when the client has not disabled it via `SETTINGS_ENABLE_PUSH=0`.

### Trailers

Responses can include trailing headers, sent after the body as a final HEADERS frame:

```zig
fn handler(allocator: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "application/octet-stream", body);
    var trailers = httpz.Headers.init(allocator);
    trailers.append("checksum", "sha256=abc123") catch {};
    resp.trailers = trailers;
    return resp;
}
```

### Protocol Details

- Full RFC 9113 binary framing (all 10 frame types)
- HPACK header compression with static/dynamic tables and Huffman coding
- Per-stream and connection-level flow control
- Concurrent stream limits (default 100)
- DoS protection: rapid reset detection, settings timeout, header size limits

## HTTP/3

HTTP/3 runs over QUIC (UDP) instead of TCP. It is opt-in — build with `-Dh3=true` to compile it in:

```sh
zig build -Dh3=true
```

Building it requires the system libraries `libngtcp2` and `libnghttp3`; they are neither translated nor linked otherwise.

### Server

```zig
const h3 = httpz.h3;

fn handler(allocator: std.mem.Allocator, request: *const h3.Request) h3.Response {
    if (request.method != .GET) return .{ .status = .method_not_allowed, .body = "only GET\n" };
    // request.path, request.headers.get("user-agent"), request.body
    return .{ .body = "Hello from H3!\n" };
}

var server = try h3.Server.init(allocator, 4433, handler, .{});
defer server.deinit();
try server.run(); // event loop: routes packets, serves requests, reaps idle connections
```

The handler answers with `h3.Response` — `status`, `content_type` and `body`, and
the body is copied, so a literal is fine. `h3.Request.method` and
`h3.Response.status` are the same enums the HTTP/1.1 and HTTP/2 sides use.

### Client

```zig
const h3 = httpz.h3;

var client = try h3.Client.init(allocator, "example.com", 443, .{});
defer client.deinit();
const body = try client.get("/");
defer allocator.free(body);

// Any method, with header fields and a body; the answer carries the status too.
const answer = try client.send("POST", "/submit", &.{
    .{ .name = "content-type", .value = "application/json" },
}, "{\"ok\":true}");
defer allocator.free(answer.header_text);
defer allocator.free(answer.body);
```

`Client.init` takes a `httpz.h3.quic.ClientTls`: it verifies the peer against the
system CA store by default, and `.insecure_skip_verify = true` turns verification
off for local testing against a self-signed certificate.

### TLS Certificates

```zig
const cert_pem = @embedFile("cert.pem");
const key_pem = @embedFile("key.pem");
try h3.quic.setServerCert(cert_pem, key_pem);
```

### QLog Debugging

```zig
try h3.quic.enableQLog("trace.qlog"); // Wireshark-compatible
defer h3.quic.disableQLog();
```

### Alt-Svc Advertisement (HTTP/3 Discovery)

Advertise your HTTP/3 endpoint to HTTP/1.1 and HTTP/2 clients via the `Alt-Svc` header (RFC 7838 / RFC 9114):

```zig
var server = httpz.Server.init(.{
    .port = 443,
    .address = "0.0.0.0",
    .alt_svc_port = 4433, // Advertises Alt-Svc: h3=":4433"; ma=86400
}, handler);
```

### Protocol Details

- QUIC transport via ngtcp2 (UDP, TLS 1.3, stream multiplexing)
- HTTP/3 framing via nghttp3 (QPACK header compression)
- Connection ID rotation and path-validation callbacks
- Automatic `Alt-Svc` header advertisement on HTTPS responses
- QLog output for Wireshark/qvis analysis (`h3.quic.enableQLog`)

Not implemented: 0-RTT early data (`connect` accepts the argument but ignores it,
so a resumed session is not used) and connection migration beyond the callbacks
above.

### Dependencies

Only needed when building with `-Dh3=true`.

```sh
# macOS
brew install libngtcp2 libnghttp3

# Ubuntu/Debian
sudo apt install libngtcp2-dev libnghttp3-dev
```

## HTTP Client

```zig
const httpz = @import("httpz");
const Client = httpz.Client;

const url = Client.Url.parse("http://example.com/path").?;

var client = Client.init(allocator, .{
    .host = url.host,
    .port = url.port,
    .connection_timeout_s = 10,
    .read_timeout_s = 10,
});
defer client.deinit();

try client.connect(io);

var resp = try client.request(io, .GET, url.path, null, null);
defer resp.deinit(allocator);
```

`request` takes method, URI path, optional `Headers`, and optional body (`[]const u8`).

## Server Configuration

All fields with their defaults:

```zig
httpz.Server.init(.{
    .port = 8080,
    .address = "127.0.0.1",
    .read_buffer_size = 8192,
    .write_buffer_size = 8192,
    .max_request_size = 1_048_576,       // 1 MiB max total request
    .max_header_size = 65536,            // 64 KiB max headers
    .keep_alive_timeout_s = 60,          // idle connection timeout
    .initial_read_timeout_s = 30,        // slowloris protection
    .max_connections = 512,              // 0 = unlimited
    .enable_trace = false,               // TRACE method (security risk)
    .enable_proxy = false,               // CONNECT proxy support
    .proxy = .{
        .allowed_ports = &.{443},
        .block_private_ips = true,
        .allowed_hosts = &.{},
    },
    .websocket_handler = null,           // global WebSocket handler
    .tls_config = null,                  // TLS for HTTPS
}, handler);
```

## Building & Testing

Requires **Zig 0.17** and **OpenSSL 3** (for TLS support).
`libngtcp2` and `libnghttp3` are only needed for HTTP/3 (`-Dh3=true`), which is off by default.

```sh
# macOS
brew install openssl@3 libngtcp2 libnghttp3

# Ubuntu/Debian
sudo apt install libssl-dev libngtcp2-dev libnghttp3-dev

# Fedora
sudo dnf install openssl-devel libngtcp2-devel libnghttp3-devel
```

```sh
# Run all tests (unit + integration)
zig build test

# Build everything, including HTTP/3
zig build -Dh3=true

# Run micro-benchmarks
zig build bench

# Run the HTTP/3 micro-benchmarks (needs -Dh3=true)
zig build bench-h3 -Dh3=true

# Run integration tests only
zig build test-integration

# Run tests with kcov coverage
zig build coverage
```

Examples:

```sh
zig build example_server_http
zig build example_server_https
zig build example_server_router
zig build example_server_streaming
zig build example_server_websocket
zig build example_client_http
zig build example_client_https
```

## License

See [LICENSE](LICENSE) for details.
