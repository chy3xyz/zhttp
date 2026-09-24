# Server, Router & Response

## Server

RFC 2616 Section 1.4: HTTP/1.1 server using Zig 0.17 `std.Io` networking.

### `Server`

```zig
const Server = struct {
    config: Config,
    handler: Connection.Handler,
    active_connections: std.atomic.Value(u32),
    sweeper: ?*ConnSweeper,
};
```

### `Server.Config`

All fields and their defaults:

```zig
pub const Config = struct {
    port: u16 = 8080,
    address: []const u8 = "127.0.0.1",
    read_buffer_size: usize = 8192,
    write_buffer_size: usize = 8192,
    max_request_size: usize = 1_048_576,          // 1 MiB max total request (headers + body)
    max_header_size: usize = 65536,                // 64 KiB max headers
    keep_alive_timeout_s: u32 = 60,                // idle connection timeout (0 = none)
    initial_read_timeout_s: u32 = 30,              // slowloris protection (0 = none)
    max_connections: u32 = 512,                    // 0 = unlimited
    enable_trace: bool = false,                    // TRACE method (security risk)
    enable_proxy: bool = false,                    // CONNECT proxy tunneling
    proxy: ProxyConfig = .{},                      // proxy access control
    websocket_handler: ?WebSocket.Handler = null,  // global WebSocket handler
    tls_config: ?tls.config.Server = null,         // TLS for HTTPS
    sweeper_interval_ms: u32 = 2000,               // CLOSE-WAIT sweeper interval (0 = disabled)
};
```

### `Server.ProxyConfig`

Controls CONNECT proxy access:

```zig
pub const ProxyConfig = struct {
    allowed_ports: []const u16 = &.{443},          // empty = all ports allowed
    block_private_ips: bool = true,                 // SSRF protection
    allowed_hosts: []const []const u8 = &.{},       // empty = all hosts allowed
};
```

### Functions

```zig
/// Create a server with the given config and handler.
pub fn init(config: Config, handler: Connection.Handler) Server
```

```zig
/// Start the server. Blocks on the accept loop.
/// Returns `error.AddressInUse` if the port is already taken.
pub fn run(self: *Server, io: Io) RunError!void
```

```zig
/// Port the listener is bound to while `run` is serving, 0 when it is not.
/// Read this when the config asked for an ephemeral port (`port = 0`).
pub fn boundPort(self: *const Server) u16

/// Take the server down: `run` closes what it is serving and returns.
/// Abrupt — a request in flight is cut off where it stands.
pub fn stop(self: *Server) void

/// Drain the server instead: stop accepting, close the connections that are
/// waiting for their next request, give the requests being served until
/// `timeout_ns` to answer, then cancel what is left. Returns how many
/// connections it had to cut off, which is 0 when every request finished.
/// An abrupt `stop` supersedes a drain in progress.
pub fn stopGraceful(self: *Server, io: Io, timeout_ns: u64) u32

/// Release what the server holds. `run` owns everything it serves and has
/// given it all back by the time it returns, so this only checks that.
pub fn deinit(self: *Server) void
```

A drain reaches both protocols a connection can speak. An HTTP/1.1 connection
that is between requests is closed under its read; one that is serving gets its
deadline and answers with `Connection: close`. An HTTP/2 connection is sent a
GOAWAY naming the last stream it accepted — the streams already open are
finished, the ids above it are refused — and it ends itself once those streams
are answered.

### `Connection.Handler`

```zig
pub const Handler = *const fn (std.mem.Allocator, std.Io, *const Request) Response;
```

A handler receives a per-request arena allocator, an `std.Io` instance, and the parsed request.

---

## Router

Comptime trie-based request dispatcher. Matches `(method, path, action)` triples against a
fixed route table, extracting path parameters.

### `Router.Method`

```zig
pub const Method = enum {
    ALL,   // matches every HTTP verb
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    TRACE,
    CONNECT,
    PATCH,

    /// True when this route method should accept the given HTTP method.
    pub fn matches(self: Method, request_method: Request.Method) bool
};
```

### `Router.Route`

```zig
pub const Route = struct {
    method: Method,
    path: []const u8,
    handler: Handler,
    ws: ?struct { handler: WebSocket.Handler } = null,
};
```

Path pattern syntax:

| Pattern      | Behavior                                                        |
| ------------ | --------------------------------------------------------------- |
| `/users`     | literal — matches one segment exactly                           |
| `:name`      | single-segment param, stored in `request.params.get("name")`    |
| `*rest`      | catch-all — swallows the rest of the path; must be last segment |
| `:verb`      | AIP-136 action — e.g. `/users/:id:archive`. `method` must be `.POST`. |

### `Router.Params` (re-export of `Request.Params`)

```zig
pub const Params = struct {
    entries: [max_params]Entry = undefined,
    len: usize = 0,

    pub const max_params = 8;
    pub const Entry = struct { name: []const u8, value: []const u8 };

    pub fn get(self: *const Params, name: []const u8) ?[]const u8
};
```

### Functions

```zig
/// Build a Connection.Handler from a comptime route table.
/// Unmatched requests get a default "Not Found" response.
pub fn handler(comptime routes: []const Route) Connection.Handler
```

```zig
/// Build a Connection.Handler with a custom fallback for unmatched routes.
pub fn handlerWithFallback(comptime routes: []const Route, comptime not_found: Handler) Connection.Handler
```

```zig
/// Extract the path component from a URI (strips ?query and #fragment).
pub fn extractPath(uri: []const u8) []const u8
```

```zig
/// Extract the AIP-136 action from the last segment of a URL path.
/// Returns `{ .path, .action }` — action is null when no valid `:verb` is present.
pub fn extractAction(path: []const u8) ActionSplit

pub const ActionSplit = struct { path: []const u8, action: ?[]const u8 };
```

```zig
/// Comptime: split a route pattern into path + optional action.
pub fn parsePatternAction(comptime pattern: []const u8) ActionSplit
```

```zig
/// Match a comptime path pattern against a runtime path.
/// Returns Params (up to 8 entries) on success, null on mismatch.
pub fn matchPath(comptime pattern: []const u8, path: []const u8) ?Params
```

### Usage

```zig
const dispatch = comptime httpz.Router.handler(&.{
    .{ .method = .GET,  .path = "/",              .handler = handleHome },
    .{ .method = .GET,  .path = "/users/:id",     .handler = handleUser },
    .{ .method = .POST, .path = "/users/:id:archive", .handler = archiveUser },
    .{ .method = .GET,  .path = "/static/*rest",  .handler = serveStatic },
    .{ .method = .ALL,  .path = "/api/*rest",     .handler = apiProxy },
});

var server = httpz.Server.init(.{ .port = 8080 }, dispatch);
```

Custom 404:

```zig
fn my404(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.not_found, "text/html", "<h1>Not Found</h1>");
}

const dispatch = comptime httpz.Router.handlerWithFallback(&.{
    .{ .method = .GET, .path = "/", .handler = handleHome },
}, my404);
```

WebSocket per-route:

```zig
.{ .method = .GET, .path = "/ws", .handler = handleWsUpgrade, .ws = .{ .handler = wsHandler } },
```

The `Response` returned by `handleWsUpgrade` must be a 101 upgrade response (use `WebSocket.upgradeResponse`). The Router will attach `ws.handler` to the response automatically.

---

## Response

RFC 2616 Section 6: server response — status line, headers, and optional body.

### `Response`

```zig
const Response = struct {
    status: StatusCode = .ok,
    headers: Headers = .{},
    body: []const u8 = "",
    version: Request.Version = .http_1_1,
    auto_content_length: bool = true,           // auto-generate Content-Length header
    strip_body: bool = false,                    // RFC 2616 §9.4: HEAD response, no body
    chunked: bool = false,                       // RFC 2616 §3.6.1: chunked transfer encoding
    ws_handler: ?WebSocket.Handler = null,       // per-route WebSocket handler
    stream_fn: ?*const fn (?*anyopaque, *std.Io.Writer) void = null,  // streaming body callback
    stream_context: ?*anyopaque = null,          // opaque state for stream_fn
    trailers: ?Headers = null,                   // HTTP/2 trailing headers
    push_paths: [4]?[]const u8 = .{ null, null, null, null },  // HTTP/2 server push paths
    push_count: u8 = 0,
};
```

### `Response.StatusCode`

RFC 2616 Section 6.1.1 — all standard HTTP status codes:

```zig
pub const StatusCode = enum(u16) {
    @"continue" = 100,
    switching_protocols = 101,
    ok = 200, created = 201, accepted = 202, non_authoritative_information = 203,
    no_content = 204, reset_content = 205, partial_content = 206,
    multiple_choices = 300, moved_permanently = 301, found = 302, see_other = 303,
    not_modified = 304, use_proxy = 305, temporary_redirect = 307,
    bad_request = 400, unauthorized = 401, payment_required = 402, forbidden = 403,
    not_found = 404, method_not_allowed = 405, not_acceptable = 406,
    proxy_authentication_required = 407, request_timeout = 408, conflict = 409,
    gone = 410, length_required = 411, precondition_failed = 412,
    request_entity_too_large = 413, request_uri_too_long = 414,
    unsupported_media_type = 415, requested_range_not_satisfiable = 416,
    expectation_failed = 417,
    internal_server_error = 500, not_implemented = 501, bad_gateway = 502,
    service_unavailable = 503, gateway_timeout = 504, http_version_not_supported = 505,

    /// Human-readable reason phrase (e.g. "Not Found").
    pub fn reason(self: StatusCode) []const u8

    /// Numeric value.
    pub fn toInt(self: StatusCode) u16
};
```

### Constants

```zig
pub const max_response_header_len = 65536;   // max serialized header section size
```

### Functions

```zig
/// Create a simple response with status, Content-Type, and body.
pub fn init(status: StatusCode, content_type: []const u8, body: []const u8) Response
```

```zig
/// Create a redirect response (301, 302, or 307).
/// Sets the Location header and Content-Type: text/plain.
pub fn redirect(status: StatusCode, location: []const u8) Response
```

```zig
/// Serialize headers + body into a caller-provided buffer.
/// Returns the serialized bytes.
pub fn serialize(self: *const Response, buf: []u8) SerializeError![]const u8
```

```zig
/// Serialize only the status line + headers (no body).
/// Used for the streaming path.
pub fn serializeHeaders(self: *const Response, buf: []u8) SerializeError![]const u8
```

```zig
/// Free any dynamically-allocated body memory.
pub fn deinit(self: *Response, allocator: std.mem.Allocator) void
```

```zig
/// Create a streaming response that serves a file from disk.
/// Uses zero-copy sendFile when available. Returns 404 / 413 on error.
/// WARNING: follows symlinks — caller must validate path.
/// The stream context is allocated with `allocator` and released once the
/// file has been streamed.
pub fn sendFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8, content_type: []const u8, max_file_size: usize) Response
```

```zig
/// Build a 206 Partial Content response for a single byte range.
/// Sets Content-Range header automatically.
pub fn partialContent(body: []const u8, range: ByteRange, total: usize, content_type: []const u8) Response
```

```zig
/// Build a 416 Range Not Satisfiable response.
/// Sets `Content-Range: bytes */total`.
pub fn rangeNotSatisfiable(total_size: usize) Response
```

```zig
/// Build a multipart/byteranges response for multiple ranges.
/// Caller provides a scratch buffer for body assembly.
pub fn multipartByteRanges(
    content: []const u8,
    content_type: []const u8,
    ranges: []const ByteRange,
    total: usize,
    buf: []u8,
) !Response
```

```zig
/// Add an HTTP/2 server push promise path (max 4 per response).
pub fn addPush(self: *Response, path: []const u8) void
```

### Usage

Simple response:

```zig
fn handleHello(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "text/plain", "Hello, world!");
}
```

Redirect:

```zig
fn handleOld(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.redirect(.moved_permanently, "/new-location");
}
```

Streaming (chunked):

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

File serving:

```zig
fn handleFile(allocator: std.mem.Allocator, io: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.sendFile(allocator, io, "/var/www/index.html", "text/html", 10 * 1024 * 1024);
}
```

Partial content (byte ranges):

```zig
fn handleRange(_: std.mem.Allocator, _: std.Io, req: *const httpz.Request) httpz.Response {
    const content = "Hello, World!";
    if (req.range) |r| {
        return httpz.Response.partialContent(content, r, content.len, "text/plain");
    }
    return httpz.Response.init(.ok, "text/plain", content);
}
```

HTTP/2 server push:

```zig
fn handlePage(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp = httpz.Response.init(.ok, "text/html", "<html>...</html>");
    resp.addPush("/style.css");
    resp.addPush("/app.js");
    return resp;
}
```
