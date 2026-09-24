const std = @import("std");
const zhttp = @import("zhttp");
const httpz = zhttp;
const Io = std.Io;
const testing = std.testing;

// ─── Test Handlers ──────────────────────────────────────────────

fn plainHandler(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/")) {
        return httpz.Response.init(.ok, "text/plain", "Hello, World!");
    }
    if (std.mem.eql(u8, request.uri, "/json")) {
        return httpz.Response.init(.ok, "application/json", "{\"status\":\"ok\"}");
    }
    if (std.mem.eql(u8, request.uri, "/health")) {
        return httpz.Response.init(.ok, "text/plain", "healthy");
    }
    if (std.mem.eql(u8, request.uri, "/echo")) {
        return httpz.Response.init(.ok, "text/plain", request.body);
    }
    if (std.mem.eql(u8, request.uri, "/redirect")) {
        return httpz.Response.redirect(.found, "/");
    }
    if (std.mem.eql(u8, request.uri, "/empty")) {
        return .{ .status = .no_content };
    }
    if (std.mem.eql(u8, request.uri, "/gzip")) {
        return httpz.Response.init(
            .ok,
            "text/plain",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
    }
    return httpz.Response.init(.not_found, "text/plain", "Not Found");
}

const router_handler = httpz.Router.handler(&.{
    .{ .method = .GET, .path = "/", .handler = routeHome },
    .{ .method = .GET, .path = "/users/:id", .handler = routeUser },
    .{ .method = .POST, .path = "/users", .handler = routeCreateUser },
    .{ .method = .GET, .path = "/compressed", .handler = httpz.middleware.compression.wrap(routeCompressed) },
    .{ .method = .GET, .path = "/stream/chunks", .handler = routeStreamChunks },
    .{ .method = .GET, .path = "/stream/events", .handler = routeStreamEvents },
    .{ .method = .GET, .path = "/stream/large", .handler = routeStreamLarge },
    .{ .method = .GET, .path = "/ws", .handler = routeWsUpgrade, .ws = .{ .handler = wsEchoHandler } },
});

fn routeHome(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "text/html", "<h1>Home</h1>");
}

fn routeUser(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    const id = request.params.get("id") orelse
        return httpz.Response.init(.bad_request, "text/plain", "Missing id");
    return httpz.Response.init(.ok, "text/plain", id);
}

fn routeCreateUser(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.created, "application/json", "{\"id\":1}");
}

fn routeCompressed(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(
        .ok,
        "text/plain",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ++
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}

fn routeStreamChunks(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok, .chunked = true };
    resp.headers.append("Content-Type", "text/plain") catch {};
    resp.stream_fn = streamChunksFn;
    return resp;
}

fn streamChunksFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        var buf: [32]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "chunk {d}\n", .{i}) catch return;
        writer.writeAll(line) catch return;
    }
}

fn routeStreamEvents(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok };
    resp.headers.append("Content-Type", "text/event-stream") catch {};
    resp.headers.append("Cache-Control", "no-cache") catch {};
    resp.auto_content_length = false;
    resp.stream_fn = streamEventsFn;
    return resp;
}

fn streamEventsFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "data: event {d}\n\n", .{i}) catch return;
        writer.writeAll(msg) catch return;
    }
}

fn routeStreamLarge(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok, .chunked = true };
    resp.headers.append("Content-Type", "text/plain") catch {};
    resp.stream_fn = streamLargeFn;
    return resp;
}

fn streamLargeFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    const line = "All work and no play makes Jack a dull boy.\n";
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        writer.writeAll(line) catch return;
    }
}

fn routeWsUpgrade(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    return httpz.WebSocket.upgradeResponse(request) orelse
        httpz.Response.init(.bad_request, "text/plain", "WebSocket upgrade required");
}

fn wsEchoHandler(conn: *httpz.WebSocket.Conn, _: *const httpz.Request) void {
    while (true) {
        const msg = conn.recv() catch break orelse break;
        switch (msg.opcode) {
            .text => conn.send(msg.payload) catch break,
            .binary => conn.sendBinary(msg.payload) catch break,
            else => {},
        }
    }
}

// A request the test can hold open, so "this request is in flight" is an event
// to wait for instead of a delay to guess at.
//
// The handler waits on the Io it was given rather than on a clock, which is
// what makes a cancelation request visible to it: a sleep a server cannot
// interrupt would let the request be cut off without the test, or the handler,
// being able to tell. The flags are atomic because the two sides are different
// threads.
var slow_entered = std.atomic.Value(bool).init(false);
var slow_release = std.atomic.Value(bool).init(false);
var slow_canceled = std.atomic.Value(bool).init(false);

fn resetSlowHandler() void {
    slow_entered.store(false, .release);
    slow_release.store(false, .release);
    slow_canceled.store(false, .release);
}

fn slowHandler(_: std.mem.Allocator, io: std.Io, request: *const httpz.Request) httpz.Response {
    if (!std.mem.eql(u8, request.uri, "/slow")) {
        return httpz.Response.init(.ok, "text/plain", "fast");
    }
    slow_entered.store(true, .release);
    while (!slow_release.load(.acquire)) {
        Io.sleep(io, Io.Duration.fromMilliseconds(1), .awake) catch |err| switch (err) {
            error.Canceled => {
                slow_canceled.store(true, .release);
                return httpz.Response.init(.internal_server_error, "text/plain", "canceled");
            },
        };
    }
    return httpz.Response.init(.ok, "text/plain", "slow done");
}

/// Waits for `slowHandler` to have hold of a request, which is how a test knows
/// one is in flight rather than hoping so.
fn waitForSlowHandler() !void {
    var attempts: usize = 0;
    while (attempts < 10_000) : (attempts += 1) {
        if (slow_entered.load(.acquire)) return;
        osSleep(1);
    }
    return error.HandlerNeverEntered;
}

/// Waits for a cancelation to reach the held request. Bounded, so that a server
/// which never gets round to cutting it off reports that rather than hanging the
/// test on it.
fn waitForSlowCanceled() !void {
    var attempts: usize = 0;
    while (attempts < 5000) : (attempts += 1) {
        if (slow_canceled.load(.acquire)) return;
        osSleep(1);
    }
    return error.HandlerWasNotCanceled;
}

// ─── Helpers ────────────────────────────────────────────────────

// Kernel-level sleep that doesn't go through Io.
//
// `std.posix.system` is the C library's own nanosleep on Darwin: `std.os.linux`
// issues syscalls in the Linux register convention, which the Darwin kernel does
// not read — a syscall it does not recognise there is a SIGSYS, "bad system
// call", and it kills the test process. That went unnoticed because the one
// caller probes a port that is ready on the first try, so the sleep is rarely
// reached.
fn osSleep(ms: u32) void {
    var ts = std.posix.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast(@as(u64, ms % 1000) * 1_000_000),
    };
    while (std.posix.errno(std.posix.system.nanosleep(&ts, &ts)) == .INTR) {}
}

/// Shared server state — start each server type exactly once.
const plain_port: u16 = 19080;
const router_port: u16 = 19090;

var plain_started = std.atomic.Value(bool).init(false);
var router_started = std.atomic.Value(bool).init(false);

fn ensurePlainServer() void {
    if (plain_started.cmpxchgStrong(false, true, .seq_cst, .seq_cst) == null) {
        spawnServer(comptime httpz.middleware.compression.wrap(plainHandler), plain_port);
    }
    waitForPort(plain_port);
}

fn ensureRouterServer() void {
    if (router_started.cmpxchgStrong(false, true, .seq_cst, .seq_cst) == null) {
        spawnServer(router_handler, router_port);
    }
    waitForPort(router_port);
}

fn spawnServer(comptime handler: *const fn (std.mem.Allocator, std.Io, *const httpz.Request) httpz.Response, port: u16) void {
    const T = struct {
        fn run(p: u16) void {
            var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
            defer threaded.deinit();
            const tio = threaded.io();
            var server = httpz.Server.init(.{
                .port = p,
                .address = "127.0.0.1",
                .max_connections = 64,
            }, handler);
            server.run(tio) catch {};
        }
    };
    const thread = std.Thread.spawn(.{}, T.run, .{port}) catch return;
    thread.detach();
}

/// Wait until a port is accepting connections using kernel-level sleep.
fn waitForPort(port: u16) void {
    // Create a temporary Io for connect probing
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        if (Io.net.IpAddress.connect(
            &(Io.net.IpAddress.parseIp4("127.0.0.1", port) catch return),
            io,
            .{ .mode = .stream },
        )) |probe| {
            probe.close(io);
            return;
        } else |_| {}
        osSleep(10);
    }
}

/// Make a raw HTTP request and return the full response bytes.
fn rawRequest(port: u16, request_bytes: []const u8) ![]const u8 {
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const addr = Io.net.IpAddress.parseIp4("127.0.0.1", port) catch return error.ConnectionFailed;
    const stream = Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream }) catch return error.ConnectionFailed;
    defer stream.close(io);

    var write_buf: [4096]u8 = undefined;
    var writer = Io.net.Stream.Writer.init(stream, io, &write_buf);
    writer.interface.writeAll(request_bytes) catch return error.SendFailed;
    writer.interface.flush() catch return error.SendFailed;

    // Read entire response — allocRemaining reads until EOF
    var read_buf: [8192]u8 = undefined;
    var reader = Io.net.Stream.Reader.init(stream, io, &read_buf);

    return reader.interface.allocRemaining(testing.allocator, .unlimited) catch return error.ReadFailed;
}

/// A server serving on a thread of its own, and the port it bound.
const BackgroundServer = struct {
    thread: std.Thread,
    port: u16,
};

/// Starts `server` on a thread of its own and waits for it to bind the port it
/// returns, which the config has to have asked for as an ephemeral one. The
/// caller stops the server and joins `thread` before touching it again.
fn startServer(server: *httpz.Server, io: Io) !BackgroundServer {
    const Runner = struct {
        fn run(srv: *httpz.Server, sio: Io) void {
            srv.run(sio) catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{ server, io });

    var attempts: usize = 0;
    while (attempts < 500) : (attempts += 1) {
        const port = server.boundPort();
        if (port != 0) return .{ .thread = thread, .port = port };
        osSleep(10);
    }

    server.stop();
    thread.join();
    return error.ServerNeverBound;
}

/// Opens a connection without saying anything on it.
fn connectRaw(io: Io, port: u16) !Io.net.Stream {
    const addr = Io.net.IpAddress.parseIp4("127.0.0.1", port) catch return error.InvalidAddress;
    return Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream }) catch return error.ConnectionFailed;
}

/// Reads one response — headers up to the blank line, then the body its
/// Content-Length announces — and leaves the connection open, which is what a
/// test of a keep-alive connection needs and what `rawRequest` cannot do: it
/// reads to the end of the connection.
fn readOneResponse(reader: *Io.Reader) !void {
    var head: [1024]u8 = undefined;
    var len: usize = 0;
    while (len < head.len) {
        const line = reader.takeDelimiterInclusive('\n') catch return error.ReadFailed;
        if (len + line.len > head.len) return error.ResponseTooLarge;
        @memcpy(head[len..][0..line.len], line);
        len += line.len;
        if (line.len == 2 and line[0] == '\r' and line[1] == '\n') break;
    }

    const headers = head[0..len];
    if (std.mem.indexOf(u8, headers, "200 OK") == null) return error.UnexpectedStatus;
    const marker = "Content-Length: ";
    const start = std.mem.indexOf(u8, headers, marker) orelse return error.NoContentLength;
    const end = std.mem.indexOfScalarPos(u8, headers, start + marker.len, '\r') orelse return error.NoContentLength;
    const body_len = std.fmt.parseInt(usize, headers[start + marker.len .. end], 10) catch return error.NoContentLength;
    reader.discardAll(body_len) catch return error.ReadFailed;
}

/// Monotonic nanoseconds, for bounding a call rather than measuring it.
fn monotonicNs(io: Io) i96 {
    return Io.Clock.awake.now(io).nanoseconds;
}

/// Create a connected client to the given port.
fn connectClient(port: u16) !httpz.Client {
    const io = getTestIo();
    var client = try httpz.Client.init(testing.allocator, .{
        .host = "127.0.0.1",
        .port = port,
        .read_timeout_s = 5,
    });
    client.connect(io) catch {
        client.deinit();
        return error.ConnectionFailed;
    };
    return client;
}

/// Shared test Io — creates a proper Io.Threaded for integration tests
/// instead of std.testing.io which is unsuitable for real network I/O.
fn getTestIo() Io {
    const state = struct {
        var instance: ?Io.Threaded = null;
    };
    if (state.instance == null) {
        state.instance = Io.Threaded.init(std.heap.page_allocator, .{});
    }
    return state.instance.?.io();
}

// ─── Basic HTTP Server Tests ────────────────────────────────────

test "integration: basic GET returns 200 with body" {
    ensurePlainServer();
    var client = try connectClient(plain_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("Hello, World!", resp.body);
}

test "integration: GET /json returns application/json" {
    ensurePlainServer();
    var client = try connectClient(plain_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/json", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("{\"status\":\"ok\"}", resp.body);
    try testing.expectEqualStrings("application/json", resp.headers.get("Content-Type").?);
}

test "integration: GET /not-a-route returns 404" {
    ensurePlainServer();
    var client = try connectClient(plain_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/nope", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.not_found, resp.status);
}

test "integration: POST with body echoed back" {
    ensurePlainServer();
    var client = try connectClient(plain_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .POST, "/echo", null, "hello from client");
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("hello from client", resp.body);
}

test "integration: redirect returns 302 with Location" {
    ensurePlainServer();
    var client = try connectClient(plain_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/redirect", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.found, resp.status);
    try testing.expectEqualStrings("/", resp.headers.get("Location").?);
}

test "integration: 204 No Content has no body" {
    ensurePlainServer();
    const raw = try rawRequest(
        plain_port,
        "GET /empty HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    defer testing.allocator.free(raw);

    try testing.expect(std.mem.indexOf(u8, raw, "204 No Content") != null);
    const header_end = std.mem.indexOf(u8, raw, "\r\n\r\n").?;
    try testing.expectEqual(raw.len, header_end + 4);
}

test "integration: gzip compression" {
    ensurePlainServer();
    const raw = try rawRequest(
        plain_port,
        "GET /gzip HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Accept-Encoding: gzip\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    defer testing.allocator.free(raw);

    try testing.expect(std.mem.indexOf(u8, raw, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Content-Encoding: gzip") != null);
}

test "integration: standard headers present (Date, Server)" {
    ensurePlainServer();
    var client = try connectClient(plain_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expect(resp.headers.get("Date") != null);
    try testing.expect(resp.headers.get("Server") != null);
    try testing.expectEqualStrings("httpz/0.1", resp.headers.get("Server").?);
}

test "integration: Content-Length header is set" {
    ensurePlainServer();
    var client = try connectClient(plain_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expectEqualStrings("13", resp.headers.get("Content-Length").?);
}

test "integration: HEAD returns headers but no body" {
    ensurePlainServer();
    const raw = try rawRequest(
        plain_port,
        "HEAD / HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    defer testing.allocator.free(raw);

    try testing.expect(std.mem.indexOf(u8, raw, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Content-Length: 13") != null);
    const header_end = std.mem.indexOf(u8, raw, "\r\n\r\n").?;
    try testing.expectEqual(raw.len, header_end + 4);
}

test "integration: keep-alive allows multiple requests" {
    ensurePlainServer();
    var client = try connectClient(plain_port);
    defer client.deinit();

    var resp1 = try client.request(getTestIo(), .GET, "/", null, null);
    defer resp1.deinit(testing.allocator);
    try testing.expectEqual(httpz.Response.StatusCode.ok, resp1.status);
    try testing.expectEqualStrings("Hello, World!", resp1.body);

    var resp2 = try client.request(getTestIo(), .GET, "/json", null, null);
    defer resp2.deinit(testing.allocator);
    try testing.expectEqual(httpz.Response.StatusCode.ok, resp2.status);
    try testing.expectEqualStrings("{\"status\":\"ok\"}", resp2.body);
}

// ─── Router Tests ───────────────────────────────────────────────

test "integration: router dispatches to correct handler" {
    ensureRouterServer();
    var client = try connectClient(router_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("<h1>Home</h1>", resp.body);
}

test "integration: router extracts path parameters" {
    ensureRouterServer();
    var client = try connectClient(router_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/users/42", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("42", resp.body);
}

test "integration: router POST returns 201 Created" {
    ensureRouterServer();
    var client = try connectClient(router_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .POST, "/users", null, "{}");
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.created, resp.status);
    try testing.expectEqualStrings("{\"id\":1}", resp.body);
}

test "integration: router 404 for unmatched route" {
    ensureRouterServer();
    var client = try connectClient(router_port);
    defer client.deinit();

    var resp = try client.request(getTestIo(), .GET, "/nonexistent", null, null);
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(httpz.Response.StatusCode.not_found, resp.status);
}

test "integration: router compression middleware" {
    ensureRouterServer();
    const raw = try rawRequest(
        router_port,
        "GET /compressed HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Accept-Encoding: gzip\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    defer testing.allocator.free(raw);

    try testing.expect(std.mem.indexOf(u8, raw, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Content-Encoding: gzip") != null);
}

// ─── Streaming Tests ────────────────────────────────────────────

test "integration: streaming chunked response" {
    ensureRouterServer();
    const raw = try rawRequest(
        router_port,
        "GET /stream/chunks HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    defer testing.allocator.free(raw);

    try testing.expect(std.mem.indexOf(u8, raw, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Transfer-Encoding: chunked") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "chunk 0") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "chunk 4") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Connection: close") != null);
}

test "integration: streaming SSE response" {
    ensureRouterServer();
    const raw = try rawRequest(
        router_port,
        "GET /stream/events HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    defer testing.allocator.free(raw);

    try testing.expect(std.mem.indexOf(u8, raw, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "text/event-stream") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Cache-Control: no-cache") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "data: event 0") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "data: event 2") != null);
}

test "integration: streaming large response" {
    ensureRouterServer();
    const raw = try rawRequest(
        router_port,
        "GET /stream/large HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n" ++
            "\r\n",
    );
    defer testing.allocator.free(raw);

    try testing.expect(std.mem.indexOf(u8, raw, "200 OK") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "Transfer-Encoding: chunked") != null);
    try testing.expect(raw.len > 22000);
    try testing.expect(std.mem.indexOf(u8, raw, "All work and no play") != null);
}

// ─── Server Lifecycle Tests ─────────────────────────────────────

// A stopped server has to give back what it took: `run` returns, the
// connections it was serving and the sweeper thread are gone with it, and an
// allocator that saw every allocation the server made is empty again.
//
// The allocator is checked here rather than in a `defer`: a defer runs after
// the check and its frees would then be reported as leaks.
test "integration: stopping the server returns from run and leaks nothing" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    var threaded = Io.Threaded.init(gpa.allocator(), .{});
    const io = threaded.io();

    var server = httpz.Server.init(.{
        .port = 0, // ephemeral: two test processes must not fight over a port
        .address = "127.0.0.1",
        .max_connections = 8,
        // Short, so that a stop is not held up by a whole sweeper interval and
        // the accept loop looks at the stop flag often.
        .sweeper_interval_ms = 20,
        .accept_poll_interval_ms = 20,
    }, plainHandler);

    const Runner = struct {
        fn run(srv: *httpz.Server, sio: Io) void {
            srv.run(sio) catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{ &server, io });

    // The config asked for an ephemeral port, so wait for `run` to bind and
    // then ask the server which port it got.
    var port: u16 = 0;
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        port = server.boundPort();
        if (port != 0) break;
        osSleep(10);
    }
    try testing.expect(port != 0);

    const raw = try rawRequest(port, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    defer testing.allocator.free(raw);
    try testing.expect(std.mem.startsWith(u8, raw, "HTTP/1.1 200 OK"));
    try testing.expect(std.mem.endsWith(u8, raw, "Hello, World!"));

    // A second connection that sends nothing and stays open: the server is
    // holding it and blocked in a read on it when it is asked to stop. Wait for
    // the accept loop to take it rather than guessing a delay.
    const addr = Io.net.IpAddress.parseIp4("127.0.0.1", port) catch return error.InvalidAddress;
    const idle = Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream }) catch return error.ConnectionFailed;
    attempts = 0;
    while (attempts < 200 and server.active_connections.load(.monotonic) == 0) : (attempts += 1) {
        osSleep(5);
    }
    try testing.expect(server.active_connections.load(.monotonic) > 0);

    server.stop();
    thread.join(); // never returns if the stop did not reach the accept loop

    idle.close(io);
    server.deinit();
    threaded.deinit();

    try testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

// ─── Graceful Stop Tests ────────────────────────────────────────

// A request being handled when the stop lands is work the server owes the
// client, so a graceful stop answers it before it goes: the response arrives
// whole, it says the connection is done with, and the stop has nothing to cut
// off and none of it to report.
//
// The idle connection is what makes the test deterministic: the drain closes
// idle connections the moment it starts, so its end of file is how this thread
// learns the drain has begun before it lets the handler go. That is also the
// signal a clock could not give — a sleep would guess when the drain starts
// rather than know it.
test "integration: a request in flight when stopGraceful is called is answered in full" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    var threaded = Io.Threaded.init(gpa.allocator(), .{});
    const io = threaded.io();

    resetSlowHandler();

    var server = httpz.Server.init(.{
        .port = 0, // ephemeral: two test processes must not fight over a port
        .address = "127.0.0.1",
        .max_connections = 8,
        .sweeper_interval_ms = 20,
        .accept_poll_interval_ms = 20,
    }, slowHandler);
    const background = try startServer(&server, io);

    // A keep-alive connection with nothing on it: one request answered, then
    // the server waiting for the next one on it.
    const idle = try connectRaw(io, background.port);
    var idle_write_buf: [1024]u8 = undefined;
    var idle_read_buf: [1024]u8 = undefined;
    var idle_writer = Io.net.Stream.Writer.init(idle, io, &idle_write_buf);
    var idle_reader = Io.net.Stream.Reader.init(idle, io, &idle_read_buf);
    try idle_writer.interface.writeAll("GET /fast HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    try idle_writer.interface.flush();
    try readOneResponse(&idle_reader.interface);

    // The slow request goes out on a thread of its own: this thread has to be
    // free to release the handler while the drain is waiting for the response.
    var response: []const u8 = &.{};
    const Requester = struct {
        fn run(port: u16, out: *[]const u8) void {
            out.* = rawRequest(port, "GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") catch return;
        }
    };
    const requester = try std.Thread.spawn(.{}, Requester.run, .{ background.port, &response });
    try waitForSlowHandler();

    var cut_off: u32 = 0;
    const Drainer = struct {
        fn run(srv: *httpz.Server, sio: Io, out: *u32) void {
            out.* = srv.stopGraceful(sio, 5 * std.time.ns_per_s);
        }
    };
    const drainer = try std.Thread.spawn(.{}, Drainer.run, .{ &server, io, &cut_off });

    var closed_buf: [16]u8 = undefined;
    try testing.expectError(error.EndOfStream, idle_reader.interface.readSliceAll(&closed_buf));

    slow_release.store(true, .release);
    requester.join();
    drainer.join();

    try testing.expectEqual(@as(u32, 0), cut_off);
    try testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK"));
    try testing.expect(std.mem.endsWith(u8, response, "slow done"));
    try testing.expect(std.mem.indexOf(u8, response, "Connection: close") != null);
    // And the request was left alone: a cancelation request reaching the
    // handler would have come back from its sleep as `error.Canceled`.
    try testing.expect(!slow_canceled.load(.acquire));
    testing.allocator.free(response);

    idle.close(io);
    background.thread.join();
    server.deinit();
    threaded.deinit();

    try testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

// An idle keep-alive connection is not work: nothing is in flight on it, so the
// stop closes it instead of waiting. That the call comes back long before its
// deadline is the assertion — a drain that waited out its five seconds would
// hold a deploy up for five seconds per idle client.
test "integration: stopGraceful closes an idle connection rather than waiting it out" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    var threaded = Io.Threaded.init(gpa.allocator(), .{});
    const io = threaded.io();

    var server = httpz.Server.init(.{
        .port = 0,
        .address = "127.0.0.1",
        .max_connections = 8,
        .sweeper_interval_ms = 20,
        .accept_poll_interval_ms = 20,
    }, plainHandler);
    const background = try startServer(&server, io);

    const idle = try connectRaw(io, background.port);
    var write_buf: [1024]u8 = undefined;
    var read_buf: [1024]u8 = undefined;
    var writer = Io.net.Stream.Writer.init(idle, io, &write_buf);
    var reader = Io.net.Stream.Reader.init(idle, io, &read_buf);
    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    try writer.interface.flush();
    try readOneResponse(&reader.interface);

    const started = monotonicNs(io);
    const cut_off = server.stopGraceful(io, 5 * std.time.ns_per_s);
    const elapsed = monotonicNs(io) - started;

    // Nothing was in flight, so nothing was cut off — the connection was
    // closed, which is not the same thing and not what the count is for.
    try testing.expectEqual(@as(u32, 0), cut_off);
    try testing.expect(elapsed < 2 * std.time.ns_per_s);

    var closed_buf: [16]u8 = undefined;
    try testing.expectError(error.EndOfStream, reader.interface.readSliceAll(&closed_buf));

    idle.close(io);
    background.thread.join();
    server.deinit();
    threaded.deinit();

    try testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

// A connection opened after the stop has landed is never served: the server
// takes no new ones, so the request either gets no answer or a socket that ends
// under it. It is the listener closing with `run` that ends this one, which is
// why the read waits for `run` to be gone first and cannot hang on a server
// that meant to answer.
test "integration: a connection opened during the drain is not served" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    var threaded = Io.Threaded.init(gpa.allocator(), .{});
    const io = threaded.io();

    resetSlowHandler();

    var server = httpz.Server.init(.{
        .port = 0,
        .address = "127.0.0.1",
        .max_connections = 8,
        .sweeper_interval_ms = 20,
        .accept_poll_interval_ms = 20,
    }, slowHandler);
    const background = try startServer(&server, io);

    const idle = try connectRaw(io, background.port);
    var idle_write_buf: [1024]u8 = undefined;
    var idle_read_buf: [1024]u8 = undefined;
    var idle_writer = Io.net.Stream.Writer.init(idle, io, &idle_write_buf);
    var idle_reader = Io.net.Stream.Reader.init(idle, io, &idle_read_buf);
    try idle_writer.interface.writeAll("GET /fast HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    try idle_writer.interface.flush();
    try readOneResponse(&idle_reader.interface);

    // Hold a request in flight so that the drain has a reason to still be
    // running when the late connection turns up.
    var response: []const u8 = &.{};
    const Requester = struct {
        fn run(port: u16, out: *[]const u8) void {
            out.* = rawRequest(port, "GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") catch return;
        }
    };
    const requester = try std.Thread.spawn(.{}, Requester.run, .{ background.port, &response });
    try waitForSlowHandler();

    var cut_off: u32 = 0;
    const Drainer = struct {
        fn run(srv: *httpz.Server, sio: Io, out: *u32) void {
            out.* = srv.stopGraceful(sio, 5 * std.time.ns_per_s);
        }
    };
    const drainer = try std.Thread.spawn(.{}, Drainer.run, .{ &server, io, &cut_off });

    var closed_buf: [16]u8 = undefined;
    try testing.expectError(error.EndOfStream, idle_reader.interface.readSliceAll(&closed_buf));

    // The drain has started, and this connection is opened after it did.
    const late = try connectRaw(io, background.port);
    var late_write_buf: [1024]u8 = undefined;
    var late_writer = Io.net.Stream.Writer.init(late, io, &late_write_buf);
    late_writer.interface.writeAll("GET /fast HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") catch {};
    late_writer.interface.flush() catch {};

    slow_release.store(true, .release);
    requester.join();
    drainer.join();
    background.thread.join();

    // Nothing on the socket: no status line, no body, no response.
    var late_buf: [512]u8 = undefined;
    var late_reader = Io.net.Stream.Reader.init(late, io, &late_buf);
    const late_bytes = late_reader.interface.readSliceShort(&late_buf) catch 0;
    try testing.expectEqual(@as(usize, 0), late_bytes);

    testing.allocator.free(response);
    late.close(io);
    idle.close(io);
    server.deinit();
    threaded.deinit();

    try testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

// A drain that runs out of deadline cuts off what is left, says how much that
// was, and gives the server its memory back all the same.
test "integration: a graceful stop that runs out of deadline reports the connections it cut off" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    var threaded = Io.Threaded.init(gpa.allocator(), .{});
    const io = threaded.io();

    resetSlowHandler();

    var server = httpz.Server.init(.{
        .port = 0,
        .address = "127.0.0.1",
        .max_connections = 8,
        .sweeper_interval_ms = 20,
        .accept_poll_interval_ms = 20,
    }, slowHandler);
    const background = try startServer(&server, io);

    const Requester = struct {
        fn run(port: u16) void {
            const raw = rawRequest(port, "GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n") catch return;
            testing.allocator.free(raw);
        }
    };
    const requester = try std.Thread.spawn(.{}, Requester.run, .{background.port});
    try waitForSlowHandler();

    // The request is still in flight when the deadline passes, so the stop does
    // not wait for it: the one connection still serving is cut off and counted.
    const cut_off = server.stopGraceful(io, 50 * std.time.ns_per_ms);
    try testing.expectEqual(@as(u32, 1), cut_off);

    // What the cut request's client got is not the point — it may be nothing at
    // all. What matters is that the request was cut off rather than left to
    // finish: `run` cancels the connection once the drain gives up on it, and
    // the handler sees that as a cancelation.
    const canceled = waitForSlowCanceled();
    // Let the handler go either way, so that the joins below cannot outlive the
    // failure they would be reporting.
    slow_release.store(true, .release);
    requester.join();
    background.thread.join();
    try canceled;
    server.deinit();
    threaded.deinit();

    try testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

// ─── WebSocket Tests ────────────────────────────────────────────

test "integration: websocket upgrade and echo" {
    ensureRouterServer();
    var threaded = Io.Threaded.init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = Io.net.IpAddress.parseIp4("127.0.0.1", router_port) catch unreachable;
    const stream = Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream }) catch
        return error.ConnectionFailed;
    defer stream.close(io);

    var write_buf: [4096]u8 = undefined;
    var read_buf: [8192]u8 = undefined;
    var net_writer = Io.net.Stream.Writer.init(stream, io, &write_buf);
    var net_reader = Io.net.Stream.Reader.init(stream, io, &read_buf);

    // Send WebSocket upgrade request
    net_writer.interface.writeAll(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    ) catch return error.SendFailed;
    net_writer.interface.flush() catch return error.SendFailed;

    // Read the upgrade response line by line until blank line
    var resp_buf: [1024]u8 = undefined;
    var resp_len: usize = 0;
    while (resp_len < resp_buf.len) {
        const line = net_reader.interface.takeDelimiterInclusive('\n') catch break;
        @memcpy(resp_buf[resp_len..][0..line.len], line);
        resp_len += line.len;
        // Blank line = end of headers
        if (line.len == 2 and line[0] == '\r' and line[1] == '\n') break;
    }

    const resp_str = resp_buf[0..resp_len];
    try testing.expect(std.mem.indexOf(u8, resp_str, "101 Switching Protocols") != null);
    try testing.expect(std.mem.indexOf(u8, resp_str, "Upgrade: websocket") != null);
    try testing.expect(std.mem.indexOf(u8, resp_str, "Sec-WebSocket-Accept:") != null);

    // Send a masked text frame (client frames must be masked per RFC 6455)
    const msg = "Hello WebSocket!";
    try sendMaskedFrame(&net_writer.interface, .text, msg);

    // Receive the echo (server frames are NOT masked per RFC 6455 Section 5.1)
    var ws_buf: [4096]u8 = undefined;
    const echo = readUnmaskedFrame(&net_reader.interface, &ws_buf) catch return error.RecvFailed;
    try testing.expect(echo != null);
    try testing.expectEqualStrings("Hello WebSocket!", echo.?);

    // Send close
    try sendMaskedFrame(&net_writer.interface, .close, &[_]u8{ 0x03, 0xe8 });
}

/// Read an unmasked frame from the server (RFC 6455: server-to-client frames are NOT masked).
fn readUnmaskedFrame(reader: *Io.Reader, buf: []u8) !?[]const u8 {
    var header: [2]u8 = undefined;
    reader.readSliceAll(&header) catch return null;

    const opcode: u4 = @truncate(header[0] & 0x0f);
    if (opcode == 8) return null; // close frame
    var payload_len: u64 = header[1] & 0x7f;

    if (payload_len == 126) {
        var ext: [2]u8 = undefined;
        reader.readSliceAll(&ext) catch return null;
        payload_len = std.mem.readInt(u16, &ext, .big);
    } else if (payload_len == 127) {
        var ext: [8]u8 = undefined;
        reader.readSliceAll(&ext) catch return null;
        payload_len = std.mem.readInt(u64, &ext, .big);
    }

    if (payload_len > buf.len) return error.MessageTooBig;
    const len: usize = @intCast(payload_len);
    const payload = buf[0..len];
    if (len > 0) {
        reader.readSliceAll(payload) catch return null;
    }
    return payload;
}

fn sendMaskedFrame(writer: *Io.Writer, opcode: httpz.WebSocket.Opcode, payload: []const u8) !void {
    var header: [14]u8 = undefined;
    var header_len: usize = 2;

    header[0] = 0x80 | @as(u8, @backingInt(opcode));
    if (payload.len < 126) {
        header[1] = 0x80 | @as(u8, @intCast(payload.len));
    } else if (payload.len <= 65535) {
        header[1] = 0x80 | 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        header_len = 4;
    } else {
        return error.PayloadTooLarge;
    }

    const mask_key = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
    @memcpy(header[header_len..][0..4], &mask_key);
    header_len += 4;

    writer.writeAll(header[0..header_len]) catch return error.WriteFailed;

    var masked: [256]u8 = undefined;
    for (payload, 0..) |b, i| {
        masked[i] = b ^ mask_key[i % 4];
    }
    writer.writeAll(masked[0..payload.len]) catch return error.WriteFailed;
    writer.flush() catch return error.WriteFailed;
}
