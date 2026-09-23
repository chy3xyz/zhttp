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

// ─── Helpers ────────────────────────────────────────────────────

/// Kernel-level sleep that doesn't go through Io.
fn osSleep(ms: u32) void {
    const ts = std.posix.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast(@as(u64, ms % 1000) * 1_000_000),
    };
    _ = std.os.linux.nanosleep(@ptrCast(&ts), null);
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
