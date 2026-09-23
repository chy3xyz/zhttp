//! End-to-end coverage for the QUIC layer: a real client against a real server
//! over loopback. The server runs on a background thread that outlives the test
//! (its `run` loop never returns), so it is allocated with the page allocator to
//! keep the testing allocator's leak detection out of it.
const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const client_mod = @import("Client.zig");
const server_mod = @import("Server.zig");
const Client = @import("Client.zig").Client;
const Server = @import("Server.zig").Server;
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");

fn nowNanos() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn handler(_: std.mem.Allocator, _: *const server_mod.Request) server_mod.Response {
    return .{ .body = "OK" };
}

fn serve(server: *Server) void {
    server.run() catch {};
}

fn sleepMs(ms: u64) void {
    var req = std.posix.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    while (std.posix.errno(std.posix.system.nanosleep(&req, &req)) == .INTR) {}
}

test "quic: handshake completes against the h3 server" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, handler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    var attempt: usize = 0;
    while (attempt < 200) : (attempt += 1) {
        quic.flushPackets(&client.quic_conn) catch {};
        quic.readPacket(&client.quic_conn) catch {};

        // A stream can only be opened once the handshake is confirmed.
        var stream_id: i64 = -1;
        if (ngtcp2.ngtcp2_conn_open_bidi_stream(client.quic_conn.conn, &stream_id, null) == 0) {
            try std.testing.expect(ngtcp2.ngtcp2_conn_get_handshake_completed(client.quic_conn.conn) != 0);
            return;
        }
        sleepMs(10);
    }

    return error.HandshakeTimeout;
}

test "h3: client gets the handler's response" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, handler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    const body = try client.get("/");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("OK", body);

    // A second request runs over the same connection and QPACK streams.
    const again = try client.get("/");
    defer allocator.free(again);
    try std.testing.expectEqualStrings("OK", again);
}

/// Answers 201 with the value of `x-test` — but only once it has seen the
/// method, the path and the body the request-inspection tests send, so the
/// answer alone says which of them arrived.
fn echoHandler(_: std.mem.Allocator, request: *const server_mod.Request) server_mod.Response {
    if (request.method != .POST) return .{ .status = .method_not_allowed, .body = "method" };
    if (!std.mem.eql(u8, request.path, "/echo")) return .{ .status = .not_found, .body = "path" };
    const seen = request.headers.get("x-test") orelse return .{ .status = .bad_request, .body = "no x-test" };
    if (!std.mem.eql(u8, request.body, "payload")) return .{ .status = .bad_request, .body = "body" };
    return .{ .status = .created, .content_type = "text/x-seen", .body = seen };
}

test "h3: the method, path, headers and body of a request reach the handler" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, echoHandler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    const answer = try client.send("POST", "/echo", &.{
        .{ .name = "x-test", .value = "seen-value" },
        .{ .name = "user-agent", .value = "httpz-test" },
    }, "payload");
    defer allocator.free(answer.header_text);
    defer allocator.free(answer.body);

    try std.testing.expectEqual(@as(u16, 201), answer.status);
    try std.testing.expect(std.mem.indexOf(u8, answer.header_text, "content-type: text/x-seen") != null);
    try std.testing.expectEqualStrings("seen-value", answer.body);
}

test "h3: a body over the limit is answered with 413" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, handler, .{ .max_request_body_bytes = 4 });
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    // Five bytes into a four-byte limit. The request is answered rather than
    // dropped, so the connection stays usable: a request that fits is served
    // right after it.
    const too_big = try client.send("POST", "/", &.{}, "12345");
    defer allocator.free(too_big.header_text);
    defer allocator.free(too_big.body);
    try std.testing.expectEqual(@as(u16, 413), too_big.status);

    const ok = try client.send("POST", "/", &.{}, "1234");
    defer allocator.free(ok.header_text);
    defer allocator.free(ok.body);
    try std.testing.expectEqual(@as(u16, 200), ok.status);
    try std.testing.expectEqualStrings("OK", ok.body);
}

/// Answers with two header fields of its own, and tries to send one that
/// repeats Content-Length.
fn headersHandler(_: std.mem.Allocator, request: *const server_mod.Request) server_mod.Response {
    _ = request;
    return .{
        .status = .found,
        .body = "moved",
        .headers = &.{
            .{ .name = "location", .value = "/elsewhere" },
            .{ .name = "set-cookie", .value = "a=b; HttpOnly" },
            .{ .name = "content-length", .value = "999" },
        },
    };
}

test "h3: a handler's own response headers reach the client" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, headersHandler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    const answer = try client.request("/");
    defer allocator.free(answer.header_text);
    defer allocator.free(answer.body);

    try std.testing.expectEqual(@as(u16, 302), answer.status);
    try std.testing.expect(std.mem.indexOf(u8, answer.header_text, "location: /elsewhere") != null);
    try std.testing.expect(std.mem.indexOf(u8, answer.header_text, "set-cookie: a=b; HttpOnly") != null);
    // The handler's own content-length is dropped, not sent beside the real one:
    // the body is five bytes long, and a second field would be malformed.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, answer.header_text, "content-length:"));
    try std.testing.expect(std.mem.indexOf(u8, answer.header_text, "content-length: 5") != null);
    try std.testing.expectEqualStrings("moved", answer.body);
}

test "h3: a stopped server gives everything back" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    // A leak-checking allocator over a whole exchange: the server and the
    // client both take their per-request state — the request arena, the header
    // arrays, the response body — from it, so anything that never comes back
    // fails the test instead of running until the process exits.
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();

    var server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, echoHandler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    const thread = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    const answer = try client.send("POST", "/echo", &.{
        .{ .name = "x-test", .value = "seen-value" },
    }, "payload");
    allocator.free(answer.header_text);
    allocator.free(answer.body);
    try std.testing.expectEqual(@as(u16, 201), answer.status);
    client.deinit();

    // The server notices `stop` between turns and closes what it was serving.
    server.stop();
    thread.join();
    server.deinit();
    allocator.destroy(server);

    try std.testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

test "h3: serves a second client while the first is still connected" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, handler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var first = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer first.deinit();
    const first_body = try first.get("/");
    defer allocator.free(first_body);
    try std.testing.expectEqualStrings("OK", first_body);

    // The first connection is still open and idle in the server's routing
    // table; a second client has to be served without waiting for it.
    var second = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer second.deinit();
    const second_body = try second.get("/");
    defer allocator.free(second_body);
    try std.testing.expectEqualStrings("OK", second_body);

    // And the first connection is still usable afterwards.
    const first_again = try first.get("/");
    defer allocator.free(first_again);
    try std.testing.expectEqualStrings("OK", first_again);
}

// The idle-timeout path: the server starts closing a quiet connection, answers
// what the peer still sends with the same CONNECTION_CLOSE, and reaps the
// connection when the period is over. It runs on a leak-checking allocator
// because that path frees a connection, its H3 state and its routing entries,
// which is the bookkeeping most likely to go wrong.
test "h3: a closing connection answers the peer with CONNECTION_CLOSE" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const allocator = gpa.allocator();

    var server = try allocator.create(Server);
    // A short idle timeout so the server starts closing while the test watches.
    server.* = try Server.init(allocator, 0, handler, .{
        .idle_timeout_ns = 200 * std.time.ns_per_ms,
        .closing_period_ns = 2 * std.time.ns_per_s,
    });
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    const thread = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    const body = try client.get("/");
    try std.testing.expectEqualStrings("OK", body);
    // Freed here rather than by a `defer`: the leak check at the end of the
    // test runs before the function's defers do.
    allocator.free(body);

    // Let the connection go idle, so the server enters its closing period.
    sleepMs(1500);

    // Whatever the client sends now is answered by the buffered
    // CONNECTION_CLOSE, and the client notices the connection is gone instead
    // of waiting out its own timeout.
    try std.testing.expectError(error.ConnectionClosed, client.get("/"));
    client.deinit();

    // Long enough for the closing period to be over and the connection to be
    // reaped before the server is taken down.
    sleepMs(1500);
    server.stop();
    thread.join();
    server.deinit();
    allocator.destroy(server);

    try std.testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

test "h3: server drops a connection as soon as the client closes it" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, handler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    const body = try client.get("/");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("OK", body);
    // One connection, but several routing entries: the client's original
    // connection ID plus the ones ngtcp2 issues.
    try std.testing.expect(server.listener.connections.count() > 0);

    // The close frame tells the server to drop the connection instead of
    // waiting out its idle timeout.
    client.deinit();

    var waited: usize = 0;
    while (waited < 100) : (waited += 1) {
        if (server.listener.connections.count() == 0) return;
        sleepMs(50);
    }
    return error.ConnectionNotReaped;
}

/// Every byte of a bulk response is derived from its offset, so a truncated or
/// reordered body shows up as a mismatch.
fn responseByte(i: usize) u8 {
    return @intCast('a' + (i % 26));
}

/// Twice the 1 MB initial window both endpoints advertise. Nothing this size can
/// be delivered unless consuming the first window buys the peer credit for the
/// second one.
const bulk_len = 2 * 1024 * 1024;

fn bulkHandler(_: std.mem.Allocator, _: *const server_mod.Request) server_mod.Response {
    return .{ .body = bulkBody() };
}

/// The bulk response is the same bytes on every call, so it is built once and
/// handed out as a view the server copies.
var bulk_body_buf: [bulk_len]u8 = undefined;
var bulk_body_ready = false;

fn bulkBody() []const u8 {
    if (!bulk_body_ready) {
        for (&bulk_body_buf, 0..) |*b, i| b.* = responseByte(i);
        bulk_body_ready = true;
    }
    return &bulk_body_buf;
}

test "h3: a response larger than the flow control window arrives complete" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, bulkHandler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    const body = try client.get("/bulk");
    defer allocator.free(body);

    try std.testing.expectEqual(@as(usize, bulk_len), body.len);
    for (body, 0..) |b, i| {
        if (b != responseByte(i)) return error.BodyCorrupted;
    }
}

/// The bulk body for "/large" and the small one for anything else, so one
/// connection can be kept busy transferring while another asks for something
/// small.
fn bulkOrOkHandler(_: std.mem.Allocator, request: *const server_mod.Request) server_mod.Response {
    if (!std.mem.eql(u8, request.path, "/large")) return .{ .body = "OK" };
    return .{ .body = bulkBody() };
}

/// One client's whole request run on its own thread, so the test can watch how
/// long it takes instead of sitting in the client's own 30 s timeout. It is
/// heap-allocated: a run that is still going when the test gives up must not
/// write into a frame that no longer exists.
const RequestRun = struct {
    client: ?Client = null,
    body: []const u8 = &.{},
    err: ?anyerror = null,
    done: std.atomic.Value(bool),

    fn create() !*RequestRun {
        const run = try std.heap.page_allocator.create(RequestRun);
        run.* = .{ .done = std.atomic.Value(bool).init(false) };
        return run;
    }
};

fn runRequest(run: *RequestRun, host: []const u8, port: u16, path: []const u8) void {
    defer run.done.store(true, .release);

    const allocator = std.heap.page_allocator;
    run.client = Client.init(allocator, host, port, .{ .insecure_skip_verify = true }) catch |err| {
        run.err = err;
        return;
    };
    run.body = run.client.?.get(path) catch |err| {
        run.err = err;
        return;
    };
}

/// Wait for a request run to finish, giving up after |ms| instead of blocking
/// for as long as the request itself would take.
fn waitForRun(run: *RequestRun, ms: u64) !void {
    var waited: u64 = 0;
    while (waited < ms) : (waited += 10) {
        if (run.done.load(.acquire)) return;
        sleepMs(10);
    }
    return error.RequestStalled;
}

test "h3: a second client is served while a large response is in flight" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, bulkOrOkHandler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    // Client A pulls the 2 MB body on its own thread.
    const large = try RequestRun.create();
    _ = try std.Thread.spawn(.{}, runRequest, .{ large, "127.0.0.1", port, "/large" });

    // Once the server knows about A, its response is on its way; a moment later
    // the second client arrives while that transfer is still running.
    var waited: usize = 0;
    while (server.listener.connections.count() == 0 and waited < 500) : (waited += 1) sleepMs(10);
    sleepMs(150);

    // Client B's request has to be answered on its own connection meanwhile.
    // The wait is bounded: when the server's write pump spins on a connection it
    // cannot send on, B is never served and this fails here in seconds instead
    // of after B's own 30 s timeout.
    const small = try RequestRun.create();
    _ = try std.Thread.spawn(.{}, runRequest, .{ small, "127.0.0.1", port, "/" });
    waitForRun(small, 10 * std.time.ms_per_s) catch return error.SecondClientNotServed;
    if (small.err) |err| return err;
    try std.testing.expectEqualStrings("OK", small.body);

    // And A's transfer is unaffected: it ends with the whole body.
    waitForRun(large, 15 * std.time.ms_per_s) catch return error.LargeResponseStalled;
    if (large.err) |err| return err;
    try std.testing.expectEqual(@as(usize, bulk_len), large.body.len);
    for (large.body, 0..) |b, i| {
        if (b != responseByte(i)) return error.BodyCorrupted;
    }
}

test "h3: one connection serves well over a hundred requests" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, handler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    // A connection advertises a stream limit to its peer, and this client closes
    // each stream once its response has been read, so the requests go out one at
    // a time on the connection that is already there.
    const requests = 110;
    for (0..requests) |i| {
        const body = client.get("/") catch |err| {
            std.debug.print("h3: request {d} of {d} failed: {s}\n", .{ i + 1, requests, @errorName(err) });
            return err;
        };
        defer allocator.free(body);
        try std.testing.expectEqualStrings("OK", body);
    }
}

test "h3: a client that verifies certificates rejects the self-signed server" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, handler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    // `.{}` keeps verification on, and the test certificate is self-signed, so
    // the handshake has to fail with a TLS error rather than a generic failure
    // or a wait for some timeout.
    const start = nowNanos();
    try std.testing.expectError(error.TlsError, Client.init(allocator, "127.0.0.1", port, .{}));
    const elapsed_ms = (nowNanos() - start) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms < 5000);
}

test "quic: a stream read that fails is reported as a connection error" {
    const session = try http3.Session.init(std.testing.allocator);
    defer session.deinit();

    // Stream 4 was never opened by either endpoint: nghttp3 must reject data
    // arriving on it, and the bridge must report that as the connection error
    // nghttp3's header says it is, rather than as "nothing was consumed".
    const result = client_mod.onQuicStreamData(@ptrCast(session.conn), 4, "GET", true, nowNanos());
    try std.testing.expect(result == .connection_error);
}

test "h3: resolves the host name it is given" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    server.* = try Server.init(allocator, 0, handler, .{});
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    // A name has to be resolved into the address the connection is opened
    // against, not assumed to be loopback.
    var client = try Client.init(allocator, "localhost", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    const body = try client.get("/");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("OK", body);
}
