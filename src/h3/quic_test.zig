//! End-to-end coverage for the QUIC layer: a real client against a real server
//! over loopback. The server runs on a background thread that outlives the test
//! (its `run` loop never returns), so it is allocated with the page allocator to
//! keep the testing allocator's leak detection out of it.
const std = @import("std");
const quic = @import("quic.zig");
const Client = @import("Client.zig").Client;
const Server = @import("Server.zig").Server;
const ngtcp2 = @import("ngtcp2_c");

fn handler(allocator: std.mem.Allocator, _: []const u8) []const u8 {
    return allocator.dupe(u8, "OK") catch "OK";
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

test "h3: a closing connection answers the peer with CONNECTION_CLOSE" {
    try quic.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(Server);
    // A short idle timeout so the server starts closing while the test watches.
    server.* = try Server.init(allocator, 0, handler, .{
        .idle_timeout_ns = 200 * std.time.ns_per_ms,
        .closing_period_ns = 2 * std.time.ns_per_s,
    });
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();
    const body = try client.get("/");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("OK", body);

    // Let the connection go idle, so the server enters its closing period.
    sleepMs(1500);

    // Whatever the client sends now is answered by the buffered
    // CONNECTION_CLOSE, and the client notices the connection is gone instead
    // of waiting out its own timeout.
    try std.testing.expectError(error.ConnectionClosed, client.get("/"));
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

fn bulkHandler(allocator: std.mem.Allocator, _: []const u8) []const u8 {
    const body = allocator.alloc(u8, bulk_len) catch return "";
    for (body, 0..) |*b, i| b.* = responseByte(i);
    return body;
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
fn bulkOrOkHandler(allocator: std.mem.Allocator, request: []const u8) []const u8 {
    if (!std.mem.eql(u8, request, "/large")) return allocator.dupe(u8, "OK") catch "OK";

    const body = allocator.alloc(u8, bulk_len) catch return "";
    for (body, 0..) |*b, i| b.* = responseByte(i);
    return body;
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
