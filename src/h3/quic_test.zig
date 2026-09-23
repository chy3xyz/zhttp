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
    server.* = try Server.init(allocator, 14777, handler, .{});
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", 14777, .{ .insecure_skip_verify = true });
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
    server.* = try Server.init(allocator, 14778, handler, .{});
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", 14778, .{ .insecure_skip_verify = true });
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
    server.* = try Server.init(allocator, 14779, handler, .{});
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var first = try Client.init(allocator, "127.0.0.1", 14779, .{ .insecure_skip_verify = true });
    defer first.deinit();
    const first_body = try first.get("/");
    defer allocator.free(first_body);
    try std.testing.expectEqualStrings("OK", first_body);

    // The first connection is still open and idle in the server's routing
    // table; a second client has to be served without waiting for it.
    var second = try Client.init(allocator, "127.0.0.1", 14779, .{ .insecure_skip_verify = true });
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
    server.* = try Server.init(allocator, 14781, handler, .{
        .idle_timeout_ns = 200 * std.time.ns_per_ms,
        .closing_period_ns = 2 * std.time.ns_per_s,
    });
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", 14781, .{ .insecure_skip_verify = true });
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
    server.* = try Server.init(allocator, 14780, handler, .{});
    _ = try std.Thread.spawn(.{}, serve, .{server});

    var client = try Client.init(allocator, "127.0.0.1", 14780, .{ .insecure_skip_verify = true });
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
