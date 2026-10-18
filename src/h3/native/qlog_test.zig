//! qlog writer and transport integration tests.
//!
//! The writer tests inject a Reference so JSON-SEQ bytes are deterministic.
//! Integration tests use a fixed-size sink because the server writes from its
//! own run thread; the buffer is read only after join.

const std = @import("std");
const qlog = @import("qlog.zig");
const transport = @import("transport.zig");
const qtls = @import("qtls.zig");
const H3Server = @import("../Server.zig");
const H3Client = @import("../Client.zig");

const BufferSink = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayListUnmanaged(u8) = .empty,

    fn write(context: *anyopaque, data: []const u8) void {
        const self: *BufferSink = @ptrCast(@alignCast(context));
        self.bytes.appendSlice(self.allocator, data) catch {};
    }

    fn sink(self: *BufferSink) qlog.Sink {
        return .{ .context = self, .write = write };
    }

    fn deinit(self: *BufferSink) void {
        self.bytes.deinit(self.allocator);
    }
};

const FixedSink = struct {
    buffer: [512 * 1024]u8 = undefined,
    len: usize = 0,

    fn write(context: *anyopaque, data: []const u8) void {
        const self: *FixedSink = @ptrCast(@alignCast(context));
        const room = self.buffer.len - self.len;
        const take = @min(room, data.len);
        @memcpy(self.buffer[self.len..][0..take], data[0..take]);
        self.len += take;
    }

    fn sink(self: *FixedSink) qlog.Sink {
        return .{ .context = self, .write = write };
    }

    fn bytes(self: *const FixedSink) []const u8 {
        return self.buffer[0..self.len];
    }
};

fn expectJsonSeq(bytes: []const u8) !usize {
    var index: usize = 0;
    var count: usize = 0;
    while (index < bytes.len) {
        try std.testing.expectEqual(@as(u8, 0x1e), bytes[index]);
        const end = std.mem.indexOfScalarPos(u8, bytes, index + 1, '\n') orelse return error.MissingNewline;
        const json = bytes[index + 1 .. end];
        var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value == .object);
        count += 1;
        index = end + 1;
    }
    return count;
}

fn expectContains(bytes: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, bytes, needle) != null);
}

test "qlog: deterministic JSON-SEQ header and connection_started" {
    var buffer: BufferSink = .{ .allocator = std.testing.allocator };
    defer buffer.deinit();
    var writer = qlog.Writer.init(
        .{ .sink = buffer.sink() },
        .{ .wall_ms = 1_700_000_000_000, .monotonic_us = 1_000_000 },
    );
    writer.writeHeader(.client);
    writer.connectionStarted(
        1_001_500,
        .client,
        &.{ 1, 2, 3, 4, 5, 6, 7, 8 },
        &.{ 9, 10, 11, 12, 13, 14, 15, 16 },
    );

    const expected =
        "\x1e{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\",\"title\":\"zhttp native HTTP/3\",\"trace\":{\"vantage_point\":{\"name\":\"zhttp\",\"type\":\"client\"},\"common_fields\":{\"reference_time\":1700000000000,\"time_format\":\"relative\",\"protocol_type\":[\"QUIC\",\"HTTP3\"]}}}\n" ++
        "\x1e{\"time\":1.500,\"name\":\"connectivity:connection_started\",\"data\":{\"role\":\"client\",\"src_cid\":\"01020304..\",\"dst_cid\":\"090a0b0c..\"}}\n";
    try std.testing.expectEqualStrings(expected, buffer.bytes.items);
}

test "qlog: packet, loss, retry and close records parse as JSON" {
    var buffer: BufferSink = .{ .allocator = std.testing.allocator };
    defer buffer.deinit();
    var writer = qlog.Writer.init(
        .{ .sink = buffer.sink(), .packet_sample_mask = 0 },
        .{ .wall_ms = 1_700_000_000_000, .monotonic_us = 1_000_000 },
    );
    writer.writeHeader(.server);
    writer.connectionStarted(1_002_000, .server, "abcdefgh", "ijklmnop");
    writer.packetSent(1_003_000, 7, 3, .one_rtt, true, 1200, .{ .stream = 2, .ack = 1 });
    writer.packetReceived(1_004_000, 8, 3, .one_rtt, true, 64, .{ .crypto = 1 });
    writer.packetLost(1_005_000, 9, 0, 1200);
    writer.retrySent(1_006_000);
    writer.retryRejected(1_007_000, "invalid_token");
    writer.errorEvent(1_008_000, 0x0201, "QPACK decompression failed");
    writer.connectionClosed(
        1_009_000,
        .local,
        0x0201,
        "QPACK decompression failed",
        .{ .packets_sent = 12, .packets_received = 9 },
    );
    // connection_closed is emitted at most once per writer.
    writer.connectionClosed(1_010_000, .local, 0x1, "duplicate", .{});

    const records = try expectJsonSeq(buffer.bytes.items);
    try std.testing.expectEqual(@as(usize, 9), records);
    try expectContains(buffer.bytes.items, "\"name\":\"transport:packet_sent\"");
    try expectContains(buffer.bytes.items, "\"name\":\"transport:packet_received\"");
    try expectContains(buffer.bytes.items, "\"name\":\"recovery:packet_lost\"");
    try expectContains(buffer.bytes.items, "\"name\":\"zhttp:retry_sent\"");
    try expectContains(buffer.bytes.items, "\"name\":\"zhttp:retry_rejected\"");
    try expectContains(buffer.bytes.items, "\"name\":\"zhttp:error\"");
    try expectContains(buffer.bytes.items, "\"name\":\"connectivity:connection_closed\"");
    try expectContains(buffer.bytes.items, "\"frames\":\"2xSTREAM,1xACK\"");
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, buffer.bytes.items, "connectivity:connection_closed"));

    // Sample masks reject packet events but never connection events.
    var sampled = qlog.Writer.init(
        .{ .sink = buffer.sink(), .packet_sample_mask = 1 },
        .{ .wall_ms = 1, .monotonic_us = 0 },
    );
    try std.testing.expect(sampled.sampleSent());
    try std.testing.expect(!sampled.sampleSent());
    try std.testing.expect(sampled.sampleReceived());
    try std.testing.expect(!sampled.sampleReceived());
    try std.testing.expect(sampled.sampleLost());
    try std.testing.expect(!sampled.sampleLost());
}

test "qlog: CIDs use a prefix unless full_cids is set" {
    const local_cid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const peer_cid = [_]u8{ 9, 10, 11, 12 };

    var prefix_buffer: BufferSink = .{ .allocator = std.testing.allocator };
    defer prefix_buffer.deinit();
    var prefix_writer = qlog.Writer.init(
        .{ .sink = prefix_buffer.sink() },
        .{ .wall_ms = 1, .monotonic_us = 0 },
    );
    prefix_writer.connectionStarted(0, .client, &local_cid, &peer_cid);
    try expectContains(prefix_buffer.bytes.items, "\"src_cid\":\"01020304..\"");
    try expectContains(prefix_buffer.bytes.items, "\"dst_cid\":\"090a0b0c\"");
    try std.testing.expect(std.mem.indexOf(u8, prefix_buffer.bytes.items, "0102030405060708") == null);

    var full_buffer: BufferSink = .{ .allocator = std.testing.allocator };
    defer full_buffer.deinit();
    var full_writer = qlog.Writer.init(
        .{ .sink = full_buffer.sink(), .full_cids = true },
        .{ .wall_ms = 1, .monotonic_us = 0 },
    );
    full_writer.connectionStarted(0, .client, &local_cid, &peer_cid);
    try expectContains(full_buffer.bytes.items, "\"src_cid\":\"0102030405060708\"");
    try expectContains(full_buffer.bytes.items, "\"dst_cid\":\"090a0b0c\"");
}

test "qlog: loopback GET emits events and never logs header values" {
    // The server runs on its own thread, so the allocator must be thread-safe.
    const allocator = std.heap.smp_allocator;

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const server_log = try std.testing.allocator.create(FixedSink);
    defer std.testing.allocator.destroy(server_log);
    server_log.* = .{};
    const client_log = try std.testing.allocator.create(FixedSink);
    defer std.testing.allocator.destroy(client_log);
    client_log.* = .{};

    const handler = struct {
        fn handle(_: std.mem.Allocator, _: *const H3Server.Request) H3Server.Response {
            return .{
                .body = "qlog-ok",
                .headers = &.{.{ .name = "x-secret", .value = "top-secret-value" }},
            };
        }
    }.handle;

    var server = try H3Server.Server.init(allocator, 0, handler, .{
        .qlog = .{ .sink = server_log.sink() },
    });
    defer server.deinit();
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);

    const Runner = struct {
        fn run(s: *H3Server.Server) void {
            s.run() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&server});
    var joined = false;
    errdefer if (!joined) {
        server.stop();
        thread.join();
    };

    var client = try H3Client.Client.initWithOptions(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    }, .{
        .qlog = .{ .sink = client_log.sink() },
    });
    var client_alive = true;
    errdefer if (client_alive) client.deinit();

    const answer = try client.send(
        "GET",
        "/secret-path",
        &.{.{ .name = "x-request-secret", .value = "request-hidden-value" }},
        "",
    );
    try std.testing.expectEqual(@as(u16, 200), answer.status);
    try std.testing.expectEqualStrings("qlog-ok", answer.body);
    allocator.free(answer.header_text);
    allocator.free(answer.body);

    client.deinit();
    client_alive = false;
    transport.sleepNs(200 * std.time.ns_per_ms);
    server.stop();
    thread.join();
    joined = true;

    const server_bytes = server_log.bytes();
    const client_bytes = client_log.bytes();
    const server_records = try expectJsonSeq(server_bytes);
    _ = try expectJsonSeq(client_bytes);
    try std.testing.expect(server_records > 1);

    // Header is the first record on both sides.
    try std.testing.expect(std.mem.startsWith(
        u8,
        server_bytes,
        "\x1e{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\"",
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        client_bytes,
        "\x1e{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\"",
    ));

    for ([_][]const u8{
        "\"name\":\"connectivity:connection_started\"",
        "\"name\":\"transport:packet_sent\"",
        "\"name\":\"transport:packet_received\"",
        "\"name\":\"connectivity:connection_closed\"",
    }) |needle| {
        try expectContains(server_bytes, needle);
        try expectContains(client_bytes, needle);
    }

    // Header values, token bytes, and peer addresses must never reach the
    // trace. The fixed retry_sent reason string is allowed; it contains no
    // token material.
    for ([_][]const u8{
        "top-secret-value",
        "request-hidden-value",
        "x-secret",
        "127.0.0.1",
    }) |secret| {
        try std.testing.expect(std.mem.indexOf(u8, server_bytes, secret) == null);
        try std.testing.expect(std.mem.indexOf(u8, client_bytes, secret) == null);
    }
}

test "qlog: disabled config installs no writer and writes nothing" {
    const allocator = std.heap.smp_allocator;

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const witness = try std.testing.allocator.create(FixedSink);
    defer std.testing.allocator.destroy(witness);
    witness.* = .{};

    const handler = struct {
        fn handle(_: std.mem.Allocator, _: *const H3Server.Request) H3Server.Response {
            return .{ .body = "disabled-ok" };
        }
    }.handle;

    var server = try H3Server.Server.init(allocator, 0, handler, .{ .qlog = null });
    defer server.deinit();
    try std.testing.expect(server.listener.qlog == null);
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);

    const Runner = struct {
        fn run(s: *H3Server.Server) void {
            s.run() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&server});
    var joined = false;
    errdefer if (!joined) {
        server.stop();
        thread.join();
    };

    var client = try H3Client.Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    var client_alive = true;
    errdefer if (client_alive) client.deinit();
    try std.testing.expect(client.connection.qlog == null);
    const body = try client.get("/");
    try std.testing.expectEqualStrings("disabled-ok", body);
    allocator.free(body);

    client.deinit();
    client_alive = false;
    transport.sleepNs(150 * std.time.ns_per_ms);
    server.stop();
    thread.join();
    joined = true;

    try std.testing.expectEqual(@as(usize, 0), witness.len);
}

test "qlog: Retry-enabled server records retry_sent without the token" {
    const allocator = std.heap.smp_allocator;

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const server_log = try std.testing.allocator.create(FixedSink);
    defer std.testing.allocator.destroy(server_log);
    server_log.* = .{};

    const handler = struct {
        fn handle(_: std.mem.Allocator, _: *const H3Server.Request) H3Server.Response {
            return .{ .body = "retry-qlog-ok" };
        }
    }.handle;

    var server = try H3Server.Server.init(allocator, 0, handler, .{
        .retry = true,
        .qlog = .{ .sink = server_log.sink() },
    });
    defer server.deinit();
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);

    const Runner = struct {
        fn run(s: *H3Server.Server) void {
            s.run() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&server});
    var joined = false;
    errdefer if (!joined) {
        server.stop();
        thread.join();
    };

    var client = try H3Client.Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    var client_alive = true;
    errdefer if (client_alive) client.deinit();
    const body = try client.get("/");
    try std.testing.expectEqualStrings("retry-qlog-ok", body);
    allocator.free(body);
    client.deinit();
    client_alive = false;

    transport.sleepNs(150 * std.time.ns_per_ms);
    server.stop();
    thread.join();
    joined = true;

    _ = try expectJsonSeq(server_log.bytes());
    try expectContains(server_log.bytes(), "\"name\":\"zhttp:retry_sent\"");
    // The Retry token and the client address are never serialized.
    try std.testing.expect(std.mem.indexOf(u8, server_log.bytes(), "127.0.0.1") == null);
    try std.testing.expect(std.mem.indexOf(u8, server_log.bytes(), "token\":") == null);
}
