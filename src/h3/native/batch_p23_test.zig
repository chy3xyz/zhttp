//! P2 packet-batching tests: coalescing 1-RTT control frames with STREAM data.
//!
//! These drive real loopback connections so the same schedule()/commit() path
//! production uses is exercised. Assertions combine sender-side coalescing
//! counters with receiver-side frame counters; the counters are process-wide,
//! so each test compares deltas rather than absolute values.

const std = @import("std");
const posix = std.posix;
const transport = @import("transport.zig");
const qtls = @import("qtls.zig");

const Listener = transport.Listener;
const Connection = transport.Connection;

/// Minimal offset-addressed STREAM sink for the peer side of a test.
const Sink = struct {
    allocator: std.mem.Allocator,
    buf: std.ArrayListUnmanaged(u8) = .empty,
    seen: std.ArrayListUnmanaged(bool) = .empty,
    bytes: usize = 0,
    fin: bool = false,

    fn deinit(self: *Sink) void {
        self.buf.deinit(self.allocator);
        self.seen.deinit(self.allocator);
    }

    fn onStream(raw: *anyopaque, _: u64, offset: u64, data: []const u8, fin: bool) anyerror!void {
        const self: *Sink = @ptrCast(@alignCast(raw));
        const end: usize = @intCast(offset + data.len);
        if (end > self.buf.items.len) {
            const old_len = self.buf.items.len;
            try self.buf.resize(self.allocator, end);
            @memset(self.buf.items[old_len..], 0);
            try self.seen.resize(self.allocator, end);
            @memset(self.seen.items[old_len..], false);
        }
        for (data, 0..) |byte, i| {
            const pos: usize = @as(usize, @intCast(offset)) + i;
            if (self.seen.items[pos]) continue;
            self.seen.items[pos] = true;
            self.buf.items[pos] = byte;
            self.bytes += 1;
        }
        if (fin) self.fin = true;
    }

    fn onEstablished(_: *anyopaque) anyerror!void {}
    fn onClosed(_: *anyopaque, _: u64) void {}
};

const SimpleHarness = struct {
    allocator: std.mem.Allocator,
    listener: Listener,
    client: *Connection,
    server: ?*Connection = null,
    sink: Sink = undefined,
    server_sink: Sink = undefined,
    buf: [transport.max_datagram_size]u8 = undefined,

    fn onConnection(raw: *anyopaque, connection: *Connection) void {
        const self: *SimpleHarness = @ptrCast(@alignCast(raw));
        self.server = connection;
    }

    fn onServerStream(raw: *anyopaque, stream_id: u64, offset: u64, data: []const u8, fin: bool) anyerror!void {
        const self: *SimpleHarness = @ptrCast(@alignCast(raw));
        return Sink.onStream(&self.server_sink, stream_id, offset, data, fin);
    }

    fn onServerEstablished(_: *anyopaque) anyerror!void {}
    fn onServerClosed(_: *anyopaque, _: u64) void {}

    fn init(allocator: std.mem.Allocator, local_max_data: u64, local_max_stream_data: u64) !*SimpleHarness {
        const self = try allocator.create(SimpleHarness);
        errdefer allocator.destroy(self);
        self.* = .{ .allocator = allocator, .listener = undefined, .client = undefined };
        self.sink = .{ .allocator = allocator };
        errdefer self.sink.deinit();
        self.server_sink = .{ .allocator = allocator };
        errdefer self.server_sink.deinit();

        self.listener = try Listener.init(allocator, 0);
        errdefer self.listener.deinit();
        self.listener.local_max_data = local_max_data;
        self.listener.local_max_stream_data = local_max_stream_data;
        self.listener.on_connection = .{ .context = self, .callback = onConnection };
        self.listener.handler = .{
            .context = self,
            .on_stream_frame = onServerStream,
            .on_established = onServerEstablished,
            .on_closed = onServerClosed,
        };

        const port = std.mem.bigToNative(u16, self.listener.local_addr.port);
        self.client = try Connection.initClient(allocator, "127.0.0.1", port, .{
            .insecure_skip_verify = true,
        });
        errdefer self.client.deinit();
        self.client.handler = .{
            .context = &self.sink,
            .on_stream_frame = Sink.onStream,
            .on_established = Sink.onEstablished,
            .on_closed = Sink.onClosed,
        };
        return self;
    }

    fn deinit(self: *SimpleHarness) void {
        self.client.deinit();
        self.listener.deinit();
        self.sink.deinit();
        self.server_sink.deinit();
        self.allocator.destroy(self);
    }

    fn pumpOnce(self: *SimpleHarness) void {
        self.client.service() catch {};
        _ = self.listener.readAndDispatch(&self.buf, 16);
        self.listener.serviceAll();

        // Drain every datagram currently queued for the client.
        while (true) {
            var peer: posix.sockaddr.in = undefined;
            var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const n = std.c.recvfrom(
                self.client.socket,
                self.buf[0..].ptr,
                self.buf.len,
                std.c.MSG.DONTWAIT,
                @ptrCast(&peer),
                &peer_len,
            );
            if (n <= 0) break;
            self.client.handleDatagram(self.buf[0..@intCast(n)]) catch {};
        }
        transport.sleepNs(std.time.ns_per_ms);
    }

    fn handshake(self: *SimpleHarness) !void {
        const deadline = transport.nowNanos() + 10 * std.time.ns_per_s;
        while (!self.client.isEstablished()) {
            if (transport.nowNanos() >= deadline) return error.Timeout;
            self.pumpOnce();
        }
    }
};

fn setCert() !void {
    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
}

test "batch P2: ACK rides the first data packet and is not duplicated" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try setCert();
    defer qtls.deinitServer();

    const harness = try SimpleHarness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();

    // Simulate a received ack-eliciting 1-RTT packet. The transport's ACK state
    // is public test surface, just like the batch counters.
    const ack_pn = harness.client.largest_pn[3] orelse 0;
    harness.client.acks[3].record(ack_pn, true);
    try std.testing.expect(harness.client.acks[3].ack_required);

    const body = try allocator.alloc(u8, 4096);
    defer allocator.free(body);
    for (body, 0..) |*byte, i| byte.* = @truncate(i *% 7);

    const stream_id = try harness.client.createBidiStream();
    try harness.client.queueStreamData(stream_id, body, true);

    const before_packets = transport.test_batch_packets;
    const before_coalesced = transport.test_control_coalesced_packets;
    const before_ack_coalesced = transport.test_ack_coalesced_packets;
    const before_standalone_ack = transport.test_standalone_ack_packets;

    // One service pass emits several data packets. Only the first may carry
    // the ACK, because the control batch is committed exactly once.
    try harness.client.service();

    try std.testing.expect(transport.test_batch_packets - before_packets >= 2);
    try std.testing.expectEqual(before_coalesced + 1, transport.test_control_coalesced_packets);
    try std.testing.expectEqual(before_ack_coalesced + 1, transport.test_ack_coalesced_packets);
    try std.testing.expectEqual(before_standalone_ack, transport.test_standalone_ack_packets);
    try std.testing.expect(!harness.client.acks[3].ack_required);
    try std.testing.expectEqual(@as(usize, 0), harness.client.acks[3].count);

    // A second pass with no new peer packet must not send the ACK again.
    try harness.client.service();
    try std.testing.expectEqual(before_coalesced + 1, transport.test_control_coalesced_packets);
    try std.testing.expectEqual(before_ack_coalesced + 1, transport.test_ack_coalesced_packets);
    try std.testing.expectEqual(before_standalone_ack, transport.test_standalone_ack_packets);

    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    while (transport.nowNanos() < deadline) {
        if (harness.server_sink.bytes == body.len and harness.server_sink.fin) break;
        harness.pumpOnce();
    }
    try std.testing.expectEqual(body.len, harness.server_sink.bytes);
    try std.testing.expectEqualSlices(u8, body, harness.server_sink.buf.items);
}

test "batch P2: flow-control updates coalesce with data and are committed once" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try setCert();
    defer qtls.deinitServer();

    const reply = try allocator.alloc(u8, 3000);
    defer allocator.free(reply);
    for (reply, 0..) |*byte, i| byte.* = @truncate(i *% 13);

    const Context = struct {
        allocator: std.mem.Allocator,
        server: ?*Connection = null,
        replied: bool = false,
        reply: []const u8,

        fn onConnection(raw: *anyopaque, connection: *Connection) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.server = connection;
        }

        fn onStream(raw: *anyopaque, stream_id: u64, _: u64, _: []const u8, _: bool) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.replied) return;
            self.replied = true;
            const server = self.server orelse return;
            try server.queueStreamData(stream_id, self.reply, false);
        }
        fn onEstablished(_: *anyopaque) anyerror!void {}
        fn onClosed(_: *anyopaque, _: u64) void {}
    };

    var listener = try Listener.init(allocator, 0);
    defer listener.deinit();
    // Small peer receive window: the client's 100-byte upload crosses half of
    // both windows, so the server queues MAX_DATA and MAX_STREAM_DATA.
    listener.local_max_data = 128;
    listener.local_max_stream_data = 128;

    var context: Context = .{ .allocator = allocator, .reply = reply };
    listener.on_connection = .{ .context = &context, .callback = Context.onConnection };
    listener.handler = .{
        .context = &context,
        .on_stream_frame = Context.onStream,
        .on_established = Context.onEstablished,
        .on_closed = Context.onClosed,
    };

    var sink: Sink = .{ .allocator = allocator };
    defer sink.deinit();

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client = try Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    });
    defer client.deinit();
    client.handler = .{
        .context = &sink,
        .on_stream_frame = Sink.onStream,
        .on_established = Sink.onEstablished,
        .on_closed = Sink.onClosed,
    };

    var buf: [transport.max_datagram_size]u8 = undefined;
    const pump = struct {
        fn once(conn: *Connection, listen: *Listener, buffer: []u8) void {
            conn.service() catch {};
            _ = listen.readAndDispatch(buffer, 16);
            listen.serviceAll();
            while (true) {
                var peer: posix.sockaddr.in = undefined;
                var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
                const n = std.c.recvfrom(
                    conn.socket,
                    buffer.ptr,
                    buffer.len,
                    std.c.MSG.DONTWAIT,
                    @ptrCast(&peer),
                    &peer_len,
                );
                if (n <= 0) break;
                conn.handleDatagram(buffer[0..@intCast(n)]) catch {};
            }
            transport.sleepNs(std.time.ns_per_ms);
        }
    }.once;

    const handshake_deadline = transport.nowNanos() + 10 * std.time.ns_per_s;
    while (!client.isEstablished()) {
        if (transport.nowNanos() >= handshake_deadline) return error.Timeout;
        pump(client, &listener, &buf);
    }

    const before_data = transport.test_max_data_sent;
    const before_stream = transport.test_max_stream_data_sent;
    const before_flow_coalesced = transport.test_flow_coalesced_packets;
    const before_coalesced = transport.test_control_coalesced_packets;
    const before_rx_max_with_stream = transport.test_rx_max_with_stream_packets;
    const before_rx_max_data = transport.test_rx_max_data_frames;
    const before_rx_max_stream = transport.test_rx_max_stream_data_frames;

    var upload: [100]u8 = undefined;
    @memset(&upload, 'x');
    const stream_id = try client.createBidiStream();
    try client.queueStreamData(stream_id, &upload, false);

    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    while (transport.nowNanos() < deadline) {
        if (sink.bytes == reply.len) break;
        pump(client, &listener, &buf);
    }
    try std.testing.expectEqual(reply.len, sink.bytes);
    try std.testing.expectEqualSlices(u8, reply, sink.buf.items);

    // Both updates were due and each was committed exactly once. If a MAX_*
    // frame had been duplicated into a later packet, the commit counters would
    // have advanced twice.
    try std.testing.expectEqual(before_data + 1, transport.test_max_data_sent);
    try std.testing.expectEqual(before_stream + 1, transport.test_max_stream_data_sent);
    // Both MAX_* frames shared their packet with STREAM data.
    try std.testing.expectEqual(before_flow_coalesced + 2, transport.test_flow_coalesced_packets);
    try std.testing.expect(transport.test_control_coalesced_packets > before_coalesced);
    // Receiver-side proof that MAX_* + STREAM arrived in one protected packet,
    // and that each MAX_* frame appeared exactly once on the wire.
    try std.testing.expect(transport.test_rx_max_with_stream_packets > before_rx_max_with_stream);
    try std.testing.expectEqual(before_rx_max_data + 1, transport.test_rx_max_data_frames);
    try std.testing.expectEqual(before_rx_max_stream + 1, transport.test_rx_max_stream_data_frames);
}

test "batch P2: ACK-only packet is still padded for header protection" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try setCert();
    defer qtls.deinitServer();

    const harness = try SimpleHarness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();

    const ack_pn = harness.client.largest_pn[3] orelse 0;
    harness.client.acks[3].record(ack_pn, true);

    const before_standalone_ack = transport.test_standalone_ack_packets;
    const before_batches = transport.test_batch_packets;

    try harness.client.service();

    try std.testing.expectEqual(before_standalone_ack + 1, transport.test_standalone_ack_packets);
    // schedule() pads ACK-only payloads to 64 bytes so the 16-byte header
    // protection sample starting four bytes after the packet number exists.
    try std.testing.expect(transport.test_standalone_ack_plaintext_len >= 64);
    try std.testing.expectEqual(before_batches, transport.test_batch_packets);
    try std.testing.expect(!harness.client.acks[3].ack_required);
}
