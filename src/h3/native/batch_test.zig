//! Packet-batching tests for the native 1-RTT STREAM send path.
//!
//! These tests drive a real loopback Connection so the batch counters observe
//! the same schedule()/commit() path production uses. A test recorder stores
//! bytes by absolute offset, which makes duplicate retransmissions harmless and
//! lets loss tests verify that data is delivered exactly once.

const std = @import("std");
const transport = @import("transport.zig");
const qtls = @import("qtls.zig");

const Listener = transport.Listener;
const Connection = transport.Connection;

/// Offset-addressed reassembly for the raw transport handler. The transport
/// hands STREAM frames to the handler as they arrive; retransmissions may
/// deliver a frame twice, so only unseen offsets are copied.
const Recorder = struct {
    allocator: std.mem.Allocator,
    streams: std.AutoHashMapUnmanaged(u64, Stream) = .empty,

    const Stream = struct {
        buf: std.ArrayListUnmanaged(u8) = .empty,
        seen: std.ArrayListUnmanaged(bool) = .empty,
        bytes: usize = 0,
        fin: bool = false,
        fin_frames: usize = 0,
    };

    fn deinit(self: *Recorder) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.buf.deinit(self.allocator);
            entry.value_ptr.seen.deinit(self.allocator);
        }
        self.streams.deinit(self.allocator);
    }

    fn onStream(raw: *anyopaque, stream_id: u64, offset: u64, data: []const u8, fin: bool) anyerror!void {
        const self: *Recorder = @ptrCast(@alignCast(raw));
        const gop = try self.streams.getOrPut(self.allocator, stream_id);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const stream = gop.value_ptr;

        const end: usize = @intCast(offset + data.len);
        if (end > stream.buf.items.len) {
            const old_len = stream.buf.items.len;
            try stream.buf.resize(self.allocator, end);
            @memset(stream.buf.items[old_len..], 0);
            try stream.seen.resize(self.allocator, end);
            @memset(stream.seen.items[old_len..], false);
        }
        for (data, 0..) |byte, i| {
            const pos: usize = @as(usize, @intCast(offset)) + i;
            if (stream.seen.items[pos]) continue;
            stream.seen.items[pos] = true;
            stream.buf.items[pos] = byte;
            stream.bytes += 1;
        }
        if (fin) {
            stream.fin = true;
            stream.fin_frames += 1;
        }
    }

    fn onEstablished(_: *anyopaque) anyerror!void {}
    fn onClosed(_: *anyopaque, _: u64) void {}

    fn get(self: *Recorder, stream_id: u64) ?*Stream {
        return self.streams.getPtr(stream_id);
    }

    fn bytesFor(self: *Recorder, stream_id: u64) []const u8 {
        const stream = self.get(stream_id) orelse return &.{};
        return stream.buf.items[0..stream.bytes];
    }
};

const Harness = struct {
    allocator: std.mem.Allocator,
    listener: Listener,
    client: *Connection,
    recorder: Recorder,
    buf: [transport.max_datagram_size]u8 = undefined,

    fn init(
        allocator: std.mem.Allocator,
        local_max_data: u64,
        local_max_stream_data: u64,
    ) !*Harness {
        const self = try allocator.create(Harness);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .listener = undefined,
            .client = undefined,
            .recorder = .{ .allocator = allocator },
        };
        errdefer self.recorder.deinit();

        self.listener = try Listener.init(allocator, 0);
        errdefer self.listener.deinit();
        self.listener.local_max_data = local_max_data;
        self.listener.local_max_stream_data = local_max_stream_data;
        self.listener.handler = .{
            .context = &self.recorder,
            .on_stream_frame = Recorder.onStream,
            .on_established = Recorder.onEstablished,
            .on_closed = Recorder.onClosed,
        };

        const port = std.mem.bigToNative(u16, self.listener.local_addr.port);
        self.client = try Connection.initClient(allocator, "127.0.0.1", port, .{
            .insecure_skip_verify = true,
        });
        errdefer self.client.deinit();
        return self;
    }

    fn deinit(self: *Harness) void {
        self.client.deinit();
        self.listener.deinit();
        self.recorder.deinit();
        self.allocator.destroy(self);
    }

    /// One client service pass, one listener receive batch, and one client
    /// receive drain. Deliberately paced so handshake and recovery timers see
    /// time pass.
    fn pump(self: *Harness) void {
        self.client.service() catch {};
        _ = self.listener.readAndDispatch(&self.buf, 16);
        self.listener.serviceAll();

        var peer: std.posix.sockaddr.in = undefined;
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        const n = std.c.recvfrom(
            self.client.socket,
            self.buf[0..].ptr,
            self.buf.len,
            std.c.MSG.DONTWAIT,
            @ptrCast(&peer),
            &peer_len,
        );
        if (n > 0) self.client.handleDatagram(self.buf[0..@intCast(n)]) catch {};
        transport.sleepNs(std.time.ns_per_ms);
    }

    fn handshake(self: *Harness) !void {
        const deadline = transport.nowNanos() + 10 * std.time.ns_per_s;
        while (!self.client.isEstablished()) {
            if (transport.nowNanos() >= deadline) return error.Timeout;
            self.pump();
        }
    }

    /// Pump until the stream has all `expected` bytes, or timeout.
    fn awaitBytes(self: *Harness, stream_id: u64, expected: usize) !void {
        const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
        while (transport.nowNanos() < deadline) {
            if (self.recorder.get(stream_id)) |stream| {
                if (stream.bytes == expected) return;
            }
            self.pump();
        }
        return error.Timeout;
    }

    /// Pump until the stream has all `expected` bytes and its FIN, or timeout.
    fn awaitStream(self: *Harness, stream_id: u64, expected: usize) !void {
        const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
        while (transport.nowNanos() < deadline) {
            if (self.recorder.get(stream_id)) |stream| {
                if (stream.bytes == expected and stream.fin) return;
            }
            self.pump();
        }
        return error.Timeout;
    }
};

test "batch: two streams share one 1-RTT packet" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var harness = try Harness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();

    const before_packets = transport.test_batch_packets;
    const before_frames = transport.test_batch_stream_frames;
    const before_multi_stream = transport.test_batch_multi_stream_packets;
    const before_multi_frame = transport.test_batch_multi_frame_packets;

    const first = try harness.client.createBidiStream();
    const second = try harness.client.createBidiStream();
    try harness.client.queueStreamData(first, "alpha", true);
    try harness.client.queueStreamData(second, "bravo", true);

    // One service pass builds and schedules exactly one data batch.
    try harness.client.service();
    try std.testing.expectEqual(before_packets + 1, transport.test_batch_packets);
    try std.testing.expectEqual(before_frames + 2, transport.test_batch_stream_frames);
    try std.testing.expectEqual(before_multi_stream + 1, transport.test_batch_multi_stream_packets);
    try std.testing.expectEqual(before_multi_frame + 1, transport.test_batch_multi_frame_packets);
    try std.testing.expectEqual(@as(u64, 10), harness.client.flow.sent_data);

    try harness.awaitStream(first, 5);
    try harness.awaitStream(second, 5);
    try std.testing.expectEqualStrings("alpha", harness.recorder.bytesFor(first));
    try std.testing.expectEqualStrings("bravo", harness.recorder.bytesFor(second));
}

test "batch: one 1 KiB stream body is one packet" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var harness = try Harness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();

    const payload = try allocator.alloc(u8, 1024);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i);

    const before_packets = transport.test_batch_packets;
    const before_frames = transport.test_batch_stream_frames;
    const before_multi_frame = transport.test_batch_multi_frame_packets;

    const stream_id = try harness.client.createBidiStream();
    try harness.client.queueStreamData(stream_id, payload, true);
    try harness.client.service();

    // 1024 bytes plus a STREAM header fit the shared budget, so this is one
    // frame in one protected packet.
    try std.testing.expectEqual(before_packets + 1, transport.test_batch_packets);
    try std.testing.expectEqual(before_frames + 1, transport.test_batch_stream_frames);
    try std.testing.expectEqual(before_multi_frame, transport.test_batch_multi_frame_packets);
    try std.testing.expect(transport.test_batch_largest_payload >= payload.len);
    try std.testing.expect(transport.test_batch_largest_payload <= transport.test_batch_budget);
    try std.testing.expectEqual(@as(u64, payload.len), harness.client.flow.sent_data);

    try harness.awaitStream(stream_id, payload.len);
    try std.testing.expectEqualSlices(u8, payload, harness.recorder.bytesFor(stream_id));
}

test "batch: large body uses the MTU budget" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var harness = try Harness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();

    const body_size: usize = 8 * 1024;
    const payload = try allocator.alloc(u8, body_size);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i *% 31);

    const before_packets = transport.test_batch_packets;
    const before_frames = transport.test_batch_stream_frames;

    const stream_id = try harness.client.createBidiStream();
    try harness.client.queueStreamData(stream_id, payload, true);
    try harness.client.service();

    const packets = transport.test_batch_packets - before_packets;
    const frames = transport.test_batch_stream_frames - before_frames;
    try std.testing.expect(packets >= 2);
    // A single stream contributes at most one frame per packet here.
    try std.testing.expectEqual(packets, frames);
    try std.testing.expect(transport.test_batch_largest_payload > 1000);
    try std.testing.expect(transport.test_batch_largest_payload <= transport.test_batch_budget);
    try std.testing.expectEqual(@as(u64, body_size), harness.client.flow.sent_data);

    try harness.awaitStream(stream_id, body_size);
    try std.testing.expectEqualSlices(u8, payload, harness.recorder.bytesFor(stream_id));
}

test "batch: a large stream contributes several chunks next to a small stream" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var harness = try Harness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();

    const large = try allocator.alloc(u8, 2 * 1024);
    defer allocator.free(large);
    @memset(large, 'L');

    const before_multi_stream = transport.test_batch_multi_stream_packets;
    const before_multi_frame = transport.test_batch_multi_frame_packets;
    const before_frames = transport.test_batch_stream_frames;

    const small_id = try harness.client.createBidiStream();
    const large_id = try harness.client.createBidiStream();
    try harness.client.queueStreamData(small_id, "s", true);
    try harness.client.queueStreamData(large_id, large, true);
    try harness.client.service();

    // Two distinct streams and at least three frames: the large stream gets a
    // fair share first and the remaining budget in a later round.
    try std.testing.expectEqual(before_multi_stream + 1, transport.test_batch_multi_stream_packets);
    try std.testing.expectEqual(before_multi_frame + 1, transport.test_batch_multi_frame_packets);
    try std.testing.expect(transport.test_batch_stream_frames >= before_frames + 3);
    try std.testing.expect(transport.test_batch_largest_payload <= transport.test_batch_budget);

    try harness.awaitStream(small_id, 1);
    try harness.awaitStream(large_id, large.len);
    try std.testing.expectEqualSlices(u8, "s", harness.recorder.bytesFor(small_id));
    try std.testing.expectEqualSlices(u8, large, harness.recorder.bytesFor(large_id));
}

test "batch: FIN-only frame is scheduled once and reaped" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var harness = try Harness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();

    const stream_id = try harness.client.createBidiStream();
    try harness.client.queueStreamData(stream_id, "head", false);
    try harness.client.service();
    try harness.awaitBytes(stream_id, 4);
    try std.testing.expect(!harness.recorder.get(stream_id).?.fin);

    const before_packets = transport.test_batch_packets;
    const before_frames = transport.test_batch_stream_frames;
    try harness.client.queueStreamData(stream_id, &.{}, true);
    try harness.client.service();
    try std.testing.expectEqual(before_packets + 1, transport.test_batch_packets);
    try std.testing.expectEqual(before_frames + 1, transport.test_batch_stream_frames);

    try harness.awaitStream(stream_id, 4);
    // A retransmitted FIN is legal and may arrive more than once; the sender
    // still scheduled exactly one FIN frame (checked above).
    try std.testing.expect(harness.recorder.get(stream_id).?.fin_frames >= 1);
}

test "batch: flow-control window blocks and never over-advances" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    // The server advertises a 100-byte connection window and a 64-byte stream
    // window. Nothing is dispatched during the blocked assertions, so no
    // MAX_DATA/MAX_STREAM_DATA can widen them behind the test's back.
    var harness = try Harness.init(allocator, 100, 64);
    defer harness.deinit();
    try harness.handshake();
    try std.testing.expectEqual(@as(u64, 100), harness.client.flow.peer_max_data);

    const payload = try allocator.alloc(u8, 1024);
    defer allocator.free(payload);
    @memset(payload, 'f');

    const stream_id = try harness.client.createBidiStream();
    try std.testing.expectEqual(@as(?u64, 64), harness.client.streamSendLimit(stream_id));
    try harness.client.queueStreamData(stream_id, payload, true);
    const before_blocked = transport.test_send_blocked;
    try harness.client.service();

    try std.testing.expect(transport.test_send_blocked > before_blocked);
    try std.testing.expectEqual(@as(u64, 64), harness.client.flow.sent_data);
    var snapshot = harness.client.streamSendSnapshot(stream_id).?;
    try std.testing.expectEqual(@as(u64, 64), snapshot.sent);
    try std.testing.expectEqual(@as(usize, 960), snapshot.pending);

    // A second pass with the same credit must not advance anything.
    try harness.client.service();
    try std.testing.expectEqual(@as(u64, 64), harness.client.flow.sent_data);
    snapshot = harness.client.streamSendSnapshot(stream_id).?;
    try std.testing.expectEqual(@as(u64, 64), snapshot.sent);
    try std.testing.expectEqual(@as(usize, 960), snapshot.pending);

    // Deliver the 64 bytes; the server's MAX_DATA/MAX_STREAM_DATA then resume
    // the upload without resetting or double-counting the sent offset.
    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    while (transport.nowNanos() < deadline) {
        if (harness.client.flow.sent_data == payload.len) break;
        harness.pump();
    }
    try std.testing.expectEqual(@as(u64, payload.len), harness.client.flow.sent_data);
    try harness.awaitStream(stream_id, payload.len);
    try std.testing.expectEqualSlices(u8, payload, harness.recorder.bytesFor(stream_id));
}

test "batch: loss and retransmission never advance sent offsets twice" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var harness = try Harness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();
    harness.client.setDropOutgoingEvery(3);

    const payload = try allocator.alloc(u8, 4 * 1024);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i);

    const before_retransmits = transport.test_retransmit_count;
    const stream_id = try harness.client.createBidiStream();
    try harness.client.queueStreamData(stream_id, payload, true);
    try harness.client.service();

    try harness.awaitStream(stream_id, payload.len);
    // The whole 4 KiB body was handed to schedule exactly once even though
    // packets were dropped and recovery retransmitted them.
    try std.testing.expectEqual(@as(u64, payload.len), harness.client.flow.sent_data);
    try std.testing.expect(transport.test_retransmit_count > before_retransmits);
    try std.testing.expectEqualSlices(u8, payload, harness.recorder.bytesFor(stream_id));
    // Loss recovery may duplicate the FIN frame; it must arrive at least once.
    try std.testing.expect(harness.recorder.get(stream_id).?.fin_frames >= 1);
}

test "batch: failed schedule leaves every send offset unchanged" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var harness = try Harness.init(allocator, transport.default_flow_window, transport.default_flow_window);
    defer harness.deinit();
    try harness.handshake();

    const payload = try allocator.alloc(u8, 3 * 1024);
    defer allocator.free(payload);
    @memset(payload, 'r');

    const stream_id = try harness.client.createBidiStream();
    try harness.client.queueStreamData(stream_id, payload, true);
    const before = harness.client.streamSendSnapshot(stream_id).?;
    const before_sent_data = harness.client.flow.sent_data;

    // Force schedule() to fail at its destination-CID check before anything is
    // protected or queued. The transaction must not commit a single byte.
    const saved_cid = harness.client.peer_cid;
    const saved_len = harness.client.peer_cid_len;
    harness.client.peer_cid_len = 0;
    try std.testing.expectError(error.QuicError, harness.client.service());
    harness.client.peer_cid = saved_cid;
    harness.client.peer_cid_len = saved_len;

    try std.testing.expectEqual(before_sent_data, harness.client.flow.sent_data);
    const after = harness.client.streamSendSnapshot(stream_id).?;
    try std.testing.expectEqual(before.sent, after.sent);
    try std.testing.expectEqual(before.pending, after.pending);
    try std.testing.expectEqual(before.buf_len, after.buf_len);
    try std.testing.expectEqual(before.fin_sent, after.fin_sent);

    // The next service pass retries the identical bytes at the identical
    // offsets and completes normally.
    try harness.client.service();
    try std.testing.expectEqual(@as(u64, payload.len), harness.client.flow.sent_data);
    try harness.awaitStream(stream_id, payload.len);
    try std.testing.expectEqualSlices(u8, payload, harness.recorder.bytesFor(stream_id));
}
