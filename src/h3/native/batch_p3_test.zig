//! Batch P3 copy-reduction tests.
//!
//! P3 removes the plaintext duplicate the transport used to make for every
//! protected send. The transport serializes frames once, hands that exact
//! allocation to zquic, and zquic stores it in SentPacket until ACK, loss, or
//! discard. These tests use a counting allocator so a reintroduced copy shows
//! up as an extra live allocation, and pointer identity proves the retained
//! payload is the caller's buffer rather than a duplicate.

const std = @import("std");
const posix = std.posix;
const zquic = @import("zquic");
const transport = @import("transport.zig");
const qtls = @import("qtls.zig");

/// Forwards to a child allocator while tracking live bytes and allocation
/// count. Remap/resize update the byte count in place; free decrements both.
const CountingAllocator = struct {
    child: std.mem.Allocator,
    live_bytes: usize = 0,
    live_allocs: usize = 0,

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn allocator(self: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.child.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.live_bytes += len;
        self.live_allocs += 1;
        return result;
    }

    fn resize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.live_bytes = self.live_bytes - memory.len + new_len;
        return true;
    }

    fn remap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.child.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.live_bytes = self.live_bytes - memory.len + new_len;
        return result;
    }

    fn free(
        ctx: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.live_bytes >= memory.len);
        std.debug.assert(self.live_allocs > 0);
        self.live_bytes -= memory.len;
        self.live_allocs -= 1;
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

const TestKeys = struct {
    dcid: [8]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
    scid: [8]u8 = .{ 9, 10, 11, 12, 13, 14, 15, 16 },
};

/// PING followed by PADDING: ack-eliciting and long enough for header
/// protection's 16-byte sample.
fn ackElicitingPlaintext(allocator: std.mem.Allocator) ![]u8 {
    const bytes = try allocator.alloc(u8, 64);
    @memset(bytes, 0);
    bytes[0] = 0x01; // PING
    return bytes;
}

/// Drain and free every protected packet zquic queued for the wire.
fn discardOutgoing(conn: *zquic.Connection.Connection, allocator: std.mem.Allocator) !void {
    const packets = try conn.super_connection.drainOutgoingRawPackets(allocator);
    defer allocator.free(packets);
    for (packets) |*packet| packet.deinit(allocator);
}

const LossObservation = struct {
    expected_ptr: [*]u8,
    expected_len: usize,
    seen: bool = false,
    calls: usize = 0,

    fn observe(raw: ?*anyopaque, level: usize, packet_number: u64, payload: []const u8) void {
        _ = level;
        _ = packet_number;
        const self: *LossObservation = @ptrCast(@alignCast(raw.?));
        self.calls += 1;
        if (payload.ptr == self.expected_ptr and payload.len == self.expected_len) self.seen = true;
    }
};

test "batch P3: queueOutgoingRawPacketOwned transfers the protected buffer" {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    var counting = CountingAllocator{ .child = gpa.allocator() };
    const allocator = counting.allocator();

    var conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    const super = &conn.super_connection;

    const owned = try allocator.dupe(u8, "protected-datagram");
    const owned_ptr = owned.ptr;
    try super.queueOutgoingRawPacketOwned(owned);

    {
        const drained = try super.drainOutgoingRawPackets(allocator);
        defer allocator.free(drained);
        try std.testing.expectEqual(@as(usize, 1), drained.len);
        try std.testing.expectEqual(owned_ptr, drained[0].data.ptr);
        try std.testing.expectEqualStrings("protected-datagram", drained[0].data);
        var first = drained[0];
        first.deinit(allocator);
    }

    // The borrowed-slice helper keeps its copy behavior for other callers.
    const borrowed = "borrowed-datagram";
    try super.queueOutgoingRawPacket(borrowed);
    {
        const copied = try super.drainOutgoingRawPackets(allocator);
        defer allocator.free(copied);
        try std.testing.expectEqual(@as(usize, 1), copied.len);
        try std.testing.expect(@intFromPtr(copied[0].data.ptr) != @intFromPtr(borrowed.ptr));
        try std.testing.expectEqualStrings(borrowed, copied[0].data);
        var second = copied[0];
        second.deinit(allocator);
    }

    conn.deinit();
    try std.testing.expectEqual(@as(usize, 0), counting.live_allocs);
    try std.testing.expectEqual(@as(usize, 0), counting.live_bytes);
    try std.testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

test "batch P3: ack-eliciting send retains one plaintext allocation and ACK frees it" {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    var counting = CountingAllocator{ .child = gpa.allocator() };
    const allocator = counting.allocator();

    var tls = try zquic.EnhancedCrypto.EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    var crypto = try zquic.PacketCrypto.init(allocator, &tls, null);
    const keys: TestKeys = .{};
    try crypto.installRfc9001ClientInitialKeys(&keys.dcid);
    var conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    const super = &conn.super_connection;
    const space = &super.packet_spaces.initial;

    // Warm-up send/ACK grows the sent_packets and outgoing_raw_packets backing
    // allocations so the measured delta below is exactly the retained
    // plaintext allocation.
    try super.sendProtectedRawPacketOwnedPlaintext(
        &crypto,
        .initial,
        .initial,
        &keys.dcid,
        &keys.scid,
        try ackElicitingPlaintext(allocator),
    );
    const warm_pn: u64 = space.largest_sent_packet.?;
    try discardOutgoing(&conn, allocator);
    var warm_ack = [_]zquic.core.PacketSpace.AckRange{.{
        .start = @intCast(warm_pn),
        .end = @intCast(warm_pn),
    }};
    _ = try space.processAck(&warm_ack, 0, 1_000);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());

    const base_allocs = counting.live_allocs;
    const base_bytes = counting.live_bytes;

    const plaintext = try ackElicitingPlaintext(allocator);
    const plaintext_ptr = plaintext.ptr;
    const plaintext_len = plaintext.len;
    try super.sendProtectedRawPacketOwnedPlaintext(
        &crypto,
        .initial,
        .initial,
        &keys.dcid,
        &keys.scid,
        plaintext,
    );
    const pn: u64 = space.largest_sent_packet.?;
    const sent = space.sent_packets.get(@intCast(pn)).?;
    try std.testing.expect(sent.payload != null);
    try std.testing.expectEqual(plaintext_ptr, sent.payload.?.ptr);
    try std.testing.expectEqual(plaintext_len, sent.payload.?.len);

    try discardOutgoing(&conn, allocator);
    try std.testing.expectEqual(base_allocs + 1, counting.live_allocs);
    try std.testing.expectEqual(base_bytes + plaintext_len, counting.live_bytes);

    var ack = [_]zquic.core.PacketSpace.AckRange{.{
        .start = @intCast(pn),
        .end = @intCast(pn),
    }};
    _ = try space.processAck(&ack, 0, 2_000);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
    try std.testing.expectEqual(base_allocs, counting.live_allocs);
    try std.testing.expectEqual(base_bytes, counting.live_bytes);

    conn.deinit();
    crypto.deinit();
    tls.deinit();
    try std.testing.expectEqual(@as(usize, 0), counting.live_allocs);
    try std.testing.expectEqual(@as(usize, 0), counting.live_bytes);
    try std.testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

test "batch P3: loss observer sees the retained plaintext and loss/discard free it" {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    var counting = CountingAllocator{ .child = gpa.allocator() };
    const allocator = counting.allocator();

    var tls = try zquic.EnhancedCrypto.EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    var crypto = try zquic.PacketCrypto.init(allocator, &tls, null);
    const keys: TestKeys = .{};
    try crypto.installRfc9001ClientInitialKeys(&keys.dcid);
    var conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    const super = &conn.super_connection;
    const space = &super.packet_spaces.initial;

    // Warm-up so the map and queue backing allocations are at steady state.
    try super.sendProtectedRawPacketOwnedPlaintext(
        &crypto,
        .initial,
        .initial,
        &keys.dcid,
        &keys.scid,
        try ackElicitingPlaintext(allocator),
    );
    const warm_pn: u64 = space.largest_sent_packet.?;
    try discardOutgoing(&conn, allocator);
    var warm_ack = [_]zquic.core.PacketSpace.AckRange{.{
        .start = @intCast(warm_pn),
        .end = @intCast(warm_pn),
    }};
    _ = try space.processAck(&warm_ack, 0, 1_000);

    const base_allocs = counting.live_allocs;
    const base_bytes = counting.live_bytes;

    const first = try ackElicitingPlaintext(allocator);
    const first_ptr = first.ptr;
    const first_len = first.len;
    try super.sendProtectedRawPacketOwnedPlaintext(&crypto, .initial, .initial, &keys.dcid, &keys.scid, first);
    const first_pn: u64 = space.largest_sent_packet.?;
    const second = try ackElicitingPlaintext(allocator);
    try super.sendProtectedRawPacketOwnedPlaintext(&crypto, .initial, .initial, &keys.dcid, &keys.scid, second);
    const second_pn: u64 = space.largest_sent_packet.?;
    try discardOutgoing(&conn, allocator);
    try std.testing.expectEqual(base_allocs + 2, counting.live_allocs);
    try std.testing.expectEqual(base_bytes + first_len * 2, counting.live_bytes);

    var ack = [_]zquic.core.PacketSpace.AckRange{.{
        .start = @intCast(second_pn),
        .end = @intCast(second_pn),
    }};
    _ = try space.processAck(&ack, 0, 2_000);
    try std.testing.expectEqual(base_allocs + 1, counting.live_allocs);

    var observation = LossObservation{
        .expected_ptr = first_ptr,
        .expected_len = first_len,
    };
    super.setLostPacketObserver(LossObservation.observe, &observation);
    {
        var lost = space.detectLostPackets(10_000, 1_000, 1);
        defer lost.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), lost.items.len);
        try std.testing.expectEqual(@as(zquic.core.PacketSpace.PacketNumber, @intCast(first_pn)), lost.items[0]);
        try std.testing.expectEqual(@as(usize, 1), observation.calls);
        try std.testing.expect(observation.seen);

        // The observer ran before zquic released the retained plaintext.
        // Live allocations here are the payload plus the `lost` list itself.
        try std.testing.expectEqual(base_allocs + 2, counting.live_allocs);
        space.onPacketsLost(lost.items);
    }
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
    try std.testing.expectEqual(base_allocs, counting.live_allocs);
    try std.testing.expectEqual(base_bytes, counting.live_bytes);
    conn.deinit();

    // Discard is the third release path. Warm a fresh connection first so its
    // map and raw-packet queue capacities are steady state; discard then frees
    // the retained plaintext and the map, leaving only those warm capacities.
    var discard_conn = try zquic.Connection.Connection.init(allocator, .client, .{});
    const discard_super = &discard_conn.super_connection;
    const discard_space = &discard_super.packet_spaces.initial;
    try discard_super.sendProtectedRawPacketOwnedPlaintext(
        &crypto,
        .initial,
        .initial,
        &keys.dcid,
        &keys.scid,
        try ackElicitingPlaintext(allocator),
    );
    const discard_warm_pn: u64 = discard_space.largest_sent_packet.?;
    try discardOutgoing(&discard_conn, allocator);
    var discard_warm_ack = [_]zquic.core.PacketSpace.AckRange{.{
        .start = @intCast(discard_warm_pn),
        .end = @intCast(discard_warm_pn),
    }};
    _ = try discard_space.processAck(&discard_warm_ack, 0, 3_000);

    const discard_base_allocs = counting.live_allocs;
    const discard_base_bytes = counting.live_bytes;
    const discarded = try ackElicitingPlaintext(allocator);
    try discard_super.sendProtectedRawPacketOwnedPlaintext(
        &crypto,
        .initial,
        .initial,
        &keys.dcid,
        &keys.scid,
        discarded,
    );
    try discardOutgoing(&discard_conn, allocator);
    try std.testing.expectEqual(discard_base_allocs + 1, counting.live_allocs);
    try std.testing.expectEqual(discard_base_bytes + discarded.len, counting.live_bytes);
    discard_space.discard();
    try std.testing.expectEqual(@as(usize, 0), discard_space.sent_packets.count());
    // The retained plaintext and the sent_packets map are both released.
    try std.testing.expectEqual(discard_base_allocs - 1, counting.live_allocs);
    discard_conn.deinit();

    crypto.deinit();
    tls.deinit();
    try std.testing.expectEqual(@as(usize, 0), counting.live_allocs);
    try std.testing.expectEqual(@as(usize, 0), counting.live_bytes);
    try std.testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}

fn setCert() !void {
    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
}

fn recvClient(client: *transport.Connection, buf: []u8) void {
    var peer: posix.sockaddr.in = undefined;
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    const n = std.c.recvfrom(
        client.socket,
        buf.ptr,
        buf.len,
        std.c.MSG.DONTWAIT,
        @ptrCast(&peer),
        &peer_len,
    );
    if (n > 0) client.handleDatagram(buf[0..@intCast(n)]) catch {};
}

/// Assert that the plaintext allocation most recently handed to zquic by
/// transport.schedule() is still the one SentPacket retains, exactly once.
fn expectRetainedOwnedPlaintext(client: *transport.Connection) !void {
    const ptr = transport.test_last_owned_plaintext_ptr orelse return error.MissingOwnedPlaintext;
    const len = transport.test_last_owned_plaintext_len;
    const spaces = [_]*zquic.core.PacketSpace.PacketSpace{
        &client.quic.super_connection.packet_spaces.initial,
        &client.quic.super_connection.packet_spaces.handshake,
        &client.quic.super_connection.packet_spaces.application,
    };
    var matches: usize = 0;
    for (spaces) |space| {
        var iterator = space.sent_packets.valueIterator();
        while (iterator.next()) |packet| {
            if (packet.payload) |payload| {
                if (payload.ptr == ptr) {
                    matches += 1;
                    try std.testing.expectEqual(len, payload.len);
                }
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 1), matches);
}

test "batch P3: transport schedule transfers its serialized plaintext" {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    var counting = CountingAllocator{ .child = gpa.allocator() };
    const allocator = counting.allocator();

    try setCert();
    defer qtls.deinitServer();

    var listener = try transport.Listener.init(allocator, 0);
    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    });

    // initClient already serialized and flushed the ClientHello. That packet is
    // ack-eliciting, so the transport must have handed its allocation over.
    try std.testing.expect(transport.test_owned_ack_eliciting_schedules > 0);
    try expectRetainedOwnedPlaintext(client);

    var buf: [transport.max_datagram_size]u8 = undefined;
    const deadline = transport.nowNanos() + 10 * std.time.ns_per_s;
    while (!client.isEstablished()) {
        if (transport.nowNanos() >= deadline) return error.Timeout;
        const before = transport.test_owned_ack_eliciting_schedules;
        client.service() catch {};
        if (transport.test_owned_ack_eliciting_schedules != before) {
            try expectRetainedOwnedPlaintext(client);
        }
        _ = listener.readAndDispatch(&buf, 16);
        listener.serviceAll();
        recvClient(client, &buf);
        transport.sleepNs(std.time.ns_per_ms);
    }
    try std.testing.expect(transport.test_owned_plaintext_schedules > 0);

    client.deinit();
    listener.deinit();
    try std.testing.expectEqual(@as(usize, 0), counting.live_allocs);
    try std.testing.expectEqual(@as(usize, 0), counting.live_bytes);
    try std.testing.expectEqual(std.heap.Check.ok, gpa.deinit());
}
