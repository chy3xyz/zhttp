//! Retained sent-packet storage for the native QUIC transport.
//!
//! zquic owns packet protection, packet-number spaces, and its own loss timers.
//! The transport keeps the plaintext of every ack-eliciting packet until the
//! peer ACKs it, so CRYPTO and STREAM frames can be resent under a new packet
//! number after an SRTT-derived timeout. This file owns that retained-packet
//! list: the 8192-entry cap, ACK-driven removal, and due-packet selection.
//! Sending a retransmission stays in transport.zig, which owns the socket and
//! packet crypto.

const std = @import("std");
const zquic = @import("zquic");
const ack = @import("ack.zig");

const Packet = zquic.Packet;
const QuicFrames = zquic.core.QuicFrames;

/// Maximum number of retained ack-eliciting packets. When the list grows past
/// this, the oldest entry is evicted and its payload freed.
const max_sent_packets = 8192;

/// One ack-eliciting packet whose payload is retained until the peer ACKs it.
/// QUIC retransmits frames, not packets: resending the same plaintext under a
/// new packet number is both legal and enough for CRYPTO and STREAM, whose
/// offsets make duplicates harmless.
pub const SentPacket = struct {
    level: usize,
    ptype: Packet.PacketType,
    packet_number: u64,
    sent_us: u64,
    payload: []u8,

    pub fn deinit(self: *SentPacket, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        self.payload = &.{};
    }
};

/// Bounded list of sent packets awaiting acknowledgment.
pub const Recovery = struct {
    allocator: std.mem.Allocator,
    sent_packets: std.ArrayListUnmanaged(SentPacket) = .empty,

    pub fn init(allocator: std.mem.Allocator) Recovery {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Recovery) void {
        for (self.sent_packets.items) |*sent| sent.deinit(self.allocator);
        self.sent_packets.deinit(self.allocator);
    }

    /// Retain `packet` until it is ACKed. Takes ownership of `packet.payload`,
    /// including when insertion fails.
    ///
    /// The cap is enforced after insertion by evicting the oldest entry, which
    /// is the transport's long-standing behavior.
    pub fn track(self: *Recovery, packet: SentPacket) !void {
        self.sent_packets.append(self.allocator, packet) catch |err| {
            var owned = packet;
            owned.deinit(self.allocator);
            return err;
        };
        if (self.sent_packets.items.len > max_sent_packets) {
            var oldest = self.sent_packets.orderedRemove(0);
            oldest.deinit(self.allocator);
        }
    }

    /// Free and remove every retained packet at `level` covered by `frame`.
    ///
    /// `level` is the TLS level index (initial = 0, early_data = 1,
    /// handshake = 2, application = 3), matching `SentPacket.level`.
    pub fn acknowledge(self: *Recovery, level: usize, frame: *const QuicFrames.AckFrame) void {
        var index = self.sent_packets.items.len;
        while (index > 0) {
            index -= 1;
            const sent = &self.sent_packets.items[index];
            if (sent.level != level) continue;
            if (!ack.covers(frame, sent.packet_number)) continue;
            sent.deinit(self.allocator);
            _ = self.sent_packets.swapRemove(index);
        }
    }

    /// Free and remove every retained packet at `level`.
    ///
    /// Used when a client restarts its Initial packet number space after
    /// accepting a Retry: packets protected with the discarded Initial keys
    /// must not be retransmitted under the new keys.
    pub fn discardLevel(self: *Recovery, level: usize) void {
        var index = self.sent_packets.items.len;
        while (index > 0) {
            index -= 1;
            const sent = &self.sent_packets.items[index];
            if (sent.level != level) continue;
            sent.deinit(self.allocator);
            _ = self.sent_packets.swapRemove(index);
        }
    }

    /// Replace `out` with pointers to every retained packet that has been
    /// waiting at least `timeout_us`.
    ///
    /// The pointers stay valid until the retained list mutates (track,
    /// acknowledge, or deinit), so callers must not advance the list while
    /// using them.
    pub fn collectDue(
        self: *Recovery,
        now_us: u64,
        timeout_us: u64,
        out: *std.ArrayListUnmanaged(*SentPacket),
    ) void {
        out.clearRetainingCapacity();
        for (self.sent_packets.items) |*sent| {
            if (now_us -| sent.sent_us < timeout_us) continue;
            out.append(self.allocator, sent) catch return;
        }
    }

    /// Record the fresh packet number and send time after `sent` was
    /// retransmitted. `sent` must be a pointer obtained from `collectDue`.
    pub fn markRetransmitted(
        self: *Recovery,
        sent: *SentPacket,
        packet_number: u64,
        now_us: u64,
    ) void {
        _ = self;
        sent.packet_number = packet_number;
        sent.sent_us = now_us;
    }
};

const testing = std.testing;

fn testPacket(
    allocator: std.mem.Allocator,
    level: usize,
    packet_number: u64,
    sent_us: u64,
) !SentPacket {
    return .{
        .level = level,
        .ptype = .one_rtt,
        .packet_number = packet_number,
        .sent_us = sent_us,
        .payload = try allocator.dupe(u8, "payload"),
    };
}

test "Recovery discardLevel frees only the discarded space" {
    const allocator = testing.allocator;
    var recovery = Recovery.init(allocator);
    defer recovery.deinit();

    try recovery.track(try testPacket(allocator, 0, 1, 0));
    try recovery.track(try testPacket(allocator, 0, 2, 0));
    try recovery.track(try testPacket(allocator, 2, 1, 0));

    recovery.discardLevel(0);

    try testing.expectEqual(@as(usize, 1), recovery.sent_packets.items.len);
    try testing.expectEqual(@as(usize, 2), recovery.sent_packets.items[0].level);
}

test "Recovery acknowledge frees covered packets at the matching level" {
    const allocator = testing.allocator;
    var recovery = Recovery.init(allocator);
    defer recovery.deinit();

    try recovery.track(try testPacket(allocator, 3, 1, 0));
    try recovery.track(try testPacket(allocator, 3, 2, 0));
    try recovery.track(try testPacket(allocator, 3, 3, 0));
    try recovery.track(try testPacket(allocator, 3, 5, 0));
    try recovery.track(try testPacket(allocator, 2, 2, 0));

    // Covers packet numbers 1..3 at the application level.
    const frame = QuicFrames.AckFrame{
        .largest_acknowledged = 3,
        .ack_delay = 0,
        .ack_range_count = 0,
        .first_ack_range = 2,
        .ack_ranges = @constCast(&[_]QuicFrames.AckFrame.AckRange{}),
    };
    recovery.acknowledge(3, &frame);

    try testing.expectEqual(@as(usize, 2), recovery.sent_packets.items.len);
    var kept_application = false;
    var kept_handshake = false;
    for (recovery.sent_packets.items) |sent| {
        if (sent.level == 3 and sent.packet_number == 5) kept_application = true;
        if (sent.level == 2 and sent.packet_number == 2) kept_handshake = true;
    }
    try testing.expect(kept_application);
    try testing.expect(kept_handshake);
}

test "Recovery cap evicts the oldest retained packet" {
    const allocator = testing.allocator;
    var recovery = Recovery.init(allocator);
    defer recovery.deinit();

    for (0..max_sent_packets + 1) |i| {
        try recovery.track(try testPacket(allocator, 3, i, i));
    }

    try testing.expectEqual(max_sent_packets, recovery.sent_packets.items.len);
    try testing.expectEqual(@as(u64, 1), recovery.sent_packets.items[0].packet_number);
    try testing.expectEqual(
        @as(u64, max_sent_packets),
        recovery.sent_packets.items[max_sent_packets - 1].packet_number,
    );
}

test "Recovery collects due packets and records retransmission" {
    const allocator = testing.allocator;
    var recovery = Recovery.init(allocator);
    defer recovery.deinit();

    try recovery.track(try testPacket(allocator, 3, 10, 1_000));
    try recovery.track(try testPacket(allocator, 2, 11, 1_050));
    try recovery.track(try testPacket(allocator, 3, 12, 1_200));

    var due: std.ArrayListUnmanaged(*SentPacket) = .empty;
    defer due.deinit(allocator);

    recovery.collectDue(1_250, 200, &due);
    try testing.expectEqual(@as(usize, 2), due.items.len);
    try testing.expectEqual(@as(u64, 10), due.items[0].packet_number);
    try testing.expectEqual(@as(u64, 11), due.items[1].packet_number);

    recovery.markRetransmitted(due.items[0], 20, 1_250);
    try testing.expectEqual(@as(u64, 20), due.items[0].packet_number);
    try testing.expectEqual(@as(u64, 1_250), due.items[0].sent_us);

    // The retransmitted packet is no longer due; the other two still are.
    recovery.collectDue(1_300, 200, &due);
    try testing.expectEqual(@as(usize, 1), due.items.len);
    try testing.expectEqual(@as(u64, 11), due.items[0].packet_number);

    recovery.collectDue(1_400, 500, &due);
    try testing.expectEqual(@as(usize, 0), due.items.len);
}
