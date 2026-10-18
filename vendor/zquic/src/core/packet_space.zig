//! QUIC Packet Number Spaces
//!
//! Implements the three QUIC packet number spaces:
//! - Initial: For initial connection establishment
//! - Handshake: For TLS handshake completion
//! - Application: For 1-RTT protected application data
//!
//! Each space maintains its own packet number sequence and crypto state.

const std = @import("std");
const Error = @import("../utils/error.zig");

/// QUIC packet number space types
pub const PacketSpaceType = enum {
    initial,
    handshake,
    application,

    pub fn toString(self: PacketSpaceType) []const u8 {
        return switch (self) {
            .initial => "Initial",
            .handshake => "Handshake",
            .application => "Application",
        };
    }

    /// TLS encryption-level index used by zhttp's transport layer.
    pub fn levelIndex(self: PacketSpaceType) usize {
        return switch (self) {
            .initial => 0,
            .handshake => 2,
            .application => 3,
        };
    }
};

/// Packet number within a space (62-bit integer)
pub const PacketNumber = u62;

/// Maximum packet number value
pub const MAX_PACKET_NUMBER: PacketNumber = (1 << 62) - 1;

/// Packet number space state
pub const PacketSpaceState = enum(u8) {
    /// Space is ready for use
    active,
    /// Space is being discarded
    discarding,
    /// Space has been discarded
    discarded,
};

/// Sent packet information for loss detection
pub const SentPacket = struct {
    packet_number: PacketNumber,
    time_sent: u64, // Timestamp in microseconds
    ack_eliciting: bool,
    in_flight: bool,
    sent_bytes: usize,
    /// Allocator-owned copy of the ack-eliciting plaintext, when retention was
    /// requested by the protected-packet send path. Null when no payload was
    /// retained, preserving the previous SentPacket layout semantics.
    payload: ?[]u8 = null,

    /// Release the retained plaintext copy, if any.
    pub fn deinit(self: *SentPacket, allocator: std.mem.Allocator) void {
        if (self.payload) |bytes| allocator.free(bytes);
        self.payload = null;
    }

    /// Check if packet is considered lost based on time threshold
    pub fn isTimeLost(self: SentPacket, now: u64, time_threshold: u64) bool {
        return self.time_sent + time_threshold < now;
    }

    /// Check if packet is considered lost based on packet number threshold
    pub fn isPacketLost(self: SentPacket, largest_acked: PacketNumber, packet_threshold: u32) bool {
        return self.packet_number + packet_threshold <= largest_acked;
    }
};

/// A packet observed as lost, together with the plaintext retained for it.
///
/// `payload` aliases the packet space's retained plaintext and is only valid
/// for the duration of the ::LostPacketCallback invocation. The packet space
/// frees it immediately after the observer returns.
pub const LostPacket = struct {
    /// TLS encryption-level index (`initial = 0`, `handshake = 2`,
    /// `application = 3`), matching the transport's SentPacket levels.
    level: usize,
    packet_number: PacketNumber,
    /// Retained ack-eliciting plaintext, or an empty slice when the packet was
    /// recorded without retention.
    payload: []const u8,
};

/// Observer invoked for each packet declared lost by ::PacketSpace.detectLostPackets.
///
/// The callback runs for both time-threshold and packet-threshold losses,
/// before the retained payload is freed. It must not retain `payload` or
/// mutate the packet space.
pub const LostPacketCallback = *const fn (
    context: ?*anyopaque,
    level: usize,
    packet_number: u64,
    payload: []const u8,
) void;

/// Acknowledgment range, inclusive.
pub const AckRange = struct {
    start: PacketNumber,
    end: PacketNumber,
};

/// Result of processing ACK ranges in a packet number space.
pub const AckResult = struct {
    newly_acked_count: usize = 0,
    newly_acked_bytes: u64 = 0,
    largest_newly_acked: ?PacketNumber = null,
    largest_newly_acked_time: u64 = 0,
};

/// Aggregate information for packets declared lost.
pub const LostPacketStats = struct {
    lost_count: usize = 0,
    lost_bytes: u64 = 0,
    largest_lost_time: u64 = 0,
};

/// QUIC Packet Number Space
pub const PacketSpace = struct {
    /// Space type identifier
    space_type: PacketSpaceType,

    /// Current state of this space
    state: PacketSpaceState,

    /// Next packet number to assign
    next_packet_number: PacketNumber,

    /// Largest packet number sent in this space
    largest_sent_packet: ?PacketNumber,

    /// Largest packet number acknowledged by peer
    largest_acked_packet: ?PacketNumber,

    /// Time when largest acked packet was acknowledged
    largest_acked_time: u64,

    /// Sent packets awaiting acknowledgment
    sent_packets: std.AutoHashMapUnmanaged(PacketNumber, SentPacket),

    /// Allocator for packet space operations
    allocator: std.mem.Allocator,

    /// Loss detection timer
    loss_detection_timer: ?u64,

    /// PTO (Probe Timeout) count
    pto_count: u32,

    /// Time of last ack-eliciting packet sent
    time_of_last_ack_eliciting_packet: u64,

    /// Optional observer for packets declared lost. Invoked before the
    /// retained payload is freed.
    on_packet_lost: ?LostPacketCallback = null,

    /// Context passed to `on_packet_lost`.
    on_packet_lost_context: ?*anyopaque = null,

    const Self = @This();

    /// Initialize a new packet space
    pub fn init(allocator: std.mem.Allocator, space_type: PacketSpaceType) !Self {
        return Self{
            .space_type = space_type,
            .state = .active,
            .next_packet_number = 0,
            .largest_sent_packet = null,
            .largest_acked_packet = null,
            .largest_acked_time = 0,
            .sent_packets = .empty,
            .allocator = allocator,
            .loss_detection_timer = null,
            .pto_count = 0,
            .time_of_last_ack_eliciting_packet = 0,
        };
    }

    /// Cleanup packet space resources
    pub fn deinit(self: *Self) void {
        var iterator = self.sent_packets.valueIterator();
        while (iterator.next()) |packet| packet.deinit(self.allocator);
        self.sent_packets.deinit(self.allocator);
    }

    /// Get the next packet number and increment counter
    pub fn nextPacketNumber(self: *Self) PacketNumber {
        const pn = self.next_packet_number;
        self.next_packet_number += 1;
        return pn;
    }

    /// Record a sent packet for loss detection without retaining plaintext.
    /// This keeps the long-standing call sites and behavior unchanged.
    pub fn onPacketSent(
        self: *Self,
        packet_number: PacketNumber,
        time_sent: u64,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
    ) !void {
        return self.onPacketSentWithPayload(
            packet_number,
            time_sent,
            ack_eliciting,
            in_flight,
            sent_bytes,
            &.{},
        );
    }

    /// Record a sent packet and retain a copy of its plaintext.
    ///
    /// `retained_payload` is copied into allocator-owned storage when non-empty
    /// and released on ACK, loss, replacement, or space discard. An empty
    /// payload preserves the previous no-retention behavior.
    pub fn onPacketSentWithPayload(
        self: *Self,
        packet_number: PacketNumber,
        time_sent: u64,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
        retained_payload: []const u8,
    ) !void {
        var sent_packet = SentPacket{
            .packet_number = packet_number,
            .time_sent = time_sent,
            .ack_eliciting = ack_eliciting,
            .in_flight = in_flight,
            .sent_bytes = sent_bytes,
        };
        if (retained_payload.len > 0) {
            sent_packet.payload = try self.allocator.dupe(u8, retained_payload);
        }
        errdefer sent_packet.deinit(self.allocator);

        const entry = try self.sent_packets.getOrPut(self.allocator, packet_number);
        if (entry.found_existing) entry.value_ptr.deinit(self.allocator);
        entry.value_ptr.* = sent_packet;

        if (ack_eliciting) {
            self.time_of_last_ack_eliciting_packet = time_sent;
        }

        self.largest_sent_packet = if (self.largest_sent_packet) |largest|
            @max(largest, packet_number)
        else
            packet_number;
    }

    /// Record a sent packet whose retained plaintext allocation is already
    /// owned by the caller.
    ///
    /// Ownership transfers unconditionally: the slice is stored in the
    /// SentPacket, or freed before this function returns an error. This avoids
    /// the copy made by onPacketSentWithPayload for ack-eliciting sends.
    pub fn onPacketSentWithOwnedPayload(
        self: *Self,
        packet_number: PacketNumber,
        time_sent: u64,
        ack_eliciting: bool,
        in_flight: bool,
        sent_bytes: usize,
        retained_payload: ?[]u8,
    ) !void {
        var sent_packet = SentPacket{
            .packet_number = packet_number,
            .time_sent = time_sent,
            .ack_eliciting = ack_eliciting,
            .in_flight = in_flight,
            .sent_bytes = sent_bytes,
            .payload = retained_payload,
        };
        errdefer sent_packet.deinit(self.allocator);

        const entry = try self.sent_packets.getOrPut(self.allocator, packet_number);
        if (entry.found_existing) entry.value_ptr.deinit(self.allocator);
        entry.value_ptr.* = sent_packet;

        if (ack_eliciting) {
            self.time_of_last_ack_eliciting_packet = time_sent;
        }

        self.largest_sent_packet = if (self.largest_sent_packet) |largest|
            @max(largest, packet_number)
        else
            packet_number;
    }

    /// Process acknowledgment of packets.
    ///
    /// ACK ranges that reference packet numbers never sent in this packet
    /// number space are protocol violations. Ranges are inclusive.
    pub fn processAck(
        self: *Self,
        acked_ranges: []const AckRange,
        ack_delay: u64,
        now: u64,
    ) Error.ZquicError!AckResult {
        _ = ack_delay; // Applied by LossRecovery when updating RTT.
        if (self.state != .active) return Error.ZquicError.InvalidState;

        var result = AckResult{};
        var newly_acked_packets = std.array_list.Managed(PacketNumber).init(self.allocator);
        defer newly_acked_packets.deinit();

        try self.validateAckRanges(acked_ranges);

        // An ACK proves every packet number it covers was delivered, even if
        // loss detection already removed that packet from sent_packets. Keep
        // largest_acked current first; otherwise a prematurely declared loss
        // would freeze it and make every later send look lost by threshold.
        for (acked_ranges) |range| {
            if (self.largest_acked_packet == null or range.end > self.largest_acked_packet.?) {
                self.largest_acked_packet = range.end;
                self.largest_acked_time = now;
            }
        }

        // Find newly acknowledged packets.
        for (acked_ranges) |range| {
            var pn = range.start;
            while (pn <= range.end) : (pn += 1) {
                if (self.sent_packets.get(pn)) |packet| {
                    try newly_acked_packets.append(pn);
                    result.newly_acked_count += 1;
                    if (packet.in_flight) {
                        result.newly_acked_bytes += packet.sent_bytes;
                    }

                    if (result.largest_newly_acked == null or pn > result.largest_newly_acked.?) {
                        result.largest_newly_acked = pn;
                        result.largest_newly_acked_time = packet.time_sent;
                    }

                    if (self.largest_acked_packet == null or pn > self.largest_acked_packet.?) {
                        self.largest_acked_packet = pn;
                        self.largest_acked_time = now;
                    }
                }
            }
        }

        for (newly_acked_packets.items) |pn| {
            if (self.sent_packets.fetchRemove(pn)) |removed| {
                var packet = removed.value;
                packet.deinit(self.allocator);
            }
        }

        if (result.newly_acked_count > 0) {
            self.pto_count = 0;
        }

        return result;
    }

    /// Backward-compatible ACK handler for older call sites.
    pub fn onAckReceived(
        self: *Self,
        acked_ranges: []const AckRange,
        ack_delay: u64,
        now: u64,
    ) void {
        _ = self.processAck(acked_ranges, ack_delay, now) catch return;
    }

    fn validateAckRanges(self: *const Self, acked_ranges: []const AckRange) Error.ZquicError!void {
        const largest_sent = self.largest_sent_packet orelse {
            if (acked_ranges.len == 0) return;
            return Error.ZquicError.ProtocolViolation;
        };

        for (acked_ranges, 0..) |range, i| {
            if (range.start > range.end) {
                return Error.ZquicError.ProtocolViolation;
            }
            if (range.end > largest_sent) {
                return Error.ZquicError.ProtocolViolation;
            }

            var j: usize = i + 1;
            while (j < acked_ranges.len) : (j += 1) {
                const other = acked_ranges[j];
                const overlaps = range.start <= other.end and other.start <= range.end;
                if (overlaps) {
                    return Error.ZquicError.ProtocolViolation;
                }
            }
        }
    }

    /// Return byte/time accounting for packets about to be declared lost.
    pub fn lostPacketStats(self: *const Self, lost_packets: []const PacketNumber) LostPacketStats {
        var stats = LostPacketStats{};
        for (lost_packets) |pn| {
            if (self.sent_packets.get(pn)) |packet| {
                stats.lost_count += 1;
                if (packet.in_flight) {
                    stats.lost_bytes += packet.sent_bytes;
                }
                stats.largest_lost_time = @max(stats.largest_lost_time, packet.time_sent);
            }
        }
        return stats;
    }

    /// Detect lost packets based on time and packet number thresholds
    pub fn detectLostPackets(
        self: *Self,
        now: u64,
        time_threshold: u64,
        packet_threshold: u32,
    ) std.ArrayList(PacketNumber) {
        var lost_packets: std.ArrayList(PacketNumber) = .empty;

        if (self.largest_acked_packet == null) {
            return lost_packets;
        }

        const largest_acked = self.largest_acked_packet.?;

        var iterator = self.sent_packets.iterator();
        while (iterator.next()) |entry| {
            const packet = entry.value_ptr.*;

            // Check time-based loss detection
            const time_lost = packet.isTimeLost(now, time_threshold);

            // Check packet-based loss detection
            const packet_lost = packet.isPacketLost(largest_acked, packet_threshold);

            if (time_lost or packet_lost) {
                lost_packets.append(self.allocator, packet.packet_number) catch continue;
                // Surface the loss before onPacketsLost releases the retained
                // plaintext. Both detection thresholds share this path.
                if (self.on_packet_lost) |callback| {
                    callback(
                        self.on_packet_lost_context,
                        self.space_type.levelIndex(),
                        packet.packet_number,
                        packet.payload orelse &.{},
                    );
                }
            }
        }

        return lost_packets;
    }

    /// Remove lost packets from sent packets tracking and release their
    /// retained plaintext.
    pub fn onPacketsLost(self: *Self, lost_packets: []const PacketNumber) void {
        for (lost_packets) |pn| {
            if (self.sent_packets.fetchRemove(pn)) |removed| {
                var packet = removed.value;
                packet.deinit(self.allocator);
            }
        }
    }

    /// Check if there are any in-flight packets
    pub fn hasInFlightPackets(self: Self) bool {
        var iterator = self.sent_packets.valueIterator();
        while (iterator.next()) |packet| {
            if (packet.in_flight) {
                return true;
            }
        }
        return false;
    }

    /// Get count of in-flight bytes
    pub fn bytesInFlight(self: Self) usize {
        var bytes: usize = 0;
        var iterator = self.sent_packets.valueIterator();
        while (iterator.next()) |packet| {
            if (packet.in_flight) {
                bytes += packet.sent_bytes;
            }
        }
        return bytes;
    }

    /// Mark space for discarding (used when transitioning crypto states)
    pub fn markForDiscard(self: *Self) void {
        self.state = .discarding;
    }

    /// Complete discarding of space
    pub fn discard(self: *Self) void {
        self.state = .discarded;
        var iterator = self.sent_packets.valueIterator();
        while (iterator.next()) |packet| packet.deinit(self.allocator);
        self.sent_packets.clearAndFree(self.allocator);
    }

    /// Check if space is active
    pub fn isActive(self: Self) bool {
        return self.state == .active;
    }

    /// Get time of earliest in-flight packet (for PTO calculation)
    pub fn getEarliestInFlightTime(self: Self) ?u64 {
        var earliest: ?u64 = null;
        var iterator = self.sent_packets.valueIterator();
        while (iterator.next()) |packet| {
            if (packet.in_flight) {
                if (earliest == null or packet.time_sent < earliest.?) {
                    earliest = packet.time_sent;
                }
            }
        }
        return earliest;
    }
};

/// Manager for all three packet number spaces
pub const PacketSpaceManager = struct {
    /// Initial packet space
    initial: PacketSpace,

    /// Handshake packet space
    handshake: PacketSpace,

    /// Application packet space
    application: PacketSpace,

    /// Allocator for space management
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize packet space manager
    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .initial = try PacketSpace.init(allocator, .initial),
            .handshake = try PacketSpace.init(allocator, .handshake),
            .application = try PacketSpace.init(allocator, .application),
            .allocator = allocator,
        };
    }

    /// Cleanup all packet spaces
    pub fn deinit(self: *Self) void {
        self.initial.deinit();
        self.handshake.deinit();
        self.application.deinit();
    }

    /// Get packet space by type
    pub fn getSpace(self: *Self, space_type: PacketSpaceType) *PacketSpace {
        return switch (space_type) {
            .initial => &self.initial,
            .handshake => &self.handshake,
            .application => &self.application,
        };
    }

    /// Discard initial and handshake spaces when handshake completes
    pub fn discardHandshakeSpaces(self: *Self) void {
        self.initial.discard();
        self.handshake.discard();
    }

    /// Get total bytes in flight across all active spaces
    pub fn totalBytesInFlight(self: Self) usize {
        var total: usize = 0;
        if (self.initial.isActive()) {
            total += self.initial.bytesInFlight();
        }
        if (self.handshake.isActive()) {
            total += self.handshake.bytesInFlight();
        }
        if (self.application.isActive()) {
            total += self.application.bytesInFlight();
        }
        return total;
    }

    /// Check if any space has in-flight packets
    pub fn hasAnyInFlightPackets(self: Self) bool {
        return (self.initial.isActive() and self.initial.hasInFlightPackets()) or
            (self.handshake.isActive() and self.handshake.hasInFlightPackets()) or
            (self.application.isActive() and self.application.hasInFlightPackets());
    }
};

// Tests
test "packet space basic operations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var space = try PacketSpace.init(allocator, .initial);
    defer space.deinit();

    // Test packet number generation
    try std.testing.expectEqual(@as(PacketNumber, 0), space.nextPacketNumber());
    try std.testing.expectEqual(@as(PacketNumber, 1), space.nextPacketNumber());
    try std.testing.expectEqual(@as(PacketNumber, 2), space.nextPacketNumber());

    // Test packet tracking
    try space.onPacketSent(0, 1000, true, true, 1200);
    try space.onPacketSent(1, 2000, true, true, 1200);

    try std.testing.expect(space.hasInFlightPackets());
    try std.testing.expectEqual(@as(usize, 2400), space.bytesInFlight());
}

test "packet space manager" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var manager = try PacketSpaceManager.init(allocator);
    defer manager.deinit();

    // Test space access
    const initial_space = manager.getSpace(.initial);
    try std.testing.expectEqual(PacketSpaceType.initial, initial_space.space_type);

    const handshake_space = manager.getSpace(.handshake);
    try std.testing.expectEqual(PacketSpaceType.handshake, handshake_space.space_type);

    const app_space = manager.getSpace(.application);
    try std.testing.expectEqual(PacketSpaceType.application, app_space.space_type);

    // Test discarding handshake spaces
    manager.discardHandshakeSpaces();
    try std.testing.expect(!initial_space.isActive());
    try std.testing.expect(!handshake_space.isActive());
    try std.testing.expect(app_space.isActive());
}

test "packet space acknowledgments and loss detection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var space = try PacketSpace.init(allocator, .application);
    defer space.deinit();

    try space.onPacketSent(0, 1_000, true, true, 1200);
    try space.onPacketSent(1, 2_000, true, true, 1200);
    try space.onPacketSent(2, 3_000, true, true, 1200);

    const ack_first = [_]AckRange{.{ .start = 0, .end = 0 }};
    space.onAckReceived(&ack_first, 0, 4_000);
    try std.testing.expectEqual(@as(PacketNumber, 0), space.largest_acked_packet.?);
    try std.testing.expectEqual(@as(usize, 2), space.sent_packets.count());

    const ack_latest = [_]AckRange{.{ .start = 2, .end = 2 }};
    space.onAckReceived(&ack_latest, 0, 5_000);
    try std.testing.expectEqual(@as(PacketNumber, 2), space.largest_acked_packet.?);

    var lost = space.detectLostPackets(6_000, 500, 1);
    defer lost.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), lost.items.len);
    try std.testing.expectEqual(@as(PacketNumber, 1), lost.items[0]);

    space.onPacketsLost(lost.items);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
}

test "packet space rejects invalid ack ranges" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();

    try space.onPacketSent(0, 1_000, true, true, 1200);
    try space.onPacketSent(1, 2_000, true, true, 1200);

    const reversed = [_]AckRange{.{ .start = 1, .end = 0 }};
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, space.processAck(&reversed, 0, 3_000));

    const unsent = [_]AckRange{.{ .start = 2, .end = 2 }};
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, space.processAck(&unsent, 0, 3_000));

    const overlapping = [_]AckRange{
        .{ .start = 0, .end = 1 },
        .{ .start = 1, .end = 1 },
    };
    try std.testing.expectError(Error.ZquicError.ProtocolViolation, space.processAck(&overlapping, 0, 3_000));
}

/// Test observer that snapshots a lost packet before its payload is freed.
const LostCapture = struct {
    calls: usize = 0,
    payload_calls: usize = 0,
    empty_calls: usize = 0,
    level: usize = 0,
    packet_number: u64 = 0,
    saw_payload: bool = false,
    payload: [64]u8 = undefined,
    payload_len: usize = 0,

    fn observe(context: ?*anyopaque, level: usize, packet_number: u64, payload: []const u8) void {
        const self: *LostCapture = @ptrCast(@alignCast(context orelse return));
        self.calls += 1;
        self.level = level;
        self.packet_number = packet_number;
        if (payload.len == 0) {
            self.empty_calls += 1;
            return;
        }
        self.payload_calls += 1;
        if (self.saw_payload) return;
        self.saw_payload = true;
        self.payload_len = @min(payload.len, self.payload.len);
        @memcpy(self.payload[0..self.payload_len], payload[0..self.payload_len]);
    }
};

test "sent packet retains plaintext until ack" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();

    const first = "first ack-eliciting plaintext";
    try space.onPacketSentWithPayload(0, 1_000, true, true, first.len, first);
    try std.testing.expectEqualStrings(first, space.sent_packets.get(0).?.payload.?);

    // Recording without a payload keeps the previous null-payload behavior.
    try space.onPacketSent(1, 2_000, true, true, 1_200);
    try std.testing.expect(space.sent_packets.get(1).?.payload == null);

    const ack = [_]AckRange{.{ .start = 0, .end = 1 }};
    _ = try space.processAck(&ack, 0, 3_000);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
    // The testing allocator reports a leak if ACK processing skipped the free.
}

test "time-threshold loss notifies before freeing plaintext" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();

    var capture = LostCapture{};
    space.on_packet_lost = LostCapture.observe;
    space.on_packet_lost_context = &capture;

    const payload = "time threshold payload";
    try space.onPacketSentWithPayload(0, 1_000, true, true, payload.len, payload);
    try space.onPacketSent(3, 3_000, true, true, 1_200);

    const ack = [_]AckRange{.{ .start = 3, .end = 3 }};
    _ = try space.processAck(&ack, 0, 3_100);

    // The huge packet threshold keeps pn 0 out of the packet-based branch, so
    // only the time threshold can mark it lost.
    var lost = space.detectLostPackets(4_000, 500, 10);
    defer lost.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(PacketNumber, &[_]PacketNumber{0}, lost.items);
    try std.testing.expectEqual(@as(usize, 1), capture.calls);
    try std.testing.expectEqual(@as(usize, 1), capture.payload_calls);
    try std.testing.expectEqual(@as(usize, 3), capture.level);
    try std.testing.expectEqual(@as(u64, 0), capture.packet_number);
    try std.testing.expectEqualStrings(payload, capture.payload[0..capture.payload_len]);

    space.onPacketsLost(lost.items);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
    // The testing allocator reports a leak if loss processing skipped the free.
}

test "packet-threshold loss notifies before freeing plaintext" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();

    var capture = LostCapture{};
    space.on_packet_lost = LostCapture.observe;
    space.on_packet_lost_context = &capture;

    const payload = "packet threshold payload";
    try space.onPacketSentWithPayload(0, 1_000, true, true, payload.len, payload);
    try space.onPacketSent(1, 1_100, true, true, 1_200);
    try space.onPacketSent(2, 1_200, true, true, 1_200);
    try space.onPacketSent(4, 1_400, true, true, 1_200);

    const ack = [_]AckRange{.{ .start = 4, .end = 4 }};
    _ = try space.processAck(&ack, 0, 1_500);

    // A huge time threshold leaves only the packet-number threshold, which
    // marks pn 0 and pn 1 lost (pn 2 is still within the threshold).
    var lost = space.detectLostPackets(1_500, 1_000_000, 3);
    defer lost.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), lost.items.len);
    try std.testing.expect(std.mem.indexOfScalar(PacketNumber, lost.items, 0) != null);
    try std.testing.expect(std.mem.indexOfScalar(PacketNumber, lost.items, 1) != null);
    try std.testing.expectEqual(@as(usize, 2), capture.calls);
    try std.testing.expectEqual(@as(usize, 1), capture.payload_calls);
    try std.testing.expectEqual(@as(usize, 1), capture.empty_calls);
    try std.testing.expectEqualStrings(payload, capture.payload[0..capture.payload_len]);

    space.onPacketsLost(lost.items);
    try std.testing.expectEqual(@as(usize, 1), space.sent_packets.count());
}

test "discard and deinit free retained plaintext" {
    var space = try PacketSpace.init(std.testing.allocator, .initial);
    defer space.deinit();

    try space.onPacketSentWithPayload(0, 1_000, true, true, 5, "hello");
    try space.onPacketSentWithPayload(1, 1_100, false, false, 5, "world");
    space.discard();
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());

    // Deinit is also responsible for packets that were never acked or lost.
    try space.onPacketSentWithPayload(2, 1_200, true, true, 7, "deinit!");
    try std.testing.expectEqualStrings("deinit!", space.sent_packets.get(2).?.payload.?);
}

test "packet space reports actual newly acked bytes" {
    var space = try PacketSpace.init(std.testing.allocator, .application);
    defer space.deinit();

    try space.onPacketSent(0, 1_000, true, true, 100);
    try space.onPacketSent(1, 2_000, true, true, 200);
    try space.onPacketSent(2, 3_000, true, false, 300);

    const ack = [_]AckRange{.{ .start = 0, .end = 2 }};
    const result = try space.processAck(&ack, 0, 4_000);

    try std.testing.expectEqual(@as(usize, 3), result.newly_acked_count);
    try std.testing.expectEqual(@as(u64, 300), result.newly_acked_bytes);
    try std.testing.expectEqual(@as(PacketNumber, 2), result.largest_newly_acked.?);
    try std.testing.expectEqual(@as(u64, 3_000), result.largest_newly_acked_time);
    try std.testing.expectEqual(@as(usize, 0), space.sent_packets.count());
}
