//! ACK ranges for one QUIC packet-number space.
//!
//! Kept separate from zquic so the transport can decrypt packets itself without
//! reaching into zquic's private frame bookkeeping.

const std = @import("std");
const zquic = @import("zquic");
const QuicFrames = zquic.core.QuicFrames;

pub const AckState = struct {
    pns: [64]u64 = undefined,
    count: usize = 0,
    ack_required: bool = false,

    pub fn record(self: *AckState, packet_number: u64, ack_eliciting: bool) void {
        for (self.pns[0..self.count]) |existing| {
            if (existing == packet_number) {
                self.ack_required = self.ack_required or ack_eliciting;
                return;
            }
        }
        if (self.count < self.pns.len) {
            self.pns[self.count] = packet_number;
            self.count += 1;
        } else {
            var smallest: usize = 0;
            for (self.pns[1..], 1..) |existing, i| {
                if (existing < self.pns[smallest]) smallest = i;
            }
            if (packet_number > self.pns[smallest]) self.pns[smallest] = packet_number;
        }
        self.ack_required = self.ack_required or ack_eliciting;
    }

    pub fn clear(self: *AckState) void {
        self.count = 0;
        self.ack_required = false;
    }

    pub fn buildFrame(self: *AckState, allocator: std.mem.Allocator) !QuicFrames.AckFrame {
        if (self.count == 0) return error.InvalidState;
        var sorted: [64]u64 = undefined;
        @memcpy(sorted[0..self.count], self.pns[0..self.count]);
        std.mem.sort(u64, sorted[0..self.count], {}, std.sort.desc(u64));

        const largest = sorted[0];
        var index: usize = 1;
        while (index < self.count and sorted[index] + 1 == sorted[index - 1]) : (index += 1) {}
        const first_range = index - 1;
        var previous_low = largest - first_range;

        var ranges: std.ArrayListUnmanaged(QuicFrames.AckFrame.AckRange) = .empty;
        defer ranges.deinit(allocator);
        while (index < self.count) {
            const high = sorted[index];
            index += 1;
            var low = high;
            while (index < self.count and sorted[index] + 1 == sorted[index - 1]) : (index += 1) {
                low = sorted[index];
            }
            if (previous_low < high + 2) break;
            try ranges.append(allocator, .{
                .gap = previous_low - high - 2,
                .ack_range_length = high - low,
            });
            previous_low = low;
        }

        return .{
            .largest_acknowledged = largest,
            .ack_delay = 0,
            .ack_range_count = ranges.items.len,
            .first_ack_range = first_range,
            .ack_ranges = try allocator.dupe(QuicFrames.AckFrame.AckRange, ranges.items),
        };
    }
};

/// Whether an ACK frame acknowledges a packet number.
pub fn covers(ack: *const QuicFrames.AckFrame, packet_number: u64) bool {
    if (packet_number > ack.largest_acknowledged) return false;
    if (ack.first_ack_range > ack.largest_acknowledged) return false;
    const first_low = ack.largest_acknowledged - ack.first_ack_range;
    if (packet_number >= first_low) return true;
    var next_largest = first_low;
    for (ack.ack_ranges) |range| {
        if (next_largest < 2 or range.gap > next_largest - 2) return false;
        const high = next_largest - range.gap - 2;
        if (high < range.ack_range_length) return false;
        const low = high - range.ack_range_length;
        if (packet_number >= low and packet_number <= high) return true;
        if (packet_number > high) return false;
        next_largest = low;
    }
    return false;
}

test "ack state: buildFrame describes recorded packet numbers" {
    var ack: AckState = .{};
    // Two disjoint runs with holes at 7 and 4..5.
    for ([_]u64{ 10, 9, 8, 6, 3, 2 }) |packet_number| ack.record(packet_number, true);

    const frame = try ack.buildFrame(std.testing.allocator);
    defer std.testing.allocator.free(frame.ack_ranges);

    try std.testing.expectEqual(@as(u64, 10), frame.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2), frame.first_ack_range);
    try std.testing.expectEqual(@as(u64, 2), frame.ack_range_count);
    try std.testing.expectEqual(@as(u64, 0), frame.ack_ranges[0].gap);
    try std.testing.expectEqual(@as(u64, 0), frame.ack_ranges[0].ack_range_length);
    try std.testing.expectEqual(@as(u64, 1), frame.ack_ranges[1].gap);
    try std.testing.expectEqual(@as(u64, 1), frame.ack_ranges[1].ack_range_length);

    try std.testing.expect(covers(&frame, 10));
    try std.testing.expect(covers(&frame, 8));
    try std.testing.expect(!covers(&frame, 7));
    try std.testing.expect(covers(&frame, 6));
    try std.testing.expect(!covers(&frame, 5));
    try std.testing.expect(covers(&frame, 3));
    try std.testing.expect(covers(&frame, 2));
    try std.testing.expect(!covers(&frame, 1));
    try std.testing.expect(!covers(&frame, 11));
}

test "ack state: duplicate records and clear" {
    var ack: AckState = .{};
    try std.testing.expectError(error.InvalidState, ack.buildFrame(std.testing.allocator));

    ack.record(4, false);
    ack.record(4, true);
    try std.testing.expectEqual(@as(usize, 1), ack.count);
    try std.testing.expect(ack.ack_required);

    ack.record(5, false);
    try std.testing.expectEqual(@as(usize, 2), ack.count);

    ack.clear();
    try std.testing.expectEqual(@as(usize, 0), ack.count);
    try std.testing.expect(!ack.ack_required);
    try std.testing.expectError(error.InvalidState, ack.buildFrame(std.testing.allocator));
}

test "ack covers: rejects malformed ranges and uncovered packet numbers" {
    const no_ranges = [_]QuicFrames.AckFrame.AckRange{};
    var frame = QuicFrames.AckFrame{
        .largest_acknowledged = 5,
        .ack_delay = 0,
        .ack_range_count = 0,
        .first_ack_range = 2, // 3..5
        .ack_ranges = @constCast(&no_ranges),
    };
    try std.testing.expect(covers(&frame, 5));
    try std.testing.expect(covers(&frame, 3));
    try std.testing.expect(!covers(&frame, 2));
    try std.testing.expect(!covers(&frame, 6));

    // first_ack_range cannot extend past largest_acknowledged.
    frame.first_ack_range = 6;
    try std.testing.expect(!covers(&frame, 5));

    // A gap larger than the space below the previous range is malformed.
    var ranges = [_]QuicFrames.AckFrame.AckRange{
        .{ .gap = 4, .ack_range_length = 0 },
    };
    frame = .{
        .largest_acknowledged = 5,
        .ack_delay = 0,
        .ack_range_count = 1,
        .first_ack_range = 0,
        .ack_ranges = &ranges,
    };
    try std.testing.expect(covers(&frame, 5));
    try std.testing.expect(!covers(&frame, 4));

    // A valid following range is covered.
    ranges[0] = .{ .gap = 2, .ack_range_length = 0 };
    try std.testing.expect(covers(&frame, 1));
    try std.testing.expect(!covers(&frame, 0));
    try std.testing.expect(!covers(&frame, 2));
}
