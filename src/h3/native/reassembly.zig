//! Byte reassembly for one QUIC stream.
//!
//! QUIC may deliver a stream's bytes out of order; this keeps the gaps and hands
//! the caller only the contiguous prefix.

const std = @import("std");

const max_stream_bytes = 16 * 1024 * 1024;

pub const Reassembler = struct {
    allocator: std.mem.Allocator,
    buf: std.ArrayListUnmanaged(u8) = .empty,
    received: std.DynamicBitSet,
    contiguous: usize = 0,
    final_size: ?usize = null,

    pub fn init(allocator: std.mem.Allocator) !Reassembler {
        return .{
            .allocator = allocator,
            .received = try std.DynamicBitSet.initEmpty(allocator, 0),
        };
    }

    pub fn deinit(self: *Reassembler) void {
        self.buf.deinit(self.allocator);
        self.received.deinit();
    }

    /// Insert bytes and return the newly contiguous prefix, if any. The slice
    /// points into this reassembler and stays valid until the next insert.
    pub fn insert(self: *Reassembler, offset: u64, data: []const u8, fin: bool) ![]const u8 {
        const start = std.math.cast(usize, offset) orelse return error.StreamTooLarge;
        const end = std.math.add(usize, start, data.len) catch return error.StreamTooLarge;
        if (end > max_stream_bytes) return error.StreamTooLarge;
        if (self.final_size) |final_size| {
            if (end > final_size or (fin and end != final_size)) return error.StreamTooLarge;
        }
        if (fin) self.final_size = end;

        if (end > self.buf.items.len) {
            const old_len = self.buf.items.len;
            try self.buf.resize(self.allocator, end);
            @memset(self.buf.items[old_len..end], 0);
            try self.received.resize(end, false);
        }

        for (data, start..) |byte, index| {
            self.buf.items[index] = byte;
            self.received.set(index);
        }

        const before = self.contiguous;
        while (self.contiguous < self.buf.items.len and self.received.isSet(self.contiguous)) {
            self.contiguous += 1;
        }
        if (self.contiguous == before) return &.{};
        return self.buf.items[before..self.contiguous];
    }

    pub fn complete(self: *const Reassembler) bool {
        return if (self.final_size) |size| self.contiguous >= size else false;
    }
};

test "reassembler: out-of-order bytes fill gaps without duplicating data" {
    var reassembler = try Reassembler.init(std.testing.allocator);
    defer reassembler.deinit();

    // A leading gap holds back the newly arrived bytes.
    try std.testing.expectEqualStrings("", try reassembler.insert(2, "cde", false));
    try std.testing.expectEqual(@as(usize, 0), reassembler.contiguous);

    // Filling the gap releases everything that was waiting behind it.
    try std.testing.expectEqualStrings("abcde", try reassembler.insert(0, "abc", false));

    // Extending the prefix releases only the newly contiguous bytes.
    try std.testing.expectEqualStrings("f", try reassembler.insert(5, "f", false));

    // A duplicate and an overlapping range add no new prefix bytes.
    try std.testing.expectEqualStrings("", try reassembler.insert(5, "f", false));
    try std.testing.expectEqualStrings("", try reassembler.insert(1, "bcd", false));

    // A later gap is filled in two steps.
    try std.testing.expectEqualStrings("", try reassembler.insert(7, "h", false));
    try std.testing.expectEqualStrings("gh", try reassembler.insert(6, "g", false));
    try std.testing.expectEqualStrings("abcdefgh", reassembler.buf.items);
    try std.testing.expect(!reassembler.complete());
}

test "reassembler: FIN completes only when the contiguous prefix reaches it" {
    var reassembler = try Reassembler.init(std.testing.allocator);
    defer reassembler.deinit();

    // The final size is known, but the data is not yet contiguous.
    try std.testing.expectEqualStrings("", try reassembler.insert(2, "c", true));
    try std.testing.expect(!reassembler.complete());

    try std.testing.expectEqualStrings("abc", try reassembler.insert(0, "ab", false));
    try std.testing.expect(reassembler.complete());

    // No bytes beyond the final size, and no conflicting FIN.
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(3, "d", false));
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(1, "b", true));

    // Repeating the matching FIN is harmless.
    try std.testing.expectEqualStrings("", try reassembler.insert(0, "abc", true));
    try std.testing.expect(reassembler.complete());
}
