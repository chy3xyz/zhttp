//! Fuzz and robustness tests for untrusted wire inputs in the native HTTP/3
//! stack.
//!
//! These tests exercise parsers and reassembly only: no sockets, no timers, no
//! external dependencies. std.testing.fuzz gives coverage-guided fuzzing when
//! the test binary is built with -ffuzz (see "zig build --fuzz"), while its
//! corpus option makes a normal "zig build test-native" run exercise the same
//! malformed seeds deterministically.
//!
//! The QUIC frame tests also pin the defensive bounds/tail handling added to
//! the vendored zquic parser (see vendor/zquic/PROVENANCE.md).

const std = @import("std");
const zquic = @import("zquic");
const qpack = @import("qpack.zig");
const transport = @import("transport.zig");

const QuicFrames = zquic.core.QuicFrames;
const Frame = QuicFrames.Frame;
const Reassembler = transport.Reassembler;

const max_fuzz_input = 1024;

/// Untrusted length fields can ask a QUIC frame parser for terabytes. The
/// parser correctly turns that into OutOfMemory, but asking the OS for those
/// allocations in a sanitizer test is slow and pointless. Cap a *single*
/// allocation while still forwarding every free to std.testing.allocator, so
/// leak and double-free detection keep working.
const max_frame_alloc = 64 * 1024;

const BoundedAllocator = struct {
    child: std.mem.Allocator,
    max_single: usize,

    fn allocator(self: *BoundedAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        if (len > self.max_single) return null;
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > self.max_single) return false;
        return self.child.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        if (new_len > self.max_single) return null;
        return self.child.rawRemap(memory, alignment, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

// ---------------------------------------------------------------------------
// QPACK
// ---------------------------------------------------------------------------

/// Decode one arbitrary header block. Any decoder error is acceptable; a
/// successful header list must be deinitialized so the testing allocator can
/// prove the arena was released.
fn exerciseQpack(block: []const u8) !void {
    var list = qpack.decode(std.testing.allocator, block) catch return;
    defer list.deinit();

    for (list.fields) |field| {
        // Successful decodes validate names, but read the slices anyway so a
        // bad length would trip the safety checks here rather than only at
        // deinit.
        try std.testing.expect(field.name.len > 0);
        for (field.name) |byte| std.mem.doNotOptimizeAway(byte);
        for (field.value) |byte| std.mem.doNotOptimizeAway(byte);
    }
}

const qpack_seeds = [_][]const u8{
    "",
    &.{ 0x00, 0x00 },
    &.{0x00},
    &.{0xff},
    // Required Insert Count non-zero: dynamic table reference.
    &.{ 0x01, 0x00 },
    // Continuation-byte run for the Required Insert Count.
    &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    // Delta Base with the high bit set.
    &.{ 0x00, 0x80 },
    // Literal with static name reference, truncated value.
    &.{ 0x00, 0x00, 0x50 },
    // Literal with static name reference, value length larger than the block.
    &.{ 0x00, 0x00, 0x50, 0x7f },
    // Indexed field line with static index 0.
    &.{ 0x00, 0x00, 0xc0 },
    // Indexed field line with an out-of-range static index.
    &.{ 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    // Literal name, zero-length name.
    &.{ 0x00, 0x00, 0x20 },
    // Literal name, name length larger than the remaining block.
    &.{ 0x00, 0x00, 0x27, 'a' },
    // Literal name with the Huffman bit set and an invalid code.
    &.{ 0x00, 0x00, 0x28, 0x01, 'a' },
    // Literal name with a valid-looking but truncated value.
    &.{ 0x00, 0x00, 0x21, 'a', 0x7f },
    // Dynamic post-base forms.
    &.{ 0x00, 0x00, 0x10 },
    &.{ 0x00, 0x00, 0x1f },
    // Truncated prefixed integer continuation.
    &.{ 0x00, 0x00, 0x3f },
};

/// Encode bytes as a std.testing.Smith slice value: a little-endian u32 length
/// followed by the bytes. smith.slice consumes this framing both for
/// fuzz-generated inputs and for the corpus entries used by normal test runs.
fn corpusSlice(comptime bytes: []const u8) []const u8 {
    const encoded = comptime blk: {
        var out: [4 + bytes.len]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], @intCast(bytes.len), .little);
        @memcpy(out[4..], bytes);
        break :blk out;
    };
    return &encoded;
}

const qpack_corpus = [_][]const u8{
    corpusSlice(""),
    corpusSlice("\x00"),
    corpusSlice("\x00\x00"),
    corpusSlice("\x00\x00\xc0"),
    corpusSlice("\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
    corpusSlice("\x00\x00\x50\x7f"),
    corpusSlice("\x00\x00\x20"),
    corpusSlice("\x00\x00\x27a"),
    corpusSlice("\x00\x00\x28\x01a"),
    corpusSlice("\x00\x00\x21a\x7f"),
    corpusSlice("\x00\x00\x10"),
    corpusSlice("\xff"),
    corpusSlice("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"),
    corpusSlice("\x01\x00"),
    corpusSlice("\x00\x80"),
};

fn qpackFuzzOne(_: void, smith: *std.testing.Smith) !void {
    var buf: [max_fuzz_input]u8 = undefined;
    const len = smith.slice(&buf);
    try exerciseQpack(buf[0..len]);
}

test "qpack fuzz: exhaustive one/two-byte blocks and fixed-seed random blocks" {
    var one: [1]u8 = undefined;
    for (0..256) |value| {
        one[0] = @intCast(value);
        try exerciseQpack(&one);
    }

    var two: [2]u8 = undefined;
    for (0..65536) |value| {
        two[0] = @truncate(value);
        two[1] = @truncate(value >> 8);
        try exerciseQpack(&two);
    }

    for (qpack_seeds) |seed| try exerciseQpack(seed);

    var prng: std.Random.DefaultPrng = .init(0x5150_9204);
    var buf: [256]u8 = undefined;
    for (0..4096) |_| {
        const len = prng.random().uintLessThan(usize, buf.len + 1);
        prng.random().bytes(buf[0..len]);
        try exerciseQpack(buf[0..len]);
    }
}

test "qpack fuzz: std.testing.fuzz arbitrary header blocks" {
    try std.testing.fuzz({}, qpackFuzzOne, .{ .corpus = &qpack_corpus });
}

// ---------------------------------------------------------------------------
// QUIC stream reassembly
// ---------------------------------------------------------------------------

test "reassembler: overlapping, duplicate, and fin inserts" {
    var reassembler = try Reassembler.init(std.testing.allocator);
    defer reassembler.deinit();

    try std.testing.expectEqualStrings("", try reassembler.insert(4, "efgh", false));
    try std.testing.expectEqual(@as(usize, 0), reassembler.contiguous);
    try std.testing.expect(!reassembler.complete());

    try std.testing.expectEqualStrings("abcdefgh", try reassembler.insert(0, "abcd", false));
    try std.testing.expectEqual(@as(usize, 8), reassembler.contiguous);
    try std.testing.expect(!reassembler.complete());

    // Duplicate/overlapping bytes replace data without moving contiguous.
    try std.testing.expectEqualStrings("", try reassembler.insert(2, "cdZZ", false));
    try std.testing.expectEqualStrings("abcdZZgh", reassembler.buf.items[0..8]);

    try std.testing.expectEqualStrings("ij", try reassembler.insert(8, "ij", false));
    try std.testing.expectEqual(@as(usize, 10), reassembler.contiguous);

    // Empty fin at the current end marks the stream complete.
    try std.testing.expectEqualStrings("", try reassembler.insert(10, "", true));
    try std.testing.expect(reassembler.complete());

    // An overlapping fin with the same final size is accepted.
    try std.testing.expectEqualStrings("", try reassembler.insert(9, "X", true));
    try std.testing.expectEqualStrings("abcdZZghiX", reassembler.buf.items[0..10]);
    try std.testing.expect(reassembler.complete());

    // Anything beyond the final size is rejected without corrupting state.
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(10, "k", false));
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(11, "", false));
    try std.testing.expectEqual(@as(usize, 10), reassembler.contiguous);
    try std.testing.expect(reassembler.complete());

    // In-range overwrites after fin are still fine.
    try std.testing.expectEqualStrings("", try reassembler.insert(0, "z", false));
    try std.testing.expectEqualStrings("z", reassembler.buf.items[0..1]);
    try std.testing.expectEqualStrings("", try reassembler.insert(10, "", true));

    // Unrepresentable/oversized offsets are rejected before resizing.
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(std.math.maxInt(u64), "", false));
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(16 * 1024 * 1024 + 1, "", false));
}

test "reassembler: fin with a gap completes only once the gap fills" {
    var reassembler = try Reassembler.init(std.testing.allocator);
    defer reassembler.deinit();

    try std.testing.expectEqualStrings("", try reassembler.insert(4, "ef", true));
    try std.testing.expect(!reassembler.complete());
    try std.testing.expectEqualStrings("", try reassembler.insert(6, "", false));
    try std.testing.expectEqual(@as(usize, 0), reassembler.contiguous);

    try std.testing.expectEqualStrings("abcdef", try reassembler.insert(0, "abcd", false));
    try std.testing.expectEqual(@as(usize, 6), reassembler.contiguous);
    try std.testing.expect(reassembler.complete());

    // fin must agree with the already-recorded final size.
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(7, "", true));
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(0, "abc", true));
    try std.testing.expectEqual(@as(usize, 6), reassembler.contiguous);
}

test "reassembler: empty fin at offset zero" {
    var reassembler = try Reassembler.init(std.testing.allocator);
    defer reassembler.deinit();

    try std.testing.expectEqualStrings("", try reassembler.insert(0, "", true));
    try std.testing.expect(reassembler.complete());
    try std.testing.expectError(error.StreamTooLarge, reassembler.insert(0, "x", false));
}

const reassembler_model_size = 1024;

test "reassembler fuzz: fixed-seed random inserts preserve contiguous tracking" {
    var reassembler = try Reassembler.init(std.testing.allocator);
    defer reassembler.deinit();

    var model: [reassembler_model_size]u8 = @splat(0);
    var present: [reassembler_model_size]bool = @splat(false);
    var expected_contiguous: usize = 0;
    var final_size: ?usize = null;

    var prng: std.Random.DefaultPrng = .init(0x5eed_c0de);
    const random = prng.random();

    for (0..4096) |_| {
        const offset = random.uintLessThan(usize, 768);
        const data_len = random.uintLessThan(usize, 33);
        const end = offset + data_len;
        var data: [32]u8 = undefined;
        random.bytes(data[0..data_len]);
        const fin = random.boolean();

        const before_contiguous = reassembler.contiguous;
        const before_buf_len = reassembler.buf.items.len;
        const should_fail = if (final_size) |size|
            end > size or (fin and end != size)
        else
            false;

        if (reassembler.insert(offset, data[0..data_len], fin)) |prefix| {
            try std.testing.expect(!should_fail);
            if (fin) final_size = end;

            @memcpy(model[offset..end], data[0..data_len]);
            for (0..data_len) |i| present[offset + i] = true;
            while (expected_contiguous < reassembler_model_size and
                present[expected_contiguous])
            {
                expected_contiguous += 1;
            }

            try std.testing.expectEqual(expected_contiguous, reassembler.contiguous);
            try std.testing.expectEqualSlices(
                u8,
                model[0..reassembler.buf.items.len],
                reassembler.buf.items,
            );
            try std.testing.expectEqualSlices(
                u8,
                reassembler.buf.items[before_contiguous..reassembler.contiguous],
                prefix,
            );
            for (0..reassembler.buf.items.len) |i| {
                if (present[i]) try std.testing.expect(reassembler.received.isSet(i));
            }
            if (final_size) |size| {
                try std.testing.expectEqual(expected_contiguous >= size, reassembler.complete());
            }
        } else |err| {
            try std.testing.expect(should_fail);
            try std.testing.expectEqual(error.StreamTooLarge, err);
            try std.testing.expectEqual(before_contiguous, reassembler.contiguous);
            try std.testing.expectEqual(before_buf_len, reassembler.buf.items.len);
            try std.testing.expectEqualSlices(
                u8,
                model[0..reassembler.buf.items.len],
                reassembler.buf.items,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// zquic QUIC frames
// ---------------------------------------------------------------------------

/// Parse one arbitrary frame. On success, deinitializing through the same
/// allocator must be safe; on error, no frame exists to free. The bounded
/// allocator keeps huge-but-untrusted length fields from becoming real
/// allocations while preserving leak detection.
fn exerciseFrame(bytes: []const u8) !void {
    var bounded = BoundedAllocator{
        .child = std.testing.allocator,
        .max_single = max_frame_alloc,
    };
    const allocator = bounded.allocator();

    var reader = std.Io.Reader.fixed(bytes);
    var frame = Frame.parse(&reader, allocator) catch return;
    defer frame.deinit(allocator);

    try std.testing.expect(reader.seek <= bytes.len);
}

const frame_seeds = [_][]const u8{
    "",
    &.{0x00},
    &.{0x01},
    &.{0x1e},
    // ACK with no ranges.
    &.{ 0x02, 0x00, 0x00, 0x00, 0x00 },
    // ACK claiming the maximum number of ranges.
    &.{ 0x02, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 },
    // Truncated ACK fields.
    &.{ 0x02, 0x00 },
    // CRYPTO/NEW_TOKEN/CONNECTION_CLOSE with huge declared lengths.
    &.{ 0x06, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    &.{ 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    &.{ 0x1c, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    &.{ 0x1d, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    // NEW_CONNECTION_ID with a maximum CID length but no following bytes.
    &.{ 0x18, 0x00, 0x00, 0xff },
    // PATH_CHALLENGE (8 bytes) and PATH_RESPONSE (8 and 16 bytes).
    &.{ 0x1a, 0, 1, 2, 3, 4, 5, 6, 7 },
    &.{ 0x1b, 0, 1, 2, 3, 4, 5, 6, 7 },
    &.{ 0x1b, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    // DATAGRAM without a length, and with a huge declared length.
    &.{ 0x30, 0, 1, 2, 3 },
    &.{ 0x31, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    // STREAM frame with a huge declared length.
    &.{ 0x0a, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    // Unknown frame type.
    &.{0x1f},
    &.{0x3f},
    // Multi-byte frame type varint with missing continuation bytes.
    &.{ 0xff, 0x00 },
};

const frame_corpus = [_][]const u8{
    corpusSlice(""),
    corpusSlice("\x00"),
    corpusSlice("\x01"),
    corpusSlice("\x1e"),
    corpusSlice("\x02\x00\x00\x00\x00"),
    corpusSlice("\x02\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00"),
    corpusSlice("\x06\x00\xff\xff\xff\xff\xff\xff\xff\xff"),
    corpusSlice("\x07\xff\xff\xff\xff\xff\xff\xff\xff"),
    corpusSlice("\x1c\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"),
    corpusSlice("\x18\x00\x00\xff"),
    corpusSlice("\x1a\x00\x01\x02\x03\x04\x05\x06\x07"),
    corpusSlice("\x1b\x00\x01\x02\x03\x04\x05\x06\x07"),
    corpusSlice("\x1b\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"),
    corpusSlice("\x30\x00\x01\x02\x03"),
    corpusSlice("\x31\xff\xff\xff\xff\xff\xff\xff\xff"),
    corpusSlice("\x0a\x00\xff\xff\xff\xff\xff\xff\xff\xff"),
    corpusSlice("\x1f"),
    corpusSlice("\x3f"),
    corpusSlice("\xff\x00"),
};

fn frameFuzzOne(_: void, smith: *std.testing.Smith) !void {
    var buf: [max_fuzz_input]u8 = undefined;
    const len = smith.slice(&buf);
    try exerciseFrame(buf[0..len]);
}

test "quic frame fuzz: every one-byte prefix, seeds, and fixed-seed random data" {
    var one: [1]u8 = undefined;
    for (0..256) |value| {
        one[0] = @intCast(value);
        try exerciseFrame(&one);
    }

    for (frame_seeds) |seed| try exerciseFrame(seed);

    // Every stream-frame type byte with a mix of truncated and complete
    // payloads.
    const stream_payloads = [_][]const u8{
        "",
        &.{0x00},
        &.{ 0x00, 0x01, 0x02 },
        &.{ 0x00, 0x00, 0x00, 0x00 },
        &.{ 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    };
    for (0x08..0x10) |frame_type| {
        for (stream_payloads) |payload| {
            var buf: [1 + 16]u8 = undefined;
            buf[0] = @intCast(frame_type);
            @memcpy(buf[1 .. 1 + payload.len], payload);
            try exerciseFrame(buf[0 .. 1 + payload.len]);
        }
    }

    var prng: std.Random.DefaultPrng = .init(0x4672_616d_6573);
    var buf: [256]u8 = undefined;
    for (0..4096) |_| {
        const len = prng.random().uintLessThan(usize, buf.len + 1);
        prng.random().bytes(buf[0..len]);
        try exerciseFrame(buf[0..len]);
    }
}

test "quic frame fuzz: std.testing.fuzz arbitrary frame bytes" {
    try std.testing.fuzz({}, frameFuzzOne, .{ .corpus = &frame_corpus });
}

test "quic frame parse: no-length STREAM and DATAGRAM consume the rest" {
    const allocator = std.testing.allocator;

    var stream_bytes = [_]u8{ 0x08, 0x00, 'a', 'b', 'c' };
    var stream_reader = std.Io.Reader.fixed(&stream_bytes);
    var stream_frame = try Frame.parse(&stream_reader, allocator);
    defer stream_frame.deinit(allocator);
    switch (stream_frame) {
        .stream => |stream| try std.testing.expectEqualStrings("abc", stream.data),
        else => return error.ExpectedStream,
    }
    try std.testing.expectEqual(@as(usize, stream_bytes.len), stream_reader.seek);

    var datagram_bytes = [_]u8{ 0x30, 'x', 'y', 'z' };
    var datagram_reader = std.Io.Reader.fixed(&datagram_bytes);
    var datagram_frame = try Frame.parse(&datagram_reader, allocator);
    defer datagram_frame.deinit(allocator);
    switch (datagram_frame) {
        .datagram => |datagram| try std.testing.expectEqualStrings("xyz", datagram.data),
        else => return error.ExpectedDatagram,
    }
    try std.testing.expectEqual(@as(usize, datagram_bytes.len), datagram_reader.seek);
}

test "quic frame parse: oversized declared lengths fail before allocating" {
    const allocator = std.testing.allocator;

    // ACK with a huge range count but no range bytes.
    var ack: std.Io.Writer.Allocating = .init(allocator);
    defer ack.deinit();
    try ack.writer.writeByte(0x02); // ACK
    try QuicFrames.writeVarint(&ack.writer, 0); // largest
    try QuicFrames.writeVarint(&ack.writer, 0); // delay
    try QuicFrames.writeVarint(&ack.writer, 0x3fff_ffff_ffff_ffff); // count
    try QuicFrames.writeVarint(&ack.writer, 0); // first range
    var ack_reader = std.Io.Reader.fixed(ack.written());
    if (Frame.parse(&ack_reader, allocator)) |frame_value| {
        var frame = frame_value;
        frame.deinit(allocator);
        return error.ExpectedFrameError;
    } else |_| {}

    // CRYPTO whose declared length is far larger than the packet.
    const crypto_bytes = [_]u8{ 0x06, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    var crypto_reader = std.Io.Reader.fixed(&crypto_bytes);
    if (Frame.parse(&crypto_reader, allocator)) |frame_value| {
        var frame = frame_value;
        frame.deinit(allocator);
        return error.ExpectedFrameError;
    } else |_| {}
}

test "quic frame parse: eight-byte PATH_RESPONSE is accepted" {
    const bytes = [_]u8{ 0x1b, 1, 2, 3, 4, 5, 6, 7, 8 };
    var reader = std.Io.Reader.fixed(&bytes);
    var frame = try Frame.parse(&reader, std.testing.allocator);
    defer frame.deinit(std.testing.allocator);
    switch (frame) {
        .path_response => |response| try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &response.data),
        else => return error.ExpectedPathResponse,
    }
    try std.testing.expectEqual(@as(usize, bytes.len), reader.seek);
}
