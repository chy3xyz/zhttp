//! CRYPTO/TLS state tests.
//!
//! Covers the reassembly, progress, flush-ordering, and Retry reset behavior
//! extracted from transport.zig. The handshake test runs a real in-memory
//! OpenSSL TLS 1.3 handshake between two CryptoStreams and hands the recorded
//! CRYPTO frames to the peer, so reassembly and key installation run end to end
//! without a socket.

const std = @import("std");
const zquic = @import("zquic");
const qtls = @import("qtls.zig");
const crypto_stream = @import("crypto_stream.zig");

const CryptoStream = crypto_stream.CryptoStream;
const Packet = zquic.Packet;
const QuicFrames = zquic.core.QuicFrames;

const Chunk = struct {
    level: usize,
    offset: u64,
    data: []u8,
};

/// Captures the CRYPTO frames a CryptoStream schedules. Padding frames are
/// ignored; the crypto payload is copied because flush() clears TLS output.
const Recorder = struct {
    allocator: std.mem.Allocator,
    chunks: std.ArrayListUnmanaged(Chunk) = .empty,
    next: usize = 0,

    fn deinit(self: *Recorder) void {
        for (self.chunks.items) |chunk| self.allocator.free(chunk.data);
        self.chunks.deinit(self.allocator);
    }

    fn sender(self: *Recorder) crypto_stream.Sender {
        return .{ .context = self, .schedule_fn = schedule };
    }

    fn schedule(
        context: *anyopaque,
        level: usize,
        ptype: Packet.PacketType,
        frames: []const QuicFrames.Frame,
    ) anyerror!void {
        _ = ptype;
        const self: *Recorder = @ptrCast(@alignCast(context));
        for (frames) |frame| {
            switch (frame) {
                .crypto => |crypto| try self.chunks.append(self.allocator, .{
                    .level = level,
                    .offset = crypto.offset,
                    .data = try self.allocator.dupe(u8, crypto.data),
                }),
                else => {},
            }
        }
    }
};

/// Feed every frame the peer produced since the last call, running progress
/// after each one that released new contiguous bytes.
fn exchange(
    from: *Recorder,
    to: *CryptoStream,
    to_rec: *Recorder,
) !?crypto_stream.Progress {
    var last: ?crypto_stream.Progress = null;
    while (from.next < from.chunks.items.len) {
        const chunk = from.chunks.items[from.next];
        from.next += 1;
        switch (try to.feed(chunk.level, chunk.offset, chunk.data)) {
            .advanced => last = try to.progress(to_rec.sender()),
            else => {},
        }
    }
    return last;
}

/// Each flush emits levels in ascending order, and each level's CRYPTO offsets
/// start at zero and advance without gaps or duplicates.
fn expectFlushOrder(rec: *const Recorder) !void {
    var last_level: usize = 0;
    var next_offset = [_]u64{ 0, 0, 0, 0 };
    for (rec.chunks.items) |chunk| {
        try std.testing.expect(chunk.level >= last_level);
        last_level = chunk.level;
        try std.testing.expectEqual(next_offset[chunk.level], chunk.offset);
        next_offset[chunk.level] += chunk.data.len;
    }
}

fn expectLevelZeroBytes(rec: *const Recorder, expected: []const u8) !void {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    defer bytes.deinit(std.testing.allocator);
    for (rec.chunks.items) |chunk| {
        if (chunk.level == 0) try bytes.appendSlice(std.testing.allocator, chunk.data);
    }
    try std.testing.expectEqualSlices(u8, expected, bytes.items);
}

fn expectRetryReplay(rec: *const Recorder, expected: []const u8) !void {
    var replay: std.ArrayListUnmanaged(u8) = .empty;
    defer replay.deinit(std.testing.allocator);
    var expected_offset: u64 = 0;
    for (rec.chunks.items) |chunk| {
        try std.testing.expectEqual(@as(usize, 0), chunk.level);
        try std.testing.expectEqual(expected_offset, chunk.offset);
        try replay.appendSlice(std.testing.allocator, chunk.data);
        expected_offset += chunk.data.len;
    }
    try std.testing.expectEqualSlices(u8, expected, replay.items);
}

test "crypto stream: out-of-order CRYPTO reassembly releases the contiguous prefix" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var stream: CryptoStream = undefined;
    try stream.init(allocator, false, &dcid);
    defer stream.deinit();

    // A leading gap holds the bytes back, then filling it releases everything.
    try std.testing.expectEqualStrings("", try stream.reassemble(2, 2, "cde"));
    try std.testing.expectEqualStrings("abcde", try stream.reassemble(2, 0, "abc"));
    // Duplicates and overlaps add nothing.
    try std.testing.expectEqualStrings("", try stream.reassemble(2, 0, "abc"));
    // A later gap fills in two steps, as TLS handshake messages may arrive.
    try std.testing.expectEqualStrings("", try stream.reassemble(2, 7, "h"));
    try std.testing.expectEqualStrings("fgh", try stream.reassemble(2, 5, "fg"));

    // Reassembly failure is reported as skipped so frame dispatch can continue
    // exactly like the old insert() catch continue path.
    try std.testing.expectEqual(
        crypto_stream.FeedResult.skipped,
        try stream.feed(0, 16 * 1024 * 1024, "x"),
    );
}

test "crypto stream: handshake, out-of-order feed, peer params, and flush order" {
    const allocator = std.testing.allocator;
    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_params = "client transport parameters";
    const server_params = "server transport parameters";

    var client: CryptoStream = undefined;
    try client.init(allocator, false, &dcid);
    defer client.deinit();
    var server: CryptoStream = undefined;
    try server.init(allocator, true, &dcid);
    defer server.deinit();

    // Connection builds Tls from its encoded transport parameters and attaches
    // it; the stream owns the destroy from here.
    client.attachTls(try qtls.Tls.initClient(allocator, "localhost", client_params, .{
        .insecure_skip_verify = true,
    }));
    server.attachTls(try qtls.Tls.initServer(allocator, server_params));

    var client_rec = Recorder{ .allocator = allocator };
    defer client_rec.deinit();
    var server_rec = Recorder{ .allocator = allocator };
    defer server_rec.deinit();

    try client.drive();
    var client_progress = try client.progress(client_rec.sender());
    try std.testing.expect(!client_progress.finished);
    try std.testing.expect(client_progress.peer_params == null);
    try std.testing.expect(client_rec.chunks.items.len > 0);

    // Deliver the ClientHello out of order: the second half is buffered until
    // the first half fills the gap.
    const first = client_rec.chunks.items[0];
    client_rec.next = 1;
    const mid = first.data.len / 2;
    try std.testing.expect(mid > 0);
    try std.testing.expectEqual(
        crypto_stream.FeedResult.buffered,
        try server.feed(first.level, first.offset + mid, first.data[mid..]),
    );
    try std.testing.expectEqual(
        crypto_stream.FeedResult.advanced,
        try server.feed(first.level, first.offset, first.data[0..mid]),
    );

    var server_progress = try server.progress(server_rec.sender());
    try std.testing.expect(!server_progress.finished);

    if (try exchange(&client_rec, &server, &server_rec)) |progress| server_progress = progress;

    var rounds: usize = 0;
    while (rounds < 16) : (rounds += 1) {
        const s = try exchange(&client_rec, &server, &server_rec);
        if (s) |progress| server_progress = progress;
        const c = try exchange(&server_rec, &client, &client_rec);
        if (c) |progress| client_progress = progress;
        if (client_progress.finished and server_progress.finished) break;
        if (s == null and c == null) break;
    }

    try std.testing.expect(client_progress.finished);
    try std.testing.expect(server_progress.finished);
    try std.testing.expectEqualStrings(server_params, client_progress.peer_params.?);
    try std.testing.expectEqualStrings(client_params, server_progress.peer_params.?);

    // Both directions installed RFC 9001 Handshake and Application keys.
    try std.testing.expect(client.handshake_keys and client.application_keys);
    try std.testing.expect(server.handshake_keys and server.application_keys);

    try expectFlushOrder(&client_rec);
    try expectFlushOrder(&server_rec);
    try std.testing.expect(client.crypto_tx_offset[0] > 0);
    try std.testing.expect(server.crypto_tx_offset[0] > 0);
    try expectLevelZeroBytes(&client_rec, client.initial_crypto.items);
}

test "crypto stream: Retry resets Initial CRYPTO state and replays the flight" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_params = "client transport parameters";

    var stream: CryptoStream = undefined;
    try stream.init(allocator, false, &dcid);
    defer stream.deinit();
    stream.attachTls(try qtls.Tls.initClient(allocator, "localhost", client_params, .{
        .insecure_skip_verify = true,
    }));

    var rec = Recorder{ .allocator = allocator };
    defer rec.deinit();
    try stream.drive();
    _ = try stream.progress(rec.sender());

    const initial = try allocator.dupe(u8, stream.initial_crypto.items);
    defer allocator.free(initial);
    try std.testing.expect(initial.len > 0);
    try std.testing.expectEqual(@as(u64, initial.len), stream.crypto_tx_offset[0]);
    try expectFlushOrder(&rec);
    try expectRetryReplay(&rec, initial);

    // Prime the Initial reassembler with bytes that are currently duplicates.
    const prefix = initial[0..@min(initial.len, 64)];
    try std.testing.expectEqual(prefix.len, (try stream.reassemble(0, 0, prefix)).len);
    try std.testing.expectEqual(@as(usize, 0), (try stream.reassemble(0, 0, prefix)).len);

    const retry_dcid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 };
    const token = "retry-token";
    var retry_rec = Recorder{ .allocator = allocator };
    defer retry_rec.deinit();

    try stream.retryInitial(&retry_dcid, token, retry_rec.sender());

    // The Initial packet number space and CRYPTO send cursor restart at zero,
    // and the reassembler dropped the pre-Retry bytes.
    try std.testing.expectEqual(@as(u64, initial.len), stream.crypto_tx_offset[0]);
    try std.testing.expectEqualSlices(u8, token, stream.packet_crypto.initial_token.?);
    try std.testing.expectEqual(prefix.len, (try stream.reassemble(0, 0, prefix)).len);

    // The replay is byte-for-byte the cached ClientHello at its original
    // offsets, not the bytes TLS might emit after a second handshake start.
    try expectRetryReplay(&retry_rec, initial);
    try std.testing.expectEqualSlices(u8, initial, stream.initial_crypto.items);
}
