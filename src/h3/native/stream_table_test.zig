//! Unit tests for StreamTable with a fake Sender.
//!
//! These tests do not open a network connection. They drive the same batch
//! builder the transport uses and prove the transactional boundaries: a failed
//! schedule commits nothing, FIN-only frames are reserved before data, and the
//! finished/closed bookkeeping only reaps after a successful commit.

const std = @import("std");
const zquic = @import("zquic");
const flow_control = @import("flow_control.zig");
const stats_mod = @import("stats.zig");
const stream_table = @import("stream_table.zig");

const QuicFrames = zquic.core.QuicFrames;

const RecordedFrame = struct {
    stream_id: u64,
    offset: u64,
    len: usize,
    fin: bool,
};

/// Records what reached schedule(). A failed send still increments calls so a
/// test can observe that the transaction stopped before commit.
const FakeSender = struct {
    allocator: std.mem.Allocator,
    fail: bool = false,
    calls: usize = 0,
    last_frame_count: usize = 0,
    frames: std.ArrayListUnmanaged(RecordedFrame) = .empty,
    payloads: std.ArrayListUnmanaged([]u8) = .empty,

    fn deinit(self: *FakeSender) void {
        for (self.payloads.items) |payload| self.allocator.free(payload);
        self.payloads.deinit(self.allocator);
        self.frames.deinit(self.allocator);
    }

    fn sender(self: *FakeSender) stream_table.Sender {
        return .{ .context = self, .schedule = schedule };
    }

    fn schedule(context: *anyopaque, frames: []const QuicFrames.Frame) anyerror!void {
        const self: *FakeSender = @ptrCast(@alignCast(context));
        self.calls += 1;
        self.last_frame_count = frames.len;
        if (self.fail) return error.ScheduleFailed;
        for (frames) |frame| {
            switch (frame) {
                .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => |stream| {
                    try self.frames.append(self.allocator, .{
                        .stream_id = stream.stream_id,
                        .offset = stream.offset,
                        .len = stream.data.len,
                        .fin = stream.fin,
                    });
                    const copy = try self.allocator.dupe(u8, stream.data);
                    errdefer self.allocator.free(copy);
                    try self.payloads.append(self.allocator, copy);
                },
                else => {},
            }
        }
    }
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    flow: flow_control.FlowControl,
    stats: stats_mod.Stats = .{},
    table: stream_table.StreamTable = .{},
    sender: FakeSender,
    batches: usize = 0,
    observed_frames: usize = 0,
    observed_streams: usize = 0,
    observed_payload_used: usize = 0,

    fn init(allocator: std.mem.Allocator) !*Fixture {
        const self = try allocator.create(Fixture);
        self.* = .{
            .allocator = allocator,
            .flow = flow_control.FlowControl.init(allocator, 1 << 20, 1 << 20),
            .sender = .{ .allocator = allocator },
        };
        self.flow.applyPeerLimits(.{
            .max_data = 1 << 20,
            .max_streams_bidi = 100,
            .max_streams_uni = 100,
            .max_stream_data_uni = 1 << 20,
            .max_stream_data_bidi_local = 1 << 20,
            .max_stream_data_bidi_remote = 1 << 20,
        }, true);
        return self;
    }

    fn deinit(self: *Fixture) void {
        self.table.deinit(self.allocator);
        self.flow.deinit();
        self.sender.deinit();
        self.allocator.destroy(self);
    }

    fn ctx(self: *Fixture) stream_table.Context {
        return .{
            .allocator = self.allocator,
            .stats = &self.stats,
            .flow = &self.flow,
            .local_is_client = true,
            .batch_observer = .{ .context = self, .record = recordBatch },
        };
    }

    fn recordBatch(raw: ?*anyopaque, observation: stream_table.BatchObservation) void {
        const self: *Fixture = @ptrCast(@alignCast(raw.?));
        self.batches += 1;
        self.observed_frames = observation.frame_count;
        self.observed_streams = observation.stream_count;
        self.observed_payload_used = observation.payload_used;
    }

    fn flush(self: *Fixture, budget: usize) !void {
        try self.table.flushStreams(self.ctx(), self.sender.sender(), null, budget);
    }
};

test "stream table: two streams share one batch" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    try fixture.table.queueStreamData(fixture.ctx(), 0, "alpha", false);
    try fixture.table.queueStreamData(fixture.ctx(), 4, "bravo", false);
    try fixture.flush(1200);

    try std.testing.expectEqual(@as(usize, 1), fixture.sender.calls);
    try std.testing.expectEqual(@as(usize, 2), fixture.sender.last_frame_count);
    try std.testing.expectEqual(@as(usize, 2), fixture.sender.frames.items.len);
    try std.testing.expectEqual(@as(usize, 1), fixture.batches);
    try std.testing.expectEqual(@as(usize, 2), fixture.observed_frames);
    try std.testing.expectEqual(@as(usize, 2), fixture.observed_streams);
    try std.testing.expect(fixture.observed_payload_used >= 10);

    var seen_first = false;
    var seen_second = false;
    var first_payload: ?[]const u8 = null;
    var second_payload: ?[]const u8 = null;
    for (fixture.sender.frames.items, 0..) |frame, index| {
        if (frame.stream_id == 0) {
            seen_first = true;
            first_payload = fixture.sender.payloads.items[index];
            try std.testing.expectEqual(@as(u64, 0), frame.offset);
            try std.testing.expectEqual(@as(usize, 5), frame.len);
            try std.testing.expect(!frame.fin);
        } else if (frame.stream_id == 4) {
            seen_second = true;
            second_payload = fixture.sender.payloads.items[index];
            try std.testing.expectEqual(@as(u64, 0), frame.offset);
            try std.testing.expectEqual(@as(usize, 5), frame.len);
            try std.testing.expect(!frame.fin);
        } else {
            return error.UnexpectedStream;
        }
    }
    try std.testing.expect(seen_first and seen_second);
    try std.testing.expectEqualStrings("alpha", first_payload.?);
    try std.testing.expectEqualStrings("bravo", second_payload.?);

    try std.testing.expectEqual(@as(u64, 5), fixture.table.streamSendSnapshot(0).?.sent);
    try std.testing.expectEqual(@as(usize, 0), fixture.table.streamSendSnapshot(0).?.pending);
    try std.testing.expectEqual(@as(u64, 5), fixture.table.streamSendSnapshot(4).?.sent);
    try std.testing.expectEqual(@as(u64, 10), fixture.flow.sent_data);
}

test "stream table: failed Sender leaves offsets and sent_data unchanged" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    try fixture.table.queueStreamData(fixture.ctx(), 0, "hello", false);
    const before = fixture.table.streamSendSnapshot(0).?;
    try std.testing.expectEqual(@as(u64, 0), before.sent);
    try std.testing.expectEqual(@as(usize, 5), before.pending);

    fixture.sender.fail = true;
    try std.testing.expectError(error.ScheduleFailed, fixture.flush(1200));

    try std.testing.expectEqual(@as(usize, 1), fixture.sender.calls);
    try std.testing.expectEqual(@as(usize, 0), fixture.batches);
    try std.testing.expectEqual(@as(u64, 0), fixture.flow.sent_data);
    const after_failure = fixture.table.streamSendSnapshot(0).?;
    try std.testing.expectEqual(before.sent, after_failure.sent);
    try std.testing.expectEqual(before.pending, after_failure.pending);
    try std.testing.expectEqual(before.buf_len, after_failure.buf_len);
    try std.testing.expectEqual(before.fin_sent, after_failure.fin_sent);

    // The retry sends the same bytes at the same offset exactly once.
    fixture.sender.fail = false;
    try fixture.flush(1200);
    try std.testing.expectEqual(@as(usize, 2), fixture.sender.calls);
    try std.testing.expectEqual(@as(usize, 1), fixture.batches);
    try std.testing.expectEqual(@as(u64, 5), fixture.flow.sent_data);
    const after_retry = fixture.table.streamSendSnapshot(0).?;
    try std.testing.expectEqual(@as(u64, 5), after_retry.sent);
    try std.testing.expectEqual(@as(usize, 0), after_retry.pending);
}

test "stream table: FIN-only frame is reserved ahead of stream data" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    const payload: [512]u8 = @splat('d');
    try fixture.table.queueStreamData(fixture.ctx(), 4, &payload, false);
    try fixture.table.queueStreamData(fixture.ctx(), 0, &.{}, true);
    try fixture.flush(1200);

    try std.testing.expectEqual(@as(usize, 1), fixture.sender.calls);
    try std.testing.expectEqual(@as(usize, 2), fixture.sender.frames.items.len);
    const fin_frame = fixture.sender.frames.items[0];
    const data_frame = fixture.sender.frames.items[1];
    try std.testing.expectEqual(@as(u64, 0), fin_frame.stream_id);
    try std.testing.expectEqual(@as(usize, 0), fin_frame.len);
    try std.testing.expect(fin_frame.fin);
    try std.testing.expectEqual(@as(u64, 4), data_frame.stream_id);
    try std.testing.expectEqual(@as(usize, payload.len), data_frame.len);
    try std.testing.expect(!data_frame.fin);
    try std.testing.expectEqual(@as(u64, payload.len), fixture.flow.sent_data);

    // The FIN stream's send state is reaped even though its receive side is
    // still open; the stream itself is not marked closed yet.
    try std.testing.expect(fixture.table.streamSendSnapshot(0) == null);
    try std.testing.expect(!fixture.table.isStreamClosed(0));
    try std.testing.expect(fixture.flow.stream_flow.get(0) != null);

    // Nothing is sendable on a second pass: the FIN was committed once and the
    // data stream has no FIN.
    try fixture.flush(1200);
    try std.testing.expectEqual(@as(usize, 1), fixture.sender.calls);
}

test "stream table: reap removes send state and closes both-FIN streams" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    const stream_id: u64 = 8;
    const recv_flow = (try fixture.flow.ensureStream(stream_id, true)).flow;
    try fixture.flow.receive(stream_id, recv_flow, 0, true, true);

    try fixture.table.queueStreamData(fixture.ctx(), stream_id, "bye", true);
    try fixture.flush(1200);

    try std.testing.expectEqual(@as(usize, 1), fixture.batches);
    try std.testing.expect(fixture.table.streamSendSnapshot(stream_id) == null);
    try std.testing.expect(fixture.table.isStreamClosed(stream_id));
    try std.testing.expectEqual(@as(u64, 1), fixture.stats.streams_closed);
    try std.testing.expect(fixture.flow.stream_flow.get(stream_id) == null);
    try std.testing.expectEqual(@as(u64, 3), fixture.flow.sent_data);
}

test "stream table: closed bitset only marks retired stream IDs" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    try std.testing.expect(!fixture.table.isStreamClosed(4000));
    fixture.table.markStreamClosed(fixture.ctx(), 4000);
    try std.testing.expect(fixture.table.isStreamClosed(4000));
    try std.testing.expect(!fixture.table.isStreamClosed(4004));
    try std.testing.expect(!fixture.table.isStreamClosed(0));
}
