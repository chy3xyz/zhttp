//! Unit tests for the flow-control module. These exercise FlowControl directly
//! so the decisions are pinned without a handshake or a real socket.

const std = @import("std");
const zquic = @import("zquic");
const flow_control = @import("flow_control.zig");

const FlowControl = flow_control.FlowControl;
const QuicFrames = zquic.core.QuicFrames;

test "flow control: peer-opened stream overflow" {
    var flow = FlowControl.init(
        std.testing.allocator,
        flow_control.default_flow_window,
        flow_control.default_flow_window,
    );
    defer flow.deinit();

    // Peer-initiated bidirectional streams: bit 0 set, bit 1 clear.
    var i: u64 = 0;
    while (i < flow_control.default_max_streams) : (i += 1) {
        const ensured = try flow.ensureStream(1 + i * 4, true);
        try std.testing.expect(ensured.created);
    }
    try std.testing.expectError(
        error.StreamLimitExceeded,
        flow.ensureStream(1 + flow_control.default_max_streams * 4, true),
    );
    // The counter advances before the limit check, exactly as the old
    // Connection.ensureStreamFlow did.
    try std.testing.expectEqual(flow_control.default_max_streams + 1, flow.peer_opened_bidi);

    // Peer-initiated unidirectional streams: both bits set.
    i = 0;
    while (i < flow_control.default_max_streams) : (i += 1) {
        _ = try flow.ensureStream(3 + i * 4, true);
    }
    try std.testing.expectError(
        error.StreamLimitExceeded,
        flow.ensureStream(3 + flow_control.default_max_streams * 4, true),
    );
    try std.testing.expectEqual(flow_control.default_max_streams + 1, flow.peer_opened_uni);
}

test "flow control: receive beyond stream and connection limits" {
    var flow = FlowControl.init(std.testing.allocator, 100, 64);
    defer flow.deinit();

    const first = try flow.ensureStream(1, true); // peer bidi stream
    try std.testing.expectEqual(@as(u64, 64), first.flow.recv_limit);

    try std.testing.expectError(
        error.StreamFlowControlExceeded,
        flow.receive(1, first.flow, 65, false, true),
    );
    try std.testing.expectEqual(@as(u64, 0), flow.recv_data);
    try std.testing.expectEqual(@as(u64, 0), first.flow.recv_offset);

    try flow.receive(1, first.flow, 64, false, true);
    try std.testing.expectEqual(@as(u64, 64), flow.recv_data);
    try std.testing.expectEqual(@as(u64, 64), first.flow.recv_offset);

    // A duplicate re-delivery below recv_offset must not consume credit twice.
    try flow.receive(1, first.flow, 64, false, true);
    try std.testing.expectEqual(@as(u64, 64), flow.recv_data);

    const second = try flow.ensureStream(5, true);
    try std.testing.expectError(
        error.ConnectionFlowControlExceeded,
        flow.receive(5, second.flow, 64, false, true),
    );
    try std.testing.expectEqual(@as(u64, 64), flow.recv_data);
    try std.testing.expectEqual(@as(u64, 0), second.flow.recv_offset);
}

test "flow control: MAX_DATA waits for half window and commits after schedule" {
    var flow = FlowControl.init(std.testing.allocator, 16 * 1024, 16 * 1024);
    defer flow.deinit();

    var frames: std.ArrayListUnmanaged(QuicFrames.Frame) = .empty;
    defer frames.deinit(std.testing.allocator);

    flow.recv_data = 8 * 1024 - 1;
    try flow.collectFlowControlFrames(&frames);
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);

    flow.recv_data = 8 * 1024;
    try flow.collectFlowControlFrames(&frames);
    try std.testing.expectEqual(@as(usize, 1), frames.items.len);
    const next = switch (frames.items[0]) {
        .max_data => |frame| frame.maximum_data,
        else => return error.UnexpectedFrame,
    };
    try std.testing.expectEqual(@as(u64, 24 * 1024), next);
    // Collection alone must not move the advertised limit; that is the commit.
    try std.testing.expectEqual(@as(u64, 16 * 1024), flow.recv_data_limit);

    flow.commitMaxData(next);
    try std.testing.expectEqual(@as(u64, 24 * 1024), flow.recv_data_limit);

    frames.clearRetainingCapacity();
    try flow.collectFlowControlFrames(&frames);
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);
}

test "flow control: MAX_STREAM_DATA commits only for the sent frame" {
    var flow = FlowControl.init(std.testing.allocator, 16 * 1024, 1024);
    defer flow.deinit();

    var frames: std.ArrayListUnmanaged(QuicFrames.Frame) = .empty;
    defer frames.deinit(std.testing.allocator);

    const ensured = try flow.ensureStream(1, true);
    const stream = ensured.flow;
    stream.recv_offset = 512;
    try flow.collectFlowControlFrames(&frames);
    try std.testing.expectEqual(@as(usize, 1), frames.items.len);
    const update = switch (frames.items[0]) {
        .max_stream_data => |frame| frame,
        else => return error.UnexpectedFrame,
    };
    try std.testing.expectEqual(@as(u64, 1), update.stream_id);
    try std.testing.expectEqual(@as(u64, 1536), update.maximum_stream_data);
    try std.testing.expectEqual(@as(u64, 1024), stream.recv_limit);

    flow.commitMaxStreamData(1, update.maximum_stream_data);
    try std.testing.expectEqual(@as(u64, 1536), stream.recv_limit);

    // Committing a frame for an unknown stream must not create flow state.
    flow.commitMaxStreamData(5, 4096);
    try std.testing.expect(flow.stream_flow.get(5) == null);

    frames.clearRetainingCapacity();
    try flow.collectFlowControlFrames(&frames);
    try std.testing.expectEqual(@as(usize, 0), frames.items.len);
}

test "flow control: stream FIN counts only peer streams and only once" {
    var flow = FlowControl.init(std.testing.allocator, 16 * 1024, 16 * 1024);
    defer flow.deinit();

    // Peer-initiated bidirectional stream: receive FIN first, then send FIN.
    const peer_bidi = try flow.ensureStream(1, true);
    try flow.receive(1, peer_bidi.flow, 0, true, true);
    try std.testing.expect(peer_bidi.flow.recv_fin);
    try std.testing.expectEqual(@as(u64, 0), flow.closed_peer_bidi);

    flow.markSendFin(1, true);
    try std.testing.expectEqual(@as(u64, 1), flow.closed_peer_bidi);
    // A retransmitted FIN and a second commit must not count again.
    flow.markSendFin(1, true);
    try flow.receive(1, peer_bidi.flow, 0, true, true);
    try std.testing.expectEqual(@as(u64, 1), flow.closed_peer_bidi);

    // Locally initiated streams close silently; they do not replenish
    // MAX_STREAMS.
    const local_bidi = try flow.ensureStream(0, true);
    try flow.receive(0, local_bidi.flow, 0, true, true);
    flow.markSendFin(0, true);
    try std.testing.expect(local_bidi.flow.closed_counted);
    try std.testing.expectEqual(@as(u64, 1), flow.closed_peer_bidi);

    // Peer-initiated unidirectional stream.
    const peer_uni = try flow.ensureStream(3, true);
    try flow.receive(3, peer_uni.flow, 0, true, true);
    flow.markSendFin(3, true);
    try std.testing.expectEqual(@as(u64, 1), flow.closed_peer_uni);
    try std.testing.expectEqual(@as(u64, 1), flow.closed_peer_bidi);
}

test "flow control: peer limits refresh initial send limits" {
    var flow = FlowControl.init(std.testing.allocator, 16 * 1024, 16 * 1024);
    defer flow.deinit();

    const local_bidi = try flow.ensureStream(0, true);
    try std.testing.expectEqual(@as(u64, 0), local_bidi.flow.send_limit);

    flow.applyPeerLimits(.{
        .max_data = 1234,
        .max_streams_bidi = 7,
        .max_streams_uni = 9,
        .max_stream_data_uni = 333,
        .max_stream_data_bidi_local = 444,
        .max_stream_data_bidi_remote = 555,
    }, true);

    try std.testing.expectEqual(@as(u64, 1234), flow.peer_max_data);
    try std.testing.expectEqual(@as(u64, 7), flow.peer_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 9), flow.peer_max_streams_uni);
    // Existing stream widened, and new local streams start at the new window.
    try std.testing.expectEqual(@as(u64, 555), local_bidi.flow.send_limit);
    const fresh = try flow.ensureStream(4, true);
    try std.testing.expectEqual(@as(u64, 555), fresh.flow.send_limit);
    // Peer-initiated bidi streams use initial_max_stream_data_bidi_local.
    const peer_bidi = try flow.ensureStream(1, true);
    try std.testing.expectEqual(@as(u64, 444), peer_bidi.flow.send_limit);
    // Streams we open as unidirectional use initial_max_stream_data_uni.
    const local_uni = try flow.ensureStream(2, true);
    try std.testing.expectEqual(@as(u64, 333), local_uni.flow.send_limit);
}
