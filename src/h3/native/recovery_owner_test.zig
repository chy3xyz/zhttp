//! Recovery-ownership tests for the native transport.
//!
//! zquic's lost-packet callback is the source of truth. The transport copies
//! the retained plaintext into a bounded queue and service resends it under a
//! fresh packet number. These tests drive real loopback connections and check
//! the observable contract: dropped datagrams recover, a lost STREAM payload
//! keeps its bytes and level, and stream offsets never advance twice.

const std = @import("std");
const posix = std.posix;
const zquic = @import("zquic");
const transport = @import("transport.zig");
const http3 = @import("http3.zig");
const qtls = @import("qtls.zig");

const QuicFrames = zquic.core.QuicFrames;

fn handleHello(allocator: std.mem.Allocator, request: *const http3.Request) http3.Response {
    _ = allocator;
    if (!std.mem.eql(u8, request.path, "/hello")) {
        return .{ .status = .not_found, .body = "not found" };
    }
    return .{ .body = "world" };
}

const SessionContext = struct {
    allocator: std.mem.Allocator,
    drop_every: usize,
    sessions: std.ArrayListUnmanaged(*http3.Session) = .empty,

    fn onConnection(raw: *anyopaque, conn: *transport.Connection) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        conn.setDropOutgoingEvery(self.drop_every);
        const session = http3.Session.initServer(self.allocator, conn, handleHello, 1024 * 1024) catch return;
        self.sessions.append(self.allocator, session) catch session.deinit();
    }

    fn deinit(self: *@This()) void {
        for (self.sessions.items) |session| session.deinit();
        self.sessions.deinit(self.allocator);
    }
};

fn pumpSession(
    client_conn: *transport.Connection,
    client: *http3.Session,
    listener: *transport.Listener,
    sessions: []const *http3.Session,
    buf: []u8,
) void {
    client_conn.service() catch {};
    client.service() catch {};
    _ = listener.readAndDispatch(buf, 8);
    listener.serviceAll();
    for (sessions) |session| session.service() catch {};
    recvClient(client_conn, buf);
    transport.sleepNs(std.time.ns_per_ms);
}

fn recvClient(client_conn: *transport.Connection, buf: []u8) void {
    var peer: posix.sockaddr.in = undefined;
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    const n = std.c.recvfrom(
        client_conn.socket,
        buf.ptr,
        buf.len,
        std.c.MSG.DONTWAIT,
        @ptrCast(&peer),
        &peer_len,
    );
    if (n > 0) client_conn.handleDatagram(buf[0..@intCast(n)]) catch {};
}

test "recovery owner: dropped datagrams still complete an HTTP/3 GET" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();
    var context: SessionContext = .{ .allocator = allocator, .drop_every = 7 };
    defer context.deinit();
    listener.on_connection = .{ .context = &context, .callback = SessionContext.onConnection };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client_conn = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    });
    defer client_conn.deinit();
    client_conn.setDropOutgoingEvery(11);
    const client = try http3.Session.initClient(allocator, client_conn, 1024 * 1024);
    defer client.deinit();

    const lost_before = transport.test_zquic_lost_packets;
    const payload_before = transport.test_zquic_lost_payload_packets;
    const bytes_before = transport.test_zquic_lost_payload_bytes;
    const retransmit_before = transport.test_retransmit_count;

    var buf: [transport.max_datagram_size]u8 = undefined;
    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    var stream_id: ?u64 = null;
    var answer: ?http3.Session.Answer = null;

    while (transport.nowNanos() < deadline) {
        pumpSession(client_conn, client, &listener, context.sessions.items, &buf);
        if (client_conn.isEstablished() and stream_id == null) {
            stream_id = try client.beginRequest("GET", "/hello", "localhost", &.{}, "");
        }
        if (stream_id) |id| {
            if (try client.takeAnswer(id)) |got| {
                answer = got;
                break;
            }
        }
    }

    const got = answer orelse return error.NoAnswer;
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(@as(u16, 200), got.status);
    try std.testing.expectEqualStrings("world", got.body);

    // The response may complete before zquic reports the dropped originals.
    // Keep the session alive until the observer and the resend path have both
    // acted, so the ownership assertions are not merely timing luck.
    const loss_deadline = transport.nowNanos() + 3 * std.time.ns_per_s;
    while ((transport.test_zquic_lost_payload_packets == payload_before or
        transport.test_retransmit_count == retransmit_before) and
        transport.nowNanos() < loss_deadline)
    {
        pumpSession(client_conn, client, &listener, context.sessions.items, &buf);
    }

    try std.testing.expect(transport.test_zquic_lost_packets > lost_before);
    try std.testing.expect(transport.test_zquic_lost_payload_packets > payload_before);
    try std.testing.expect(transport.test_zquic_lost_payload_bytes > bytes_before);
    try std.testing.expect(transport.test_retransmit_count > retransmit_before);
}

/// Offset-addressed receive side. Duplicate STREAM frames are harmless: only
/// unseen offsets are copied, so bytes counts the unique payload exactly.
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

    fn uniqueBytes(self: *Recorder, stream_id: u64) []const u8 {
        const stream = self.get(stream_id) orelse return &.{};
        return stream.buf.items[0..stream.bytes];
    }
};

fn pumpRaw(client: *transport.Connection, listener: *transport.Listener, buf: []u8) void {
    client.service() catch {};
    _ = listener.readAndDispatch(buf, 16);
    listener.serviceAll();
    recvClient(client, buf);
    transport.sleepNs(std.time.ns_per_ms);
}

/// True when the captured resend contains a STREAM frame whose bytes match the
/// original payload at that absolute offset.
fn capturedStreamChunkMatches(expected: []const u8) bool {
    if (transport.test_retransmit_last_level != 3) return false;
    if (transport.test_retransmit_last_old_packet_number >= transport.test_retransmit_last_new_packet_number) return false;
    if (transport.test_retransmit_last_payload_len == 0) return false;

    const payload = transport.test_retransmit_last_payload[0..transport.test_retransmit_last_payload_len];
    var reader = std.Io.Reader.fixed(payload);
    while (reader.seek < reader.end) {
        var frame = QuicFrames.Frame.parse(&reader, std.testing.allocator) catch return false;
        defer frame.deinit(std.testing.allocator);
        switch (frame) {
            .stream,
            .stream_fin,
            .stream_len,
            .stream_len_fin,
            .stream_off,
            .stream_off_fin,
            .stream_off_len,
            .stream_off_len_fin,
            => |stream| {
                if (stream.data.len == 0) continue;
                const start: usize = @intCast(stream.offset);
                const end = start + stream.data.len;
                if (end > expected.len) continue;
                if (std.mem.eql(u8, expected[start..end], stream.data)) return true;
            },
            else => {},
        }
    }
    return false;
}

test "recovery owner: a lost STREAM payload keeps its bytes and gets a new packet number" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();
    var recorder: Recorder = .{ .allocator = allocator };
    defer recorder.deinit();
    listener.handler = .{
        .context = &recorder,
        .on_stream_frame = Recorder.onStream,
        .on_established = Recorder.onEstablished,
        .on_closed = Recorder.onClosed,
    };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    });
    defer client.deinit();

    var buf: [transport.max_datagram_size]u8 = undefined;
    const handshake_deadline = transport.nowNanos() + 10 * std.time.ns_per_s;
    while (!client.isEstablished()) {
        if (transport.nowNanos() >= handshake_deadline) return error.HandshakeTimeout;
        pumpRaw(client, &listener, &buf);
    }

    transport.test_capture_retransmit_payload = true;
    defer transport.test_capture_retransmit_payload = false;
    transport.test_retransmit_last_payload_len = 0;
    transport.test_retransmit_last_old_packet_number = 0;
    transport.test_retransmit_last_new_packet_number = 0;
    transport.test_retransmit_last_level = 0;

    // A body larger than one packet ensures at least one STREAM-carrying
    // datagram participates in the synthetic drop cycle.
    const payload = try allocator.alloc(u8, 4096);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @truncate(i *% 37 + 11);

    client.setDropOutgoingEvery(3);
    const retransmit_before = transport.test_retransmit_count;
    const app_lost_before = transport.test_zquic_lost_application_payload_packets;

    const stream_id = try client.createBidiStream();
    // No FIN: the send entry must stay observable so the test can prove that a
    // retransmission does not advance the stream cursor a second time.
    try client.queueStreamData(stream_id, payload, false);
    try client.service();

    const sent_before = client.streamSendSnapshot(stream_id).?;
    try std.testing.expectEqual(@as(u64, payload.len), sent_before.sent);
    try std.testing.expectEqual(@as(usize, 0), sent_before.pending);

    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    var captured_old: u64 = 0;
    var captured_new: u64 = 0;
    var captured = false;
    while (transport.nowNanos() < deadline) {
        pumpRaw(client, &listener, &buf);
        if (!captured and capturedStreamChunkMatches(payload)) {
            captured = true;
            captured_old = transport.test_retransmit_last_old_packet_number;
            captured_new = transport.test_retransmit_last_new_packet_number;
        }
        if (captured) {
            if (recorder.get(stream_id)) |stream| {
                if (stream.bytes == payload.len) break;
            }
        }
    }

    try std.testing.expect(captured);
    try std.testing.expect(captured_new > captured_old);
    try std.testing.expect(transport.test_retransmit_count > retransmit_before);
    try std.testing.expect(transport.test_zquic_lost_application_payload_packets > app_lost_before);

    const stream = recorder.get(stream_id) orelse return error.NoStream;
    try std.testing.expectEqual(payload.len, stream.bytes);
    try std.testing.expectEqualSlices(u8, payload, recorder.uniqueBytes(stream_id));

    // The original schedule advanced the stream cursor once. The resend is a
    // packet-level replay of retained bytes and must not advance it again.
    const sent_after = client.streamSendSnapshot(stream_id).?;
    try std.testing.expectEqual(sent_before.sent, sent_after.sent);
    try std.testing.expectEqual(@as(usize, 0), sent_after.pending);
    try std.testing.expectEqual(@as(u64, payload.len), client.flow.sent_data);
}
