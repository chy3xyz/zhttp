//! Transport-level observation of zquic lost packets.
//!
//! zquic owns loss detection and reports each lost packet with its retained
//! plaintext. The transport copies that plaintext into a bounded queue during
//! the callback and resends it later from service; this test proves the
//! callback, the counters, and the zquic-driven resend path work together on a
//! real loopback HTTP/3 request.

const std = @import("std");
const posix = std.posix;
const zquic = @import("zquic");
const transport = @import("transport.zig");
const http3 = @import("http3.zig");
const qtls = @import("qtls.zig");

const LostPacket = zquic.Connection.LostPacket;

fn handle(allocator: std.mem.Allocator, request: *const http3.Request) http3.Response {
    _ = allocator;
    if (!std.mem.eql(u8, request.path, "/hello")) {
        return .{ .status = .not_found, .body = "not found" };
    }
    return .{ .body = "world" };
}

const Context = struct {
    allocator: std.mem.Allocator,
    drop_every: usize,
    sessions: std.ArrayListUnmanaged(*http3.Session) = .empty,

    fn onConnection(raw: *anyopaque, conn: *transport.Connection) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        conn.setDropOutgoingEvery(self.drop_every);
        const session = http3.Session.initServer(self.allocator, conn, handle, 1024 * 1024) catch return;
        self.sessions.append(self.allocator, session) catch {
            session.deinit();
        };
    }

    fn deinit(self: *@This()) void {
        for (self.sessions.items) |session| session.deinit();
        self.sessions.deinit(self.allocator);
    }
};

fn pumpOnce(
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
    transport.sleepNs(std.time.ns_per_ms);
}

test "transport observes zquic lost payloads and resends through the owner path" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    // The re-exported LostPacket is part of zquic's public surface.
    const sample: LostPacket = .{ .level = 0, .packet_number = 0, .payload = &.{} };
    try std.testing.expectEqual(@as(usize, 0), sample.level);

    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();
    var context: Context = .{ .allocator = allocator, .drop_every = 7 };
    defer context.deinit();
    listener.on_connection = .{ .context = &context, .callback = Context.onConnection };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client_conn = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    });
    defer client_conn.deinit();
    // Drop one in seven server datagrams and one in eleven client datagrams.
    // The drops make zquic's loss detector expire while the transport keeps
    // servicing the session.
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
        pumpOnce(client_conn, client, &listener, context.sessions.items, &buf);

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

    // The request can complete before every dropped original is declared lost.
    // Keep the normal service loop running until the callback has observed a
    // non-empty loss and the transport has actually resent one payload.
    const loss_deadline = transport.nowNanos() + 3 * std.time.ns_per_s;
    while ((transport.test_zquic_lost_payload_packets == payload_before or
        transport.test_retransmit_count == retransmit_before) and
        transport.nowNanos() < loss_deadline)
    {
        pumpOnce(client_conn, client, &listener, context.sessions.items, &buf);
    }

    // The callback runs before zquic frees each retained payload, so the
    // counters must see real non-empty plaintext. The resend is zquic-driven:
    // no transport SentPacket timer remains in service.
    try std.testing.expect(transport.test_zquic_lost_packets > lost_before);
    try std.testing.expect(transport.test_zquic_lost_payload_packets > payload_before);
    try std.testing.expect(transport.test_zquic_lost_payload_bytes > bytes_before);
    try std.testing.expect(transport.test_retransmit_count > retransmit_before);
}
