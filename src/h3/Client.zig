const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");

pub const Client = struct {
    quic_conn: quic.Connection,
    h3_session: *http3.Session,
    allocator: std.mem.Allocator,
    host: []const u8,

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16, tls: quic.ClientTls) !Client {
        const h3 = try http3.Session.init(allocator);
        errdefer h3.deinit();

        // Set up stream data bridge: ngtcp2 recv_stream_data → nghttp3 readStream
        const stream_ctx = quic.StreamDataCtx{
            .h3_conn = @ptrCast(h3.conn),
            .recv_stream_data = onQuicStreamData,
        };
        const qc = try quic.connect(host, port, stream_ctx, null, tls);
        errdefer {
            var conn = qc;
            conn.deinit();
        }

        var client = Client{
            .quic_conn = qc,
            .h3_session = h3,
            .allocator = allocator,
            .host = host,
        };
        // On failure the two errdefers above free the session and the
        // connection, so this must not clean up a second time.
        try openH3Streams(&client);
        return client;
    }

    pub fn deinit(self: *Client) void {
        // Tell the server to drop this connection instead of leaving it to its
        // idle timeout.
        quic.sendConnectionClose(&self.quic_conn, .{ .application = http3.H3_NO_ERROR }, "client done");
        self.h3_session.deinit();
        self.quic_conn.deinit();
    }

    /// Send a GET request, return response body as bytes.
    /// Caller owns the returned slice (allocated with self.allocator).
    pub fn get(self: *Client, path: []const u8) ![]const u8 {
        // 1. Open a bidirectional QUIC stream (retry up to 100 times)
        var stream_id: i64 = -1;
        for (0..100) |_| {
            const ret = ngtcp2.ngtcp2_conn_open_bidi_stream(self.quic_conn.conn, &stream_id, null);
            if (ret == 0) break;
            // Retry: flush, take whatever has arrived, then wait for the
            // peer's answer or the next attempt — poll wakes on the datagram
            // instead of sleeping through it.
            quic.flushPackets(&self.quic_conn) catch {};
            quic.readPacket(&self.quic_conn) catch {};
            _ = quic.pollReadable(self.quic_conn.socket, 10 * std.time.ns_per_ms);
        }
        if (stream_id < 0) return error.QuicError;

        // 2. The response callbacks fill this in; it has to outlive the request.
        var ctx = try http3.ResponseContext.init(self.allocator);
        defer ctx.deinit();

        // 3. Submit HTTP/3 request
        try self.h3_session.submitRequest(stream_id, path, self.host, &ctx);

        // 4. I/O loop: pump writes, wait for the socket or the next QUIC timer,
        // take everything that arrived, and repeat. The wait is a poll() whose
        // timeout is the connection's own next timer (or the request's
        // deadline), so the loop moves as fast as the peer answers instead of
        // one datagram per fixed sleep.
        const start = nowNanos();
        while (!ctx.done) {
            // The peer may have closed the connection: do not spin out the
            // timeout waiting for a response that can no longer come.
            if (ngtcp2.ngtcp2_conn_in_draining_period2(self.quic_conn.conn) != 0) {
                return error.ConnectionClosed;
            }

            // Pump outgoing data: nghttp3 → ngtcp2 → UDP
            try pumpWrites(self);

            // Flush QUIC packets to UDP
            quic.flushPackets(&self.quic_conn) catch {};

            // Timeout after 30 seconds, and wake up for it rather than
            // checking the clock in a sleep loop.
            const elapsed = nowNanos() -% start;
            if (elapsed >= request_timeout_ns) return error.Timeout;
            const until_timer = quic.expiryDelayNs(&self.quic_conn) orelse std.math.maxInt(u64);
            const wait = @min(request_timeout_ns - elapsed, until_timer);

            if (quic.pollReadable(self.quic_conn.socket, wait)) {
                // Read incoming UDP packets — feeds QUIC engine which triggers
                // recv_stream_data → nghttp3 conn_read_stream2 → ctx populated.
                // Everything the socket holds is taken here: waiting for one
                // datagram per poll would cap the connection at one packet per
                // wakeup. A read error ends the connection (a TLS failure, a
                // connection the peer closed, an HTTP/3 connection error): the
                // caller hears why instead of waiting out the timeout above.
                _ = try quic.readAvailablePackets(&self.quic_conn);
            }
            quic.handleExpiryIfDue(&self.quic_conn);
        }

        // 5. Return body (copy to heap since ctx is stack-local)
        const result = try self.allocator.dupe(u8, ctx.body.items);
        return result;
    }
};

/// How long a request may take before it is reported as `error.Timeout`.
const request_timeout_ns = 30 * std.time.ns_per_s;

/// Bridge: ngtcp2 recv_stream_data callback → nghttp3 conn_read_stream2.
/// Called by quic.zig's recvStreamDataCb whenever stream data arrives.
/// Returns the flow control credit the QUIC connection gets back for this
/// stream. nghttp3 counts only the frame bytes it parsed and deliberately
/// leaves the payload of a DATA frame out of that count — those bytes reach the
/// application through `recv_data` — so the whole datagram is credited here: the
/// application consumed all of it.
///
/// A negative return from nghttp3 is a connection error, not a short read:
/// nghttp3.h says the connection must then be closed, and that calling anything
/// on the connection but `nghttp3_conn_del` is undefined behaviour. It is
/// reported as such, with the QUIC error code the connection is closed with.
pub fn onQuicStreamData(h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool, ts: u64) quic.StreamRead {
    const conn: *nghttp3.nghttp3_conn = @ptrCast(@alignCast(h3_conn));
    const consumed = nghttp3.nghttp3_conn_read_stream2(conn, stream_id, data.ptr, data.len, @intFromBool(fin), ts);
    if (consumed < 0) {
        return .{ .connection_error = nghttp3.nghttp3_err_infer_quic_app_error_code(@intCast(consumed)) };
    }
    return .{ .consumed = data.len };
}

/// Pump pending HTTP/3 write data (headers, body, FIN) into QUIC packets.
/// Each call packs one datagram with as much of what nghttp3 has queued as fits,
/// and the round ends when ngtcp2 has nothing it can send — congestion limited,
/// or nothing left to write.
fn pumpWrites(self: *Client) quic.Error!void {
    // One timestamp for the whole round: every call that adds to the same
    // packet has to pass the timestamp the packet was started with.
    const ts = nowNanos();
    var wrote = false;
    while (true) {
        const sent = try quic.writePackedPacket(&self.quic_conn, self.h3_session.conn, ts);
        if (sent == 0) break;
        wrote = true;
    }
    // ngtcp2.h: the application must tell ngtcp2 when packets carrying stream
    // data went out, which is what its send pacing is measured from.
    if (wrote) ngtcp2.ngtcp2_conn_update_pkt_tx_time(self.quic_conn.conn, ts);
}

/// Open this endpoint's control and QPACK streams and bind them to nghttp3.
/// HTTP/3 requires both endpoints to open these, and ngtcp2 only allows it once
/// the peer's stream limits are known.
fn openH3Streams(client: *Client) !void {
    const ctrl = try openUniStream(client);
    const qpack_enc = try openUniStream(client);
    const qpack_dec = try openUniStream(client);
    try client.h3_session.bindControlStream(ctrl);
    try client.h3_session.bindQpackStreams(qpack_enc, qpack_dec);
}

fn openUniStream(client: *Client) !i64 {
    var attempt: usize = 0;
    while (attempt < 200) : (attempt += 1) {
        var stream_id: i64 = -1;
        if (ngtcp2.ngtcp2_conn_open_uni_stream(client.quic_conn.conn, &stream_id, null) == 0) return stream_id;
        quic.flushPackets(&client.quic_conn) catch {};
        // The handshake is done before the connection is handed out, so the
        // limit this needs is already known; an error here means the connection
        // is gone, and retrying it would only hide that.
        quic.readPacket(&client.quic_conn) catch |err| return err;
        _ = quic.pollReadable(client.quic_conn.socket, 10 * std.time.ns_per_ms);
    }
    return error.QuicError;
}

fn nowNanos() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test {
    _ = Client;
    _ = quic;
    _ = http3;
}
