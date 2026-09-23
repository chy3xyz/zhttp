const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");

/// Sleep for a given number of nanoseconds.
fn sleepNs(ns: u64) void {
    const ts = std.posix.timespec{
        .sec = @intCast(ns / 1_000_000_000),
        .nsec = @intCast(ns % 1_000_000_000),
    };
    _ = std.c.nanosleep(&ts, null);
}

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
        quic.sendConnectionClose(&self.quic_conn, http3.H3_NO_ERROR, "client done");
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
            // Retry: flush, read, sleep
            quic.flushPackets(&self.quic_conn) catch {};
            quic.readPacket(&self.quic_conn) catch {};
            sleepNs(10 * std.time.ns_per_ms);
        }
        if (stream_id < 0) return error.QuicError;

        // 2. The response callbacks fill this in; it has to outlive the request.
        var ctx = try http3.ResponseContext.init(self.allocator);
        defer ctx.deinit();

        // 3. Submit HTTP/3 request
        try self.h3_session.submitRequest(stream_id, path, self.host, &ctx);

        // 4. I/O loop: pump writes, read responses until done
        const start = nowNanos();
        while (!ctx.done) {
            // The peer may have closed the connection: do not spin out the
            // timeout waiting for a response that can no longer come.
            if (ngtcp2.ngtcp2_conn_in_draining_period2(self.quic_conn.conn) != 0) {
                return error.ConnectionClosed;
            }

            // Pump outgoing data: nghttp3 → ngtcp2 → UDP
            pumpWrites(self);

            // Flush QUIC packets to UDP
            quic.flushPackets(&self.quic_conn) catch {};

            // Read incoming UDP packets — feeds QUIC engine which triggers
            // recv_stream_data → nghttp3 readStream → ctx populated
            quic.readPacket(&self.quic_conn) catch {};
            quic.handleExpiryIfDue(&self.quic_conn);

            // Timeout after 30 seconds
            if (nowNanos() - start > 30 * std.time.ns_per_s) return error.Timeout;

            sleepNs(1 * std.time.ns_per_ms);
        }

        // 5. Return body (copy to heap since ctx is stack-local)
        const result = try self.allocator.dupe(u8, ctx.body.items);
        return result;
    }
};

/// Bridge: ngtcp2 recv_stream_data callback → nghttp3 conn_read_stream2.
/// Called by quic.zig's recvStreamDataCb whenever stream data arrives.
fn onQuicStreamData(h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool) void {
    const conn: *nghttp3.nghttp3_conn = @alignCast(@ptrCast(h3_conn));
    _ = nghttp3.nghttp3_conn_read_stream2(conn, stream_id, data.ptr, data.len, @intFromBool(fin), 0);
}

/// Pump pending HTTP/3 write data (headers, body, FIN) into the QUIC connection.
fn pumpWrites(self: *Client) void {
    while (true) {
        var write_stream_id: i64 = -1;
        var write_fin: c_int = 0;
        var vec: nghttp3.nghttp3_vec = undefined;
        const nvec = nghttp3.nghttp3_conn_writev_stream(self.h3_session.conn, &write_stream_id, &write_fin, &vec, 1);
        if (nvec < 0 or write_stream_id == -1) break;

        const data: []const u8 = if (nvec > 0) vec.base[0..vec.len] else &.{};
        const written = quic.writeStreamPacket(&self.quic_conn, write_stream_id, write_fin != 0, data) catch break;
        if (nvec > 0) {
            _ = nghttp3.nghttp3_conn_add_write_offset(self.h3_session.conn, write_stream_id, written);
        } else if (write_fin != 0) {
            // Zero-length fin — just acknowledge
            _ = nghttp3.nghttp3_conn_add_write_offset(self.h3_session.conn, write_stream_id, 0);
        }
    }
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
        quic.readPacket(&client.quic_conn) catch {};
        sleepNs(10 * std.time.ns_per_ms);
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
