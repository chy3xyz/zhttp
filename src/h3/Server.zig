const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");
const posix = std.posix;

/// Handler signature matching httpz convention: returns response body as bytes.
pub const Handler = *const fn (allocator: std.mem.Allocator, request: []const u8) []const u8;

pub const Server = struct {
    listener: quic.Listener,
    allocator: std.mem.Allocator,
    handler: Handler,

    pub fn init(allocator: std.mem.Allocator, port: u16, handler: Handler) !Server {
        return .{
            .listener = try quic.Listener.init(allocator, port),
            .allocator = allocator,
            .handler = handler,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit();
    }

    pub fn run(self: *Server) !void {
        var buf: [65536]u8 = undefined;
        std.debug.print("H3 server listening on UDP\n", .{});

        while (true) {
            const n = std.c.recvfrom(self.listener.socket, &buf, buf.len, 0, null, null);
            if (n < 0) {
                sleepNs(10 * std.time.ns_per_ms);
                continue;
            }
            if (n < 6) continue;
            if (buf[0] & 0x80 == 0) continue;

            const dcid_len: usize = @intCast(buf[5]);
            if (6 + dcid_len > @as(usize, @intCast(n))) continue;
            var dcid: [18]u8 = @splat(0);
            @memcpy(dcid[0..@min(dcid_len, @as(usize, 18))], buf[6..][0..@min(dcid_len, @as(usize, 18))]);

            if (self.listener.connections.get(dcid)) |conn| {
                const data = buf[0..@intCast(n)];
                const pkt = ngtcp2.ngtcp2_pkt_info{};
                var path: ngtcp2.ngtcp2_path = .{ .local = .{ .addr = undefined, .addrlen = 0 }, .remote = .{ .addr = undefined, .addrlen = 0 } };
                _ = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, &path, &pkt, data.ptr, data.len, nowNanos());
                _ = quic.flushPackets(conn) catch {};
                continue;
            }

            try self.handleNewConnection(&buf, @intCast(n), dcid, dcid_len);
        }
    }

    fn handleNewConnection(self: *Server, buf: []u8, n: usize, dcid: [18]u8, dcid_len: usize) !void {
        const scid_ofs = 6 + dcid_len;
        if (scid_ofs + 1 > n) return;

        var server_scid: ngtcp2.ngtcp2_cid = undefined;
        server_scid.datalen = 18;
        std.c.arc4random_buf(&server_scid.data, 18);

        var client_dcid: ngtcp2.ngtcp2_cid = undefined;
        client_dcid.datalen = @intCast(@min(dcid_len, @as(usize, 18)));
        @memcpy(client_dcid.data[0..client_dcid.datalen], dcid[0..client_dcid.datalen]);

        var callbacks: ngtcp2.ngtcp2_callbacks = std.mem.zeroes(ngtcp2.ngtcp2_callbacks);
        callbacks.recv_client_initial = quic.serverRecvClientInitialCb;
        callbacks.recv_crypto_data = ngtcp2.ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2.ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2.ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2.ngtcp2_crypto_hp_mask_cb;
        callbacks.update_key = ngtcp2.ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2.ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2.ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.get_path_challenge_data = ngtcp2.ngtcp2_crypto_get_path_challenge_data_cb;
        callbacks.version_negotiation = ngtcp2.ngtcp2_crypto_version_negotiation_cb;
        callbacks.get_new_connection_id = quic.getNewConnIdCb;
        callbacks.remove_connection_id = quic.removeConnIdCb;
        callbacks.path_validation = quic.pathValidationCb;

        var settings: ngtcp2.ngtcp2_settings = undefined;
        ngtcp2.ngtcp2_settings_default(&settings);
        if (quic.qlog_fd >= 0) {
            settings.qlog_write = quic.qlogWriteCb;
        }

        var params: ngtcp2.ngtcp2_transport_params = undefined;
        ngtcp2.ngtcp2_transport_params_default(&params);
        params.initial_max_streams_uni = 3;
        params.initial_max_streams_bidi = 100;
        params.initial_max_data = 1048576;
        params.initial_max_stream_data_bidi_local = 1048576;
        params.initial_max_stream_data_bidi_remote = 1048576;

        const path: ngtcp2.ngtcp2_path = .{
            .local = .{ .addr = undefined, .addrlen = 0 },
            .remote = .{ .addr = undefined, .addrlen = 0 },
        };

        var conn_ptr: ?*ngtcp2.ngtcp2_conn = null;
        const mem: ?*const ngtcp2.struct_ngtcp2_mem = null;
        // Create H3 server session and serve
        var h3_session = http3.Session.initServer(self.allocator) catch return;
        defer h3_session.deinit();

        const ctx_ptr = try self.allocator.create(quic.StreamDataCtx);
        ctx_ptr.* = quic.StreamDataCtx{
            .h3_conn = @ptrCast(h3_session.conn),
            .recv_stream_data = onQuicServerStreamData,
        };
        errdefer self.allocator.destroy(ctx_ptr);

        callbacks.recv_stream_data = quic.recvStreamDataCb;

        const ret = ngtcp2.ngtcp2_conn_server_new(&conn_ptr, &client_dcid, &server_scid, &path, ngtcp2.NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, mem, @as(?*anyopaque, @ptrCast(ctx_ptr)));
        if (ret != 0) return error.QuicError;
        errdefer ngtcp2.ngtcp2_conn_del(conn_ptr.?);

        const pkt = ngtcp2.ngtcp2_pkt_info{};
        const init_data = buf[0..n];
        var init_path: ngtcp2.ngtcp2_path = .{ .local = .{ .addr = undefined, .addrlen = 0 }, .remote = .{ .addr = undefined, .addrlen = 0 } };
        _ = ngtcp2.ngtcp2_conn_read_pkt(conn_ptr.?, &init_path, &pkt, init_data.ptr, init_data.len, nowNanos());

        const conn = try self.allocator.create(quic.Connection);
        conn.* = quic.Connection{
            .conn = conn_ptr.?,
            .socket = self.listener.socket,
        };

        var scid_key: [18]u8 = undefined;
        @memcpy(&scid_key, server_scid.data[0..18]);
        try self.listener.connections.put(scid_key, conn);
        _ = try quic.flushPackets(conn);

        // Drive handshake
        for (0..20) |_| {
            quic.readPacket(conn) catch {};
            _ = quic.flushPackets(conn) catch {};
            sleepNs(10 * std.time.ns_per_ms);
        }

        conn.stream_ctx_alloc = ctx_ptr;

        // Poll for H3 data and dispatch requests
        const start = nowNanos();
        while (nowNanos() - start < 10 * std.time.ns_per_s) {
            quic.readPacket(conn) catch {};
            pumpServerWrites(&h3_session, conn);
            _ = quic.flushPackets(conn) catch {};
            sleepNs(1 * std.time.ns_per_ms);
        }
    }
};

fn onQuicServerStreamData(h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool) void {
    const conn: *nghttp3.nghttp3_conn = @alignCast(@ptrCast(h3_conn));
    _ = nghttp3.nghttp3_conn_read_stream2(conn, stream_id, data.ptr, data.len, @intFromBool(fin), 0);
}

fn pumpServerWrites(session: *http3.Session, quic_conn: *quic.Connection) void {
    while (true) {
        var write_stream_id: i64 = -1;
        var write_fin: c_int = 0;
        var vec: nghttp3.nghttp3_vec = undefined;
        const nvec = nghttp3.nghttp3_conn_writev_stream(session.conn, &write_stream_id, &write_fin, &vec, 1);
        if (nvec < 0) break;
        if (write_stream_id == -1) break;
        if (nvec > 0) {
            var pi: ngtcp2.ngtcp2_pkt_info = undefined;
            var dest: ngtcp2.ngtcp2_path = .{ .local = .{}, .remote = .{} };
            const nwritten = ngtcp2.ngtcp2_conn_write_stream_versioned(
                quic_conn.conn,
                &dest,
                ngtcp2.NGTCP2_PKT_INFO_VERSION,
                &pi,
                &quic_conn.buf,
                quic_conn.buf.len,
                null,
                0,
                write_stream_id,
                vec.base,
                vec.len,
                nowNanos(),
            );
            _ = nghttp3.nghttp3_conn_add_write_offset(session.conn, write_stream_id, if (nwritten > 0) @as(usize, @intCast(nwritten)) else 0);
        } else if (write_fin != 0) {
            _ = nghttp3.nghttp3_conn_add_write_offset(session.conn, write_stream_id, 0);
        }
    }
}

fn sleepNs(ns: u64) void {
    const req = posix.timespec{
        .sec = @intCast(ns / 1_000_000_000),
        .nsec = @intCast(ns % 1_000_000_000),
    };
    _ = std.c.nanosleep(@ptrCast(&req), null);
}

fn nowNanos() u64 {
    var ts: posix.timespec = undefined;
    _ = std.c.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "H3 Server init/deinit" {
    var server = try Server.init(std.testing.allocator, 14433, struct {
        fn h(allocator: std.mem.Allocator, _: []const u8) []const u8 {
            return allocator.dupe(u8, "OK") catch "OK";
        }
    }.h);
    defer server.deinit();
}

test "H3: TLS cert loading" {
    const cert_pem = @embedFile("test_cert.pem");
    const key_pem = @embedFile("test_key.pem");
    try quic.setServerCert(cert_pem, key_pem);
}

test {
    _ = Server;
}
