const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");
const posix = std.posix;

/// Handler called for each completed HTTP/3 request. `request` is the request
/// path, and the returned body is owned by the server, which frees it once the
/// response has been sent — allocate it with |allocator|.
pub const Handler = *const fn (allocator: std.mem.Allocator, request: []const u8) []const u8;

/// Server state for one accepted connection: the HTTP/3 session on top of it,
/// the endpoint's own H3 streams, and when it last heard from the client.
const H3Conn = struct {
    allocator: std.mem.Allocator,
    session: *http3.Session,
    ctrl_stream: ?i64 = null,
    qpack_enc_stream: ?i64 = null,
    qpack_dec_stream: ?i64 = null,
    h3_streams_bound: bool = false,
    last_activity_ns: u64,
    /// Set once this connection started closing: it stays around until then,
    /// answering the peer with the same CONNECTION_CLOSE.
    closing_until_ns: ?u64 = null,

    fn deinit(self: *H3Conn) void {
        self.session.deinit();
        self.allocator.destroy(self);
    }
};

pub const Options = struct {
    /// Connections quiet for this long start closing; ngtcp2's own idle timeout
    /// is disabled in the transport parameters.
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// How long a closing connection sticks around to answer the peer, used when
    /// ngtcp2 does not provide a closing deadline of its own.
    closing_period_ns: u64 = 3 * std.time.ns_per_s,
};

pub const Server = struct {
    listener: quic.Listener,
    allocator: std.mem.Allocator,
    handler: Handler,
    options: Options,

    const reap_interval_ns = 1 * std.time.ns_per_s;

    pub fn init(allocator: std.mem.Allocator, port: u16, handler: Handler, options: Options) !Server {
        return .{
            .listener = try quic.Listener.init(allocator, port),
            .allocator = allocator,
            .handler = handler,
            .options = options,
        };
    }

    pub fn deinit(self: *Server) void {
        self.closeAllConnections();
        self.listener.deinit();
    }

    pub fn run(self: *Server) !void {
        var buf: [65536]u8 = undefined;
        std.debug.print("H3 server listening on UDP\n", .{});

        var last_reap = nowNanos();
        while (true) {
            // One datagram per turn, read without blocking: an idle server sleeps
            // instead of waiting on the socket.
            var peer_addr: posix.sockaddr.in = undefined;
            var peer_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const n = std.c.recvfrom(self.listener.socket, &buf, buf.len, std.c.MSG.DONTWAIT, @ptrCast(&peer_addr), &peer_addr_len);
            if (n > 0) {
                self.handleDatagram(&buf, @intCast(n), &peer_addr);
            } else {
                sleepMs(1);
            }

            self.serviceConnections();

            if (nowNanos() -% last_reap >= reap_interval_ns) {
                self.reapConnections();
                last_reap = nowNanos();
            }
        }
    }

    /// Routes a datagram to the connection that owns its destination CID, or
    /// accepts it as a new connection.
    fn handleDatagram(self: *Server, buf: []u8, n: usize, peer_addr: *const posix.sockaddr.in) void {
        const dcid = quic.destinationCid(buf, n) orelse return;
        if (self.listener.connections.get(dcid)) |conn| {
            self.readDatagram(conn, buf[0..n], peer_addr);
            return;
        }
        self.acceptConnection(buf, n, dcid, peer_addr) catch {};
    }

    fn readDatagram(self: *Server, conn: *quic.Connection, data: []const u8, peer_addr: *const posix.sockaddr.in) void {
        if (h3Conn(conn)) |h3| {
            if (h3.closing_until_ns != null) {
                // RFC 9000: an endpoint in the closing period answers every
                // packet it receives with its CONNECTION_CLOSE.
                quic.resendConnectionClose(conn);
                return;
            }
        }
        var path_storage: ngtcp2.ngtcp2_path_storage = undefined;
        quic.initPath(&path_storage, &self.listener.local_addr, peer_addr);
        const pkt = ngtcp2.ngtcp2_pkt_info{};
        _ = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, &path_storage.path, &pkt, data.ptr, data.len, nowNanos());
        if (h3Conn(conn)) |h3| h3.last_activity_ns = nowNanos();
    }

    fn h3Conn(conn: *quic.Connection) ?*H3Conn {
        return @ptrCast(@alignCast(conn.app_state));
    }

    fn acceptConnection(
        self: *Server,
        buf: []u8,
        n: usize,
        dcid: [quic.cid_length]u8,
        peer_addr: *const posix.sockaddr.in,
    ) !void {
        const dcid_len: usize = buf[5];
        const scid_ofs = 6 + dcid_len;
        if (scid_ofs + 1 > n) return;
        const scid_len: usize = buf[scid_ofs];
        if (scid_ofs + 1 + scid_len > n) return;

        var server_scid: ngtcp2.ngtcp2_cid = undefined;
        server_scid.datalen = quic.cid_length;
        std.c.arc4random_buf(&server_scid.data, quic.cid_length);

        // The server sends to the client's source connection ID: for the server
        // `dcid` is "the Connection ID that appears in client Initial packet as
        // Source Connection ID" (ngtcp2.h, ngtcp2_conn_server_new).
        var client_scid: ngtcp2.ngtcp2_cid = undefined;
        client_scid.datalen = @intCast(@min(scid_len, @as(usize, quic.cid_length)));
        @memcpy(client_scid.data[0..client_scid.datalen], buf[scid_ofs + 1 ..][0..client_scid.datalen]);

        // The client's original destination connection ID goes back to it in the
        // server's transport parameters (RFC 9000).
        var original_dcid: ngtcp2.ngtcp2_cid = undefined;
        original_dcid.datalen = @intCast(@min(dcid_len, @as(usize, quic.cid_length)));
        @memcpy(original_dcid.data[0..original_dcid.datalen], dcid[0..original_dcid.datalen]);

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
        callbacks.extend_max_stream_data = quic.extendMaxStreamDataCb;
        // The stream limit in the transport parameters below is what the client
        // spends one stream per request from, and ngtcp2 never raises it on its
        // own, so a closed request stream has to hand its place back here.
        callbacks.stream_close = quic.streamCloseCb;
        callbacks.extend_max_remote_streams_bidi = quic.extendMaxRemoteStreamsBidiCb;
        callbacks.rand = quic.randCb;

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
        // The HTTP/3 control and QPACK streams are unidirectional, and a zero
        // limit here blocks every byte the client sends on them.
        params.initial_max_stream_data_uni = 1048576;
        // RFC 9000: the server has to echo back the DCID of the client's first
        // Initial packet ("Server must specify this field" — ngtcp2.h).
        params.original_dcid = original_dcid;
        params.original_dcid_present = 1;

        // ngtcp2 reads the connection's addresses back out of this storage every
        // time it writes a packet, so it has to outlive the connection.
        var path_storage: ?*ngtcp2.ngtcp2_path_storage = try std.heap.page_allocator.create(ngtcp2.ngtcp2_path_storage);
        errdefer if (path_storage) |ps| std.heap.page_allocator.destroy(ps);
        quic.initPath(path_storage.?, &self.listener.local_addr, peer_addr);

        var h3_alloc: ?*H3Conn = try newH3Conn(self.allocator, params.initial_max_streams_bidi);
        errdefer if (h3_alloc) |h| h.deinit();
        const h3 = h3_alloc.?;

        // `Connection.deinit` frees this with the page allocator, so it has to
        // be allocated with it too.
        var ctx_ptr: ?*quic.StreamDataCtx = try std.heap.page_allocator.create(quic.StreamDataCtx);
        errdefer if (ctx_ptr) |p| std.heap.page_allocator.destroy(p);
        ctx_ptr.?.* = quic.StreamDataCtx{
            .h3_conn = @ptrCast(h3.session.conn),
            .recv_stream_data = onQuicServerStreamData,
        };

        // recv_client_initial runs inside ngtcp2_conn_server_new and attaches
        // this session to the connection, so it has to exist first.
        var tls_session: ?*quic.TlsSession = try quic.serverTlsSession();
        errdefer if (tls_session) |s| s.deinit();
        ctx_ptr.?.tls_session = tls_session.?;

        callbacks.recv_stream_data = quic.recvStreamDataCb;

        var conn_ptr: ?*ngtcp2.ngtcp2_conn = null;
        const mem: ?*const ngtcp2.struct_ngtcp2_mem = null;
        const ret = ngtcp2.ngtcp2_conn_server_new(&conn_ptr, &client_scid, &server_scid, &path_storage.?.path, ngtcp2.NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, mem, @as(?*anyopaque, @ptrCast(ctx_ptr.?)));
        if (ret != 0) return error.QuicError;
        errdefer if (conn_ptr) |c| ngtcp2.ngtcp2_conn_del(c);

        const pkt = ngtcp2.ngtcp2_pkt_info{};
        const init_data = buf[0..n];
        _ = ngtcp2.ngtcp2_conn_read_pkt(conn_ptr.?, &path_storage.?.path, &pkt, init_data.ptr, init_data.len, nowNanos());

        const conn = try self.allocator.create(quic.Connection);
        conn.* = quic.Connection{
            .conn = conn_ptr.?,
            .socket = self.listener.socket,
            .stream_ctx_alloc = ctx_ptr,
            .tls_session = tls_session,
            .path_alloc = path_storage,
            .owns_socket = false, // the listener owns it
            .app_state = @ptrCast(h3),
            .listener = &self.listener,
        };
        // The connection owns all of the above from here on, so the errdefers
        // above have to stop applying to them.
        conn_ptr = null;
        ctx_ptr = null;
        tls_session = null;
        path_storage = null;
        h3_alloc = null;

        // From now on the CID callbacks can route back to this connection.
        const ctx: *quic.StreamDataCtx = @ptrCast(@alignCast(conn.stream_ctx_alloc.?));
        ctx.connection = conn;

        self.listener.connections.put(quic.cidKey(server_scid), conn) catch |err| {
            quic.sendConnectionClose(conn, http3.H3_NO_ERROR, "server out of resources");
            self.dropConnection(conn);
            return err;
        };
        // Until it hears from us, the client addresses its Initial and Handshake
        // packets to the connection ID it chose itself, so that alias has to
        // route to this connection too.
        self.listener.connections.put(quic.cidKey(original_dcid), conn) catch {};

        _ = quic.flushPackets(conn) catch {};
    }

    /// Drives every connection: its own H3 streams, pending requests, queued
    /// writes and QUIC timers.
    fn serviceConnections(self: *Server) void {
        var it = self.listener.connections.iterator();
        while (it.next()) |entry| {
            const conn = entry.value_ptr.*;
            const h3 = h3Conn(conn) orelse continue;
            // A closing connection only answers packets now.
            if (h3.closing_until_ns != null) continue;
            // The endpoint's own control/QPACK streams can only be opened once
            // the handshake has given ngtcp2 the client's stream limits.
            if (!h3.h3_streams_bound and ngtcp2.ngtcp2_conn_get_handshake_completed(conn.conn) != 0) {
                setupH3Streams(h3, conn) catch {};
            }
            serveRequests(self, h3.session);
            pumpServerWrites(h3.session, conn);
            _ = quic.flushPackets(conn) catch {};
            quic.handleExpiryIfDue(conn);
        }
    }

    fn reapConnections(self: *Server) void {
        const now = nowNanos();
        var dead: std.ArrayList(*quic.Connection) = .empty;
        defer dead.deinit(self.allocator);

        var it = self.listener.connections.iterator();
        while (it.next()) |entry| {
            const conn = entry.value_ptr.*;
            // A connection owns several routing entries; only look at it once.
            var seen = false;
            for (dead.items) |c| {
                if (c == conn) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;

            // The peer closed: nothing left to say.
            if (ngtcp2.ngtcp2_conn_in_draining_period2(conn.conn) != 0) {
                dead.append(self.allocator, conn) catch break;
                continue;
            }

            if (h3Conn(conn)) |h3| {
                if (h3.closing_until_ns) |until| {
                    // Closing: drop it once the period is over.
                    if (now >= until) dead.append(self.allocator, conn) catch break;
                    continue;
                }
                if (now -% h3.last_activity_ns > self.options.idle_timeout_ns) {
                    self.startClosing(conn, h3);
                    continue;
                }
            }
        }
        for (dead.items) |conn| self.dropConnection(conn);
    }

    /// Enters the closing period: tell the peer, then keep answering its packets
    /// with the same CONNECTION_CLOSE until the period is over.
    fn startClosing(self: *Server, conn: *quic.Connection, h3: *H3Conn) void {
        quic.sendConnectionClose(conn, http3.H3_NO_ERROR, "server closing connection");
        // ngtcp2 arms a 3xPTO timer for the closing period; fall back to a fixed
        // period if it has none.
        h3.closing_until_ns = quic.getExpiry(conn) orelse (nowNanos() + self.options.closing_period_ns);
    }

    /// Frees a connection and drops every connection ID that routed to it.
    fn dropConnection(self: *Server, conn: *quic.Connection) void {
        var keys: std.ArrayList([quic.cid_length]u8) = .empty;
        defer keys.deinit(self.allocator);

        var it = self.listener.connections.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.* == conn) {
                keys.append(self.allocator, entry.key_ptr.*) catch break;
            }
        }
        for (keys.items) |key| _ = self.listener.connections.remove(key);

        if (h3Conn(conn)) |h3| h3.deinit();
        conn.deinit();
        self.allocator.destroy(conn);
    }

    fn closeAllConnections(self: *Server) void {
        var dead: std.ArrayList(*quic.Connection) = .empty;
        defer dead.deinit(self.allocator);

        var it = self.listener.connections.iterator();
        while (it.next()) |entry| {
            const conn = entry.value_ptr.*;
            // A connection owns several routing entries; only take it once.
            var seen = false;
            for (dead.items) |c| {
                if (c == conn) {
                    seen = true;
                    break;
                }
            }
            if (!seen) dead.append(self.allocator, conn) catch break;
        }
        for (dead.items) |conn| {
            // Shutting down: tell the peers and go, without a closing period.
            quic.sendConnectionClose(conn, http3.H3_NO_ERROR, "server shutting down");
            self.dropConnection(conn);
        }
    }
};

/// Creates the H3 state for a new connection.
fn newH3Conn(allocator: std.mem.Allocator, max_client_streams_bidi: u64) !*H3Conn {
    const h3 = try allocator.create(H3Conn);
    errdefer allocator.destroy(h3);

    h3.* = .{
        .allocator = allocator,
        .session = try http3.Session.initServer(allocator, max_client_streams_bidi),
        .last_activity_ns = nowNanos(),
    };
    return h3;
}

/// Opens this endpoint's control and QPACK streams and binds them to nghttp3.
/// HTTP/3 requires both endpoints to open these. Streams already opened by an
/// earlier partial attempt are reused, so a retry cannot exhaust the peer's
/// stream limit.
fn setupH3Streams(h3: *H3Conn, conn: *quic.Connection) !void {
    if (h3.ctrl_stream == null) h3.ctrl_stream = try openUniStream(conn);
    if (h3.qpack_enc_stream == null) h3.qpack_enc_stream = try openUniStream(conn);
    if (h3.qpack_dec_stream == null) h3.qpack_dec_stream = try openUniStream(conn);

    try h3.session.bindControlStream(h3.ctrl_stream.?);
    try h3.session.bindQpackStreams(h3.qpack_enc_stream.?, h3.qpack_dec_stream.?);
    h3.h3_streams_bound = true;
}

fn openUniStream(conn: *quic.Connection) !i64 {
    var stream_id: i64 = -1;
    if (ngtcp2.ngtcp2_conn_open_uni_stream(conn.conn, &stream_id, null) != 0) return error.QuicError;
    return stream_id;
}

/// Runs the handler for every complete request and queues its response. The
/// request bytes handed to the handler are the request path.
fn serveRequests(self: *Server, session: *http3.Session) void {
    for (session.requests.items) |req| {
        if (!req.complete or req.responded) continue;
        const body = self.handler(self.allocator, req.path.items);
        session.submitResponse(req, 200, "text/plain", body) catch {
            self.allocator.free(body);
            req.responded = true; // nothing to send; don't retry it forever
            continue;
        };
    }
}

/// Bridge: ngtcp2 recv_stream_data callback → nghttp3 conn_read_stream2.
/// Returns the flow control credit the QUIC connection gets back for this
/// stream. nghttp3 counts only the frame bytes it parsed and deliberately
/// leaves the payload of a DATA frame out of that count — those bytes reach the
/// application through `recv_data` — so the whole datagram is credited here: the
/// application consumed all of it.
fn onQuicServerStreamData(h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool) usize {
    const conn: *nghttp3.nghttp3_conn = @alignCast(@ptrCast(h3_conn));
    const consumed = nghttp3.nghttp3_conn_read_stream2(conn, stream_id, data.ptr, data.len, @intFromBool(fin), 0);
    // A negative return means nghttp3 hit a connection error and will not be
    // handed anything else.
    if (consumed < 0) return 0;
    return data.len;
}

/// Pump pending HTTP/3 write data (headers, body, FIN) into the QUIC connection.
/// One round ends as soon as it stops making progress; whatever is left is
/// offered again on the next event-loop turn.
fn pumpServerWrites(session: *http3.Session, quic_conn: *quic.Connection) void {
    while (true) {
        var write_stream_id: i64 = -1;
        var write_fin: c_int = 0;
        var vec: nghttp3.nghttp3_vec = undefined;
        const nvec = nghttp3.nghttp3_conn_writev_stream(session.conn, &write_stream_id, &write_fin, &vec, 1);
        if (nvec < 0 or write_stream_id == -1) break;

        const data: []const u8 = if (nvec > 0) vec.base[0..vec.len] else &.{};
        const result = quic.writeStreamPacket(quic_conn, write_stream_id, write_fin != 0, data) catch |err| switch (err) {
            // nghttp3 would otherwise offer the same stream forever, so it has
            // to be told why ngtcp2 did not take its data.
            error.StreamDataBlocked => {
                nghttp3.nghttp3_conn_block_stream(session.conn, write_stream_id);
                continue;
            },
            error.StreamShutWrite => {
                nghttp3.nghttp3_conn_shutdown_stream_write(session.conn, write_stream_id);
                continue;
            },
            else => break,
        };

        switch (result) {
            .blocked, .no_stream_frame => break,
            .wrote => |written| {
                if (nvec > 0) {
                    _ = nghttp3.nghttp3_conn_add_write_offset(session.conn, write_stream_id, written);
                    if (written == 0) break;
                } else if (write_fin != 0) {
                    // A packet carrying the zero length FIN went out, so the
                    // stream's write side is done.
                    _ = nghttp3.nghttp3_conn_add_write_offset(session.conn, write_stream_id, 0);
                }
            },
        }
    }
}

fn sleepMs(ms: u64) void {
    var req = posix.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    while (posix.errno(posix.system.nanosleep(&req, &req)) == .INTR) {}
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
    }.h, .{});
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
