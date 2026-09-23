const std = @import("std");
const quic = @import("quic.zig");
const http3 = @import("http3.zig");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");
const posix = std.posix;

const h1 = @import("../Request.zig");

/// The request method, from the same enum the HTTP/1.1 and HTTP/2 sides use.
pub const Method = h1.Method;
/// Header fields of a request or response.
pub const Headers = @import("../Headers.zig");
/// Response status, from the same enum the other protocols use.
pub const StatusCode = @import("../Response.zig").StatusCode;

/// A received HTTP/3 request, as the handler sees it: `:method` and `:path`
/// arrive folded into `method` and `path`, and every other field in `headers`,
/// in the order the client sent it. Pseudo-headers other than those two are
/// dropped. All of it stays valid until the handler returns.
pub const Request = struct {
    method: Method,
    path: []const u8,
    headers: Headers = .{},
    /// The request body, empty for a request that has none.
    body: []const u8 = "",
};

/// What a handler answers with. `body` is copied by the server before it is
/// sent, so it may be a literal or a buffer the handler owns. A handler that
/// would rather produce the body as it goes streams it instead, with
/// `body_reader`.
pub const Response = struct {
    status: StatusCode = .ok,
    content_type: []const u8 = "text/plain",
    body: []const u8 = "",
    /// Streams the body instead of handing it over: the server calls this when
    /// the stream has room for more, and it fills `buf` and returns how many
    /// bytes were written — 0 for the end of the body. Together with
    /// `body_context` this replaces `body`, which is then ignored, and no
    /// `content-length` goes out: RFC 9114 Section 4.1 lets an HTTP/3 response
    /// leave it out, and the length is not known before the body has been
    /// produced. `status`, `content_type` and `headers` are unaffected.
    ///
    /// Called from the server's event loop, so it holds up every connection
    /// that loop is serving while it runs: a reader that has to wait for the
    /// next piece of a long-lived stream has to return from one call with the
    /// bytes it has and produce the rest on the next. Returning an error fails
    /// the request's stream, which closes its connection.
    body_reader: ?*const fn (context: ?*anyopaque, buf: []u8) anyerror!usize = null,
    /// Passed to `body_reader`.
    body_context: ?*anyopaque = null,
    /// Header fields to send after Content-Type, e.g. `Set-Cookie` or
    /// `Location`. Names have to be lowercase (RFC 9114 Section 4.2).
    /// `content-length` is set from the body, and a field that repeats it is
    /// dropped rather than sent twice; a streamed body has no length to set,
    /// so a field that would carry one is dropped.
    headers: []const Header = &.{},
};

/// One header field of a response. The name has to be lowercase.
pub const Header = http3.HeaderField;

/// Handler called for each completed HTTP/3 request. The returned body is
/// copied, so the handler keeps ownership of everything it hands over; a
/// `body_reader` is called later and belongs to the handler the same way.
pub const Handler = *const fn (allocator: std.mem.Allocator, request: *const Request) Response;

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
    /// Largest request body accepted; a larger one is answered with 413. The
    /// body is buffered in full before the handler runs, so this is also what
    /// bounds the memory one request can hold.
    max_request_body_bytes: usize = http3.Session.default_max_request_body_bytes,
};

pub const Server = struct {
    listener: quic.Listener,
    allocator: std.mem.Allocator,
    handler: Handler,
    options: Options,
    /// Set by `stop` and read by the run loop, so the server can be taken down
    /// from another thread.
    stopping: std.atomic.Value(bool) = .init(false),
    /// How many connections are in their closing period: told the connection is
    /// over, still answering every packet the peer sends with the same
    /// CONNECTION_CLOSE, and kept until the period is out. Derived from the
    /// routing table, but counted separately because that table is only safe to
    /// read from the server's own thread — this says the same thing from any
    /// thread, so a test can wait for the state rather than for the clock.
    closing_connections: std.atomic.Value(usize) = .init(0),

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

    /// Asks `run` to come back, so a server can be taken down from another
    /// thread. The loop notices between turns — it is waiting in `poll` for up
    /// to a second when nothing is happening — and then closes what it was
    /// serving. This is a stop, not a graceful shutdown: requests in flight are
    /// cut off rather than drained, and the peers get a CONNECTION_CLOSE rather
    /// than a GOAWAY.
    pub fn stop(self: *Server) void {
        self.stopping.store(true, .release);
    }

    pub fn run(self: *Server) !void {
        var buf: [65536]u8 = undefined;
        std.debug.print("H3 server listening on UDP\n", .{});

        var last_reap = nowNanos();
        while (!self.stopping.load(.acquire)) {
            // Wait for a datagram, for the nearest QUIC timer, or for the reap
            // interval — whichever comes first. Sleeping a fixed amount here is
            // what held the whole server to one datagram per turn; a connection
            // knows when it next has something to do (`ngtcp2_conn_get_expiry`),
            // and until then only the socket can change anything.
            if (quic.pollReadable(self.listener.socket, self.waitNs())) {
                // Take everything that is already queued, not one datagram.
                self.drainSocket(&buf);
            }

            self.serviceConnections();

            if (nowNanos() -% last_reap >= reap_interval_ns) {
                self.reapConnections();
                last_reap = nowNanos();
            }
        }

        // Nothing that arrived after the loop may be answered from state the
        // caller is about to free: this returns with the connections gone.
        self.closeAllConnections();
    }

    /// Nanoseconds until the event loop has to run again: the nearest of the
    /// connections' QUIC timers, and never longer than the reap interval, so an
    /// idle server still runs its idle-connection bookkeeping.
    fn waitNs(self: *Server) u64 {
        var wait: u64 = reap_interval_ns;
        const now = nowNanos();
        var it = self.listener.connections.iterator();
        while (it.next()) |entry| {
            const expiry = quic.getExpiry(entry.value_ptr.*) orelse continue;
            wait = @min(wait, expiry -| now);
        }
        return wait;
    }

    /// Feeds every datagram already waiting on the listener socket to the
    /// connection that owns it.
    fn drainSocket(self: *Server, buf: []u8) void {
        for (0..quic.max_datagrams_per_drain) |_| {
            var peer_addr: posix.sockaddr.in = undefined;
            var peer_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const n = std.c.recvfrom(self.listener.socket, buf.ptr, buf.len, std.c.MSG.DONTWAIT, @ptrCast(&peer_addr), &peer_addr_len);
            if (n <= 0) return;
            self.handleDatagram(buf, @intCast(n), &peer_addr);
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
        const ret = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, &path_storage.path, &pkt, data.ptr, data.len, nowNanos());
        if (ret != 0) {
            // May free `conn`, so nothing touches it afterwards.
            self.handleReadError(conn, ret);
            return;
        }
        if (h3Conn(conn)) |h3| h3.last_activity_ns = nowNanos();
    }

    /// Acts on what `ngtcp2_conn_read_pkt` reported, as ngtcp2.h defines each
    /// code. Two of them mean the connection state has to go; the rest mean the
    /// peer is told why the connection ends.
    fn handleReadError(self: *Server, conn: *quic.Connection, ret: c_int) void {
        switch (quic.classifyReadError(conn.conn, ret)) {
            // ngtcp2.h: "Server application must drop the connection silently
            // (without sending any CONNECTION_CLOSE frame), and discard
            // connection state." Retry means the same here: ngtcp2 asks for
            // address validation, which this endpoint does not do, so there is
            // no state worth keeping while a client would wait for a Retry.
            error.ConnectionDropped, error.RetryRequired => self.dropConnection(conn),
            // The peer closed, or this endpoint already sent its close: the
            // connection leaves once the closing period is over.
            error.ConnectionClosed => {},
            error.TlsError => {
                quic.sendConnectionClose(conn, .{ .tls_alert = quic.last_tls_failure.alert }, "tls error");
                self.dropConnection(conn);
            },
            else => {
                quic.sendConnectionClose(conn, .{ .ngtcp2_error = ret }, "quic connection error");
                self.dropConnection(conn);
            },
        }
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
        quic.fillRandom(server_scid.data[0..quic.cid_length]);

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
        // Without this nghttp3 never learns that a response it sent was
        // acknowledged, and so never reclaims it.
        callbacks.acked_stream_data_offset = quic.ackedStreamDataOffsetCb;
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

        var h3_alloc: ?*H3Conn = try newH3Conn(self.allocator, params.initial_max_streams_bidi, self.options.max_request_body_bytes);
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
        const init_ret = ngtcp2.ngtcp2_conn_read_pkt(conn_ptr.?, &path_storage.?.path, &pkt, init_data.ptr, init_data.len, nowNanos());
        if (init_ret != 0) {
            // The Initial that would have created this connection already
            // failed. ngtcp2.h says what that means — most often that the state
            // itself has to be discarded, which is what returning an error does
            // here: the errdefers above free the connection and it is never
            // registered, so it cannot linger in the routing table.
            return quic.classifyReadError(conn_ptr.?, init_ret);
        }

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
            quic.sendConnectionClose(conn, .{ .application = http3.H3_NO_ERROR }, "server out of resources");
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
            // A failure here means nghttp3 or ngtcp2 has had it with this
            // connection (nghttp3.h: after a connection error nothing but
            // deleting the HTTP/3 connection may touch it), so it is closed
            // instead of being offered to either of them again.
            pumpServerWrites(h3.session, conn) catch {
                self.startClosing(conn, h3);
                continue;
            };
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
    /// with the same CONNECTION_CLOSE until the period is over. A second call
    /// leaves both the close that already went out and the deadline it set where
    /// they are, which is what keeps `closing_connections` counting once per
    /// connection.
    fn startClosing(self: *Server, conn: *quic.Connection, h3: *H3Conn) void {
        if (h3.closing_until_ns != null) return;
        quic.sendConnectionClose(conn, .{ .application = http3.H3_NO_ERROR }, "server closing connection");
        // ngtcp2 arms a 3xPTO timer for the closing period; fall back to a fixed
        // period if it has none.
        h3.closing_until_ns = quic.getExpiry(conn) orelse (nowNanos() + self.options.closing_period_ns);
        _ = self.closing_connections.fetchAdd(1, .monotonic);
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

        if (h3Conn(conn)) |h3| {
            // Every connection leaves through here — reaped, dropped by an
            // error, or taken down by `deinit`/`stop` — so this is where a
            // closing connection stops being one.
            if (h3.closing_until_ns != null) _ = self.closing_connections.fetchSub(1, .monotonic);
            h3.deinit();
        }
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
            quic.sendConnectionClose(conn, .{ .application = http3.H3_NO_ERROR }, "server shutting down");
            self.dropConnection(conn);
        }
    }
};

/// Creates the H3 state for a new connection.
fn newH3Conn(allocator: std.mem.Allocator, max_client_streams_bidi: u64, max_request_body_bytes: usize) !*H3Conn {
    const h3 = try allocator.create(H3Conn);
    errdefer allocator.destroy(h3);

    h3.* = .{
        .allocator = allocator,
        .session = try http3.Session.initServer(allocator, max_client_streams_bidi, max_request_body_bytes),
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

/// Runs the handler for every complete request and queues its response.
fn serveRequests(self: *Server, session: *http3.Session) void {
    for (session.requests.items) |req| {
        if (!req.complete or req.responded) continue;

        const answer: Response = if (req.body_too_large)
            .{
                .status = .request_entity_too_large,
                .body = "Request Entity Too Large",
            }
        else
            callHandler(self, req);

        // A streamed body is pulled from the handler's reader while it is sent,
        // one chunk at a time, so there is nothing to copy and nothing to keep
        // alive here.
        if (answer.body_reader) |reader| {
            session.submitStreamingResponse(req, @backingInt(answer.status), answer.content_type, answer.headers, reader, answer.body_context) catch {
                req.responded = true;
                continue;
            };
            continue;
        }

        // The handler keeps what it handed over, and the body has to outlive the
        // response, so this is the one copy made on the response path.
        const body = self.allocator.dupe(u8, answer.body) catch {
            req.responded = true; // nothing to send; don't retry it forever
            continue;
        };
        session.submitResponse(req, @backingInt(answer.status), answer.content_type, answer.headers, body) catch {
            self.allocator.free(body);
            req.responded = true;
            continue;
        };
    }
}

/// Hands one complete request to the handler, as a `Request` it can read.
fn callHandler(self: *Server, req: *http3.ServerRequest) Response {
    const method = Method.fromString(req.method) orelse
        return .{ .status = .not_implemented, .body = "Not Implemented" };

    var request: Request = .{
        .method = method,
        .path = req.path,
        .body = req.body.items,
    };
    for (req.headers.items) |field| {
        // A handler reads headers with `request.headers.get(...)`; a field the
        // table cannot hold is dropped rather than failing the request.
        request.headers.append(field.name, field.value) catch break;
    }
    return self.handler(self.allocator, &request);
}

/// Bridge: ngtcp2 recv_stream_data callback → nghttp3 conn_read_stream2.
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
pub fn onQuicServerStreamData(h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool, ts: u64) quic.StreamRead {
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
fn pumpServerWrites(session: *http3.Session, quic_conn: *quic.Connection) quic.Error!void {
    // One timestamp for the whole round: every call that adds to the same
    // packet has to pass the timestamp the packet was started with.
    const ts = nowNanos();
    var wrote = false;
    while (true) {
        const sent = try quic.writePackedPacket(quic_conn, session.conn, ts);
        if (sent == 0) break;
        wrote = true;
    }
    // ngtcp2.h: the application must tell ngtcp2 when packets carrying stream
    // data went out, which is what its send pacing is measured from.
    if (wrote) ngtcp2.ngtcp2_conn_update_pkt_tx_time(quic_conn.conn, ts);
}

fn nowNanos() u64 {
    var ts: posix.timespec = undefined;
    _ = std.c.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "H3 Server init/deinit" {
    var server = try Server.init(std.testing.allocator, 14433, struct {
        fn h(_: std.mem.Allocator, _: *const Request) Response {
            return .{ .body = "OK" };
        }
    }.h, .{});
    defer server.deinit();
}

test "H3: an unknown method is answered with 501" {
    var server = try Server.init(std.testing.allocator, 14434, struct {
        fn h(_: std.mem.Allocator, _: *const Request) Response {
            return .{ .body = "OK" };
        }
    }.h, .{});
    defer server.deinit();

    const req = try http3.ServerRequest.init(std.testing.allocator, 0, 1024);
    defer req.deinit();
    req.method = "BREW";
    const answer = callHandler(&server, req);
    try std.testing.expectEqual(StatusCode.not_implemented, answer.status);
}

test "H3: the handler sees the method, path, headers and body" {
    var server = try Server.init(std.testing.allocator, 14435, struct {
        fn h(_: std.mem.Allocator, request: *const Request) Response {
            const seen = request.headers.get("x-test").?;
            if (request.method != .POST) return .{ .status = .bad_request, .body = "method" };
            if (!std.mem.eql(u8, request.path, "/submit")) return .{ .status = .bad_request, .body = "path" };
            if (!std.mem.eql(u8, request.body, "payload")) return .{ .status = .bad_request, .body = "body" };
            return .{ .status = .created, .content_type = "text/x-seen", .body = seen };
        }
    }.h, .{});
    defer server.deinit();

    const req = try http3.ServerRequest.init(std.testing.allocator, 0, 1024);
    defer req.deinit();
    const a = req.arena.allocator();
    req.method = "POST";
    req.path = "/submit";
    try req.headers.append(a, .{ .name = "x-test", .value = "seen-value" });
    try req.body.appendSlice(a, "payload");

    const answer = callHandler(&server, req);
    try std.testing.expectEqual(StatusCode.created, answer.status);
    try std.testing.expectEqualStrings("text/x-seen", answer.content_type);
    try std.testing.expectEqualStrings("seen-value", answer.body);
}

test "H3: TLS cert loading" {
    const cert_pem = @embedFile("test_cert.pem");
    const key_pem = @embedFile("test_key.pem");
    try quic.setServerCert(cert_pem, key_pem);
}

test {
    _ = Server;
}
