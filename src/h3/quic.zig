const std = @import("std");
const ngtcp2 = @import("ngtcp2_c");
const ossl = @import("openssl_c");
const posix = std.posix;
const builtin = @import("builtin");
const c = std.c;

const NGTCP2_STREAM_DATA_FLAG_FIN = ngtcp2.NGTCP2_STREAM_DATA_FLAG_FIN;

const max_datagram_size = 65536;

/// An Initial/Handshake sized CONNECTION_CLOSE packet fits in one datagram.
const max_close_packet_len = 1500;

/// Thread-local QLog file descriptor. Set by enableQLog before creating connections.
pub threadlocal var qlog_fd: posix.fd_t = -1;

/// Sleep for a given number of nanoseconds.
fn sleepNs(ns: u64) void {
    var req = posix.timespec{
        .sec = @intCast(ns / 1_000_000_000),
        .nsec = @intCast(ns % 1_000_000_000),
    };
    while (posix.errno(posix.system.nanosleep(&req, &req)) == .INTR) {}
}

/// Server SSL_CTX for QUIC TLS handshake (set by setServerCert).
var server_ssl_ctx: ?*anyopaque = null;

/// Load a server certificate for QUIC TLS.
/// Must be called BEFORE creating server connections.
pub fn setServerCert(cert_pem: []const u8, key_pem: []const u8) !void {
    const ctx = ossl.SSL_CTX_new(ossl.TLS_server_method()) orelse return error.TlsError;
    errdefer ossl.SSL_CTX_free(ctx);

    // Load certificate
    const cert_bio = ossl.BIO_new_mem_buf(cert_pem.ptr, @intCast(cert_pem.len)) orelse return error.TlsError;
    defer _ = ossl.BIO_free(cert_bio);
    const x509 = ossl.PEM_read_bio_X509(cert_bio, null, null, null) orelse return error.TlsError;
    if (ossl.SSL_CTX_use_certificate(ctx, x509) != 1) { ossl.X509_free(x509); return error.TlsError; }
    ossl.X509_free(x509);

    // Load private key
    const key_bio = ossl.BIO_new_mem_buf(key_pem.ptr, @intCast(key_pem.len)) orelse return error.TlsError;
    defer _ = ossl.BIO_free(key_bio);
    const pkey = ossl.PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse return error.TlsError;
    defer ossl.EVP_PKEY_free(pkey);
    if (ossl.SSL_CTX_use_PrivateKey(ctx, pkey) != 1) return error.TlsError;
    if (ossl.SSL_CTX_check_private_key(ctx) != 1) return error.TlsError;

    // QUIC mandates ALPN, and HTTP/3 peers only ever offer "h3".
    ossl.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectH3Cb, null);

    server_ssl_ctx = @ptrCast(ctx);
}

/// ALPN selection for QUIC: HTTP/3 is the only protocol spoken here.
fn alpnSelectH3Cb(
    _: ?*ossl.SSL,
    out: [*c][*c]const u8,
    outlen: [*c]u8,
    in: [*c]const u8,
    inlen: c_uint,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const h3 = "\x02h3";
    const ret = ossl.SSL_select_next_proto(@constCast(@ptrCast(out)), outlen, h3, h3.len, in, inlen);
    if (ret == ossl.OPENSSL_NPN_NEGOTIATED) return ossl.SSL_TLSEXT_ERR_OK;
    return ossl.SSL_TLSEXT_ERR_ALERT_FATAL;
}

/// Custom server-side recv_client_initial that uses our SSL_CTX with cert.
/// ngtcp2 calls it while it is creating the connection, so this is where the
/// TLS session prepared by the caller is attached and where the Initial keys
/// get installed ("generate initial keys and IVs for both transmission and
/// reception" — ngtcp2_recv_client_initial).
pub fn serverRecvClientInitialCb(
    conn: ?*ngtcp2.ngtcp2_conn,
    dcid: [*c]const ngtcp2.ngtcp2_cid,
    user_data: ?*anyopaque,
) callconv(.c) c_int {
    const ctx: *StreamDataCtx = @ptrCast(@alignCast(user_data orelse return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE));
    const session = ctx.tls_session orelse return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE;
    const ngtcp2_conn_ptr = conn orelse return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE;
    session.attach(ngtcp2_conn_ptr);
    return ngtcp2.ngtcp2_crypto_recv_client_initial_cb(ngtcp2_conn_ptr, dcid, user_data);
}

/// Builds a network path from a local and a remote address. ngtcp2 copies both
/// into |ps|, so the arguments do not need to outlive the call.
pub fn initPath(
    ps: *ngtcp2.ngtcp2_path_storage,
    local: *const posix.sockaddr.in,
    remote: *const posix.sockaddr.in,
) void {
    ngtcp2.ngtcp2_path_storage_init(
        ps,
        @ptrCast(local),
        @sizeOf(posix.sockaddr.in),
        @ptrCast(remote),
        @sizeOf(posix.sockaddr.in),
        null,
    );
}

pub fn qlogWriteCb(
    user_data: ?*anyopaque,
    _: u32,
    data: ?*const anyopaque,
    datalen: usize,
) callconv(.c) void {
    _ = user_data;
    if (qlog_fd < 0) return;
    if (data) |d| {
        _ = std.c.write(qlog_fd, @as([*]const u8, @ptrCast(d)), datalen);
    }
}

/// Enable QLog debugging output to the given file path.
/// Must be called BEFORE creating QUIC connections.
pub fn enableQLog(path: []const u8) !void {
    qlog_fd = try posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
}

/// Disable QLog and close the file.
pub fn disableQLog() void {
    if (qlog_fd >= 0) {
        _ = std.c.close(qlog_fd);
        qlog_fd = -1;
    }
}

pub const Error = error{ QuicError, OutOfMemory, NoSpaceLeft, TlsError };

/// TLS settings for a QUIC client connection, mirroring `httpz.tls.config.Client`.
pub const ClientTls = struct {
    /// `.system` verifies the peer against the system CA store, `.empty` trusts
    /// whatever the peer presents.
    root_ca: RootCa = .system,
    /// Skip peer verification entirely. Local testing only.
    insecure_skip_verify: bool = false,
};

pub const RootCa = enum { empty, system };

/// Callback type for receiving stream data. Called from ngtcp2 recv_stream_data.
/// `h3_conn` is the nghttp3 connection pointer to feed data into.
pub const StreamDataCtx = struct {
    h3_conn: *anyopaque, // *nghttp3.nghttp3_conn — opaque to avoid circular dep
    recv_stream_data: *const fn (h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool) void,
    /// The connection this context belongs to, once it exists. ngtcp2 hands this
    /// context to the callbacks, which is how they reach it.
    connection: ?*Connection = null,
    /// Server side only: the TLS session the connection is being built with.
    /// `serverRecvClientInitialCb` runs during `ngtcp2_conn_server_new`, before
    /// the `Connection` that ends up owning the session exists, so the caller
    /// creates it here and the callback only wires it up.
    tls_session: ?*TlsSession = null,
};

/// OpenSSL session plus the ngtcp2 crypto state for one QUIC connection.
///
/// ngtcp2's crypto callbacks reach OpenSSL through the connection's TLS native
/// handle, and OpenSSL reaches the ngtcp2 connection back through the SSL
/// app_data pointer, so the two point at each other and have to outlive the
/// connection.
pub const TlsSession = struct {
    ssl: *ossl.SSL,
    ssl_ctx: *ossl.SSL_CTX,
    ossl_ctx: *ngtcp2.ngtcp2_crypto_ossl_ctx,
    /// False when the context is shared: a server's comes from `setServerCert`
    /// and outlives every connection that uses it.
    owns_ssl_ctx: bool = true,
    conn_ref: ngtcp2.ngtcp2_crypto_conn_ref = .{},
    conn: ?*ngtcp2.ngtcp2_conn = null,

    fn getConn(conn_ref: [*c]ngtcp2.ngtcp2_crypto_conn_ref) callconv(.c) ?*ngtcp2.ngtcp2_conn {
        const self: *TlsSession = @ptrCast(@alignCast(conn_ref.*.user_data orelse return null));
        return self.conn;
    }

    /// Points the ngtcp2 connection and the OpenSSL session at each other. Must
    /// run before the connection's first handshake packet.
    pub fn attach(self: *TlsSession, conn: *ngtcp2.ngtcp2_conn) void {
        self.conn = conn;
        self.conn_ref = .{ .get_conn = getConn, .user_data = @ptrCast(self) };
        _ = ossl.SSL_set_app_data(self.ssl, @ptrCast(&self.conn_ref));
        ngtcp2.ngtcp2_conn_set_tls_native_handle(conn, @ptrCast(self.ossl_ctx));
    }

    pub fn deinit(self: *TlsSession) void {
        // The ngtcp2 connection is already gone when this runs; clear the
        // back-pointer so OpenSSL cannot call into it.
        _ = ossl.SSL_set_app_data(self.ssl, null);
        ossl.SSL_free(self.ssl);
        if (self.owns_ssl_ctx) {
            ossl.SSL_CTX_free(self.ssl_ctx);
        }
        ngtcp2.ngtcp2_crypto_ossl_ctx_del(self.ossl_ctx);
        std.heap.page_allocator.destroy(self);
    }
};

/// OpenSSL session for a QUIC client. HTTP/3 requires ALPN, and the client has
/// to offer "h3".
fn clientTlsSession(tls: ClientTls) !*TlsSession {
    const ssl_ctx = ossl.SSL_CTX_new(ossl.TLS_client_method()) orelse return error.TlsError;
    errdefer ossl.SSL_CTX_free(ssl_ctx);
    if (tls.insecure_skip_verify) {
        ossl.SSL_CTX_set_verify(ssl_ctx, ossl.SSL_VERIFY_NONE, null);
    } else {
        ossl.SSL_CTX_set_verify(ssl_ctx, ossl.SSL_VERIFY_PEER, null);
        if (tls.root_ca == .system and ossl.SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
            return error.TlsError;
        }
    }

    const ssl = ossl.SSL_new(ssl_ctx) orelse return error.TlsError;
    errdefer ossl.SSL_free(ssl);
    ossl.SSL_set_connect_state(ssl);
    _ = ossl.SSL_set_alpn_protos(ssl, "\x02h3", 3);
    if (ngtcp2.ngtcp2_crypto_ossl_configure_client_session(@ptrCast(ssl)) != 0) return error.TlsError;

    return newTlsSession(ssl, ssl_ctx, true);
}

/// OpenSSL session for a QUIC server, built on the context loaded by
/// `setServerCert`.
pub fn serverTlsSession() !*TlsSession {
    const ssl_ctx: *ossl.SSL_CTX = @ptrCast(@alignCast(server_ssl_ctx orelse return error.TlsError));
    const ssl = ossl.SSL_new(ssl_ctx) orelse return error.TlsError;
    errdefer ossl.SSL_free(ssl);
    ossl.SSL_set_accept_state(ssl);
    if (ngtcp2.ngtcp2_crypto_ossl_configure_server_session(@ptrCast(ssl)) != 0) return error.TlsError;

    return newTlsSession(ssl, ssl_ctx, false);
}

fn newTlsSession(ssl: *ossl.SSL, ssl_ctx: *ossl.SSL_CTX, owns_ssl_ctx: bool) !*TlsSession {
    const session = try std.heap.page_allocator.create(TlsSession);
    errdefer std.heap.page_allocator.destroy(session);

    var ossl_ctx: ?*ngtcp2.ngtcp2_crypto_ossl_ctx = null;
    if (ngtcp2.ngtcp2_crypto_ossl_ctx_new(&ossl_ctx, @ptrCast(ssl)) != 0) return error.TlsError;

    session.* = .{
        .ssl = ssl,
        .ssl_ctx = ssl_ctx,
        .ossl_ctx = ossl_ctx.?,
        .owns_ssl_ctx = owns_ssl_ctx,
    };
    return session;
}

pub const Connection = struct {
    conn: *ngtcp2.ngtcp2_conn,
    socket: posix.fd_t,
    buf: [max_datagram_size]u8 = undefined,
    stream_ctx_alloc: ?*StreamDataCtx = null,
    qlog_fd: ?posix.fd_t = null,
    tls_session: ?*TlsSession = null,
    /// Addresses this connection was created with. Owned separately because
    /// ngtcp2 fills packet paths from the buffers inside it.
    path_alloc: ?*ngtcp2.ngtcp2_path_storage = null,
    /// False when the socket belongs to somebody else (H3 server connections
    /// share the listener's).
    owns_socket: bool = true,
    /// CONNECTION_CLOSE packet this endpoint sent, kept so the peer's
    /// retransmissions can be answered with the same bytes during the closing
    /// period (the normal write path refuses to run then).
    close_buf: [max_close_packet_len]u8 = undefined,
    close_len: usize = 0,
    /// Per-connection application state, owned by the application: this type
    /// never frees it.
    app_state: ?*anyopaque = null,
    /// Server side: the listener this connection came in on, so connection IDs
    /// ngtcp2 issues later can be routed too.
    listener: ?*Listener = null,

    pub fn deinit(self: *Connection) void {
        ngtcp2.ngtcp2_conn_del(self.conn);
        // The TLS session must outlive the connection, but be freed with it.
        if (self.tls_session) |session| session.deinit();
        if (self.owns_socket) {
            _ = posix.system.close(self.socket);
        }
        if (self.stream_ctx_alloc) |ptr| {
            std.heap.page_allocator.destroy(ptr);
        }
        if (self.path_alloc) |ps| {
            std.heap.page_allocator.destroy(ps);
        }
        if (self.qlog_fd) |fd| {
            _ = std.c.close(fd);
        }
        self.* = undefined;
    }
};

pub fn recvStreamDataCb(
    conn: ?*ngtcp2.ngtcp2_conn,
    flags: u32,
    stream_id: i64,
    offset: u64,
    data: [*c]const u8,
    datalen: usize,
    user_data: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    _ = offset;
    _ = stream_user_data;
    const ctx: *StreamDataCtx = @alignCast(@ptrCast(user_data));
    const fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    ctx.recv_stream_data(ctx.h3_conn, stream_id, data[0..datalen], fin);
    _ = conn;
    return 0;
}

/// Sends |bytes| to the remote end of |path|.
fn sendBytes(conn: *Connection, path: *const ngtcp2.ngtcp2_path, bytes: []const u8) Error!void {
    if (bytes.len == 0) return;
    const sent = posix.system.sendto(conn.socket, bytes.ptr, bytes.len, 0, @ptrCast(path.remote.addr), path.remote.addrlen);
    if (sent < 0) return error.QuicError;
}

/// Sends a packet that a write function put into `conn.buf`.
fn sendPacket(conn: *Connection, path: *const ngtcp2.ngtcp2_path, len: usize) Error!void {
    return sendBytes(conn, path, conn.buf[0..len]);
}

/// Packs one HTTP/3 stream chunk into a QUIC packet and sends it. `data` may be
/// empty when only the stream's FIN needs to go out. Returns how many bytes of
/// `data` made it into the packet, which is what nghttp3 has to be told about.
pub fn writeStreamPacket(conn: *Connection, stream_id: i64, fin: bool, data: []const u8) Error!usize {
    var pi: ngtcp2.ngtcp2_pkt_info = undefined;
    // ngtcp2 writes the destination path here and needs storage for the
    // addresses (ngtcp2.h, `ngtcp2_conn_writev_stream`).
    var dest: ngtcp2.ngtcp2_path_storage = undefined;
    ngtcp2.ngtcp2_path_storage_zero(&dest);
    var pdatalen: ngtcp2.ngtcp2_ssize = 0;
    const flags: u32 = if (fin) ngtcp2.NGTCP2_WRITE_STREAM_FLAG_FIN else ngtcp2.NGTCP2_WRITE_STREAM_FLAG_NONE;

    const n = ngtcp2.ngtcp2_conn_write_stream_versioned(
        conn.conn,
        &dest.path,
        ngtcp2.NGTCP2_PKT_INFO_VERSION,
        &pi,
        &conn.buf,
        conn.buf.len,
        &pdatalen,
        flags,
        stream_id,
        data.ptr,
        data.len,
        nowNanos(),
    );
    if (n < 0) return error.QuicError;
    if (n == 0) return 0;
    try sendPacket(conn, &dest.path, @intCast(n));
    return if (pdatalen > 0) @intCast(pdatalen) else 0;
}

/// Handles the QUIC timer when it is due, e.g. for retransmissions.
pub fn handleExpiryIfDue(conn: *Connection) void {
    const expiry = getExpiry(conn) orelse return;
    if (nowNanos() >= expiry) handleExpiry(conn) catch {};
}

/// Tells the peer the connection is going away, so it can drop its state
/// instead of waiting out its idle timeout. Best effort: the packet is written
/// and sent once, and nothing waits for the closing period to pass.
pub fn sendConnectionClose(conn: *Connection, error_code: u64, reason: []const u8) void {
    var ccerr: ngtcp2.ngtcp2_ccerr = std.mem.zeroes(ngtcp2.ngtcp2_ccerr);
    ngtcp2.ngtcp2_ccerr_default(&ccerr);
    ngtcp2.ngtcp2_ccerr_set_application_error(&ccerr, error_code, reason.ptr, reason.len);

    var pi: ngtcp2.ngtcp2_pkt_info = undefined;
    var dest: ngtcp2.ngtcp2_path_storage = undefined;
    ngtcp2.ngtcp2_path_storage_zero(&dest);
    const n = ngtcp2.ngtcp2_conn_write_connection_close_versioned(
        conn.conn,
        &dest.path,
        ngtcp2.NGTCP2_PKT_INFO_VERSION,
        &pi,
        &conn.close_buf,
        conn.close_buf.len,
        &ccerr,
        nowNanos(),
    );
    if (n <= 0) return;
    conn.close_len = @intCast(n);
    sendBytes(conn, &dest.path, conn.close_buf[0..conn.close_len]) catch {};
}

/// Sends the buffered CONNECTION_CLOSE again. RFC 9000: an endpoint in the
/// closing period answers every packet it receives with its close frame.
pub fn resendConnectionClose(conn: *Connection) void {
    if (conn.close_len == 0) return;
    const path = if (conn.path_alloc) |ps| &ps.path else return;
    sendBytes(conn, path, conn.close_buf[0..conn.close_len]) catch {};
}

/// Get nanoseconds until next QUIC timer fires, or null if idle.
pub fn getExpiry(conn: *Connection) ?u64 {
    const ts = ngtcp2.ngtcp2_conn_get_expiry(conn.conn);
    if (ts == std.math.maxInt(u64)) return null;
    return ts;
}

/// Handle QUIC timer expiry — call when getExpiry time elapses.
pub fn handleExpiry(conn: *Connection) Error!void {
    const ret = ngtcp2.ngtcp2_conn_handle_expiry(conn.conn, nowNanos());
    if (ret != 0) return error.QuicError;
    _ = try flushPackets(conn);
}

fn nowNanos() u64 {
    var ts: posix.timespec = undefined;
    _ = posix.system.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// Read a UDP packet and feed it to the QUIC connection.
pub fn readPacket(conn: *Connection) Error!void {
    const n = posix.system.recvfrom(conn.socket, &conn.buf, conn.buf.len, 0, null, null);
    if (n < 0) return;
    const data = conn.buf[0..@intCast(n)];
    const pkt = ngtcp2.ngtcp2_pkt_info{};
    // ngtcp2 wants the network path the packet arrived on; the connection's own
    // addresses are the only ones that fit for a connected UDP socket.
    const path: [*c]ngtcp2.ngtcp2_path = if (conn.path_alloc) |ps| &ps.path else null;
    const ret = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, path, &pkt, data.ptr, data.len, nowNanos());
    if (ret != 0) return error.QuicError;
}

/// Write any pending QUIC packets to the UDP socket.
pub fn flushPackets(conn: *Connection) Error!void {
    // ngtcp2 stores the destination path here and requires each addr field to
    // point at a buffer of its own (ngtcp2.h: "must point to the buffer which
    // should be at least sizeof(sockaddr_union) bytes long"), which a bare
    // `ngtcp2_path` does not provide.
    var path_storage: ngtcp2.ngtcp2_path_storage = undefined;
    ngtcp2.ngtcp2_path_storage_zero(&path_storage);
    while (true) {
        var pi: ngtcp2.ngtcp2_pkt_info = undefined;
        const n = ngtcp2.ngtcp2_conn_write_pkt(conn.conn, &path_storage.path, &pi, conn.buf[0..].ptr, conn.buf.len, nowNanos());
        if (n <= 0) return;
        const sent = posix.system.sendto(conn.socket, conn.buf[0..@intCast(n)].ptr, @intCast(n), 0, @ptrCast(path_storage.path.remote.addr), path_storage.path.remote.addrlen);
        if (sent < 0) return error.QuicError;
    }
}

/// Resolve a hostname to an IPv4 address (network byte order u32).
fn resolveHostIp(host: []const u8, port: u16) !u32 {
    const host_z = try std.heap.page_allocator.alloc(u8, host.len + 1);
    @memcpy(host_z[0..host.len], host);
    host_z[host.len] = 0;
    defer std.heap.page_allocator.free(host_z);

    var port_buf: [6]u8 = @splat(0);
    const port_z = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    const port_z_null: ?[*:0]const u8 = @ptrCast(port_buf[0..port_z.len :0]);

    var hints: std.c.addrinfo = std.mem.zeroes(std.c.addrinfo);
    hints.family = posix.AF.INET;
    hints.socktype = posix.SOCK.DGRAM;
    hints.protocol = posix.IPPROTO.UDP;

    var res: ?*std.c.addrinfo = null;
    const rc = std.c.getaddrinfo(@as(?[*:0]const u8, @ptrCast(host_z)), port_z_null, &hints, &res);
    if (@intFromEnum(rc) != 0) return error.QuicError;
    defer std.c.freeaddrinfo(res.?);

    const addr = res.?.addr orelse return error.QuicError;
    const in_addr: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
    return in_addr.addr;
}

/// Create a QUIC client connection and perform handshake over UDP.
pub fn connect(host: []const u8, port: u16, stream_ctx: ?StreamDataCtx, _: ?[]const u8, tls: ClientTls) Error!Connection {
    // Resolve host to IP (simplified — loopback for local testing)
    _ = host;
    const server_ip: u32 = 0x0100007F; // 127.0.0.1 in network byte order

    const sock: posix.fd_t = @intCast(posix.system.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP));
    if (sock < 0) return error.QuicError;
    errdefer _ = std.c.close(sock);

    // Handshake progress is driven by short polling loops, so a read must not
    // block one of them forever when the peer has nothing to say.
    const recv_timeout = posix.timeval{ .sec = 0, .usec = 100 * std.time.us_per_ms };
    _ = posix.system.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&recv_timeout), @sizeOf(posix.timeval));

    const server_sockaddr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = @byteSwap(port),
        .addr = server_ip,
        .zero = @splat(0),
    };

    // ngtcp2 drives TLS through its crypto callbacks, which need an OpenSSL
    // session attached to the connection as the TLS native handle.
    const tls_session = try clientTlsSession(tls);
    errdefer tls_session.deinit();

    // Generate random connection IDs (use getrandom syscall)
    var dcid: ngtcp2.ngtcp2_cid = undefined;
    var scid: ngtcp2.ngtcp2_cid = undefined;
    dcid.datalen = 18;
    scid.datalen = 18;
    std.c.arc4random_buf(&dcid.data, 18);
    std.c.arc4random_buf(&scid.data, 18);

    var callbacks = clientCallbacks();

    // Install stream data callback if H3 bridge context is provided.
    // Heap-allocate the context so it lives beyond this stack frame.
    var stream_ctx_ptr: ?*StreamDataCtx = null;
    if (stream_ctx) |ctx| {
        callbacks.recv_stream_data = recvStreamDataCb;
        const ptr = try std.heap.page_allocator.create(StreamDataCtx);
        errdefer std.heap.page_allocator.destroy(ptr);
        ptr.* = ctx;
        stream_ctx_ptr = ptr;
    }

    // Set QLog if enabled
    var settings: ngtcp2.ngtcp2_settings = undefined;
    ngtcp2.ngtcp2_settings_default(&settings);
    if (qlog_fd >= 0) {
        settings.qlog_write = qlogWriteCb;
    }

    var params: ngtcp2.ngtcp2_transport_params = undefined;
    ngtcp2.ngtcp2_transport_params_default(&params);
    params.initial_max_streams_uni = 3;
    params.initial_max_streams_bidi = 100;
    params.initial_max_data = 1048576;
    params.initial_max_stream_data_bidi_local = 1048576;
    params.initial_max_stream_data_bidi_remote = 1048576;
    // The HTTP/3 control and QPACK streams are unidirectional, and a zero
    // limit here blocks every byte the peer sends on them.
    params.initial_max_stream_data_uni = 1048576;

    // The connection's addresses live here for as long as it does: ngtcp2 fills
    // packet paths (and compares them) out of these buffers, so they cannot be
    // stack locals or a bare `ngtcp2_path`.
    const path_storage = try std.heap.page_allocator.create(ngtcp2.ngtcp2_path_storage);
    errdefer std.heap.page_allocator.destroy(path_storage);
    var local_sockaddr = posix.sockaddr.in{ .family = posix.AF.INET, .port = 0, .addr = 0, .zero = @splat(0) };
    ngtcp2.ngtcp2_path_storage_init(
        path_storage,
        @ptrCast(&local_sockaddr),
        @sizeOf(posix.sockaddr.in),
        @ptrCast(&server_sockaddr),
        @sizeOf(posix.sockaddr.in),
        null,
    );

    const user_data: ?*anyopaque = if (stream_ctx_ptr) |ptr| @ptrCast(ptr) else null;
    var conn_ptr: ?*ngtcp2.ngtcp2_conn = null;
    const mem: ?*const ngtcp2.struct_ngtcp2_mem = null;
    const ret = ngtcp2.ngtcp2_conn_client_new(&conn_ptr, &dcid, &scid, &path_storage.path, ngtcp2.NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, mem, user_data);
    if (ret != 0) return error.QuicError;
    errdefer ngtcp2.ngtcp2_conn_del(conn_ptr.?);

    tls_session.attach(conn_ptr.?);

    // Enable 0-RTT early data with remembered transport params (deferred)
    // if (early_data) |ed| { ... }

    var self = Connection{
        .conn = conn_ptr.?,
        .socket = sock,
        .stream_ctx_alloc = stream_ctx_ptr,
        .tls_session = tls_session,
        .path_alloc = path_storage,
    };

    // Drive handshake
    _ = try flushPackets(&self);
    for (0..10) |_| {
        readPacket(&self) catch {};
        _ = flushPackets(&self) catch {};
        sleepNs(10 * std.time.ns_per_ms);
    }

    return self;
}

/// Get encoded transport params for 0-RTT resumption.
/// Returns allocated buffer — caller owns and must free.
pub fn getTransportParams(conn: *Connection) ![]u8 {
    var buf: [4096]u8 = undefined;
    const n = ngtcp2.ngtcp2_conn_encode_0rtt_transport_params(conn.conn, &buf, buf.len);
    if (n < 0) return error.QuicError;
    const result = try std.heap.page_allocator.alloc(u8, @intCast(n));
    @memcpy(result, buf[0..@intCast(n)]);
    return result;
}

/// Server-side QUIC listener, binds UDP and routes by Connection ID.
pub const Listener = struct {
    socket: posix.fd_t,
    /// Address the socket is bound to; the local half of every QUIC path.
    local_addr: posix.sockaddr.in,
    connections: std.AutoHashMap([18]u8, *Connection),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, port: u16) Error!Listener {
        const sock: posix.fd_t = @intCast(posix.system.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP));
        if (sock < 0) return error.QuicError;
        errdefer _ = std.c.close(sock);

        const enable: c_int = 1;
        _ = posix.system.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&enable), @sizeOf(c_int));

        const addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = @byteSwap(port),
            .addr = 0, // INADDR_ANY
            .zero = @splat(0),
        };
        const rc = posix.system.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
        if (rc < 0) return error.QuicError;

        // Requests are served from a polling loop, so a read must not block it
        // waiting for a peer that has nothing to say.
        const recv_timeout = posix.timeval{ .sec = 0, .usec = 10 * std.time.us_per_ms };
        _ = posix.system.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&recv_timeout), @sizeOf(posix.timeval));
        var back: posix.timeval = undefined;
        var backlen: posix.socklen_t = @sizeOf(posix.timeval);
        _ = posix.system.getsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, @ptrCast(&back), &backlen);

        // The bound address is half of every QUIC path the server hands ngtcp2.
        var local_addr: posix.sockaddr.in = undefined;
        var local_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        if (posix.system.getsockname(sock, @ptrCast(&local_addr), &local_addr_len) < 0) return error.QuicError;

        return .{
            .socket = sock,
            .local_addr = local_addr,
            .connections = std.AutoHashMap([18]u8, *Connection).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Listener) void {
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.connections.deinit();
        _ = posix.system.close(self.socket);
    }
};

// ---- Connection migration callbacks ----

/// ngtcp2 get_new_connection_id callback — generates a random CID and, on the
/// server, registers it so datagrams addressed to it reach the same connection.
pub fn getNewConnIdCb(
    _: ?*ngtcp2.ngtcp2_conn,
    cid: ?*ngtcp2.ngtcp2_cid,
    _: [*c]u8,
    _: usize,
    user_data: ?*anyopaque,
) callconv(.c) c_int {
    const out = cid orelse return 0;
    out.datalen = cid_length;
    std.c.arc4random_buf(@ptrCast(&out.data), cid_length);

    const ctx: *StreamDataCtx = @ptrCast(@alignCast(user_data orelse return 0));
    const connection = ctx.connection orelse return 0; // client side: nothing to route
    const listener = connection.listener orelse return 0;
    listener.connections.put(cidKey(out.*), connection) catch {};
    return 0;
}

/// ngtcp2 remove_connection_id callback — retires an old CID.
pub fn removeConnIdCb(
    _: ?*ngtcp2.ngtcp2_conn,
    cid: [*c]const ngtcp2.ngtcp2_cid,
    user_data: ?*anyopaque,
) callconv(.c) c_int {
    const ctx: *StreamDataCtx = @ptrCast(@alignCast(user_data orelse return 0));
    const connection = ctx.connection orelse return 0;
    const listener = connection.listener orelse return 0;
    _ = listener.connections.remove(cidKey(cid.*));
    return 0;
}

/// The fixed length of every connection ID this endpoint issues. Short headers
/// carry no length, so routing depends on it.
pub const cid_length = 18;

/// A connection ID as the routing table keys it.
pub fn cidKey(cid: ngtcp2.ngtcp2_cid) [cid_length]u8 {
    var key: [cid_length]u8 = @splat(0);
    const len = @min(@as(usize, cid.datalen), cid_length);
    @memcpy(key[0..len], cid.data[0..len]);
    return key;
}

/// The connection ID a datagram is addressed to, or null if it is too short to
/// tell. Long headers carry the length; short (1-RTT) headers do not, and this
/// endpoint only ever issues `cid_length` byte ones.
pub fn destinationCid(buf: []const u8, n: usize) ?[cid_length]u8 {
    if (n == 0) return null;
    var cid: [cid_length]u8 = @splat(0);
    if (buf[0] & 0x80 != 0) {
        if (n < 6) return null;
        const dcid_len: usize = buf[5];
        if (dcid_len == 0 or dcid_len > cid_length) return null;
        if (6 + dcid_len > n) return null;
        @memcpy(cid[0..dcid_len], buf[6..][0..dcid_len]);
        return cid;
    }
    if (1 + cid_length > n) return null;
    @memcpy(&cid, buf[1..][0..cid_length]);
    return cid;
}

/// ngtcp2 path_validation callback — logs path changes.
pub fn pathValidationCb(
    _: ?*ngtcp2.ngtcp2_conn,
    _: u32,
    _: ?*const ngtcp2.ngtcp2_path,
    _: ?*const ngtcp2.ngtcp2_path,
    _: ngtcp2.ngtcp2_path_validation_result,
    _: ?*anyopaque,
) callconv(.c) c_int {
    return 0; // Accept all path changes
}

/// ngtcp2 rand callback — mandatory for every connection. ngtcp2 calls it for
/// unpredictable bytes it derives itself (stateless reset tokens, CIDs).
pub fn randCb(dest: [*c]u8, destlen: usize, _: [*c]const ngtcp2.ngtcp2_rand_ctx) callconv(.c) void {
    std.c.arc4random_buf(dest, destlen);
}

/// Callbacks for a client connection. ngtcp2 marks several of these as
/// mandatory and asserts on a null one when the connection is created, so every
/// field it documents as required has to be set here.
fn clientCallbacks() ngtcp2.ngtcp2_callbacks {
    var callbacks: ngtcp2.ngtcp2_callbacks = std.mem.zeroes(ngtcp2.ngtcp2_callbacks);
    callbacks.client_initial = ngtcp2.ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2.ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2.ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2.ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2.ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_retry = ngtcp2.ngtcp2_crypto_recv_retry_cb;
    callbacks.update_key = ngtcp2.ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2.ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2.ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data = ngtcp2.ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation = ngtcp2.ngtcp2_crypto_version_negotiation_cb;
    callbacks.get_new_connection_id = getNewConnIdCb;
    callbacks.remove_connection_id = removeConnIdCb;
    callbacks.path_validation = pathValidationCb;
    callbacks.rand = randCb;
    return callbacks;
}

test {
    _ = @import("quic_test.zig");
}

test "clientCallbacks: sets every callback ngtcp2 requires" {
    const callbacks = clientCallbacks();
    try std.testing.expect(callbacks.client_initial != null);
    try std.testing.expect(callbacks.recv_crypto_data != null);
    try std.testing.expect(callbacks.encrypt != null);
    try std.testing.expect(callbacks.decrypt != null);
    try std.testing.expect(callbacks.hp_mask != null);
    try std.testing.expect(callbacks.recv_retry != null);
    try std.testing.expect(callbacks.update_key != null);
    try std.testing.expect(callbacks.delete_crypto_aead_ctx != null);
    try std.testing.expect(callbacks.delete_crypto_cipher_ctx != null);
    try std.testing.expect(callbacks.get_path_challenge_data != null);
    try std.testing.expect(callbacks.version_negotiation != null);
    try std.testing.expect(callbacks.get_new_connection_id != null);
    try std.testing.expect(callbacks.remove_connection_id != null);
    try std.testing.expect(callbacks.path_validation != null);
    try std.testing.expect(callbacks.rand != null);
}

// Flipping this on also makes `connect` reach ngtcp2_crypto_client_initial_cb,
// which needs the connection's TLS native handle.
test "connect: creates a client connection" {
    var conn = try connect("127.0.0.1", 45454, null, null, .{ .insecure_skip_verify = true });
    defer conn.deinit();
}
