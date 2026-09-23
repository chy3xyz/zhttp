const std = @import("std");
const ngtcp2 = @import("ngtcp2_c");
const nghttp3 = @import("nghttp3_c");
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

/// Fill `buf` with bytes from the system's cryptographically secure random
/// source. Every connection ID and the stateless reset secret this layer
/// chooses come from here.
///
/// `std.c.arc4random_buf` is not usable on its own: it is a `switch (native_os)`
/// in std/c.zig that resolves to an empty tuple — a call that does nothing —
/// on Linux unless the ABI is Android or glibc >= 2.36, and on any other
/// platform whose libc has no such function. A connection ID or a reset secret
/// filled that way is whatever the memory happened to hold, which is both a
/// protocol and a security failure. This is what `std.Io.Threaded` does for
/// `Io.randomSecure`, without needing the `Io`: the libc primitive where the
/// ABI has one, the `getrandom` syscall otherwise, and a compile error where
/// neither exists — never a silent no-op.
pub fn fillRandom(buf: []u8) void {
    if (buf.len == 0) return;
    if (comptime builtin.link_libc and @TypeOf(c.arc4random_buf) != void) {
        c.arc4random_buf(buf.ptr, buf.len);
    } else if (comptime builtin.os.tag == .linux) {
        // The syscall, not `std.c.getrandom`: this std leaves that one
        // unimplemented for glibc < 2.25 and every musl, and the syscall is
        // what it falls back to itself. `getrandom` hands back at most 256
        // bytes per call, so a longer buffer takes several.
        var filled: usize = 0;
        while (filled < buf.len) {
            const rc = std.os.linux.getrandom(buf.ptr + filled, buf.len - filled, 0);
            switch (posix.errno(rc)) {
                .SUCCESS => filled += @intCast(rc),
                .INTR => continue,
                // EFAULT and EINVAL are the only other ways this call fails and
                // neither can happen here: the buffer is a live Zig slice and
                // the flags word is 0. Stopping loudly beats handing out bytes
                // that were never written.
                else => @panic("h3: getrandom failed"),
            }
        }
    } else {
        @compileError("h3: no source of cryptographically secure random bytes for this target");
    }
}

/// Server SSL_CTX for QUIC TLS handshake (set by setServerCert).
var server_ssl_ctx: ?*anyopaque = null;

/// The certificate store of an SSL_CTX, and the call that installs a CA into
/// it. OpenSSL's usual way to trust a CA is `SSL_CTX_load_verify_locations`,
/// which takes a path; the CA here is PEM in memory, so it goes into the store
/// the context already has.
const X509_STORE = opaque {};
extern fn SSL_CTX_get_cert_store(ctx: ?*ossl.SSL_CTX) ?*X509_STORE;
extern fn X509_STORE_add_cert(store: ?*X509_STORE, x: ?*ossl.X509) c_int;

/// `SSL_VERIFY_FAIL_IF_NO_PEER_CERT` (ssl.h): on a server, "the client sent no
/// certificate" is a handshake failure instead of a policy the application would
/// have to check for itself after the connection was already established.
const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 0x02;

/// Load a certificate and its private key, both PEM, into an SSL_CTX. The same
/// call serves a server's own certificate and the certificate a client presents
/// when a server asks for one; the X509 and EVP_PKEY are freed here because the
/// context takes its own references to them.
fn loadCertInto(ctx: *ossl.SSL_CTX, cert_pem: []const u8, key_pem: []const u8) !void {
    const cert_bio = ossl.BIO_new_mem_buf(cert_pem.ptr, @intCast(cert_pem.len)) orelse return error.TlsError;
    defer _ = ossl.BIO_free(cert_bio);
    const x509 = ossl.PEM_read_bio_X509(cert_bio, null, null, null) orelse return error.TlsError;
    if (ossl.SSL_CTX_use_certificate(ctx, x509) != 1) {
        ossl.X509_free(x509);
        return error.TlsError;
    }
    ossl.X509_free(x509);

    const key_bio = ossl.BIO_new_mem_buf(key_pem.ptr, @intCast(key_pem.len)) orelse return error.TlsError;
    defer _ = ossl.BIO_free(key_bio);
    const pkey = ossl.PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse return error.TlsError;
    defer ossl.EVP_PKEY_free(pkey);
    if (ossl.SSL_CTX_use_PrivateKey(ctx, pkey) != 1) return error.TlsError;
    if (ossl.SSL_CTX_check_private_key(ctx) != 1) return error.TlsError;
}

/// Load a server certificate for QUIC TLS.
/// Must be called BEFORE creating server connections.
pub fn setServerCert(cert_pem: []const u8, key_pem: []const u8) !void {
    const ctx = ossl.SSL_CTX_new(ossl.TLS_server_method()) orelse return error.TlsError;
    errdefer ossl.SSL_CTX_free(ctx);

    try loadCertInto(ctx, cert_pem, key_pem);

    // QUIC mandates ALPN, and HTTP/3 peers only ever offer "h3".
    ossl.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectH3Cb, null);

    server_ssl_ctx = @ptrCast(ctx);
}

/// Require a client certificate from every QUIC connection, verified against
/// `ca_pem`. A client that sends nothing, or a certificate this CA does not
/// verify, fails the handshake instead of being served.
///
/// Must be called after `setServerCert` — both configure the same server
/// context — and before creating connections. It applies to every connection
/// that context creates from then on.
pub fn setClientCa(ca_pem: []const u8) !void {
    const ctx: *ossl.SSL_CTX = @ptrCast(@alignCast(server_ssl_ctx orelse return error.TlsError));

    const ca_bio = ossl.BIO_new_mem_buf(ca_pem.ptr, @intCast(ca_pem.len)) orelse return error.TlsError;
    defer _ = ossl.BIO_free(ca_bio);
    const ca = ossl.PEM_read_bio_X509(ca_bio, null, null, null) orelse return error.TlsError;
    defer ossl.X509_free(ca);

    const store = SSL_CTX_get_cert_store(ctx) orelse return error.TlsError;
    // A CA the store already holds is reported as a failure — "cert already in
    // hash table" — and that is the state this wants, so it is not an error
    // here: an endpoint that trusts several CAs installs them one at a time.
    _ = X509_STORE_add_cert(store, ca);

    ossl.SSL_CTX_set_verify(ctx, ossl.SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null);
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
    const ret = ossl.SSL_select_next_proto(@ptrCast(@constCast(out)), outlen, h3, h3.len, in, inlen);
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

pub const Error = error{
    QuicError,
    OutOfMemory,
    NoSpaceLeft,
    /// The TLS handshake failed. ngtcp2 reports the alert and the TLS library's
    /// own error code; `lastTlsFailure` has them.
    TlsError,
    /// The QUIC handshake did not finish within the time a connection attempt
    /// allowed, so there is no connection to hand back.
    HandshakeTimeout,
    /// The HTTP/3 layer reported a connection error. nghttp3.h: the connection
    /// must be closed, and calling anything but `nghttp3_conn_del` on it
    /// afterwards is undefined behaviour.
    Http3Error,
    /// The connection is closing or draining — the peer ended it, or an endpoint
    /// already sent a CONNECTION_CLOSE.
    ConnectionClosed,
    /// ngtcp2.h, `ngtcp2_conn_read_pkt`: the endpoint must drop the connection
    /// silently, without a CONNECTION_CLOSE, and discard its state.
    ConnectionDropped,
    /// ngtcp2.h, `ngtcp2_conn_read_pkt`: the server must validate the peer's
    /// address by sending a Retry packet and discard the connection state.
    RetryRequired,
};

/// What ngtcp2 knows about a TLS failure: the alert that ended the handshake and
/// the error code the TLS library reported. Both are 0 when ngtcp2 has neither.
pub const TlsFailure = struct {
    alert: u8 = 0,
    error_code: c_int = 0,
};

/// The TLS failure the last read or write on this thread ran into. ngtcp2 keeps
/// the details only until the next one, so they are lifted out of the connection
/// when it reports the error (`ngtcp2_conn_get_tls_alert2`,
/// `ngtcp2_conn_get_tls_error2`), where a caller that no longer has a connection
/// can still see them.
pub threadlocal var last_tls_failure: TlsFailure = .{};

/// The error an ngtcp2 return value means. TLS is the one failure ngtcp2 keeps
/// detail for, so it is read out here; everything else is the code itself.
fn classify(conn: *ngtcp2.ngtcp2_conn, ret: c_int) Error {
    switch (ret) {
        ngtcp2.NGTCP2_ERR_CRYPTO => {
            last_tls_failure = .{
                .alert = ngtcp2.ngtcp2_conn_get_tls_alert2(conn),
                .error_code = ngtcp2.ngtcp2_conn_get_tls_error2(conn),
            };
            return error.TlsError;
        },
        ngtcp2.NGTCP2_ERR_DRAINING, ngtcp2.NGTCP2_ERR_CLOSING => return error.ConnectionClosed,
        ngtcp2.NGTCP2_ERR_DROP_CONN => return error.ConnectionDropped,
        ngtcp2.NGTCP2_ERR_RETRY => return error.RetryRequired,
        else => return error.QuicError,
    }
}

/// The error `ngtcp2_conn_read_pkt`'s return value means, as ngtcp2.h documents
/// it. Public because a caller that drives ngtcp2 itself (the H3 server does)
/// has to act on the same codes.
pub fn classifyReadError(conn: *ngtcp2.ngtcp2_conn, ret: c_int) Error {
    return classify(conn, ret);
}

/// A certificate and its private key, both PEM-encoded, the shape
/// `setServerCert` takes.
pub const CertKeyPair = struct {
    cert_pem: []const u8,
    key_pem: []const u8,
};

/// TLS settings for a QUIC client connection, mirroring `httpz.tls.config.Client`.
pub const ClientTls = struct {
    /// `.system` verifies the peer against the system CA store, `.empty` trusts
    /// whatever the peer presents.
    root_ca: RootCa = .system,
    /// Skip peer verification entirely. Local testing only.
    insecure_skip_verify: bool = false,
    /// The certificate to present to a server that asks for one (mutual TLS).
    /// OpenSSL answers a server's CertificateRequest with it, so a client that
    /// has one still reaches a server that asks for none.
    auth: ?CertKeyPair = null,
};

pub const RootCa = enum { empty, system };

/// What the HTTP/3 layer did with one chunk of stream data.
pub const StreamRead = union(enum) {
    /// The bytes nghttp3 consumed. This much flow control credit goes back to
    /// the peer.
    consumed: usize,
    /// nghttp3 hit a connection error, which nghttp3.h defines as: the
    /// connection must be closed, and calling anything but `nghttp3_conn_del`
    /// on it is undefined behaviour. The payload is the QUIC application error
    /// code to close it with (`nghttp3_err_infer_quic_app_error_code`).
    connection_error: u64,
};

/// Callback type for receiving stream data. Called from ngtcp2 recv_stream_data.
/// `h3_conn` is the nghttp3 connection pointer to feed data into. `ts` is the
/// timestamp ngtcp2 was given for the packet that carried the data: nghttp3
/// requires the timestamp of every read to be non-decreasing and to come from a
/// steadily increasing clock, and feeding it a constant disables its rate
/// limiter (nghttp3.h, `nghttp3_conn_read_stream2`).
pub const StreamDataCtx = struct {
    h3_conn: *anyopaque, // *nghttp3.nghttp3_conn — opaque to avoid circular dep
    recv_stream_data: *const fn (h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool, ts: u64) StreamRead,
    /// Set once `recv_stream_data` reported `connection_error`: the HTTP/3
    /// connection is dead, and this is the application error code the QUIC
    /// connection is closed with. Nothing calls into nghttp3 again after that.
    h3_error_code: ?u64 = null,
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

    if (tls.auth) |auth| try loadCertInto(ssl_ctx, auth.cert_pem, auth.key_pem);

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
    const ctx: *StreamDataCtx = @ptrCast(@alignCast(user_data));
    const fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    // The timestamp ngtcp2 is working off is the one this packet was read with,
    // so nghttp3 sees the same clock ngtcp2 does and never sees it go backwards.
    const ts = if (conn) |quic_conn| ngtcp2.ngtcp2_conn_get_timestamp(quic_conn) else nowNanos();
    switch (ctx.recv_stream_data(ctx.h3_conn, stream_id, data[0..datalen], fin, ts)) {
        .consumed => |consumed| {
            if (conn) |quic_conn| extendFlowControl(quic_conn, stream_id, consumed);
            return 0;
        },
        // nghttp3 documents the connection as unwritable from here on: report
        // the failure to ngtcp2 rather than pretend the bytes were taken, and
        // remember why so the read that is running can close the connection.
        .connection_error => |code| {
            ctx.h3_error_code = code;
            return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE;
        },
    }
}

/// ngtcp2 acked_stream_data_offset callback — stream data this endpoint sent has
/// been acknowledged by the peer, which is the only thing that lets nghttp3
/// reclaim it: an entry of a stream's outgoing queue is popped only from
/// `nghttp3_stream_update_ack_offset` (nghttp3_stream.c), which
/// `nghttp3_conn_add_ack_offset` feeds. Without this the queue of a long-lived
/// stream holds every byte the stream ever sent.
pub fn ackedStreamDataOffsetCb(
    _: ?*ngtcp2.ngtcp2_conn,
    stream_id: i64,
    _: u64,
    datalen: u64,
    user_data: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) c_int {
    // A connection without an HTTP/3 layer (or one that is not attached to an
    // H3 session yet) has nothing to hand the acknowledgement to.
    const ctx: *StreamDataCtx = @ptrCast(@alignCast(user_data orelse return 0));
    const h3_conn: *nghttp3.nghttp3_conn = @ptrCast(@alignCast(ctx.h3_conn));
    if (nghttp3.nghttp3_conn_add_ack_offset(h3_conn, stream_id, @intCast(datalen)) != 0) {
        return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

/// Hands consumed data back as flow control credit, so the peer's window grows
/// past the initial one as its data is read (ngtcp2 turns this into
/// MAX_STREAM_DATA and MAX_DATA frames).
fn extendFlowControl(conn: *ngtcp2.ngtcp2_conn, stream_id: i64, consumed: usize) void {
    if (consumed == 0) return;
    _ = ngtcp2.ngtcp2_conn_extend_max_stream_offset(conn, stream_id, consumed);
    ngtcp2.ngtcp2_conn_extend_max_offset(conn, consumed);
}

/// ngtcp2 extend_max_stream_data callback — the peer grew an outgoing stream's
/// flow control window, so the data nghttp3 is holding for that stream can be
/// offered again.
pub fn extendMaxStreamDataCb(
    _: ?*ngtcp2.ngtcp2_conn,
    stream_id: i64,
    _: u64,
    user_data: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const ctx: *StreamDataCtx = @ptrCast(@alignCast(user_data orelse return 0));
    _ = nghttp3.nghttp3_conn_unblock_stream(@ptrCast(@alignCast(ctx.h3_conn)), stream_id);
    return 0;
}

/// ngtcp2 stream_close callback — a stream is gone, so the room it took up in
/// the peer's stream limit can be handed back. ngtcp2 does not raise the limit
/// on its own ("The library does not increase maximum stream limit
/// automatically" — ngtcp2_conn_extend_max_streams_bidi), so a connection that
/// never does it serves only as many requests as it advertised streams.
/// The peer opens exactly the three unidirectional streams HTTP/3 requires, so
/// only the bidirectional limit needs tracking.
pub fn streamCloseCb(
    conn: ?*ngtcp2.ngtcp2_conn,
    _: u32,
    stream_id: i64,
    _: u64,
    _: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const quic_conn = conn orelse return 0;
    // Only a stream the peer opened frees up room for another of the same kind.
    if (ngtcp2.ngtcp2_conn_is_local_stream2(quic_conn, stream_id) != 0) return 0;
    if (ngtcp2.ngtcp2_is_bidi_stream(stream_id) == 0) return 0;
    ngtcp2.ngtcp2_conn_extend_max_streams_bidi(quic_conn, 1);
    return 0;
}

/// ngtcp2 extend_max_remote_streams_bidi callback — the stream limit this
/// endpoint advertises to the peer grew along with the MAX_STREAMS frame ngtcp2
/// is about to send, and nghttp3 tracks that limit separately: without telling
/// it, it refuses the request streams the peer is now allowed to open.
pub fn extendMaxRemoteStreamsBidiCb(
    _: ?*ngtcp2.ngtcp2_conn,
    max_streams: u64,
    user_data: ?*anyopaque,
) callconv(.c) c_int {
    const ctx: *StreamDataCtx = @ptrCast(@alignCast(user_data orelse return 0));
    nghttp3.nghttp3_conn_set_max_client_streams_bidi(@ptrCast(@alignCast(ctx.h3_conn)), max_streams);
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

/// How many vectors nghttp3 may hand over for one stream in one call. A
/// response is a header block followed by its body, queued as several
/// contiguous runs, and ngtcp2 can only fill a packet with as much of them as
/// it is given in one go.
const max_stream_vecs = 16;

/// Packs one QUIC datagram with everything pending in the HTTP/3 session and
/// sends it, coalescing frames from several streams into the packet the way
/// ngtcp2 structures it (`NGTCP2_WRITE_STREAM_FLAG_MORE`). Returns the number of
/// bytes sent, or 0 when ngtcp2 had nothing it could put on the wire.
///
/// Without MORE each call to `ngtcp2_conn_writev_stream` finalizes its own
/// packet, so a response always leaves as at least two datagrams — one for the
/// HEADERS and one for the DATA and FIN — and a header block that would have fit
/// alongside its body costs a whole extra packet. ngtcp2.h spells out the shape
/// this has to take: the packet stays open while the calls keep returning
/// `NGTCP2_ERR_WRITE_MORE`, every call has to pass the same path, packet info,
/// buffer, and timestamp, and the way to end the packet is one more call with
/// `stream_id` = -1 and nothing to offer.
///
/// A stream ngtcp2 refuses (flow control, or the write side already shut) is
/// blocked or shut down in nghttp3 before the loop goes on, so it cannot be
/// offered again forever; the packet being built is kept, because it still
/// holds whatever was written before.
pub fn writePackedPacket(conn: *Connection, h3_conn: *nghttp3.nghttp3_conn, ts: u64) Error!usize {
    // The packet's destination path and metadata live for the whole packet:
    // ngtcp2 requires the same path, packet info, buffer, and timestamp on
    // every call that adds to it, and it writes the packed addresses into this
    // storage (ngtcp2.h, `ngtcp2_conn_writev_stream`).
    var dest: ngtcp2.ngtcp2_path_storage = undefined;
    ngtcp2.ngtcp2_path_storage_zero(&dest);
    var pi: ngtcp2.ngtcp2_pkt_info = undefined;
    var vec: [max_stream_vecs]nghttp3.nghttp3_vec = undefined;

    while (true) {
        var stream_id: i64 = -1;
        var fin: c_int = 0;
        var nvec: nghttp3.nghttp3_ssize = 0;

        // There is no point offering nghttp3's data while the connection's own
        // flow control window is empty: ngtcp2 would refuse every stream and
        // each one would have to be blocked in nghttp3 until the peer extends
        // the window (ngtcp2.h, `ngtcp2_conn_get_max_data_left2`).
        if (ngtcp2.ngtcp2_conn_get_max_data_left2(conn.conn) != 0) {
            nvec = nghttp3.nghttp3_conn_writev_stream(h3_conn, &stream_id, &fin, &vec, vec.len);
            if (nvec < 0) {
                // nghttp3.h: a negative return is a connection error and the
                // connection may only be deleted from here on. There is no
                // packet to finish for it, so it is reported to the caller the
                // same way a broken QUIC connection is.
                return error.Http3Error;
            }
        }

        var pdatalen: ngtcp2.ngtcp2_ssize = 0;
        var flags: u32 = ngtcp2.NGTCP2_WRITE_STREAM_FLAG_MORE;
        if (fin != 0) flags |= ngtcp2.NGTCP2_WRITE_STREAM_FLAG_FIN;

        const n = ngtcp2.ngtcp2_conn_writev_stream_versioned(
            conn.conn,
            &dest.path,
            ngtcp2.NGTCP2_PKT_INFO_VERSION,
            &pi,
            &conn.buf,
            conn.buf.len,
            &pdatalen,
            flags,
            stream_id,
            @ptrCast(&vec),
            @intCast(nvec),
            ts,
        );

        // The packet is not finished yet: ngtcp2 took `pdatalen` bytes of this
        // stream into it and is waiting for more, so nghttp3 has to be told how
        // much of the stream went out before the next chunk is taken.
        if (n == ngtcp2.NGTCP2_ERR_WRITE_MORE) {
            _ = nghttp3.nghttp3_conn_add_write_offset(h3_conn, stream_id, @intCast(pdatalen));
            continue;
        }
        // These two stop this stream alone; the packet survives them and is
        // finished below, so nghttp3 is told why ngtcp2 did not take its data
        // instead of being offered the same stream again.
        if (n == ngtcp2.NGTCP2_ERR_STREAM_DATA_BLOCKED) {
            nghttp3.nghttp3_conn_block_stream(h3_conn, stream_id);
            continue;
        }
        if (n == ngtcp2.NGTCP2_ERR_STREAM_SHUT_WR) {
            _ = nghttp3.nghttp3_conn_shutdown_stream_write(h3_conn, stream_id);
            continue;
        }
        // ngtcp2.h: any other negative return is a connection error, and a TLS
        // failure reaches the application this way too.
        if (n < 0) return classify(conn.conn, @intCast(n));
        // Nothing could be sent at all: congestion limited, or nothing to say.
        if (n == 0) return 0;

        // A packet went out. -1 means it carried no STREAM frame for this
        // stream, i.e. none of the data was taken.
        if (pdatalen >= 0) {
            _ = nghttp3.nghttp3_conn_add_write_offset(h3_conn, stream_id, @intCast(pdatalen));
        }
        try sendPacket(conn, &dest.path, @intCast(n));
        return @intCast(n);
    }
}

/// Handles the QUIC timer when it is due, e.g. for retransmissions.
pub fn handleExpiryIfDue(conn: *Connection) void {
    const expiry = getExpiry(conn) orelse return;
    if (nowNanos() >= expiry) handleExpiry(conn) catch {};
}

/// Why a connection is ending, as the CONNECTION_CLOSE frame states it.
pub const CloseReason = union(enum) {
    /// An HTTP/3 or application error code.
    application: u64,
    /// A TLS alert number; ngtcp2 turns it into the QUIC CRYPTO_ERROR code that
    /// carries it (ngtcp2.h, `ngtcp2_ccerr_set_tls_alert`).
    tls_alert: u8,
    /// One of ngtcp2's own error codes, from which ngtcp2 infers the QUIC
    /// transport error code (ngtcp2.h, `ngtcp2_ccerr_set_liberr`).
    ngtcp2_error: c_int,
};

/// Tells the peer the connection is going away, so it can drop its state
/// instead of waiting out its idle timeout. Best effort: the packet is written
/// and sent once, and nothing waits for the closing period to pass.
pub fn sendConnectionClose(conn: *Connection, reason: CloseReason, text: []const u8) void {
    var ccerr: ngtcp2.ngtcp2_ccerr = std.mem.zeroes(ngtcp2.ngtcp2_ccerr);
    ngtcp2.ngtcp2_ccerr_default(&ccerr);
    switch (reason) {
        .application => |code| ngtcp2.ngtcp2_ccerr_set_application_error(&ccerr, code, text.ptr, text.len),
        .tls_alert => |alert| ngtcp2.ngtcp2_ccerr_set_tls_alert(&ccerr, alert, text.ptr, text.len),
        .ngtcp2_error => |liberr| ngtcp2.ngtcp2_ccerr_set_liberr(&ccerr, liberr, text.ptr, text.len),
    }

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
///
/// A failure ends the connection, and the peer is told why before this returns:
/// ngtcp2.h documents that a CONNECTION_CLOSE is the terminal packet for every
/// error `ngtcp2_conn_read_pkt` reports except the two that mean the state is
/// dropped, and an HTTP/3 error carries the code nghttp3 named.
pub fn readPacket(conn: *Connection) Error!void {
    const n = posix.system.recvfrom(conn.socket, &conn.buf, conn.buf.len, 0, null, null);
    if (n < 0) return;
    return handlePacket(conn, conn.buf[0..@intCast(n)]);
}

/// How many datagrams one turn of an event loop takes off the socket before it
/// goes back to whatever else it has to do. Reading one per turn would make the
/// loop — and with it the connection — move at one datagram per wakeup; reading
/// without a bound would let a peer that sends faster than this endpoint
/// processes keep it from ever pumping its own writes. The reference server
/// drains in the same bounded way (64 datagrams per readable event).
pub const max_datagrams_per_drain = 64;

/// Feeds one datagram that is already waiting to the QUIC connection without
/// waiting for one to arrive, and reports whether there was one.
pub fn readPacketIfAvailable(conn: *Connection) Error!bool {
    const n = posix.system.recvfrom(conn.socket, &conn.buf, conn.buf.len, std.c.MSG.DONTWAIT, null, null);
    if (n < 0) return false;
    try handlePacket(conn, conn.buf[0..@intCast(n)]);
    return true;
}

/// Takes up to `max_datagrams_per_drain` datagrams off the socket and feeds
/// them to the QUIC connection. An event loop calls this when `pollReadable`
/// reported the socket is readable.
pub fn readAvailablePackets(conn: *Connection) Error!usize {
    var read_count: usize = 0;
    while (read_count < max_datagrams_per_drain) {
        if (!try readPacketIfAvailable(conn)) break;
        read_count += 1;
    }
    return read_count;
}

/// Handles one datagram's worth of bytes that came off the socket.
fn handlePacket(conn: *Connection, data: []const u8) Error!void {
    const pkt = ngtcp2.ngtcp2_pkt_info{};
    // ngtcp2 wants the network path the packet arrived on; the connection's own
    // addresses are the only ones that fit for a connected UDP socket.
    const path: [*c]ngtcp2.ngtcp2_path = if (conn.path_alloc) |ps| &ps.path else null;
    const ret = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, path, &pkt, data.ptr, data.len, nowNanos());
    if (ret == 0) return;

    // The HTTP/3 layer found the error first: ngtcp2 only saw the callback
    // failing, and knows nothing of the HTTP/3 code that ended the connection.
    if (conn.stream_ctx_alloc) |ctx| {
        if (ctx.h3_error_code) |code| {
            sendConnectionClose(conn, .{ .application = code }, "http/3 connection error");
            return error.Http3Error;
        }
    }

    const err = classify(conn.conn, ret);
    if (err == error.TlsError) {
        // ngtcp2 keeps the alert for exactly this: RFC 9000 sends a TLS failure
        // to the peer as CRYPTO_ERROR carrying the alert.
        sendConnectionClose(conn, .{ .tls_alert = last_tls_failure.alert }, "tls error");
    }
    return err;
}

/// The longest `pollReadable` is allowed to wait. A connection with no timer
/// pending and a silent peer reports no deadline at all, and waiting for one
/// forever would leave whatever else the loop has to do undone.
const max_poll_wait_ns = 5 * std.time.ns_per_s;

/// Waits until the socket has a datagram to read or `timeout_ns` has passed,
/// and reports whether one is waiting.
///
/// This is what an event loop waits on instead of sleeping a fixed amount: a
/// connection knows exactly when it next has to do something (the QUIC timers
/// `getExpiry` reports), and until then the only thing that can change its
/// state is a datagram.
pub fn pollReadable(fd: posix.fd_t, timeout_ns: u64) bool {
    // poll() counts in whole milliseconds and rounds the wait up, which is also
    // what is wanted for a deadline that has already passed: asking for 0 there
    // would spin the loop.
    const wait = @min(timeout_ns, max_poll_wait_ns);
    const timeout_ms: i32 = @intCast((wait + std.time.ns_per_ms - 1) / std.time.ns_per_ms);
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    const ready = posix.poll(&fds, timeout_ms) catch return false;
    return ready > 0 and (fds[0].revents & posix.POLL.IN) != 0;
}

/// Nanoseconds until this connection's next QUIC timer is due, or null when it
/// has none pending. A timer that is already due is 0, so a loop that waits for
/// this long and then handles the timer does not wait at all in that case.
pub fn expiryDelayNs(conn: *Connection) ?u64 {
    const expiry = getExpiry(conn) orelse return null;
    const now = nowNanos();
    return if (expiry <= now) 0 else expiry - now;
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
        // A TLS failure can surface on the write side too (the handshake runs
        // from both), and ngtcp2.h makes every other negative return a
        // connection error just like on the read side.
        if (n < 0) return classify(conn.conn, @intCast(n));
        if (n == 0) return;
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
    if (@backingInt(rc) != 0) return error.QuicError;
    defer std.c.freeaddrinfo(res.?);

    const addr = res.?.addr orelse return error.QuicError;
    const in_addr: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
    return in_addr.addr;
}

/// How long `connect` drives the handshake before giving up: loopback needs a
/// couple of round trips, and a peer that has not answered within this many
/// poll rounds (each of which waits up to the socket's 100 ms read timeout) is
/// reported as `error.HandshakeTimeout` instead of being handed back as a
/// connection.
const handshake_attempts = 10;

/// Create a QUIC client connection and perform handshake over UDP. Returns only
/// once the handshake has completed; the failure modes are `error.TlsError` for
/// a TLS alert, whatever ngtcp2 reported for a broken connection, and
/// `error.HandshakeTimeout` for a handshake that never happened.
pub fn connect(host: []const u8, port: u16, stream_ctx: ?StreamDataCtx, _: ?[]const u8, tls: ClientTls) Error!Connection {
    // Literal addresses ("127.0.0.1") and names ("localhost") both work here;
    // a name that does not resolve is reported the same way as any other
    // failure to reach the peer.
    const server_ip = resolveHostIp(host, port) catch return error.QuicError;

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

    // Generate random connection IDs
    var dcid: ngtcp2.ngtcp2_cid = undefined;
    var scid: ngtcp2.ngtcp2_cid = undefined;
    dcid.datalen = 18;
    scid.datalen = 18;
    fillRandom(dcid.data[0..dcid.datalen]);
    fillRandom(scid.data[0..scid.datalen]);

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

    // Drive the handshake to completion. Every other outcome is a failed
    // connection attempt, not a connection: a TLS failure surfaces as
    // `error.TlsError` on the first read that hits it, a peer that closes or
    // breaks the connection reports what ngtcp2 saw, and a peer that never
    // answers leaves the handshake unfinished.
    try flushPackets(&self);
    for (0..handshake_attempts) |_| {
        // A read or write error is not transient: none of them can be retried
        // into a handshake (ngtcp2.h lists exactly what each one means).
        try readPacket(&self);
        try flushPackets(&self);
        if (ngtcp2.ngtcp2_conn_get_handshake_completed(self.conn) != 0) return self;
        sleepNs(10 * std.time.ns_per_ms);
    }

    return error.HandshakeTimeout;
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

/// Length of the secret stateless reset tokens are derived from. ngtcp2 only
/// fixes the length of the token itself (NGTCP2_STATELESS_RESET_TOKENLEN); this
/// matches the secret the reference server uses.
const stateless_reset_secret_len = 32;

/// Secret the stateless reset tokens this endpoint issues are derived from, and
/// the lock that keeps two threads from filling it at the same time: it belongs
/// to the endpoint rather than to one connection, and the client and the server
/// callback below share it.
var stateless_reset_secret: [stateless_reset_secret_len]u8 = @splat(0);
var stateless_reset_secret_ready = false;
var stateless_reset_secret_lock: std.atomic.Mutex = .unlocked;

fn statelessResetSecret() []const u8 {
    while (!stateless_reset_secret_lock.tryLock()) std.atomic.spinLoopHint();
    defer stateless_reset_secret_lock.unlock();
    if (!stateless_reset_secret_ready) {
        fillRandom(&stateless_reset_secret);
        stateless_reset_secret_ready = true;
    }
    return &stateless_reset_secret;
}

/// ngtcp2 get_new_connection_id callback — generates a connection ID of the
/// length ngtcp2 asked for together with the stateless reset token that goes
/// with it, and on the server registers the ID so datagrams addressed to it
/// reach the same connection.
pub fn getNewConnIdCb(
    _: ?*ngtcp2.ngtcp2_conn,
    cid: ?*ngtcp2.ngtcp2_cid,
    token: [*c]u8,
    cidlen: usize,
    user_data: ?*anyopaque,
) callconv(.c) c_int {
    const out = cid orelse return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE;
    // ngtcp2 rejects the connection ID it asked for unless it comes back with
    // exactly this length (ngtcp2_conn.c, conn_enqueue_new_connection_id).
    if (cidlen > out.data.len) return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE;
    out.datalen = cidlen;
    fillRandom(out.data[0..cidlen]);

    // RFC 9000: the peer can only end this connection with a stateless reset
    // whose token is derived from the connection ID it is using, so one has to
    // be issued alongside every connection ID.
    if (ngtcp2.ngtcp2_crypto_generate_stateless_reset_token(token, statelessResetSecret().ptr, stateless_reset_secret_len, out) != 0) {
        return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE;
    }

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
    fillRandom(dest[0..destlen]);
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
    callbacks.extend_max_stream_data = extendMaxStreamDataCb;
    callbacks.acked_stream_data_offset = ackedStreamDataOffsetCb;
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
    // Not one ngtcp2 demands, but without it nghttp3 never learns that sent
    // stream data was acknowledged, and so cannot reclaim it.
    try std.testing.expect(callbacks.acked_stream_data_offset != null);
    try std.testing.expect(callbacks.rand != null);
}

test "fillRandom: fills the whole buffer with bytes that change" {
    // A source that silently does nothing (which is what `std.c.arc4random_buf`
    // is on Linux for musl and glibc < 2.36) leaves the buffer as it was, and a
    // stuck source repeats itself: neither can pass this.
    var a: [64]u8 = @splat(0);
    var b: [64]u8 = @splat(0);
    fillRandom(&a);
    fillRandom(&b);

    try std.testing.expect(!std.mem.allEqual(u8, &a, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &b, 0));
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    // Every byte, not just the first: a partial fill leaves the tail untouched.
    try std.testing.expect(!std.mem.allEqual(u8, a[a.len / 2 ..], 0));

    var empty: [0]u8 = .{};
    fillRandom(&empty);
}

test "getNewConnIdCb: fills the requested CID length and its reset token" {
    // Deliberately not the length this endpoint uses for the connection IDs it
    // chooses: ngtcp2 hands down the length it wants back.
    const cidlen = 17;
    var cid: ngtcp2.ngtcp2_cid = undefined;
    var token: [ngtcp2.NGTCP2_STATELESS_RESET_TOKENLEN]u8 = @splat(0);
    try std.testing.expectEqual(0, getNewConnIdCb(null, &cid, &token, cidlen, null));

    try std.testing.expectEqual(@as(usize, cidlen), cid.datalen);
    try std.testing.expect(!std.mem.allEqual(u8, cid.data[0..cidlen], 0));

    // The token has to be the one derived from that connection ID, not whatever
    // the buffer the callback was given happened to hold.
    var expected: [ngtcp2.NGTCP2_STATELESS_RESET_TOKENLEN]u8 = undefined;
    try std.testing.expectEqual(0, ngtcp2.ngtcp2_crypto_generate_stateless_reset_token(&expected, statelessResetSecret().ptr, stateless_reset_secret_len, &cid));
    try std.testing.expectEqualSlices(u8, &expected, &token);
}

// Nothing is listening on this port, so the handshake never completes. That is
// a failed connection attempt, not a connection to hand back — and it is
// reported as exactly that instead of as an unreachable or broken peer. Sending
// the Initial reaches ngtcp2_crypto_client_initial_cb, which needs the
// connection's TLS native handle, before the attempt gives up.
test "connect: reports a handshake that never happened" {
    try std.testing.expectError(error.HandshakeTimeout, connect("127.0.0.1", 45454, null, null, .{ .insecure_skip_verify = true }));
}

// Test-only support: a real H3 server, on the other side of a real connection,
// for the mutual-TLS tests below.
const server_mod = @import("Server.zig");
const client_mod = @import("Client.zig");

/// Answers every request, so a mutual-TLS test only has to look at whether the
/// answer arrived.
fn okHandler(_: std.mem.Allocator, _: *const server_mod.Request) server_mod.Response {
    return .{ .body = "OK" };
}

fn serveH3(server: *server_mod.Server) void {
    server.run() catch {};
}

/// An H3 server on a background thread, with the port it bound read back, so a
/// test can take it down and free it rather than leave the thread behind.
const RunningServer = struct {
    server: *server_mod.Server,
    thread: std.Thread,
    allocator: std.mem.Allocator,

    fn start(allocator: std.mem.Allocator, handler: server_mod.Handler) !RunningServer {
        const server = try allocator.create(server_mod.Server);
        errdefer allocator.destroy(server);
        server.* = try server_mod.Server.init(allocator, 0, handler, .{});
        errdefer server.deinit();
        return .{
            .server = server,
            .thread = try std.Thread.spawn(.{}, serveH3, .{server}),
            .allocator = allocator,
        };
    }

    fn port(self: RunningServer) u16 {
        return std.mem.bigToNative(u16, self.server.listener.local_addr.port);
    }

    fn stop(self: RunningServer) void {
        self.server.stop();
        self.thread.join();
        self.server.deinit();
        self.allocator.destroy(self.server);
    }
};

/// The server context is process-wide, and `setClientCa` changes it for every
/// connection it creates from then on. `setServerCert` builds a fresh context,
/// so calling it again drops the client-certificate requirement and leaves the
/// rest of the test binary with plain server TLS.
fn resetServerTls() void {
    setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem")) catch {};
}

// The store the CA goes into lives with the server context, so a second CA
// installed on it has to be accepted: `X509_STORE_add_cert` reports a CA that is
// already there as a failure, and refusing it would make an endpoint that trusts
// more than one CA impossible to configure.
test "setClientCa: a CA that is already trusted is not an error" {
    defer resetServerTls();
    try setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));
    try setClientCa(@embedFile("test_cert.pem"));
    try setClientCa(@embedFile("test_cert.pem"));
}

test "quic: a server that asks for a client certificate serves one that has it" {
    const cert_pem = @embedFile("test_cert.pem");
    const key_pem = @embedFile("test_key.pem");
    defer resetServerTls();
    try setServerCert(cert_pem, key_pem);
    // The test certificate is self-signed with CA:TRUE and no key usage or
    // extended key usage, so one copy of it serves as the server's certificate,
    // as the client's certificate, and as the CA that verifies it.
    try setClientCa(cert_pem);

    const allocator = std.heap.page_allocator;
    const server = try RunningServer.start(allocator, okHandler);
    defer server.stop();

    var client = try client_mod.Client.init(allocator, "127.0.0.1", server.port(), .{
        .insecure_skip_verify = true,
        .auth = .{ .cert_pem = cert_pem, .key_pem = key_pem },
    });
    defer client.deinit();

    const body = try client.get("/");
    defer allocator.free(body);
    try std.testing.expectEqualStrings("OK", body);
}

test "quic: a server that asks for a client certificate refuses one without" {
    const cert_pem = @embedFile("test_cert.pem");
    defer resetServerTls();
    try setServerCert(cert_pem, @embedFile("test_key.pem"));
    try setClientCa(cert_pem);

    const allocator = std.heap.page_allocator;
    const server = try RunningServer.start(allocator, okHandler);
    defer server.stop();

    // The certificate goes out in the same flight as the client's Finished, and
    // the client's handshake is finished by then, so this succeeds: what the
    // server refuses is the connection, not the handshake this endpoint had
    // already completed before the server could see the certificate.
    var client = try client_mod.Client.init(allocator, "127.0.0.1", server.port(), .{ .insecure_skip_verify = true });
    defer client.deinit();

    // RFC 9001: a handshake that fails reaches the peer as a CONNECTION_CLOSE
    // whose CRYPTO_ERROR code carries the TLS alert. ngtcp2 reports that as the
    // draining state, so the request fails at once instead of waiting out its
    // own timeout for a response that cannot come.
    const start = nowNanos();
    try std.testing.expectError(error.ConnectionClosed, client.get("/"));
    const elapsed_ms = (nowNanos() - start) / std.time.ns_per_ms;
    try std.testing.expect(elapsed_ms < 5000);
}

// A client certificate that cannot be loaded is a failed connection attempt of
// its own: it is reported as the TLS error it is, before anything goes on the
// wire, and never as a handshake that ran out of time.
test "connect: a client certificate that does not load is a TLS error" {
    try std.testing.expectError(error.TlsError, connect("127.0.0.1", 45455, null, null, .{
        .insecure_skip_verify = true,
        .auth = .{ .cert_pem = "not a certificate", .key_pem = @embedFile("test_key.pem") },
    }));
    try std.testing.expectError(error.TlsError, connect("127.0.0.1", 45455, null, null, .{
        .insecure_skip_verify = true,
        .auth = .{ .cert_pem = @embedFile("test_cert.pem"), .key_pem = "not a key" },
    }));
}
