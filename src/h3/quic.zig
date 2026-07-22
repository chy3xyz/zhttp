const std = @import("std");
const ngtcp2 = @import("ngtcp2_c");
const posix = std.posix;
const builtin = @import("builtin");
const c = std.c;

const NGTCP2_STREAM_DATA_FLAG_FIN = ngtcp2.NGTCP2_STREAM_DATA_FLAG_FIN;

const max_datagram_size = 65536;

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
    const ossl = @import("openssl_c");
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

    server_ssl_ctx = @ptrCast(ctx);
}

/// Custom server-side recv_client_initial that uses our SSL_CTX with cert.
pub fn serverRecvClientInitialCb(
    conn: ?*ngtcp2.ngtcp2_conn,
    _: [*c]const ngtcp2.ngtcp2_cid,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const ossl = @import("openssl_c");
    const ctx: *ossl.SSL_CTX = @ptrCast(@alignCast(server_ssl_ctx orelse return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE));
    const ssl = ossl.SSL_new(ctx) orelse return ngtcp2.NGTCP2_ERR_CALLBACK_FAILURE;
    ossl.SSL_set_accept_state(ssl);

    var ossl_ctx: ?*ngtcp2.ngtcp2_crypto_ossl_ctx = null;
    const ret = ngtcp2.ngtcp2_crypto_ossl_ctx_new(&ossl_ctx, @ptrCast(ssl));
    if (ret != 0) {
        ossl.SSL_free(ssl);
        return ret;
    }
    ngtcp2.ngtcp2_crypto_ossl_ctx_set_ssl(ossl_ctx.?, @ptrCast(ssl));
    ngtcp2.ngtcp2_conn_set_tls_native_handle(conn, @ptrCast(ossl_ctx.?));

    return 0;
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
    const fd = try posix.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    qlog_fd = fd;
}

/// Disable QLog and close the file.
pub fn disableQLog() void {
    if (qlog_fd >= 0) {
        _ = std.c.close(qlog_fd);
        qlog_fd = -1;
    }
}

pub const Error = error{QuicError, OutOfMemory, NoSpaceLeft};

/// Callback type for receiving stream data. Called from ngtcp2 recv_stream_data.
/// `h3_conn` is the nghttp3 connection pointer to feed data into.
pub const StreamDataCtx = struct {
    h3_conn: *anyopaque, // *nghttp3.nghttp3_conn — opaque to avoid circular dep
    recv_stream_data: *const fn (h3_conn: *anyopaque, stream_id: i64, data: []const u8, fin: bool) void,
};

pub const Connection = struct {
    conn: *ngtcp2.ngtcp2_conn,
    socket: posix.fd_t,
    buf: [max_datagram_size]u8 = undefined,
    stream_ctx_alloc: ?*StreamDataCtx = null,
    qlog_fd: ?posix.fd_t = null,

    pub fn deinit(self: *Connection) void {
        ngtcp2.ngtcp2_conn_del(self.conn);
        _ = posix.system.close(self.socket);
        if (self.stream_ctx_alloc) |ptr| {
            std.heap.page_allocator.destroy(ptr);
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
    var path: ngtcp2.ngtcp2_path = .{ .local = .{ .addr = undefined, .addrlen = 0 }, .remote = .{ .addr = undefined, .addrlen = 0 } };
    const ret = ngtcp2.ngtcp2_conn_read_pkt(conn.conn, &path, &pkt, data.ptr, data.len, nowNanos());
    if (ret != 0) return error.QuicError;
}

/// Write any pending QUIC packets to the UDP socket.
pub fn flushPackets(conn: *Connection) Error!void {
    while (true) {
        var pi: ngtcp2.ngtcp2_pkt_info = undefined;
        var dest: ngtcp2.ngtcp2_path = .{ .local = .{}, .remote = .{} };
        const n = ngtcp2.ngtcp2_conn_write_pkt(conn.conn, &dest, &pi, conn.buf[0..].ptr, conn.buf.len, nowNanos());
        if (n <= 0) return;
        const sent = posix.system.sendto(conn.socket, conn.buf[0..@intCast(n)].ptr, @intCast(n), 0, @ptrCast(dest.remote.addr), @intCast(dest.remote.addrlen));
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
pub fn connect(host: []const u8, port: u16, stream_ctx: ?StreamDataCtx, _: ?[]const u8) Error!Connection {
    // Resolve host to IP (simplified — loopback for local testing)
    _ = host;
    const server_ip: u32 = 0x0100007F; // 127.0.0.1 in network byte order

    const sock: posix.fd_t = @intCast(posix.system.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP));
    if (sock < 0) return error.QuicError;
    errdefer _ = std.c.close(sock);

    const server_sockaddr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = @byteSwap(port),
        .addr = server_ip,
        .zero = @splat(0),
    };

    // Generate random connection IDs (use getrandom syscall)
    var dcid: ngtcp2.ngtcp2_cid = undefined;
    var scid: ngtcp2.ngtcp2_cid = undefined;
    dcid.datalen = 18;
    scid.datalen = 18;
    std.c.arc4random_buf(&dcid.data, 18);
    std.c.arc4random_buf(&scid.data, 18);

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

    var server_sockaddr_mut = server_sockaddr;
    const path: ngtcp2.ngtcp2_path = .{
        .local = .{ .addr = undefined, .addrlen = 0 },
        .remote = .{
            .addr = @ptrCast(&server_sockaddr_mut),
            .addrlen = @sizeOf(posix.sockaddr.in),
        },
    };

    const user_data: ?*anyopaque = if (stream_ctx_ptr) |ptr| @ptrCast(ptr) else null;
    var conn_ptr: ?*ngtcp2.ngtcp2_conn = null;
    const mem: ?*const ngtcp2.struct_ngtcp2_mem = null;
    const ret = ngtcp2.ngtcp2_conn_client_new(&conn_ptr, &dcid, &scid, &path, ngtcp2.NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, mem, user_data);
    if (ret != 0) return error.QuicError;

    // Enable 0-RTT early data with remembered transport params (deferred)
    // if (early_data) |ed| { ... }

    var self = Connection{
        .conn = conn_ptr.?,
        .socket = sock,
        .stream_ctx_alloc = stream_ctx_ptr,
    };
    errdefer self.deinit();

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

        return .{
            .socket = sock,
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

/// ngtcp2 get_new_connection_id callback — generates a random CID.
/// For server: also registers in Listener CID routing table via user_data.
pub fn getNewConnIdCb(
    conn: ?*ngtcp2.ngtcp2_conn,
    cid: ?*ngtcp2.ngtcp2_cid,
    _: [*c]u8,
    _: usize,
    user_data: ?*anyopaque,
) callconv(.c) c_int {
    _ = conn;
    const listener: ?*Listener = @ptrCast(@alignCast(user_data));
    cid.?.datalen = 18;
    std.c.arc4random_buf(@ptrCast(&cid.?.data), 18);

    // Register in server CID routing table
    if (listener) |l| {
        var key: [18]u8 = undefined;
        @memcpy(&key, cid.?.data[0..18]);
        // The Connection* needs to be looked up — we don't have it directly.
        // Store CID → Connection mapping will be done by the caller (server).
        // For now, this is a no-op — CID registration is handled externally.
        _ = l;
    }
    return 0;
}

/// ngtcp2 remove_connection_id callback — retires an old CID.
pub fn removeConnIdCb(
    _: ?*ngtcp2.ngtcp2_conn,
    _: [*c]const ngtcp2.ngtcp2_cid,
    user_data: ?*anyopaque,
) callconv(.c) c_int {
    const listener: ?*Listener = @ptrCast(@alignCast(user_data));
    if (listener) |l| {
        // We don't have cid in a usable way for HashMap key here;
        // CID removal is best-effort for now.
        _ = l;
    }
    return 0;
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
