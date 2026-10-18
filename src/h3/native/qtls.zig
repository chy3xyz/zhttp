//! OpenSSL's QUIC-TLS callback interface, wrapped for a Zig QUIC transport.
//!
//! OpenSSL 3.6 exposes SSL_set_quic_tls_cbs: the TLS stack hands handshake
//! bytes and traffic secrets to the QUIC implementation instead of writing them
//! to a BIO. That is exactly the seam ngtcp2's ngtcp2_crypto_ossl backend uses,
//! and it is the seam this module implements directly so no C QUIC library is
//! needed.

const std = @import("std");

const c = @import("openssl_c");

// Keep the public type names stable for embedders; all C declarations live in
// the single hand-written bindings module (src/openssl_c.zig).
pub const SSL = c.SSL;
pub const SSL_CTX = c.SSL_CTX;
pub const SSL_METHOD = c.SSL_METHOD;
pub const BIO = c.BIO;
pub const X509 = c.X509;
pub const X509_STORE = c.X509_STORE;
pub const EVP_PKEY = c.EVP_PKEY;
pub const OSSL_DISPATCH = c.OSSL_DISPATCH;

pub const OPENSSL_NPN_NEGOTIATED = c.OPENSSL_NPN_NEGOTIATED;
pub const SSL_TLSEXT_ERR_OK = c.SSL_TLSEXT_ERR_OK;
pub const SSL_TLSEXT_ERR_ALERT_FATAL = c.SSL_TLSEXT_ERR_ALERT_FATAL;
pub const SSL_VERIFY_NONE = c.SSL_VERIFY_NONE;
pub const SSL_VERIFY_PEER = c.SSL_VERIFY_PEER;
pub const SSL_VERIFY_FAIL_IF_NO_PEER_CERT = c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

const TLS_client_method = c.TLS_client_method;
const TLS_server_method = c.TLS_server_method;
const SSL_CTX_new = c.SSL_CTX_new;
const SSL_CTX_up_ref = c.SSL_CTX_up_ref;
const SSL_CTX_free = c.SSL_CTX_free;
const SSL_CTX_set_verify = c.SSL_CTX_set_verify;
const SSL_CTX_set_default_verify_paths = c.SSL_CTX_set_default_verify_paths;
const SSL_CTX_set_ciphersuites = c.SSL_CTX_set_ciphersuites;
const SSL_CTX_use_certificate = c.SSL_CTX_use_certificate;
const SSL_CTX_use_PrivateKey = c.SSL_CTX_use_PrivateKey;
const SSL_CTX_check_private_key = c.SSL_CTX_check_private_key;
const SSL_CTX_set_alpn_select_cb = c.SSL_CTX_set_alpn_select_cb;
const SSL_CTX_get_cert_store = c.SSL_CTX_get_cert_store;
const X509_STORE_add_cert = c.X509_STORE_add_cert;
const SSL_select_next_proto = c.SSL_select_next_proto;
const SSL_new = c.SSL_new;
const SSL_free = c.SSL_free;
const SSL_set_connect_state = c.SSL_set_connect_state;
const SSL_set_accept_state = c.SSL_set_accept_state;
const SSL_set1_host = c.SSL_set1_host;
const SSL_set_alpn_protos = c.SSL_set_alpn_protos;
const SSL_do_handshake = c.SSL_do_handshake;
const SSL_get_error = c.SSL_get_error;
const SSL_get_verify_result = c.SSL_get_verify_result;
const SSL_is_init_finished = c.SSL_is_init_finished;
const SSL_set_ex_data = c.SSL_set_ex_data;
const SSL_get_ex_data = c.SSL_get_ex_data;
const SSL_set_quic_tls_cbs = c.SSL_set_quic_tls_cbs;
const SSL_set_quic_tls_transport_params = c.SSL_set_quic_tls_transport_params;
const SSL_ctrl = c.SSL_ctrl;
const RAND_bytes = c.RAND_bytes;
const BIO_new_mem_buf = c.BIO_new_mem_buf;
const BIO_free = c.BIO_free;
const X509_free = c.X509_free;
const EVP_PKEY_free = c.EVP_PKEY_free;
const PEM_read_bio_X509 = c.PEM_read_bio_X509;
const PEM_read_bio_PrivateKey = c.PEM_read_bio_PrivateKey;
const SSL_CTRL_SET_TLSEXT_HOSTNAME = c.SSL_CTRL_SET_TLSEXT_HOSTNAME;
const TLSEXT_NAMETYPE_host_name = c.TLSEXT_NAMETYPE_host_name;

pub const Error = error{
    TlsError,
    TlsAlert,
    CertificateVerifyFailed,
    OutOfMemory,
};

pub const level_count = 4;

/// TLS traffic-secret slots, indexed by OpenSSL record protection level:
/// 0 = Initial, 1 = Early, 2 = Handshake, 3 = Application.
pub const SecretSet = struct {
    local: ?[32]u8 = null,
    remote: ?[32]u8 = null,

    pub fn complete(self: *const SecretSet) bool {
        return self.local != null and self.remote != null;
    }
};

pub const ClientTls = struct {
    /// Verify the peer against the system CA store. False is for local
    /// development and tests only.
    insecure_skip_verify: bool = false,
    /// Optional client certificate for mutual TLS.
    cert_pem: ?[]const u8 = null,
    key_pem: ?[]const u8 = null,
    /// Initial transport flow-control window advertised to the server, in
    /// bytes. The default matches the transport's 16 MiB receive window.
    initial_max_data: u64 = 16 * 1024 * 1024,
    /// Initial per-stream flow-control window advertised to the server.
    initial_max_stream_data: u64 = 16 * 1024 * 1024,
};

/// Server certificate loaded once by setServerCert.
var server_ctx: ?*SSL_CTX = null;

/// Load the certificate and key used by every server connection. Call this
/// before accepting connections: replacing the context frees the one existing
/// connections still reference.
pub fn setServerCert(cert_pem: []const u8, key_pem: []const u8) Error!void {
    if (server_ctx) |old| {
        SSL_CTX_free(old);
        server_ctx = null;
    }
    const ctx = SSL_CTX_new(TLS_server_method()) orelse return error.TlsError;
    errdefer SSL_CTX_free(ctx);
    try loadCert(ctx, cert_pem, key_pem);
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") != 1) return error.TlsError;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, null);
    SSL_CTX_set_alpn_select_cb(ctx, alpnSelectH3, null);
    server_ctx = ctx;
}

/// Require a client certificate verified against `ca_pem` on every subsequent
/// server connection. Call after `setServerCert` and before accepting.
pub fn setClientCa(ca_pem: []const u8) Error!void {
    const ctx = server_ctx orelse return error.TlsError;
    const bio = BIO_new_mem_buf(ca_pem.ptr, @intCast(ca_pem.len)) orelse return error.TlsError;
    defer _ = BIO_free(bio);
    const ca = PEM_read_bio_X509(bio, null, null, null) orelse return error.TlsError;
    defer X509_free(ca);
    const store = SSL_CTX_get_cert_store(ctx) orelse return error.TlsError;
    // A CA already in the store is reported as failure; that is the desired
    // state, so the return value is deliberately not fatal here.
    _ = X509_STORE_add_cert(store, ca);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null);
}

pub fn deinitServer() void {
    if (server_ctx) |ctx| {
        SSL_CTX_free(ctx);
        server_ctx = null;
    }
}

pub fn fillRandom(buf: []u8) void {
    if (buf.len == 0) return;
    if (RAND_bytes(buf.ptr, @intCast(buf.len)) != 1) @panic("OpenSSL RAND_bytes failed");
}

fn loadCert(ctx: *SSL_CTX, cert_pem: []const u8, key_pem: []const u8) Error!void {
    const cert_bio = BIO_new_mem_buf(cert_pem.ptr, @intCast(cert_pem.len)) orelse return error.TlsError;
    defer _ = BIO_free(cert_bio);
    const x509 = PEM_read_bio_X509(cert_bio, null, null, null) orelse return error.TlsError;
    defer X509_free(x509);
    if (SSL_CTX_use_certificate(ctx, x509) != 1) return error.TlsError;

    const key_bio = BIO_new_mem_buf(key_pem.ptr, @intCast(key_pem.len)) orelse return error.TlsError;
    defer _ = BIO_free(key_bio);
    const pkey = PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse return error.TlsError;
    defer EVP_PKEY_free(pkey);
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) return error.TlsError;
    if (SSL_CTX_check_private_key(ctx) != 1) return error.TlsError;
}

fn alpnSelectH3(
    _: ?*SSL,
    out: [*c][*c]const u8,
    outlen: [*c]u8,
    in: [*c]const u8,
    inlen: c_uint,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const h3 = "\x02h3";
    const ret = SSL_select_next_proto(
        @ptrCast(@constCast(out)),
        outlen,
        h3,
        h3.len,
        in,
        inlen,
    );
    if (ret == OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

pub const Tls = struct {
    allocator: std.mem.Allocator,
    ssl: ?*SSL,
    ctx: ?*SSL_CTX,
    owns_ctx: bool,
    bridge: Bridge,

    pub fn initClient(
        allocator: std.mem.Allocator,
        host: []const u8,
        params: []const u8,
        options: ClientTls,
    ) Error!*Tls {
        const ctx = SSL_CTX_new(TLS_client_method()) orelse return error.TlsError;
        errdefer SSL_CTX_free(ctx);
        _ = SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
        if (options.insecure_skip_verify) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, null);
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, null);
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) return error.TlsError;
        }
        if (options.cert_pem) |cert| {
            if (options.key_pem) |key| try loadCert(ctx, cert, key);
        }

        const ssl = SSL_new(ctx) orelse return error.TlsError;
        errdefer SSL_free(ssl);
        SSL_set_connect_state(ssl);
        if (SSL_set_alpn_protos(ssl, "\x02h3", 3) != 0) return error.TlsError;
        if (!options.insecure_skip_verify and host.len > 0) {
            const zhost = allocator.allocSentinel(u8, host.len, 0) catch return error.OutOfMemory;
            defer allocator.free(zhost);
            @memcpy(zhost[0..host.len], host);
            if (SSL_set1_host(ssl, zhost.ptr) != 1) return error.TlsError;
        }

        const self = allocator.create(Tls) catch return error.OutOfMemory;
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .ssl = ssl,
            .ctx = ctx,
            .owns_ctx = true,
            .bridge = .{ .allocator = allocator },
        };
        errdefer self.bridge.deinit();
        try self.configure(host, params);
        return self;
    }

    pub fn initServer(allocator: std.mem.Allocator, params: []const u8) Error!*Tls {
        const ctx = server_ctx orelse return error.TlsError;
        // Take a reference so a later setServerCert() can replace the global
        // context without invalidating connections that are still handshaking.
        if (SSL_CTX_up_ref(ctx) != 1) return error.TlsError;
        errdefer SSL_CTX_free(ctx);
        const ssl = SSL_new(ctx) orelse return error.TlsError;
        errdefer SSL_free(ssl);
        SSL_set_accept_state(ssl);

        const self = allocator.create(Tls) catch return error.OutOfMemory;
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .ssl = ssl,
            .ctx = ctx,
            .owns_ctx = true,
            .bridge = .{ .allocator = allocator },
        };
        errdefer self.bridge.deinit();
        try self.configure(null, params);
        return self;
    }

    fn configure(self: *Tls, host: ?[]const u8, params: []const u8) Error!void {
        if (SSL_set_quic_tls_cbs(self.ssl, &qtdis, null) != 1) return error.TlsError;
        if (SSL_set_quic_tls_transport_params(self.ssl, params.ptr, params.len) != 1) return error.TlsError;
        if (SSL_set_ex_data(self.ssl, 0, @ptrCast(self)) != 1) return error.TlsError;
        if (host) |name| {
            if (name.len > 0) {
                const zname = self.allocator.allocSentinel(u8, name.len, 0) catch return error.OutOfMemory;
                defer self.allocator.free(zname);
                @memcpy(zname[0..name.len], name);
                if (SSL_ctrl(self.ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, @ptrCast(zname.ptr)) != 1) {
                    return error.TlsError;
                }
            }
        }
    }

    pub fn destroy(self: *Tls) void {
        const allocator = self.allocator;
        self.deinit();
        allocator.destroy(self);
    }

    pub fn deinit(self: *Tls) void {
        if (self.ssl) |ssl| {
            _ = SSL_set_ex_data(ssl, 0, null);
            SSL_free(ssl);
            self.ssl = null;
        }
        self.bridge.deinit();
        if (self.owns_ctx) {
            if (self.ctx) |ctx| {
                SSL_CTX_free(ctx);
                self.ctx = null;
            }
        }
    }

    /// Hand received CRYPTO bytes to TLS at their QUIC encryption level.
    /// CRYPTO streams are ordered per level; the bridge hands OpenSSL one level
    /// at a time so a coalesced Initial+Handshake flight is not mistaken for a
    /// single TLS record stream.
    pub fn pushCrypto(self: *Tls, level: usize, data: []const u8) Error!void {
        if (level >= level_count) return;
        self.bridge.rx[level].appendSlice(self.allocator, data) catch return error.OutOfMemory;
    }

    /// Run the TLS state machine. Call after pushCrypto and once at start.
    pub fn drive(self: *Tls) Error!void {
        const ret = SSL_do_handshake(self.ssl);
        if (ret == 1) return;
        const err = SSL_get_error(self.ssl, ret);
        switch (err) {
            c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => {},
            else => {
                std.log.debug("qtls: SSL_do_handshake failed ssl_err={} alert={}", .{ err, self.bridge.alert });
                if (self.bridge.alert >= 0) return error.TlsAlert;
                if (SSL_get_verify_result(self.ssl) != 0) return error.CertificateVerifyFailed;
                return error.TlsError;
            },
        }
    }

    pub fn isFinished(self: *const Tls) bool {
        return SSL_is_init_finished(self.ssl) == 1;
    }

    pub fn peerParams(self: *const Tls) []const u8 {
        return self.bridge.peer_params.items;
    }

    /// Take the handshake bytes TLS produced at the given encryption level.
    pub fn takeOut(self: *Tls, level: usize) []const u8 {
        return self.bridge.takeOut(level);
    }

    pub fn clearOut(self: *Tls, level: usize) void {
        self.bridge.clearOut(level);
    }

    /// Take the traffic secrets learned so far, clearing them.
    pub fn takeSecrets(self: *Tls, level: usize) SecretSet {
        if (level >= level_count) return .{};
        const result = self.bridge.secrets[level];
        self.bridge.secrets[level] = .{};
        return result;
    }

    pub fn alert(self: *const Tls) c_int {
        return self.bridge.alert;
    }
};

pub const Bridge = struct {
    rx: [level_count]std.ArrayListUnmanaged(u8) = .{ .empty, .empty, .empty, .empty },
    rx_pos: [level_count]usize = .{ 0, 0, 0, 0 },
    tx: [level_count]std.ArrayListUnmanaged(u8) = .{ .empty, .empty, .empty, .empty },
    secrets: [level_count]SecretSet = .{ .{}, .{}, .{}, .{} },
    peer_params: std.ArrayListUnmanaged(u8) = .empty,
    alert: c_int = -1,
    tx_level: usize = 0,
    last_rx_level: usize = 0,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Bridge) void {
        for (&self.rx) |*slot| slot.deinit(self.allocator);
        for (&self.tx) |*slot| slot.deinit(self.allocator);
        self.peer_params.deinit(self.allocator);
    }

    fn takeOut(self: *Bridge, level: usize) []const u8 {
        if (level >= level_count) return &.{};
        return self.tx[level].items;
    }

    fn clearOut(self: *Bridge, level: usize) void {
        if (level >= level_count) return;
        self.tx[level].clearRetainingCapacity();
    }
};

fn bridgeFrom(ssl: ?*SSL) ?*Bridge {
    const tls: *Tls = @ptrCast(@alignCast(SSL_get_ex_data(ssl, 0) orelse return null));
    return &tls.bridge;
}

fn cryptoSend(ssl: ?*SSL, buf: [*c]const u8, len: usize, consumed: *usize, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const bridge = bridgeFrom(ssl) orelse return 1;
    const level = @min(bridge.tx_level, level_count - 1);
    bridge.tx[level].appendSlice(bridge.allocator, buf[0..len]) catch return 0;
    consumed.* = len;
    return 1;
}

fn cryptoRecv(ssl: ?*SSL, buf: *[*c]const u8, bytes_read: *usize, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const bridge = bridgeFrom(ssl) orelse return 1;
    var level: usize = 0;
    while (level < level_count) : (level += 1) {
        if (bridge.rx_pos[level] < bridge.rx[level].items.len) break;
    }
    if (level == level_count) {
        buf.* = null;
        bytes_read.* = 0;
        return 1;
    }
    bridge.last_rx_level = level;
    buf.* = bridge.rx[level].items.ptr + bridge.rx_pos[level];
    bytes_read.* = bridge.rx[level].items.len - bridge.rx_pos[level];
    return 1;
}

fn cryptoRelease(ssl: ?*SSL, released: usize, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const bridge = bridgeFrom(ssl) orelse return 1;
    const level = bridge.last_rx_level;
    if (level >= level_count) return 1;
    bridge.rx_pos[level] += released;
    if (bridge.rx_pos[level] >= bridge.rx[level].items.len) {
        bridge.rx[level].clearRetainingCapacity();
        bridge.rx_pos[level] = 0;
    }
    return 1;
}

fn yieldSecret(
    ssl: ?*SSL,
    prot_level: u32,
    direction: c_int,
    secret: [*c]const u8,
    secret_len: usize,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    _ = arg;
    const bridge = bridgeFrom(ssl) orelse return 1;
    const level: usize = @intCast(prot_level);
    if (level >= level_count) return 1;
    if (secret_len != 32) return 0;
    var copy: [32]u8 = undefined;
    @memcpy(&copy, secret[0..32]);
    if (direction != 0) {
        bridge.secrets[level].local = copy;
        bridge.tx_level = level;
    } else {
        bridge.secrets[level].remote = copy;
    }
    return 1;
}

fn gotTransportParams(ssl: ?*SSL, params: [*c]const u8, len: usize, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const bridge = bridgeFrom(ssl) orelse return 1;
    bridge.peer_params.clearRetainingCapacity();
    bridge.peer_params.appendSlice(bridge.allocator, params[0..len]) catch return 0;
    return 1;
}

fn alertCb(ssl: ?*SSL, code: u8, arg: ?*anyopaque) callconv(.c) c_int {
    _ = arg;
    const bridge = bridgeFrom(ssl) orelse return 1;
    bridge.alert = code;
    return 1;
}

const qtdis = [_]OSSL_DISPATCH{
    .{ .function_id = 2001, .function = @ptrCast(&cryptoSend) },
    .{ .function_id = 2002, .function = @ptrCast(&cryptoRecv) },
    .{ .function_id = 2003, .function = @ptrCast(&cryptoRelease) },
    .{ .function_id = 2004, .function = @ptrCast(&yieldSecret) },
    .{ .function_id = 2005, .function = @ptrCast(&gotTransportParams) },
    .{ .function_id = 2006, .function = @ptrCast(&alertCb) },
    .{ .function_id = 0, .function = null },
};
