/// OpenSSL TLS wrapper providing the same interface as the previous tls.zig module.
///
/// Uses the system OpenSSL library (libssl + libcrypto) for TLS operations.
/// OpenSSL works directly with socket file descriptors via SSL_set_fd(),
/// and this module wraps SSL_read/SSL_write into Zig's std.Io.Reader/Writer
/// interfaces for seamless integration with the HTTP layer.
const std = @import("std");
const Io = std.Io;
const mem = std.mem;
const posix = std.posix;

pub const c = @import("openssl_c");

const Mutex = std.atomic.Mutex;

/// Buffer sizes matching TLS record sizes. These are kept for API
/// compatibility — they size the Io.Reader/Writer buffers, not
/// OpenSSL's internal buffers.
pub const input_buffer_len = 16645;
pub const output_buffer_len = 16469;

// SSL_set_tlsext_host_name is a C macro — replicate its constant here.
const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
const TLSEXT_NAMETYPE_host_name: c_long = 0;

// SSL_CTX_set_tlsext_servername_callback is a C macro — use the underlying ctrl constant.
const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB_ARG: c_int = 54;

pub const config = struct {
    pub const cert = struct {
        pub const Bundle = enum {
            /// Skip server certificate verification.
            empty,
            /// Use the system default CA certificate store.
            system,
        };
    };

    pub const CertKeyPair = struct {
        cert_pem: []const u8,
        key_pem: []const u8,
        allocator: std.mem.Allocator,

        /// Read certificate and key files into memory.
        pub fn fromFilePath(
            allocator: std.mem.Allocator,
            io: Io,
            dir: Io.Dir,
            cert_name: []const u8,
            key_name: []const u8,
        ) !CertKeyPair {
            const cert_pem = try readFileAlloc(allocator, io, dir, cert_name);
            errdefer allocator.free(cert_pem);
            const key_pem = try readFileAlloc(allocator, io, dir, key_name);
            return .{
                .cert_pem = cert_pem,
                .key_pem = key_pem,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *CertKeyPair, _: std.mem.Allocator) void {
            self.allocator.free(self.cert_pem);
            self.allocator.free(self.key_pem);
        }

        fn readFileAlloc(allocator: std.mem.Allocator, io: Io, dir: Io.Dir, name: []const u8) ![]const u8 {
            const file = dir.openFile(io, name, .{}) catch return error.InvalidCertificate;
            defer file.close(io);

            // PEM cert/key files are typically under 8KB
            const max_pem_size = 32768;
            const result_buf = allocator.alloc(u8, max_pem_size) catch return error.InvalidCertificate;
            errdefer allocator.free(result_buf);

            var io_buf: [4096]u8 = undefined;
            var rdr = file.reader(io, &io_buf);
            var total: usize = 0;

            // Read one byte at a time using readSliceAll
            while (total < max_pem_size) {
                rdr.interface.readSliceAll(result_buf[total..][0..1]) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return error.InvalidCertificate,
                };
                total += 1;
            }

            if (total == 0) return error.InvalidCertificate;

            // Copy to exact-size buffer
            const exact = allocator.alloc(u8, total) catch return error.InvalidCertificate;
            @memcpy(exact, result_buf[0..total]);
            allocator.free(result_buf);
            return exact;
        }
    };

    pub const Client = struct {
        host: []const u8,
        root_ca: cert.Bundle = .system,
        /// Client certificate & private key for mTLS (Mutual TLS authentication).
        auth: ?*const CertKeyPair = null,
        /// Alias for `auth` for client certificate keypair.
        cert: ?*const CertKeyPair = null,
        insecure_skip_verify: bool = false,
        /// When true, only advertise http/1.1 via ALPN (skip h2).
        disable_h2: bool = false,
    };

    pub const Server = struct {
        auth: ?*const CertKeyPair = null,
        /// ALPN protocol names supported by the server, in preference order.
        alpn_protocols: []const []const u8 = &.{},
        /// SNI context for per-domain certificate selection.
        /// When set, uses a shared SSL_CTX with an SNI callback instead of
        /// creating a new SSL_CTX per connection.
        sni_context: ?*SniContext = null,
    };
};

pub const ConnectionError = error{
    TlsAlert,
    EndOfStream,
    WouldBlock,
    ReadFailed,
};

pub const Connection = struct {
    ssl: *c.SSL,
    ctx: *c.SSL_CTX,
    /// ALPN protocol negotiated during TLS handshake (e.g., "h2", "http/1.1").
    alpn_protocol: ?[]const u8 = null,
    /// Whether this connection owns (and should free) its SSL_CTX.
    /// False when using a shared SniContext.
    owns_ctx: bool = true,
    /// Read buffer — must outlive the returned slice from next().
    read_buf: [16384]u8 = undefined,

    /// Returns next chunk of cleartext data, or null on end of stream.
    pub fn next(conn: *Connection) ConnectionError!?[]const u8 {
        const ret = c.SSL_read(conn.ssl, &conn.read_buf, @intCast(conn.read_buf.len));
        if (ret <= 0) {
            const err = c.SSL_get_error(conn.ssl, ret);
            if (err == c.SSL_ERROR_ZERO_RETURN) return null;
            return sslToError(err);
        }
        const n: usize = @intCast(ret);
        return conn.read_buf[0..n];
    }

    /// Encrypt and write all data to the underlying connection.
    pub fn writeAll(conn: *Connection, data: []const u8) ConnectionError!void {
        var offset: usize = 0;
        while (offset < data.len) {
            const remaining = data.len - offset;
            const chunk: c_int = @intCast(@min(remaining, 16384));
            const ret = c.SSL_write(conn.ssl, @ptrCast(data.ptr + offset), chunk);
            if (ret <= 0) {
                const err = c.SSL_get_error(conn.ssl, ret);
                return sslToError(err);
            }
            offset += @intCast(ret);
        }
    }

    /// Read decrypted data into the provided buffer.
    pub fn read(conn: *Connection, buf: []u8) ConnectionError!usize {
        if (buf.len == 0) return 0;
        const ret = c.SSL_read(conn.ssl, @ptrCast(buf.ptr), @intCast(@min(buf.len, 16384)));
        if (ret <= 0) {
            const err = c.SSL_get_error(conn.ssl, ret);
            if (err == c.SSL_ERROR_ZERO_RETURN) return error.EndOfStream;
            return sslToError(err);
        }
        return @intCast(ret);
    }

    /// Gracefully close the TLS connection.
    pub fn close(conn: *Connection) !void {
        _ = c.SSL_shutdown(conn.ssl);
    }

    /// Free the SSL object and, if owned, the SSL_CTX.
    pub fn deinit(conn: *Connection) void {
        c.SSL_free(conn.ssl);
        if (conn.owns_ctx) {
            c.SSL_CTX_free(conn.ctx);
        }
    }

    // -- Io.Reader interface --

    pub const Reader = struct {
        conn: *Connection,
        interface: Io.Reader,
        err: ?anyerror = null,

        pub fn init(conn_ptr: *Connection, buffer: []u8) Reader {
            return .{
                .conn = conn_ptr,
                .interface = .{
                    .vtable = &.{
                        .stream = streamImpl,
                    },
                    .buffer = buffer,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn streamImpl(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            const self: *Reader = @fieldParentPtr("interface", r);
            const buf = limit.slice(try w.writableSliceGreedy(1));
            const n = self.conn.read(buf) catch |err| {
                self.err = err;
                if (err == error.EndOfStream) return error.EndOfStream;
                return error.ReadFailed;
            };
            if (n == 0) return error.EndOfStream;
            w.advance(n);
            return n;
        }
    };

    pub fn reader(conn: *Connection, buffer: []u8) Reader {
        return Reader.init(conn, buffer);
    }

    // -- Io.Writer interface --

    pub const Writer = struct {
        conn: *Connection,
        interface: Io.Writer,
        err: ?anyerror = null,

        pub fn init(conn_ptr: *Connection, buffer: []u8) Writer {
            return .{
                .conn = conn_ptr,
                .interface = .{
                    .vtable = &.{
                        .drain = drainImpl,
                    },
                    .buffer = buffer,
                    .end = 0,
                },
            };
        }

        fn drainImpl(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
            const self: *Writer = @fieldParentPtr("interface", w);
            // Flush buffered data first
            self.writeAllBytes(w.buffered()) catch return error.WriteFailed;
            w.end = 0;

            if (data.len == 0) return 0;
            var n: usize = 0;
            for (data[0 .. data.len - 1]) |bytes| {
                self.writeAllBytes(bytes) catch return error.WriteFailed;
                n += bytes.len;
            }
            const pattern = data[data.len - 1];
            for (0..splat) |_| {
                self.writeAllBytes(pattern) catch return error.WriteFailed;
                n += pattern.len;
            }
            return n;
        }

        fn writeAllBytes(self: *Writer, bytes: []const u8) !void {
            self.conn.writeAll(bytes) catch |err| {
                self.err = err;
                return error.WriteFailed;
            };
        }
    };

    pub fn writer(conn: *Connection, buffer: []u8) Writer {
        return Writer.init(conn, buffer);
    }
};

/// Perform a TLS client handshake on the given socket fd.
pub fn client(fd: posix.fd_t, opts: config.Client) !Connection {
    const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TlsHandshakeFailure;
    errdefer c.SSL_CTX_free(ctx);

    // Certificate verification
    if (opts.insecure_skip_verify) {
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
    } else {
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);
        switch (opts.root_ca) {
            .system => {
                if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) {
                    return error.TlsHandshakeFailure;
                }
            },
            .empty => {
                c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_NONE, null);
            },
        }
    }

    // Client certificate & key for mTLS (Mutual TLS)
    const client_auth = opts.auth orelse opts.cert;
    if (client_auth) |auth| {
        try loadCertIntoCtx(ctx, auth.cert_pem, auth.key_pem);
    }

    // ALPN: advertise http/1.1 (and optionally h2)
    if (opts.disable_h2) {
        const alpn = "\x08http/1.1";
        _ = c.SSL_CTX_set_alpn_protos(ctx, alpn, alpn.len);
    } else {
        const alpn = "\x02h2\x08http/1.1";
        _ = c.SSL_CTX_set_alpn_protos(ctx, alpn, alpn.len);
    }

    const ssl = c.SSL_new(ctx) orelse return error.TlsHandshakeFailure;
    errdefer c.SSL_free(ssl);

    // Set SNI hostname (SSL_set_tlsext_host_name is a C macro, use SSL_ctrl directly)
    if (opts.host.len > 0) {
        var host_buf: [256]u8 = undefined;
        if (opts.host.len < host_buf.len) {
            @memcpy(host_buf[0..opts.host.len], opts.host);
            host_buf[opts.host.len] = 0;
            _ = c.SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, @ptrCast(&host_buf));
        }
    }

    if (c.SSL_set_fd(ssl, fd) != 1) return error.TlsHandshakeFailure;

    if (c.SSL_connect(ssl) != 1) {
        return mapSslHandshakeError(ssl);
    }

    // Check negotiated ALPN
    var alpn_proto: [*c]const u8 = null;
    var alpn_len: c_uint = 0;
    c.SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_len);

    const negotiated_alpn: ?[]const u8 = if (alpn_proto != null and alpn_len > 0)
        alpn_proto[0..alpn_len]
    else
        null;

    return .{
        .ssl = ssl,
        .ctx = ctx,
        .alpn_protocol = negotiated_alpn,
    };
}

/// SNI context for per-domain certificate selection.
/// Holds a default SSL_CTX and a map of domain → SSL_CTX for custom certs.
pub const SniContext = struct {
    default_ctx: *c.SSL_CTX,
    domain_contexts: std.StringHashMap(*c.SSL_CTX),
    allocator: std.mem.Allocator,
    mutex: Mutex,

    pub fn init(allocator: std.mem.Allocator, default_cert: *const config.CertKeyPair) !SniContext {
        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
        errdefer c.SSL_CTX_free(ctx);

        try loadCertIntoCtx(ctx, default_cert.cert_pem, default_cert.key_pem);

        // ALPN callback
        c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCallback, null);

        var sni = SniContext{
            .default_ctx = ctx,
            .domain_contexts = std.StringHashMap(*c.SSL_CTX).init(allocator),
            .allocator = allocator,
            .mutex = .unlocked,
        };

        // Register the SNI callback on the default context
        sni.installSniCallback();

        return sni;
    }

    fn installSniCallback(self: *SniContext) void {
        // SSL_CTX_set_tlsext_servername_callback is a C macro that Zig can't
        // translate. Use SSL_CTX_callback_ctrl with the underlying control code.
        _ = c.SSL_CTX_callback_ctrl(
            self.default_ctx,
            SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,
            @ptrCast(&sniCallbackFn),
        );
        // Set the arg pointer to this SniContext
        _ = c.SSL_CTX_ctrl(
            self.default_ctx,
            SSL_CTRL_SET_TLSEXT_SERVERNAME_CB_ARG,
            0,
            @ptrCast(self),
        );
    }

    /// Add or replace a domain's TLS certificate.
    pub fn addDomain(self: *SniContext, domain: []const u8, cert_pem: []const u8, key_pem: []const u8) !void {
        const ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
        errdefer c.SSL_CTX_free(ctx);

        try loadCertIntoCtx(ctx, cert_pem, key_pem);
        c.SSL_CTX_set_alpn_select_cb(ctx, alpnSelectCallback, null);

        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        defer self.mutex.unlock();

        // Replace existing entry if present
        if (self.domain_contexts.fetchRemove(domain)) |old| {
            c.SSL_CTX_free(old.value);
            self.allocator.free(old.key);
        }

        const owned_domain = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned_domain);
        try self.domain_contexts.put(owned_domain, ctx);
    }

    /// Dynamically reload the default server TLS certificate without restarting the server.
    pub fn reloadDefaultCert(self: *SniContext, cert_pem: []const u8, key_pem: []const u8) !void {
        const new_ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
        errdefer c.SSL_CTX_free(new_ctx);

        try loadCertIntoCtx(new_ctx, cert_pem, key_pem);
        c.SSL_CTX_set_alpn_select_cb(new_ctx, alpnSelectCallback, null);

        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        defer self.mutex.unlock();

        const old_ctx = self.default_ctx;
        self.default_ctx = new_ctx;
        self.installSniCallback();
        c.SSL_CTX_free(old_ctx);
    }

    /// Remove a domain's TLS certificate.
    pub fn removeDomain(self: *SniContext, domain: []const u8) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        defer self.mutex.unlock();

        if (self.domain_contexts.fetchRemove(domain)) |old| {
            c.SSL_CTX_free(old.value);
            self.allocator.free(old.key);
        }
    }

    pub fn deinit(self: *SniContext) void {
        var it = self.domain_contexts.iterator();
        while (it.next()) |entry| {
            c.SSL_CTX_free(entry.value_ptr.*);
            self.allocator.free(entry.key_ptr.*);
        }
        self.domain_contexts.deinit();
        c.SSL_CTX_free(self.default_ctx);
    }
};

/// SNI callback — called by OpenSSL during TLS handshake to select the
/// correct SSL_CTX based on the client's requested hostname.
pub fn sniCallbackFn(
    ssl: ?*c.SSL,
    _: ?*c_int,
    arg: ?*anyopaque,
) callconv(.c) c_int {
    const sni_ctx: *SniContext = @ptrCast(@alignCast(arg orelse return c.SSL_TLSEXT_ERR_OK));
    const hostname_ptr = c.SSL_get_servername(ssl, @intCast(TLSEXT_NAMETYPE_host_name));
    if (hostname_ptr == null) return c.SSL_TLSEXT_ERR_OK;

    const hostname = mem.sliceTo(hostname_ptr, 0);

    while (!sni_ctx.mutex.tryLock()) std.atomic.spinLoopHint();
    defer sni_ctx.mutex.unlock();

    if (sni_ctx.domain_contexts.get(hostname)) |domain_ctx| {
        _ = c.SSL_set_SSL_CTX(ssl, domain_ctx);
    }
    // If not found, the default_ctx cert is used (already set)
    return c.SSL_TLSEXT_ERR_OK;
}

/// Load a certificate chain and private key into an SSL_CTX.
pub fn loadCertIntoCtx(ctx: *c.SSL_CTX, cert_pem: []const u8, key_pem: []const u8) !void {
    // Load certificate chain
    const cert_bio = c.BIO_new_mem_buf(@ptrCast(cert_pem.ptr), @intCast(cert_pem.len)) orelse return error.InvalidCertificate;
    defer _ = c.BIO_free(cert_bio);

    const cert_x509 = c.PEM_read_bio_X509(cert_bio, null, null, null) orelse return error.InvalidCertificate;
    if (c.SSL_CTX_use_certificate(ctx, cert_x509) != 1) {
        c.X509_free(cert_x509);
        return error.InvalidCertificate;
    }
    c.X509_free(cert_x509);

    // Load any additional chain certificates
    while (true) {
        const chain_cert = c.PEM_read_bio_X509(cert_bio, null, null, null);
        if (chain_cert == null) break;
        if (c.SSL_CTX_add_extra_chain_cert(ctx, chain_cert) != 1) {
            c.X509_free(chain_cert);
            break;
        }
        // Note: SSL_CTX_add_extra_chain_cert takes ownership, don't free
    }

    // Load private key
    const key_bio = c.BIO_new_mem_buf(@ptrCast(key_pem.ptr), @intCast(key_pem.len)) orelse return error.InvalidCertificate;
    defer _ = c.BIO_free(key_bio);

    const pkey = c.PEM_read_bio_PrivateKey(key_bio, null, null, null) orelse return error.InvalidCertificate;
    defer c.EVP_PKEY_free(pkey);

    if (c.SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        return error.InvalidCertificate;
    }
    if (c.SSL_CTX_check_private_key(ctx) != 1) {
        return error.InvalidCertificate;
    }
}

/// Perform a TLS server handshake on the given socket fd.
pub fn server(fd: posix.fd_t, opts: config.Server) !Connection {
    // When an SniContext is available, use its shared default_ctx
    // (with SNI callback already registered). Otherwise create a
    // new per-connection SSL_CTX as before.
    var owned_ctx: ?*c.SSL_CTX = null;
    const ctx = if (opts.sni_context) |sni| sni.default_ctx else blk: {
        const new_ctx = c.SSL_CTX_new(c.TLS_server_method()) orelse return error.TlsHandshakeFailure;
        owned_ctx = new_ctx;
        errdefer c.SSL_CTX_free(new_ctx);

        if (opts.auth) |auth| {
            try loadCertIntoCtx(new_ctx, auth.cert_pem, auth.key_pem);
        }

        // ALPN callback
        c.SSL_CTX_set_alpn_select_cb(new_ctx, alpnSelectCallback, null);
        break :blk new_ctx;
    };
    errdefer if (owned_ctx) |oc| c.SSL_CTX_free(oc);

    const ssl = c.SSL_new(ctx) orelse return error.TlsHandshakeFailure;
    errdefer c.SSL_free(ssl);

    if (c.SSL_set_fd(ssl, fd) != 1) return error.TlsHandshakeFailure;

    if (c.SSL_accept(ssl) != 1) {
        return mapSslHandshakeError(ssl);
    }

    // Check negotiated ALPN
    var alpn_proto: [*c]const u8 = null;
    var alpn_len: c_uint = 0;
    c.SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_len);

    const negotiated_alpn: ?[]const u8 = if (alpn_proto != null and alpn_len > 0)
        alpn_proto[0..alpn_len]
    else
        null;

    return .{
        .ssl = ssl,
        .ctx = ctx,
        .alpn_protocol = negotiated_alpn,
        .owns_ctx = owned_ctx != null,
    };
}

/// ALPN selection callback for the server side.
/// Prefers h2 if the client supports it, otherwise http/1.1.
fn alpnSelectCallback(
    _: ?*c.SSL,
    out: [*c][*c]const u8,
    outlen: [*c]u8,
    in_ptr: [*c]const u8,
    inlen: c_uint,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const server_protos = "\x02h2\x08http/1.1";
    const ret = c.SSL_select_next_proto(
        @constCast(@ptrCast(out)),
        @ptrCast(outlen),
        server_protos,
        server_protos.len,
        in_ptr,
        inlen,
    );
    if (ret == c.OPENSSL_NPN_NEGOTIATED) {
        return c.SSL_TLSEXT_ERR_OK;
    }
    return c.SSL_TLSEXT_ERR_NOACK;
}

fn mapSslHandshakeError(ssl: *c.SSL) error{
    TlsHandshakeFailure,
    TlsCertificateExpired,
    TlsCertificateRevoked,
    TlsCertificateUnknown,
    TlsUnsupportedCertificate,
    TlsCertificateRequired,
} {
    const ssl_err = c.SSL_get_error(ssl, -1);
    if (ssl_err == c.SSL_ERROR_SSL) {
        const verify_result = c.SSL_get_verify_result(ssl);
        return switch (verify_result) {
            c.X509_V_ERR_CERT_HAS_EXPIRED => error.TlsCertificateExpired,
            c.X509_V_ERR_CERT_REVOKED => error.TlsCertificateRevoked,
            c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
            c.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
            => error.TlsCertificateUnknown,
            c.X509_V_ERR_CERT_UNTRUSTED => error.TlsUnsupportedCertificate,
            else => error.TlsHandshakeFailure,
        };
    }
    return error.TlsHandshakeFailure;
}

fn sslToError(ssl_error: c_int) ConnectionError {
    return switch (ssl_error) {
        c.SSL_ERROR_ZERO_RETURN => error.EndOfStream,
        c.SSL_ERROR_WANT_READ, c.SSL_ERROR_WANT_WRITE => error.WouldBlock,
        c.SSL_ERROR_SYSCALL => error.ReadFailed,
        c.SSL_ERROR_SSL => error.TlsAlert,
        else => error.ReadFailed,
    };
}

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("openssl_test.zig");
}
