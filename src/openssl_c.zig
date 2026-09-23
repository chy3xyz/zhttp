//! Hand-written bindings for the OpenSSL C API (libssl + libcrypto) used by zhttp.
//!
//! These declarations replace a `zig translate-c` pass over <openssl/ssl.h> and
//! friends. That pass emitted ~46k lines describing every OpenSSL symbol and
//! type, and every compilation unit reaching for TLS had to parse the whole file
//! to get at the few dozen declarations below.
//!
//! The signatures are ABI, not source: a wrong one is silently undefined
//! behaviour instead of a compile error. `openssl_test.zig` drives every entry
//! point here against the real library (handshakes, mTLS, SNI, ALPN), so a
//! mismatch surfaces as a failing test rather than as a broken server.

pub const SSL = opaque {};
pub const SSL_CTX = opaque {};
pub const SSL_METHOD = opaque {};
pub const BIO = opaque {};
pub const X509 = opaque {};
pub const X509_STORE_CTX = opaque {};
pub const EVP_PKEY = opaque {};

pub const pem_password_cb = fn (buf: [*c]u8, size: c_int, rwflag: c_int, userdata: ?*anyopaque) callconv(.c) c_int;

pub const SSL_verify_cb = ?*const fn (preverify_ok: c_int, x509_ctx: ?*X509_STORE_CTX) callconv(.c) c_int;

pub const SSL_CTX_alpn_select_cb_func = ?*const fn (
    ssl: ?*SSL,
    out: [*c][*c]const u8,
    outlen: [*c]u8,
    in: [*c]const u8,
    inlen: c_uint,
    arg: ?*anyopaque,
) callconv(.c) c_int;

// -- Methods and contexts --

pub extern fn TLS_client_method() ?*const SSL_METHOD;
pub extern fn TLS_server_method() ?*const SSL_METHOD;

pub extern fn SSL_CTX_new(meth: ?*const SSL_METHOD) ?*SSL_CTX;
pub extern fn SSL_CTX_free(ctx: ?*SSL_CTX) void;
pub extern fn SSL_CTX_set_verify(ctx: ?*SSL_CTX, mode: c_int, callback: SSL_verify_cb) void;
pub extern fn SSL_CTX_set_default_verify_paths(ctx: ?*SSL_CTX) c_int;
pub extern fn SSL_CTX_use_certificate(ctx: ?*SSL_CTX, x: ?*X509) c_int;
pub extern fn SSL_CTX_use_PrivateKey(ctx: ?*SSL_CTX, pkey: ?*EVP_PKEY) c_int;
pub extern fn SSL_CTX_check_private_key(ctx: ?*const SSL_CTX) c_int;
pub extern fn SSL_CTX_ctrl(ctx: ?*SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
pub extern fn SSL_CTX_callback_ctrl(ctx: ?*SSL_CTX, cmd: c_int, fp: ?*const fn () callconv(.c) void) c_long;
pub extern fn SSL_CTX_set_alpn_protos(ctx: ?*SSL_CTX, protos: [*c]const u8, protos_len: c_uint) c_int;
pub extern fn SSL_CTX_set_alpn_select_cb(ctx: ?*SSL_CTX, cb: SSL_CTX_alpn_select_cb_func, arg: ?*anyopaque) void;
pub extern fn SSL_select_next_proto(
    out: [*c][*c]u8,
    outlen: [*c]u8,
    server: [*c]const u8,
    server_len: c_uint,
    client: [*c]const u8,
    client_len: c_uint,
) c_int;

// -- Connections --

pub extern fn SSL_new(ctx: ?*SSL_CTX) ?*SSL;
pub extern fn SSL_free(ssl: ?*SSL) void;
pub extern fn SSL_set_fd(s: ?*SSL, fd: c_int) c_int;
pub extern fn SSL_accept(ssl: ?*SSL) c_int;
pub extern fn SSL_connect(ssl: ?*SSL) c_int;
pub extern fn SSL_read(ssl: ?*SSL, buf: ?*anyopaque, num: c_int) c_int;
pub extern fn SSL_write(ssl: ?*SSL, buf: ?*const anyopaque, num: c_int) c_int;
pub extern fn SSL_shutdown(s: ?*SSL) c_int;
pub extern fn SSL_get_error(s: ?*const SSL, ret_code: c_int) c_int;
pub extern fn SSL_get_servername(s: ?*const SSL, @"type": c_int) [*c]const u8;
pub extern fn SSL_get_verify_result(ssl: ?*const SSL) c_long;
pub extern fn SSL_get0_alpn_selected(ssl: ?*const SSL, data: [*c][*c]const u8, len: [*c]c_uint) void;
pub extern fn SSL_set_SSL_CTX(ssl: ?*SSL, ctx: ?*SSL_CTX) ?*SSL_CTX;
pub extern fn SSL_get_SSL_CTX(ssl: ?*const SSL) ?*SSL_CTX;
pub extern fn SSL_set_accept_state(s: ?*SSL) void;
pub extern fn SSL_set_connect_state(s: ?*SSL) void;
pub extern fn SSL_set_alpn_protos(ssl: ?*SSL, protos: [*c]const u8, protos_len: c_uint) c_int;
pub extern fn SSL_set_ex_data(ssl: ?*SSL, idx: c_int, data: ?*anyopaque) c_int;
pub extern fn SSL_get_ex_data(ssl: ?*const SSL, idx: c_int) ?*anyopaque;
pub extern fn SSL_ctrl(ssl: ?*SSL, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;

// -- Certificates, keys and BIOs --

pub extern fn BIO_new_mem_buf(buf: ?*const anyopaque, len: c_int) ?*BIO;
pub extern fn BIO_free(a: ?*BIO) c_int;
pub extern fn X509_free(a: ?*X509) void;
pub extern fn EVP_PKEY_free(pkey: ?*EVP_PKEY) void;
pub extern fn PEM_read_bio_X509(
    out: ?*BIO,
    x: [*c]?*X509,
    cb: ?*const pem_password_cb,
    u: ?*anyopaque,
) ?*X509;
pub extern fn PEM_read_bio_PrivateKey(
    out: ?*BIO,
    x: [*c]?*EVP_PKEY,
    cb: ?*const pem_password_cb,
    u: ?*anyopaque,
) ?*EVP_PKEY;

// -- Macros --
// C macros have no symbol to link against, so they wrap the control function
// they expand to.

/// `SSL_CTX_add_extra_chain_cert(ctx, x509)`.
pub inline fn SSL_CTX_add_extra_chain_cert(ctx: ?*SSL_CTX, x509: ?*X509) c_long {
    return SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, @ptrCast(x509));
}

/// `SSL_set_tlsext_host_name(s, name)`.
pub inline fn SSL_set_tlsext_host_name(s: ?*SSL, name: [*c]const u8) c_long {
    return SSL_ctrl(s, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, @ptrCast(@constCast(name)));
}

/// `SSL_CTX_set_tlsext_servername_callback(ctx, cb)`.
pub inline fn SSL_CTX_set_tlsext_servername_callback(
    ctx: ?*SSL_CTX,
    cb: *const fn (?*SSL, ?*c_int, ?*anyopaque) callconv(.c) c_int,
) c_long {
    return SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, @ptrCast(cb));
}

/// `SSL_CTX_set_tlsext_servername_arg(ctx, arg)`.
pub inline fn SSL_CTX_set_tlsext_servername_arg(ctx: ?*SSL_CTX, arg: ?*anyopaque) c_long {
    return SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, arg);
}

/// `SSL_set_app_data(s, arg)` — application data stored under ex_data index 0.
pub inline fn SSL_set_app_data(s: ?*SSL, arg: ?*anyopaque) c_int {
    return SSL_set_ex_data(s, 0, arg);
}

/// `SSL_get_app_data(s)`.
pub inline fn SSL_get_app_data(s: ?*const SSL) ?*anyopaque {
    return SSL_get_ex_data(s, 0);
}

// -- Constants --
// Control codes and error codes are C macro constants; their values are part of
// OpenSSL's ABI (ssl.h / tls1.h / x509_vfy.h).

pub const SSL_CTRL_EXTRA_CHAIN_CERT: c_int = 14;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG: c_int = 54;
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
pub const TLSEXT_NAMETYPE_host_name: c_int = 0;

pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;

pub const SSL_VERIFY_NONE: c_int = 0x00;
pub const SSL_VERIFY_PEER: c_int = 0x01;

pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_ALERT_WARNING: c_int = 1;
pub const SSL_TLSEXT_ERR_ALERT_FATAL: c_int = 2;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;

pub const OPENSSL_NPN_UNSUPPORTED: c_int = 0;
pub const OPENSSL_NPN_NEGOTIATED: c_int = 1;

pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: c_int = 2;
pub const X509_V_ERR_CERT_HAS_EXPIRED: c_int = 10;
pub const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: c_int = 20;
pub const X509_V_ERR_CERT_REVOKED: c_int = 23;
pub const X509_V_ERR_CERT_UNTRUSTED: c_int = 27;
