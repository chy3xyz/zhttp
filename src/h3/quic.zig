//! QUIC transport surface for the native HTTP/3 stack.
//!
//! Kept as the public compatibility namespace: callers still reach the server
//! certificate and client TLS settings through httpz.h3.quic. The transport
//! itself lives in native/transport.zig and is built on zquic + OpenSSL's
//! QUIC-TLS callbacks, not ngtcp2.

const transport = @import("native/transport.zig");
const qtls = @import("native/qtls.zig");

pub const ClientTls = qtls.ClientTls;
pub const Error = transport.Error;
pub const Role = transport.Role;
pub const Connection = transport.Connection;
pub const Listener = transport.Listener;
pub const connect = transport.connect;
pub const fillRandom = qtls.fillRandom;
pub const max_datagram_size = transport.max_datagram_size;

pub const setServerCert = qtls.setServerCert;
pub const setClientCa = qtls.setClientCa;

/// QLog output was wired to ngtcp2's per-connection writer. The native
/// transport emits no qlog yet; the entry points stay so existing callers do
/// not have to change.
pub fn enableQLog(path: []const u8) !void {
    _ = path;
}

pub fn disableQLog() void {}

test {
    _ = Connection;
    _ = Listener;
}
