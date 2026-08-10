/// zhttp - HTTP/1.1, HTTP/2, and HTTP/3 library for Zig 0.17
///
/// Implements RFC 2616 (HTTP/1.1) with the new std.Io async model.
///
/// Public API:
/// - Server: TCP listener and connection manager
/// - Client: HTTP/1.1 client
/// - Request: HTTP request parser
/// - Response: HTTP response builder
/// - Headers: HTTP header storage
pub const Server = @import("server/Server.zig");
pub const Client = @import("client/Client.zig");
pub const Request = @import("Request.zig");
pub const Response = @import("Response.zig");
pub const Headers = @import("Headers.zig");
pub const WebSocket = @import("server/WebSocket.zig");
pub const Router = @import("Router.zig");
pub const Cookie = @import("Cookie.zig");
pub const Handler = @import("server/Connection.zig").Handler;
pub const middleware = struct {
    pub const compression = @import("middleware/compression.zig");
    pub const cors = @import("middleware/cors.zig");
    pub const security_headers = @import("middleware/security_headers.zig");
    pub const rate_limit = @import("middleware/rate_limit.zig");
};
pub const h2 = @import("h2/root.zig");
const httpz_options = @import("httpz_options");
pub const h3 = if (httpz_options.h3) @import("h3/root.zig") else struct {};
pub const tls = @import("openssl.zig");

const std = @import("std");

test {
    std.testing.refAllDecls(@This());
}
