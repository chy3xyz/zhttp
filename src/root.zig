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
    // Every file of the library is walked here, so each one is compiled even
    // when nothing else reaches it: a function that only a caller's code would
    // analyse is a function whose breakage ships as a build failure for that
    // caller. `refAllDecls` on a namespace does not descend into the files it
    // holds, which is how a `RateLimiter` still using a removed
    // `std.Thread.Mutex` stayed green in here.
    std.testing.refAllDecls(@import("Request.zig"));
    std.testing.refAllDecls(@import("Response.zig"));
    std.testing.refAllDecls(@import("Headers.zig"));
    std.testing.refAllDecls(@import("Router.zig"));
    std.testing.refAllDecls(@import("Cookie.zig"));
    std.testing.refAllDecls(@import("openssl.zig"));
    // openssl_c.zig is its own module, so it is compiled on its own; importing
    // it again by path would put the same file in two modules.
    std.testing.refAllDecls(@import("client/Client.zig"));
    std.testing.refAllDecls(@import("client/H2Client.zig"));
    std.testing.refAllDecls(@import("h2/frame.zig"));
    std.testing.refAllDecls(@import("h2/hpack.zig"));
    std.testing.refAllDecls(@import("h2/huffman.zig"));
    std.testing.refAllDecls(@import("h2/Settings.zig"));
    std.testing.refAllDecls(@import("h2/Stream.zig"));
    std.testing.refAllDecls(@import("h2/StreamRegistry.zig"));
    std.testing.refAllDecls(@import("h2/ConnectionIO.zig"));
    std.testing.refAllDecls(@import("h2/FlowControl.zig"));
    std.testing.refAllDecls(@import("h2/errors.zig"));
    std.testing.refAllDecls(@import("middleware/compression.zig"));
    std.testing.refAllDecls(@import("middleware/cors.zig"));
    std.testing.refAllDecls(@import("middleware/rate_limit.zig"));
    std.testing.refAllDecls(@import("middleware/security_headers.zig"));
    std.testing.refAllDecls(@import("server/ChunkedWriter.zig"));
    std.testing.refAllDecls(@import("server/Compression.zig"));
    std.testing.refAllDecls(@import("server/Connection.zig"));
    std.testing.refAllDecls(@import("server/Date.zig"));
    std.testing.refAllDecls(@import("server/H2Connection.zig"));
    std.testing.refAllDecls(@import("server/Proxy.zig"));
    std.testing.refAllDecls(@import("server/Server.zig"));
    std.testing.refAllDecls(@import("server/WebSocket.zig"));

    if (httpz_options.h3) {
        std.testing.refAllDecls(@import("h3/quic.zig"));
        std.testing.refAllDecls(@import("h3/http3.zig"));
        std.testing.refAllDecls(@import("h3/Client.zig"));
        std.testing.refAllDecls(@import("h3/Server.zig"));
    }
}
