pub const quic = @import("quic.zig");
pub const http3 = @import("http3.zig");
pub const Client = @import("Client.zig").Client;
pub const Server = @import("Server.zig").Server;
pub const ServerHandler = @import("Server.zig").Handler;
/// The request a server handler is given, and what it answers with.
pub const Request = @import("Server.zig").Request;
pub const Response = @import("Server.zig").Response;
/// The method and status enums the other protocols use, so a handler written
/// for HTTP/1.1 or HTTP/2 needs nothing new to read these.
pub const Method = @import("Server.zig").Method;
pub const StatusCode = @import("Server.zig").StatusCode;

test {
    _ = @import("quic.zig");
    _ = @import("http3.zig");
    _ = @import("Client.zig");
    _ = @import("Server.zig");
}
