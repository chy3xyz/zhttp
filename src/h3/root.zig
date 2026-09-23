pub const quic = @import("quic.zig");
pub const http3 = @import("http3.zig");
pub const Client = @import("Client.zig").Client;
pub const Server = @import("Server.zig").Server;
pub const ServerHandler = @import("Server.zig").Handler;

test {
    _ = @import("quic.zig");
    _ = @import("http3.zig");
    _ = @import("Client.zig");
    _ = @import("Server.zig");
}
