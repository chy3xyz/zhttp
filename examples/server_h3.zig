const std = @import("std");
const httpz = @import("httpz");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    const cert_pem = @embedFile("cert/cert.pem");
    const key_pem = @embedFile("cert/key.pem");

    try httpz.h3.quic.setServerCert(cert_pem, key_pem);

    var server = try httpz.h3.Server.init(allocator, 8443, struct {
        fn handle(alloc: std.mem.Allocator, req: []const u8) []const u8 {
            _ = req;
            return alloc.dupe(u8, "Hello from httpz HTTP/3 Server!") catch "Hello from httpz HTTP/3 Server!";
        }
    }.handle);
    defer server.deinit();

    std.debug.print("httpz HTTP/3 Server running on UDP 127.0.0.1:8443...\n", .{});
    try server.run();
}
