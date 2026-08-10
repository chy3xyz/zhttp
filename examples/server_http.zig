const std = @import("std");
const Io = std.Io;
const zhttp = @import("zhttp");
const httpz = zhttp;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    std.debug.print("httpz - HTTP/1.1 Server\n", .{});
    std.debug.print("Listening on 127.0.0.1:8080\n", .{});

    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, handler);

    server.run(io) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("Error: port 8080 is already in use\n", .{});
            std.process.exit(1);
        },
    };
}

fn handler(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/")) {
        return httpz.Response.init(.ok, "text/plain", "Hello from httpz!");
    }

    if (std.mem.eql(u8, request.uri, "/health")) {
        // No compression for small JSON responses
        return httpz.Response.init(.ok, "application/json", "{\"status\":\"ok\"}");
    }

    return httpz.Response.init(.not_found, "text/plain", "Not Found");
}
