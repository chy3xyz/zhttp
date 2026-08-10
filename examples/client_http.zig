const std = @import("std");
const Io = std.Io;
const zhttp = @import("zhttp");
const httpz = zhttp;
const Client = httpz.Client;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    const url_str = "http://example.com";
    const url = Client.Url.parse(url_str).?;

    std.debug.print("Connecting to {s}:{}...\n", .{ url.host, url.port });

    var client = try Client.init(allocator, .{
        .host = url.host,
        .port = url.port,
        .connection_timeout_s = 10,
        .read_timeout_s = 10,
    });
    defer client.deinit();

    try client.connect(io);

    std.debug.print("Connected! Sending request...\n", .{});

    var resp = try client.request(io, .GET, url.path, null, null);
    defer resp.deinit(allocator);

    std.debug.print("Status: {}\n", .{resp.status});
    std.debug.print("Body length: {} bytes\n", .{resp.body.len});

    if (resp.body.len > 0 and resp.body.len < 1000) {
        std.debug.print("Body: {s}\n", .{resp.body});
    }
}
