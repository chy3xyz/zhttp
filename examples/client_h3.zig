const std = @import("std");
const zhttp = @import("zhttp");
const httpz = zhttp;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    std.debug.print("httpz HTTP/3 Client connecting to 127.0.0.1:8443...\n", .{});
    var client = try httpz.h3.Client.init(allocator, "127.0.0.1", 8443);
    defer client.deinit();

    const body = client.get("/") catch |err| {
        std.debug.print("Request failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer allocator.free(body);

    std.debug.print("Response received: {s}\n", .{body});
}
