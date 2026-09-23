const std = @import("std");
const zhttp = @import("zhttp");
const httpz = zhttp;

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    std.debug.print("httpz HTTP/3 Client connecting to 127.0.0.1:8443...\n", .{});
    // The example server uses the self-signed certificate in examples/cert.
    var client = try httpz.h3.Client.init(allocator, "127.0.0.1", 8443, .{ .insecure_skip_verify = true });
    defer client.deinit();

    const body = client.get("/") catch |err| {
        std.debug.print("Request failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer allocator.free(body);

    std.debug.print("Response received: {s}\n", .{body});
}
