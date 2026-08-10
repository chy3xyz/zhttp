const std = @import("std");
const zhttp = @import("zhttp");
const httpz = zhttp;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    std.debug.print("httpz - Streaming Example\n", .{});
    std.debug.print("Listening on 127.0.0.1:8080\n\n", .{});
    std.debug.print("Routes:\n", .{});
    std.debug.print("  GET  /            - Home page\n", .{});
    std.debug.print("  GET  /events      - SSE endpoint\n", .{});
    std.debug.print("  GET  /large       - Stream generated data\n", .{});

    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, comptime httpz.Router.handler(&.{
        .{ .method = .GET, .path = "/", .handler = handleHome },
        .{ .method = .GET, .path = "/events", .handler = handleEvents },
        .{ .method = .GET, .path = "/large", .handler = handleLarge },
    }));

    server.run(io) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("Error: port 8080 is already in use\n", .{});
            std.process.exit(1);
        },
    };
}

fn handleHome(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "text/html",
        \\<!DOCTYPE html><html><body>
        \\<h1>httpz Streaming Example</h1>
        \\<ul>
        \\<li><a href="/events">GET /events</a> - Server-Sent Events</li>
        \\<li><a href="/large">GET /large</a> - Stream generated data</li>
        \\</ul>
        \\</body></html>
    );
}

/// SSE endpoint — streams events until the connection is closed.
fn handleEvents(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok };
    resp.headers.append("Content-Type", "text/event-stream") catch {};
    resp.headers.append("Cache-Control", "no-cache") catch {};
    resp.auto_content_length = false;
    resp.stream_fn = sseStreamFn;
    return resp;
}

fn sseStreamFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var buf: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "data: event {d}\n\n", .{i}) catch return;
        writer.writeAll(msg) catch return;
        writer.flush() catch return;
    }
}

/// Stream a large generated response without buffering everything in memory.
fn handleLarge(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok, .chunked = true };
    resp.headers.append("Content-Type", "text/plain") catch {};
    resp.stream_fn = largeStreamFn;
    return resp;
}

fn largeStreamFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    const chunk = "All work and no play makes Jack a dull boy.\n";
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        writer.writeAll(chunk) catch return;
    }
}
