const std = @import("std");
const zhttp = @import("zhttp");
const httpz = zhttp;

const cors = httpz.middleware.cors.init(.{
    .origin = "*",
    .methods = "GET, POST, PUT, DELETE, OPTIONS, PATCH",
    .headers = "Content-Type, Authorization",
});

const compress = httpz.middleware.compression;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    std.debug.print("httpz - Router Example\n", .{});
    std.debug.print("Listening on 127.0.0.1:8080\n\n", .{});
    std.debug.print("Routes:\n", .{});
    std.debug.print("  GET  /              - Home page\n", .{});
    std.debug.print("  GET  /users         - List users (compressed)\n", .{});
    std.debug.print("  GET  /users/:id     - Get user by ID (CORS enabled)\n", .{});
    std.debug.print("  POST /users         - Create user\n", .{});
    std.debug.print("  GET  /stream        - Streaming response\n", .{});
    std.debug.print("  GET  /ws            - WebSocket echo endpoint\n", .{});

    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
    }, comptime httpz.Router.handler(&.{
        .{ .method = .GET, .path = "/", .handler = handleHome },
        .{ .method = .GET, .path = "/users", .handler = compress.wrap(handleListUsers) },
        .{ .method = .GET, .path = "/users/:id", .handler = cors.wrap(handleGetUser) },
        .{ .method = .POST, .path = "/users", .handler = handleCreateUser },
        .{ .method = .GET, .path = "/stream", .handler = compress.wrap(handleStream) },
        .{ .method = .GET, .path = "/ws", .handler = handleWsUpgrade, .ws = .{ .handler = wsHandler } },
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
        \\<h1>httpz Router Example</h1>
        \\<ul>
        \\<li><a href="/users">GET /users</a></li>
        \\<li><a href="/users/42">GET /users/42</a></li>
        \\</ul>
        \\</body></html>
    );
}

fn handleListUsers(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "application/json",
        \\[{"id":1,"name":"Alice"},{"id":2,"name":"Bob"},{"id":3,"name":"Charlie"}]
    );
}

fn handleGetUser(allocator: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    const id = request.params.get("id") orelse
        return httpz.Response.init(.bad_request, "text/plain", "Missing id");
    var buf: [128]u8 = undefined;
    const body = std.fmt.bufPrint(&buf, "{{\"id\":\"{s}\",\"name\":\"User {s}\"}}", .{ id, id }) catch
        return httpz.Response.init(.internal_server_error, "text/plain", "Response too large");

    // Heap-allocate so the body outlives this stack frame.
    // The server calls response.deinit() after sending, which frees it.
    const owned = allocator.dupe(u8, body) catch
        return httpz.Response.init(.internal_server_error, "text/plain", "Out of memory");

    var resp = httpz.Response.init(.ok, "application/json", owned);
    resp._body_allocated = owned;
    return resp;
}

fn handleCreateUser(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.created, "application/json",
        \\{"id":4,"name":"New User"}
    );
}

fn handleStream(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    var resp: httpz.Response = .{ .status = .ok, .chunked = true };
    resp.headers.append("Content-Type", "text/plain") catch {};
    resp.stream_fn = streamFn;
    return resp;
}

fn streamFn(_: ?*anyopaque, writer: *std.Io.Writer) void {
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var buf: [32]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "line {d}\n", .{i}) catch return;
        writer.writeAll(line) catch return;
    }
}

fn handleWsUpgrade(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    return httpz.WebSocket.upgradeResponse(request) orelse
        httpz.Response.init(.bad_request, "text/plain", "WebSocket upgrade required");
}

fn wsHandler(conn: *httpz.WebSocket.Conn, _: *const httpz.Request) void {
    std.debug.print("WebSocket client connected\n", .{});

    while (true) {
        const msg = conn.recv() catch break orelse break;
        std.debug.print("WS received: {s}\n", .{msg.payload});

        switch (msg.opcode) {
            .text => conn.send(msg.payload) catch break,
            .binary => conn.sendBinary(msg.payload) catch break,
            else => {},
        }
    }

    std.debug.print("WebSocket client disconnected\n", .{});
}
