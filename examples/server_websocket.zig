const std = @import("std");
const Io = std.Io;
const zhttp = @import("zhttp");
const httpz = zhttp;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    std.debug.print("httpz - WebSocket Echo Server\n", .{});
    std.debug.print("Listening on 127.0.0.1:8080\n", .{});
    std.debug.print("Connect with: websocat ws://127.0.0.1:8080/ws\n", .{});

    var server = httpz.Server.init(.{
        .port = 8080,
        .address = "127.0.0.1",
        .websocket_handler = wsHandler,
    }, handler);

    server.run(io) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("Error: port 8080 is already in use\n", .{});
            std.process.exit(1);
        },
    };
}

fn handler(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/ws")) {
        // Attempt WebSocket upgrade
        return httpz.WebSocket.upgradeResponse(request) orelse
            httpz.Response.init(.bad_request, "text/plain", "WebSocket upgrade required");
    }

    if (std.mem.eql(u8, request.uri, "/")) {
        return httpz.Response.init(.ok, "text/html",
            \\<!DOCTYPE html><html><body>
            \\<h1>WebSocket Echo</h1>
            \\<script>
            \\const ws = new WebSocket('ws://' + location.host + '/ws');
            \\ws.onmessage = e => document.body.innerHTML += '<p>' + e.data + '</p>';
            \\ws.onopen = () => ws.send('Hello from browser!');
            \\</script>
            \\</body></html>
        );
    }

    return httpz.Response.init(.not_found, "text/plain", "Not Found");
}

fn wsHandler(conn: *httpz.WebSocket.Conn, request: *const httpz.Request) void {
    _ = request;
    std.debug.print("WebSocket client connected\n", .{});

    while (true) {
        const msg = conn.recv() catch break orelse break;
        std.debug.print("Received: {s}\n", .{msg.payload});

        // Echo it back
        switch (msg.opcode) {
            .text => conn.send(msg.payload) catch break,
            .binary => conn.sendBinary(msg.payload) catch break,
            else => {},
        }
    }

    std.debug.print("WebSocket client disconnected\n", .{});
}
