//! CLOSE-WAIT reproducer.
//!
//! Listens on :8081 with two routes:
//! - GET /fast    — returns immediately
//! - GET /slow    — sleeps for SLOW_MS ms, then returns
//!
//! The slow handler simulates a request handler stuck on a pool/DB. Under
//! parallel keep-alive load, with N concurrent /slow requests where N > the
//! worker pool's available threads, requests pile up. If the client (e.g.
//! node:undici) sends FIN while the server is mid-handler, the server cannot
//! observe the FIN until the handler returns and the loop re-enters
//! readHeaders. Until then the FD sits in CLOSE-WAIT.

const std = @import("std");
const zhttp = @import("zhttp");
const httpz = zhttp;

const SLOW_MS: u64 = 200;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    std.debug.print("repro server on 127.0.0.1:8081\n", .{});

    var server = httpz.Server.init(.{
        .port = 8081,
        .address = "127.0.0.1",
    }, handler);

    server.run(io) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("port 8081 in use\n", .{});
            std.process.exit(1);
        },
    };
}

fn handler(_: std.mem.Allocator, io: std.Io, request: *const httpz.Request) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/fast")) {
        return httpz.Response.init(.ok, "text/plain", "fast\n");
    }
    if (std.mem.eql(u8, request.uri, "/slow")) {
        io.sleep(std.Io.Duration.fromMilliseconds(@intCast(SLOW_MS)), .awake) catch {};
        return httpz.Response.init(.ok, "text/plain", "slow\n");
    }
    return httpz.Response.init(.not_found, "text/plain", "not found\n");
}
