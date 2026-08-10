const std = @import("std");
const zhttp = @import("zhttp");
const httpz = zhttp;

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("=== httpz.zig Micro-benchmarks ===\n\n", .{});

    // 1. Request Parsing Benchmark
    {
        const raw_req =
            "GET /api/v1/users/123?format=json HTTP/1.1\r\n" ++
            "Host: api.example.com\r\n" ++
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\n" ++
            "Accept: application/json, text/plain, */*\r\n" ++
            "Accept-Language: en-US,en;q=0.9\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Authorization: Bearer secret_token_12345\r\n" ++
            "\r\n";

        const start_ns = nowNs();
        const iterations: usize = 1_000_000;
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            var raw_buf: [raw_req.len]u8 = undefined;
            @memcpy(&raw_buf, raw_req);
            const req = try httpz.Request.parse(&raw_buf);
            std.mem.doNotOptimizeAway(req);
        }
        const elapsed_ns = @max(1, nowNs() - start_ns);
        const ops_per_sec = (@as(f64, @floatFromInt(iterations)) / @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0;
        const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iterations));

        std.debug.print("1. HTTP Request Parser:\n", .{});
        std.debug.print("   Iterations: {d}\n", .{iterations});
        std.debug.print("   Total Time: {d:.2} ms\n", .{@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0});
        std.debug.print("   Latency:    {d:.2} ns/op\n", .{ns_per_op});
        std.debug.print("   Throughput: {d:.0} ops/sec\n\n", .{ops_per_sec});
    }

    // 2. Router Dispatch Benchmark
    {
        const routes = [_]httpz.Router.Route{
            .{ .method = .GET, .path = "/health", .handler = dummyHandler },
            .{ .method = .GET, .path = "/api/v1/users/:id", .handler = dummyHandler },
            .{ .method = .POST, .path = "/api/v1/users", .handler = dummyHandler },
        };
        const dispatcher = httpz.Router.handler(&routes);

        var req_raw: [256]u8 = undefined;
        const raw_str = "GET /api/v1/users/456 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        @memcpy(req_raw[0..raw_str.len], raw_str);
        const req = try httpz.Request.parse(req_raw[0..raw_str.len]);

        const dummy_io: std.Io = undefined;
        const start_ns = nowNs();
        const iterations: usize = 1_000_000;
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            const resp = dispatcher(allocator, dummy_io, &req);
            std.mem.doNotOptimizeAway(resp);
        }
        const elapsed_ns = @max(1, nowNs() - start_ns);
        const ops_per_sec = (@as(f64, @floatFromInt(iterations)) / @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0;
        const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iterations));

        std.debug.print("2. Router Match & Dispatch:\n", .{});
        std.debug.print("   Iterations: {d}\n", .{iterations});
        std.debug.print("   Total Time: {d:.2} ms\n", .{@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0});
        std.debug.print("   Latency:    {d:.2} ns/op\n", .{ns_per_op});
        std.debug.print("   Throughput: {d:.0} ops/sec\n\n", .{ops_per_sec});
    }

    std.debug.print("Benchmark run completed successfully.\n", .{});
}

fn dummyHandler(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "text/plain", "OK");
}
