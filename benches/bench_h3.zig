//! HTTP/3 micro-benchmarks: a real `httpz.h3.Server` and `httpz.h3.Client`
//! talking over loopback, reported in the same style as `bench_http.zig`.
//!
//! Run with `zig build bench-h3 -Dh3=true`.
const std = @import("std");
const zhttp = @import("zhttp");
const httpz = zhttp;
const h3 = httpz.h3;

const small_body_size: usize = 1024;
const large_body_size: usize = 2 * 1024 * 1024;
const small_iterations: usize = 500;
const large_iterations: usize = 3;
const port: u16 = 14881;

/// Bodies are filled once at startup. The handler hands the server a fresh copy
/// of one of them because the server takes ownership of the body it is given
/// and frees it after sending.
var small_body_buf: [small_body_size]u8 = undefined;
var large_body_buf: [large_body_size]u8 = undefined;

fn handle(allocator: std.mem.Allocator, path: []const u8) []const u8 {
    const body: []const u8 = if (std.mem.eql(u8, path, "/large")) &large_body_buf else &small_body_buf;
    return allocator.dupe(u8, body) catch &.{};
}

/// The server's run loop never returns, so it keeps serving until the process
/// exits; the benchmark only reports if it stops early.
fn serve(server: *h3.Server) void {
    server.run() catch |err| std.debug.print("h3 server stopped: {s}\n", .{@errorName(err)});
}

fn sleepMs(ms: u64) void {
    const ts = std.posix.timespec{
        .sec = @intCast(ms / 1000),
        .nsec = @intCast((ms % 1000) * std.time.ns_per_ms),
    };
    _ = std.c.nanosleep(&ts, null);
}

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// What one phase of the benchmark measured.
///
/// `service_ns` is the time the completed requests themselves took, which is
/// what the throughput numbers are derived from: a phase that gives up on a
/// request pays the client's full timeout once, and charging that stall to the
/// requests that did work would hide how fast a working request is.
const Phase = struct {
    requests: usize = 0,
    completed: usize = 0,
    connections: usize = 0,
    bytes: usize = 0,
    service_ns: u64 = 0,
    wall_ns: u64 = 0,
    fastest_ns: u64 = std.math.maxInt(u64),
    slowest_ns: u64 = 0,
    /// Where the first request that did not come back as expected sits, and how
    /// long the client spent on it before giving up.
    failed_at: ?usize = null,
    failed_after_ns: u64 = 0,
    err_name: ?[]const u8 = null,
    /// Requests the connection that failed carried before it refused another.
    last_connection_requests: usize = 0,

    fn ok(self: Phase) bool {
        return self.err_name == null and self.completed == self.requests;
    }

    fn meanLatencyNs(self: Phase) f64 {
        return @as(f64, @floatFromInt(self.service_ns)) / @as(f64, @floatFromInt(@max(self.completed, 1)));
    }

    fn requestsPerSecond(self: Phase) f64 {
        const seconds = @as(f64, @floatFromInt(self.service_ns)) / 1_000_000_000.0;
        return @as(f64, @floatFromInt(self.completed)) / @max(seconds, 1e-9);
    }

    /// 10^6 bytes per MB.
    fn megabytesPerSecond(self: Phase) f64 {
        const seconds = @as(f64, @floatFromInt(self.service_ns)) / 1_000_000_000.0;
        const mb = @as(f64, @floatFromInt(self.bytes)) / 1_000_000.0;
        return mb / @max(seconds, 1e-9);
    }
};

fn measure(client: *h3.Client, path: []const u8, expected_len: usize, phase: *Phase) !void {
    const req_start = nowNs();
    const body = client.get(path) catch |err| {
        phase.failed_at = phase.completed;
        phase.failed_after_ns = @max(1, nowNs() - req_start);
        phase.err_name = @errorName(err);
        return err;
    };
    const req_ns = @max(1, nowNs() - req_start);
    defer std.heap.page_allocator.free(body);

    if (body.len != expected_len) {
        phase.failed_at = phase.completed;
        phase.failed_after_ns = req_ns;
        phase.err_name = "ShortResponse";
        return error.ShortResponse;
    }

    phase.completed += 1;
    phase.bytes += body.len;
    phase.service_ns += req_ns;
    phase.fastest_ns = @min(phase.fastest_ns, req_ns);
    phase.slowest_ns = @max(phase.slowest_ns, req_ns);
}

/// One connection carries every request; a connection that refuses another
/// stream ends the phase, which is reported as the failure it is.
fn benchPhase(client: *h3.Client, path: []const u8, expected_len: usize, iterations: usize, phase: *Phase) void {
    phase.requests = iterations;
    phase.connections = 1;

    const wall_start = nowNs();
    for (0..iterations) |_| {
        const carried = phase.completed;
        measure(client, path, expected_len, phase) catch {
            phase.last_connection_requests = carried;
            break;
        };
    }
    phase.wall_ns = @max(1, nowNs() - wall_start);
    if (phase.completed == iterations) phase.last_connection_requests = phase.completed;
}

fn printMs(ns: u64) void {
    std.debug.print("{d:.2} ms", .{@as(f64, @floatFromInt(ns)) / 1_000_000.0});
}

fn printCommon(phase: Phase) void {
    std.debug.print("   Requested:   {d}\n", .{phase.requests});
    std.debug.print("   Completed:   {d}\n", .{phase.completed});
    std.debug.print("   Connections: {d}\n", .{phase.connections});
    std.debug.print("   Total Time:  {d:.2} ms\n", .{@as(f64, @floatFromInt(phase.wall_ns)) / 1_000_000.0});
}

fn printLatency(phase: Phase) void {
    if (phase.completed == 0) {
        std.debug.print("   Latency:     n/a\n", .{});
        return;
    }
    std.debug.print("   Latency:     {d:.2} ms/req (min ", .{phase.meanLatencyNs() / 1_000_000.0});
    printMs(phase.fastest_ns);
    std.debug.print(", max ", .{});
    printMs(phase.slowest_ns);
    std.debug.print(")\n", .{});
}

fn printFailure(phase: Phase) void {
    std.debug.print("   FAILED:      request {d} returned {s} after ", .{
        (phase.failed_at orelse 0) + 1,
        phase.err_name orelse "unknown",
    });
    printMs(phase.failed_after_ns);
    std.debug.print("\n", .{});
    if (phase.last_connection_requests > 0) {
        std.debug.print("   FAILED:      the connection took {d} requests before it refused another stream\n", .{phase.last_connection_requests});
    }
}

fn printSmallPhase(phase: Phase) void {
    std.debug.print("1. Small responses (1 KiB):\n", .{});
    printCommon(phase);
    printLatency(phase);
    std.debug.print("   Throughput:  {d:.0} req/sec\n", .{phase.requestsPerSecond()});
    if (!phase.ok()) printFailure(phase);
    std.debug.print("\n", .{});
}

fn printLargePhase(phase: Phase) void {
    std.debug.print("2. Large response body (2 MiB):\n", .{});
    printCommon(phase);
    std.debug.print("   Transferred: {d} B\n", .{phase.bytes});
    printLatency(phase);
    std.debug.print("   Throughput:  {d:.2} MB/s\n", .{phase.megabytesPerSecond()});
    if (!phase.ok()) printFailure(phase);
    std.debug.print("\n", .{});
}

fn printSummary(small: Phase, large: Phase) void {
    std.debug.print("=== Summary ===\n", .{});
    std.debug.print("{s:<26}{s:>11}{s:>12}{s:>16}   {s}\n", .{ "benchmark", "done/requests", "time", "throughput", "status" });

    std.debug.print("{s:<26}{d:>6}/{d:<4}{d:>12.2}{d:>16.0}   {s}\n", .{
        "h3 small response (1 KiB)",
        small.completed,
        small.requests,
        @as(f64, @floatFromInt(small.wall_ns)) / 1_000_000_000.0,
        small.requestsPerSecond(),
        if (small.ok()) "ok" else "FAILED",
    });
    std.debug.print("{s:<26}{d:>6}/{d:<4}{d:>12.2}{d:>16.2}   {s}\n", .{
        "h3 large response (2 MiB)",
        large.completed,
        large.requests,
        @as(f64, @floatFromInt(large.wall_ns)) / 1_000_000_000.0,
        large.megabytesPerSecond(),
        if (large.ok()) "ok" else "FAILED",
    });

    std.debug.print("\nthroughput: req/s for the small responses, MB/s (10^6 bytes/s) for the large body,\n", .{});
    std.debug.print("both derived from the time the completed requests took.\n", .{});
    if (!small.ok()) {
        std.debug.print("small responses failed: {s} after {d} requests\n", .{
            small.err_name orelse "unknown",
            small.completed,
        });
    }
    if (!large.ok()) {
        std.debug.print("large body failed: {s} after {d} requests\n", .{
            large.err_name orelse "unknown",
            large.completed,
        });
    }
}

const CertKey = struct {
    cert: []u8,
    key: []u8,
};

fn readCertPair(
    dir: std.Io.Dir,
    io: std.Io,
    allocator: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
) !CertKey {
    const limit = std.Io.Limit.limited(64 * 1024);
    const cert = try dir.readFileAlloc(io, cert_path, allocator, limit);
    errdefer allocator.free(cert);
    const key = try dir.readFileAlloc(io, key_path, allocator, limit);
    return .{ .cert = cert, .key = key };
}

/// The certificate is read at run time rather than embedded: `@embedFile` can
/// only reach files inside the `benches` directory, and `examples/cert` is
/// generated locally instead of committed. The h3 test suite's certificate does
/// ship with the repository, so it is preferred when it is there.
fn loadCertKey(allocator: std.mem.Allocator, io: std.Io) !CertKey {
    const dir = std.Io.Dir.cwd();

    const test_cert = "src/h3/test_cert.pem";
    const test_key = "src/h3/test_key.pem";
    if (readCertPair(dir, io, allocator, test_cert, test_key)) |pair| {
        std.debug.print("TLS certificate: {s}\n\n", .{test_cert});
        return pair;
    } else |_| {}

    const example_cert = "examples/cert/cert.pem";
    const example_key = "examples/cert/key.pem";
    if (readCertPair(dir, io, allocator, example_cert, example_key)) |pair| {
        std.debug.print("TLS certificate: {s}\n\n", .{example_cert});
        return pair;
    } else |_| {}

    std.debug.print("\nError: could not load a TLS certificate.\n", .{});
    std.debug.print("Tried {s} + {s}, then {s} + {s}.\n", .{ test_cert, test_key, example_cert, example_key });
    std.debug.print("Run the following from the project root to generate a certificate:\n", .{});
    std.debug.print("  bash examples/gen_cert.sh\n\n", .{});
    return error.NoCertificate;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    std.debug.print("=== httpz.zig HTTP/3 Micro-benchmarks ===\n\n", .{});

    // The PEM buffers stay alive for the whole run: the TLS context built from
    // them lives as long as the server.
    const cert_key = try loadCertKey(gpa, io);

    @memset(&small_body_buf, 's');
    for (&large_body_buf, 0..) |*byte, i| byte.* = @truncate(i);

    try h3.quic.setServerCert(cert_key.cert, cert_key.key);

    const allocator = std.heap.page_allocator;
    const server = try allocator.create(h3.Server);
    server.* = try h3.Server.init(allocator, port, handle, .{});
    _ = try std.Thread.spawn(.{}, serve, .{server});
    // Give the server's receive loop a moment to come up before the client's
    // handshake retries start.
    sleepMs(100);

    var small = Phase{};
    {
        var client = try h3.Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
        defer client.deinit();
        benchPhase(&client, "/small", small_body_size, small_iterations, &small);
    }

    // The large transfer gets a connection of its own: the small phase may have
    // used up this connection's stream budget, which would say nothing about
    // how the layer moves 2 MiB.
    var large = Phase{};
    {
        var client = try h3.Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
        defer client.deinit();
        benchPhase(&client, "/large", large_body_size, large_iterations, &large);
    }

    printSmallPhase(small);
    printLargePhase(large);
    printSummary(small, large);

    if (!small.ok() or !large.ok()) {
        std.debug.print("\nBenchmark run completed with failures.\n", .{});
        return error.H3BenchmarkFailed;
    }
    std.debug.print("\nBenchmark run completed successfully.\n", .{});
}
