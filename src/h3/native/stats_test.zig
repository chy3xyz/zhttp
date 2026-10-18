//! Tests for the native H3 transport statistics surface.

const std = @import("std");
const transport = @import("transport.zig");
const qtls = @import("qtls.zig");
const H3Server = @import("../Server.zig");
const H3Client = @import("../Client.zig");

const Stats = transport.Stats;

test "stats: aggregation and active stream arithmetic" {
    var total: Stats = .{};
    total.add(.{
        .packets_sent = 2,
        .packets_received = 3,
        .bytes_sent = 100,
        .bytes_received = 200,
        .retransmits = 1,
        .streams_opened = 4,
        .streams_closed = 2,
        .flow_updates = 5,
        .ack_frames_sent = 6,
    });
    total.add(.{
        .packets_sent = 7,
        .streams_opened = 1,
        .streams_closed = 1,
    });

    try std.testing.expectEqual(@as(u64, 9), total.packets_sent);
    try std.testing.expectEqual(@as(u64, 3), total.packets_received);
    try std.testing.expectEqual(@as(u64, 100), total.bytes_sent);
    try std.testing.expectEqual(@as(u64, 200), total.bytes_received);
    try std.testing.expectEqual(@as(u64, 1), total.retransmits);
    try std.testing.expectEqual(@as(u64, 5), total.streams_opened);
    try std.testing.expectEqual(@as(u64, 3), total.streams_closed);
    try std.testing.expectEqual(@as(u64, 5), total.flow_updates);
    try std.testing.expectEqual(@as(u64, 6), total.ack_frames_sent);

    const merged = Stats.merged(total, .{ .packets_sent = 1, .bytes_sent = 50 });
    try std.testing.expectEqual(@as(u64, 10), merged.packets_sent);
    try std.testing.expectEqual(@as(u64, 150), merged.bytes_sent);

    try std.testing.expectEqual(@as(u64, 2), (Stats{ .streams_opened = 5, .streams_closed = 3 }).activeStreams());
    // A half-observed close never underflows.
    try std.testing.expectEqual(@as(u64, 0), (Stats{ .streams_closed = 3 }).activeStreams());

    // Aggregation saturates rather than panicking on overflow.
    var saturated = Stats{ .packets_sent = std.math.maxInt(u64) - 1 };
    saturated.add(.{ .packets_sent = 2 });
    try std.testing.expectEqual(std.math.maxInt(u64), saturated.packets_sent);
}

fn expectCountersPositive(snapshot: Stats) !void {
    try std.testing.expect(snapshot.packets_sent > 0);
    try std.testing.expect(snapshot.packets_received > 0);
    try std.testing.expect(snapshot.bytes_sent > 0);
    try std.testing.expect(snapshot.bytes_received > 0);
    try std.testing.expect(snapshot.streams_opened > 0);
    try std.testing.expect(snapshot.ack_frames_sent > 0);
}

fn expectMonotonic(before: Stats, after: Stats) !void {
    try std.testing.expect(after.packets_sent >= before.packets_sent);
    try std.testing.expect(after.packets_received >= before.packets_received);
    try std.testing.expect(after.bytes_sent >= before.bytes_sent);
    try std.testing.expect(after.bytes_received >= before.bytes_received);
    try std.testing.expect(after.retransmits >= before.retransmits);
    try std.testing.expect(after.streams_opened >= before.streams_opened);
    try std.testing.expect(after.streams_closed >= before.streams_closed);
    try std.testing.expect(after.flow_updates >= before.flow_updates);
    try std.testing.expect(after.ack_frames_sent >= before.ack_frames_sent);
}

test "stats: loopback GET counters are monotonic" {
    // The server runs on its own thread, so this integration test uses a
    // thread-safe allocator. The pure Stats test above uses no allocator.
    const allocator = std.heap.smp_allocator;

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const handler = struct {
        fn handle(_: std.mem.Allocator, _: *const H3Server.Request) H3Server.Response {
            return .{ .body = "stats-ok" };
        }
    }.handle;

    var server = try H3Server.Server.init(allocator, 0, handler, .{});
    defer server.deinit();
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);

    const Runner = struct {
        fn run(s: *H3Server.Server) void {
            s.run() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&server});

    var joined = false;
    errdefer if (!joined) {
        server.stop();
        thread.join();
    };

    var client = try H3Client.Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    var client_alive = true;
    errdefer if (client_alive) client.deinit();

    const body = try client.get("/one");
    try std.testing.expectEqualStrings("stats-ok", body);
    allocator.free(body);

    const first = client.stats();
    try expectCountersPositive(first);
    try std.testing.expect(first.streams_opened >= first.streams_closed);
    try std.testing.expect(first.activeStreams() >= 1);
    try std.testing.expect(first.activeStreams() <= first.streams_opened);

    // Snapshot semantics: later traffic must not mutate an earlier copy.
    const first_copy = first;

    const second_body = try client.get("/two");
    try std.testing.expectEqualStrings("stats-ok", second_body);
    allocator.free(second_body);

    const second = client.stats();
    try expectMonotonic(first, second);
    // A second request necessarily adds datagrams, bytes, and a stream.
    try std.testing.expect(second.packets_sent > first.packets_sent);
    try std.testing.expect(second.packets_received > first.packets_received);
    try std.testing.expect(second.bytes_sent > first.bytes_sent);
    try std.testing.expect(second.bytes_received > first.bytes_received);
    try std.testing.expect(second.streams_opened > first.streams_opened);
    try std.testing.expect(second.streams_opened >= second.streams_closed);
    try std.testing.expect(second.activeStreams() >= 1);
    try std.testing.expect(second.activeStreams() <= second.streams_opened);
    try std.testing.expectEqual(first.packets_sent, first_copy.packets_sent);
    try std.testing.expectEqual(first.streams_opened, first_copy.streams_opened);

    client.deinit();
    client_alive = false;
    // Deliberately do not read the Client or either snapshot after deinit.

    // Let the server process CONNECTION_CLOSE and reap the connection; both the
    // live listener sum and the retained closed history are valid reads after
    // run returns.
    transport.sleepNs(200 * std.time.ns_per_ms);
    server.stop();
    thread.join();
    joined = true;

    const server_stats = server.stats();
    try expectCountersPositive(server_stats);
    try std.testing.expect(server_stats.streams_opened >= server_stats.streams_closed);
    try std.testing.expect(server_stats.activeStreams() >= 1);
    try std.testing.expect(server_stats.activeStreams() <= server_stats.streams_opened);
}
