//! Client-side QUIC Retry tests.
//!
//! Covers the three pieces a retried connection depends on: RFC 9001 Retry
//! Integrity Tag validation, the Initial header token plumbing in zquic, and a
//! loopback handshake against a Retry-enabled h3.Server.

const std = @import("std");
const zquic = @import("zquic");
const transport = @import("transport.zig");
const retry = @import("retry.zig");
const qtls = @import("qtls.zig");
const H3Server = @import("../Server.zig");
const H3Client = @import("../Client.zig");

const Packet = zquic.Packet;

test "client Retry: RFC 9001 Appendix A.4 integrity tag" {
    // Appendix A.2's client Initial has an empty Source Connection ID and an
    // original destination connection ID of 0x8394c8f03e515708. Appendix A.4
    // retries it with SCID 0xf067a5502a4262b5 and token "token".
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_without_tag = [_]u8{
        0xff, // Long header, fixed bit, Retry
        0x00,
        0x00,
        0x00,
        0x01,
        0x00, // DCID length (client Initial SCID)
        0x08,
        0xf0,
        0x67,
        0xa5,
        0x50,
        0x2a,
        0x42,
        0x62,
        0xb5,
        0x74, 0x6f, 0x6b, 0x65, 0x6e, // "token"
    };
    const expected_tag = [16]u8{
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    };

    const computed = try Packet.computeRetryIntegrityTag(&original_dcid, &retry_without_tag);
    try std.testing.expectEqualSlices(u8, &expected_tag, &computed);

    var packet: [retry_without_tag.len + 16]u8 = undefined;
    @memcpy(packet[0..retry_without_tag.len], &retry_without_tag);
    @memcpy(packet[retry_without_tag.len..], &expected_tag);
    const parsed = try Packet.RetryPacket.parse(&packet, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, "token", parsed.token);
    try parsed.validateClientRetry(&packet, &.{}, &original_dcid);

    // RFC 9000 17.2.5.1 checks the client's Initial SCID, not the ODCID.
    try std.testing.expectError(
        error.InvalidConnectionId,
        parsed.validateClientRetry(&packet, &original_dcid, &original_dcid),
    );

    // The tag is bound to the original destination connection ID.
    var wrong_odcid = original_dcid;
    wrong_odcid[7] ^= 0x01;
    try std.testing.expectError(
        error.InvalidPacket,
        parsed.validateClientRetry(&packet, &.{}, &wrong_odcid),
    );

    // Tampering with the token invalidates the tag.
    var tampered = packet;
    tampered[retry_without_tag.len - 1] ^= 0x01;
    const tampered_retry = try Packet.RetryPacket.parse(&tampered, std.testing.allocator);
    try std.testing.expectError(
        error.InvalidPacket,
        tampered_retry.validateClientRetry(&tampered, &.{}, &original_dcid),
    );
}

test "client Retry: server-built Retry validates and binds both CIDs" {
    const allocator = std.testing.allocator;
    var key: [32]u8 = undefined;
    @memset(&key, 0x5a);
    const odcid = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };
    const client_scid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const retry_scid = [_]u8{ 17, 18, 19, 20, 21, 22, 23, 24 };
    const address = [_]u8{ 127, 0, 0, 1, 0x1f, 0x90 };

    var token_buf: [retry.max_token_len]u8 = undefined;
    var retry_impl = retry.Retry{ .key = key };
    const token = try retry_impl.makeToken(&odcid, &address, &retry_scid, &client_scid, 1_000_000, &token_buf);
    var packet_buf: [retry.max_retry_packet_len]u8 = undefined;
    const bytes = try retry.Retry.buildPacket(&odcid, &client_scid, &retry_scid, token, &packet_buf);

    const parsed = try Packet.RetryPacket.parse(bytes, allocator);
    try std.testing.expectEqualSlices(u8, token, parsed.token);
    try parsed.validateClientRetry(bytes, &client_scid, &odcid);

    // Wrong client Initial SCID.
    try std.testing.expectError(
        error.InvalidConnectionId,
        parsed.validateClientRetry(bytes, &retry_scid, &odcid),
    );

    // Wrong original DCID invalidates the integrity tag.
    try std.testing.expectError(
        error.InvalidPacket,
        parsed.validateClientRetry(bytes, &client_scid, &client_scid),
    );

    // A Retry with an empty token is not conformant even with a valid tag.
    var empty_token_buf: [retry.max_retry_packet_len]u8 = undefined;
    const empty_bytes = try retry.Retry.buildPacket(&odcid, &client_scid, &retry_scid, &.{}, &empty_token_buf);
    const empty_token_retry = try Packet.RetryPacket.parse(empty_bytes, allocator);
    try std.testing.expectEqual(@as(usize, 0), empty_token_retry.token.len);
    try std.testing.expectError(
        error.InvalidPacket,
        empty_token_retry.validateClientRetry(empty_bytes, &client_scid, &odcid),
    );

    // parse() always treats the trailing 16 bytes as the tag, so a short tag
    // surfaces at validation time rather than parse time.
    const truncated = try Packet.RetryPacket.parse(bytes[0 .. bytes.len - 1], allocator);
    try std.testing.expectError(
        error.InvalidPacket,
        truncated.validateClientRetry(bytes[0 .. bytes.len - 1], &client_scid, &odcid),
    );
}

test "client Retry: Initial keys and token survive the retry rekey" {
    const allocator = std.testing.allocator;
    const EnhancedTlsContext = zquic.EnhancedCrypto.EnhancedTlsContext;

    var client_tls = try EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();

    var client_crypto = try zquic.PacketCrypto.init(allocator, &client_tls, null);
    defer client_crypto.deinit();
    var server_crypto = try zquic.PacketCrypto.init(allocator, &server_tls, null);
    defer server_crypto.deinit();

    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const client_scid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const retry_scid = [_]u8{ 17, 18, 19, 20, 21, 22, 23, 24 };
    const token = "opaque-retry-token";
    const payload = "ClientHello bytes that must be replayed exactly";

    // Pre-Retry flight: original keys, empty token.
    try client_crypto.installRfc9001ClientInitialKeys(&original_dcid);
    try server_crypto.installRfc9001ServerInitialKeys(&original_dcid);
    const first = try client_crypto.createProtectedRawPacket(.initial, .initial, &original_dcid, &client_scid, payload);
    defer allocator.free(first);
    const first_header = try Packet.PacketHeader.parse(first, allocator);
    try std.testing.expect(first_header.token != null);
    try std.testing.expectEqual(@as(usize, 0), first_header.token.?.len);

    // Retry accepted: fresh keys from the Retry SCID, restart Initial Pn, and
    // the same payload under a non-empty token.
    try client_crypto.installRfc9001ClientInitialKeys(&retry_scid);
    client_crypto.resetInitialPacketNumberState();
    client_crypto.initial_token = token;
    try server_crypto.installRfc9001ServerInitialKeys(&retry_scid);

    const second = try client_crypto.createProtectedRawPacket(.initial, .initial, &retry_scid, &client_scid, payload);
    defer allocator.free(second);
    const second_header = try Packet.PacketHeader.parse(second, allocator);
    try std.testing.expectEqualSlices(u8, token, second_header.token.?);
    try std.testing.expectEqualSlices(u8, &retry_scid, second_header.dest_conn_id.bytes());

    var processed = try server_crypto.processProtectedRawPacket(second, null);
    defer processed.deinit(allocator);
    try std.testing.expectEqualStrings(payload, processed.payload);
    try std.testing.expectEqual(@as(u64, 0), processed.packet_number);

    // The old server key set (derived from the ODCID) cannot open it.
    var old_server = try zquic.PacketCrypto.init(allocator, &server_tls, null);
    defer old_server.deinit();
    try old_server.installRfc9001ServerInitialKeys(&original_dcid);
    if (old_server.processProtectedRawPacket(second, null)) |processed_old| {
        var stale = processed_old;
        stale.deinit(allocator);
        try std.testing.expect(false);
    } else |_| {}
}

test "client Retry: loopback to a Retry-enabled h3.Server" {
    // The server runs on its own thread, so this integration test must use a
    // thread-safe allocator. The single-threaded unit tests above keep
    // std.testing.allocator for leak checking.
    const allocator = std.heap.smp_allocator;

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const handler = struct {
        fn handle(_: std.mem.Allocator, _: *const H3Server.Request) H3Server.Response {
            return .{ .body = "retried-ok" };
        }
    }.handle;

    var server = try H3Server.Server.init(allocator, 0, handler, .{ .retry = true });
    defer server.deinit();
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);

    const accepted_before = transport.test_retry_accepted;

    const Runner = struct {
        fn run(s: *H3Server.Server) void {
            s.run() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&server});

    // The run thread must always be stopped and joined before the deferred
    // server.deinit(), including when an assertion below fails.
    var joined = false;
    errdefer if (!joined) {
        server.stop();
        thread.join();
    };

    var client = try H3Client.Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    var client_alive = true;
    errdefer if (client_alive) client.deinit();

    const body = try client.get("/");
    try std.testing.expectEqualStrings("retried-ok", body);
    allocator.free(body);
    // A duplicate tokenless Initial (for example a PTO probe racing the
    // Retry) can make the server send more than one Retry. The client must
    // accept exactly one and discard the rest, so only acceptance is pinned.
    try std.testing.expectEqual(accepted_before + 1, transport.test_retry_accepted);

    client.deinit();
    client_alive = false;

    // Let the server process CONNECTION_CLOSE and reap the session.
    transport.sleepNs(200 * std.time.ns_per_ms);
    server.stop();
    thread.join();
    joined = true;

    try std.testing.expectEqual(@as(usize, 0), server.connectionCount());
}
