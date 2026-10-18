const std = @import("std");
const zquic = @import("zquic");

test {
    _ = @import("h3/native/qpack.zig");
    _ = @import("h3/native/qtls.zig");
    _ = @import("h3/native/transport.zig");
    _ = @import("h3/native/crypto_stream_test.zig");
    _ = @import("h3/native/stream_table_test.zig");
    _ = @import("h3/native/flow_control_test.zig");
    _ = @import("h3/native/packet_io_test.zig");
    _ = @import("h3/native/stats_test.zig");
    _ = @import("h3/native/recovery_observe_test.zig");
    _ = @import("h3/native/recovery_owner_test.zig");
    _ = @import("h3/native/retry_client_test.zig");
    _ = @import("h3/native/http3.zig");
    _ = @import("h3/native/http3_test.zig");
    _ = @import("h3/native/qtls_test.zig");
    _ = @import("h3/native/fuzz_test.zig");
    _ = @import("h3/native/batch_test.zig");
    _ = @import("h3/native/batch_p23_test.zig");
    _ = @import("h3/native/batch_p3_test.zig");
    _ = @import("h3/native/qlog_test.zig");
    _ = @import("h3/native/production_safety_test.zig");
}

test "zquic Initial keys interoperate between client and server" {
    const allocator = std.testing.allocator;
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };

    var client_tls = try zquic.EnhancedCrypto.EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer client_tls.deinit();
    var server_tls = try zquic.EnhancedCrypto.EnhancedTlsContext.init(allocator, true, .aes_128_gcm_sha256);
    defer server_tls.deinit();

    var client_pc = try zquic.PacketCrypto.init(allocator, &client_tls, null);
    defer client_pc.deinit();
    var server_pc = try zquic.PacketCrypto.init(allocator, &server_tls, null);
    defer server_pc.deinit();

    try client_pc.installRfc9001ClientInitialKeys(&dcid);
    try server_pc.installRfc9001ServerInitialKeys(&dcid);

    const payload = "hello initial payload with enough bytes for a header protection sample";
    const packet = try client_pc.createProtectedRawPacket(.initial, .initial, &dcid, &scid, payload);
    defer allocator.free(packet);

    var processed = try server_pc.processProtectedRawPacket(packet, null);
    defer processed.deinit(allocator);
    try std.testing.expectEqualStrings(payload, processed.payload);
}
