const std = @import("std");
const qtls = @import("qtls.zig");

test "OpenSSL QUIC TLS callbacks complete a handshake" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const client = try qtls.Tls.initClient(allocator, "localhost", "client-params", .{ .insecure_skip_verify = true });
    defer client.destroy();
    const server = try qtls.Tls.initServer(allocator, "server-params");
    defer server.destroy();

    try client.drive();
    try std.testing.expect(client.takeOut(0).len > 0);
    try server.pushCrypto(0, client.takeOut(0));
    client.clearOut(0);
    try server.drive();

    try std.testing.expect(server.takeOut(0).len > 0);
    try std.testing.expect(server.takeOut(2).len > 0);
    try client.pushCrypto(0, server.takeOut(0));
    try client.pushCrypto(2, server.takeOut(2));
    server.clearOut(0);
    server.clearOut(2);
    const hs = server.takeSecrets(2);
    try std.testing.expect(hs.complete());

    try client.drive();
    const chs = client.takeSecrets(2);
    try std.testing.expect(chs.complete());
    try std.testing.expect(client.takeOut(2).len > 0);
    try server.pushCrypto(2, client.takeOut(2));
    client.clearOut(2);
    try server.drive();

    const app = server.takeSecrets(3);
    try std.testing.expect(app.complete());
    try std.testing.expect(client.isFinished());
    try std.testing.expect(server.isFinished());
    try std.testing.expectEqualStrings("client-params", server.peerParams());
    try std.testing.expectEqualStrings("server-params", client.peerParams());
}
