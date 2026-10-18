//! Production-safety hardening tests for the native transport.
//!
//! Covers RFC 9000 Section 8.1 anti-amplification (3x receive budget before
//! address validation, retention of over-budget packets, and validation by a
//! decrypted Handshake packet) and congestion-window enforcement in flush()
//! (in-order requeue, no drop, ACK-driven resumption).

const std = @import("std");
const posix = std.posix;
const zquic = @import("zquic");
const transport = @import("transport.zig");
const packet_io = @import("packet_io.zig");
const qtls = @import("qtls.zig");

const Connection = transport.Connection;
const PacketCrypto = zquic.PacketCrypto;

const Harness = struct {
    conn: *Connection,
    send_fd: posix.fd_t,
    recv_fd: posix.fd_t,
    recv_addr: posix.sockaddr.in,
    initial_dcid: [8]u8,

    fn init(allocator: std.mem.Allocator) !Harness {
        try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
        const receiver = try packet_io.bindListener(0);
        errdefer packet_io.closeSocket(receiver.fd);
        const sender = try packet_io.createSocket();
        errdefer packet_io.closeSocket(sender);
        // bindListener() binds INADDR_ANY; sending to 0.0.0.0 fails on macOS.
        var remote_addr = receiver.local_addr;
        remote_addr.addr = std.mem.nativeToBig(u32, 0x7f000001);

        const initial_dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        const original_dcid = [_]u8{ 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11 };
        const client_cid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
        const conn = try Connection.initServer(
            allocator,
            sender,
            receiver.local_addr,
            remote_addr,
            &initial_dcid,
            &original_dcid,
            &client_cid,
            &.{},
            1024 * 1024,
            64 * 1024,
        );
        errdefer conn.deinit();
        return .{
            .conn = conn,
            .send_fd = sender,
            .recv_fd = receiver.fd,
            .recv_addr = remote_addr,
            .initial_dcid = initial_dcid,
        };
    }

    fn deinit(self: *Harness) void {
        self.conn.deinit();
        packet_io.closeSocket(self.send_fd);
        packet_io.closeSocket(self.recv_fd);
    }
};

fn queuePacket(
    conn: *Connection,
    allocator: std.mem.Allocator,
    marker: u8,
    len: usize,
    ack_eliciting: bool,
) !void {
    const data = try allocator.alloc(u8, len);
    @memset(data, marker);
    try conn.quic.super_connection.queueOutgoingRawPacketOwnedWithMetadata(
        data,
        3,
        len,
        ack_eliciting,
    );
}

fn expectDatagram(fd: posix.fd_t, marker: u8, len: usize) !void {
    // Never block the test runner: a missing datagram is a failure, not a
    // reason to hang. pollReadable is capped at one second by packet_io.
    if (!packet_io.pollReadable(fd, 500 * std.time.ns_per_ms)) return error.TestExpectedDatagram;
    var buf: [2048]u8 = undefined;
    const received = packet_io.recvDatagram(fd, &buf, std.c.MSG.DONTWAIT) orelse return error.TestExpectedDatagram;
    try std.testing.expectEqual(len, received.data.len);
    try std.testing.expectEqual(marker, received.data[0]);
}

fn expectNoDatagram(fd: posix.fd_t) !void {
    var buf: [2048]u8 = undefined;
    try std.testing.expect(packet_io.recvDatagram(fd, &buf, std.c.MSG.DONTWAIT) == null);
}

fn countReceived(conn: *Connection, bytes: usize) !void {
    // A syntactically invalid datagram still counts for RFC 9000 8.1: the
    // limit is about bytes received, not about successful authentication.
    const datagram = try std.testing.allocator.alloc(u8, bytes);
    defer std.testing.allocator.free(datagram);
    @memset(datagram, 0);
    try conn.handleDatagram(datagram);
}

test "server anti-amplification: 3x cap, requeue, then send after validation" {
    const allocator = std.testing.allocator;
    defer qtls.deinitServer();
    var h = try Harness.init(allocator);
    defer h.deinit();

    try countReceived(h.conn, 1200);
    try std.testing.expectEqual(@as(u64, 1200), h.conn.unvalidatedBytesReceived());
    try std.testing.expect(!h.conn.isAddressValidated());

    // 1200 received -> 3600 byte budget, so only three 1000-byte datagrams fit.
    for (0..5) |index| try queuePacket(h.conn, allocator, @intCast(index), 1000, false);
    try h.conn.flush();

    try std.testing.expectEqual(@as(u64, 3000), h.conn.unvalidatedBytesSent());
    try std.testing.expectEqual(@as(usize, 2), h.conn.quic.super_connection.outgoing_raw_packets.items.len);
    try expectDatagram(h.recv_fd, 0, 1000);
    try expectDatagram(h.recv_fd, 1, 1000);
    try expectDatagram(h.recv_fd, 2, 1000);
    try expectNoDatagram(h.recv_fd);

    // A second flush without more received bytes cannot spend the remaining
    // 600-byte allowance on a 1000-byte packet; nothing is dropped.
    try h.conn.flush();
    try std.testing.expectEqual(@as(usize, 2), h.conn.quic.super_connection.outgoing_raw_packets.items.len);
    try expectNoDatagram(h.recv_fd);

    // Token validation or an authenticated Handshake lifts the cap. The two
    // retained packets leave in their original order.
    h.conn.markAddressValidated();
    try h.conn.flush();
    try std.testing.expectEqual(@as(usize, 0), h.conn.quic.super_connection.outgoing_raw_packets.items.len);
    try expectDatagram(h.recv_fd, 3, 1000);
    try expectDatagram(h.recv_fd, 4, 1000);
    try expectNoDatagram(h.recv_fd);
    try std.testing.expectEqual(@as(u64, 5000), h.conn.statsSnapshot().bytes_sent);
}

test "server anti-amplification: Initial does not validate, decrypted Handshake does" {
    const allocator = std.testing.allocator;
    defer qtls.deinitServer();
    var h = try Harness.init(allocator);
    defer h.deinit();

    try countReceived(h.conn, 1200);
    for (0..5) |index| try queuePacket(h.conn, allocator, @intCast(index), 1000, false);
    try h.conn.flush();
    try std.testing.expectEqual(@as(u64, 3000), h.conn.unvalidatedBytesSent());
    try std.testing.expectEqual(@as(usize, 2), h.conn.quic.super_connection.outgoing_raw_packets.items.len);
    try expectDatagram(h.recv_fd, 0, 1000);
    try expectDatagram(h.recv_fd, 1, 1000);
    try expectDatagram(h.recv_fd, 2, 1000);
    try expectNoDatagram(h.recv_fd);

    // Handshake key material shared by the server (conn) and a synthetic
    // client PacketCrypto. No TLS state machine is involved: the test only
    // needs a packet that authenticates under the Handshake keys.
    var shared_secret: [32]u8 = @splat(0x5a);
    var transcript_hash: [32]u8 = @splat(0x6b);
    var schedule = try zquic.Tls13KeySchedule.deriveHandshakeKeySchedule(
        &shared_secret,
        &transcript_hash,
    );
    defer schedule.zeroize();
    try h.conn.crypto.packet_crypto.installRfc9001HandshakeKeys(
        &schedule.server_packet_keys,
        &schedule.client_packet_keys,
    );

    var peer_tls = try zquic.EnhancedCrypto.EnhancedTlsContext.init(allocator, false, .aes_128_gcm_sha256);
    defer peer_tls.deinit();
    var peer = try PacketCrypto.init(allocator, &peer_tls, null);
    defer peer.deinit();
    try peer.installRfc9001ClientInitialKeys(&h.initial_dcid);
    try peer.installRfc9001HandshakeKeys(
        &schedule.client_packet_keys,
        &schedule.server_packet_keys,
    );

    const dcid = h.conn.local_cid[0..h.conn.local_cid_len];
    const scid = h.conn.peer_cid[0..h.conn.peer_cid_len];
    const padding: [64]u8 = @splat(0);

    // A decrypted Initial is not proof of address ownership.
    const initial = try peer.createProtectedRawPacket(.initial, .initial, dcid, scid, &padding);
    defer allocator.free(initial);
    try h.conn.handleDatagram(initial);
    try std.testing.expect(!h.conn.isAddressValidated());
    try std.testing.expectEqual(@as(u64, 3000), h.conn.unvalidatedBytesSent());
    try std.testing.expectEqual(@as(usize, 2), h.conn.quic.super_connection.outgoing_raw_packets.items.len);

    // A successfully decrypted Handshake packet validates the address and the
    // same service pass flushes the two retained datagrams.
    const handshake = try peer.createProtectedRawPacket(.handshake, .handshake, dcid, scid, &padding);
    defer allocator.free(handshake);
    try h.conn.handleDatagram(handshake);
    try std.testing.expect(h.conn.isAddressValidated());
    try std.testing.expectEqual(@as(usize, 0), h.conn.quic.super_connection.outgoing_raw_packets.items.len);
    try expectDatagram(h.recv_fd, 3, 1000);
    try expectDatagram(h.recv_fd, 4, 1000);
    try expectNoDatagram(h.recv_fd);
}

test "congestion window: blocked packet is requeued in order and an ACK resumes" {
    const allocator = std.testing.allocator;
    defer qtls.deinitServer();
    var h = try Harness.init(allocator);
    defer h.deinit();
    h.conn.markAddressValidated();

    // Three 1000-byte ack-eliciting packets are recorded in zquic's flight
    // state, exactly as schedule() would have done, and the same three are
    // still queued for the wire. A 1500-byte window lets one go at a time.
    h.conn.quic.super_connection.loss_recovery.congestion_controller.congestion_window = 1500;
    const space = &h.conn.quic.super_connection.packet_spaces.application;
    const now = transport.nowMicros();
    for (0..3) |index| {
        try space.onPacketSent(@intCast(index), now, true, true, 1000);
        try queuePacket(h.conn, allocator, @intCast(index), 1000, true);
    }

    try h.conn.flush();
    try std.testing.expectEqual(@as(usize, 2), h.conn.quic.super_connection.outgoing_raw_packets.items.len);
    try std.testing.expectEqual(@as(u8, 1), h.conn.quic.super_connection.outgoing_raw_packets.items[0].data[0]);
    try std.testing.expectEqual(@as(u8, 2), h.conn.quic.super_connection.outgoing_raw_packets.items[1].data[0]);
    try expectDatagram(h.recv_fd, 0, 1000);
    try expectNoDatagram(h.recv_fd);

    // ACK packet 0: one packet's worth of flight leaves, so exactly one more
    // queued packet may be sent. Order and packet contents remain intact.
    var acked = [_]zquic.core.PacketSpace.AckRange{.{ .start = 0, .end = 0 }};
    _ = try space.processAck(&acked, 0, transport.nowMicros());
    try h.conn.flush();
    try std.testing.expectEqual(@as(usize, 1), h.conn.quic.super_connection.outgoing_raw_packets.items.len);
    try std.testing.expectEqual(@as(u8, 2), h.conn.quic.super_connection.outgoing_raw_packets.items[0].data[0]);
    try expectDatagram(h.recv_fd, 1, 1000);
    try expectNoDatagram(h.recv_fd);

    acked = .{.{ .start = 1, .end = 1 }};
    _ = try space.processAck(&acked, 0, transport.nowMicros());
    try h.conn.flush();
    try std.testing.expectEqual(@as(usize, 0), h.conn.quic.super_connection.outgoing_raw_packets.items.len);
    try expectDatagram(h.recv_fd, 2, 1000);
    try expectNoDatagram(h.recv_fd);
}

test "zquic prepend preserves ownership and order" {
    const allocator = std.testing.allocator;
    var conn = try zquic.Connection.SuperConnection.init(allocator, .server, .{});
    defer conn.deinit();

    var first: [1]u8 = .{1};
    var second: [1]u8 = .{2};
    var front_a: [1]u8 = .{3};
    var front_b: [1]u8 = .{4};
    try conn.queueOutgoingRawPacketOwned(try allocator.dupe(u8, &first));
    try conn.queueOutgoingRawPacketOwned(try allocator.dupe(u8, &second));

    var prepend = [_]zquic.Connection.OwnedRawPacket{
        .{ .data = try allocator.dupe(u8, &front_a) },
        .{ .data = try allocator.dupe(u8, &front_b) },
    };
    try conn.queueOutgoingRawPacketsFront(&prepend);

    const drained = try conn.drainOutgoingRawPackets(allocator);
    defer allocator.free(drained);
    defer for (drained) |*packet| packet.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 4), drained.len);
    try std.testing.expectEqual(@as(u8, 3), drained[0].data[0]);
    try std.testing.expectEqual(@as(u8, 4), drained[1].data[0]);
    try std.testing.expectEqual(@as(u8, 1), drained[2].data[0]);
    try std.testing.expectEqual(@as(u8, 2), drained[3].data[0]);
}
