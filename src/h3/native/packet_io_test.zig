//! Unit tests for the packet_io wire seam: coalesced-datagram splitting,
//! destination-CID parsing, QUIC varints, random CIDs, and the datagram
//! send/recv/drop helpers. No TLS or Connection state is involved.

const std = @import("std");
const posix = std.posix;
const packet_io = @import("packet_io.zig");

const cid_len = packet_io.cid_len;

/// Write one long-header packet with an empty token into `buf` and return the
/// used slice. Payloads stay below 64 bytes, so the Length field is one byte.
fn writeLongPacket(
    buf: []u8,
    first_byte: u8,
    dcid: []const u8,
    scid: []const u8,
    payload: []const u8,
) []u8 {
    var i: usize = 0;
    buf[i] = first_byte;
    i += 1;
    @memcpy(buf[i..][0..4], &[_]u8{ 0, 0, 0, 1 });
    i += 4;
    buf[i] = @intCast(dcid.len);
    i += 1;
    @memcpy(buf[i..][0..dcid.len], dcid);
    i += dcid.len;
    buf[i] = @intCast(scid.len);
    i += 1;
    @memcpy(buf[i..][0..scid.len], scid);
    i += scid.len;
    if ((first_byte & 0x30) >> 4 == 0) {
        buf[i] = 0; // empty Initial token
        i += 1;
    }
    buf[i] = @intCast(payload.len);
    i += 1;
    @memcpy(buf[i..][0..payload.len], payload);
    i += payload.len;
    return buf[0..i];
}

test "packet_io: nextPacket splits coalesced datagrams" {
    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };

    var first_buf: [96]u8 = undefined;
    const first_packet = writeLongPacket(&first_buf, 0xc0, &dcid, &scid, "initial");
    var second_buf: [96]u8 = undefined;
    const second_packet = writeLongPacket(&second_buf, 0xe0, &dcid, &scid, "handshake");

    var datagram: [192]u8 = undefined;
    @memcpy(datagram[0..first_packet.len], first_packet);
    @memcpy(datagram[first_packet.len..][0..second_packet.len], second_packet);
    const total = first_packet.len + second_packet.len;

    const first = packet_io.nextPacket(datagram[0..total], 0) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, first_packet, first);

    const second = packet_io.nextPacket(datagram[0..total], first.len) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, second_packet, second);

    try std.testing.expect(packet_io.nextPacket(datagram[0..total], first.len + second.len) == null);
}

test "packet_io: nextPacket handles short and retry headers" {
    var short: [1 + cid_len + 3]u8 = undefined;
    short[0] = 0x40;
    for (short[1 .. 1 + cid_len]) |*byte| byte.* = 0xaa;
    @memcpy(short[1 + cid_len ..], "abc");
    const short_packet = packet_io.nextPacket(&short, 0) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &short, short_packet);

    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const scid = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };
    var retry_buf: [64]u8 = undefined;
    const retry = writeLongPacket(&retry_buf, 0xf0, &dcid, &scid, "token-and-tag");
    const retry_packet = packet_io.nextPacket(retry, 0) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, retry, retry_packet);
}

test "packet_io: nextPacket rejects truncated packets" {
    try std.testing.expect(packet_io.nextPacket(&[_]u8{0xc0}, 0) == null);
    try std.testing.expect(packet_io.nextPacket(&[_]u8{ 0xc0, 0, 0, 0, 1, 8 }, 0) == null);

    const dcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var buf: [32]u8 = undefined;
    const packet = writeLongPacket(&buf, 0xc0, &dcid, &dcid, "x");
    // The Length field still claims one payload byte, but the datagram is cut.
    try std.testing.expect(packet_io.nextPacket(packet[0 .. packet.len - 1], 0) == null);
}

test "packet_io: destinationCid reads short and long headers" {
    const cid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var short: [1 + cid_len]u8 = undefined;
    short[0] = 0x40;
    @memcpy(short[1..], &cid);
    try std.testing.expectEqualSlices(u8, &cid, packet_io.destinationCid(&short).?);
    try std.testing.expect(packet_io.destinationCid(short[0 .. short.len - 1]) == null);
    try std.testing.expect(packet_io.destinationCid(&[_]u8{ 0x40, 1, 2 }) == null);

    var long: [6 + cid_len]u8 = undefined;
    long[0] = 0xc0;
    @memset(long[1..5], 0);
    long[5] = cid_len;
    @memcpy(long[6..], &cid);
    try std.testing.expectEqualSlices(u8, &cid, packet_io.destinationCid(&long).?);

    long[5] = cid_len + 1; // claims one byte past the datagram
    try std.testing.expect(packet_io.destinationCid(&long) == null);
}

test "packet_io: readVarint boundaries" {
    const cases = [_]struct { encoded: []const u8, value: u64 }{
        .{ .encoded = &[_]u8{0x00}, .value = 0 },
        .{ .encoded = &[_]u8{0x3f}, .value = 63 },
        .{ .encoded = &[_]u8{ 0x40, 0x40 }, .value = 64 },
        .{ .encoded = &[_]u8{ 0x7f, 0xff }, .value = 16383 },
        .{ .encoded = &[_]u8{ 0x80, 0x00, 0x40, 0x00 }, .value = 16384 },
        .{ .encoded = &[_]u8{ 0xbf, 0xff, 0xff, 0xff }, .value = (1 << 30) - 1 },
        .{ .encoded = &[_]u8{ 0xc0, 0, 0, 0, 0x40, 0, 0, 0 }, .value = 1 << 30 },
        .{ .encoded = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, .value = (1 << 62) - 1 },
    };
    for (cases) |case| {
        var cursor: usize = 0;
        const value = packet_io.readVarint(case.encoded, &cursor) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(case.value, value);
        try std.testing.expectEqual(case.encoded.len, cursor);
    }

    var cursor: usize = 0;
    try std.testing.expect(packet_io.readVarint(&[_]u8{0x40}, &cursor) == null);
    try std.testing.expect(packet_io.readVarint(&[_]u8{}, &cursor) == null);
    try std.testing.expectEqual(@as(usize, 0), cursor);

    cursor = 1;
    const value = packet_io.readVarint(&[_]u8{ 0xff, 0x3f }, &cursor) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 63), value);
    try std.testing.expectEqual(@as(usize, 2), cursor);
}

test "packet_io: randomCid returns cid_len random bytes" {
    const cid = try packet_io.randomCid();
    try std.testing.expectEqual(@as(usize, 20), cid.len);
    for (cid[cid_len..]) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test "packet_io: resolveAddress fills an IPv4 datagram address" {
    const addr = try packet_io.resolveAddress("127.0.0.1", 4433);
    try std.testing.expect(addr.family == posix.AF.INET);
    try std.testing.expectEqual(@as(u16, 4433), std.mem.bigToNative(u16, addr.port));
}

test "packet_io: bind, send, recv, poll, and drop hook" {
    const receiver = try packet_io.bindListener(0);
    defer packet_io.closeSocket(receiver.fd);
    const sender = try packet_io.bindListener(0);
    defer packet_io.closeSocket(sender.fd);

    try std.testing.expect(!packet_io.pollReadable(receiver.fd, 0));

    // bindListener() binds INADDR_ANY; the kernel's getsockname() leaves
    // addr at 0.0.0.0, which is not a valid destination. Send to loopback.
    var remote = receiver.local_addr;
    remote.addr = std.mem.nativeToBig(u32, 0x7f000001);
    var io = packet_io.PacketIo.initClient(remote);
    try std.testing.expectEqual(packet_io.SendOutcome.sent, io.sendDatagram(sender.fd, "one"));
    try std.testing.expect(packet_io.pollReadable(receiver.fd, std.time.ns_per_s));

    var buf: [64]u8 = undefined;
    const first = packet_io.recvDatagram(receiver.fd, &buf, std.c.MSG.DONTWAIT) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("one", first.data);
    try std.testing.expectEqual(sender.local_addr.port, first.peer.port);

    io.setDropOutgoingEvery(2);
    try std.testing.expectEqual(packet_io.SendOutcome.dropped, io.sendDatagram(sender.fd, "two"));
    try std.testing.expectEqual(packet_io.SendOutcome.sent, io.sendDatagram(sender.fd, "three"));
    try std.testing.expectEqual(@as(usize, 3), io.tx_count);

    // The dropped datagram never reaches the peer; delivered order is intact.
    try std.testing.expect(packet_io.pollReadable(receiver.fd, std.time.ns_per_s));
    const second = packet_io.recvDatagram(receiver.fd, &buf, std.c.MSG.DONTWAIT) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("three", second.data);
    try std.testing.expect(packet_io.recvDatagram(receiver.fd, &buf, std.c.MSG.DONTWAIT) == null);
}
