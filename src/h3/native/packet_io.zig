//! UDP datagram and socket I/O for the native QUIC transport.
//!
//! This is the wire seam: it creates and binds sockets, parses destination
//! connection IDs for routing, splits coalesced QUIC packets, reads QUIC
//! varints, generates random CIDs, and wraps sendto/recvfrom/poll. transport
//! keeps packet scheduling, qlog pairing, recovery, and stats accounting; it
//! calls these helpers so packet bytes, syscall order, and the test loss hook
//! stay unchanged.

const std = @import("std");
const posix = std.posix;
const qtls = @import("qtls.zig");

/// Connection IDs generated and routed by this stack. Long headers carry the
/// length; short (1-RTT) headers use this fixed width.
pub const cid_len = 8;

/// Largest UDP payload accepted or sent.
pub const max_datagram_size = 65535;

/// Result of one outgoing datagram. transport uses this to keep qlog pairing
/// and stats accounting identical to the pre-split flush loop.
pub const SendOutcome = enum { sent, dropped, failed };

/// Socket-adjacent state that is not the fd itself: addresses, the synthetic
/// loss counter, and the test drop hook. The fd stays on Connection/Listener
/// so socket lifetime has one authority and out-of-module callers that read
/// `connection.socket` keep working.
pub const PacketIo = struct {
    local_addr: posix.sockaddr.in,
    remote_addr: posix.sockaddr.in,
    tx_count: usize = 0,
    /// Test hook: drop every Nth outgoing datagram (0 disables). Production
    /// callers leave this at zero; the retransmission tests use it to simulate
    /// loss without a network shim. zquic recorded the packet when it was
    /// scheduled, so its loss detector recovers the dropped datagram.
    drop_outgoing_every: usize = 0,

    pub fn initClient(remote_addr: posix.sockaddr.in) PacketIo {
        return .{
            .local_addr = .{ .family = posix.AF.INET, .port = 0, .addr = 0, .zero = @splat(0) },
            .remote_addr = remote_addr,
        };
    }

    pub fn initServer(local_addr: posix.sockaddr.in, remote_addr: posix.sockaddr.in) PacketIo {
        return .{ .local_addr = local_addr, .remote_addr = remote_addr };
    }

    pub fn setDropOutgoingEvery(self: *PacketIo, every: usize) void {
        self.drop_outgoing_every = every;
    }

    /// Send one datagram, applying the test drop hook before the syscall.
    /// tx_count advances for every attempted datagram, including dropped and
    /// failed ones, matching the old flush loop.
    pub fn sendDatagram(self: *PacketIo, fd: posix.fd_t, data: []const u8) SendOutcome {
        self.tx_count += 1;
        if (self.drop_outgoing_every != 0 and self.tx_count % self.drop_outgoing_every == 0) {
            return .dropped;
        }
        return if (sendDatagramTo(fd, data, self.remote_addr)) .sent else .failed;
    }
};

pub const BoundSocket = struct {
    fd: posix.fd_t,
    local_addr: posix.sockaddr.in,
};

pub fn createSocket() !posix.fd_t {
    const fd = posix.system.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    if (fd < 0) return error.QuicError;
    const sock: posix.fd_t = @intCast(fd);
    errdefer closeSocket(sock);
    const enable: c_int = 1;
    _ = posix.system.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, @ptrCast(&enable), @sizeOf(c_int));
    // A 2 MiB response is ~2,100 datagrams; the default macOS/Linux UDP queue
    // is smaller than that and silently drops the overflow. This stack does not
    // retransmit STREAM frames yet, so give the kernel queue room to absorb a
    // burst while the peer drains it.
    const socket_buffer: c_int = 4 * 1024 * 1024;
    _ = posix.system.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVBUF, @ptrCast(&socket_buffer), @sizeOf(c_int));
    _ = posix.system.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDBUF, @ptrCast(&socket_buffer), @sizeOf(c_int));
    return sock;
}

pub fn closeSocket(socket: posix.fd_t) void {
    _ = posix.system.close(socket);
}

/// Create a UDP socket bound to `port` and report the address the kernel chose.
/// The caller owns the returned fd and closes it with closeSocket().
pub fn bindListener(port: u16) !BoundSocket {
    const socket = try createSocket();
    errdefer closeSocket(socket);
    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = 0,
        .zero = @splat(0),
    };
    const rc = posix.system.bind(socket, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    if (rc < 0) return error.QuicError;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    if (posix.system.getsockname(socket, @ptrCast(&addr), &len) < 0) return error.QuicError;
    return .{ .fd = socket, .local_addr = addr };
}

/// Send one datagram to an explicit peer address.
pub fn sendDatagramTo(fd: posix.fd_t, data: []const u8, address: posix.sockaddr.in) bool {
    const sent = posix.system.sendto(
        fd,
        data.ptr,
        @intCast(data.len),
        0,
        @ptrCast(&address),
        @sizeOf(posix.sockaddr.in),
    );
    return sent >= 0;
}

pub const ReceivedDatagram = struct {
    data: []u8,
    peer: posix.sockaddr.in,
};

/// One recvfrom() attempt. Returns null when the socket has no datagram or the
/// syscall failed, matching the old non-blocking drain loops.
pub fn recvDatagram(fd: posix.fd_t, buf: []u8, flags: u32) ?ReceivedDatagram {
    var peer: posix.sockaddr.in = undefined;
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    const n = std.c.recvfrom(
        fd,
        buf.ptr,
        buf.len,
        flags,
        @ptrCast(&peer),
        &peer_len,
    );
    if (n <= 0) return null;
    return .{ .data = buf[0..@intCast(n)], .peer = peer };
}

/// Wait up to `timeout_ns` for a readable datagram, capped at one second.
pub fn pollReadable(fd: posix.fd_t, timeout_ns: u64) bool {
    const wait = @min(timeout_ns, std.time.ns_per_s);
    const timeout_ms: i32 = @intCast((wait + std.time.ns_per_ms - 1) / std.time.ns_per_ms);
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    const ready = posix.poll(&fds, timeout_ms) catch return false;
    return ready > 0 and (fds[0].revents & posix.POLL.IN) != 0;
}

pub fn randomCid() ![20]u8 {
    var out: [20]u8 = @splat(0);
    qtls.fillRandom(out[0..cid_len]);
    return out;
}

pub fn resolveAddress(host: []const u8, port: u16) !posix.sockaddr.in {
    const allocator = std.heap.page_allocator;
    const host_z = try allocator.allocSentinel(u8, host.len, 0);
    defer allocator.free(host_z);
    @memcpy(host_z[0..host.len], host);

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    const port_z = try allocator.allocSentinel(u8, port_str.len, 0);
    defer allocator.free(port_z);
    @memcpy(port_z[0..port_str.len], port_str);

    var hints: std.c.addrinfo = std.mem.zeroes(std.c.addrinfo);
    hints.family = posix.AF.INET;
    hints.socktype = posix.SOCK.DGRAM;
    hints.protocol = posix.IPPROTO.UDP;

    var result: ?*std.c.addrinfo = null;
    const rc = std.c.getaddrinfo(host_z.ptr, port_z.ptr, &hints, &result);
    if (@backingInt(rc) != 0) return error.QuicError;
    defer std.c.freeaddrinfo(result.?);

    var out: posix.sockaddr.in = undefined;
    @memcpy(std.mem.asBytes(&out), @as([*]const u8, @ptrCast(result.?.addr.?))[0..@sizeOf(posix.sockaddr.in)]);
    return out;
}

/// Destination connection ID used to route one datagram. Long headers carry an
/// explicit length; short headers use cid_len bytes.
pub fn destinationCid(datagram: []const u8) ?[]const u8 {
    if (datagram.len < 6) return null;
    if (datagram[0] & 0x80 != 0) {
        const dcil = datagram[5];
        if (6 + dcil > datagram.len) return null;
        return datagram[6 .. 6 + dcil];
    }
    if (datagram.len < 1 + cid_len) return null;
    return datagram[1 .. 1 + cid_len];
}

/// Split a datagram into the QUIC packets it coalesces.
pub fn nextPacket(datagram: []const u8, start: usize) ?[]const u8 {
    if (start >= datagram.len) return null;
    if (datagram[start] & 0x80 == 0) return datagram[start..];
    if (start + 7 > datagram.len) return null;
    var pos = start + 5;
    const dcil = datagram[pos];
    pos += 1;
    if (pos + dcil > datagram.len) return null;
    pos += dcil;
    if (pos >= datagram.len) return null;
    const scil = datagram[pos];
    pos += 1;
    if (pos + scil > datagram.len) return null;
    pos += scil;

    const packet_type = (datagram[start] & 0x30) >> 4;
    // Retry has no Length field: by definition it consumes the rest of the
    // datagram, and its token and integrity tag are the trailing bytes.
    if (packet_type == 0x03) return datagram[start..];
    if (packet_type == 0x00) {
        const token_len = readVarint(datagram, &pos) orelse return null;
        if (token_len > datagram.len - pos) return null;
        pos += @intCast(token_len);
    }
    const length = readVarint(datagram, &pos) orelse return null;
    const end = std.math.add(usize, pos, @intCast(length)) catch return null;
    if (end > datagram.len) return null;
    return datagram[start..end];
}

pub fn readVarint(data: []const u8, cursor: *usize) ?u64 {
    if (cursor.* >= data.len) return null;
    const encoded_len: usize = @as(usize, 1) << @intCast(data[cursor.*] >> 6);
    if (cursor.* + encoded_len > data.len) return null;
    var value: u64 = data[cursor.*] & 0x3f;
    var i: usize = 1;
    while (i < encoded_len) : (i += 1) {
        value = (value << 8) | data[cursor.* + i];
    }
    cursor.* += encoded_len;
    return value;
}
