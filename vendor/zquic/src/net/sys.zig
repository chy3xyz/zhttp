//! Low-level socket operations isolated from QUIC transport logic.
//!
//! Linux goes through raw syscalls; Darwin and the other POSIX targets use the
//! libc wrappers exposed by `std.posix.system`.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const NetAddress = @import("address.zig");

pub const Socket = posix.socket_t;
pub const PosixAddress = NetAddress.PosixAddress;

comptime {
    switch (builtin.os.tag) {
        .windows, .wasi, .freestanding, .uefi, .other => @compileError("zquic net.sys needs socket support for this target"),
        else => {},
    }
}

pub fn createDatagramSocket(local_address: *const NetAddress.Address) !Socket {
    const family = NetAddress.family(local_address);

    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socket(
            @intCast(family),
            linux.SOCK.DGRAM | linux.SOCK.CLOEXEC,
            linux.IPPROTO.UDP,
        );
        return switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .ACCES, .PERM => error.PermissionDenied,
            .AFNOSUPPORT => error.AddressFamilyNotSupported,
            .MFILE => error.ProcessFdQuotaExceeded,
            .NFILE => error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => error.SystemResources,
            .PROTONOSUPPORT => error.ProtocolNotSupported,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    // Darwin rejects SOCK_CLOEXEC, so the descriptor is flagged after creation.
    const rc = posix.system.socket(family, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolNotSupported,
        else => |err| return posix.unexpectedErrno(err),
    }

    const socket_fd: Socket = @intCast(rc);
    errdefer _ = posix.system.close(socket_fd);
    try setCloseOnExec(socket_fd);
    return socket_fd;
}

fn setCloseOnExec(socket_fd: Socket) !void {
    const rc = posix.system.fcntl(socket_fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC));
    return switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => |err| posix.unexpectedErrno(err),
    };
}

pub fn bind(socket_fd: Socket, bind_addr: *const PosixAddress, bind_addr_len: posix.socklen_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.bind(socket_fd, @ptrCast(bind_addr), bind_addr_len);
        return switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => error.AccessDenied,
            .ADDRINUSE => error.AddressInUse,
            .ADDRNOTAVAIL => error.AddressNotAvailable,
            .AFNOSUPPORT => error.AddressFamilyNotSupported,
            .BADF => error.FileDescriptorNotASocket,
            .INVAL => error.InvalidArgument,
            .NOTSOCK => error.FileDescriptorNotASocket,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    const rc = posix.system.bind(socket_fd, @ptrCast(bind_addr), bind_addr_len);
    return switch (posix.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => error.AccessDenied,
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .AFNOSUPPORT => error.AddressFamilyNotSupported,
        .BADF => error.FileDescriptorNotASocket,
        .INVAL => error.InvalidArgument,
        .NOTSOCK => error.FileDescriptorNotASocket,
        else => |err| posix.unexpectedErrno(err),
    };
}

pub fn getSocketName(socket_fd: Socket, bound_addr_storage: *PosixAddress, addr_len: *posix.socklen_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.getsockname(socket_fd, @ptrCast(bound_addr_storage), addr_len);
        return switch (linux.errno(rc)) {
            .SUCCESS => {},
            .BADF => error.FileDescriptorNotASocket,
            .FAULT => error.InvalidArgument,
            .INVAL => error.InvalidArgument,
            .NOTSOCK => error.FileDescriptorNotASocket,
            .NOBUFS => error.SystemResources,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    const rc = posix.system.getsockname(socket_fd, @ptrCast(bound_addr_storage), addr_len);
    return switch (posix.errno(rc)) {
        .SUCCESS => {},
        .BADF => error.FileDescriptorNotASocket,
        .FAULT => error.InvalidArgument,
        .INVAL => error.InvalidArgument,
        .NOTSOCK => error.FileDescriptorNotASocket,
        .NOBUFS => error.SystemResources,
        else => |err| posix.unexpectedErrno(err),
    };
}

pub fn setReuseAddress(socket_fd: Socket, enabled: bool) !void {
    const value: c_int = if (enabled) 1 else 0;
    try posix.setsockopt(socket_fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(value));
}

pub fn setReceiveBufferSize(socket_fd: Socket, size: usize) !void {
    const value: c_int = @intCast(@min(size, @as(usize, @intCast(std.math.maxInt(c_int)))));
    try posix.setsockopt(socket_fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &std.mem.toBytes(value));
}

pub fn setSendBufferSize(socket_fd: Socket, size: usize) !void {
    const value: c_int = @intCast(@min(size, @as(usize, @intCast(std.math.maxInt(c_int)))));
    try posix.setsockopt(socket_fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &std.mem.toBytes(value));
}

pub fn setNonBlocking(socket_fd: Socket, non_blocking: bool) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const flags_rc = linux.fcntl(socket_fd, linux.F.GETFL, 0);
        const flags: u32 = switch (linux.errno(flags_rc)) {
            .SUCCESS => @intCast(flags_rc),
            else => |err| return posix.unexpectedErrno(err),
        };

        var flags_struct: linux.O = @bitCast(flags);
        flags_struct.NONBLOCK = non_blocking;
        const new_flags: u32 = @bitCast(flags_struct);

        const set_rc = linux.fcntl(socket_fd, linux.F.SETFL, new_flags);
        return switch (linux.errno(set_rc)) {
            .SUCCESS => {},
            else => |err| posix.unexpectedErrno(err),
        };
    }

    const flags_rc = posix.system.fcntl(socket_fd, posix.F.GETFL, @as(c_int, 0));
    const flags: u32 = switch (posix.errno(flags_rc)) {
        .SUCCESS => @intCast(flags_rc),
        else => |err| return posix.unexpectedErrno(err),
    };

    var flags_struct: std.c.O = @bitCast(flags);
    flags_struct.NONBLOCK = non_blocking;
    const new_flags: u32 = @bitCast(flags_struct);

    const set_rc = posix.system.fcntl(socket_fd, posix.F.SETFL, new_flags);
    return switch (posix.errno(set_rc)) {
        .SUCCESS => {},
        else => |err| posix.unexpectedErrno(err),
    };
}

pub fn sendTo(socket_fd: Socket, data: []const u8, dest_addr_storage: *const PosixAddress, dest_addr_len: posix.socklen_t) !usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.sendto(socket_fd, data.ptr, data.len, 0, @ptrCast(dest_addr_storage), dest_addr_len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .ACCES, .PERM => error.AccessDenied,
            .AGAIN => error.WouldBlock,
            .BADF => error.FileDescriptorNotASocket,
            .CONNREFUSED => error.ConnectionRefused,
            .DESTADDRREQ => error.DestinationAddressRequired,
            .INTR => error.Interrupted,
            .INVAL => error.InvalidArgument,
            .MSGSIZE => error.MessageTooBig,
            .NETUNREACH => error.NetworkUnreachable,
            .NOBUFS, .NOMEM => error.SystemResources,
            .NOTSOCK => error.FileDescriptorNotASocket,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    const rc = posix.system.sendto(socket_fd, data.ptr, data.len, 0, @ptrCast(dest_addr_storage), dest_addr_len);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => error.AccessDenied,
        .AGAIN => error.WouldBlock,
        .BADF => error.FileDescriptorNotASocket,
        .CONNREFUSED => error.ConnectionRefused,
        .DESTADDRREQ => error.DestinationAddressRequired,
        .INTR => error.Interrupted,
        .INVAL => error.InvalidArgument,
        .MSGSIZE => error.MessageTooBig,
        .NETUNREACH => error.NetworkUnreachable,
        .NOBUFS, .NOMEM => error.SystemResources,
        .NOTSOCK => error.FileDescriptorNotASocket,
        else => |err| posix.unexpectedErrno(err),
    };
}

pub fn send(socket_fd: Socket, data: []const u8) !usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.sendto(socket_fd, data.ptr, data.len, 0, null, 0);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .ACCES, .PERM => error.AccessDenied,
            .AGAIN => error.WouldBlock,
            .BADF => error.FileDescriptorNotASocket,
            .CONNRESET => error.ConnectionResetByPeer,
            .DESTADDRREQ => error.DestinationAddressRequired,
            .INTR => error.Interrupted,
            .INVAL => error.InvalidArgument,
            .MSGSIZE => error.MessageTooBig,
            .NETUNREACH => error.NetworkUnreachable,
            .NOBUFS, .NOMEM => error.SystemResources,
            .NOTCONN => error.SocketNotConnected,
            .NOTSOCK => error.FileDescriptorNotASocket,
            .PIPE => error.BrokenPipe,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    const rc = posix.system.sendto(socket_fd, data.ptr, data.len, 0, null, 0);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .ACCES, .PERM => error.AccessDenied,
        .AGAIN => error.WouldBlock,
        .BADF => error.FileDescriptorNotASocket,
        .CONNRESET => error.ConnectionResetByPeer,
        .DESTADDRREQ => error.DestinationAddressRequired,
        .INTR => error.Interrupted,
        .INVAL => error.InvalidArgument,
        .MSGSIZE => error.MessageTooBig,
        .NETUNREACH => error.NetworkUnreachable,
        .NOBUFS, .NOMEM => error.SystemResources,
        .NOTCONN => error.SocketNotConnected,
        .NOTSOCK => error.FileDescriptorNotASocket,
        .PIPE => error.BrokenPipe,
        else => |err| posix.unexpectedErrno(err),
    };
}

pub fn receiveFrom(socket_fd: Socket, buffer: []u8, src_addr_storage: *PosixAddress, addr_len: *posix.socklen_t) !usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.recvfrom(socket_fd, buffer.ptr, buffer.len, 0, @ptrCast(src_addr_storage), addr_len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .BADF => error.FileDescriptorNotASocket,
            .CONNREFUSED => error.ConnectionRefused,
            .FAULT => error.InvalidArgument,
            .INTR => error.Interrupted,
            .INVAL => error.InvalidArgument,
            .NOMEM => error.SystemResources,
            .NOTCONN => error.SocketNotConnected,
            .NOTSOCK => error.FileDescriptorNotASocket,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    const rc = posix.system.recvfrom(socket_fd, buffer.ptr, buffer.len, 0, @ptrCast(src_addr_storage), addr_len);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => error.WouldBlock,
        .BADF => error.FileDescriptorNotASocket,
        .CONNREFUSED => error.ConnectionRefused,
        .FAULT => error.InvalidArgument,
        .INTR => error.Interrupted,
        .INVAL => error.InvalidArgument,
        .NOMEM => error.SystemResources,
        .NOTCONN => error.SocketNotConnected,
        .NOTSOCK => error.FileDescriptorNotASocket,
        else => |err| posix.unexpectedErrno(err),
    };
}

pub fn receive(socket_fd: Socket, buffer: []u8) !usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.recvfrom(socket_fd, buffer.ptr, buffer.len, 0, null, null);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            .BADF => error.FileDescriptorNotASocket,
            .CONNRESET => error.ConnectionResetByPeer,
            .FAULT => error.InvalidArgument,
            .INTR => error.Interrupted,
            .INVAL => error.InvalidArgument,
            .NOMEM => error.SystemResources,
            .NOTCONN => error.SocketNotConnected,
            .NOTSOCK => error.FileDescriptorNotASocket,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    const rc = posix.system.recvfrom(socket_fd, buffer.ptr, buffer.len, 0, null, null);
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .AGAIN => error.WouldBlock,
        .BADF => error.FileDescriptorNotASocket,
        .CONNRESET => error.ConnectionResetByPeer,
        .FAULT => error.InvalidArgument,
        .INTR => error.Interrupted,
        .INVAL => error.InvalidArgument,
        .NOMEM => error.SystemResources,
        .NOTCONN => error.SocketNotConnected,
        .NOTSOCK => error.FileDescriptorNotASocket,
        else => |err| posix.unexpectedErrno(err),
    };
}

pub fn close(socket_fd: Socket) void {
    _ = posix.system.close(socket_fd);
}
