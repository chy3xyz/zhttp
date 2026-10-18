//! HTTP/3 client on the native QUIC transport.

const std = @import("std");
const posix = std.posix;
const native = @import("native/transport.zig");
const h3 = @import("native/http3.zig");
const qlog = @import("native/qlog.zig");

pub const ClientTls = native.ClientTls;
pub const Stats = native.Stats;
/// qlog types are re-exported here so callers do not need a native import.
pub const Qlog = qlog;

pub const Client = struct {
    allocator: std.mem.Allocator,
    host: []u8,
    connection: *native.Connection,
    session: *h3.Session,

    pub const Answer = struct {
        status: u16,
        header_text: []const u8,
        body: []const u8,
    };

    pub const Header = h3.HeaderField;

    pub const Options = struct {
        /// Optional qlog sink. The header and connection_started are written
        /// during init, before the first packet is scheduled.
        qlog: ?qlog.Config = null,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        tls: ClientTls,
    ) !Client {
        return initWithOptions(allocator, host, port, tls, .{});
    }

    /// Client constructor with optional qlog installation. The existing init
    /// signature stays as a thin wrapper.
    pub fn initWithOptions(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        tls: ClientTls,
        options: Options,
    ) !Client {
        const host_copy = try allocator.dupe(u8, host);
        errdefer allocator.free(host_copy);
        const connection = try native.connectWithQlog(allocator, host, port, tls, options.qlog);
        errdefer connection.deinit();
        const session = try h3.Session.initClient(allocator, connection, 1024 * 1024);
        errdefer session.deinit();
        return .{
            .allocator = allocator,
            .host = host_copy,
            .connection = connection,
            .session = session,
        };
    }

    pub fn deinit(self: *Client) void {
        self.connection.close(0x0100, "client done");
        self.session.deinit();
        self.connection.deinit();
        self.allocator.free(self.host);
    }

    /// By-value snapshot of this client connection's transport counters.
    pub fn stats(self: *const Client) Stats {
        return self.connection.statsSnapshot();
    }

    pub fn get(self: *Client, path: []const u8) ![]const u8 {
        const answer = try self.request(path);
        self.allocator.free(answer.header_text);
        return answer.body;
    }

    pub fn request(self: *Client, path: []const u8) !Answer {
        return self.send("GET", path, &.{}, "");
    }

    pub fn send(
        self: *Client,
        method: []const u8,
        path: []const u8,
        headers: []const Header,
        body: []const u8,
    ) !Answer {
        const stream_id = try self.session.beginRequest(method, path, self.host, headers, body);
        const deadline = native.nowNanos() +| request_timeout_ns;
        var buf: [native.max_datagram_size]u8 = undefined;

        while (native.nowNanos() < deadline) {
            self.connection.service() catch {};
            self.session.service() catch {};
            if (try self.session.takeAnswer(stream_id)) |answer| {
                return .{ .status = answer.status, .header_text = answer.header_text, .body = answer.body };
            }
            if (self.connection.isClosed()) return error.ConnectionClosed;

            var fds = [_]posix.pollfd{.{ .fd = self.connection.socket, .events = posix.POLL.IN, .revents = 0 }};
            const ready = posix.poll(&fds, 10) catch 0;
            if (ready > 0 and (fds[0].revents & posix.POLL.IN) != 0) {
                var peer: posix.sockaddr.in = undefined;
                var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
                const n = std.c.recvfrom(
                    self.connection.socket,
                    buf[0..].ptr,
                    buf.len,
                    0,
                    @ptrCast(&peer),
                    &peer_len,
                );
                if (n > 0) self.connection.handleDatagram(buf[0..@intCast(n)]) catch {};
            }
        }
        return error.Timeout;
    }
};

const request_timeout_ns = 30 * std.time.ns_per_s;
