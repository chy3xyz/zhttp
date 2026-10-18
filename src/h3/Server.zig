//! HTTP/3 server on the native QUIC transport.

const std = @import("std");
const native = @import("native/transport.zig");
const h3 = @import("native/http3.zig");
const qlog = @import("native/qlog.zig");

/// qlog types are re-exported here so callers do not need a native import.
pub const Qlog = qlog;

pub const Method = h3.Method;
pub const Headers = h3.Headers;
pub const StatusCode = h3.StatusCode;
pub const Request = h3.Request;
pub const Response = h3.Response;
pub const Header = h3.Header;
pub const Handler = h3.Handler;
pub const ContextHandler = h3.ContextHandler;
pub const Stats = native.Stats;

pub const Options = struct {
    /// Connections quiet for this long start closing.
    idle_timeout_ns: u64 = 30 * std.time.ns_per_s,
    /// Reserved for a future closing period; close currently takes effect
    /// immediately after the CONNECTION_CLOSE is written.
    closing_period_ns: u64 = 3 * std.time.ns_per_s,
    /// Largest request body accepted; a larger one is answered with 413.
    max_request_body_bytes: usize = 1024 * 1024,
    /// Connection-level receive flow-control window advertised to clients.
    initial_max_data: u64 = native.default_flow_window,
    /// Per-stream receive flow-control window advertised to clients.
    initial_max_stream_data: u64 = native.default_flow_window,
    /// Require an HMAC Retry token before allocating a Connection/Session.
    /// The built-in zhttp H3 client and aioquic answer Retry. Enabled by
    /// default for public-internet safety: the token validates the client's
    /// address before the handshake flight has to fit inside the RFC 9000
    /// Section 8.1 anti-amplification budget.
    retry: bool = true,
    /// Optional qlog sink. Disabled when null; when set, the listener writes
    /// the JSON-SEQ header before accepting any datagram and each connection
    /// emits transport/connectivity events.
    qlog: ?qlog.Config = null,
};

/// Owns the sessions for accepted connections. Heap-allocated so its address
/// stays put while the Server itself is returned by value from init.
const Registry = struct {
    allocator: std.mem.Allocator,
    handler: ?Handler,
    context_handler: ?h3.ContextHandler,
    handler_context: ?*anyopaque,
    max_body_bytes: usize,
    sessions: std.AutoHashMapUnmanaged(*native.Connection, *h3.Session) = .empty,

    fn create(allocator: std.mem.Allocator, handler: Handler, max_body_bytes: usize) !*Registry {
        const self = try allocator.create(Registry);
        self.* = .{
            .allocator = allocator,
            .handler = handler,
            .context_handler = null,
            .handler_context = null,
            .max_body_bytes = max_body_bytes,
        };
        return self;
    }

    fn createWithContext(
        allocator: std.mem.Allocator,
        context: ?*anyopaque,
        handler: h3.ContextHandler,
        max_body_bytes: usize,
    ) !*Registry {
        const self = try allocator.create(Registry);
        self.* = .{
            .allocator = allocator,
            .handler = null,
            .context_handler = handler,
            .handler_context = context,
            .max_body_bytes = max_body_bytes,
        };
        return self;
    }

    fn deinit(self: *Registry) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            // Best-effort GOAWAY-less close: the listener frees the connection
            // after the sessions are gone.
            entry.key_ptr.*.close(0x0100, "server shutdown");
            entry.value_ptr.*.deinit();
        }
        self.sessions.deinit(self.allocator);
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    fn onConnection(raw: *anyopaque, connection: *native.Connection) void {
        const self: *Registry = @ptrCast(@alignCast(raw));
        const session = if (self.context_handler) |handler|
            h3.Session.initServerWithContext(
                self.allocator,
                connection,
                self.handler_context,
                handler,
                self.max_body_bytes,
            ) catch return
        else
            h3.Session.initServer(
                self.allocator,
                connection,
                self.handler orelse return,
                self.max_body_bytes,
            ) catch return;
        self.sessions.put(self.allocator, connection, session) catch {
            session.deinit();
        };
    }

    fn serviceAll(self: *Registry) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (entry.key_ptr.*.isClosed()) continue;
            entry.value_ptr.*.service() catch {};
        }
    }

    /// Free sessions whose connection has closed. This must run before the
    /// Listener frees the Connection: Session.deinit clears conn.handler.
    fn reapClosed(self: *Registry) void {
        var closed: std.ArrayListUnmanaged(*native.Connection) = .empty;
        defer closed.deinit(self.allocator);
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (!entry.key_ptr.*.isClosed()) continue;
            closed.append(self.allocator, entry.key_ptr.*) catch return;
        }
        for (closed.items) |connection| {
            if (self.sessions.fetchRemove(connection)) |entry| {
                const session = @constCast(entry.value);
                session.deinit();
            }
        }
    }

    fn goAwayAll(self: *Registry) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| entry.value_ptr.*.goAway() catch {};
    }

    fn count(self: *const Registry) usize {
        return self.sessions.count();
    }

    fn closeIdle(self: *Registry, timeout_ns: u64) void {
        const now = native.nowMicros();
        const timeout_us = timeout_ns / 1000;
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            const connection = entry.key_ptr.*;
            if (connection.isClosed()) continue;
            if (now -| connection.last_activity_us < timeout_us) continue;
            connection.close(0x0100, "idle timeout");
        }
    }
};

pub const Server = struct {
    listener: native.Listener,
    allocator: std.mem.Allocator,
    registry: *Registry,
    options: Options,
    stopping: std.atomic.Value(bool) = .init(false),
    draining: std.atomic.Value(bool) = .init(false),
    goaway_sent: bool = false,
    drained: std.atomic.Value(bool) = .init(false),
    drained_left: std.atomic.Value(u32) = .init(0),

    const poll_ns = 10 * std.time.ns_per_ms;

    pub fn init(allocator: std.mem.Allocator, port: u16, handler: Handler, options: Options) !Server {
        return initInternal(allocator, port, handler, null, null, options);
    }

    /// Like init, but the handler receives an application context pointer.
    pub fn initWithContext(
        allocator: std.mem.Allocator,
        port: u16,
        context: ?*anyopaque,
        handler: h3.ContextHandler,
        options: Options,
    ) !Server {
        return initInternal(allocator, port, null, handler, context, options);
    }

    fn initInternal(
        allocator: std.mem.Allocator,
        port: u16,
        handler: ?Handler,
        context_handler: ?h3.ContextHandler,
        context: ?*anyopaque,
        options: Options,
    ) !Server {
        var listener = try native.Listener.init(allocator, port);
        errdefer listener.deinit();
        listener.local_max_data = options.initial_max_data;
        listener.local_max_stream_data = options.initial_max_stream_data;
        if (options.retry) listener.enableRetry();
        if (options.qlog) |config| listener.installQlog(config);

        const registry = if (context_handler) |ch|
            try Registry.createWithContext(allocator, context, ch, options.max_request_body_bytes)
        else
            try Registry.create(allocator, handler orelse return error.HandlerRequired, options.max_request_body_bytes);
        errdefer registry.deinit();

        listener.on_connection = .{ .context = registry, .callback = Registry.onConnection };
        return .{
            .listener = listener,
            .allocator = allocator,
            .registry = registry,
            .options = options,
        };
    }

    pub fn deinit(self: *Server) void {
        self.registry.deinit();
        self.listener.deinit();
    }

    pub fn stop(self: *Server) void {
        self.stopping.store(true, .release);
    }

    /// Number of live sessions. Safe from the run thread, or after `run`
    /// returns; the registry itself is not synchronized for concurrent reads.
    pub fn connectionCount(self: *const Server) usize {
        return self.registry.count();
    }

    /// Aggregate transport counters for live connections plus connections that
    /// have already been reaped. The listener retains the counters, so this
    /// also works after run returns. Call from the run thread or after run
    /// stops; the maps are not synchronized for concurrent reads.
    pub fn stats(self: *const Server) Stats {
        return self.listener.totalStats();
    }

    pub fn stopGraceful(self: *Server, timeout_ns: u64) u32 {
        self.draining.store(true, .release);
        const deadline = native.nowNanos() +| timeout_ns;
        while (!self.drained.load(.acquire) and !self.stopping.load(.acquire) and native.nowNanos() < deadline) {
            native.sleepNs(std.time.ns_per_ms);
        }
        self.drained.store(true, .release);
        self.stopping.store(true, .release);
        return self.drained_left.load(.acquire);
    }

    pub fn run(self: *Server) !void {
        var buf: [native.max_datagram_size]u8 = undefined;
        var last_reap = native.nowNanos();
        while (!self.stopping.load(.acquire)) {
            const readable = self.listener.pollReadable(poll_ns);
            const handled = self.listener.readAndDispatch(&buf, 32);
            self.listener.serviceAll();
            self.registry.serviceAll();
            // Sessions must go first: Session.deinit clears conn.handler, and
            // the Listener may then release the Connection.
            self.registry.reapClosed();
            self.listener.reapClosed();

            if (self.draining.load(.acquire)) {
                if (!self.goaway_sent) {
                    self.registry.goAwayAll();
                    self.goaway_sent = true;
                }
                const active = self.registry.count();
                self.drained_left.store(@intCast(active), .release);
                if (active == 0) self.drained.store(true, .release);
            }
            if (native.nowNanos() -| last_reap >= std.time.ns_per_s) {
                self.registry.closeIdle(self.options.idle_timeout_ns);
                self.registry.reapClosed();
                self.listener.reapClosed();
                last_reap = native.nowNanos();
            }
            // pollReadable already blocks for up to poll_ns; only back off on
            // an idle/error pass. Sleeping unconditionally here used to cap a
            // sequential connection at roughly 1000 req/s.
            if (!readable and handled == 0) native.sleepNs(std.time.ns_per_ms);
        }
        self.registry.serviceAll();
    }
};

test "H3 server init and deinit" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const handler = struct {
        fn handle(_: std.mem.Allocator, _: *const Request) Response {
            return .{ .body = "ok" };
        }
    }.handle;

    var server = try Server.init(allocator, 0, handler, .{});
    defer server.deinit();
    try std.testing.expectEqual(@as(usize, 0), server.connectionCount());
}

test "H3 server reaps closed connections" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const qtls = @import("native/qtls.zig");
    try qtls.setServerCert(@embedFile("test_cert.pem"), @embedFile("test_key.pem"));
    defer qtls.deinitServer();

    var handled: usize = 0;
    const handler = struct {
        fn handle(context: ?*anyopaque, _: std.mem.Allocator, _: *const Request) Response {
            const count: *usize = @ptrCast(@alignCast(context orelse return .{ .status = .internal_server_error }));
            count.* += 1;
            return .{ .body = "ok" };
        }
    }.handle;

    var server = try Server.initWithContext(allocator, 0, &handled, handler, .{});
    defer server.deinit();
    const port = std.mem.bigToNative(u16, server.listener.local_addr.port);

    const Runner = struct {
        fn run(s: *Server) void {
            s.run() catch {};
        }
    };
    const thread = try std.Thread.spawn(.{}, Runner.run, .{&server});

    const H3Client = @import("Client.zig");
    var client = try H3Client.Client.init(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    const body = try client.get("/");
    allocator.free(body);
    try std.testing.expectEqual(@as(usize, 1), handled);
    client.deinit();

    // Give the run loop time to process CONNECTION_CLOSE and reap the session.
    native.sleepNs(200 * std.time.ns_per_ms);
    server.stop();
    thread.join();

    try std.testing.expectEqual(@as(usize, 0), server.connectionCount());
}
