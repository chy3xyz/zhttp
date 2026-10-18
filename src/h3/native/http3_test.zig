const std = @import("std");
const transport = @import("transport.zig");
const http3 = @import("http3.zig");
const qpack = @import("qpack.zig");
const qtls = @import("qtls.zig");

fn handle(allocator: std.mem.Allocator, request: *const http3.Request) http3.Response {
    _ = allocator;
    if (!std.mem.eql(u8, request.path, "/hello")) {
        return .{ .status = .not_found, .body = "not found" };
    }
    return .{ .body = "world" };
}

fn handleAuthority(_: std.mem.Allocator, request: *const http3.Request) http3.Response {
    return .{ .body = request.authority };
}

fn handleScheme(_: std.mem.Allocator, request: *const http3.Request) http3.Response {
    return .{ .body = request.scheme };
}

fn handleConnect(_: std.mem.Allocator, request: *const http3.Request) http3.Response {
    if (request.method != .CONNECT) return .{ .status = .bad_request, .body = "not CONNECT" };
    if (request.path.len != 0) return .{ .status = .bad_request, .body = "CONNECT must omit :path" };
    if (request.scheme.len != 0) return .{ .status = .bad_request, .body = "CONNECT must omit :scheme" };
    return .{ .body = request.authority };
}

var dynamic_header_seen = false;

fn handleDynamicHeader(_: std.mem.Allocator, request: *const http3.Request) http3.Response {
    const value = request.headers.get("x-dynamic") orelse {
        dynamic_header_seen = false;
        return .{ .status = .bad_request, .body = "missing dynamic header" };
    };
    dynamic_header_seen = std.mem.eql(u8, value, "hello");
    if (!dynamic_header_seen) {
        return .{ .status = .bad_request, .body = "wrong dynamic header" };
    }
    return .{ .body = "seen" };
}

var stream_cleanup_count: usize = 0;

fn streamCleanup(_: ?*anyopaque) void {
    stream_cleanup_count += 1;
}

fn handleStreamCleanup(_: std.mem.Allocator, request: *const http3.Request) http3.Response {
    if (!std.mem.eql(u8, request.path, "/stream")) {
        return .{ .status = .not_found, .body = "not found" };
    }
    stream_progress = 0;
    return .{
        .content_type = "application/octet-stream",
        .body_reader = streamReader,
        .body_context = &stream_progress,
        .body_reader_deinit = streamCleanup,
    };
}

const stream_body_size = 64 * 1024;
var stream_progress: usize = 0;

fn streamReader(context: ?*anyopaque, buf: []u8) anyerror!usize {
    const at: *usize = @ptrCast(@alignCast(context orelse return 0));
    if (at.* >= stream_body_size) return 0;
    const n = @min(buf.len, stream_body_size - at.*);
    @memset(buf[0..n], 'x');
    at.* += n;
    return n;
}

fn handleStream(_: std.mem.Allocator, request: *const http3.Request) http3.Response {
    if (!std.mem.eql(u8, request.path, "/stream")) {
        return .{ .status = .not_found, .body = "not found" };
    }
    stream_progress = 0;
    return .{
        .content_type = "application/octet-stream",
        .body_reader = streamReader,
        .body_context = &stream_progress,
    };
}

const Context = struct {
    allocator: std.mem.Allocator,
    handler: http3.Handler,
    drop_every: usize = 0,
    sessions: std.ArrayListUnmanaged(*http3.Session) = .empty,

    fn onConnection(raw: *anyopaque, conn: *transport.Connection) void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        conn.setDropOutgoingEvery(self.drop_every);
        const session = http3.Session.initServer(self.allocator, conn, self.handler, 1024 * 1024) catch return;
        self.sessions.append(self.allocator, session) catch {
            session.deinit();
        };
    }

    fn deinit(self: *@This()) void {
        for (self.sessions.items) |session| session.deinit();
        self.sessions.deinit(self.allocator);
    }
};

fn runOnce(
    allocator: std.mem.Allocator,
    path: []const u8,
    handler: http3.Handler,
) !http3.Session.Answer {
    return runOnceOptions(allocator, path, handler, 0, 0, transport.default_flow_window, transport.default_flow_window);
}

fn runOnceOptions(
    allocator: std.mem.Allocator,
    path: []const u8,
    handler: http3.Handler,
    drop_server_every: usize,
    drop_client_every: usize,
    client_window: u64,
    server_window: u64,
) !http3.Session.Answer {
    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();
    listener.local_max_data = server_window;
    listener.local_max_stream_data = server_window;

    var context: Context = .{ .allocator = allocator, .handler = handler, .drop_every = drop_server_every };
    defer context.deinit();
    listener.on_connection = .{ .context = &context, .callback = Context.onConnection };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client_conn = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
        .initial_max_data = client_window,
        .initial_max_stream_data = client_window,
    });
    defer client_conn.deinit();
    client_conn.setDropOutgoingEvery(drop_client_every);
    const client = try http3.Session.initClient(allocator, client_conn, 1024 * 1024);
    defer client.deinit();

    var buf: [transport.max_datagram_size]u8 = undefined;
    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    var stream_id: ?u64 = null;

    while (transport.nowNanos() < deadline) {
        client_conn.service() catch {};
        client.service() catch {};
        _ = listener.readAndDispatch(&buf, 8);
        listener.serviceAll();
        for (context.sessions.items) |session| session.service() catch {};

        var peer: std.posix.sockaddr.in = undefined;
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        const n = std.c.recvfrom(
            client_conn.socket,
            buf[0..].ptr,
            buf.len,
            std.c.MSG.DONTWAIT,
            @ptrCast(&peer),
            &peer_len,
        );
        if (n > 0) client_conn.handleDatagram(buf[0..@intCast(n)]) catch {};

        if (client_conn.isEstablished() and stream_id == null) {
            stream_id = try client.beginRequest("GET", path, "localhost", &.{}, "");
        }
        if (stream_id) |id| {
            if (try client.takeAnswer(id)) |answer| return answer;
        }
        transport.sleepNs(std.time.ns_per_ms);
    }
    return error.NoAnswer;
}

fn appendVarint(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, value_in: u64) !void {
    const value = value_in;
    if (value < 0x40) {
        try out.append(allocator, @intCast(value));
        return;
    }
    const len: usize = if (value < 0x4000) 2 else if (value < 0x40000000) 4 else 8;
    try out.ensureUnusedCapacity(allocator, len);
    const prefix: u8 = switch (len) {
        2 => 0x40,
        4 => 0x80,
        else => 0xc0,
    };
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const shift: u6 = @intCast((len - 1 - i) * 8);
        const byte: u8 = @truncate(value >> shift);
        out.appendAssumeCapacity(if (i == 0) (byte & 0x3f) | prefix else byte);
    }
}

/// Queue one complete HEADERS frame with FIN on a raw client bidi stream. The
/// client session only sees the response, which lets a test put arbitrary
/// pseudo-header combinations on the wire.
fn queueRequestHeaders(
    allocator: std.mem.Allocator,
    conn: *transport.Connection,
    stream_id: u64,
    fields: []const http3.HeaderField,
) !void {
    const block = try qpack.encode(allocator, fields);
    defer allocator.free(block);

    var frame: std.ArrayListUnmanaged(u8) = .empty;
    defer frame.deinit(allocator);
    try appendVarint(&frame, allocator, 0x01); // HEADERS frame type
    try appendVarint(&frame, allocator, block.len);
    try frame.appendSlice(allocator, block);
    try conn.queueStreamData(stream_id, frame.items, true);
}

/// Like runOnce, but the request is a caller-supplied pseudo-header list sent
/// over a raw bidi stream. Used for invalid or unusual header blocks that
/// Session.beginRequest never produces.
fn runRawOnce(
    allocator: std.mem.Allocator,
    fields: []const http3.HeaderField,
    handler: http3.Handler,
) !http3.Session.Answer {
    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();

    var context: Context = .{ .allocator = allocator, .handler = handler };
    defer context.deinit();
    listener.on_connection = .{ .context = &context, .callback = Context.onConnection };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client_conn = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    });
    defer client_conn.deinit();
    const client = try http3.Session.initClient(allocator, client_conn, 1024 * 1024);
    defer client.deinit();

    var buf: [transport.max_datagram_size]u8 = undefined;
    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    var stream_id: ?u64 = null;

    while (transport.nowNanos() < deadline) {
        client_conn.service() catch {};
        client.service() catch {};
        _ = listener.readAndDispatch(&buf, 8);
        listener.serviceAll();
        for (context.sessions.items) |session| session.service() catch {};

        var peer: std.posix.sockaddr.in = undefined;
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        const n = std.c.recvfrom(
            client_conn.socket,
            buf[0..].ptr,
            buf.len,
            std.c.MSG.DONTWAIT,
            @ptrCast(&peer),
            &peer_len,
        );
        if (n > 0) client_conn.handleDatagram(buf[0..@intCast(n)]) catch {};

        if (client_conn.isEstablished() and stream_id == null) {
            const id = try client_conn.createBidiStream();
            try queueRequestHeaders(allocator, client_conn, id, fields);
            stream_id = id;
        }
        if (stream_id) |id| {
            if (try client.takeAnswer(id)) |answer| return answer;
        }
        transport.sleepNs(std.time.ns_per_ms);
    }
    return error.NoAnswer;
}

fn expectRawStatus(
    allocator: std.mem.Allocator,
    fields: []const http3.HeaderField,
    handler: http3.Handler,
    expected: u16,
) !void {
    const got = try runRawOnce(allocator, fields, handler);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(expected, got.status);
}

const CaptureStream = struct {
    reasm: transport.Reassembler,
    fin: bool = false,

    fn deinit(self: *CaptureStream) void {
        const allocator = self.reasm.allocator;
        self.reasm.deinit();
        allocator.destroy(self);
    }
};

const CapturedResponse = struct {
    status: u16,
    body: []u8,
};

/// Captures the server's response on a raw client connection that has no HTTP/3
/// Session (so the test can inject arbitrary peer encoder-stream data).
const Capture = struct {
    allocator: std.mem.Allocator,
    streams: std.AutoHashMapUnmanaged(u64, *CaptureStream) = .empty,
    closed_code: ?u64 = null,

    fn deinit(self: *Capture) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| entry.value_ptr.*.deinit();
        self.streams.deinit(self.allocator);
    }

    fn onStream(raw: *anyopaque, stream_id: u64, offset: u64, data: []const u8, fin: bool) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(raw));
        // Responses arrive on client-initiated bidirectional streams.
        if (stream_id & 0x3 != 0) return;
        const stream = self.streams.get(stream_id) orelse blk: {
            const created = try self.allocator.create(CaptureStream);
            errdefer self.allocator.destroy(created);
            created.* = .{ .reasm = try transport.Reassembler.init(self.allocator) };
            errdefer created.reasm.deinit();
            try self.streams.put(self.allocator, stream_id, created);
            break :blk created;
        };
        _ = stream.reasm.insert(offset, data, fin) catch return;
        if (fin) stream.fin = true;
    }

    fn onEstablished(_: *anyopaque) anyerror!void {}

    fn onClosed(raw: *anyopaque, code: u64) void {
        const self: *Capture = @ptrCast(@alignCast(raw));
        self.closed_code = code;
    }

    fn takeResponse(self: *Capture, stream_id: u64) !?CapturedResponse {
        const stream = self.streams.get(stream_id) orelse return null;
        if (!stream.fin or !stream.reasm.complete()) return null;
        const data = stream.reasm.buf.items[0..stream.reasm.contiguous];

        var cursor: usize = 0;
        var status: u16 = 0;
        var body: std.ArrayListUnmanaged(u8) = .empty;
        errdefer body.deinit(self.allocator);

        while (http3.readFrame(data, &cursor)) |frame| {
            switch (frame.frame_type) {
                0x01 => {
                    var headers = qpack.decode(self.allocator, frame.payload) catch
                        return error.InvalidResponse;
                    defer headers.deinit();
                    const text = headers.get(":status") orelse return error.InvalidResponse;
                    status = std.fmt.parseInt(u16, text, 10) catch return error.InvalidResponse;
                },
                0x00 => try body.appendSlice(self.allocator, frame.payload),
                else => {},
            }
        }
        if (status == 0) return null;
        return .{ .status = status, .body = try body.toOwnedSlice(self.allocator) };
    }
};

/// Run one request from a raw transport client: announce a peer QPACK encoder
/// stream carrying encoder_instructions, then send one HEADERS block. The
/// response is captured and decoded without a client Session.
fn runDynamicEncoderOnce(
    allocator: std.mem.Allocator,
    encoder_instructions: []const u8,
    block: []const u8,
    handler: http3.Handler,
) !CapturedResponse {
    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();

    var context: Context = .{ .allocator = allocator, .handler = handler };
    defer context.deinit();
    listener.on_connection = .{ .context = &context, .callback = Context.onConnection };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client_conn = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    });
    defer client_conn.deinit();

    var capture: Capture = .{ .allocator = allocator };
    defer capture.deinit();
    client_conn.handler = .{
        .context = &capture,
        .on_stream_frame = Capture.onStream,
        .on_established = Capture.onEstablished,
        .on_closed = Capture.onClosed,
    };
    defer client_conn.handler = null;

    var buf: [transport.max_datagram_size]u8 = undefined;
    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    var encoder_sent = false;
    var request_sent = false;
    var request_stream: ?u64 = null;

    while (transport.nowNanos() < deadline) {
        client_conn.service() catch {};
        _ = listener.readAndDispatch(&buf, 8);
        listener.serviceAll();
        for (context.sessions.items) |session| session.service() catch {};

        var peer: std.posix.sockaddr.in = undefined;
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        const n = std.c.recvfrom(
            client_conn.socket,
            buf[0..].ptr,
            buf.len,
            std.c.MSG.DONTWAIT,
            @ptrCast(&peer),
            &peer_len,
        );
        if (n > 0) client_conn.handleDatagram(buf[0..@intCast(n)]) catch {};

        if (client_conn.isEstablished() and !encoder_sent) {
            // Announce the encoder stream first; the request follows on the
            // next pass so the server applies the insert first.
            const stream_id = try client_conn.createUniStream();
            var encoder: std.ArrayListUnmanaged(u8) = .empty;
            defer encoder.deinit(allocator);
            try appendVarint(&encoder, allocator, 0x02);
            try encoder.appendSlice(allocator, encoder_instructions);
            try client_conn.queueStreamData(stream_id, encoder.items, false);
            encoder_sent = true;
        } else if (encoder_sent and !request_sent) {
            const stream_id = try client_conn.createBidiStream();
            var frame: std.ArrayListUnmanaged(u8) = .empty;
            defer frame.deinit(allocator);
            try appendVarint(&frame, allocator, 0x01);
            try appendVarint(&frame, allocator, block.len);
            try frame.appendSlice(allocator, block);
            try client_conn.queueStreamData(stream_id, frame.items, true);
            request_stream = stream_id;
            request_sent = true;
        }

        if (request_stream) |stream_id| {
            if (try capture.takeResponse(stream_id)) |response| return response;
        }
        if (capture.closed_code != null) return error.ConnectionClosed;
        transport.sleepNs(std.time.ns_per_ms);
    }
    return error.NoAnswer;
}

test "native HTTP/3: GET request and response over QUIC" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const got = try runOnce(allocator, "/hello", handle);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(@as(u16, 200), got.status);
    try std.testing.expectEqualStrings("world", got.body);
}

test "native HTTP/3: streamed response body" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const got = try runOnce(allocator, "/stream", handleStream);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(@as(u16, 200), got.status);
    try std.testing.expectEqual(stream_body_size, got.body.len);
    try std.testing.expectEqual(@as(u8, 'x'), got.body[0]);
    try std.testing.expectEqual(@as(u8, 'x'), got.body[got.body.len - 1]);
}

test "native HTTP/3: retransmits lost packets" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    // Drop one in seven server datagrams and one in eleven client datagrams.
    // The handshake, the request, and the response all exercise the retained
    // packet history in transport.zig.
    const before = transport.test_retransmit_count;
    const got = try runOnceOptions(allocator, "/hello", handle, 7, 11, transport.default_flow_window, transport.default_flow_window);
    try std.testing.expect(transport.test_retransmit_count > before);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(@as(u16, 200), got.status);
    try std.testing.expectEqualStrings("world", got.body);
}

test "native HTTP/3: respects small flow-control windows" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    // 64 KiB of response through 16 KiB windows: the server must stop at the
    // peer's MAX_DATA/MAX_STREAM_DATA and resume when the client updates them.
    const window: u64 = 16 * 1024;
    const before_data = transport.test_max_data_sent;
    const before_stream = transport.test_max_stream_data_sent;
    const before_blocked = transport.test_send_blocked;
    const got = try runOnceOptions(allocator, "/stream", handleStream, 0, 0, window, window);
    try std.testing.expect(transport.test_max_data_sent > before_data);
    try std.testing.expect(transport.test_max_stream_data_sent > before_stream);
    try std.testing.expect(transport.test_send_blocked > before_blocked);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(@as(u16, 200), got.status);
    try std.testing.expectEqual(stream_body_size, got.body.len);
    try std.testing.expectEqual(@as(u8, 'x'), got.body[got.body.len - 1]);
}

test "native HTTP/3: concurrent streams on one connection" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();
    var context: Context = .{ .allocator = allocator, .handler = handle };
    defer context.deinit();
    listener.on_connection = .{ .context = &context, .callback = Context.onConnection };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client_conn = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client_conn.deinit();
    const client = try http3.Session.initClient(allocator, client_conn, 1024 * 1024);
    defer client.deinit();

    const request_count = 20;
    var ids: [request_count]u64 = undefined;
    var opened = false;
    var completed: usize = 0;
    var buf: [transport.max_datagram_size]u8 = undefined;
    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;

    while (transport.nowNanos() < deadline and completed < request_count) {
        client_conn.service() catch {};
        client.service() catch {};
        _ = listener.readAndDispatch(&buf, 8);
        listener.serviceAll();
        for (context.sessions.items) |session| session.service() catch {};

        var peer: std.posix.sockaddr.in = undefined;
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        const n = std.c.recvfrom(
            client_conn.socket,
            buf[0..].ptr,
            buf.len,
            std.c.MSG.DONTWAIT,
            @ptrCast(&peer),
            &peer_len,
        );
        if (n > 0) client_conn.handleDatagram(buf[0..@intCast(n)]) catch {};

        if (!opened and client_conn.isEstablished()) {
            for (&ids) |*id| id.* = try client.beginRequest("GET", "/hello", "localhost", &.{}, "");
            opened = true;
        }
        if (opened) {
            for (ids) |id| {
                if (try client.takeAnswer(id)) |answer| {
                    defer allocator.free(answer.header_text);
                    defer allocator.free(answer.body);
                    try std.testing.expectEqual(@as(u16, 200), answer.status);
                    try std.testing.expectEqualStrings("world", answer.body);
                    completed += 1;
                }
            }
        }
        transport.sleepNs(std.time.ns_per_ms);
    }

    try std.testing.expectEqual(@as(usize, request_count), completed);
}

test "native HTTP/3: completed requests do not accumulate" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();
    var context: Context = .{ .allocator = allocator, .handler = handle };
    defer context.deinit();
    listener.on_connection = .{ .context = &context, .callback = Context.onConnection };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client_conn = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client_conn.deinit();
    const client = try http3.Session.initClient(allocator, client_conn, 1024 * 1024);
    defer client.deinit();

    var buf: [transport.max_datagram_size]u8 = undefined;
    const deadline = transport.nowNanos() + 12 * std.time.ns_per_s;
    var baseline: ?usize = null;

    for (0..50) |_| {
        var stream_id: ?u64 = null;
        var answered = false;
        while (!answered and transport.nowNanos() < deadline) {
            client_conn.service() catch {};
            client.service() catch {};
            _ = listener.readAndDispatch(&buf, 8);
            listener.serviceAll();
            for (context.sessions.items) |session| session.service() catch {};

            var peer: std.posix.sockaddr.in = undefined;
            var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
            const n = std.c.recvfrom(
                client_conn.socket,
                buf[0..].ptr,
                buf.len,
                std.c.MSG.DONTWAIT,
                @ptrCast(&peer),
                &peer_len,
            );
            if (n > 0) client_conn.handleDatagram(buf[0..@intCast(n)]) catch {};

            if (client_conn.isEstablished() and stream_id == null) {
                stream_id = try client.beginRequest("GET", "/hello", "localhost", &.{}, "");
            }
            if (stream_id) |id| {
                if (try client.takeAnswer(id)) |answer| {
                    defer allocator.free(answer.header_text);
                    defer allocator.free(answer.body);
                    answered = true;
                }
            }
            transport.sleepNs(std.time.ns_per_ms);
        }
        try std.testing.expect(answered);
        client.service() catch {};
        for (context.sessions.items) |session| session.service() catch {};

        // Three peer control/QPACK streams stay open for the connection;
        // completed request streams must not add to that baseline.
        const streams = client.streams.count();
        if (baseline) |expected| {
            try std.testing.expectEqual(expected, streams);
        } else {
            baseline = streams;
            try std.testing.expect(streams <= 4);
        }
        // Three locally-created control/QPACK streams remain open; request
        // send/flow entries must not accumulate.
        try std.testing.expect(client_conn.stream_send.count() <= 4);
        try std.testing.expect(client_conn.stream_flow.count() <= 6);
    }
}

test "native HTTP/3: at most one peer control stream" {
    var control: http3.ControlState = .{};
    try std.testing.expect(control.claimStream(3) == null);
    try std.testing.expectEqual(@as(u64, 3), control.stream_id.?);
    // Re-announcing the same stream is idempotent; a second stream is not.
    try std.testing.expect(control.claimStream(3) == null);
    try std.testing.expectEqual(
        http3.ControlState.Violation.duplicate_control_stream,
        control.claimStream(7).?,
    );
    try std.testing.expectEqual(@as(u64, 3), control.stream_id.?);
}

test "native HTTP/3: control stream requires SETTINGS first and once" {
    var control: http3.ControlState = .{};
    // A complete HEADERS frame cannot be the first frame on a control stream.
    try std.testing.expectEqual(
        http3.ControlState.Violation.missing_settings,
        control.onFrame(0x01).?,
    );
    try std.testing.expect(!control.settings_received);

    var valid: http3.ControlState = .{};
    try std.testing.expect(valid.onFrame(0x04) == null);
    try std.testing.expect(valid.settings_received);
    try std.testing.expectEqual(
        http3.ControlState.Violation.duplicate_settings,
        valid.onFrame(0x04).?,
    );
    try std.testing.expect(valid.onFrame(0x07) == null); // GOAWAY
    try std.testing.expect(valid.onFrame(0x0d) == null); // MAX_PUSH_ID
    try std.testing.expect(valid.onFrame(0x03) == null); // CANCEL_PUSH
    try std.testing.expect(valid.onFrame(0x21) == null); // unknown extension
    try std.testing.expectEqual(
        http3.ControlState.Violation.unexpected_frame,
        valid.onFrame(0x00).?,
    );
    try std.testing.expectEqual(
        http3.ControlState.Violation.unexpected_frame,
        valid.onFrame(0x01).?,
    );
}

test "native HTTP/3: control stream violations have stable RFC 9114 codes" {
    const duplicate = http3.ControlState.Violation.duplicate_control_stream;
    const missing = http3.ControlState.Violation.missing_settings;
    const duplicate_settings = http3.ControlState.Violation.duplicate_settings;
    const closed = http3.ControlState.Violation.closed_critical_stream;
    const unexpected = http3.ControlState.Violation.unexpected_frame;

    try std.testing.expectEqual(@as(u64, 0x0103), duplicate.closeCode());
    try std.testing.expectEqual(@as(u64, 0x010a), missing.closeCode());
    try std.testing.expectEqual(@as(u64, 0x0109), duplicate_settings.closeCode());
    try std.testing.expectEqual(@as(u64, 0x0104), closed.closeCode());
    try std.testing.expectEqual(@as(u64, 0x0105), unexpected.closeCode());

    try std.testing.expectEqualStrings("duplicate control stream", duplicate.reason());
    try std.testing.expectEqualStrings("missing settings", missing.reason());
    try std.testing.expectEqualStrings("duplicate settings", duplicate_settings.reason());
    try std.testing.expectEqualStrings("control stream closed", closed.reason());
    try std.testing.expectEqualStrings("unexpected control frame", unexpected.reason());

    var control: http3.ControlState = .{};
    try std.testing.expectEqual(
        http3.ControlState.Violation.closed_critical_stream,
        control.onFin().?,
    );
}

test "native HTTP/3: partial control frames are not violations" {
    var cursor: usize = 0;
    // Missing the length varint.
    try std.testing.expect(http3.readFrame(&.{0x04}, &cursor) == null);
    try std.testing.expectEqual(@as(usize, 0), cursor);
    // Incomplete two-byte frame type varint.
    try std.testing.expect(http3.readFrame(&.{0x40}, &cursor) == null);
    try std.testing.expectEqual(@as(usize, 0), cursor);
    // Complete header, incomplete payload.
    try std.testing.expect(http3.readFrame(&.{ 0x04, 0x03, 0xaa }, &cursor) == null);
    try std.testing.expectEqual(@as(usize, 0), cursor);

    const buffer = [_]u8{ 0x04, 0x03, 0xaa, 0xbb, 0xcc, 0x07, 0x00 };
    const settings = http3.readFrame(&buffer, &cursor).?;
    try std.testing.expectEqual(@as(u64, 0x04), settings.frame_type);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, settings.payload);
    try std.testing.expectEqual(@as(usize, 5), cursor);

    const goaway = http3.readFrame(&buffer, &cursor).?;
    try std.testing.expectEqual(@as(u64, 0x07), goaway.frame_type);
    try std.testing.expectEqual(@as(usize, 0), goaway.payload.len);
    try std.testing.expectEqual(@as(usize, 7), cursor);

    // Nothing left: the parser does not fabricate a frame.
    try std.testing.expect(http3.readFrame(&buffer, &cursor) == null);
    try std.testing.expectEqual(@as(usize, 7), cursor);
}

const ControlFault = enum {
    second_control_stream,
    settings_not_first,
    control_stream_fin,
};

fn injectControlFault(conn: *transport.Connection, fault: ControlFault) !void {
    switch (fault) {
        .second_control_stream => {
            const first = try conn.createUniStream();
            // Control stream type 0x00, then an empty SETTINGS frame.
            try conn.queueStreamData(first, &.{ 0x00, 0x04, 0x00 }, false);
            const second = try conn.createUniStream();
            try conn.queueStreamData(second, &.{0x00}, false);
        },
        .settings_not_first => {
            const id = try conn.createUniStream();
            // Control stream type 0x00, then a zero-length DATA frame (0x00).
            try conn.queueStreamData(id, &.{ 0x00, 0x00, 0x00 }, false);
        },
        .control_stream_fin => {
            const id = try conn.createUniStream();
            // A valid SETTINGS frame followed immediately by FIN.
            try conn.queueStreamData(id, &.{ 0x00, 0x04, 0x00 }, true);
        },
    }
}

const QpackFault = enum {
    duplicate_settings_id,
    encoder_capacity_too_large,
    encoder_entry_too_large,
    decoder_byte,
    second_encoder,
    encoder_fin,
    dynamic_reference,
    blocked_after_insert,
};

fn injectQpackFault(conn: *transport.Connection, fault: QpackFault) !void {
    switch (fault) {
        .duplicate_settings_id => {
            const id = try conn.createUniStream();
            // Control stream type 0x00, SETTINGS frame (4 bytes), then the
            // same identifier (0x01) twice.
            try conn.queueStreamData(id, &.{ 0x00, 0x04, 0x04, 0x01, 0x00, 0x01, 0x00 }, false);
        },
        .encoder_capacity_too_large => {
            const id = try conn.createUniStream();
            // Encoder stream type 0x02, then Set Dynamic Table Capacity 4097:
            // 001 11111, 4097 - 31 = 4066 as a 7-bit-prefixed integer.
            try conn.queueStreamData(id, &.{ 0x02, 0x3f, 0xe2, 0x1f }, false);
        },
        .encoder_entry_too_large => {
            const id = try conn.createUniStream();
            // Capacity 64, then Insert With Name Reference to static
            // :authority with a 40-byte value: 10 + 40 + 32 > 64.
            var data: [45]u8 = undefined;
            data[0..5].* = .{ 0x02, 0x3f, 0x21, 0xc0, 0x28 };
            @memset(data[5..], 'a');
            try conn.queueStreamData(id, &data, false);
        },
        .decoder_byte => {
            const id = try conn.createUniStream();
            // Decoder stream type 0x03, then Insert Count Increment 0.
            try conn.queueStreamData(id, &.{ 0x03, 0x00 }, false);
        },
        .second_encoder => {
            const first = try conn.createUniStream();
            try conn.queueStreamData(first, &.{0x02}, false);
            const second = try conn.createUniStream();
            try conn.queueStreamData(second, &.{0x02}, false);
        },
        .encoder_fin => {
            const id = try conn.createUniStream();
            // Empty encoder stream (type only) followed by FIN.
            try conn.queueStreamData(id, &.{0x02}, true);
        },
        .dynamic_reference => {
            const id = try conn.createBidiStream();
            // HEADERS frame with Required Insert Count 1 and Delta Base 0.
            try conn.queueStreamData(id, &.{ 0x01, 0x02, 0x01, 0x00 }, true);
        },
        .blocked_after_insert => {
            const encoder = try conn.createUniStream();
            // Capacity 64, then insert :authority -> "x".
            try conn.queueStreamData(encoder, &.{ 0x02, 0x3f, 0x21, 0xc0, 0x01, 'x' }, false);
            const request = try conn.createBidiStream();
            // HEADERS block claiming Required Insert Count 2 (encoded 3) when
            // only one insert has been applied.
            try conn.queueStreamData(request, &.{ 0x01, 0x02, 0x03, 0x00 }, true);
        },
    }
}

const ProtocolFault = union(enum) {
    control: ControlFault,
    qpack: QpackFault,
};

fn runProtocolFault(allocator: std.mem.Allocator, fault: ProtocolFault) !u64 {
    var listener = try transport.Listener.init(allocator, 0);
    defer listener.deinit();

    var context: Context = .{ .allocator = allocator, .handler = handle };
    defer context.deinit();
    listener.on_connection = .{ .context = &context, .callback = Context.onConnection };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client_conn = try transport.Connection.initClient(allocator, "127.0.0.1", port, .{
        .insecure_skip_verify = true,
    });
    defer client_conn.deinit();

    var buf: [transport.max_datagram_size]u8 = undefined;
    const deadline = transport.nowNanos() + 8 * std.time.ns_per_s;
    var injected = false;
    while (transport.nowNanos() < deadline) {
        client_conn.service() catch {};
        _ = listener.readAndDispatch(&buf, 8);
        listener.serviceAll();
        for (context.sessions.items) |session| session.service() catch {};

        var peer: std.posix.sockaddr.in = undefined;
        var peer_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
        const n = std.c.recvfrom(
            client_conn.socket,
            buf[0..].ptr,
            buf.len,
            std.c.MSG.DONTWAIT,
            @ptrCast(&peer),
            &peer_len,
        );
        if (n > 0) client_conn.handleDatagram(buf[0..@intCast(n)]) catch {};

        if (!injected and client_conn.isEstablished()) {
            switch (fault) {
                .control => |control_fault| try injectControlFault(client_conn, control_fault),
                .qpack => |qpack_fault| try injectQpackFault(client_conn, qpack_fault),
            }
            injected = true;
        }
        if (injected and context.sessions.items.len > 0) {
            const session = context.sessions.items[0];
            if (session.conn.isClosed()) return session.conn.close_code;
        }
        transport.sleepNs(std.time.ns_per_ms);
    }
    return error.ProtocolFaultDidNotClose;
}

fn runControlFault(allocator: std.mem.Allocator, fault: ControlFault) !u64 {
    return runProtocolFault(allocator, .{ .control = fault });
}

fn runQpackFault(allocator: std.mem.Allocator, fault: QpackFault) !u64 {
    return runProtocolFault(allocator, .{ .qpack = fault });
}

test "native HTTP/3: control stream faults close with RFC 9114 codes" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.h3_stream_creation_error,
        try runControlFault(allocator, .second_control_stream),
    );
    try std.testing.expectEqual(
        http3.h3_missing_settings,
        try runControlFault(allocator, .settings_not_first),
    );
    try std.testing.expectEqual(
        http3.h3_closed_critical_stream,
        try runControlFault(allocator, .control_stream_fin),
    );
}

test "native HTTP/3: peer SETTINGS parse accepts capacity zero" {
    var settings: http3.Settings = .{};
    // QPACK capacity 0, blocked streams 0, max field section size 4096
    // (two-byte QUIC varint 0x50 0x00), then an unknown identifier.
    const payload = [_]u8{ 0x01, 0x00, 0x07, 0x00, 0x06, 0x50, 0x00, 0x08, 0x01 };
    try std.testing.expect(http3.parseSettings(&payload, &settings) == null);
    try std.testing.expectEqual(@as(u64, 0), settings.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 0), settings.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, 4096), settings.max_field_section_size);

    // The defaults stay at zero capacity when SETTINGS omit QPACK values.
    var defaults: http3.Settings = .{};
    try std.testing.expect(http3.parseSettings(&.{}, &defaults) == null);
    try std.testing.expectEqual(@as(u64, 0), defaults.qpack_max_table_capacity);
    try std.testing.expectEqual(@as(u64, 0), defaults.qpack_blocked_streams);
    try std.testing.expectEqual(@as(?u64, null), defaults.max_field_section_size);

    var scratch: http3.Settings = .{};
    try std.testing.expectEqual(
        http3.SettingsError.duplicate_id,
        http3.parseSettings(&.{ 0x01, 0x00, 0x01, 0x00 }, &scratch).?,
    );
    try std.testing.expectEqual(
        http3.h3_settings_error,
        http3.SettingsError.duplicate_id.violation().closeCode(),
    );
    try std.testing.expectEqual(
        http3.SettingsError.malformed,
        http3.parseSettings(&.{0x01}, &scratch).?,
    );
    try std.testing.expectEqual(
        http3.SettingsError.reserved_id,
        http3.parseSettings(&.{ 0x02, 0x00 }, &scratch).?,
    );
}

test "native HTTP/3: duplicate SETTINGS identifiers close with H3_SETTINGS_ERROR" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.h3_settings_error,
        try runQpackFault(allocator, .duplicate_settings_id),
    );
}

test "native HTTP/3: peer QPACK encoder capacity over 4096 closes with 0x0202" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.qpack_encoder_stream_error,
        try runQpackFault(allocator, .encoder_capacity_too_large),
    );
}

test "native HTTP/3: peer QPACK insert larger than capacity closes with 0x0202" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.qpack_encoder_stream_error,
        try runQpackFault(allocator, .encoder_entry_too_large),
    );
}

test "native HTTP/3: peer QPACK decoder byte closes with 0x0203" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.qpack_decoder_stream_error,
        try runQpackFault(allocator, .decoder_byte),
    );
}

test "native HTTP/3: second QPACK encoder stream closes with 0x0103" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.h3_stream_creation_error,
        try runQpackFault(allocator, .second_encoder),
    );
}

test "native HTTP/3: FIN on peer QPACK encoder stream closes with 0x0104" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.h3_closed_critical_stream,
        try runQpackFault(allocator, .encoder_fin),
    );
}

test "native HTTP/3: peer encoder insert feeds a dynamic HEADERS block" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var encoder: std.ArrayListUnmanaged(u8) = .empty;
    defer encoder.deinit(allocator);
    // Set Dynamic Table Capacity 64: 001 11111, 64 - 31 = 33.
    try encoder.appendSlice(allocator, &.{ 0x3f, 0x21 });
    // Insert With Literal Name: 01 + 5-bit name length, name, value.
    try encoder.append(allocator, 0x49); // 0x40 | "x-dynamic".len
    try encoder.appendSlice(allocator, "x-dynamic");
    try encoder.append(allocator, 5);
    try encoder.appendSlice(allocator, "hello");

    var block: std.ArrayListUnmanaged(u8) = .empty;
    defer block.deinit(allocator);
    // Required Insert Count 1 is encoded as 2; Delta Base 0 means Base = 1.
    try block.appendSlice(allocator, &.{ 0x02, 0x00 });
    // :method GET (static index 17), :scheme https (static index 23).
    try block.appendSlice(allocator, &.{ 0xd1, 0xd7 });
    // :authority and :path with static name references.
    try block.append(allocator, 0x50);
    try block.append(allocator, "localhost".len);
    try block.appendSlice(allocator, "localhost");
    try block.append(allocator, 0x51);
    try block.append(allocator, "/dyn".len);
    try block.appendSlice(allocator, "/dyn");
    // Indexed Field Line, pre-base dynamic index 0 (the inserted entry).
    try block.append(allocator, 0x80);

    dynamic_header_seen = false;
    const response = try runDynamicEncoderOnce(
        allocator,
        encoder.items,
        block.items,
        handleDynamicHeader,
    );
    defer allocator.free(response.body);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("seen", response.body);
    try std.testing.expect(dynamic_header_seen);
}

test "native HTTP/3: dynamic table reference in HEADERS closes with 0x0201" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.qpack_decompression_failed,
        try runQpackFault(allocator, .dynamic_reference),
    );
}

test "native HTTP/3: RIC above insert count closes with 0x0201" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try std.testing.expectEqual(
        http3.qpack_decompression_failed,
        try runQpackFault(allocator, .blocked_after_insert),
    );
}

test "native HTTP/3: body reader cleanup runs once" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    stream_cleanup_count = 0;
    const got = try runOnce(allocator, "/stream", handleStreamCleanup);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(stream_body_size, got.body.len);
    try std.testing.expectEqual(@as(usize, 1), stream_cleanup_count);
}

test "native HTTP/3: :authority reaches the handler" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const got = try runOnce(allocator, "/", handleAuthority);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqualStrings("localhost", got.body);
}

test "native HTTP/3: :scheme reaches the handler" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const got = try runOnce(allocator, "/", handleScheme);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(@as(u16, 200), got.status);
    try std.testing.expectEqualStrings("https", got.body);
}

test "native HTTP/3: non-CONNECT requests require :scheme and a valid :path" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const missing_scheme = [_]http3.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/hello" },
    };
    try expectRawStatus(allocator, &missing_scheme, handle, 400);

    const empty_scheme = [_]http3.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/hello" },
    };
    try expectRawStatus(allocator, &empty_scheme, handle, 400);

    const missing_path = [_]http3.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    try expectRawStatus(allocator, &missing_path, handle, 400);

    const empty_path = [_]http3.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "" },
    };
    try expectRawStatus(allocator, &empty_path, handle, 400);

    // Origin-form only: a bare query or relative reference is not a target.
    const relative_path = [_]http3.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "hello" },
    };
    try expectRawStatus(allocator, &relative_path, handle, 400);

    // "*" is the OPTIONS asterisk-form, not a GET path.
    const asterisk_get = [_]http3.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "*" },
    };
    try expectRawStatus(allocator, &asterisk_get, handle, 400);
}

test "native HTTP/3: plain CONNECT requires :authority and omits :path/:scheme" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    const missing_authority = [_]http3.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
    };
    try expectRawStatus(allocator, &missing_authority, handleConnect, 400);

    const empty_authority = [_]http3.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "" },
    };
    try expectRawStatus(allocator, &empty_authority, handleConnect, 400);

    const with_path = [_]http3.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
        .{ .name = ":path", .value = "/" },
    };
    try expectRawStatus(allocator, &with_path, handleConnect, 400);

    const with_scheme = [_]http3.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com:443" },
    };
    try expectRawStatus(allocator, &with_scheme, handleConnect, 400);

    const valid = [_]http3.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
    };
    const got = try runRawOnce(allocator, &valid, handleConnect);
    defer allocator.free(got.header_text);
    defer allocator.free(got.body);
    try std.testing.expectEqual(@as(u16, 200), got.status);
    try std.testing.expectEqualStrings("example.com:443", got.body);
}

test "native HTTP/3: duplicate pseudo-headers are rejected" {
    // qpack.decode enforces one occurrence per pseudo-header (RFC 9114
    // section 4.3). Verify that here before relying on it; if it ever changes,
    // handleHeaders needs its own duplicate check.
    const duplicate = [_]http3.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/hello" },
        .{ .name = ":path", .value = "/duplicate" },
    };

    const block = try qpack.encode(std.testing.allocator, &duplicate);
    defer std.testing.allocator.free(block);
    try std.testing.expectError(error.InvalidHeaderBlock, qpack.decode(std.testing.allocator, block));

    // The same duplicate header block is also rejected end to end with 400.
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    try expectRawStatus(allocator, &duplicate, handle, 400);
}

test "native HTTP/3: extended CONNECT is rejected, not treated as plain CONNECT" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    // RFC 8441 extended CONNECT needs :protocol. qpack.decode rejects the
    // unknown pseudo-header, so the server answers 400 rather than running the
    // handler as if this were a plain CONNECT.
    const extended = [_]http3.HeaderField{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
        .{ .name = ":protocol", .value = "websocket" },
    };
    try expectRawStatus(allocator, &extended, handleConnect, 400);
}
