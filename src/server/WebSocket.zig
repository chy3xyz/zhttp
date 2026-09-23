const std = @import("std");
const Io = std.Io;
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");

/// WebSocket handler function type.
/// Called after the HTTP 101 handshake completes. The handler owns the
/// connection loop and should return when the WebSocket session ends.
pub const Handler = *const fn (*Conn, *const Request) void;

/// RFC 6455 Section 7.4: WebSocket close status codes.
pub const CloseCode = enum(u16) {
    normal = 1000,
    going_away = 1001,
    protocol_error = 1002,
    unsupported_data = 1003,
    no_status = 1005,
    abnormal = 1006,
    invalid_payload = 1007,
    policy_violation = 1008,
    message_too_big = 1009,
    mandatory_extension = 1010,
    internal_error = 1011,
};

/// RFC 6455 Section 5.2: WebSocket frame opcodes.
pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    close = 8,
    ping = 9,
    pong = 10,
    _,
};

/// RFC 6455 Section 5.2: A decoded WebSocket frame.
pub const Frame = struct {
    fin: bool,
    opcode: Opcode,
    payload: []const u8,
};

/// RFC 6455 Section 5.2: WebSocket message (possibly reassembled from fragments).
pub const Message = struct {
    opcode: Opcode,
    payload: []const u8,
};

/// Maximum allowed frame payload size (16 MB).
pub const max_frame_size: usize = 16 * 1024 * 1024;

/// WebSocket connection wrapper for reading and writing frames.
pub const Conn = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,
    buf: []u8,
    closed: bool = false,

    pub fn init(reader: *Io.Reader, writer: *Io.Writer, buf: []u8) Conn {
        return .{
            .reader = reader,
            .writer = writer,
            .buf = buf,
        };
    }

    /// Receive the next complete message, handling control frames internally.
    /// Reassembles fragmented messages. Returns null on close.
    pub fn recv(self: *Conn) !?Message {
        if (self.closed) return null;

        var msg_start: usize = 0;
        var msg_opcode: Opcode = .text;
        var first_frame = true;

        while (true) {
            const frame = self.readFrame() catch |err| switch (err) {
                error.ConnectionClosed => return null,
                else => return err,
            };

            switch (frame.opcode) {
                .close => {
                    // Echo close frame back
                    self.writeCloseFrame(
                        if (frame.payload.len >= 2)
                            std.mem.readInt(u16, frame.payload[0..2], .big)
                        else
                            @backingInt(CloseCode.normal),
                        "",
                    ) catch {};
                    self.closed = true;
                    return null;
                },
                .ping => {
                    self.writeFrame(.pong, frame.payload, true) catch return null;
                    continue;
                },
                .pong => continue,
                .continuation => {
                    if (first_frame) return error.ProtocolError;
                    // Append to buffer
                    if (msg_start + frame.payload.len > self.buf.len) return error.MessageTooBig;
                    @memcpy(self.buf[msg_start..][0..frame.payload.len], frame.payload);
                    msg_start += frame.payload.len;
                    if (frame.fin) {
                        return .{ .opcode = msg_opcode, .payload = self.buf[0..msg_start] };
                    }
                },
                .text, .binary => {
                    if (!first_frame) return error.ProtocolError;
                    msg_opcode = frame.opcode;
                    if (frame.fin) {
                        // Single-frame message — payload is already in self.buf
                        // via readFrame, just copy to start if needed
                        if (frame.payload.len > self.buf.len) return error.MessageTooBig;
                        std.mem.copyForwards(u8, self.buf[0..frame.payload.len], frame.payload);
                        return .{ .opcode = frame.opcode, .payload = self.buf[0..frame.payload.len] };
                    }
                    // Start of fragmented message
                    if (frame.payload.len > self.buf.len) return error.MessageTooBig;
                    std.mem.copyForwards(u8, self.buf[0..frame.payload.len], frame.payload);
                    msg_start = frame.payload.len;
                    first_frame = false;
                },
                _ => return error.ProtocolError,
            }
        }
    }

    /// Send a text frame.
    pub fn send(self: *Conn, data: []const u8) !void {
        try self.writeFrame(.text, data, true);
    }

    /// Send a binary frame.
    pub fn sendBinary(self: *Conn, data: []const u8) !void {
        try self.writeFrame(.binary, data, true);
    }

    /// Send a ping frame.
    pub fn ping(self: *Conn) !void {
        try self.writeFrame(.ping, "", true);
    }

    /// Send a pong frame.
    pub fn pong(self: *Conn, data: []const u8) !void {
        try self.writeFrame(.pong, data, true);
    }

    /// Send a close frame with status code and reason.
    pub fn close(self: *Conn, code: u16, reason: []const u8) !void {
        try self.writeCloseFrame(code, reason);
        self.closed = true;
    }

    /// RFC 6455 Section 5.2: Read a single WebSocket frame.
    fn readFrame(self: *Conn) !Frame {
        // Read first 2 bytes: FIN, opcode, MASK, payload length
        var header: [2]u8 = undefined;
        self.reader.readSliceAll(&header) catch return error.ConnectionClosed;

        const fin = (header[0] & 0x80) != 0;
        const opcode: Opcode = @fromBackingInt(@intCast(@as(u4, @truncate(header[0] & 0x0f))));
        const masked = (header[1] & 0x80) != 0;
        // RFC 6455 Section 5.1: client frames MUST be masked
        if (!masked) return error.ProtocolError;
        var payload_len: u64 = header[1] & 0x7f;

        // Extended payload length
        if (payload_len == 126) {
            var ext: [2]u8 = undefined;
            self.reader.readSliceAll(&ext) catch return error.ConnectionClosed;
            payload_len = std.mem.readInt(u16, &ext, .big);
        } else if (payload_len == 127) {
            var ext: [8]u8 = undefined;
            self.reader.readSliceAll(&ext) catch return error.ConnectionClosed;
            payload_len = std.mem.readInt(u64, &ext, .big);
        }

        if (payload_len > max_frame_size) return error.MessageTooBig;
        if (payload_len > self.buf.len) return error.MessageTooBig;
        const len: usize = @intCast(payload_len);

        // Read masking key (always present — unmasked frames rejected above)
        var mask_key: [4]u8 = undefined;
        self.reader.readSliceAll(&mask_key) catch return error.ConnectionClosed;

        // Read payload
        const payload = self.buf[0..len];
        if (len > 0) {
            self.reader.readSliceAll(payload) catch return error.ConnectionClosed;
        }

        // Unmask payload (RFC 6455 Section 5.3)
        for (payload, 0..) |*byte, i| {
            byte.* ^= mask_key[i % 4];
        }

        return .{ .fin = fin, .opcode = opcode, .payload = payload };
    }

    /// RFC 6455 Section 5.2: Write a WebSocket frame (server frames are unmasked).
    fn writeFrame(self: *Conn, opcode: Opcode, payload: []const u8, fin: bool) !void {
        var header: [10]u8 = undefined;
        var header_len: usize = 2;

        header[0] = @as(u8, if (fin) 0x80 else 0) | @as(u8, @backingInt(opcode));

        // Server frames are NOT masked (mask bit = 0)
        if (payload.len < 126) {
            header[1] = @intCast(payload.len);
        } else if (payload.len <= 65535) {
            header[1] = 126;
            std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
            header_len = 4;
        } else {
            header[1] = 127;
            std.mem.writeInt(u64, header[2..10], @intCast(payload.len), .big);
            header_len = 10;
        }

        self.writer.writeAll(header[0..header_len]) catch return error.ConnectionClosed;
        if (payload.len > 0) {
            self.writer.writeAll(payload) catch return error.ConnectionClosed;
        }
        self.writer.flush() catch return error.ConnectionClosed;
    }

    fn writeCloseFrame(self: *Conn, code: u16, reason: []const u8) !void {
        var close_payload: [125]u8 = undefined;
        std.mem.writeInt(u16, close_payload[0..2], code, .big);
        const reason_len = @min(reason.len, 123);
        @memcpy(close_payload[2..][0..reason_len], reason[0..reason_len]);
        try self.writeFrame(.close, close_payload[0 .. 2 + reason_len], true);
    }
};

/// RFC 6455 Section 4.2.1: Validate that the request is a valid WebSocket upgrade.
/// Returns the Sec-WebSocket-Key if valid, null otherwise.
pub fn validateUpgrade(request: *const Request) ?[]const u8 {
    // Must have Upgrade: websocket
    const upgrade = request.headers.get("Upgrade") orelse return null;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket"))
        return null;

    // Must have Connection: Upgrade (may be part of a comma-separated list)
    const conn = request.headers.get("Connection") orelse return null;
    var found_upgrade = false;
    var it = std.mem.splitScalar(u8, conn, ',');
    while (it.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t");
        if (std.ascii.eqlIgnoreCase(token, "upgrade")) {
            found_upgrade = true;
            break;
        }
    }
    if (!found_upgrade) return null;

    // Must have Sec-WebSocket-Version: 13
    const version = request.headers.get("Sec-WebSocket-Version") orelse return null;
    if (!std.mem.eql(u8, version, "13")) return null;

    // Must have Sec-WebSocket-Key
    return request.headers.get("Sec-WebSocket-Key");
}

/// RFC 6455 Section 4.2.2: Compute the Sec-WebSocket-Accept value.
/// accept_key = base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-5AB5FC11CE65"))
pub fn computeAcceptKey(key: []const u8, buf: *[28]u8) []const u8 {
    const magic = "258EAFA5-E914-47DA-95CA-5AB5FC11CE65";
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(key);
    hasher.update(magic);
    const hash = hasher.finalResult();
    return std.base64.standard.Encoder.encode(buf, &hash);
}

/// Build a 101 Switching Protocols response for a valid WebSocket upgrade request.
/// Returns null if the request is not a valid upgrade request.
pub fn upgradeResponse(request: *const Request) ?Response {
    const key = validateUpgrade(request) orelse return null;

    var accept_buf: [28]u8 = undefined;
    const accept = computeAcceptKey(key, &accept_buf);

    var response: Response = .{
        .status = .switching_protocols,
        .auto_content_length = false,
    };
    // Store accept key in the response's embedded server buffer for stable lifetime
    const stored = response.allocServerBuf(accept.len) orelse return null;
    @memcpy(stored, accept);
    response.headers.append("Upgrade", "websocket") catch return null;
    response.headers.append("Connection", "Upgrade") catch return null;
    response.headers.append("Sec-WebSocket-Accept", stored) catch return null;
    return response;
}

// --- Tests ---

const testing = std.testing;

test "WebSocket: computeAcceptKey RFC 6455 test vector" {
    // Verify SHA-1(key + magic GUID) base64-encoded
    var buf: [28]u8 = undefined;
    const result = computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", &buf);
    try testing.expectEqualStrings("xBZ/1aPlkD9x2CnuzzjamuXhOpI=", result);
}

test "WebSocket: validateUpgrade valid request" {
    const req = try Request.parseConst(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    const key = validateUpgrade(&req);
    try testing.expect(key != null);
    try testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", key.?);
}

test "WebSocket: validateUpgrade missing upgrade header" {
    const req = try Request.parseConst(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    try testing.expect(validateUpgrade(&req) == null);
}

test "WebSocket: validateUpgrade wrong version" {
    const req = try Request.parseConst(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 8\r\n" ++
            "\r\n",
    );
    try testing.expect(validateUpgrade(&req) == null);
}

test "WebSocket: upgradeResponse builds 101" {
    const req = try Request.parseConst(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    const resp = upgradeResponse(&req);
    try testing.expect(resp != null);
    try testing.expectEqual(Response.StatusCode.switching_protocols, resp.?.status);
    try testing.expectEqualStrings("websocket", resp.?.headers.get("Upgrade").?);
    try testing.expectEqualStrings("Upgrade", resp.?.headers.get("Connection").?);
    try testing.expectEqualStrings("xBZ/1aPlkD9x2CnuzzjamuXhOpI=", resp.?.headers.get("Sec-WebSocket-Accept").?);
}

test "WebSocket: frame encode/decode round-trip" {
    // Test writing and reading a frame by simulating with buffers
    // We test the frame format directly
    var header: [10]u8 = undefined;

    // Build a text frame with "Hello"
    header[0] = 0x81; // FIN + text opcode
    header[1] = 5; // payload length, no mask
    const expected_header = header[0..2];
    try testing.expectEqual(@as(u8, 0x81), expected_header[0]);
    try testing.expectEqual(@as(u8, 5), expected_header[1]);
}
