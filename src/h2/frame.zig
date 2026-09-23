const std = @import("std");
const mem = std.mem;
const Io = std.Io;
const ErrorCode = @import("errors.zig").ErrorCode;

/// HTTP/2 connection preface sent by the client (RFC 9113 §3.4).
/// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
pub const connection_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Default maximum frame payload size (RFC 9113 §4.2): 2^14 = 16,384 bytes.
pub const default_max_frame_size: u24 = 16_384;

/// Absolute maximum frame payload size (RFC 9113 §4.2): 2^24 - 1.
pub const max_frame_size: u24 = 16_777_215;

/// Frame header is always 9 bytes (RFC 9113 §4.1).
pub const header_size: usize = 9;

/// Default initial flow-control window size: 65,535 bytes (RFC 9113 §6.9.2).
pub const default_initial_window_size: u31 = 65_535;

/// Frame types (RFC 9113 §6).
pub const FrameType = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
    _,
};

/// Frame flags (RFC 9113 §6).
pub const Flags = struct {
    value: u8,

    pub const none: Flags = .{ .value = 0 };

    // Shared flags
    pub const end_stream: u8 = 0x1; // DATA, HEADERS
    pub const ack: u8 = 0x1; // SETTINGS, PING
    pub const end_headers: u8 = 0x4; // HEADERS, PUSH_PROMISE, CONTINUATION
    pub const padded: u8 = 0x8; // DATA, HEADERS, PUSH_PROMISE
    pub const priority_flag: u8 = 0x20; // HEADERS

    pub fn has(self: Flags, flag: u8) bool {
        return self.value & flag != 0;
    }

    pub fn with(self: Flags, flag: u8) Flags {
        return .{ .value = self.value | flag };
    }
};

/// Settings identifiers (RFC 9113 §6.5.2).
pub const SettingsId = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    _,
};

/// A parsed HTTP/2 frame header.
pub const FrameHeader = struct {
    length: u24,
    frame_type: FrameType,
    flags: Flags,
    stream_id: u31,

    /// Read a frame header from a 9-byte buffer.
    pub fn parse(buf: *const [header_size]u8) FrameHeader {
        const length: u24 = @as(u24, buf[0]) << 16 | @as(u24, buf[1]) << 8 | @as(u24, buf[2]);
        return .{
            .length = length,
            .frame_type = @fromBackingInt(@intCast(buf[3])),
            .flags = .{ .value = buf[4] },
            .stream_id = @intCast(mem.readInt(u32, buf[5..9], .big) & 0x7FFFFFFF),
        };
    }

    /// Serialize a frame header into a 9-byte buffer.
    pub fn encode(self: FrameHeader) [header_size]u8 {
        var buf: [header_size]u8 = undefined;
        buf[0] = @intCast((self.length >> 16) & 0xFF);
        buf[1] = @intCast((self.length >> 8) & 0xFF);
        buf[2] = @intCast(self.length & 0xFF);
        buf[3] = @backingInt(self.frame_type);
        buf[4] = self.flags.value;
        mem.writeInt(u32, buf[5..9], @as(u32, self.stream_id), .big);
        return buf;
    }
};

/// A complete HTTP/2 frame: header + payload.
pub const Frame = struct {
    header: FrameHeader,
    payload: []const u8,
};

/// Read a complete frame from an I/O reader.
/// Validates frame size against `max_payload_size`.
pub fn readFrame(reader: *Io.Reader, max_payload_size: u24) !Frame {
    const hdr_buf = try reader.peek(header_size);
    const header = FrameHeader.parse(hdr_buf[0..header_size]);

    if (header.length > max_payload_size) {
        return error.FrameSizeError;
    }

    const total = header_size + @as(usize, header.length);
    const buf = try reader.take(total);
    return .{
        .header = header,
        .payload = buf[header_size..total],
    };
}

/// Write a frame to an I/O writer.
pub fn writeFrame(writer: *Io.Writer, frame_type: FrameType, flags: Flags, stream_id: u31, payload: []const u8) !void {
    const header = FrameHeader{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    };
    const hdr = header.encode();
    try writer.writeAll(&hdr);
    if (payload.len > 0) {
        try writer.writeAll(payload);
    }
}

/// Write a SETTINGS frame (stream 0).
pub fn writeSettings(writer: *Io.Writer, settings: []const Setting) !void {
    const payload_len = settings.len * 6;
    const header = FrameHeader{
        .length = @intCast(payload_len),
        .frame_type = .settings,
        .flags = Flags.none,
        .stream_id = 0,
    };
    const hdr = header.encode();
    try writer.writeAll(&hdr);
    for (settings) |s| {
        try writer.writeInt(u16, @backingInt(s.id), .big);
        try writer.writeInt(u32, s.value, .big);
    }
}

/// Write a SETTINGS ACK frame (empty payload, stream 0).
pub fn writeSettingsAck(writer: *Io.Writer) !void {
    try writeFrame(writer, .settings, .{ .value = Flags.ack }, 0, &.{});
}

/// Write a GOAWAY frame.
pub fn writeGoaway(writer: *Io.Writer, last_stream_id: u31, error_code: ErrorCode, debug_data: []const u8) !void {
    var buf: [8]u8 = undefined;
    mem.writeInt(u32, buf[0..4], @as(u32, last_stream_id), .big);
    mem.writeInt(u32, buf[4..8], @backingInt(error_code), .big);

    const header = FrameHeader{
        .length = @intCast(8 + debug_data.len),
        .frame_type = .goaway,
        .flags = Flags.none,
        .stream_id = 0,
    };
    const hdr = header.encode();
    try writer.writeAll(&hdr);
    try writer.writeAll(&buf);
    if (debug_data.len > 0) {
        try writer.writeAll(debug_data);
    }
}

/// Write a WINDOW_UPDATE frame.
pub fn writeWindowUpdate(writer: *Io.Writer, stream_id: u31, increment: u31) !void {
    var buf: [4]u8 = undefined;
    mem.writeInt(u32, buf[0..4], @as(u32, increment), .big);
    try writeFrame(writer, .window_update, Flags.none, stream_id, &buf);
}

/// Write a RST_STREAM frame.
pub fn writeRstStream(writer: *Io.Writer, stream_id: u31, error_code: ErrorCode) !void {
    var buf: [4]u8 = undefined;
    mem.writeInt(u32, buf[0..4], @backingInt(error_code), .big);
    try writeFrame(writer, .rst_stream, Flags.none, stream_id, &buf);
}

/// Write a PING frame.
pub fn writePing(writer: *Io.Writer, data: *const [8]u8, is_ack: bool) !void {
    const flags: Flags = if (is_ack) .{ .value = Flags.ack } else Flags.none;
    try writeFrame(writer, .ping, flags, 0, data);
}

/// A single SETTINGS parameter.
pub const Setting = struct {
    id: SettingsId,
    value: u32,
};

/// Parse SETTINGS payload into individual settings.
pub fn parseSettings(payload: []const u8) SettingsIterator {
    return .{ .data = payload };
}

pub const SettingsIterator = struct {
    data: []const u8,
    offset: usize = 0,

    pub fn next(self: *SettingsIterator) ?Setting {
        if (self.offset + 6 > self.data.len) return null;
        const id: u16 = mem.readInt(u16, self.data[self.offset..][0..2], .big);
        const value: u32 = mem.readInt(u32, self.data[self.offset + 2 ..][0..4], .big);
        self.offset += 6;
        return .{
            .id = @fromBackingInt(@intCast(id)),
            .value = value,
        };
    }
};

/// Parse GOAWAY payload.
pub const GoawayPayload = struct {
    last_stream_id: u31,
    error_code: ErrorCode,
    debug_data: []const u8,

    pub fn parse(payload: []const u8) !GoawayPayload {
        if (payload.len < 8) return error.FrameSizeError;
        return .{
            .last_stream_id = @intCast(mem.readInt(u32, payload[0..4], .big) & 0x7FFFFFFF),
            .error_code = @fromBackingInt(@intCast(mem.readInt(u32, payload[4..8], .big))),
            .debug_data = payload[8..],
        };
    }
};

/// Parse WINDOW_UPDATE payload.
pub fn parseWindowUpdate(payload: []const u8) !u31 {
    if (payload.len != 4) return error.FrameSizeError;
    const val = mem.readInt(u32, payload[0..4], .big) & 0x7FFFFFFF;
    if (val == 0) return error.ProtocolError;
    return @intCast(val);
}

/// Parse RST_STREAM payload.
pub fn parseRstStream(payload: []const u8) !ErrorCode {
    if (payload.len != 4) return error.FrameSizeError;
    return @fromBackingInt(@intCast(mem.readInt(u32, payload[0..4], .big)));
}

/// Parse PING payload.
pub fn parsePing(payload: []const u8) !*const [8]u8 {
    if (payload.len != 8) return error.FrameSizeError;
    return payload[0..8];
}

// --- Tests ---

const testing = std.testing;

test "FrameHeader parse and encode round-trip" {
    const original = FrameHeader{
        .length = 16384,
        .frame_type = .data,
        .flags = .{ .value = Flags.end_stream },
        .stream_id = 1,
    };
    const encoded = original.encode();
    const decoded = FrameHeader.parse(&encoded);
    try testing.expectEqual(original.length, decoded.length);
    try testing.expectEqual(original.frame_type, decoded.frame_type);
    try testing.expectEqual(original.flags.value, decoded.flags.value);
    try testing.expectEqual(original.stream_id, decoded.stream_id);
}

test "FrameHeader parse known bytes" {
    // Length=0, Type=SETTINGS(4), Flags=ACK(1), Stream=0
    const buf = [_]u8{ 0, 0, 0, 0x04, 0x01, 0, 0, 0, 0 };
    const h = FrameHeader.parse(&buf);
    try testing.expectEqual(@as(u24, 0), h.length);
    try testing.expectEqual(FrameType.settings, h.frame_type);
    try testing.expect(h.flags.has(Flags.ack));
    try testing.expectEqual(@as(u31, 0), h.stream_id);
}

test "FrameHeader encode HEADERS with END_STREAM and END_HEADERS" {
    const h = FrameHeader{
        .length = 100,
        .frame_type = .headers,
        .flags = (Flags{ .value = 0 }).with(Flags.end_stream).with(Flags.end_headers),
        .stream_id = 3,
    };
    const buf = h.encode();
    try testing.expectEqual(@as(u8, 0), buf[0]); // length high
    try testing.expectEqual(@as(u8, 0), buf[1]); // length mid
    try testing.expectEqual(@as(u8, 100), buf[2]); // length low
    try testing.expectEqual(@as(u8, 0x01), buf[3]); // type = headers
    try testing.expectEqual(@as(u8, 0x05), buf[4]); // flags = END_STREAM | END_HEADERS
    try testing.expectEqual(@as(u8, 3), buf[8]); // stream id low byte
}

test "Flags operations" {
    const f = Flags.none.with(Flags.end_stream).with(Flags.padded);
    try testing.expect(f.has(Flags.end_stream));
    try testing.expect(f.has(Flags.padded));
    try testing.expect(!f.has(Flags.end_headers));
    try testing.expect(!f.has(Flags.priority_flag));
}

test "SettingsIterator" {
    // Two settings: HEADER_TABLE_SIZE=8192, MAX_CONCURRENT_STREAMS=100
    var payload: [12]u8 = undefined;
    mem.writeInt(u16, payload[0..2], 0x1, .big); // HEADER_TABLE_SIZE
    mem.writeInt(u32, payload[2..6], 8192, .big);
    mem.writeInt(u16, payload[6..8], 0x3, .big); // MAX_CONCURRENT_STREAMS
    mem.writeInt(u32, payload[8..12], 100, .big);

    var iter = parseSettings(&payload);
    const s1 = iter.next().?;
    try testing.expectEqual(SettingsId.header_table_size, s1.id);
    try testing.expectEqual(@as(u32, 8192), s1.value);

    const s2 = iter.next().?;
    try testing.expectEqual(SettingsId.max_concurrent_streams, s2.id);
    try testing.expectEqual(@as(u32, 100), s2.value);

    try testing.expectEqual(@as(?Setting, null), iter.next());
}

test "GoawayPayload parse" {
    var buf: [12]u8 = undefined;
    mem.writeInt(u32, buf[0..4], 5, .big); // last_stream_id = 5
    mem.writeInt(u32, buf[4..8], 0x0, .big); // NO_ERROR
    @memcpy(buf[8..12], "test");

    const g = try GoawayPayload.parse(&buf);
    try testing.expectEqual(@as(u31, 5), g.last_stream_id);
    try testing.expectEqual(ErrorCode.no_error, g.error_code);
    try testing.expectEqualStrings("test", g.debug_data);
}

test "parseWindowUpdate valid" {
    var buf: [4]u8 = undefined;
    mem.writeInt(u32, buf[0..4], 1000, .big);
    const inc = try parseWindowUpdate(&buf);
    try testing.expectEqual(@as(u31, 1000), inc);
}

test "parseWindowUpdate zero increment is error" {
    var buf: [4]u8 = undefined;
    mem.writeInt(u32, buf[0..4], 0, .big);
    try testing.expectError(error.ProtocolError, parseWindowUpdate(&buf));
}

test "parseRstStream" {
    var buf: [4]u8 = undefined;
    mem.writeInt(u32, buf[0..4], 0x8, .big); // CANCEL
    const code = try parseRstStream(&buf);
    try testing.expectEqual(ErrorCode.cancel, code);
}

test "connection preface is correct" {
    try testing.expectEqual(@as(usize, 24), connection_preface.len);
    try testing.expectEqualStrings("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", connection_preface);
}
