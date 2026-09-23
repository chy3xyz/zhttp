const std = @import("std");
const frame = @import("frame.zig");
const SettingsId = frame.SettingsId;

/// HTTP/2 connection settings (RFC 9113 §6.5.2).
///
/// Each endpoint maintains two copies: the settings it has sent to
/// the peer (pending until ACKed), and the settings the peer has
/// sent to it (effective immediately on receipt).
pub const Settings = @This();

/// Maximum size of the HPACK dynamic table (bytes).
/// Default: 4096.
header_table_size: u32 = 4096,

/// Whether server push is permitted.
/// Default: true (1). Clients can disable by sending 0.
enable_push: bool = true,

/// Maximum number of concurrent streams the peer can open.
/// Default: no limit (we use a practical default of 100).
max_concurrent_streams: u32 = 100,

/// Initial flow-control window size for new streams (bytes).
/// Default: 65535. Applies to new streams only; existing streams
/// are adjusted via the delta when this changes.
initial_window_size: u32 = 65535,

/// Maximum frame payload size the peer is willing to receive.
/// Default: 16384. Must be between 16384 and 16777215.
max_frame_size: u32 = 16384,

/// Advisory limit on the decompressed size of header lists.
/// Default: unlimited (we use a practical default).
max_header_list_size: u32 = 8192,

/// Apply a single setting parameter. Returns error on invalid values.
pub fn apply(self: *Settings, id: SettingsId, value: u32) !void {
    switch (id) {
        .header_table_size => self.header_table_size = value,
        .enable_push => {
            if (value > 1) return error.ProtocolError;
            self.enable_push = value == 1;
        },
        .max_concurrent_streams => self.max_concurrent_streams = value,
        .initial_window_size => {
            if (value > 2147483647) return error.FlowControlError; // max i31
            self.initial_window_size = value;
        },
        .max_frame_size => {
            if (value < 16384 or value > 16777215) return error.ProtocolError;
            self.max_frame_size = value;
        },
        .max_header_list_size => self.max_header_list_size = value,
        _ => {}, // Unknown settings MUST be ignored (RFC 9113 §6.5.2)
    }
}

/// Apply all settings from a SETTINGS frame payload.
/// Returns the old initial_window_size for delta computation.
pub fn applyAll(self: *Settings, payload: []const u8) !u32 {
    if (payload.len % 6 != 0) return error.FrameSizeError;

    const old_initial_window = self.initial_window_size;
    var iter = frame.parseSettings(payload);
    while (iter.next()) |setting| {
        try self.apply(setting.id, setting.value);
    }
    return old_initial_window;
}

/// Encode the non-default settings as a SETTINGS frame payload.
/// Returns the number of bytes written.
pub fn encode(self: *const Settings, buf: []u8) !usize {
    const default: Settings = .{};
    var pos: usize = 0;

    inline for (.{
        .{ SettingsId.header_table_size, "header_table_size" },
        .{ SettingsId.enable_push, "enable_push" },
        .{ SettingsId.max_concurrent_streams, "max_concurrent_streams" },
        .{ SettingsId.initial_window_size, "initial_window_size" },
        .{ SettingsId.max_frame_size, "max_frame_size" },
        .{ SettingsId.max_header_list_size, "max_header_list_size" },
    }) |pair| {
        const id = pair[0];
        const field = pair[1];
        const self_val = if (comptime std.mem.eql(u8, field, "enable_push"))
            @as(u32, if (self.enable_push) 1 else 0)
        else
            @field(self, field);
        const default_val = if (comptime std.mem.eql(u8, field, "enable_push"))
            @as(u32, if (default.enable_push) 1 else 0)
        else
            @field(default, field);

        if (self_val != default_val) {
            if (pos + 6 > buf.len) return error.BufferTooSmall;
            std.mem.writeInt(u16, buf[pos..][0..2], @backingInt(id), .big);
            std.mem.writeInt(u32, buf[pos + 2 ..][0..4], self_val, .big);
            pos += 6;
        }
    }

    return pos;
}

/// Tracks the settings synchronization lifecycle (RFC 9113 §6.5.3).
///
/// When we send SETTINGS to the peer, the new header_table_size must not
/// be applied to the HPACK encoder until the peer ACKs. This struct
/// queues the pending value and applies it on ACK.
pub const Sync = struct {
    /// Our local settings (what we advertise to the peer).
    local: Settings = .{},
    /// Peer's settings (what the peer advertises to us).
    peer: Settings = .{},
    /// Pending HPACK encoder table size, waiting for peer ACK.
    /// null means no pending change.
    pending_encoder_table_size: ?u32 = null,
    /// Whether we have sent SETTINGS that haven't been ACKed yet.
    awaiting_ack: bool = false,
    /// Number of frames received since we sent SETTINGS.
    /// Used for timeout detection — if this exceeds the threshold
    /// without an ACK, the peer is misbehaving (SETTINGS_TIMEOUT).
    frames_since_sent: u32 = 0,

    /// Maximum frames to wait for a SETTINGS ACK before considering it timed out.
    const settings_ack_frame_limit: u32 = 1000;

    /// Record that we sent our local settings to the peer.
    /// If header_table_size differs from the current encoder size,
    /// the change is deferred until receiveAck().
    pub fn markSent(self: *Sync, encoder_current_size: u32) void {
        self.awaiting_ack = true;
        self.frames_since_sent = 0;
        if (self.local.header_table_size != encoder_current_size) {
            self.pending_encoder_table_size = self.local.header_table_size;
        }
    }

    /// Process a received SETTINGS ACK from the peer.
    /// Returns the new HPACK encoder table size if it changed, or null.
    pub fn receiveAck(self: *Sync) ?u32 {
        self.awaiting_ack = false;
        if (self.pending_encoder_table_size) |size| {
            self.pending_encoder_table_size = null;
            return size;
        }
        return null;
    }

    /// Record that a frame was received. Call this on every incoming frame.
    /// Returns error.SettingsTimeout if ACK is overdue.
    pub fn frameReceived(self: *Sync) !void {
        if (self.awaiting_ack) {
            self.frames_since_sent += 1;
            if (self.frames_since_sent > settings_ack_frame_limit) {
                return error.SettingsTimeout;
            }
        }
    }

    /// Apply received peer SETTINGS.
    /// Returns the old initial_window_size for stream window adjustment.
    /// The HPACK decoder table size should be updated immediately.
    pub fn applyPeerSettings(self: *Sync, payload: []const u8) !struct { old_window: u32, new_decoder_table_size: u32 } {
        const old_window = try self.peer.applyAll(payload);
        return .{
            .old_window = old_window,
            .new_decoder_table_size = self.peer.header_table_size,
        };
    }
};

// --- Tests ---

const testing = std.testing;

test "default settings" {
    const s: Settings = .{};
    try testing.expectEqual(@as(u32, 4096), s.header_table_size);
    try testing.expectEqual(true, s.enable_push);
    try testing.expectEqual(@as(u32, 100), s.max_concurrent_streams);
    try testing.expectEqual(@as(u32, 65535), s.initial_window_size);
    try testing.expectEqual(@as(u32, 16384), s.max_frame_size);
    try testing.expectEqual(@as(u32, 8192), s.max_header_list_size);
}

test "apply valid settings" {
    var s: Settings = .{};
    try s.apply(.header_table_size, 8192);
    try testing.expectEqual(@as(u32, 8192), s.header_table_size);

    try s.apply(.enable_push, 0);
    try testing.expectEqual(false, s.enable_push);

    try s.apply(.max_concurrent_streams, 50);
    try testing.expectEqual(@as(u32, 50), s.max_concurrent_streams);

    try s.apply(.initial_window_size, 32768);
    try testing.expectEqual(@as(u32, 32768), s.initial_window_size);

    try s.apply(.max_frame_size, 32768);
    try testing.expectEqual(@as(u32, 32768), s.max_frame_size);
}

test "apply invalid enable_push" {
    var s: Settings = .{};
    try testing.expectError(error.ProtocolError, s.apply(.enable_push, 2));
}

test "apply invalid initial_window_size" {
    var s: Settings = .{};
    try testing.expectError(error.FlowControlError, s.apply(.initial_window_size, 2147483648));
}

test "apply invalid max_frame_size" {
    var s: Settings = .{};
    try testing.expectError(error.ProtocolError, s.apply(.max_frame_size, 100));
    try testing.expectError(error.ProtocolError, s.apply(.max_frame_size, 16777216));
}

test "apply unknown setting is ignored" {
    var s: Settings = .{};
    try s.apply(@fromBackingInt(@intCast(0xFF)), 42);
    // No crash, no change to known fields
    try testing.expectEqual(@as(u32, 4096), s.header_table_size);
}

test "applyAll from payload" {
    var payload: [12]u8 = undefined;
    // HEADER_TABLE_SIZE = 8192
    std.mem.writeInt(u16, payload[0..2], 0x1, .big);
    std.mem.writeInt(u32, payload[2..6], 8192, .big);
    // MAX_CONCURRENT_STREAMS = 50
    std.mem.writeInt(u16, payload[6..8], 0x3, .big);
    std.mem.writeInt(u32, payload[8..12], 50, .big);

    var s: Settings = .{};
    const old_window = try s.applyAll(&payload);
    try testing.expectEqual(@as(u32, 65535), old_window);
    try testing.expectEqual(@as(u32, 8192), s.header_table_size);
    try testing.expectEqual(@as(u32, 50), s.max_concurrent_streams);
}

test "applyAll bad payload length" {
    const payload = [_]u8{ 0, 1, 0, 0, 0 }; // 5 bytes, not multiple of 6
    var s: Settings = .{};
    try testing.expectError(error.FrameSizeError, s.applyAll(&payload));
}

test "encode non-default settings" {
    var s: Settings = .{};
    s.max_concurrent_streams = 50;
    s.enable_push = false;

    var buf: [64]u8 = undefined;
    const n = try s.encode(&buf);

    // Should have 2 settings = 12 bytes
    try testing.expectEqual(@as(usize, 12), n);

    // Parse them back
    var s2: Settings = .{};
    _ = try s2.applyAll(buf[0..n]);
    try testing.expectEqual(false, s2.enable_push);
    try testing.expectEqual(@as(u32, 50), s2.max_concurrent_streams);
}

test "encode default settings produces empty payload" {
    const s: Settings = .{};
    var buf: [64]u8 = undefined;
    const n = try s.encode(&buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "applyAll returns old window for delta computation" {
    var s: Settings = .{};
    s.initial_window_size = 65535;

    var payload: [6]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 0x4, .big); // INITIAL_WINDOW_SIZE
    std.mem.writeInt(u32, payload[2..6], 32768, .big);

    const old = try s.applyAll(&payload);
    try testing.expectEqual(@as(u32, 65535), old);
    try testing.expectEqual(@as(u32, 32768), s.initial_window_size);
    // Caller would compute delta = 32768 - 65535 = -32767 and adjust all stream windows
}

test "Sync: markSent and receiveAck with table size change" {
    var sync: Sync = .{};
    sync.local.header_table_size = 8192; // changed from default 4096

    // Mark sent with current encoder size = 4096 (the default)
    sync.markSent(4096);
    try testing.expect(sync.awaiting_ack);
    try testing.expectEqual(@as(?u32, 8192), sync.pending_encoder_table_size);

    // Receive ACK — should return the new table size
    const new_size = sync.receiveAck();
    try testing.expectEqual(@as(?u32, 8192), new_size);
    try testing.expect(!sync.awaiting_ack);
    try testing.expectEqual(@as(?u32, null), sync.pending_encoder_table_size);
}

test "Sync: markSent with no table size change" {
    var sync: Sync = .{};
    // local.header_table_size == 4096 (default), encoder also at 4096
    sync.markSent(4096);
    try testing.expect(sync.awaiting_ack);
    try testing.expectEqual(@as(?u32, null), sync.pending_encoder_table_size);

    const new_size = sync.receiveAck();
    try testing.expectEqual(@as(?u32, null), new_size);
}

test "Sync: applyPeerSettings" {
    var sync: Sync = .{};

    var payload: [6]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], 0x1, .big); // HEADER_TABLE_SIZE
    std.mem.writeInt(u32, payload[2..6], 2048, .big);

    const result = try sync.applyPeerSettings(&payload);
    try testing.expectEqual(@as(u32, 65535), result.old_window);
    try testing.expectEqual(@as(u32, 2048), result.new_decoder_table_size);
    try testing.expectEqual(@as(u32, 2048), sync.peer.header_table_size);
}
