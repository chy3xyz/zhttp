//! Minimal qlog 0.3 (JSON-SEQ) writer for the native HTTP/3 transport.
//!
//! The writer owns no state beyond its configuration and the caller-supplied
//! sink, never allocates, and never locks. Each event is serialized into one
//! fixed stack buffer and handed to the sink with exactly one write. A writer
//! is therefore safe to keep on the thread that owns the connection; sharing a
//! sink between threads is the caller's responsibility.
//!
//! Privacy: packet payloads, header values, tokens, and peer addresses are
//! never recorded. Connection IDs are shortened to a four-byte prefix unless
//! `full_cids` is set, and free-form reasons are capped and escaped.

const std = @import("std");

/// Caller-owned synchronous byte sink. The callback must not retain `bytes`
/// past the call. It is invoked once per complete JSON-SEQ record.
pub const Sink = struct {
    context: *anyopaque,
    write: *const fn (context: *anyopaque, bytes: []const u8) void,
};

pub const Config = struct {
    sink: Sink,
    /// Sample packet events: 0 logs every packet, 1 every other packet,
    /// 3 every fourth packet, and so on. Connection and error events are
    /// never sampled. The counter is per direction.
    packet_sample_mask: u32 = 0,
    /// Log complete connection IDs instead of their four-byte prefixes.
    full_cids: bool = false,
};

pub const VantagePoint = enum {
    client,
    server,
    unknown,

    pub fn name(self: VantagePoint) []const u8 {
        return switch (self) {
            .client => "client",
            .server => "server",
            .unknown => "unknown",
        };
    }
};

pub const Initiator = enum {
    local,
    remote,
    transport,

    pub fn name(self: Initiator) []const u8 {
        return switch (self) {
            .local => "local",
            .remote => "remote",
            .transport => "transport",
        };
    }
};

pub const PacketType = enum {
    initial,
    handshake,
    zero_rtt,
    one_rtt,
    retry,
    version_negotiation,

    pub fn name(self: PacketType) []const u8 {
        return switch (self) {
            .initial => "Initial",
            .handshake => "Handshake",
            .zero_rtt => "0RTT",
            .one_rtt => "1RTT",
            .retry => "Retry",
            .version_negotiation => "VersionNegotiation",
        };
    }
};

/// Coarse, allocation-free frame summary. Counts are saturating and only
/// describe frame categories, never their contents.
pub const FrameSummary = struct {
    stream: u16 = 0,
    crypto: u16 = 0,
    ack: u16 = 0,
    flow: u16 = 0,
    control: u16 = 0,
    other: u16 = 0,
    padding: u16 = 0,
};

/// Transport counter snapshot copied into connectivity:connection_closed.
/// Kept independent of transport.zig so this module stays dependency-free.
pub const ConnectionStats = struct {
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
    retransmits: u64 = 0,
    streams_opened: u64 = 0,
    streams_closed: u64 = 0,
    flow_updates: u64 = 0,
    ack_frames_sent: u64 = 0,

    pub fn from(other: anytype) ConnectionStats {
        return .{
            .packets_sent = other.packets_sent,
            .packets_received = other.packets_received,
            .bytes_sent = other.bytes_sent,
            .bytes_received = other.bytes_received,
            .retransmits = other.retransmits,
            .streams_opened = other.streams_opened,
            .streams_closed = other.streams_closed,
            .flow_updates = other.flow_updates,
            .ack_frames_sent = other.ack_frames_sent,
        };
    }
};

/// Wall-clock milliseconds plus the monotonic microsecond clock used by all
/// event timestamps. Injecting this keeps writer output deterministic in tests.
pub const Reference = struct {
    wall_ms: u64 = 0,
    monotonic_us: u64 = 0,

    pub fn now() Reference {
        var ts: std.posix.timespec = undefined;
        _ = std.c.clock_gettime(std.posix.CLOCK.REALTIME, &ts);
        const wall_ms = @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
        _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
        const monotonic_us = @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1000;
        return .{ .wall_ms = wall_ms, .monotonic_us = monotonic_us };
    }
};

const record_separator: u8 = 0x1e; // RFC 7464 RS
const max_record_len = 2048;
const cid_prefix_len = 4;
const max_reason_len = 96;

pub const Writer = struct {
    sink: Sink,
    packet_sample_mask: u32,
    full_cids: bool,
    reference: Reference,
    sent_packets: u64 = 0,
    received_packets: u64 = 0,
    lost_packets: u64 = 0,
    closed: bool = false,

    pub fn init(config: Config, reference: Reference) Writer {
        return .{
            .sink = config.sink,
            .packet_sample_mask = config.packet_sample_mask,
            .full_cids = config.full_cids,
            .reference = reference,
        };
    }

    /// Emit the qlog 0.3 JSON-SEQ stream header. Call exactly once per sink
    /// before any event record.
    pub fn writeHeader(self: *Writer, vantage: VantagePoint) void {
        var buf: [max_record_len]u8 = undefined;
        buf[0] = record_separator;
        var w = std.Io.Writer.fixed(buf[1..]);
        w.print(
            "{{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\",\"title\":\"zhttp native HTTP/3\",\"trace\":{{\"vantage_point\":{{\"name\":\"zhttp\",\"type\":\"{s}\"}},\"common_fields\":{{\"reference_time\":{d},\"time_format\":\"relative\",\"protocol_type\":[\"QUIC\",\"HTTP3\"]}}}}}}\n",
            .{ vantage.name(), self.reference.wall_ms },
        ) catch return;
        self.sink.write(self.sink.context, buf[0 .. 1 + w.end]);
    }

    pub fn connectionStarted(
        self: *Writer,
        now_us: u64,
        role: VantagePoint,
        local_cid: []const u8,
        peer_cid: []const u8,
    ) void {
        var buf: [max_record_len]u8 = undefined;
        var w = self.startRecord(&buf, now_us, "connectivity:connection_started") orelse return;
        w.writeAll("{\"role\":\"") catch return;
        w.writeAll(role.name()) catch return;
        w.writeAll("\",\"src_cid\":") catch return;
        self.writeCid(&w, local_cid) catch return;
        w.writeAll(",\"dst_cid\":") catch return;
        self.writeCid(&w, peer_cid) catch return;
        w.writeAll("}") catch return;
        self.finishRecord(&buf, &w);
    }

    pub fn connectionClosed(
        self: *Writer,
        now_us: u64,
        initiator: Initiator,
        error_code: u64,
        reason: []const u8,
        stats: ConnectionStats,
    ) void {
        if (self.closed) return;
        self.closed = true;
        var buf: [max_record_len]u8 = undefined;
        var w = self.startRecord(&buf, now_us, "connectivity:connection_closed") orelse return;
        w.writeAll("{\"initiator\":\"") catch return;
        w.writeAll(initiator.name()) catch return;
        w.print("\",\"error_code\":{d},\"error\":", .{error_code}) catch return;
        writeJsonString(&w, reason, max_reason_len) catch return;
        w.writeAll(",\"stats\":") catch return;
        writeStats(&w, stats) catch return;
        w.writeAll("}") catch return;
        self.finishRecord(&buf, &w);
    }

    pub fn packetSent(
        self: *Writer,
        now_us: u64,
        packet_number: u64,
        level: u8,
        packet_type: PacketType,
        ack_eliciting: bool,
        plaintext_len: usize,
        frames: FrameSummary,
    ) void {
        var buf: [max_record_len]u8 = undefined;
        var w = self.startRecord(&buf, now_us, "transport:packet_sent") orelse return;
        self.writePacketData(&w, packet_number, level, packet_type, ack_eliciting, plaintext_len, frames) catch return;
        self.finishRecord(&buf, &w);
    }

    pub fn packetReceived(
        self: *Writer,
        now_us: u64,
        packet_number: u64,
        level: u8,
        packet_type: PacketType,
        ack_eliciting: bool,
        plaintext_len: usize,
        frames: FrameSummary,
    ) void {
        var buf: [max_record_len]u8 = undefined;
        var w = self.startRecord(&buf, now_us, "transport:packet_received") orelse return;
        self.writePacketData(&w, packet_number, level, packet_type, ack_eliciting, plaintext_len, frames) catch return;
        self.finishRecord(&buf, &w);
    }

    /// Record only the packet number, level, and plaintext length of a packet
    /// the transport has declared lost. Payload bytes are never logged.
    pub fn packetLost(self: *Writer, now_us: u64, packet_number: u64, level: u8, payload_len: usize) void {
        var buf: [max_record_len]u8 = undefined;
        var w = self.startRecord(&buf, now_us, "recovery:packet_lost") orelse return;
        w.print(
            "{{\"level\":{d},\"packet_number\":{d},\"payload_len\":{d}}}",
            .{ level, packet_number, payload_len },
        ) catch return;
        self.finishRecord(&buf, &w);
    }

    /// The listener emitted a Retry. No token, address, or CID is recorded.
    pub fn retrySent(self: *Writer, now_us: u64) void {
        var buf: [max_record_len]u8 = undefined;
        var w = self.startRecord(&buf, now_us, "zhttp:retry_sent") orelse return;
        w.writeAll("{\"reason\":\"token_required\"}") catch return;
        self.finishRecord(&buf, &w);
    }

    /// A Retry was refused before a connection existed. The reason is one of
    /// the listener's fixed strings, never peer-supplied text.
    pub fn retryRejected(self: *Writer, now_us: u64, reason: []const u8) void {
        var buf: [max_record_len]u8 = undefined;
        var w = self.startRecord(&buf, now_us, "zhttp:retry_rejected") orelse return;
        w.writeAll("{\"reason\":") catch return;
        writeJsonString(&w, reason, max_reason_len) catch return;
        w.writeAll("}") catch return;
        self.finishRecord(&buf, &w);
    }

    /// Transport or HTTP/3 close point. `reason` is capped; it should be an
    /// internal constant, never a header value or peer-supplied text.
    pub fn errorEvent(self: *Writer, now_us: u64, code: u64, reason: []const u8) void {
        var buf: [max_record_len]u8 = undefined;
        var w = self.startRecord(&buf, now_us, "zhttp:error") orelse return;
        w.print("{{\"code\":{d},\"reason\":", .{code}) catch return;
        writeJsonString(&w, reason, max_reason_len) catch return;
        w.writeAll("}") catch return;
        self.finishRecord(&buf, &w);
    }

    /// Sampling is checked before the caller reads a timestamp, so rejected
    /// packet events cost a counter increment only.
    pub fn sampleSent(self: *Writer) bool {
        return sample(&self.sent_packets, self.packet_sample_mask);
    }

    pub fn sampleReceived(self: *Writer) bool {
        return sample(&self.received_packets, self.packet_sample_mask);
    }

    pub fn sampleLost(self: *Writer) bool {
        return sample(&self.lost_packets, self.packet_sample_mask);
    }

    fn sample(counter: *u64, mask: u32) bool {
        const index = counter.*;
        counter.* +%= 1;
        return mask == 0 or (index & mask) == 0;
    }

    fn writePacketData(
        self: *Writer,
        w: *std.Io.Writer,
        packet_number: u64,
        level: u8,
        packet_type: PacketType,
        ack_eliciting: bool,
        plaintext_len: usize,
        frames: FrameSummary,
    ) !void {
        _ = self;
        try w.print(
            "{{\"level\":{d},\"packet_type\":\"{s}\",\"packet_number\":{d},\"ack_eliciting\":{s},\"plaintext_len\":{d},\"frames\":\"",
            .{ level, packet_type.name(), packet_number, if (ack_eliciting) "true" else "false", plaintext_len },
        );
        try writeFrameSummary(w, frames);
        try w.writeAll("\"}");
    }

    fn startRecord(
        self: *Writer,
        buf: *[max_record_len]u8,
        now_us: u64,
        name: []const u8,
    ) ?std.Io.Writer {
        buf[0] = record_separator;
        var w = std.Io.Writer.fixed(buf[1..]);
        const delta_us = now_us -| self.reference.monotonic_us;
        w.print("{{\"time\":{d}.{d:0>3},\"name\":\"{s}\",\"data\":", .{
            delta_us / 1000,
            delta_us % 1000,
            name,
        }) catch return null;
        return w;
    }

    fn finishRecord(self: *Writer, buf: *[max_record_len]u8, w: *std.Io.Writer) void {
        // Close the event object itself; each event wrote its "data" object.
        w.writeAll("}\n") catch return;
        self.sink.write(self.sink.context, buf[0 .. 1 + w.end]);
    }

    fn writeCid(self: *const Writer, w: *std.Io.Writer, cid: []const u8) !void {
        const hex = "0123456789abcdef";
        const shown = if (self.full_cids) cid.len else @min(cid.len, cid_prefix_len);
        try w.writeByte('"');
        for (cid[0..shown]) |byte| {
            try w.writeByte(hex[byte >> 4]);
            try w.writeByte(hex[byte & 0x0f]);
        }
        if (!self.full_cids and cid.len > shown) try w.writeAll("..");
        try w.writeByte('"');
    }
};

fn writeFrameSummary(w: *std.Io.Writer, frames: FrameSummary) !void {
    const Entry = struct { count: u16, name: []const u8 };
    const entries = [_]Entry{
        .{ .count = frames.stream, .name = "STREAM" },
        .{ .count = frames.crypto, .name = "CRYPTO" },
        .{ .count = frames.ack, .name = "ACK" },
        .{ .count = frames.flow, .name = "FLOW" },
        .{ .count = frames.control, .name = "CONTROL" },
        .{ .count = frames.other, .name = "OTHER" },
        .{ .count = frames.padding, .name = "PADDING" },
    };
    var first = true;
    for (entries) |entry| {
        if (entry.count == 0) continue;
        if (!first) try w.writeByte(',');
        first = false;
        try w.print("{d}x{s}", .{ entry.count, entry.name });
    }
}

fn writeStats(w: *std.Io.Writer, stats: ConnectionStats) !void {
    try w.print(
        "{{\"packets_sent\":{d},\"packets_received\":{d},\"bytes_sent\":{d},\"bytes_received\":{d},\"retransmits\":{d},\"streams_opened\":{d},\"streams_closed\":{d},\"flow_updates\":{d},\"ack_frames_sent\":{d}}}",
        .{
            stats.packets_sent,
            stats.packets_received,
            stats.bytes_sent,
            stats.bytes_received,
            stats.retransmits,
            stats.streams_opened,
            stats.streams_closed,
            stats.flow_updates,
            stats.ack_frames_sent,
        },
    );
}

fn writeJsonString(w: *std.Io.Writer, text: []const u8, max_len: usize) !void {
    const shown = @min(text.len, max_len);
    try w.writeByte('"');
    for (text[0..shown]) |byte| {
        switch (byte) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(byte),
            else => try w.print("\\u00{x:0>2}", .{byte}),
        }
    }
    try w.writeByte('"');
}
