//! HTTP/3 framing and request/response state for the native stack.
//!
//! The transport hands this layer ordered stream bytes. This file owns the
//! HTTP/3 control/QPACK streams, decoder-stream acknowledgments, blocked-stream
//! resume, the per-stream frame parser, QPACK header blocks, and the
//! server/client exchange state machines.

const std = @import("std");
const transport = @import("transport.zig");
const qpack = @import("qpack.zig");
const h1 = @import("../../Request.zig");
const h1_response = @import("../../Response.zig");
pub const Headers = @import("../../Headers.zig");

pub const Method = h1.Method;
pub const StatusCode = h1_response.StatusCode;
pub const HeaderField = qpack.HeaderField;
pub const Header = HeaderField;

pub const Request = struct {
    method: Method,
    path: []const u8,
    authority: []const u8 = "",
    /// URI scheme from the :scheme pseudo-header. Plain CONNECT must omit
    /// :scheme (RFC 9114 section 4.4), so the field is empty for that form.
    scheme: []const u8 = "",
    headers: Headers = .{},
    body: []const u8 = "",
};

pub const Response = struct {
    status: StatusCode = .ok,
    content_type: []const u8 = "text/plain",
    body: []const u8 = "",
    body_reader: ?*const fn (context: ?*anyopaque, buf: []u8) anyerror!usize = null,
    body_context: ?*anyopaque = null,
    /// Optional cleanup for body_context, called exactly once when the reader
    /// finishes, fails, or the stream is torn down.
    body_reader_deinit: ?*const fn (context: ?*anyopaque) void = null,
    headers: []const Header = &.{},
};

pub const Handler = *const fn (allocator: std.mem.Allocator, request: *const Request) Response;

/// A handler that also receives an application context. This keeps multiple
/// servers/sessions from having to route application state through globals.
pub const ContextHandler = *const fn (context: ?*anyopaque, allocator: std.mem.Allocator, request: *const Request) Response;

const control_stream_type: u64 = 0x00;
const push_stream_type: u64 = 0x01;
const qpack_encoder_stream_type: u64 = 0x02;
const qpack_decoder_stream_type: u64 = 0x03;

const frame_data: u64 = 0x00;
const frame_headers: u64 = 0x01;
const frame_settings: u64 = 0x04;
const frame_goaway: u64 = 0x07;

// RFC 9114 section 7.2.4.1 SETTINGS identifiers.
const setting_qpack_max_table_capacity: u64 = 0x01;
const setting_max_field_section_size: u64 = 0x06;
const setting_qpack_blocked_streams: u64 = 0x07;
// Identifiers reserved from HTTP/2 (RFC 9114 section 7.2.4.1) MUST NOT be
// sent; receiving one is H3_SETTINGS_ERROR rather than an unknown setting.
const setting_reserved_first: u64 = 0x02;
const setting_reserved_last: u64 = 0x05;

// RFC 9114 section 8.1 application error codes used when validating the peer's
// control stream.
pub const h3_stream_creation_error: u64 = 0x0103;
pub const h3_closed_critical_stream: u64 = 0x0104;
pub const h3_frame_unexpected: u64 = 0x0105;
pub const h3_settings_error: u64 = 0x0109;
pub const h3_missing_settings: u64 = 0x010a;

// RFC 9204 section 6 QPACK error codes.
pub const qpack_decompression_failed: u64 = 0x0201;
pub const qpack_encoder_stream_error: u64 = 0x0202;
pub const qpack_decoder_stream_error: u64 = 0x0203;

/// SETTINGS_QPACK_MAX_TABLE_CAPACITY advertised by this endpoint. The decoder
/// dynamic table can grow this large, so peers may send encoder instructions.
pub const qpack_table_capacity: u64 = 4096;
/// SETTINGS_QPACK_BLOCKED_STREAMS. A small bound keeps the number of parked
/// request streams bounded while still letting a peer reference inserts that
/// are in flight on its encoder stream.
const max_blocked_streams: usize = 16;
pub const qpack_blocked_streams: u64 = max_blocked_streams;
/// A request stream may wait this long for Required Insert Count inserts to
/// arrive before the connection fails with QPACK_DECOMPRESSION_FAILED.
pub const qpack_blocked_stream_timeout_ns: u64 = 2 * std.time.ns_per_s;

const default_max_body = 1024 * 1024;

pub const Error = error{
    InvalidFrame,
    InvalidHeaderBlock,
    /// QPACK block referenced a dynamic-table entry that is not present
    /// (blocked streams are disabled) or an invalid dynamic index. Maps to
    /// QPACK_DECOMPRESSION_FAILED (0x0201).
    DynamicTableReference,
    BodyTooLarge,
    NotEstablished,
    StreamClosed,
    OutOfMemory,
    ConnectionClosed,
};

const StreamKind = enum {
    unknown,
    request,
    control,
    qpack_encoder,
    qpack_decoder,
    ignored,
};

/// Validation state for the peer's control stream (RFC 9114 sections 6.2.1
/// and 6.2.4). This is deliberately free of transport and allocator state so
/// every state transition is unit-testable without a live QUIC connection.
pub const ControlState = struct {
    /// Stream ID of the first peer-initiated unidirectional stream that
    /// announced the control stream type.
    stream_id: ?u64 = null,
    /// SETTINGS is mandatory as the first complete frame on the stream.
    settings_received: bool = false,
    frames_seen: u64 = 0,

    pub const Violation = enum {
        duplicate_control_stream,
        duplicate_qpack_stream,
        missing_settings,
        duplicate_settings,
        duplicate_setting,
        malformed_settings,
        reserved_setting,
        closed_critical_stream,
        unexpected_frame,

        /// RFC 9114 section 8.1 error code plus a short, stable reason phrase.
        pub fn closeCode(self: Violation) u64 {
            return switch (self) {
                .duplicate_control_stream => h3_stream_creation_error,
                .duplicate_qpack_stream => h3_stream_creation_error,
                .missing_settings => h3_missing_settings,
                .duplicate_settings,
                .duplicate_setting,
                .malformed_settings,
                .reserved_setting,
                => h3_settings_error,
                .closed_critical_stream => h3_closed_critical_stream,
                .unexpected_frame => h3_frame_unexpected,
            };
        }

        pub fn reason(self: Violation) []const u8 {
            return switch (self) {
                .duplicate_control_stream => "duplicate control stream",
                .duplicate_qpack_stream => "duplicate QPACK stream",
                .missing_settings => "missing settings",
                .duplicate_settings => "duplicate settings",
                .duplicate_setting => "duplicate setting identifier",
                .malformed_settings => "malformed settings",
                .reserved_setting => "reserved setting identifier",
                .closed_critical_stream => "control stream closed",
                .unexpected_frame => "unexpected control frame",
            };
        }
    };

    /// Claim a peer-initiated unidirectional stream for the control stream
    /// type. Re-claiming the same stream ID is idempotent; any other ID is a
    /// second control stream and fails with H3_STREAM_CREATION_ERROR.
    pub fn claimStream(self: *ControlState, stream_id: u64) ?Violation {
        if (self.stream_id) |existing| {
            return if (existing == stream_id) null else .duplicate_control_stream;
        }
        self.stream_id = stream_id;
        return null;
    }

    /// Validate one fully received control-stream frame. Partial frames must
    /// never reach this helper: only a complete frame can prove a violation.
    pub fn onFrame(self: *ControlState, frame_type: u64) ?Violation {
        if (!self.settings_received) {
            if (frame_type != frame_settings) return .missing_settings;
            self.settings_received = true;
            self.frames_seen += 1;
            return null;
        }
        if (frame_type == frame_settings) return .duplicate_settings;
        // DATA and HEADERS are explicitly forbidden on a control stream
        // (RFC 9114 sections 7.2.1 and 7.2.2). Unknown frame types are ignored.
        if (frame_type == frame_data or frame_type == frame_headers) {
            return .unexpected_frame;
        }
        self.frames_seen += 1;
        return null;
    }

    /// FIN on the peer's control stream before the connection closes.
    pub fn onFin(self: *ControlState) ?Violation {
        _ = self;
        return .closed_critical_stream;
    }
};

/// The QPACK-relevant subset of the peer's SETTINGS frame.
pub const Settings = struct {
    qpack_max_table_capacity: u64 = 0,
    qpack_blocked_streams: u64 = 0,
    /// Null when the peer did not send SETTINGS_MAX_FIELD_SECTION_SIZE, which
    /// means it accepts field sections of any size (RFC 9114 section 7.2.4.1).
    max_field_section_size: ?u64 = null,
};

pub const SettingsError = enum {
    malformed,
    duplicate_id,
    reserved_id,

    pub fn violation(self: SettingsError) ControlState.Violation {
        return switch (self) {
            .malformed => .malformed_settings,
            .duplicate_id => .duplicate_setting,
            .reserved_id => .reserved_setting,
        };
    }
};

/// Parse a complete SETTINGS payload. Unknown identifiers are ignored, but a
/// duplicated identifier (known or unknown) is H3_SETTINGS_ERROR, as is a
/// payload that does not decode into complete identifier/value pairs.
pub fn parseSettings(payload: []const u8, settings: *Settings) ?SettingsError {
    var parsed: Settings = .{};
    var cursor: usize = 0;
    while (cursor < payload.len) {
        const pair_start = cursor;
        const id = readVarint(payload, &cursor) orelse return .malformed;
        const value = readVarint(payload, &cursor) orelse return .malformed;
        if (settingIdSeen(payload[0..pair_start], id)) return .duplicate_id;
        if (id >= setting_reserved_first and id <= setting_reserved_last) {
            return .reserved_id;
        }
        switch (id) {
            setting_qpack_max_table_capacity => parsed.qpack_max_table_capacity = value,
            setting_qpack_blocked_streams => parsed.qpack_blocked_streams = value,
            setting_max_field_section_size => parsed.max_field_section_size = value,
            else => {},
        }
    }
    settings.* = parsed;
    return null;
}

fn settingIdSeen(prefix: []const u8, id: u64) bool {
    var cursor: usize = 0;
    while (cursor < prefix.len) {
        const seen = readVarint(prefix, &cursor) orelse return false;
        _ = readVarint(prefix, &cursor) orelse return false;
        if (seen == id) return true;
    }
    return false;
}

const ClientResponse = struct {
    status: u16 = 0,
    header_text: std.ArrayListUnmanaged(u8) = .empty,
    body: std.ArrayListUnmanaged(u8) = .empty,

    fn deinit(self: *ClientResponse, allocator: std.mem.Allocator) void {
        self.header_text.deinit(allocator);
        self.body.deinit(allocator);
    }
};

/// One HEADERS frame parked because its Required Insert Count is ahead of
/// the peer's encoder stream. The frame is not consumed: `parse_offset` stays
/// at the frame start and the reassembler retains every following byte.
const BlockedSection = struct {
    required_insert_count: u64,
    /// Stream offset of the HEADERS frame header.
    frame_offset: usize,
    /// Stream offset of the QPACK field-section payload.
    block_offset: usize,
    since_ns: u64,
};

const HeaderOutcome = enum { decoded, blocked };

const StreamState = struct {
    allocator: std.mem.Allocator,
    id: u64,
    kind: StreamKind = .unknown,
    reassembler: transport.Reassembler,
    parse_offset: usize = 0,
    headers: ?qpack.HeaderList = null,
    /// HEADERS frame waiting for peer inserts (a blocked request stream).
    blocked: ?BlockedSection = null,
    /// Number of decoded dynamic field sections whose Section Acknowledgment
    /// has not been queued yet (decoder-stream backpressure or an allocation
    /// error). A stream can carry request HEADERS and trailers.
    section_ack_pending: u32 = 0,
    method: ?Method = null,
    method_unknown: bool = false,
    path: []const u8 = "",
    authority: []const u8 = "",
    scheme: []const u8 = "",
    request_headers: Headers = .{},
    body: std.ArrayListUnmanaged(u8) = .empty,
    fin: bool = false,
    handled: bool = false,
    reader: ?*const fn (context: ?*anyopaque, buf: []u8) anyerror!usize = null,
    reader_context: ?*anyopaque = null,
    reader_deinit: ?*const fn (context: ?*anyopaque) void = null,
    reader_released: bool = false,
    reader_done: bool = false,
    answer_taken: bool = false,
    done: bool = false,
    response: ?*ClientResponse = null,

    fn init(allocator: std.mem.Allocator, id: u64) !*StreamState {
        const self = try allocator.create(StreamState);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
            .id = id,
            .reassembler = try transport.Reassembler.init(allocator),
        };
        return self;
    }

    fn releaseReader(self: *StreamState) void {
        if (self.reader_released) return;
        self.reader_released = true;
        if (self.reader_deinit) |cleanup| cleanup(self.reader_context);
        self.reader_deinit = null;
    }

    fn deinit(self: *StreamState) void {
        const allocator = self.allocator;
        self.releaseReader();
        if (self.headers) |*headers| headers.deinit();
        self.body.deinit(allocator);
        if (self.response) |response| {
            response.deinit(allocator);
            allocator.destroy(response);
        }
        self.reassembler.deinit();
        allocator.destroy(self);
    }
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    conn: *transport.Connection,
    role: transport.Role,
    handler: ?Handler = null,
    context_handler: ?ContextHandler = null,
    handler_context: ?*anyopaque = null,
    max_body_bytes: usize = default_max_body,
    started: bool = false,
    peer_settings_received: bool = false,
    /// QPACK limits advertised by the peer in its SETTINGS frame. They bound
    /// the peer's decoder, so our encoder must respect them. The local
    /// advertised limits are qpack_table_capacity / qpack_blocked_streams.
    peer_qpack_max_table_capacity: u64 = 0,
    peer_qpack_blocked_streams: u64 = 0,
    /// Zero when the peer did not advertise a field section size limit.
    peer_max_field_section_size: u64 = 0,
    /// Decoder-side dynamic table. It applies the peer's encoder-stream
    /// instructions and resolves request HEADERS that reference inserted
    /// entries. Our SETTINGS advertise 4096 bytes; Insert Count Increment and
    /// Section Acknowledgment bytes are queued on qpack_decoder_stream.
    decoder: qpack.Decoder,
    /// Encoder-side dynamic table plus the peer's limits. It stages inserts
    /// and field-section references; qpack_encoder_stream carries the staged
    /// instructions. Until the peer's SETTINGS arrive its capacity is zero,
    /// so field sections stay static-only.
    encoder: qpack.Encoder,
    /// Highest insert count acknowledged to the peer on our decoder stream.
    /// Insert Count Increment always sends the delta to decoder.insertCount().
    decoder_acked_insert_count: u64 = 0,
    goaway_id: ?u64 = null,
    max_request_stream_id: u64 = 0,
    streams: std.AutoHashMapUnmanaged(u64, *StreamState) = .empty,
    retired: std.DynamicBitSet,
    done_streams: std.ArrayListUnmanaged(u64) = .empty,
    control_stream: u64 = 0,
    qpack_encoder_stream: u64 = 0,
    qpack_decoder_stream: u64 = 0,
    /// Peer control stream validation; this stream is distinct from the
    /// locally created control stream above.
    peer_control: ControlState = .{},
    /// Stream IDs of the peer's QPACK encoder/decoder unidirectional streams.
    /// A second stream of either type is H3_STREAM_CREATION_ERROR.
    peer_qpack_encoder_stream: ?u64 = null,
    peer_qpack_decoder_stream: ?u64 = null,

    pub fn initServer(
        allocator: std.mem.Allocator,
        conn: *transport.Connection,
        handler: Handler,
        max_body_bytes: usize,
    ) !*Session {
        return init(allocator, conn, .server, handler, null, null, max_body_bytes);
    }

    pub fn initServerWithContext(
        allocator: std.mem.Allocator,
        conn: *transport.Connection,
        context: ?*anyopaque,
        handler: ContextHandler,
        max_body_bytes: usize,
    ) !*Session {
        return init(allocator, conn, .server, null, handler, context, max_body_bytes);
    }

    pub fn initClient(
        allocator: std.mem.Allocator,
        conn: *transport.Connection,
        max_body_bytes: usize,
    ) !*Session {
        return init(allocator, conn, .client, null, null, null, max_body_bytes);
    }

    fn init(
        allocator: std.mem.Allocator,
        conn: *transport.Connection,
        role: transport.Role,
        handler: ?Handler,
        context_handler: ?ContextHandler,
        handler_context: ?*anyopaque,
        max_body_bytes: usize,
    ) !*Session {
        const self = try allocator.create(Session);
        errdefer allocator.destroy(self);
        var retired = try std.DynamicBitSet.initEmpty(allocator, 0);
        errdefer retired.deinit();
        self.* = .{
            .allocator = allocator,
            .conn = conn,
            .role = role,
            .handler = handler,
            .context_handler = context_handler,
            .handler_context = handler_context,
            .max_body_bytes = max_body_bytes,
            .decoder = qpack.Decoder.init(allocator, @intCast(qpack_table_capacity)),
            .encoder = qpack.Encoder.init(allocator),
            .retired = retired,
        };
        // Field-section timestamps and the encoder timeout both use the
        // transport's monotonic clock so they cannot drift apart.
        self.encoder.clock = transport.nowNanos;
        errdefer self.encoder.deinit();
        errdefer self.decoder.deinit();
        conn.handler = .{
            .context = self,
            .on_stream_frame = onStreamFrame,
            .on_established = onEstablished,
            .on_closed = onClosed,
        };
        if (conn.isEstablished()) self.begin() catch |err| {
            conn.handler = null;
            return err;
        };
        return self;
    }

    pub fn deinit(self: *Session) void {
        if (self.conn.handler != null and self.conn.handler.?.context == @as(*anyopaque, @ptrCast(self))) {
            self.conn.handler = null;
        }
        var it = self.streams.iterator();
        while (it.next()) |entry| entry.value_ptr.*.deinit();
        self.streams.deinit(self.allocator);
        self.decoder.deinit();
        self.encoder.deinit();
        self.retired.deinit();
        self.done_streams.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    fn streamIndex(stream_id: u64) usize {
        return @intCast(stream_id >> 2);
    }

    fn isRetired(self: *const Session, stream_id: u64) bool {
        const index = streamIndex(stream_id);
        return index < self.retired.capacity() and self.retired.isSet(index);
    }

    /// Drop a completed stream and remember its ID so a late retransmitted
    /// frame cannot recreate it. Stream IDs are monotonically increasing, so a
    /// bitset indexed by id/4 stays tiny even for long-lived connections.
    fn retireStream(self: *Session, stream_id: u64) void {
        const index = streamIndex(stream_id);
        if (index >= self.retired.capacity()) {
            self.retired.resize(index + 64, false) catch {};
        }
        if (index < self.retired.capacity()) self.retired.set(index);
        if (self.streams.fetchRemove(stream_id)) |entry| {
            const state = @constCast(entry.value);
            // A reset/retired stream may still hold an unacknowledged section.
            // Tell the peer's encoder to drop it before releasing the state.
            self.cancelSection(state);
            state.deinit();
        }
    }

    fn queueRetire(self: *Session, stream_id: u64) void {
        const state = self.streams.get(stream_id) orelse return;
        if (state.done) return;
        state.done = true;
        self.done_streams.append(self.allocator, stream_id) catch {};
    }

    fn reapRetired(self: *Session) void {
        var index: usize = 0;
        while (index < self.done_streams.items.len) : (index += 1) {
            self.retireStream(self.done_streams.items[index]);
        }
        self.done_streams.clearRetainingCapacity();
    }

    pub fn setHandler(self: *Session, handler: ?Handler) void {
        self.handler = handler;
    }

    pub fn peerSettingsReceived(self: *const Session) bool {
        return self.peer_settings_received;
    }

    /// Number of request streams currently parked on future peer inserts.
    /// Exposed for diagnostics and deterministic blocked-stream tests.
    pub fn blockedStreamCount(self: *const Session) usize {
        return self.blockedCount();
    }

    fn onEstablished(context: *anyopaque) anyerror!void {
        const self: *Session = @ptrCast(@alignCast(context));
        try self.begin();
    }

    fn onClosed(context: *anyopaque, code: u64) void {
        _ = context;
        _ = code;
    }

    fn begin(self: *Session) !void {
        if (self.started) return;

        self.control_stream = try self.conn.createUniStream();
        self.qpack_encoder_stream = try self.conn.createUniStream();
        self.qpack_decoder_stream = try self.conn.createUniStream();

        var control: std.ArrayListUnmanaged(u8) = .empty;
        defer control.deinit(self.allocator);
        try writeVarint(&control, self.allocator, control_stream_type);

        var settings: std.ArrayListUnmanaged(u8) = .empty;
        defer settings.deinit(self.allocator);
        // SETTINGS_QPACK_MAX_TABLE_CAPACITY = 4096
        try writeVarint(&settings, self.allocator, setting_qpack_max_table_capacity);
        try writeVarint(&settings, self.allocator, qpack_table_capacity);
        // SETTINGS_QPACK_BLOCKED_STREAMS = 0
        try writeVarint(&settings, self.allocator, setting_qpack_blocked_streams);
        try writeVarint(&settings, self.allocator, qpack_blocked_streams);
        // SETTINGS_MAX_FIELD_SECTION_SIZE
        try writeVarint(&settings, self.allocator, 0x06);
        try writeVarint(&settings, self.allocator, 64 * 1024);
        try writeFrame(&control, self.allocator, frame_settings, settings.items);
        try self.conn.queueStreamData(self.control_stream, control.items, false);

        var enc: std.ArrayListUnmanaged(u8) = .empty;
        defer enc.deinit(self.allocator);
        try writeVarint(&enc, self.allocator, qpack_encoder_stream_type);
        try self.conn.queueStreamData(self.qpack_encoder_stream, enc.items, false);

        // Type 0x03 local decoder stream. queueDecoderInstruction appends
        // Insert Count Increment, Section Acknowledgment, and Stream
        // Cancellation instructions here as QPACK events happen.
        var dec: std.ArrayListUnmanaged(u8) = .empty;
        defer dec.deinit(self.allocator);
        try writeVarint(&dec, self.allocator, qpack_decoder_stream_type);
        try self.conn.queueStreamData(self.qpack_decoder_stream, dec.items, false);
        self.started = true;
        // The peer's SETTINGS may already have been applied when begin() runs
        // late; flush any encoder instructions staged before startup.
        try self.flushEncoderInstructions();
    }

    fn onStreamFrame(
        context: *anyopaque,
        stream_id: u64,
        offset: u64,
        data: []const u8,
        fin: bool,
    ) anyerror!void {
        const self: *Session = @ptrCast(@alignCast(context));
        const state = try self.getOrCreate(stream_id);
        _ = state.reassembler.insert(offset, data, fin) catch return;
        if (fin) state.fin = true;
        self.processStream(state) catch |err| {
            self.handleStreamError(state, err);
            return;
        };
    }

    fn getOrCreate(self: *Session, stream_id: u64) !*StreamState {
        if (self.isRetired(stream_id)) return error.StreamClosed;
        if (self.streams.get(stream_id)) |state| return state;
        const state = try StreamState.init(self.allocator, stream_id);
        errdefer state.deinit();
        try self.streams.put(self.allocator, stream_id, state);

        // Bidi streams are requests (server side) or responses on a stream the
        // client already created. Uni streams announce their type in-band.
        if (stream_id & 0x2 == 0) {
            // Server-initiated bidirectional streams are push; this stack does
            // not implement push, so ignore them instead of treating a push
            // header block as a response.
            state.kind = if (self.role == .client and (stream_id & 0x3) == 1) .ignored else .request;
        }
        return state;
    }

    fn processStream(self: *Session, state: *StreamState) !void {
        if (state.kind == .unknown) {
            if (state.id & 0x2 == 0) {
                state.kind = .request;
            } else {
                var cursor: usize = 0;
                const data = state.reassembler.buf.items[0..state.reassembler.contiguous];
                const stream_type = readVarint(data, &cursor) orelse return;
                state.parse_offset = cursor;
                if (stream_type == control_stream_type) {
                    if (self.peer_control.claimStream(state.id)) |violation| {
                        self.closeForControlViolation(violation);
                        state.kind = .ignored;
                        return;
                    }
                    state.kind = .control;
                } else {
                    state.kind = switch (stream_type) {
                        qpack_encoder_stream_type => .qpack_encoder,
                        qpack_decoder_stream_type => .qpack_decoder,
                        push_stream_type => .ignored,
                        else => .ignored,
                    };
                    if (state.kind == .qpack_encoder or state.kind == .qpack_decoder) {
                        if (self.claimQpackStream(state.id, state.kind)) |violation| {
                            self.closeForControlViolation(violation);
                            state.kind = .ignored;
                            return;
                        }
                    }
                }
            }
        }

        switch (state.kind) {
            .control => self.parseControl(state),
            .qpack_encoder => self.parseQpackEncoder(state),
            .qpack_decoder => self.parseQpackDecoder(state),
            .ignored => {},
            .request => {
                if (state.blocked) |blocked| {
                    if (self.decoder.insertCount() < blocked.required_insert_count) return;
                    // The inserts arrived while other stream bytes kept coming.
                    // Retry the parked frame; its bytes are still at
                    // parse_offset, so request-stream order is unchanged.
                    state.blocked = null;
                }
                try self.parseRequest(state);
            },
            .unknown => {},
        }

        // Control and QPACK streams are critical: the peer must keep them open
        // for the lifetime of the connection. A stream-content violation above
        // may already have closed the connection, in which case that first
        // error wins.
        if (state.fin and !self.conn.isClosed()) {
            switch (state.kind) {
                .control => self.closeForControlViolation(.closed_critical_stream),
                .qpack_encoder, .qpack_decoder => self.conn.close(
                    h3_closed_critical_stream,
                    "QPACK stream closed",
                ),
                else => {},
            }
        }
    }

    /// Claim one of the peer's QPACK unidirectional streams. Re-claiming the
    /// same stream is idempotent; a second stream of either type is
    /// H3_STREAM_CREATION_ERROR (RFC 9114 section 6.2).
    fn claimQpackStream(self: *Session, stream_id: u64, kind: StreamKind) ?ControlState.Violation {
        const slot: *?u64 = switch (kind) {
            .qpack_encoder => &self.peer_qpack_encoder_stream,
            .qpack_decoder => &self.peer_qpack_decoder_stream,
            else => unreachable,
        };
        if (slot.*) |existing| {
            if (existing == stream_id) return null;
            return .duplicate_qpack_stream;
        }
        slot.* = stream_id;
        return null;
    }

    fn closeForControlViolation(self: *Session, violation: ControlState.Violation) void {
        self.conn.close(violation.closeCode(), violation.reason());
    }

    fn parseControl(self: *Session, state: *StreamState) void {
        const data = state.reassembler.buf.items[0..state.reassembler.contiguous];
        var cursor = state.parse_offset;
        while (cursor < data.len) {
            const frame_start = cursor;
            const frame = readFrame(data, &cursor) orelse {
                // The header or payload is incomplete. Rewind to the frame
                // start so the next call replays it once more bytes arrive.
                cursor = frame_start;
                break;
            };
            if (self.peer_control.onFrame(frame.frame_type)) |violation| {
                self.closeForControlViolation(violation);
                state.parse_offset = cursor;
                return;
            }
            if (frame.frame_type == frame_settings) {
                var settings: Settings = .{};
                if (parseSettings(frame.payload, &settings)) |settings_error| {
                    self.closeForControlViolation(settings_error.violation());
                    state.parse_offset = cursor;
                    return;
                }
                self.applyPeerSettings(settings);
            }
            if (frame.frame_type == frame_goaway) {
                var payload_cursor: usize = 0;
                if (readVarint(frame.payload, &payload_cursor)) |id| self.goaway_id = id;
            }
        }
        state.parse_offset = cursor;
    }

    fn applyPeerSettings(self: *Session, settings: Settings) void {
        self.peer_qpack_max_table_capacity = settings.qpack_max_table_capacity;
        self.peer_qpack_blocked_streams = settings.qpack_blocked_streams;
        self.peer_max_field_section_size = settings.max_field_section_size orelse 0;
        self.peer_settings_received = true;
        // Size the encoder table from the peer's SETTINGS and stage exactly
        // one Set Dynamic Table Capacity instruction. A failed staging
        // attempt leaves the encoder at capacity zero, which keeps encoding
        // correct (static-only) rather than desynchronized.
        self.encoder.configure(
            settings.qpack_max_table_capacity,
            settings.qpack_blocked_streams,
        ) catch return;
        self.flushEncoderInstructions() catch {};
    }

    /// Queue staged encoder-stream instructions on the local QPACK encoder
    /// stream (type 0x02). Instructions are staged whole, so a failed queue
    /// can be retried from service() without splitting one.
    fn flushEncoderInstructions(self: *Session) !void {
        if (!self.started or self.conn.isClosed()) return;
        const pending = self.encoder.pendingInstructions();
        if (pending.len == 0) return;
        if (self.conn.pendingStreamBytes(self.qpack_encoder_stream) >= 64 * 1024) return;
        try self.conn.queueStreamData(self.qpack_encoder_stream, pending, false);
        self.encoder.clearPendingInstructions();
    }

    /// Parse and apply the peer's QPACK encoder-stream instructions. The local
    /// SETTINGS advertise a 4096-byte table, so Set Dynamic Table Capacity up
    /// to 4096, insert, and duplicate are all applied in order. A capacity
    /// above 4096, an entry larger than the current capacity, an invalid
    /// index, or a malformed instruction is QPACK_ENCODER_STREAM_ERROR. A
    /// partial instruction at the end of the received prefix is left
    /// unconsumed so it can be replayed when more bytes arrive.
    fn parseQpackEncoder(self: *Session, state: *StreamState) void {
        if (self.conn.isClosed()) return;
        const insert_count_before = self.decoder.insertCount();
        const data = state.reassembler.buf.items[0..state.reassembler.contiguous];
        var cursor = state.parse_offset;
        while (cursor < data.len) {
            const result = qpack.applyEncoderInstruction(&self.decoder, data, cursor) catch {
                state.parse_offset = cursor;
                self.conn.close(qpack_encoder_stream_error, "invalid QPACK encoder instruction");
                return;
            };
            switch (result) {
                .incomplete => break,
                .invalid => {
                    state.parse_offset = cursor;
                    self.conn.close(qpack_encoder_stream_error, "invalid QPACK encoder instruction");
                    return;
                },
                .applied => |done| cursor = done.end,
            }
        }
        state.parse_offset = cursor;
        // Every applied insert (including duplicates) advances Insert Count;
        // tell the peer once per batch so it can free its dynamic table. Then
        // give any blocked request stream its turn.
        self.queueInsertCountIncrement();
        if (self.decoder.insertCount() > insert_count_before) self.retryBlockedStreams();
    }

    /// Parse the peer's QPACK decoder stream. Section Acknowledgment releases
    /// the dynamic references held by that stream, Insert Count Increment
    /// advances known_received_count, and Stream Cancellation drops the
    /// stream's references. A malformed instruction, an increment of zero or
    /// beyond the outstanding insert count, or an acknowledgment for a stream
    /// with nothing outstanding is QPACK_DECODER_STREAM_ERROR (0x0203).
    fn parseQpackDecoder(self: *Session, state: *StreamState) void {
        if (self.conn.isClosed()) return;
        const data = state.reassembler.buf.items[0..state.reassembler.contiguous];
        var cursor = state.parse_offset;
        while (cursor < data.len) {
            switch (qpack.scanDecoderInstruction(data, cursor)) {
                .incomplete => break,
                .invalid => {
                    state.parse_offset = cursor;
                    self.conn.close(qpack_decoder_stream_error, "invalid QPACK decoder instruction");
                    return;
                },
                .complete => |done| {
                    if (!self.applyDecoderInstruction(done.instruction, done.value)) {
                        state.parse_offset = cursor;
                        self.conn.close(qpack_decoder_stream_error, "invalid QPACK decoder instruction");
                        return;
                    }
                    cursor = done.end;
                },
            }
        }
        state.parse_offset = cursor;
    }

    /// Apply one complete peer decoder-stream instruction. False means a
    /// protocol violation that maps to 0x0203.
    fn applyDecoderInstruction(
        self: *Session,
        instruction: qpack.DecoderInstruction,
        value: u64,
    ) bool {
        switch (instruction) {
            .section_acknowledgment => self.encoder.onSectionAcknowledgment(value) catch return false,
            .stream_cancellation => self.encoder.onStreamCancellation(value),
            .insert_count_increment => self.encoder.onInsertCountIncrement(value) catch return false,
        }
        return true;
    }

    fn handleStreamError(self: *Session, state: *StreamState, err: anyerror) void {
        if (err == error.DynamicTableReference) {
            // The field section references entries the decoder does not have,
            // or a blocked stream outlived QPACK_BLOCKED_STREAMS / its
            // timeout. RFC 9204 section 3.2.5 maps these to 0x0201.
            state.handled = true;
            self.conn.close(qpack_decompression_failed, "QPACK decompression failed");
            return;
        }
        if (self.role == .server and state.kind == .request and !state.handled) {
            state.handled = true;
            const status: StatusCode = if (err == error.BodyTooLarge)
                .request_entity_too_large
            else
                .bad_request;
            self.sendError(state.id, status, "bad request\n") catch {};
        }
    }

    /// Queue one fixed-size decoder-stream instruction. The instruction is
    /// written straight into the transport's per-stream send buffer; no
    /// session-owned staging buffer grows with the number of acknowledgments.
    fn queueDecoderInstruction(
        self: *Session,
        instruction: qpack.DecoderInstructionValue,
    ) !void {
        var buf: [qpack.max_decoder_instruction_len]u8 = undefined;
        const len = try qpack.writeDecoderInstruction(&buf, instruction);
        try self.conn.queueStreamData(self.qpack_decoder_stream, buf[0..len], false);
    }

    fn decoderBacklogged(self: *const Session) bool {
        return self.conn.pendingStreamBytes(self.qpack_decoder_stream) >= 64 * 1024;
    }

    /// Acknowledge every insert applied so far that the peer has not yet been
    /// told about. Increment is always positive and never exceeds the number of
    /// inserts the decoder has actually applied.
    fn queueInsertCountIncrement(self: *Session) void {
        if (!self.started) return;
        if (self.decoderBacklogged()) return;
        const insert_count = self.decoder.insertCount();
        if (insert_count <= self.decoder_acked_insert_count) return;
        const increment = insert_count - self.decoder_acked_insert_count;
        self.queueDecoderInstruction(.{ .insert_count_increment = increment }) catch return;
        self.decoder_acked_insert_count = insert_count;
    }

    /// A dynamic field section has been decoded; Section Acknowledgment is due
    /// as soon as the decoder stream has room.
    fn markSectionDecoded(
        self: *Session,
        state: *StreamState,
        required_insert_count: u64,
    ) void {
        if (required_insert_count == 0) return;
        state.section_ack_pending += 1;
        self.flushSectionAck(state);
    }

    fn flushSectionAck(self: *Session, state: *StreamState) void {
        if (state.section_ack_pending == 0) return;
        if (!self.started or self.conn.isClosed() or self.decoderBacklogged()) return;
        // Order the insert acknowledgment before the section ack: the encoder
        // may need the released table space before it can make progress.
        self.queueInsertCountIncrement();
        while (state.section_ack_pending > 0) {
            if (self.decoderBacklogged()) return;
            self.queueDecoderInstruction(.{ .section_acknowledgment = state.id }) catch return;
            state.section_ack_pending -= 1;
        }
    }

    /// The stream was reset or retired without a Section Acknowledgment. Tell
    /// the peer's encoder it can drop the field section. A blocked section was
    /// never decoded, so it is cancelled as well.
    fn cancelSection(self: *Session, state: *StreamState) void {
        if (state.blocked == null and state.section_ack_pending == 0) return;
        state.blocked = null;
        state.section_ack_pending = 0;
        if (!self.started) return;
        self.queueDecoderInstruction(.{ .stream_cancellation = state.id }) catch {};
    }

    fn blockedCount(self: *const Session) usize {
        var count: usize = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.blocked != null) count += 1;
        }
        return count;
    }

    fn blockSection(
        self: *Session,
        state: *StreamState,
        required_insert_count: u64,
        frame_offset: usize,
        block_offset: usize,
    ) !void {
        if (state.blocked == null and self.blockedCount() >= max_blocked_streams) {
            // More blocked streams than advertised in SETTINGS is
            // QPACK_DECOMPRESSION_FAILED (RFC 9204 section 3.2.5).
            return error.DynamicTableReference;
        }
        state.blocked = .{
            .required_insert_count = required_insert_count,
            .frame_offset = frame_offset,
            .block_offset = block_offset,
            .since_ns = transport.nowNanos(),
        };
    }

    /// Retry every parked HEADERS frame whose Required Insert Count is now
    /// covered. The frame bytes are still at `parse_offset`, so request-stream
    /// ordering is unchanged.
    fn retryBlockedStreams(self: *Session) void {
        if (self.conn.isClosed()) return;
        const insert_count = self.decoder.insertCount();
        var ready: [max_blocked_streams]u64 = undefined;
        var count: usize = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            if (state.kind != .request) continue;
            const blocked = state.blocked orelse continue;
            if (blocked.required_insert_count > insert_count) continue;
            ready[count] = entry.key_ptr.*;
            count += 1;
            if (count == ready.len) break;
        }
        for (ready[0..count]) |stream_id| {
            const state = self.streams.get(stream_id) orelse continue;
            state.blocked = null;
            self.processStream(state) catch |err| self.handleStreamError(state, err);
            if (self.conn.isClosed()) return;
        }
    }

    fn expireBlockedStreams(self: *Session) void {
        if (self.conn.isClosed()) return;
        const now = transport.nowNanos();
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            const blocked = state.blocked orelse continue;
            if (now < blocked.since_ns) continue;
            if (now - blocked.since_ns < qpack_blocked_stream_timeout_ns) continue;
            state.blocked = null;
            self.conn.close(qpack_decompression_failed, "QPACK blocked stream timeout");
            return;
        }
    }

    /// Encoder-side counterpart to expireBlockedStreams. A field section whose
    /// referenced inserts the peer has not acknowledged for two seconds cannot
    /// make progress; release its references and fail the connection with
    /// 0x0203. Without this timer those table entries stay pinned until session
    /// teardown. The encoder removes each expired section before releasing its
    /// refs, so a later deinit or cancellation cannot double-release.
    fn expireEncoderSections(self: *Session) void {
        if (self.conn.isClosed()) return;
        if (self.encoder.expireBlockedSections(transport.nowNanos()) == 0) return;
        self.conn.close(qpack_decoder_stream_error, "QPACK encoder section timeout");
    }

    fn flushPendingSectionAcks(self: *Session) void {
        if (!self.started or self.conn.isClosed()) return;
        var it = self.streams.iterator();
        while (it.next()) |entry| self.flushSectionAck(entry.value_ptr.*);
    }

    fn parseRequest(self: *Session, state: *StreamState) !void {
        if (state.id > self.max_request_stream_id) self.max_request_stream_id = state.id;
        const data = state.reassembler.buf.items[0..state.reassembler.contiguous];
        var cursor = state.parse_offset;
        while (cursor < data.len) {
            const frame_start = cursor;
            const frame_type = readVarint(data, &cursor) orelse {
                cursor = frame_start;
                break;
            };
            const length = readVarint(data, &cursor) orelse {
                cursor = frame_start;
                break;
            };
            const end = std.math.add(usize, cursor, @intCast(length)) catch {
                cursor = frame_start;
                break;
            };
            if (end > data.len) {
                cursor = frame_start;
                break;
            }
            const block_offset = cursor;
            const payload = data[cursor..end];
            switch (frame_type) {
                frame_headers => {
                    const outcome = try self.handleHeaders(state, frame_start, block_offset, payload);
                    // A blocked HEADERS frame stays at parse_offset; every
                    // later frame on the stream stays behind it.
                    if (outcome == .blocked) return;
                },
                frame_data => try self.handleData(state, payload),
                else => {},
            }
            cursor = end;
        }
        state.parse_offset = cursor;

        if (state.fin and state.reassembler.complete() and !state.handled) {
            state.handled = true;
            if (self.role == .server) {
                try self.completeServerRequest(state);
            } else {
                try self.completeClientResponse(state);
            }
        }
    }

    fn handleHeaders(
        self: *Session,
        state: *StreamState,
        frame_offset: usize,
        block_offset: usize,
        block: []const u8,
    ) !HeaderOutcome {
        var headers = self.decoder.decodeBlock(block) catch |err| switch (err) {
            error.Blocked => {
                // The prefix is valid but needs inserts that have not arrived.
                // Park the frame without consuming it. A prefix that cannot
                // ever be satisfied is still 0x0201.
                const required = qpack.peekRequiredInsertCount(
                    block,
                    self.decoder.insertCount(),
                    self.decoder.max_capacity,
                ) catch return error.DynamicTableReference;
                if (required <= self.decoder.insertCount()) return error.DynamicTableReference;
                try self.blockSection(state, required, frame_offset, block_offset);
                return .blocked;
            },
            error.InvalidDynamicReference => return error.DynamicTableReference,
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidHeaderBlock,
        };
        // A Section Acknowledgment is due for every decoded field section with
        // a nonzero Required Insert Count, even if HTTP/3 validation later
        // rejects the request (the section was decoded).
        self.markSectionDecoded(state, headers.required_insert_count);
        if (self.role == .client) {
            defer headers.deinit();
            const status_text = headers.get(":status") orelse return error.InvalidHeaderBlock;
            const response = state.response orelse blk: {
                const r = try self.allocator.create(ClientResponse);
                r.* = .{};
                state.response = r;
                break :blk r;
            };
            response.status = std.fmt.parseInt(u16, status_text, 10) catch 0;
            try response.header_text.appendSlice(self.allocator, ":status: ");
            try response.header_text.appendSlice(self.allocator, status_text);
            try response.header_text.appendSlice(self.allocator, "\r\n");
            for (headers.fields) |field| {
                if (field.name.len > 0 and field.name[0] == ':') continue;
                try response.header_text.appendSlice(self.allocator, field.name);
                try response.header_text.appendSlice(self.allocator, ": ");
                try response.header_text.appendSlice(self.allocator, field.value);
                try response.header_text.appendSlice(self.allocator, "\r\n");
            }
            return .decoded;
        }

        if (state.headers != null) {
            // Trailers after the request header block. They are not surfaced to
            // the handler, and must not replace the request fields.
            headers.deinit();
            return .decoded;
        }
        // qpack.decode already rejects duplicate pseudo-headers, pseudo-fields
        // after regular fields, and unknown pseudo-headers (RFC 9114 section
        // 4.3), so there is no duplicate tracking to do here.
        const method_text = headers.get(":method") orelse {
            headers.deinit();
            return error.InvalidHeaderBlock;
        };
        if (method_text.len == 0) {
            headers.deinit();
            return error.InvalidHeaderBlock;
        }
        const method = Method.fromString(method_text);
        const authority = headers.get(":authority");
        const scheme = headers.get(":scheme");
        const path = headers.get(":path");

        if (method == .CONNECT) {
            // Plain CONNECT uses the authority-form target (RFC 9114 section
            // 4.4): :authority is mandatory and :path/:scheme are forbidden.
            // Extended CONNECT needs :protocol, which qpack.decode rejects as
            // an unknown pseudo-header, so it becomes a 400 and is never
            // mistaken for a plain CONNECT.
            if (authority == null or authority.?.len == 0) {
                headers.deinit();
                return error.InvalidHeaderBlock;
            }
            if (path != null or scheme != null) {
                headers.deinit();
                return error.InvalidHeaderBlock;
            }
        } else {
            // Non-CONNECT requests require :scheme and a non-empty, valid
            // :path (RFC 9114 section 4.3.1).
            if (scheme == null or scheme.?.len == 0) {
                headers.deinit();
                return error.InvalidHeaderBlock;
            }
            const request_path = path orelse {
                headers.deinit();
                return error.InvalidHeaderBlock;
            };
            if (!validRequestPath(method, request_path)) {
                headers.deinit();
                return error.InvalidHeaderBlock;
            }
        }

        if (state.headers) |*old| old.deinit();
        state.headers = headers;
        state.method = method;
        state.method_unknown = method == null;
        state.path = path orelse "";
        state.authority = authority orelse "";
        state.scheme = scheme orelse "";
        state.request_headers = .{};
        for (headers.fields) |field| {
            if (field.name.len > 0 and field.name[0] == ':') continue;
            state.request_headers.append(field.name, field.value) catch {};
        }
        return .decoded;
    }

    fn handleData(self: *Session, state: *StreamState, data: []const u8) !void {
        if (self.role == .client) {
            const response = state.response orelse return;
            try response.body.appendSlice(self.allocator, data);
            return;
        }
        if (state.body.items.len + data.len > self.max_body_bytes) return error.BodyTooLarge;
        try state.body.appendSlice(self.allocator, data);
    }

    fn completeClientResponse(self: *Session, state: *StreamState) !void {
        _ = self;
        _ = state;
    }

    fn completeServerRequest(self: *Session, state: *StreamState) !void {
        if (self.context_handler == null and self.handler == null) return;
        if (state.method_unknown) {
            try self.sendError(state.id, .not_implemented, "unknown method\n");
            return;
        }
        const method = state.method orelse {
            try self.sendError(state.id, .bad_request, "invalid request\n");
            return;
        };

        var request = Request{
            .method = method,
            .path = state.path,
            .authority = state.authority,
            .scheme = state.scheme,
            .headers = state.request_headers,
            .body = state.body.items,
        };
        const response = if (self.context_handler) |handler|
            handler(self.handler_context, self.allocator, &request)
        else
            self.handler.?(self.allocator, &request);
        try self.sendResponse(state.id, method, response);
    }

    fn sendResponse(self: *Session, stream_id: u64, method: Method, response: Response) !void {
        var fields: std.ArrayListUnmanaged(HeaderField) = .empty;
        defer fields.deinit(self.allocator);

        var status_buf: [8]u8 = undefined;
        const status_code = @backingInt(response.status);
        const status_text = try std.fmt.bufPrint(&status_buf, "{d}", .{status_code});
        var len_buf: [24]u8 = undefined;
        const len_text = try std.fmt.bufPrint(&len_buf, "{d}", .{response.body.len});
        const no_body = status_code < 200 or status_code == 204 or status_code == 304;

        try fields.append(self.allocator, .{ .name = ":status", .value = status_text });
        if (!no_body and response.body_reader == null) {
            try fields.append(self.allocator, .{ .name = "content-length", .value = len_text });
        }
        if (response.content_type.len > 0) {
            try fields.append(self.allocator, .{ .name = "content-type", .value = response.content_type });
        }
        for (response.headers) |header| {
            if (std.mem.eql(u8, header.name, "content-length")) continue;
            if (!validHeaderName(header.name)) continue;
            try fields.append(self.allocator, header);
        }

        const block = try self.encoder.encodeSection(self.allocator, stream_id, fields.items);
        defer self.allocator.free(block);
        try self.flushEncoderInstructions();
        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.allocator);
        try writeFrame(&frame, self.allocator, frame_headers, block);
        try self.conn.queueStreamData(stream_id, frame.items, false);

        if (no_body or method == .HEAD) {
            try self.conn.queueStreamData(stream_id, &.{}, true);
            self.queueRetire(stream_id);
            return;
        }

        if (response.body_reader) |reader| {
            if (self.streams.get(stream_id)) |state| {
                state.reader = reader;
                state.reader_context = response.body_context;
                state.reader_deinit = response.body_reader_deinit;
            }
            return;
        }

        if (method != .HEAD and response.body.len > 0) {
            var data_frame: std.ArrayListUnmanaged(u8) = .empty;
            defer data_frame.deinit(self.allocator);
            try writeFrame(&data_frame, self.allocator, frame_data, response.body);
            try self.conn.queueStreamData(stream_id, data_frame.items, false);
        }
        try self.conn.queueStreamData(stream_id, &.{}, true);
        self.queueRetire(stream_id);
    }

    fn sendError(self: *Session, stream_id: u64, status: StatusCode, body: []const u8) !void {
        try self.sendResponse(stream_id, .GET, .{ .status = status, .body = body });
    }

    pub fn service(self: *Session) !void {
        self.reapRetired();
        if (!self.started and self.conn.isEstablished()) try self.begin();
        try self.flushEncoderInstructions();
        self.expireBlockedStreams();
        self.expireEncoderSections();
        if (self.conn.isClosed()) return;
        self.queueInsertCountIncrement();
        self.flushPendingSectionAcks();
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const state = entry.value_ptr.*;
            const reader = state.reader orelse continue;
            if (state.reader_done) continue;
            // Keep one stream's queued-but-unsent bytes bounded; the transport
            // only writes 64 KiB per service pass.
            if (self.conn.pendingStreamBytes(state.id) > 64 * 1024) continue;

            var buf: [16 * 1024]u8 = undefined;
            const n = reader(state.reader_context, &buf) catch {
                state.reader_done = true;
                state.releaseReader();
                self.conn.close(0x0102, "body reader failed");
                continue;
            };
            if (n == 0) {
                try self.conn.queueStreamData(state.id, &.{}, true);
                state.reader_done = true;
                state.releaseReader();
                self.queueRetire(state.id);
            } else {
                var data_frame: std.ArrayListUnmanaged(u8) = .empty;
                defer data_frame.deinit(self.allocator);
                try writeFrame(&data_frame, self.allocator, frame_data, buf[0..n]);
                try self.conn.queueStreamData(state.id, data_frame.items, false);
            }
        }
    }

    pub const Answer = struct {
        status: u16,
        header_text: []const u8,
        body: []const u8,
    };

    /// Send HTTP/3 GOAWAY on the server's control stream. Existing requests
    /// keep running; new requests with larger stream IDs are refused by a
    /// conforming client.
    pub fn goAway(self: *Session) !void {
        if (self.role != .server) return error.NotEstablished;
        if (!self.started) {
            if (!self.conn.isEstablished()) return error.NotEstablished;
            try self.begin();
        }
        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.allocator);
        try writeVarint(&payload, self.allocator, self.max_request_stream_id);
        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.allocator);
        try writeFrame(&frame, self.allocator, frame_goaway, payload.items);
        try self.conn.queueStreamData(self.control_stream, frame.items, false);
    }

    /// Start a client request. Returns the request stream id.
    pub fn beginRequest(
        self: *Session,
        method: []const u8,
        path: []const u8,
        authority: []const u8,
        headers: []const HeaderField,
        body: []const u8,
    ) !u64 {
        if (self.goaway_id != null) return error.ConnectionClosed;
        if (!self.started) {
            if (!self.conn.isEstablished()) return error.NotEstablished;
            try self.begin();
        }
        const stream_id = try self.conn.createBidiStream();
        const state = try self.getOrCreate(stream_id);
        state.kind = .request;

        var fields: std.ArrayListUnmanaged(HeaderField) = .empty;
        defer fields.deinit(self.allocator);
        try fields.append(self.allocator, .{ .name = ":method", .value = method });
        try fields.append(self.allocator, .{ .name = ":scheme", .value = "https" });
        try fields.append(self.allocator, .{ .name = ":authority", .value = authority });
        try fields.append(self.allocator, .{ .name = ":path", .value = path });
        for (headers) |header| try fields.append(self.allocator, header);

        const block = try self.encoder.encodeSection(self.allocator, stream_id, fields.items);
        defer self.allocator.free(block);
        try self.flushEncoderInstructions();

        var frame: std.ArrayListUnmanaged(u8) = .empty;
        defer frame.deinit(self.allocator);
        try writeFrame(&frame, self.allocator, frame_headers, block);
        try self.conn.queueStreamData(stream_id, frame.items, false);

        if (body.len > 0) {
            var data_frame: std.ArrayListUnmanaged(u8) = .empty;
            defer data_frame.deinit(self.allocator);
            try writeFrame(&data_frame, self.allocator, frame_data, body);
            try self.conn.queueStreamData(stream_id, data_frame.items, false);
        }
        try self.conn.queueStreamData(stream_id, &.{}, true);
        return stream_id;
    }

    /// Take a completed client answer, or null while the response is still open.
    pub fn takeAnswer(self: *Session, stream_id: u64) !?Answer {
        const state = self.streams.get(stream_id) orelse return null;
        if (!state.fin or !state.reassembler.complete() or state.answer_taken) return null;
        const response = state.response orelse return null;
        state.answer_taken = true;
        const header_text = try self.allocator.dupe(u8, response.header_text.items);
        errdefer self.allocator.free(header_text);
        const body = try self.allocator.dupe(u8, response.body.items);
        const answer = Answer{
            .status = response.status,
            .header_text = header_text,
            .body = body,
        };
        self.retireStream(stream_id);
        return answer;
    }
};

/// One complete HTTP/3 frame over a contiguous prefix of a stream.
pub const Frame = struct {
    frame_type: u64,
    payload: []const u8,
};

/// Read one complete HTTP/3 frame starting at `cursor`. Returns null and
/// leaves `cursor` unchanged while the frame header or payload still needs
/// QUIC bytes; a partial frame is never a protocol violation.
pub fn readFrame(data: []const u8, cursor: *usize) ?Frame {
    const start = cursor.*;
    const frame_type = readVarint(data, cursor) orelse {
        cursor.* = start;
        return null;
    };
    const length = readVarint(data, cursor) orelse {
        cursor.* = start;
        return null;
    };
    const payload_start = cursor.*;
    const payload_len = std.math.cast(usize, length) orelse {
        cursor.* = start;
        return null;
    };
    if (payload_len > data.len - payload_start) {
        cursor.* = start;
        return null;
    }
    cursor.* = payload_start + payload_len;
    return .{ .frame_type = frame_type, .payload = data[payload_start..cursor.*] };
}

fn writeFrame(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    frame_type: u64,
    payload: []const u8,
) !void {
    try writeVarint(out, allocator, frame_type);
    try writeVarint(out, allocator, payload.len);
    try out.appendSlice(allocator, payload);
}

fn writeVarint(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    value_in: u64,
) !void {
    const value = value_in;
    if (value < 0x40) {
        try out.append(allocator, @intCast(value));
        return;
    }
    const len: usize = if (value < 0x4000) 2 else if (value < 0x40000000) 4 else 8;
    try out.ensureUnusedCapacity(allocator, len);
    // QUIC varint length prefix: 00=1, 01=2, 10=4, 11=8 bytes.
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

fn readVarint(data: []const u8, cursor: *usize) ?u64 {
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

/// RFC 9114 section 4.3.1: :path is mandatory and MUST NOT be empty for
/// non-CONNECT requests. It is an origin-form target beginning with "/", with
/// "*" allowed only for OPTIONS. Control characters and spaces cannot appear
/// in a request target.
fn validRequestPath(method: ?Method, path: []const u8) bool {
    if (path.len == 0) return false;
    if (std.mem.eql(u8, path, "*")) return method == .OPTIONS;
    if (path[0] != '/') return false;
    for (path) |ch| {
        if (ch <= 0x20 or ch == 0x7f) return false;
    }
    return true;
}

fn validHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |ch| {
        if (std.ascii.isUpper(ch) or ch == 0 or ch == '\r' or ch == '\n') return false;
    }
    return true;
}
