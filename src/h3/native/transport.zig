//! QUIC transport for the native HTTP/3 stack.
//!
//! zquic supplies packet protection, packet-number spaces, loss-recovery
//! timers, stream IDs, and frame encoding. This file keeps its own ACK ranges
//! because it decrypts packets before handing the surviving frames to zquic. OpenSSL supplies the
//! TLS 1.3 handshake through its QUIC-TLS callback interface. This file is the
//! seam between them: it splits coalesced datagrams, feeds CRYPTO frames to TLS,
//! installs the RFC 9001 keys TLS yields, and dispatches STREAM frames to the
//! HTTP/3 layer.

const std = @import("std");
const posix = std.posix;
const zquic = @import("zquic");
const qtls = @import("qtls.zig");
const ack = @import("ack.zig");
const retry = @import("retry.zig");
const stats = @import("stats.zig");
const qlog = @import("qlog.zig");
const flow_control = @import("flow_control.zig");

/// Re-exported so callers can name a snapshot without importing stats.zig.
pub const Stats = stats.Stats;

const FlowControl = flow_control.FlowControl;

const Packet = zquic.Packet;
const PacketCrypto = zquic.PacketCrypto;
const QuicFrames = zquic.core.QuicFrames;
const TransportParametersMod = zquic.core.TransportParameters;
const TransportParameters = TransportParametersMod.TransportParameters;
const NegotiationContext = TransportParametersMod.NegotiationContext;
const Tls13KeySchedule = zquic.Tls13KeySchedule;
const EnhancedTlsContext = zquic.EnhancedCrypto.EnhancedTlsContext;

pub const Error = error{
    QuicError,
    TlsError,
    OutOfMemory,
    Timeout,
    ConnectionClosed,
    InvalidPacket,
    HandshakeFailed,
    NotEstablished,
    StreamClosed,
};

pub const cid_len = 8;
pub const max_datagram_size = 65535;
/// Re-exported for h3.Server.Options and the transport tests; the module that
/// owns flow-control state defines the value.
pub const default_flow_window: u64 = flow_control.default_flow_window;
const max_handshake_bytes = 1024 * 1024;
const handshake_timeout_ns = 15 * std.time.ns_per_s;

pub const Role = enum { client, server };

/// zquic has its own role enum on the connection type; mirror it here without
/// exporting a private module path.
const ConnRole = @TypeOf(@as(zquic.Connection.Connection, undefined).super_connection.role);

pub const ClientTls = qtls.ClientTls;

/// Callbacks the HTTP/3 session installs on a connection.
pub const ConnectionHook = struct {
    context: *anyopaque,
    callback: *const fn (context: *anyopaque, connection: *Connection) void,
};

pub const Handler = struct {
    context: *anyopaque,
    on_stream_frame: *const fn (
        context: *anyopaque,
        stream_id: u64,
        offset: u64,
        data: []const u8,
        fin: bool,
    ) anyerror!void,
    on_established: *const fn (context: *anyopaque) anyerror!void,
    on_closed: *const fn (context: *anyopaque, code: u64) void,
};

pub fn nowMicros() u64 {
    var ts: posix.timespec = undefined;
    _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1000;
}

pub fn nowNanos() u64 {
    var ts: posix.timespec = undefined;
    _ = std.c.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn sleepNs(ns: u64) void {
    var req = posix.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    while (posix.errno(posix.system.nanosleep(&req, &req)) == .INTR) {}
}

/// Byte reassembly for one QUIC stream. Re-exported so http3.zig and tests keep
/// using transport.Reassembler.
pub const Reassembler = @import("reassembly.zig").Reassembler;

const AckState = ack.AckState;

const StreamSend = struct {
    buf: std.ArrayListUnmanaged(u8) = .empty,
    sent: u64 = 0,
    fin: bool = false,
    fin_sent: bool = false,

    fn deinit(self: *StreamSend, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
    }

    fn pending(self: *const StreamSend) []const u8 {
        if (self.sent >= self.buf.items.len) return &.{};
        return self.buf.items[@intCast(self.sent)..];
    }
};

/// One STREAM frame selected for a 1-RTT data batch. A claim only becomes
/// visible in StreamSend.sent / FlowControl.sent_data after the packet carrying
/// it has been scheduled successfully.
const StreamClaim = struct {
    stream_id: u64,
    offset: u64,
    len: usize,
    fin: bool,
};

/// A stream with work available when a batch was built. `pending` is a slice of
/// StreamSend.buf taken while no send state is being mutated, `planned` counts
/// bytes already claimed by this batch, and `credit` is the peer's stream
/// limit minus the stream's current sent offset.
const BatchStream = struct {
    stream_id: u64,
    pending: []const u8,
    base: u64,
    credit: u64,
    fin_pending: bool,
    planned: usize = 0,
    fin_planned: bool = false,
    claimed: bool = false,
};

/// Result of assembling one candidate batch.
const BatchBuild = struct {
    budget: usize = 0,
    used: usize = 0,
    stream_count: usize = 0,
};

/// 1-RTT control frames gathered for the current service pass, in the order
/// they are placed ahead of STREAM data. The transport's ACK ranges, flow
/// limits, and stream-limit counters are advanced by commitControlFrames()
/// only after a protected packet carrying the frames was scheduled, so a
/// failed schedule leaves the whole control set pending for the next pass.
const ControlBatch = struct {
    frames: std.ArrayListUnmanaged(QuicFrames.Frame) = .empty,
    /// Owns the ACK ranges referenced by the .ack entry in frames.
    ack: ?QuicFrames.AckFrame = null,
    /// Set once every frame in frames has been handed to a successful
    /// schedule call; a later packet must not repeat them in this pass.
    sent: bool = false,

    fn deinit(self: *ControlBatch, allocator: std.mem.Allocator) void {
        if (self.ack) |ack_frame| ack_frame.deinit(allocator);
        self.frames.deinit(allocator);
    }
};

/// One packet scheduled for emission. qlog pairs these FIFO with the raw
/// packets drained by flush(), after sendto succeeds.
const PendingSend = struct {
    packet_number: u64,
    level: u8,
    ptype: qlog.PacketType,
    ack_eliciting: bool,
    plaintext_len: u32,
    frames: qlog.FrameSummary,
};

/// Bounded FIFO of scheduled sends for qlog. Only allocated when qlog is
/// enabled; on overflow the whole batch is dropped rather than mislabelled.
const max_pending_sends = 256;
const PendingSends = struct {
    items: [max_pending_sends]PendingSend = undefined,
    head: usize = 0,
    count: usize = 0,
    overflow: bool = false,

    fn push(self: *PendingSends, item: PendingSend) void {
        if (self.count == self.items.len) {
            self.head = 0;
            self.count = 0;
            self.overflow = true;
            return;
        }
        self.items[(self.head + self.count) % self.items.len] = item;
        self.count += 1;
    }

    fn pop(self: *PendingSends) ?PendingSend {
        if (self.count == 0) return null;
        const item = self.items[self.head];
        self.head = (self.head + 1) % self.items.len;
        self.count -= 1;
        return item;
    }

    fn reset(self: *PendingSends) void {
        self.head = 0;
        self.count = 0;
        self.overflow = false;
    }
};

fn qlogPacketType(ptype: Packet.PacketType) qlog.PacketType {
    return switch (ptype) {
        .initial => .initial,
        .handshake => .handshake,
        .zero_rtt => .zero_rtt,
        .one_rtt => .one_rtt,
        .retry => .retry,
        .version_negotiation => .version_negotiation,
    };
}

/// Coarse frame categories; never serializes frame contents.
fn summarizeFrame(summary: *qlog.FrameSummary, frame: QuicFrames.Frame) void {
    switch (frame) {
        .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => summary.stream +|= 1,
        .crypto => summary.crypto +|= 1,
        .ack, .ack_ecn => summary.ack +|= 1,
        .max_data, .max_stream_data, .max_streams_bidi, .max_streams_uni, .data_blocked, .stream_data_blocked, .streams_blocked_bidi, .streams_blocked_uni => summary.flow +|= 1,
        .padding => summary.padding +|= 1,
        .ping, .reset_stream, .stop_sending, .new_token, .new_connection_id, .retire_connection_id, .path_challenge, .path_response, .connection_close, .connection_close_app, .handshake_done => summary.control +|= 1,
        else => summary.other +|= 1,
    }
}

/// Minimal QUIC varint size for `value`, matching zquic's writeVarint.
fn varintSize(value: u64) usize {
    if (value < 0x40) return 1;
    if (value < 0x4000) return 2;
    if (value < 0x40000000) return 4;
    return 8;
}

/// Serialized STREAM frame bytes excluding `data.len`: frame type, stream ID,
/// offset, and payload length.
fn streamFrameOverhead(stream_id: u64, offset: u64, data_len: usize) usize {
    return 1 + varintSize(stream_id) + varintSize(offset) + varintSize(@intCast(data_len));
}

/// Largest take whose frame header and data fit in `budget_left`. The length
/// varint grows at 64/16384, so shrink and re-check until it fits.
fn streamFrameDataThatFits(fixed_overhead: usize, budget_left: usize, max_take: usize) usize {
    if (budget_left <= fixed_overhead) return 0;
    const available = budget_left - fixed_overhead;
    var take = @min(max_take, available);
    while (take > 0) {
        const length_size = varintSize(@intCast(take));
        if (length_size + take <= available) return take;
        if (length_size >= available) return 0;
        const next = available - length_size;
        if (next >= take) return 0;
        take = next;
    }
    return 0;
}

/// Maximum lost payloads resent in one service pass. Anything beyond this stays
/// queued for the next pass, so a loss storm cannot monopolize the event loop.
const max_retransmits_per_service = 64;

/// Maximum lost payloads retained while waiting to be resent. The oldest entry
/// is evicted when the queue grows past this cap.
const max_lost_payloads_retained = 8192;

/// zquic can declare a packet lost just before its ACK is read from the socket
/// (its loss floor is 1 ms). Keep a lost payload briefly before resending so a
/// delayed ACK wins instead of turning every control packet into a retransmit
/// storm. This is pacing, not a second loss detector: the decision stays with
/// zquic's callback. The synthetic drop hook bypasses the grace.
const lost_payload_grace_us = 200_000;

/// Test-visible count of successful frame retransmissions. The test runner is
/// single-threaded; production code does not read this.
pub var test_retransmit_count: u64 = 0;

/// Test-visible capture of the most recent successful lost-payload resend.
/// Copying and frame parsing are disabled in production;
/// recovery_owner_test enables them.
pub const max_captured_retransmit_payload = 2048;
pub var test_capture_retransmit_payload: bool = false;
pub var test_retransmit_last_old_packet_number: u64 = 0;
pub var test_retransmit_last_new_packet_number: u64 = 0;
pub var test_retransmit_last_level: usize = 0;
pub var test_retransmit_last_payload_len: usize = 0;
pub var test_retransmit_last_payload: [max_captured_retransmit_payload]u8 = @splat(0);

/// One lost packet copied out of zquic's callback. zquic frees its retained
/// plaintext as soon as the callback returns, so the transport owns this copy.
const LostPayload = struct {
    level: usize,
    packet_number: u64,
    detected_us: u64,
    payload: []u8,

    fn deinit(self: *const LostPayload, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
};

/// Test-visible flow-control observations.
pub var test_max_data_sent: u64 = 0;
pub var test_max_stream_data_sent: u64 = 0;
pub var test_send_blocked: u64 = 0;

/// Test-visible packet-batching observations. A batch is one protected 1-RTT
/// packet carrying one or more STREAM frames built by flushStreams.
pub var test_batch_packets: u64 = 0;
pub var test_batch_stream_frames: u64 = 0;
/// Batches carrying more than one STREAM frame, whether those frames belong to
/// different streams or split one stream's bytes across chunks.
pub var test_batch_multi_frame_packets: u64 = 0;
/// Batches whose frames include at least two distinct stream IDs.
pub var test_batch_multi_stream_packets: u64 = 0;
/// Largest and most recent serialized plaintext batch size, in bytes. Both stay
/// within the connection's maxStreamFramePayload() budget.
pub var test_batch_largest_payload: usize = 0;
pub var test_batch_budget: usize = 0;

/// Test-visible control/data coalescing observations. A "coalesced" packet is
/// one protected 1-RTT packet whose plaintext contains at least one control
/// frame (ACK, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, HANDSHAKE_DONE) before
/// its STREAM frames. Counters are only for this single-threaded test runner.
pub var test_control_coalesced_packets: u64 = 0;
pub var test_ack_coalesced_packets: u64 = 0;
pub var test_flow_coalesced_packets: u64 = 0;
pub var test_handshake_done_coalesced_packets: u64 = 0;
/// Standalone 1-RTT ACK packets (the fallback when no STREAM data is queued)
/// and the padded plaintext length of the most recent one. Header protection
/// needs a 16-byte sample starting four bytes after the packet number, so
/// schedule() pads every payload to at least 64 bytes.
pub var test_standalone_ack_packets: u64 = 0;
pub var test_standalone_ack_plaintext_len: usize = 0;
/// Plaintext length of the most recent successfully scheduled packet.
pub var test_last_scheduled_plaintext_len: usize = 0;

/// Receive-side observations: which frame mixtures arrived and how many
/// duplicate control frames a single protected packet carried.
pub var test_rx_ack_frames: u64 = 0;
pub var test_rx_max_data_frames: u64 = 0;
pub var test_rx_max_stream_data_frames: u64 = 0;
pub var test_rx_ack_with_stream_packets: u64 = 0;
pub var test_rx_max_with_stream_packets: u64 = 0;
pub var test_rx_duplicate_ack_packets: u64 = 0;

/// Test-visible Retry decisions made by client connections.
pub var test_retry_accepted: u64 = 0;
pub var test_retry_rejected: u64 = 0;

/// Test-visible observation of packets zquic declared lost. The callback runs
/// before zquic frees its retained plaintext. The test runner is single-threaded.
pub var test_zquic_lost_packets: u64 = 0;
pub var test_zquic_lost_payload_packets: u64 = 0;
pub var test_zquic_lost_payload_bytes: u64 = 0;
pub var test_zquic_lost_application_payload_packets: u64 = 0;
pub var test_zquic_lost_last_level: usize = 0;
pub var test_zquic_lost_last_packet_number: u64 = 0;

/// Lost-packet observer installed on client and server SuperConnections.
///
/// zquic is the retransmission owner: this callback copies each lost plaintext
/// into the connection's bounded queue and returns immediately. Service drains
/// the queue through sendProtectedRawPacket after pollLossRecovery, so no send
/// happens inside zquic's packet-space iterator.
fn observeZquicLostPacket(
    context: ?*anyopaque,
    level: usize,
    packet_number: u64,
    payload: []const u8,
) void {
    test_zquic_lost_packets +|= 1;
    test_zquic_lost_last_level = level;
    test_zquic_lost_last_packet_number = packet_number;
    if (payload.len == 0) return;
    test_zquic_lost_payload_packets +|= 1;
    test_zquic_lost_payload_bytes +|= payload.len;
    if (level == 3) test_zquic_lost_application_payload_packets +|= 1;
    const self: *Connection = @ptrCast(@alignCast(context orelse return));
    self.queueLostPayload(level, packet_number, payload);
}

pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: Role,
    socket: posix.fd_t,
    owns_socket: bool,
    remote_addr: posix.sockaddr.in,
    local_addr: posix.sockaddr.in,

    quic: zquic.Connection.Connection,
    tls_ctx: EnhancedTlsContext,
    packet_crypto: PacketCrypto,
    tls: *qtls.Tls,

    local_cid: [20]u8 = @splat(0),
    local_cid_len: u8 = cid_len,
    peer_cid: [20]u8 = @splat(0),
    peer_cid_len: u8 = 0,
    original_dcid: [20]u8 = @splat(0),
    original_dcid_len: u8 = 0,
    retry_scid: [20]u8 = @splat(0),
    retry_scid_len: u8 = 0,
    /// A client accepts at most one Retry per connection attempt (RFC 9000
    /// Section 17.2.5.2); later Retry packets are dropped.
    retry_received: bool = false,
    /// Token from the accepted Retry, copied out of the datagram so it stays
    /// valid for every Initial this connection sends afterwards.
    retry_token: std.ArrayListUnmanaged(u8) = .empty,
    /// Plaintext CRYPTO bytes TLS produced at the Initial level. A Retry must
    /// resend the identical ClientHello without resetting the TLS transcript,
    /// so the bytes are kept instead of relying on TLS to emit them again.
    initial_crypto: std.ArrayListUnmanaged(u8) = .empty,

    largest_pn: [4]?u64 = .{ null, null, null, null },
    acks: [4]AckState = .{ .{}, .{}, .{}, .{} },
    crypto_rx: [4]Reassembler,
    crypto_tx_offset: [4]u64 = .{ 0, 0, 0, 0 },
    secrets: [qtls.level_count]qtls.SecretSet = .{ .{}, .{}, .{}, .{} },
    handshake_keys: bool = false,
    application_keys: bool = false,
    peer_params_applied: bool = false,
    peer_params: ?TransportParameters = null,
    local_params: []u8 = &.{},

    established: bool = false,
    handshake_done_sent: bool = false,
    /// A server queues HANDSHAKE_DONE here and flushStreams() coalesces it
    /// ahead of STREAM data when possible; otherwise finishControlFrames()
    /// sends it standalone in the same service pass.
    handshake_done_pending: bool = false,
    closing: bool = false,
    closed: bool = false,
    close_code: u64 = 0,
    established_notified: bool = false,
    /// Monotonic transport counters for this connection. Single-threaded: only
    /// the owning service/dispatch thread updates them.
    stats: Stats = .{},
    /// Allocated only when a qlog sink was installed for this connection.
    /// Everything qlog-related is checked through this pointer first.
    qlog: ?*qlog.Writer = null,
    qlog_pending: ?*PendingSends = null,

    stream_send: std.AutoHashMapUnmanaged(u64, StreamSend) = .empty,
    /// Stream windows, connection windows, and stream-count bookkeeping.
    flow: FlowControl,
    finished_streams: std.ArrayListUnmanaged(u64) = .empty,
    closed_streams: std.DynamicBitSet = undefined,
    closed_streams_ready: bool = false,
    /// Plaintexts zquic declared lost, copied out of its callback and awaiting
    /// a new packet number in service. Bounded; oldest entries are evicted.
    lost_queue: std.ArrayListUnmanaged(LostPayload) = .empty,
    /// Index of the first unread entry in lost_queue. Compaction reclaims the
    /// consumed prefix without shifting on every callback.
    lost_queue_head: usize = 0,
    /// Test hook: drop every Nth outgoing datagram (0 disables). Production
    /// callers leave this at zero; the retransmission test uses it to simulate
    /// loss without a network shim. zquic recorded the packet when it was
    /// scheduled, so its loss detector recovers the dropped datagram.
    drop_outgoing_every: usize = 0,
    tx_count: usize = 0,
    handler: ?Handler = null,
    last_activity_us: u64,
    handshake_started_us: u64,

    pub fn initClient(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        options: ClientTls,
    ) !*Connection {
        return initWithQlog(allocator, host, port, options, null);
    }

    /// Client connection constructor with an optional qlog sink. The header
    /// and connectivity:connection_started are emitted as soon as both local
    /// and peer CIDs exist, before the first packet is scheduled.
    pub fn initWithQlog(
        allocator: std.mem.Allocator,
        host: []const u8,
        port: u16,
        options: ClientTls,
        qlog_config: ?qlog.Config,
    ) !*Connection {
        const remote = try resolveAddress(host, port);
        const socket = try createSocket();
        errdefer closeSocket(socket);

        const self = try allocator.create(Connection);
        errdefer allocator.destroy(self);

        const client_cid = try randomCid();
        const original_dcid = try randomCid();

        self.* = .{
            .allocator = allocator,
            .role = .client,
            .socket = socket,
            .owns_socket = true,
            .remote_addr = remote,
            .local_addr = .{ .family = posix.AF.INET, .port = 0, .addr = 0, .zero = @splat(0) },
            .quic = undefined,
            .tls_ctx = undefined,
            .packet_crypto = undefined,
            .tls = undefined,
            .crypto_rx = undefined,
            .flow = FlowControl.init(
                allocator,
                options.initial_max_data,
                options.initial_max_stream_data,
            ),
            .last_activity_us = nowMicros(),
            .handshake_started_us = nowMicros(),
        };
        self.local_cid = client_cid;
        self.local_cid_len = cid_len;
        self.original_dcid = original_dcid;
        self.original_dcid_len = cid_len;
        self.installQlog(qlog_config, qlog.Reference.now(), true);
        errdefer self.freeQlog();

        try self.initCrypto(original_dcid[0..cid_len]);
        self.quic.super_connection.local_conn_id = try Packet.ConnectionId.init(client_cid[0..cid_len]);
        errdefer self.deinitCrypto();

        const params = try self.encodeParams(false);
        defer allocator.free(params);
        self.local_params = try allocator.dupe(u8, params);
        errdefer allocator.free(self.local_params);

        self.tls = try qtls.Tls.initClient(allocator, host, self.local_params, options);
        errdefer self.tls.destroy();

        try self.tls.drive();
        try self.afterTlsProgress();
        try self.flushCrypto();
        try self.flush();
        return self;
    }

    pub fn initServer(
        allocator: std.mem.Allocator,
        socket: posix.fd_t,
        local_addr: posix.sockaddr.in,
        remote_addr: posix.sockaddr.in,
        initial_dcid: []const u8,
        original_dcid: []const u8,
        client_cid: []const u8,
        retry_scid: []const u8,
        local_max_data: u64,
        local_max_stream_data: u64,
    ) !*Connection {
        return initServerWithQlog(
            allocator,
            socket,
            local_addr,
            remote_addr,
            initial_dcid,
            original_dcid,
            client_cid,
            retry_scid,
            local_max_data,
            local_max_stream_data,
            null,
            .{},
        );
    }

    /// Server-side constructor used by Listener.dispatch. The listener has
    /// already written the stream header; this only emits connection events.
    pub fn initServerWithQlog(
        allocator: std.mem.Allocator,
        socket: posix.fd_t,
        local_addr: posix.sockaddr.in,
        remote_addr: posix.sockaddr.in,
        initial_dcid: []const u8,
        original_dcid: []const u8,
        client_cid: []const u8,
        retry_scid: []const u8,
        local_max_data: u64,
        local_max_stream_data: u64,
        qlog_config: ?qlog.Config,
        qlog_reference: qlog.Reference,
    ) !*Connection {
        const self = try allocator.create(Connection);
        errdefer allocator.destroy(self);

        const server_cid = if (retry_scid.len > 0) blk: {
            var cid: [20]u8 = @splat(0);
            @memcpy(cid[0..retry_scid.len], retry_scid);
            break :blk cid;
        } else try randomCid();
        self.* = .{
            .allocator = allocator,
            .role = .server,
            .socket = socket,
            .owns_socket = false,
            .remote_addr = remote_addr,
            .local_addr = local_addr,
            .quic = undefined,
            .tls_ctx = undefined,
            .packet_crypto = undefined,
            .tls = undefined,
            .crypto_rx = undefined,
            .flow = FlowControl.init(allocator, local_max_data, local_max_stream_data),
            .last_activity_us = nowMicros(),
            .handshake_started_us = nowMicros(),
        };
        self.local_cid = server_cid;
        self.local_cid_len = cid_len;
        self.peer_cid = @splat(0);
        self.peer_cid_len = @intCast(client_cid.len);
        @memcpy(self.peer_cid[0..client_cid.len], client_cid);
        self.original_dcid = @splat(0);
        self.original_dcid_len = @intCast(original_dcid.len);
        @memcpy(self.original_dcid[0..original_dcid.len], original_dcid);
        self.retry_scid = @splat(0);
        self.retry_scid_len = @intCast(retry_scid.len);
        @memcpy(self.retry_scid[0..retry_scid.len], retry_scid);
        self.installQlog(qlog_config, qlog_reference, false);
        errdefer self.freeQlog();

        try self.initCrypto(initial_dcid);
        self.quic.super_connection.local_conn_id = try Packet.ConnectionId.init(server_cid[0..cid_len]);
        self.quic.super_connection.remote_conn_id = try Packet.ConnectionId.init(client_cid);
        errdefer self.deinitCrypto();

        const params = try self.encodeParams(true);
        defer allocator.free(params);
        self.local_params = try allocator.dupe(u8, params);
        errdefer allocator.free(self.local_params);

        self.tls = try qtls.Tls.initServer(allocator, self.local_params);
        errdefer self.tls.destroy();
        return self;
    }

    fn vantagePoint(self: *const Connection) qlog.VantagePoint {
        return switch (self.role) {
            .client => .client,
            .server => .server,
        };
    }

    /// Allocate the per-connection writer only when a sink was installed. A
    /// failed allocation leaves qlog disabled instead of failing the connection.
    fn installQlog(self: *Connection, config: ?qlog.Config, reference: qlog.Reference, write_header: bool) void {
        const cfg = config orelse return;
        const writer = self.allocator.create(qlog.Writer) catch return;
        writer.* = qlog.Writer.init(cfg, reference);
        self.qlog = writer;
        const pending = self.allocator.create(PendingSends) catch null;
        if (pending) |p| p.* = .{};
        self.qlog_pending = pending;
        if (write_header) writer.writeHeader(self.vantagePoint());
        writer.connectionStarted(
            nowMicros(),
            self.vantagePoint(),
            self.local_cid[0..self.local_cid_len],
            self.peer_cid[0..self.peer_cid_len],
        );
    }

    fn freeQlog(self: *Connection) void {
        if (self.qlog_pending) |pending| {
            self.allocator.destroy(pending);
            self.qlog_pending = null;
        }
        if (self.qlog) |writer| {
            self.allocator.destroy(writer);
            self.qlog = null;
        }
    }

    fn qlogError(self: *Connection, now_us: u64, code: u64, reason: []const u8) void {
        const writer = self.qlog orelse return;
        if (code == 0x0100) return;
        writer.errorEvent(now_us, code, reason);
    }

    fn qlogRemoteClose(self: *Connection, code: u64) void {
        const writer = self.qlog orelse return;
        const now = nowMicros();
        if (code != 0 and code != 0x0100) writer.errorEvent(now, code, "peer connection close");
        writer.connectionClosed(
            now,
            .remote,
            code,
            "peer connection close",
            qlog.ConnectionStats.from(self.stats),
        );
    }

    fn initCrypto(self: *Connection, initial_dcid: []const u8) !void {
        const role: ConnRole = switch (self.role) {
            .client => .client,
            .server => .server,
        };
        self.tls_ctx = try EnhancedTlsContext.init(self.allocator, self.role == .server, .aes_128_gcm_sha256);
        errdefer self.tls_ctx.deinit();
        self.packet_crypto = try PacketCrypto.init(self.allocator, &self.tls_ctx, null);
        errdefer self.packet_crypto.deinit();
        self.quic = try zquic.Connection.Connection.init(self.allocator, role, .{});
        errdefer self.quic.deinit();
        // zquic owns loss detection and names the lost plaintexts; the observer
        // copies each one into this connection's bounded queue. PTO probes stay
        // enabled so a tail loss (no later packet to ACK) still elicits an ACK,
        // which lets zquic's detector surface the original packet.
        self.quic.super_connection.setLostPacketObserver(observeZquicLostPacket, self);

        var initialized: usize = 0;
        errdefer for (self.crypto_rx[0..initialized]) |*r| r.deinit();
        for (&self.crypto_rx) |*r| {
            r.* = try Reassembler.init(self.allocator);
            initialized += 1;
        }
        if (self.role == .client) {
            try self.packet_crypto.installRfc9001ClientInitialKeys(initial_dcid);
        } else {
            try self.packet_crypto.installRfc9001ServerInitialKeys(initial_dcid);
        }
    }

    fn deinitCrypto(self: *Connection) void {
        for (&self.crypto_rx) |*r| r.deinit();
        self.quic.deinit();
        self.packet_crypto.deinit();
        self.tls_ctx.deinit();
    }

    pub fn deinit(self: *Connection) void {
        if (self.qlog) |writer| {
            writer.connectionClosed(
                nowMicros(),
                .transport,
                self.close_code,
                "connection deinit",
                qlog.ConnectionStats.from(self.stats),
            );
        }
        self.freeQlog();
        self.retry_token.deinit(self.allocator);
        self.initial_crypto.deinit(self.allocator);
        var it = self.stream_send.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.stream_send.deinit(self.allocator);
        self.flow.deinit();
        self.finished_streams.deinit(self.allocator);
        if (self.closed_streams_ready) self.closed_streams.deinit();
        self.clearLostQueue();
        self.lost_queue.deinit(self.allocator);
        self.tls.destroy();
        self.deinitCrypto();
        if (self.local_params.len > 0) self.allocator.free(self.local_params);
        if (self.owns_socket) closeSocket(self.socket);
        self.allocator.destroy(self);
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.established;
    }

    pub fn isClosed(self: *const Connection) bool {
        return self.closed;
    }

    /// Return a by-value copy of this connection's counters. No pointer is
    /// exposed and the snapshot stays valid after Connection.deinit.
    pub fn statsSnapshot(self: *const Connection) Stats {
        return self.stats;
    }

    /// Test hook used by the retransmission tests; see drop_outgoing_every.
    pub fn setDropOutgoingEvery(self: *Connection, every: usize) void {
        self.drop_outgoing_every = every;
    }

    fn encodeParams(self: *Connection, server: bool) ![]u8 {
        const params = TransportParameters{
            .max_idle_timeout = 30_000,
            .max_udp_payload_size = 1472,
            // This stack routes by the original CIDs and keeps a fixed peer
            // address; advertise that migration is not supported.
            .disable_active_migration = true,
            .initial_max_data = self.flow.local_max_data,
            .initial_max_stream_data_bidi_local = self.flow.local_max_stream_data,
            .initial_max_stream_data_bidi_remote = self.flow.local_max_stream_data,
            .initial_max_stream_data_uni = self.flow.local_max_stream_data,
            .initial_max_streams_bidi = self.flow.local_max_streams_bidi,
            .initial_max_streams_uni = self.flow.local_max_streams_uni,
            .initial_source_connection_id = self.local_cid[0..self.local_cid_len],
            .original_destination_connection_id = if (server)
                self.original_dcid[0..self.original_dcid_len]
            else
                &.{},
            .retry_source_connection_id = if (server and self.retry_scid_len > 0)
                self.retry_scid[0..self.retry_scid_len]
            else
                &.{},
        };
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        TransportParametersMod.encode(params, &out.writer) catch return error.QuicError;
        return self.allocator.dupe(u8, out.written()) catch error.OutOfMemory;
    }

    /// Feed one UDP datagram, which may contain several coalesced QUIC packets.
    pub fn handleDatagram(self: *Connection, datagram: []const u8) !void {
        if (self.closed or self.closing) return;
        self.stats.packets_received +|= 1;
        self.stats.bytes_received +|= @intCast(datagram.len);
        self.last_activity_us = nowMicros();
        var offset: usize = 0;
        while (offset < datagram.len) {
            const packet = nextPacket(datagram, offset) orelse break;
            self.handlePacket(packet) catch |err| {
                if (err == error.ConnectionClosed) return;
                // A packet that cannot be authenticated is dropped, as QUIC
                // requires; a protocol failure that repeats will surface as a
                // handshake timeout instead of poisoning the whole connection.
            };
            offset += packet.len;
            if (packet.len == 0) break;
        }
        try self.service();
    }

    fn handlePacket(self: *Connection, packet: []const u8) !void {
        if (packet.len < 1) return;
        const header = Packet.PacketHeader.parse(packet, self.allocator) catch return;
        if (header.version) |version| {
            if (version != 1) return;
        }
        if (header.packet_type == .retry) {
            // Retry is never protected and is only meaningful to a client.
            if (self.role == .client) self.handleRetry(packet) catch {};
            return;
        }
        if (self.role == .client) {
            if (header.src_conn_id) |scid| {
                if (scid.bytes().len > 0 and (self.peer_cid_len == 0 or !std.mem.eql(u8, scid.bytes(), self.peer_cid[0..self.peer_cid_len]))) {
                    self.peer_cid_len = @intCast(scid.bytes().len);
                    @memcpy(self.peer_cid[0..self.peer_cid_len], scid.bytes());
                    self.quic.super_connection.remote_conn_id = scid;
                }
            }
        }

        const idx = levelIndexForPacketType(header.packet_type);
        var processed = self.packet_crypto.processProtectedRawPacket(packet, self.largest_pn[idx]) catch return;
        defer processed.deinit(self.allocator);
        self.largest_pn[idx] = processed.packet_number;
        // 0-RTT is not implemented; never let replayable early data reach the
        // HTTP/3 state machine.
        if (processed.encryption_level == .early_data) return;

        var ack_eliciting = false;
        var rx_ack_frames: usize = 0;
        var rx_max_frames: usize = 0;
        var rx_has_stream = false;
        var frame_summary: qlog.FrameSummary = .{};
        const log_frames = self.qlog != null;
        var sanitized: std.Io.Writer.Allocating = .init(self.allocator);
        defer sanitized.deinit();
        var reader = std.Io.Reader.fixed(processed.payload);
        while (reader.seek < reader.end) {
            var frame = QuicFrames.Frame.parse(&reader, self.allocator) catch break;
            defer frame.deinit(self.allocator);
            if (log_frames) summarizeFrame(&frame_summary, frame);

            switch (frame) {
                .crypto => |crypto| {
                    if (processed.encryption_level == .early_data) continue;
                    const tls_level = tlsLevel(processed.encryption_level);
                    const fresh = self.crypto_rx[idx].insert(crypto.offset, crypto.data, false) catch continue;
                    if (fresh.len > 0) {
                        try self.tls.pushCrypto(tls_level, fresh);
                        try self.tls.drive();
                        try self.afterTlsProgress();
                    }
                    ack_eliciting = true;
                },
                .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => |stream| {
                    ack_eliciting = true;
                    rx_has_stream = true;
                    if (self.isStreamClosed(stream.stream_id)) continue;
                    const end = std.math.add(u64, stream.offset, @intCast(stream.data.len)) catch {
                        self.close(0x3, "flow control");
                        return;
                    };
                    const flow = self.ensureStreamFlow(stream.stream_id) catch |err| {
                        self.close(if (err == error.StreamLimitExceeded) 0x4 else 0x1, "flow state");
                        return;
                    };
                    self.flow.receive(
                        stream.stream_id,
                        flow,
                        end,
                        stream.fin,
                        self.role == .client,
                    ) catch |err| {
                        self.close(0x3, switch (err) {
                            error.StreamFlowControlExceeded => "stream flow control",
                            error.ConnectionFlowControlExceeded => "connection flow control",
                        });
                        return;
                    };
                    if (stream.fin and flow.send_fin) {
                        self.finished_streams.append(self.allocator, stream.stream_id) catch {};
                    }
                    if (self.handler) |handler| {
                        handler.on_stream_frame(
                            handler.context,
                            stream.stream_id,
                            stream.offset,
                            stream.data,
                            stream.fin,
                        ) catch {};
                    }
                },
                .ack, .ack_ecn => {
                    // ACK generation/retention stays in the transport for this
                    // milestone; only the resend decision moved to zquic.
                    rx_ack_frames += 1;
                },
                .max_data => |max_data| {
                    rx_max_frames += 1;
                    test_rx_max_data_frames +|= 1;
                    self.flow.receiveMaxData(max_data.maximum_data);
                },
                .max_stream_data => |max_stream| {
                    rx_max_frames += 1;
                    test_rx_max_stream_data_frames +|= 1;
                    self.flow.receiveMaxStreamData(
                        max_stream.stream_id,
                        max_stream.maximum_stream_data,
                    );
                },
                .max_streams_bidi => |max_streams| {
                    self.flow.receiveMaxStreams(max_streams.maximum_streams, true);
                },
                .max_streams_uni => |max_streams| {
                    self.flow.receiveMaxStreams(max_streams.maximum_streams, false);
                },
                .padding, .connection_close, .connection_close_app => {
                    const tag = std.meta.activeTag(frame);
                    if (tag == .connection_close or tag == .connection_close_app) {
                        self.closed = true;
                        const close_code: u64 = switch (frame) {
                            .connection_close => |close_frame| close_frame.error_code,
                            .connection_close_app => |close_frame| close_frame.error_code,
                            else => 0,
                        };
                        self.qlogRemoteClose(close_code);
                        if (self.handler) |handler| handler.on_closed(handler.context, 0);
                    }
                },
                .handshake_done => {},
                else => ack_eliciting = true,
            }

            // Only ACK/flow-control/handshake frames go through zquic's own
            // dispatcher. CRYPTO and STREAM are handled above; passing them on
            // would either fail (CRYPTO) or duplicate stream state.
            switch (frame) {
                .crypto, .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => {},
                else => {
                    frame.serialize(&sanitized.writer) catch {};
                },
            }
        }

        if (rx_ack_frames > 0) {
            test_rx_ack_frames +|= @intCast(rx_ack_frames);
            if (rx_ack_frames > 1) test_rx_duplicate_ack_packets +|= 1;
            if (rx_has_stream) test_rx_ack_with_stream_packets +|= 1;
        }
        if (rx_max_frames > 0 and rx_has_stream) {
            test_rx_max_with_stream_packets +|= 1;
        }

        self.acks[idx].record(processed.packet_number, ack_eliciting);
        if (self.qlog) |writer| {
            if (writer.sampleReceived()) writer.packetReceived(
                nowMicros(),
                processed.packet_number,
                @intCast(idx),
                qlogPacketType(header.packet_type),
                ack_eliciting,
                processed.payload.len,
                frame_summary,
            );
        }
        if (sanitized.written().len > 0) {
            self.quic.super_connection.processPlaintextPayloadAtLevel(processed.encryption_level, sanitized.written()) catch {};
        }
    }

    /// Accept the first valid Retry for this connection attempt.
    ///
    /// RFC 9000 Section 17.2.5 requires a fresh Initial key set derived from
    /// the Retry SCID, the Retry SCID as the new destination CID, and the same
    /// ClientHello resent with the token. TLS is deliberately untouched: the
    /// cached CRYPTO bytes below are the exact input to the existing handshake
    /// transcript, so the client never restarts the handshake.
    fn handleRetry(self: *Connection, packet: []const u8) !void {
        if (self.role != .client) return;
        if (self.retry_received) {
            test_retry_rejected += 1;
            return error.InvalidPacket;
        }

        const retry_packet = Packet.RetryPacket.parse(packet, self.allocator) catch {
            test_retry_rejected += 1;
            return error.InvalidPacket;
        };
        retry_packet.validateClientRetry(
            packet,
            self.local_cid[0..self.local_cid_len],
            self.original_dcid[0..self.original_dcid_len],
        ) catch |err| {
            test_retry_rejected += 1;
            return err;
        };

        // Prepare every fallible allocation before committing the retried
        // state, so a failure leaves the original Initial key set usable.
        var fresh_crypto_rx = try Reassembler.init(self.allocator);
        var fresh_rx_owned = true;
        errdefer if (fresh_rx_owned) fresh_crypto_rx.deinit();
        try self.retry_token.resize(self.allocator, retry_packet.token.len);
        @memcpy(self.retry_token.items, retry_packet.token);
        try self.packet_crypto.installRfc9001ClientInitialKeys(retry_packet.src_conn_id.bytes());

        self.retry_received = true;
        self.retry_scid_len = @intCast(retry_packet.src_conn_id.bytes().len);
        self.retry_scid = @splat(0);
        @memcpy(self.retry_scid[0..self.retry_scid_len], retry_packet.src_conn_id.bytes());
        self.peer_cid = @splat(0);
        self.peer_cid_len = self.retry_scid_len;
        @memcpy(self.peer_cid[0..self.peer_cid_len], self.retry_scid[0..self.retry_scid_len]);
        self.quic.super_connection.remote_conn_id = retry_packet.src_conn_id;

        // Restart the Initial packet number space from zero (RFC 9000
        // Section 17.2.5.2) and discard everything protected with the old
        // Initial keys. zquic owns sent-packet retention now; queued lost
        // Initial payloads from before the Retry must never be resent with the
        // new keys.
        self.packet_crypto.resetInitialPacketNumberState();
        self.packet_crypto.initial_token = self.retry_token.items;
        self.clearLostQueue();
        self.quic.super_connection.discardPacketNumberSpace(.initial);
        self.crypto_tx_offset[0] = 0;
        self.largest_pn[0] = null;
        self.acks[0] = .{};
        self.crypto_rx[0].deinit();
        self.crypto_rx[0] = fresh_crypto_rx;
        fresh_rx_owned = false;

        test_retry_accepted += 1;
        try self.resendInitialCrypto();
        try self.flush();
    }

    /// Resend the cached Initial CRYPTO bytes after a Retry.
    ///
    /// The payload is identical to the original flight (same ClientHello,
    /// same chunking, same offsets); only the packet protection keys, the
    /// destination CID, and the header token change.
    fn resendInitialCrypto(self: *Connection) !void {
        const bytes = self.initial_crypto.items;
        if (bytes.len == 0) return error.QuicError;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const take: usize = @min(bytes.len - offset, 1000);
            const frame = [_]QuicFrames.Frame{
                .{ .crypto = QuicFrames.CryptoFrame.init(offset, bytes[offset .. offset + take]) },
            };
            try self.schedule(0, .initial, &frame);
            offset += take;
        }
        self.crypto_tx_offset[0] = bytes.len;
    }

    fn afterTlsProgress(self: *Connection) !void {
        for ([_]usize{ 2, 3 }) |level| {
            const incoming = self.tls.takeSecrets(level);
            if (incoming.local) |secret| self.secrets[level].local = secret;
            if (incoming.remote) |secret| self.secrets[level].remote = secret;
        }

        if (!self.handshake_keys and self.secrets[2].complete()) {
            try self.installLevelKeys(2);
        }
        if (!self.application_keys and self.secrets[3].complete()) {
            try self.installLevelKeys(3);
        }

        if (!self.peer_params_applied and self.tls.peerParams().len > 0) {
            self.applyPeerParams(self.tls.peerParams()) catch {};
        }

        try self.flushCrypto();

        if (!self.established and self.tls.isFinished()) {
            self.established = true;
            self.quic.super_connection.state = .established;
            if (self.role == .server and !self.handshake_done_sent) {
                try self.sendHandshakeDone();
            }
            if (!self.established_notified) {
                self.established_notified = true;
                if (self.handler) |handler| {
                    handler.on_established(handler.context) catch {};
                }
            }
        }
    }

    fn installLevelKeys(self: *Connection, level: usize) !void {
        const secrets = self.secrets[level];
        const local_secret = secrets.local orelse return;
        const remote_secret = secrets.remote orelse return;
        const local_keys = try Tls13KeySchedule.deriveQuicPacketKeys(&local_secret);
        const remote_keys = try Tls13KeySchedule.deriveQuicPacketKeys(&remote_secret);
        if (level == 2) {
            try self.packet_crypto.installRfc9001HandshakeKeys(&local_keys, &remote_keys);
            self.handshake_keys = true;
        } else {
            try self.packet_crypto.installRfc9001ApplicationKeys(&local_keys, &remote_keys);
            self.application_keys = true;
        }
    }

    fn applyPeerParams(self: *Connection, encoded: []const u8) !void {
        const params = TransportParametersMod.decode(encoded) catch return error.QuicError;
        const context = if (self.role == .client)
            NegotiationContext{
                .peer_role = .server,
                // RFC 9000 Section 7.3: a retried client keeps the original
                // destination CID, and the server's retry_source_connection_id
                // must match the SCID from the Retry packet.
                .original_destination_connection_id = self.original_dcid[0..self.original_dcid_len],
                .initial_source_connection_id = self.peer_cid[0..self.peer_cid_len],
                .retry_source_connection_id = if (self.retry_scid_len > 0)
                    self.retry_scid[0..self.retry_scid_len]
                else
                    &.{},
            }
        else
            NegotiationContext{
                .peer_role = .client,
                .initial_source_connection_id = self.peer_cid[0..self.peer_cid_len],
            };
        self.quic.super_connection.applyPeerTransportParameters(params, context) catch return error.QuicError;
        self.peer_params = params;
        self.flow.applyPeerLimits(.{
            .max_data = params.initial_max_data,
            .max_streams_bidi = params.initial_max_streams_bidi,
            .max_streams_uni = params.initial_max_streams_uni,
            .max_stream_data_uni = params.initial_max_stream_data_uni,
            .max_stream_data_bidi_local = params.initial_max_stream_data_bidi_local,
            .max_stream_data_bidi_remote = params.initial_max_stream_data_bidi_remote,
        }, self.role == .client);
        self.peer_params_applied = true;
    }

    /// Queue HANDSHAKE_DONE for the current service pass. flushStreams() puts
    /// it ahead of STREAM data when the packet has room; otherwise the
    /// standalone control path sends it before flush() drains the datagrams.
    fn sendHandshakeDone(self: *Connection) !void {
        if (!self.application_keys) return;
        self.handshake_done_pending = true;
    }

    /// Find or create flow state; a created entry counts toward
    /// Stats.streams_opened. The statistics counter stays with Connection.
    fn ensureStreamFlow(self: *Connection, stream_id: u64) !*flow_control.StreamFlow {
        const ensured = try self.flow.ensureStream(stream_id, self.role == .client);
        if (ensured.created) self.stats.streams_opened +|= 1;
        return ensured.flow;
    }

    fn refreshStreamSendLimits(self: *Connection) void {
        self.flow.refreshStreamSendLimits(self.role == .client);
    }

    /// Append stream data and schedule it on the next service pass.
    pub fn queueStreamData(self: *Connection, stream_id: u64, data: []const u8, fin: bool) !void {
        _ = try self.ensureStreamFlow(stream_id);
        const entry = try self.stream_send.getOrPut(self.allocator, stream_id);
        if (!entry.found_existing) entry.value_ptr.* = .{};
        try entry.value_ptr.buf.appendSlice(self.allocator, data);
        if (fin) entry.value_ptr.fin = true;
    }

    /// Bytes queued for a stream but not yet written to the socket.
    pub fn pendingStreamBytes(self: *const Connection, stream_id: u64) usize {
        const send = self.stream_send.get(stream_id) orelse return 0;
        return send.pending().len;
    }

    /// Test-visible copy of one stream's send cursor. The private StreamSend
    /// type stays private; batching tests use this to prove that a failed
    /// schedule advances nothing and a retransmit never advances twice.
    pub const StreamSendSnapshot = struct {
        sent: u64,
        pending: usize,
        buf_len: usize,
        fin: bool,
        fin_sent: bool,
    };

    pub fn streamSendSnapshot(self: *const Connection, stream_id: u64) ?StreamSendSnapshot {
        const send = self.stream_send.get(stream_id) orelse return null;
        return .{
            .sent = send.sent,
            .pending = send.pending().len,
            .buf_len = send.buf.items.len,
            .fin = send.fin,
            .fin_sent = send.fin_sent,
        };
    }

    /// Test-visible peer stream send limit, or null when the stream has no flow
    /// state yet.
    pub fn streamSendLimit(self: *const Connection, stream_id: u64) ?u64 {
        return self.flow.streamSendLimit(stream_id);
    }

    pub fn createBidiStream(self: *Connection) !u64 {
        if (self.flow.opened_bidi >= self.flow.peer_max_streams_bidi) return error.StreamLimitExceeded;
        const stream_type: zquic.core.Stream.StreamType = switch (self.role) {
            .client => .client_bidirectional,
            .server => .server_bidirectional,
        };
        const stream = self.quic.createStream(stream_type) catch return error.QuicError;
        self.flow.opened_bidi += 1;
        _ = try self.ensureStreamFlow(stream.id);
        return stream.id;
    }

    pub fn createUniStream(self: *Connection) !u64 {
        if (self.flow.opened_uni >= self.flow.peer_max_streams_uni) return error.StreamLimitExceeded;
        const stream_type: zquic.core.Stream.StreamType = switch (self.role) {
            .client => .client_unidirectional,
            .server => .server_unidirectional,
        };
        const stream = self.quic.createStream(stream_type) catch return error.QuicError;
        self.flow.opened_uni += 1;
        _ = try self.ensureStreamFlow(stream.id);
        return stream.id;
    }

    fn flushCrypto(self: *Connection) !void {
        for (0..qtls.level_count) |level| {
            if (level == 1) {
                // 0-RTT is not implemented; discard anything TLS produced for it.
                self.tls.clearOut(level);
                continue;
            }
            const data = self.tls.takeOut(level);
            if (data.len == 0) continue;
            if (level == 0) {
                // Keep a copy so an accepted Retry can replay the exact same
                // CRYPTO stream under new Initial keys and a token.
                try self.initial_crypto.appendSlice(self.allocator, data);
            }
            var offset: usize = 0;
            while (offset < data.len) {
                const take: usize = @min(data.len - offset, 1000);
                var frames_buf: [2]QuicFrames.Frame = undefined;
                frames_buf[0] = .{ .crypto = QuicFrames.CryptoFrame.init(self.crypto_tx_offset[level], data[offset .. offset + take]) };
                var frame_count: usize = 1;
                // RFC 9000 Section 14.1: every datagram carrying an Initial
                // packet must be at least 1200 bytes. A ClientHello larger than
                // one packet is split above, so each piece needs its own pad.
                if (level == 0) {
                    const overhead: usize = 40; // header + AEAD tag, with slack
                    if (take + overhead < 1200) {
                        const padding_len: usize = 1200 - overhead - take;
                        if (padding_len > 0) {
                            frames_buf[1] = .{ .padding = QuicFrames.PaddingFrame.init(padding_len) };
                            frame_count = 2;
                        }
                    }
                }
                const ptype: Packet.PacketType = switch (level) {
                    0 => .initial,
                    2 => .handshake,
                    else => .one_rtt,
                };
                try self.schedule(level, ptype, frames_buf[0..frame_count]);
                self.crypto_tx_offset[level] += take;
                offset += take;
            }
            self.tls.clearOut(level);
        }
    }

    /// Conservative plaintext budget for one 1-RTT STREAM frame. The QUIC
    /// header, packet number, AEAD tag, and STREAM frame varints are reserved;
    /// this replaces the old hardcoded 1000-byte chunk without requiring a
    /// full packet builder yet.
    /// Plaintext bytes available in one 1-RTT packet after the short header,
    /// packet number, and AEAD tag. 24 more bytes are reserved for a STREAM
    /// frame's type/stream-id/offset/length varints by maxStreamFramePayload.
    fn maxPacketPayload(self: *const Connection) usize {
        const advertised = if (self.peer_params) |params| params.max_udp_payload_size else 1472;
        const mtu: usize = @intCast(std.math.clamp(advertised, 1200, 1472));
        const overhead: usize = 1 + self.destinationCid(3).len + 4 + 16;
        if (mtu <= overhead) return 0;
        return mtu - overhead;
    }

    fn maxStreamFramePayload(self: *const Connection) usize {
        const payload = self.maxPacketPayload();
        if (payload <= 24) return 0;
        return payload - 24;
    }

    /// Build one candidate 1-RTT data batch. The caller schedules the frames as
    /// a single protected packet and only then commits the claims, so a failure
    /// leaves every stream byte-identical.
    fn collectStreamBatch(
        self: *Connection,
        streams: *std.ArrayListUnmanaged(BatchStream),
        frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
        claims: *std.ArrayListUnmanaged(StreamClaim),
        budget_limit: usize,
    ) !BatchBuild {
        var build = BatchBuild{};
        build.budget = budget_limit;
        if (build.budget == 0) return build;

        // Snapshot sendable work. No send state is mutated here; flow entries
        // created by ensureStreamFlow only affect the receive/send limit maps.
        var it = self.stream_send.iterator();
        while (it.next()) |entry| {
            const stream_id = entry.key_ptr.*;
            if (self.isStreamClosed(stream_id)) continue;
            const send = entry.value_ptr;
            const pending = send.pending();
            if (pending.len == 0) {
                if (send.fin and !send.fin_sent) {
                    try streams.append(self.allocator, .{
                        .stream_id = stream_id,
                        .pending = &.{},
                        .base = send.sent,
                        .credit = 0,
                        .fin_pending = true,
                    });
                }
                continue;
            }
            // A stream whose FIN was already scheduled has no bytes left; be
            // defensive rather than resend at a stale offset.
            if (send.fin_sent) continue;
            const flow = try self.ensureStreamFlow(stream_id);
            const credit = flow.send_limit -| send.sent;
            if (credit == 0 or self.flow.sent_data >= self.flow.peer_max_data) {
                test_send_blocked += 1;
                continue;
            }
            try streams.append(self.allocator, .{
                .stream_id = stream_id,
                .pending = pending,
                .base = send.sent,
                .credit = credit,
                .fin_pending = send.fin,
            });
        }
        if (streams.items.len == 0) return build;

        var budget_left = build.budget;

        // FIN-only frames are tiny and latency-sensitive: reserve them before a
        // large stream can consume the whole shared budget. `fin_planned` keeps
        // the later data pass from emitting a duplicate FIN.
        for (streams.items) |*s| {
            if (s.pending.len != 0 or !s.fin_pending or s.fin_planned) continue;
            const overhead = streamFrameOverhead(s.stream_id, s.base, 0);
            if (overhead > budget_left) continue;
            _ = try self.appendStreamFrame(frames, claims, s, 0, true);
            budget_left -= overhead;
        }

        var connection_credit = self.flow.peer_max_data -| self.flow.sent_data;
        while (budget_left > 0) {
            var remaining: usize = 0;
            for (streams.items) |*s| {
                if (s.planned < s.pending.len) {
                    if (s.planned < s.credit and connection_credit > 0) remaining += 1;
                } else if (s.fin_pending and !s.fin_planned) {
                    remaining += 1;
                }
            }
            if (remaining == 0) break;

            var progressed = false;
            for (streams.items) |*s| {
                if (budget_left == 0) break;
                const data_left = s.pending.len - s.planned;
                if (data_left == 0) {
                    if (s.fin_pending and !s.fin_planned) {
                        const overhead = streamFrameOverhead(s.stream_id, s.base + s.planned, 0);
                        if (overhead <= budget_left) {
                            _ = try self.appendStreamFrame(frames, claims, s, 0, true);
                            budget_left -= overhead;
                            progressed = true;
                        }
                    }
                    continue;
                }
                if (connection_credit == 0) continue;
                const credit_left = s.credit -| s.planned;
                if (credit_left == 0) continue;

                // Equal share per active stream keeps a large stream from
                // monopolizing the packet. Leftover budget goes to a later
                // round, which is how one stream can contribute several chunks
                // to the same packet next to other streams.
                const share = @max(@as(usize, 1), budget_left / remaining);
                const demand: u64 = @min(@as(u64, @intCast(data_left)), credit_left);
                const max_take: usize = @intCast(@min(demand, @min(connection_credit, @as(u64, @intCast(share)))));
                if (max_take == 0) continue;
                const offset = s.base + s.planned;
                const fixed = 1 + varintSize(s.stream_id) + varintSize(offset);
                const take = streamFrameDataThatFits(fixed, budget_left, max_take);
                if (take == 0) continue;
                const fin = s.fin_pending and s.planned + take == s.pending.len;
                const used = try self.appendStreamFrame(frames, claims, s, take, fin);
                budget_left -= used;
                connection_credit -= take;
                progressed = true;
            }
            if (!progressed) break;
        }

        build.used = build.budget - budget_left;
        for (streams.items) |*s| {
            if (s.claimed) build.stream_count += 1;
        }
        return build;
    }

    /// Append a STREAM frame and its claim. Offsets are send.sent plus the bytes
    /// already planned for this stream in this batch, so repeated frames form a
    /// contiguous range. Never call this after schedule has failed.
    fn appendStreamFrame(
        self: *Connection,
        frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
        claims: *std.ArrayListUnmanaged(StreamClaim),
        s: *BatchStream,
        take: usize,
        fin: bool,
    ) !usize {
        const offset = s.base + s.planned;
        const data = s.pending[s.planned..][0..take];
        try frames.append(self.allocator, .{
            .stream = QuicFrames.StreamFrame.init(s.stream_id, offset, data, fin, true, true),
        });
        try claims.append(self.allocator, .{
            .stream_id = s.stream_id,
            .offset = offset,
            .len = take,
            .fin = fin,
        });
        s.planned += take;
        if (fin) s.fin_planned = true;
        s.claimed = true;
        return streamFrameOverhead(s.stream_id, offset, take) + take;
    }

    /// Commit a scheduled batch. This is the only place send offsets, the
    /// connection send counter, and FIN state advance.
    fn commitStreamBatch(self: *Connection, claims: []const StreamClaim) void {
        for (claims) |claim| {
            const send = self.stream_send.getPtr(claim.stream_id) orelse continue;
            // The batch was built from this exact offset. Do not advance twice
            // if state ever disagrees; the bytes stay queued for a later pass.
            if (send.sent != claim.offset) continue;
            if (claim.len > 0) {
                send.sent = claim.offset + claim.len;
                self.flow.sent_data += claim.len;
            }
            if (claim.fin) {
                send.fin_sent = true;
                self.flow.markSendFin(claim.stream_id, self.role == .client);
                self.finished_streams.append(self.allocator, claim.stream_id) catch {};
            }
            if (send.fin_sent and send.sent >= send.buf.items.len) {
                // zquic retains the protected plaintext until ACK/loss and the
                // lost-payload queue copies it before a resend, so the stream's
                // own copy can be released after the FIN frame was successfully
                // scheduled and committed.
                send.buf.clearRetainingCapacity();
                send.sent = 0;
            }
        }
    }

    /// Serialized size of a control frame this file emits. Only the coalescible
    /// frame types are handled; callers never pass anything else.
    fn controlFrameLen(frame: QuicFrames.Frame) usize {
        return switch (frame) {
            .ack => |ack_frame| blk: {
                var len: usize = 1 +
                    varintSize(ack_frame.largest_acknowledged) +
                    varintSize(ack_frame.ack_delay) +
                    varintSize(ack_frame.ack_range_count) +
                    varintSize(ack_frame.first_ack_range);
                for (ack_frame.ack_ranges) |range| {
                    len += varintSize(range.gap) + varintSize(range.ack_range_length);
                }
                break :blk len;
            },
            .max_data => |max_data| 1 + varintSize(max_data.maximum_data),
            .max_stream_data => |max_stream| 1 +
                varintSize(max_stream.stream_id) +
                varintSize(max_stream.maximum_stream_data),
            .max_streams_bidi, .max_streams_uni => |max_streams| 1 +
                varintSize(max_streams.maximum_streams),
            .handshake_done => 1,
            else => 0,
        };
    }

    /// Exact serialized size of the gathered control frames. Used to reserve
    /// room in the first data packet without an extra frame-size table.
    fn controlPayloadLen(self: *Connection, control: *const ControlBatch) !usize {
        var out: std.Io.Writer.Allocating = .init(self.allocator);
        defer out.deinit();
        for (control.frames.items) |frame| {
            frame.serialize(&out.writer) catch return error.OutOfMemory;
        }
        return out.written().len;
    }

    fn countCoalescedControl(self: *Connection, control: *const ControlBatch) void {
        _ = self;
        test_control_coalesced_packets +|= 1;
        for (control.frames.items) |frame| {
            switch (frame) {
                .ack => test_ack_coalesced_packets +|= 1,
                .max_data, .max_stream_data, .max_streams_bidi, .max_streams_uni => {
                    test_flow_coalesced_packets +|= 1;
                },
                .handshake_done => test_handshake_done_coalesced_packets +|= 1,
                else => {},
            }
        }
    }

    /// Advance the transport state for a control frame that reached a
    /// successfully scheduled protected packet. Never call this on a frame
    /// whose packet failed to schedule.
    fn commitControlFrame(self: *Connection, frame: QuicFrames.Frame) void {
        switch (frame) {
            .ack => {
                self.acks[3].clear();
                self.stats.ack_frames_sent +|= 1;
            },
            .max_data => |max_data| {
                self.flow.commitMaxData(max_data.maximum_data);
                test_max_data_sent += 1;
                self.stats.flow_updates +|= 1;
            },
            .max_stream_data => |max_stream| {
                self.flow.commitMaxStreamData(
                    max_stream.stream_id,
                    max_stream.maximum_stream_data,
                );
                test_max_stream_data_sent += 1;
                self.stats.flow_updates +|= 1;
            },
            .max_streams_bidi => |max_streams| {
                self.flow.commitMaxStreams(max_streams.maximum_streams, true);
            },
            .max_streams_uni => |max_streams| {
                self.flow.commitMaxStreams(max_streams.maximum_streams, false);
            },
            .handshake_done => {
                self.handshake_done_sent = true;
                self.handshake_done_pending = false;
            },
            else => {},
        }
    }

    /// Send the gathered control set without STREAM data, splitting it so one
    /// protected packet stays within the plaintext budget. Each successfully
    /// scheduled chunk is committed immediately; a later failure leaves only
    /// the not-yet-sent frames for the next service pass.
    fn sendStandaloneControl(self: *Connection, control: *ControlBatch) !void {
        var start: usize = 0;
        const limit = self.maxPacketPayload();
        while (start < control.frames.items.len) {
            var end = start;
            var used: usize = 0;
            while (end < control.frames.items.len) {
                const frame_len = controlFrameLen(control.frames.items[end]);
                if (end > start and used + frame_len > limit) break;
                used += frame_len;
                end += 1;
                if (used >= limit) break;
            }
            if (end == start) end += 1; // a single frame larger than one packet
            try self.schedule(3, .one_rtt, control.frames.items[start..end]);

            var has_ack = false;
            for (control.frames.items[start..end]) |frame| {
                if (std.meta.activeTag(frame) == .ack) has_ack = true;
                self.commitControlFrame(frame);
            }
            if (has_ack) {
                test_standalone_ack_packets +|= 1;
                test_standalone_ack_plaintext_len = test_last_scheduled_plaintext_len;
            }
            start = end;
        }
        control.sent = true;
    }

    /// Send any control frames flushStreams() could not place in a data packet.
    fn finishControlFrames(self: *Connection, control: *ControlBatch) !void {
        if (control.sent or control.frames.items.len == 0) return;
        if (!self.application_keys or self.closed) return;
        try self.sendStandaloneControl(control);
    }

    /// Gather the 1-RTT control frame set for this service pass. Nothing is
    /// committed here: ACK ranges stay required, recv limits stay put, and
    /// MAX_STREAMS bookkeeping is untouched until a packet is scheduled.
    fn collectControlFrames(self: *Connection, control: *ControlBatch) !void {
        if (!self.application_keys or self.closed) return;
        try self.collectAckFrame(control);
        try self.collectFlowControlFrames(control);
        try self.collectStreamLimitFrames(control);
        if (self.handshake_done_pending and !self.handshake_done_sent) {
            try control.frames.append(self.allocator, .{
                .handshake_done = QuicFrames.HandshakeDoneFrame.init(),
            });
        }
    }

    fn collectAckFrame(self: *Connection, control: *ControlBatch) !void {
        const state = &self.acks[3];
        if (!state.ack_required or state.count == 0) return;
        var ack_frame = state.buildFrame(self.allocator) catch return;
        control.frames.append(self.allocator, .{ .ack = ack_frame }) catch {
            ack_frame.deinit(self.allocator);
            return error.OutOfMemory;
        };
        control.ack = ack_frame;
    }

    /// Queue receive-window updates. Nothing is committed here: the receive
    /// limit advances only in commitControlFrame() after schedule() succeeds.
    fn collectFlowControlFrames(self: *Connection, control: *ControlBatch) !void {
        try self.flow.collectFlowControlFrames(&control.frames);
    }

    /// Queue MAX_STREAMS replacements. Advertised/last-sent counters advance at
    /// commit time, never during collection.
    fn collectStreamLimitFrames(self: *Connection, control: *ControlBatch) !void {
        try self.flow.collectStreamLimitFrames(&control.frames);
    }

    /// Build and schedule 1-RTT packets. control is the same set gathered at
    /// the start of the service pass; when it fits, its frames are placed
    /// before the first STREAM frame of the first packet. Bookkeeping for both
    /// the controls and the stream claims is committed only after schedule()
    /// succeeds, and the control set is sent at most once per pass.
    fn flushStreams(self: *Connection, control: ?*ControlBatch) !void {
        if (!self.application_keys) return;

        var frames: std.ArrayListUnmanaged(QuicFrames.Frame) = .empty;
        defer frames.deinit(self.allocator);
        var claims: std.ArrayListUnmanaged(StreamClaim) = .empty;
        defer claims.deinit(self.allocator);
        var streams: std.ArrayListUnmanaged(BatchStream) = .empty;
        defer streams.deinit(self.allocator);

        var control_pending = if (control) |batch|
            !batch.sent and batch.frames.items.len > 0
        else
            false;
        const packet_budget = self.maxStreamFramePayload();

        // At most 64 protected data packets per service pass. Each packet is a
        // transaction: build, schedule, then commit. schedule() failures leave
        // every claim and control frame uncommitted, so the next service pass
        // retries the same bytes at the same offsets and does not resend an
        // ACK/MAX_* that was never scheduled.
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            frames.clearRetainingCapacity();
            claims.clearRetainingCapacity();
            streams.clearRetainingCapacity();

            var control_len: usize = 0;
            if (control_pending) control_len = try self.controlPayloadLen(control.?);

            // Reserve the control bytes only when at least a minimal STREAM
            // frame still fits; otherwise the controls go out alone first.
            const reserve_control = control_pending and
                control_len < packet_budget and
                packet_budget - control_len > 26;
            if (reserve_control) {
                for (control.?.frames.items) |frame| {
                    try frames.append(self.allocator, frame);
                }
            }

            const budget = if (reserve_control) packet_budget - control_len else packet_budget;
            const build = try self.collectStreamBatch(&streams, &frames, &claims, budget);

            if (claims.items.len == 0) {
                if (control_pending) {
                    // No STREAM data to coalesce with: send the control set on
                    // its own (split if necessary), then rebuild with the full
                    // budget in case streams became sendable in between.
                    if (reserve_control) frames.clearRetainingCapacity();
                    try self.sendStandaloneControl(control.?);
                    control_pending = false;
                    continue;
                }
                break;
            }
            if (control_pending and !reserve_control) {
                // The control set does not fit next to data. Sending it once
                // first keeps ACK/flow state timely and guarantees it is not
                // duplicated into a later data packet in this pass.
                try self.sendStandaloneControl(control.?);
                control_pending = false;
                continue;
            }

            try self.schedule(3, .one_rtt, frames.items);

            if (reserve_control) {
                self.countCoalescedControl(control.?);
                for (control.?.frames.items) |frame| self.commitControlFrame(frame);
                control.?.sent = true;
                control_pending = false;
            }
            self.commitStreamBatch(claims.items);

            test_batch_packets +|= 1;
            test_batch_stream_frames +|= @intCast(claims.items.len);
            if (claims.items.len > 1) test_batch_multi_frame_packets +|= 1;
            if (build.stream_count > 1) test_batch_multi_stream_packets +|= 1;
            const plaintext_used = build.used + control_len;
            test_batch_largest_payload = @max(test_batch_largest_payload, plaintext_used);
            test_batch_budget = packet_budget;
        }
        self.reapFinishedStreams();
    }

    fn markStreamClosed(self: *Connection, stream_id: u64) void {
        const index: usize = @intCast(stream_id >> 2);
        if (!self.closed_streams_ready) {
            self.closed_streams = std.DynamicBitSet.initEmpty(self.allocator, 0) catch return;
            self.closed_streams_ready = true;
        }
        if (index >= self.closed_streams.capacity()) {
            self.closed_streams.resize(index + 64, false) catch return;
        }
        self.closed_streams.set(index);
    }

    fn isStreamClosed(self: *const Connection, stream_id: u64) bool {
        if (!self.closed_streams_ready) return false;
        const index: usize = @intCast(stream_id >> 2);
        return index < self.closed_streams.capacity() and self.closed_streams.isSet(index);
    }

    fn reapFinishedStreams(self: *Connection) void {
        for (self.finished_streams.items) |stream_id| {
            if (self.stream_send.fetchRemove(stream_id)) |entry| {
                var send = entry.value;
                send.deinit(self.allocator);
            }
            if (self.flow.isFinished(stream_id)) {
                self.markStreamClosed(stream_id);
                self.flow.removeStream(stream_id);
                self.stats.streams_closed +|= 1;
            }
        }
        self.finished_streams.clearRetainingCapacity();
    }

    fn schedule(
        self: *Connection,
        level: usize,
        ptype: Packet.PacketType,
        frames: []const QuicFrames.Frame,
    ) !void {
        // Only a server sends Retry, and it builds the packet itself. A client
        // must never send one, so make that impossible at the one send path.
        if (ptype == .retry) return error.QuicError;
        const dest = self.destinationCid(level);
        if (dest.len == 0) return error.QuicError;

        var payload: std.Io.Writer.Allocating = .init(self.allocator);
        defer payload.deinit();
        var ack_eliciting = false;
        for (frames) |frame| {
            frame.serialize(&payload.writer) catch return error.QuicError;
            ack_eliciting = ack_eliciting or frame.isAckEliciting();
        }
        // Header protection samples 16 bytes starting four bytes into the
        // packet number; very small frames (MAX_STREAMS is three bytes) would
        // otherwise fail packet construction. Initial datagrams must also be
        // at least 1200 bytes on the wire.
        const min_payload: usize = if (level == 0) 1200 else 64;
        var pad = payload.written().len;
        while (pad < min_payload) : (pad += 1) {
            payload.writer.writeByte(0) catch return error.OutOfMemory;
        }
        const bytes = payload.written();
        if (bytes.len == 0) return error.QuicError;

        const src: []const u8 = if (ptype == .one_rtt) &.{} else self.local_cid[0..self.local_cid_len];
        const log_packet = self.qlog != null and self.qlog_pending != null;
        var frame_summary: qlog.FrameSummary = .{};
        if (log_packet) {
            for (frames) |frame| summarizeFrame(&frame_summary, frame);
        }
        const packet_number = self.packet_crypto.nextPacketNumberForLevel(switch (level) {
            0 => .initial,
            2 => .handshake,
            else => .application,
        });
        self.quic.super_connection.sendProtectedRawPacket(
            &self.packet_crypto,
            switch (level) {
                0 => .initial,
                2 => .handshake,
                else => .application,
            },
            ptype,
            dest,
            src,
            bytes,
        ) catch return error.QuicError;

        if (log_packet) self.qlog_pending.?.push(.{
            .packet_number = packet_number,
            .level = @intCast(level),
            .ptype = qlogPacketType(ptype),
            .ack_eliciting = ack_eliciting,
            .plaintext_len = @intCast(bytes.len),
            .frames = frame_summary,
        });

        test_last_scheduled_plaintext_len = bytes.len;
    }

    /// Copy one lost packet out of zquic's callback. The payload is only valid
    /// during the callback, so this is the only place it is copied; resending
    /// happens later from service.
    fn queueLostPayload(
        self: *Connection,
        level: usize,
        packet_number: u64,
        payload: []const u8,
    ) void {
        if (payload.len == 0) return;
        // Only the three levels the transport emits are meaningful.
        if (level != 0 and level != 2 and level != 3) return;

        const owned = self.allocator.dupe(u8, payload) catch return;
        if (self.retainedLostPayloads() >= max_lost_payloads_retained) {
            var oldest = self.lost_queue.items[self.lost_queue_head];
            oldest.deinit(self.allocator);
            self.lost_queue_head += 1;
            if (self.lost_queue_head >= 1024) self.compactLostQueue();
        }
        self.lost_queue.append(self.allocator, .{
            .level = level,
            .packet_number = packet_number,
            .detected_us = nowMicros(),
            .payload = owned,
        }) catch {
            self.allocator.free(owned);
            return;
        };
    }

    fn retainedLostPayloads(self: *const Connection) usize {
        return self.lost_queue.items.len - self.lost_queue_head;
    }

    /// Move unread entries to the front and release the consumed prefix.
    fn compactLostQueue(self: *Connection) void {
        if (self.lost_queue_head == 0) return;
        const unread = self.lost_queue.items[self.lost_queue_head..];
        if (unread.len > 0) {
            std.mem.copyForwards(LostPayload, self.lost_queue.items[0..unread.len], unread);
        }
        self.lost_queue.shrinkRetainingCapacity(unread.len);
        self.lost_queue_head = 0;
    }

    /// Free every queued lost payload. Used on deinit and when Retry discards
    /// the Initial packet number space.
    fn clearLostQueue(self: *Connection) void {
        for (self.lost_queue.items[self.lost_queue_head..]) |*lost| lost.deinit(self.allocator);
        self.lost_queue.clearRetainingCapacity();
        self.lost_queue_head = 0;
    }

    const ResendOutcome = enum { sent, retry, dropped };

    /// Resend one lost plaintext under a fresh packet number at the same
    /// encryption level. Initial keeps its type/CIDs, Handshake keeps its
    /// type/CIDs, and application data becomes 1-RTT.
    fn resendLostPayload(self: *Connection, lost: LostPayload) ResendOutcome {
        const packet_type: Packet.PacketType = switch (lost.level) {
            0 => .initial,
            2 => .handshake,
            3 => .one_rtt,
            else => {
                lost.deinit(self.allocator);
                return .dropped;
            },
        };
        if (lost.payload.len == 0) {
            lost.deinit(self.allocator);
            return .dropped;
        }
        const dest = self.destinationCid(lost.level);
        if (dest.len == 0) {
            self.requeueLostPayload(lost);
            return .retry;
        }
        const src: []const u8 = if (packet_type == .one_rtt) &.{} else self.local_cid[0..self.local_cid_len];
        const packet_number = self.packet_crypto.nextPacketNumberForLevel(switch (lost.level) {
            0 => .initial,
            2 => .handshake,
            else => .application,
        });
        if (self.qlog) |writer| {
            if (writer.sampleLost()) writer.packetLost(
                nowMicros(),
                lost.packet_number,
                @intCast(lost.level),
                lost.payload.len,
            );
        }
        const send_result = switch (lost.level) {
            0 => self.quic.super_connection.sendProtectedRawPacket(
                &self.packet_crypto,
                .initial,
                packet_type,
                dest,
                src,
                lost.payload,
            ),
            2 => self.quic.super_connection.sendProtectedRawPacket(
                &self.packet_crypto,
                .handshake,
                packet_type,
                dest,
                src,
                lost.payload,
            ),
            else => self.quic.super_connection.sendProtectedRawPacket(
                &self.packet_crypto,
                .application,
                packet_type,
                dest,
                src,
                lost.payload,
            ),
        };
        send_result catch {
            self.requeueLostPayload(lost);
            return .retry;
        };
        if (self.qlog_pending) |pending| pending.push(.{
            .packet_number = packet_number,
            .level = @intCast(lost.level),
            .ptype = qlogPacketType(packet_type),
            .ack_eliciting = true,
            .plaintext_len = @intCast(lost.payload.len),
            .frames = .{},
        });
        test_retransmit_count +|= 1;
        self.stats.retransmits +|= 1;
        self.captureRetransmit(lost, packet_number);
        lost.deinit(self.allocator);
        return .sent;
    }

    fn requeueLostPayload(self: *Connection, lost: LostPayload) void {
        if (self.retainedLostPayloads() >= max_lost_payloads_retained) {
            var oldest = self.lost_queue.items[self.lost_queue_head];
            oldest.deinit(self.allocator);
            self.lost_queue_head += 1;
        }
        self.lost_queue.append(self.allocator, lost) catch {
            var dropped = lost;
            dropped.deinit(self.allocator);
        };
    }

    fn captureRetransmit(self: *Connection, lost: LostPayload, new_packet_number: u64) void {
        if (!test_capture_retransmit_payload) return;
        // Tests need the STREAM-carrying resend, not whichever control frame
        // happened to be drained last in the same service pass.
        if (!self.payloadHasStreamFrame(lost.payload)) return;
        const copy_len = @min(lost.payload.len, test_retransmit_last_payload.len);
        @memcpy(test_retransmit_last_payload[0..copy_len], lost.payload[0..copy_len]);
        test_retransmit_last_payload_len = copy_len;
        test_retransmit_last_old_packet_number = lost.packet_number;
        test_retransmit_last_new_packet_number = new_packet_number;
        test_retransmit_last_level = lost.level;
    }

    fn payloadHasStreamFrame(self: *Connection, payload: []const u8) bool {
        var reader = std.Io.Reader.fixed(payload);
        while (reader.seek < reader.end) {
            var frame = QuicFrames.Frame.parse(&reader, self.allocator) catch return false;
            defer frame.deinit(self.allocator);
            switch (frame) {
                .stream,
                .stream_fin,
                .stream_len,
                .stream_len_fin,
                .stream_off,
                .stream_off_fin,
                .stream_off_len,
                .stream_off_len_fin,
                => return true,
                else => {},
            }
        }
        return false;
    }

    /// Drain at most max_retransmits_per_service queued losses. Entries that
    /// fail to send stay queued for the next pass.
    fn resendLostPayloads(self: *Connection) void {
        const drain_end = self.lost_queue.items.len;
        const now = nowMicros();
        // Production keeps the brief grace window. The synthetic loss hook is
        // an explicit test signal, so it drains as soon as zquic reports the
        // loss (the old force-retransmit hook had the same effect).
        const grace_us: u64 = if (self.drop_outgoing_every != 0) 0 else lost_payload_grace_us;
        var attempted: usize = 0;
        while (self.lost_queue_head < drain_end and attempted < max_retransmits_per_service) {
            const lost = self.lost_queue.items[self.lost_queue_head];
            if (now -| lost.detected_us < grace_us) break;
            self.lost_queue_head += 1;
            attempted += 1;
            switch (self.resendLostPayload(lost)) {
                .sent, .dropped => {},
                .retry => {}, // resendLostPayload already requeued it
            }
        }
        self.compactLostQueue();
    }

    fn destinationCid(self: *const Connection, level: usize) []const u8 {
        if (self.peer_cid_len > 0) return self.peer_cid[0..self.peer_cid_len];
        if (level == 0 and self.original_dcid_len > 0) return self.original_dcid[0..self.original_dcid_len];
        return &.{};
    }

    fn flush(self: *Connection) !void {
        const packets = self.quic.super_connection.drainOutgoingRawPackets(self.allocator) catch return error.QuicError;
        defer self.allocator.free(packets);
        const pending_log = self.qlog_pending;
        const drop_log_batch = if (pending_log) |pending| pending.overflow else false;
        for (packets) |*packet| {
            defer packet.deinit(self.allocator);
            if (packet.data.len == 0) continue;
            self.tx_count += 1;
            if (self.drop_outgoing_every != 0 and self.tx_count % self.drop_outgoing_every == 0) {
                // A test drop never reaches the peer. zquic already recorded
                // the packet when it was scheduled, so its loss detector (and
                // PTO probes after a tail loss) recovers it.
                if (pending_log) |pending| _ = pending.pop();
                continue;
            }
            const sent = posix.system.sendto(
                self.socket,
                packet.data.ptr,
                @intCast(packet.data.len),
                0,
                @ptrCast(&self.remote_addr),
                @sizeOf(posix.sockaddr.in),
            );
            if (pending_log) |pending| {
                if (pending.pop()) |entry| {
                    if (!drop_log_batch and sent >= 0) {
                        if (self.qlog) |writer| {
                            if (writer.sampleSent()) writer.packetSent(
                                nowMicros(),
                                entry.packet_number,
                                entry.level,
                                entry.ptype,
                                entry.ack_eliciting,
                                entry.plaintext_len,
                                entry.frames,
                            );
                        }
                    }
                }
            }
            if (sent < 0) continue;
            self.stats.packets_sent +|= 1;
            self.stats.bytes_sent +|= @intCast(packet.data.len);
        }
        if (pending_log) |pending| pending.reset();
    }

    /// Deliver anything queued and consume the ACK/recovery work zquic owns.
    pub fn service(self: *Connection) !void {
        if (self.closed) return;
        try self.afterTlsProgress();

        // zquic owns loss detection. Poll first so this pass sees the freshest
        // callback queue, then resend each lost payload under a new packet
        // number. PTO probes are still zquic's; ACK generation stays below in
        // the transport for this milestone.
        const recovery_now: u64 = @intCast(@max(zquic.Time.nowMicros(), 0));
        _ = self.quic.super_connection.pollLossRecovery(
            &self.packet_crypto,
            recovery_now,
            self.destinationCid(0),
            self.local_cid[0..self.local_cid_len],
        ) catch {};
        self.resendLostPayloads();

        // Gather ACK/flow/stream-limit control frames once, coalesce them into
        // the first data packet where they fit, and send any remainder on its
        // own. Committing happens only on successful scheduling, so the same
        // frame cannot appear in a later packet of this pass.
        var control: ControlBatch = .{};
        defer control.deinit(self.allocator);
        try self.collectControlFrames(&control);

        try self.flushStreams(&control);
        try self.finishControlFrames(&control);
        self.reapFinishedStreams();

        try self.sendAcks();
        try self.flush();
    }

    /// ACKs for the Initial and Handshake levels stay standalone; 1-RTT ACKs
    /// are collected into ControlBatch and may share a packet with STREAM data.
    fn sendAcks(self: *Connection) !void {
        for ([_]usize{ 0, 2 }) |level| {
            if (!self.acks[level].ack_required or self.acks[level].count == 0) continue;
            if (level == 2 and !self.handshake_keys) continue;
            var ack_frame = self.acks[level].buildFrame(self.allocator) catch continue;
            defer ack_frame.deinit(self.allocator);
            const ptype: Packet.PacketType = if (level == 0) .initial else .handshake;
            const frame = [_]QuicFrames.Frame{.{ .ack = ack_frame }};
            self.schedule(level, ptype, &frame) catch continue;
            self.stats.ack_frames_sent +|= 1;
            self.acks[level].clear();
        }
    }

    pub fn close(self: *Connection, code: u64, reason: []const u8) void {
        if (self.closed or self.closing) return;
        self.closing = true;
        self.close_code = code;
        const level: usize = if (self.application_keys) 3 else if (self.handshake_keys) 2 else 0;
        const ptype: Packet.PacketType = switch (level) {
            0 => .initial,
            2 => .handshake,
            else => .one_rtt,
        };
        const frame = [_]QuicFrames.Frame{
            .{ .connection_close_app = QuicFrames.ConnectionCloseAppFrame.init(code, reason) },
        };
        self.schedule(level, ptype, &frame) catch {};
        self.flush() catch {};
        self.closed = true;
        if (self.qlog) |writer| {
            const now = nowMicros();
            if (code != 0x0100) writer.errorEvent(now, code, reason);
            writer.connectionClosed(now, .local, code, reason, qlog.ConnectionStats.from(self.stats));
        }
    }

    pub fn timeoutNs(self: *const Connection) u64 {
        if (self.closed) return std.time.ns_per_s;
        const deadline = self.handshake_started_us + handshake_timeout_ns / 1000;
        const now = nowMicros();
        if (!self.established) {
            if (now >= deadline) return 0;
            return (deadline - now) * 1000;
        }
        return 10 * std.time.ns_per_ms;
    }
};

/// UDP listener that routes datagrams by destination connection ID.
pub const Listener = struct {
    allocator: std.mem.Allocator,
    socket: posix.fd_t,
    local_addr: posix.sockaddr.in,
    connections: std.StringHashMap(*Connection),
    key_cids: std.ArrayListUnmanaged([]u8) = .empty,
    /// Counters of connections already reaped and freed. Server.stats adds
    /// these to the live sum so closed connections are not lost.
    closed_stats: Stats = .{},
    /// Installed on each accepted connection before its first datagram runs.
    handler: ?Handler = null,
    /// Called once per accepted connection, before its first datagram. The
    /// HTTP/3 server uses this to install a session before any stream frame or
    /// handshake-completion callback can arrive.
    on_connection: ?ConnectionHook = null,
    /// Receive flow-control windows advertised by accepted connections.
    local_max_data: u64 = default_flow_window,
    local_max_stream_data: u64 = default_flow_window,
    /// When enabled, tokenless Initials get an HMAC Retry before any
    /// Connection/Session is allocated.
    retry_enabled: bool = false,
    retry_key: [32]u8 = undefined,
    /// Set by Server.initInternal from Server.Options.qlog before any
    /// connection can be accepted. The listener owns the stream header and the
    /// Retry events; each Connection owns its own writer.
    qlog: ?qlog.Config = null,
    qlog_reference: qlog.Reference = .{},
    qlog_header_written: bool = false,

    pub fn enableRetry(self: *Listener) void {
        if (self.retry_enabled) return;
        qtls.fillRandom(&self.retry_key);
        self.retry_enabled = true;
    }

    /// Install the listener qlog sink and write the JSON-SEQ stream header
    /// immediately. Must run before the listener accepts its first datagram.
    pub fn installQlog(self: *Listener, config: qlog.Config) void {
        self.qlog = config;
        self.qlog_reference = qlog.Reference.now();
        self.qlog_header_written = false;
        self.ensureQlogHeader();
    }

    fn ensureQlogHeader(self: *Listener) void {
        const config = self.qlog orelse return;
        if (self.qlog_header_written) return;
        if (self.qlog_reference.wall_ms == 0) self.qlog_reference = qlog.Reference.now();
        var writer = qlog.Writer.init(config, self.qlog_reference);
        writer.writeHeader(.server);
        self.qlog_header_written = true;
    }

    fn qlogRetrySent(self: *Listener) void {
        const config = self.qlog orelse return;
        var writer = qlog.Writer.init(config, self.qlog_reference);
        writer.retrySent(nowMicros());
    }

    fn qlogRetryRejected(self: *Listener, reason: []const u8) void {
        const config = self.qlog orelse return;
        var writer = qlog.Writer.init(config, self.qlog_reference);
        writer.retryRejected(nowMicros(), reason);
    }

    pub fn init(allocator: std.mem.Allocator, port: u16) !Listener {
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

        return .{
            .allocator = allocator,
            .socket = socket,
            .local_addr = addr,
            .connections = std.StringHashMap(*Connection).init(allocator),
        };
    }

    pub fn deinit(self: *Listener) void {
        var seen = std.AutoHashMap(*Connection, void).init(self.allocator);
        defer seen.deinit();
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            const connection = entry.value_ptr.*;
            if (seen.contains(connection)) continue;
            // On OOM, leave the connection rather than deinitialising the same
            // pointer twice; leaking during teardown is the safer failure.
            seen.put(connection, {}) catch continue;
            connection.deinit();
        }
        self.connections.deinit();
        for (self.key_cids.items) |key| self.allocator.free(key);
        self.key_cids.deinit(self.allocator);
        closeSocket(self.socket);
    }

    pub fn pollReadable(self: *Listener, timeout_ns: u64) bool {
        const wait = @min(timeout_ns, std.time.ns_per_s);
        const timeout_ms: i32 = @intCast((wait + std.time.ns_per_ms - 1) / std.time.ns_per_ms);
        var fds = [_]posix.pollfd{.{ .fd = self.socket, .events = posix.POLL.IN, .revents = 0 }};
        const ready = posix.poll(&fds, timeout_ms) catch return false;
        return ready > 0 and (fds[0].revents & posix.POLL.IN) != 0;
    }

    pub fn readAndDispatch(self: *Listener, buf: []u8, max_datagrams: usize) usize {
        var handled: usize = 0;
        while (handled < max_datagrams) : (handled += 1) {
            var peer: posix.sockaddr.in = undefined;
            var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const n = std.c.recvfrom(
                self.socket,
                buf.ptr,
                buf.len,
                std.c.MSG.DONTWAIT,
                @ptrCast(&peer),
                &peer_len,
            );
            if (n <= 0) break;
            self.dispatch(buf[0..@intCast(n)], peer) catch {};
        }
        return handled;
    }

    pub fn dispatch(self: *Listener, datagram: []const u8, peer: posix.sockaddr.in) !void {
        self.ensureQlogHeader();
        if (datagram.len < 1) return;
        const dcid = destinationCid(datagram) orelse return;
        if (self.connections.get(dcid)) |connection| {
            try connection.handleDatagram(datagram);
            return;
        }
        if ((datagram[0] & 0x80) == 0) return;
        const header = Packet.PacketHeader.parse(datagram, self.allocator) catch return;
        if (header.packet_type != .initial) return;
        if (header.version) |version| {
            if (version != 1) return;
        }
        const scid = header.src_conn_id orelse return;
        if (scid.bytes().len == 0) return;
        if (header.dest_conn_id.bytes().len < cid_len) return;

        var original_dcid: [20]u8 = @splat(0);
        var original_dcid_len: u8 = 0;
        var retry_scid: [20]u8 = @splat(0);
        var retry_scid_len: u8 = 0;
        if (self.retry_enabled) {
            if (datagram.len < 1200) {
                self.qlogRetryRejected("short_initial");
                return;
            }
            var address: [6]u8 = undefined;
            @memcpy(address[0..4], std.mem.asBytes(&peer.addr));
            @memcpy(address[4..6], std.mem.asBytes(&peer.port));
            const token = header.token orelse &.{};
            var retry_impl = retry.Retry{ .key = self.retry_key };
            if (token.len == 0) {
                const fresh = try randomCid();
                var token_buf: [retry.max_token_len]u8 = undefined;
                const made = retry_impl.makeToken(
                    header.dest_conn_id.bytes(),
                    &address,
                    fresh[0..cid_len],
                    scid.bytes(),
                    nowMicros(),
                    &token_buf,
                ) catch {
                    self.qlogRetryRejected("token_error");
                    return;
                };
                var packet_buf: [retry.max_retry_packet_len]u8 = undefined;
                const packet = retry.Retry.buildPacket(
                    header.dest_conn_id.bytes(),
                    scid.bytes(),
                    fresh[0..cid_len],
                    made,
                    &packet_buf,
                ) catch {
                    self.qlogRetryRejected("retry_build_failed");
                    return;
                };
                const sent = posix.system.sendto(
                    self.socket,
                    packet.ptr,
                    @intCast(packet.len),
                    0,
                    @ptrCast(&peer),
                    @sizeOf(posix.sockaddr.in),
                );
                if (sent >= 0) self.qlogRetrySent() else self.qlogRetryRejected("send_failed");
                return;
            }
            const verified = retry_impl.verifyToken(
                token,
                &address,
                header.dest_conn_id.bytes(),
                scid.bytes(),
                nowMicros(),
            ) orelse {
                self.qlogRetryRejected("invalid_token");
                return;
            };
            const len = token[15];
            original_dcid = verified;
            original_dcid_len = len;
            retry_scid = @splat(0);
            @memcpy(retry_scid[0..cid_len], header.dest_conn_id.bytes()[0..cid_len]);
            retry_scid_len = cid_len;
        } else {
            original_dcid = @splat(0);
            @memcpy(original_dcid[0..cid_len], header.dest_conn_id.bytes()[0..cid_len]);
            original_dcid_len = cid_len;
        }

        const initial_dcid = header.dest_conn_id.bytes();
        const connection = try Connection.initServerWithQlog(
            self.allocator,
            self.socket,
            self.local_addr,
            peer,
            initial_dcid,
            original_dcid[0..original_dcid_len],
            scid.bytes(),
            retry_scid[0..retry_scid_len],
            self.local_max_data,
            self.local_max_stream_data,
            self.qlog,
            self.qlog_reference,
        );
        errdefer connection.deinit();
        connection.handler = self.handler;
        try self.addConnection(connection);
        if (self.on_connection) |hook| hook.callback(hook.context, connection);
        try connection.handleDatagram(datagram);
    }

    fn addConnection(self: *Listener, connection: *Connection) !void {
        // After Retry the old ODCID must not route into the new connection;
        // the retry SCID (local_cid) is the only accepted key.
        if (connection.retry_scid_len == 0) {
            try self.addKey(connection.original_dcid[0..connection.original_dcid_len], connection);
        }
        try self.addKey(connection.local_cid[0..connection.local_cid_len], connection);
    }

    fn addKey(self: *Listener, cid: []const u8, connection: *Connection) !void {
        if (cid.len == 0) return;
        if (self.connections.contains(cid)) return;
        const key = try self.allocator.dupe(u8, cid);
        errdefer self.allocator.free(key);
        try self.connections.put(key, connection);
        try self.key_cids.append(self.allocator, key);
    }

    pub fn serviceAll(self: *Listener) void {
        var it = self.connections.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.isClosed()) continue;
            entry.value_ptr.*.service() catch {};
        }
    }

    /// Remove and free connections that closed since the last pass. A
    /// connection owns two CID keys, so all of them must leave the map before
    /// the Connection itself is released.
    pub fn reapClosed(self: *Listener) void {
        var closed: std.ArrayListUnmanaged(*Connection) = .empty;
        defer closed.deinit(self.allocator);
        var keys: std.ArrayListUnmanaged([]const u8) = .empty;
        defer keys.deinit(self.allocator);
        var seen = std.AutoHashMap(*Connection, void).init(self.allocator);
        defer seen.deinit();

        var it = self.connections.iterator();
        while (it.next()) |entry| {
            const connection = entry.value_ptr.*;
            if (!connection.isClosed()) continue;
            keys.append(self.allocator, entry.key_ptr.*) catch return;
            if (seen.contains(connection)) continue;
            seen.put(connection, {}) catch return;
            closed.append(self.allocator, connection) catch return;
        }
        if (closed.items.len == 0) return;

        for (keys.items) |key| {
            _ = self.connections.fetchRemove(key);
            for (self.key_cids.items, 0..) |cid, index| {
                if (cid.ptr == key.ptr and cid.len == key.len) {
                    _ = self.key_cids.swapRemove(index);
                    break;
                }
            }
            self.allocator.free(key);
        }
        for (closed.items) |connection| {
            self.closed_stats.add(connection.statsSnapshot());
            connection.deinit();
        }
    }

    /// Sum the counters of live connections. A connection is normally reachable
    /// under two CIDs, so duplicate keys are skipped. Like count(), this walks
    /// the listener map and must run from the listener's thread or after it
    /// stops.
    pub fn stats(self: *const Listener) Stats {
        var total: Stats = .{};
        for (self.key_cids.items, 0..) |cid, index| {
            const connection = self.connections.get(cid) orelse continue;
            var already_counted = false;
            for (self.key_cids.items[0..index]) |previous| {
                const other = self.connections.get(previous) orelse continue;
                if (other == connection) {
                    already_counted = true;
                    break;
                }
            }
            if (!already_counted) total.add(connection.statsSnapshot());
        }
        return total;
    }

    /// Live connections plus the counters retained for already-reaped ones.
    pub fn totalStats(self: *const Listener) Stats {
        var total = self.stats();
        total.add(self.closed_stats);
        return total;
    }

    pub fn count(self: *const Listener) usize {
        var seen = std.AutoHashMap(*Connection, void).init(self.allocator);
        defer seen.deinit();
        var it = self.connections.valueIterator();
        while (it.next()) |conn| seen.put(conn.*, {}) catch {};
        return seen.count();
    }
};

pub fn connect(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    options: ClientTls,
) !*Connection {
    return connectWithQlog(allocator, host, port, options, null);
}

pub fn connectWithQlog(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    options: ClientTls,
    qlog_config: ?qlog.Config,
) !*Connection {
    const connection = try Connection.initWithQlog(allocator, host, port, options, qlog_config);
    errdefer connection.deinit();

    var buf: [max_datagram_size]u8 = undefined;
    const deadline = nowNanos() + handshake_timeout_ns;
    while (!connection.isEstablished()) {
        if (connection.isClosed()) return error.ConnectionClosed;
        if (nowNanos() >= deadline) return error.Timeout;
        connection.service() catch {};
        const timeout_ns = @as(u64, 10 * std.time.ns_per_ms);
        var fds = [_]posix.pollfd{.{ .fd = connection.socket, .events = posix.POLL.IN, .revents = 0 }};
        const timeout_ms: i32 = @intCast((timeout_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms);
        const ready = posix.poll(&fds, timeout_ms) catch 0;
        if (ready > 0 and (fds[0].revents & posix.POLL.IN) != 0) {
            var peer: posix.sockaddr.in = undefined;
            var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const n = std.c.recvfrom(
                connection.socket,
                buf[0..].ptr,
                buf.len,
                0,
                @ptrCast(&peer),
                &peer_len,
            );
            if (n > 0) connection.handleDatagram(buf[0..@intCast(n)]) catch {};
        }
    }
    return connection;
}

fn createSocket() !posix.fd_t {
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

fn closeSocket(socket: posix.fd_t) void {
    _ = posix.system.close(socket);
}

fn randomCid() ![20]u8 {
    var out: [20]u8 = @splat(0);
    qtls.fillRandom(out[0..cid_len]);
    return out;
}

fn resolveAddress(host: []const u8, port: u16) !posix.sockaddr.in {
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

fn destinationCid(datagram: []const u8) ?[]const u8 {
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
fn nextPacket(datagram: []const u8, start: usize) ?[]const u8 {
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

fn levelIndexForPacketType(packet_type: Packet.PacketType) usize {
    return switch (packet_type) {
        .initial, .retry, .version_negotiation => 0,
        .zero_rtt => 1,
        .handshake => 2,
        .one_rtt => 3,
    };
}

fn tlsLevel(level: anytype) usize {
    return switch (level) {
        .initial => 0,
        .early_data => 1,
        .handshake => 2,
        .application => 3,
    };
}

test "native transport: handshake and one stream" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var listener = try Listener.init(allocator, 0);
    defer listener.deinit();

    const Received = struct {
        bytes: std.ArrayListUnmanaged(u8) = .empty,
        fin: bool = false,
        fn onStream(
            context: *anyopaque,
            stream_id: u64,
            offset: u64,
            data: []const u8,
            fin: bool,
        ) anyerror!void {
            _ = stream_id;
            _ = offset;
            const self: *@This() = @ptrCast(@alignCast(context));
            try self.bytes.appendSlice(std.heap.page_allocator, data);
            if (fin) self.fin = true;
        }
        fn onEstablished(_: *anyopaque) anyerror!void {}
        fn onClosed(_: *anyopaque, _: u64) void {}
    };
    var received: Received = .{};
    defer received.bytes.deinit(std.heap.page_allocator);
    listener.handler = .{
        .context = &received,
        .on_stream_frame = Received.onStream,
        .on_established = Received.onEstablished,
        .on_closed = Received.onClosed,
    };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client = try Connection.initClient(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    var buf: [max_datagram_size]u8 = undefined;
    const deadline = nowNanos() + 10 * std.time.ns_per_s;
    var stream_id: ?u64 = null;
    while (nowNanos() < deadline) {
        client.service() catch {};
        _ = listener.readAndDispatch(&buf, 8);
        listener.serviceAll();

        var peer: posix.sockaddr.in = undefined;
        var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        const n = std.c.recvfrom(client.socket, buf[0..].ptr, buf.len, std.c.MSG.DONTWAIT, @ptrCast(&peer), &peer_len);
        if (n > 0) {
            client.handleDatagram(buf[0..@intCast(n)]) catch {};
        }

        if (client.isEstablished() and received.fin) break;
        if (client.isEstablished() and stream_id == null) {
            stream_id = try client.createBidiStream();
            try client.queueStreamData(stream_id.?, "hello", true);
        }
        sleepNs(std.time.ns_per_ms);
    }

    try std.testing.expect(client.isEstablished());
    try std.testing.expect(received.fin);
    try std.testing.expectEqualStrings("hello", received.bytes.items);

    // A closed connection must leave the CID map, not accumulate until
    // Listener.deinit.
    try std.testing.expectEqual(@as(usize, 1), listener.count());
    client.close(0x0100, "done");
    for (0..200) |_| {
        _ = listener.readAndDispatch(&buf, 8);
        listener.serviceAll();
        listener.reapClosed();
        if (listener.count() == 0) break;
        sleepNs(std.time.ns_per_ms);
    }
    try std.testing.expectEqual(@as(usize, 0), listener.count());
}

test {
    _ = @import("reassembly.zig");
    _ = @import("ack.zig");
    _ = @import("recovery.zig");
    _ = @import("retry.zig");
}

test "native transport: ACK ranges cover sent packet numbers" {
    const ranges = [_]QuicFrames.AckFrame.AckRange{
        .{ .gap = 0, .ack_range_length = 0 }, // adds 6
        .{ .gap = 1, .ack_range_length = 1 }, // adds 2..3
    };
    const frame = QuicFrames.AckFrame{
        .largest_acknowledged = 10,
        .ack_delay = 0,
        .ack_range_count = 2,
        .first_ack_range = 2, // 8..10
        .ack_ranges = @constCast(&ranges),
    };
    try std.testing.expect(ack.covers(&frame, 10));
    try std.testing.expect(ack.covers(&frame, 8));
    try std.testing.expect(!ack.covers(&frame, 7));
    try std.testing.expect(ack.covers(&frame, 6));
    try std.testing.expect(!ack.covers(&frame, 5));
    try std.testing.expect(ack.covers(&frame, 3));
    try std.testing.expect(ack.covers(&frame, 2));
    try std.testing.expect(!ack.covers(&frame, 1));
}

test "native transport: upload resumes after MAX_DATA" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var listener = try Listener.init(allocator, 0);
    defer listener.deinit();
    listener.local_max_data = 16 * 1024;
    listener.local_max_stream_data = 16 * 1024;

    const Received = struct {
        bytes: std.ArrayListUnmanaged(u8) = .empty,
        fin: bool = false,
        fn onStream(
            context: *anyopaque,
            stream_id: u64,
            offset: u64,
            data: []const u8,
            fin: bool,
        ) anyerror!void {
            _ = stream_id;
            _ = offset;
            const self: *@This() = @ptrCast(@alignCast(context));
            try self.bytes.appendSlice(std.heap.page_allocator, data);
            if (fin) self.fin = true;
        }
        fn onEstablished(_: *anyopaque) anyerror!void {}
        fn onClosed(_: *anyopaque, _: u64) void {}
    };
    var received: Received = .{};
    defer received.bytes.deinit(std.heap.page_allocator);
    listener.handler = .{
        .context = &received,
        .on_stream_frame = Received.onStream,
        .on_established = Received.onEstablished,
        .on_closed = Received.onClosed,
    };

    const port = std.mem.bigToNative(u16, listener.local_addr.port);
    const client = try Connection.initClient(allocator, "127.0.0.1", port, .{ .insecure_skip_verify = true });
    defer client.deinit();

    const payload = try std.heap.page_allocator.alloc(u8, 64 * 1024);
    defer std.heap.page_allocator.free(payload);
    @memset(payload, 'z');

    var buf: [max_datagram_size]u8 = undefined;
    const deadline = nowNanos() + 12 * std.time.ns_per_s;
    var stream_id: ?u64 = null;
    const before_data = test_max_data_sent;
    const before_stream = test_max_stream_data_sent;

    while (nowNanos() < deadline) {
        client.service() catch {};
        _ = listener.readAndDispatch(&buf, 8);
        listener.serviceAll();

        var peer: posix.sockaddr.in = undefined;
        var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        const n = std.c.recvfrom(client.socket, buf[0..].ptr, buf.len, std.c.MSG.DONTWAIT, @ptrCast(&peer), &peer_len);
        if (n > 0) client.handleDatagram(buf[0..@intCast(n)]) catch {};

        if (client.isEstablished() and stream_id == null) {
            stream_id = try client.createBidiStream();
            try client.queueStreamData(stream_id.?, payload, true);
        }
        if (received.fin) break;
        sleepNs(std.time.ns_per_ms);
    }

    try std.testing.expect(received.fin);
    try std.testing.expectEqual(payload.len, received.bytes.items.len);
    try std.testing.expect(test_max_data_sent > before_data);
    try std.testing.expect(test_max_stream_data_sent > before_stream);
}

fn putTestInitial(dst: []u8, dcid: []const u8, scid: []const u8, token: []const u8) void {
    @memset(dst, 0);
    dst[0] = 0xc0; // long header, fixed bit, Initial
    std.mem.writeInt(u32, dst[1..5], 0x00000001, .big);
    dst[5] = @intCast(dcid.len);
    @memcpy(dst[6 .. 6 + dcid.len], dcid);
    var pos: usize = 6 + dcid.len;
    dst[pos] = @intCast(scid.len);
    pos += 1;
    @memcpy(dst[pos .. pos + scid.len], scid);
    pos += scid.len;
    dst[pos] = @intCast(token.len);
    pos += 1;
    @memcpy(dst[pos .. pos + token.len], token);
}

test "native transport: Retry challenges before allocating a connection" {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try qtls.setServerCert(@embedFile("../test_cert.pem"), @embedFile("../test_key.pem"));
    defer qtls.deinitServer();

    var listener = try Listener.init(allocator, 0);
    defer listener.deinit();
    listener.enableRetry();

    const Hook = struct {
        count: usize = 0,
        fn onConnection(context: *anyopaque, _: *Connection) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.count += 1;
        }
    };
    var hook: Hook = .{};
    listener.on_connection = .{ .context = &hook, .callback = Hook.onConnection };

    const client_fd = try createSocket();
    defer closeSocket(client_fd);
    var client_addr = posix.sockaddr.in{ .family = posix.AF.INET, .port = 0, .addr = std.mem.nativeToBig(u32, 0x7f000001), .zero = @splat(0) };
    if (posix.system.bind(client_fd, @ptrCast(&client_addr), @sizeOf(posix.sockaddr.in)) < 0) return error.QuicError;
    var client_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    if (posix.system.getsockname(client_fd, @ptrCast(&client_addr), &client_len) < 0) return error.QuicError;

    const client_scid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const original_dcid = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };
    var first: [1200]u8 = undefined;
    putTestInitial(&first, &original_dcid, &client_scid, &.{});
    try listener.dispatch(&first, client_addr);
    try std.testing.expectEqual(@as(usize, 0), listener.count());
    try std.testing.expectEqual(@as(usize, 0), hook.count);

    var retry_buf: [1200]u8 = undefined;
    var n: isize = -1;
    for (0..100) |_| {
        n = std.c.recvfrom(client_fd, &retry_buf, retry_buf.len, std.c.MSG.DONTWAIT, null, null);
        if (n > 0) break;
        sleepNs(std.time.ns_per_ms);
    }
    try std.testing.expect(n > 0);
    var retry_packet = try Packet.RetryPacket.parse(retry_buf[0..@intCast(n)], allocator);
    try std.testing.expect(retry_packet.token.len > 0);

    var second: [1200]u8 = undefined;
    putTestInitial(&second, retry_packet.src_conn_id.bytes(), &client_scid, retry_packet.token);
    try listener.dispatch(&second, client_addr);

    try std.testing.expectEqual(@as(usize, 1), listener.count());
    try std.testing.expectEqual(@as(usize, 1), hook.count);
}
