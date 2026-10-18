//! QUIC transport for the native HTTP/3 stack.
//!
//! zquic supplies packet protection, packet-number spaces, loss-recovery
//! timers, stream IDs, and frame encoding. This file keeps its own ACK ranges
//! because it decrypts packets before handing the surviving frames to zquic. OpenSSL supplies the
//! TLS 1.3 handshake through its QUIC-TLS callback interface. packet_io.zig
//! supplies the UDP socket and datagram seam; this file feeds CRYPTO frames to
//! TLS, installs the RFC 9001 keys TLS yields, schedules packets, tracks ACKs,
//! drives recovery, and dispatches STREAM frames to the HTTP/3 layer.

const std = @import("std");
const posix = std.posix;
const zquic = @import("zquic");
const qtls = @import("qtls.zig");
const ack = @import("ack.zig");
const retry = @import("retry.zig");
const stats = @import("stats.zig");
const qlog = @import("qlog.zig");
const flow_control = @import("flow_control.zig");
const stream_table = @import("stream_table.zig");
const crypto_stream = @import("crypto_stream.zig");
const packet_io = @import("packet_io.zig");

/// Re-exported so callers can name a snapshot without importing stats.zig.
pub const Stats = stats.Stats;

const FlowControl = flow_control.FlowControl;

const Packet = zquic.Packet;
const OwnedRawPacket = zquic.Connection.OwnedRawPacket;
const QuicFrames = zquic.core.QuicFrames;
const TransportParametersMod = zquic.core.TransportParameters;
const TransportParameters = TransportParametersMod.TransportParameters;
const NegotiationContext = TransportParametersMod.NegotiationContext;

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

pub const cid_len = packet_io.cid_len;
pub const max_datagram_size = packet_io.max_datagram_size;
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

/// Adapts ControlBatch to stream_table.ControlBatch. StreamTable learns only
/// whether controls are pending, their serialized size, and how to append,
/// send, or commit them; frame collection and commit stay in this file.
const ControlBatchBridge = struct {
    connection: *Connection,
    batch: *ControlBatch,

    const vtable: stream_table.ControlBatch.VTable = .{
        .isPending = isPending,
        .payloadLen = payloadLen,
        .appendFrames = appendFrames,
        .sendStandalone = sendStandalone,
        .commitCoalesced = commitCoalesced,
    };

    fn interface(self: *ControlBatchBridge) stream_table.ControlBatch {
        return .{ .context = self, .vtable = &vtable };
    }

    fn isPending(raw: *anyopaque) bool {
        const self: *ControlBatchBridge = @ptrCast(@alignCast(raw));
        return !self.batch.sent and self.batch.frames.items.len > 0;
    }

    fn payloadLen(raw: *anyopaque, allocator: std.mem.Allocator) anyerror!usize {
        const self: *ControlBatchBridge = @ptrCast(@alignCast(raw));
        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        for (self.batch.frames.items) |frame| {
            frame.serialize(&out.writer) catch return error.OutOfMemory;
        }
        return out.written().len;
    }

    fn appendFrames(
        raw: *anyopaque,
        allocator: std.mem.Allocator,
        frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
    ) anyerror!void {
        const self: *ControlBatchBridge = @ptrCast(@alignCast(raw));
        for (self.batch.frames.items) |frame| try frames.append(allocator, frame);
    }

    fn sendStandalone(raw: *anyopaque, sender: stream_table.Sender) anyerror!void {
        const self: *ControlBatchBridge = @ptrCast(@alignCast(raw));
        try self.connection.sendStandaloneControl(self.batch, sender);
    }

    fn commitCoalesced(raw: *anyopaque) void {
        const self: *ControlBatchBridge = @ptrCast(@alignCast(raw));
        self.connection.countCoalescedControl(self.batch);
        for (self.batch.frames.items) |frame| self.connection.commitControlFrame(frame);
        self.batch.sent = true;
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
/// Test-visible accounting for the owned-plaintext handoff in schedule(). The
/// pointer is only valid while zquic still retains the scheduled packet; tests
/// compare addresses and never dereference it.
pub var test_owned_plaintext_schedules: u64 = 0;
pub var test_owned_ack_eliciting_schedules: u64 = 0;
pub var test_last_owned_plaintext_ptr: ?[*]u8 = null;
pub var test_last_owned_plaintext_len: usize = 0;

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

/// Packet-scheduling adapter for crypto_stream.Sender.
fn scheduleCryptoPacket(
    context: *anyopaque,
    level: usize,
    ptype: Packet.PacketType,
    frames: []const QuicFrames.Frame,
) anyerror!void {
    const self: *Connection = @ptrCast(@alignCast(context));
    return self.schedule(level, ptype, frames);
}

pub const Connection = struct {
    allocator: std.mem.Allocator,
    role: Role,
    socket: posix.fd_t,
    owns_socket: bool,
    /// Destination address, synthetic loss counter, and test drop hook. The fd
    /// itself stays above so socket lifetime has one authority.
    packet_io: packet_io.PacketIo,

    quic: zquic.Connection.Connection,
    /// TLS context, packet protection, CRYPTO reassembly, and RFC 9001 keys.
    crypto: crypto_stream.CryptoStream,

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

    /// RFC 9000 Section 8.1 anti-amplification state. A server may send at
    /// most three times the bytes it has received until the client's address
    /// is validated by an accepted Retry token or a successfully decrypted
    /// Handshake/1-RTT packet. Clients and post-validation servers ignore it.
    address_validated: bool = false,
    bytes_received_unvalidated: u64 = 0,
    bytes_sent_unvalidated: u64 = 0,

    largest_pn: [4]?u64 = .{ null, null, null, null },
    acks: [4]AckState = .{ .{}, .{}, .{}, .{} },
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

    /// Per-stream send buffers, batching, and retired-stream bookkeeping.
    streams: stream_table.StreamTable = .{},
    /// Stream windows, connection windows, and stream-count bookkeeping.
    flow: FlowControl,
    /// Plaintexts zquic declared lost, copied out of its callback and awaiting
    /// a new packet number in service. Bounded; oldest entries are evicted.
    lost_queue: std.ArrayListUnmanaged(LostPayload) = .empty,
    /// Index of the first unread entry in lost_queue. Compaction reclaims the
    /// consumed prefix without shifting on every callback.
    lost_queue_head: usize = 0,
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
        const remote = try packet_io.resolveAddress(host, port);
        const socket = try packet_io.createSocket();
        errdefer packet_io.closeSocket(socket);

        const self = try allocator.create(Connection);
        errdefer allocator.destroy(self);

        const client_cid = try packet_io.randomCid();
        const original_dcid = try packet_io.randomCid();

        self.* = .{
            .allocator = allocator,
            .role = .client,
            .socket = socket,
            .owns_socket = true,
            .packet_io = packet_io.PacketIo.initClient(remote),
            .quic = undefined,
            .crypto = undefined,
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

        const tls = try qtls.Tls.initClient(allocator, host, self.local_params, options);
        self.crypto.attachTls(tls);

        try self.crypto.drive();
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
        } else try packet_io.randomCid();
        self.* = .{
            .allocator = allocator,
            .role = .server,
            .socket = socket,
            .owns_socket = false,
            .packet_io = packet_io.PacketIo.initServer(local_addr, remote_addr),
            .quic = undefined,
            .crypto = undefined,
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

        const tls = try qtls.Tls.initServer(allocator, self.local_params);
        self.crypto.attachTls(tls);
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

    /// Packet-scheduling seam for the CRYPTO state. CRYPTO framing lives in
    /// crypto_stream.zig; packet construction stays here.
    fn cryptoSender(self: *Connection) crypto_stream.Sender {
        return .{ .context = self, .schedule_fn = scheduleCryptoPacket };
    }

    fn initCrypto(self: *Connection, initial_dcid: []const u8) !void {
        try self.crypto.init(self.allocator, self.role == .server, initial_dcid);
        errdefer self.crypto.deinit();

        const role: ConnRole = switch (self.role) {
            .client => .client,
            .server => .server,
        };
        self.quic = try zquic.Connection.Connection.init(self.allocator, role, .{});
        errdefer self.quic.deinit();
        // zquic owns loss detection and names the lost plaintexts; the observer
        // copies each one into this connection's bounded queue. PTO probes stay
        // enabled so a tail loss (no later packet to ACK) still elicits an ACK,
        // which lets zquic's detector surface the original packet.
        self.quic.super_connection.setLostPacketObserver(observeZquicLostPacket, self);
    }

    fn deinitCrypto(self: *Connection) void {
        self.quic.deinit();
        self.crypto.deinit();
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
        self.streams.deinit(self.allocator);
        self.flow.deinit();
        self.clearLostQueue();
        self.lost_queue.deinit(self.allocator);
        self.deinitCrypto();
        if (self.local_params.len > 0) self.allocator.free(self.local_params);
        if (self.owns_socket) packet_io.closeSocket(self.socket);
        self.allocator.destroy(self);
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.established;
    }

    pub fn isClosed(self: *const Connection) bool {
        return self.closed;
    }

    /// Mark the peer address validated, lifting the RFC 9000 Section 8.1
    /// anti-amplification limit. The listener calls this after admitting a
    /// valid Retry token; handlePacket calls it after authenticating a
    /// Handshake or 1-RTT packet. Initial and 0-RTT packets never validate.
    pub fn markAddressValidated(self: *Connection) void {
        self.address_validated = true;
    }

    pub fn isAddressValidated(self: *const Connection) bool {
        return self.address_validated;
    }

    /// Bytes received while the address was unvalidated. Exposed for the
    /// production-safety tests and operational observability.
    pub fn unvalidatedBytesReceived(self: *const Connection) u64 {
        return self.bytes_received_unvalidated;
    }

    pub fn unvalidatedBytesSent(self: *const Connection) u64 {
        return self.bytes_sent_unvalidated;
    }

    /// Return a by-value copy of this connection's counters. No pointer is
    /// exposed and the snapshot stays valid after Connection.deinit.
    pub fn statsSnapshot(self: *const Connection) Stats {
        return self.stats;
    }

    /// Test hook used by the retransmission tests; see PacketIo.drop_outgoing_every.
    pub fn setDropOutgoingEvery(self: *Connection, every: usize) void {
        self.packet_io.setDropOutgoingEvery(every);
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
        // RFC 9000 Section 8.1 counts every UDP datagram carrying a packet
        // received from the unvalidated peer, including its padding.
        if (self.role == .server and !self.address_validated) {
            self.bytes_received_unvalidated +|= @intCast(datagram.len);
        }
        self.last_activity_us = nowMicros();
        var offset: usize = 0;
        while (offset < datagram.len) {
            const packet = packet_io.nextPacket(datagram, offset) orelse break;
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
        var processed = self.crypto.packet_crypto.processProtectedRawPacket(packet, self.largest_pn[idx]) catch return;
        defer processed.deinit(self.allocator);
        self.largest_pn[idx] = processed.packet_number;
        // 0-RTT is not implemented; never let replayable early data reach the
        // HTTP/3 state machine.
        if (processed.encryption_level == .early_data) return;
        // A successfully authenticated Handshake or 1-RTT packet proves the
        // peer owns its address (RFC 9000 Section 8.1). Initial and 0-RTT
        // packets are explicitly not sufficient.
        if (self.role == .server and !self.address_validated) {
            switch (processed.encryption_level) {
                .handshake, .application => self.markAddressValidated(),
                .initial, .early_data => {},
            }
        }

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
                    switch (try self.crypto.feed(tls_level, crypto.offset, crypto.data)) {
                        .skipped => continue,
                        .buffered => {},
                        .advanced => try self.afterTlsProgress(),
                    }
                    ack_eliciting = true;
                },
                .stream, .stream_fin, .stream_len, .stream_len_fin, .stream_off, .stream_off_fin, .stream_off_len, .stream_off_len_fin => |stream| {
                    ack_eliciting = true;
                    rx_has_stream = true;
                    if (self.streams.isStreamClosed(stream.stream_id)) continue;
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
                        self.streams.finishStream(self.streamContext(), stream.stream_id);
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
        try self.retry_token.resize(self.allocator, retry_packet.token.len);
        @memcpy(self.retry_token.items, retry_packet.token);

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
        self.clearLostQueue();
        self.quic.super_connection.discardPacketNumberSpace(.initial);
        self.largest_pn[0] = null;
        self.acks[0] = .{};

        test_retry_accepted += 1;
        try self.crypto.retryInitial(retry_packet.src_conn_id.bytes(), self.retry_token.items, self.cryptoSender());
        try self.flush();
    }

    fn afterTlsProgress(self: *Connection) !void {
        const progress = try self.crypto.progress(self.cryptoSender());

        if (!self.peer_params_applied) {
            if (progress.peer_params) |encoded| self.applyPeerParams(encoded) catch {};
        }

        if (!self.established and progress.finished) {
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
        if (!self.crypto.application_keys) return;
        self.handshake_done_pending = true;
    }

    /// Flow-control/statistics context for the stream table. The table never
    /// receives the Connection itself, only the state it is allowed to touch.
    fn streamContext(self: *Connection) stream_table.Context {
        return .{
            .allocator = self.allocator,
            .stats = &self.stats,
            .flow = &self.flow,
            .local_is_client = self.role == .client,
            .send_blocked = &test_send_blocked,
            .batch_observer = .{ .context = null, .record = recordStreamBatch },
        };
    }

    fn streamSender(self: *Connection) stream_table.Sender {
        return .{ .context = self, .schedule = scheduleStreamPacket };
    }

    fn peerMaxUdpPayload(self: *const Connection) ?u64 {
        return if (self.peer_params) |params| params.max_udp_payload_size else null;
    }

    /// Find or create flow state; a created entry counts toward
    /// Stats.streams_opened. The statistics counter stays with StreamTable.
    fn ensureStreamFlow(self: *Connection, stream_id: u64) !*flow_control.StreamFlow {
        return stream_table.ensureStreamFlow(self.streamContext(), stream_id);
    }

    fn refreshStreamSendLimits(self: *Connection) void {
        self.flow.refreshStreamSendLimits(self.role == .client);
    }

    /// Append stream data and schedule it on the next service pass.
    pub fn queueStreamData(self: *Connection, stream_id: u64, data: []const u8, fin: bool) !void {
        return self.streams.queueStreamData(self.streamContext(), stream_id, data, fin);
    }

    /// Bytes queued for a stream but not yet written to the socket.
    pub fn pendingStreamBytes(self: *const Connection, stream_id: u64) usize {
        return self.streams.pendingStreamBytes(stream_id);
    }

    /// Test-visible copy of one stream's send cursor. The private StreamSend
    /// type stays private; batching tests use this to prove that a failed
    /// schedule advances nothing and a retransmit never advances twice.
    pub const StreamSendSnapshot = stream_table.StreamSendSnapshot;

    pub fn streamSendSnapshot(self: *const Connection, stream_id: u64) ?StreamSendSnapshot {
        return self.streams.streamSendSnapshot(stream_id);
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

    /// Flush TLS handshake output. Chunking, padding, and the Initial replay
    /// cache live in crypto_stream.zig; scheduling stays with the transport.
    fn flushCrypto(self: *Connection) !void {
        try self.crypto.flush(self.cryptoSender());
    }

    /// Serialized size of a control frame this file emits. Only the coalescible
    /// frame types are handled; callers never pass anything else.
    fn controlFrameLen(frame: QuicFrames.Frame) usize {
        return switch (frame) {
            .ack => |ack_frame| blk: {
                var len: usize = 1 +
                    stream_table.varintSize(ack_frame.largest_acknowledged) +
                    stream_table.varintSize(ack_frame.ack_delay) +
                    stream_table.varintSize(ack_frame.ack_range_count) +
                    stream_table.varintSize(ack_frame.first_ack_range);
                for (ack_frame.ack_ranges) |range| {
                    len += stream_table.varintSize(range.gap) + stream_table.varintSize(range.ack_range_length);
                }
                break :blk len;
            },
            .max_data => |max_data| 1 + stream_table.varintSize(max_data.maximum_data),
            .max_stream_data => |max_stream| 1 +
                stream_table.varintSize(max_stream.stream_id) +
                stream_table.varintSize(max_stream.maximum_stream_data),
            .max_streams_bidi, .max_streams_uni => |max_streams| 1 +
                stream_table.varintSize(max_streams.maximum_streams),
            .handshake_done => 1,
            else => 0,
        };
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
    fn sendStandaloneControl(
        self: *Connection,
        control: *ControlBatch,
        sender: stream_table.Sender,
    ) !void {
        var start: usize = 0;
        const limit = stream_table.maxPacketPayload(
            self.peerMaxUdpPayload(),
            self.destinationCid(3).len,
        );
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
            try sender.scheduleFrames(control.frames.items[start..end]);

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
        if (!self.crypto.application_keys or self.closed) return;
        try self.sendStandaloneControl(control, self.streamSender());
    }

    /// Gather the 1-RTT control frame set for this service pass. Nothing is
    /// committed here: ACK ranges stay required, recv limits stay put, and
    /// MAX_STREAMS bookkeeping is untouched until a packet is scheduled.
    fn collectControlFrames(self: *Connection, control: *ControlBatch) !void {
        if (!self.crypto.application_keys or self.closed) return;
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

    /// Thin forwarding wrapper: the batch builder and its transactional commit
    /// live in stream_table.zig. Controls are passed through an opaque interface
    /// so ACK/flow collection and commit stay in this file.
    fn flushStreams(self: *Connection, control: ?*ControlBatch) !void {
        if (!self.crypto.application_keys) return;

        var bridge: ControlBatchBridge = undefined;
        var iface: stream_table.ControlBatch = undefined;
        var table_control: ?*stream_table.ControlBatch = null;
        if (control) |batch| {
            bridge = .{ .connection = self, .batch = batch };
            iface = bridge.interface();
            table_control = &iface;
        }

        const packet_budget = stream_table.maxStreamFramePayload(
            self.peerMaxUdpPayload(),
            self.destinationCid(3).len,
        );
        try self.streams.flushStreams(
            self.streamContext(),
            self.streamSender(),
            table_control,
            packet_budget,
        );
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
        const plaintext_len = payload.written().len;
        if (plaintext_len == 0) return error.QuicError;

        const src: []const u8 = if (ptype == .one_rtt) &.{} else self.local_cid[0..self.local_cid_len];
        const log_packet = self.qlog != null and self.qlog_pending != null;
        var frame_summary: qlog.FrameSummary = .{};
        if (log_packet) {
            for (frames) |frame| summarizeFrame(&frame_summary, frame);
        }
        const packet_number = self.crypto.packet_crypto.nextPacketNumberForLevel(switch (level) {
            0 => .initial,
            2 => .handshake,
            else => .application,
        });
        // Transfer the serialized plaintext to zquic. It becomes the exact
        // allocation SentPacket retains for loss recovery instead of being
        // freed here and copied by sendProtectedRawPacket. toOwnedSlice resets
        // the writer, so the deferred deinit stays a no-op on the success path.
        const plaintext = payload.toOwnedSlice() catch return error.OutOfMemory;
        const plaintext_ptr = plaintext.ptr;
        self.quic.super_connection.sendProtectedRawPacketOwnedPlaintext(
            &self.crypto.packet_crypto,
            switch (level) {
                0 => .initial,
                2 => .handshake,
                else => .application,
            },
            ptype,
            dest,
            src,
            plaintext,
        ) catch return error.QuicError;
        test_owned_plaintext_schedules +|= 1;
        if (ack_eliciting) {
            test_owned_ack_eliciting_schedules +|= 1;
            test_last_owned_plaintext_ptr = plaintext_ptr;
            test_last_owned_plaintext_len = plaintext_len;
        }

        if (log_packet) self.qlog_pending.?.push(.{
            .packet_number = packet_number,
            .level = @intCast(level),
            .ptype = qlogPacketType(ptype),
            .ack_eliciting = ack_eliciting,
            .plaintext_len = @intCast(plaintext_len),
            .frames = frame_summary,
        });

        test_last_scheduled_plaintext_len = plaintext_len;
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
        const packet_number = self.crypto.packet_crypto.nextPacketNumberForLevel(switch (lost.level) {
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
                &self.crypto.packet_crypto,
                .initial,
                packet_type,
                dest,
                src,
                lost.payload,
            ),
            2 => self.quic.super_connection.sendProtectedRawPacket(
                &self.crypto.packet_crypto,
                .handshake,
                packet_type,
                dest,
                src,
                lost.payload,
            ),
            else => self.quic.super_connection.sendProtectedRawPacket(
                &self.crypto.packet_crypto,
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
        const grace_us: u64 = if (self.packet_io.drop_outgoing_every != 0) 0 else lost_payload_grace_us;
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

    /// Largest payload the peer's anti-amplification allowance still permits.
    fn amplificationBudget(self: *const Connection) u64 {
        return self.bytes_received_unvalidated *| 3;
    }

    /// RFC 9000 Section 8.1: a server must not send more than three times the
    /// bytes it has received before validating the client address.
    fn withinAmplificationLimit(self: *const Connection, packet_len: usize) bool {
        if (self.role != .server or self.address_validated) return true;
        const budget = self.amplificationBudget();
        const remaining = budget -| self.bytes_sent_unvalidated;
        return @as(u64, @intCast(packet_len)) <= remaining;
    }

    /// Congestion control applies to ack-eliciting 1-RTT packets. ACK-only
    /// packets do not count in flight, and Initial/Handshake packets are
    /// allowed through so the handshake can make progress and never deadlock
    /// on a window that has not grown yet.
    ///
    /// zquic records a packet in flight when it is scheduled, so bytes that
    /// are still queued are subtracted: the check is about what is actually on
    /// the wire plus the packet we are about to send.
    fn congestionAllows(
        self: *const Connection,
        packet: *const OwnedRawPacket,
        queued_in_flight: u64,
    ) bool {
        if (!packet.ack_eliciting or packet.level != 3) return true;
        const in_flight = self.quic.super_connection.bytesInFlight();
        const on_wire = in_flight -| queued_in_flight;
        return self.quic.super_connection.loss_recovery.canSend(
            on_wire,
            @intCast(packet.data.len),
        );
    }

    fn canTransmitNow(
        self: *const Connection,
        packet: *const OwnedRawPacket,
        queued_in_flight: u64,
    ) bool {
        return self.withinAmplificationLimit(packet.data.len) and
            self.congestionAllows(packet, queued_in_flight);
    }

    /// Drain the queued protected packets in order. A packet that exceeds the
    /// anti-amplification allowance or the congestion window is put back at
    /// the front of zquic's outgoing queue with every packet behind it, and
    /// the flush stops. Nothing is dropped: the next service pass retries once
    /// an ACK grows the window or the peer proves it owns its address.
    ///
    /// qlog pending entries are consumed only for packets the loop actually
    /// attempted, so requeued packets keep their pairing.
    pub fn flush(self: *Connection) !void {
        var remaining_queued_in_flight = self.quic.super_connection.queuedInFlightBytes();
        const packets = self.quic.super_connection.drainOutgoingRawPackets(self.allocator) catch return error.QuicError;
        defer self.allocator.free(packets);
        const pending_log = self.qlog_pending;
        const drop_log_batch = if (pending_log) |pending| pending.overflow else false;
        var blocked_at: ?usize = null;

        for (packets, 0..) |*packet, index| {
            if (packet.data.len == 0) {
                remaining_queued_in_flight -|= packet.in_flight_bytes;
                packet.deinit(self.allocator);
                continue;
            }
            if (!self.canTransmitNow(packet, remaining_queued_in_flight)) {
                blocked_at = index;
                break;
            }
            const outcome = self.packet_io.sendDatagram(self.socket, packet.data);
            // The pending qlog entry is consumed for every attempt, including a
            // synthetic test drop; only a successful send is logged.
            if (pending_log) |pending| {
                if (pending.pop()) |entry| {
                    if (!drop_log_batch and outcome == .sent) {
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
            remaining_queued_in_flight -|= packet.in_flight_bytes;
            if (outcome == .sent) {
                self.stats.packets_sent +|= 1;
                self.stats.bytes_sent +|= @intCast(packet.data.len);
                if (self.role == .server and !self.address_validated) {
                    self.bytes_sent_unvalidated +|= @intCast(packet.data.len);
                }
            }
            packet.deinit(self.allocator);
        }

        if (blocked_at) |index| {
            // Ownership of packets[index..] moves to zquic. On allocation
            // failure the API releases them; reset the qlog pairing rather
            // than leave entries for packets that no longer exist.
            self.quic.super_connection.queueOutgoingRawPacketsFront(packets[index..]) catch {
                if (pending_log) |pending| pending.reset();
                return error.QuicError;
            };
            return;
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
            &self.crypto.packet_crypto,
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
        self.streams.reapFinishedStreams(self.streamContext());

        try self.sendAcks();
        try self.flush();
    }

    /// ACKs for the Initial and Handshake levels stay standalone; 1-RTT ACKs
    /// are collected into ControlBatch and may share a packet with STREAM data.
    fn sendAcks(self: *Connection) !void {
        for ([_]usize{ 0, 2 }) |level| {
            if (!self.acks[level].ack_required or self.acks[level].count == 0) continue;
            if (level == 2 and !self.crypto.handshake_keys) continue;
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
        const level: usize = if (self.crypto.application_keys) 3 else if (self.crypto.handshake_keys) 2 else 0;
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

/// Sender adapter used by StreamTable. It always schedules a 1-RTT packet.
fn scheduleStreamPacket(context: *anyopaque, frames: []const QuicFrames.Frame) anyerror!void {
    const self: *Connection = @ptrCast(@alignCast(context));
    try self.schedule(3, .one_rtt, frames);
}

/// Keep the process-wide batching counters owned by transport.zig; StreamTable
/// reports each successful batch without importing test state.
fn recordStreamBatch(_: ?*anyopaque, observation: stream_table.BatchObservation) void {
    test_batch_packets +|= 1;
    test_batch_stream_frames +|= @intCast(observation.frame_count);
    if (observation.frame_count > 1) test_batch_multi_frame_packets +|= 1;
    if (observation.stream_count > 1) test_batch_multi_stream_packets +|= 1;
    const plaintext_used = observation.payload_used + observation.control_len;
    test_batch_largest_payload = @max(test_batch_largest_payload, plaintext_used);
    test_batch_budget = observation.packet_budget;
}

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
        const bound = try packet_io.bindListener(port);
        return .{
            .allocator = allocator,
            .socket = bound.fd,
            .local_addr = bound.local_addr,
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
        packet_io.closeSocket(self.socket);
    }

    pub fn pollReadable(self: *Listener, timeout_ns: u64) bool {
        return packet_io.pollReadable(self.socket, timeout_ns);
    }

    pub fn readAndDispatch(self: *Listener, buf: []u8, max_datagrams: usize) usize {
        var handled: usize = 0;
        while (handled < max_datagrams) : (handled += 1) {
            const received = packet_io.recvDatagram(self.socket, buf, std.c.MSG.DONTWAIT) orelse break;
            self.dispatch(received.data, received.peer) catch {};
        }
        return handled;
    }

    pub fn dispatch(self: *Listener, datagram: []const u8, peer: posix.sockaddr.in) !void {
        self.ensureQlogHeader();
        if (datagram.len < 1) return;
        const dcid = packet_io.destinationCid(datagram) orelse return;
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
                const fresh = try packet_io.randomCid();
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
                if (packet_io.sendDatagramTo(self.socket, packet, peer)) {
                    self.qlogRetrySent();
                } else {
                    self.qlogRetryRejected("send_failed");
                }
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
        // The token was verified against this peer's address above, so the
        // address is validated before the connection sends its first packet.
        if (self.retry_enabled) connection.markAddressValidated();
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
        if (packet_io.pollReadable(connection.socket, 10 * std.time.ns_per_ms)) {
            if (packet_io.recvDatagram(connection.socket, buf[0..], 0)) |received| {
                connection.handleDatagram(received.data) catch {};
            }
        }
    }
    return connection;
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

    const client_fd = try packet_io.createSocket();
    defer packet_io.closeSocket(client_fd);
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
