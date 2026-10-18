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
const recovery = @import("recovery.zig");
const retry = @import("retry.zig");
const stats = @import("stats.zig");

/// Re-exported so callers can name a snapshot without importing stats.zig.
pub const Stats = stats.Stats;

const Recovery = recovery.Recovery;
const SentPacket = recovery.SentPacket;

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
/// visible in StreamSend.sent / Connection.sent_data after the packet carrying
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

/// Per-stream flow-control state. Send limits are the peer's transport
/// parameters; receive limits are what this endpoint advertised.
const StreamFlow = struct {
    /// Highest absolute stream offset this endpoint may send.
    send_limit: u64,
    /// Highest absolute stream offset the peer may send.
    recv_limit: u64,
    /// Highest offset actually observed from the peer.
    recv_offset: u64 = 0,
    send_fin: bool = false,
    recv_fin: bool = false,
    closed_counted: bool = false,
};

pub const default_flow_window: u64 = 16 * 1024 * 1024;
const max_retransmits_per_service = 64;

/// Test-visible count of successful frame retransmissions. The test runner is
/// single-threaded; production code does not read this.
pub var test_retransmit_count: u64 = 0;

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

/// Test-visible Retry decisions made by client connections.
pub var test_retry_accepted: u64 = 0;
pub var test_retry_rejected: u64 = 0;

/// Test-visible observation of packets zquic declared lost. The observer only
/// records what zquic already decided; it does not resend anything. The test
/// runner is single-threaded.
pub var test_zquic_lost_packets: u64 = 0;
pub var test_zquic_lost_payload_packets: u64 = 0;
pub var test_zquic_lost_payload_bytes: u64 = 0;
pub var test_zquic_lost_last_level: usize = 0;
pub var test_zquic_lost_last_packet_number: u64 = 0;

/// Lost-packet observer installed on client and server SuperConnections. The
/// payload is only valid during this call; this intentionally keeps no copy.
fn observeZquicLostPacket(
    _: ?*anyopaque,
    level: usize,
    packet_number: u64,
    payload: []const u8,
) void {
    test_zquic_lost_packets += 1;
    test_zquic_lost_last_level = level;
    test_zquic_lost_last_packet_number = packet_number;
    if (payload.len == 0) return;
    test_zquic_lost_payload_packets += 1;
    test_zquic_lost_payload_bytes += payload.len;
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
    closing: bool = false,
    closed: bool = false,
    close_code: u64 = 0,
    established_notified: bool = false,
    /// Monotonic transport counters for this connection. Single-threaded: only
    /// the owning service/dispatch thread updates them.
    stats: Stats = .{},

    stream_send: std.AutoHashMapUnmanaged(u64, StreamSend) = .empty,
    stream_flow: std.AutoHashMapUnmanaged(u64, StreamFlow) = .empty,
    finished_streams: std.ArrayListUnmanaged(u64) = .empty,
    closed_streams: std.DynamicBitSet = undefined,
    closed_streams_ready: bool = false,
    local_max_data: u64 = default_flow_window,
    local_max_stream_data: u64 = default_flow_window,
    recv_data_limit: u64 = default_flow_window,
    recv_data: u64 = 0,
    peer_max_data: u64 = 0,
    sent_data: u64 = 0,
    local_max_streams_bidi: u64 = 100,
    local_max_streams_uni: u64 = 100,
    advertised_streams_bidi: u64 = 100,
    advertised_streams_uni: u64 = 100,
    peer_opened_bidi: u64 = 0,
    peer_opened_uni: u64 = 0,
    peer_max_streams_bidi: u64 = 0,
    peer_max_streams_uni: u64 = 0,
    opened_bidi: u64 = 0,
    opened_uni: u64 = 0,
    closed_peer_bidi: u64 = 0,
    closed_peer_uni: u64 = 0,
    last_max_streams_bidi_sent: u64 = 0,
    last_max_streams_uni_sent: u64 = 0,
    /// Retained ack-eliciting packets awaiting acknowledgment.
    recovery: Recovery,
    /// Test hook: drop every Nth outgoing datagram (0 disables). Production
    /// callers leave this at zero; the retransmission test uses it to simulate
    /// loss without a network shim.
    drop_outgoing_every: usize = 0,
    /// Test hook: a datagram discarded by drop_outgoing_every is known lost, so
    /// the next retransmitLost pass treats every retained packet as due once.
    /// This keeps loss tests meaningful when batching changes how many
    /// datagrams a response occupies. Always false in production.
    force_retransmit: bool = false,
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
            .recovery = Recovery.init(allocator),
            .local_max_data = options.initial_max_data,
            .local_max_stream_data = options.initial_max_stream_data,
            .recv_data_limit = options.initial_max_data,
            .last_activity_us = nowMicros(),
            .handshake_started_us = nowMicros(),
        };
        self.local_cid = client_cid;
        self.local_cid_len = cid_len;
        self.original_dcid = original_dcid;
        self.original_dcid_len = cid_len;

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
            .recovery = Recovery.init(allocator),
            .local_max_data = local_max_data,
            .local_max_stream_data = local_max_stream_data,
            .recv_data_limit = local_max_data,
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
        // Observe (never retransmit) packets zquic declares lost. The existing
        // transport retransmitter below remains the only sender on this path,
        // so suppress zquic's duplicate PTO PING/CRYPTO probes until recovery
        // ownership moves into zquic.
        self.quic.super_connection.setLostPacketObserver(observeZquicLostPacket, null);
        self.quic.super_connection.pto_probes_enabled = false;

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
        self.retry_token.deinit(self.allocator);
        self.initial_crypto.deinit(self.allocator);
        var it = self.stream_send.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.stream_send.deinit(self.allocator);
        self.stream_flow.deinit(self.allocator);
        self.finished_streams.deinit(self.allocator);
        if (self.closed_streams_ready) self.closed_streams.deinit();
        self.recovery.deinit();
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
            .initial_max_data = self.local_max_data,
            .initial_max_stream_data_bidi_local = self.local_max_stream_data,
            .initial_max_stream_data_bidi_remote = self.local_max_stream_data,
            .initial_max_stream_data_uni = self.local_max_stream_data,
            .initial_max_streams_bidi = self.local_max_streams_bidi,
            .initial_max_streams_uni = self.local_max_streams_uni,
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
        var sanitized: std.Io.Writer.Allocating = .init(self.allocator);
        defer sanitized.deinit();
        var reader = std.Io.Reader.fixed(processed.payload);
        while (reader.seek < reader.end) {
            var frame = QuicFrames.Frame.parse(&reader, self.allocator) catch break;
            defer frame.deinit(self.allocator);

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
                    if (self.isStreamClosed(stream.stream_id)) continue;
                    const end = std.math.add(u64, stream.offset, @intCast(stream.data.len)) catch {
                        self.close(0x3, "flow control");
                        return;
                    };
                    const flow = self.ensureStreamFlow(stream.stream_id) catch |err| {
                        self.close(if (err == error.StreamLimitExceeded) 0x4 else 0x1, "flow state");
                        return;
                    };
                    if (end > flow.recv_limit) {
                        self.close(0x3, "stream flow control");
                        return;
                    }
                    if (end > flow.recv_offset) {
                        const delta = end - flow.recv_offset;
                        const total = std.math.add(u64, self.recv_data, delta) catch {
                            self.close(0x3, "connection flow control");
                            return;
                        };
                        if (total > self.recv_data_limit) {
                            self.close(0x3, "connection flow control");
                            return;
                        }
                        self.recv_data = total;
                        flow.recv_offset = end;
                    }
                    if (stream.fin) {
                        flow.recv_fin = true;
                        self.maybeCountClosed(stream.stream_id, flow);
                        if (flow.send_fin) {
                            self.finished_streams.append(self.allocator, stream.stream_id) catch {};
                        }
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
                .ack => |ack_frame| self.recovery.acknowledge(tlsLevel(processed.encryption_level), &ack_frame),
                .ack_ecn => |ack_ecn| self.recovery.acknowledge(tlsLevel(processed.encryption_level), &ack_ecn.ack_frame),
                .max_data => |max_data| {
                    if (max_data.maximum_data > self.peer_max_data) self.peer_max_data = max_data.maximum_data;
                },
                .max_stream_data => |max_stream| {
                    if (self.stream_flow.getPtr(max_stream.stream_id)) |flow| {
                        if (max_stream.maximum_stream_data > flow.send_limit) {
                            flow.send_limit = max_stream.maximum_stream_data;
                        }
                    }
                },
                .max_streams_bidi => |max_streams| {
                    if (max_streams.maximum_streams > self.peer_max_streams_bidi) {
                        self.peer_max_streams_bidi = max_streams.maximum_streams;
                    }
                },
                .max_streams_uni => |max_streams| {
                    if (max_streams.maximum_streams > self.peer_max_streams_uni) {
                        self.peer_max_streams_uni = max_streams.maximum_streams;
                    }
                },
                .padding, .connection_close, .connection_close_app => {
                    const tag = std.meta.activeTag(frame);
                    if (tag == .connection_close or tag == .connection_close_app) {
                        self.closed = true;
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

        self.acks[idx].record(processed.packet_number, ack_eliciting);
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
        // Initial keys, in both the transport's recovery store and zquic's
        // own packet space.
        self.packet_crypto.resetInitialPacketNumberState();
        self.packet_crypto.initial_token = self.retry_token.items;
        self.recovery.discardLevel(0);
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
        self.peer_max_data = params.initial_max_data;
        self.peer_max_streams_bidi = params.initial_max_streams_bidi;
        self.peer_max_streams_uni = params.initial_max_streams_uni;
        self.refreshStreamSendLimits();
        self.peer_params_applied = true;
    }

    fn sendHandshakeDone(self: *Connection) !void {
        if (!self.application_keys) return;
        const frames = [_]QuicFrames.Frame{.{ .handshake_done = QuicFrames.HandshakeDoneFrame.init() }};
        try self.schedule(3, .one_rtt, &frames);
        self.handshake_done_sent = true;
    }

    fn streamIsUni(stream_id: u64) bool {
        return (stream_id & 0x2) != 0;
    }

    fn streamOpenedByUs(self: *const Connection, stream_id: u64) bool {
        const client_initiated = (stream_id & 0x1) == 0;
        return client_initiated == (self.role == .client);
    }

    fn initialSendLimit(self: *const Connection, stream_id: u64) u64 {
        const params = self.peer_params orelse return 0;
        const ours = self.streamOpenedByUs(stream_id);
        if (streamIsUni(stream_id)) {
            return if (ours) params.initial_max_stream_data_uni else 0;
        }
        return if (ours)
            params.initial_max_stream_data_bidi_remote
        else
            params.initial_max_stream_data_bidi_local;
    }

    fn ensureStreamFlow(self: *Connection, stream_id: u64) !*StreamFlow {
        const gop = try self.stream_flow.getOrPut(self.allocator, stream_id);
        if (!gop.found_existing) {
            const ours = self.streamOpenedByUs(stream_id);
            if (!ours) {
                if (streamIsUni(stream_id)) {
                    self.peer_opened_uni += 1;
                    if (self.peer_opened_uni > self.advertised_streams_uni) return error.StreamLimitExceeded;
                } else {
                    self.peer_opened_bidi += 1;
                    if (self.peer_opened_bidi > self.advertised_streams_bidi) return error.StreamLimitExceeded;
                }
            }
            const recv_limit: u64 = if (streamIsUni(stream_id) and ours)
                0
            else
                self.local_max_stream_data;
            gop.value_ptr.* = .{
                .send_limit = self.initialSendLimit(stream_id),
                .recv_limit = recv_limit,
            };
            self.stats.streams_opened +|= 1;
        }
        return gop.value_ptr;
    }

    fn refreshStreamSendLimits(self: *Connection) void {
        var it = self.stream_flow.iterator();
        while (it.next()) |entry| {
            const updated = self.initialSendLimit(entry.key_ptr.*);
            if (updated > entry.value_ptr.send_limit) entry.value_ptr.send_limit = updated;
        }
    }

    /// A bidirectional stream is closed once both sides have sent FIN. Count
    /// peer-initiated streams so MAX_STREAMS can replace them.
    fn maybeCountClosed(self: *Connection, stream_id: u64, flow: *StreamFlow) void {
        if (!flow.send_fin or !flow.recv_fin or flow.closed_counted) return;
        flow.closed_counted = true;
        if (self.streamOpenedByUs(stream_id)) return;
        if (streamIsUni(stream_id)) {
            self.closed_peer_uni += 1;
        } else {
            self.closed_peer_bidi += 1;
        }
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
        const flow = self.stream_flow.get(stream_id) orelse return null;
        return flow.send_limit;
    }

    pub fn createBidiStream(self: *Connection) !u64 {
        if (self.opened_bidi >= self.peer_max_streams_bidi) return error.StreamLimitExceeded;
        const stream_type: zquic.core.Stream.StreamType = switch (self.role) {
            .client => .client_bidirectional,
            .server => .server_bidirectional,
        };
        const stream = self.quic.createStream(stream_type) catch return error.QuicError;
        self.opened_bidi += 1;
        _ = try self.ensureStreamFlow(stream.id);
        return stream.id;
    }

    pub fn createUniStream(self: *Connection) !u64 {
        if (self.opened_uni >= self.peer_max_streams_uni) return error.StreamLimitExceeded;
        const stream_type: zquic.core.Stream.StreamType = switch (self.role) {
            .client => .client_unidirectional,
            .server => .server_unidirectional,
        };
        const stream = self.quic.createStream(stream_type) catch return error.QuicError;
        self.opened_uni += 1;
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
    fn maxStreamFramePayload(self: *const Connection) usize {
        const advertised = if (self.peer_params) |params| params.max_udp_payload_size else 1472;
        const mtu: usize = @intCast(std.math.clamp(advertised, 1200, 1472));
        const overhead: usize = 1 + self.destinationCid(3).len + 4 + 16 + 24;
        if (mtu <= overhead) return 0;
        return mtu - overhead;
    }

    /// Build one candidate 1-RTT data batch. The caller schedules the frames as
    /// a single protected packet and only then commits the claims, so a failure
    /// leaves every stream byte-identical.
    fn collectStreamBatch(
        self: *Connection,
        streams: *std.ArrayListUnmanaged(BatchStream),
        frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
        claims: *std.ArrayListUnmanaged(StreamClaim),
    ) !BatchBuild {
        var build = BatchBuild{};
        build.budget = self.maxStreamFramePayload();
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
            if (credit == 0 or self.sent_data >= self.peer_max_data) {
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

        var connection_credit = self.peer_max_data -| self.sent_data;
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
                self.sent_data += claim.len;
            }
            if (claim.fin) {
                send.fin_sent = true;
                if (self.stream_flow.getPtr(claim.stream_id)) |flow| {
                    flow.send_fin = true;
                    self.maybeCountClosed(claim.stream_id, flow);
                }
                self.finished_streams.append(self.allocator, claim.stream_id) catch {};
            }
            if (send.fin_sent and send.sent >= send.buf.items.len) {
                // The frames are retained in the recovery store until ACKed, so
                // the stream's own copy can be released only after the FIN frame
                // was successfully scheduled and committed.
                send.buf.clearRetainingCapacity();
                send.sent = 0;
            }
        }
    }

    fn flushStreams(self: *Connection) !void {
        if (!self.application_keys) return;

        var frames: std.ArrayListUnmanaged(QuicFrames.Frame) = .empty;
        defer frames.deinit(self.allocator);
        var claims: std.ArrayListUnmanaged(StreamClaim) = .empty;
        defer claims.deinit(self.allocator);
        var streams: std.ArrayListUnmanaged(BatchStream) = .empty;
        defer streams.deinit(self.allocator);

        // At most 64 protected data packets per service pass. Each packet is a
        // transaction: build, schedule, then commit. schedule() failures leave
        // every claim uncommitted, so the next service pass retries the same
        // bytes at the same offsets.
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            frames.clearRetainingCapacity();
            claims.clearRetainingCapacity();
            streams.clearRetainingCapacity();

            const build = try self.collectStreamBatch(&streams, &frames, &claims);
            if (frames.items.len == 0) break;
            try self.schedule(3, .one_rtt, frames.items);

            self.commitStreamBatch(claims.items);
            test_batch_packets +|= 1;
            test_batch_stream_frames +|= @intCast(frames.items.len);
            if (frames.items.len > 1) test_batch_multi_frame_packets +|= 1;
            if (build.stream_count > 1) test_batch_multi_stream_packets +|= 1;
            test_batch_largest_payload = @max(test_batch_largest_payload, build.used);
            test_batch_budget = build.budget;
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
            if (self.stream_flow.getPtr(stream_id)) |flow| {
                if (flow.send_fin and flow.recv_fin) {
                    self.markStreamClosed(stream_id);
                    _ = self.stream_flow.fetchRemove(stream_id);
                    self.stats.streams_closed +|= 1;
                }
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

        if (ack_eliciting) {
            const owned = self.allocator.dupe(u8, bytes) catch return error.OutOfMemory;
            self.recovery.track(.{
                .level = level,
                .ptype = ptype,
                .packet_number = packet_number,
                .sent_us = nowMicros(),
                .payload = owned,
            }) catch return error.OutOfMemory;
        }
    }

    fn retransmitTimeoutUs(self: *const Connection) u64 {
        const srtt = self.quic.super_connection.loss_recovery.getSmoothedRtt();
        return std.math.clamp(srtt *| 2, 200_000, 1_000_000);
    }

    fn retransmitLost(self: *Connection, now_us: u64) void {
        const forced = self.force_retransmit;
        self.force_retransmit = false;
        const timeout_us = if (forced) 0 else self.retransmitTimeoutUs();
        var due: std.ArrayListUnmanaged(*SentPacket) = .empty;
        defer due.deinit(self.allocator);
        self.recovery.collectDue(now_us, timeout_us, &due);

        var count: usize = 0;
        for (due.items) |sent| {
            if (count >= max_retransmits_per_service) break;
            const dest = self.destinationCid(sent.level);
            if (dest.len == 0) continue;
            const src: []const u8 = if (sent.ptype == .one_rtt) &.{} else self.local_cid[0..self.local_cid_len];
            const packet_number = self.packet_crypto.nextPacketNumberForLevel(switch (sent.level) {
                0 => .initial,
                2 => .handshake,
                else => .application,
            });
            self.quic.super_connection.sendProtectedRawPacket(
                &self.packet_crypto,
                switch (sent.level) {
                    0 => .initial,
                    2 => .handshake,
                    else => .application,
                },
                sent.ptype,
                dest,
                src,
                sent.payload,
            ) catch {
                // Keep the old entry, but do not hammer it every service pass.
                sent.sent_us = now_us;
                continue;
            };
            self.recovery.markRetransmitted(sent, packet_number, now_us);
            count += 1;
            test_retransmit_count += 1;
            self.stats.retransmits +|= 1;
        }
    }

    fn destinationCid(self: *const Connection, level: usize) []const u8 {
        if (self.peer_cid_len > 0) return self.peer_cid[0..self.peer_cid_len];
        if (level == 0 and self.original_dcid_len > 0) return self.original_dcid[0..self.original_dcid_len];
        return &.{};
    }

    fn flush(self: *Connection) !void {
        const packets = self.quic.super_connection.drainOutgoingRawPackets(self.allocator) catch return error.QuicError;
        defer self.allocator.free(packets);
        for (packets) |*packet| {
            defer packet.deinit(self.allocator);
            if (packet.data.len == 0) continue;
            self.tx_count += 1;
            if (self.drop_outgoing_every != 0 and self.tx_count % self.drop_outgoing_every == 0) {
                // A test drop never reaches the peer. Treat it as loss now
                // instead of relying on the batch's packet count aligning with
                // the SRTT timeout, which packet batching intentionally changes.
                self.force_retransmit = true;
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
            if (sent < 0) continue;
            self.stats.packets_sent +|= 1;
            self.stats.bytes_sent +|= @intCast(packet.data.len);
        }
    }

    /// Deliver anything queued and consume the ACK/recovery work zquic owns.
    pub fn service(self: *Connection) !void {
        if (self.closed) return;
        try self.afterTlsProgress();
        try self.flushStreams();
        self.reapFinishedStreams();

        self.retransmitLost(nowMicros());

        // PTO probes and retained-CRYPTO retransmission. zquic timestamps
        // packets and its loss deadline with wall-clock microseconds, so the
        // recovery poll must use that same clock; retransmitLost above keeps
        // the transport's monotonic clock.
        const recovery_now: u64 = @intCast(@max(zquic.Time.nowMicros(), 0));
        _ = self.quic.super_connection.pollLossRecovery(
            &self.packet_crypto,
            recovery_now,
            self.destinationCid(0),
            self.local_cid[0..self.local_cid_len],
        ) catch {};
        self.sendFlowControlUpdates();
        self.sendStreamLimitUpdates();
        try self.sendAcks();
        try self.flush();
    }

    fn sendFlowControlUpdates(self: *Connection) void {
        if (!self.application_keys or self.closed) return;
        var frames: std.ArrayListUnmanaged(QuicFrames.Frame) = .empty;
        defer frames.deinit(self.allocator);

        const data_half = self.local_max_data / 2;
        if (self.recv_data + data_half >= self.recv_data_limit) {
            const next = self.recv_data +| self.local_max_data;
            if (next > self.recv_data_limit) {
                frames.append(self.allocator, .{ .max_data = QuicFrames.MaxDataFrame.init(next) }) catch return;
                test_max_data_sent += 1;
                self.recv_data_limit = next;
            }
        }

        var it = self.stream_flow.iterator();
        while (it.next()) |entry| {
            const flow = entry.value_ptr;
            if (flow.recv_limit == 0) continue;
            const stream_half = self.local_max_stream_data / 2;
            if (flow.recv_offset + stream_half < flow.recv_limit) continue;
            const next = flow.recv_offset +| self.local_max_stream_data;
            if (next <= flow.recv_limit) continue;
            frames.append(self.allocator, .{
                .max_stream_data = QuicFrames.MaxStreamDataFrame.init(entry.key_ptr.*, next),
            }) catch return;
            test_max_stream_data_sent += 1;
            flow.recv_limit = next;
        }

        if (frames.items.len == 0) return;
        self.schedule(3, .one_rtt, frames.items) catch return;
        self.stats.flow_updates +|= @intCast(frames.items.len);
    }

    fn sendStreamLimitUpdates(self: *Connection) void {
        if (!self.application_keys or self.closed) return;
        var frames: std.ArrayListUnmanaged(QuicFrames.Frame) = .empty;
        defer frames.deinit(self.allocator);

        const active_bidi = self.peer_opened_bidi -| self.closed_peer_bidi;
        const bidi_due = self.closed_peer_bidi > self.last_max_streams_bidi_sent and
            (self.closed_peer_bidi -| self.last_max_streams_bidi_sent >= 8 or
                self.advertised_streams_bidi -| active_bidi <= 4);
        if (bidi_due) {
            const limit = self.local_max_streams_bidi + self.closed_peer_bidi;
            frames.append(self.allocator, .{
                .max_streams_bidi = QuicFrames.MaxStreamsFrame.init(limit, true),
            }) catch return;
            self.advertised_streams_bidi = limit;
            self.last_max_streams_bidi_sent = self.closed_peer_bidi;
        }
        const active_uni = self.peer_opened_uni -| self.closed_peer_uni;
        const uni_due = self.closed_peer_uni > self.last_max_streams_uni_sent and
            (self.closed_peer_uni -| self.last_max_streams_uni_sent >= 8 or
                self.advertised_streams_uni -| active_uni <= 4);
        if (uni_due) {
            const limit = self.local_max_streams_uni + self.closed_peer_uni;
            frames.append(self.allocator, .{
                .max_streams_uni = QuicFrames.MaxStreamsFrame.init(limit, false),
            }) catch return;
            self.advertised_streams_uni = limit;
            self.last_max_streams_uni_sent = self.closed_peer_uni;
        }

        if (frames.items.len == 0) return;
        self.schedule(3, .one_rtt, frames.items) catch {};
    }

    fn sendAcks(self: *Connection) !void {
        for (0..4) |level| {
            if (!self.acks[level].ack_required or self.acks[level].count == 0) continue;
            switch (level) {
                0 => {},
                2 => if (!self.handshake_keys) continue,
                3 => if (!self.application_keys) continue,
                else => continue,
            }
            var ack_frame = self.acks[level].buildFrame(self.allocator) catch continue;
            defer ack_frame.deinit(self.allocator);
            const ptype: Packet.PacketType = switch (level) {
                0 => .initial,
                2 => .handshake,
                else => .one_rtt,
            };
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

    pub fn enableRetry(self: *Listener) void {
        if (self.retry_enabled) return;
        qtls.fillRandom(&self.retry_key);
        self.retry_enabled = true;
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
            if (datagram.len < 1200) return;
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
                ) catch return;
                var packet_buf: [retry.max_retry_packet_len]u8 = undefined;
                const packet = retry.Retry.buildPacket(
                    header.dest_conn_id.bytes(),
                    scid.bytes(),
                    fresh[0..cid_len],
                    made,
                    &packet_buf,
                ) catch return;
                _ = posix.system.sendto(
                    self.socket,
                    packet.ptr,
                    @intCast(packet.len),
                    0,
                    @ptrCast(&peer),
                    @sizeOf(posix.sockaddr.in),
                );
                return;
            }
            const verified = retry_impl.verifyToken(
                token,
                &address,
                header.dest_conn_id.bytes(),
                scid.bytes(),
                nowMicros(),
            ) orelse return;
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
        const connection = try Connection.initServer(
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
    const connection = try Connection.initClient(allocator, host, port, options);
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
