//! STREAM send state, batching, and lifecycle for the native HTTP/3 transport.
//!
//! StreamTable owns the per-stream send buffers, the finished/retired stream
//! bookkeeping, and the transactional 1-RTT STREAM batch builder. It never
//! imports transport.zig and does not know about Connection: every operation
//! that needs connection-wide state receives it through Context, and the packet
//! schedule is a Sender callback. All send offsets, the FlowControl sent counter,
//! FIN state, and the finished-list only advance after Sender.schedule returned
//! successfully.

const std = @import("std");
const zquic = @import("zquic");
const flow_control = @import("flow_control.zig");
const stats_mod = @import("stats.zig");

const QuicFrames = zquic.core.QuicFrames;
const FlowControl = flow_control.FlowControl;
const StreamFlow = flow_control.StreamFlow;

/// Per-stream send state. The buffer owns bytes that have not been committed to
/// a protected packet yet; sent is the absolute stream offset of the next byte
/// to send.
pub const StreamSend = struct {
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
pub const StreamClaim = struct {
    stream_id: u64,
    offset: u64,
    len: usize,
    fin: bool,
};

/// A stream with work available when a batch was built. pending is a slice of
/// StreamSend.buf taken while no send state is being mutated, planned counts
/// bytes already claimed by this batch, and credit is the peer's stream limit
/// minus the stream's current sent offset.
pub const BatchStream = struct {
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
pub const BatchBuild = struct {
    budget: usize = 0,
    used: usize = 0,
    stream_count: usize = 0,
};

/// Test-visible summary of one successfully scheduled STREAM batch. Production
/// passes an observer that updates the transport's process-wide counters; unit
/// tests can leave it null.
pub const BatchObservation = struct {
    frame_count: usize,
    stream_count: usize,
    payload_used: usize,
    control_len: usize,
    packet_budget: usize,
};

pub const BatchObserver = struct {
    context: ?*anyopaque = null,
    record: *const fn (context: ?*anyopaque, observation: BatchObservation) void,
};

/// Everything StreamTable needs from its owner. The owner supplies the allocator,
/// its Stats, the FlowControl it also exposes to the HTTP/3 layer, and the
/// endpoint orientation that decides which stream IDs count as ours.
pub const Context = struct {
    allocator: std.mem.Allocator,
    stats: *stats_mod.Stats,
    flow: *FlowControl,
    local_is_client: bool,
    /// Incremented when a stream has pending bytes but no flow credit. The
    /// transport points this at its test counter; production leaves it null.
    send_blocked: ?*u64 = null,
    batch_observer: ?BatchObserver = null,
};

/// Schedules one protected packet carrying exactly the given frames. The
/// transport adapts this to Connection.schedule(3, .one_rtt, frames).
pub const Sender = struct {
    context: *anyopaque,
    schedule: *const fn (context: *anyopaque, frames: []const QuicFrames.Frame) anyerror!void,

    pub fn scheduleFrames(self: Sender, frames: []const QuicFrames.Frame) anyerror!void {
        return self.schedule(self.context, frames);
    }
};

/// Opaque view of the transport's 1-RTT control batch. ACK/MAX_* collection and
/// commit stay in transport.zig; flushStreams only asks this interface whether
/// controls are pending, how large they are, how to append/send/commit them.
pub const ControlBatch = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        isPending: *const fn (context: *anyopaque) bool,
        payloadLen: *const fn (context: *anyopaque, allocator: std.mem.Allocator) anyerror!usize,
        appendFrames: *const fn (
            context: *anyopaque,
            allocator: std.mem.Allocator,
            frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
        ) anyerror!void,
        sendStandalone: *const fn (context: *anyopaque, sender: Sender) anyerror!void,
        commitCoalesced: *const fn (context: *anyopaque) void,
    };

    pub fn isPending(self: *const ControlBatch) bool {
        return self.vtable.isPending(self.context);
    }

    pub fn payloadLen(self: *const ControlBatch, allocator: std.mem.Allocator) anyerror!usize {
        return self.vtable.payloadLen(self.context, allocator);
    }

    pub fn appendFrames(
        self: *const ControlBatch,
        allocator: std.mem.Allocator,
        frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
    ) anyerror!void {
        return self.vtable.appendFrames(self.context, allocator, frames);
    }

    pub fn sendStandalone(self: *const ControlBatch, sender: Sender) anyerror!void {
        return self.vtable.sendStandalone(self.context, sender);
    }

    pub fn commitCoalesced(self: *const ControlBatch) void {
        self.vtable.commitCoalesced(self.context);
    }
};

/// Minimal QUIC varint size for value, matching zquic's writeVarint.
pub fn varintSize(value: u64) usize {
    if (value < 0x40) return 1;
    if (value < 0x4000) return 2;
    if (value < 0x40000000) return 4;
    return 8;
}

/// Serialized STREAM frame bytes excluding data.len: frame type, stream ID,
/// offset, and payload length.
fn streamFrameOverhead(stream_id: u64, offset: u64, data_len: usize) usize {
    return 1 + varintSize(stream_id) + varintSize(offset) + varintSize(@intCast(data_len));
}

/// Largest take whose frame header and data fit in budget_left. The length
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

/// Plaintext bytes available in one 1-RTT packet after the short header,
/// packet number, and AEAD tag. destination_cid_len is the CID the caller will
/// put in that packet.
pub fn maxPacketPayload(advertised_max_udp_payload_size: ?u64, destination_cid_len: usize) usize {
    const advertised = advertised_max_udp_payload_size orelse 1472;
    const mtu: usize = @intCast(std.math.clamp(advertised, 1200, 1472));
    const overhead: usize = 1 + destination_cid_len + 4 + 16;
    if (mtu <= overhead) return 0;
    return mtu - overhead;
}

/// Budget for one STREAM frame after reserving room for its type/stream-id/
/// offset/length varints.
pub fn maxStreamFramePayload(advertised_max_udp_payload_size: ?u64, destination_cid_len: usize) usize {
    const payload = maxPacketPayload(advertised_max_udp_payload_size, destination_cid_len);
    if (payload <= 24) return 0;
    return payload - 24;
}

/// Test-visible copy of one stream's send cursor. The private send state stays
/// private; batching tests use this to prove that a failed schedule advances
/// nothing and a retransmit never advances twice.
pub const StreamSendSnapshot = struct {
    sent: u64,
    pending: usize,
    buf_len: usize,
    fin: bool,
    fin_sent: bool,
};

/// Find or create flow state; a created entry counts toward
/// Stats.streams_opened. The statistics counter stays with the owner.
pub fn ensureStreamFlow(ctx: Context, stream_id: u64) !*StreamFlow {
    const ensured = try ctx.flow.ensureStream(stream_id, ctx.local_is_client);
    if (ensured.created) ctx.stats.streams_opened +|= 1;
    return ensured.flow;
}

/// Append a STREAM frame and its claim. Offsets are send.sent plus the bytes
/// already planned for this stream in this batch, so repeated frames form a
/// contiguous range. Never call this after schedule has failed.
fn appendStreamFrame(
    ctx: Context,
    frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
    claims: *std.ArrayListUnmanaged(StreamClaim),
    s: *BatchStream,
    take: usize,
    fin: bool,
) !usize {
    const offset = s.base + s.planned;
    const data = s.pending[s.planned..][0..take];
    try frames.append(ctx.allocator, .{
        .stream = QuicFrames.StreamFrame.init(s.stream_id, offset, data, fin, true, true),
    });
    try claims.append(ctx.allocator, .{
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

/// Transactional STREAM send state for one connection.
pub const StreamTable = struct {
    stream_send: std.AutoHashMapUnmanaged(u64, StreamSend) = .empty,
    /// Streams whose FIN was committed and which are ready to be reaped.
    finished_streams: std.ArrayListUnmanaged(u64) = .empty,
    closed_streams: std.DynamicBitSet = undefined,
    closed_streams_ready: bool = false,

    pub fn deinit(self: *StreamTable, allocator: std.mem.Allocator) void {
        var it = self.stream_send.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        self.stream_send.deinit(allocator);
        self.finished_streams.deinit(allocator);
        if (self.closed_streams_ready) self.closed_streams.deinit();
    }

    /// Append stream data and schedule it on the next service pass.
    pub fn queueStreamData(
        self: *StreamTable,
        ctx: Context,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) !void {
        _ = try ensureStreamFlow(ctx, stream_id);
        const entry = try self.stream_send.getOrPut(ctx.allocator, stream_id);
        if (!entry.found_existing) entry.value_ptr.* = .{};
        try entry.value_ptr.buf.appendSlice(ctx.allocator, data);
        if (fin) entry.value_ptr.fin = true;
    }

    /// Bytes queued for a stream but not yet written to the socket.
    pub fn pendingStreamBytes(self: *const StreamTable, stream_id: u64) usize {
        const send = self.stream_send.get(stream_id) orelse return 0;
        return send.pending().len;
    }

    pub fn streamSendSnapshot(self: *const StreamTable, stream_id: u64) ?StreamSendSnapshot {
        const send = self.stream_send.get(stream_id) orelse return null;
        return .{
            .sent = send.sent,
            .pending = send.pending().len,
            .buf_len = send.buf.items.len,
            .fin = send.fin,
            .fin_sent = send.fin_sent,
        };
    }

    /// Queue a stream for reaping after a receive-side FIN was observed and the
    /// send side already reached FIN.
    pub fn finishStream(self: *StreamTable, ctx: Context, stream_id: u64) void {
        self.finished_streams.append(ctx.allocator, stream_id) catch {};
    }

    /// Build one candidate 1-RTT data batch. The caller schedules the frames as
    /// a single protected packet and only then commits the claims, so a failure
    /// leaves every stream byte-identical.
    pub fn collectStreamBatch(
        self: *StreamTable,
        ctx: Context,
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
                    try streams.append(ctx.allocator, .{
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
            const flow = try ensureStreamFlow(ctx, stream_id);
            const credit = flow.send_limit -| send.sent;
            if (credit == 0 or ctx.flow.sent_data >= ctx.flow.peer_max_data) {
                if (ctx.send_blocked) |blocked| blocked.* += 1;
                continue;
            }
            try streams.append(ctx.allocator, .{
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
        // large stream can consume the whole shared budget. fin_planned keeps
        // the later data pass from emitting a duplicate FIN.
        for (streams.items) |*s| {
            if (s.pending.len != 0 or !s.fin_pending or s.fin_planned) continue;
            const overhead = streamFrameOverhead(s.stream_id, s.base, 0);
            if (overhead > budget_left) continue;
            _ = try appendStreamFrame(ctx, frames, claims, s, 0, true);
            budget_left -= overhead;
        }

        var connection_credit = ctx.flow.peer_max_data -| ctx.flow.sent_data;
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
                            _ = try appendStreamFrame(ctx, frames, claims, s, 0, true);
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
                const used = try appendStreamFrame(ctx, frames, claims, s, take, fin);
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

    /// Commit a scheduled batch. This is the only place send offsets, the
    /// connection send counter, and FIN state advance.
    pub fn commitStreamBatch(self: *StreamTable, ctx: Context, claims: []const StreamClaim) void {
        for (claims) |claim| {
            const send = self.stream_send.getPtr(claim.stream_id) orelse continue;
            // The batch was built from this exact offset. Do not advance twice
            // if state ever disagrees; the bytes stay queued for a later pass.
            if (send.sent != claim.offset) continue;
            if (claim.len > 0) {
                send.sent = claim.offset + claim.len;
                ctx.flow.sent_data += claim.len;
            }
            if (claim.fin) {
                send.fin_sent = true;
                ctx.flow.markSendFin(claim.stream_id, ctx.local_is_client);
                self.finished_streams.append(ctx.allocator, claim.stream_id) catch {};
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

    /// Build and schedule 1-RTT packets. control is the same set gathered at the
    /// start of the service pass; when it fits, its frames are placed before the
    /// first STREAM frame of the first packet. Bookkeeping for both the controls
    /// and the stream claims is committed only after sender.schedule() succeeds,
    /// and the control set is sent at most once per pass. The caller gates this
    /// on application keys.
    pub fn flushStreams(
        self: *StreamTable,
        ctx: Context,
        sender: Sender,
        control: ?*ControlBatch,
        packet_budget: usize,
    ) !void {
        var frames: std.ArrayListUnmanaged(QuicFrames.Frame) = .empty;
        defer frames.deinit(ctx.allocator);
        var claims: std.ArrayListUnmanaged(StreamClaim) = .empty;
        defer claims.deinit(ctx.allocator);
        var streams: std.ArrayListUnmanaged(BatchStream) = .empty;
        defer streams.deinit(ctx.allocator);

        var control_pending = if (control) |batch| batch.isPending() else false;

        // At most 64 protected data packets per service pass. Each packet is a
        // transaction: build, schedule, then commit. A schedule failure leaves
        // every claim and control frame uncommitted, so the next service pass
        // retries the same bytes at the same offsets and does not resend an
        // ACK/MAX_* that was never scheduled.
        var guard: usize = 0;
        while (guard < 64) : (guard += 1) {
            frames.clearRetainingCapacity();
            claims.clearRetainingCapacity();
            streams.clearRetainingCapacity();

            var control_len: usize = 0;
            if (control_pending) control_len = try control.?.payloadLen(ctx.allocator);

            // Reserve the control bytes only when at least a minimal STREAM
            // frame still fits; otherwise the controls go out alone first.
            const reserve_control = control_pending and
                control_len < packet_budget and
                packet_budget - control_len > 26;
            if (reserve_control) {
                try control.?.appendFrames(ctx.allocator, &frames);
            }

            const budget = if (reserve_control) packet_budget - control_len else packet_budget;
            const build = try self.collectStreamBatch(ctx, &streams, &frames, &claims, budget);

            if (claims.items.len == 0) {
                if (control_pending) {
                    // No STREAM data to coalesce with: send the control set on
                    // its own (split if necessary), then rebuild with the full
                    // budget in case streams became sendable in between.
                    if (reserve_control) frames.clearRetainingCapacity();
                    try control.?.sendStandalone(sender);
                    control_pending = false;
                    continue;
                }
                break;
            }
            if (control_pending and !reserve_control) {
                // The control set does not fit next to data. Sending it once
                // first keeps ACK/flow state timely and guarantees it is not
                // duplicated into a later data packet in this pass.
                try control.?.sendStandalone(sender);
                control_pending = false;
                continue;
            }

            try sender.scheduleFrames(frames.items);

            if (reserve_control) {
                control.?.commitCoalesced();
                control_pending = false;
            }
            self.commitStreamBatch(ctx, claims.items);

            if (ctx.batch_observer) |observer| {
                observer.record(observer.context, .{
                    .frame_count = claims.items.len,
                    .stream_count = build.stream_count,
                    .payload_used = build.used,
                    .control_len = control_len,
                    .packet_budget = packet_budget,
                });
            }
        }
        self.reapFinishedStreams(ctx);
    }

    pub fn markStreamClosed(self: *StreamTable, ctx: Context, stream_id: u64) void {
        const index: usize = @intCast(stream_id >> 2);
        if (!self.closed_streams_ready) {
            self.closed_streams = std.DynamicBitSet.initEmpty(ctx.allocator, 0) catch return;
            self.closed_streams_ready = true;
        }
        if (index >= self.closed_streams.capacity()) {
            self.closed_streams.resize(index + 64, false) catch return;
        }
        self.closed_streams.set(index);
    }

    pub fn isStreamClosed(self: *const StreamTable, stream_id: u64) bool {
        if (!self.closed_streams_ready) return false;
        const index: usize = @intCast(stream_id >> 2);
        return index < self.closed_streams.capacity() and self.closed_streams.isSet(index);
    }

    pub fn reapFinishedStreams(self: *StreamTable, ctx: Context) void {
        for (self.finished_streams.items) |stream_id| {
            if (self.stream_send.fetchRemove(stream_id)) |entry| {
                var send = entry.value;
                send.deinit(ctx.allocator);
            }
            if (ctx.flow.isFinished(stream_id)) {
                self.markStreamClosed(ctx, stream_id);
                ctx.flow.removeStream(stream_id);
                ctx.stats.streams_closed +|= 1;
            }
        }
        self.finished_streams.clearRetainingCapacity();
    }
};
