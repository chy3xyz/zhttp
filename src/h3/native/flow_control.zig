//! QUIC flow-control state and decisions for the native HTTP/3 transport.
//!
//! FlowControl owns the per-stream map and every connection/stream window
//! counter. It never imports transport.zig and does not know about Connection:
//! callers pass the endpoint orientation (`local_is_client`), the peer's
//! transport-parameter limits, and the absolute end offset of a received STREAM
//! frame as plain values.
//!
//! Receive accounting mutates state immediately because the peer already sent
//! the bytes. MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS advances happen only in
//! the commit* methods, after the caller successfully scheduled the packet that
//! carries those frames.

const std = @import("std");
const zquic = @import("zquic");

const QuicFrames = zquic.core.QuicFrames;

/// Initial connection and stream receive window used when the caller does not
/// override it. Matches the HTTP/3 server option default.
pub const default_flow_window: u64 = 16 * 1024 * 1024;

/// Number of locally initiated streams and peer streams allowed before a
/// MAX_STREAMS update widens the window.
pub const default_max_streams: u64 = 100;

/// Per-stream flow-control state. Send limits are the peer's transport
/// parameters; receive limits are what this endpoint advertised.
pub const StreamFlow = struct {
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

/// Plain copy of the peer transport-parameter limits that feed flow control.
/// The transport fills this from zquic's decoded TransportParameters so this
/// module never depends on that type.
pub const PeerLimits = struct {
    max_data: u64 = 0,
    max_streams_bidi: u64 = 0,
    max_streams_uni: u64 = 0,
    max_stream_data_uni: u64 = 0,
    max_stream_data_bidi_local: u64 = 0,
    max_stream_data_bidi_remote: u64 = 0,
};

pub const EnsureResult = struct {
    flow: *StreamFlow,
    /// True only when this call inserted the map entry. The caller uses it to
    /// bump Stats.streams_opened.
    created: bool,
};

pub const EnsureError = error{ StreamLimitExceeded, OutOfMemory };

/// Receive-side violations. The transport maps these to QUIC close codes.
pub const ReceiveError = error{
    StreamFlowControlExceeded,
    ConnectionFlowControlExceeded,
};

/// Flow-control state for one connection. The owning transport decides when a
/// control frame is committed; nothing here touches the wire.
pub const FlowControl = struct {
    allocator: std.mem.Allocator,

    stream_flow: std.AutoHashMapUnmanaged(u64, StreamFlow) = .empty,

    local_max_data: u64 = default_flow_window,
    local_max_stream_data: u64 = default_flow_window,
    recv_data_limit: u64 = default_flow_window,
    recv_data: u64 = 0,
    peer_max_data: u64 = 0,
    sent_data: u64 = 0,
    local_max_streams_bidi: u64 = default_max_streams,
    local_max_streams_uni: u64 = default_max_streams,
    advertised_streams_bidi: u64 = default_max_streams,
    advertised_streams_uni: u64 = default_max_streams,
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

    /// Peer's initial per-stream send windows, copied from its transport
    /// parameters. They feed initialSendLimit() and stream refreshes.
    peer_initial_max_stream_data_uni: u64 = 0,
    peer_initial_max_stream_data_bidi_local: u64 = 0,
    peer_initial_max_stream_data_bidi_remote: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        local_max_data: u64,
        local_max_stream_data: u64,
    ) FlowControl {
        return .{
            .allocator = allocator,
            .local_max_data = local_max_data,
            .local_max_stream_data = local_max_stream_data,
            .recv_data_limit = local_max_data,
        };
    }

    pub fn deinit(self: *FlowControl) void {
        self.stream_flow.deinit(self.allocator);
    }

    pub fn streamIsUni(stream_id: u64) bool {
        return (stream_id & 0x2) != 0;
    }

    /// RFC 9000 stream IDs encode the initiator in bit 0.
    pub fn streamOpenedByUs(stream_id: u64, local_is_client: bool) bool {
        const client_initiated = (stream_id & 0x1) == 0;
        return client_initiated == local_is_client;
    }

    pub fn initialSendLimit(
        self: *const FlowControl,
        stream_id: u64,
        local_is_client: bool,
    ) u64 {
        const ours = streamOpenedByUs(stream_id, local_is_client);
        if (streamIsUni(stream_id)) {
            return if (ours) self.peer_initial_max_stream_data_uni else 0;
        }
        return if (ours)
            self.peer_initial_max_stream_data_bidi_remote
        else
            self.peer_initial_max_stream_data_bidi_local;
    }

    /// Apply the peer's transport parameters and widen any existing stream
    /// send limits that the new values unlock.
    pub fn applyPeerLimits(
        self: *FlowControl,
        limits: PeerLimits,
        local_is_client: bool,
    ) void {
        self.peer_max_data = limits.max_data;
        self.peer_max_streams_bidi = limits.max_streams_bidi;
        self.peer_max_streams_uni = limits.max_streams_uni;
        self.peer_initial_max_stream_data_uni = limits.max_stream_data_uni;
        self.peer_initial_max_stream_data_bidi_local = limits.max_stream_data_bidi_local;
        self.peer_initial_max_stream_data_bidi_remote = limits.max_stream_data_bidi_remote;
        self.refreshStreamSendLimits(local_is_client);
    }

    /// Find or create flow state. Peer-initiated streams are counted against
    /// the advertised MAX_STREAMS window here, matching the original
    /// Connection.ensureStreamFlow order: the map entry is inserted before the
    /// limit check, as it always was.
    pub fn ensureStream(
        self: *FlowControl,
        stream_id: u64,
        local_is_client: bool,
    ) EnsureError!EnsureResult {
        const gop = try self.stream_flow.getOrPut(self.allocator, stream_id);
        const created = !gop.found_existing;
        if (created) {
            const ours = streamOpenedByUs(stream_id, local_is_client);
            if (!ours) {
                if (streamIsUni(stream_id)) {
                    self.peer_opened_uni += 1;
                    if (self.peer_opened_uni > self.advertised_streams_uni) {
                        return error.StreamLimitExceeded;
                    }
                } else {
                    self.peer_opened_bidi += 1;
                    if (self.peer_opened_bidi > self.advertised_streams_bidi) {
                        return error.StreamLimitExceeded;
                    }
                }
            }
            const recv_limit: u64 = if (streamIsUni(stream_id) and ours)
                0
            else
                self.local_max_stream_data;
            gop.value_ptr.* = .{
                .send_limit = self.initialSendLimit(stream_id, local_is_client),
                .recv_limit = recv_limit,
            };
        }
        return .{ .flow = gop.value_ptr, .created = created };
    }

    pub fn refreshStreamSendLimits(
        self: *FlowControl,
        local_is_client: bool,
    ) void {
        var it = self.stream_flow.iterator();
        while (it.next()) |entry| {
            const updated = self.initialSendLimit(entry.key_ptr.*, local_is_client);
            if (updated > entry.value_ptr.send_limit) entry.value_ptr.send_limit = updated;
        }
    }

    /// Record a FIN that reached a successfully scheduled packet. A
    /// bidirectional stream closes only once both FIN directions were seen;
    /// peer-initiated closes then become eligible for a MAX_STREAMS update.
    pub fn markSendFin(
        self: *FlowControl,
        stream_id: u64,
        local_is_client: bool,
    ) void {
        const flow = self.stream_flow.getPtr(stream_id) orelse return;
        flow.send_fin = true;
        self.maybeCountClosed(stream_id, flow, local_is_client);
    }

    fn maybeCountClosed(
        self: *FlowControl,
        stream_id: u64,
        flow: *StreamFlow,
        local_is_client: bool,
    ) void {
        if (!flow.send_fin or !flow.recv_fin or flow.closed_counted) return;
        flow.closed_counted = true;
        if (streamOpenedByUs(stream_id, local_is_client)) return;
        if (streamIsUni(stream_id)) {
            self.closed_peer_uni += 1;
        } else {
            self.closed_peer_bidi += 1;
        }
    }

    /// Account for one received STREAM frame. `end` is offset + data length;
    /// the caller rejects length overflow before calling this. The frame writes
    /// no state that a failed schedule could need to roll back.
    pub fn receive(
        self: *FlowControl,
        stream_id: u64,
        flow: *StreamFlow,
        end: u64,
        fin: bool,
        local_is_client: bool,
    ) ReceiveError!void {
        if (end > flow.recv_limit) return error.StreamFlowControlExceeded;
        if (end > flow.recv_offset) {
            const delta = end - flow.recv_offset;
            const total = std.math.add(u64, self.recv_data, delta) catch
                return error.ConnectionFlowControlExceeded;
            if (total > self.recv_data_limit) return error.ConnectionFlowControlExceeded;
            self.recv_data = total;
            flow.recv_offset = end;
        }
        if (fin) {
            flow.recv_fin = true;
            self.maybeCountClosed(stream_id, flow, local_is_client);
        }
    }

    pub fn receiveMaxData(self: *FlowControl, maximum_data: u64) void {
        if (maximum_data > self.peer_max_data) self.peer_max_data = maximum_data;
    }

    pub fn receiveMaxStreamData(
        self: *FlowControl,
        stream_id: u64,
        maximum_stream_data: u64,
    ) void {
        if (self.stream_flow.getPtr(stream_id)) |flow| {
            if (maximum_stream_data > flow.send_limit) {
                flow.send_limit = maximum_stream_data;
            }
        }
    }

    pub fn receiveMaxStreams(
        self: *FlowControl,
        maximum_streams: u64,
        bidi: bool,
    ) void {
        if (bidi) {
            if (maximum_streams > self.peer_max_streams_bidi) {
                self.peer_max_streams_bidi = maximum_streams;
            }
        } else {
            if (maximum_streams > self.peer_max_streams_uni) {
                self.peer_max_streams_uni = maximum_streams;
            }
        }
    }

    /// Test-visible peer stream send limit, or null when the stream has no flow
    /// state yet.
    pub fn streamSendLimit(self: *const FlowControl, stream_id: u64) ?u64 {
        const flow = self.stream_flow.get(stream_id) orelse return null;
        return flow.send_limit;
    }

    pub fn isFinished(self: *const FlowControl, stream_id: u64) bool {
        const flow = self.stream_flow.get(stream_id) orelse return false;
        return flow.send_fin and flow.recv_fin;
    }

    pub fn removeStream(self: *FlowControl, stream_id: u64) void {
        _ = self.stream_flow.fetchRemove(stream_id);
    }

    /// Observe the receive side and decide whether this pass must advertise a
    /// larger connection window. Nothing is committed here: the frame only
    /// reaches the wire if the transport schedules the packet successfully.
    pub fn collectFlowControlFrames(
        self: *FlowControl,
        frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
    ) !void {
        const data_half = self.local_max_data / 2;
        if (self.recv_data + data_half >= self.recv_data_limit) {
            const next = self.recv_data +| self.local_max_data;
            if (next > self.recv_data_limit) {
                try frames.append(self.allocator, .{
                    .max_data = QuicFrames.MaxDataFrame.init(next),
                });
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
            try frames.append(self.allocator, .{
                .max_stream_data = QuicFrames.MaxStreamDataFrame.init(entry.key_ptr.*, next),
            });
        }
    }

    /// Replace closed peer streams. Like the old sendStreamLimitUpdates this
    /// only decides; advertised/last-sent counters advance at commit time.
    pub fn collectStreamLimitFrames(
        self: *FlowControl,
        frames: *std.ArrayListUnmanaged(QuicFrames.Frame),
    ) !void {
        const active_bidi = self.peer_opened_bidi -| self.closed_peer_bidi;
        const bidi_due = self.closed_peer_bidi > self.last_max_streams_bidi_sent and
            (self.closed_peer_bidi -| self.last_max_streams_bidi_sent >= 8 or
                self.advertised_streams_bidi -| active_bidi <= 4);
        if (bidi_due) {
            const limit = self.local_max_streams_bidi + self.closed_peer_bidi;
            try frames.append(self.allocator, .{
                .max_streams_bidi = QuicFrames.MaxStreamsFrame.init(limit, true),
            });
        }

        const active_uni = self.peer_opened_uni -| self.closed_peer_uni;
        const uni_due = self.closed_peer_uni > self.last_max_streams_uni_sent and
            (self.closed_peer_uni -| self.last_max_streams_uni_sent >= 8 or
                self.advertised_streams_uni -| active_uni <= 4);
        if (uni_due) {
            const limit = self.local_max_streams_uni + self.closed_peer_uni;
            try frames.append(self.allocator, .{
                .max_streams_uni = QuicFrames.MaxStreamsFrame.init(limit, false),
            });
        }
    }

    pub fn commitMaxData(self: *FlowControl, maximum_data: u64) void {
        if (maximum_data > self.recv_data_limit) {
            self.recv_data_limit = maximum_data;
        }
    }

    pub fn commitMaxStreamData(
        self: *FlowControl,
        stream_id: u64,
        maximum_stream_data: u64,
    ) void {
        if (self.stream_flow.getPtr(stream_id)) |flow| {
            if (maximum_stream_data > flow.recv_limit) {
                flow.recv_limit = maximum_stream_data;
            }
        }
    }

    pub fn commitMaxStreams(
        self: *FlowControl,
        maximum_streams: u64,
        bidi: bool,
    ) void {
        if (bidi) {
            if (maximum_streams > self.advertised_streams_bidi) {
                self.advertised_streams_bidi = maximum_streams;
            }
            self.last_max_streams_bidi_sent = self.closed_peer_bidi;
        } else {
            if (maximum_streams > self.advertised_streams_uni) {
                self.advertised_streams_uni = maximum_streams;
            }
            self.last_max_streams_uni_sent = self.closed_peer_uni;
        }
    }
};
