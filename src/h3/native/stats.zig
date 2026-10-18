//! Lightweight, single-threaded counters for the native HTTP/3 transport.
//!
//! A Stats value is a plain snapshot: every field is a u64 that only grows.
//! Nothing here allocates, locks, or uses atomics. Each Connection owns one
//! Stats instance and updates it from its normal service/dispatch path, so a
//! snapshot must be taken from the thread that owns the connection (or after
//! that thread has stopped).

pub const Stats = struct {
    /// UDP datagrams successfully handed to sendto by Connection.flush.
    packets_sent: u64 = 0,
    /// UDP datagrams accepted by Connection.handleDatagram. Coalesced QUIC
    /// packets in one datagram count as one received datagram, matching the
    /// sent side, which sends one protected packet per datagram.
    packets_received: u64 = 0,
    /// Wire bytes of packets_sent.
    bytes_sent: u64 = 0,
    /// Wire bytes of packets_received.
    bytes_received: u64 = 0,
    /// Lost plaintexts resent under a new packet number after zquic's
    /// lost-packet observer surfaced them.
    retransmits: u64 = 0,
    /// Unique QUIC streams first seen by the transport, whether opened locally
    /// through createBidiStream/createUniStream or by the peer.
    streams_opened: u64 = 0,
    /// Streams reaped after both the send and receive sides reached FIN.
    streams_closed: u64 = 0,
    /// MAX_DATA and MAX_STREAM_DATA frames scheduled successfully.
    flow_updates: u64 = 0,
    /// ACK frames scheduled successfully.
    ack_frames_sent: u64 = 0,

    /// Saturating field-wise accumulation. Used to aggregate connections into
    /// a listener/server snapshot without ever wrapping a counter.
    pub fn add(self: *Stats, other: Stats) void {
        self.packets_sent +|= other.packets_sent;
        self.packets_received +|= other.packets_received;
        self.bytes_sent +|= other.bytes_sent;
        self.bytes_received +|= other.bytes_received;
        self.retransmits +|= other.retransmits;
        self.streams_opened +|= other.streams_opened;
        self.streams_closed +|= other.streams_closed;
        self.flow_updates +|= other.flow_updates;
        self.ack_frames_sent +|= other.ack_frames_sent;
    }

    /// Copy-and-accumulate helper for callers that prefer a value result.
    pub fn merged(a: Stats, b: Stats) Stats {
        var out = a;
        out.add(b);
        return out;
    }

    /// Streams that have been opened but not reaped yet. Saturates at zero, so
    /// a malformed or partially observed close can never underflow.
    pub fn activeStreams(self: Stats) u64 {
        return self.streams_opened -| self.streams_closed;
    }
};
