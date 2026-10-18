//! TLS and CRYPTO state for the native QUIC transport.
//!
//! This owns the TLS 1.3 context, packet protection, per-encryption-level
//! CRYPTO reassembly, traffic secrets, and RFC 9001 key installation. The
//! transport keeps packet routing, loss recovery, and transport parameters; it
//! reaches this state through thin wrappers and supplies a packet-scheduling
//! callback so packet construction stays in transport.zig.

const std = @import("std");
const zquic = @import("zquic");
const qtls = @import("qtls.zig");
const Reassembler = @import("reassembly.zig").Reassembler;

const Packet = zquic.Packet;
const PacketCrypto = zquic.PacketCrypto;
const QuicFrames = zquic.core.QuicFrames;
const Tls13KeySchedule = zquic.Tls13KeySchedule;
const EnhancedTlsContext = zquic.EnhancedCrypto.EnhancedTlsContext;

/// Largest plaintext CRYPTO payload put in one packet. Keeping the old value
/// preserves the ClientHello chunking and therefore the wire bytes.
pub const max_crypto_chunk = 1000;

/// Packet-scheduling seam. transport.Connection turns this into its schedule().
pub const Sender = struct {
    context: *anyopaque,
    schedule_fn: *const fn (
        context: *anyopaque,
        level: usize,
        ptype: Packet.PacketType,
        frames: []const QuicFrames.Frame,
    ) anyerror!void,

    pub fn schedule(
        self: Sender,
        level: usize,
        ptype: Packet.PacketType,
        frames: []const QuicFrames.Frame,
    ) anyerror!void {
        return self.schedule_fn(self.context, level, ptype, frames);
    }
};

/// Outcome of one CRYPTO frame feed. The caller uses this to preserve the old
/// frame-dispatch behavior: a reassembly failure skips the frame entirely,
/// while a duplicate or buffered frame is still ACK-eliciting.
pub const FeedResult = enum {
    /// Reassembly rejects the frame (too large / conflicts with FIN).
    skipped,
    /// Buffered or duplicate; no new contiguous bytes reached TLS.
    buffered,
    /// New contiguous bytes were handed to TLS and it was driven.
    advanced,
};

/// TLS state observed after one progress step.
pub const Progress = struct {
    /// Peer transport parameters, present once the peer sent them.
    peer_params: ?[]const u8 = null,
    /// TLS considers the handshake finished.
    finished: bool = false,
};

pub const CryptoStream = struct {
    allocator: std.mem.Allocator,
    is_server: bool,
    tls_ctx: EnhancedTlsContext,
    packet_crypto: PacketCrypto,
    /// Created by Connection (it needs the encoded transport parameters) and
    /// attached with attachTls(). Destroyed by deinit().
    tls: ?*qtls.Tls,
    crypto_rx: [qtls.level_count]Reassembler,
    crypto_tx_offset: [qtls.level_count]u64,
    secrets: [qtls.level_count]qtls.SecretSet,
    handshake_keys: bool,
    application_keys: bool,
    /// Plaintext CRYPTO bytes TLS produced at the Initial level. A Retry must
    /// resend the identical ClientHello without resetting the TLS transcript,
    /// so the bytes are kept instead of relying on TLS to emit them again.
    initial_crypto: std.ArrayListUnmanaged(u8),

    /// Initialize in place: packet_crypto keeps a pointer to tls_ctx, so the
    /// struct must not be moved after this returns.
    pub fn init(
        self: *CryptoStream,
        allocator: std.mem.Allocator,
        is_server: bool,
        initial_dcid: []const u8,
    ) !void {
        self.* = .{
            .allocator = allocator,
            .is_server = is_server,
            .tls_ctx = undefined,
            .packet_crypto = undefined,
            .tls = null,
            .crypto_rx = undefined,
            .crypto_tx_offset = .{ 0, 0, 0, 0 },
            .secrets = .{ .{}, .{}, .{}, .{} },
            .handshake_keys = false,
            .application_keys = false,
            .initial_crypto = .empty,
        };
        self.tls_ctx = try EnhancedTlsContext.init(allocator, is_server, .aes_128_gcm_sha256);
        errdefer self.tls_ctx.deinit();
        self.packet_crypto = try PacketCrypto.init(allocator, &self.tls_ctx, null);
        errdefer self.packet_crypto.deinit();

        var initialized: usize = 0;
        errdefer for (self.crypto_rx[0..initialized]) |*r| r.deinit();
        for (&self.crypto_rx) |*r| {
            r.* = try Reassembler.init(allocator);
            initialized += 1;
        }
        if (is_server) {
            try self.packet_crypto.installRfc9001ServerInitialKeys(initial_dcid);
        } else {
            try self.packet_crypto.installRfc9001ClientInitialKeys(initial_dcid);
        }
    }

    pub fn deinit(self: *CryptoStream) void {
        if (self.tls) |tls| {
            tls.destroy();
            self.tls = null;
        }
        for (&self.crypto_rx) |*r| r.deinit();
        self.packet_crypto.deinit();
        self.tls_ctx.deinit();
        self.initial_crypto.deinit(self.allocator);
    }

    /// Adopt the qtls.Tls Connection built from its transport parameters.
    /// Ownership of the destroy moves to this stream.
    pub fn attachTls(self: *CryptoStream, tls: *qtls.Tls) void {
        self.tls = tls;
    }

    /// Run the TLS state machine. Call after feed() and once at start.
    pub fn drive(self: *CryptoStream) !void {
        const tls = self.tls orelse return error.TlsError;
        try tls.drive();
    }

    /// Reassembly half of feed(), split out so tests can exercise gaps without
    /// a live TLS object.
    pub fn reassemble(self: *CryptoStream, level: usize, offset: u64, data: []const u8) ![]const u8 {
        return self.crypto_rx[level].insert(offset, data, false);
    }

    /// Feed one CRYPTO frame. Only the newly contiguous prefix reaches TLS;
    /// the caller runs progress() when this returns .advanced.
    pub fn feed(self: *CryptoStream, level: usize, offset: u64, data: []const u8) !FeedResult {
        const fresh = self.reassemble(level, offset, data) catch return .skipped;
        if (fresh.len == 0) return .buffered;
        const tls = self.tls orelse return error.TlsError;
        try tls.pushCrypto(level, fresh);
        try tls.drive();
        return .advanced;
    }

    /// Harvest secrets, install any newly complete key set, and flush TLS
    /// output. The transport applies the returned peer parameters and marks the
    /// connection established; those are Connection state, not TLS state.
    pub fn progress(self: *CryptoStream, sender: Sender) !Progress {
        const tls = self.tls orelse return .{};
        for ([_]usize{ 2, 3 }) |level| {
            const incoming = tls.takeSecrets(level);
            if (incoming.local) |secret| self.secrets[level].local = secret;
            if (incoming.remote) |secret| self.secrets[level].remote = secret;
        }

        if (!self.handshake_keys and self.secrets[2].complete()) {
            try self.installLevelKeys(2);
        }
        if (!self.application_keys and self.secrets[3].complete()) {
            try self.installLevelKeys(3);
        }

        try self.flush(sender);

        const params = tls.peerParams();
        return .{
            .peer_params = if (params.len > 0) params else null,
            .finished = tls.isFinished(),
        };
    }

    fn installLevelKeys(self: *CryptoStream, level: usize) !void {
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

    /// Move TLS handshake bytes into CRYPTO frames, in level order. A client
    /// Retry replays the cached Initial flight byte-for-byte from this buffer.
    pub fn flush(self: *CryptoStream, sender: Sender) !void {
        const tls = self.tls orelse return;
        for (0..qtls.level_count) |level| {
            if (level == 1) {
                // 0-RTT is not implemented; discard anything TLS produced for it.
                tls.clearOut(level);
                continue;
            }
            const data = tls.takeOut(level);
            if (data.len == 0) continue;
            if (level == 0) {
                // Keep a copy so an accepted Retry can replay the exact same
                // CRYPTO stream under new Initial keys and a token.
                try self.initial_crypto.appendSlice(self.allocator, data);
            }
            var offset: usize = 0;
            while (offset < data.len) {
                const take: usize = @min(data.len - offset, max_crypto_chunk);
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
                try sender.schedule(level, ptype, frames_buf[0..frame_count]);
                self.crypto_tx_offset[level] += take;
                offset += take;
            }
            tls.clearOut(level);
        }
    }

    /// Rekey the Initial packet number space after an accepted Retry and replay
    /// the cached ClientHello with the Retry token. Fallible allocation happens
    /// before the old receive state is dropped, matching the pre-split order.
    pub fn retryInitial(
        self: *CryptoStream,
        dcid: []const u8,
        token: []const u8,
        sender: Sender,
    ) !void {
        var fresh_rx = try Reassembler.init(self.allocator);
        var fresh_owned = true;
        errdefer if (fresh_owned) fresh_rx.deinit();

        try self.packet_crypto.installRfc9001ClientInitialKeys(dcid);
        self.packet_crypto.resetInitialPacketNumberState();
        self.packet_crypto.initial_token = token;
        self.crypto_tx_offset[0] = 0;
        self.crypto_rx[0].deinit();
        self.crypto_rx[0] = fresh_rx;
        fresh_owned = false;

        try self.resendInitial(sender);
    }

    /// Resend the cached Initial CRYPTO bytes after a Retry.
    ///
    /// The payload is identical to the original flight (same ClientHello,
    /// same chunking, same offsets); only the packet protection keys, the
    /// destination CID, and the header token change.
    fn resendInitial(self: *CryptoStream, sender: Sender) !void {
        const bytes = self.initial_crypto.items;
        if (bytes.len == 0) return error.QuicError;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const take: usize = @min(bytes.len - offset, max_crypto_chunk);
            const frame = [_]QuicFrames.Frame{
                .{ .crypto = QuicFrames.CryptoFrame.init(offset, bytes[offset .. offset + take]) },
            };
            try sender.schedule(0, .initial, &frame);
            offset += take;
        }
        self.crypto_tx_offset[0] = bytes.len;
    }
};
