//! QUIC packet parsing and serialization
//!
//! Implements QUIC packet format according to RFC 9000

const std = @import("std");
const Io = std.Io;
const Error = @import("../utils/error.zig");

pub const supported_versions = [_]u32{0x00000001};

pub fn isSupportedVersion(version: u32) bool {
    for (supported_versions) |supported| {
        if (version == supported) return true;
    }
    return false;
}

/// QUIC packet types
pub const PacketType = enum(u8) {
    initial = 0x00,
    zero_rtt = 0x10,
    handshake = 0x20,
    retry = 0x30,
    version_negotiation = 0xf0,
    one_rtt = 0x40,
};

/// QUIC packet number space
pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application,
};

pub fn packetNumberSpace(packet_type: PacketType) PacketNumberSpace {
    return switch (packet_type) {
        .initial, .retry, .version_negotiation => .initial,
        .handshake => .handshake,
        .zero_rtt, .one_rtt => .application,
    };
}

pub fn readTruncatedPacketNumber(bytes: []const u8) Error.ZquicError!u64 {
    if (bytes.len == 0 or bytes.len > 4) return Error.ZquicError.InvalidPacket;

    var value: u64 = 0;
    for (bytes) |byte| {
        value = (value << 8) | byte;
    }
    return value;
}

/// Reconstruct a full packet number from the truncated packet number bits.
///
/// Implements RFC 9000 Appendix A using the largest successfully processed
/// packet number in the same packet number space.
pub fn reconstructPacketNumber(
    largest_processed: ?u64,
    truncated_packet_number: u64,
    packet_number_len: u8,
) Error.ZquicError!u64 {
    if (packet_number_len == 0 or packet_number_len > 4) return Error.ZquicError.InvalidPacket;

    const packet_number_bits = @as(u6, @intCast(packet_number_len * 8));
    const packet_number_window = @as(u64, 1) << packet_number_bits;
    const packet_number_half_window = packet_number_window / 2;
    const packet_number_mask = packet_number_window - 1;
    const expected_packet_number = (largest_processed orelse 0) + 1;

    var candidate = (expected_packet_number & ~packet_number_mask) | truncated_packet_number;
    if (candidate + packet_number_half_window <= expected_packet_number) {
        candidate += packet_number_window;
    } else if (candidate > expected_packet_number + packet_number_half_window and candidate >= packet_number_window) {
        candidate -= packet_number_window;
    }

    return candidate;
}

/// Connection ID
pub const ConnectionId = struct {
    data: [20]u8,
    len: u8,

    const Self = @This();

    pub fn init(data: []const u8) Error.ZquicError!Self {
        if (data.len > 20) {
            return Error.ZquicError.InvalidArgument;
        }

        var cid = Self{
            .data = std.mem.zeroes([20]u8),
            .len = @intCast(data.len),
        };

        @memcpy(cid.data[0..data.len], data);
        return cid;
    }

    pub fn bytes(self: *const Self) []const u8 {
        return self.data[0..self.len];
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        if (self.len != other.len) return false;
        return std.mem.eql(u8, self.bytes(), other.bytes());
    }
};

/// QUIC packet header
pub const PacketHeader = struct {
    packet_type: PacketType,
    version: ?u32, // null for short header packets
    dest_conn_id: ConnectionId,
    src_conn_id: ?ConnectionId, // null for short header packets
    packet_number: u64,
    packet_number_len: u8,
    token: ?[]const u8, // for Initial packets
    header_length: usize, // number of bytes consumed by the header

    const Self = @This();

    /// Parse a QUIC packet header from bytes
    pub fn parse(data: []const u8, allocator: std.mem.Allocator) Error.ZquicError!Self {
        if (data.len == 0) {
            return Error.ZquicError.InvalidPacket;
        }

        var offset: usize = 0;
        const first_byte = data[offset];
        offset += 1;

        const header_form = (first_byte & 0x80) != 0;
        const fixed_bit = (first_byte & 0x40) != 0;
        if (!fixed_bit and !header_form) {
            return Error.ZquicError.InvalidPacket;
        }

        if (header_form) {
            // Long header packet
            return parseLongHeader(data, offset, first_byte, allocator);
        } else {
            // Short header packet
            return parseShortHeader(data, offset, first_byte, allocator);
        }
    }

    fn readVarint(data: []const u8, pos: *usize) ?u64 {
        if (pos.* >= data.len) return null;
        const first = data[pos.*];
        const len: usize = @as(usize, 1) << @intCast(first >> 6);
        if (pos.* + len > data.len) return null;
        var value: u64 = first & 0x3f;
        var index: usize = 1;
        while (index < len) : (index += 1) value = (value << 8) | data[pos.* + index];
        pos.* += len;
        return value;
    }

    fn parseLongHeader(data: []const u8, offset: usize, first_byte: u8, allocator: std.mem.Allocator) Error.ZquicError!Self {
        _ = allocator;
        var pos = offset;

        if (pos + 4 > data.len) {
            return Error.ZquicError.InvalidPacket;
        }

        // Parse version
        const version_slice = data[pos .. pos + 4];
        const version_bytes: *const [4]u8 = @ptrCast(version_slice.ptr);
        const version = std.mem.readInt(u32, version_bytes, .big);
        pos += 4;
        if (version != 0 and !((first_byte & 0x40) != 0)) {
            return Error.ZquicError.InvalidPacket;
        }

        // Parse destination connection ID length
        if (pos >= data.len) {
            return Error.ZquicError.InvalidPacket;
        }
        const dest_cid_len = data[pos];
        pos += 1;

        if (pos + dest_cid_len > data.len) {
            return Error.ZquicError.InvalidPacket;
        }

        const dest_conn_id = try ConnectionId.init(data[pos .. pos + dest_cid_len]);
        pos += dest_cid_len;

        // Parse source connection ID length
        if (pos >= data.len) {
            return Error.ZquicError.InvalidPacket;
        }
        const src_cid_len = data[pos];
        pos += 1;

        if (pos + src_cid_len > data.len) {
            return Error.ZquicError.InvalidPacket;
        }

        const src_conn_id = try ConnectionId.init(data[pos .. pos + src_cid_len]);
        pos += src_cid_len;

        if (version == 0) {
            return Self{
                .packet_type = .version_negotiation,
                .version = 0,
                .dest_conn_id = dest_conn_id,
                .src_conn_id = src_conn_id,
                .packet_number = 0,
                .packet_number_len = 0,
                .token = null,
                .header_length = pos,
            };
        }

        if (!isSupportedVersion(version)) {
            return Error.ZquicError.NotSupported;
        }

        const packet_type: PacketType = switch (first_byte & 0x30) {
            0x00 => .initial,
            0x10 => .zero_rtt,
            0x20 => .handshake,
            0x30 => .retry,
            else => return Error.ZquicError.InvalidPacket,
        };

        var token: ?[]const u8 = null;
        if (packet_type == .initial) {
            const token_len = readVarint(data, &pos) orelse return Error.ZquicError.InvalidPacket;
            if (token_len > data.len - pos) return Error.ZquicError.InvalidPacket;
            token = data[pos .. pos + @as(usize, @intCast(token_len))];
            pos += @intCast(token_len);
        }

        return Self{
            .packet_type = packet_type,
            .version = version,
            .dest_conn_id = dest_conn_id,
            .src_conn_id = src_conn_id,
            .packet_number = 0, // Would be parsed from protected header
            .packet_number_len = (first_byte & 0x03) + 1,
            .token = token,
            .header_length = pos, // Track how many bytes were consumed
        };
    }

    fn parseShortHeader(data: []const u8, offset: usize, first_byte: u8, allocator: std.mem.Allocator) Error.ZquicError!Self {
        _ = allocator;
        var pos = offset;

        if ((first_byte & 0x40) == 0) {
            return Error.ZquicError.InvalidPacket;
        }

        // Parse destination connection ID (length is negotiated during handshake)
        // For simplicity, assume 8 bytes
        const dest_cid_len = 8;
        if (pos + dest_cid_len > data.len) {
            return Error.ZquicError.InvalidPacket;
        }

        const dest_conn_id = try ConnectionId.init(data[pos .. pos + dest_cid_len]);
        pos += dest_cid_len;

        return Self{
            .packet_type = .one_rtt,
            .version = null,
            .dest_conn_id = dest_conn_id,
            .src_conn_id = null,
            .packet_number = 0, // Would be parsed from protected header
            .packet_number_len = (first_byte & 0x03) + 1,
            .token = null,
            .header_length = pos, // Track how many bytes were consumed
        };
    }

    /// Serialize packet header to bytes
    pub fn serialize(self: *const Self, writer: anytype) !void {
        switch (self.packet_type) {
            .initial, .zero_rtt, .handshake, .retry => {
                // Long header
                var first_byte: u8 = 0x80; // Header form = 1
                first_byte |= switch (self.packet_type) {
                    .initial => 0x00,
                    .zero_rtt => 0x10,
                    .handshake => 0x20,
                    .retry => 0x30,
                    else => unreachable,
                };

                try writer.writeByte(first_byte);
                try writer.writeInt(u32, self.version.?, .big);
                try writer.writeByte(self.dest_conn_id.len);
                try writer.writeAll(self.dest_conn_id.bytes());

                if (self.src_conn_id) |src_cid| {
                    try writer.writeByte(src_cid.len);
                    try writer.writeAll(src_cid.bytes());
                } else {
                    try writer.writeByte(0);
                }
            },
            .version_negotiation => {
                try writer.writeByte(0x80);
                try writer.writeInt(u32, 0, .big);
                try writer.writeByte(self.dest_conn_id.len);
                try writer.writeAll(self.dest_conn_id.bytes());

                if (self.src_conn_id) |src_cid| {
                    try writer.writeByte(src_cid.len);
                    try writer.writeAll(src_cid.bytes());
                } else {
                    try writer.writeByte(0);
                }
            },
            .one_rtt => {
                // Short header
                const first_byte: u8 = 0x40; // Header form = 0, Fixed bit = 1
                try writer.writeByte(first_byte);
                try writer.writeAll(self.dest_conn_id.bytes());
            },
        }
    }
};

pub const VersionNegotiationPacket = struct {
    dest_conn_id: ConnectionId,
    src_conn_id: ConnectionId,
    version_bytes: []const u8,
    header_length: usize,

    pub fn parse(data: []const u8, allocator: std.mem.Allocator) Error.ZquicError!VersionNegotiationPacket {
        const header = try PacketHeader.parse(data, allocator);
        if (header.packet_type != .version_negotiation or header.version.? != 0) {
            return Error.ZquicError.InvalidPacket;
        }
        if (header.src_conn_id == null) return Error.ZquicError.InvalidPacket;

        const versions_bytes = data[header.header_length..];
        if (versions_bytes.len == 0 or versions_bytes.len % 4 != 0) {
            return Error.ZquicError.InvalidPacket;
        }

        return .{
            .dest_conn_id = header.dest_conn_id,
            .src_conn_id = header.src_conn_id.?,
            .version_bytes = versions_bytes,
            .header_length = header.header_length,
        };
    }

    pub fn versionCount(self: VersionNegotiationPacket) usize {
        return self.version_bytes.len / 4;
    }

    pub fn versionAt(self: VersionNegotiationPacket, index: usize) Error.ZquicError!u32 {
        if (index >= self.versionCount()) return Error.ZquicError.InvalidArgument;
        const version_slice = self.version_bytes[index * 4 ..][0..4];
        const version_bytes: *const [4]u8 = @ptrCast(version_slice.ptr);
        return std.mem.readInt(u32, version_bytes, .big);
    }

    pub fn serializeResponse(
        writer: anytype,
        client_dest_conn_id: ConnectionId,
        client_src_conn_id: ConnectionId,
        versions: []const u32,
    ) Error.ZquicError!void {
        if (versions.len == 0) return Error.ZquicError.InvalidArgument;

        writer.writeByte(0x80) catch return Error.ZquicError.BufferTooSmall;
        writer.writeInt(u32, 0, .big) catch return Error.ZquicError.BufferTooSmall;
        writer.writeByte(client_src_conn_id.len) catch return Error.ZquicError.BufferTooSmall;
        writer.writeAll(client_src_conn_id.bytes()) catch return Error.ZquicError.BufferTooSmall;
        writer.writeByte(client_dest_conn_id.len) catch return Error.ZquicError.BufferTooSmall;
        writer.writeAll(client_dest_conn_id.bytes()) catch return Error.ZquicError.BufferTooSmall;

        for (versions) |version| {
            writer.writeInt(u32, version, .big) catch return Error.ZquicError.BufferTooSmall;
        }
    }
};

/// RFC 9001 Section 5.8 Retry integrity protection key and nonce. These are
/// fixed by the QUIC version and carry no secret: they authenticate the Retry
/// packet against the client's original destination connection ID.
pub const retry_integrity_key = [16]u8{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
pub const retry_integrity_nonce = [12]u8{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

/// Compute the RFC 9001 Section 5.8 Retry Integrity Tag.
///
/// The AEAD input is a pseudo-packet made of the original destination
/// connection ID's length byte, that connection ID, and the Retry packet with
/// its trailing 16-byte tag removed. The plaintext is empty, so AES-128-GCM
/// yields only the authentication tag.
pub fn computeRetryIntegrityTag(
    original_destination_connection_id: []const u8,
    retry_without_tag: []const u8,
) Error.ZquicError![16]u8 {
    if (original_destination_connection_id.len > 20) return Error.ZquicError.InvalidConnectionId;
    const aad_len = 1 + original_destination_connection_id.len + retry_without_tag.len;
    var aad: [1 + 20 + 1200]u8 = undefined;
    if (aad_len > aad.len) return Error.ZquicError.PacketTooLarge;
    aad[0] = @intCast(original_destination_connection_id.len);
    @memcpy(aad[1 .. 1 + original_destination_connection_id.len], original_destination_connection_id);
    @memcpy(aad[1 + original_destination_connection_id.len .. aad_len], retry_without_tag);

    var tag: [16]u8 = undefined;
    Aes128Gcm.encrypt(&.{}, &tag, "", aad[0..aad_len], retry_integrity_nonce, retry_integrity_key);
    return tag;
}

pub const RetryPacket = struct {
    dest_conn_id: ConnectionId,
    src_conn_id: ConnectionId,
    token: []const u8,
    integrity_tag: [16]u8,
    header_length: usize,

    pub fn parse(data: []const u8, allocator: std.mem.Allocator) Error.ZquicError!RetryPacket {
        const header = try PacketHeader.parse(data, allocator);
        if (header.packet_type != .retry or header.version.? != 1) {
            return Error.ZquicError.InvalidPacket;
        }
        if (header.src_conn_id == null) return Error.ZquicError.InvalidPacket;
        if (data.len < header.header_length + 16) return Error.ZquicError.InvalidPacket;

        const token_end = data.len - 16;
        var tag: [16]u8 = undefined;
        @memcpy(&tag, data[token_end..]);

        return .{
            .dest_conn_id = header.dest_conn_id,
            .src_conn_id = header.src_conn_id.?,
            .token = data[header.header_length..token_end],
            .integrity_tag = tag,
            .header_length = header.header_length,
        };
    }

    /// Validate the CID rules from RFC 9000 Section 17.2.5.1: a Retry's
    /// Destination Connection ID MUST equal the Source Connection ID of the
    /// Initial packet that triggered it, and its Source Connection ID becomes
    /// the client's new destination connection ID.
    pub fn validateConnectionIds(
        self: RetryPacket,
        client_initial_source_connection_id: []const u8,
        retry_source_connection_id: []const u8,
    ) Error.ZquicError!void {
        // A zero-length client SCID is legal (RFC 9000 Section 5.1), so only
        // the Retry SCID must be non-empty.
        if (retry_source_connection_id.len == 0) return Error.ZquicError.InvalidConnectionId;
        if (!std.mem.eql(u8, self.dest_conn_id.bytes(), client_initial_source_connection_id)) {
            return Error.ZquicError.InvalidConnectionId;
        }
        if (!std.mem.eql(u8, self.src_conn_id.bytes(), retry_source_connection_id)) {
            return Error.ZquicError.InvalidConnectionId;
        }
    }

    /// Full client-side Retry acceptance check (RFC 9000 Section 17.2.5.1 and
    /// RFC 9001 Section 5.8): CID rules plus the Retry Integrity Tag computed
    /// from the original destination connection ID.
    ///
    /// raw_packet is the complete Retry packet, including the tag.
    pub fn validateClientRetry(
        self: RetryPacket,
        raw_packet: []const u8,
        client_initial_source_connection_id: []const u8,
        original_destination_connection_id: []const u8,
    ) Error.ZquicError!void {
        // RFC 9000 Section 17.2.5.2 forbids a Retry with an empty token.
        if (self.token.len == 0) return Error.ZquicError.InvalidPacket;
        try self.validateConnectionIds(client_initial_source_connection_id, self.src_conn_id.bytes());
        if (raw_packet.len != self.header_length + self.token.len + 16) {
            return Error.ZquicError.InvalidPacket;
        }
        const expected = try computeRetryIntegrityTag(
            original_destination_connection_id,
            raw_packet[0 .. raw_packet.len - 16],
        );
        var diff: u8 = 0;
        for (expected, self.integrity_tag) |a, b| diff |= a ^ b;
        if (diff != 0) return Error.ZquicError.InvalidPacket;
    }
};

pub const StatelessReset = struct {
    pub const token_len = 16;
    pub const min_packet_len = token_len + 5;

    pub fn matches(packet: []const u8, expected_token: *const [token_len]u8) bool {
        if (packet.len < min_packet_len) return false;
        const token = packet[packet.len - token_len ..];
        return std.mem.eql(u8, token, expected_token);
    }
};

/// QUIC packet
pub const Packet = struct {
    header: PacketHeader,
    payload: []const u8,

    const Self = @This();

    pub fn init(header: PacketHeader, payload: []const u8) Self {
        return Self{
            .header = header,
            .payload = payload,
        };
    }
};

test "connection id creation and comparison" {
    const cid1 = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const cid2 = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const cid3 = try ConnectionId.init(&[_]u8{ 1, 2, 3, 5 });

    try std.testing.expect(cid1.eql(&cid2));
    try std.testing.expect(!cid1.eql(&cid3));
    try std.testing.expect(cid1.len == 4);
}

test "packet header serialization" {
    var buffer: [256]u8 = undefined;
    var writer = Io.Writer.fixed(&buffer);

    const dest_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const src_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    const header = PacketHeader{
        .packet_type = .initial,
        .version = 0x00000001,
        .dest_conn_id = dest_cid,
        .src_conn_id = src_cid,
        .packet_number = 0,
        .packet_number_len = 1,
        .token = null,
        .header_length = 0, // Not relevant for serialization test
    };

    try header.serialize(&writer);
    try std.testing.expect(Io.Writer.buffered(&writer).len > 0);
}

test "unsupported long header version is distinguished from malformed packet" {
    const unsupported_initial = [_]u8{
        0xC0,
        0x0A,
        0x0A,
        0x0A,
        0x0A,
        0x04,
        0x01,
        0x02,
        0x03,
        0x04,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
    };

    try std.testing.expectError(Error.ZquicError.NotSupported, PacketHeader.parse(&unsupported_initial, std.testing.allocator));
}

test "version negotiation response swaps client connection ids" {
    const client_dcid = try ConnectionId.init(&[_]u8{ 0xde, 0xad, 0xbe, 0xef });
    const client_scid = try ConnectionId.init(&[_]u8{ 0x01, 0x02, 0x03, 0x04 });

    var buffer: [64]u8 = undefined;
    var writer = Io.Writer.fixed(&buffer);
    try VersionNegotiationPacket.serializeResponse(&writer, client_dcid, client_scid, &supported_versions);

    const written = Io.Writer.buffered(&writer);
    const header = try PacketHeader.parse(written, std.testing.allocator);
    try std.testing.expectEqual(PacketType.version_negotiation, header.packet_type);
    try std.testing.expectEqual(@as(?u32, 0), header.version);
    try std.testing.expectEqualSlices(u8, client_scid.bytes(), header.dest_conn_id.bytes());
    try std.testing.expect(header.src_conn_id != null);
    try std.testing.expectEqualSlices(u8, client_dcid.bytes(), header.src_conn_id.?.bytes());

    const vn = try VersionNegotiationPacket.parse(written, std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), vn.versionCount());
    try std.testing.expectEqual(@as(u32, 0x00000001), try vn.versionAt(0));
}

test "retry integrity tag matches RFC 9001 Appendix A.4" {
    // Appendix A.2's client Initial has an empty Source Connection ID and an
    // original destination connection ID of 0x8394c8f03e515708. Appendix A.4
    // retries it with SCID 0xf067a5502a4262b5 and token "token".
    const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const retry_without_tag = [_]u8{
        0xff, // Long header, fixed bit, Retry
        0x00,
        0x00,
        0x00,
        0x01,
        0x00, // DCID length
        0x08,
        0xf0,
        0x67,
        0xa5,
        0x50,
        0x2a,
        0x42,
        0x62,
        0xb5,
        0x74, 0x6f, 0x6b, 0x65, 0x6e, // "token"
    };
    const expected_tag = [16]u8{
        0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82,
        0x90, 0x58, 0xfb, 0x3f, 0x4d, 0x6b, 0x2f, 0x3e,
    };

    const computed = try computeRetryIntegrityTag(&original_dcid, &retry_without_tag);
    try std.testing.expectEqualSlices(u8, &expected_tag, &computed);

    var packet: [retry_without_tag.len + 16]u8 = undefined;
    @memcpy(packet[0..retry_without_tag.len], &retry_without_tag);
    @memcpy(packet[retry_without_tag.len..], &expected_tag);
    const parsed = try RetryPacket.parse(&packet, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, "token", parsed.token);
    try parsed.validateClientRetry(&packet, &.{}, &original_dcid);

    // The RFC CID rule is about the client's Initial SCID, not the ODCID.
    try std.testing.expectError(
        Error.ZquicError.InvalidConnectionId,
        parsed.validateClientRetry(&packet, &original_dcid, &original_dcid),
    );

    // The tag is bound to the original destination connection ID.
    var wrong_odcid = original_dcid;
    wrong_odcid[7] ^= 0x01;
    try std.testing.expectError(
        Error.ZquicError.InvalidPacket,
        parsed.validateClientRetry(&packet, &.{}, &wrong_odcid),
    );

    // A modified token invalidates the tag.
    var tampered = packet;
    tampered[retry_without_tag.len - 1] ^= 0x01;
    const tampered_retry = try RetryPacket.parse(&tampered, std.testing.allocator);
    try std.testing.expectError(
        Error.ZquicError.InvalidPacket,
        tampered_retry.validateClientRetry(&tampered, &.{}, &original_dcid),
    );

    var long_odcid: [21]u8 = undefined;
    @memset(&long_odcid, 0);
    try std.testing.expectError(
        Error.ZquicError.InvalidConnectionId,
        computeRetryIntegrityTag(&long_odcid, &.{}),
    );
}

test "retry packet validates client initial and retry source connection ids" {
    const retry_packet = [_]u8{
        0xf0, // Long header, fixed bit, Retry
        0x00,
        0x00,
        0x00,
        0x01,
        0x04,
        0xde,
        0xad,
        0xbe,
        0xef,
        0x04,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0x74,
        0x6f,
        0x6b,
        0x65,
        0x6e,
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f,
    };

    const retry = try RetryPacket.parse(&retry_packet, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, "token", retry.token);
    try retry.validateConnectionIds(&[_]u8{ 0xde, 0xad, 0xbe, 0xef }, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd });
    try std.testing.expectError(
        Error.ZquicError.InvalidConnectionId,
        retry.validateConnectionIds(&[_]u8{ 0xde, 0xad, 0xbe, 0xef }, &[_]u8{ 0x01, 0x02, 0x03, 0x04 }),
    );
}

test "stateless reset token matcher requires minimum packet length and token match" {
    const expected_token = [_]u8{
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f,
    };

    const reset_packet = [_]u8{
        0x41, 0xaa, 0xbb, 0xcc, 0xdd,
        0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    };
    try std.testing.expect(StatelessReset.matches(&reset_packet, &expected_token));

    const wrong_token_packet = [_]u8{
        0x41, 0xaa, 0xbb, 0xcc, 0xdd,
        0x10, 0x11, 0x12, 0x13, 0x14,
        0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x00,
    };
    try std.testing.expect(!StatelessReset.matches(&wrong_token_packet, &expected_token));

    const too_short = [_]u8{ 0x41, 0xaa, 0xbb };
    try std.testing.expect(!StatelessReset.matches(&too_short, &expected_token));
}

test "packet number reconstruction follows expected packet number window" {
    try std.testing.expectEqual(@as(u64, 0xabcd), try reconstructPacketNumber(null, 0xabcd, 2));
    try std.testing.expectEqual(@as(u64, 0xabe8), try reconstructPacketNumber(0xabe7, 0xe8, 1));
    try std.testing.expectEqual(@as(u64, 0xac12), try reconstructPacketNumber(0xabe7, 0x12, 1));
    try std.testing.expectEqual(@as(u64, 0xabf0), try reconstructPacketNumber(0xabe7, 0xf0, 1));
    try std.testing.expectEqual(@as(u64, 0x01000010), try reconstructPacketNumber(0x00fffff0, 0x10, 1));
    try std.testing.expectEqual(@as(u64, 0x12345678), try reconstructPacketNumber(0x12340000, 0x5678, 2));
    try std.testing.expectError(Error.ZquicError.InvalidPacket, reconstructPacketNumber(0, 0, 0));
    try std.testing.expectError(Error.ZquicError.InvalidPacket, reconstructPacketNumber(0, 0, 5));
}

test "truncated packet number reader accepts one to four bytes" {
    try std.testing.expectEqual(@as(u64, 0x12), try readTruncatedPacketNumber(&[_]u8{0x12}));
    try std.testing.expectEqual(@as(u64, 0x1234), try readTruncatedPacketNumber(&[_]u8{ 0x12, 0x34 }));
    try std.testing.expectEqual(@as(u64, 0x123456), try readTruncatedPacketNumber(&[_]u8{ 0x12, 0x34, 0x56 }));
    try std.testing.expectEqual(@as(u64, 0x12345678), try readTruncatedPacketNumber(&[_]u8{ 0x12, 0x34, 0x56, 0x78 }));
    try std.testing.expectError(Error.ZquicError.InvalidPacket, readTruncatedPacketNumber(&.{}));
    try std.testing.expectError(Error.ZquicError.InvalidPacket, readTruncatedPacketNumber(&[_]u8{ 1, 2, 3, 4, 5 }));
}
