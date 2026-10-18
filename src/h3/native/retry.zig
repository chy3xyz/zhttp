//! Server-side QUIC Retry tokens and Retry packet construction.
//!
//! The listener validates a client's address before allocating a Connection:
//! the first tokenless Initial gets an HMAC-authenticated token in a Retry
//! packet; the next Initial presents that token and only then is a connection
//! created. Tokens are stateless and bound to the client address and both
//! connection IDs.

const std = @import("std");

pub const token_lifetime_us: u64 = 30 * std.time.ns_per_s;
pub const max_token_len = 64;
pub const max_retry_packet_len = 1200;

const token_version: u8 = 1;
const token_fixed_len = 16;
const tag_len = 16;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

// RFC 9001 section 5.8 Retry integrity protection key and nonce.
const retry_key = [16]u8{ 0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e };
const retry_nonce = [12]u8{ 0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb };

pub const Retry = struct {
    key: [32]u8,

    pub fn init(key: [32]u8) Retry {
        return .{ .key = key };
    }

    pub fn makeToken(
        self: *const Retry,
        odcid: []const u8,
        address: []const u8,
        retry_scid: []const u8,
        client_scid: []const u8,
        now_us: u64,
        out: *[max_token_len]u8,
    ) ![]const u8 {
        if (odcid.len > 20 or address.len != 6 or retry_scid.len > 20 or client_scid.len > 20) {
            return error.InvalidTokenInput;
        }
        const prefix_len = token_fixed_len + odcid.len;
        if (prefix_len + tag_len > out.len) return error.InvalidTokenInput;

        out[0] = token_version;
        @memcpy(out[1..7], address);
        std.mem.writeInt(u64, out[7..15], now_us, .big);
        out[15] = @intCast(odcid.len);
        @memcpy(out[16 .. 16 + odcid.len], odcid);

        var mac = HmacSha256.init(&self.key);
        mac.update(out[0..prefix_len]);
        mac.update(retry_scid);
        mac.update(client_scid);
        var full: [32]u8 = undefined;
        mac.final(&full);
        @memcpy(out[prefix_len .. prefix_len + tag_len], full[0..tag_len]);
        return out[0 .. prefix_len + tag_len];
    }

    /// Returns the original destination connection ID carried by a valid
    /// token, or null when the token is malformed, expired, for another
    /// address, or not bound to these connection IDs.
    pub fn verifyToken(
        self: *const Retry,
        token: []const u8,
        address: []const u8,
        retry_scid: []const u8,
        client_scid: []const u8,
        now_us: u64,
    ) ?[20]u8 {
        if (token.len < token_fixed_len + tag_len) return null;
        if (address.len != 6 or token[0] != token_version) return null;
        if (!std.mem.eql(u8, token[1..7], address)) return null;

        const issued = std.mem.readInt(u64, token[7..15], .big);
        if (now_us < issued or now_us - issued > token_lifetime_us) return null;

        const odcid_len = token[15];
        if (odcid_len > 20) return null;
        const prefix_len = token_fixed_len + odcid_len;
        if (token.len != prefix_len + tag_len) return null;

        var mac = HmacSha256.init(&self.key);
        mac.update(token[0..prefix_len]);
        mac.update(retry_scid);
        mac.update(client_scid);
        var full: [32]u8 = undefined;
        mac.final(&full);
        if (!std.crypto.timing_safe.eql([tag_len]u8, full[0..tag_len].*, token[prefix_len..][0..tag_len].*)) return null;

        var odcid: [20]u8 = @splat(0);
        @memcpy(odcid[0..odcid_len], token[16..prefix_len]);
        return odcid;
    }

    /// Build the RFC 9000 Retry packet. The client's next Initial uses the
    /// returned SCID as its destination connection ID and copies the token.
    pub fn buildPacket(
        odcid: []const u8,
        client_scid: []const u8,
        retry_scid: []const u8,
        token: []const u8,
        out: *[max_retry_packet_len]u8,
    ) ![]const u8 {
        if (odcid.len > 20 or client_scid.len > 20 or retry_scid.len > 20) return error.InvalidRetryInput;
        if (8 + client_scid.len + retry_scid.len + token.len + tag_len > out.len) return error.InvalidRetryInput;

        var pos: usize = 0;
        out[pos] = 0xf0; // long header, fixed bit, Retry type, unused nibble 0
        pos += 1;
        std.mem.writeInt(u32, out[pos..][0..4], 0x00000001, .big);
        pos += 4;
        out[pos] = @intCast(client_scid.len);
        pos += 1;
        @memcpy(out[pos .. pos + client_scid.len], client_scid);
        pos += client_scid.len;
        out[pos] = @intCast(retry_scid.len);
        pos += 1;
        @memcpy(out[pos .. pos + retry_scid.len], retry_scid);
        pos += retry_scid.len;
        @memcpy(out[pos .. pos + token.len], token);
        pos += token.len;

        var aad_buf: [1 + 20 + max_retry_packet_len]u8 = undefined;
        aad_buf[0] = @intCast(odcid.len);
        @memcpy(aad_buf[1 .. 1 + odcid.len], odcid);
        @memcpy(aad_buf[1 + odcid.len .. 1 + odcid.len + pos], out[0..pos]);
        const aad = aad_buf[0 .. 1 + odcid.len + pos];

        var tag: [tag_len]u8 = undefined;
        Aes128Gcm.encrypt(&.{}, &tag, "", aad, retry_nonce, retry_key);
        @memcpy(out[pos .. pos + tag_len], &tag);
        return out[0 .. pos + tag_len];
    }
};

const testing = std.testing;

fn testAddress() [6]u8 {
    return .{ 127, 0, 0, 1, 0x1f, 0x90 };
}

test "Retry token round trip binds address and connection IDs" {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*byte, index| byte.* = @intCast(index);
    const retry = Retry.init(key);
    const address = testAddress();
    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const retry_scid = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };
    const client_scid = [_]u8{ 17, 18, 19, 20, 21, 22, 23, 24 };
    var token_buf: [max_token_len]u8 = undefined;
    const token = try retry.makeToken(&odcid, &address, &retry_scid, &client_scid, 1_000_000, &token_buf);

    const got = retry.verifyToken(token, &address, &retry_scid, &client_scid, 1_500_000).?;
    try testing.expectEqualSlices(u8, &odcid, got[0..odcid.len]);

    var wrong_address = address;
    wrong_address[5] +%= 1;
    try testing.expect(retry.verifyToken(token, &wrong_address, &retry_scid, &client_scid, 1_500_000) == null);
    try testing.expect(retry.verifyToken(token, &address, &client_scid, &client_scid, 1_500_000) == null);
    try testing.expect(retry.verifyToken(token, &address, &retry_scid, &retry_scid, 1_500_000) == null);
    try testing.expect(retry.verifyToken(token, &address, &retry_scid, &client_scid, 1_000_000 + token_lifetime_us + 1) == null);
    try testing.expect(retry.verifyToken(token, &address, &retry_scid, &client_scid, 999_999) == null);
}

test "Retry packet construction emits a long-header Retry with a tag" {
    const odcid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const client_scid = [_]u8{ 9, 10, 11, 12, 13, 14, 15, 16 };
    const retry_scid = [_]u8{ 17, 18, 19, 20, 21, 22, 23, 24 };
    const token = [_]u8{ 0xaa, 0xbb, 0xcc };
    var out: [max_retry_packet_len]u8 = undefined;
    const packet = try Retry.buildPacket(&odcid, &client_scid, &retry_scid, &token, &out);

    try testing.expectEqual(@as(u8, 0xf0), packet[0]);
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, packet[1..5], .big));
    try testing.expectEqual(@as(u8, 8), packet[5]);
    try testing.expectEqualSlices(u8, &client_scid, packet[6..14]);
    try testing.expectEqual(@as(u8, 8), packet[14]);
    try testing.expectEqualSlices(u8, &retry_scid, packet[15..23]);
    try testing.expectEqualSlices(u8, &token, packet[23..26]);
    try testing.expectEqual(@as(usize, 26 + tag_len), packet.len);
}
