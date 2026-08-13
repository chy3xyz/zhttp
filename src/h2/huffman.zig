const std = @import("std");

/// HPACK Huffman Coding (RFC 7541 Appendix B)
///
/// Static Huffman table for HTTP/2 header compression.
/// Each symbol (0-255) maps to a fixed bit code. Symbol 256 is EOS.
/// Adapted from the bit-level I/O patterns in github.com/Maartz/huffman_encoding.

/// A Huffman code entry: the bit pattern and its length.
const Code = struct {
    bits: u32,
    len: u6,
};

/// RFC 7541 Appendix B — Huffman code table.
/// Index = byte value (0-255), value 256 = EOS (not used in encoding).
const huffman_table = [257]Code{
    .{ .bits = 0x1ff8, .len = 13 }, // 0
    .{ .bits = 0x7fffd8, .len = 23 }, // 1
    .{ .bits = 0xfffffe2, .len = 28 }, // 2
    .{ .bits = 0xfffffe3, .len = 28 }, // 3
    .{ .bits = 0xfffffe4, .len = 28 }, // 4
    .{ .bits = 0xfffffe5, .len = 28 }, // 5
    .{ .bits = 0xfffffe6, .len = 28 }, // 6
    .{ .bits = 0xfffffe7, .len = 28 }, // 7
    .{ .bits = 0xfffffe8, .len = 28 }, // 8
    .{ .bits = 0xffffea, .len = 24 }, // 9
    .{ .bits = 0x3ffffffc, .len = 30 }, // 10
    .{ .bits = 0xfffffe9, .len = 28 }, // 11
    .{ .bits = 0xfffffea, .len = 28 }, // 12
    .{ .bits = 0x3ffffffd, .len = 30 }, // 13
    .{ .bits = 0xfffffeb, .len = 28 }, // 14
    .{ .bits = 0xfffffec, .len = 28 }, // 15
    .{ .bits = 0xfffffed, .len = 28 }, // 16
    .{ .bits = 0xfffffee, .len = 28 }, // 17
    .{ .bits = 0xfffffef, .len = 28 }, // 18
    .{ .bits = 0xffffff0, .len = 28 }, // 19
    .{ .bits = 0xffffff1, .len = 28 }, // 20
    .{ .bits = 0xffffff2, .len = 28 }, // 21
    .{ .bits = 0x3ffffffe, .len = 30 }, // 22
    .{ .bits = 0xffffff3, .len = 28 }, // 23
    .{ .bits = 0xffffff4, .len = 28 }, // 24
    .{ .bits = 0xffffff5, .len = 28 }, // 25
    .{ .bits = 0xffffff6, .len = 28 }, // 26
    .{ .bits = 0xffffff7, .len = 28 }, // 27
    .{ .bits = 0xffffff8, .len = 28 }, // 28
    .{ .bits = 0xffffff9, .len = 28 }, // 29
    .{ .bits = 0xffffffa, .len = 28 }, // 30
    .{ .bits = 0xffffffb, .len = 28 }, // 31
    .{ .bits = 0x14, .len = 6 }, // 32 ' '
    .{ .bits = 0x3f8, .len = 10 }, // 33 '!'
    .{ .bits = 0x3f9, .len = 10 }, // 34 '"'
    .{ .bits = 0xffa, .len = 12 }, // 35 '#'
    .{ .bits = 0x1ff9, .len = 13 }, // 36 '$'
    .{ .bits = 0x15, .len = 6 }, // 37 '%'
    .{ .bits = 0xf8, .len = 8 }, // 38 '&'
    .{ .bits = 0x7fa, .len = 11 }, // 39 '''
    .{ .bits = 0x3fa, .len = 10 }, // 40 '('
    .{ .bits = 0x3fb, .len = 10 }, // 41 ')'
    .{ .bits = 0xf9, .len = 8 }, // 42 '*'
    .{ .bits = 0x7fb, .len = 11 }, // 43 '+'
    .{ .bits = 0xfa, .len = 8 }, // 44 ','
    .{ .bits = 0x16, .len = 6 }, // 45 '-'
    .{ .bits = 0x17, .len = 6 }, // 46 '.'
    .{ .bits = 0x18, .len = 6 }, // 47 '/'
    .{ .bits = 0x0, .len = 5 }, // 48 '0'
    .{ .bits = 0x1, .len = 5 }, // 49 '1'
    .{ .bits = 0x2, .len = 5 }, // 50 '2'
    .{ .bits = 0x19, .len = 6 }, // 51 '3'
    .{ .bits = 0x1a, .len = 6 }, // 52 '4'
    .{ .bits = 0x1b, .len = 6 }, // 53 '5'
    .{ .bits = 0x1c, .len = 6 }, // 54 '6'
    .{ .bits = 0x1d, .len = 6 }, // 55 '7'
    .{ .bits = 0x1e, .len = 6 }, // 56 '8'
    .{ .bits = 0x1f, .len = 6 }, // 57 '9'
    .{ .bits = 0x5c, .len = 7 }, // 58 ':'
    .{ .bits = 0xfb, .len = 8 }, // 59 ';'
    .{ .bits = 0x7ffc, .len = 15 }, // 60 '<'
    .{ .bits = 0x20, .len = 6 }, // 61 '='
    .{ .bits = 0xffb, .len = 12 }, // 62 '>'
    .{ .bits = 0x3fc, .len = 10 }, // 63 '?'
    .{ .bits = 0x1ffa, .len = 13 }, // 64 '@'
    .{ .bits = 0x21, .len = 6 }, // 65 'A'
    .{ .bits = 0x5d, .len = 7 }, // 66 'B'
    .{ .bits = 0x5e, .len = 7 }, // 67 'C'
    .{ .bits = 0x5f, .len = 7 }, // 68 'D'
    .{ .bits = 0x60, .len = 7 }, // 69 'E'
    .{ .bits = 0x61, .len = 7 }, // 70 'F'
    .{ .bits = 0x62, .len = 7 }, // 71 'G'
    .{ .bits = 0x63, .len = 7 }, // 72 'H'
    .{ .bits = 0x64, .len = 7 }, // 73 'I'
    .{ .bits = 0x65, .len = 7 }, // 74 'J'
    .{ .bits = 0x66, .len = 7 }, // 75 'K'
    .{ .bits = 0x67, .len = 7 }, // 76 'L'
    .{ .bits = 0x68, .len = 7 }, // 77 'M'
    .{ .bits = 0x69, .len = 7 }, // 78 'N'
    .{ .bits = 0x6a, .len = 7 }, // 79 'O'
    .{ .bits = 0x6b, .len = 7 }, // 80 'P'
    .{ .bits = 0x6c, .len = 7 }, // 81 'Q'
    .{ .bits = 0x6d, .len = 7 }, // 82 'R'
    .{ .bits = 0x6e, .len = 7 }, // 83 'S'
    .{ .bits = 0x6f, .len = 7 }, // 84 'T'
    .{ .bits = 0x70, .len = 7 }, // 85 'U'
    .{ .bits = 0x71, .len = 7 }, // 86 'V'
    .{ .bits = 0x72, .len = 7 }, // 87 'W'
    .{ .bits = 0xfc, .len = 8 }, // 88 'X'
    .{ .bits = 0x73, .len = 7 }, // 89 'Y'
    .{ .bits = 0xfd, .len = 8 }, // 90 'Z'
    .{ .bits = 0x1ffb, .len = 13 }, // 91 '['
    .{ .bits = 0x7fff0, .len = 19 }, // 92 '\'
    .{ .bits = 0x1ffc, .len = 13 }, // 93 ']'
    .{ .bits = 0x3ffc, .len = 14 }, // 94 '^'
    .{ .bits = 0x22, .len = 6 }, // 95 '_'
    .{ .bits = 0x7ffd, .len = 15 }, // 96 '`'
    .{ .bits = 0x3, .len = 5 }, // 97 'a'
    .{ .bits = 0x23, .len = 6 }, // 98 'b'
    .{ .bits = 0x4, .len = 5 }, // 99 'c'
    .{ .bits = 0x24, .len = 6 }, // 100 'd'
    .{ .bits = 0x5, .len = 5 }, // 101 'e'
    .{ .bits = 0x25, .len = 6 }, // 102 'f'
    .{ .bits = 0x26, .len = 6 }, // 103 'g'
    .{ .bits = 0x27, .len = 6 }, // 104 'h'
    .{ .bits = 0x6, .len = 5 }, // 105 'i'
    .{ .bits = 0x74, .len = 7 }, // 106 'j'
    .{ .bits = 0x75, .len = 7 }, // 107 'k'
    .{ .bits = 0x28, .len = 6 }, // 108 'l'
    .{ .bits = 0x29, .len = 6 }, // 109 'm'
    .{ .bits = 0x2a, .len = 6 }, // 110 'n'
    .{ .bits = 0x7, .len = 5 }, // 111 'o'
    .{ .bits = 0x2b, .len = 6 }, // 112 'p'
    .{ .bits = 0x76, .len = 7 }, // 113 'q'
    .{ .bits = 0x2c, .len = 6 }, // 114 'r'
    .{ .bits = 0x8, .len = 5 }, // 115 's'
    .{ .bits = 0x9, .len = 5 }, // 116 't'
    .{ .bits = 0x2d, .len = 6 }, // 117 'u'
    .{ .bits = 0x77, .len = 7 }, // 118 'v'
    .{ .bits = 0x78, .len = 7 }, // 119 'w'
    .{ .bits = 0x79, .len = 7 }, // 120 'x'
    .{ .bits = 0x7a, .len = 7 }, // 121 'y'
    .{ .bits = 0x7b, .len = 7 }, // 122 'z'
    .{ .bits = 0x7fffe, .len = 19 }, // 123 '{'
    .{ .bits = 0x7fc, .len = 11 }, // 124 '|'
    .{ .bits = 0x3ffd, .len = 14 }, // 125 '}'
    .{ .bits = 0x1ffd, .len = 13 }, // 126 '~'
    .{ .bits = 0xffffffc, .len = 28 }, // 127
    .{ .bits = 0xfffe6, .len = 20 }, // 128
    .{ .bits = 0x3fffd2, .len = 22 }, // 129
    .{ .bits = 0xfffe7, .len = 20 }, // 130
    .{ .bits = 0xfffe8, .len = 20 }, // 131
    .{ .bits = 0x3fffd3, .len = 22 }, // 132
    .{ .bits = 0x3fffd4, .len = 22 }, // 133
    .{ .bits = 0x3fffd5, .len = 22 }, // 134
    .{ .bits = 0x7fffd9, .len = 23 }, // 135
    .{ .bits = 0x3fffd6, .len = 22 }, // 136
    .{ .bits = 0x7fffda, .len = 23 }, // 137
    .{ .bits = 0x7fffdb, .len = 23 }, // 138
    .{ .bits = 0x7fffdc, .len = 23 }, // 139
    .{ .bits = 0x7fffdd, .len = 23 }, // 140
    .{ .bits = 0x7fffde, .len = 23 }, // 141
    .{ .bits = 0xffffeb, .len = 24 }, // 142
    .{ .bits = 0x7fffdf, .len = 23 }, // 143
    .{ .bits = 0xffffec, .len = 24 }, // 144
    .{ .bits = 0xffffed, .len = 24 }, // 145
    .{ .bits = 0x3fffd7, .len = 22 }, // 146
    .{ .bits = 0x7fffe0, .len = 23 }, // 147
    .{ .bits = 0xffffee, .len = 24 }, // 148
    .{ .bits = 0x7fffe1, .len = 23 }, // 149
    .{ .bits = 0x7fffe2, .len = 23 }, // 150
    .{ .bits = 0x7fffe3, .len = 23 }, // 151
    .{ .bits = 0x7fffe4, .len = 23 }, // 152
    .{ .bits = 0x1fffdc, .len = 21 }, // 153
    .{ .bits = 0x3fffd8, .len = 22 }, // 154
    .{ .bits = 0x7fffe5, .len = 23 }, // 155
    .{ .bits = 0x3fffd9, .len = 22 }, // 156
    .{ .bits = 0x7fffe6, .len = 23 }, // 157
    .{ .bits = 0x7fffe7, .len = 23 }, // 158
    .{ .bits = 0xffffef, .len = 24 }, // 159
    .{ .bits = 0x3fffda, .len = 22 }, // 160
    .{ .bits = 0x1fffdd, .len = 21 }, // 161
    .{ .bits = 0xfffe9, .len = 20 }, // 162
    .{ .bits = 0x3fffdb, .len = 22 }, // 163
    .{ .bits = 0x3fffdc, .len = 22 }, // 164
    .{ .bits = 0x7fffe8, .len = 23 }, // 165
    .{ .bits = 0x7fffe9, .len = 23 }, // 166
    .{ .bits = 0x1fffde, .len = 21 }, // 167
    .{ .bits = 0x7fffea, .len = 23 }, // 168
    .{ .bits = 0x3fffdd, .len = 22 }, // 169
    .{ .bits = 0x3fffde, .len = 22 }, // 170
    .{ .bits = 0xfffff0, .len = 24 }, // 171
    .{ .bits = 0x1fffdf, .len = 21 }, // 172
    .{ .bits = 0x3fffdf, .len = 22 }, // 173
    .{ .bits = 0x7fffeb, .len = 23 }, // 174
    .{ .bits = 0x7fffec, .len = 23 }, // 175
    .{ .bits = 0x1fffe0, .len = 21 }, // 176
    .{ .bits = 0x1fffe1, .len = 21 }, // 177
    .{ .bits = 0x3fffe0, .len = 22 }, // 178
    .{ .bits = 0x1fffe2, .len = 21 }, // 179
    .{ .bits = 0x7fffed, .len = 23 }, // 180
    .{ .bits = 0x3fffe1, .len = 22 }, // 181
    .{ .bits = 0x7fffee, .len = 23 }, // 182
    .{ .bits = 0x7fffef, .len = 23 }, // 183
    .{ .bits = 0xfffea, .len = 20 }, // 184
    .{ .bits = 0x3fffe2, .len = 22 }, // 185
    .{ .bits = 0x3fffe3, .len = 22 }, // 186
    .{ .bits = 0x3fffe4, .len = 22 }, // 187
    .{ .bits = 0x7ffff0, .len = 23 }, // 188
    .{ .bits = 0x3fffe5, .len = 22 }, // 189
    .{ .bits = 0x3fffe6, .len = 22 }, // 190
    .{ .bits = 0x7ffff1, .len = 23 }, // 191
    .{ .bits = 0x3ffffe0, .len = 26 }, // 192
    .{ .bits = 0x3ffffe1, .len = 26 }, // 193
    .{ .bits = 0xfffeb, .len = 20 }, // 194
    .{ .bits = 0x7fff1, .len = 19 }, // 195
    .{ .bits = 0x3fffe7, .len = 22 }, // 196
    .{ .bits = 0x7ffff2, .len = 23 }, // 197
    .{ .bits = 0x3fffe8, .len = 22 }, // 198
    .{ .bits = 0x1ffffec, .len = 25 }, // 199
    .{ .bits = 0x3ffffe2, .len = 26 }, // 200
    .{ .bits = 0x3ffffe3, .len = 26 }, // 201
    .{ .bits = 0x3ffffe4, .len = 26 }, // 202
    .{ .bits = 0x7ffffde, .len = 27 }, // 203
    .{ .bits = 0x7ffffdf, .len = 27 }, // 204
    .{ .bits = 0x3ffffe5, .len = 26 }, // 205
    .{ .bits = 0xfffff1, .len = 24 }, // 206
    .{ .bits = 0x1ffffed, .len = 25 }, // 207
    .{ .bits = 0x7fff2, .len = 19 }, // 208
    .{ .bits = 0x1fffe3, .len = 21 }, // 209
    .{ .bits = 0x3ffffe6, .len = 26 }, // 210
    .{ .bits = 0x7ffffe0, .len = 27 }, // 211
    .{ .bits = 0x7ffffe1, .len = 27 }, // 212
    .{ .bits = 0x3ffffe7, .len = 26 }, // 213
    .{ .bits = 0x7ffffe2, .len = 27 }, // 214
    .{ .bits = 0xfffff2, .len = 24 }, // 215
    .{ .bits = 0x1fffe4, .len = 21 }, // 216
    .{ .bits = 0x1fffe5, .len = 21 }, // 217
    .{ .bits = 0x3ffffe8, .len = 26 }, // 218
    .{ .bits = 0x3ffffe9, .len = 26 }, // 219
    .{ .bits = 0xffffffd, .len = 28 }, // 220
    .{ .bits = 0x7ffffe3, .len = 27 }, // 221
    .{ .bits = 0x7ffffe4, .len = 27 }, // 222
    .{ .bits = 0x7ffffe5, .len = 27 }, // 223
    .{ .bits = 0xfffec, .len = 20 }, // 224
    .{ .bits = 0xfffff3, .len = 24 }, // 225
    .{ .bits = 0xfffed, .len = 20 }, // 226
    .{ .bits = 0x1fffe6, .len = 21 }, // 227
    .{ .bits = 0x3fffe9, .len = 22 }, // 228
    .{ .bits = 0x1fffe7, .len = 21 }, // 229
    .{ .bits = 0x1fffe8, .len = 21 }, // 230
    .{ .bits = 0x7ffff3, .len = 23 }, // 231
    .{ .bits = 0x3fffea, .len = 22 }, // 232
    .{ .bits = 0x3fffeb, .len = 22 }, // 233
    .{ .bits = 0x1ffffee, .len = 25 }, // 234
    .{ .bits = 0x1ffffef, .len = 25 }, // 235
    .{ .bits = 0xfffff4, .len = 24 }, // 236
    .{ .bits = 0xfffff5, .len = 24 }, // 237
    .{ .bits = 0x3ffffea, .len = 26 }, // 238
    .{ .bits = 0x7ffff4, .len = 23 }, // 239
    .{ .bits = 0x3ffffeb, .len = 26 }, // 240
    .{ .bits = 0x7ffffe6, .len = 27 }, // 241
    .{ .bits = 0x3ffffec, .len = 26 }, // 242
    .{ .bits = 0x3ffffed, .len = 26 }, // 243
    .{ .bits = 0x7ffffe7, .len = 27 }, // 244
    .{ .bits = 0x7ffffe8, .len = 27 }, // 245
    .{ .bits = 0x7ffffe9, .len = 27 }, // 246
    .{ .bits = 0x7ffffea, .len = 27 }, // 247
    .{ .bits = 0x7ffffeb, .len = 27 }, // 248
    .{ .bits = 0xfffffffe, .len = 30 }, // 249
    .{ .bits = 0x7ffffec, .len = 27 }, // 250
    .{ .bits = 0x7ffffed, .len = 27 }, // 251
    .{ .bits = 0x7ffffee, .len = 27 }, // 252
    .{ .bits = 0x7ffffef, .len = 27 }, // 253
    .{ .bits = 0x7fffff0, .len = 27 }, // 254
    .{ .bits = 0x3ffffee, .len = 26 }, // 255
    .{ .bits = 0x3fffffff, .len = 30 }, // 256 EOS
};

/// Encode a string using HPACK Huffman coding.
/// Writes encoded bytes into `dst`. Returns the number of bytes written.
pub fn encode(dst: []u8, src: []const u8) !usize {
    var bit_pos: usize = 0; // total bits written

    // Zero the output buffer
    const max_bytes = (encodedLength(src) + 7) / 8;
    if (max_bytes > dst.len) return error.HpackEncodingError;
    @memset(dst[0..max_bytes], 0);

    for (src) |byte| {
        const code = huffman_table[byte];
        // Write `code.len` bits of `code.bits` into dst, MSB first
        // Adapted from BitWriter pattern in Maartz/huffman_encoding
        var remaining: u6 = code.len;
        const bits = code.bits;
        while (remaining > 0) {
            remaining -= 1;
            const bit: u1 = @intCast((bits >> @as(u5, @intCast(remaining))) & 1);
            const byte_idx = bit_pos / 8;
            const bit_idx: u3 = @intCast(7 - (bit_pos % 8));
            dst[byte_idx] |= @as(u8, bit) << bit_idx;
            bit_pos += 1;
        }
    }

    // Pad with 1-bits to byte boundary (RFC 7541 §5.2)
    const padding = (8 - (bit_pos % 8)) % 8;
    var i: usize = 0;
    while (i < padding) : (i += 1) {
        const byte_idx = bit_pos / 8;
        const bit_idx: u3 = @intCast(7 - (bit_pos % 8));
        dst[byte_idx] |= @as(u8, 1) << bit_idx;
        bit_pos += 1;
    }

    return bit_pos / 8;
}

/// Calculate the encoded length in bits for a given input.
pub fn encodedLength(src: []const u8) usize {
    var total: usize = 0;
    for (src) |byte| {
        total += huffman_table[byte].len;
    }
    return total;
}

/// Decode a Huffman-encoded byte sequence.
/// `src` is the encoded data, `dst` receives the decoded bytes.
/// Returns the number of bytes decoded.
///
/// Uses a bit-by-bit accumulator approach similar to the BitReader
/// pattern from Maartz/huffman_encoding, but against the fixed
/// HPACK Huffman table. Matches are found by trying code lengths
/// from shortest (5) to longest (30), ensuring the correct
/// prefix-free match.
pub fn decode(dst: []u8, src: []const u8) !usize {
    var dst_pos: usize = 0;
    var accumulator: u64 = 0;
    var bits_left: u7 = 0;

    for (src) |byte| {
        // `accumulator` is a u64: at most 64 bits of pending input are
        // representable. If more than 56 bits are still unmatched, shifting
        // in another byte would discard the high bits and later make `shift`
        // exceed the 6-bit shift operand range. Treat it as invalid data.
        if (bits_left > 56) return error.HpackDecodingError;
        accumulator = (accumulator << 8) | byte;
        bits_left += 8;

        while (bits_left >= 5) {
            // Try matching from shortest to longest code length.
            // Huffman codes are prefix-free, so the first match by
            // length is the correct one.
            var found = false;
            for (huffman_table[0..256], 0..) |code, sym| {
                if (code.len <= bits_left) {
                    const shift: u7 = bits_left - code.len;
                    const candidate: u32 = @intCast((accumulator >> @intCast(shift)) & ((@as(u64, 1) << @intCast(code.len)) - 1));
                    if (candidate == code.bits) {
                        if (dst_pos >= dst.len) return error.HpackDecodingError;
                        dst[dst_pos] = @intCast(sym);
                        dst_pos += 1;
                        bits_left -= code.len;
                        accumulator &= (@as(u64, 1) << @intCast(bits_left)) - 1;
                        found = true;
                        break;
                    }
                }
            }
            if (!found) break;
        }
    }

    // Remaining bits should be padding (all 1s) of at most 7 bits
    if (bits_left > 7) return error.HpackDecodingError;
    if (bits_left > 0) {
        const mask = (@as(u64, 1) << @intCast(bits_left)) - 1;
        if (accumulator & mask != mask) return error.HpackDecodingError;
    }

    return dst_pos;
}

// --- Tests ---

const testing = std.testing;

test "encode and decode round-trip: simple ASCII" {
    const input = "www.example.com";
    var encoded: [256]u8 = undefined;
    const enc_len = try encode(&encoded, input);

    var decoded: [256]u8 = undefined;
    const dec_len = try decode(&decoded, encoded[0..enc_len]);
    try testing.expectEqualStrings(input, decoded[0..dec_len]);
}

test "encode and decode round-trip: empty string" {
    var encoded: [16]u8 = undefined;
    const enc_len = try encode(&encoded, "");
    try testing.expectEqual(@as(usize, 0), enc_len);

    var decoded: [16]u8 = undefined;
    const dec_len = try decode(&decoded, encoded[0..enc_len]);
    try testing.expectEqual(@as(usize, 0), dec_len);
}

test "encode and decode: header values" {
    const cases = [_][]const u8{
        "no-cache",
        "custom-key",
        "custom-value",
        "/sample/path",
        "Mon, 21 Oct 2013 20:13:21 GMT",
        "https",
        "200",
        "302",
    };
    for (cases) |input| {
        var encoded: [512]u8 = undefined;
        const enc_len = try encode(&encoded, input);

        var decoded: [512]u8 = undefined;
        const dec_len = try decode(&decoded, encoded[0..enc_len]);
        try testing.expectEqualStrings(input, decoded[0..dec_len]);
    }
}

test "encodedLength" {
    // '0' has code length 5, '1' has code length 5
    try testing.expectEqual(@as(usize, 10), encodedLength("01"));
    // 'a' = 5 bits
    try testing.expectEqual(@as(usize, 5), encodedLength("a"));
}

test "padding is all 1-bits" {
    var encoded: [16]u8 = undefined;
    const enc_len = try encode(&encoded, "a"); // 5 bits + 3 padding bits
    try testing.expectEqual(@as(usize, 1), enc_len);
    // 'a' = 00011, padded = 00011|111 = 0x1f
    try testing.expectEqual(@as(u8, 0b00011_111), encoded[0]);
}
