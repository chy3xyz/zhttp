const std = @import("std");
const mem = std.mem;
const huffman = @import("huffman.zig");

/// HPACK: Header Compression for HTTP/2 (RFC 7541)
///
/// Provides encoding and decoding of HTTP/2 header fields using
/// the static table, dynamic table, and Huffman coding.

/// Maximum number of headers we support per field block.
pub const max_decoded_headers = 128;

/// A decoded header field name-value pair.
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

// --- Static Table (RFC 7541 Appendix A) ---

pub const static_table = [_]HeaderField{
    .{ .name = ":authority", .value = "" }, // 1
    .{ .name = ":method", .value = "GET" }, // 2
    .{ .name = ":method", .value = "POST" }, // 3
    .{ .name = ":path", .value = "/" }, // 4
    .{ .name = ":path", .value = "/index.html" }, // 5
    .{ .name = ":scheme", .value = "http" }, // 6
    .{ .name = ":scheme", .value = "https" }, // 7
    .{ .name = ":status", .value = "200" }, // 8
    .{ .name = ":status", .value = "204" }, // 9
    .{ .name = ":status", .value = "206" }, // 10
    .{ .name = ":status", .value = "304" }, // 11
    .{ .name = ":status", .value = "400" }, // 12
    .{ .name = ":status", .value = "404" }, // 13
    .{ .name = ":status", .value = "500" }, // 14
    .{ .name = "accept-charset", .value = "" }, // 15
    .{ .name = "accept-encoding", .value = "gzip, deflate" }, // 16
    .{ .name = "accept-language", .value = "" }, // 17
    .{ .name = "accept-ranges", .value = "" }, // 18
    .{ .name = "accept", .value = "" }, // 19
    .{ .name = "access-control-allow-origin", .value = "" }, // 20
    .{ .name = "age", .value = "" }, // 21
    .{ .name = "allow", .value = "" }, // 22
    .{ .name = "authorization", .value = "" }, // 23
    .{ .name = "cache-control", .value = "" }, // 24
    .{ .name = "content-disposition", .value = "" }, // 25
    .{ .name = "content-encoding", .value = "" }, // 26
    .{ .name = "content-language", .value = "" }, // 27
    .{ .name = "content-length", .value = "" }, // 28
    .{ .name = "content-location", .value = "" }, // 29
    .{ .name = "content-range", .value = "" }, // 30
    .{ .name = "content-type", .value = "" }, // 31
    .{ .name = "cookie", .value = "" }, // 32
    .{ .name = "date", .value = "" }, // 33
    .{ .name = "etag", .value = "" }, // 34
    .{ .name = "expect", .value = "" }, // 35
    .{ .name = "expires", .value = "" }, // 36
    .{ .name = "from", .value = "" }, // 37
    .{ .name = "host", .value = "" }, // 38
    .{ .name = "if-match", .value = "" }, // 39
    .{ .name = "if-modified-since", .value = "" }, // 40
    .{ .name = "if-none-match", .value = "" }, // 41
    .{ .name = "if-range", .value = "" }, // 42
    .{ .name = "if-unmodified-since", .value = "" }, // 43
    .{ .name = "last-modified", .value = "" }, // 44
    .{ .name = "link", .value = "" }, // 45
    .{ .name = "location", .value = "" }, // 46
    .{ .name = "max-forwards", .value = "" }, // 47
    .{ .name = "proxy-authenticate", .value = "" }, // 48
    .{ .name = "proxy-authorization", .value = "" }, // 49
    .{ .name = "range", .value = "" }, // 50
    .{ .name = "referer", .value = "" }, // 51
    .{ .name = "refresh", .value = "" }, // 52
    .{ .name = "retry-after", .value = "" }, // 53
    .{ .name = "server", .value = "" }, // 54
    .{ .name = "set-cookie", .value = "" }, // 55
    .{ .name = "strict-transport-security", .value = "" }, // 56
    .{ .name = "transfer-encoding", .value = "" }, // 57
    .{ .name = "user-agent", .value = "" }, // 58
    .{ .name = "vary", .value = "" }, // 59
    .{ .name = "via", .value = "" }, // 60
    .{ .name = "www-authenticate", .value = "" }, // 61
};

// --- Integer Encoding/Decoding (RFC 7541 §5.1) ---

/// Decode an HPACK integer with the given prefix bit width.
fn decodeInt(data: []const u8, comptime prefix_bits: u4) !struct { value: u32, consumed: usize } {
    if (data.len == 0) return error.HpackDecodingError;

    const mask: u8 = if (prefix_bits == 8) 0xFF else (@as(u8, 1) << @intCast(prefix_bits)) - 1;
    var value: u64 = data[0] & mask;

    if (value < mask) {
        return .{ .value = @intCast(value), .consumed = 1 };
    }

    var i: usize = 1;
    var shift: u6 = 0;
    while (i < data.len) : (i += 1) {
        // Cap M at 28 (RFC 7541 §5.1) so `(b & 0x7F) << M` cannot overflow
        // u64; the value itself is additionally bounded to u32 below.
        if (shift > 28) return error.HpackDecodingError;
        const b = data[i];
        value += @as(u64, b & 0x7F) << @intCast(shift);
        if (value > std.math.maxInt(u32)) return error.HpackDecodingError;
        if (b & 0x80 == 0) {
            return .{ .value = @intCast(value), .consumed = i + 1 };
        }
        shift += 7;
    }
    return error.HpackDecodingError; // incomplete
}

/// Encode an HPACK integer with the given prefix bit width.
/// `first_byte_bits` are the non-prefix bits of the first byte (already shifted).
fn encodeInt(buf: []u8, value: u32, comptime prefix_bits: u4, first_byte_bits: u8) !usize {
    const mask: u8 = if (prefix_bits == 8) 0xFF else (@as(u8, 1) << @intCast(prefix_bits)) - 1;

    if (value < mask) {
        if (buf.len < 1) return error.HpackEncodingError;
        buf[0] = first_byte_bits | @as(u8, @intCast(value));
        return 1;
    }

    if (buf.len < 1) return error.HpackEncodingError;
    buf[0] = first_byte_bits | mask;

    var remaining = value - mask;
    var i: usize = 1;
    while (remaining >= 128) : (i += 1) {
        if (i >= buf.len) return error.HpackEncodingError;
        buf[i] = @intCast((remaining & 0x7F) | 0x80);
        remaining >>= 7;
    }
    if (i >= buf.len) return error.HpackEncodingError;
    buf[i] = @intCast(remaining);
    return i + 1;
}

// --- Dynamic Table (RFC 7541 §2.3.2) ---

/// HPACK dynamic table with FIFO eviction.
pub const DynamicTable = struct {
    /// Storage for entries. Entries are stored as packed name_len(u16) + value_len(u16) + name + value.
    buffer: []u8,
    /// Ring buffer of entry offsets into `buffer`.
    entries: []Entry,
    /// Index of the oldest entry (front of queue).
    head: usize = 0,
    /// Number of active entries.
    len: usize = 0,
    /// Current size in HPACK size units (name.len + value.len + 32 per entry).
    current_size: usize = 0,
    /// Maximum size (set by SETTINGS_HEADER_TABLE_SIZE).
    max_size: usize = 4096,
    /// Write position in buffer.
    buf_pos: usize = 0,

    pub const Entry = struct {
        offset: u32,
        name_len: u16,
        value_len: u16,
    };

    pub fn init(buffer: []u8, entries: []Entry) DynamicTable {
        return .{
            .buffer = buffer,
            .entries = entries,
        };
    }

    fn entrySize(name_len: usize, value_len: usize) usize {
        return name_len + value_len + 32; // RFC 7541 §4.1
    }

    /// Get entry by 0-based dynamic table index (0 = most recently added).
    pub fn get(self: *const DynamicTable, idx: usize) ?HeaderField {
        if (idx >= self.len) return null;
        const actual = (self.head + self.len - 1 - idx) % self.entries.len;
        const entry = self.entries[actual];
        const name_start = entry.offset;
        const name = self.buffer[name_start..][0..entry.name_len];
        const value = self.buffer[name_start + entry.name_len ..][0..entry.value_len];
        return .{ .name = name, .value = value };
    }

    /// Add a new entry, evicting oldest entries if needed.
    pub fn add(self: *DynamicTable, name: []const u8, value: []const u8) void {
        const new_size = entrySize(name.len, value.len);
        const total_data = name.len + value.len;

        // If the new entry is too large for the table, clear everything
        // (RFC 7541 §4.4). Also refuse entries that cannot physically fit in
        // the storage buffer — a peer may raise SETTINGS_HEADER_TABLE_SIZE
        // above our fixed buffer capacity.
        if (new_size > self.max_size or total_data > self.buffer.len) {
            self.clear();
            return;
        }

        // Evict until there's room in size units and in the entry ring.
        while ((self.current_size + new_size > self.max_size or
            self.len >= self.entries.len) and self.len > 0)
        {
            self.evict();
        }

        // Write name + value into buffer
        if (self.buf_pos + total_data > self.buffer.len) {
            self.buf_pos = 0; // wrap around
        }
        const offset = self.buf_pos;
        @memcpy(self.buffer[offset..][0..name.len], name);
        @memcpy(self.buffer[offset + name.len ..][0..value.len], value);
        self.buf_pos += total_data;

        // Add entry to ring buffer
        const idx = (self.head + self.len) % self.entries.len;
        self.entries[idx] = .{
            .offset = @intCast(offset),
            .name_len = @intCast(name.len),
            .value_len = @intCast(value.len),
        };
        self.len += 1;
        self.current_size += new_size;
    }

    fn clear(self: *DynamicTable) void {
        self.len = 0;
        self.current_size = 0;
        self.buf_pos = 0;
        self.head = 0;
    }

    fn evict(self: *DynamicTable) void {
        if (self.len == 0) return;
        const entry = self.entries[self.head];
        self.current_size -= entrySize(entry.name_len, entry.value_len);
        self.head = (self.head + 1) % self.entries.len;
        self.len -= 1;
    }

    /// Update maximum table size, evicting as needed.
    pub fn setMaxSize(self: *DynamicTable, new_max: usize) void {
        self.max_size = new_max;
        while (self.current_size > self.max_size and self.len > 0) {
            self.evict();
        }
    }

    /// Look up a header in the dynamic table. Returns index (0-based) if found.
    pub fn find(self: *const DynamicTable, name: []const u8, value: []const u8) ?struct { index: usize, value_match: bool } {
        var name_match_idx: ?usize = null;
        var i: usize = 0;
        while (i < self.len) : (i += 1) {
            const entry = self.get(i) orelse continue;
            if (mem.eql(u8, entry.name, name)) {
                if (mem.eql(u8, entry.value, value)) {
                    return .{ .index = i, .value_match = true };
                }
                if (name_match_idx == null) {
                    name_match_idx = i;
                }
            }
        }
        if (name_match_idx) |idx| {
            return .{ .index = idx, .value_match = false };
        }
        return null;
    }
};

// --- Decoder ---

pub const Decoder = struct {
    dynamic_table: DynamicTable,

    pub fn init(buffer: []u8, entries: []DynamicTable.Entry) Decoder {
        return .{
            .dynamic_table = DynamicTable.init(buffer, entries),
        };
    }

    /// Look up an index in the combined static + dynamic table.
    /// Index 1-61 = static table, 62+ = dynamic table.
    fn lookup(self: *const Decoder, index: u32) !HeaderField {
        if (index == 0) return error.HpackDecodingError;
        if (index <= static_table.len) {
            return static_table[index - 1];
        }
        const dyn_idx = index - static_table.len - 1;
        return self.dynamic_table.get(dyn_idx) orelse error.HpackDecodingError;
    }

    /// Decode a complete header block fragment into header fields.
    /// Returns the number of headers decoded.
    pub fn decode(self: *Decoder, data: []const u8, headers: []HeaderField) !usize {
        // Reset Huffman scratch buffer for this header block
        huffman_scratch_offset = 0;

        var pos: usize = 0;
        var count: usize = 0;

        while (pos < data.len) {
            if (count >= headers.len) return error.HpackDecodingError;

            const b = data[pos];

            if (b & 0x80 != 0) {
                // Indexed Header Field (RFC 7541 §6.1)
                const result = try decodeInt(data[pos..], 7);
                pos += result.consumed;
                headers[count] = try self.lookup(result.value);
                count += 1;
            } else if (b & 0x40 != 0) {
                // Literal Header Field with Incremental Indexing (RFC 7541 §6.2.1)
                const result = try decodeInt(data[pos..], 6);
                pos += result.consumed;

                var name: []const u8 = undefined;
                if (result.value != 0) {
                    name = (try self.lookup(result.value)).name;
                } else {
                    const str = try decodeString(data[pos..]);
                    name = str.value;
                    pos += str.consumed;
                }

                const value_str = try decodeString(data[pos..]);
                pos += value_str.consumed;

                self.dynamic_table.add(name, value_str.value);
                headers[count] = .{ .name = name, .value = value_str.value };
                count += 1;
            } else if (b & 0x20 != 0) {
                // Dynamic Table Size Update (RFC 7541 §6.3)
                const result = try decodeInt(data[pos..], 5);
                pos += result.consumed;
                self.dynamic_table.setMaxSize(result.value);
            } else {
                // Literal Header Field without Indexing (§6.2.2) or Never Indexed (§6.2.3)
                const result = try decodeInt(data[pos..], 4);
                pos += result.consumed;

                var name: []const u8 = undefined;
                if (result.value != 0) {
                    name = (try self.lookup(result.value)).name;
                } else {
                    const str = try decodeString(data[pos..]);
                    name = str.value;
                    pos += str.consumed;
                }

                const value_str = try decodeString(data[pos..]);
                pos += value_str.consumed;

                // Don't add to dynamic table
                headers[count] = .{ .name = name, .value = value_str.value };
                count += 1;
            }
        }

        return count;
    }

    pub fn setMaxTableSize(self: *Decoder, size: usize) void {
        self.dynamic_table.setMaxSize(size);
    }
};

/// Decode an HPACK string (RFC 7541 §5.2).
/// Huffman encoding is indicated by the high bit of the first byte.
/// When Huffman-encoded, decodes into the scratch buffer at the current
/// offset so multiple decoded strings don't overwrite each other.
fn decodeString(data: []const u8) !struct { value: []const u8, consumed: usize } {
    if (data.len == 0) return error.HpackDecodingError;

    const is_huffman = data[0] & 0x80 != 0;
    const result = try decodeInt(data, 7);
    const str_start = result.consumed;
    const str_len = result.value;

    if (str_start + str_len > data.len) return error.HpackDecodingError;

    const encoded = data[str_start..][0..str_len];

    if (is_huffman) {
        if (huffman_scratch_offset >= huffman_decode_scratch.len)
            return error.HpackDecodingError;
        const remaining = huffman_decode_scratch[huffman_scratch_offset..];
        const dec_len = huffman.decode(remaining, encoded) catch
            return error.HpackDecodingError;
        const value = remaining[0..dec_len];
        huffman_scratch_offset += dec_len;
        return .{
            .value = value,
            .consumed = str_start + str_len,
        };
    }

    return .{
        .value = encoded,
        .consumed = str_start + str_len,
    };
}

/// Scratch buffer for Huffman decoding. Each decoded string occupies
/// a separate region so slices remain valid for the header block.
var huffman_decode_scratch: [16384]u8 = undefined;
var huffman_scratch_offset: usize = 0;

// --- Encoder ---

pub const Encoder = struct {
    dynamic_table: DynamicTable,

    pub fn init(buffer: []u8, entries: []DynamicTable.Entry) Encoder {
        return .{
            .dynamic_table = DynamicTable.init(buffer, entries),
        };
    }

    /// Encode a single header field into the output buffer.
    /// Uses static table lookup and incremental indexing for efficiency.
    /// Returns the number of bytes written.
    pub fn encodeHeader(self: *Encoder, buf: []u8, name: []const u8, value: []const u8) !usize {
        // Try static table first (full match)
        for (static_table, 0..) |entry, i| {
            if (mem.eql(u8, entry.name, name) and mem.eql(u8, entry.value, value)) {
                // Indexed Header Field
                return encodeInt(buf, @intCast(i + 1), 7, 0x80);
            }
        }

        // Try dynamic table (full match)
        if (self.dynamic_table.find(name, value)) |result| {
            if (result.value_match) {
                const index: u32 = @intCast(result.index + static_table.len + 1);
                return encodeInt(buf, index, 7, 0x80);
            }
        }

        // Try static table (name-only match) for incremental indexing
        var name_index: ?u32 = null;
        for (static_table, 0..) |entry, i| {
            if (mem.eql(u8, entry.name, name)) {
                name_index = @intCast(i + 1);
                break;
            }
        }

        // Try dynamic table (name-only match)
        if (name_index == null) {
            if (self.dynamic_table.find(name, value)) |result| {
                name_index = @intCast(result.index + static_table.len + 1);
            }
        }

        var pos: usize = 0;

        if (name_index) |idx| {
            // Literal with Incremental Indexing, indexed name
            pos += try encodeInt(buf[pos..], idx, 6, 0x40);
        } else {
            // Literal with Incremental Indexing, new name
            pos += try encodeInt(buf[pos..], 0, 6, 0x40);
            pos += try encodeString(buf[pos..], name);
        }

        pos += try encodeString(buf[pos..], value);

        // Add to dynamic table
        self.dynamic_table.add(name, value);

        return pos;
    }

    /// Encode a Dynamic Table Size Update.
    pub fn encodeTableSizeUpdate(self: *Encoder, buf: []u8, new_size: u32) !usize {
        self.dynamic_table.setMaxSize(new_size);
        return encodeInt(buf, new_size, 5, 0x20);
    }

    /// Encode a header without adding it to the dynamic table.
    pub fn encodeHeaderWithoutIndexing(buf: []u8, name: []const u8, value: []const u8) !usize {
        // Try static table for name match
        var name_index: ?u32 = null;
        for (static_table, 0..) |entry, i| {
            if (mem.eql(u8, entry.name, name)) {
                name_index = @intCast(i + 1);
                break;
            }
        }

        var pos: usize = 0;
        if (name_index) |idx| {
            pos += try encodeInt(buf[pos..], idx, 4, 0x00);
        } else {
            pos += try encodeInt(buf[pos..], 0, 4, 0x00);
            pos += try encodeString(buf[pos..], name);
        }
        pos += try encodeString(buf[pos..], value);
        return pos;
    }

    pub fn setMaxTableSize(self: *Encoder, size: usize) void {
        self.dynamic_table.setMaxSize(size);
    }
};

/// Encode an HPACK string literal (no Huffman, RFC 7541 §5.2).
fn encodeString(buf: []u8, str: []const u8) !usize {
    const pos = try encodeInt(buf, @intCast(str.len), 7, 0x00);
    if (pos + str.len > buf.len) return error.HpackEncodingError;
    @memcpy(buf[pos..][0..str.len], str);
    return pos + str.len;
}

// --- Tests ---

const testing = std.testing;

test "integer encoding/decoding round-trip" {
    var buf: [8]u8 = undefined;

    // Small value (fits in prefix)
    const n1 = try encodeInt(&buf, 10, 5, 0x00);
    const d1 = try decodeInt(buf[0..n1], 5);
    try testing.expectEqual(@as(u32, 10), d1.value);
    try testing.expectEqual(n1, d1.consumed);

    // Value at prefix boundary
    const n2 = try encodeInt(&buf, 31, 5, 0x00);
    const d2 = try decodeInt(buf[0..n2], 5);
    try testing.expectEqual(@as(u32, 31), d2.value);

    // Large value
    const n3 = try encodeInt(&buf, 1337, 5, 0x00);
    const d3 = try decodeInt(buf[0..n3], 5);
    try testing.expectEqual(@as(u32, 1337), d3.value);
}

test "RFC 7541 §C.1.1: integer encoding example (10 with 5-bit prefix)" {
    var buf: [1]u8 = undefined;
    const n = try encodeInt(&buf, 10, 5, 0x00);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x0A), buf[0]);
}

test "RFC 7541 §C.1.2: integer encoding example (1337 with 5-bit prefix)" {
    var buf: [4]u8 = undefined;
    const n = try encodeInt(&buf, 1337, 5, 0x00);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(@as(u8, 0x1F), buf[0]); // 31
    try testing.expectEqual(@as(u8, 0x9A), buf[1]); // 154 | 0x80
    try testing.expectEqual(@as(u8, 0x0A), buf[2]); // 10
}

test "RFC 7541 §C.1.3: integer encoding example (42 at start of octet)" {
    var buf: [2]u8 = undefined;
    const n = try encodeInt(&buf, 42, 8, 0x00);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 42), buf[0]);
}

test "dynamic table add and get" {
    var buf: [4096]u8 = undefined;
    var entries: [64]DynamicTable.Entry = undefined;
    var dt = DynamicTable.init(&buf, &entries);

    dt.add("custom-header", "custom-value");
    const entry = dt.get(0).?;
    try testing.expectEqualStrings("custom-header", entry.name);
    try testing.expectEqualStrings("custom-value", entry.value);

    // Second entry becomes index 0, first becomes index 1
    dt.add("another", "val");
    const e0 = dt.get(0).?;
    try testing.expectEqualStrings("another", e0.name);
    const e1 = dt.get(1).?;
    try testing.expectEqualStrings("custom-header", e1.name);
}

test "dynamic table eviction" {
    var buf: [256]u8 = undefined;
    var entries: [16]DynamicTable.Entry = undefined;
    var dt = DynamicTable.init(&buf, &entries);
    dt.max_size = 100; // Very small table

    // Each entry size = name.len + value.len + 32
    // "a" + "b" + 32 = 34
    dt.add("a", "b"); // 34 bytes
    dt.add("c", "d"); // 34 bytes -> total 68
    dt.add("e", "f"); // 34 bytes -> total 102, must evict first

    try testing.expectEqual(@as(usize, 2), dt.len);
    const e0 = dt.get(0).?;
    try testing.expectEqualStrings("e", e0.name);
    const e1 = dt.get(1).?;
    try testing.expectEqualStrings("c", e1.name);
}

test "decoder: indexed header from static table" {
    var buf: [4096]u8 = undefined;
    var entries: [64]DynamicTable.Entry = undefined;
    var decoder = Decoder.init(&buf, &entries);
    var headers: [16]HeaderField = undefined;

    // Indexed header field: index 2 = :method GET (0x82)
    const data = [_]u8{0x82};
    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
}

test "decoder: literal with incremental indexing, indexed name" {
    var buf: [4096]u8 = undefined;
    var entries: [64]DynamicTable.Entry = undefined;
    var decoder = Decoder.init(&buf, &entries);
    var headers: [16]HeaderField = undefined;

    // Literal with incremental indexing, name index 1 (:authority), value "example.com"
    const data = [_]u8{
        0x41, // 0100_0001 -> incremental indexing, name index 1
        0x0B, // value length 11 (no Huffman)
    } ++ "example.com".*;

    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings(":authority", headers[0].name);
    try testing.expectEqualStrings("example.com", headers[0].value);

    // Verify it was added to dynamic table
    const dyn = decoder.dynamic_table.get(0).?;
    try testing.expectEqualStrings(":authority", dyn.name);
    try testing.expectEqualStrings("example.com", dyn.value);
}

test "decoder: literal without indexing" {
    var buf: [4096]u8 = undefined;
    var entries: [64]DynamicTable.Entry = undefined;
    var decoder = Decoder.init(&buf, &entries);
    var headers: [16]HeaderField = undefined;

    // Literal without indexing, new name "x", value "y"
    const data = [_]u8{
        0x00, // 0000_0000 -> without indexing, name index 0 (new name)
        0x01, 'x', // name length 1, "x"
        0x01, 'y', // value length 1, "y"
    };

    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("x", headers[0].name);
    try testing.expectEqualStrings("y", headers[0].value);

    // Should NOT be in dynamic table
    try testing.expectEqual(@as(usize, 0), decoder.dynamic_table.len);
}

test "encoder: indexed header from static table" {
    var dbuf: [4096]u8 = undefined;
    var dentries: [64]DynamicTable.Entry = undefined;
    var encoder = Encoder.init(&dbuf, &dentries);

    var out: [64]u8 = undefined;
    const n = try encoder.encodeHeader(&out, ":method", "GET");

    // Should produce indexed header field for static entry 2
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(@as(u8, 0x82), out[0]);
}

test "encoder: literal with incremental indexing" {
    var dbuf: [4096]u8 = undefined;
    var dentries: [64]DynamicTable.Entry = undefined;
    var encoder = Encoder.init(&dbuf, &dentries);

    var out: [128]u8 = undefined;
    const n = try encoder.encodeHeader(&out, "custom-key", "custom-value");

    // Decode what was encoded
    var dec_buf: [4096]u8 = undefined;
    var dec_entries: [64]DynamicTable.Entry = undefined;
    var decoder = Decoder.init(&dec_buf, &dec_entries);
    var headers: [16]HeaderField = undefined;
    const count = try decoder.decode(out[0..n], &headers);

    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("custom-key", headers[0].name);
    try testing.expectEqualStrings("custom-value", headers[0].value);
}

test "encoder/decoder round-trip with multiple headers" {
    var enc_buf: [4096]u8 = undefined;
    var enc_entries: [64]DynamicTable.Entry = undefined;
    var encoder = Encoder.init(&enc_buf, &enc_entries);

    var out: [512]u8 = undefined;
    var pos: usize = 0;

    pos += try encoder.encodeHeader(out[pos..], ":method", "GET");
    pos += try encoder.encodeHeader(out[pos..], ":path", "/");
    pos += try encoder.encodeHeader(out[pos..], ":scheme", "https");
    pos += try encoder.encodeHeader(out[pos..], "custom", "value");

    var dec_buf: [4096]u8 = undefined;
    var dec_entries: [64]DynamicTable.Entry = undefined;
    var decoder = Decoder.init(&dec_buf, &dec_entries);
    var headers: [16]HeaderField = undefined;
    const count = try decoder.decode(out[0..pos], &headers);

    try testing.expectEqual(@as(usize, 4), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
    try testing.expectEqualStrings(":path", headers[1].name);
    try testing.expectEqualStrings("/", headers[1].value);
    try testing.expectEqualStrings(":scheme", headers[2].name);
    try testing.expectEqualStrings("https", headers[2].value);
    try testing.expectEqualStrings("custom", headers[3].name);
    try testing.expectEqualStrings("value", headers[3].value);
}
