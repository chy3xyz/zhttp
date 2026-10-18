//! QPACK (RFC 9204) for the native HTTP/3 stack.
//!
//! The encoder is static-only. The decoder owns a dynamic table (SETTINGS
//! advertises QPACK_MAX_TABLE_CAPACITY = 4096) and applies the peer's encoder
//! stream instructions. Blocked streams are not implemented: a field section
//! whose Required Insert Count exceeds the current insert count, or whose
//! dynamic references cannot be resolved, is QPACK_DECOMPRESSION_FAILED rather
//! than being queued for later.

const std = @import("std");
const huffman = @import("../../h2/huffman.zig");

pub const Error = error{
    InvalidHeaderBlock,
    /// Static-table-only decode met a dynamic reference, or the HTTP/3 layer
    /// mapped a blocked/invalid dynamic reference to 0x0201.
    DynamicTableReference,
    InvalidIndex,
    InvalidHuffman,
    /// A field section requires inserts the decoder has not applied yet.
    /// Blocked streams are disabled (BLOCKED_STREAMS = 0), so this fails.
    Blocked,
    /// A dynamic-table index, base, or delta base cannot be resolved.
    InvalidDynamicReference,
    /// A capacity update exceeds the advertised maximum, or does not fit.
    CapacityExceeded,
    /// An insert's name + value + 32 exceeds the current table capacity.
    EntryTooLarge,
    OutOfMemory,
};

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

/// QPACK encoder-stream instructions (RFC 9204 section 4.3). The scanner finds
/// complete instruction boundaries; applyEncoderInstruction then mutates the
/// decoder table. Bytes behind a partial instruction must never be consumed.
pub const EncoderInstruction = enum {
    set_dynamic_table_capacity,
    insert_with_name_reference,
    insert_with_literal_name,
    duplicate,
};

/// QPACK decoder-stream instructions (RFC 9204 section 4.4).
pub const DecoderInstruction = enum {
    section_acknowledgment,
    stream_cancellation,
    insert_count_increment,
};

pub const EncoderScan = union(enum) {
    complete: struct {
        instruction: EncoderInstruction,
        end: usize,
        /// Prefix value for Set Dynamic Table Capacity; null for other forms.
        value: ?u64 = null,
    },
    incomplete,
    invalid,
};

pub const DecoderScan = union(enum) {
    complete: struct {
        instruction: DecoderInstruction,
        end: usize,
    },
    incomplete,
    invalid,
};

/// Result of parsing and applying one complete encoder-stream instruction.
pub const EncoderApply = union(enum) {
    applied: struct {
        instruction: EncoderInstruction,
        end: usize,
        /// Set Dynamic Table Capacity value; null for insert/duplicate.
        value: ?u64 = null,
    },
    /// More bytes are needed; the table is unchanged.
    incomplete,
    /// The instruction can never be completed (overlong integer, bad Huffman).
    invalid,
};

const TableEntry = struct {
    name: []const u8,
    value: []const u8,
};

/// RFC 9204 Appendix A. Index is the array position.
pub const static_table = [_]TableEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

/// One decoded header block. The arena owns every name and value.
pub const HeaderList = struct {
    arena: std.heap.ArenaAllocator,
    fields: []HeaderField,

    pub fn deinit(self: *HeaderList) void {
        self.arena.deinit();
    }

    pub fn get(self: *const HeaderList, name: []const u8) ?[]const u8 {
        for (self.fields) |field| {
            if (std.mem.eql(u8, field.name, name)) return field.value;
        }
        return null;
    }
};

const SeenPseudo = struct {
    method: bool = false,
    path: bool = false,
    scheme: bool = false,
    authority: bool = false,
    status: bool = false,

    fn mark(self: *SeenPseudo, name: []const u8) Error!void {
        const slot = if (std.mem.eql(u8, name, ":method"))
            &self.method
        else if (std.mem.eql(u8, name, ":path"))
            &self.path
        else if (std.mem.eql(u8, name, ":scheme"))
            &self.scheme
        else if (std.mem.eql(u8, name, ":authority"))
            &self.authority
        else if (std.mem.eql(u8, name, ":status"))
            &self.status
        else
            return error.InvalidHeaderBlock;
        if (slot.*) return error.InvalidHeaderBlock;
        slot.* = true;
    }
};

/// The decoder's dynamic table. Entries are allocator-owned and kept in
/// increasing absolute index order (oldest first), so FIFO eviction is a
/// prefix removal. The byte size of an entry is name.len + value.len + 32
/// (RFC 9204 section 3.2.1).
pub const DynamicTable = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayListUnmanaged(TableEntry) = .empty,
    /// Current capacity in bytes, set by the peer's Set Dynamic Table Capacity.
    capacity: usize = 0,
    /// Maximum capacity this endpoint advertised in SETTINGS.
    max_capacity: usize = 0,
    /// Absolute number of insertions ever performed. Entries remain indexed by
    /// their original absolute index even after eviction.
    insert_count: u64 = 0,
    /// Sum of the sizes of the live entries.
    size: usize = 0,

    pub fn init(allocator: std.mem.Allocator, max_capacity: usize) DynamicTable {
        return .{ .allocator = allocator, .max_capacity = max_capacity };
    }

    pub fn deinit(self: *DynamicTable) void {
        for (self.entries.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const DynamicTable) usize {
        return self.entries.items.len;
    }

    /// Change the current capacity. Reducing it evicts oldest-first until the
    /// live entries fit. A capacity above the advertised maximum is rejected.
    pub fn setCapacity(self: *DynamicTable, capacity: usize) Error!void {
        if (capacity > self.max_capacity) return error.CapacityExceeded;
        self.capacity = capacity;
        while (self.size > self.capacity) self.evictOldest();
    }

    /// Insert an entry, evicting oldest entries until it fits. The entry is
    /// rejected before touching the table if it can never fit.
    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) Error!void {
        const entry_size = entrySize(name, value);
        if (entry_size > self.capacity) return error.EntryTooLarge;

        // Duplicate the input before eviction: name/value may borrow from an
        // entry this insert is about to evict (duplicate and name-reference
        // inserts do exactly that).
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        while (self.size + entry_size > self.capacity) self.evictOldest();

        try self.entries.append(self.allocator, .{
            .name = owned_name,
            .value = owned_value,
        });
        self.size += entry_size;
        self.insert_count += 1;
    }

    /// Apply an insertion whose name comes from the static table or a relative
    /// dynamic-table index (0 is the most recently inserted entry).
    pub fn insertWithNameReference(
        self: *DynamicTable,
        is_static: bool,
        index: u64,
        value: []const u8,
    ) Error!void {
        const entry = if (is_static) blk: {
            if (index >= static_table.len) return error.InvalidIndex;
            break :blk static_table[@intCast(index)];
        } else self.getRelative(index) orelse return error.InvalidIndex;
        return self.insert(entry.name, value);
    }

    /// Insert a field whose name is carried literally.
    pub fn insertWithLiteralName(self: *DynamicTable, name: []const u8, value: []const u8) Error!void {
        return self.insert(name, value);
    }

    /// Duplicate the entry at a relative dynamic-table index.
    pub fn duplicate(self: *DynamicTable, relative_index: u64) Error!void {
        const entry = self.getRelative(relative_index) orelse return error.InvalidIndex;
        return self.insert(entry.name, entry.value);
    }

    /// Resolve a relative index (0 = most recent) against the live table.
    pub fn getRelative(self: *const DynamicTable, relative_index: u64) ?TableEntry {
        if (relative_index >= self.insert_count) return null;
        return self.getAbsolute(self.insert_count - 1 - relative_index);
    }

    /// Resolve an absolute insert index. Evicted entries are no longer
    /// resolvable even though their index is below insert_count.
    pub fn getAbsolute(self: *const DynamicTable, absolute_index: u64) ?TableEntry {
        if (absolute_index >= self.insert_count) return null;
        const newest_offset = self.insert_count - 1 - absolute_index;
        if (newest_offset >= self.entries.items.len) return null;
        return self.entries.items[self.entries.items.len - 1 - @as(usize, @intCast(newest_offset))];
    }

    fn evictOldest(self: *DynamicTable) void {
        const entry = self.entries.orderedRemove(0);
        self.size -= entrySize(entry.name, entry.value);
        self.allocator.free(entry.name);
        self.allocator.free(entry.value);
    }
};

fn entrySize(name: []const u8, value: []const u8) usize {
    return name.len + value.len + 32;
}

/// Decoder-side QPACK state: the dynamic table and the maximum capacity this
/// endpoint advertised. One instance lives in each HTTP/3 Session.
pub const Decoder = struct {
    allocator: std.mem.Allocator,
    table: DynamicTable,
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY advertised by this endpoint. This is
    /// the upper bound for the peer's Set Dynamic Table Capacity and the basis
    /// for Required Insert Count wraparound (RFC 9204 section 4.5.1.1).
    max_capacity: usize,

    pub fn init(allocator: std.mem.Allocator, max_capacity: usize) Decoder {
        return .{
            .allocator = allocator,
            .table = DynamicTable.init(allocator, max_capacity),
            .max_capacity = max_capacity,
        };
    }

    pub fn deinit(self: *Decoder) void {
        self.table.deinit();
        self.* = undefined;
    }

    pub fn insertCount(self: *const Decoder) u64 {
        return self.table.insert_count;
    }

    /// Decode one complete field section. The table must already contain every
    /// entry the section references; otherwise this returns Blocked (there is
    /// no blocked-stream queue) or InvalidDynamicReference.
    pub fn decodeBlock(self: *Decoder, block: []const u8) Error!HeaderList {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const a = arena.allocator();

        if (block.len < 2) return error.InvalidHeaderBlock;
        var cursor: usize = 0;

        const encoded_required_insert_count = try readPrefixedInt(block, &cursor, 8);
        const required_insert_count = try decodeRequiredInsertCount(
            encoded_required_insert_count,
            self.table.insert_count,
            self.max_capacity,
        );
        if (required_insert_count > self.table.insert_count) return error.Blocked;
        if (cursor >= block.len) return error.InvalidHeaderBlock;

        // Delta Base: sign bit plus a 7-bit prefix, relative to the Required
        // Insert Count (RFC 9204 section 4.5.1.2).
        const negative_base = block[cursor] & 0x80 != 0;
        const delta_base = try readPrefixedInt(block, &cursor, 7);

        var base: u64 = 0;
        if (required_insert_count == 0) {
            // A zero Required Insert Count means a static-only field section,
            // so Delta Base must be zero too.
            if (negative_base or delta_base != 0) return error.InvalidDynamicReference;
        } else if (negative_base) {
            if (delta_base >= required_insert_count) return error.InvalidDynamicReference;
            base = required_insert_count - delta_base - 1;
        } else {
            base = std.math.add(u64, required_insert_count, delta_base) catch
                return error.InvalidDynamicReference;
        }

        var fields: std.ArrayListUnmanaged(HeaderField) = .empty;
        errdefer fields.deinit(a);

        var seen_regular = false;
        var seen: SeenPseudo = .{};
        while (cursor < block.len) {
            const first = block[cursor];
            if (first & 0x80 != 0) {
                // Indexed Field Line: 1 T + 6-bit index.
                const is_static = first & 0x40 != 0;
                const index = try readPrefixedInt(block, &cursor, 6);
                const entry = if (is_static)
                    try staticEntry(index)
                else
                    try self.resolvePreBase(base, required_insert_count, index);
                try appendDecodedField(a, &fields, &seen, &seen_regular, entry.name, entry.value);
            } else if (first & 0xc0 == 0x40) {
                // Literal Field Line with Name Reference: 01 N T + 4-bit index.
                const is_static = first & 0x10 != 0;
                const index = try readPrefixedInt(block, &cursor, 4);
                const entry = if (is_static)
                    try staticEntry(index)
                else
                    try self.resolvePreBase(base, required_insert_count, index);
                const value = try readString(a, block, &cursor);
                try appendDecodedField(a, &fields, &seen, &seen_regular, entry.name, value);
            } else if (first & 0xe0 == 0x20) {
                // Literal Field Line with Literal Name: 001 N H + 3-bit length.
                const name_huffman = first & 0x08 != 0;
                const name_len = try readPrefixedInt(block, &cursor, 3);
                if (name_len > block.len - cursor) return error.InvalidHeaderBlock;
                const name = try decodeString(
                    a,
                    block[cursor .. cursor + @as(usize, @intCast(name_len))],
                    name_huffman,
                );
                cursor += @intCast(name_len);
                const value = try readString(a, block, &cursor);
                try appendDecodedField(a, &fields, &seen, &seen_regular, name, value);
            } else if (first & 0xf0 == 0x10) {
                // Indexed Field Line with Post-Base Index: 0001 + 4-bit index.
                const index = try readPrefixedInt(block, &cursor, 4);
                const entry = try self.resolvePostBase(base, required_insert_count, index);
                try appendDecodedField(a, &fields, &seen, &seen_regular, entry.name, entry.value);
            } else {
                // Literal Field Line with Post-Base Name Reference:
                // 0000 N + 3-bit index, then the value.
                const index = try readPrefixedInt(block, &cursor, 3);
                const entry = try self.resolvePostBase(base, required_insert_count, index);
                const value = try readString(a, block, &cursor);
                try appendDecodedField(a, &fields, &seen, &seen_regular, entry.name, value);
            }
        }

        return .{
            .arena = arena,
            .fields = try fields.toOwnedSlice(a),
        };
    }

    fn resolvePreBase(
        self: *const Decoder,
        base: u64,
        required_insert_count: u64,
        index: u64,
    ) Error!TableEntry {
        if (required_insert_count == 0) return error.InvalidDynamicReference;
        if (base <= index) return error.InvalidDynamicReference;
        const absolute_index = base - index - 1;
        if (absolute_index >= required_insert_count) return error.InvalidDynamicReference;
        return self.table.getAbsolute(absolute_index) orelse error.InvalidDynamicReference;
    }

    fn resolvePostBase(
        self: *const Decoder,
        base: u64,
        required_insert_count: u64,
        index: u64,
    ) Error!TableEntry {
        if (required_insert_count == 0) return error.InvalidDynamicReference;
        const absolute_index = std.math.add(u64, base, index) catch
            return error.InvalidDynamicReference;
        if (absolute_index >= required_insert_count) return error.InvalidDynamicReference;
        return self.table.getAbsolute(absolute_index) orelse error.InvalidDynamicReference;
    }
};

/// Decode the wrapped Required Insert Count (RFC 9204 section 4.5.1.1).
/// `max_capacity` is the value this endpoint advertised, so MaxEntries is
/// floor(max_capacity / 32) even while the current table capacity is smaller.
fn decodeRequiredInsertCount(
    encoded: u64,
    insert_count: u64,
    max_capacity: usize,
) Error!u64 {
    if (encoded == 0) return 0;
    const max_entries: u64 = @intCast(max_capacity / 32);
    if (max_entries == 0) return error.Blocked;
    const full_range = max_entries * 2;
    if (encoded > full_range) return error.Blocked;

    const max_value = std.math.add(u64, insert_count, max_entries) catch
        std.math.maxInt(u64);
    const max_wrapped = (max_value / full_range) * full_range;
    var required = max_wrapped + encoded - 1;
    if (required > max_value) {
        if (required <= full_range) return error.Blocked;
        required -= full_range;
    }
    if (required == 0) return error.Blocked;
    return required;
}

fn staticEntry(index: u64) Error!TableEntry {
    if (index >= static_table.len) return error.InvalidIndex;
    return static_table[@intCast(index)];
}

fn appendDecodedField(
    allocator: std.mem.Allocator,
    fields: *std.ArrayListUnmanaged(HeaderField),
    seen: *SeenPseudo,
    seen_regular: *bool,
    name: []const u8,
    value: []const u8,
) Error!void {
    try validateName(name);
    if (name.len > 0 and name[0] == ':') {
        if (seen_regular.*) return error.InvalidHeaderBlock;
        try seen.mark(name);
    } else {
        seen_regular.* = true;
    }
    try fields.append(allocator, .{
        .name = try allocator.dupe(u8, name),
        .value = try allocator.dupe(u8, value),
    });
}
/// Static-only wrapper retained for the fuzz harness and callers that never
/// install a decoder table. Dynamic prefixes and field lines are reported as
/// DynamicTableReference, as they were before the decoder existed.
pub fn decode(allocator: std.mem.Allocator, block: []const u8) Error!HeaderList {
    var decoder = Decoder.init(allocator, 0);
    defer decoder.deinit();
    return decoder.decodeBlock(block) catch |err| switch (err) {
        error.Blocked, error.InvalidDynamicReference => error.DynamicTableReference,
        else => err,
    };
}

/// Encode a header list for a peer that advertises a zero-capacity dynamic
/// table. Exact static-table matches use indexed field lines; everything else
/// uses a literal with a static name reference where possible.
pub fn encode(allocator: std.mem.Allocator, fields: []const HeaderField) Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    // Required Insert Count = 0, Delta Base = 0.
    try out.append(allocator, 0);
    try out.append(allocator, 0);

    for (fields) |field| {
        try validateName(field.name);
        if (findStaticExact(field)) |index| {
            const first: u8 = 0xc0; // 1, static
            try writePrefixedInt(allocator, &out, first, 6, index);
            continue;
        }
        if (findStaticName(field.name)) |index| {
            const first: u8 = 0x50; // 01, static
            try writePrefixedInt(allocator, &out, first, 4, index);
            try writeString(allocator, &out, field.value);
            continue;
        }
        // Literal name, no Huffman: 001 N H + 3-bit name length.
        try writePrefixedInt(allocator, &out, 0x20, 3, field.name.len);
        try out.appendSlice(allocator, field.name);
        try writeString(allocator, &out, field.value);
    }

    return out.toOwnedSlice(allocator);
}

fn findStaticExact(field: HeaderField) ?u64 {
    for (static_table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, field.name) and std.mem.eql(u8, entry.value, field.value)) {
            return @intCast(i);
        }
    }
    return null;
}

fn findStaticName(name: []const u8) ?u64 {
    for (static_table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name)) return @intCast(i);
    }
    return null;
}

fn validateName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidHeaderBlock;
    for (name) |ch| {
        if (std.ascii.isUpper(ch) or ch == 0 or ch == '\r' or ch == '\n') {
            return error.InvalidHeaderBlock;
        }
    }
}

fn readString(allocator: std.mem.Allocator, data: []const u8, cursor: *usize) Error![]u8 {
    if (cursor.* >= data.len) return error.InvalidHeaderBlock;
    const huffman_bit = data[cursor.*] & 0x80 != 0;
    const len = try readPrefixedInt(data, cursor, 7);
    if (len > data.len - cursor.*) return error.InvalidHeaderBlock;
    const encoded = data[cursor.* .. cursor.* + @as(usize, @intCast(len))];
    cursor.* += @intCast(len);
    return decodeString(allocator, encoded, huffman_bit);
}

fn decodeString(allocator: std.mem.Allocator, encoded: []const u8, is_huffman: bool) Error![]u8 {
    if (!is_huffman) return allocator.dupe(u8, encoded) catch error.OutOfMemory;

    // RFC 7541's Huffman code is shared by HPACK and QPACK. The longest code
    // is 30 bits, so decoding never expands beyond 2 bytes per encoded byte.
    const capacity = @max(encoded.len * 2 + 16, 64);
    const decoded = allocator.alloc(u8, capacity) catch return error.OutOfMemory;
    const n = huffman.decode(decoded, encoded) catch {
        allocator.free(decoded);
        return error.InvalidHuffman;
    };
    return allocator.realloc(decoded, n) catch decoded[0..n];
}

fn writeString(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: []const u8) Error!void {
    try writePrefixedInt(allocator, out, 0, 7, value.len);
    try out.appendSlice(allocator, value);
}

/// Scan one complete encoder-stream instruction starting at `offset`.
/// `incomplete` means more stream bytes are needed; `invalid` means the
/// integer representation can never be completed (overlong).
pub fn scanEncoderInstruction(data: []const u8, offset: usize) EncoderScan {
    if (offset >= data.len) return .incomplete;
    var cursor = offset;
    const first = data[cursor];
    if (first & 0x80 != 0) {
        // Insert With Name Reference: 1 T + 6-bit name index, then value.
        _ = readInt(data, &cursor, 6) catch |err| return encoderScanFailure(err);
        skipString(data, &cursor) catch |err| return encoderScanFailure(err);
        return .{ .complete = .{ .instruction = .insert_with_name_reference, .end = cursor } };
    }
    if (first & 0xc0 == 0x40) {
        // Insert With Literal Name: 01 H + 5-bit name length, name, value.
        const name_len = readInt(data, &cursor, 5) catch |err| return encoderScanFailure(err);
        const name_bytes = std.math.cast(usize, name_len) orelse return .invalid;
        if (name_bytes > data.len - cursor) return .incomplete;
        cursor += name_bytes;
        skipString(data, &cursor) catch |err| return encoderScanFailure(err);
        return .{ .complete = .{ .instruction = .insert_with_literal_name, .end = cursor } };
    }
    if (first & 0xe0 == 0x20) {
        // Set Dynamic Table Capacity: 001 + 5-bit capacity.
        const capacity = readInt(data, &cursor, 5) catch |err| return encoderScanFailure(err);
        return .{ .complete = .{ .instruction = .set_dynamic_table_capacity, .end = cursor, .value = capacity } };
    }
    // Duplicate: 000 + 5-bit index.
    _ = readInt(data, &cursor, 5) catch |err| return encoderScanFailure(err);
    return .{ .complete = .{ .instruction = .duplicate, .end = cursor } };
}

/// Parse one encoder-stream instruction and apply it to the decoder table.
/// Truncated instructions return .incomplete without changing the table.
/// Structural errors (overlong integer, invalid Huffman) return .invalid;
/// table violations (entry too large, bad index, capacity > advertised max)
/// return an Error. The HTTP/3 layer maps all of these to 0x0202.
pub fn applyEncoderInstruction(
    decoder: *Decoder,
    data: []const u8,
    offset: usize,
) Error!EncoderApply {
    if (offset >= data.len) return .incomplete;
    var cursor = offset;
    const first = data[cursor];

    if (first & 0x80 != 0) {
        // Insert With Name Reference: 1 T + 6-bit name index, then value.
        const is_static = first & 0x40 != 0;
        const index = readInt(data, &cursor, 6) catch |err| return encoderApplyFailure(err);
        const encoded_value = readEncodedString(data, &cursor) catch |err|
            return encoderApplyFailure(err);
        const value = decodeEncodedString(decoder.allocator, encoded_value) catch |err| switch (err) {
            error.InvalidHuffman => return .invalid,
            else => return err,
        };
        defer decoder.allocator.free(value);
        try decoder.table.insertWithNameReference(is_static, index, value);
        return .{ .applied = .{
            .instruction = .insert_with_name_reference,
            .end = cursor,
        } };
    }

    if (first & 0xc0 == 0x40) {
        // Insert With Literal Name: 01 H + 5-bit name length, name, value.
        const encoded_name = readLiteralName(data, &cursor) catch |err|
            return encoderApplyFailure(err);
        const name = decodeEncodedString(decoder.allocator, encoded_name) catch |err| switch (err) {
            error.InvalidHuffman => return .invalid,
            else => return err,
        };
        defer decoder.allocator.free(name);
        const encoded_value = readEncodedString(data, &cursor) catch |err|
            return encoderApplyFailure(err);
        const value = decodeEncodedString(decoder.allocator, encoded_value) catch |err| switch (err) {
            error.InvalidHuffman => return .invalid,
            else => return err,
        };
        defer decoder.allocator.free(value);
        try decoder.table.insertWithLiteralName(name, value);
        return .{ .applied = .{
            .instruction = .insert_with_literal_name,
            .end = cursor,
        } };
    }

    if (first & 0xe0 == 0x20) {
        // Set Dynamic Table Capacity: 001 + 5-bit capacity.
        const capacity = readInt(data, &cursor, 5) catch |err|
            return encoderApplyFailure(err);
        const value = std.math.cast(usize, capacity) orelse return error.CapacityExceeded;
        try decoder.table.setCapacity(value);
        return .{ .applied = .{
            .instruction = .set_dynamic_table_capacity,
            .end = cursor,
            .value = capacity,
        } };
    }

    // Duplicate: 000 + 5-bit dynamic-table relative index.
    const index = readInt(data, &cursor, 5) catch |err| return encoderApplyFailure(err);
    try decoder.table.duplicate(index);
    return .{ .applied = .{
        .instruction = .duplicate,
        .end = cursor,
    } };
}

const EncodedString = struct {
    bytes: []const u8,
    huffman: bool,
};

fn readEncodedString(
    data: []const u8,
    cursor: *usize,
) error{ Truncated, Overlong }!EncodedString {
    if (cursor.* >= data.len) return error.Truncated;
    const huffman_bit = data[cursor.*] & 0x80 != 0;
    const len = try readInt(data, cursor, 7);
    const bytes_len = std.math.cast(usize, len) orelse return error.Overlong;
    if (bytes_len > data.len - cursor.*) return error.Truncated;
    const bytes = data[cursor.* .. cursor.* + bytes_len];
    cursor.* += bytes_len;
    return .{ .bytes = bytes, .huffman = huffman_bit };
}

fn readLiteralName(
    data: []const u8,
    cursor: *usize,
) error{ Truncated, Overlong }!EncodedString {
    if (cursor.* >= data.len) return error.Truncated;
    const huffman_bit = data[cursor.*] & 0x20 != 0;
    const len = try readInt(data, cursor, 5);
    const bytes_len = std.math.cast(usize, len) orelse return error.Overlong;
    if (bytes_len > data.len - cursor.*) return error.Truncated;
    const bytes = data[cursor.* .. cursor.* + bytes_len];
    cursor.* += bytes_len;
    return .{ .bytes = bytes, .huffman = huffman_bit };
}

fn decodeEncodedString(allocator: std.mem.Allocator, encoded: EncodedString) Error![]u8 {
    return decodeString(allocator, encoded.bytes, encoded.huffman);
}

fn encoderApplyFailure(err: error{ Truncated, Overlong }) EncoderApply {
    return switch (err) {
        error.Truncated => .incomplete,
        error.Overlong => .invalid,
    };
}

/// Scan one complete decoder-stream instruction starting at `offset`.
pub fn scanDecoderInstruction(data: []const u8, offset: usize) DecoderScan {
    if (offset >= data.len) return .incomplete;
    var cursor = offset;
    const first = data[cursor];
    if (first & 0x80 != 0) {
        // Section Acknowledgment: 1 + 7-bit stream ID.
        _ = readInt(data, &cursor, 7) catch |err| return decoderScanFailure(err);
        return .{ .complete = .{ .instruction = .section_acknowledgment, .end = cursor } };
    }
    if (first & 0xc0 == 0x40) {
        // Stream Cancellation: 01 + 6-bit stream ID.
        _ = readInt(data, &cursor, 6) catch |err| return decoderScanFailure(err);
        return .{ .complete = .{ .instruction = .stream_cancellation, .end = cursor } };
    }
    // Insert Count Increment: 00 + 6-bit increment.
    _ = readInt(data, &cursor, 6) catch |err| return decoderScanFailure(err);
    return .{ .complete = .{ .instruction = .insert_count_increment, .end = cursor } };
}

fn encoderScanFailure(err: error{ Truncated, Overlong }) EncoderScan {
    return switch (err) {
        error.Truncated => .incomplete,
        error.Overlong => .invalid,
    };
}

fn decoderScanFailure(err: error{ Truncated, Overlong }) DecoderScan {
    return switch (err) {
        error.Truncated => .incomplete,
        error.Overlong => .invalid,
    };
}

/// HPACK-style prefixed integer (RFC 7541 section 5.1) shared by header
/// field lines and QPACK stream instructions.
fn readInt(
    data: []const u8,
    cursor: *usize,
    comptime prefix_bits: u4,
) error{ Truncated, Overlong }!u64 {
    if (cursor.* >= data.len) return error.Truncated;
    const mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    var value: u64 = data[cursor.*] & mask;
    cursor.* += 1;
    if (value < mask) return value;

    var shift: u7 = 0;
    while (true) {
        if (cursor.* >= data.len) return error.Truncated;
        const byte = data[cursor.*];
        cursor.* += 1;
        if (shift > 56) return error.Overlong;
        const chunk: u64 = @as(u64, byte & 0x7f);
        const shifted = @shlWithOverflow(chunk, @as(u6, @intCast(shift)));
        if (shifted[1] != 0) return error.Overlong;
        const sum = @addWithOverflow(value, shifted[0]);
        if (sum[1] != 0) return error.Overlong;
        value = sum[0];
        if (byte & 0x80 == 0) break;
        shift += 7;
    }
    return value;
}

fn skipString(data: []const u8, cursor: *usize) error{ Truncated, Overlong }!void {
    // H bit plus a 7-bit length; the H bit only describes the string encoding.
    const len = try readInt(data, cursor, 7);
    const bytes = std.math.cast(usize, len) orelse return error.Overlong;
    if (bytes > data.len - cursor.*) return error.Truncated;
    cursor.* += bytes;
}

fn readPrefixedInt(data: []const u8, cursor: *usize, comptime prefix_bits: u4) Error!u64 {
    return readInt(data, cursor, prefix_bits) catch |err| switch (err) {
        error.Truncated, error.Overlong => error.InvalidHeaderBlock,
    };
}

fn writePrefixedInt(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    first_bits: u8,
    comptime prefix_bits: u4,
    value_in: u64,
) Error!void {
    const mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    var value = value_in;
    if (value < mask) {
        try out.append(allocator, first_bits | @as(u8, @intCast(value)));
        return;
    }
    try out.append(allocator, first_bits | mask);
    value -= mask;
    while (value >= 0x80) {
        try out.append(allocator, @as(u8, @intCast(value & 0x7f)) | 0x80);
        value >>= 7;
    }
    try out.append(allocator, @intCast(value));
}

test "QPACK: RFC 9204 B.1 literal with static name reference" {
    const block = [_]u8{ 0x00, 0x00, 0x51, 0x0b } ++ "/index.html".*;
    var list = try decode(std.testing.allocator, &block);
    defer list.deinit();
    try std.testing.expectEqual(@as(usize, 1), list.fields.len);
    try std.testing.expectEqualStrings(":path", list.fields[0].name);
    try std.testing.expectEqualStrings("/index.html", list.fields[0].value);
}

test "QPACK: encode/decode roundtrip with static and literal fields" {
    const fields = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "user-agent", .value = "zhttp-native/0.1" },
        .{ .name = "x-custom", .value = "hello" },
    };
    const encoded = try encode(std.testing.allocator, &fields);
    defer std.testing.allocator.free(encoded);

    var list = try decode(std.testing.allocator, encoded);
    defer list.deinit();
    try std.testing.expectEqual(fields.len, list.fields.len);
    for (fields, list.fields) |want, got| {
        try std.testing.expectEqualStrings(want.name, got.name);
        try std.testing.expectEqualStrings(want.value, got.value);
    }
}

test "QPACK: status + content-length + content-type block" {
    const block = [_]u8{ 0x00, 0x00, 0xd9, 0x54, 0x04 } ++ "1024".* ++ [_]u8{0xf5};
    var list = try decode(std.testing.allocator, &block);
    defer list.deinit();
    try std.testing.expectEqual(@as(usize, 3), list.fields.len);
    try std.testing.expectEqualStrings(":status", list.fields[0].name);
    try std.testing.expectEqualStrings("200", list.fields[0].value);
    try std.testing.expectEqualStrings("content-length", list.fields[1].name);
    try std.testing.expectEqualStrings("1024", list.fields[1].value);
    try std.testing.expectEqualStrings("content-type", list.fields[2].name);
    try std.testing.expectEqualStrings("text/plain", list.fields[2].value);
}

test "QPACK: huffman value from a real peer decodes" {
    // Literal with name reference to static index 53 (content-type), plain
    // value "text/plain". Index 53 needs the 4-bit prefix continuation.
    const block = [_]u8{ 0x00, 0x00, 0x5f, 0x26, 0x0a } ++ "text/plain".*;
    var list = try decode(std.testing.allocator, &block);
    defer list.deinit();
    try std.testing.expectEqual(@as(usize, 1), list.fields.len);
    try std.testing.expectEqualStrings("content-type", list.fields[0].name);
    try std.testing.expectEqualStrings("text/plain", list.fields[0].value);
}

test "QPACK: dynamic table references are a distinct error" {
    // Required Insert Count 1 followed by a zero delta base.
    try std.testing.expectError(error.DynamicTableReference, decode(std.testing.allocator, &.{ 0x01, 0x00 }));
    // Zero base, then an indexed field line with the static bit clear.
    try std.testing.expectError(error.DynamicTableReference, decode(std.testing.allocator, &.{ 0x00, 0x00, 0x80 }));
}

test "QPACK: encoder stream instructions scan incrementally" {
    // Set Dynamic Table Capacity 31: 001 11111, continuation 0.
    const capacity = [_]u8{ 0x3f, 0x00 };
    const cap_scan = scanEncoderInstruction(&capacity, 0);
    try std.testing.expectEqual(EncoderInstruction.set_dynamic_table_capacity, cap_scan.complete.instruction);
    try std.testing.expectEqual(@as(usize, 2), cap_scan.complete.end);
    try std.testing.expectEqual(@as(?u64, 31), cap_scan.complete.value);

    // Capacity zero is a legal redundant update against our zero-capacity table.
    const zero_capacity = [_]u8{0x20};
    const zero_scan = scanEncoderInstruction(&zero_capacity, 0);
    try std.testing.expectEqual(EncoderInstruction.set_dynamic_table_capacity, zero_scan.complete.instruction);
    try std.testing.expectEqual(@as(?u64, 0), zero_scan.complete.value);
    try std.testing.expectEqual(@as(usize, 1), zero_scan.complete.end);

    // One byte of a two-byte capacity instruction: not complete, no progress.
    try std.testing.expect(scanEncoderInstruction(capacity[0..1], 0) == .incomplete);

    // Insert With Name Reference: static index 0 and an empty value.
    const insert = [_]u8{ 0xc0, 0x00 };
    const insert_scan = scanEncoderInstruction(&insert, 0);
    try std.testing.expectEqual(EncoderInstruction.insert_with_name_reference, insert_scan.complete.instruction);
    try std.testing.expectEqual(@as(usize, 2), insert_scan.complete.end);

    // Duplicate: 000 + index 0.
    const duplicate = [_]u8{0x00};
    const dup_scan = scanEncoderInstruction(&duplicate, 0);
    try std.testing.expectEqual(EncoderInstruction.duplicate, dup_scan.complete.instruction);
    try std.testing.expectEqual(@as(usize, 1), dup_scan.complete.end);
}

test "QPACK: dynamic table insert, eviction, duplicate, and capacity" {
    var table = DynamicTable.init(std.testing.allocator, 128);
    defer table.deinit();

    // Capacity starts at zero, so even a small insert is rejected until the
    // peer sends Set Dynamic Table Capacity.
    try std.testing.expectError(error.EntryTooLarge, table.insert("x", "1"));
    try table.setCapacity(100);

    try table.insert("x", "1");
    try table.insert("y", "2");
    try std.testing.expectEqual(@as(u64, 2), table.insert_count);
    try std.testing.expectEqual(@as(usize, 2), table.len());
    try std.testing.expectEqual(@as(usize, 68), table.size);
    try std.testing.expectEqualStrings("y", table.getRelative(0).?.name);
    try std.testing.expectEqualStrings("x", table.getRelative(1).?.name);
    try std.testing.expect(table.getRelative(2) == null);
    try std.testing.expectEqualStrings("x", table.getAbsolute(0).?.name);

    // Duplicate the newest entry. Three 34-byte entries do not fit in 100
    // bytes, so the oldest entry is evicted.
    try table.duplicate(0);
    try std.testing.expectEqual(@as(u64, 3), table.insert_count);
    try std.testing.expectEqual(@as(usize, 2), table.len());
    try std.testing.expectEqual(@as(usize, 68), table.size);
    try std.testing.expectEqualStrings("2", table.getRelative(0).?.value);
    try std.testing.expect(table.getAbsolute(0) == null);

    // Reducing capacity evicts oldest-first. Only the newest 34-byte entry
    // survives.
    try table.setCapacity(40);
    try std.testing.expectEqual(@as(usize, 1), table.len());
    try std.testing.expectEqual(@as(usize, 34), table.size);
    try std.testing.expectEqualStrings("2", table.getRelative(0).?.value);
    try std.testing.expect(table.getRelative(1) == null);

    // An entry whose name + value + 32 exceeds the capacity is rejected, as
    // is a capacity above the advertised maximum.
    try std.testing.expectError(error.EntryTooLarge, table.insert("long", "value"));
    try std.testing.expectError(error.CapacityExceeded, table.setCapacity(129));
}

test "QPACK: dynamic table rejects invalid indices and resolves name refs" {
    var table = DynamicTable.init(std.testing.allocator, 128);
    defer table.deinit();
    try table.setCapacity(128);

    try std.testing.expectError(error.InvalidIndex, table.duplicate(0));
    try table.insert("x", "one");
    try std.testing.expectError(error.InvalidIndex, table.duplicate(1));
    try std.testing.expectError(
        error.InvalidIndex,
        table.insertWithNameReference(false, 1, "two"),
    );
    try std.testing.expectError(
        error.InvalidIndex,
        table.insertWithNameReference(true, static_table.len, "two"),
    );

    // Static and dynamic name references both insert a new entry with the
    // referenced name.
    try table.insertWithNameReference(true, 0, "authority-value");
    try std.testing.expectEqualStrings(":authority", table.getRelative(0).?.name);
    try std.testing.expectEqualStrings("authority-value", table.getRelative(0).?.value);

    try table.insertWithNameReference(false, 0, "one");
    try std.testing.expectEqualStrings(":authority", table.getRelative(0).?.name);
    try std.testing.expectEqualStrings("one", table.getRelative(0).?.value);
    try std.testing.expectEqual(@as(u64, 3), table.insert_count);
}

test "QPACK: decoder resolves pre-base and post-base dynamic references" {
    var decoder = Decoder.init(std.testing.allocator, 4096);
    defer decoder.deinit();
    try decoder.table.setCapacity(4096);
    try decoder.table.insert("x-dyn", "one");
    try decoder.table.insert("y-dyn", "two");

    // RIC 2 encodes as 3 (2 mod 256 + 1). Delta Base 0 with Base == RIC = 2.
    // Pre-base index 0 is the newest entry.
    var newest = try decoder.decodeBlock(&.{ 0x03, 0x00, 0x80 });
    defer newest.deinit();
    try std.testing.expectEqual(@as(usize, 1), newest.fields.len);
    try std.testing.expectEqualStrings("y-dyn", newest.fields[0].name);
    try std.testing.expectEqualStrings("two", newest.fields[0].value);

    var older = try decoder.decodeBlock(&.{ 0x03, 0x00, 0x81 });
    defer older.deinit();
    try std.testing.expectEqualStrings("x-dyn", older.fields[0].name);
    try std.testing.expectEqualStrings("one", older.fields[0].value);

    // Negative Delta Base of 0 gives Base == RIC - 1 = 1. Post-base index 0
    // resolves to absolute index 1; index 1 would be absolute 2, which does
    // not exist yet.
    var post = try decoder.decodeBlock(&.{ 0x03, 0x80, 0x10 });
    defer post.deinit();
    try std.testing.expectEqualStrings("y-dyn", post.fields[0].name);
    try std.testing.expectEqualStrings("two", post.fields[0].value);
    try std.testing.expectError(
        error.InvalidDynamicReference,
        decoder.decodeBlock(&.{ 0x03, 0x80, 0x11 }),
    );

    // Literal with a pre-base dynamic name reference.
    var literal = try decoder.decodeBlock(&.{ 0x03, 0x00, 0x40, 0x01, 'v' });
    defer literal.deinit();
    try std.testing.expectEqualStrings("y-dyn", literal.fields[0].name);
    try std.testing.expectEqualStrings("v", literal.fields[0].value);

    // Literal with a post-base dynamic name reference.
    var literal_post = try decoder.decodeBlock(&.{ 0x03, 0x80, 0x00, 0x01, 'w' });
    defer literal_post.deinit();
    try std.testing.expectEqualStrings("y-dyn", literal_post.fields[0].name);
    try std.testing.expectEqualStrings("w", literal_post.fields[0].value);
}

test "QPACK: blocked and invalid dynamic references fail" {
    var decoder = Decoder.init(std.testing.allocator, 4096);
    defer decoder.deinit();
    try decoder.table.setCapacity(64);
    try decoder.table.insert("x", "y");

    // RIC 2 needs two inserts but the table has one: a blocked field section.
    try std.testing.expectError(
        error.Blocked,
        decoder.decodeBlock(&.{ 0x03, 0x00 }),
    );

    // Negative Delta Base larger than RIC underflows.
    try std.testing.expectError(
        error.InvalidDynamicReference,
        decoder.decodeBlock(&.{ 0x02, 0x81 }),
    );
    // Pre-base index at or above Base underflows.
    try std.testing.expectError(
        error.InvalidDynamicReference,
        decoder.decodeBlock(&.{ 0x02, 0x00, 0x81 }),
    );
    // A dynamic field line is inconsistent with RIC == 0.
    try std.testing.expectError(
        error.InvalidDynamicReference,
        decoder.decodeBlock(&.{ 0x00, 0x00, 0x80 }),
    );

    // Evict the entry, insert another, then reference the evicted absolute
    // index through a pre-base index. insert_count is 2, so RIC 2 works.
    try decoder.table.setCapacity(0);
    try decoder.table.setCapacity(64);
    try decoder.table.insert("z", "w");
    try std.testing.expectError(
        error.InvalidDynamicReference,
        decoder.decodeBlock(&.{ 0x03, 0x00, 0x81 }),
    );
}

test "QPACK: decoder stream instructions scan incrementally" {
    const ack = [_]u8{0x80};
    const ack_scan = scanDecoderInstruction(&ack, 0);
    try std.testing.expectEqual(DecoderInstruction.section_acknowledgment, ack_scan.complete.instruction);

    const cancellation = [_]u8{0x40};
    const cancel_scan = scanDecoderInstruction(&cancellation, 0);
    try std.testing.expectEqual(DecoderInstruction.stream_cancellation, cancel_scan.complete.instruction);

    const increment = [_]u8{0x00};
    const inc_scan = scanDecoderInstruction(&increment, 0);
    try std.testing.expectEqual(DecoderInstruction.insert_count_increment, inc_scan.complete.instruction);

    // Section Acknowledgment needs a continuation byte before it is complete.
    try std.testing.expect(scanDecoderInstruction(&.{0xff}, 0) == .incomplete);
}
