//! QPACK (RFC 9204) for the native HTTP/3 stack.
//!
//! The decoder owns a dynamic table (SETTINGS advertises
//! QPACK_MAX_TABLE_CAPACITY = 4096) and applies the peer's encoder stream
//! instructions. The encoder owns a second dynamic table bounded by the peer's
//! SETTINGS_QPACK_MAX_TABLE_CAPACITY: it inserts field values that are likely
//! to repeat, serializes the matching encoder-stream instructions, and
//! references entries from field sections only when the peer can resolve them
//! (acknowledged inserts, or within the peer's blocked-stream limit). This
//! module also serializes the three decoder-stream instructions (Insert Count
//! Increment, Section Acknowledgment, and Stream Cancellation) into fixed-size
//! bytes. http3.Session owns both QPACK streams, queues those bytes, parks
//! field sections whose Required Insert Count is not yet satisfied, and
//! retries them as inserts arrive.

const std = @import("std");
const huffman = @import("../../h2/huffman.zig");

pub const Error = error{
    InvalidHeaderBlock,
    /// Static-table-only decode met a dynamic reference, or the HTTP/3 layer
    /// mapped a blocked/invalid dynamic reference to 0x0201.
    DynamicTableReference,
    InvalidIndex,
    InvalidHuffman,
    /// A field section requires inserts the decoder has not applied yet, or
    /// its Required Insert Count prefix is outside the wraparound window.
    /// http3.Session parks the frame when the RIC is still reachable.
    Blocked,
    /// A dynamic-table index, base, or delta base cannot be resolved.
    InvalidDynamicReference,
    /// A capacity update exceeds the advertised maximum, or does not fit.
    CapacityExceeded,
    /// An insert's name + value + 32 exceeds the current table capacity.
    EntryTooLarge,
    /// An encoder insert would have to evict an entry that an outstanding
    /// field section still references.
    WouldEvictReferenced,
    /// The peer's decoder stream sent an Insert Count Increment of zero or
    /// larger than the number of inserts it has not acknowledged yet.
    InvalidInsertCountIncrement,
    /// The peer's decoder stream acknowledged a stream with no outstanding
    /// dynamic reference.
    UnexpectedSectionAcknowledgment,
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
        /// Stream ID for Section Acknowledgment / Stream Cancellation, or the
        /// increment for Insert Count Increment.
        value: u64 = 0,
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
    /// Outstanding field sections that reference this entry. Only the
    /// encoder's table uses it: an entry with a nonzero count must not be
    /// evicted until the peer acknowledges or cancels the section. The
    /// decoder leaves it at zero.
    refs: u32 = 0,
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
    /// Required Insert Count of the decoded field section. Zero means the
    /// section is static-only and needs no Section Acknowledgment.
    required_insert_count: u64 = 0,

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

    /// Insert like insert, but never evict an entry that an outstanding field
    /// section references. The encoder uses this after canEvictFor succeeds;
    /// an entry referenced by a section whose Section Acknowledgment is still
    /// outstanding must stay resolvable for the peer.
    pub fn insertAvoidingReferenced(self: *DynamicTable, name: []const u8, value: []const u8) Error!void {
        const entry_size = entrySize(name, value);
        if (entry_size > self.capacity) return error.EntryTooLarge;
        if (!self.canEvictFor(entry_size)) return error.WouldEvictReferenced;

        // Duplicate the input before eviction: name/value may borrow from an
        // entry this insert is about to evict.
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

    /// True when inserting an entry of entry_size bytes only evicts entries
    /// that no outstanding field section references.
    pub fn canEvictFor(self: *const DynamicTable, entry_size: usize) bool {
        if (entry_size > self.capacity) return false;
        var projected = self.size;
        var index: usize = 0;
        while (projected + entry_size > self.capacity) {
            if (index >= self.entries.items.len) return false;
            if (self.entries.items[index].refs != 0) return false;
            projected -= entrySize(
                self.entries.items[index].name,
                self.entries.items[index].value,
            );
            index += 1;
        }
        return true;
    }

    /// Record one outstanding reference to a live entry. Returns false when
    /// the absolute index is no longer in the table.
    pub fn addReference(self: *DynamicTable, absolute_index: u64) bool {
        const index = self.entryIndex(absolute_index) orelse return false;
        const entry = &self.entries.items[index];
        if (entry.refs < std.math.maxInt(u32)) entry.refs += 1;
        return true;
    }

    /// Drop one outstanding reference. Returns false when the entry has
    /// already been evicted (which an encoder must never let happen while
    /// refs is nonzero).
    pub fn releaseReference(self: *DynamicTable, absolute_index: u64) bool {
        const index = self.entryIndex(absolute_index) orelse return false;
        const entry = &self.entries.items[index];
        if (entry.refs > 0) entry.refs -= 1;
        return true;
    }

    /// Number of outstanding references to an entry, zero once it is evicted.
    pub fn referenceCount(self: *const DynamicTable, absolute_index: u64) u32 {
        const index = self.entryIndex(absolute_index) orelse return 0;
        return self.entries.items[index].refs;
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
        const index = self.entryIndex(absolute_index) orelse return null;
        return self.entries.items[index];
    }

    /// Array position of an absolute insert index, or null once evicted.
    fn entryIndex(self: *const DynamicTable, absolute_index: u64) ?usize {
        if (absolute_index >= self.insert_count) return null;
        const newest_offset = self.insert_count - 1 - absolute_index;
        if (newest_offset >= self.entries.items.len) return null;
        return self.entries.items.len - 1 - @as(usize, @intCast(newest_offset));
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

/// SETTINGS_QPACK_BLOCKED_STREAMS cap applied to our encoder. The peer sets
/// the actual limit; capping keeps the number of streams it can park bounded.
pub const encoder_blocked_streams_cap: usize = 16;

/// Only field name + value pairs at least this long are inserted. Every table
/// entry costs 32 bytes of overhead, so short values are cheaper as literals.
pub const encoder_min_insert_len: usize = 40;

const StreamRefs = struct {
    /// Absolute indexes referenced by field sections this encoder sent on the
    /// stream. Released by Section Acknowledgment or Stream Cancellation.
    refs: std.ArrayListUnmanaged(u64) = .empty,
    /// True while at least one reference is to an insert the peer has not
    /// acknowledged. Such a stream counts against the peer's blocked-stream
    /// limit until every referenced insert is acknowledged.
    blocked: bool = false,
};

const FieldPlan = union(enum) {
    static_indexed: u64,
    static_name: struct { index: u64, value: []const u8 },
    literal_name: struct { name: []const u8, value: []const u8 },
    dynamic_indexed: u64,
    dynamic_name: struct { absolute_index: u64, value: []const u8 },
};

/// Encoder-side QPACK state: the dynamic table, the peer's limits, and the
/// per-stream references that keep entries alive until the peer acknowledges
/// them. One instance lives in each HTTP/3 Session.
pub const Encoder = struct {
    allocator: std.mem.Allocator,
    table: DynamicTable,
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY from the peer. Required Insert Count
    /// wraparound uses this, not the current capacity (RFC 9204 section
    /// 4.5.1.1).
    peer_max_capacity: usize = 0,
    /// min(peer SETTINGS_QPACK_BLOCKED_STREAMS, encoder_blocked_streams_cap).
    blocked_stream_limit: usize = 0,
    /// Highest Insert Count covered by the peer's Insert Count Increments.
    known_received_count: u64 = 0,
    /// Streams with at least one reference to an unacknowledged insert.
    blocked_stream_count: usize = 0,
    streams: std.AutoHashMapUnmanaged(u64, StreamRefs) = .empty,
    /// Encoder-stream instructions waiting to be queued on the local type
    /// 0x02 stream. http3.Session drains this after encoding a section and
    /// from service().
    pending: std.ArrayListUnmanaged(u8) = .empty,
    configured: bool = false,

    pub fn init(allocator: std.mem.Allocator) Encoder {
        return .{
            .allocator = allocator,
            .table = DynamicTable.init(allocator, 0),
        };
    }

    pub fn deinit(self: *Encoder) void {
        var it = self.streams.iterator();
        while (it.next()) |entry| entry.value_ptr.refs.deinit(self.allocator);
        self.streams.deinit(self.allocator);
        self.pending.deinit(self.allocator);
        self.table.deinit();
        self.* = undefined;
    }

    /// Apply the peer's SETTINGS. The first call sizes the table and stages
    /// exactly one Set Dynamic Table Capacity instruction; a second call is
    /// ignored because a peer sends SETTINGS once.
    pub fn configure(self: *Encoder, max_capacity: u64, blocked_streams: u64) Error!void {
        if (self.configured) return;
        const capacity = std.math.cast(usize, max_capacity) orelse std.math.maxInt(usize);
        if (capacity > 0) {
            // Stage the instruction before mutating the table so an
            // allocation failure leaves the encoder unconfigured instead of
            // desynchronized.
            try writeEncoderCapacity(self.allocator, &self.pending, capacity);
        }
        self.table.max_capacity = capacity;
        try self.table.setCapacity(capacity);
        self.peer_max_capacity = capacity;
        self.blocked_stream_limit = @intCast(@min(blocked_streams, encoder_blocked_streams_cap));
        self.configured = true;
    }

    pub fn insertCount(self: *const Encoder) u64 {
        return self.table.insert_count;
    }

    pub fn knownReceivedCount(self: *const Encoder) u64 {
        return self.known_received_count;
    }

    pub fn blockedStreamCount(self: *const Encoder) usize {
        return self.blocked_stream_count;
    }

    pub fn pendingInstructions(self: *const Encoder) []const u8 {
        return self.pending.items;
    }

    pub fn clearPendingInstructions(self: *Encoder) void {
        self.pending.clearRetainingCapacity();
    }

    /// Encode one field section, staging any needed encoder-stream
    /// instructions in pending. The caller must flush pending on the local
    /// encoder stream before sending the returned block.
    pub fn encodeSection(
        self: *Encoder,
        allocator: std.mem.Allocator,
        stream_id: u64,
        fields: []const HeaderField,
    ) Error![]u8 {
        var plans: std.ArrayListUnmanaged(FieldPlan) = .empty;
        defer plans.deinit(allocator);
        var section_refs: std.ArrayListUnmanaged(u64) = .empty;
        defer section_refs.deinit(allocator);
        var refs_attached = false;
        errdefer if (!refs_attached) self.releaseReferences(section_refs.items);

        const may_block = self.mayBlockNewSection(stream_id);
        var highest: u64 = 0;
        var has_dynamic = false;

        try plans.ensureTotalCapacity(allocator, fields.len);
        for (fields) |field| {
            try validateName(field.name);
            plans.appendAssumeCapacity(try self.planField(
                allocator,
                field,
                may_block,
                &section_refs,
                &highest,
                &has_dynamic,
            ));
        }

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        const base: u64 = if (has_dynamic) highest + 1 else 0;
        if (has_dynamic) {
            const encoded = try encodeRequiredInsertCount(base, self.peer_max_capacity);
            try writePrefixedInt(allocator, &out, 0x00, 8, encoded);
            // Delta Base 0 with Base == Required Insert Count: every dynamic
            // reference is a pre-base reference.
            try writePrefixedInt(allocator, &out, 0x00, 7, 0);
        } else {
            try out.append(allocator, 0);
            try out.append(allocator, 0);
        }
        for (plans.items) |plan| try writePlan(allocator, &out, plan, base);

        if (section_refs.items.len > 0) {
            try self.attachSection(allocator, stream_id, section_refs.items);
            refs_attached = true;
        }
        return out.toOwnedSlice(allocator);
    }

    /// Append a Duplicate instruction for a live entry and mirror it in the
    /// encoder table. The default field policy references an exact match
    /// instead, but the encoder supports the form and tests exercise it.
    pub fn duplicateEntry(self: *Encoder, absolute_index: u64) Error!void {
        const entry = self.table.getAbsolute(absolute_index) orelse return error.InvalidIndex;
        const relative = self.table.insert_count - 1 - absolute_index;
        try self.pending.ensureUnusedCapacity(self.allocator, 11);
        try self.table.insertAvoidingReferenced(entry.name, entry.value);
        try writeEncoderDuplicate(self.allocator, &self.pending, relative);
    }

    /// A Section Acknowledgment releases every dynamic reference the field
    /// section held on the stream. An acknowledgment for a stream with no
    /// outstanding reference is a decoder-stream error (RFC 9204 section
    /// 4.4.1).
    pub fn onSectionAcknowledgment(self: *Encoder, stream_id: u64) Error!void {
        const removed = self.streams.fetchRemove(stream_id) orelse
            return error.UnexpectedSectionAcknowledgment;
        var stream = removed.value;
        defer stream.refs.deinit(self.allocator);
        if (stream.refs.items.len == 0) return error.UnexpectedSectionAcknowledgment;
        self.releaseReferences(stream.refs.items);
        if (stream.blocked and self.blocked_stream_count > 0) {
            self.blocked_stream_count -= 1;
        }
    }

    /// Stream Cancellation drops the stream's references without requiring an
    /// acknowledgment. Cancelling a stream with nothing outstanding is
    /// explicitly allowed.
    pub fn onStreamCancellation(self: *Encoder, stream_id: u64) void {
        const removed = self.streams.fetchRemove(stream_id) orelse return;
        var stream = removed.value;
        defer stream.refs.deinit(self.allocator);
        self.releaseReferences(stream.refs.items);
        if (stream.blocked and self.blocked_stream_count > 0) {
            self.blocked_stream_count -= 1;
        }
    }

    /// Advance known_received_count. Zero is illegal, and the peer can never
    /// acknowledge more inserts than have been sent but not acknowledged yet.
    pub fn onInsertCountIncrement(self: *Encoder, increment: u64) Error!void {
        if (increment == 0) return error.InvalidInsertCountIncrement;
        const outstanding = self.table.insert_count - self.known_received_count;
        if (increment > outstanding) return error.InvalidInsertCountIncrement;
        self.known_received_count += increment;

        // Streams whose every referenced insert is now acknowledged stop
        // counting against the blocked-stream limit.
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            const stream = entry.value_ptr;
            if (!stream.blocked) continue;
            var still_blocked = false;
            for (stream.refs.items) |absolute_index| {
                if (absolute_index >= self.known_received_count) {
                    still_blocked = true;
                    break;
                }
            }
            if (!still_blocked) {
                stream.blocked = false;
                if (self.blocked_stream_count > 0) self.blocked_stream_count -= 1;
            }
        }
    }

    fn planField(
        self: *Encoder,
        allocator: std.mem.Allocator,
        field: HeaderField,
        may_block: bool,
        refs: *std.ArrayListUnmanaged(u64),
        highest: *u64,
        has_dynamic: *bool,
    ) Error!FieldPlan {
        if (findStaticExact(field)) |index| return .{ .static_indexed = index };

        if (self.findNewest(field.name, field.value)) |absolute_index| {
            if (self.canReference(absolute_index, may_block)) {
                try self.recordReference(allocator, refs, absolute_index, highest, has_dynamic);
                return .{ .dynamic_indexed = absolute_index };
            }
        }

        // A value that is already in the table but not yet safe to reference
        // is not inserted again: the copy would be just as unsafe.
        const already_present = self.findNewest(field.name, field.value) != null;
        if (!already_present and self.shouldInsert(field)) {
            if (try self.insertField(allocator, field)) |absolute_index| {
                if (self.canReference(absolute_index, may_block)) {
                    try self.recordReference(allocator, refs, absolute_index, highest, has_dynamic);
                    return .{ .dynamic_indexed = absolute_index };
                }
            }
        }

        if (findStaticName(field.name)) |index| {
            return .{ .static_name = .{ .index = index, .value = field.value } };
        }
        if (self.findNewestName(field.name)) |absolute_index| {
            if (self.canReference(absolute_index, may_block)) {
                try self.recordReference(allocator, refs, absolute_index, highest, has_dynamic);
                return .{ .dynamic_name = .{
                    .absolute_index = absolute_index,
                    .value = field.value,
                } };
            }
        }
        return .{ .literal_name = .{ .name = field.name, .value = field.value } };
    }

    fn shouldInsert(self: *const Encoder, field: HeaderField) bool {
        if (self.table.capacity == 0) return false;
        if (field.name.len + field.value.len < encoder_min_insert_len) return false;
        if (!insertableName(field.name)) return false;
        const entry_size = entrySize(field.name, field.value);
        // One entry may use at most a quarter of the table, so a single large
        // header cannot flush everything the peer has learned.
        if (entry_size > self.table.capacity / 4) return false;
        return self.table.canEvictFor(entry_size);
    }

    fn insertField(
        self: *Encoder,
        allocator: std.mem.Allocator,
        field: HeaderField,
    ) Error!?u64 {
        // Reserve room for the longest encoding before mutating the table:
        // the name and value strings plus a worst-case integer or two.
        try self.pending.ensureUnusedCapacity(
            allocator,
            field.name.len + field.value.len + 24,
        );
        const dynamic_name_relative: ?u64 = if (self.findNewestName(field.name)) |absolute_index|
            self.table.insert_count - 1 - absolute_index
        else
            null;

        self.table.insertAvoidingReferenced(field.name, field.value) catch |err| switch (err) {
            error.WouldEvictReferenced, error.EntryTooLarge => return null,
            else => return err,
        };

        if (findStaticName(field.name)) |index| {
            try writeEncoderInsertNameRef(allocator, &self.pending, true, index, field.value);
        } else if (dynamic_name_relative) |relative| {
            // The peer already has this name: the insert that created it is
            // earlier on the same encoder stream.
            try writeEncoderInsertNameRef(allocator, &self.pending, false, relative, field.value);
        } else {
            try writeEncoderInsertLiteral(allocator, &self.pending, field.name, field.value);
        }
        return self.table.insert_count - 1;
    }

    fn canReference(self: *const Encoder, absolute_index: u64, may_block: bool) bool {
        if (self.table.getAbsolute(absolute_index) == null) return false;
        if (absolute_index < self.known_received_count) return true;
        return may_block;
    }

    fn mayBlockNewSection(self: *const Encoder, stream_id: u64) bool {
        if (self.blocked_stream_limit == 0) return false;
        if (self.streams.get(stream_id)) |stream| {
            if (stream.blocked) return true;
        }
        return self.blocked_stream_count < self.blocked_stream_limit;
    }

    fn recordReference(
        self: *Encoder,
        allocator: std.mem.Allocator,
        refs: *std.ArrayListUnmanaged(u64),
        absolute_index: u64,
        highest: *u64,
        has_dynamic: *bool,
    ) Error!void {
        try refs.append(allocator, absolute_index);
        if (!self.table.addReference(absolute_index)) return error.InvalidDynamicReference;
        if (!has_dynamic.* or absolute_index > highest.*) highest.* = absolute_index;
        has_dynamic.* = true;
    }

    fn releaseReferences(self: *Encoder, refs: []const u64) void {
        for (refs) |absolute_index| _ = self.table.releaseReference(absolute_index);
    }

    fn attachSection(
        self: *Encoder,
        allocator: std.mem.Allocator,
        stream_id: u64,
        refs: []const u64,
    ) Error!void {
        const gop = try self.streams.getOrPut(allocator, stream_id);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        try gop.value_ptr.refs.appendSlice(allocator, refs);
        if (gop.value_ptr.blocked) return;

        for (refs) |absolute_index| {
            if (absolute_index < self.known_received_count) continue;
            gop.value_ptr.blocked = true;
            self.blocked_stream_count += 1;
            return;
        }
    }

    fn findNewest(self: *const Encoder, name: []const u8, value: []const u8) ?u64 {
        return self.findNewestMatch(name, value, true);
    }

    fn findNewestName(self: *const Encoder, name: []const u8) ?u64 {
        return self.findNewestMatch(name, null, false);
    }

    fn findNewestMatch(
        self: *const Encoder,
        name: []const u8,
        value: ?[]const u8,
        match_value: bool,
    ) ?u64 {
        const entries = self.table.entries.items;
        if (entries.len == 0) return null;
        var index = entries.len;
        while (index > 0) {
            index -= 1;
            const entry = entries[index];
            if (!std.mem.eql(u8, entry.name, name)) continue;
            if (match_value and !std.mem.eql(u8, entry.value, value.?)) continue;
            return self.table.insert_count - entries.len + index;
        }
        return null;
    }
};

/// Header names that are never worth inserting. Pseudo-headers change every
/// request, and cookie/date/set-cookie values are unique or short-lived
/// (RFC 9204 section 4.1.2 advises encoders to avoid them).
fn insertableName(name: []const u8) bool {
    if (name.len == 0 or name[0] == ':') return false;
    const excluded = [_][]const u8{ "cookie", "date", "set-cookie" };
    for (excluded) |candidate| {
        if (std.mem.eql(u8, name, candidate)) return false;
    }
    return true;
}

/// Required Insert Count encoding (RFC 9204 section 4.5.1.1). MaxEntries is
/// floor(peer SETTINGS_QPACK_MAX_TABLE_CAPACITY / 32).
fn encodeRequiredInsertCount(required_insert_count: u64, max_capacity: usize) Error!u64 {
    if (required_insert_count == 0) return 0;
    const max_entries: u64 = @intCast(max_capacity / 32);
    if (max_entries == 0) return error.CapacityExceeded;
    const full_range = max_entries * 2;
    return (required_insert_count % full_range) + 1;
}

fn writePlan(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    plan: FieldPlan,
    base: u64,
) Error!void {
    switch (plan) {
        .static_indexed => |index| try writePrefixedInt(allocator, out, 0xc0, 6, index),
        .static_name => |field| {
            try writePrefixedInt(allocator, out, 0x50, 4, field.index);
            try writeString(allocator, out, field.value);
        },
        .literal_name => |field| {
            try writePrefixedInt(allocator, out, 0x20, 3, field.name.len);
            try out.appendSlice(allocator, field.name);
            try writeString(allocator, out, field.value);
        },
        .dynamic_indexed => |absolute_index| {
            const index = base - 1 - absolute_index;
            try writePrefixedInt(allocator, out, 0x80, 6, index);
        },
        .dynamic_name => |field| {
            const index = base - 1 - field.absolute_index;
            try writePrefixedInt(allocator, out, 0x40, 4, index);
            try writeString(allocator, out, field.value);
        },
    }
}

fn writeEncoderCapacity(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    capacity: usize,
) Error!void {
    // Set Dynamic Table Capacity: 001 + 5-bit capacity.
    try writePrefixedInt(allocator, out, 0x20, 5, capacity);
}

fn writeEncoderInsertNameRef(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    is_static: bool,
    index: u64,
    value: []const u8,
) Error!void {
    // Insert With Name Reference: 1 T + 6-bit name index, then value.
    const first: u8 = if (is_static) 0xc0 else 0x80;
    try writePrefixedInt(allocator, out, first, 6, index);
    try writeString(allocator, out, value);
}

fn writeEncoderInsertLiteral(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    name: []const u8,
    value: []const u8,
) Error!void {
    // Insert With Literal Name: 01 H + 5-bit name length (H = 0).
    try writePrefixedInt(allocator, out, 0x40, 5, name.len);
    try out.appendSlice(allocator, name);
    try writeString(allocator, out, value);
}

fn writeEncoderDuplicate(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    relative_index: u64,
) Error!void {
    // Duplicate: 000 + 5-bit relative index.
    try writePrefixedInt(allocator, out, 0x00, 5, relative_index);
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
    /// entry the section references; otherwise this returns Blocked (the caller
    /// may park the frame and retry after more inserts) or
    /// InvalidDynamicReference (the section can never decode).
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
            .required_insert_count = required_insert_count,
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

/// Decode only the Required Insert Count prefix. The HTTP/3 layer uses this
/// helper for blocked-stream bookkeeping.
/// after decodeBlock returns Blocked to distinguish a section waiting for
/// future inserts from a prefix that can never be satisfied.
pub fn peekRequiredInsertCount(
    block: []const u8,
    insert_count: u64,
    max_capacity: usize,
) Error!u64 {
    if (block.len == 0) return error.InvalidHeaderBlock;
    var cursor: usize = 0;
    const encoded = try readPrefixedInt(block, &cursor, 8);
    return decodeRequiredInsertCount(encoded, insert_count, max_capacity);
}

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
        const stream_id = readInt(data, &cursor, 7) catch |err| return decoderScanFailure(err);
        return .{ .complete = .{
            .instruction = .section_acknowledgment,
            .end = cursor,
            .value = stream_id,
        } };
    }
    if (first & 0xc0 == 0x40) {
        // Stream Cancellation: 01 + 6-bit stream ID.
        const stream_id = readInt(data, &cursor, 6) catch |err| return decoderScanFailure(err);
        return .{ .complete = .{
            .instruction = .stream_cancellation,
            .end = cursor,
            .value = stream_id,
        } };
    }
    // Insert Count Increment: 00 + 6-bit increment.
    const increment = readInt(data, &cursor, 6) catch |err| return decoderScanFailure(err);
    return .{ .complete = .{
        .instruction = .insert_count_increment,
        .end = cursor,
        .value = increment,
    } };
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
        // A u64 needs at most ten 7-bit continuation groups; 63 is the last
        // bit position a group can start at. Anything beyond cannot fit.
        if (shift >= 64) return error.Overlong;
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

/// One QPACK decoder-stream instruction to serialize (RFC 9204 section 4.4).
pub const DecoderInstructionValue = union(enum) {
    section_acknowledgment: u64,
    stream_cancellation: u64,
    insert_count_increment: u64,
};

/// Largest encoding of one decoder-stream instruction: a first byte plus ten
/// 7-bit continuation bytes for a full u64 value.
pub const max_decoder_instruction_len = 11;

/// Serialize one decoder-stream instruction into `out` and return its length.
/// The write is allocation-free and fixed-size so the HTTP/3 layer can queue
/// individual acknowledgments without an unbounded staging buffer. An Insert
/// Count Increment of zero is illegal and rejected.
pub fn writeDecoderInstruction(
    out: []u8,
    instruction: DecoderInstructionValue,
) Error!usize {
    if (out.len < max_decoder_instruction_len) return error.InvalidHeaderBlock;
    switch (instruction) {
        .section_acknowledgment => |stream_id| return writePrefixedIntFixed(out, 0x80, 7, stream_id),
        .stream_cancellation => |stream_id| return writePrefixedIntFixed(out, 0x40, 6, stream_id),
        .insert_count_increment => |increment| {
            if (increment == 0) return error.InvalidHeaderBlock;
            return writePrefixedIntFixed(out, 0x00, 6, increment);
        },
    }
}

fn writePrefixedIntFixed(
    out: []u8,
    first_bits: u8,
    comptime prefix_bits: u4,
    value_in: u64,
) usize {
    const mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    var value = value_in;
    var n: usize = 0;
    if (value < mask) {
        out[n] = first_bits | @as(u8, @intCast(value));
        return n + 1;
    }
    out[n] = first_bits | mask;
    n += 1;
    value -= mask;
    while (value >= 0x80) {
        out[n] = @as(u8, @intCast(value & 0x7f)) | 0x80;
        n += 1;
        value >>= 7;
    }
    out[n] = @intCast(value);
    n += 1;
    return n;
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

test "QPACK: decoder stream acknowledgments encode with the right prefixes" {
    var buf: [max_decoder_instruction_len]u8 = undefined;

    var n = try writeDecoderInstruction(&buf, .{ .insert_count_increment = 1 });
    try std.testing.expectEqualSlices(u8, &.{0x01}, buf[0..n]);
    var scan = scanDecoderInstruction(buf[0..n], 0);
    try std.testing.expectEqual(DecoderInstruction.insert_count_increment, scan.complete.instruction);
    try std.testing.expectEqual(@as(u64, 1), scan.complete.value);

    // 63 consumes the full 6-bit prefix and needs a zero continuation byte;
    // 64 is one past it.
    n = try writeDecoderInstruction(&buf, .{ .insert_count_increment = 63 });
    try std.testing.expectEqualSlices(u8, &.{ 0x3f, 0x00 }, buf[0..n]);
    n = try writeDecoderInstruction(&buf, .{ .insert_count_increment = 64 });
    try std.testing.expectEqualSlices(u8, &.{ 0x3f, 0x01 }, buf[0..n]);
    scan = scanDecoderInstruction(buf[0..n], 0);
    try std.testing.expectEqual(@as(u64, 64), scan.complete.value);

    // Section Acknowledgment: 1 + 7-bit stream ID.
    n = try writeDecoderInstruction(&buf, .{ .section_acknowledgment = 0 });
    try std.testing.expectEqualSlices(u8, &.{0x80}, buf[0..n]);
    n = try writeDecoderInstruction(&buf, .{ .section_acknowledgment = 4 });
    try std.testing.expectEqualSlices(u8, &.{0x84}, buf[0..n]);
    scan = scanDecoderInstruction(buf[0..n], 0);
    try std.testing.expectEqual(DecoderInstruction.section_acknowledgment, scan.complete.instruction);
    try std.testing.expectEqual(@as(u64, 4), scan.complete.value);
    n = try writeDecoderInstruction(&buf, .{ .section_acknowledgment = 127 });
    try std.testing.expectEqualSlices(u8, &.{ 0xff, 0x00 }, buf[0..n]);
    n = try writeDecoderInstruction(&buf, .{ .section_acknowledgment = 300 });
    scan = scanDecoderInstruction(buf[0..n], 0);
    try std.testing.expectEqual(@as(u64, 300), scan.complete.value);
    // The fixed 11-byte buffer holds a full u64 stream ID.
    n = try writeDecoderInstruction(&buf, .{ .section_acknowledgment = std.math.maxInt(u64) });
    scan = scanDecoderInstruction(buf[0..n], 0);
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), scan.complete.value);

    // Stream Cancellation: 01 + 6-bit stream ID.
    n = try writeDecoderInstruction(&buf, .{ .stream_cancellation = 0 });
    try std.testing.expectEqualSlices(u8, &.{0x40}, buf[0..n]);
    n = try writeDecoderInstruction(&buf, .{ .stream_cancellation = 4 });
    try std.testing.expectEqualSlices(u8, &.{0x44}, buf[0..n]);
    n = try writeDecoderInstruction(&buf, .{ .stream_cancellation = 63 });
    try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0x00 }, buf[0..n]);
    scan = scanDecoderInstruction(buf[0..n], 0);
    try std.testing.expectEqual(DecoderInstruction.stream_cancellation, scan.complete.instruction);
    try std.testing.expectEqual(@as(u64, 63), scan.complete.value);
    n = try writeDecoderInstruction(&buf, .{ .stream_cancellation = 64 });
    try std.testing.expectEqualSlices(u8, &.{ 0x7f, 0x01 }, buf[0..n]);

    // An increment of zero and an undersized output buffer are rejected.
    try std.testing.expectError(
        error.InvalidHeaderBlock,
        writeDecoderInstruction(&buf, .{ .insert_count_increment = 0 }),
    );
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(
        error.InvalidHeaderBlock,
        writeDecoderInstruction(&tiny, .{ .section_acknowledgment = 0 }),
    );
}

test "QPACK: Required Insert Count can be peeked before decoding" {
    try std.testing.expectEqual(
        @as(u64, 2),
        try peekRequiredInsertCount(&.{ 0x03, 0x00 }, 1, 4096),
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        try peekRequiredInsertCount(&.{ 0x00, 0x00 }, 7, 4096),
    );
    // 254 decodes to 253 when the insert count is zero, outside the 128-entry
    // wraparound window: this prefix can never become satisfiable.
    try std.testing.expectError(
        error.Blocked,
        peekRequiredInsertCount(&.{0xfe}, 0, 4096),
    );
    try std.testing.expectError(
        error.InvalidHeaderBlock,
        peekRequiredInsertCount(&.{}, 0, 4096),
    );
}

/// Apply every complete instruction in bytes to a decoder table. The encoder
/// only stages complete instructions.
fn applyEncoderInstructions(decoder: *Decoder, bytes: []const u8) !void {
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        switch (try applyEncoderInstruction(decoder, bytes, cursor)) {
            .incomplete => return error.IncompleteEncoderInstruction,
            .invalid => return error.InvalidEncoderInstruction,
            .applied => |done| cursor = done.end,
        }
    }
}

fn fillValue(comptime seed: u8, out: []u8) void {
    for (out, 0..) |*ch, i| {
        ch.* = 'a' + @as(u8, @intCast((@as(usize, seed) + i) % 26));
    }
}

test "QPACK: encoder insert, ack, and later dynamic reference" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    try encoder.configure(4096, 0);

    try std.testing.expectEqual(@as(u64, 0), encoder.insertCount());
    try std.testing.expect(encoder.pendingInstructions().len > 0);

    var decoder = Decoder.init(allocator, 4096);
    defer decoder.deinit();
    try applyEncoderInstructions(&decoder, encoder.pendingInstructions());
    encoder.clearPendingInstructions();

    var value_storage: [40]u8 = undefined;
    fillValue(1, &value_storage);
    const field = HeaderField{ .name = "x-request-id", .value = &value_storage };

    // With the peer's blocked-stream limit at zero the fresh insert cannot be
    // referenced yet, but it is still inserted for later sections.
    const first = try encoder.encodeSection(allocator, 4, &.{field});
    defer allocator.free(first);
    try std.testing.expectEqual(@as(u8, 0), first[0]);
    try std.testing.expectEqual(@as(u64, 1), encoder.insertCount());
    try std.testing.expect(encoder.pendingInstructions().len > 0);
    try applyEncoderInstructions(&decoder, encoder.pendingInstructions());
    encoder.clearPendingInstructions();

    var decoded_first = try decoder.decodeBlock(first);
    defer decoded_first.deinit();
    try std.testing.expectEqual(@as(u64, 0), decoded_first.required_insert_count);
    try std.testing.expectEqualStrings(field.name, decoded_first.fields[0].name);
    try std.testing.expectEqualStrings(field.value, decoded_first.fields[0].value);

    // The peer acknowledges the insert, so a later section can reference it
    // without blocking.
    try encoder.onInsertCountIncrement(1);
    try std.testing.expectEqual(@as(u64, 1), encoder.knownReceivedCount());
    const second = try encoder.encodeSection(allocator, 8, &.{field});
    defer allocator.free(second);
    try std.testing.expectEqual(@as(u8, 2), second[0]);
    try std.testing.expectEqual(@as(usize, 0), encoder.pendingInstructions().len);
    try std.testing.expectEqual(@as(u32, 1), encoder.table.referenceCount(0));
    try std.testing.expectEqual(@as(usize, 0), encoder.blockedStreamCount());

    var decoded_second = try decoder.decodeBlock(second);
    defer decoded_second.deinit();
    try std.testing.expectEqual(@as(u64, 1), decoded_second.required_insert_count);
    try std.testing.expectEqualStrings(field.value, decoded_second.fields[0].value);

    // An unknown stream is a decoder-stream error; the real Section Ack
    // releases the reference.
    try std.testing.expectError(
        error.UnexpectedSectionAcknowledgment,
        encoder.onSectionAcknowledgment(12),
    );
    try encoder.onSectionAcknowledgment(8);
    try std.testing.expectEqual(@as(u32, 0), encoder.table.referenceCount(0));
    try std.testing.expectEqual(@as(usize, 0), encoder.blockedStreamCount());
}

test "QPACK: encoder with zero peer capacity never inserts" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    try encoder.configure(0, 16);
    try std.testing.expectEqual(@as(usize, 0), encoder.pendingInstructions().len);

    var value_storage: [40]u8 = undefined;
    fillValue(2, &value_storage);
    const fields = [_]HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "x-custom", .value = &value_storage },
    };
    const block = try encoder.encodeSection(allocator, 0, &fields);
    defer allocator.free(block);
    try std.testing.expectEqual(@as(u8, 0), block[0]);
    try std.testing.expectEqual(@as(u8, 0), block[1]);
    try std.testing.expectEqual(@as(u64, 0), encoder.insertCount());
    try std.testing.expectEqual(@as(usize, 0), encoder.pendingInstructions().len);

    // Without any insert there is nothing to acknowledge.
    try std.testing.expectError(
        error.InvalidInsertCountIncrement,
        encoder.onInsertCountIncrement(1),
    );
}

test "QPACK: encoder rejects zero and over-count Insert Count Increments" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    try encoder.configure(4096, 16);
    encoder.clearPendingInstructions();

    try std.testing.expectError(
        error.InvalidInsertCountIncrement,
        encoder.onInsertCountIncrement(0),
    );
    try std.testing.expectError(
        error.InvalidInsertCountIncrement,
        encoder.onInsertCountIncrement(1),
    );

    var value_storage: [40]u8 = undefined;
    fillValue(3, &value_storage);
    const block = try encoder.encodeSection(allocator, 0, &.{
        .{ .name = "x-count", .value = &value_storage },
    });
    defer allocator.free(block);
    try std.testing.expectEqual(@as(u64, 1), encoder.insertCount());
    try std.testing.expectError(
        error.InvalidInsertCountIncrement,
        encoder.onInsertCountIncrement(2),
    );
    try encoder.onInsertCountIncrement(1);
    try std.testing.expectError(
        error.InvalidInsertCountIncrement,
        encoder.onInsertCountIncrement(1),
    );
}

test "QPACK: encoder refuses to evict referenced entries" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    // Four 82-byte entries fit (328 <= 400) and each is below capacity / 4.
    try encoder.configure(400, 0);
    encoder.clearPendingInstructions();

    var names: [5][10]u8 = undefined;
    var values: [5][40]u8 = undefined;
    var fields: [5]HeaderField = undefined;
    for (0..5) |i| {
        _ = try std.fmt.bufPrint(&names[i], "x-field-{d:0>2}", .{i});
        _ = try std.fmt.bufPrint(
            &values[i],
            "value-{d:0>2}-0123456789abcdef0123456789abc",
            .{i},
        );
        fields[i] = .{ .name = &names[i], .value = &values[i] };
    }
    try std.testing.expectEqual(@as(usize, 10), fields[0].name.len);
    try std.testing.expectEqual(@as(usize, 40), fields[0].value.len);

    for (fields[0..4]) |field| {
        const section = try encoder.encodeSection(allocator, 0, &.{field});
        allocator.free(section);
    }
    try std.testing.expectEqual(@as(u64, 4), encoder.insertCount());
    encoder.clearPendingInstructions();

    // Ack every insert, then reference the oldest entry from a new section.
    try encoder.onInsertCountIncrement(4);
    const referenced = try encoder.encodeSection(allocator, 4, &.{fields[0]});
    defer allocator.free(referenced);
    try std.testing.expect(referenced[0] != 0);
    try std.testing.expectEqual(@as(u32, 1), encoder.table.referenceCount(0));

    // A fifth entry would have to evict absolute index 0, which the section
    // above still references: the encoder emits a literal instead.
    const blocked_insert = try encoder.encodeSection(allocator, 0, &.{fields[4]});
    defer allocator.free(blocked_insert);
    try std.testing.expectEqual(@as(u8, 0), blocked_insert[0]);
    try std.testing.expectEqual(@as(u64, 4), encoder.insertCount());
    try std.testing.expectEqual(@as(usize, 0), encoder.pendingInstructions().len);

    // Releasing the reference lets the insert proceed and evict entry 0.
    try encoder.onSectionAcknowledgment(4);
    try std.testing.expectEqual(@as(u32, 0), encoder.table.referenceCount(0));
    const allowed = try encoder.encodeSection(allocator, 8, &.{fields[4]});
    defer allocator.free(allowed);
    try std.testing.expectEqual(@as(u64, 5), encoder.insertCount());
    try std.testing.expect(encoder.pendingInstructions().len > 0);
    try std.testing.expect(encoder.table.getAbsolute(0) == null);
}

test "QPACK: encoder respects the peer blocked-stream limit" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    try encoder.configure(4096, 1);
    encoder.clearPendingInstructions();

    var value_storage: [40]u8 = undefined;
    fillValue(4, &value_storage);
    const field = HeaderField{ .name = "x-blocked", .value = &value_storage };

    // The first stream consumes the single blocked-stream slot.
    const first = try encoder.encodeSection(allocator, 4, &.{field});
    defer allocator.free(first);
    try std.testing.expect(first[0] != 0);
    try std.testing.expectEqual(@as(usize, 1), encoder.blockedStreamCount());

    // A second stream must not reference the unacknowledged entry.
    const second = try encoder.encodeSection(allocator, 8, &.{field});
    defer allocator.free(second);
    try std.testing.expectEqual(@as(u8, 0), second[0]);
    try std.testing.expectEqual(@as(usize, 1), encoder.blockedStreamCount());

    // Stream cancellation releases the slot and the references.
    encoder.onStreamCancellation(4);
    try std.testing.expectEqual(@as(usize, 0), encoder.blockedStreamCount());
    try std.testing.expectEqual(@as(u32, 0), encoder.table.referenceCount(0));

    const third = try encoder.encodeSection(allocator, 12, &.{field});
    defer allocator.free(third);
    try std.testing.expect(third[0] != 0);
    try std.testing.expectEqual(@as(usize, 1), encoder.blockedStreamCount());
    try encoder.onSectionAcknowledgment(12);
    try std.testing.expectEqual(@as(usize, 0), encoder.blockedStreamCount());
}

test "QPACK: Insert Count Increment unblocks acked streams" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    try encoder.configure(4096, 1);
    encoder.clearPendingInstructions();

    var value_storage: [40]u8 = undefined;
    fillValue(5, &value_storage);
    const field = HeaderField{ .name = "x-unblock", .value = &value_storage };
    const section = try encoder.encodeSection(allocator, 4, &.{field});
    defer allocator.free(section);
    try std.testing.expectEqual(@as(usize, 1), encoder.blockedStreamCount());

    // The insert is acknowledged, so the stream no longer blocks even though
    // its Section Acknowledgment has not arrived yet.
    try encoder.onInsertCountIncrement(1);
    try std.testing.expectEqual(@as(usize, 0), encoder.blockedStreamCount());
    try std.testing.expectEqual(@as(u32, 1), encoder.table.referenceCount(0));
    try encoder.onSectionAcknowledgment(4);
    try std.testing.expectEqual(@as(u32, 0), encoder.table.referenceCount(0));
}

test "QPACK: encoder duplicate instruction mirrors the peer table" {
    const allocator = std.testing.allocator;
    var encoder = Encoder.init(allocator);
    defer encoder.deinit();
    try encoder.configure(4096, 0);

    var decoder = Decoder.init(allocator, 4096);
    defer decoder.deinit();
    try applyEncoderInstructions(&decoder, encoder.pendingInstructions());
    encoder.clearPendingInstructions();

    var value_storage: [40]u8 = undefined;
    fillValue(6, &value_storage);
    const field = HeaderField{ .name = "x-duplicate", .value = &value_storage };
    const section = try encoder.encodeSection(allocator, 0, &.{field});
    defer allocator.free(section);
    try applyEncoderInstructions(&decoder, encoder.pendingInstructions());
    encoder.clearPendingInstructions();

    try encoder.duplicateEntry(0);
    try std.testing.expectEqual(@as(u64, 2), encoder.insertCount());
    try applyEncoderInstructions(&decoder, encoder.pendingInstructions());
    encoder.clearPendingInstructions();
    try std.testing.expectEqual(@as(u64, 2), decoder.insertCount());
    try std.testing.expectEqualStrings(field.value, decoder.table.getRelative(0).?.value);
}
