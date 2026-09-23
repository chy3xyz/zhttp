const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const hpack = @import("hpack.zig");
const huffman = @import("huffman.zig");

// RFC 7541 Appendix C test vectors for HPACK.

// --- C.1: Integer Representation Examples ---
// (Already tested in hpack.zig, included here for completeness)

// --- C.2: Header Field Representation Examples ---

// C.2.1: Literal Header Field with Indexing
test "RFC 7541 C.2.1: literal with indexing" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    const data = hexToBytes(
        "400a" ++ "637573746f6d2d6b6579" ++ // custom-key
            "0d" ++ "637573746f6d2d686561646572", // custom-header
    );

    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("custom-key", headers[0].name);
    try testing.expectEqualStrings("custom-header", headers[0].value);

    // Dynamic table should contain this entry
    const dyn = decoder.dynamic_table.get(0).?;
    try testing.expectEqualStrings("custom-key", dyn.name);
    try testing.expectEqualStrings("custom-header", dyn.value);
    try testing.expectEqual(@as(usize, 55), decoder.dynamic_table.current_size);
}

// C.2.2: Literal Header Field without Indexing
test "RFC 7541 C.2.2: literal without indexing" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    const data = hexToBytes(
        "040c" ++ "2f73616d706c652f70617468", // :path: /sample/path
    );

    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings(":path", headers[0].name);
    try testing.expectEqualStrings("/sample/path", headers[0].value);

    // Should NOT be in dynamic table
    try testing.expectEqual(@as(usize, 0), decoder.dynamic_table.len);
}

// C.2.3: Literal Header Field Never Indexed
test "RFC 7541 C.2.3: literal never indexed" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    const data = hexToBytes(
        "1008" ++ "70617373776f7264" ++ // password
            "06" ++ "736563726574", // secret
    );

    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("password", headers[0].name);
    try testing.expectEqualStrings("secret", headers[0].value);

    // Should NOT be in dynamic table
    try testing.expectEqual(@as(usize, 0), decoder.dynamic_table.len);
}

// C.2.4: Indexed Header Field
test "RFC 7541 C.2.4: indexed header field" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    const data = [_]u8{0x82}; // index 2 = :method: GET

    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
}

// --- C.3: Request Examples without Huffman Coding ---

// C.3.1: First Request
test "RFC 7541 C.3.1: first request (no huffman)" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    const data = hexToBytes(
        "828684" ++ // :method GET, :scheme http, :path /
            "410f" ++ "7777772e6578616d706c652e636f6d", // :authority www.example.com
    );

    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 4), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
    try testing.expectEqualStrings(":scheme", headers[1].name);
    try testing.expectEqualStrings("http", headers[1].value);
    try testing.expectEqualStrings(":path", headers[2].name);
    try testing.expectEqualStrings("/", headers[2].value);
    try testing.expectEqualStrings(":authority", headers[3].name);
    try testing.expectEqualStrings("www.example.com", headers[3].value);

    // Dynamic table: [1] :authority: www.example.com (size=57)
    try testing.expectEqual(@as(usize, 1), decoder.dynamic_table.len);
    try testing.expectEqual(@as(usize, 57), decoder.dynamic_table.current_size);
}

// C.3.2: Second Request (reuses dynamic table from C.3.1)
test "RFC 7541 C.3.2: second request (no huffman)" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    // First, process C.3.1 to set up dynamic table
    const req1 = hexToBytes(
        "828684" ++ "410f" ++ "7777772e6578616d706c652e636f6d",
    );
    _ = try decoder.decode(&req1, &headers);

    // Now process C.3.2
    const req2 = hexToBytes(
        "828684" ++ // :method GET, :scheme http, :path /
            "be" ++ // :authority www.example.com (dynamic index 62)
            "5808" ++ "6e6f2d6361636865", // cache-control: no-cache
    );

    const count = try decoder.decode(&req2, &headers);
    try testing.expectEqual(@as(usize, 5), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
    try testing.expectEqualStrings(":scheme", headers[1].name);
    try testing.expectEqualStrings("http", headers[1].value);
    try testing.expectEqualStrings(":path", headers[2].name);
    try testing.expectEqualStrings("/", headers[2].value);
    try testing.expectEqualStrings(":authority", headers[3].name);
    try testing.expectEqualStrings("www.example.com", headers[3].value);
    try testing.expectEqualStrings("cache-control", headers[4].name);
    try testing.expectEqualStrings("no-cache", headers[4].value);

    // Dynamic table: [1] cache-control: no-cache (53), [2] :authority: www.example.com (57)
    try testing.expectEqual(@as(usize, 2), decoder.dynamic_table.len);
    try testing.expectEqual(@as(usize, 110), decoder.dynamic_table.current_size);
}

// C.3.3: Third Request (reuses dynamic table from C.3.1 + C.3.2)
test "RFC 7541 C.3.3: third request (no huffman)" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    // Process C.3.1
    const req1 = hexToBytes("828684" ++ "410f" ++ "7777772e6578616d706c652e636f6d");
    _ = try decoder.decode(&req1, &headers);

    // Process C.3.2
    const req2 = hexToBytes("828684" ++ "be" ++ "5808" ++ "6e6f2d6361636865");
    _ = try decoder.decode(&req2, &headers);

    // Process C.3.3
    const req3 = hexToBytes(
        "8287" ++ "85" ++ // :method GET, :scheme https, :path /index.html
            "bf" ++ // :authority www.example.com (dynamic index, shifted by one)
            "400a" ++ "637573746f6d2d6b6579" ++ // custom-key
            "0c" ++ "637573746f6d2d76616c7565", // custom-value
    );

    const count = try decoder.decode(&req3, &headers);
    try testing.expectEqual(@as(usize, 5), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
    try testing.expectEqualStrings(":scheme", headers[1].name);
    try testing.expectEqualStrings("https", headers[1].value);
    try testing.expectEqualStrings(":path", headers[2].name);
    try testing.expectEqualStrings("/index.html", headers[2].value);
    try testing.expectEqualStrings(":authority", headers[3].name);
    try testing.expectEqualStrings("www.example.com", headers[3].value);
    try testing.expectEqualStrings("custom-key", headers[4].name);
    try testing.expectEqualStrings("custom-value", headers[4].value);

    // Dynamic table: [1] custom-key: custom-value (55), [2] cache-control: no-cache (53), [3] :authority: www.example.com (57)
    try testing.expectEqual(@as(usize, 3), decoder.dynamic_table.len);
    // 10+12+32 = 54 (custom-key:custom-value) + 53 (cache-control:no-cache) + 57 (:authority:www.example.com) = 164
    try testing.expectEqual(@as(usize, 164), decoder.dynamic_table.current_size);
}

// --- C.4: Request Examples with Huffman Coding ---

// C.4.1: First Request (Huffman)
test "RFC 7541 C.4.1: first request (huffman)" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    const data = hexToBytes(
        "828684" ++ "418c" ++ "f1e3c2e5f23a6ba0ab90f4ff",
    );

    const count = try decoder.decode(&data, &headers);
    try testing.expectEqual(@as(usize, 4), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
    try testing.expectEqualStrings(":scheme", headers[1].name);
    try testing.expectEqualStrings("http", headers[1].value);
    try testing.expectEqualStrings(":path", headers[2].name);
    try testing.expectEqualStrings("/", headers[2].value);
    try testing.expectEqualStrings(":authority", headers[3].name);
    try testing.expectEqualStrings("www.example.com", headers[3].value);
}

// C.4.2: Second Request (Huffman)
test "RFC 7541 C.4.2: second request (huffman)" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    // Set up dynamic table with C.4.1
    const req1 = hexToBytes("828684" ++ "418c" ++ "f1e3c2e5f23a6ba0ab90f4ff");
    _ = try decoder.decode(&req1, &headers);

    // C.4.2
    const req2 = hexToBytes(
        "828684" ++ "be" ++ "5886" ++ "a8eb10649cbf",
    );

    const count = try decoder.decode(&req2, &headers);
    try testing.expectEqual(@as(usize, 5), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
    try testing.expectEqualStrings(":scheme", headers[1].name);
    try testing.expectEqualStrings("http", headers[1].value);
    try testing.expectEqualStrings(":path", headers[2].name);
    try testing.expectEqualStrings("/", headers[2].value);
    try testing.expectEqualStrings(":authority", headers[3].name);
    try testing.expectEqualStrings("www.example.com", headers[3].value);
    try testing.expectEqualStrings("cache-control", headers[4].name);
    try testing.expectEqualStrings("no-cache", headers[4].value);
}

// C.4.3: Third Request (Huffman)
test "RFC 7541 C.4.3: third request (huffman)" {
    var buf: [4096]u8 = undefined;
    var entries: [64]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&buf, &entries);
    var headers: [16]hpack.HeaderField = undefined;

    // Set up dynamic table with C.4.1 and C.4.2
    const req1 = hexToBytes("828684" ++ "418c" ++ "f1e3c2e5f23a6ba0ab90f4ff");
    _ = try decoder.decode(&req1, &headers);
    const req2 = hexToBytes("828684" ++ "be" ++ "5886" ++ "a8eb10649cbf");
    _ = try decoder.decode(&req2, &headers);

    // C.4.3
    const req3 = hexToBytes(
        "828785" ++ "bf" ++ "4088" ++ "25a849e95ba97d7f" ++ "89" ++ "25a849e95bb8e8b4bf",
    );

    const count = try decoder.decode(&req3, &headers);
    try testing.expectEqual(@as(usize, 5), count);
    try testing.expectEqualStrings(":method", headers[0].name);
    try testing.expectEqualStrings("GET", headers[0].value);
    try testing.expectEqualStrings(":scheme", headers[1].name);
    try testing.expectEqualStrings("https", headers[1].value);
    try testing.expectEqualStrings(":path", headers[2].name);
    try testing.expectEqualStrings("/index.html", headers[2].value);
    try testing.expectEqualStrings(":authority", headers[3].name);
    try testing.expectEqualStrings("www.example.com", headers[3].value);
    try testing.expectEqualStrings("custom-key", headers[4].name);
    try testing.expectEqualStrings("custom-value", headers[4].value);
}

// --- Huffman encode/decode standalone tests ---

test "Huffman: encode www.example.com matches RFC" {
    // From C.4.1: www.example.com Huffman-encoded = f1e3c2e5f23a6ba0ab90f4ff
    const expected = hexToBytes("f1e3c2e5f23a6ba0ab90f4ff");
    var encoded: [256]u8 = undefined;
    const len = try huffman.encode(&encoded, "www.example.com");
    try testing.expectEqualSlices(u8, &expected, encoded[0..len]);
}

test "Huffman: encode no-cache matches RFC" {
    // From C.4.2: no-cache Huffman-encoded = a8eb10649cbf
    const expected = hexToBytes("a8eb10649cbf");
    var encoded: [256]u8 = undefined;
    const len = try huffman.encode(&encoded, "no-cache");
    try testing.expectEqualSlices(u8, &expected, encoded[0..len]);
}

test "Huffman: encode custom-key matches RFC" {
    // From C.4.3: custom-key Huffman-encoded = 25a849e95ba97d7f
    const expected = hexToBytes("25a849e95ba97d7f");
    var encoded: [256]u8 = undefined;
    const len = try huffman.encode(&encoded, "custom-key");
    try testing.expectEqualSlices(u8, &expected, encoded[0..len]);
}

test "Huffman: encode custom-value matches RFC" {
    // From C.4.3: custom-value Huffman-encoded = 25a849e95bb8e8b4bf
    const expected = hexToBytes("25a849e95bb8e8b4bf");
    var encoded: [256]u8 = undefined;
    const len = try huffman.encode(&encoded, "custom-value");
    try testing.expectEqualSlices(u8, &expected, encoded[0..len]);
}

// --- Decoder isolation: one decoder per HTTP/2 connection ---

// RFC 7541 C.4.1: :authority: www.example.com (Huffman-encoded value)
const authority_block = hexToBytes("418c" ++ "f1e3c2e5f23a6ba0ab90f4ff");
// RFC 7541 C.4.2: cache-control: no-cache (Huffman-encoded value)
const no_cache_block = hexToBytes("5886" ++ "a8eb10649cbf");

test "decoders on separate connections do not share decoded strings" {
    var buf_a: [4096]u8 = undefined;
    var entries_a: [64]hpack.DynamicTable.Entry = undefined;
    var dec_a = hpack.Decoder.init(&buf_a, &entries_a);

    var buf_b: [4096]u8 = undefined;
    var entries_b: [64]hpack.DynamicTable.Entry = undefined;
    var dec_b = hpack.Decoder.init(&buf_b, &entries_b);

    var headers_a: [16]hpack.HeaderField = undefined;
    var headers_b: [16]hpack.HeaderField = undefined;

    const count_a = try dec_a.decode(&authority_block, &headers_a);
    try testing.expectEqual(@as(usize, 1), count_a);
    const value_a = headers_a[0].value;

    const count_b = try dec_b.decode(&no_cache_block, &headers_b);
    try testing.expectEqual(@as(usize, 1), count_b);
    try testing.expectEqualStrings("no-cache", headers_b[0].value);

    // Decoding on connection B must not disturb connection A's decoded
    // header list, which stays valid until A decodes its next block.
    try testing.expectEqualStrings(":authority", headers_a[0].name);
    try testing.expectEqualStrings("www.example.com", value_a);
}

test "decoders on separate threads do not corrupt each other" {
    const Worker = struct {
        fn run(block: []const u8, expected: []const u8, corrupt: *std.atomic.Value(u32)) void {
            var buf: [4096]u8 = undefined;
            var entries: [64]hpack.DynamicTable.Entry = undefined;
            var decoder = hpack.Decoder.init(&buf, &entries);
            var headers: [16]hpack.HeaderField = undefined;

            for (0..500) |_| {
                const count = decoder.decode(block, &headers) catch {
                    _ = corrupt.fetchAdd(1, .monotonic);
                    return;
                };
                if (count != 1 or !mem.eql(u8, headers[0].value, expected)) {
                    _ = corrupt.fetchAdd(1, .monotonic);
                    return;
                }
            }
        }
    };

    var corrupt = std.atomic.Value(u32).init(0);
    const thread_a = try std.Thread.spawn(.{}, Worker.run, .{ &authority_block, "www.example.com", &corrupt });
    const thread_b = try std.Thread.spawn(.{}, Worker.run, .{ &no_cache_block, "no-cache", &corrupt });
    thread_a.join();
    thread_b.join();

    try testing.expectEqual(@as(u32, 0), corrupt.load(.monotonic));
}

// --- Helper: compile-time hex string to bytes ---

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var result: [hex.len / 2]u8 = undefined;
    for (&result, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[i * 2 ..][0..2], 16) catch unreachable;
    }
    return result;
}
