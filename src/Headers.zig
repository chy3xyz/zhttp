const Headers = @This();
const std = @import("std");

/// RFC 2616 Section 4.2: HTTP headers are case-insensitive field names
/// with associated values. Multiple headers with the same name are
/// combined with comma separation.
pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

entries: [max_headers]Entry = undefined,
len: usize = 0,

pub const max_headers = 64;
/// Number of header slots reserved for server-generated headers
/// (Date, Server, Connection, Allow, WWW-Authenticate, Location,
/// Transfer-Encoding, Via). User handlers should not fill beyond
/// max_headers - reserved_headers to ensure server headers succeed.
pub const reserved_headers = 8;
pub const max_name_len = 256;
pub const max_value_len = 8192;

pub const Error = error{
    TooManyHeaders,
    InvalidHeaderName,
    InvalidHeaderValue,
};

/// RFC 2616 Section 4.2: Add a header field.
/// User-facing headers are limited to (max_headers - reserved_headers)
/// to ensure server-generated headers always have room.
pub fn append(self: *Headers, name: []const u8, value: []const u8) Error!void {
    // User-facing headers are limited to (max_headers - reserved_headers)
    // so server-generated headers always have room.
    if (self.len >= max_headers - reserved_headers) return error.TooManyHeaders;
    if (name.len == 0 or name.len > max_name_len) return error.InvalidHeaderName;
    if (!isValidToken(name)) return error.InvalidHeaderName;
    if (value.len > max_value_len) return error.InvalidHeaderValue;
    if (containsCrlf(value)) return error.InvalidHeaderValue;

    self.entries[self.len] = .{ .name = name, .value = value };
    self.len += 1;
}

/// Append a server-generated header, using reserved header slots.
/// These headers (Date, Server, Connection, etc.) are known-valid
/// and must not be silently dropped. Panics if the reserved space
/// is also exhausted (indicates a bug in server logic).
pub fn appendServer(self: *Headers, name: []const u8, value: []const u8) void {
    if (self.len >= max_headers) {
        // This should never happen — reserved slots guarantee space.
        // If it does, it means server logic is appending too many
        // server headers. Log in all builds so this is never silent.
        std.log.err("appendServer: header table full, dropping {s}", .{name});
        std.debug.assert(false);
        return;
    }
    self.entries[self.len] = .{ .name = name, .value = value };
    self.len += 1;
}

/// RFC 2616 Section 4.2: Header field names are case-insensitive.
pub fn get(self: *const Headers, name: []const u8) ?[]const u8 {
    for (self.entries[0..self.len]) |entry| {
        if (eqlIgnoreCase(entry.name, name)) return entry.value;
    }
    return null;
}

/// Get all values for a given header name.
pub fn getAll(self: *const Headers, name: []const u8, buf: [][]const u8) usize {
    var count: usize = 0;
    for (self.entries[0..self.len]) |entry| {
        if (eqlIgnoreCase(entry.name, name)) {
            if (count < buf.len) {
                buf[count] = entry.value;
            }
            count += 1;
        }
    }
    return count;
}

/// Remove all headers with the given name (case-insensitive).
pub fn remove(self: *Headers, name: []const u8) void {
    var i: usize = 0;
    while (i < self.len) {
        if (eqlIgnoreCase(self.entries[i].name, name)) {
            // Shift remaining entries down
            var j = i;
            while (j + 1 < self.len) : (j += 1) {
                self.entries[j] = self.entries[j + 1];
            }
            self.len -= 1;
        } else {
            i += 1;
        }
    }
}

/// RFC 2616 Section 2.2: Check if a string is a valid HTTP token.
/// token = 1*<any CHAR except CTLs or separators>
pub fn isValidToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!isTokenChar(c)) return false;
    }
    return true;
}

/// RFC 2616 Section 2.2: Token characters.
/// separators = "(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\" | <">
///            | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP | HT
fn isTokenChar(c: u8) bool {
    // Must be a CHAR (0-127), not a CTL (0-31, 127), and not a separator
    if (c <= 31 or c == 127) return false;
    return switch (c) {
        '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', ' ', '\t' => false,
        else => c <= 126,
    };
}

/// Check if a string contains CR or LF characters.
/// RFC 7230 Section 3.2.6: Field values must not contain bare CR or LF.
fn containsCrlf(s: []const u8) bool {
    var i: usize = 0;
    // SIMD 16-byte vector scan for \r or \n
    while (i + 16 <= s.len) : (i += 16) {
        const chunk: @Vector(16, u8) = s[i..][0..16].*;
        const is_cr = chunk == @as(@Vector(16, u8), @splat('\r'));
        const is_lf = chunk == @as(@Vector(16, u8), @splat('\n'));
        if (@reduce(.Or, is_cr | is_lf)) return true;
    }
    while (i < s.len) : (i += 1) {
        if (s[i] == '\r' or s[i] == '\n') return true;
    }
    return false;
}

/// Case-insensitive comparison for ASCII strings.
/// RFC 2616 Section 4.2: Field names are case-insensitive.
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    // SIMD 16-byte vector lowercasing & comparison
    while (i + 16 <= a.len) : (i += 16) {
        const va: @Vector(16, u8) = a[i..][0..16].*;
        const vb: @Vector(16, u8) = b[i..][0..16].*;

        const is_upper_a = (va >= @as(@Vector(16, u8), @splat('A'))) & (va <= @as(@Vector(16, u8), @splat('Z')));
        const is_upper_b = (vb >= @as(@Vector(16, u8), @splat('A'))) & (vb <= @as(@Vector(16, u8), @splat('Z')));

        const add_32: @Vector(16, u8) = @splat(32);
        const add_0: @Vector(16, u8) = @splat(0);

        const lower_a = va + @select(u8, is_upper_a, add_32, add_0);
        const lower_b = vb + @select(u8, is_upper_b, add_32, add_0);

        if (@reduce(.Or, lower_a != lower_b)) return false;
    }
    while (i < a.len) : (i += 1) {
        if (toLower(a[i]) != toLower(b[i])) return false;
    }
    return true;
}

fn toLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

// --- Tests ---

const testing = std.testing;

// /// RFC 2616 Section 4.2: Message headers consist of field-name ":" field-value
test "Headers: basic append and get" {
    var h: Headers = .{};
    try h.append("Content-Type", "text/html");
    try h.append("Content-Length", "42");

    try testing.expectEqualStrings("text/html", h.get("Content-Type").?);
    try testing.expectEqualStrings("42", h.get("Content-Length").?);
    try testing.expect(h.get("X-Missing") == null);
}

// /// RFC 2616 Section 4.2: Field names are case-insensitive.
test "Headers: case-insensitive lookup" {
    var h: Headers = .{};
    try h.append("Content-Type", "text/html");

    try testing.expectEqualStrings("text/html", h.get("content-type").?);
    try testing.expectEqualStrings("text/html", h.get("CONTENT-TYPE").?);
    try testing.expectEqualStrings("text/html", h.get("Content-type").?);
}

// RFC 2616 Section 4.2: Multiple message-header fields with the same field-name
// MAY be present in a message.
test "Headers: multiple values for same name" {
    var h: Headers = .{};
    try h.append("Set-Cookie", "a=1");
    try h.append("Set-Cookie", "b=2");

    var buf: [4][]const u8 = undefined;
    const count = h.getAll("Set-Cookie", &buf);
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("a=1", buf[0]);
    try testing.expectEqualStrings("b=2", buf[1]);
}

// /// RFC 2616 Section 4.2: get returns the first matching header.
test "Headers: get returns first match" {
    var h: Headers = .{};
    try h.append("X-Custom", "first");
    try h.append("X-Custom", "second");

    try testing.expectEqualStrings("first", h.get("X-Custom").?);
}

// /// RFC 2616 Section 4.2: Too many headers should be rejected.
test "Headers: too many headers" {
    var h: Headers = .{};
    // User headers are limited to (max_headers - reserved_headers) so the
    // reserved slots stay available for server-generated headers.
    for (0..max_headers - reserved_headers) |i| {
        _ = i;
        try h.append("X-Header", "value");
    }
    try testing.expectError(error.TooManyHeaders, h.append("X-Extra", "value"));
}

// /// RFC 2616 Section 2.2: Token validation - field names must be valid tokens.
test "Headers: invalid header name rejected" {
    var h: Headers = .{};
    try testing.expectError(error.InvalidHeaderName, h.append("", "value"));
    try testing.expectError(error.InvalidHeaderName, h.append("Bad Header", "value"));
    try testing.expectError(error.InvalidHeaderName, h.append("Bad:Header", "value"));
    try testing.expectError(error.InvalidHeaderName, h.append("Bad\x00Header", "value"));
}

// /// RFC 2616 Section 2.2: Token character validation.
test "Headers: token validation" {
    try testing.expect(isValidToken("Content-Type"));
    try testing.expect(isValidToken("X-Custom-Header"));
    try testing.expect(!isValidToken("Bad Header"));
    try testing.expect(!isValidToken("Bad\tHeader"));
    try testing.expect(!isValidToken(""));
    // Separators
    try testing.expect(!isValidToken("a(b"));
    try testing.expect(!isValidToken("a@b"));
    try testing.expect(!isValidToken("a[b"));
}

// RFC 2616 Section 13.5.1: Remove hop-by-hop headers.
test "Headers: remove" {
    var h: Headers = .{};
    try h.append("Content-Type", "text/html");
    try h.append("Connection", "keep-alive");
    try h.append("X-Custom", "value");

    h.remove("Connection");
    try testing.expect(h.get("Connection") == null);
    try testing.expectEqual(@as(usize, 2), h.len);
    try testing.expectEqualStrings("text/html", h.get("Content-Type").?);
    try testing.expectEqualStrings("value", h.get("X-Custom").?);
}

// /// RFC 2616 Section 4.2: Case-insensitive comparison utility.
test "Headers: eqlIgnoreCase" {
    try testing.expect(eqlIgnoreCase("abc", "ABC"));
    try testing.expect(eqlIgnoreCase("Content-Type", "content-type"));
    try testing.expect(!eqlIgnoreCase("abc", "abcd"));
    try testing.expect(!eqlIgnoreCase("abc", "abd"));
}

// RFC 7230 Section 3.2.6: CRLF in header values causes response splitting
test "Headers: CRLF in header value rejected" {
    var h: Headers = .{};
    try testing.expectError(error.InvalidHeaderValue, h.append("X-Header", "foo\r\nSet-Cookie: stolen=1"));
    try testing.expectError(error.InvalidHeaderValue, h.append("X-Header", "foo\rbar"));
    try testing.expectError(error.InvalidHeaderValue, h.append("X-Header", "foo\nbar"));
    // Valid values should still work
    try h.append("X-Header", "normal value");
}

// Server headers use reserved slots
test "Headers: appendServer basic" {
    var h: Headers = .{};
    h.appendServer("Date", "Thu, 01 Jan 1970 00:00:00 GMT");
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", h.get("Date").?);
}

// Reserved header constant
test "Headers: reserved_headers constant" {
    try testing.expect(reserved_headers > 0);
    try testing.expect(reserved_headers < max_headers);
}
