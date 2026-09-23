const Request = @This();
const std = @import("std");
const Headers = @import("Headers.zig");
const Date = @import("server/Date.zig");

/// RFC 2616 Section 5: Request
///
/// Request = Request-Line
///           *(( general-header | request-header | entity-header ) CRLF)
///           CRLF
///           [ message-body ]
/// RFC 2616 Section 5.1.1: Method
pub const Method = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    TRACE,
    CONNECT,
    PATCH,

    pub fn fromString(s: []const u8) ?Method {
        const map = std.StaticStringMap(Method).initComptime(.{
            .{ "GET", .GET },
            .{ "HEAD", .HEAD },
            .{ "POST", .POST },
            .{ "PUT", .PUT },
            .{ "DELETE", .DELETE },
            .{ "OPTIONS", .OPTIONS },
            .{ "TRACE", .TRACE },
            .{ "CONNECT", .CONNECT },
            .{ "PATCH", .PATCH },
        });
        return map.get(s);
    }

    pub fn toBytes(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .HEAD => "HEAD",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .OPTIONS => "OPTIONS",
            .TRACE => "TRACE",
            .CONNECT => "CONNECT",
            .PATCH => "PATCH",
        };
    }
};

/// RFC 2616 Section 3.1: HTTP Version
pub const Version = enum {
    http_1_0,
    http_1_1,

    pub fn toBytes(self: Version) []const u8 {
        return switch (self) {
            .http_1_0 => "HTTP/1.0",
            .http_1_1 => "HTTP/1.1",
        };
    }
};

method: Method = .GET,
uri: []const u8 = "/",
version: Version = .http_1_1,
headers: Headers = .{},
body: []const u8 = "",
/// Raw request bytes (request-line + headers + terminator).
/// Used by TRACE to echo the received message (RFC 2616 §9.8).
raw: []const u8 = "",
/// Path parameters extracted from route matching.
params: Params = .{},
/// AIP-136 custom-method action parsed from the URL's trailing `:verb`.
/// Set whenever the URL contains a syntactically valid action
/// (`[A-Za-z][A-Za-z0-9]*`), independent of whether routing matched.
action: ?[]const u8 = null,
/// Type-keyed context for middleware to pass state to handlers.
context: Context = .{},

/// Type-keyed store for middleware state. Each middleware sets a value
/// under its own type; handlers retrieve it with `get`. Uses `@typeName`
/// pointer identity for O(1) key comparison.
pub const Context = struct {
    entries: [max_entries]Entry = undefined,
    len: usize = 0,

    pub const max_entries = 8;

    const Entry = struct {
        key: *const anyopaque,
        value: *anyopaque,
    };

    /// Store a pointer to `T`, keyed by its type. Replaces any existing
    /// entry for the same type.
    pub fn put(self: *Context, comptime T: type, ptr: *T) void {
        const key: *const anyopaque = @ptrCast(@typeName(T));
        for (self.entries[0..self.len]) |*entry| {
            if (entry.key == key) {
                entry.value = @ptrCast(ptr);
                return;
            }
        }
        if (self.len < max_entries) {
            self.entries[self.len] = .{ .key = key, .value = @ptrCast(ptr) };
            self.len += 1;
        }
    }

    /// Retrieve the value stored for type `T`, or null if not set.
    pub fn get(self: *const Context, comptime T: type) ?*T {
        const key: *const anyopaque = @ptrCast(@typeName(T));
        for (self.entries[0..self.len]) |entry| {
            if (entry.key == key) return @ptrCast(@alignCast(entry.value));
        }
        return null;
    }
};

/// Path parameters extracted from a matched route.
pub const Params = struct {
    entries: [max_params]Entry = undefined,
    len: usize = 0,

    pub const max_params = 8;
    pub const Entry = struct { name: []const u8, value: []const u8 };

    pub fn get(self: *const Params, name: []const u8) ?[]const u8 {
        for (self.entries[0..self.len]) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.value;
        }
        return null;
    }
};

pub const max_request_line_len = 8192;
pub const max_header_line_len = 8192;
pub const max_body_len = 1_048_576; // 1 MiB

pub const ParseError = error{
    /// RFC 2616 Section 5.1: Malformed request line
    InvalidRequestLine,
    /// RFC 2616 Section 5.1.1: Unknown method (501 Not Implemented)
    UnknownMethod,
    /// RFC 2616 Section 3.1: Invalid HTTP version
    InvalidVersion,
    /// RFC 2616 Section 14.23: Missing Host header in HTTP/1.1
    MissingHostHeader,
    /// RFC 2616 Section 4.2: Malformed header line
    InvalidHeader,
    /// RFC 2616 Section 5: Request line or header too long
    LineTooLong,
    /// RFC 2616 Section 4.4: Invalid or missing Content-Length
    InvalidContentLength,
    /// Body exceeds maximum allowed size
    BodyTooLarge,
    /// Unexpected end of input
    UnexpectedEndOfInput,
    /// Too many headers
    TooManyHeaders,
    /// RFC 2616 Section 14.23: Multiple Host headers
    MultipleHostHeaders,
    /// RFC 2616 Section 4.4: Multiple conflicting Content-Length headers
    ConflictingContentLength,
    /// URI contains path traversal sequences (e.g. /../, /%2e%2e/)
    UriPathTraversal,
    /// RFC 2616 Section 14.23: Invalid Host header value
    InvalidHostHeader,
};

/// Parse a complete HTTP/1.1 request from raw bytes.
///
/// RFC 2616 Section 5: The request message format is:
///   Request-Line CRLF
///   *(header-field CRLF)
///   CRLF
///   [message-body]
pub fn parse(data: []u8) ParseError!Request {
    var request: Request = .{};
    var pos: usize = 0;

    // RFC 2616 Section 4.1: "In the interest of robustness, servers SHOULD
    // ignore any empty line(s) received where a Request-Line is expected."
    while (pos + 1 < data.len and data[pos] == '\r' and data[pos + 1] == '\n') {
        pos += 2;
    }

    // Parse Request-Line: Method SP Request-URI SP HTTP-Version CRLF
    const request_line_end = findCrlf(data, pos) orelse return error.UnexpectedEndOfInput;
    const request_line = data[pos..request_line_end];
    if (request_line.len > max_request_line_len) return error.LineTooLong;

    try parseRequestLine(&request, request_line);
    pos = request_line_end + 2; // skip CRLF

    // Parse headers until empty line (CRLF CRLF)
    var found_end_of_headers = false;
    while (pos + 1 < data.len) {
        // Empty line signals end of headers
        if (data[pos] == '\r' and data[pos + 1] == '\n') {
            pos += 2;
            found_end_of_headers = true;
            break;
        }

        const header_end = findCrlf(data, pos) orelse return error.UnexpectedEndOfInput;
        const header_line = data[pos..header_end];
        if (header_line.len > max_header_line_len) return error.LineTooLong;

        // RFC 2616 Section 4.2: Header continuation lines start with SP or HTAB.
        // LWS at start of line means this is a continuation of the previous header.
        // We unfold by replacing the CRLF between lines with SP (in-place) and
        // extending the previous header's value slice.
        if (header_line.len > 0 and (header_line[0] == ' ' or header_line[0] == '\t')) {
            if (request.headers.len > 0) {
                const prev = &request.headers.entries[request.headers.len - 1];
                // Replace the CRLF before this continuation line with spaces.
                // The CRLF sits at (header_line.ptr - 2) in the mutable buffer.
                // The data buffer is mutable ([]u8), so we can modify the
                // CRLF bytes that sit right before this continuation line.
                const line_start = @intFromPtr(header_line.ptr);
                const data_start = @intFromPtr(data.ptr);
                const line_offset = line_start - data_start;
                if (line_offset >= 2) {
                    data[line_offset - 2] = ' ';
                    data[line_offset - 1] = ' ';
                }
                // Extend the value slice through the continuation.
                const start = @intFromPtr(prev.value.ptr);
                const end = @intFromPtr(header_line.ptr) + header_line.len;
                prev.value = @as([*]const u8, @ptrFromInt(start))[0 .. end - start];
            }
        } else {
            try parseHeaderLine(&request.headers, header_line);
        }
        pos = header_end + 2;
    }

    if (!found_end_of_headers) return error.UnexpectedEndOfInput;

    // Store raw request (request-line + headers + blank line) for TRACE echo.
    request.raw = data[0..pos];

    // RFC 2616 Section 14.23: HTTP/1.1 requests MUST include exactly one
    // Host header. Multiple Host headers MUST be rejected with 400.
    if (request.version == .http_1_1) {
        var host_buf: [2][]const u8 = undefined;
        const host_count = request.headers.getAll("Host", &host_buf);
        if (host_count > 1) return error.MultipleHostHeaders;

        // RFC 2616 Section 5.2: If the Request-URI is an absoluteURI, the
        // host is part of the Request-URI. Any Host header field value MUST
        // be ignored in favor of the URI's host.
        if (extractHostFromAbsoluteUri(&request)) {
            // Host extracted from absolute URI; remove any existing Host header
            // and use the URI's host instead (already appended by extract fn).
        } else if (host_count == 0) {
            return error.MissingHostHeader;
        }

        // Validate Host header value: no control characters, no whitespace,
        // must match host[:port] pattern.
        if (request.headers.get("Host")) |host| {
            if (!isValidHostValue(host)) return error.InvalidHostHeader;
        }
    }

    // RFC 2616 Section 4.4: Message Length
    // Rule 3: If Transfer-Encoding is present and is not "identity",
    // it takes precedence over Content-Length.
    const te = request.headers.get("Transfer-Encoding");
    if (te != null and !Headers.eqlIgnoreCase(te.?, "identity")) {
        // Chunked body data starts at pos; store raw data for later decoding.
        // The server is responsible for calling parseChunkedBody on a mutable buffer.
        request.body = data[pos..];
    } else if (request.headers.get("Content-Length")) |cl_str| {
        // RFC 2616 Section 4.4: Multiple Content-Length headers with
        // differing values indicate an invalid message (request smuggling risk).
        // Check ALL Content-Length values against the first to prevent
        // smuggling via 3+ headers where only the first two match.
        var cl_vals: [Headers.max_headers][]const u8 = undefined;
        const cl_count = request.headers.getAll("Content-Length", &cl_vals);
        if (cl_count > 1) {
            const first = trimOws(cl_vals[0]);
            for (cl_vals[1..cl_count]) |v| {
                if (!std.mem.eql(u8, first, trimOws(v))) {
                    return error.ConflictingContentLength;
                }
            }
        }
        const content_length = std.fmt.parseInt(usize, trimOws(cl_str), 10) catch
            return error.InvalidContentLength;
        if (pos + content_length > data.len) return error.UnexpectedEndOfInput;
        request.body = data[pos..][0..content_length];
    }

    return request;
}

/// RFC 2616 Section 5.1: Request-Line = Method SP Request-URI SP HTTP-Version CRLF
fn parseRequestLine(request: *Request, line: []const u8) ParseError!void {
    // Find first SP
    const method_end = std.mem.indexOfScalar(u8, line, ' ') orelse
        return error.InvalidRequestLine;
    const method_str = line[0..method_end];

    // Find second SP (searching from after method)
    const rest = line[method_end + 1 ..];
    const uri_end = std.mem.indexOfScalar(u8, rest, ' ') orelse
        return error.InvalidRequestLine;

    const uri = rest[0..uri_end];
    const version_str = rest[uri_end + 1 ..];

    // Parse method
    request.method = Method.fromString(method_str) orelse
        return error.UnknownMethod;

    // Parse URI - must not be empty
    if (uri.len == 0) return error.InvalidRequestLine;

    // Validate URI against path traversal attacks.
    // CONNECT uses authority-form (host:port), OPTIONS may use "*" —
    // only validate path-bearing URIs.
    if (request.method != .CONNECT and !(uri.len == 1 and uri[0] == '*')) {
        if (containsPathTraversal(uri)) return error.UriPathTraversal;
    }

    request.uri = uri;

    // RFC 2616 Section 3.1: HTTP-Version = "HTTP" "/" 1*DIGIT "." 1*DIGIT
    request.version = parseVersion(version_str) orelse
        return error.InvalidVersion;
}

fn parseVersion(s: []const u8) ?Version {
    if (std.mem.eql(u8, s, "HTTP/1.1")) return .http_1_1;
    if (std.mem.eql(u8, s, "HTTP/1.0")) return .http_1_0;
    return null;
}

/// RFC 2616 Section 4.2: message-header = field-name ":" [ field-value ]
fn parseHeaderLine(headers: *Headers, line: []const u8) ParseError!void {
    const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse
        return error.InvalidHeader;

    const name = line[0..colon_pos];
    // RFC 2616 Section 4.2: field-value may be preceded by optional whitespace (OWS)
    const raw_value = line[colon_pos + 1 ..];
    const value = trimOws(raw_value);

    headers.append(name, value) catch |err| switch (err) {
        error.TooManyHeaders => return error.TooManyHeaders,
        error.InvalidHeaderName => return error.InvalidHeader,
        error.InvalidHeaderValue => return error.InvalidHeader,
    };
}

/// RFC 2616 Section 14.1: Check if the request accepts a given content type.
/// Checks the `Accept` header for a matching media type.
/// Returns true if the type is accepted or if no Accept header is present
/// (which means all types are acceptable per RFC 2616 §14.1).
pub fn accepts(self: *const Request, content_type: []const u8) bool {
    const accept = self.headers.get("Accept") orelse return true;

    // Check for wildcard
    if (std.mem.indexOf(u8, accept, "*/*") != null) return true;

    // Check for exact match or type/* match
    if (std.mem.indexOf(u8, accept, content_type) != null) return true;

    // Check for type/* match (e.g., "text/*" matches "text/html")
    if (std.mem.indexOfScalar(u8, content_type, '/')) |slash| {
        const type_prefix = content_type[0 .. slash + 1];
        var search_buf: [64]u8 = undefined;
        if (type_prefix.len + 1 <= search_buf.len) {
            @memcpy(search_buf[0..type_prefix.len], type_prefix);
            search_buf[type_prefix.len] = '*';
            if (std.mem.indexOf(u8, accept, search_buf[0 .. type_prefix.len + 1]) != null) return true;
        }
    }

    return false;
}

/// RFC 2616 Section 14.3: Check if the request accepts a given encoding.
/// Checks the `Accept-Encoding` header. Returns true if the encoding
/// is accepted or if no Accept-Encoding header is present.
pub fn acceptsEncoding(self: *const Request, encoding: []const u8) bool {
    const ae = self.headers.get("Accept-Encoding") orelse return true;
    if (std.mem.indexOf(u8, ae, "*") != null) return true;
    return std.mem.indexOf(u8, ae, encoding) != null;
}

/// RFC 2616 Section 5.2: Extract host from an absolute URI and replace
/// any existing Host header. Returns true if a host was found.
/// RFC 2616 Section 14.23: Validate Host header value.
/// Must be a valid hostname or IP, optionally followed by :port.
/// Rejects control characters, whitespace, and other invalid characters.
fn isValidHostValue(host: []const u8) bool {
    if (host.len == 0) return false;

    // IPv6 literal: [addr] or [addr]:port
    if (host[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host, ']') orelse return false;
        // Validate IPv6 address characters inside brackets
        for (host[1..close]) |c| {
            if (!std.ascii.isHex(c) and c != ':' and c != '.') return false;
        }
        // After ']', must be end or :port
        const after = host[close + 1 ..];
        if (after.len == 0) return true;
        if (after[0] != ':' or after.len < 2) return false;
        _ = std.fmt.parseInt(u16, after[1..], 10) catch return false;
        return true;
    }

    // Regular hostname or IPv4: find optional port suffix
    const colon = std.mem.lastIndexOfScalar(u8, host, ':');
    const hostname = if (colon) |c| host[0..c] else host;
    const port_str = if (colon) |c| host[c + 1 ..] else "";

    if (hostname.len == 0) return false;

    // Validate port if present
    if (port_str.len > 0) {
        _ = std.fmt.parseInt(u16, port_str, 10) catch return false;
    }

    for (hostname) |c| {
        switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.' => {},
            else => return false,
        }
    }
    return true;
}

fn extractHostFromAbsoluteUri(request: *Request) bool {
    const uri = request.uri;
    // Look for "://" scheme separator
    const scheme_end = std.mem.indexOf(u8, uri, "://") orelse return false;
    const after_scheme = uri[scheme_end + 3 ..];
    // Host ends at '/' or end of URI
    const host_end = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
    const host = after_scheme[0..host_end];
    if (host.len == 0) return false;
    // Remove any existing Host header; the absolute URI takes precedence.
    request.headers.remove("Host");
    request.headers.append("Host", host) catch return false;
    return true;
}

/// RFC 2616 Section 14.25: Check if the resource has been modified since
/// the date in the `If-Modified-Since` header. Returns true if the
/// resource has NOT been modified (i.e., a 304 should be returned).
///
/// Accepts all three HTTP date formats per RFC 2616 Section 3.3.1.
/// Note: Per RFC 2616 Section 14.25, if If-None-Match is also present,
/// If-Modified-Since MUST be ignored. Callers should check matchesEtag first.
pub fn isNotModifiedSince(self: *const Request, resource_timestamp: i64) bool {
    const ims = self.headers.get("If-Modified-Since") orelse return false;
    const ims_timestamp = Date.parseHttpDate(ims) orelse return false;
    return resource_timestamp <= ims_timestamp;
}

/// Parse the request body as JSON into type T.
pub fn json(self: *const Request, comptime T: type, allocator: std.mem.Allocator) !std.json.Parsed(T) {
    const body = self.body orelse return error.MissingBody;
    return std.json.parseFromSlice(T, allocator, body, .{});
}

/// Extract Bearer token from "Authorization: Bearer <token>" header.
pub fn bearerToken(self: *const Request) ?[]const u8 {
    const auth = self.headers.get("Authorization") orelse return null;
    const trimmed = trimOws(auth);
    if (trimmed.len > 7 and std.ascii.startsWithIgnoreCase(trimmed, "bearer ")) {
        return trimOws(trimmed[7..]);
    }
    return null;
}

/// Returns true if Content-Type header indicates JSON payload.
pub fn isJson(self: *const Request) bool {
    const ct = self.headers.get("Content-Type") orelse return false;
    return std.mem.indexOf(u8, ct, "application/json") != null;
}

/// Returns true if Content-Type header indicates form-urlencoded payload.
pub fn isForm(self: *const Request) bool {
    const ct = self.headers.get("Content-Type") orelse return false;
    return std.mem.indexOf(u8, ct, "application/x-www-form-urlencoded") != null;
}

/// Returns true if Content-Type header indicates multipart form payload.
pub fn isMultipart(self: *const Request) bool {
    const ct = self.headers.get("Content-Type") orelse return false;
    return std.mem.indexOf(u8, ct, "multipart/form-data") != null;
}

/// Extract a query parameter value by name from the Request URI. Zero-copy.
/// Example: GET /search?q=zig&page=2 -> req.query("q") returns "zig"
pub fn query(self: *const Request, name: []const u8) ?[]const u8 {
    const qpos = std.mem.indexOfScalar(u8, self.uri, '?') orelse return null;
    var raw_query = self.uri[qpos + 1 ..];
    if (std.mem.indexOfScalar(u8, raw_query, '#')) |fpos| {
        raw_query = raw_query[0..fpos];
    }

    var iter = std.mem.splitScalar(u8, raw_query, '&');
    while (iter.next()) |pair| {
        if (pair.len == 0) continue;
        const eq_pos = std.mem.indexOfScalar(u8, pair, '=') orelse pair.len;
        const key = pair[0..eq_pos];
        if (std.mem.eql(u8, key, name)) {
            return if (eq_pos < pair.len) pair[eq_pos + 1 ..] else "";
        }
    }
    return null;
}

pub const BasicAuth = struct {
    username: []const u8,
    password: []const u8,
};

/// Extract and Base64-decode Basic Auth credentials from "Authorization: Basic <base64>" header.
/// Uses the provided `out_buf` to hold the decoded "username:password" string.
pub fn basicAuth(self: *const Request, out_buf: []u8) ?BasicAuth {
    const auth = self.headers.get("Authorization") orelse return null;
    const trimmed = trimOws(auth);
    if (trimmed.len <= 6 or !std.ascii.startsWithIgnoreCase(trimmed, "basic ")) return null;
    const b64_str = trimOws(trimmed[6..]);

    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(b64_str) catch return null;
    if (decoded_len > out_buf.len) return null;

    decoder.decode(out_buf[0..decoded_len], b64_str) catch return null;
    const decoded = out_buf[0..decoded_len];

    const colon = std.mem.indexOfScalar(u8, decoded, ':') orelse return null;
    return .{
        .username = decoded[0..colon],
        .password = decoded[colon + 1 ..],
    };
}

/// RFC 2616 Section 14.35: Parse a byte Range header.
/// Format: "bytes=0-499", "bytes=500-999", "bytes=-500", "bytes=500-"
/// Returns the first range as start/end byte positions.
pub const ByteRange = struct {
    start: ?usize,
    end: ?usize,
};

pub fn parseRange(self: *const Request, total_size: usize) ?ByteRange {
    const range_header = self.headers.get("Range") orelse return null;
    const trimmed = trimOws(range_header);

    // Must start with "bytes="
    if (!std.mem.startsWith(u8, trimmed, "bytes=")) return null;
    const spec = trimmed[6..];

    // Only handle the first range (no multi-range support)
    const range_end = std.mem.indexOfScalar(u8, spec, ',') orelse spec.len;
    const range_str = spec[0..range_end];

    const dash = std.mem.indexOfScalar(u8, range_str, '-') orelse return null;

    if (dash == 0) {
        // Suffix range: "-500" means last 500 bytes
        const suffix_len = std.fmt.parseInt(usize, range_str[1..], 10) catch return null;
        if (suffix_len == 0 or suffix_len > total_size) return null;
        return .{ .start = total_size - suffix_len, .end = total_size - 1 };
    }

    const start = std.fmt.parseInt(usize, range_str[0..dash], 10) catch return null;
    if (start >= total_size) return null;

    if (dash + 1 >= range_str.len) {
        // Open-ended range: "500-"
        return .{ .start = start, .end = total_size - 1 };
    }

    const end = std.fmt.parseInt(usize, range_str[dash + 1 ..], 10) catch return null;
    if (end < start) return null;
    return .{ .start = start, .end = @min(end, total_size - 1) };
}

/// RFC 2616 Section 14.35: Parse all byte ranges from a Range header.
/// Format: "bytes=0-499,500-999,-100"
/// Returns the number of valid ranges written to `buf`, or null if no
/// Range header is present or it is malformed.
pub fn parseRanges(self: *const Request, total_size: usize, buf: []ByteRange) ?usize {
    const range_header = self.headers.get("Range") orelse return null;
    const trimmed_header = trimOws(range_header);

    if (!std.mem.startsWith(u8, trimmed_header, "bytes=")) return null;
    const spec = trimmed_header[6..];

    var count: usize = 0;
    var it = std.mem.splitScalar(u8, spec, ',');
    while (it.next()) |range_raw| {
        if (count >= buf.len) break;
        const range_str = trimOws(range_raw);
        if (range_str.len == 0) continue;

        const dash = std.mem.indexOfScalar(u8, range_str, '-') orelse return null;

        if (dash == 0) {
            // Suffix range: "-500"
            const suffix_len = std.fmt.parseInt(usize, range_str[1..], 10) catch return null;
            if (suffix_len == 0 or suffix_len > total_size) return null;
            buf[count] = .{ .start = total_size - suffix_len, .end = total_size - 1 };
        } else {
            const start = std.fmt.parseInt(usize, range_str[0..dash], 10) catch return null;
            if (start >= total_size) return null;

            if (dash + 1 >= range_str.len) {
                buf[count] = .{ .start = start, .end = total_size - 1 };
            } else {
                const end = std.fmt.parseInt(usize, range_str[dash + 1 ..], 10) catch return null;
                if (end < start) return null;
                buf[count] = .{ .start = start, .end = @min(end, total_size - 1) };
            }
        }
        count += 1;
    }

    if (count == 0) return null;
    return count;
}

/// RFC 2616 Section 14.26: Check If-None-Match against an ETag.
/// Returns true if the request ETag matches (resource not modified).
/// Handles comma-separated ETag lists: `If-None-Match: "a", "b", "c"`
///
/// RFC 2616 Section 14.25: If If-None-Match is present, If-Modified-Since
/// MUST be ignored. Callers should check matchesEtag first.
pub fn matchesEtag(self: *const Request, etag: []const u8) bool {
    const inm = self.headers.get("If-None-Match") orelse return false;
    // Wildcard match
    if (std.mem.eql(u8, trimOws(inm), "*")) return true;
    // Check each comma-separated ETag
    var it = std.mem.splitScalar(u8, inm, ',');
    while (it.next()) |part| {
        if (std.mem.eql(u8, trimOws(part), etag)) return true;
    }
    return false;
}

/// RFC 2616 Section 3.7.2: A multipart body part.
pub const MultipartPart = struct {
    headers: Headers = .{},
    body: []const u8 = "",
};

/// RFC 2616 Section 3.7.2: Parse a multipart body into individual parts.
/// The boundary is extracted from the Content-Type header.
/// Returns the number of parts found and fills the provided buffer.
pub fn parseMultipart(self: *const Request, parts: []MultipartPart) ?usize {
    const ct = self.headers.get("Content-Type") orelse return null;

    // Extract boundary from Content-Type: multipart/form-data; boundary=----xxx
    const boundary = extractBoundary(ct) orelse return null;

    return parseMultipartBody(self.body, boundary, parts);
}

fn extractBoundary(content_type: []const u8) ?[]const u8 {
    const needle = "boundary=";
    const idx = std.mem.indexOf(u8, content_type, needle) orelse return null;
    const start = idx + needle.len;
    // Boundary may be quoted
    if (start < content_type.len and content_type[start] == '"') {
        const end = std.mem.indexOfScalarPos(u8, content_type, start + 1, '"') orelse return null;
        return content_type[start + 1 .. end];
    }
    // Unquoted: ends at whitespace, semicolon, or end of string
    var end = start;
    while (end < content_type.len and content_type[end] != ' ' and
        content_type[end] != ';' and content_type[end] != '\t') : (end += 1)
    {}
    if (end == start) return null;
    return content_type[start..end];
}

fn parseMultipartBody(body: []const u8, boundary: []const u8, parts: []MultipartPart) usize {
    // Each part is delimited by "\r\n--boundary\r\n" (or "--boundary\r\n" at start)
    // The body ends with "\r\n--boundary--\r\n"
    var count: usize = 0;
    var pos: usize = 0;

    // Find the first boundary: "--boundary\r\n"
    // Build delimiter: "--" + boundary
    var delim_buf: [74]u8 = undefined; // max boundary is 70 chars per RFC
    if (boundary.len + 2 > delim_buf.len) return 0;
    delim_buf[0] = '-';
    delim_buf[1] = '-';
    @memcpy(delim_buf[2..][0..boundary.len], boundary);
    const delim = delim_buf[0 .. boundary.len + 2];

    // Skip preamble - find first boundary
    pos = std.mem.indexOf(u8, body, delim) orelse return 0;
    pos += delim.len;

    // Check for CRLF after boundary
    if (pos + 2 <= body.len and body[pos] == '\r' and body[pos + 1] == '\n') {
        pos += 2;
    } else if (pos + 2 <= body.len and body[pos] == '-' and body[pos + 1] == '-') {
        return 0; // Immediate close: "--boundary--"
    } else {
        return 0;
    }

    while (count < parts.len) {
        // Find the next boundary
        const next = std.mem.indexOf(u8, body[pos..], delim) orelse break;
        const part_data = body[pos .. pos + next];

        // Strip trailing CRLF before the boundary
        const part_end = if (part_data.len >= 2 and
            part_data[part_data.len - 2] == '\r' and part_data[part_data.len - 1] == '\n')
            part_data.len - 2
        else
            part_data.len;

        // Parse part: headers then body separated by \r\n\r\n
        const header_end_pos = findHeaderEnd(part_data[0..part_end]);
        if (header_end_pos) |he| {
            var part: MultipartPart = .{};
            // Parse part headers
            var hpos: usize = 0;
            while (hpos < he) {
                const hline_end = findCrlf(part_data, hpos) orelse break;
                const hline = part_data[hpos..hline_end];
                parseHeaderLine(&part.headers, hline) catch {};
                hpos = hline_end + 2;
            }
            part.body = part_data[he + 4 .. part_end];
            parts[count] = part;
        } else {
            // No headers, entire part is body
            parts[count] = .{ .body = part_data[0..part_end] };
        }
        count += 1;

        pos += next + delim.len;
        // Check if this is the closing boundary (--boundary--)
        if (pos + 2 <= body.len and body[pos] == '-' and body[pos + 1] == '-') {
            break;
        }
        // Skip CRLF after boundary
        if (pos + 2 <= body.len and body[pos] == '\r' and body[pos + 1] == '\n') {
            pos += 2;
        }
    }

    return count;
}

fn findHeaderEnd(data: []const u8) ?usize {
    if (data.len < 4) return null;
    var i: usize = 0;
    while (i + 3 < data.len) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n' and data[i + 2] == '\r' and data[i + 3] == '\n') {
            return i;
        }
    }
    return null;
}

/// Trim optional whitespace (OWS = *(SP / HTAB)) from both ends.
/// RFC 2616 Section 2.2
pub fn trimOws(s: []const u8) []const u8 {
    var start: usize = 0;
    while (start < s.len and (s[start] == ' ' or s[start] == '\t')) : (start += 1) {}
    var end: usize = s.len;
    while (end > start and (s[end - 1] == ' ' or s[end - 1] == '\t')) : (end -= 1) {}
    return s[start..end];
}

/// Check if a URI path contains traversal sequences that could escape
/// the document root. Detects:
///   - Literal: /../, /..  (at end), ..\
///   - Percent-encoded: /%2e%2e/, /%2E%2E/, mixed case
///   - Overlong UTF-8 percent-encoded: /%c0%ae/ (overlong dot encoding)
///   - Double-encoded: /%252e%252e/
///   - Backslash variants: \..\, \..
///   - Null bytes: %00
///
/// We decode the URI's path component in a single pass and check the
/// resulting segments for ".." after decoding.
pub fn containsPathTraversal(uri: []const u8) bool {
    // Isolate path component: strip query and fragment
    const path = blk: {
        for (uri, 0..) |c, i| {
            if (c == '?' or c == '#') break :blk uri[0..i];
        }
        break :blk uri;
    };

    // Null bytes in URI are always suspicious
    for (path) |c| {
        if (c == 0) return true;
    }
    // Check for encoded null bytes (%00)
    if (containsEncodedByte(path, 0x00)) return true;

    // Decode the path and check each segment between separators.
    // A segment of ".." (after decoding) is path traversal.
    var i: usize = 0;
    while (i < path.len) {
        // Skip separators
        if (path[i] == '/' or path[i] == '\\') {
            i += 1;
            continue;
        }

        // Read one segment (until next / or \ or end)
        var decoded: [2]u8 = undefined;
        var seg_len: usize = 0;
        var is_only_dots = true;

        while (i < path.len and path[i] != '/' and path[i] != '\\') {
            const ch = decodeUriChar(path, &i);
            // After first decode pass, check for double-encoding by
            // decoding again if we got a '%'
            const final_ch = if (ch == '%') blk2: {
                // This was a literal '%' after decoding — could be double-encoded.
                // We need to look at the original decoded sequence.
                break :blk2 ch;
            } else ch;

            if (final_ch != '.') is_only_dots = false;
            if (seg_len < 2) {
                decoded[seg_len] = final_ch;
            }
            seg_len += 1;
        }

        if (seg_len == 2 and is_only_dots and decoded[0] == '.' and decoded[1] == '.') {
            return true;
        }
    }

    // Also check for double-encoded traversal: %252e%252e
    // After one round of decoding, %25 -> %, so %252e -> %2e -> .
    if (containsDoubleEncodedTraversal(path)) return true;

    return false;
}

/// Decode one character from a URI, advancing the index past it.
/// Handles percent-encoding (%XX) and overlong UTF-8 percent sequences
/// that encode '.', '/', or '\'.
fn decodeUriChar(path: []const u8, i: *usize) u8 {
    if (path[i.*] == '%' and i.* + 2 < path.len) {
        const h = hexVal(path[i.* + 1]);
        const l = hexVal(path[i.* + 2]);
        if (h != null and l != null) {
            const byte = h.? * 16 + l.?;
            i.* += 3;

            // Detect overlong UTF-8 encoding of '.' (U+002E):
            //   %c0%ae      = 0xC0 0xAE        (overlong 2-byte)
            //   %e0%80%ae   = 0xE0 0x80 0xAE   (overlong 3-byte)
            if (byte == 0xC0) {
                if (peekEncodedByte(path, i.*)) |byte2| {
                    if (byte2 == 0xAE) {
                        i.* += 3;
                        return '.';
                    }
                }
            } else if (byte == 0xE0) {
                if (peekEncodedByte(path, i.*)) |byte2| {
                    if (byte2 == 0x80) {
                        const after = i.* + 3;
                        if (peekEncodedByte(path, after)) |byte3| {
                            if (byte3 == 0xAE) {
                                i.* = after + 3;
                                return '.';
                            }
                        }
                    }
                }
            }

            return @intCast(byte);
        }
    }

    const ch = path[i.*];
    i.* += 1;
    return ch;
}

/// Peek a single percent-encoded byte at `idx` without advancing.
/// Returns null when there is no valid %XX sequence at that position.
fn peekEncodedByte(path: []const u8, idx: usize) ?u8 {
    if (idx + 2 < path.len and path[idx] == '%') {
        const h = hexVal(path[idx + 1]);
        const l = hexVal(path[idx + 2]);
        if (h != null and l != null) return h.? * 16 + l.?;
    }
    return null;
}

fn hexVal(c: u8) ?u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return null;
}

/// Check if the path contains a percent-encoded specific byte value.
fn containsEncodedByte(path: []const u8, byte: u8) bool {
    const hi_chars = "0123456789abcdefABCDEF";
    const target_hi = byte >> 4;
    const target_lo = byte & 0x0F;
    var i: usize = 0;
    while (i + 2 < path.len) : (i += 1) {
        if (path[i] == '%') {
            const h = hexVal(path[i + 1]);
            const l = hexVal(path[i + 2]);
            if (h != null and l != null) {
                _ = hi_chars;
                if (h.? == target_hi and l.? == target_lo) return true;
            }
        }
    }
    return false;
}

/// Detect double-encoded path traversal: %252e%252e
/// When a server decodes once, %25 -> %, leaving %2e%2e -> ..
fn containsDoubleEncodedTraversal(path: []const u8) bool {
    // Look for %252e or %252E (double-encoded dot)
    const patterns = [_][]const u8{
        "%252e", "%252E",
    };
    for (patterns) |dot_enc| {
        // Need two consecutive encoded dots to form ".."
        var i: usize = 0;
        while (i + dot_enc.len * 2 <= path.len) : (i += 1) {
            if (asciiEqlIgnoreCase(path[i..][0..dot_enc.len], dot_enc) and
                asciiEqlIgnoreCase(path[i + dot_enc.len ..][0..dot_enc.len], dot_enc))
            {
                // Check that it's bounded by separators or start/end
                const before_ok = (i == 0) or path[i - 1] == '/' or path[i - 1] == '\\';
                const after = i + dot_enc.len * 2;
                const after_ok = (after >= path.len) or path[after] == '/' or
                    path[after] == '\\' or path[after] == '?' or path[after] == '#';
                if (before_ok and after_ok) return true;
            }
        }
    }
    return false;
}

fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        const la = if (ca >= 'A' and ca <= 'Z') ca + 32 else ca;
        const lb = if (cb >= 'A' and cb <= 'Z') cb + 32 else cb;
        if (la != lb) return false;
    }
    return true;
}

fn findCrlf(data: []const u8, start: usize) ?usize {
    var i = start;
    while (i + 1 < data.len) : (i += 1) {
        if (data[i] == '\r' and data[i + 1] == '\n') return i;
    }
    return null;
}

/// Parse chunked transfer-encoding body.
/// RFC 2616 Section 3.6.1:
///   Chunked-Body  = *chunk last-chunk trailer CRLF
///   chunk          = chunk-size [ chunk-extension ] CRLF chunk-data CRLF
///   chunk-size     = 1*HEX
///   last-chunk     = 1*("0") [ chunk-extension ] CRLF
pub const ChunkedResult = struct {
    body_len: usize,
    consumed: usize,
    /// RFC 2616 Section 14.40: Trailer headers sent after the last chunk.
    trailers: Headers = .{},
};

pub fn parseChunkedBody(data: []const u8, out: []u8) ParseError!ChunkedResult {
    var pos: usize = 0;
    var out_pos: usize = 0;
    var result: ChunkedResult = .{ .body_len = 0, .consumed = 0 };

    while (true) {
        // Read chunk-size line
        const size_line_end = findCrlf(data, pos) orelse return error.UnexpectedEndOfInput;
        const size_line = data[pos..size_line_end];

        // chunk-size may be followed by chunk-extension (;...)
        const size_str = if (std.mem.indexOfScalar(u8, size_line, ';')) |semi|
            size_line[0..semi]
        else
            size_line;

        const chunk_size = std.fmt.parseInt(usize, trimOws(size_str), 16) catch
            return error.InvalidContentLength;

        pos = size_line_end + 2; // skip CRLF after size

        if (chunk_size == 0) {
            // RFC 2616 Section 14.40: Parse trailer headers after last chunk.
            while (pos + 1 < data.len) {
                if (data[pos] == '\r' and data[pos + 1] == '\n') {
                    pos += 2;
                    break;
                }
                const trailer_end = findCrlf(data, pos) orelse return error.UnexpectedEndOfInput;
                const trailer_line = data[pos..trailer_end];
                try parseHeaderLine(&result.trailers, trailer_line);
                pos = trailer_end + 2;
            }
            result.body_len = out_pos;
            result.consumed = pos;
            return result;
        }

        // chunk_size comes from parseInt and may be as large as maxInt(usize);
        // use saturating subtraction to avoid overflow in the bounds checks
        // and the additions below.
        if (chunk_size > out.len -| out_pos) return error.BodyTooLarge;
        if (chunk_size > data.len -| pos -| 2) return error.UnexpectedEndOfInput;

        @memcpy(out[out_pos..][0..chunk_size], data[pos..][0..chunk_size]);
        out_pos += chunk_size;
        pos += chunk_size;

        // Each chunk-data is followed by CRLF
        if (data[pos] != '\r' or data[pos + 1] != '\n') return error.InvalidRequestLine;
        pos += 2;
    }
}

/// Parse from a const slice. This copies into an internal buffer first
/// so the parse can do in-place modifications (header continuation folding).
/// Only available in test and debug builds. Production code MUST use
/// `parse()` with a mutable buffer — the threadlocal buffer used here
/// has lifetime issues in concurrent production workloads.
pub const parseConst = if (@import("builtin").is_test or @import("builtin").mode == .Debug)
    parseConstImpl
else
    @compileError("parseConst is only available in test/debug builds; use parse() with a mutable buffer");

fn parseConstImpl(data: []const u8) ParseError!Request {
    const S = struct {
        threadlocal var buf: [max_request_line_len + max_header_line_len * Headers.max_headers + max_body_len]u8 = undefined;
    };
    if (data.len > S.buf.len) return error.BodyTooLarge;
    @memcpy(S.buf[0..data.len], data);
    return parse(S.buf[0..data.len]);
}

// --- Tests ---

const testing = std.testing;

// RFC 2616 Section 5.1.1: Method = "OPTIONS" | "GET" | "HEAD" | "POST" |
// "PUT" | "DELETE" | "TRACE" | "CONNECT" | extension-method
test "Request.Method: fromString parses all standard methods" {
    try testing.expectEqual(Method.GET, Method.fromString("GET").?);
    try testing.expectEqual(Method.HEAD, Method.fromString("HEAD").?);
    try testing.expectEqual(Method.POST, Method.fromString("POST").?);
    try testing.expectEqual(Method.PUT, Method.fromString("PUT").?);
    try testing.expectEqual(Method.DELETE, Method.fromString("DELETE").?);
    try testing.expectEqual(Method.OPTIONS, Method.fromString("OPTIONS").?);
    try testing.expectEqual(Method.TRACE, Method.fromString("TRACE").?);
    try testing.expectEqual(Method.CONNECT, Method.fromString("CONNECT").?);
    try testing.expectEqual(Method.PATCH, Method.fromString("PATCH").?);
    try testing.expect(Method.fromString("INVALID") == null);
}

// /// RFC 2616 Section 5.1.1: Method.toBytes roundtrip
test "Request.Method: toBytes roundtrip" {
    const enum_info = @typeInfo(Method).@"enum";
    inline for (enum_info.field_names, enum_info.field_values) |_, value| {
        const m: Method = @fromBackingInt(@intCast(value));
        try testing.expectEqual(m, Method.fromString(m.toBytes()).?);
    }
}

// /// RFC 2616 Section 3.1: HTTP-Version = "HTTP" "/" 1*DIGIT "." 1*DIGIT
test "Request.Version: parsing and serialization" {
    try testing.expectEqualStrings("HTTP/1.1", Version.http_1_1.toBytes());
    try testing.expectEqualStrings("HTTP/1.0", Version.http_1_0.toBytes());
}

// /// RFC 2616 Section 5: Complete GET request parsing
test "Request: parse simple GET request" {
    const raw =
        "GET /index.html HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept: text/html\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/index.html", req.uri);
    try testing.expectEqual(Version.http_1_1, req.version);
    try testing.expectEqualStrings("example.com", req.headers.get("Host").?);
    try testing.expectEqualStrings("text/html", req.headers.get("Accept").?);
    try testing.expectEqualStrings("", req.body);
}

// /// RFC 2616 Section 5: POST request with body
test "Request: parse POST request with body" {
    const raw =
        "POST /submit HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 11\r\n" ++
        "\r\n" ++
        "hello=world";

    const req = try Request.parseConst(raw);
    try testing.expectEqual(Method.POST, req.method);
    try testing.expectEqualStrings("/submit", req.uri);
    try testing.expectEqualStrings("hello=world", req.body);
}

// RFC 2616 Section 4.1: "servers SHOULD ignore any empty line(s) received
// where a Request-Line is expected"
test "Request: ignore leading CRLF" {
    const raw =
        "\r\n\r\n" ++
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqual(Method.GET, req.method);
    try testing.expectEqualStrings("/", req.uri);
}

// RFC 2616 Section 14.23: "All HTTP/1.1 requests MUST include exactly one
// Host header field."
test "Request: missing Host header in HTTP/1.1 returns error" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";

    try testing.expectError(error.MissingHostHeader, Request.parseConst(raw));
}

// /// RFC 2616 Section 14.23: HTTP/1.0 requests don't require Host.
test "Request: HTTP/1.0 without Host is valid" {
    const raw =
        "GET / HTTP/1.0\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqual(Version.http_1_0, req.version);
}

// /// RFC 2616 Section 5.1: Invalid request line
test "Request: invalid request line" {
    try testing.expectError(error.InvalidRequestLine, Request.parseConst("GET\r\n\r\n"));
    try testing.expectError(error.InvalidRequestLine, Request.parseConst("GET /\r\n\r\n"));
}

// /// RFC 2616 Section 5.1.1: Unknown method
test "Request: unknown method" {
    const raw =
        "FROBNICATE / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.UnknownMethod, Request.parseConst(raw));
}

// /// RFC 2616 Section 3.1: Invalid HTTP version
test "Request: invalid version" {
    const raw =
        "GET / HTTP/2.0\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidVersion, Request.parseConst(raw));
}

// /// RFC 2616 Section 4.2: Header with optional whitespace around value
test "Request: header value whitespace trimming" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host:   example.com  \r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("example.com", req.headers.get("Host").?);
}

// /// RFC 2616 Section 4.2: Malformed header (no colon)
test "Request: malformed header" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidHeader, Request.parseConst(raw));
}

// /// RFC 2616 Section 4.4: Invalid Content-Length value
test "Request: invalid content-length" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: abc\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidContentLength, Request.parseConst(raw));
}

// /// RFC 2616 Section 4.4: Content-Length exceeds body data
test "Request: content-length exceeds available data" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 100\r\n" ++
        "\r\n" ++
        "short";
    try testing.expectError(error.UnexpectedEndOfInput, Request.parseConst(raw));
}

// /// RFC 2616 Section 5: Unexpected end of input
test "Request: unexpected end of input" {
    try testing.expectError(error.UnexpectedEndOfInput, Request.parseConst("GET / HTTP/1.1\r\n"));
}

// /// RFC 2616 Section 5.1: Request-URI with query string
test "Request: URI with query string" {
    const raw =
        "GET /search?q=test&page=1 HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("/search?q=test&page=1", req.uri);
}

// /// RFC 2616 Section 5.1.2: Request-URI as absolute URI
test "Request: absolute URI" {
    const raw =
        "GET http://example.com/path HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("http://example.com/path", req.uri);
}

// /// RFC 2616 Section 5.1.2: Request-URI "*" for OPTIONS
test "Request: OPTIONS with asterisk URI" {
    const raw =
        "OPTIONS * HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqual(Method.OPTIONS, req.method);
    try testing.expectEqualStrings("*", req.uri);
}

// /// RFC 2616 Section 2.2: trimOws utility
test "Request: trimOws" {
    try testing.expectEqualStrings("hello", trimOws("  hello  "));
    try testing.expectEqualStrings("hello", trimOws("\thello\t"));
    try testing.expectEqualStrings("hello", trimOws("hello"));
    try testing.expectEqualStrings("", trimOws("   "));
    try testing.expectEqualStrings("", trimOws(""));
}

// /// RFC 2616 Section 3.6.1: Chunked transfer encoding parsing
test "Request: parseChunkedBody simple" {
    const chunked =
        "5\r\n" ++
        "Hello\r\n" ++
        "6\r\n" ++
        "World!\r\n" ++
        "0\r\n" ++
        "\r\n";

    var out: [64]u8 = undefined;
    const result = try parseChunkedBody(chunked, &out);
    try testing.expectEqualStrings("HelloWorld!", out[0..result.body_len]);
    try testing.expectEqual(chunked.len, result.consumed);
}

// /// RFC 2616 Section 3.6.1: Chunked with extension
test "Request: parseChunkedBody with extension" {
    const chunked =
        "5;ext=val\r\n" ++
        "Hello\r\n" ++
        "0\r\n" ++
        "\r\n";

    var out: [64]u8 = undefined;
    const result = try parseChunkedBody(chunked, &out);
    try testing.expectEqualStrings("Hello", out[0..result.body_len]);
    try testing.expectEqual(chunked.len, result.consumed);
}

// RFC 2616 Section 3.6.1 / 14.40: Chunked with trailer headers
test "Request: parseChunkedBody with trailers" {
    const chunked =
        "3\r\n" ++
        "abc\r\n" ++
        "0\r\n" ++
        "X-Checksum: abc123\r\n" ++
        "X-Timestamp: 12345\r\n" ++
        "\r\n";

    var out: [64]u8 = undefined;
    const result = try parseChunkedBody(chunked, &out);
    try testing.expectEqualStrings("abc", out[0..result.body_len]);
    try testing.expectEqual(chunked.len, result.consumed);
    // RFC 2616 Section 14.40: Trailer headers are parsed
    try testing.expectEqualStrings("abc123", result.trailers.get("X-Checksum").?);
    try testing.expectEqualStrings("12345", result.trailers.get("X-Timestamp").?);
}

// /// RFC 2616 Section 3.6.1: Chunked with zero-length body
test "Request: parseChunkedBody empty" {
    const chunked = "0\r\n\r\n";

    var out: [64]u8 = undefined;
    const result = try parseChunkedBody(chunked, &out);
    try testing.expectEqual(@as(usize, 0), result.body_len);
}

// /// RFC 2616 Section 5: Multiple headers with various methods
test "Request: HEAD request" {
    const raw =
        "HEAD /resource HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqual(Method.HEAD, req.method);
    try testing.expectEqualStrings("/resource", req.uri);
}

// /// RFC 2616 Section 5: PUT request with body
test "Request: PUT request with body" {
    const raw =
        "PUT /resource HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 13\r\n" ++
        "\r\n" ++
        "Hello, World!";

    const req = try Request.parseConst(raw);
    try testing.expectEqual(Method.PUT, req.method);
    try testing.expectEqualStrings("Hello, World!", req.body);
}

// /// RFC 2616 Section 5: DELETE request
test "Request: DELETE request" {
    const raw =
        "DELETE /resource/42 HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqual(Method.DELETE, req.method);
    try testing.expectEqualStrings("/resource/42", req.uri);
}

// RFC 2616 Section 4.4: Transfer-Encoding takes precedence over Content-Length
test "Request: Transfer-Encoding precedence over Content-Length" {
    const raw =
        "POST /upload HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Content-Length: 999\r\n" ++
        "\r\n" ++
        "5\r\nHello\r\n0\r\n\r\n";

    const req = try Request.parseConst(raw);
    // Body should contain the raw chunked data, not 999 bytes
    try testing.expect(req.body.len > 0);
    try testing.expect(req.body.len < 999);
}

// RFC 2616 Section 4.4: Transfer-Encoding "identity" defers to Content-Length
test "Request: Transfer-Encoding identity uses Content-Length" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Transfer-Encoding: identity\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "Hello";

    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("Hello", req.body);
}

// RFC 2616 Section 4.2: Header continuation lines (LWS folding)
test "Request: header continuation line" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "X-Long-Header: value1\r\n" ++
        " continued-value\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    const val = req.headers.get("X-Long-Header").?;
    // The folded value should contain both parts
    try testing.expect(std.mem.indexOf(u8, val, "value1") != null);
    try testing.expect(std.mem.indexOf(u8, val, "continued-value") != null);
}

// RFC 2616 Section 4.2: Tab-prefixed continuation line
test "Request: header continuation with tab" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "X-Header: first\r\n" ++
        "\tsecond\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    const val = req.headers.get("X-Header").?;
    try testing.expect(std.mem.indexOf(u8, val, "first") != null);
    try testing.expect(std.mem.indexOf(u8, val, "second") != null);
}

// RFC 2616 Section 14.25: If-Modified-Since - not modified
test "Request: isNotModifiedSince returns true when not modified" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    // Resource modified at epoch (same time) - not modified
    try testing.expect(req.isNotModifiedSince(0));
    // Resource modified before the date - not modified
    try testing.expect(req.isNotModifiedSince(-1));
}

// RFC 2616 Section 14.25: If-Modified-Since - modified
test "Request: isNotModifiedSince returns false when modified" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    // Resource modified after the date - modified
    try testing.expect(!req.isNotModifiedSince(1));
}

// RFC 2616 Section 14.25: No If-Modified-Since header
test "Request: isNotModifiedSince returns false when header absent" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(!req.isNotModifiedSince(0));
}

test "Request: query parameter parser" {
    const raw =
        "GET /search?q=zig+lang&page=2&sort=desc#top HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("zig+lang", req.query("q").?);
    try testing.expectEqualStrings("2", req.query("page").?);
    try testing.expectEqualStrings("desc", req.query("sort").?);
    try testing.expect(req.query("nonexistent") == null);
}

test "Request: basicAuth credentials decoding" {
    // "admin:secret123" Base64 encoded is "YWRtaW46c2VjcmV0MTIz"
    const raw =
        "GET /protected HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Authorization: Basic YWRtaW46c2VjcmV0MTIz\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    var buf: [64]u8 = undefined;
    const creds = req.basicAuth(&buf).?;
    try testing.expectEqualStrings("admin", creds.username);
    try testing.expectEqualStrings("secret123", creds.password);
}

test "Request: bearerToken and Content-Type helpers" {
    const raw =
        "POST /api/data HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Authorization: Bearer my_jwt_token_xyz\r\n" ++
        "Content-Type: application/json; charset=utf-8\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("my_jwt_token_xyz", req.bearerToken().?);
    try testing.expect(req.isJson());
    try testing.expect(!req.isForm());
    try testing.expect(!req.isMultipart());
}

// RFC 2616 Section 14.26: If-None-Match ETag comparison
test "Request: matchesEtag" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-None-Match: \"abc123\"\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.matchesEtag("\"abc123\""));
    try testing.expect(!req.matchesEtag("\"def456\""));
}

// RFC 2616 Section 14.26: If-None-Match wildcard
test "Request: matchesEtag wildcard" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-None-Match: *\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.matchesEtag("\"anything\""));
}

// RFC 2616 Section 14.1: Accept header - exact match
test "Request: accepts content type" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept: text/html, application/json\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.accepts("text/html"));
    try testing.expect(req.accepts("application/json"));
    try testing.expect(!req.accepts("image/png"));
}

// RFC 2616 Section 14.1: Accept header - wildcard
test "Request: accepts wildcard" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept: */*\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.accepts("text/html"));
    try testing.expect(req.accepts("application/json"));
}

// RFC 2616 Section 14.1: Accept header - type wildcard
test "Request: accepts type wildcard" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept: text/*\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.accepts("text/html"));
    try testing.expect(req.accepts("text/plain"));
    try testing.expect(!req.accepts("application/json"));
}

// RFC 2616 Section 14.1: No Accept header means all types accepted
test "Request: accepts without header" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.accepts("anything/at-all"));
}

// RFC 2616 Section 14.3: Accept-Encoding
test "Request: acceptsEncoding" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Accept-Encoding: gzip, deflate\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.acceptsEncoding("gzip"));
    try testing.expect(req.acceptsEncoding("deflate"));
    try testing.expect(!req.acceptsEncoding("br"));
}

// RFC 2616 Section 14.35: Range header parsing - simple range
test "Request: parseRange simple" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=0-499\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    const range = req.parseRange(1000).?;
    try testing.expectEqual(@as(usize, 0), range.start.?);
    try testing.expectEqual(@as(usize, 499), range.end.?);
}

// RFC 2616 Section 14.35: Range header - suffix range
test "Request: parseRange suffix" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=-500\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    const range = req.parseRange(1000).?;
    try testing.expectEqual(@as(usize, 500), range.start.?);
    try testing.expectEqual(@as(usize, 999), range.end.?);
}

// RFC 2616 Section 14.35: Range header - open-ended
test "Request: parseRange open-ended" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=500-\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    const range = req.parseRange(1000).?;
    try testing.expectEqual(@as(usize, 500), range.start.?);
    try testing.expectEqual(@as(usize, 999), range.end.?);
}

// RFC 2616 Section 14.35: Range header - no Range header
test "Request: parseRange no header" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.parseRange(1000) == null);
}

// RFC 2616 Section 14.35: Range header - start beyond size
test "Request: parseRange out of bounds" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=2000-3000\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expect(req.parseRange(1000) == null);
}

// RFC 2616 Section 14.35: Range header - end clamped to size
test "Request: parseRange end clamped" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=500-5000\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    const range = req.parseRange(1000).?;
    try testing.expectEqual(@as(usize, 500), range.start.?);
    try testing.expectEqual(@as(usize, 999), range.end.?);
}

// RFC 2616 Section 5.2: Absolute URI provides Host when header is missing
test "Request: absolute URI provides Host header" {
    const raw =
        "GET http://example.com/path HTTP/1.1\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("example.com", req.headers.get("Host").?);
}

// RFC 2616 Section 5.2: Absolute URI with port
test "Request: absolute URI with port provides Host" {
    const raw =
        "GET http://example.com:8080/path HTTP/1.1\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("example.com:8080", req.headers.get("Host").?);
}

// RFC 2616 Section 3.7.2: Multipart body parsing
test "Request: parseMultipart simple" {
    const boundary = "----boundary";
    const body =
        "------boundary\r\n" ++
        "Content-Disposition: form-data; name=\"field1\"\r\n" ++
        "\r\n" ++
        "value1\r\n" ++
        "------boundary\r\n" ++
        "Content-Disposition: form-data; name=\"field2\"\r\n" ++
        "\r\n" ++
        "value2\r\n" ++
        "------boundary--\r\n";

    const raw =
        "POST /upload HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Type: multipart/form-data; boundary=" ++ boundary ++ "\r\n" ++
        "Content-Length: " ++ std.fmt.comptimePrint("{d}", .{body.len}) ++ "\r\n" ++
        "\r\n" ++
        body;

    const req = try Request.parseConst(raw);
    var parts: [4]MultipartPart = undefined;
    const count = req.parseMultipart(&parts).?;
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("value1", parts[0].body);
    try testing.expectEqualStrings("value2", parts[1].body);
    try testing.expectEqualStrings("form-data; name=\"field1\"", parts[0].headers.get("Content-Disposition").?);
}

// RFC 2616 Section 3.7.2: Multipart - no Content-Type
test "Request: parseMultipart no content type" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    var parts: [4]MultipartPart = undefined;
    try testing.expect(req.parseMultipart(&parts) == null);
}

// RFC 2616 Section 3.7.2: extractBoundary
test "Request: extractBoundary" {
    try testing.expectEqualStrings("abc", extractBoundary("multipart/form-data; boundary=abc").?);
    try testing.expectEqualStrings("abc", extractBoundary("multipart/form-data; boundary=\"abc\"").?);
    try testing.expect(extractBoundary("text/plain") == null);
}

// /// RFC 2616 Section 5.1: Empty URI is invalid
test "Request: empty URI rejected" {
    const raw =
        "GET  HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";
    try testing.expectError(error.InvalidRequestLine, Request.parseConst(raw));
}

// RFC 2616 Section 14.23: Multiple Host headers MUST be rejected.
test "Request: multiple Host headers rejected" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Host: other.com\r\n" ++
        "\r\n";
    try testing.expectError(error.MultipleHostHeaders, Request.parseConst(raw));
}

// RFC 2616 Section 4.4: Conflicting Content-Length headers rejected.
test "Request: conflicting Content-Length rejected" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 5\r\n" ++
        "Content-Length: 10\r\n" ++
        "\r\n" ++
        "hello";
    try testing.expectError(error.ConflictingContentLength, Request.parseConst(raw));
}

// RFC 2616 Section 4.4: Identical Content-Length headers are accepted.
test "Request: identical Content-Length accepted" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 5\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "hello";
    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("hello", req.body);
}

// RFC 2616 Section 5.2: Absolute URI host takes precedence over Host header.
test "Request: absolute URI host overrides Host header" {
    const raw =
        "GET http://proxy-target.com/path HTTP/1.1\r\n" ++
        "Host: original-host.com\r\n" ++
        "\r\n";
    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("proxy-target.com", req.headers.get("Host").?);
}

// RFC 2616 Section 14.26: If-None-Match with comma-separated ETags.
test "Request: matchesEtag comma-separated list" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-None-Match: \"aaa\", \"bbb\", \"ccc\"\r\n" ++
        "\r\n";
    const req = try Request.parseConst(raw);
    try testing.expect(req.matchesEtag("\"bbb\""));
    try testing.expect(!req.matchesEtag("\"ddd\""));
}

// RFC 2616 Section 3.3.1: isNotModifiedSince accepts RFC 850 format.
test "Request: isNotModifiedSince RFC 850 date" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-Modified-Since: Sunday, 06-Nov-94 08:49:37 GMT\r\n" ++
        "\r\n";
    const req = try Request.parseConst(raw);
    // 784111777 = Sun, 06 Nov 1994 08:49:37 GMT
    try testing.expect(req.isNotModifiedSince(784111777));
    try testing.expect(!req.isNotModifiedSince(784111778));
}

// RFC 2616 Section 3.3.1: isNotModifiedSince accepts asctime format.
test "Request: isNotModifiedSince asctime date" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "If-Modified-Since: Sun Nov  6 08:49:37 1994\r\n" ++
        "\r\n";
    const req = try Request.parseConst(raw);
    try testing.expect(req.isNotModifiedSince(784111777));
}

// --- Path traversal detection ---

// Literal traversal
test "Request: path traversal - literal /../" {
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /foo/../bar HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /foo/bar/.. HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
}

// Percent-encoded traversal
test "Request: path traversal - percent-encoded" {
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /%2e%2e/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /%2E%2E/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /foo/%2e%2e/bar HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
}

// Mixed literal and encoded
test "Request: path traversal - mixed encoding" {
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /%2e./etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /.%2e/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
}

// Double-encoded traversal
test "Request: path traversal - double-encoded" {
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /%252e%252e/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
}

// Backslash traversal
test "Request: path traversal - backslash" {
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /foo\\..\\bar HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
}

// Overlong UTF-8 encoded dot (%c0%ae)
test "Request: path traversal - overlong UTF-8" {
    try testing.expectError(error.UriPathTraversal, Request.parseConst(
        "GET /%c0%ae%c0%ae/etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n",
    ));
}

// Safe paths should be accepted
test "Request: safe paths accepted" {
    _ = try Request.parseConst("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try Request.parseConst("GET /foo/bar HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try Request.parseConst("GET /foo/bar.html HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try Request.parseConst("GET /foo/..bar HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try Request.parseConst("GET /foo/bar..baz HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try Request.parseConst("GET /a/b/c?q=1 HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = try Request.parseConst("GET /a/./b HTTP/1.1\r\nHost: x\r\n\r\n");
}

// CONNECT uses authority-form, no path traversal check
test "Request: CONNECT skips path traversal check" {
    _ = try Request.parseConst("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n");
}

// OPTIONS * skips path traversal check
test "Request: OPTIONS * skips path traversal check" {
    _ = try Request.parseConst("OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n");
}

// containsPathTraversal unit tests
test "Request: containsPathTraversal" {
    try testing.expect(containsPathTraversal("/.."));
    try testing.expect(containsPathTraversal("/../"));
    try testing.expect(containsPathTraversal("/foo/../bar"));
    try testing.expect(containsPathTraversal("\\..\\"));
    try testing.expect(containsPathTraversal("/%2e%2e/"));
    try testing.expect(containsPathTraversal("/%2E%2E/"));
    try testing.expect(containsPathTraversal("/%c0%ae%c0%ae/"));
    try testing.expect(containsPathTraversal("/%252e%252e/"));

    try testing.expect(!containsPathTraversal("/"));
    try testing.expect(!containsPathTraversal("/foo/bar"));
    try testing.expect(!containsPathTraversal("/foo/..bar"));
    try testing.expect(!containsPathTraversal("/foo/bar.."));
    try testing.expect(!containsPathTraversal("/foo/./bar"));
}

// Traversal in query string is ignored (query is not a path)
test "Request: traversal in query string is allowed" {
    _ = try Request.parseConst("GET /foo?bar=/../baz HTTP/1.1\r\nHost: x\r\n\r\n");
}

// 3+ conflicting Content-Length headers detected
test "Request: three conflicting Content-Length headers rejected" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 5\r\n" ++
        "Content-Length: 5\r\n" ++
        "Content-Length: 10\r\n" ++
        "\r\n" ++
        "hello";
    try testing.expectError(error.ConflictingContentLength, Request.parseConst(raw));
}

// 3 identical Content-Length headers are fine
test "Request: three identical Content-Length headers accepted" {
    const raw =
        "POST / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Content-Length: 5\r\n" ++
        "Content-Length: 5\r\n" ++
        "Content-Length: 5\r\n" ++
        "\r\n" ++
        "hello";
    const req = try Request.parseConst(raw);
    try testing.expectEqualStrings("hello", req.body);
}

// RFC 2616 Section 14.23: Host header validation
test "Request: valid Host headers accepted" {
    _ = try Request.parseConst("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    _ = try Request.parseConst("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n");
    _ = try Request.parseConst("GET / HTTP/1.1\r\nHost: sub.domain.example.com\r\n\r\n");
    _ = try Request.parseConst("GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n");
    _ = try Request.parseConst("GET / HTTP/1.1\r\nHost: 192.168.1.1:443\r\n\r\n");
    _ = try Request.parseConst("GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n");
    _ = try Request.parseConst("GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n");
}

test "Request: invalid Host header rejected" {
    // Control characters
    try testing.expectError(error.InvalidHostHeader, Request.parseConst(
        "GET / HTTP/1.1\r\nHost: example\x00.com\r\n\r\n",
    ));
    // Whitespace in host
    try testing.expectError(error.InvalidHostHeader, Request.parseConst(
        "GET / HTTP/1.1\r\nHost: example .com\r\n\r\n",
    ));
    // Path characters
    try testing.expectError(error.InvalidHostHeader, Request.parseConst(
        "GET / HTTP/1.1\r\nHost: example.com/path\r\n\r\n",
    ));
    // Invalid port
    try testing.expectError(error.InvalidHostHeader, Request.parseConst(
        "GET / HTTP/1.1\r\nHost: example.com:abc\r\n\r\n",
    ));
    // At sign
    try testing.expectError(error.InvalidHostHeader, Request.parseConst(
        "GET / HTTP/1.1\r\nHost: user@example.com\r\n\r\n",
    ));
}

// RFC 2616 Section 14.35: Multi-range parsing
test "Request: parseRanges multi-range" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=0-499,500-999\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    var ranges: [8]ByteRange = undefined;
    const count = req.parseRanges(1000, &ranges).?;
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqual(@as(usize, 0), ranges[0].start.?);
    try testing.expectEqual(@as(usize, 499), ranges[0].end.?);
    try testing.expectEqual(@as(usize, 500), ranges[1].start.?);
    try testing.expectEqual(@as(usize, 999), ranges[1].end.?);
}

test "Request: parseRanges single range" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=0-99\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    var ranges: [8]ByteRange = undefined;
    const count = req.parseRanges(1000, &ranges).?;
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(@as(usize, 0), ranges[0].start.?);
    try testing.expectEqual(@as(usize, 99), ranges[0].end.?);
}

test "Request: parseRanges suffix range" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Range: bytes=-100\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    var ranges: [8]ByteRange = undefined;
    const count = req.parseRanges(1000, &ranges).?;
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(@as(usize, 900), ranges[0].start.?);
    try testing.expectEqual(@as(usize, 999), ranges[0].end.?);
}

test "Request: parseRanges no header" {
    const raw =
        "GET / HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "\r\n";

    const req = try Request.parseConst(raw);
    var ranges: [8]ByteRange = undefined;
    try testing.expect(req.parseRanges(1000, &ranges) == null);
}
