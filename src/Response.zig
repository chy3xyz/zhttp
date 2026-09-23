const Response = @This();
const std = @import("std");
const Headers = @import("Headers.zig");

/// RFC 2616 Section 6: Response
///
/// Response = Status-Line
///            *(( general-header | response-header | entity-header ) CRLF)
///            CRLF
///            [ message-body ]
/// RFC 2616 Section 6.1.1: Status Code and Reason Phrase
pub const StatusCode = enum(u16) {
    // 1xx Informational (RFC 2616 Section 10.1)
    @"continue" = 100,
    switching_protocols = 101,

    // 2xx Success (RFC 2616 Section 10.2)
    ok = 200,
    created = 201,
    accepted = 202,
    non_authoritative_information = 203,
    no_content = 204,
    reset_content = 205,
    partial_content = 206,

    // 3xx Redirection (RFC 2616 Section 10.3)
    multiple_choices = 300,
    moved_permanently = 301,
    found = 302,
    see_other = 303,
    not_modified = 304,
    use_proxy = 305,
    temporary_redirect = 307,

    // 4xx Client Error (RFC 2616 Section 10.4)
    bad_request = 400,
    unauthorized = 401,
    payment_required = 402,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    not_acceptable = 406,
    proxy_authentication_required = 407,
    request_timeout = 408,
    conflict = 409,
    gone = 410,
    length_required = 411,
    precondition_failed = 412,
    request_entity_too_large = 413,
    request_uri_too_long = 414,
    unsupported_media_type = 415,
    requested_range_not_satisfiable = 416,
    expectation_failed = 417,
    too_many_requests = 429,

    // 5xx Server Error (RFC 2616 Section 10.5)
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,
    http_version_not_supported = 505,

    pub fn reason(self: StatusCode) []const u8 {
        return switch (self) {
            .@"continue" => "Continue",
            .switching_protocols => "Switching Protocols",
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .non_authoritative_information => "Non-Authoritative Information",
            .no_content => "No Content",
            .reset_content => "Reset Content",
            .partial_content => "Partial Content",
            .multiple_choices => "Multiple Choices",
            .moved_permanently => "Moved Permanently",
            .found => "Found",
            .see_other => "See Other",
            .not_modified => "Not Modified",
            .use_proxy => "Use Proxy",
            .temporary_redirect => "Temporary Redirect",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .payment_required => "Payment Required",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .not_acceptable => "Not Acceptable",
            .proxy_authentication_required => "Proxy Authentication Required",
            .request_timeout => "Request Timeout",
            .conflict => "Conflict",
            .gone => "Gone",
            .length_required => "Length Required",
            .precondition_failed => "Precondition Failed",
            .request_entity_too_large => "Request Entity Too Large",
            .request_uri_too_long => "Request-URI Too Long",
            .unsupported_media_type => "Unsupported Media Type",
            .requested_range_not_satisfiable => "Requested Range Not Satisfiable",
            .expectation_failed => "Expectation Failed",
            .too_many_requests => "Too Many Requests",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
            .http_version_not_supported => "HTTP Version Not Supported",
        };
    }

    pub fn toInt(self: StatusCode) u16 {
        return @backingInt(self);
    }
};

status: StatusCode = .ok,
headers: Headers = .{},
body: []const u8 = "",
/// Internal: if non-null, the body was dynamically allocated and should be freed
_body_allocated: ?[]u8 = null,
/// Internal: backing buffer for TLS responses (headers point into this).
_tls_buf: ?struct { ptr: [*]u8, len: usize, allocator: std.mem.Allocator } = null,
version: @import("Request.zig").Version = .http_1_1,
/// When true, serialize() will auto-generate a Content-Length header.
auto_content_length: bool = true,
/// RFC 2616 Section 9.4: When true, serialize headers (including Content-Length)
/// but strip the message body. Used for HEAD responses.
strip_body: bool = false,
/// RFC 2616 Section 3.6.1: When true, send body using chunked transfer encoding
/// instead of Content-Length.
chunked: bool = false,
/// Per-route WebSocket handler, set by Router dispatch. When present,
/// the server uses this instead of the global websocket_handler config.
ws_handler: ?@import("server/WebSocket.zig").Handler = null,
/// Optional streaming callback. When set, the server serializes headers only,
/// then calls this function with the network writer for streaming the body.
/// The function writes directly to the wire. Void return matches the WebSocket
/// handler precedent — errors mean "connection lost" and the server closes
/// the connection regardless.
stream_fn: ?*const fn (?*anyopaque, *std.Io.Writer) void = null,
/// Optional opaque context pointer passed to stream_fn. Zig has no closures,
/// so this lets handlers pass state (file handles, etc.) to their stream function.
stream_context: ?*anyopaque = null,
/// HTTP/2 trailer headers. When set, these are sent as a trailing HEADERS
/// frame with END_STREAM after the response body DATA frames.
/// In HTTP/1.1 chunked encoding, trailers are appended after the final chunk.
trailers: ?Headers = null,

/// HTTP/2 server push promises. Each entry is a path that the server
/// will proactively push to the client. Only used in HTTP/2 connections
/// when the client has not disabled push (SETTINGS_ENABLE_PUSH=1).
/// Maximum 4 push promises per response.
push_paths: [4]?[]const u8 = .{ null, null, null, null },
push_count: u8 = 0,

/// Embedded buffer for server-generated header values (Date, Via).
/// Avoids threadlocal storage so header value slices have a well-defined
/// lifetime tied to the Response itself.
server_header_buf: [max_server_header_buf]u8 = undefined,
server_header_buf_len: usize = 0,

/// 29 bytes for Date + 256 bytes for Via = 285, round up
const max_server_header_buf = 300;

/// Add an HTTP/2 server push promise path.
pub fn addPush(self: *Response, path: []const u8) void {
    if (self.push_count < 4) {
        self.push_paths[self.push_count] = path;
        self.push_count += 1;
    }
}

/// Allocate space in the embedded buffer and return a slice.
/// Returns null if the buffer is full.
pub fn allocServerBuf(self: *Response, len: usize) ?[]u8 {
    if (self.server_header_buf_len + len > max_server_header_buf) return null;
    const start = self.server_header_buf_len;
    self.server_header_buf_len += len;
    return self.server_header_buf[start..][0..len];
}

/// Maximum size for serialized response headers (status line + headers + CRLF).
/// Body is written separately to the network writer, so this only needs to
/// cover the header section.
pub const max_response_header_len = 65536;

pub const SerializeError = error{
    ResponseTooLarge,
};

/// Serialize only the response headers (status line + headers + terminating CRLF).
/// Used by the streaming path — body is written separately via stream_fn.
/// Also used internally by serialize().
pub fn serializeHeaders(self: *const Response, buf: []u8) SerializeError![]const u8 {
    var pos: usize = 0;

    // Status-Line
    pos = appendSlice(buf, pos, self.version.toBytes()) orelse return error.ResponseTooLarge;
    pos = appendSlice(buf, pos, " ") orelse return error.ResponseTooLarge;
    pos = appendInt(buf, pos, self.status.toInt()) orelse return error.ResponseTooLarge;
    pos = appendSlice(buf, pos, " ") orelse return error.ResponseTooLarge;
    pos = appendSlice(buf, pos, self.status.reason()) orelse return error.ResponseTooLarge;
    pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;

    // Headers
    for (self.headers.entries[0..self.headers.len]) |entry| {
        pos = appendSlice(buf, pos, entry.name) orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, ": ") orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, entry.value) orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;
    }

    // RFC 2616 Section 3.6.1: Chunked transfer encoding
    if (self.chunked and self.headers.get("Transfer-Encoding") == null) {
        pos = appendSlice(buf, pos, "Transfer-Encoding: chunked\r\n") orelse return error.ResponseTooLarge;
    } else if (self.auto_content_length and
        self.headers.get("Content-Length") == null and
        self.headers.get("Transfer-Encoding") == null)
    {
        // Auto-generate Content-Length if needed
        var cl_buf: [20]u8 = undefined;
        const cl_str = formatUsize(self.body.len, &cl_buf);
        pos = appendSlice(buf, pos, "Content-Length: ") orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, cl_str) orelse return error.ResponseTooLarge;
        pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;
    }

    // End of headers
    pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;

    return buf[0..pos];
}

/// Serialize the response into a buffer.
///
/// RFC 2616 Section 6: The response format is:
///   Status-Line CRLF
///   *(header-field CRLF)
///   CRLF
///   [message-body]
///
/// RFC 2616 Section 6.1:
///   Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
pub fn serialize(self: *const Response, buf: []u8) SerializeError![]const u8 {
    const header_data = try self.serializeHeaders(buf);
    var pos: usize = header_data.len;

    // RFC 2616 Section 9.4: HEAD responses MUST NOT include a body
    if (!self.strip_body) {
        if (self.chunked and self.body.len > 0) {
            // RFC 2616 Section 3.6.1: Encode body as a single chunk
            var chunk_size_buf: [20]u8 = undefined;
            const chunk_size_str = formatHex(self.body.len, &chunk_size_buf);
            pos = appendSlice(buf, pos, chunk_size_str) orelse return error.ResponseTooLarge;
            pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;
            pos = appendSlice(buf, pos, self.body) orelse return error.ResponseTooLarge;
            pos = appendSlice(buf, pos, "\r\n") orelse return error.ResponseTooLarge;
            // Last-chunk
            pos = appendSlice(buf, pos, "0\r\n\r\n") orelse return error.ResponseTooLarge;
        } else if (self.chunked) {
            // Empty chunked body
            pos = appendSlice(buf, pos, "0\r\n\r\n") orelse return error.ResponseTooLarge;
        } else {
            pos = appendSlice(buf, pos, self.body) orelse return error.ResponseTooLarge;
        }
    }

    return buf[0..pos];
}

fn appendSlice(buf: []u8, pos: usize, data: []const u8) ?usize {
    if (pos + data.len > buf.len) return null;
    @memcpy(buf[pos..][0..data.len], data);
    return pos + data.len;
}

fn formatUsize(value: usize, buf: *[20]u8) []const u8 {
    var v = value;
    var i: usize = 20;
    if (v == 0) {
        buf[19] = '0';
        return buf[19..20];
    }
    while (v > 0) {
        i -= 1;
        buf[i] = @intCast(v % 10 + '0');
        v /= 10;
    }
    return buf[i..20];
}

fn formatHex(value: usize, buf: *[20]u8) []const u8 {
    const hex_chars = "0123456789abcdef";
    var v = value;
    var i: usize = 20;
    if (v == 0) {
        buf[19] = '0';
        return buf[19..20];
    }
    while (v > 0) {
        i -= 1;
        buf[i] = hex_chars[v & 0xf];
        v >>= 4;
    }
    return buf[i..20];
}

fn appendInt(buf: []u8, pos: usize, value: u16) ?usize {
    var tmp: [5]u8 = undefined;
    const len = formatInt(value, &tmp);
    return appendSlice(buf, pos, tmp[0..len]);
}

fn formatInt(value: u16, buf: *[5]u8) usize {
    var v = value;
    var i: usize = 5;
    if (v == 0) {
        buf[0] = '0';
        return 1;
    }
    while (v > 0) {
        i -= 1;
        buf[i] = @intCast(v % 10 + '0');
        v /= 10;
    }
    const len = 5 - i;
    if (i > 0) {
        std.mem.copyForwards(u8, buf[0..len], buf[i..5]);
    }
    return len;
}

/// RFC 2616 Section 10.3: Create a redirect response.
/// 301 Moved Permanently, 302 Found, 307 Temporary Redirect.
/// The Location header is REQUIRED for redirect responses (§14.30).
pub fn redirect(status: StatusCode, location: []const u8) Response {
    var resp: Response = .{
        .status = status,
        .body = status.reason(),
    };
    resp.headers.append("Location", location) catch {};
    resp.headers.append("Content-Type", "text/plain") catch {};
    return resp;
}

/// RFC 2616 Section 14.47: Return a 401 Unauthorized response requiring Basic Auth.
pub fn requireBasicAuth(realm: []const u8) Response {
    var resp = Response.init(.unauthorized, "text/plain", "401 Unauthorized\n");
    var realm_buf: [256]u8 = undefined;
    const realm_hdr = std.fmt.bufPrint(&realm_buf, "Basic realm=\"{s}\"", .{realm}) catch "Basic";
    resp.headers.append("WWW-Authenticate", realm_hdr) catch {};
    return resp;
}

/// Create a simple response with status, content-type, and body.
pub fn init(status: StatusCode, content_type: []const u8, body: []const u8) Response {
    var resp: Response = .{
        .status = status,
        .body = body,
    };
    resp.headers.append("Content-Type", content_type) catch unreachable;
    // We format Content-Length inline in serialize for dynamic responses
    return resp;
}

/// Serialize a Zig value into JSON and create a Response with Content-Type application/json.
pub fn json(allocator: std.mem.Allocator, value: anytype, status: StatusCode) !Response {
    const stringified = try std.json.Stringify.valueAlloc(allocator, value, .{});
    var resp = Response.init(status, "application/json", stringified);
    resp._body_allocated = stringified;
    return resp;
}

/// Free any allocated body memory.
pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
    if (self._body_allocated) |allocated| {
        allocator.free(allocated);
        self.body = "";
        self._body_allocated = null;
    }
    if (self._tls_buf) |tls_buf| {
        tls_buf.allocator.free(tls_buf.ptr[0..tls_buf.len]);
        self._tls_buf = null;
    }
}

/// Context for the sendFile stream function.
const SendFileContext = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    file: std.Io.File,
    reader: std.Io.File.Reader,
    read_buf: [read_buf_len]u8 = undefined,

    const read_buf_len = 16 * 1024;

    fn streamFn(ctx_ptr: ?*anyopaque, writer: *std.Io.Writer) void {
        const self: *SendFileContext = @ptrCast(@alignCast(ctx_ptr));
        defer {
            self.file.close(self.io);
            self.allocator.destroy(self);
        }
        _ = writer.sendFileAll(&self.reader, .unlimited) catch return;
    }
};

/// Create a streaming response that serves a file from disk.
/// Uses the writer's native sendFile support (may use zero-copy on Linux).
/// The file is opened at call time, streamed when the server calls stream_fn.
/// The stream context is allocated with `allocator` and released when the file
/// has been streamed (or closed early by the server).
///
/// WARNING: This follows symlinks. Callers must validate that the path
/// is within an expected directory to prevent path traversal attacks.
///
/// `max_file_size`: maximum allowed file size in bytes. Pass 0 for unlimited.
/// Returns 413 Request Entity Too Large if the file exceeds the limit.
pub fn sendFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8, content_type: []const u8, max_file_size: usize) Response {
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch {
        return Response.init(.not_found, "text/plain", "Not Found");
    };

    const stat = file.stat(io) catch {
        file.close(io);
        return Response.init(.internal_server_error, "text/plain", "Internal Server Error");
    };

    if (max_file_size > 0 and stat.size > max_file_size) {
        file.close(io);
        return Response.init(.request_entity_too_large, "text/plain", "Request Entity Too Large");
    }

    const ctx = allocator.create(SendFileContext) catch {
        file.close(io);
        return Response.init(.internal_server_error, "text/plain", "Internal Server Error");
    };
    ctx.io = io;
    ctx.allocator = allocator;
    ctx.file = file;
    ctx.reader = file.reader(io, &ctx.read_buf);

    var resp: Response = .{ .status = .ok };
    resp.headers.append("Content-Type", content_type) catch {};

    // Set Content-Length from file size — no chunked encoding needed
    var cl_buf_storage: [20]u8 = undefined;
    const cl_str = formatUsize(stat.size, &cl_buf_storage);
    if (resp.allocServerBuf(cl_str.len)) |buf| {
        @memcpy(buf, cl_str);
        resp.headers.append("Content-Length", buf) catch {};
    }
    resp.auto_content_length = false;

    resp.stream_fn = SendFileContext.streamFn;
    resp.stream_context = @ptrCast(ctx);
    return resp;
}

const ByteRange = @import("Request.zig").ByteRange;

/// RFC 2616 Section 10.2.7: Build a 206 Partial Content response for a single range.
/// Sets status 206 and adds Content-Range header.
pub fn partialContent(body: []const u8, range: ByteRange, total: usize, content_type: []const u8) Response {
    var resp: Response = .{
        .status = .partial_content,
    };
    resp.headers.append("Content-Type", content_type) catch {};
    const start = range.start orelse 0;
    const end = range.end orelse (total - 1);
    resp.body = body[start .. end + 1];
    // Content-Range is stored via server_header_buf to keep stable lifetime
    const cr = formatContentRange(start, end, total, resp.allocServerBuf(content_range_max_len).?);
    resp.headers.append("Content-Range", cr) catch {};
    return resp;
}

/// RFC 2616 Section 10.4.17: Build a 416 Range Not Satisfiable response.
pub fn rangeNotSatisfiable(total_size: usize) Response {
    var resp: Response = .{
        .status = .requested_range_not_satisfiable,
    };
    const cr = formatContentRangeStar(total_size, resp.allocServerBuf(content_range_max_len).?);
    resp.headers.append("Content-Range", cr) catch {};
    return resp;
}

/// RFC 2616 Section 14.16: Format "bytes start-end/total".
const content_range_max_len = 6 + 20 + 1 + 20 + 1 + 20; // "bytes " + start + "-" + end + "/" + total
fn formatContentRange(start: usize, end: usize, total: usize, buf: []u8) []const u8 {
    var pos: usize = 0;
    const prefix = "bytes ";
    @memcpy(buf[pos..][0..prefix.len], prefix);
    pos += prefix.len;
    pos += writeUsize(buf[pos..], start);
    buf[pos] = '-';
    pos += 1;
    pos += writeUsize(buf[pos..], end);
    buf[pos] = '/';
    pos += 1;
    pos += writeUsize(buf[pos..], total);
    return buf[0..pos];
}

fn formatContentRangeStar(total: usize, buf: []u8) []const u8 {
    var pos: usize = 0;
    const prefix = "bytes */";
    @memcpy(buf[pos..][0..prefix.len], prefix);
    pos += prefix.len;
    pos += writeUsize(buf[pos..], total);
    return buf[0..pos];
}

fn writeUsize(buf: []u8, value: usize) usize {
    var tmp: [20]u8 = undefined;
    const s = formatUsize(value, &tmp);
    @memcpy(buf[0..s.len], s);
    return s.len;
}

/// Build a multipart/byteranges response for multiple ranges.
/// The caller provides a scratch buffer `buf` for assembling the multipart body.
pub fn multipartByteRanges(
    content: []const u8,
    content_type: []const u8,
    ranges: []const ByteRange,
    total: usize,
    buf: []u8,
) !Response {
    const boundary = "httpz_range_boundary";
    var pos: usize = 0;

    for (ranges) |range| {
        const start = range.start orelse 0;
        const end = range.end orelse (total - 1);
        const part_data = content[start .. end + 1];

        // --boundary\r\n
        pos = appendTo(buf, pos, "--") orelse return error.ResponseTooLarge;
        pos = appendTo(buf, pos, boundary) orelse return error.ResponseTooLarge;
        pos = appendTo(buf, pos, "\r\n") orelse return error.ResponseTooLarge;

        // Content-Type: ...\r\n
        pos = appendTo(buf, pos, "Content-Type: ") orelse return error.ResponseTooLarge;
        pos = appendTo(buf, pos, content_type) orelse return error.ResponseTooLarge;
        pos = appendTo(buf, pos, "\r\n") orelse return error.ResponseTooLarge;

        // Content-Range: bytes start-end/total\r\n
        pos = appendTo(buf, pos, "Content-Range: ") orelse return error.ResponseTooLarge;
        var cr_buf: [content_range_max_len]u8 = undefined;
        const cr = formatContentRange(start, end, total, &cr_buf);
        pos = appendTo(buf, pos, cr) orelse return error.ResponseTooLarge;
        pos = appendTo(buf, pos, "\r\n") orelse return error.ResponseTooLarge;

        // \r\n + body data
        pos = appendTo(buf, pos, "\r\n") orelse return error.ResponseTooLarge;
        pos = appendTo(buf, pos, part_data) orelse return error.ResponseTooLarge;
        pos = appendTo(buf, pos, "\r\n") orelse return error.ResponseTooLarge;
    }

    // Closing boundary: --boundary--\r\n
    pos = appendTo(buf, pos, "--") orelse return error.ResponseTooLarge;
    pos = appendTo(buf, pos, boundary) orelse return error.ResponseTooLarge;
    pos = appendTo(buf, pos, "--\r\n") orelse return error.ResponseTooLarge;

    var resp: Response = .{
        .status = .partial_content,
        .body = buf[0..pos],
    };
    resp.headers.append("Content-Type", "multipart/byteranges; boundary=" ++ boundary) catch {};
    return resp;
}

fn appendTo(buf: []u8, pos: usize, data: []const u8) ?usize {
    if (pos + data.len > buf.len) return null;
    @memcpy(buf[pos..][0..data.len], data);
    return pos + data.len;
}

// --- Tests ---

const testing = std.testing;

// /// RFC 2616 Section 6.1.1: Status codes and reason phrases
test "Response.StatusCode: reason phrases" {
    try testing.expectEqualStrings("OK", StatusCode.ok.reason());
    try testing.expectEqualStrings("Not Found", StatusCode.not_found.reason());
    try testing.expectEqualStrings("Internal Server Error", StatusCode.internal_server_error.reason());
    try testing.expectEqualStrings("Bad Request", StatusCode.bad_request.reason());
    try testing.expectEqualStrings("Continue", StatusCode.@"continue".reason());
    try testing.expectEqualStrings("Method Not Allowed", StatusCode.method_not_allowed.reason());
}

// /// RFC 2616 Section 6.1.1: Status code integer values
test "Response.StatusCode: toInt" {
    try testing.expectEqual(@as(u16, 200), StatusCode.ok.toInt());
    try testing.expectEqual(@as(u16, 404), StatusCode.not_found.toInt());
    try testing.expectEqual(@as(u16, 500), StatusCode.internal_server_error.toInt());
    try testing.expectEqual(@as(u16, 100), StatusCode.@"continue".toInt());
    try testing.expectEqual(@as(u16, 301), StatusCode.moved_permanently.toInt());
}

// /// RFC 2616 Section 6: Serialize a simple 200 OK response
test "Response: serialize simple 200 OK" {
    var resp: Response = .{
        .status = .ok,
    };
    try resp.headers.append("Content-Type", "text/plain");
    resp.body = "Hello";

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n" ++
            "Hello",
        result,
    );
}

// /// RFC 2616 Section 6: Serialize a 404 Not Found response
test "Response: serialize 404 Not Found" {
    var resp: Response = .{
        .status = .not_found,
        .body = "Not Found",
    };
    try resp.headers.append("Content-Type", "text/plain");

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 404 Not Found\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: 9\r\n" ++
            "\r\n" ++
            "Not Found",
        result,
    );
}

// /// RFC 2616 Section 6: Serialize response with no body
test "Response: serialize no body" {
    const resp: Response = .{
        .status = .no_content,
    };

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 204 No Content\r\n" ++
            "Content-Length: 0\r\n" ++
            "\r\n",
        result,
    );
}

// /// RFC 2616 Section 6: Serialize response with multiple headers
test "Response: serialize multiple headers" {
    var resp: Response = .{
        .status = .ok,
        .body = "test",
    };
    try resp.headers.append("Content-Type", "text/html");
    try resp.headers.append("X-Custom", "value");
    try resp.headers.append("Cache-Control", "no-cache");

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/html\r\n" ++
            "X-Custom: value\r\n" ++
            "Cache-Control: no-cache\r\n" ++
            "Content-Length: 4\r\n" ++
            "\r\n" ++
            "test",
        result,
    );
}

// /// RFC 2616 Section 6: Buffer too small
test "Response: serialize buffer too small" {
    var resp: Response = .{
        .status = .ok,
    };
    try resp.headers.append("Content-Type", "text/plain");
    resp.body = "Hello";

    var buf: [10]u8 = undefined;
    try testing.expectError(error.ResponseTooLarge, resp.serialize(&buf));
}

// /// RFC 2616 Section 6: HTTP/1.0 response version
test "Response: serialize HTTP/1.0 response" {
    const resp: Response = .{
        .status = .ok,
        .version = .http_1_0,
        .body = "",
    };

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.0 200 OK\r\n" ++
            "Content-Length: 0\r\n" ++
            "\r\n",
        result,
    );
}

// /// RFC 2616 Section 6.1.1: All status code families
test "Response: status codes from all families" {
    const codes: []const StatusCode = &.{
        .@"continue", .ok,                    .moved_permanently,
        .bad_request, .internal_server_error,
    };
    for (codes) |code| {
        const resp: Response = .{ .status = code };
        var buf: [1024]u8 = undefined;
        _ = try resp.serialize(&buf);
    }
}

// /// RFC 2616 Section 6: init helper
test "Response: init helper" {
    const resp = Response.init(.ok, "text/plain", "Hello");
    try testing.expectEqual(StatusCode.ok, resp.status);
    try testing.expectEqualStrings("Hello", resp.body);
    try testing.expectEqualStrings("text/plain", resp.headers.get("Content-Type").?);
}

// RFC 2616 Section 9.4: HEAD response includes Content-Length but no body
test "Response: serialize with strip_body" {
    var resp: Response = .{
        .status = .ok,
        .body = "Hello",
        .strip_body = true,
    };
    try resp.headers.append("Content-Type", "text/plain");

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n",
        result,
    );
}

// RFC 2616 Section 10.3: Redirect response with Location header
test "Response: redirect" {
    const resp = Response.redirect(.moved_permanently, "/new-location");
    try testing.expectEqual(StatusCode.moved_permanently, resp.status);
    try testing.expectEqualStrings("/new-location", resp.headers.get("Location").?);
    try testing.expectEqualStrings("Moved Permanently", resp.body);

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expect(std.mem.indexOf(u8, result, "Location: /new-location\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, result, "301 Moved Permanently") != null);
}

// RFC 2616 Section 10.3: Temporary redirect
test "Response: temporary redirect" {
    const resp = Response.redirect(.temporary_redirect, "https://example.com/");
    try testing.expectEqual(StatusCode.temporary_redirect, resp.status);
    try testing.expectEqualStrings("https://example.com/", resp.headers.get("Location").?);
}

// RFC 2616 Section 3.6.1: Chunked transfer encoding response
test "Response: serialize chunked response" {
    var resp: Response = .{
        .status = .ok,
        .body = "Hello",
        .chunked = true,
    };
    try resp.headers.append("Content-Type", "text/plain");

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "5\r\n" ++
            "Hello\r\n" ++
            "0\r\n" ++
            "\r\n",
        result,
    );
}

// RFC 2616 Section 3.6.1: Empty chunked response
test "Response: serialize empty chunked response" {
    const resp: Response = .{
        .status = .ok,
        .chunked = true,
    };

    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "0\r\n" ++
            "\r\n",
        result,
    );
}

// formatHex utility
test "Response: formatHex" {
    var buf: [20]u8 = undefined;

    try testing.expectEqualStrings("0", formatHex(0, &buf));
    try testing.expectEqualStrings("5", formatHex(5, &buf));
    try testing.expectEqualStrings("a", formatHex(10, &buf));
    try testing.expectEqualStrings("ff", formatHex(255, &buf));
    try testing.expectEqualStrings("100", formatHex(256, &buf));
}

// RFC 2616 Section 14.13: Content-Length: 0 for empty body responses.
test "Response: serialize empty body includes Content-Length 0" {
    const resp: Response = .{
        .status = .ok,
    };
    var buf: [1024]u8 = undefined;
    const result = try resp.serialize(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Length: 0\r\n" ++
            "\r\n",
        result,
    );
}

// Server header embedded buffer
test "Response: allocServerBuf" {
    var resp: Response = .{};
    const buf1 = resp.allocServerBuf(29).?;
    try testing.expectEqual(@as(usize, 29), buf1.len);
    try testing.expectEqual(@as(usize, 29), resp.server_header_buf_len);

    const buf2 = resp.allocServerBuf(100).?;
    try testing.expectEqual(@as(usize, 100), buf2.len);
    try testing.expectEqual(@as(usize, 129), resp.server_header_buf_len);

    // Filling up should return null
    try testing.expect(resp.allocServerBuf(max_server_header_buf) == null);
}

// /// formatInt utility
test "Response: formatInt" {
    var buf: [5]u8 = undefined;

    var len = formatInt(0, &buf);
    try testing.expectEqualStrings("0", buf[0..len]);

    len = formatInt(200, &buf);
    try testing.expectEqualStrings("200", buf[0..len]);

    len = formatInt(404, &buf);
    try testing.expectEqualStrings("404", buf[0..len]);

    len = formatInt(65535, &buf);
    try testing.expectEqualStrings("65535", buf[0..len]);
}

// RFC 2616 Section 10.2.7: partialContent builds 206 with Content-Range
test "Response: partialContent" {
    const body = "Hello, World!";
    const resp = Response.partialContent(body, .{ .start = 0, .end = 4 }, 13, "text/plain");
    try testing.expectEqual(StatusCode.partial_content, resp.status);
    try testing.expectEqualStrings("Hello", resp.body);
    const cr = resp.headers.get("Content-Range").?;
    try testing.expect(std.mem.startsWith(u8, cr, "bytes 0-4/13"));
}

// RFC 2616 Section 10.4.17: rangeNotSatisfiable returns 416
test "Response: rangeNotSatisfiable" {
    const resp = Response.rangeNotSatisfiable(1000);
    try testing.expectEqual(StatusCode.requested_range_not_satisfiable, resp.status);
    const cr = resp.headers.get("Content-Range").?;
    try testing.expect(std.mem.startsWith(u8, cr, "bytes */1000"));
}

// Multipart byte ranges
test "Response: multipartByteRanges" {
    const content = "Hello, World!";
    const ranges = [_]ByteRange{
        .{ .start = 0, .end = 4 },
        .{ .start = 7, .end = 11 },
    };
    var buf: [4096]u8 = undefined;
    const resp = try Response.multipartByteRanges(content, "text/plain", &ranges, 13, &buf);
    try testing.expectEqual(StatusCode.partial_content, resp.status);
    // Content-Type should be multipart/byteranges
    const ct = resp.headers.get("Content-Type").?;
    try testing.expect(std.mem.startsWith(u8, ct, "multipart/byteranges"));
    // Body should contain both parts
    try testing.expect(std.mem.indexOf(u8, resp.body, "Hello") != null);
    try testing.expect(std.mem.indexOf(u8, resp.body, "World") != null);
}

// serializeHeaders returns only status line + headers + CRLF
test "Response: serializeHeaders" {
    var resp: Response = .{
        .status = .ok,
        .body = "Hello",
    };
    try resp.headers.append("Content-Type", "text/plain");

    var buf: [1024]u8 = undefined;
    const result = try resp.serializeHeaders(&buf);
    try testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n",
        result,
    );
    // Body should NOT be included
    try testing.expect(std.mem.indexOf(u8, result, "Hello") == null);
}

// Streaming fields default to null
test "Response: streaming fields default to null" {
    const resp: Response = .{};
    try testing.expect(resp.stream_fn == null);
    try testing.expect(resp.stream_context == null);
}

// serializeHeaders with chunked transfer encoding
test "Response: serializeHeaders with chunked" {
    const resp: Response = .{
        .status = .ok,
        .chunked = true,
    };
    var buf: [1024]u8 = undefined;
    const result = try resp.serializeHeaders(&buf);
    try testing.expect(std.mem.indexOf(u8, result, "Transfer-Encoding: chunked\r\n") != null);
    // Should end with \r\n (no body/chunk data)
    try testing.expect(std.mem.endsWith(u8, result, "\r\n\r\n"));
}

// The JSON body is allocated with the caller's allocator and released by deinit
test "Response: json helper" {
    var resp = try Response.json(testing.allocator, .{ .ok = true, .count = 3 }, .created);
    defer resp.deinit(testing.allocator);

    try testing.expectEqual(StatusCode.created, resp.status);
    try testing.expectEqualStrings("application/json", resp.headers.get("Content-Type").?);
    try testing.expectEqualStrings("{\"ok\":true,\"count\":3}", resp.body);

    var buf: [256]u8 = undefined;
    const wire = try resp.serialize(&buf);
    try testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 201 Created\r\n"));
    try testing.expect(std.mem.endsWith(u8, wire, "{\"ok\":true,\"count\":3}"));
}

// sendFile opens the file, reports its size, and streams it through stream_fn
test "Response: sendFile streams file contents" {
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const contents = "hello from sendFile";
    try tmp.dir.writeFile(io, .{ .sub_path = "index.html", .data = contents });

    const abs_path = try tmp.dir.realPathFileAlloc(io, "index.html", testing.allocator);
    defer testing.allocator.free(abs_path);

    var resp = Response.sendFile(testing.allocator, io, abs_path, "text/html", 0);
    try testing.expectEqual(StatusCode.ok, resp.status);
    try testing.expectEqualStrings("text/html", resp.headers.get("Content-Type").?);
    try testing.expectEqualStrings("19", resp.headers.get("Content-Length").?);
    try testing.expect(!resp.auto_content_length);
    const stream_fn = resp.stream_fn orelse return error.MissingStreamFn;

    // Drive the streaming path the server uses. It also releases the context.
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try out.ensureUnusedCapacity(1);
    stream_fn(resp.stream_context, &out.writer);
    try testing.expectEqualStrings(contents, out.writer.buffered());

    // Missing file
    const missing = Response.sendFile(testing.allocator, io, "/zhttp-no-such-file", "text/plain", 0);
    try testing.expectEqual(StatusCode.not_found, missing.status);
    try testing.expectEqualStrings("Not Found", missing.body);

    // File larger than the limit
    const too_big = Response.sendFile(testing.allocator, io, abs_path, "text/plain", contents.len - 1);
    try testing.expectEqual(StatusCode.request_entity_too_large, too_big.status);
    try testing.expectEqualStrings("Request Entity Too Large", too_big.body);
}
