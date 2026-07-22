const Client = @This();
const std = @import("std");
const Io = std.Io;
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Headers = @import("../Headers.zig");
const tls = @import("../openssl.zig");
const H2Client = @import("H2Client.zig");

/// RFC 2616: HTTP/1.1 Client implementation.
///
/// This client uses the Zig 0.16 std.Io interface for networking,
/// supporting both threaded and evented I/O backends.
/// TLS support is provided by OpenSSL.
pub const Config = struct {
    host: []const u8,
    port: u16 = 80,
    read_buffer_size: usize = 8192,
    write_buffer_size: usize = 8192,
    connection_timeout_s: u32 = 30,
    read_timeout_s: u32 = 60,
    /// Maximum response body size in bytes (default 10 MB). Responses with
    /// Content-Length exceeding this are rejected with error.ResponseTooLarge.
    max_response_size: usize = 10 * 1024 * 1024,
    /// TLS configuration - if provided, HTTPS will be used
    tls_config: ?tls.config.Client = null,
    /// Use HTTP/2 with prior knowledge (h2c) over cleartext TCP.
    /// When true, the client sends the HTTP/2 connection preface
    /// immediately without TLS or Upgrade negotiation.
    h2_prior_knowledge: bool = false,
};

pub const Url = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    path: []const u8,

    pub fn parse(url_str: []const u8) ?Url {
        const scheme_end = std.mem.indexOf(u8, url_str, "://") orelse return null;
        const scheme = url_str[0..scheme_end];
        const after_scheme = url_str[scheme_end + 3 ..];

        const has_scheme = (scheme.len == 4 and std.mem.eql(u8, scheme, "http")) or
            (scheme.len == 5 and std.mem.eql(u8, scheme, "https"));

        const default_port: u16 = if (has_scheme and scheme[scheme.len - 1] == 's') 443 else 80;

        const path_start = std.mem.indexOfScalar(u8, after_scheme, '/') orelse after_scheme.len;
        const host_port = after_scheme[0..path_start];
        const path = if (path_start < after_scheme.len) after_scheme[path_start..] else "/";

        const port_end = std.mem.indexOfScalar(u8, host_port, ':');
        const host = if (port_end) |pe| host_port[0..pe] else host_port;
        const port = if (port_end) |pe|
            std.fmt.parseInt(u16, host_port[pe + 1 ..], 10) catch default_port
        else
            default_port;

        return .{
            .scheme = scheme,
            .host = host,
            .port = port,
            .path = path,
        };
    }
};

const ClientError = error{
    ConnectionFailed,
    SendFailed,
    ResponseTooLarge,
    InvalidResponse,
    ReadTimeout,
    WriteFailed,
    TlsCertificateExpired,
    TlsCertificateRevoked,
    TlsCertificateUnknown,
    TlsUnsupportedCertificate,
    TlsCertificateRequired,
    TlsHandshakeFailure,
    TlsAlert,
    TlsUnexpectedMessage,
    TlsCipherNoSpaceLeft,
};

pub const ResponseParseError = ClientError || error{
    InvalidStatusLine,
    InvalidVersion,
    InvalidStatusCode,
    InvalidHeader,
    MissingContentLength,
    InvalidChunkedEncoding,
};

config: Config,
stream: ?Io.net.Stream = null,
tls_conn: ?tls.Connection = null,
read_buf: []u8,
write_buf: []u8,
allocator: std.mem.Allocator,
/// HTTP/2 client state — initialized when ALPN negotiates "h2" or h2c prior knowledge.
h2_client: ?H2Client = null,
tls_read_buf_h2: [8192]u8 = undefined,
tls_write_buf_h2: [8192]u8 = undefined,
tls_reader_h2: ?tls.Connection.Reader = null,
tls_writer_h2: ?tls.Connection.Writer = null,
/// Persistent net reader/writer for h2c (cleartext HTTP/2)
h2c_net_reader: ?Io.net.Stream.Reader = null,
h2c_net_writer: ?Io.net.Stream.Writer = null,
h2c_read_buf: [8192]u8 = undefined,
h2c_write_buf: [8192]u8 = undefined,
/// Persistent net reader/writer for streaming responses
stream_reader: ?Io.net.Stream.Reader = null,
stream_writer: ?Io.net.Stream.Writer = null,
/// TLS reader/writer for streaming responses over TLS
tls_reader_stream: ?tls.Connection.Reader = null,
tls_read_buf_stream: [8192]u8 = undefined,

pub fn init(allocator: std.mem.Allocator, config: Config) error{OutOfMemory}!Client {
    const buf_size = @max(config.read_buffer_size, config.write_buffer_size);
    const read_buf = try allocator.alloc(u8, buf_size);
    errdefer allocator.free(read_buf);
    const write_buf = try allocator.alloc(u8, buf_size);
    return .{
        .config = config,
        .read_buf = read_buf,
        .write_buf = write_buf,
        .allocator = allocator,
    };
}

pub fn deinit(self: *Client) void {
    self.close();
    self.allocator.free(self.read_buf);
    self.allocator.free(self.write_buf);
}

pub fn connect(self: *Client, io: Io) ClientError!void {
    self.close();
    const hostname = Io.net.HostName.init(self.config.host) catch {
        return error.ConnectionFailed;
    };
    const stream = hostname.connect(io, self.config.port, .{ .mode = .stream }) catch {
        return error.ConnectionFailed;
    };

    if (self.config.tls_config) |tls_config| {
        // OpenSSL uses the socket fd directly
        self.tls_conn = tls.client(stream.socket.handle, tls_config) catch {
            return error.ConnectionFailed;
        };
        self.stream = stream;

        // Check if ALPN negotiated HTTP/2
        if (self.tls_conn) |*tc| {
            if (tc.alpn_protocol) |proto| {
                if (std.mem.eql(u8, proto, "h2")) {
                    self.tls_reader_h2 = tc.reader(&self.tls_read_buf_h2);
                    self.tls_writer_h2 = tc.writer(&self.tls_write_buf_h2);
                    self.h2_client = H2Client.init(&self.tls_reader_h2.?.interface, &self.tls_writer_h2.?.interface);
                    self.h2_client.?.handshake() catch {
                        self.h2_client = null;
                        return error.ConnectionFailed;
                    };
                }
            }
        }
    } else {
        self.stream = stream;

        // h2c prior knowledge: HTTP/2 over cleartext TCP
        if (self.config.h2_prior_knowledge) {
            self.h2c_net_reader = Io.net.Stream.Reader.init(stream, io, &self.h2c_read_buf);
            self.h2c_net_writer = Io.net.Stream.Writer.init(stream, io, &self.h2c_write_buf);
            self.h2_client = H2Client.init(&self.h2c_net_reader.?.interface, &self.h2c_net_writer.?.interface);
            self.h2_client.?.handshake() catch {
                self.h2_client = null;
                return error.ConnectionFailed;
            };
        }
    }
}

pub fn close(self: *Client) void {
    if (self.h2_client) |*h2c| {
        h2c.close();
        self.h2_client = null;
    }
    if (self.tls_conn) |*tc| {
        tc.close() catch {};
        tc.deinit();
        self.tls_conn = null;
    }
    if (self.stream) |stream| {
        _ = std.posix.system.close(stream.socket.handle);
        self.stream = null;
    }
}

/// A streaming response where headers have been parsed but the body
/// is available as a reader for incremental consumption (e.g., SSE streams).
pub const StreamResponse = struct {
    response: Response,
    reader: *Io.Reader,
    chunked: bool,
    content_length: ?usize,
};

/// Like `request`, but returns a `StreamResponse` with the body reader
/// instead of buffering the entire response body. The caller reads the
/// body incrementally via `stream_resp.reader`.
///
/// The caller must NOT call `response.deinit()` until done reading.
pub fn requestStream(self: *Client, io: Io, method: Request.Method, uri: []const u8, headers: ?Headers, body: ?[]const u8) ResponseParseError!StreamResponse {
    // HTTP/2 not supported for streaming
    if (self.h2_client != null) return error.InvalidResponse;

    if (self.tls_conn) |*conn| {
        try self.sendRequestTls(conn, method, uri, headers, body);
        self.tls_reader_stream = conn.reader(&self.tls_read_buf_stream);
        return try self.readResponseHeaders(&self.tls_reader_stream.?.interface);
    }

    const stream = self.stream orelse return error.ConnectionFailed;

    self.stream_reader = Io.net.Stream.Reader.init(stream, io, self.read_buf);
    self.stream_writer = Io.net.Stream.Writer.init(stream, io, self.write_buf);

    try self.sendRequest(&self.stream_writer.?, method, uri, headers, body);
    self.stream_writer.?.interface.flush() catch return error.SendFailed;

    return try self.readResponseHeaders(&self.stream_reader.?.interface);
}

/// Parse response headers only, leaving the reader positioned at the body start.
fn readResponseHeaders(self: *Client, reader: *Io.Reader) ResponseParseError!StreamResponse {
    _ = self;
    var response: Response = .{};
    var header_buf: [8192]u8 = undefined;
    var header_pos: usize = 0;

    while (true) {
        const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => {
                if (header_pos == 0) return error.InvalidResponse;
                break;
            },
            error.StreamTooLong => {
                if (header_pos == 0) return error.InvalidResponse;
                break;
            },
            else => return error.InvalidResponse,
        };

        if (header_pos + line.len > header_buf.len) return error.ResponseTooLarge;
        @memcpy(header_buf[header_pos..][0..line.len], line);
        header_pos += line.len;

        if (line.len == 2 and line[0] == '\r' and line[1] == '\n') {
            break;
        }
    }

    const header_str = header_buf[0..header_pos];

    const status_line_end = std.mem.indexOf(u8, header_str, "\r\n") orelse return error.InvalidResponse;
    try parseStatusLine(header_str[0..status_line_end], &response);

    var pos: usize = status_line_end + 2;
    while (pos + 1 < header_str.len) {
        const line_end = blk: {
            var j = pos;
            while (j + 1 < header_str.len) : (j += 1) {
                if (header_str[j] == '\r' and header_str[j + 1] == '\n') break :blk j;
            }
            break :blk header_str.len;
        };
        const line = header_str[pos..line_end];
        pos = if (line_end + 2 <= header_str.len) line_end + 2 else header_str.len;

        if (line.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        const name = line[0..colon];
        const value = Request.trimOws(line[colon + 1 ..]);

        response.headers.append(name, value) catch return error.ResponseTooLarge;
    }

    const te = response.headers.get("Transfer-Encoding");
    const is_chunked = te != null and Headers.eqlIgnoreCase(te.?, "chunked");

    var content_length: ?usize = null;
    if (!is_chunked) {
        if (response.headers.get("Content-Length")) |cl_str| {
            content_length = std.fmt.parseInt(usize, cl_str, 10) catch null;
        }
    }

    if (is_chunked) {
        response.chunked = true;
    }

    return .{
        .response = response,
        .reader = reader,
        .chunked = is_chunked,
        .content_length = content_length,
    };
}

pub fn request(self: *Client, io: Io, method: Request.Method, uri: []const u8, headers: ?Headers, body: ?[]const u8) ResponseParseError!Response {
    // HTTP/2 path
    if (self.h2_client) |*h2c| {
        const scheme: []const u8 = if (self.config.tls_config != null) "https" else "http";
        return h2c.request(self.allocator, method, self.config.host, uri, scheme, headers, body) catch
            return error.InvalidResponse;
    }

    if (self.tls_conn) |*conn| {
        return try self.requestTls(conn, method, uri, headers, body);
    }

    const stream = self.stream orelse return error.ConnectionFailed;

    var reader = Io.net.Stream.Reader.init(stream, io, self.read_buf);
    var writer = Io.net.Stream.Writer.init(stream, io, self.write_buf);

    try self.sendRequest(&writer, method, uri, headers, body);
    writer.interface.flush() catch return error.SendFailed;

    return try self.readResponse(&reader.interface);
}

fn requestTls(self: *Client, conn: *tls.Connection, method: Request.Method, uri: []const u8, headers: ?Headers, body: ?[]const u8) ResponseParseError!Response {
    try self.sendRequestTls(conn, method, uri, headers, body);

    // Accumulate TLS records into a single buffer — large responses span
    // multiple records, so a single conn.next() is not enough.
    var buf = std.ArrayList(u8).empty;
    errdefer buf.deinit(self.allocator);

    while (true) {
        const data = conn.next() catch |err| return mapTlsError(err);
        const chunk = data orelse break;
        buf.appendSlice(self.allocator, chunk) catch return error.ResponseTooLarge;

        // Check if we have enough data: find headers, then check content-length
        if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |header_end| {
            const header_data = buf.items[0..header_end];
            // Look for Content-Length header
            if (findHeaderValue(header_data, "Content-Length")) |cl_str| {
                const content_length = std.fmt.parseInt(usize, cl_str, 10) catch break;
                const body_start = header_end + 4;
                if (buf.items.len >= body_start + content_length) break;
            } else {
                // No content-length (might be chunked or connection-close) — check for chunked
                if (findHeaderValue(header_data, "Transfer-Encoding")) |te| {
                    if (std.ascii.findIgnoreCasePos(te, 0, "chunked") != null) {
                        // For chunked, look for the terminating 0\r\n\r\n
                        if (std.mem.indexOf(u8, buf.items[header_end + 4 ..], "0\r\n\r\n") != null) break;
                        if (std.mem.indexOf(u8, buf.items[header_end + 4 ..], "\r\n0\r\n") != null) break;
                    }
                } else {
                    // No content-length, not chunked — read until connection close
                    // We'll get null from conn.next() when done
                }
            }
        }
    }

    if (buf.items.len == 0) return error.InvalidResponse;
    var response = try self.parseTlsResponse(buf.items);
    // Transfer buffer ownership to response so headers remain valid
    response._tls_buf = .{
        .ptr = buf.items.ptr,
        .len = buf.capacity,
        .allocator = self.allocator,
    };
    return response;
}

/// Find a header value in raw header data (before \r\n\r\n).
fn findHeaderValue(header_data: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < header_data.len) {
        const line_end = std.mem.indexOf(u8, header_data[pos..], "\r\n") orelse header_data.len - pos;
        const line = header_data[pos .. pos + line_end];
        pos += line_end + 2;

        if (line.len > name.len + 1 and line[name.len] == ':') {
            if (std.ascii.eqlIgnoreCase(line[0..name.len], name)) {
                return Request.trimOws(line[name.len + 1 ..]);
            }
        }
    }
    return null;
}

fn mapTlsError(err: anyerror) ResponseParseError {
    return switch (err) {
        error.WriteFailed => error.SendFailed,
        error.ReadFailed, error.EndOfStream => error.InvalidResponse,
        error.TlsAlert => error.TlsHandshakeFailure,
        error.WouldBlock => error.InvalidResponse,
        else => error.InvalidResponse,
    };
}

fn sendRequestTls(self: *Client, conn: *tls.Connection, method: Request.Method, uri: []const u8, headers: ?Headers, body: ?[]const u8) ResponseParseError!void {
    var buf: [8192]u8 = undefined;
    var pos: usize = 0;

    const method_str = method.toBytes();
    @memcpy(buf[pos..][0..method_str.len], method_str);
    pos += method_str.len;
    buf[pos] = ' ';
    pos += 1;
    @memcpy(buf[pos..][0..uri.len], uri);
    pos += uri.len;
    @memcpy(buf[pos..][0..11], " HTTP/1.1\r\n");
    pos += 11;

    var host_written = false;
    if (headers) |h| {
        for (h.entries[0..h.len]) |entry| {
            @memcpy(buf[pos..][0..entry.name.len], entry.name);
            pos += entry.name.len;
            buf[pos] = ':';
            pos += 1;
            buf[pos] = ' ';
            pos += 1;
            @memcpy(buf[pos..][0..entry.value.len], entry.value);
            pos += entry.value.len;
            buf[pos] = '\r';
            pos += 1;
            buf[pos] = '\n';
            pos += 1;
            if (Headers.eqlIgnoreCase(entry.name, "Host")) {
                host_written = true;
            }
        }
    }

    if (!host_written) {
        @memcpy(buf[pos..][0..6], "Host: ");
        pos += 6;
        @memcpy(buf[pos..][0..self.config.host.len], self.config.host);
        pos += self.config.host.len;
        if (self.config.port != 80 and self.config.port != 443) {
            buf[pos] = ':';
            pos += 1;
            var port_buf: [20]u8 = undefined;
            const port_str = formatUsize(self.config.port, &port_buf);
            @memcpy(buf[pos..][0..port_str.len], port_str);
            pos += port_str.len;
        }
        buf[pos] = '\r';
        pos += 1;
        buf[pos] = '\n';
        pos += 1;
    }

    const has_body = body != null and body.?.len > 0;
    if (has_body) {
        @memcpy(buf[pos..][0..16], "Content-Length: ");
        pos += 16;
        var cl_buf: [20]u8 = undefined;
        const cl_str = formatUsize(body.?.len, &cl_buf);
        @memcpy(buf[pos..][0..cl_str.len], cl_str);
        pos += cl_str.len;
        buf[pos] = '\r';
        pos += 1;
        buf[pos] = '\n';
        pos += 1;
    }

    buf[pos] = '\r';
    pos += 1;
    buf[pos] = '\n';
    pos += 1;

    conn.writeAll(buf[0..pos]) catch return error.SendFailed;

    if (has_body) {
        conn.writeAll(body.?) catch return error.SendFailed;
    }
}

fn parseTlsResponse(self: *Client, data: []const u8) ResponseParseError!Response {
    var response: Response = .{};

    const header_end = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return error.InvalidResponse;
    // Include the trailing \r\n so the last header line is terminated
    const header_data = data[0 .. header_end + 2];

    const status_line_end = std.mem.indexOf(u8, header_data, "\r\n") orelse return error.InvalidResponse;
    try parseStatusLine(header_data[0..status_line_end], &response);

    var pos: usize = status_line_end + 2;
    while (pos < header_end) {
        const line_end = std.mem.indexOf(u8, header_data[pos..], "\r\n") orelse break;
        const line = header_data[pos .. pos + line_end];
        pos += line_end + 2;

        if (line.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        const name = line[0..colon];
        const value = Request.trimOws(line[colon + 1 ..]);

        response.headers.append(name, value) catch return error.ResponseTooLarge;
    }

    const te = response.headers.get("Transfer-Encoding");
    const is_chunked = te != null and Headers.eqlIgnoreCase(te.?, "chunked");

    const body_start = header_end + 4;

    if (is_chunked) {
        // Decode chunked transfer encoding from the TLS buffer
        var decoded = std.ArrayList(u8).empty;
        var chunk_pos = body_start;
        while (chunk_pos < data.len) {
            const chunk_header_end = std.mem.indexOf(u8, data[chunk_pos..], "\r\n") orelse break;
            const size_str = std.mem.trim(u8, data[chunk_pos .. chunk_pos + chunk_header_end], " ");
            // Strip chunk extensions (after semicolon)
            const semi = std.mem.indexOfScalar(u8, size_str, ';');
            const pure_size = if (semi) |s| size_str[0..s] else size_str;
            const chunk_size = std.fmt.parseInt(usize, pure_size, 16) catch break;
            if (chunk_size == 0) break;
            chunk_pos += chunk_header_end + 2;
            if (chunk_pos + chunk_size > data.len) break;
            decoded.appendSlice(self.allocator, data[chunk_pos .. chunk_pos + chunk_size]) catch
                return error.ResponseTooLarge;
            chunk_pos += chunk_size + 2; // skip trailing \r\n
        }
        if (decoded.items.len > 0) {
            const body_data = decoded.toOwnedSlice(self.allocator) catch
                return error.ResponseTooLarge;
            response.body = body_data;
            response._body_allocated = body_data;
        } else {
            decoded.deinit(self.allocator);
        }
        return response;
    }

    const cl = response.headers.get("Content-Length");
    if (cl) |cl_str| {
        const content_length = std.fmt.parseInt(usize, cl_str, 10) catch
            return error.InvalidResponse;

        if (content_length > self.config.max_response_size) return error.ResponseTooLarge;

        if (body_start + content_length <= data.len) {
            const body_data = self.allocator.alloc(u8, content_length) catch
                return error.ResponseTooLarge;
            @memcpy(body_data, data[body_start .. body_start + content_length]);
            response.body = body_data;
            response._body_allocated = body_data;
        }
    }

    return response;
}

fn sendRequest(self: *Client, writer: *Io.net.Stream.Writer, method: Request.Method, uri: []const u8, headers: ?Headers, body: ?[]const u8) ClientError!void {
    const method_str = method.toBytes();
    writer.interface.writeAll(method_str) catch return error.SendFailed;
    writer.interface.writeAll(" ") catch return error.SendFailed;
    writer.interface.writeAll(uri) catch return error.SendFailed;
    writer.interface.writeAll(" HTTP/1.1\r\n") catch return error.SendFailed;

    var host_written = false;
    if (headers) |h| {
        for (h.entries[0..h.len]) |entry| {
            writer.interface.writeAll(entry.name) catch return error.SendFailed;
            writer.interface.writeAll(": ") catch return error.SendFailed;
            writer.interface.writeAll(entry.value) catch return error.SendFailed;
            writer.interface.writeAll("\r\n") catch return error.SendFailed;
            if (Headers.eqlIgnoreCase(entry.name, "Host")) {
                host_written = true;
            }
        }
    }

    if (!host_written) {
        writer.interface.writeAll("Host: ") catch return error.SendFailed;
        writer.interface.writeAll(self.config.host) catch return error.SendFailed;
        if (self.config.port != 80 and self.config.port != 443) {
            writer.interface.writeAll(":") catch return error.SendFailed;
            var port_buf: [20]u8 = undefined;
            const port_str = formatUsize(self.config.port, &port_buf);
            writer.interface.writeAll(port_str) catch return error.SendFailed;
        }
        writer.interface.writeAll("\r\n") catch return error.SendFailed;
    }

    const has_body = body != null and body.?.len > 0;
    if (has_body) {
        var cl_buf: [20]u8 = undefined;
        const cl_str = formatUsize(body.?.len, &cl_buf);
        writer.interface.writeAll("Content-Length: ") catch return error.SendFailed;
        writer.interface.writeAll(cl_str) catch return error.SendFailed;
        writer.interface.writeAll("\r\n") catch return error.SendFailed;
    }

    writer.interface.writeAll("\r\n") catch return error.SendFailed;

    if (has_body) {
        writer.interface.writeAll(body.?) catch return error.SendFailed;
    }
}

fn readResponse(self: *Client, reader: *Io.Reader) ResponseParseError!Response {
    var response: Response = .{};
    var header_buf: [8192]u8 = undefined;
    var header_pos: usize = 0;

    while (true) {
        const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => {
                if (header_pos == 0) return error.InvalidResponse;
                break;
            },
            error.StreamTooLong => {
                if (header_pos == 0) return error.InvalidResponse;
                break;
            },
            else => return error.InvalidResponse,
        };

        if (header_pos + line.len > header_buf.len) return error.ResponseTooLarge;
        @memcpy(header_buf[header_pos..][0..line.len], line);
        header_pos += line.len;

        if (line.len == 2 and line[0] == '\r' and line[1] == '\n') {
            break;
        }
    }

    const header_str = header_buf[0..header_pos];

    const status_line_end = std.mem.indexOf(u8, header_str, "\r\n") orelse return error.InvalidResponse;
    try parseStatusLine(header_str[0..status_line_end], &response);

    var pos: usize = status_line_end + 2;
    while (pos + 1 < header_str.len) {
        const line_end = blk: {
            var j = pos;
            while (j + 1 < header_str.len) : (j += 1) {
                if (header_str[j] == '\r' and header_str[j + 1] == '\n') break :blk j;
            }
            break :blk header_str.len;
        };
        const line = header_str[pos..line_end];
        pos = if (line_end + 2 <= header_str.len) line_end + 2 else header_str.len;

        if (line.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidHeader;
        const name = line[0..colon];
        const value = Request.trimOws(line[colon + 1 ..]);

        response.headers.append(name, value) catch return error.ResponseTooLarge;
    }

    const te = response.headers.get("Transfer-Encoding");
    const is_chunked = te != null and Headers.eqlIgnoreCase(te.?, "chunked");

    if (is_chunked) {
        response.chunked = true;
        response.body = "";
        return response;
    }

    const cl = response.headers.get("Content-Length");
    if (cl) |cl_str| {
        const content_length = std.fmt.parseInt(usize, cl_str, 10) catch
            return error.InvalidResponse;

        if (content_length > self.config.max_response_size) return error.ResponseTooLarge;

        if (content_length > 0) {
            const body_buf = self.allocator.alloc(u8, content_length) catch
                return error.ResponseTooLarge;

            reader.readSliceAll(body_buf) catch {
                self.allocator.free(body_buf);
                return error.InvalidResponse;
            };
            response.body = body_buf;
            response._body_allocated = body_buf;
        }
    }

    return response;
}

fn parseStatusLine(data: []const u8, response: *Response) ResponseParseError!void {
    const version_end = std.mem.indexOfScalar(u8, data, ' ') orelse
        return error.InvalidStatusLine;

    const version_str = data[0..version_end];
    if (std.mem.eql(u8, version_str, "HTTP/1.1")) {
        response.version = .http_1_1;
    } else if (std.mem.eql(u8, version_str, "HTTP/1.0")) {
        response.version = .http_1_0;
    } else {
        return error.InvalidVersion;
    }

    const rest = data[version_end + 1 ..];
    const status_end = std.mem.indexOfScalar(u8, rest, ' ') orelse
        return error.InvalidStatusLine;

    const status_str = rest[0..status_end];
    const status_code = std.fmt.parseInt(u16, status_str, 10) catch
        return error.InvalidStatusCode;

    response.status = intToStatusCode(status_code) orelse return error.InvalidStatusCode;
}

pub fn intToStatusCode(code: u16) ?Response.StatusCode {
    return switch (code) {
        100 => .@"continue",
        101 => .switching_protocols,
        200 => .ok,
        201 => .created,
        202 => .accepted,
        203 => .non_authoritative_information,
        204 => .no_content,
        205 => .reset_content,
        206 => .partial_content,
        300 => .multiple_choices,
        301 => .moved_permanently,
        302 => .found,
        303 => .see_other,
        304 => .not_modified,
        305 => .use_proxy,
        307 => .temporary_redirect,
        400 => .bad_request,
        401 => .unauthorized,
        402 => .payment_required,
        403 => .forbidden,
        404 => .not_found,
        405 => .method_not_allowed,
        406 => .not_acceptable,
        407 => .proxy_authentication_required,
        408 => .request_timeout,
        409 => .conflict,
        410 => .gone,
        411 => .length_required,
        412 => .precondition_failed,
        413 => .request_entity_too_large,
        414 => .request_uri_too_long,
        415 => .unsupported_media_type,
        416 => .requested_range_not_satisfiable,
        417 => .expectation_failed,
        500 => .internal_server_error,
        501 => .not_implemented,
        502 => .bad_gateway,
        503 => .service_unavailable,
        504 => .gateway_timeout,
        505 => .http_version_not_supported,
        else => null,
    };
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

fn setSocketTimeout(handle: Io.net.Socket.Handle, timeout_s: u32) void {
    const timeval = std.posix.timeval{
        .sec = @intCast(timeout_s),
        .usec = 0,
    };
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeval)) catch |err| {
        std.log.warn("setsockopt SO_RCVTIMEO failed: {}", .{err});
    };
}

const testing = std.testing;

test "Client: intToStatusCode" {
    try testing.expectEqual(Response.StatusCode.ok, intToStatusCode(200).?);
    try testing.expectEqual(Response.StatusCode.not_found, intToStatusCode(404).?);
    try testing.expectEqual(Response.StatusCode.internal_server_error, intToStatusCode(500).?);
    try testing.expect(intToStatusCode(999) == null);
}

test "Client: formatUsize" {
    var buf: [20]u8 = undefined;
    try testing.expectEqualStrings("0", formatUsize(0, &buf));
    try testing.expectEqualStrings("42", formatUsize(42, &buf));
    try testing.expectEqualStrings("1000", formatUsize(1000, &buf));
}

test "Client: Url.parse" {
    const url = Url.parse("https://api.iconify.design/mdi/home.svg").?;
    try testing.expectEqualStrings("https", url.scheme);
    try testing.expectEqualStrings("api.iconify.design", url.host);
    try testing.expectEqual(@as(u16, 443), url.port);
    try testing.expectEqualStrings("/mdi/home.svg", url.path);
}

test "Client: Url.parse http with port" {
    const url = Url.parse("http://example.com:8080/path").?;
    try testing.expectEqualStrings("http", url.scheme);
    try testing.expectEqualStrings("example.com", url.host);
    try testing.expectEqual(@as(u16, 8080), url.port);
    try testing.expectEqualStrings("/path", url.path);
}

test "Client: Url.parse no path" {
    const url = Url.parse("http://example.com").?;
    try testing.expectEqualStrings("/", url.path);
}

test "Client: download from httpbin.org" {
    const test_url = Url.parse("http://httpbin.org/html").?;

    var client = try Client.init(std.testing.allocator, .{
        .host = test_url.host,
        .port = test_url.port,
        .connection_timeout_s = 10,
        .read_timeout_s = 10,
    });
    defer client.deinit();

    const io = std.testing.io;
    try client.connect(io);

    var resp = try client.request(io, .GET, test_url.path, null, null);
    defer resp.deinit(std.testing.allocator);

    if (resp.status != .ok) return;

    const content_type = resp.headers.get("Content-Type");
    try testing.expect(content_type != null);
    try testing.expect(std.mem.indexOf(u8, content_type.?, "text/html") != null);

    try testing.expect(resp.body.len > 0);
}
