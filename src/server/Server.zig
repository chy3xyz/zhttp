const Server = @This();
const std = @import("std");
const Io = std.Io;
const tls = @import("../openssl.zig");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Connection = @import("Connection.zig");
const ChunkedWriter = @import("ChunkedWriter.zig");
const Headers = @import("../Headers.zig");
const Date = @import("Date.zig");
const Proxy = @import("Proxy.zig");
const WebSocket = @import("WebSocket.zig");
const H2Connection = @import("H2Connection.zig");
const h2 = @import("../h2/root.zig");

/// RFC 2616 Section 1.4: HTTP/1.1 server implementation.
///
/// This server uses the Zig 0.16 std.Io interface for networking,
/// supporting both threaded and evented I/O backends.
/// Proxy access control configuration.
/// Controls which targets can be reached through CONNECT tunneling.
pub const ProxyConfig = struct {
    /// Allowed destination ports. If empty, all ports are allowed.
    /// Common safe default: &.{443} (HTTPS only).
    allowed_ports: []const u16 = &.{443},
    /// Block connections to private/loopback IP ranges (SSRF protection).
    /// When true, rejects targets resolving to 127.0.0.0/8, 10.0.0.0/8,
    /// 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, and ::1.
    block_private_ips: bool = true,
    /// Optional allowed target hosts. If non-empty, only these hosts
    /// are permitted as CONNECT targets. Checked case-insensitively.
    allowed_hosts: []const []const u8 = &.{},
};

pub const Config = struct {
    port: u16 = 8080,
    address: []const u8 = "127.0.0.1",
    /// RFC 2616 Section 8.1.4: Servers SHOULD implement persistent connections
    /// but may close idle connections after a timeout.
    read_buffer_size: usize = 8192,
    write_buffer_size: usize = 8192,
    /// Maximum total request size (headers + body)
    max_request_size: usize = 1_048_576,
    /// Maximum size for HTTP headers (before body). Limits how much data
    /// readHeaders will consume, preventing a client from forcing a full
    /// max_request_size read with unterminated headers.
    max_header_size: usize = 65536,
    /// RFC 2616 Section 8.1.4: Idle connection timeout in seconds.
    /// Connections with no activity for this duration will be closed.
    /// 0 means no timeout. Requires async Io backend for enforcement.
    keep_alive_timeout_s: u32 = 60,
    /// Timeout in seconds for reading the initial request on a new
    /// connection. Prevents slowloris-style attacks where a client
    /// connects but never sends data. Applied independently of
    /// keep_alive_timeout_s. 0 means no initial timeout.
    initial_read_timeout_s: u32 = 30,
    /// Maximum number of concurrent connections. 0 means unlimited.
    /// When the limit is reached, new connections are accepted and
    /// immediately closed.
    max_connections: u32 = 512,
    /// RFC 2616 Section 9.8: Enable TRACE method support.
    /// TRACE echoes the full request (including headers like Cookie and
    /// Authorization) back to the client. This is a security risk (XST)
    /// and is disabled by default.
    enable_trace: bool = false,
    /// RFC 2616 Section 9.9 / 14.45: Enable proxy support.
    /// When true, the server handles CONNECT requests for tunneling
    /// and adds Via headers to proxied responses.
    enable_proxy: bool = false,
    /// Proxy access control settings. Only used when enable_proxy is true.
    proxy: ProxyConfig = .{},
    /// WebSocket handler. When set, responses with status 101 trigger
    /// a WebSocket session using this handler.
    websocket_handler: ?WebSocket.Handler = null,
    /// TLS configuration for HTTPS support.
    /// When set, the server performs a TLS handshake on each accepted
    /// connection and serves HTTP over the encrypted channel.
    tls_config: ?tls.config.Server = null,
    /// Optional HTTP/3 UDP port for Alt-Svc header advertisement (RFC 7838 / RFC 9114).
    /// When non-zero, the server automatically appends `Alt-Svc: h3=":port"; ma=86400`
    /// to HTTPS responses.
    alt_svc_port: u16 = 0,
    /// CLOSE-WAIT sweeper interval, in milliseconds. The sweeper polls all
    /// active connection fds for POLLRDHUP and forces `shutdown(SHUT_RDWR)`
    /// on any that the peer has closed. This breaks a handler thread that
    /// is stuck (e.g., on a saturated downstream pool) so the deferred
    /// close on the connection task can run, releasing the fd.
    ///
    /// 0 disables the sweeper. Default 2000ms balances responsiveness with
    /// poll() syscall overhead.
    sweeper_interval_ms: u32 = 2000,
};

const min_initial_request_buffer_size = 16 * 1024;

/// POLLRDHUP — fires when the peer has closed its write side (sent FIN).
/// Linux-specific. Not currently exposed via `std.posix.POLL`, but the
/// kernel ABI value is stable at 0x2000 on all supported architectures.
const POLLRDHUP: i16 = 0x2000;

/// CLOSE-WAIT sweeper config.
///
/// Each accepted connection's fd is registered with the sweeper. A background
/// thread polls all registered fds for `POLLRDHUP` (peer closed write side).
/// When peer FIN is observed, the sweeper calls `shutdown(fd, SHUT_RDWR)` so
/// any blocked read/write on that fd in the handler task fails immediately,
/// causing the connection task to return and run its deferred close.
///
/// This bounds CLOSE-WAIT FD pile-up under load, in particular when a handler
/// thread is stuck (e.g., waiting on a saturated downstream pool) and would
/// otherwise never re-enter the read loop to observe the peer's FIN.
const ConnSweeper = struct {
    mutex: std.atomic.Mutex = .unlocked,
    fds: std.ArrayListUnmanaged(Io.net.Socket.Handle) = .empty,
    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    allocator: std.mem.Allocator,
    interval_ms: u32,

    fn lockMutex(self: *ConnSweeper) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }

    fn register(self: *ConnSweeper, fd: Io.net.Socket.Handle) void {
        self.lockMutex();
        defer self.mutex.unlock();
        self.fds.append(self.allocator, fd) catch {};
    }

    fn unregister(self: *ConnSweeper, fd: Io.net.Socket.Handle) void {
        self.lockMutex();
        defer self.mutex.unlock();
        for (self.fds.items, 0..) |existing, i| {
            if (existing == fd) {
                _ = self.fds.swapRemove(i);
                return;
            }
        }
    }

    fn run(self: *ConnSweeper) void {
        var pollfds: std.ArrayListUnmanaged(std.posix.pollfd) = .empty;
        defer pollfds.deinit(self.allocator);

        while (!self.stop.load(.acquire)) {
            // Sleep the interval. Use posix nanosleep — std.Thread.sleep was
            // removed in Zig 0.16, and Io.sleep requires an Io handle we don't
            // own here (the sweeper is a plain std.Thread).
            const total_ns: u64 = @as(u64, self.interval_ms) * std.time.ns_per_ms;
            var req = std.posix.timespec{
                .sec = @intCast(total_ns / std.time.ns_per_s),
                .nsec = @intCast(total_ns % std.time.ns_per_s),
            };
            while (std.posix.errno(std.posix.system.nanosleep(&req, &req)) == .INTR) {}

            self.lockMutex();
            pollfds.clearRetainingCapacity();
            for (self.fds.items) |fd| {
                pollfds.append(self.allocator, .{
                    .fd = fd,
                    // POLLRDHUP fires when the peer closed its write side.
                    // POLLHUP fires when the peer closed the connection entirely.
                    // POLLERR fires for connection errors.
                    .events = POLLRDHUP,
                    .revents = 0,
                }) catch break;
            }
            self.mutex.unlock();

            if (pollfds.items.len == 0) continue;

            // Non-blocking poll: timeout 0.
            const rc = std.posix.system.poll(pollfds.items.ptr, @intCast(pollfds.items.len), 0);
            if (rc <= 0) continue;

            for (pollfds.items) |pf| {
                // POLLRDHUP/POLLHUP/POLLERR all indicate peer is gone or socket is broken.
                const hup_mask: i16 = POLLRDHUP | std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL;
                if ((pf.revents & hup_mask) != 0) {
                    // Force any blocked read/write in the handler task to fail.
                    // The handler task's `defer stream.close(io)` then runs and the fd
                    // is released. We deliberately don't close() here — that would risk
                    // a double-close race with the handler task's defer.
                    _ = std.posix.system.shutdown(pf.fd, std.posix.SHUT.RDWR);
                }
            }
        }
    }
};

config: Config,
handler: Connection.Handler,
active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
sweeper: ?*ConnSweeper = null,

pub fn init(config: Config, handler: Connection.Handler) Server {
    return .{
        .config = config,
        .handler = handler,
    };
}

/// Start the server. This is the main entry point for running the HTTP server
/// with the Zig 0.16 std.Io networking API.
///
/// Uses Io.net.IpAddress.listen() to create a listening socket and
/// Server.accept() to handle incoming connections.
pub const RunError = error{AddressInUse};

pub fn run(self: *Server, io: Io) RunError!void {
    const addr = Io.net.IpAddress.parseIp4(self.config.address, self.config.port) catch return error.AddressInUse;

    // Check if something is already listening on this port.
    // reuse_address allows binding even when another process holds the port,
    // so we probe with a connect first.
    if (Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream })) |probe| {
        probe.close(io);
        return error.AddressInUse;
    } else |_| {}

    var server = Io.net.IpAddress.listen(&addr, io, .{ .reuse_address = true }) catch return error.AddressInUse;
    defer server.deinit(io);
    var connection_group: Io.Group = .init;
    defer connection_group.cancel(io);

    // Spawn the CLOSE-WAIT sweeper. Best-effort: if anything fails (allocator
    // out of memory, thread spawn fails), we proceed without it — connections
    // will still be served correctly, just without the FD-pile-up bound.
    const gpa = std.heap.page_allocator;
    var sweeper: ConnSweeper = .{
        .allocator = gpa,
        .interval_ms = self.config.sweeper_interval_ms,
    };
    var sweeper_started = false;
    if (self.config.sweeper_interval_ms > 0) {
        if (std.Thread.spawn(.{}, ConnSweeper.run, .{&sweeper})) |t| {
            sweeper.thread = t;
            self.sweeper = &sweeper;
            sweeper_started = true;
        } else |_| {}
    }
    defer if (sweeper_started) {
        sweeper.stop.store(true, .release);
        if (sweeper.thread) |t| t.join();
        sweeper.fds.deinit(sweeper.allocator);
        self.sweeper = null;
    };

    while (true) {
        const stream = server.accept(io) catch |err| {
            std.debug.print("Accept error: {}\n", .{err});
            continue;
        };

        // Enforce connection limit atomically: increment first, then check.
        // This avoids the TOCTOU race where concurrent accepts could both
        // pass a load() check before either increments.
        if (self.config.max_connections > 0) {
            const prev = self.active_connections.fetchAdd(1, .acquire);
            if (prev >= self.config.max_connections) {
                _ = self.active_connections.fetchSub(1, .release);
                stream.close(io);
                continue;
            }
        }

        connection_group.concurrent(io, handleConnectionTask, .{ self, stream, io }) catch {
            // The concurrent() failure means the connection's task didn't start.
            // Decrement the counter we incremented above so it stays accurate.
            if (self.config.max_connections > 0) {
                _ = self.active_connections.fetchSub(1, .release);
            }
            rejectBusyConnection(stream, io);
            continue;
        };
    }
}

/// Handle a single TCP connection, potentially with multiple requests
/// (keep-alive).
///
/// RFC 2616 Section 8.1: Persistent Connections
fn handleConnection(self: *Server, stream: Io.net.Stream, io: Io) !void {
    const fd = stream.socket.handle;

    // TLS handshake if configured — OpenSSL uses the socket fd directly
    var tls_conn: ?tls.Connection = null;
    var tls_read_buf: [8192]u8 = undefined;
    var tls_write_buf: [8192]u8 = undefined;

    // Buffered TCP reader/writer for plain HTTP and error responses.
    // For TLS connections, OpenSSL reads/writes the socket directly,
    // so these are only used for the plain HTTP path.
    var read_buf: [tls.input_buffer_len]u8 = undefined;
    var write_buf: [tls.output_buffer_len]u8 = undefined;
    var net_reader = Io.net.Stream.Reader.init(stream, io, &read_buf);
    var net_writer = Io.net.Stream.Writer.init(stream, io, &write_buf);

    if (self.config.tls_config) |tls_config| {
        // Peek at the first byte to detect plain HTTP vs TLS.
        // Use MSG_PEEK at the socket level so the byte remains available
        // to OpenSSL for the handshake.
        var peek_buf: [1]u8 = undefined;
        const peek_result = std.posix.system.recvfrom(fd, &peek_buf, 1, std.os.linux.MSG.PEEK, null, null);
        const is_tls_client_hello = peek_result > 0 and peek_buf[0] == 0x16;

        if (is_tls_client_hello) {
            // Client is speaking TLS — perform handshake (with SNI if configured)
            tls_conn = tls.server(fd, tls_config) catch {
                return;
            };
        } else if (tls_config.sni_context != null) {
            // SNI mode: accept plain HTTP alongside TLS (e.g., from a reverse
            // proxy like Traefik that terminates TLS for the primary domain
            // and forwards plain HTTP to this port).
        } else {
            // Strict TLS mode — reject plain HTTP
            net_writer.interface.writeAll(
                "HTTP/1.1 400 Bad Request\r\n" ++
                    "Content-Type: text/plain\r\n" ++
                    "Content-Length: 46\r\n" ++
                    "Connection: close\r\n" ++
                    "\r\n" ++
                    "Client sent plain HTTP to an HTTPS-only port.\n",
            ) catch {};
            net_writer.interface.flush() catch {};
            return;
        }
    }
    defer if (tls_conn) |*tc| {
        tc.close() catch {};
        tc.deinit();
    };

    // Get the appropriate reader/writer interfaces - either TLS or plain TCP
    var tls_reader_wrapper: tls.Connection.Reader = undefined;
    var tls_writer_wrapper: tls.Connection.Writer = undefined;

    if (tls_conn) |*tc| {
        tls_reader_wrapper = tc.reader(&tls_read_buf);
        tls_writer_wrapper = tc.writer(&tls_write_buf);
    }

    const reader: *Io.Reader = if (tls_conn != null)
        &tls_reader_wrapper.interface
    else
        &net_reader.interface;
    const writer: *Io.Writer = if (tls_conn != null)
        &tls_writer_wrapper.interface
    else
        &net_writer.interface;

    // HTTP/2 via ALPN: if TLS negotiated "h2", handle as HTTP/2
    if (tls_conn) |tc| {
        if (tc.alpn_protocol) |proto| {
            if (std.mem.eql(u8, proto, "h2")) {
                H2Connection.serve(reader, writer, self.handler, io);
                return;
            }
        }
    }

    // Detect TLS ClientHello on a non-TLS port.
    if (self.config.tls_config == null) {
        const first = net_reader.interface.peek(1) catch {
            return;
        };
        if (first.len > 0 and first[0] == 0x16) {
            net_writer.interface.writeAll(
                "HTTP/1.1 400 Bad Request\r\n" ++
                    "Content-Type: text/plain\r\n" ++
                    "Content-Length: 49\r\n" ++
                    "Connection: close\r\n" ++
                    "\r\n" ++
                    "Client sent HTTPS request to a plain HTTP port.\n",
            ) catch {};
            net_writer.interface.flush() catch {};
            return;
        }
    }

    // HTTP/2 via prior knowledge (h2c): detect the connection preface
    // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" on cleartext connections.
    if (self.config.tls_config == null) {
        const peek = reader.peek(h2.connection_preface.len) catch null;
        if (peek) |data| {
            if (data.len >= h2.connection_preface.len and
                std.mem.eql(u8, data[0..h2.connection_preface.len], h2.connection_preface))
            {
                H2Connection.serve(reader, writer, self.handler, io);
                return;
            }
        }
    }

    // Heap-allocate the request buffer to avoid ~1 MiB stack usage per
    // connection, which can cause stack overflows under concurrent load.
    var request_buf = std.heap.page_allocator.alloc(u8, initialRequestBufferSize(self.config)) catch return;
    defer std.heap.page_allocator.free(request_buf);

    while (true) {
        // Read request headers into a sub-slice limited by max_header_size
        // to prevent unterminated headers from consuming the full request buffer.
        const header_limit = @min(self.config.max_header_size, request_buf.len);
        const header_len = readHeaders(reader, request_buf[0..header_limit]) catch |err| switch (err) {
            error.EndOfStream => return, // Client closed connection
            error.ReadFailed => return, // Timeout or connection reset
        };

        // RFC 2616 Section 14.20: Check for Expect header.
        // If "100-continue", send 100 Continue before reading body.
        // If any other expectation, respond with 417 Expectation Failed.
        const expect_value = extractHeaderValue(request_buf[0..header_len], "expect");
        if (expect_value) |ev| {
            if (Headers.eqlIgnoreCase(ev, "100-continue")) {
                writer.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return;
                writer.flush() catch return;
            } else {
                const resp: Response = .{ .status = .expectation_failed, .body = "Expectation Failed" };
                var resp_buf: [Response.max_response_header_len]u8 = undefined;
                const resp_data = resp.serialize(&resp_buf) catch return;
                writer.writeAll(resp_data) catch return;
                writer.flush() catch return;
                return;
            }
        }

        // Read body based on Transfer-Encoding or Content-Length
        var total = header_len;
        const te = extractHeaderValue(request_buf[0..header_len], "transfer-encoding");

        // RFC 2616 Section 3.6: If an unrecognized transfer-coding is
        // received, the server SHOULD return 501 Not Implemented.
        if (te != null and !Headers.eqlIgnoreCase(te.?, "chunked") and
            !Headers.eqlIgnoreCase(te.?, "identity"))
        {
            const resp: Response = .{ .status = .not_implemented, .body = "Unsupported Transfer-Encoding" };
            var resp_buf: [Response.max_response_header_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            writer.writeAll(resp_data) catch return;
            writer.flush() catch return;
            return;
        }

        if (te != null and Headers.eqlIgnoreCase(te.?, "chunked")) {
            // RFC 2616 Section 3.6.1: Read chunked body from stream.
            total = readChunkedBody(reader, &request_buf, total, self.config.max_request_size) catch |err| switch (err) {
                error.EndOfStream => {
                    const resp: Response = .{ .status = .bad_request, .body = "Incomplete chunked body" };
                    var resp_buf: [Response.max_response_header_len]u8 = undefined;
                    const resp_data = resp.serialize(&resp_buf) catch return;
                    writer.writeAll(resp_data) catch return;
                    writer.flush() catch return;
                    return;
                },
                error.ReadFailed => return error.ReadFailed,
                error.BodyTooLarge => {
                    const resp: Response = .{ .status = .request_entity_too_large, .body = "Request Entity Too Large" };
                    var resp_buf: [Response.max_response_header_len]u8 = undefined;
                    const resp_data = resp.serialize(&resp_buf) catch return;
                    writer.writeAll(resp_data) catch return;
                    writer.flush() catch return;
                    return;
                },
                error.InvalidChunkedEncoding => {
                    const resp: Response = .{ .status = .bad_request, .body = "Invalid chunked body" };
                    var resp_buf: [Response.max_response_header_len]u8 = undefined;
                    const resp_data = resp.serialize(&resp_buf) catch return;
                    writer.writeAll(resp_data) catch return;
                    writer.flush() catch return;
                    return;
                },
            };
        } else {
            const cl = extractContentLength(request_buf[0..header_len]);
            if (cl) |body_len| {
                if (body_len > self.config.max_request_size - header_len) {
                    const resp: Response = .{ .status = .request_entity_too_large, .body = "Request Entity Too Large" };
                    var resp_buf: [Response.max_response_header_len]u8 = undefined;
                    const resp_data = resp.serialize(&resp_buf) catch return;
                    writer.writeAll(resp_data) catch return;
                    writer.flush() catch return;
                    return;
                }
                ensureRequestCapacity(&request_buf, header_len + body_len, self.config.max_request_size) catch return;
                const to_read = body_len;
                if (to_read > 0) {
                    reader.readSliceAll(request_buf[total..][0..to_read]) catch |err| switch (err) {
                        error.EndOfStream => {},
                        error.ReadFailed => return error.ReadFailed,
                    };
                    total += to_read;
                }
            }
        }

        const request_data = request_buf[0..total];

        // Parse the request
        const request = Request.parse(request_data) catch |err| {
            const status: Response.StatusCode = switch (err) {
                error.UnknownMethod => .not_implemented,
                error.InvalidVersion => .http_version_not_supported,
                error.MissingHostHeader => .bad_request,
                error.MultipleHostHeaders => .bad_request,
                error.ConflictingContentLength => .bad_request,
                error.InvalidHostHeader => .bad_request,
                error.UriPathTraversal => .bad_request,
                error.LineTooLong => .request_uri_too_long,
                error.BodyTooLarge => .request_entity_too_large,
                error.InvalidContentLength => .bad_request,
                else => .bad_request,
            };
            const resp: Response = .{ .status = status, .body = status.reason() };
            var resp_buf: [Response.max_response_header_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            writer.writeAll(resp_data) catch return;
            writer.flush() catch return;
            return;
        };

        // RFC 2616 Section 9.9: Handle CONNECT for proxy tunneling.
        if (request.method == .CONNECT and self.config.enable_proxy) {
            self.handleConnect(stream, io, &request, &net_writer) catch return;
            return;
        }

        // Per-request arena allocator — freed after the response cycle completes.
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const request_allocator = arena.allocator();

        // Process the request
        const timestamp = Date.now(io);
        var response = Connection.processRequestWithOptions(request_allocator, io, timestamp, &request, self.handler, .{
            .enable_trace = self.config.enable_trace,
        });

        // RFC 2616 Section 14.45: Add Via header for proxied responses.
        if (self.config.enable_proxy) {
            Proxy.addViaHeader(&response, request.version);
        }

        // RFC 7838 / RFC 9114: Advertise HTTP/3 Alt-Svc if configured.
        if (self.config.alt_svc_port > 0) {
            var alt_svc_buf: [64]u8 = undefined;
            const alt_svc_val = std.fmt.bufPrint(&alt_svc_buf, "h3=\":{d}\"; ma=86400", .{self.config.alt_svc_port}) catch null;
            if (alt_svc_val) |val| {
                const val_dupe = request_allocator.dupe(u8, val) catch null;
                if (val_dupe) |vd| {
                    response.headers.appendServer("Alt-Svc", vd);
                }
            }
        }

        // Serialize and send response
        var resp_buf: [Response.max_response_header_len]u8 = undefined;

        if (response.stream_fn) |stream_fn| {
            // Streaming response path: send headers, then call stream_fn
            const header_data = response.serializeHeaders(&resp_buf) catch {
                const err_resp: Response = .{ .status = .internal_server_error, .body = "Internal Server Error" };
                const err_data = err_resp.serialize(&resp_buf) catch return;
                writer.writeAll(err_data) catch return;
                writer.flush() catch return;
                return;
            };
            writer.writeAll(header_data) catch return;
            writer.flush() catch return;

            // Hand stream_fn a writer that produces correctly-framed
            // bytes. When the response advertises `Transfer-Encoding:
            // chunked`, the wrapper turns every drain into a chunk
            // (RFC 7230 §4.1) and we emit the terminating `0\r\n\r\n`
            // marker afterwards. Without the wrapper, the raw bytes
            // would go out unframed but the header would lie about it.
            if (response.chunked) {
                var chunked = ChunkedWriter.init(writer);
                stream_fn(response.stream_context, &chunked.interface);
                chunked.finish() catch {};
            } else {
                stream_fn(response.stream_context, writer);
                writer.flush() catch return;
            }
            response.deinit(request_allocator);
            // Streaming responses don't keep-alive (simplicity)
            return;
        }

        const header_data = response.serializeHeaders(&resp_buf) catch {
            const err_resp: Response = .{ .status = .internal_server_error, .body = "Internal Server Error" };
            const err_data = err_resp.serializeHeaders(&resp_buf) catch return;
            writer.writeAll(err_data) catch return;
            writer.flush() catch return;
            return;
        };

        writer.writeAll(header_data) catch return;
        if (!response.strip_body) {
            if (response.chunked and response.body.len > 0) {
                // RFC 2616 Section 3.6.1: Encode body as a single chunk
                var chunk_size_buf: [20]u8 = undefined;
                const chunk_size_str = std.fmt.bufPrint(&chunk_size_buf, "{x}", .{response.body.len}) catch return;
                writer.writeAll(chunk_size_str) catch return;
                writer.writeAll("\r\n") catch return;
                writer.writeAll(response.body) catch return;
                writer.writeAll("\r\n0\r\n\r\n") catch return;
            } else if (response.chunked) {
                writer.writeAll("0\r\n\r\n") catch return;
            } else {
                writer.writeAll(response.body) catch return;
            }
        }
        writer.flush() catch return;

        // Free any allocated body (e.g. from gzip compression)
        response.deinit(request_allocator);

        // RFC 6455: WebSocket upgrade — hand off to WebSocket handler
        // Per-route ws_handler (from Router) takes precedence over global config.
        if (response.status == .switching_protocols) {
            const ws = response.ws_handler orelse self.config.websocket_handler;
            if (ws) |ws_handler| {
                var ws_buf: [65536]u8 = undefined;
                var ws_conn = WebSocket.Conn.init(reader, writer, &ws_buf);
                ws_handler(&ws_conn, &request);
            }
            return;
        }

        // RFC 2616 Section 8.1: Check if connection should persist
        if (!Connection.shouldKeepAlive(&request)) {
            return;
        }

        // NOTE: keep-alive timeout via SO_RCVTIMEO is not used because
        // it causes EAGAIN panics in Zig's threaded I/O backend.
    }
}

fn handleConnectionTask(self: *Server, stream: Io.net.Stream, io: Io) Io.Cancelable!void {
    defer stream.close(io);
    defer if (self.config.max_connections > 0) {
        _ = self.active_connections.fetchSub(1, .release);
    };

    // Register this connection with the sweeper so it can detect peer FIN
    // (POLLRDHUP) and break us out of a stuck handler via shutdown(). The
    // sweeper itself never closes the fd — the defer above does that — so
    // there's no double-close race.
    if (self.sweeper) |sw| sw.register(stream.socket.handle);
    defer if (self.sweeper) |sw| sw.unregister(stream.socket.handle);

    self.handleConnection(stream, io) catch |err| {
        std.debug.print("Connection error: {}\n", .{err});
    };
}

fn rejectBusyConnection(stream: Io.net.Stream, io: Io) void {
    defer stream.close(io);

    var write_buf: [8192]u8 = undefined;
    var writer = Io.net.Stream.Writer.init(stream, io, &write_buf);
    const resp: Response = .{
        .status = .service_unavailable,
        .body = "Server busy",
    };
    var resp_buf: [Response.max_response_header_len]u8 = undefined;
    const resp_data = resp.serialize(&resp_buf) catch return;
    writer.interface.writeAll(resp_data) catch return;
    writer.interface.flush() catch return;
}

/// RFC 2616 Section 9.9: Handle CONNECT method for proxy tunneling.
///
/// Establishes a TCP tunnel between the client and the target authority.
/// After sending "200 Connection Established", raw bytes are forwarded
/// bidirectionally until either side closes the connection.
///
/// Note: Bidirectional forwarding uses an alternating read loop. For
/// full-duplex tunneling (e.g., TLS), the async Io backend is recommended.
fn handleConnect(self: *Server, client_stream: Io.net.Stream, io: Io, request: *const Request, client_writer: *Io.net.Stream.Writer) !void {
    const authority = Proxy.parseAuthority(request.uri) orelse {
        const resp: Response = .{ .status = .bad_request, .body = "Invalid CONNECT authority" };
        var resp_buf: [Response.max_response_header_len]u8 = undefined;
        const resp_data = resp.serialize(&resp_buf) catch return;
        client_writer.interface.writeAll(resp_data) catch return;
        client_writer.interface.flush() catch return;
        return;
    };

    // Proxy access control: check allowed ports
    const proxy_cfg = self.config.proxy;
    if (proxy_cfg.allowed_ports.len > 0) {
        var port_allowed = false;
        for (proxy_cfg.allowed_ports) |p| {
            if (p == authority.port) {
                port_allowed = true;
                break;
            }
        }
        if (!port_allowed) {
            const resp: Response = .{ .status = .forbidden, .body = "Port not allowed" };
            var resp_buf: [Response.max_response_header_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            client_writer.interface.writeAll(resp_data) catch return;
            client_writer.interface.flush() catch return;
            return;
        }
    }

    // Proxy access control: check allowed hosts
    if (proxy_cfg.allowed_hosts.len > 0) {
        var host_allowed = false;
        for (proxy_cfg.allowed_hosts) |h| {
            if (Headers.eqlIgnoreCase(h, authority.host)) {
                host_allowed = true;
                break;
            }
        }
        if (!host_allowed) {
            const resp: Response = .{ .status = .forbidden, .body = "Host not allowed" };
            var resp_buf: [Response.max_response_header_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            client_writer.interface.writeAll(resp_data) catch return;
            client_writer.interface.flush() catch return;
            return;
        }
    }

    // Proxy access control: block private/loopback IPs (SSRF protection)
    if (proxy_cfg.block_private_ips) {
        if (isPrivateIp(authority.host)) {
            const resp: Response = .{ .status = .forbidden, .body = "Private IP targets not allowed" };
            var resp_buf: [Response.max_response_header_len]u8 = undefined;
            const resp_data = resp.serialize(&resp_buf) catch return;
            client_writer.interface.writeAll(resp_data) catch return;
            client_writer.interface.flush() catch return;
            return;
        }
    }

    // Connect to the target server.
    const target_addr = Io.net.IpAddress.parseIp4(authority.host, authority.port) catch {
        const resp: Response = .{ .status = .bad_gateway, .body = "Cannot resolve target" };
        var resp_buf: [Response.max_response_header_len]u8 = undefined;
        const resp_data = resp.serialize(&resp_buf) catch return;
        client_writer.interface.writeAll(resp_data) catch return;
        client_writer.interface.flush() catch return;
        return;
    };

    const target_stream = Io.net.IpAddress.connect(&target_addr, io, .{ .mode = .stream }) catch {
        const resp: Response = .{ .status = .bad_gateway, .body = "Connection to target failed" };
        var resp_buf: [Response.max_response_header_len]u8 = undefined;
        const resp_data = resp.serialize(&resp_buf) catch return;
        client_writer.interface.writeAll(resp_data) catch return;
        client_writer.interface.flush() catch return;
        return;
    };
    defer target_stream.close(io);

    // Apply read timeout to the target socket to prevent a stalled target
    // from holding the tunnel (and connection slot) open indefinitely.
    const tunnel_timeout = if (self.config.keep_alive_timeout_s > 0)
        self.config.keep_alive_timeout_s
    else
        60;
    setSocketTimeout(target_stream.socket.handle, tunnel_timeout);

    // Send 200 Connection Established to the client.
    var est_buf: [64]u8 = undefined;
    const est_resp = Proxy.connectionEstablishedResponse(&est_buf) orelse return;
    client_writer.interface.writeAll(est_resp) catch return;
    client_writer.interface.flush() catch return;

    // Set up target reader/writer.
    var target_read_buf: [8192]u8 = undefined;
    var target_write_buf: [8192]u8 = undefined;
    var target_reader = Io.net.Stream.Reader.init(target_stream, io, &target_read_buf);
    var target_writer = Io.net.Stream.Writer.init(target_stream, io, &target_write_buf);

    // Set up client reader for tunnel (reuse existing stream).
    var tunnel_read_buf: [8192]u8 = undefined;
    var tunnel_reader = Io.net.Stream.Reader.init(client_stream, io, &tunnel_read_buf);

    // Bidirectional forwarding loop.
    // Alternates reading from each side and forwarding to the other.
    while (true) {
        // Client -> Target
        const client_data = tunnel_reader.interface.takeDelimiterInclusive(0) catch |err| switch (err) {
            error.StreamTooLong => tunnel_reader.interface.buffered(),
            error.EndOfStream => {
                // Forward any remaining buffered data
                const remaining = tunnel_reader.interface.buffered();
                if (remaining.len > 0) {
                    target_writer.interface.writeAll(remaining) catch break;
                    target_writer.interface.flush() catch break;
                }
                break;
            },
            error.ReadFailed => break,
        };
        if (client_data.len > 0) {
            target_writer.interface.writeAll(client_data) catch break;
            target_writer.interface.flush() catch break;
            tunnel_reader.interface.toss(client_data.len);
        }

        // Target -> Client
        const target_data = target_reader.interface.takeDelimiterInclusive(0) catch |err| switch (err) {
            error.StreamTooLong => target_reader.interface.buffered(),
            error.EndOfStream => {
                const remaining = target_reader.interface.buffered();
                if (remaining.len > 0) {
                    client_writer.interface.writeAll(remaining) catch break;
                    client_writer.interface.flush() catch break;
                }
                break;
            },
            error.ReadFailed => break,
        };
        if (target_data.len > 0) {
            client_writer.interface.writeAll(target_data) catch break;
            client_writer.interface.flush() catch break;
            target_reader.interface.toss(target_data.len);
        }
    }
}

/// Read HTTP headers from the stream, line by line until the blank line
/// terminator (\r\n\r\n). Returns the number of bytes read including
/// the terminator.
fn readHeaders(reader: *Io.Reader, buf: []u8) Io.Reader.Error!usize {
    var total: usize = 0;

    while (total < buf.len) {
        const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.StreamTooLong => return total,
            error.EndOfStream => {
                const remaining = reader.buffered();
                if (remaining.len > 0 and total + remaining.len <= buf.len) {
                    @memcpy(buf[total..][0..remaining.len], remaining);
                    total += remaining.len;
                    reader.toss(remaining.len);
                }
                if (total > 0) return total;
                return error.EndOfStream;
            },
            error.ReadFailed => return error.ReadFailed,
        };

        if (total + line.len > buf.len) return total;
        @memcpy(buf[total..][0..line.len], line);
        total += line.len;

        // Check if this was the blank line terminator (just \r\n)
        if (line.len == 2 and line[0] == '\r' and line[1] == '\n') {
            return total;
        }
    }

    return total;
}

const ReadChunkedBodyError = Io.Reader.Error || error{
    BodyTooLarge,
    InvalidChunkedEncoding,
};

/// Read a chunked request body from the stream into the buffer.
/// Reads chunk-size lines and chunk data until the last-chunk (0\r\n)
/// and the trailing CRLF. Returns the total bytes in the buffer
/// (headers + raw chunked body).
///
/// Each chunk-size is validated against the remaining buffer space
/// to prevent a malicious chunk-size from causing excessive reads.
fn readChunkedBody(reader: *Io.Reader, buf: *[]u8, start: usize, max_size: usize) ReadChunkedBodyError!usize {
    var total = start;
    while (true) {
        const line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.StreamTooLong => return error.InvalidChunkedEncoding,
            error.EndOfStream => return if (total > start) total else error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };
        const chunk_size = parseChunkSizeLine(line) catch return error.InvalidChunkedEncoding;
        try ensureRequestCapacity(buf, total + line.len, max_size);
        @memcpy(buf.*[total..][0..line.len], line);
        total += line.len;

        if (chunk_size == 0) {
            while (true) {
                const trailer_line = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
                    error.StreamTooLong => return error.InvalidChunkedEncoding,
                    error.EndOfStream => return error.InvalidChunkedEncoding,
                    error.ReadFailed => return error.ReadFailed,
                };
                if (trailer_line.len < 2 or trailer_line[trailer_line.len - 2] != '\r' or trailer_line[trailer_line.len - 1] != '\n') {
                    return error.InvalidChunkedEncoding;
                }
                try ensureRequestCapacity(buf, total + trailer_line.len, max_size);
                @memcpy(buf.*[total..][0..trailer_line.len], trailer_line);
                total += trailer_line.len;
                if (trailer_line.len == 2) {
                    return total;
                }
            }
        }

        // chunk_size comes from parseInt and may be as large as maxInt(usize);
        // guard the addition with saturating subtraction to avoid overflow.
        if (chunk_size > max_size -| total -| 2) return error.BodyTooLarge;
        try ensureRequestCapacity(buf, total + chunk_size + 2, max_size);
        reader.readSliceAll(buf.*[total..][0 .. chunk_size + 2]) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };
        if (buf.*[total + chunk_size] != '\r' or buf.*[total + chunk_size + 1] != '\n') {
            return error.InvalidChunkedEncoding;
        }
        total += chunk_size + 2;
    }
}

fn parseChunkSizeLine(line: []const u8) error{InvalidChunkedEncoding}!usize {
    if (line.len < 2 or line[line.len - 2] != '\r' or line[line.len - 1] != '\n') {
        return error.InvalidChunkedEncoding;
    }

    const size_part = line[0 .. line.len - 2];
    const size_str = if (std.mem.indexOfScalar(u8, size_part, ';')) |semi|
        size_part[0..semi]
    else
        size_part;
    const trimmed = Request.trimOws(size_str);
    if (trimmed.len == 0) {
        return error.InvalidChunkedEncoding;
    }
    return std.fmt.parseInt(usize, trimmed, 16) catch error.InvalidChunkedEncoding;
}

fn initialRequestBufferSize(config: Config) usize {
    const target = @max(config.max_header_size, min_initial_request_buffer_size);
    return @max(@as(usize, 1), @min(config.max_request_size, target));
}

fn ensureRequestCapacity(buf: *[]u8, needed: usize, max_size: usize) error{BodyTooLarge}!void {
    if (needed <= buf.*.len) return;
    if (needed > max_size) return error.BodyTooLarge;

    var new_len = buf.*.len;
    while (new_len < needed) {
        if (new_len >= max_size) {
            new_len = max_size;
            break;
        }
        new_len = @min(max_size, if (new_len == 0) min_initial_request_buffer_size else new_len * 2);
    }
    buf.* = std.heap.page_allocator.realloc(buf.*, new_len) catch return error.BodyTooLarge;
}

fn isAllZeros(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c != '0') return false;
    }
    return true;
}

/// Find the \r\n\r\n that marks the end of HTTP headers.
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

/// Quick extraction of Content-Length from raw header bytes without full parsing.
/// Delegates to extractHeaderValue for robust case-insensitive matching.
fn extractContentLength(headers: []const u8) ?usize {
    const val = extractHeaderValue(headers, "content-length") orelse return null;
    return std.fmt.parseInt(usize, val, 10) catch null;
}

/// Extract the value of a named header from raw header bytes (case-insensitive).
fn extractHeaderValue(headers: []const u8, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < headers.len) {
        const line_end = blk: {
            var j = pos;
            while (j + 1 < headers.len) : (j += 1) {
                if (headers[j] == '\r' and headers[j + 1] == '\n') break :blk j;
            }
            break :blk headers.len;
        };
        const line = headers[pos..line_end];
        pos = if (line_end + 2 <= headers.len) line_end + 2 else headers.len;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const header_name = line[0..colon];
        if (header_name.len == name.len and Headers.eqlIgnoreCase(header_name, name)) {
            return Request.trimOws(line[colon + 1 ..]);
        }
    }
    return null;
}

/// RFC 2616 Section 8.1.4: Set SO_RCVTIMEO on a socket to enforce
/// idle connection timeouts. When the timeout expires, reads return
/// an error and the connection is closed.
fn setSocketTimeout(handle: Io.net.Socket.Handle, timeout_s: u32) void {
    const timeval = std.posix.timeval{
        .sec = @intCast(timeout_s),
        .usec = 0,
    };
    std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeval)) catch |err| {
        std.log.warn("setsockopt SO_RCVTIMEO failed: {}", .{err});
    };
}

/// Check if a host string is a private/loopback target.
/// Blocks: known loopback hostnames, IPv6 loopback variants,
/// 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
/// 169.254.0.0/16 (link-local), and 0.0.0.0.
///
/// Note: This cannot protect against DNS rebinding attacks where a
/// hostname resolves to a private IP. For full SSRF protection,
/// the resolved IP should be checked after DNS resolution.
fn isPrivateIp(host: []const u8) bool {
    // Block well-known loopback/private hostnames (case-insensitive)
    if (Headers.eqlIgnoreCase(host, "localhost")) return true;
    if (Headers.eqlIgnoreCase(host, "localhost.localdomain")) return true;

    // IPv6 loopback in various forms
    if (std.mem.eql(u8, host, "::1")) return true;
    if (std.mem.eql(u8, host, "[::1]")) return true;
    if (std.mem.eql(u8, host, "0:0:0:0:0:0:0:1")) return true;
    if (std.mem.eql(u8, host, "[0:0:0:0:0:0:0:1]")) return true;

    // IPv6-mapped IPv4 loopback
    if (std.mem.startsWith(u8, host, "::ffff:") or std.mem.startsWith(u8, host, "::FFFF:")) {
        const mapped = host[7..];
        const mapped_octets = parseIpv4Octets(mapped) orelse return false;
        return isPrivateOctets(mapped_octets);
    }

    if (std.mem.eql(u8, host, "0.0.0.0")) return true;

    // Parse IPv4 octets
    const octets = parseIpv4Octets(host) orelse return false;

    return isPrivateOctets(octets);
}

fn isPrivateOctets(octets: [4]u8) bool {
    // 127.0.0.0/8
    if (octets[0] == 127) return true;
    // 0.0.0.0/8
    if (octets[0] == 0) return true;
    // 10.0.0.0/8
    if (octets[0] == 10) return true;
    // 172.16.0.0/12
    if (octets[0] == 172 and octets[1] >= 16 and octets[1] <= 31) return true;
    // 192.168.0.0/16
    if (octets[0] == 192 and octets[1] == 168) return true;
    // 169.254.0.0/16 (link-local)
    if (octets[0] == 169 and octets[1] == 254) return true;
    return false;
}

fn parseIpv4Octets(host: []const u8) ?[4]u8 {
    var octets: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var current: u16 = 0;
    var has_digit = false;

    for (host) |c| {
        if (c == '.') {
            if (!has_digit or octet_idx >= 3) return null;
            if (current > 255) return null;
            octets[octet_idx] = @intCast(current);
            octet_idx += 1;
            current = 0;
            has_digit = false;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            has_digit = true;
        } else {
            return null;
        }
    }
    if (!has_digit or octet_idx != 3) return null;
    if (current > 255) return null;
    octets[3] = @intCast(current);
    return octets;
}

// --- Tests ---

const testing = std.testing;

// RFC 2616 Section 4: findHeaderEnd locates the blank line (CRLFCRLF)
// that separates headers from body.
test "Server: findHeaderEnd" {
    try testing.expectEqual(@as(?usize, 0), findHeaderEnd("\r\n\r\n"));
    try testing.expectEqual(@as(?usize, 5), findHeaderEnd("hello\r\n\r\n"));
    try testing.expect(findHeaderEnd("hello\r\n") == null);
    try testing.expect(findHeaderEnd("") == null);
    try testing.expect(findHeaderEnd("\r\n") == null);
}

// /// RFC 2616 Section 14.13: extractContentLength from raw headers
test "Server: extractContentLength" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n";
    try testing.expectEqual(@as(?usize, 42), extractContentLength(headers));
}

// /// RFC 2616 Section 14.13: extractContentLength case-insensitive
test "Server: extractContentLength case-insensitive" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\ncontent-length: 100\r\n";
    try testing.expectEqual(@as(?usize, 100), extractContentLength(headers));
}

// /// RFC 2616 Section 14.13: extractContentLength missing
test "Server: extractContentLength missing" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\n";
    try testing.expect(extractContentLength(headers) == null);
}

// /// Server init
test "Server: init" {
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: Io, _: *const Request) Response {
            return Response.init(.ok, "text/plain", "OK");
        }
    }.handle;

    const srv = Server.init(.{}, handler);
    try testing.expectEqual(@as(u16, 8080), srv.config.port);
}

// RFC 2616 Section 8.2.3: extractHeaderValue for Expect header
test "Server: extractHeaderValue" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\n\r\n";
    const val = extractHeaderValue(headers, "expect");
    try testing.expect(val != null);
    try testing.expectEqualStrings("100-continue", val.?);
}

// RFC 2616 Section 8.2.3: extractHeaderValue missing
test "Server: extractHeaderValue missing" {
    const headers = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try testing.expect(extractHeaderValue(headers, "expect") == null);
}

// isAllZeros utility
test "Server: isAllZeros" {
    try testing.expect(isAllZeros("0"));
    try testing.expect(isAllZeros("000"));
    try testing.expect(!isAllZeros("01"));
    try testing.expect(!isAllZeros("a"));
    try testing.expect(!isAllZeros(""));
}

// Private IP detection for proxy SSRF protection
test "Server: isPrivateIp loopback" {
    try testing.expect(isPrivateIp("127.0.0.1"));
    try testing.expect(isPrivateIp("127.255.255.255"));
    try testing.expect(isPrivateIp("::1"));
    try testing.expect(isPrivateIp("0.0.0.0"));
}

test "Server: isPrivateIp private ranges" {
    try testing.expect(isPrivateIp("10.0.0.1"));
    try testing.expect(isPrivateIp("10.255.255.255"));
    try testing.expect(isPrivateIp("172.16.0.1"));
    try testing.expect(isPrivateIp("172.31.255.255"));
    try testing.expect(isPrivateIp("192.168.0.1"));
    try testing.expect(isPrivateIp("192.168.255.255"));
    try testing.expect(isPrivateIp("169.254.1.1"));
}

test "Server: isPrivateIp public IPs" {
    try testing.expect(!isPrivateIp("8.8.8.8"));
    try testing.expect(!isPrivateIp("1.1.1.1"));
    try testing.expect(!isPrivateIp("203.0.113.1"));
    try testing.expect(!isPrivateIp("172.32.0.1"));
    try testing.expect(!isPrivateIp("172.15.255.255"));
}

test "Server: isPrivateIp hostnames and aliases" {
    try testing.expect(isPrivateIp("localhost"));
    try testing.expect(isPrivateIp("LOCALHOST"));
    try testing.expect(isPrivateIp("localhost.localdomain"));
    try testing.expect(!isPrivateIp("example.com"));
    try testing.expect(!isPrivateIp(""));
}

test "Server: isPrivateIp IPv6 variants" {
    try testing.expect(isPrivateIp("[::1]"));
    try testing.expect(isPrivateIp("0:0:0:0:0:0:0:1"));
    try testing.expect(isPrivateIp("[0:0:0:0:0:0:0:1]"));
    try testing.expect(isPrivateIp("::ffff:127.0.0.1"));
    try testing.expect(isPrivateIp("::ffff:10.0.0.1"));
    try testing.expect(!isPrivateIp("::ffff:8.8.8.8"));
}

test "Server: parseIpv4Octets" {
    const valid = parseIpv4Octets("192.168.1.1").?;
    try testing.expectEqual(@as(u8, 192), valid[0]);
    try testing.expectEqual(@as(u8, 168), valid[1]);
    try testing.expectEqual(@as(u8, 1), valid[2]);
    try testing.expectEqual(@as(u8, 1), valid[3]);

    try testing.expect(parseIpv4Octets("256.0.0.1") == null);
    try testing.expect(parseIpv4Octets("1.2.3") == null);
    try testing.expect(parseIpv4Octets("1.2.3.4.5") == null);
    try testing.expect(parseIpv4Octets("abc") == null);
    try testing.expect(parseIpv4Octets("") == null);
}

// ProxyConfig defaults
test "Server: ProxyConfig defaults" {
    const cfg: ProxyConfig = .{};
    try testing.expect(cfg.block_private_ips);
    try testing.expectEqual(@as(usize, 1), cfg.allowed_ports.len);
    try testing.expectEqual(@as(u16, 443), cfg.allowed_ports[0]);
    try testing.expectEqual(@as(usize, 0), cfg.allowed_hosts.len);
}

// Config defaults
test "Server: Config defaults include trace disabled" {
    const cfg: Config = .{};
    try testing.expect(!cfg.enable_trace);
    try testing.expect(!cfg.enable_proxy);
    try testing.expectEqual(@as(u32, 512), cfg.max_connections);
}

test "Server: initialRequestBufferSize defaults to header cap" {
    const cfg: Config = .{};
    try testing.expectEqual(@as(usize, 65536), initialRequestBufferSize(cfg));
}

test "Server: initialRequestBufferSize respects smaller request cap" {
    const cfg: Config = .{
        .max_request_size = 32768,
        .max_header_size = 65536,
    };
    try testing.expectEqual(@as(usize, 32768), initialRequestBufferSize(cfg));
}

test "Server: parseChunkSizeLine accepts extensions and whitespace" {
    try testing.expectEqual(@as(usize, 10), try parseChunkSizeLine(" A ;foo=bar\r\n"));
}

test "Server: parseChunkSizeLine rejects malformed lines" {
    try testing.expectError(error.InvalidChunkedEncoding, parseChunkSizeLine("\r\n"));
    try testing.expectError(error.InvalidChunkedEncoding, parseChunkSizeLine("ZZ\r\n"));
    try testing.expectError(error.InvalidChunkedEncoding, parseChunkSizeLine("1\n"));
}

// Connection counter
test "Server: active_connections counter" {
    const handler = struct {
        fn handle(_: std.mem.Allocator, _: Io, _: *const Request) Response {
            return Response.init(.ok, "text/plain", "OK");
        }
    }.handle;
    var srv = Server.init(.{}, handler);
    try testing.expectEqual(@as(u32, 0), srv.active_connections.load(.monotonic));
    _ = srv.active_connections.fetchAdd(1, .monotonic);
    try testing.expectEqual(@as(u32, 1), srv.active_connections.load(.monotonic));
    _ = srv.active_connections.fetchSub(1, .monotonic);
    try testing.expectEqual(@as(u32, 0), srv.active_connections.load(.monotonic));
}

// CLOSE-WAIT sweeper unit test.
//
// Creates a UNIX socketpair, registers the server-side fd with a sweeper, then
// closes the client end so the server-side fd transitions to CLOSE_WAIT. The
// sweeper's poll() must observe POLLRDHUP and call shutdown(SHUT_RDWR) on the
// server-side fd within a short interval. We detect "shutdown happened" by
// observing that a subsequent send() on the fd fails (EPIPE) or that
// recv()/read() returns 0.
test "Server: ConnSweeper detects peer FIN and shuts down the fd" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const posix = std.posix;

    // socketpair gives two endpoints, both AF_UNIX SOCK_STREAM.
    var sv: [2]std.c.fd_t = .{ -1, -1 };
    const sp_rc = posix.system.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &sv);
    if (posix.errno(sp_rc) != .SUCCESS) return error.SkipZigTest;
    defer {
        if (sv[0] >= 0) _ = posix.system.close(sv[0]);
        if (sv[1] >= 0) _ = posix.system.close(sv[1]);
    }
    // Treat sv[1] as the "server-accepted" fd; sv[0] as the "client" fd.

    var sweeper: ConnSweeper = .{
        .allocator = testing.allocator,
        .interval_ms = 25, // poll quickly so the test is snappy
    };
    sweeper.thread = try std.Thread.spawn(.{}, ConnSweeper.run, .{&sweeper});
    defer {
        sweeper.stop.store(true, .release);
        if (sweeper.thread) |t| t.join();
        sweeper.fds.deinit(sweeper.allocator);
    }

    sweeper.register(sv[1]);
    defer sweeper.unregister(sv[1]);

    // Client closes — this is the peer-FIN equivalent.
    _ = posix.system.close(sv[0]);
    sv[0] = -1;

    // Wait up to ~1s for the sweeper to shut down the server-accepted side.
    // Probe via send(); after shutdown(SHUT_WR), send() returns EPIPE.
    var i: usize = 0;
    const probe = [_]u8{'x'};
    while (i < 40) : (i += 1) {
        var req = posix.timespec{ .sec = 0, .nsec = 25 * std.time.ns_per_ms };
        while (posix.errno(posix.system.nanosleep(&req, &req)) == .INTR) {}
        const rc = posix.system.send(sv[1], &probe, probe.len, std.c.MSG.NOSIGNAL);
        const e = posix.errno(rc);
        if (e == .PIPE) return; // success — write side shut down
    }
    return error.TestExpectedFailure;
}
