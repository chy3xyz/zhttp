//! Thin adapter between the native HTTP/3 server and zhttp's HTTP/1.1
//! Router/Connection machinery.
//!
//! The H3 server hands us an `h3.Request`; we convert it to the zhttp
//! `Request` the Router and Connection layers understand, run it through
//! `Connection.processRequestWithOptions`, and convert the resulting zhttp
//! `Response` back to the `h3.Response` the HTTP/3 session can send.
//!
//! ## Arena and slice lifetime
//!
//! Each `Adapter` owns one arena. `handle` resets it at entry, so every
//! allocation made while converting a request — response header names and
//! values, content types, buffered stream bodies — belongs to one request.
//! **All slices in the returned `h3.Response` are valid only until the next
//! call to `handle` on the same adapter.** The HTTP/3 session consumes the
//! response synchronously (it QPACK-encodes the headers and copies the body
//! into DATA frames before returning to its event loop), so this contract is
//! sufficient for the normal server path.
//!
//! The adapter is intentionally not thread-safe: one adapter is used by the
//! single-threaded H3 server event loop.
//!
//! ## Request conversion notes
//!
//! HTTP/3 has no request line or HTTP/1.x version. The converted request uses
//! `.http_1_1` as the version sentinel (the only non-1.0 value available) and
//! an empty `raw`; TRACE therefore echoes an empty body if trace is enabled.
//! `:authority` is exposed as a `Host` header, since zhttp's Request has no
//! authority field. Request slices (URI, headers, body) borrow from the h3
//! request and are valid for the duration of `handle`.
//!
//! WebSocket upgrades are not supported over HTTP/3 (that would require
//! extended CONNECT, which this stack does not negotiate). A response that is
//! 101 Switching Protocols or carries a WebSocket handler is converted to a
//! 501 Not Implemented response instead.

const std = @import("std");
const Connection = @import("../server/Connection.zig");
const Date = @import("../server/Date.zig");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const h3 = @import("Server.zig");

const OptionsImpl = struct {
    /// Passed through to `Connection.processRequestWithOptions`.
    enable_trace: bool = false,
    /// Maximum number of streamed response bytes buffered per request.
    /// A `stream_fn` that writes more than this is answered with 500.
    max_buffered_stream: usize = 1 << 20,
};

pub const Adapter = struct {
    /// Options accepted by `create`.
    pub const Options = OptionsImpl;

    allocator: std.mem.Allocator,
    io: std.Io,
    handler: Connection.Handler,
    options: OptionsImpl,
    arena: std.heap.ArenaAllocator,

    /// Create an adapter. `gpa` owns the adapter and its arena; the handler is
    /// the same `Connection.Handler` a TCP server would use.
    pub fn create(
        gpa: std.mem.Allocator,
        io: std.Io,
        handler: Connection.Handler,
        options: OptionsImpl,
    ) !*Adapter {
        const self = try gpa.create(Adapter);
        errdefer gpa.destroy(self);
        self.* = .{
            .allocator = gpa,
            .io = io,
            .handler = handler,
            .options = options,
            .arena = std.heap.ArenaAllocator.init(gpa),
        };
        return self;
    }

    /// Free the adapter and every allocation its arena still holds.
    pub fn destroy(self: *Adapter) void {
        const gpa = self.allocator;
        self.arena.deinit();
        gpa.destroy(self);
    }

    /// The context handler for `h3.Server.initWithContext`. Pass the adapter
    /// pointer as the server's context.
    pub fn contextHandler() h3.ContextHandler {
        return handle;
    }

    fn handle(context: ?*anyopaque, _: std.mem.Allocator, request: *const h3.Request) h3.Response {
        const self: *Adapter = @ptrCast(@alignCast(context orelse return serverError()));
        return self.handleRequest(request);
    }

    fn handleRequest(self: *Adapter, request: *const h3.Request) h3.Response {
        // Contract: every slice returned by the previous call dies here.
        _ = self.arena.reset(.retain_capacity);
        const arena = self.arena.allocator();

        const converted = convertRequest(request);
        const response = Connection.processRequestWithOptions(
            arena,
            self.io,
            Date.now(self.io),
            &converted,
            self.handler,
            .{ .enable_trace = self.options.enable_trace },
        );
        return self.convertResponse(arena, response) catch serverError();
    }

    fn convertResponse(
        self: *Adapter,
        arena: std.mem.Allocator,
        response: Response,
    ) !h3.Response {
        // Release any Response-owned body/TLS storage after we copy what the
        // H3 response needs. With the adapter arena this is a no-op for
        // arena-owned bodies, but it also makes handlers that return a
        // Response.json()-style allocation safe.
        var owned = response;
        defer owned.deinit(arena);

        // A 101 only makes sense for a protocol upgrade. HTTP/3 WebSocket
        // needs extended CONNECT, which this stack does not implement.
        if (response.status == .switching_protocols or response.ws_handler != null) {
            return notImplemented();
        }

        const content_type = if (response.headers.get("Content-Type")) |value|
            try arena.dupe(u8, value)
        else
            "text/plain";

        // Allocate the worst case up front; skipped headers leave a tail that
        // is simply not exposed. The returned slice points into the arena.
        const storage = try arena.alloc(h3.Header, response.headers.len);
        var count: usize = 0;
        for (response.headers.entries[0..response.headers.len]) |header| {
            if (header.name.len == 0) continue;
            if (skipResponseHeader(header.name)) continue;
            const name = try lowerDupe(arena, header.name);
            // Duplicate unconditionally: the value may point into the zhttp
            // Response's embedded Date buffer or a handler's stack frame, and
            // the returned h3.Response must outlive both.
            const value = try arena.dupe(u8, header.value);
            storage[count] = .{ .name = name, .value = value };
            count += 1;
        }

        var converted: h3.Response = .{
            .status = response.status,
            .content_type = content_type,
            .headers = if (count == 0) &.{} else storage[0..count],
        };

        if (response.stream_fn) |stream_fn| {
            // sendFile's stream function owns an fd and closes it in a defer;
            // it must run even when the data does not fit. A one-byte buffer
            // keeps Writer.sendFileAll's non-empty-buffer assertion satisfied
            // when max_buffered_stream is zero; the cap check below catches
            // any byte written in that configuration.
            var fallback: [1]u8 = undefined;
            var allocation_failed = false;
            const buffer = arena.alloc(u8, @max(self.options.max_buffered_stream, 1)) catch blk: {
                allocation_failed = true;
                break :blk fallback[0..];
            };
            var sink = StreamSink{
                .writer = .{
                    .vtable = &.{
                        .drain = StreamSink.drain,
                        .flush = std.Io.Writer.noopFlush,
                    },
                    .buffer = buffer,
                },
            };
            stream_fn(response.stream_context, &sink.writer);

            if (allocation_failed or sink.overflow or sink.writer.end > self.options.max_buffered_stream) {
                return serverError();
            }
            converted.body = buffer[0..sink.writer.end];
        } else {
            // Duplicate the body as well: it can point into request-owned or
            // handler-owned memory (and must not point into this stack frame).
            converted.body = try arena.dupe(u8, response.body);
        }

        return converted;
    }
};

/// Top-level alias, so both `Adapter.zig.Options` and `Adapter.Options` work.
pub const Options = OptionsImpl;

/// Convert an HTTP/3 request to the HTTP/1.1-shaped request zhttp speaks.
///
/// Request slices borrow from `request`; they stay valid for the duration of
/// the handler call. The fields are assigned one by one rather than with an
/// aggregate initializer because Request is large and contains undefined
/// entry arrays (the same reason Request.parse initializes them this way).
fn convertRequest(request: *const h3.Request) Request {
    var converted: Request = undefined;
    converted.method = request.method;
    converted.uri = request.path;
    // HTTP/3 has no HTTP/1.x version. There is no HTTP/3 variant in
    // Request.Version, so 1.1 is the sentinel the rest of the stack expects.
    converted.version = .http_1_1;
    converted.headers = .{ .len = 0 };
    converted.body = request.body;
    // No raw HTTP/1-style message exists for an HTTP/3 request. TRACE (only
    // enabled via Options.enable_trace) will echo an empty body.
    converted.raw = "";
    converted.params = .{ .len = 0 };
    converted.action = null;
    converted.context = .{ .len = 0 };

    for (request.headers.entries[0..request.headers.len]) |header| {
        if (header.name.len == 0 or header.name[0] == ':') continue;
        converted.headers.append(header.name, header.value) catch continue;
    }
    // Preserve :authority for handlers that read Host. Do not overwrite an
    // explicit Host field if the peer sent one too.
    if (request.authority.len > 0 and converted.headers.get("Host") == null) {
        converted.headers.append("Host", request.authority) catch {};
    }

    return converted;
}

/// Headers that describe an HTTP/1.1 hop or framing and must not be copied to
/// HTTP/3. Content-Type moves to h3.Response.content_type; Content-Length is
/// computed by the HTTP/3 session from the body it actually sends.
fn skipResponseHeader(name: []const u8) bool {
    const skipped = [_][]const u8{
        "content-type",
        "content-length",
        "connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "keep-alive",
    };
    inline for (skipped) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    return false;
}

fn lowerDupe(allocator: std.mem.Allocator, name: []const u8) ![]const u8 {
    const lowered = try allocator.dupe(u8, name);
    for (lowered) |*byte| byte.* = std.ascii.toLower(byte.*);
    return lowered;
}

fn serverError() h3.Response {
    return .{
        .status = .internal_server_error,
        .content_type = "text/plain",
        .body = "Internal Server Error",
    };
}

fn notImplemented() h3.Response {
    return .{
        .status = .not_implemented,
        .content_type = "text/plain",
        .body = "Not Implemented",
    };
}

/// Writer sink that counts overflow. The fixed writer reports WriteFailed when
/// the buffer is full, which the stream function may swallow; the flag records
/// that the body did not fit so handle can answer 500 after the function has
/// had its chance to release resources.
const StreamSink = struct {
    writer: std.Io.Writer,
    overflow: bool = false,

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *StreamSink = @alignCast(@fieldParentPtr("writer", w));
        return std.Io.Writer.fixedDrain(w, data, splat) catch |err| {
            self.overflow = true;
            return err;
        };
    }
};

test {
    _ = @import("Adapter_test.zig");
}
