const std = @import("std");
const nghttp3 = @import("nghttp3_c");

pub const Error = error{
    H3Error,
    StreamClosed,
};

/// HTTP/3 application error codes (RFC 9114 — HTTP/3 error codes).
pub const H3_NO_ERROR: u64 = 0x0100;

/// Accumulated response state populated by nghttp3 callbacks. It is the state
/// nghttp3 hands back for a stream, so a client keeps the request body it is
/// still sending in here too.
pub const ResponseContext = struct {
    status: u16 = 0,
    headers: std.ArrayList(u8),
    body: std.ArrayList(u8),
    done: bool = false,
    allocator: std.mem.Allocator,
    /// Client side: the request body being sent, and how much of it has gone
    /// out. The bytes belong to the caller and have to outlive the request.
    request_body: []const u8 = &.{},
    request_body_sent: usize = 0,

    pub fn init(allocator: std.mem.Allocator) !ResponseContext {
        return .{
            .headers = try std.ArrayList(u8).initCapacity(allocator, 0),
            .body = try std.ArrayList(u8).initCapacity(allocator, 0),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ResponseContext) void {
        self.headers.deinit(self.allocator);
        self.body.deinit(self.allocator);
    }
};

/// One header field of a request, as it arrived. The bytes belong to the
/// request's arena and stay valid until the request is released.
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

/// Pulls the next chunk of a streamed response body: fill `buf` and return how
/// many bytes were written, 0 at the end of the body.
pub const BodyReader = *const fn (context: ?*anyopaque, buf: []u8) anyerror!usize;

/// A chunk of a streamed response body. ngtcp2 keeps the bytes it is given so
/// it can retransmit a lost packet ("The caller must keep the portion of data
/// covered by |*pdatalen| bytes intact until
/// :member:`ngtcp2_callbacks.acked_stream_data_offset` indicates that they are
/// acknowledged" — ngtcp2.h), so a chunk stays where it is until the peer
/// acknowledges it.
const BodyChunk = struct {
    buf: []u8,
    /// Offset in the body just past this chunk. The buffer holds nothing the
    /// peer may need once the acknowledgement has reached it.
    end: usize,
};

/// A request the server received, plus the response being sent for it. Answers
/// `nghttp3_conn_submit_response`'s need for a body that stays alive until the
/// stream closes.
///
/// Everything the request owns lives in `arena`, so releasing it is one
/// `deinit`, and the slices handed to the handler stay valid for as long as it
/// runs. nghttp3's own buffers do not outlive the callback that hands them over,
/// so the bytes are copied out of them as they arrive.
pub const ServerRequest = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    stream_id: i64,
    /// `:method`, as sent.
    method: []const u8 = "",
    /// `:path`, as sent; every other pseudo-header is dropped.
    path: []const u8 = "",
    /// The regular header fields, in the order they arrived.
    headers: std.ArrayList(HeaderField) = .empty,
    /// The request body. Drained while it arrives; what is kept is the whole
    /// body unless `body_too_large` is set.
    body: std.ArrayList(u8) = .empty,
    /// Largest body this request accepts. Credit for a body beyond it is
    /// returned to the peer anyway, so a large upload cannot stall the
    /// connection, but the request is answered with 413.
    max_body_bytes: usize,
    body_too_large: bool = false,
    /// Set once the request stream ended, i.e. the request is complete.
    complete: bool = false,
    /// Set once a response has been submitted for it.
    responded: bool = false,
    /// Response body, owned here until the stream closes. Empty for a response
    /// whose body is streamed (see `body_reader`).
    response_body: []const u8 = &.{},
    response_sent: usize = 0,
    /// Streamed response: where the next chunk of the body comes from, and what
    /// it is passed. Set by `submitStreamingResponse`.
    body_reader: ?BodyReader = null,
    body_context: ?*anyopaque = null,
    /// The buffer the reader fills. Every chunk is read out of it and copied
    /// into a buffer of its own, so the same buffer serves the whole response;
    /// it is taken from the arena with the first chunk, so a response that does
    /// not stream never allocates it.
    read_buf: []u8 = &.{},
    /// Chunks handed to nghttp3 and not acknowledged yet. Bounded by the peer's
    /// flow control window: its bytes are what may still need resending.
    chunks: std.ArrayList(BodyChunk) = .empty,
    /// Body bytes handed to nghttp3, and how many of them the peer has
    /// acknowledged (see `ackedStreamDataCb`).
    body_sent: usize = 0,
    body_acked: usize = 0,
    /// Set once the reader has reported the end of the body.
    body_eof: bool = false,

    pub fn init(allocator: std.mem.Allocator, stream_id: i64, max_body_bytes: usize) !*ServerRequest {
        const req = try allocator.create(ServerRequest);
        req.* = .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .stream_id = stream_id,
            .max_body_bytes = max_body_bytes,
        };
        return req;
    }

    pub fn deinit(self: *ServerRequest) void {
        self.allocator.free(self.response_body);
        self.arena.deinit();
        self.allocator.destroy(self);
    }
};

pub const Session = struct {
    conn: *nghttp3.nghttp3_conn,
    callbacks: nghttp3.nghttp3_callbacks,
    allocator: std.mem.Allocator,
    /// Which side of the connection this session is. The nghttp2 callbacks use
    /// it to tell a request arriving at a server from a response arriving at a
    /// client: the two hang different state off the stream.
    server: bool,
    /// Server side: requests received, in arrival order. Completed but
    /// unanswered ones are picked up by the server.
    requests: std.ArrayList(*ServerRequest) = .empty,
    /// Largest request body a server-side session accepts (see
    /// `ServerRequest.max_body_bytes`).
    max_request_body_bytes: usize = default_max_request_body_bytes,

    /// What a request body may grow to when the caller does not say otherwise.
    pub const default_max_request_body_bytes = 1024 * 1024;

    pub fn init(allocator: std.mem.Allocator) !*Session {
        return create(allocator, false, 0, 0);
    }

    /// Create a server-side H3 session (for use in H3 server).
    pub fn initServer(allocator: std.mem.Allocator, max_client_streams_bidi: u64, max_body_bytes: usize) !*Session {
        return create(allocator, true, max_client_streams_bidi, max_body_bytes);
    }

    fn create(allocator: std.mem.Allocator, server: bool, max_client_streams_bidi: u64, max_body_bytes: usize) !*Session {
        const session = try allocator.create(Session);
        errdefer allocator.destroy(session);
        session.* = .{
            .conn = undefined,
            .callbacks = std.mem.zeroes(nghttp3.nghttp3_callbacks),
            .allocator = allocator,
            .server = server,
            .max_request_body_bytes = max_body_bytes,
        };

        session.callbacks.recv_header = recvHeaderCb;
        session.callbacks.recv_data = recvDataCb;
        session.callbacks.end_stream = endStreamCb;
        session.callbacks.begin_headers = beginHeadersCb;
        session.callbacks.stream_close = streamCloseCb;
        // A streamed response needs to know when the peer has taken what it
        // sent, since that is what frees a chunk (see `BodyChunk`).
        session.callbacks.acked_stream_data = ackedStreamDataCb;

        var settings: nghttp3.nghttp3_settings = undefined;
        nghttp3.nghttp3_settings_default(&settings);

        var conn_ptr: ?*nghttp3.nghttp3_conn = null;
        const ret = if (server)
            nghttp3.nghttp3_conn_server_new(&conn_ptr, &session.callbacks, &settings, null, @as(?*anyopaque, @ptrCast(session)))
        else
            nghttp3.nghttp3_conn_client_new(&conn_ptr, &session.callbacks, &settings, null, @as(?*anyopaque, @ptrCast(session)));
        if (ret != 0) return error.H3Error;

        session.conn = conn_ptr.?;
        if (server) {
            nghttp3.nghttp3_conn_set_max_client_streams_bidi(session.conn, max_client_streams_bidi);
        }
        return session;
    }

    pub fn deinit(self: *Session) void {
        for (self.requests.items) |req| req.deinit();
        self.requests.deinit(self.allocator);
        nghttp3.nghttp3_conn_del(self.conn);
        self.allocator.destroy(self);
    }

    /// Bind this endpoint's own control stream; HTTP/3 requires each endpoint to
    /// open one.
    pub fn bindControlStream(self: *Session, stream_id: i64) !void {
        if (nghttp3.nghttp3_conn_bind_control_stream(self.conn, stream_id) != 0) return error.H3Error;
    }

    /// Bind QPACK encoder and decoder streams to this H3 session.
    pub fn bindQpackStreams(self: *Session, enc_stream_id: i64, dec_stream_id: i64) !void {
        const ret = nghttp3.nghttp3_conn_bind_qpack_streams(self.conn, enc_stream_id, dec_stream_id);
        if (ret != 0) return error.H3Error;
    }

    /// Submit an HTTP/3 request on a QUIC stream. |state| is the
    /// `ResponseContext` the response callbacks fill in, and — when |body| is
    /// not empty — the one its bytes are read out of, so they have to outlive
    /// the request.
    ///
    /// |headers| are the regular fields to send after the pseudo-headers; the
    /// names have to be lowercase (RFC 9114 Section 4.2).
    pub fn submitRequest(
        self: *Session,
        stream_id: i64,
        method: []const u8,
        path: []const u8,
        authority: []const u8,
        headers: []const HeaderField,
        body: []const u8,
        state: *ResponseContext,
    ) !void {
        // :method, :path, :authority and :scheme come first (RFC 9114
        // Section 4.3), then whatever the caller sends. nghttp3 encodes the
        // fields during this call, so the array itself does not have to live on.
        const nva = try self.allocator.alloc(nghttp3.nghttp3_nv, 4 + headers.len);
        defer self.allocator.free(nva);

        nva[0] = makeNv(":method", method);
        nva[1] = makeNv(":path", path);
        nva[2] = makeNv(":authority", authority);
        nva[3] = makeNv(":scheme", "https");
        for (headers, 0..) |header, i| nva[4 + i] = makeNv(header.name, header.value);

        state.request_body = body;
        state.request_body_sent = 0;
        var reader: nghttp3.nghttp3_data_reader = .{ .read_data = readRequestBodyCb };
        const ret = nghttp3.nghttp3_conn_submit_request(
            self.conn,
            stream_id,
            nva.ptr,
            nva.len,
            if (body.len == 0) null else &reader,
            @ptrCast(state),
        );
        if (ret != 0) return error.H3Error;
    }

    /// Submit a response for |req|, with |body| as its content. Ownership of
    /// |body| moves to the request and it is freed when the stream closes.
    ///
    /// |headers| are additional fields to send after Content-Type. A
    /// `content-length` among them is dropped: the length of |body| is what
    /// goes out, and RFC 9114 Section 4.1 allows only one.
    pub fn submitResponse(
        self: *Session,
        req: *ServerRequest,
        status: u16,
        content_type: []const u8,
        headers: []const HeaderField,
        body: []const u8,
    ) !void {
        // nghttp3 copies the header values, so stack buffers are fine here.
        var status_buf: [16]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.H3Error;
        var len_buf: [20]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body.len}) catch return error.H3Error;

        const nva = try self.allocator.alloc(nghttp3.nghttp3_nv, 3 + headers.len);
        defer self.allocator.free(nva);
        const nvlen = fillResponseFields(nva, status_str, content_type, headers, len_str);

        const reader = nghttp3.nghttp3_data_reader{ .read_data = readDataCb };

        const ret = nghttp3.nghttp3_conn_submit_response(self.conn, req.stream_id, nva.ptr, nvlen, &reader);
        if (ret != 0) return error.H3Error;

        req.response_body = body;
        req.response_sent = 0;
        req.responded = true;
    }

    /// Submit a response for |req| whose body is pulled from |body_reader| while
    /// it is sent, for a body too large — or too long-lived — to hand over in
    /// one piece.
    ///
    /// No `content-length` goes out: RFC 9114 Section 4.1 lets an HTTP/3
    /// response leave it out, and the length is not known before the body has
    /// been produced. `status`, `content_type` and `headers` are what
    /// `submitResponse` makes of them.
    pub fn submitStreamingResponse(
        self: *Session,
        req: *ServerRequest,
        status: u16,
        content_type: []const u8,
        headers: []const HeaderField,
        body_reader: BodyReader,
        body_context: ?*anyopaque,
    ) !void {
        var status_buf: [16]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.H3Error;

        const nva = try self.allocator.alloc(nghttp3.nghttp3_nv, 3 + headers.len);
        defer self.allocator.free(nva);
        const nvlen = fillResponseFields(nva, status_str, content_type, headers, null);

        var reader = nghttp3.nghttp3_data_reader{ .read_data = readStreamedDataCb };

        const ret = nghttp3.nghttp3_conn_submit_response(self.conn, req.stream_id, nva.ptr, nvlen, &reader);
        if (ret != 0) return error.H3Error;

        req.body_reader = body_reader;
        req.body_context = body_context;
        req.responded = true;
    }
};

/// Fills |nva| with the fields of a response — `:status`, `content-type`, the
/// length when it is known, then the caller's own — and returns how many of
/// them were written. A `content-length` among the caller's fields is dropped:
/// RFC 9114 Section 4.1 allows only one, and the server's is the one that
/// matches the body.
fn fillResponseFields(
    nva: []nghttp3.nghttp3_nv,
    status: []const u8,
    content_type: []const u8,
    headers: []const HeaderField,
    content_length: ?[]const u8,
) usize {
    var n: usize = 0;
    nva[n] = makeNv(":status", status);
    n += 1;
    nva[n] = makeNv("content-type", content_type);
    n += 1;
    if (content_length) |len| {
        nva[n] = makeNv("content-length", len);
        n += 1;
    }
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, "content-length")) continue;
        nva[n] = makeNv(header.name, header.value);
        n += 1;
    }
    return n;
}

// ---- nghttp3 callback implementations ----

/// Creates the state for a request arriving at a server. Clients attach their
/// state before sending, so a stream that has none is a new request.
fn beginHeadersCb(
    conn: ?*nghttp3.nghttp3_conn,
    stream_id: i64,
    conn_user_data: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    if (stream_user_data != null) return 0;

    const session: *Session = @ptrCast(@alignCast(conn_user_data orelse return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE));
    const req = ServerRequest.init(session.allocator, stream_id, session.max_request_body_bytes) catch
        return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    errdefer req.deinit();

    session.requests.append(session.allocator, req) catch {
        req.deinit();
        return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    };

    if (nghttp3.nghttp3_conn_set_stream_user_data(conn.?, stream_id, @ptrCast(req)) != 0) {
        return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

fn recvHeaderCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    _: i32,
    name: ?*nghttp3.nghttp3_rcbuf,
    value: ?*nghttp3.nghttp3_rcbuf,
    _: u8,
    conn_user_data: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    const nv = nghttp3.nghttp3_rcbuf_get_buf(name.?);
    const vv = nghttp3.nghttp3_rcbuf_get_buf(value.?);
    const name_bytes = nv.base[0..nv.len];
    const value_bytes = vv.base[0..vv.len];

    const session: *Session = @ptrCast(@alignCast(conn_user_data orelse return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE));
    if (session.server) {
        const req: *ServerRequest = @ptrCast(@alignCast(stream_user_data orelse return 0));
        const a = req.arena.allocator();
        if (std.mem.eql(u8, name_bytes, ":path")) {
            req.path = a.dupe(u8, value_bytes) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
            return 0;
        }
        if (std.mem.eql(u8, name_bytes, ":method")) {
            req.method = a.dupe(u8, value_bytes) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
            return 0;
        }
        // :authority and :scheme carry nothing a handler can act on here, and
        // the other pseudo-headers are not defined for a request.
        if (name_bytes.len > 0 and name_bytes[0] == ':') return 0;

        const name_copy = a.dupe(u8, name_bytes) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        const value_copy = a.dupe(u8, value_bytes) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        req.headers.append(a, .{ .name = name_copy, .value = value_copy }) catch
            return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        return 0;
    }

    const ctx: *ResponseContext = @ptrCast(@alignCast(stream_user_data orelse return 0));
    if (std.mem.eql(u8, name_bytes, ":status")) {
        ctx.status = std.fmt.parseInt(u16, value_bytes, 10) catch 0;
    }
    ctx.headers.appendSlice(ctx.allocator, name_bytes) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    ctx.headers.appendSlice(ctx.allocator, ": ") catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    ctx.headers.appendSlice(ctx.allocator, value_bytes) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    ctx.headers.appendSlice(ctx.allocator, "\r\n") catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    return 0;
}

fn recvDataCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    data: [*c]const u8,
    datalen: usize,
    conn_user_data: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    const session: *Session = @ptrCast(@alignCast(conn_user_data orelse return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE));
    if (session.server) {
        // The whole body is kept, up to what the request accepts. A body beyond
        // that is dropped rather than refused: the credit for it goes back to
        // the peer either way, so a client that keeps sending cannot wedge the
        // connection, and the request is answered with 413 once it ends.
        const req: *ServerRequest = @ptrCast(@alignCast(stream_user_data orelse return 0));
        if (req.body.items.len + datalen > req.max_body_bytes) {
            req.body_too_large = true;
            return 0;
        }
        req.body.appendSlice(req.arena.allocator(), data[0..datalen]) catch
            return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        return 0;
    }

    const ctx: *ResponseContext = @ptrCast(@alignCast(stream_user_data orelse return 0));
    ctx.body.appendSlice(ctx.allocator, data[0..datalen]) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    return 0;
}

fn endStreamCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    conn_user_data: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    const session: *Session = @ptrCast(@alignCast(conn_user_data orelse return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE));
    if (session.server) {
        const req: *ServerRequest = @ptrCast(@alignCast(stream_user_data orelse return 0));
        req.complete = true;
        return 0;
    }

    const ctx: *ResponseContext = @ptrCast(@alignCast(stream_user_data orelse return 0));
    ctx.done = true;
    return 0;
}

/// The peer acknowledged stream data. For a streamed response this is what
/// frees the chunk that data came from: ngtcp2 may read the bytes it was given
/// again for a retransmission until the acknowledgement reaches them.
fn ackedStreamDataCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    datalen: u64,
    conn_user_data: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    const session: *Session = @ptrCast(@alignCast(conn_user_data orelse return 0));
    if (!session.server) return 0;
    // Streams that are not a request (the endpoint's own control and QPACK
    // streams) are not the application's to account for.
    const req: *ServerRequest = @ptrCast(@alignCast(stream_user_data orelse return 0));
    req.body_acked += @intCast(datalen);
    return 0;
}

/// Frees the state a server request hung off its stream.
fn streamCloseCb(
    _: ?*nghttp3.nghttp3_conn,
    stream_id: i64,
    _: u64,
    conn_user_data: ?*anyopaque,
    _: ?*anyopaque,
) callconv(.c) c_int {
    const session: *Session = @ptrCast(@alignCast(conn_user_data orelse return 0));
    if (!session.server) return 0;

    for (session.requests.items, 0..) |req, i| {
        if (req.stream_id == stream_id) {
            _ = session.requests.swapRemove(i);
            req.deinit();
            break;
        }
    }
    return 0;
}

/// Hands the response body to nghttp3 in one piece.
fn readDataCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    vec: [*c]nghttp3.nghttp3_vec,
    veccnt: usize,
    pflags: [*c]u32,
    _: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) nghttp3.nghttp3_ssize {
    if (veccnt == 0) return 0;
    const req: *ServerRequest = @ptrCast(@alignCast(stream_user_data orelse return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE));

    const remaining = req.response_body[req.response_sent..];
    if (remaining.len == 0) {
        pflags.* = nghttp3.NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    vec[0] = .{ .base = @constCast(remaining.ptr), .len = remaining.len };
    req.response_sent = req.response_body.len;
    pflags.* = nghttp3.NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

/// Hands nghttp3 one chunk of a streamed body per call, taken from the
/// request's reader. A chunk is copied onto a buffer of its own before it goes
/// out, because nghttp3 is free to hand the same bytes to ngtcp2 again for a
/// retransmission (see `BodyChunk`); the read buffer that chunk was read into
/// is only reused once its content has been copied.
///
/// A reader that returns an error fails the stream: nghttp3.h makes
/// `NGHTTP3_ERR_CALLBACK_FAILURE` the way to report that the application could
/// not produce the data, and the failure surfaces as a write error the server
/// acts on. A short chunk is not the end of the body — only the reader
/// returning 0 is.
fn readStreamedDataCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    vec: [*c]nghttp3.nghttp3_vec,
    veccnt: usize,
    pflags: [*c]u32,
    _: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) nghttp3.nghttp3_ssize {
    if (veccnt == 0) return 0;
    const req: *ServerRequest = @ptrCast(@alignCast(stream_user_data orelse return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE));

    const chunk = readStreamedChunk(req) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    if (chunk.len == 0) {
        // The reader reported the end of the body: with nothing left to hand
        // over, the response ends here.
        pflags.* = nghttp3.NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    vec[0] = .{ .base = @constCast(chunk.ptr), .len = chunk.len };
    return 1;
}

/// What the size of the buffer a streamed body's reader is offered, i.e. the
/// largest chunk one call can produce.
pub const stream_chunk_bytes = 64 * 1024;

const StreamedReadError = error{ OutOfMemory, ReaderFailed };

/// Reads the next chunk of a streamed body, and returns an empty slice at the
/// end of it.
fn readStreamedChunk(req: *ServerRequest) StreamedReadError![]u8 {
    const reader = req.body_reader orelse return &.{};
    if (req.body_eof) return &.{};

    const a = req.arena.allocator();
    if (req.read_buf.len == 0) {
        req.read_buf = try a.alloc(u8, stream_chunk_bytes);
    }

    const n = reader(req.body_context, req.read_buf) catch return error.ReaderFailed;
    if (n == 0) {
        req.body_eof = true;
        return &.{};
    }
    // The contract is "fill `buf` and return how many bytes were written", so a
    // reader that reports more than it was given has broken it.
    if (n > req.read_buf.len) return error.ReaderFailed;

    const chunk = try takeChunk(req, a, n);
    @memcpy(chunk, req.read_buf[0..n]);
    req.body_sent += n;
    return chunk;
}

/// A buffer for the next chunk of a streamed body: one an acknowledged chunk
/// has given back, or a new one. Everything a response holds comes from its
/// arena, so what it holds is the chunks the peer has not acknowledged yet,
/// which its flow control window bounds.
fn takeChunk(req: *ServerRequest, a: std.mem.Allocator, len: usize) StreamedReadError![]u8 {
    const end = req.body_sent + len;
    for (req.chunks.items) |*chunk| {
        if (chunk.end > req.body_acked) continue;
        if (chunk.buf.len < len) continue;
        chunk.end = end;
        return chunk.buf[0..len];
    }

    const buf = try a.alloc(u8, len);
    try req.chunks.append(a, .{ .buf = buf, .end = end });
    return buf;
}

/// Hands the request body to nghttp3 in one piece — the client side of
/// `readDataCb`, reading out of the `ResponseContext` the request was submitted
/// with.
fn readRequestBodyCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    vec: [*c]nghttp3.nghttp3_vec,
    veccnt: usize,
    pflags: [*c]u32,
    _: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) nghttp3.nghttp3_ssize {
    if (veccnt == 0) return 0;
    const state: *ResponseContext = @ptrCast(@alignCast(stream_user_data orelse return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE));

    const remaining = state.request_body[state.request_body_sent..];
    if (remaining.len == 0) {
        pflags.* = nghttp3.NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    vec[0] = .{ .base = @constCast(remaining.ptr), .len = remaining.len };
    state.request_body_sent = state.request_body.len;
    pflags.* = nghttp3.NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

/// Create an nghttp3_nv (name-value pair) for header submission.
fn makeNv(name: []const u8, value: []const u8) nghttp3.nghttp3_nv {
    return .{
        .name = @ptrCast(name.ptr),
        .namelen = name.len,
        .value = @ptrCast(value.ptr),
        .valuelen = value.len,
        .flags = nghttp3.NGHTTP3_NV_FLAG_NONE,
    };
}

test {
    _ = Session;
    _ = ResponseContext;
    _ = ServerRequest;
}
