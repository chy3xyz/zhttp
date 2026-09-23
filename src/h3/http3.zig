const std = @import("std");
const nghttp3 = @import("nghttp3_c");

pub const Error = error{
    H3Error,
    StreamClosed,
};

/// HTTP/3 application error codes (RFC 9114 — HTTP/3 error codes).
pub const H3_NO_ERROR: u64 = 0x0100;

/// Accumulated response state populated by nghttp3 callbacks.
pub const ResponseContext = struct {
    status: u16 = 0,
    headers: std.ArrayList(u8),
    body: std.ArrayList(u8),
    done: bool = false,
    allocator: std.mem.Allocator,

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

/// A request the server received, plus the response being sent for it. Answers
/// `nghttp3_conn_submit_response`'s need for a body that stays alive until the
/// stream closes.
pub const ServerRequest = struct {
    allocator: std.mem.Allocator,
    stream_id: i64,
    method: std.ArrayList(u8),
    path: std.ArrayList(u8),
    /// Set once the request stream ended, i.e. the request is complete.
    complete: bool = false,
    /// Set once a response has been submitted for it.
    responded: bool = false,
    /// Response body, owned here until the stream closes.
    body: []const u8 = &.{},
    body_sent: usize = 0,

    pub fn deinit(self: *ServerRequest) void {
        self.method.deinit(self.allocator);
        self.path.deinit(self.allocator);
        self.allocator.free(self.body);
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

    pub fn init(allocator: std.mem.Allocator) !*Session {
        return create(allocator, false, 0);
    }

    /// Create a server-side H3 session (for use in H3 server).
    pub fn initServer(allocator: std.mem.Allocator, max_client_streams_bidi: u64) !*Session {
        return create(allocator, true, max_client_streams_bidi);
    }

    fn create(allocator: std.mem.Allocator, server: bool, max_client_streams_bidi: u64) !*Session {
        const session = try allocator.create(Session);
        errdefer allocator.destroy(session);
        session.* = .{
            .conn = undefined,
            .callbacks = std.mem.zeroes(nghttp3.nghttp3_callbacks),
            .allocator = allocator,
            .server = server,
        };

        session.callbacks.recv_header = recvHeaderCb;
        session.callbacks.recv_data = recvDataCb;
        session.callbacks.end_stream = endStreamCb;
        session.callbacks.begin_headers = beginHeadersCb;
        session.callbacks.stream_close = streamCloseCb;

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

    /// Submit an HTTP/3 GET request on a QUIC stream. |state| is the
    /// `ResponseContext` the response callbacks fill in.
    pub fn submitRequest(self: *Session, stream_id: i64, path: []const u8, authority: []const u8, state: *ResponseContext) !void {
        // Build nva array: :method, :path, :authority, :scheme
        var nva: [4]nghttp3.nghttp3_nv = undefined;

        nva[0] = makeNv(":method", "GET");
        nva[1] = makeNv(":path", path);
        nva[2] = makeNv(":authority", authority);
        nva[3] = makeNv(":scheme", "https");

        const ret = nghttp3.nghttp3_conn_submit_request(self.conn, stream_id, &nva, nva.len, null, @ptrCast(state));
        if (ret != 0) return error.H3Error;
    }

    /// Submit a response for |req|, with |body| as its content. Ownership of
    /// |body| moves to the request and it is freed when the stream closes.
    pub fn submitResponse(self: *Session, req: *ServerRequest, status: u16, content_type: []const u8, body: []const u8) !void {
        // nghttp3 copies the header values, so stack buffers are fine here.
        var status_buf: [16]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.H3Error;
        var len_buf: [20]u8 = undefined;
        const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{body.len}) catch return error.H3Error;

        const nva = [3]nghttp3.nghttp3_nv{
            makeNv(":status", status_str),
            makeNv("content-type", content_type),
            makeNv("content-length", len_str),
        };
        const reader = nghttp3.nghttp3_data_reader{ .read_data = readDataCb };

        const ret = nghttp3.nghttp3_conn_submit_response(self.conn, req.stream_id, &nva, nva.len, &reader);
        if (ret != 0) return error.H3Error;

        req.body = body;
        req.body_sent = 0;
        req.responded = true;
    }

    /// Feed received stream data to nghttp3 for HTTP/3 processing.
    /// Returns number of bytes consumed.
    pub fn readStream(self: *Session, stream_id: i64, data: []const u8, fin: bool) !usize {
        const consumed = nghttp3.nghttp3_conn_read_stream2(self.conn, stream_id, data.ptr, data.len, @intFromBool(fin));
        if (consumed < 0) return error.H3Error;
        return @intCast(consumed);
    }
};

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
    const req = session.allocator.create(ServerRequest) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    req.* = .{
        .allocator = session.allocator,
        .stream_id = stream_id,
        .method = std.ArrayList(u8).initCapacity(session.allocator, 16) catch {
            session.allocator.destroy(req);
            return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        },
        .path = std.ArrayList(u8).initCapacity(session.allocator, 16) catch {
            req.method.deinit(req.allocator);
            session.allocator.destroy(req);
            return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        },
    };

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
        const target = if (std.mem.eql(u8, name_bytes, ":path"))
            &req.path
        else if (std.mem.eql(u8, name_bytes, ":method"))
            &req.method
        else
            return 0;
        target.appendSlice(req.allocator, value_bytes) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        return 0;
    }

    const ctx: *ResponseContext = @ptrCast(@alignCast(stream_user_data orelse return 0));
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
    if (session.server) return 0; // request bodies are not used by the H3 server

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

    const remaining = req.body[req.body_sent..];
    if (remaining.len == 0) {
        pflags.* = nghttp3.NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }

    vec[0] = .{ .base = @constCast(remaining.ptr), .len = remaining.len };
    req.body_sent = req.body.len;
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
