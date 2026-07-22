const std = @import("std");
const nghttp3 = @import("nghttp3_c");

pub const Error = error{
    H3Error,
    StreamClosed,
};

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

pub const Session = struct {
    conn: *nghttp3.nghttp3_conn,
    callbacks: nghttp3.nghttp3_callbacks,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Session {
        var callbacks: nghttp3.nghttp3_callbacks = std.mem.zeroes(nghttp3.nghttp3_callbacks);

        // Set response accumulation callbacks
        callbacks.recv_header = recvHeaderCb;
        callbacks.recv_data = recvDataCb;
        callbacks.end_stream = endStreamCb;

        var settings: nghttp3.nghttp3_settings = undefined;
        nghttp3.nghttp3_settings_default(&settings);

        var conn_ptr: ?*nghttp3.nghttp3_conn = null;
        const ret = nghttp3.nghttp3_conn_client_new(&conn_ptr, &callbacks, &settings, null, null);
        if (ret != 0) return error.H3Error;

        return .{
            .conn = conn_ptr.?,
            .callbacks = callbacks,
            .allocator = allocator,
        };
    }

    /// Create a server-side H3 session (for use in H3 server).
    pub fn initServer(allocator: std.mem.Allocator) !Session {
        var callbacks: nghttp3.nghttp3_callbacks = std.mem.zeroes(nghttp3.nghttp3_callbacks);

        callbacks.recv_header = recvHeaderCb;
        callbacks.recv_data = recvDataCb;
        callbacks.end_stream = endStreamCb;

        var settings: nghttp3.nghttp3_settings = undefined;
        nghttp3.nghttp3_settings_default(&settings);

        var conn_ptr: ?*nghttp3.nghttp3_conn = null;
        const ret = nghttp3.nghttp3_conn_server_new(&conn_ptr, &callbacks, &settings, null, null);
        if (ret != 0) return error.H3Error;

        return .{
            .conn = conn_ptr.?,
            .callbacks = callbacks,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Session) void {
        nghttp3.nghttp3_conn_del(self.conn);
        self.* = undefined;
    }

    /// Submit an HTTP/3 GET request on a QUIC stream.
    /// Returns 0 on success, negative error code on failure.
    pub fn submitRequest(self: *Session, stream_id: i64, path: []const u8, authority: []const u8) !void {
        // Build nva array: :method, :path, :authority, :scheme
        var nva: [4]nghttp3.nghttp3_nv = undefined;

        nva[0] = makeNv(":method", "GET");
        nva[1] = makeNv(":path", path);
        nva[2] = makeNv(":authority", authority);
        nva[3] = makeNv(":scheme", "https");

        const ret = nghttp3.nghttp3_conn_submit_request(self.conn, stream_id, &nva, nva.len, null, null);
        if (ret != 0) return error.H3Error;
    }

    /// Submit an HTTP/3 response on a QUIC stream (server-side).
    pub fn submitResponse(self: *Session, stream_id: i64, status: u16, _: []const u8, _: []const u8) !void {
        var status_buf: [16]u8 = undefined;
        const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return error.H3Error;

        var nva: [2]nghttp3.nghttp3_nv = undefined;
        nva[0] = makeNv(":status", status_str);
        nva[1] = makeNv("content-type", "text/plain");

        const ret = nghttp3.nghttp3_conn_submit_response(self.conn, stream_id, &nva, nva.len, null);
        if (ret != 0) return error.H3Error;
    }

    /// Bind QPACK encoder and decoder streams to this H3 session.
    pub fn bindQpackStreams(self: *Session, enc_stream_id: i64, dec_stream_id: i64) !void {
        const ret = nghttp3.nghttp3_conn_bind_qpack_streams(self.conn, enc_stream_id, dec_stream_id);
        if (ret != 0) return error.H3Error;
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

fn recvHeaderCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    _: i32,
    name: ?*nghttp3.nghttp3_rcbuf,
    value: ?*nghttp3.nghttp3_rcbuf,
    _: u8,
    _: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    if (stream_user_data) |ud| {
        var mutable_ctx: *ResponseContext = @alignCast(@ptrCast(ud));
        const nv = nghttp3.nghttp3_rcbuf_get_buf(name.?);
        const vv = nghttp3.nghttp3_rcbuf_get_buf(value.?);
        mutable_ctx.headers.appendSlice(mutable_ctx.allocator, nv.base[0..nv.len]) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        mutable_ctx.headers.appendSlice(mutable_ctx.allocator, ": ") catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        mutable_ctx.headers.appendSlice(mutable_ctx.allocator, vv.base[0..vv.len]) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
        mutable_ctx.headers.appendSlice(mutable_ctx.allocator, "\r\n") catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

fn recvDataCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    data: [*c]const u8,
    datalen: usize,
    _: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    if (stream_user_data) |ud| {
        var mutable_ctx: *ResponseContext = @alignCast(@ptrCast(ud));
        mutable_ctx.body.appendSlice(mutable_ctx.allocator, data[0..datalen]) catch return nghttp3.NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

fn endStreamCb(
    _: ?*nghttp3.nghttp3_conn,
    _: i64,
    _: ?*anyopaque,
    stream_user_data: ?*anyopaque,
) callconv(.c) c_int {
    if (stream_user_data) |ud| {
        const ctx: *ResponseContext = @alignCast(@ptrCast(ud));
        ctx.done = true;
    }
    return 0;
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
}
