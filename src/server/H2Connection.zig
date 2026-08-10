const H2Connection = @This();
const std = @import("std");
const mem = std.mem;
const Io = std.Io;

const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Headers = @import("../Headers.zig");
const Connection = @import("Connection.zig");
const Date = @import("Date.zig");

const h2 = @import("../h2/root.zig");
const frame = h2.frame;
const hpack = h2.hpack;
const FrameType = frame.FrameType;
const FrameHeader = frame.FrameHeader;
const Flags = frame.Flags;
const Stream = h2.Stream;
const StreamRegistry = h2.StreamRegistry;
const FlowControl = h2.FlowControl;
const Settings = h2.Settings;
const ErrorCode = h2.ErrorCode;

const Handler = Connection.Handler;

/// RFC 9113 §8.2: Header field names MUST be lowercase in HTTP/2.
/// Returns a stack buffer with the lowercased name.
fn lowerHeaderName(buf: *[256]u8, name: []const u8) []const u8 {
    if (name.len > buf.len) return name;
    for (name, 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    return buf[0..name.len];
}

/// Serve an HTTP/2 connection.
///
/// This is called after TLS negotiation selects "h2" via ALPN, or
/// when prior knowledge (h2c) is detected on a cleartext connection.
///
/// The caller provides the reader/writer that sit on top of TLS
/// (or raw TCP for h2c).
pub fn serve(reader: *Io.Reader, writer: *Io.Writer, handler: Handler, io: Io) void {
    serveImpl(reader, writer, handler, io) catch {};
}

fn serveImpl(reader: *Io.Reader, writer: *Io.Writer, handler: Handler, io: Io) !void {
    // --- Connection Preface (RFC 9113 §3.4) ---
    // Client must send the 24-byte preface, then a SETTINGS frame.
    // We validate the preface, then send our own SETTINGS + ACK.

    var preface_buf: [frame.connection_preface.len]u8 = undefined;
    reader.readSliceAll(&preface_buf) catch return;
    if (!mem.eql(u8, &preface_buf, frame.connection_preface)) {
        // Invalid preface — close without GOAWAY per RFC 9113 §3.4
        return;
    }

    // Send our server preface: SETTINGS frame
    var settings_sync: Settings.Sync = .{};
    settings_sync.local.max_concurrent_streams = 100;
    const settings_list = [_]frame.Setting{
        .{ .id = .max_concurrent_streams, .value = 100 },
    };
    try frame.writeSettings(writer, &settings_list);
    try writer.flush();

    // HPACK encoder state — initialized before settings exchange
    var hpack_enc_buf: [4096]u8 = undefined;
    var hpack_enc_entries: [128]hpack.DynamicTable.Entry = undefined;
    var encoder = hpack.Encoder.init(&hpack_enc_buf, &hpack_enc_entries);

    settings_sync.markSent(@intCast(encoder.dynamic_table.max_size));

    // Read the client's SETTINGS frame (must be first frame after preface)
    {
        const f = readFrameFromReader(reader) catch return;
        if (f.header.frame_type != .settings or f.header.flags.has(Flags.ack)) {
            try sendGoaway(writer, 0, .protocol_error);
            return;
        }
        if (f.header.stream_id != 0) {
            try sendGoaway(writer, 0, .protocol_error);
            return;
        }
        const result = settings_sync.applyPeerSettings(f.payload) catch {
            try sendGoaway(writer, 0, .protocol_error);
            return;
        };
        _ = result;
    }
    // ACK the client's SETTINGS
    try frame.writeSettingsAck(writer);
    try writer.flush();

    // --- Connection state ---
    var registry: StreamRegistry = .{ .is_server = true, .max_concurrent_streams = settings_sync.local.max_concurrent_streams };
    var flow: FlowControl.FlowController = .{};

    // HPACK decoder state
    var hpack_dec_buf: [4096]u8 = undefined;
    var hpack_dec_entries: [128]hpack.DynamicTable.Entry = undefined;
    var decoder = hpack.Decoder.init(&hpack_dec_buf, &hpack_dec_entries);
    decoder.dynamic_table.setMaxSize(settings_sync.peer.header_table_size);

    // Header block assembly buffer (for CONTINUATION frames)
    var header_block_buf: [16384]u8 = undefined;
    var header_block_len: usize = 0;
    var header_block_stream_id: u31 = 0;
    var header_block_end_stream: bool = false;

    // Pending request state — when HEADERS arrives without END_STREAM,
    // we store the decoded header block and wait for DATA + END_STREAM.
    var pending_header_block: [16384]u8 = undefined;
    var pending_header_block_len: usize = 0;
    var pending_stream_id: u31 = 0;
    // Request body buffer: stack for ≤64 KiB, heap for larger.
    const max_stack_body: usize = 65536;
    var body_stack_buf: [max_stack_body]u8 = undefined;
    var body_heap: ?[]u8 = null;
    var body_len: usize = 0;
    defer if (body_heap) |h| std.heap.page_allocator.free(h);

    // Track last stream ID for GOAWAY (also used by deferred graceful shutdown)
    var last_client_stream_id: u31 = 0;
    // Graceful shutdown: send GOAWAY with NO_ERROR when we exit the frame loop
    defer sendGoaway(writer, last_client_stream_id, .no_error) catch {};

    // DoS protection: rapid reset detection (RFC 9113 §10.5)
    var rst_stream_count: u32 = 0;
    const max_rst_stream_per_cycle: u32 = 100;

    // --- Frame loop ---
    while (true) {
        const f = readFrameFromReader(reader) catch |err| switch (err) {
            error.EndOfStream => return,
            else => {
                sendGoaway(writer, last_client_stream_id, .protocol_error) catch {};
                return;
            },
        };

        // Settings timeout detection (RFC 9113 §6.5.3)
        settings_sync.frameReceived() catch {
            sendGoaway(writer, last_client_stream_id, .settings_timeout) catch {};
            return;
        };

        // If we're assembling a header block, only CONTINUATION on the same
        // stream is allowed (RFC 9113 §4.3)
        if (header_block_len > 0) {
            if (f.header.frame_type != .continuation or f.header.stream_id != header_block_stream_id) {
                try sendGoaway(writer, last_client_stream_id, .protocol_error);
                return;
            }
        }

        switch (f.header.frame_type) {
            .settings => {
                if (f.header.stream_id != 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                if (f.header.flags.has(Flags.ack)) {
                    // ACK of our settings — apply deferred HPACK encoder table size
                    if (settings_sync.receiveAck()) |new_table_size| {
                        encoder.setMaxTableSize(new_table_size);
                    }
                    continue;
                }
                const result = settings_sync.applyPeerSettings(f.payload) catch {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                };
                // Adjust stream windows if initial_window_size changed
                if (settings_sync.peer.initial_window_size != result.old_window) {
                    const delta: i32 = @as(i32, @intCast(settings_sync.peer.initial_window_size)) - @as(i32, @intCast(result.old_window));
                    for (registry.streams[0..registry.len]) |*s| {
                        if (s.isActive()) {
                            s.send_window +|= delta;
                        }
                    }
                }
                // HPACK decoder table size takes effect immediately on receipt
                decoder.dynamic_table.setMaxSize(result.new_decoder_table_size);
                try frame.writeSettingsAck(writer);
                try writer.flush();
            },

            .ping => {
                if (f.header.stream_id != 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                if (f.payload.len != 8) {
                    try sendGoaway(writer, last_client_stream_id, .frame_size_error);
                    return;
                }
                if (!f.header.flags.has(Flags.ack)) {
                    try frame.writePing(writer, f.payload[0..8], true);
                    try writer.flush();
                }
            },

            .goaway => {
                // Peer is shutting down — stop processing
                return;
            },

            .window_update => {
                if (f.payload.len != 4) {
                    try sendGoaway(writer, last_client_stream_id, .frame_size_error);
                    return;
                }
                const increment = frame.parseWindowUpdate(f.payload) catch {
                    if (f.header.stream_id == 0) {
                        try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    } else {
                        try frame.writeRstStream(writer, f.header.stream_id, .protocol_error);
                        try writer.flush();
                    }
                    return;
                };
                if (f.header.stream_id == 0) {
                    flow.recvWindowUpdate(increment) catch {
                        try sendGoaway(writer, last_client_stream_id, .flow_control_error);
                        return;
                    };
                } else {
                    if (registry.get(f.header.stream_id)) |s| {
                        const new: i64 = @as(i64, s.send_window) + @as(i64, increment);
                        if (new > std.math.maxInt(i32)) {
                            try frame.writeRstStream(writer, f.header.stream_id, .flow_control_error);
                            try writer.flush();
                            continue;
                        }
                        s.send_window = @intCast(new);
                    }
                }
            },

            .headers => {
                if (f.header.stream_id == 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }

                // Parse past padding and priority fields to get the header block fragment
                var payload = f.payload;
                var pad_len: usize = 0;
                if (f.header.flags.has(Flags.padded)) {
                    if (payload.len < 1) {
                        try sendGoaway(writer, last_client_stream_id, .protocol_error);
                        return;
                    }
                    pad_len = payload[0];
                    payload = payload[1..];
                }
                if (f.header.flags.has(Flags.priority_flag)) {
                    if (payload.len < 5) {
                        try sendGoaway(writer, last_client_stream_id, .protocol_error);
                        return;
                    }
                    payload = payload[5..]; // skip dependency(4) + weight(1)
                }
                if (pad_len > payload.len) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                const fragment = payload[0 .. payload.len - pad_len];

                if (f.header.flags.has(Flags.end_headers)) {
                    last_client_stream_id = f.header.stream_id;
                    if (f.header.flags.has(Flags.end_stream)) {
                        // No body — process immediately
                        processRequest(
                            &registry, &decoder, &encoder, &flow,
                            &settings_sync.peer, fragment,
                            f.header.stream_id, &.{}, writer, handler, io,
                        );
                    } else {
                        // Body will follow via DATA frames — store headers
                        if (fragment.len <= pending_header_block.len) {
                            @memcpy(pending_header_block[0..fragment.len], fragment);
                            pending_header_block_len = fragment.len;
                            pending_stream_id = f.header.stream_id;
                            body_len = 0;
                        } else {
                            try frame.writeRstStream(writer, f.header.stream_id, .internal_error);
                            try writer.flush();
                        }
                    }
                } else {
                    // Start of multi-frame header block — buffer it
                    if (fragment.len > header_block_buf.len) {
                        try sendGoaway(writer, last_client_stream_id, .internal_error);
                        return;
                    }
                    @memcpy(header_block_buf[0..fragment.len], fragment);
                    header_block_len = fragment.len;
                    header_block_stream_id = f.header.stream_id;
                    header_block_end_stream = f.header.flags.has(Flags.end_stream);
                }
            },

            .continuation => {
                // Must be assembling a header block
                if (header_block_len == 0 or f.header.stream_id != header_block_stream_id) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                if (header_block_len + f.payload.len > header_block_buf.len) {
                    try sendGoaway(writer, last_client_stream_id, .internal_error);
                    return;
                }
                @memcpy(header_block_buf[header_block_len..][0..f.payload.len], f.payload);
                header_block_len += f.payload.len;

                if (f.header.flags.has(Flags.end_headers)) {
                    last_client_stream_id = header_block_stream_id;
                    const assembled = header_block_buf[0..header_block_len];
                    if (header_block_end_stream) {
                        processRequest(
                            &registry, &decoder, &encoder, &flow,
                            &settings_sync.peer, assembled,
                            header_block_stream_id, &.{}, writer, handler, io,
                        );
                    } else {
                        // Body will follow — store headers
                        if (assembled.len <= pending_header_block.len) {
                            @memcpy(pending_header_block[0..assembled.len], assembled);
                            pending_header_block_len = assembled.len;
                            pending_stream_id = header_block_stream_id;
                            body_len = 0;
                        }
                    }
                    header_block_len = 0;
                    header_block_stream_id = 0;
                }
            },

            .data => {
                if (f.header.stream_id == 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }

                // Flow control: account for received data (entire payload including padding)
                if (f.payload.len > 0) {
                    const should_update = flow.recordRecv(@intCast(f.payload.len)) catch {
                        try sendGoaway(writer, last_client_stream_id, .flow_control_error);
                        return;
                    };
                    if (should_update) {
                        const inc = flow.pendingWindowUpdate() catch {
                            try sendGoaway(writer, last_client_stream_id, .internal_error);
                            return;
                        };
                        if (inc > 0) {
                            try frame.writeWindowUpdate(writer, 0, inc);
                            try frame.writeWindowUpdate(writer, f.header.stream_id, inc);
                            try writer.flush();
                        }
                    }
                }

                // Strip padding to get actual data
                var data_payload = f.payload;
                var pad_len: usize = 0;
                if (f.header.flags.has(Flags.padded) and data_payload.len > 0) {
                    pad_len = data_payload[0];
                    data_payload = data_payload[1..];
                }
                if (pad_len > data_payload.len) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                const actual_data = data_payload[0 .. data_payload.len - pad_len];

                // Buffer request body data
                if (actual_data.len > 0 and pending_stream_id == f.header.stream_id) {
                    const total = body_len + actual_data.len;
                    const max_body: usize = 1_048_576; // 1 MiB max body
                    if (total > max_body) {
                        try frame.writeRstStream(writer, f.header.stream_id, .refused_stream);
                        try writer.flush();
                        body_len = 0;
                        pending_stream_id = 0;
                        pending_header_block_len = 0;
                        continue;
                    }

                    // Grow buffer if needed
                    if (body_heap) |h| {
                        if (total > h.len) {
                            const new_buf = std.heap.page_allocator.alloc(u8, total) catch {
                                try frame.writeRstStream(writer, f.header.stream_id, .refused_stream);
                                try writer.flush();
                                body_len = 0;
                                pending_stream_id = 0;
                                pending_header_block_len = 0;
                                continue;
                            };
                            @memcpy(new_buf[0..body_len], h[0..body_len]);
                            std.heap.page_allocator.free(h);
                            body_heap = new_buf;
                        }
                    } else if (total > body_stack_buf.len) {
                        // Migrate to heap
                        const new_buf = std.heap.page_allocator.alloc(u8, total) catch {
                            try frame.writeRstStream(writer, f.header.stream_id, .refused_stream);
                            try writer.flush();
                            body_len = 0;
                            pending_stream_id = 0;
                            pending_header_block_len = 0;
                            continue;
                        };
                        @memcpy(new_buf[0..body_len], body_stack_buf[0..body_len]);
                        body_heap = new_buf;
                    }

                    const target = if (body_heap) |h| h else &body_stack_buf;
                    @memcpy(target[body_len..][0..actual_data.len], actual_data);
                    body_len += actual_data.len;
                }

                // Update stream state
                if (registry.get(f.header.stream_id)) |s| {
                    s.recv(f.header.frame_type, f.header.flags) catch {
                        try frame.writeRstStream(writer, f.header.stream_id, .stream_closed);
                        try writer.flush();
                    };
                }

                // END_STREAM on DATA — request is complete, dispatch to handler
                if (f.header.flags.has(Flags.end_stream) and pending_stream_id == f.header.stream_id and pending_header_block_len > 0) {
                    processRequest(
                        &registry, &decoder, &encoder, &flow,
                        &settings_sync.peer,
                        pending_header_block[0..pending_header_block_len],
                        pending_stream_id, if (body_heap) |h| h[0..body_len] else body_stack_buf[0..body_len],
                        writer, handler, io,
                    );
                    pending_stream_id = 0;
                    pending_header_block_len = 0;
                    body_len = 0;
                }
            },

            .rst_stream => {
                if (f.header.stream_id == 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
                if (registry.get(f.header.stream_id)) |s| {
                    s.recv(.rst_stream, Flags.none) catch {};
                }
                // DoS: rapid reset detection
                rst_stream_count += 1;
                if (rst_stream_count > max_rst_stream_per_cycle) {
                    try sendGoaway(writer, last_client_stream_id, .enhance_your_calm);
                    return;
                }
            },

            .priority => {
                // Deprecated in RFC 9113 but must be tolerated
                if (f.header.stream_id == 0) {
                    try sendGoaway(writer, last_client_stream_id, .protocol_error);
                    return;
                }
            },

            .push_promise => {
                // Clients must not send PUSH_PROMISE
                try sendGoaway(writer, last_client_stream_id, .protocol_error);
                return;
            },

            _ => {
                // Unknown frame types MUST be ignored (RFC 9113 §4.1)
            },
        }

        // Periodic GC of closed streams and reset DoS counters
        if (registry.len > 64) {
            registry.gc();
            rst_stream_count = 0;
        }
    }
}

/// Process a complete request (headers decoded from HPACK) and send the response.
fn processRequest(
    registry: *StreamRegistry,
    decoder: *hpack.Decoder,
    encoder: *hpack.Encoder,
    flow: *FlowControl.FlowController,
    peer_settings: *const Settings,
    header_block: []const u8,
    stream_id: u31,
    request_body: []const u8,
    writer: *Io.Writer,
    handler: Handler,
    io: Io,
) void {
    processRequestImpl(registry, decoder, encoder, flow, peer_settings, header_block, stream_id, request_body, writer, handler, io) catch {
        // Send RST_STREAM on error
        frame.writeRstStream(writer, stream_id, .internal_error) catch {};
        writer.flush() catch {};
    };
}

fn processRequestImpl(
    registry: *StreamRegistry,
    decoder: *hpack.Decoder,
    encoder: *hpack.Encoder,
    flow: *FlowControl.FlowController,
    peer_settings: *const Settings,
    header_block: []const u8,
    stream_id: u31,
    request_body: []const u8,
    writer: *Io.Writer,
    handler: Handler,
    io: Io,
) !void {
    // Create/get stream
    const stream = registry.getOrCreate(stream_id) catch |err| switch (err) {
        error.RefusedStream => {
            try frame.writeRstStream(writer, stream_id, .refused_stream);
            try writer.flush();
            return;
        },
        else => {
            try frame.writeRstStream(writer, stream_id, .protocol_error);
            try writer.flush();
            return;
        },
    };

    // Transition stream state for HEADERS recv
    // For requests with body, the stream was already opened by the frame loop
    // when it received HEADERS without END_STREAM. For bodyless requests, we
    // transition here.
    if (stream.state == .idle) {
        const es = request_body.len == 0;
        const flags_value: u8 = Flags.end_headers | if (es) Flags.end_stream else 0;
        stream.recv(.headers, .{ .value = flags_value }) catch {
            try frame.writeRstStream(writer, stream_id, .protocol_error);
            try writer.flush();
            return;
        };
    }

    // Decode HPACK headers
    var decoded_headers: [hpack.max_decoded_headers]hpack.HeaderField = undefined;
    const header_count = decoder.decode(header_block, &decoded_headers) catch {
        // HPACK decompression failure is a connection error
        try sendGoaway(writer, stream_id, .compression_error);
        return;
    };
    const headers = decoded_headers[0..header_count];

    // DoS: enforce header list size limit (RFC 9113 §10.5.1)
    {
        const max_header_list_size: usize = 8192; // matches our SETTINGS_MAX_HEADER_LIST_SIZE default
        var total_header_size: usize = 0;
        for (headers) |h| {
            total_header_size += h.name.len + h.value.len + 32;
        }
        if (total_header_size > max_header_list_size) {
            try frame.writeRstStream(writer, stream_id, .refused_stream);
            try writer.flush();
            return;
        }
    }

    // Extract pseudo-headers (RFC 9113 §8.3.1)
    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;

    for (headers) |h| {
        if (h.name.len > 0 and h.name[0] == ':') {
            if (mem.eql(u8, h.name, ":method")) {
                method = h.value;
            } else if (mem.eql(u8, h.name, ":path")) {
                path = h.value;
            } else if (mem.eql(u8, h.name, ":scheme")) {
                scheme = h.value;
            } else if (mem.eql(u8, h.name, ":authority")) {
                authority = h.value;
            }
        }
    }

    // Validate required pseudo-headers
    // RFC 9113 §8.5: CONNECT uses only :method and :authority (no :scheme or :path)
    const is_connect = method != null and mem.eql(u8, method.?, "CONNECT");
    if (is_connect) {
        if (authority == null or scheme != null or path != null) {
            try frame.writeRstStream(writer, stream_id, .protocol_error);
            try writer.flush();
            return;
        }
    } else {
        if (method == null or path == null or scheme == null) {
            try frame.writeRstStream(writer, stream_id, .protocol_error);
            try writer.flush();
            return;
        }
    }

    // Build a synthetic HTTP/1.1 request line + headers for the existing handler
    var request_buf: [8192]u8 = undefined;
    var pos: usize = 0;

    const m = method.?;
    // CONNECT: "CONNECT host:port HTTP/1.1\r\n", others: "GET /path HTTP/1.1\r\n"
    const p = if (is_connect) authority.? else path.?;
    @memcpy(request_buf[pos..][0..m.len], m);
    pos += m.len;
    request_buf[pos] = ' ';
    pos += 1;
    @memcpy(request_buf[pos..][0..p.len], p);
    pos += p.len;
    @memcpy(request_buf[pos..][0..11], " HTTP/1.1\r\n");
    pos += 11;

    // Host header from :authority
    if (authority) |auth| {
        @memcpy(request_buf[pos..][0..6], "Host: ");
        pos += 6;
        @memcpy(request_buf[pos..][0..auth.len], auth);
        pos += auth.len;
        @memcpy(request_buf[pos..][0..2], "\r\n");
        pos += 2;
    }

    // Regular headers (skip pseudo-headers)
    for (headers) |h| {
        if (h.name.len > 0 and h.name[0] == ':') continue;
        // Skip prohibited headers (RFC 9113 §8.2.2)
        if (Headers.eqlIgnoreCase(h.name, "connection")) continue;
        if (Headers.eqlIgnoreCase(h.name, "keep-alive")) continue;
        if (Headers.eqlIgnoreCase(h.name, "transfer-encoding")) continue;
        if (Headers.eqlIgnoreCase(h.name, "upgrade")) continue;

        if (pos + h.name.len + h.value.len + 4 > request_buf.len) break;
        @memcpy(request_buf[pos..][0..h.name.len], h.name);
        pos += h.name.len;
        @memcpy(request_buf[pos..][0..2], ": ");
        pos += 2;
        @memcpy(request_buf[pos..][0..h.value.len], h.value);
        pos += h.value.len;
        @memcpy(request_buf[pos..][0..2], "\r\n");
        pos += 2;
    }

    // Add Content-Length for request body
    if (request_body.len > 0) {
        var cl_tmp: [20]u8 = undefined;
        const cl_str = std.fmt.bufPrint(&cl_tmp, "{d}", .{request_body.len}) catch unreachable;
        @memcpy(request_buf[pos..][0..16], "Content-Length: ");
        pos += 16;
        @memcpy(request_buf[pos..][0..cl_str.len], cl_str);
        pos += cl_str.len;
        @memcpy(request_buf[pos..][0..2], "\r\n");
        pos += 2;
    }

    // End of headers
    @memcpy(request_buf[pos..][0..2], "\r\n");
    pos += 2;

    // Append request body
    if (request_body.len > 0 and pos + request_body.len <= request_buf.len) {
        @memcpy(request_buf[pos..][0..request_body.len], request_body);
        pos += request_body.len;
    }

    // Parse the synthetic request
    const request = Request.parse(request_buf[0..pos]) catch {
        try frame.writeRstStream(writer, stream_id, .protocol_error);
        try writer.flush();
        return;
    };

    // RFC 9113 §8.5: 100-continue — send informational HEADERS if client expects it
    if (request.headers.get("expect")) |expect_val| {
        if (Headers.eqlIgnoreCase(expect_val, "100-continue")) {
            // Send :status 100 as an informational response HEADERS frame
            var info_hdr_buf: [64]u8 = undefined;
            const info_len = encoder.encodeHeader(&info_hdr_buf, ":status", "100") catch 0;
            if (info_len > 0) {
                frame.writeFrame(writer, .headers, .{ .value = Flags.end_headers }, stream_id, info_hdr_buf[0..info_len]) catch {};
                writer.flush() catch {};
            }
        }
    }

    // Call the handler
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const timestamp = Date.now(io);
    var response = Connection.processRequest(allocator, io, timestamp, &request, handler);
    defer response.deinit(allocator);

    // --- HTTP/2 Server Push (RFC 9113 §8.4) ---
    // Send PUSH_PROMISE for each path the handler wants to push,
    // if the client hasn't disabled push.
    if (response.push_count > 0 and peer_settings.enable_push) {
        for (response.push_paths[0..response.push_count]) |maybe_push_path| {
            const push_path = maybe_push_path orelse continue;
            // Open a new server-initiated (even) stream for the push
            const push_stream = registry.open() catch break;
            const push_stream_id = push_stream.id;

            // Encode PUSH_PROMISE header block: the promised request headers
            var pp_hdr_buf: [1024]u8 = undefined;
            var pp_pos: usize = 0;
            // Promised Stream ID (4 bytes, first bit reserved)
            pp_hdr_buf[0] = @intCast((push_stream_id >> 24) & 0x7F);
            pp_hdr_buf[1] = @intCast((push_stream_id >> 16) & 0xFF);
            pp_hdr_buf[2] = @intCast((push_stream_id >> 8) & 0xFF);
            pp_hdr_buf[3] = @intCast(push_stream_id & 0xFF);
            pp_pos = 4;
            // Encode the promised request pseudo-headers
            pp_pos += encoder.encodeHeader(pp_hdr_buf[pp_pos..], ":method", "GET") catch break;
            pp_pos += encoder.encodeHeader(pp_hdr_buf[pp_pos..], ":path", push_path) catch break;
            if (scheme) |s| {
                pp_pos += encoder.encodeHeader(pp_hdr_buf[pp_pos..], ":scheme", s) catch break;
            }
            if (authority) |a| {
                pp_pos += encoder.encodeHeader(pp_hdr_buf[pp_pos..], ":authority", a) catch break;
            }

            // Send PUSH_PROMISE on the original stream
            frame.writeFrame(writer, .push_promise, .{ .value = Flags.end_headers }, stream_id, pp_hdr_buf[0..pp_pos]) catch break;
            writer.flush() catch break;

            // Now send the pushed response on the promised stream
            // Build a synthetic GET request for the push path
            var push_req_buf: [4096]u8 = undefined;
            var prp: usize = 0;
            @memcpy(push_req_buf[prp..][0..4], "GET ");
            prp += 4;
            @memcpy(push_req_buf[prp..][0..push_path.len], push_path);
            prp += push_path.len;
            @memcpy(push_req_buf[prp..][0..11], " HTTP/1.1\r\n");
            prp += 11;
            if (authority) |auth| {
                @memcpy(push_req_buf[prp..][0..6], "Host: ");
                prp += 6;
                @memcpy(push_req_buf[prp..][0..auth.len], auth);
                prp += auth.len;
                @memcpy(push_req_buf[prp..][0..2], "\r\n");
                prp += 2;
            }
            @memcpy(push_req_buf[prp..][0..2], "\r\n");
            prp += 2;

            const push_request = Request.parse(push_req_buf[0..prp]) catch break;
            var push_response = Connection.processRequest(allocator, io, timestamp, &push_request, handler);

            // Encode pushed response headers
            var push_resp_buf: [4096]u8 = undefined;
            var push_hpos: usize = 0;
            var push_status_str: [3]u8 = undefined;
            _ = std.fmt.bufPrint(&push_status_str, "{d}", .{push_response.status.toInt()}) catch break;
            push_hpos += encoder.encodeHeader(push_resp_buf[push_hpos..], ":status", &push_status_str) catch break;
            var push_lower_buf: [256]u8 = undefined;
            for (push_response.headers.entries[0..push_response.headers.len]) |entry| {
                if (entry.name.len == 0) continue;
                if (Headers.eqlIgnoreCase(entry.name, "connection")) continue;
                if (Headers.eqlIgnoreCase(entry.name, "transfer-encoding")) continue;
                if (push_hpos + entry.name.len + entry.value.len + 10 > push_resp_buf.len) break;
                push_hpos += encoder.encodeHeader(push_resp_buf[push_hpos..], lowerHeaderName(&push_lower_buf, entry.name), entry.value) catch break;
            }

            const push_has_body = !push_response.strip_body and push_response.body.len > 0;
            const push_hdr_flags: u8 = Flags.end_headers | if (!push_has_body) Flags.end_stream else 0;
            frame.writeFrame(writer, .headers, .{ .value = push_hdr_flags }, push_stream_id, push_resp_buf[0..push_hpos]) catch break;
            if (push_has_body) {
                const fw = h2.ConnectionIO.FrameWriter{ .max_frame_size = @intCast(peer_settings.max_frame_size) };
                fw.writeData(writer, push_stream_id, push_response.body, true) catch break;
            }
            writer.flush() catch break;

            push_response.deinit(allocator);
        }
    }

    // --- Encode and send the HTTP/2 response ---

    // Encode response headers via HPACK
    var resp_header_buf: [8192]u8 = undefined;
    var hpos: usize = 0;

    // :status pseudo-header
    var status_str: [3]u8 = undefined;
    _ = std.fmt.bufPrint(&status_str, "{d}", .{response.status.toInt()}) catch unreachable;
    hpos += try encoder.encodeHeader(resp_header_buf[hpos..], ":status", &status_str);

    // Response headers (RFC 9113 §8.2: names must be lowercase)
    var lower_buf: [256]u8 = undefined;
    for (response.headers.entries[0..response.headers.len]) |entry| {
        if (entry.name.len == 0) continue;
        // Skip HTTP/1.1-only headers
        if (Headers.eqlIgnoreCase(entry.name, "connection")) continue;
        if (Headers.eqlIgnoreCase(entry.name, "keep-alive")) continue;
        if (Headers.eqlIgnoreCase(entry.name, "transfer-encoding")) continue;
        if (hpos + entry.name.len + entry.value.len + 10 > resp_header_buf.len) break;
        hpos += try encoder.encodeHeader(resp_header_buf[hpos..], lowerHeaderName(&lower_buf, entry.name), entry.value);
    }

    // Content-Length if we have a body and auto_content_length
    if (response.auto_content_length and response.body.len > 0 and !response.strip_body) {
        var cl_buf: [20]u8 = undefined;
        const cl_str = std.fmt.bufPrint(&cl_buf, "{d}", .{response.body.len}) catch unreachable;
        hpos += try encoder.encodeHeader(resp_header_buf[hpos..], "content-length", cl_str);
    }

    const has_body = !response.strip_body and response.body.len > 0;
    const has_trailers = response.trailers != null and response.trailers.?.len > 0;
    // END_STREAM goes on headers only if no body and no trailers
    const header_flags: u8 = Flags.end_headers | if (!has_body and !has_trailers) Flags.end_stream else 0;

    // Send HEADERS frame(s) — split if exceeds max frame size
    const max_payload: usize = peer_settings.max_frame_size;
    if (hpos <= max_payload) {
        try frame.writeFrame(writer, .headers, .{ .value = header_flags }, stream_id, resp_header_buf[0..hpos]);
    } else {
        // First frame: HEADERS without END_HEADERS
        try frame.writeFrame(writer, .headers, Flags.none, stream_id, resp_header_buf[0..max_payload]);
        var sent: usize = max_payload;
        while (sent < hpos) {
            const chunk = @min(hpos - sent, max_payload);
            const is_last = sent + chunk >= hpos;
            const cont_flags: Flags = if (is_last) .{ .value = Flags.end_headers | if (!has_body) Flags.end_stream else 0 } else Flags.none;
            try frame.writeFrame(writer, .continuation, cont_flags, stream_id, resp_header_buf[sent..][0..chunk]);
            sent += chunk;
        }
    }

    // Send DATA frame(s) for the body
    if (has_body) {
        const body = response.body;
        var sent: usize = 0;
        var stall_count: usize = 0;
        while (sent < body.len) {
            const chunk = @min(body.len - sent, max_payload);

            // Flow control: respect connection & stream send window
            const raw_avail = flow.effectiveSendWindow(stream.send_window);
            if (raw_avail <= 0) {
                // Window is exhausted — yield to allow incoming WINDOW_UPDATE frames to be processed
                stall_count += 1;
                if (stall_count > 1000) {
                    // Avoid infinite loop if peer deadlocks or never sends WINDOW_UPDATE
                    return error.FlowControlBlocked;
                }
                std.Thread.yield() catch {};
                continue;
            }
            stall_count = 0;

            const send_len = @min(chunk, @as(usize, @intCast(raw_avail)));
            const is_last = (sent + send_len >= body.len);

            const data_flags: Flags = if (is_last and !has_trailers) .{ .value = Flags.end_stream } else Flags.none;
            try frame.writeFrame(writer, .data, data_flags, stream_id, body[sent..][0..send_len]);

            // Consume from flow control windows
            if (send_len > 0) {
                flow.send_window.consume(@intCast(send_len)) catch {};
                stream.send_window -= @intCast(send_len);
            }

            sent += send_len;
        }
    }

    // Send trailing HEADERS with END_STREAM if trailers are present
    if (has_trailers) {
        var trailer_buf: [4096]u8 = undefined;
        var tpos: usize = 0;
        const trailers = response.trailers.?;
        var trailer_lower_buf: [256]u8 = undefined;
        for (trailers.entries[0..trailers.len]) |entry| {
            if (entry.name.len == 0) continue;
            if (tpos + entry.name.len + entry.value.len + 10 > trailer_buf.len) break;
            tpos += encoder.encodeHeader(trailer_buf[tpos..], lowerHeaderName(&trailer_lower_buf, entry.name), entry.value) catch break;
        }
        if (tpos > 0) {
            const trailer_flags: u8 = Flags.end_headers | Flags.end_stream;
            try frame.writeFrame(writer, .headers, .{ .value = trailer_flags }, stream_id, trailer_buf[0..tpos]);
        }
    }

    // Update stream state for sent response
    stream.send(.headers, .{ .value = Flags.end_stream }) catch {};

    try writer.flush();
}

fn readFrameFromReader(reader: *Io.Reader) !frame.Frame {
    // Read the 9-byte frame header
    const hdr_buf = try reader.take(frame.header_size);
    const header = FrameHeader.parse(hdr_buf[0..frame.header_size]);

    if (header.length > frame.default_max_frame_size) {
        return error.FrameSizeError;
    }

    // Read the payload
    var payload: []const u8 = &.{};
    if (header.length > 0) {
        payload = try reader.take(header.length);
    }

    return .{
        .header = header,
        .payload = payload,
    };
}

fn sendGoaway(writer: *Io.Writer, last_stream_id: u31, error_code: ErrorCode) !void {
    try frame.writeGoaway(writer, last_stream_id, error_code, &.{});
    try writer.flush();
}
