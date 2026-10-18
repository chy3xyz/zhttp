const std = @import("std");
const AdapterFile = @import("Adapter.zig");
const Adapter = AdapterFile.Adapter;
const h3 = @import("Server.zig");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Router = @import("../Router.zig");
const WebSocket = @import("../server/WebSocket.zig");

const testing = std.testing;

fn makeRequest(method: h3.Method, path: []const u8, authority: []const u8) h3.Request {
    return .{
        .method = method,
        .path = path,
        .authority = authority,
        .headers = .{ .len = 0 },
        .body = "",
    };
}

fn call(adapter: *Adapter, request: *const h3.Request) h3.Response {
    // Exercise the exact public ContextHandler the server installs.
    return Adapter.contextHandler()(adapter, testing.allocator, request);
}

fn findHeader(headers: []const h3.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) return header.value;
    }
    return null;
}

fn countHeader(headers: []const h3.Header, name: []const u8) usize {
    var count: usize = 0;
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) count += 1;
    }
    return count;
}

fn expectLowercaseNames(headers: []const h3.Header) !void {
    for (headers) |header| {
        for (header.name) |byte| {
            try testing.expect(!std.ascii.isUpper(byte));
        }
    }
}

fn helloHandler(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return Response.init(.ok, "text/plain", "hello");
}

test "Adapter: direct handler GET keeps status, body, and Date/Server" {
    const routes = [_]Router.Route{
        .{ .method = .GET, .path = "/hello", .handler = helloHandler },
    };
    const handler = Router.handler(&routes);

    const adapter = try Adapter.create(testing.allocator, testing.io, handler, .{});
    defer adapter.destroy();

    var request = makeRequest(.GET, "/hello?name=world", "example.com");
    const response = call(adapter, &request);

    try testing.expectEqual(h3.StatusCode.ok, response.status);
    try testing.expectEqualStrings("hello", response.body);
    // Response.init's Content-Type becomes content_type, not a header field.
    try testing.expectEqualStrings("text/plain", response.content_type);
    try testing.expect(findHeader(response.headers, "content-type") == null);
    // Connection.addStandardHeaders adds both; the adapter lowercases them.
    try testing.expect(findHeader(response.headers, "date") != null);
    try testing.expectEqualStrings("httpz/0.1", findHeader(response.headers, "server").?);
    // 200 has no reason to carry a hop-by-hop connection header.
    try testing.expect(findHeader(response.headers, "connection") == null);
}

test "Adapter: router miss becomes 404" {
    const routes = [_]Router.Route{
        .{ .method = .GET, .path = "/hello", .handler = helloHandler },
    };
    const handler = Router.handler(&routes);

    const adapter = try Adapter.create(testing.allocator, testing.io, handler, .{});
    defer adapter.destroy();

    var request = makeRequest(.GET, "/missing", "example.com");
    const response = call(adapter, &request);

    try testing.expectEqual(h3.StatusCode.not_found, response.status);
    try testing.expectEqualStrings("Not Found", response.body);
    try testing.expectEqualStrings("text/plain", response.content_type);
}

fn mixedHeaderHandler(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    var response = Response.init(.ok, "text/plain", "headers");
    response.headers.append("X-Custom-Header", "MiXeD") catch {};
    response.headers.append("SET-COOKIE", "a=1") catch {};
    response.headers.append("Set-Cookie", "b=2") catch {};
    response.headers.append("Connection", "keep-alive") catch {};
    response.headers.append("TE", "trailers") catch {};
    response.headers.append("Trailer", "Expires") catch {};
    response.headers.append("Transfer-Encoding", "chunked") catch {};
    response.headers.append("Upgrade", "h2c") catch {};
    response.headers.append("Keep-Alive", "timeout=5") catch {};
    return response;
}

test "Adapter: lowercases names, duplicates Set-Cookie, drops hop-by-hop headers" {
    const adapter = try Adapter.create(testing.allocator, testing.io, mixedHeaderHandler, .{});
    defer adapter.destroy();

    var request = makeRequest(.GET, "/headers", "example.com");
    const response = call(adapter, &request);

    try testing.expectEqual(h3.StatusCode.ok, response.status);
    try testing.expectEqualStrings("headers", response.body);
    try expectLowercaseNames(response.headers);

    try testing.expectEqualStrings("MiXeD", findHeader(response.headers, "x-custom-header").?);
    try testing.expectEqual(@as(usize, 2), countHeader(response.headers, "set-cookie"));
    try testing.expect(findHeader(response.headers, "content-type") == null);
    try testing.expect(findHeader(response.headers, "content-length") == null);
    try testing.expect(findHeader(response.headers, "connection") == null);
    try testing.expect(findHeader(response.headers, "te") == null);
    try testing.expect(findHeader(response.headers, "trailer") == null);
    try testing.expect(findHeader(response.headers, "transfer-encoding") == null);
    try testing.expect(findHeader(response.headers, "upgrade") == null);
    try testing.expect(findHeader(response.headers, "keep-alive") == null);
    try testing.expect(findHeader(response.headers, "date") != null);
    try testing.expect(findHeader(response.headers, "server") != null);
}

/// A Response whose header values and body live in the Response's own
/// embedded buffer. The adapter must copy all of them out.
var response_owned_by_handler: Response = undefined;
var handler_response_addr: usize = 0;

fn responseOwnedHandler(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    response_owned_by_handler = .{ .status = .ok };

    const content_type = response_owned_by_handler.allocServerBuf("text/x-local".len).?;
    @memcpy(content_type, "text/x-local");
    response_owned_by_handler.headers.append("Content-Type", content_type) catch {};

    const body = response_owned_by_handler.allocServerBuf("local-body".len).?;
    @memcpy(body, "local-body");
    response_owned_by_handler.body = body;

    const value = response_owned_by_handler.allocServerBuf("local-value".len).?;
    @memcpy(value, "local-value");
    response_owned_by_handler.headers.append("X-Local", value) catch {};

    handler_response_addr = @intFromPtr(&response_owned_by_handler);
    return response_owned_by_handler;
}

fn pointsIntoResponse(pointer: [*]const u8) bool {
    const address = @intFromPtr(pointer);
    return address >= handler_response_addr and
        address < handler_response_addr + @sizeOf(Response);
}

test "Adapter: returned slices never point into the zhttp Response" {
    const adapter = try Adapter.create(testing.allocator, testing.io, responseOwnedHandler, .{});
    defer adapter.destroy();

    var request = makeRequest(.GET, "/owned", "example.com");
    const response = call(adapter, &request);

    try testing.expect(handler_response_addr != 0);
    try testing.expectEqualStrings("text/x-local", response.content_type);
    try testing.expectEqualStrings("local-body", response.body);
    const local = findHeader(response.headers, "x-local").?;
    try testing.expectEqualStrings("local-value", local);

    try testing.expect(!pointsIntoResponse(response.content_type.ptr));
    try testing.expect(!pointsIntoResponse(response.body.ptr));
    try testing.expect(!pointsIntoResponse(local.ptr));
}

fn echoHandler(allocator: std.mem.Allocator, _: std.Io, request: *const Request) Response {
    const body = std.fmt.allocPrint(allocator, "echo:{s}", .{request.uri}) catch
        return Response.init(.internal_server_error, "text/plain", "alloc failed");
    return Response.init(.ok, "text/plain", body);
}

test "Adapter: two sequential requests survive the per-request arena reset" {
    const routes = [_]Router.Route{
        .{ .method = .GET, .path = "/echo/*rest", .handler = echoHandler },
    };
    const handler = Router.handler(&routes);

    const adapter = try Adapter.create(testing.allocator, testing.io, handler, .{});
    defer adapter.destroy();

    var first_request = makeRequest(.GET, "/echo/first", "example.com");
    const first = call(adapter, &first_request);
    try testing.expectEqualStrings("echo:/echo/first", first.body);
    try testing.expect(findHeader(first.headers, "date") != null);

    var second_request = makeRequest(.GET, "/echo/second", "example.com");
    const second = call(adapter, &second_request);
    try testing.expectEqual(h3.StatusCode.ok, second.status);
    try testing.expectEqualStrings("echo:/echo/second", second.body);
    try testing.expect(findHeader(second.headers, "date") != null);

    // A third call proves resetting did not leave the arena in a broken state.
    var third_request = makeRequest(.GET, "/echo/third", "example.com");
    const third = call(adapter, &third_request);
    try testing.expectEqualStrings("echo:/echo/third", third.body);
}

fn switchingProtocolsHandler(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return .{ .status = .switching_protocols, .body = "upgrade" };
}

fn websocketConnection(_: *WebSocket.Conn, _: *const Request) void {}

fn websocketRouteHandler(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return .{ .status = .ok, .ws_handler = websocketConnection, .body = "ws" };
}

test "Adapter: WebSocket and 101 results are rejected with 501" {
    const adapter = try Adapter.create(testing.allocator, testing.io, switchingProtocolsHandler, .{});
    defer adapter.destroy();

    var request = makeRequest(.GET, "/ws", "example.com");
    const response = call(adapter, &request);
    try testing.expectEqual(h3.StatusCode.not_implemented, response.status);
    try testing.expectEqualStrings("Not Implemented", response.body);

    const ws_adapter = try Adapter.create(testing.allocator, testing.io, websocketRouteHandler, .{});
    defer ws_adapter.destroy();
    const ws_response = call(ws_adapter, &request);
    try testing.expectEqual(h3.StatusCode.not_implemented, ws_response.status);
}

var stream_ran: bool = false;

fn tenByteStream(_: ?*anyopaque, writer: *std.Io.Writer) void {
    stream_ran = true;
    _ = writer.writeAll("0123456789") catch {};
}

fn streamHandler(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return .{
        .status = .ok,
        .stream_fn = tenByteStream,
        .stream_context = null,
    };
}

test "Adapter: streamed body fits, overflows with 500, and always runs" {
    const exact = try Adapter.create(testing.allocator, testing.io, streamHandler, .{
        .max_buffered_stream = 10,
    });
    defer exact.destroy();

    var request = makeRequest(.GET, "/stream", "example.com");
    stream_ran = false;
    const exact_response = call(exact, &request);
    try testing.expectEqual(h3.StatusCode.ok, exact_response.status);
    try testing.expectEqualStrings("0123456789", exact_response.body);
    try testing.expect(stream_ran);

    const small = try Adapter.create(testing.allocator, testing.io, streamHandler, .{
        .max_buffered_stream = 4,
    });
    defer small.destroy();

    stream_ran = false;
    const overflow_response = call(small, &request);
    try testing.expectEqual(h3.StatusCode.internal_server_error, overflow_response.status);
    try testing.expectEqualStrings("Internal Server Error", overflow_response.body);
    // The stream function must run so sendFile's fd-owning context closes it.
    try testing.expect(stream_ran);
}

test "Adapter: zero buffering cap overflows a non-empty stream" {
    const adapter = try Adapter.create(testing.allocator, testing.io, streamHandler, .{
        .max_buffered_stream = 0,
    });
    defer adapter.destroy();

    var request = makeRequest(.GET, "/stream", "example.com");
    stream_ran = false;
    const response = call(adapter, &request);
    try testing.expectEqual(h3.StatusCode.internal_server_error, response.status);
    try testing.expect(stream_ran);
}

var seen_request: Request = undefined;

fn captureHandler(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
    seen_request = request.*;
    return Response.init(.ok, "text/plain", "captured");
}

test "Adapter: request fields, headers, authority, and body are converted" {
    const adapter = try Adapter.create(testing.allocator, testing.io, captureHandler, .{});
    defer adapter.destroy();

    var request = makeRequest(.POST, "/things?q=1", "example.com");
    request.headers.append("X-Test", "yes") catch {};
    request.body = "payload";

    const response = call(adapter, &request);
    try testing.expectEqual(h3.StatusCode.ok, response.status);
    try testing.expectEqualStrings("captured", response.body);

    try testing.expectEqual(Request.Method.POST, seen_request.method);
    try testing.expectEqualStrings("/things?q=1", seen_request.uri);
    // HTTP/3 has no HTTP/1.x version; 1.1 is the sentinel.
    try testing.expectEqual(Request.Version.http_1_1, seen_request.version);
    try testing.expectEqualStrings("payload", seen_request.body);
    try testing.expectEqualStrings("", seen_request.raw);
    try testing.expectEqual(@as(usize, 0), seen_request.params.len);
    try testing.expect(seen_request.action == null);
    try testing.expectEqual(@as(usize, 0), seen_request.context.len);
    try testing.expectEqualStrings("yes", seen_request.headers.get("X-Test").?);
    // `:authority` is exposed as Host because Request has no authority field.
    try testing.expectEqualStrings("example.com", seen_request.headers.get("Host").?);
}

fn jsonHandler(allocator: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return Response.json(allocator, .{ .ok = true }, .ok) catch
        Response.init(.internal_server_error, "text/plain", "json failed");
}

test "Adapter: Response.json allocation is copied before release" {
    const adapter = try Adapter.create(testing.allocator, testing.io, jsonHandler, .{});
    defer adapter.destroy();

    var request = makeRequest(.GET, "/json", "example.com");
    const response = call(adapter, &request);
    try testing.expectEqual(h3.StatusCode.ok, response.status);
    try testing.expect(std.mem.indexOf(u8, response.body, "\"ok\":true") != null);
}

test "Adapter: composes with h3.Server.initWithContext" {
    const adapter = try Adapter.create(testing.allocator, testing.io, helloHandler, .{});
    defer adapter.destroy();

    var server = try h3.Server.initWithContext(
        testing.allocator,
        0,
        adapter,
        Adapter.contextHandler(),
        .{ .max_request_body_bytes = 4096 },
    );
    defer server.deinit();
    try testing.expectEqual(@as(usize, 0), server.connectionCount());
}
