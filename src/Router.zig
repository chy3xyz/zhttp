const Router = @This();
const std = @import("std");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Connection = @import("server/Connection.zig");
const WebSocket = @import("server/WebSocket.zig");

// Pattern syntax supported by the dispatcher:
//   literal      — matches one path segment exactly (`/users`)
//   :name        — matches a single path segment and captures it as `name`
//   *name        — catch-all: must be the last segment; matches the rest of the
//                  path (possibly empty) and captures it as `name`. Requires the
//                  prefix to be followed by `/` in the request path, i.e.
//                  `/foo/*rest` matches `/foo/` and `/foo/bar/baz` but not `/foo`.
//   :verb suffix — AIP-136 Action attached to the last segment (e.g.
//                  `/users/:id:archive`). A non-leading `:` on the last segment
//                  introduces an Action. Action names must match
//                  [A-Za-z][A-Za-z0-9]*. Not allowed on catch-all segments.
//                  Routes match on the (method, path, action) triple — a Route
//                  with no Action does not match a URL with one, and vice
//                  versa. AIP-136 requires custom methods to use POST, so a
//                  Route with an Action must declare `.method = .POST`
//                  (enforced at comptime). The parsed Action is exposed as
//                  `Request.action`.

pub const Handler = Connection.Handler;

/// Re-export Params from Request for backwards compatibility.
pub const Params = Request.Params;

/// Method selector for a route. Mirrors `Request.Method` and adds `ALL`, a
/// wildcard that matches every verb — use it for prefix routes that should
/// accept any method (e.g. a proxy).
pub const Method = enum {
    ALL,
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    OPTIONS,
    TRACE,
    CONNECT,
    PATCH,

    /// True when this route method should accept the given HTTP method.
    pub fn matches(self: Method, request_method: Request.Method) bool {
        return switch (self) {
            .ALL => true,
            .GET => request_method == .GET,
            .HEAD => request_method == .HEAD,
            .POST => request_method == .POST,
            .PUT => request_method == .PUT,
            .DELETE => request_method == .DELETE,
            .OPTIONS => request_method == .OPTIONS,
            .TRACE => request_method == .TRACE,
            .CONNECT => request_method == .CONNECT,
            .PATCH => request_method == .PATCH,
        };
    }
};

/// A single route definition. Use `method = .ALL` for routes that should
/// match every HTTP verb.
pub const Route = struct {
    method: Method,
    path: []const u8,
    handler: Handler,
    ws: ?struct { handler: WebSocket.Handler } = null,
};

/// Build a Connection.Handler from a comptime route table.
/// Dispatches requests by matching method and path, extracting parameters.
pub fn handler(comptime routes: []const Route) Connection.Handler {
    return handlerWithFallback(routes, defaultNotFound);
}

/// Build a Connection.Handler with a custom fallback for unmatched routes.
pub fn handlerWithFallback(comptime routes: []const Route, comptime not_found: Handler) Connection.Handler {
    return struct {
        fn dispatch(allocator: std.mem.Allocator, io: std.Io, request: *const Request) Response {
            const raw_path = extractPath(request.uri);
            const url_split = extractAction(raw_path);

            var mutable_req = request.*;
            mutable_req.action = url_split.action;

            inline for (routes) |route| {
                const pattern_split = comptime parsePatternAction(route.path);
                comptime if (pattern_split.action != null and route.method != .POST) {
                    @compileError("AIP-136 action routes must use .method = .POST; pattern '" ++ route.path ++ "' has action '" ++ pattern_split.action.? ++ "' on method " ++ @tagName(route.method));
                };
                if (route.method.matches(request.method)) {
                    if (actionEql(pattern_split.action, url_split.action)) {
                        if (matchPath(pattern_split.path, url_split.path)) |params| {
                            mutable_req.params = params;
                            var response = route.handler(allocator, io, &mutable_req);
                            if (route.ws) |ws| {
                                response.ws_handler = ws.handler;
                            }
                            return response;
                        }
                    }
                }
            }

            return not_found(allocator, io, &mutable_req);
        }
    }.dispatch;
}

fn defaultNotFound(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
    return Response.init(.not_found, "text/plain", "Not Found");
}

/// Result of splitting an AIP-136 Action off of a path or pattern.
pub const ActionSplit = struct { path: []const u8, action: ?[]const u8 };

/// Extract the AIP-136 Action from the last segment of a URL path at runtime.
///
/// Returns the path with the `:action` suffix removed and the Action name.
/// Recognized only when the last segment contains a non-leading `:` followed by
/// a tail matching `[A-Za-z][A-Za-z0-9]*`. Any other `:tail` (invalid
/// characters, empty, multiple `:` in one segment) is left as part of the path
/// and the returned action is `null` — incoming URLs that happen to contain
/// `:` in non-AIP forms keep matching whatever literal/param routes they did
/// before.
pub fn extractAction(path: []const u8) ActionSplit {
    var trimmed = path;
    if (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
        trimmed = trimmed[0 .. trimmed.len - 1];
    }
    const last_slash = std.mem.lastIndexOfScalar(u8, trimmed, '/');
    const last_seg_start: usize = if (last_slash) |pos| pos + 1 else 0;
    if (last_seg_start >= trimmed.len) return .{ .path = path, .action = null };
    const last_seg = trimmed[last_seg_start..];
    var i: usize = 1;
    while (i < last_seg.len) : (i += 1) {
        if (last_seg[i] == ':') {
            const tail = last_seg[i + 1 ..];
            if (!isValidActionName(tail)) return .{ .path = path, .action = null };
            return .{ .path = trimmed[0 .. last_seg_start + i], .action = tail };
        }
    }
    return .{ .path = path, .action = null };
}

/// Comptime: split a Route Pattern into its path-pattern and optional Action.
///
/// Compile-errors on invalid Action names and on Actions attached to a
/// catch-all segment (`*name:action` is disallowed because catch-alls
/// swallow everything by design).
pub fn parsePatternAction(comptime pattern: []const u8) ActionSplit {
    comptime {
        const last_slash = std.mem.lastIndexOfScalar(u8, pattern, '/');
        const last_seg_start: usize = if (last_slash) |pos| pos + 1 else 0;
        if (last_seg_start >= pattern.len) return .{ .path = pattern, .action = null };
        const last_seg = pattern[last_seg_start..];

        if (last_seg[0] == '*') {
            for (last_seg) |c| {
                if (c == ':') {
                    @compileError("action not allowed on catch-all segment in pattern '" ++ pattern ++ "'");
                }
            }
            return .{ .path = pattern, .action = null };
        }

        var i: usize = 1;
        while (i < last_seg.len) : (i += 1) {
            if (last_seg[i] == ':') {
                const tail = last_seg[i + 1 ..];
                if (!isValidActionName(tail)) {
                    @compileError("invalid action name '" ++ tail ++ "' in pattern '" ++ pattern ++ "' (must match [A-Za-z][A-Za-z0-9]*)");
                }
                return .{ .path = pattern[0 .. last_seg_start + i], .action = tail };
            }
        }
        return .{ .path = pattern, .action = null };
    }
}

fn isValidActionName(s: []const u8) bool {
    if (s.len == 0) return false;
    if (!std.ascii.isAlphabetic(s[0])) return false;
    for (s[1..]) |c| {
        if (!std.ascii.isAlphanumeric(c)) return false;
    }
    return true;
}

fn actionEql(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null and b == null) return true;
    if (a == null or b == null) return false;
    return std.mem.eql(u8, a.?, b.?);
}

/// Extract the path component from a URI, stripping query string and fragment.
pub fn extractPath(uri: []const u8) []const u8 {
    var end = uri.len;
    for (uri, 0..) |c, i| {
        if (c == '?' or c == '#') {
            end = i;
            break;
        }
    }
    return uri[0..end];
}

/// Match a comptime path pattern against a runtime path, extracting parameters.
///
/// Pattern syntax:
///   literal — matches one path segment exactly (e.g. `/users`)
///   :name   — matches a single segment and binds it as `name`
///   *name   — matches the rest of the path (possibly empty) and binds it as
///             `name`; must be the last segment in the pattern. The prefix
///             before `*name` must be followed by `/` in the request path.
pub fn matchPath(comptime pattern: []const u8, path: []const u8) ?Params {
    const segments = comptime splitSegments(pattern);

    // The number of `:param` / `*rest` segments is known at comptime; reject
    // patterns that would overflow Params.entries at runtime.
    comptime {
        var param_count: usize = 0;
        for (segments) |seg| {
            if (seg.len > 0 and (seg[0] == ':' or seg[0] == '*')) param_count += 1;
        }
        if (param_count > Params.max_params) {
            @compileError(std.fmt.comptimePrint("route pattern '{s}' captures {d} parameters, exceeding Params.max_params ({d})", .{ pattern, param_count, Params.max_params }));
        }
    }

    const has_catch_all = comptime blk: {
        if (segments.len == 0) break :blk false;
        break :blk segments[segments.len - 1][0] == '*';
    };

    // Catch-all keeps the trailing slash in `rest` (it's valid content).
    // Non-catch-all paths get a trailing slash stripped for tolerance.
    var rest = if (has_catch_all)
        stripLeadingSlashOnly(path)
    else
        stripLeadingAndTrailingSlash(path);

    var params: Params = .{};
    // Tracks whether the previous segment consumed a `/` separator from the
    // path. The catch-all requires this so that `/foo/*rest` does NOT match
    // `/foo` — only `/foo/` and deeper. Starts true because the leading `/`
    // of the path has already been stripped.
    var prev_consumed_slash = true;

    inline for (segments, 0..) |seg, i| {
        const is_last = i == segments.len - 1;
        if (seg[0] == '*') {
            // Catch-all: requires a separator to have been consumed by the
            // preceding segment, otherwise `/foo/*rest` would match `/foo`.
            if (!prev_consumed_slash) return null;
            params.entries[params.len] = .{
                .name = seg[1..],
                .value = rest,
            };
            params.len += 1;
            rest = "";
            // `inline for` has no break; the is_last branch below skips the
            // residual length check for catch-all segments.
        } else if (seg[0] == ':') {
            // Single-segment param.
            const slash_pos = std.mem.indexOfScalar(u8, rest, '/');
            const value = if (slash_pos) |pos| rest[0..pos] else rest;
            if (value.len == 0) return null;
            params.entries[params.len] = .{
                .name = seg[1..],
                .value = value,
            };
            params.len += 1;
            if (slash_pos) |pos| {
                rest = rest[pos + 1 ..];
                prev_consumed_slash = true;
            } else {
                rest = "";
                prev_consumed_slash = false;
            }
        } else {
            // Literal segment — must match exactly.
            if (rest.len < seg.len) return null;
            if (!std.mem.eql(u8, rest[0..seg.len], seg)) return null;
            const after = rest[seg.len..];
            if (after.len == 0) {
                rest = "";
                prev_consumed_slash = false;
            } else if (after[0] == '/') {
                rest = after[1..];
                prev_consumed_slash = true;
            } else {
                return null;
            }
        }

        // Last segment: in non-catch-all mode the path must be exhausted.
        if (is_last and seg[0] != '*') {
            if (rest.len != 0) return null;
        }
    }

    if (segments.len == 0) {
        if (rest.len != 0) return null;
    }

    return params;
}

fn stripLeadingAndTrailingSlash(path: []const u8) []const u8 {
    if (path.len > 0 and path[0] == '/') {
        const trimmed = path[1..];
        if (trimmed.len > 0 and trimmed[trimmed.len - 1] == '/') {
            return trimmed[0 .. trimmed.len - 1];
        }
        return trimmed;
    }
    return path;
}

fn stripLeadingSlashOnly(path: []const u8) []const u8 {
    if (path.len > 0 and path[0] == '/') return path[1..];
    return path;
}

/// Split a pattern like "/users/:id/posts" into ["users", ":id", "posts"] at comptime.
/// Enforces that a `*name` catch-all segment, if present, is the last segment
/// and has a non-empty name.
fn splitSegments(comptime pattern: []const u8) []const []const u8 {
    comptime {
        var count: usize = 0;
        var rest: []const u8 = pattern;
        // Strip leading slash
        if (rest.len > 0 and rest[0] == '/') rest = rest[1..];
        // Strip trailing slash
        if (rest.len > 0 and rest[rest.len - 1] == '/') rest = rest[0 .. rest.len - 1];
        if (rest.len == 0) return &.{};

        // Count segments
        var tmp = rest;
        while (true) {
            count += 1;
            if (std.mem.indexOfScalar(u8, tmp, '/')) |pos| {
                tmp = tmp[pos + 1 ..];
            } else break;
        }

        // Extract segments
        var segments: [count][]const u8 = undefined;
        var i: usize = 0;
        var src = rest;
        while (true) {
            if (std.mem.indexOfScalar(u8, src, '/')) |pos| {
                segments[i] = src[0..pos];
                src = src[pos + 1 ..];
                i += 1;
            } else {
                segments[i] = src;
                break;
            }
        }

        // Validate catch-all usage: a `*name` segment must be last and must
        // have a non-empty name.
        for (segments, 0..) |seg, idx| {
            if (seg.len > 0 and seg[0] == '*') {
                if (idx != segments.len - 1) {
                    @compileError("catch-all segment must be the last segment in pattern '" ++ pattern ++ "'");
                }
                if (seg.len < 2) {
                    @compileError("catch-all segment needs a name, e.g. '*rest' in pattern '" ++ pattern ++ "'");
                }
            }
        }

        const final = segments;
        return &final;
    }
}

// --- Tests ---

const testing = std.testing;

test "Router: extractPath strips query string" {
    try testing.expectEqualStrings("/users", extractPath("/users?page=1"));
    try testing.expectEqualStrings("/users", extractPath("/users#section"));
    try testing.expectEqualStrings("/users", extractPath("/users?page=1#section"));
    try testing.expectEqualStrings("/users/42", extractPath("/users/42"));
    try testing.expectEqualStrings("/", extractPath("/"));
    try testing.expectEqualStrings("", extractPath(""));
}

test "Router: matchPath exact match" {
    const result = matchPath("/", "/");
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 0), result.?.len);
}

test "Router: matchPath single segment" {
    const result = matchPath("/users", "/users");
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 0), result.?.len);
}

test "Router: matchPath no match" {
    try testing.expect(matchPath("/users", "/posts") == null);
    try testing.expect(matchPath("/users", "/") == null);
    try testing.expect(matchPath("/", "/users") == null);
}

test "Router: matchPath single param" {
    const result = matchPath("/users/:id", "/users/42");
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 1), result.?.len);
    try testing.expectEqualStrings("id", result.?.entries[0].name);
    try testing.expectEqualStrings("42", result.?.entries[0].value);
}

test "Router: matchPath multiple params" {
    const result = matchPath("/users/:id/posts/:post_id", "/users/42/posts/7");
    try testing.expect(result != null);
    try testing.expectEqual(@as(usize, 2), result.?.len);
    try testing.expectEqualStrings("id", result.?.entries[0].name);
    try testing.expectEqualStrings("42", result.?.entries[0].value);
    try testing.expectEqualStrings("post_id", result.?.entries[1].name);
    try testing.expectEqualStrings("7", result.?.entries[1].value);
}

test "Router: matchPath trailing slash tolerance" {
    const result = matchPath("/users/:id", "/users/42/");
    try testing.expect(result != null);
    try testing.expectEqualStrings("42", result.?.entries[0].value);

    const result2 = matchPath("/users", "/users/");
    try testing.expect(result2 != null);
}

test "Router: matchPath empty param rejected" {
    try testing.expect(matchPath("/users/:id", "/users/") == null);
}

test "Router: matchPath extra segments rejected" {
    try testing.expect(matchPath("/users/:id", "/users/42/extra") == null);
}

test "Router: Params.get" {
    var params: Params = .{};
    params.entries[0] = .{ .name = "id", .value = "42" };
    params.entries[1] = .{ .name = "name", .value = "alice" };
    params.len = 2;

    try testing.expectEqualStrings("42", params.get("id").?);
    try testing.expectEqualStrings("alice", params.get("name").?);
    try testing.expect(params.get("missing") == null);
}

test "Router: dispatch selects correct handler" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "home");
            }
        }.h },
        .{ .method = .GET, .path = "/users/:id", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", request.params.get("id") orelse "none");
            }
        }.h },
        .{ .method = .POST, .path = "/users", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.created, "text/plain", "created");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    // GET /
    const req1 = try Request.parseConst("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp1 = dispatch(std.testing.allocator, test_io, &req1);
    try testing.expectEqualStrings("home", resp1.body);

    // GET /users/42
    const req2 = try Request.parseConst("GET /users/42 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp2 = dispatch(std.testing.allocator, test_io, &req2);
    try testing.expectEqualStrings("42", resp2.body);

    // POST /users
    const req3 = try Request.parseConst("POST /users HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp3 = dispatch(std.testing.allocator, test_io, &req3);
    try testing.expectEqual(Response.StatusCode.created, resp3.status);

    // GET /nonexistent → 404
    const req4 = try Request.parseConst("GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp4 = dispatch(std.testing.allocator, test_io, &req4);
    try testing.expectEqual(Response.StatusCode.not_found, resp4.status);
}

test "Router: custom 404 fallback" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "home");
            }
        }.h },
    };

    const custom_404 = struct {
        fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
            return Response.init(.not_found, "text/html", "<h1>Custom 404</h1>");
        }
    }.h;

    const dispatch = handlerWithFallback(&routes, custom_404);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("<h1>Custom 404</h1>", resp.body);
}

test "Router: dispatch with query string" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/search", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "search");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("GET /search?q=test HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("search", resp.body);
}

test "Router: matchPath catch-all root" {
    const r1 = matchPath("/*rest", "/");
    try testing.expect(r1 != null);
    try testing.expectEqualStrings("rest", r1.?.entries[0].name);
    try testing.expectEqualStrings("", r1.?.entries[0].value);

    const r2 = matchPath("/*rest", "/foo");
    try testing.expect(r2 != null);
    try testing.expectEqualStrings("foo", r2.?.entries[0].value);

    const r3 = matchPath("/*rest", "/foo/bar/baz");
    try testing.expect(r3 != null);
    try testing.expectEqualStrings("foo/bar/baz", r3.?.entries[0].value);
}

test "Router: matchPath catch-all prefix" {
    // /foo/*rest should match /foo/ and /foo/... but not /foo and not /foobar
    const r1 = matchPath("/foo/*rest", "/foo/");
    try testing.expect(r1 != null);
    try testing.expectEqualStrings("", r1.?.entries[0].value);

    const r2 = matchPath("/foo/*rest", "/foo/bar");
    try testing.expect(r2 != null);
    try testing.expectEqualStrings("bar", r2.?.entries[0].value);

    const r3 = matchPath("/foo/*rest", "/foo/bar/baz/qux");
    try testing.expect(r3 != null);
    try testing.expectEqualStrings("bar/baz/qux", r3.?.entries[0].value);

    try testing.expect(matchPath("/foo/*rest", "/foo") == null);
    try testing.expect(matchPath("/foo/*rest", "/foobar") == null);
    try testing.expect(matchPath("/foo/*rest", "/") == null);
}

test "Router: matchPath catch-all preserves query trimming via dispatcher" {
    // extractPath strips query, so matchPath sees the bare path.
    const r = matchPath("/api/*rest", extractPath("/api/users/42?q=1"));
    try testing.expect(r != null);
    try testing.expectEqualStrings("users/42", r.?.entries[0].value);
}

test "Router: matchPath named param then catch-all" {
    const r = matchPath("/api/:app/*rest", "/api/demo/data/batch");
    try testing.expect(r != null);
    try testing.expectEqual(@as(usize, 2), r.?.len);
    try testing.expectEqualStrings("app", r.?.entries[0].name);
    try testing.expectEqualStrings("demo", r.?.entries[0].value);
    try testing.expectEqualStrings("rest", r.?.entries[1].name);
    try testing.expectEqualStrings("data/batch", r.?.entries[1].value);

    const r2 = matchPath("/api/:app/*rest", "/api/demo/");
    try testing.expect(r2 != null);
    try testing.expectEqualStrings("demo", r2.?.entries[0].value);
    try testing.expectEqualStrings("", r2.?.entries[1].value);
}

test "Router: any-method route matches all verbs" {
    const routes = [_]Route{
        .{ .method = .ALL, .path = "/api/*rest", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", request.params.get("rest") orelse "");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req_get = try Request.parseConst("GET /api/foo HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp_get = dispatch(std.testing.allocator, test_io, &req_get);
    try testing.expectEqualStrings("foo", resp_get.body);

    const req_post = try Request.parseConst("POST /api/bar HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp_post = dispatch(std.testing.allocator, test_io, &req_post);
    try testing.expectEqualStrings("bar", resp_post.body);

    const req_delete = try Request.parseConst("DELETE /api/baz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp_delete = dispatch(std.testing.allocator, test_io, &req_delete);
    try testing.expectEqualStrings("baz", resp_delete.body);
}

test "Router: first-match-wins ordering with catch-alls" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/@cnc/admin/*rest", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "admin");
            }
        }.h },
        .{ .method = .GET, .path = "/@cnc/*rest", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "static");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req1 = try Request.parseConst("GET /@cnc/admin/users HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try testing.expectEqualStrings("admin", dispatch(std.testing.allocator, test_io, &req1).body);

    const req2 = try Request.parseConst("GET /@cnc/cnc.mjs HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try testing.expectEqualStrings("static", dispatch(std.testing.allocator, test_io, &req2).body);
}

test "Router: ws_handler is set on response" {
    const ws_fn = struct {
        fn h(_: *WebSocket.Conn, _: *const Request) void {}
    }.h;

    const routes = [_]Route{
        .{ .method = .GET, .path = "/ws", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return WebSocket.upgradeResponse(request) orelse
                    Response.init(.bad_request, "text/plain", "upgrade failed");
            }
        }.h, .ws = .{ .handler = ws_fn } },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst(
        "GET /ws HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "\r\n",
    );
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.switching_protocols, resp.status);
    try testing.expect(resp.ws_handler != null);
}

// --- AIP-136 Action tests ---

test "Router: extractAction valid action" {
    const r = extractAction("/users/123:archive");
    try testing.expectEqualStrings("/users/123", r.path);
    try testing.expectEqualStrings("archive", r.action.?);
}

test "Router: extractAction collection-level action" {
    const r = extractAction("/users:batchGet");
    try testing.expectEqualStrings("/users", r.path);
    try testing.expectEqualStrings("batchGet", r.action.?);
}

test "Router: extractAction trailing slash" {
    const r = extractAction("/users/123:archive/");
    try testing.expectEqualStrings("/users/123", r.path);
    try testing.expectEqualStrings("archive", r.action.?);
}

test "Router: extractAction no colon" {
    const r = extractAction("/users/123");
    try testing.expectEqualStrings("/users/123", r.path);
    try testing.expect(r.action == null);
}

test "Router: extractAction invalid character class falls back to literal" {
    const r = extractAction("/users/123:foo-bar");
    try testing.expectEqualStrings("/users/123:foo-bar", r.path);
    try testing.expect(r.action == null);
}

test "Router: extractAction multiple colons in last segment" {
    // First non-leading `:` splits; tail `bar:baz` is invalid → no action.
    const r = extractAction("/users/foo:bar:baz");
    try testing.expectEqualStrings("/users/foo:bar:baz", r.path);
    try testing.expect(r.action == null);
}

test "Router: extractAction empty tail" {
    const r = extractAction("/users/123:");
    try testing.expectEqualStrings("/users/123:", r.path);
    try testing.expect(r.action == null);
}

test "Router: extractAction leading colon in segment is not an action" {
    // `:foo` is the segment — leading `:` is the path-param sigil, not Action.
    const r = extractAction("/:foo");
    try testing.expectEqualStrings("/:foo", r.path);
    try testing.expect(r.action == null);
}

test "Router: extractAction colon in non-last segment is literal" {
    const r = extractAction("/users/foo:archive/extra");
    try testing.expectEqualStrings("/users/foo:archive/extra", r.path);
    try testing.expect(r.action == null);
}

test "Router: parsePatternAction extracts action from pattern" {
    const r = comptime parsePatternAction("/users/:id:archive");
    try testing.expectEqualStrings("/users/:id", r.path);
    try testing.expectEqualStrings("archive", r.action.?);
}

test "Router: parsePatternAction no action returns original" {
    const r = comptime parsePatternAction("/users/:id");
    try testing.expectEqualStrings("/users/:id", r.path);
    try testing.expect(r.action == null);
}

test "Router: dispatch matches action route" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id:archive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", request.params.get("id") orelse "");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("POST /users/42:archive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("42", resp.body);
}

test "Router: dispatch action route does not match URL without action" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id:archive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "matched");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("POST /users/42 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.not_found, resp.status);
}

test "Router: dispatch plain route does not match URL with action" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "matched");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("POST /users/42:archive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.not_found, resp.status);
}

test "Router: dispatch picks the right action among several" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id:archive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "archived");
            }
        }.h },
        .{ .method = .POST, .path = "/users/:id:unarchive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "unarchived");
            }
        }.h },
        .{ .method = .POST, .path = "/users/:id:transfer", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "transferred");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const r1 = try Request.parseConst("POST /users/1:archive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    try testing.expectEqualStrings("archived", dispatch(std.testing.allocator, test_io, &r1).body);

    const r2 = try Request.parseConst("POST /users/1:unarchive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    try testing.expectEqualStrings("unarchived", dispatch(std.testing.allocator, test_io, &r2).body);

    const r3 = try Request.parseConst("POST /users/1:transfer HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    try testing.expectEqualStrings("transferred", dispatch(std.testing.allocator, test_io, &r3).body);

    const r4 = try Request.parseConst("POST /users/1:unknown HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    try testing.expectEqual(Response.StatusCode.not_found, dispatch(std.testing.allocator, test_io, &r4).status);
}

test "Router: dispatch sets request.action for matched route" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id:archive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", request.action orelse "<none>");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("POST /users/42:archive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("archive", resp.body);
}

test "Router: dispatch sets request.action on 404 fall-through" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "home");
            }
        }.h },
    };

    const custom_404 = struct {
        fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
            return Response.init(.not_found, "text/plain", request.action orelse "<none>");
        }
    }.h;

    const dispatch = handlerWithFallback(&routes, custom_404);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("POST /users/42:archive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.not_found, resp.status);
    try testing.expectEqualStrings("archive", resp.body);
}

test "Router: dispatch leaves request.action null when URL has no action" {
    const routes = [_]Route{
        .{ .method = .GET, .path = "/users/:id", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", if (request.action == null) "null" else "set");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("GET /users/42 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try testing.expectEqualStrings("null", dispatch(std.testing.allocator, test_io, &req).body);
}

test "Router: invalid action in URL falls back to literal param capture" {
    // `:foo-bar` is not a valid action — it stays as part of the param value.
    const routes = [_]Route{
        .{ .method = .GET, .path = "/items/:sku", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", request.params.get("sku") orelse "");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("GET /items/SKU-123:foo-bar HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("SKU-123:foo-bar", resp.body);
}

test "Router: collection-level action route" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users:batchGet", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "batched");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("POST /users:batchGet HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("batched", resp.body);
}

test "Router: action route coexists with plain route on same path" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id:archive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "archived");
            }
        }.h },
        .{ .method = .GET, .path = "/users/:id", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "got");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const r1 = try Request.parseConst("GET /users/42 HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try testing.expectEqualStrings("got", dispatch(std.testing.allocator, test_io, &r1).body);

    const r2 = try Request.parseConst("POST /users/42:archive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    try testing.expectEqualStrings("archived", dispatch(std.testing.allocator, test_io, &r2).body);
}

test "Router: action route with query string" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id:archive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, request: *const Request) Response {
                return Response.init(.ok, "text/plain", request.params.get("id") orelse "");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("POST /users/42:archive?reason=spam HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqualStrings("42", resp.body);
}

test "Router: action route with trailing slash" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id:archive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "ok");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("POST /users/42:archive/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.ok, resp.status);
}

test "Router: action route rejects non-POST GET request at runtime" {
    const routes = [_]Route{
        .{ .method = .POST, .path = "/users/:id:archive", .handler = struct {
            fn h(_: std.mem.Allocator, _: std.Io, _: *const Request) Response {
                return Response.init(.ok, "text/plain", "ok");
            }
        }.h },
    };

    const dispatch = handler(&routes);
    const test_io: std.Io = .{ .userdata = null, .vtable = undefined };

    const req = try Request.parseConst("GET /users/42:archive HTTP/1.1\r\nHost: localhost\r\n\r\n");
    const resp = dispatch(std.testing.allocator, test_io, &req);
    try testing.expectEqual(Response.StatusCode.not_found, resp.status);
}
