const std = @import("std");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");

/// Security Headers configuration options.
pub const Options = struct {
    x_content_type_options: ?[]const u8 = "nosniff",
    x_frame_options: ?[]const u8 = "DENY",
    x_xss_protection: ?[]const u8 = "0",
    hsts: ?[]const u8 = "max-age=31536000; includeSubDomains",
    content_security_policy: ?[]const u8 = null,
    referrer_policy: ?[]const u8 = "no-referrer-when-downgrade",
};

/// Applies standard security headers to an HTTP response.
pub fn apply(response: *Response, options: Options) void {
    if (options.x_content_type_options) |v| {
        response.headers.append("X-Content-Type-Options", v) catch {};
    }
    if (options.x_frame_options) |v| {
        response.headers.append("X-Frame-Options", v) catch {};
    }
    if (options.x_xss_protection) |v| {
        response.headers.append("X-XSS-Protection", v) catch {};
    }
    if (options.hsts) |v| {
        response.headers.append("Strict-Transport-Security", v) catch {};
    }
    if (options.content_security_policy) |v| {
        response.headers.append("Content-Security-Policy", v) catch {};
    }
    if (options.referrer_policy) |v| {
        response.headers.append("Referrer-Policy", v) catch {};
    }
}

test "security_headers middleware" {
    var resp = Response.init(.ok, "text/plain", "");
    apply(&resp, .{
        .content_security_policy = "default-src 'self'",
    });

    try std.testing.expectEqualStrings("nosniff", resp.headers.get("X-Content-Type-Options").?);
    try std.testing.expectEqualStrings("DENY", resp.headers.get("X-Frame-Options").?);
    try std.testing.expectEqualStrings("0", resp.headers.get("X-XSS-Protection").?);
    try std.testing.expectEqualStrings("max-age=31536000; includeSubDomains", resp.headers.get("Strict-Transport-Security").?);
    try std.testing.expectEqualStrings("default-src 'self'", resp.headers.get("Content-Security-Policy").?);
    try std.testing.expectEqualStrings("no-referrer-when-downgrade", resp.headers.get("Referrer-Policy").?);
}
