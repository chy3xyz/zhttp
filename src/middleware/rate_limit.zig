const std = @import("std");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");

/// Token bucket rate limiter entry.
const Bucket = struct {
    tokens: f64,
    last_update_ms: i64,
};

/// RateLimiter implements thread-safe token bucket rate limiting per IP or key.
pub const RateLimiter = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    buckets: std.StringHashMap(Bucket),
    max_tokens: f64,
    refill_rate_per_sec: f64,

    pub fn init(allocator: std.mem.Allocator, max_tokens: usize, refill_rate_per_sec: usize) RateLimiter {
        return .{
            .allocator = allocator,
            .buckets = std.StringHashMap(Bucket).init(allocator),
            .max_tokens = @floatFromInt(max_tokens),
            .refill_rate_per_sec = @floatFromInt(refill_rate_per_sec),
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        var it = self.buckets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.buckets.deinit();
    }

    /// Attempts to consume 1 token for the specified key.
    /// Returns true if allowed, false if rate limited.
    pub fn allow(self: *RateLimiter, key: []const u8) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now_ms = std.time.milliTimestamp();
        const gop = try self.buckets.getOrPut(key);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = .{
                .tokens = self.max_tokens - 1.0,
                .last_update_ms = now_ms,
            };
            return true;
        }

        const bucket = gop.value_ptr;
        const elapsed_sec: f64 = @as(f64, @floatFromInt(now_ms - bucket.last_update_ms)) / 1000.0;
        bucket.tokens = @min(self.max_tokens, bucket.tokens + (elapsed_sec * self.refill_rate_per_sec));
        bucket.last_update_ms = now_ms;

        if (bucket.tokens >= 1.0) {
            bucket.tokens -= 1.0;
            return true;
        }

        return false;
    }

    /// Enforces rate limiting on a request/response pair.
    /// If rate limited, sets response status to 429 Too Many Requests.
    pub fn enforce(self: *RateLimiter, key: []const u8, response: *Response) !bool {
        const is_allowed = try self.allow(key);
        if (!is_allowed) {
            response.status = .too_many_requests;
            response.body = "429 Too Many Requests\n";
            try response.headers.append("Retry-After", "1");
            return false;
        }
        return true;
    }
};

test "rate_limiter token bucket" {
    var limiter = RateLimiter.init(std.testing.allocator, 2, 1);
    defer limiter.deinit();

    // First two requests should pass
    try std.testing.expect(try limiter.allow("client1"));
    try std.testing.expect(try limiter.allow("client1"));

    // Third request immediately after should fail
    try std.testing.expect(!try limiter.allow("client1"));

    // Different client should still have capacity
    try std.testing.expect(try limiter.allow("client2"));
}
