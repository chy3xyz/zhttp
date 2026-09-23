const std = @import("std");
const Io = std.Io;
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
    /// Io handle used for locking and for reading the wall clock.
    io: Io,
    mutex: Io.Mutex = .init,
    buckets: std.StringHashMap(Bucket),
    max_tokens: f64,
    refill_rate_per_sec: f64,

    pub fn init(allocator: std.mem.Allocator, io: Io, max_tokens: usize, refill_rate_per_sec: usize) RateLimiter {
        return .{
            .allocator = allocator,
            .io = io,
            .buckets = std.StringHashMap(Bucket).init(allocator),
            .max_tokens = @floatFromInt(max_tokens),
            .refill_rate_per_sec = @floatFromInt(refill_rate_per_sec),
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        var it = self.buckets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.buckets.deinit();
    }

    /// Attempts to consume 1 token for the specified key.
    /// Returns true if allowed, false if rate limited.
    pub fn allow(self: *RateLimiter, key: []const u8) !bool {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);

        const now_ms = Io.Clock.real.now(self.io).toMilliseconds();
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
    var limiter = RateLimiter.init(std.testing.allocator, std.testing.io, 2, 1);
    defer limiter.deinit();

    // First two requests should pass
    try std.testing.expect(try limiter.allow("client1"));
    try std.testing.expect(try limiter.allow("client1"));

    // Third request immediately after should fail
    try std.testing.expect(!try limiter.allow("client1"));

    // Different client should still have capacity
    try std.testing.expect(try limiter.allow("client2"));
}

test "rate_limiter enforces 429 on exhausted bucket" {
    var limiter = RateLimiter.init(std.testing.allocator, std.testing.io, 2, 0);
    defer limiter.deinit();

    var response: Response = .{};
    try std.testing.expect(try limiter.enforce("10.0.0.1", &response));
    try std.testing.expect(try limiter.enforce("10.0.0.1", &response));

    try std.testing.expect(!try limiter.enforce("10.0.0.1", &response));
    try std.testing.expectEqual(Response.StatusCode.too_many_requests, response.status);
    try std.testing.expectEqualStrings("429 Too Many Requests\n", response.body);
    try std.testing.expectEqualStrings("1", response.headers.get("Retry-After").?);

    // A different key is unaffected by the first key's exhaustion
    var other: Response = .{};
    try std.testing.expect(try limiter.enforce("10.0.0.2", &other));
    try std.testing.expectEqual(Response.StatusCode.ok, other.status);
}

test "rate_limiter refills tokens over time" {
    // 50 refill tokens/sec refills one token every 20ms, so sleeping longer
    // than that cannot race with the wall clock.
    var limiter = RateLimiter.init(std.testing.allocator, std.testing.io, 1, 50);
    defer limiter.deinit();

    try std.testing.expect(try limiter.allow("client"));

    try std.Io.sleep(std.testing.io, .fromMilliseconds(60), .awake);
    try std.testing.expect(try limiter.allow("client"));
}
