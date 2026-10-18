//! HTTP/3 framing surface over the native session type.

pub const native = @import("native/http3.zig");

pub const Session = native.Session;
pub const HeaderField = native.HeaderField;
pub const Header = native.Header;
pub const Handler = native.Handler;
pub const Request = native.Request;
pub const Response = native.Response;
pub const Method = native.Method;
pub const StatusCode = native.StatusCode;

pub const H3_NO_ERROR: u64 = 0x0100;
pub const default_max_request_body_bytes: usize = 1024 * 1024;

test {
    _ = Session;
}
