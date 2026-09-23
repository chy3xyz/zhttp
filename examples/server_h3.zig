const std = @import("std");
const Io = std.Io;
const zhttp = @import("zhttp");
const httpz = zhttp;
const tls = httpz.tls;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    // The certificate is generated locally (see examples/gen_cert.sh) and is
    // not part of the repository, so it is read at run time rather than
    // embedded — the example has to build without it.
    const dir = std.Io.Dir.cwd().openDir(io, "examples/cert", .{}) catch {
        std.debug.print("\nError: Certificate directory not found.\n", .{});
        std.debug.print("Run the following to generate certificates:\n", .{});
        std.debug.print("  bash examples/gen_cert.sh\n\n", .{});
        return error.NoCertificate;
    };
    defer dir.close(io);

    var auth = tls.config.CertKeyPair.fromFilePath(allocator, io, dir, "cert.pem", "key.pem") catch {
        std.debug.print("\nError: Could not load certificates.\n", .{});
        std.debug.print("Run the following to generate certificates:\n", .{});
        std.debug.print("  bash examples/gen_cert.sh\n\n", .{});
        return error.InvalidCertificate;
    };
    defer auth.deinit(allocator);

    try httpz.h3.quic.setServerCert(auth.cert_pem, auth.key_pem);

    var server = try httpz.h3.Server.init(allocator, 8443, struct {
        fn handle(alloc: std.mem.Allocator, req: *const httpz.h3.Request) httpz.h3.Response {
            _ = alloc;
            // `req.method`, `req.path`, `req.headers.get("...")` and `req.body`
            // are the whole request the client sent.
            if (req.method != .GET) {
                return .{ .status = .method_not_allowed, .body = "only GET\n" };
            }
            return .{ .body = "Hello from httpz HTTP/3 Server!\n" };
        }
    }.handle, .{});
    defer server.deinit();

    std.debug.print("httpz HTTP/3 Server running on UDP 127.0.0.1:8443...\n", .{});
    try server.run();
}
