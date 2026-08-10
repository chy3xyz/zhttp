const std = @import("std");
const Io = std.Io;
const zhttp = @import("zhttp");
const httpz = zhttp;
const tls = httpz.tls;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;

    std.debug.print("httpsz - HTTPS/1.1 Server\n", .{});
    std.debug.print("Listening on 127.0.0.1:4433\n", .{});

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

    var server = httpz.Server.init(.{
        .port = 4433,
        .address = "127.0.0.1",
        .tls_config = .{
            .auth = &auth,
        },
    }, handler);

    server.run(io) catch |err| switch (err) {
        error.AddressInUse => {
            std.debug.print("Error: port 4433 is already in use\n", .{});
            std.process.exit(1);
        },
    };
}

fn handler(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    if (std.mem.eql(u8, request.uri, "/")) {
        return httpz.Response.init(.ok, "text/plain", "Hello from httpsz!");
    }

    if (std.mem.eql(u8, request.uri, "/health")) {
        return httpz.Response.init(.ok, "application/json", "{\"status\":\"ok\"}");
    }

    return httpz.Response.init(.not_found, "text/plain", "Not Found");
}
