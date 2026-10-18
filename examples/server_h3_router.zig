const std = @import("std");
const Io = std.Io;
const zhttp = @import("zhttp");
const httpz = zhttp;
const tls = httpz.tls;

// One route table, dispatched unchanged for HTTP/3: h3.Adapter converts the H3
// request into the same httpz.Request the TCP server hands to Router.handler.
const routes = [_]httpz.Router.Route{
    .{ .method = .GET, .path = "/", .handler = handleHome },
    .{ .method = .GET, .path = "/hello/:name", .handler = handleHello },
    .{ .method = .POST, .path = "/echo", .handler = handleEcho },
};

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

    // The adapter is the server's context pointer, so it must stay alive for
    // the whole run. It is created before the server, which makes the defers
    // run in the right order: server.deinit() first, adapter.destroy() second.
    const adapter = try httpz.h3.Adapter.create(
        allocator,
        io,
        httpz.Router.handler(&routes),
        .{},
    );
    defer adapter.destroy();

    var server = try httpz.h3.Server.initWithContext(
        allocator,
        8444,
        adapter,
        httpz.h3.Adapter.contextHandler(),
        .{},
    );
    defer server.deinit();

    std.debug.print("httpz Router over native HTTP/3 listening on UDP 127.0.0.1:8444\n", .{});
    std.debug.print("Routes:\n", .{});
    std.debug.print("  GET  /             - Home page\n", .{});
    std.debug.print("  GET  /hello/:name  - Greet a name\n", .{});
    std.debug.print("  POST /echo         - Echo the request body\n", .{});
    try server.run();
}

fn handleHome(_: std.mem.Allocator, _: std.Io, _: *const httpz.Request) httpz.Response {
    return httpz.Response.init(.ok, "text/plain",
        \\httpz Router over native HTTP/3
        \\
        \\Routes:
        \\  GET  /
        \\  GET  /hello/:name
        \\  POST /echo
        \\
    );
}

fn handleHello(allocator: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    const name = request.params.get("name") orelse "world";
    // The H3 adapter passes its per-request arena here and copies the body
    // before returning to its event loop, so this allocation needs no
    // Response.deinit: the arena reset after the request reclaims it.
    const body = std.fmt.allocPrint(allocator, "Hello, {s}!\n", .{name}) catch
        return httpz.Response.init(.internal_server_error, "text/plain", "Out of memory\n");
    return httpz.Response.init(.ok, "text/plain", body);
}

fn handleEcho(_: std.mem.Allocator, _: std.Io, request: *const httpz.Request) httpz.Response {
    // The request body borrows from the H3 request; the adapter copies it into
    // its arena when it builds the H3 response.
    return httpz.Response.init(.ok, "text/plain", request.body);
}
