const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const h3 = b.option(bool, "h3", "Enable HTTP/3 support (native zquic transport + OpenSSL QUIC-TLS)") orelse false;

    // Library path for OpenSSL, when it is not on the system search path.
    const openssl_lib = b.option([]const u8, "openssl-lib", "Path to the OpenSSL library directory");
    const lib_paths: LibPaths = .{ .openssl = openssl_lib };

    // Hand-written OpenSSL bindings (see src/openssl_c.zig) — no C translation,
    // so no OpenSSL headers are needed to build.
    const openssl_c_mod = b.createModule(.{
        .root_source_file = b.path("src/openssl_c.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Build options exposed to source code.
    const options = b.addOptions();
    options.addOption(bool, "h3", h3);

    var imports: std.ArrayList(std.Build.Module.Import) = .empty;
    imports.append(b.allocator, .{ .name = "openssl_c", .module = openssl_c_mod }) catch @panic("OOM");
    imports.append(b.allocator, .{ .name = "httpz_options", .module = options.createModule() }) catch @panic("OOM");

    // The native HTTP/3 stack is built on zquic's Zig QUIC transport.
    var zquic_mod: ?*std.Build.Module = null;

    // HTTP/3 is the native stack: zquic owns the QUIC transport and OpenSSL's
    // QUIC-TLS callbacks own the handshake. No ngtcp2/nghttp3 translation.
    if (h3) {
        const zquic_dep = b.dependency("zquic", .{
            .target = target,
            .optimize = optimize,
            .http3 = true,
            .doq = false,
            .examples = false,
        });
        zquic_mod = zquic_dep.module("zquic");
        imports.append(b.allocator, .{ .name = "zquic", .module = zquic_mod.? }) catch @panic("OOM");
    }

    // Library module
    const zhttp_imports = imports.toOwnedSlice(b.allocator) catch @panic("OOM");
    const zhttp_mod = b.addModule("zhttp", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = zhttp_imports,
    });
    linkSystemLibraries(zhttp_mod, lib_paths, h3);

    // Example executables
    const examples = [_][]const u8{
        "client_http",
        "client_https",
        "server_http",
        "server_https",
        "server_websocket",
        "server_router",
        "server_streaming",
        "server_repro",
    };
    // These import `httpz.h3`, which is only wired up with -Dh3=true.
    const h3_examples = [_][]const u8{
        "server_h3",
        "server_h3_router",
        "client_h3",
    };

    inline for (examples) |name| {
        addExample(b, zhttp_mod, target, optimize, name);
    }
    if (h3) {
        inline for (h3_examples) |name| {
            addExample(b, zhttp_mod, target, optimize, name);
        }
    }

    // Module tests
    const mod_tests = b.addTest(.{
        .root_module = zhttp_mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Native HTTP/3 layer tests. Compiled against zquic and OpenSSL directly so
    // the transport can be exercised without the rest of the library.
    var native_test_step: ?*std.Build.Step = null;
    if (h3) {
        const native_mod = b.createModule(.{
            .root_source_file = b.path("src/native_tests.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zquic", .module = zquic_mod.? },
                .{ .name = "openssl_c", .module = openssl_c_mod },
            },
        });
        native_mod.linkSystemLibrary("ssl", .{});
        native_mod.linkSystemLibrary("crypto", .{});
        native_mod.link_libc = true;
        if (lib_paths.openssl) |path| native_mod.addLibraryPath(.{ .cwd_relative = path });
        const native_tests = b.addTest(.{ .root_module = native_mod });
        const run_native_tests = b.addRunArtifact(native_tests);
        const native_step = b.step("test-native", "Run native HTTP/3 layer tests");
        native_step.dependOn(&run_native_tests.step);
        native_test_step = &run_native_tests.step;
    }

    // Integration tests
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zhttp", .module = zhttp_mod },
            },
        }),
    });

    const run_integration_tests = b.addRunArtifact(integration_tests);

    // Integration test step (separate because they use networking)
    const integration_step = b.step("test-integration", "Run integration tests");
    integration_step.dependOn(&run_integration_tests.step);

    // Test step
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    if (native_test_step) |step| test_step.dependOn(step);

    // Benchmark step
    //
    // The micro-benchmarks measure the library, so the library is built the way
    // a release build would: `zig build bench` against a default (Debug) library
    // reports numbers nobody ships with — three times the per-request cost of
    // the same code in ReleaseFast. An explicit `-Doptimize` still wins.
    const bench_optimize: std.builtin.OptimizeMode =
        if (b.user_input_options.contains("optimize")) optimize else .ReleaseFast;
    const bench_zhttp_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = bench_optimize,
        .imports = zhttp_imports,
    });
    linkSystemLibraries(bench_zhttp_mod, lib_paths, h3);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("benches/bench_http.zig"),
        .target = target,
        .optimize = bench_optimize,
        .imports = &.{
            .{ .name = "zhttp", .module = bench_zhttp_mod },
        },
    });
    const bench_exe = b.addExecutable(.{
        .name = "bench_http",
        .root_module = bench_mod,
    });
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run httpz micro-benchmarks");
    bench_step.dependOn(&run_bench.step);

    // HTTP/3 benchmark — imports `httpz.h3`, which only exists with -Dh3=true.
    if (h3) {
        const bench_h3_mod = b.createModule(.{
            .root_source_file = b.path("benches/bench_h3.zig"),
            .target = target,
            .optimize = bench_optimize,
            .imports = &.{
                .{ .name = "zhttp", .module = bench_zhttp_mod },
            },
        });
        const bench_h3_exe = b.addExecutable(.{
            .name = "bench_h3",
            .root_module = bench_h3_mod,
        });
        const run_bench_h3 = b.addRunArtifact(bench_h3_exe);
        // The benchmark reads its TLS certificate relative to the project root.
        run_bench_h3.setCwd(b.path("."));
        const bench_h3_step = b.step("bench-h3", "Run httpz HTTP/3 benchmarks (requires -Dh3=true)");
        bench_h3_step.dependOn(&run_bench_h3.step);
    }

    // Coverage step using kcov
    const coverage_step = b.step("coverage", "Run tests with kcov code coverage");

    const cov_mod_test = b.addTest(.{
        .root_module = zhttp_mod,
        .use_llvm = true,
        .use_lld = true,
    });

    const kcov_mod = b.addSystemCommand(&.{"kcov"});
    kcov_mod.addPrefixedDirectoryArg("--include-path=", b.path("src"));
    kcov_mod.addArg("kcov-output");
    kcov_mod.addArtifactArg(cov_mod_test);
    coverage_step.dependOn(&kcov_mod.step);
}

/// Everything the library needs from the system: OpenSSL always. The QUIC and
/// HTTP/3 layers are Zig code now (zquic + OpenSSL's QUIC-TLS callbacks), so no
/// ngtcp2/nghttp3 library is linked even when h3 is enabled.
/// Where the libraries linked below live, when they are not on the system's own
/// search path. A null field means "look it up the usual way".
const LibPaths = struct {
    openssl: ?[]const u8 = null,
};

fn linkSystemLibraries(mod: *std.Build.Module, libs: LibPaths, h3: bool) void {
    _ = h3;
    if (libs.openssl) |path| mod.addLibraryPath(.{ .cwd_relative = path });
    mod.linkSystemLibrary("ssl", .{});
    mod.linkSystemLibrary("crypto", .{});
    mod.link_libc = true;
}

fn addExample(
    b: *std.Build,
    zhttp_mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    comptime name: []const u8,
) void {
    const example_mod = b.createModule(.{
        .root_source_file = b.path("examples/" ++ name ++ ".zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zhttp", .module = zhttp_mod },
        },
    });
    const example_exe = b.addExecutable(.{
        .name = name,
        .root_module = example_mod,
    });
    b.installArtifact(example_exe);

    const run_step = b.step("example_" ++ name, "Run the " ++ name ++ " example");
    const run_cmd = b.addRunArtifact(example_exe);
    run_step.dependOn(&run_cmd.step);
}
