const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const h3 = b.option(bool, "h3", "Enable HTTP/3 support (requires nghttp3 and ngtcp2)") orelse false;

    // Include paths — configurable via -D flags for cross-platform support.
    // Defaults work for macOS Homebrew. Override for Linux/pkg-config paths.
    const openssl_include = b.option([]const u8, "openssl-include",
        "Path to OpenSSL include directory") orelse "/opt/homebrew/opt/openssl@3/include";

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

    // Translate C headers for HTTP/3 (ngtcp2 + nghttp3)
    if (h3) {
        const ngtcp2_include = b.option([]const u8, "ngtcp2-include",
            "Path to ngtcp2 include directory") orelse "/opt/homebrew/opt/libngtcp2/include";
        const nghttp3_include = b.option([]const u8, "nghttp3-include",
            "Path to nghttp3 include directory") orelse "/opt/homebrew/opt/libnghttp3/include";

        const ngtcp2_h = b.addTranslateC(.{
            .root_source_file = b.path("src/h3/ngtcp2.h"),
            .target = target,
            .optimize = optimize,
        });
        ngtcp2_h.addIncludePath(.{ .cwd_relative = ngtcp2_include });
        ngtcp2_h.addIncludePath(.{ .cwd_relative = openssl_include });
        const ngtcp2_mod = ngtcp2_h.createModule();

        const nghttp3_h = b.addTranslateC(.{
            .root_source_file = b.path("src/h3/nghttp3.h"),
            .target = target,
            .optimize = optimize,
        });
        nghttp3_h.addIncludePath(.{ .cwd_relative = nghttp3_include });
        const nghttp3_mod = nghttp3_h.createModule();

        imports.append(b.allocator, .{ .name = "ngtcp2_c", .module = ngtcp2_mod }) catch @panic("OOM");
        imports.append(b.allocator, .{ .name = "nghttp3_c", .module = nghttp3_mod }) catch @panic("OOM");
    }

    // Library module
    const zhttp_mod = b.addModule("zhttp", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports.toOwnedSlice(b.allocator) catch @panic("OOM"),
    });
    zhttp_mod.linkSystemLibrary("ssl", .{});
    zhttp_mod.linkSystemLibrary("crypto", .{});
    if (h3) {
        zhttp_mod.linkSystemLibrary("ngtcp2", .{});
        zhttp_mod.linkSystemLibrary("ngtcp2_crypto_ossl", .{});
        zhttp_mod.linkSystemLibrary("nghttp3", .{});
    }
    zhttp_mod.link_libc = true;

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

    // Benchmark step
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("benches/bench_http.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "zhttp", .module = zhttp_mod },
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
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zhttp", .module = zhttp_mod },
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
