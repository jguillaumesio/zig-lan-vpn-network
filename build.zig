const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // macOS needs libc for the utun ioctl (std.c.ioctl); Windows benefits from
    // libc for the Wintun path. Linux uses raw syscalls and stays libc-free.
    switch (target.result.os.tag) {
        .macos, .windows => exe_mod.link_libc = true,
        else => {},
    }

    const exe = b.addExecutable(.{
        .name = "hamachi-like",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // `zig build test` runs unit tests scattered across the sources plus the
    // end-to-end coordinator handshake test.
    const tests = b.addTest(.{ .root_module = exe_mod });
    const run_tests = b.addRunArtifact(tests);

    const it_mod = b.createModule(.{
        .root_source_file = b.path("src/integration_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    switch (target.result.os.tag) {
        .macos, .windows => it_mod.link_libc = true,
        else => {},
    }
    const it_tests = b.addTest(.{ .root_module = it_mod });
    const run_it = b.addRunArtifact(it_tests);

    const test_step = b.step("test", "Run unit + integration tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_it.step);
}
