const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/landlock.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "landlock",
        .root_module = lib_mod,
    });

    _ = b.addModule("landlock", .{ .root_source_file = b.path("src/landlock.zig"), .optimize = optimize, .target = target });

    const check = b.step("check", "See if landlock-zig builds");
    check.dependOn(&lib.step);
}
