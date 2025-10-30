const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    { // library
        const lib_mod = b.addModule("Landlock", .{
            .root_source_file = b.path("src/Landlock.zig"),
            .optimize = optimize,
            .target = target,
        });

        const lib = b.addLibrary(.{
            .name = "landlock-zig",
            .root_module = lib_mod,
        });

        b.installDirectory(.{
            .install_dir = .{ .custom = "doc" },
            .source_dir = lib.getEmittedDocs(),
            .install_subdir = "",
        });
    }

    { // example CLI runner program
        const lib_mod = b.createModule(.{
            .root_source_file = b.path("src/Landlock.zig"),
            .optimize = optimize,
            .target = target,
        });

        const runner = b.addExecutable(.{
            .name = "landlock-run",
            .root_module = b.addModule("landlock-run", .{
                .root_source_file = b.path("src/runner.zig"),
                .optimize = optimize,
                .target = target,
                .imports = &.{ .{ .name = "Landlock", .module = lib_mod } },
            }),
        });
        b.installArtifact(runner);
    }
}
