const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    { // library
        const lib_mod = b.addModule("landlock", .{
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

        const options = b.addOptions();

        const ignore_unsupported = b.option(bool, "ignore-unsupported-actions", "whether to implicitly ignore restrictions unsupported by a given Landlock ABI") orelse true;
        const enable_logging = b.option(bool, "enable-logging", "whether to enable logging of implicitly ignored restrictions; useful for debugging") orelse false;
        options.addOption(bool, "enable_logging", enable_logging);
        options.addOption(bool, "ignore_unsupported", ignore_unsupported);
        lib_mod.addOptions("build_options", options);
    }

    { // example CLI runner program
        const lib_mod = b.createModule(.{
            .root_source_file = b.path("src/Landlock.zig"),
            .optimize = optimize,
            .target = target,
        });

        const options = b.addOptions();
        options.addOption(bool, "enable_logging", false);
        options.addOption(bool, "ignore_unsupported", true);
        lib_mod.addOptions("build_options", options);

        const runner = b.addExecutable(.{
            .name = "landlock-run",
            .root_source_file = b.path("src/runner.zig"),
            .optimize = optimize,
            .target = target,
        });
        runner.root_module.addImport("landlock", lib_mod);
        b.installArtifact(runner);
    }
}
