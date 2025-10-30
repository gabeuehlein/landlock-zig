//! Example CLI program to show off `landlock-zig`'s usage.

const std = @import("std");
const eql = std.mem.eql;
const sliceTo = std.mem.sliceTo;
const Landlock = @import("Landlock");

pub fn main() !void {
    var arena_allocator: std.heap.ArenaAllocator = .init(std.heap.smp_allocator);
    defer arena_allocator.deinit();
    var arena = arena_allocator.allocator();
    var i: usize = 1;
    const argv = std.os.argv;
    if (std.os.argv.len < 2)
        usage(1);
    try setup(argv, &i);
    var space = try arena.alloc([]const u8, argv[i..].len);
    for (0.., argv[i..]) |j, arg| {
        space[j] = try arena.dupe(u8, std.mem.sliceTo(arg, 0));
    }
    if (i == argv.len)
        usage(1);
    return std.process.execv(std.heap.smp_allocator, space);
}

fn usage(exit_code: u8) noreturn {
    const string = "usage: landlock-run [--ro <path>...] [--rw <path>...] [--port <port>...] [--scope-abstract-unix-socket] [--scope-signal] <program> [args...]\n";
    if (exit_code == 0)
        std.fs.File.stdout().writeAll(string) catch {}
    else
        std.debug.print(string, .{});

    std.process.exit(exit_code);
}

fn isDir(path: [*:0]const u8) bool {
    var stat: std.os.linux.Stat = undefined;
    switch (std.os.linux.E.init(std.os.linux.stat(path, &stat))) {
        .SUCCESS => {},
        else => |code| {
            std.debug.print("stat {s}: {s}\n", .{ path, @tagName(code) });
            std.process.exit(1);
        },
    }
    return std.posix.S.ISDIR(stat.mode);
}

fn setup(argv: []const [*:0]const u8, argi: *usize) !void {
    var i = argi.*;
    defer argi.* = i;

    const gpa = std.heap.smp_allocator;

    const rw_dir_extra: Landlock.Rule.PathBeneath.Access = .{
        .read_dir = true,
        .make_block = true,
        .make_char = true,
        .make_dir = true,
        .make_fifo = true,
        .make_reg = true,
        .make_sock = true,
        .make_sym = true,
        .refer = true,
        .remove_file = true,
        .remove_dir = true,
    };

    const ro: Landlock.Rule.PathBeneath.Access = .{
        .read_file = true,
        .exec = true,
    };

    const rw: Landlock.Rule.PathBeneath.Access = .{
        .read_file = true,
        .write_file = true,
        .exec = true,
        .ioctl_dev = true,
        .truncate = true,
    };

    const ver = try Landlock.queryVersion();
    
    var deferred: Landlock.Deferred = try .init(.{
        .path_beneath = .filled(ver),
        .net_port = .filled(ver),
        .scoped = .filled(ver),
        .version = ver,
    });
    defer deferred.deinit(gpa);

    while (i < argv.len) : (i += 1) {
        const arg = sliceTo(argv[i], 0);
        if (eql(u8, arg, "--ro")) {
            if (i + 1 >= argv.len)
                usage(1);

            var options = ro;
            if (isDir(argv[i + 1]))
                options.read_dir = true;

            try deferred.addRule(gpa, .{ .path_beneath = try .init(sliceTo(argv[i + 1], 0), options, .any) });
            i += 1;
        } else if (eql(u8, arg, "--rw")) {
            if (i + 1 >= argv.len)
                usage(1);

            var options = rw;
            if (isDir(argv[i + 1]))
                options = options.orWith(rw_dir_extra);

            try deferred.addRule(gpa, .{ .path_beneath = try .init(sliceTo(argv[i + 1], 0), options, .any) });
            i += 1;
        } else if (eql(u8, arg, "--port")) {
            if (i + 1 >= argv.len)
                usage(1);

            const port = std.fmt.parseInt(u16, sliceTo(argv[i + 1], 0), 0) catch usage(1);
            try deferred.addRule(gpa, .{ .net_port = .{ .port = port, .access = .filled(ver) } });
            i += 1;
        } else if (eql(u8, arg, "--scope-abstract-unix-socket")) {
            deferred.options.scoped.abstract_unix_socket = true;
        } else if (eql(u8, arg, "--scope-signal")) {
            deferred.options.scoped.signal = true;
        } else if (eql(u8, arg, "--help") or eql(u8, arg, "-h")) {
            usage(0);
        } else {
            break;
        }
    }

    var ll = try deferred.get();
    defer ll.deinit();

    try ll.commit(true);
}
