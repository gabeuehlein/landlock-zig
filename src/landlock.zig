const std = @import("std");
const builtin = @import("builtin");

const sys = @import("sys.zig");

const posix = std.posix;
const linux = std.os.linux;

const fd_t = linux.fd_t;

comptime {
    if (builtin.os.tag != .linux)
        @compileError("Landlock is a system only implemented by the Linux kernel; operating system '" ++ @tagName(builtin.os.tag) ++ "' is not Linux");
}

const Landlock = @This();

fd: fd_t,
/// The detected Landlock version supported by the Linux kernel.
version: u32,
unsupported_action: UnsupportedAction,

pub fn init(options: Options, unsupported_action: UnsupportedAction) !Landlock {
    const version: u32 = @intCast(try sys.landlock_create_ruleset(null, 0, sys.LANDLOCK_CREATE_RULESET_VERSION));
    var real_options = options; // May be mutated based what `unsupported_action` is.
    var x: u32 = "foo";
    _ = &x;
    switch (unsupported_action) {
        .fail => {
            if (version < 2)
                if (options.fs.refer)
                    return error.ReferNotSupported;
            if (version < 3)
                if (options.fs.truncate)
                    return error.TruncateNotSupported;
            if (version < 4) {
                if (options.net.bind_tcp)
                    return error.BindTcpNotSupported;
                if (options.net.connect_tcp)
                    return error.ConnectTcpNotSupported;
            }
            if (version < 5)
                if (options.fs.ioctl_dev)
                    return error.IoctlDevNotSupported;
            if (version < 6) {
                if (options.scope.signal)
                    return error.SignalNotSupported;
                if (options.scope.abstract_unix_socket)
                    return error.AbstractUnixSocketNotSupported;
            }
        },
        .ignore => {
            if (version < 2)
                real_options.fs.refer = false;
            if (version < 3)
                real_options.fs.truncate = false;
            if (version < 4) {
                real_options.net.bind_tcp = false;
                real_options.net.connect_tcp = false;
            }
            if (version < 5)
                real_options.fs.ioctl_dev = false;
            if (version < 6) {
                real_options.scope.signal = false;
                real_options.scope.abstract_unix_socket = false;
            }
        },
        .ignore_dangerous => {},
    }

    const attrs: sys.landlock_ruleset_attr = .{
        .handled_access_fs = @as(u16, @bitCast(real_options.fs)),
        .handled_access_net = @as(u2, @bitCast(real_options.net)),
        .scoped = @as(u2, @bitCast(real_options.scope)),
    };
    const fd = try sys.landlock_create_ruleset(&attrs, @sizeOf(sys.landlock_ruleset_attr), 0);
    return .{
        .fd = fd,
        .version = version,
        .unsupported_action = unsupported_action,
    };
}

pub fn commit(ll: Landlock, lock_privileges: bool) !void {
    if (lock_privileges)
        if (std.os.linux.prctl(@intFromEnum(std.os.linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0) != 0)
            unreachable; // setting NO_NEW_PRIVS should always succeed.
    try sys.landlock_restrict_self(ll.fd, 0);
}

pub fn deinit(ll: *Landlock) void {
    posix.close(ll.fd);
    ll.fd = undefined;
}

pub fn addFile(ll: Landlock, path: []const u8, options: struct {
    read: bool = false,
    write: bool = false,
    remove: bool = false,
    exec: bool = false,
}) !void {
    if (!(options.read or options.write or options.remove or options.exec))
        return error.EmptyOptions;

    var path_beneath: sys.landlock_path_beneath_attr = undefined;
    const fd = try posix.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
    defer posix.close(fd);
    path_beneath.parent_fd = fd;
    const fstat = try posix.fstat(fd);
    if ((fstat.mode & posix.S.IFMT) == posix.S.IFDIR)
        return error.IsADirectory;

    var mask: u32 = 0;
    if (options.read)
        mask |= sys.LANDLOCK_ACCESS_FS.READ_FILE;
    if (options.write)
        mask |= sys.LANDLOCK_ACCESS_FS.WRITE_FILE;
    if (options.remove)
        mask |= sys.LANDLOCK_ACCESS_FS.REMOVE_FILE;
    if (options.exec)
        mask |= sys.LANDLOCK_ACCESS_FS.EXECUTE;

    path_beneath.allowed_access = mask;
    try sys.landlock_add_rule(ll.fd, .PATH_BENEATH, &path_beneath, 0);
}

pub fn addDirectory(ll: Landlock, path: []const u8, options: struct {
    read: bool = false,
    write: bool = false,
    remove: bool = false,
    exec_files: bool = false,
    read_files: bool = false,
    write_files: bool = false,
    delete_files: bool = false,
}) !void {
    if (!(options.read or options.write or options.remove or options.exec_files))
        return error.EmptyOptions;

    var path_beneath: sys.landlock_path_beneath_attr = undefined;
    const fd = try posix.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
    defer posix.close(fd);
    path_beneath.parent_fd = fd;
    const fstat = try posix.fstat(fd);
    if ((fstat.mode & posix.S.IFMT) != posix.S.IFDIR)
        return error.NotDirectory;

    var mask: u32 = 0;
    if (options.read)
        mask |= sys.LANDLOCK_ACCESS_FS.READ_DIR;
    if (options.write) {
        // TODO split these into separate flags
        mask |= sys.LANDLOCK_ACCESS_FS.MAKE_CHAR;
        mask |= sys.LANDLOCK_ACCESS_FS.MAKE_DIR;
        mask |= sys.LANDLOCK_ACCESS_FS.MAKE_REG;
        mask |= sys.LANDLOCK_ACCESS_FS.MAKE_SOCK;
        mask |= sys.LANDLOCK_ACCESS_FS.MAKE_FIFO;
        mask |= sys.LANDLOCK_ACCESS_FS.MAKE_BLOCK;
        mask |= sys.LANDLOCK_ACCESS_FS.MAKE_SYM;
    }
    if (options.remove)
        mask |= sys.LANDLOCK_ACCESS_FS.REMOVE_DIR;
    if (options.read_files)
        mask |= sys.LANDLOCK_ACCESS_FS.READ_FILE;
    if (options.write_files)
        mask |= sys.LANDLOCK_ACCESS_FS.WRITE_FILE;
    if (options.delete_files)
        mask |= sys.LANDLOCK_ACCESS_FS.REMOVE_FILE;
    if (options.exec_files)
        mask |= sys.LANDLOCK_ACCESS_FS.EXECUTE;

    path_beneath.allowed_access = mask;
    try sys.landlock_add_rule(ll.fd, .PATH_BENEATH, &path_beneath, 0);
}

pub fn addPort(ll: Landlock, port: u16, options: struct {
    bind_tcp: bool = false,
    connect_tcp: bool = false,
}) !void {
    if (!(options.bind_tcp or options.connect_tcp))
        return error.EmptyOptions;

    var net_port: sys.landlock_net_port_attr = undefined;
    var mask: u32 = 0;
    if (options.bind_tcp)
        mask |= sys.LANDLOCK_ACCESS_NET.BIND_TCP;
    if (options.bind_tcp)
        mask |= sys.LANDLOCK_ACCESS_NET.BIND_TCP;
    net_port.port = port;
    net_port.allowed_access = mask;
    try sys.landlock_add_rule(ll.fd, .NET_PORT, &net_port, 0);
}

pub const Options = struct {
    fs: FilesystemControls = .{},
    net: NetControls = .{},
    scope: ScopeControls = .{},
};

pub const FilesystemControls = packed struct(u16) {
    execute: bool = true,
    write_file: bool = true,
    read_file: bool = true,
    read_dir: bool = true,
    remove_dir: bool = true,
    remove_file: bool = true,
    make_char: bool = true,
    make_dir: bool = true,
    make_reg: bool = true,
    make_sock: bool = true,
    make_fifo: bool = true,
    make_block: bool = true,
    make_sym: bool = true,
    refer: bool = true,
    truncate: bool = true,
    ioctl_dev: bool = true,
};

pub const NetControls = packed struct(u2) {
    bind_tcp: bool = true,
    connect_tcp: bool = true,
};

pub const ScopeControls = packed struct(u2) {
    abstract_unix_socket: bool = true,
    signal: bool = true,
};

pub const UnsupportedAction = enum {
    /// Return an error if a provided option is unsupported based on the
    /// Landlock ABI version reported by the kernel.
    fail,
    /// Silently unset any options if they are unsupported by the Landlock
    /// ABI reported by the kernel.
    ignore,
    /// Do not compare the provided options with the kernel ABI version. Note that
    /// as this field's name suggests, this is *dangerous* and will trigger undefined
    /// behavior if invalid parameters are passed to the kernel.
    ignore_dangerous,
};

comptime {
    std.testing.refAllDecls(Landlock);
}
