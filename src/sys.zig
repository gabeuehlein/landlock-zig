//! Contains wrappers for the `landlock_*` system calls and associated constants
//! and structures needed to communicate with the kernel.

const std = @import("std");
const linux = std.os.linux;

const fd_t = linux.fd_t;
const E = linux.E;

pub fn landlock_create_ruleset(attr: ?*const landlock_ruleset_attr, size: usize, flags: u32) !fd_t {
    switch (linux.syscall3(.landlock_create_ruleset, @intFromPtr(attr), size, flags)) {
        0...std.math.maxInt(i32) => |fd| return @intCast(fd),
        else => |err| return switch (E.init(err)) {
            .NOSYS => error.LandlockNotSupported,
            .OPNOTSUPP => error.LandlockDisabled,
            .NOMSG => error.EmptyAccesses,
            // These named errors can only happen as a result of
            // invalid internal logic or users using intentionally unsafe options.
            .@"2BIG", .INVAL, .FAULT => unreachable,
            else => unreachable,
        },
    }
}

pub fn landlock_add_rule(
    ruleset_fd: fd_t,
    rule_type: landlock_rule_type,
    attr: ?*const anyopaque,
    flags: u32,
) !void {
    switch (linux.syscall4(.landlock_add_rule, @intCast(ruleset_fd), @intFromEnum(rule_type), @intFromPtr(attr), flags)) {
        0 => {},
        else => |err| return switch (E.init(err)) {
            .OPNOTSUPP => error.LandlockDisabled,
            .INVAL => error.InvalidFlags,
            .NOMSG => unreachable,
            .BADF => unreachable,
            else => unreachable,
        },
    }
}

pub fn landlock_restrict_self(ruleset_fd: fd_t, flags: u32) !void {
    switch (linux.syscall2(.landlock_restrict_self, @intCast(ruleset_fd), flags)) {
        0 => {},
        else => |err| return switch (E.init(err)) {
            .OPNOTSUPP => error.LandlockDisabled,
            .INVAL => unreachable,
            .BADF => error.BadFileDescriptor,
            .BADFD => error.InvalidFileDescriptor,
            .PERM => error.NotPermitted,
            .@"2BIG" => error.TooManyRules,
            else => unreachable,
        },
    }
}

pub const LANDLOCK_ACCESS_FS = struct {
    pub const EXECUTE = 1;
    pub const WRITE_FILE = 2;
    pub const READ_FILE = 4;
    pub const READ_DIR = 8;
    pub const REMOVE_DIR = 16;
    pub const REMOVE_FILE = 32;
    pub const MAKE_CHAR = 64;
    pub const MAKE_DIR = 128;
    pub const MAKE_REG = 256;
    pub const MAKE_SOCK = 512;
    pub const MAKE_FIFO = 1024;
    pub const MAKE_BLOCK = 2048;
    pub const MAKE_SYM = 4096;
    pub const REFER = 8192;
    pub const TRUNCATE = 16384;
    pub const IOCTL_DEV = 32768;
};

pub const LANDLOCK_ACCESS_NET = struct {
    pub const BIND_TCP = 1;
    pub const CONNECT_TCP = 2;
};

pub const LANDLOCK_CREATE_RULESET_VERSION = 1;

pub const landlock_ruleset_attr = extern struct {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
};

pub const landlock_rule_type = enum(u32) {
    PATH_BENEATH = 1,
    NET_PORT = 2,
};

pub const landlock_path_beneath_attr = packed struct(u96) {
    allowed_access: u64,
    parent_fd: fd_t,
};

pub const landlock_net_port_attr = extern struct {
    allowed_access: u64,
    port: u64,
};
