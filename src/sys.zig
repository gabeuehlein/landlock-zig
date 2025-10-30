const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const fd_t = linux.fd_t;
const E = linux.E;

pub fn landlock_create_ruleset(attr: ?*const landlock_ruleset_attr, size: usize, flags: u32) error{ LandlockNotSupported, LandlockDisabled, EmptyAccesses, InvalidFlags, Unexpected }!fd_t {
    switch (linux.syscall3(.landlock_create_ruleset, @intFromPtr(attr), size, flags)) {
        0...std.math.maxInt(i32) => |fd| return @intCast(fd),
        else => |err| return switch (E.init(err)) {
            .NOSYS => error.LandlockNotSupported,
            .OPNOTSUPP => error.LandlockDisabled,
            .NOMSG => error.EmptyAccesses, // No restrictions were asked for
            .INVAL => error.InvalidFlags, 
            else => |e| posix.unexpectedErrno(e),
        },
    }
}

pub fn landlock_add_rule(
    ruleset_fd: fd_t,
    rule_type: landlock_rule_type,
    attr: ?*const anyopaque,
    flags: u32,
) error{LandlockDisabled,InvalidFlags,EmptyAccesses,BadFileDescriptor,Unexpected}!void {
    switch (linux.syscall4(.landlock_add_rule, @intCast(ruleset_fd), @intFromEnum(rule_type), @intFromPtr(attr), flags)) {
        0 => {},
        else => |err| return switch (E.init(err)) {
            .OPNOTSUPP => error.LandlockDisabled,
            .INVAL => error.InvalidFlags,
            .NOMSG => error.EmptyAccesses,
            .BADF => error.BadFileDescriptor,
            else => |e| posix.unexpectedErrno(e),
        },
    }
}

pub fn landlock_restrict_self(ruleset_fd: fd_t, flags: u32) error{LandlockDisabled,BadFileDescriptor,InvalidFileDescriptor,NotPermitted,TooManyRules,InvalidFlags,Unexpected}!void {
    switch (linux.syscall2(.landlock_restrict_self, @intCast(ruleset_fd), flags)) {
        0 => {},
        else => |err| return switch (E.init(err)) {
            .OPNOTSUPP => error.LandlockDisabled,
            .INVAL => error.InvalidFlags,
            .BADF => error.BadFileDescriptor,
            .BADFD => error.InvalidFileDescriptor,
            .PERM => error.NotPermitted,
            .@"2BIG" => error.TooManyRules,
            else => |e| posix.unexpectedErrno(e),
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

pub const LANDLOCK_SCOPE = struct {
    pub const ABSTRACT_UNIX_SOCKET = 1;
    pub const SIGNAL = 2;
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
