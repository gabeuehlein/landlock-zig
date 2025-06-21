//! `landlock-zig` is a Zig wrapper around the [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
//! API supported by Linux kernels 5.13 and greater as a Linux Security Module. To use it, add it as a module
//! in a `build.zig` file:
//! ```zig
//! pub fn build(b: *Build) !void {
//!     ...
//!     const my_cool_module: std.build.Module = ...;
//!
//!     const landlock_dep = b.dependency("landlock");
//!     my_cool_module.addImport(landlock_dep.module("landlock"));
//!     ...
//! }
//! ```
//!
//! This module's root is a distinct `struct` providing the features offered by this library.
//! It should be used directly and should be treated like any regular data structure (e.g. [std.ArrayListUnmanaged]):
//! ```zig
//! const Landlock = @import("landlock");
//!
//! ...
//!
//! var ll = try Landlock.init(.{});
//! // add rules...
//! try ll.commit(true);
//! ```

/// The Landlock file descriptor which is referenced in any related syscalls.
fd: fd_t,
/// The (cached) detected Landlock ABI version supported by the Linux kernel. If for
/// whatever reason this needs to be recomputed, set this to the result returned by [queryVersion].
version: u32,

pub fn init(options: Options) !Landlock {
    const version = try queryVersion();

    const checked_access_fs = checkRule(version, options.fs, false);
    const checked_access_net = checkRule(version, options.net, false);
    const checked_access_scope = checkRule(version, options.scope, false);

    var attrs: sys.landlock_ruleset_attr = .{
        .handled_access_fs = @as(u64, @bitCast(checked_access_fs)),
        .handled_access_net = @as(u64, @bitCast(checked_access_net)),
        .scoped = @as(u64, @bitCast(checked_access_scope)),
    };

    return .{
        .fd = try sys.landlock_create_ruleset(&attrs, @sizeOf(sys.landlock_ruleset_attr), 0),
        .version = version,
    };
}

/// Attempts to activate the Landlock restrictions previously made by any calls
/// to [addPath] or [addPort]. If `set_no_new_privs` is called, this will automatically
/// call `prctl(SET_NO_NEW_PRIVS)`, preventing the process from obtaining new [capabilities](https://linux.die.net/man/7/capabilities).
pub fn commit(ll: Landlock, set_no_new_privs: bool) !void {
    if (set_no_new_privs)
        _ = try posix.prctl(.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 });
    try sys.landlock_restrict_self(ll.fd, 0);
}

pub fn deinit(ll: *Landlock) void {
    defer ll.* = undefined;
    posix.close(ll.fd);
}

/// Adds a filesystem path rule to the Landlock ruleset, following symlinks. Checks that `path`
/// refers to a file of type `path_kind` if `path_kind != .any`.
pub fn addPath(ll: Landlock, path: []const u8, options: AddPathOptions, path_kind: AddPathKind) !void {
    const fd = try posix.open(path, .{
        .PATH = true,
        .DIRECTORY = path_kind == .dir,
        .CLOEXEC = true,
    }, 0);
    defer posix.close(fd);
    if (path_kind != .any) {
        const stat = try posix.fstat(fd);
        const S = posix.S;
        const ty = stat.mode;
        switch (path_kind) {
            .any => unreachable,
            .dir => {}, // handled by opening fd
            .char => if (!S.ISCHR(ty))
                return error.NotChar,
            .block => if (!S.ISBLK(ty))
                return error.NotBlock,
            .file => if (!S.ISREG(ty))
                return error.NotFile,
            .fifo => if (!S.ISFIFO(ty))
                return error.NotFifo,
            .sock => if (!S.ISSOCK(ty))
                return error.NotSock,
        }
    }

    const path_beneath: sys.landlock_path_beneath_attr = .{
        .parent_fd = fd,
        .allowed_access = @bitCast(checkRule(ll.version, options, false)),
    };

    try sys.landlock_add_rule(ll.fd, .PATH_BENEATH, &path_beneath, 0);
}

/// Adds a network port rule to the Landlock ruleset.
pub fn addPort(ll: Landlock, port: u16, options: AddPortOptions) !void {
    const net_port: sys.landlock_net_port_attr = .{
        .port = port,
        .allowed_access = @bitCast(checkRule(ll.version, options, false)),
    };

    try sys.landlock_add_rule(ll.fd, .NET_PORT, &net_port, 0);
}

/// Checks the rule for validity against the Landlock ABI version `version`. If the compile
/// option `ignore_unsupported` is `true` *or* `force_ignore_unsupported` is `true`, then unsupported
/// options will be set to `false` (and a debug log will be emitted if `enable_logging == true`). Otherwise, an `assert`
/// will be made that no unsupported options are present in `options`
pub fn checkRule(version: u32, options: anytype, comptime force_ignore_unsupported: bool) @TypeOf(options) {
    const kind: RestrictionType = switch (@TypeOf(options)) {
        FilesystemControls, AddPathOptions => .fs,
        NetControls, AddPortOptions => .net,
        ScopeControls => .scope,
        else => @compileError("invalid options type '" ++ @typeName(@TypeOf(options)) ++ "'"),
    };
    const as_int: u64 = @bitCast(options);
    const mask = getCompatMask(version, kind);
    const masked = mask & as_int;

    if (ignore_unsupported or force_ignore_unsupported) {
        if (enable_logging) {
            if (masked != as_int) {
                switch (kind) {
                    .fs => log.debug("ignoring unsupported filesystem restriction options (mask changed from 0x{x} -> 0x{x})", .{ as_int, masked }),
                    .net => log.debug("ignoring unsupported network restriction options (mask changed from 0x{x} -> 0x{x})", .{ as_int, masked }),
                    .scope => log.debug("ignoring unsupported scope restriction options (mask changed from 0x{x} -> 0x{x})", .{ as_int, masked }),
                }
            }
        }
    } else {
        assert(ruleIsValidForAbiVersion(version, options)); // set `ignore_unsupported` and `enable_logging` in build.zig to see the mismatched bits
    }

    return @bitCast(masked);
}

/// Returns whether the provided `options` is valid for the provided Landlock ABI version. It is considered
/// to be valid if using the rule is not guaranteed to return an error (related to the rule).
pub fn ruleIsValidForAbiVersion(version: u32, options: anytype) bool {
    const kind: RestrictionType = switch (@TypeOf(options)) {
        FilesystemControls, AddPathOptions => .fs,
        NetControls, AddPortOptions => .net,
        ScopeControls => .scope,
        else => @compileError("invalid options type '" ++ @typeName(@TypeOf(options)) ++ "'"),
    };
    const as_int: u64 = @bitCast(options);
    const mask = getCompatMask(version, kind);
    const masked = mask & as_int;

    return masked == as_int;
}

/// Attempts to obtain the Landlock ABI version from the kernel directly.
pub fn queryVersion() !u32 {
    const version: u32 = @intCast(try sys.landlock_create_ruleset(null, 0, sys.LANDLOCK_CREATE_RULESET_VERSION));
    if (version == 0)
        return error.Unexpected; // Landlock LSM is broken!
    return version;
}

pub inline fn getCompatMask(version: u32, req_ty: RestrictionType) u64 {
    const index = compatIndex(version);
    return (switch (req_ty) {
        .fs => fs_compatibility_array,
        .net => net_compatibility_array,
        .scope => scope_compatibility_array,
    })[index];
}

inline fn compatIndex(version: u32) usize {
    return @min(version, max_abi_version) - 1;
}

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const log = std.log.scoped(.landlock);
const assert = std.debug.assert;

const ignore_unsupported = build_options.ignore_unsupported;
const enable_logging = build_options.enable_logging;

/// Low-level wrappers around the `landlock_*` system calls, as well as definitions for Landlock-related constants.
pub const sys = @import("sys.zig");

const posix = std.posix;
const linux = std.os.linux;

const fd_t = linux.fd_t;

const Landlock = @This();

pub const AddPathKind = enum {
    any,
    /// Directory
    dir,
    /// Character device
    char,
    /// Block device
    block,
    /// Regular file
    file,
    /// FIFO (first in, first out) file. Also known as a named pipe.
    fifo,
    /// Filesystem-based socket (e.g. a UNIX socket)
    sock,
};

pub const AddPathOptions = packed struct(u64) {
    exec: bool = false,
    write: bool = false,
    read_file: bool = false,
    read_dir: bool = false,
    remove_dir: bool = false,
    remove_file: bool = false,
    make_char: bool = false,
    make_dir: bool = false,
    make_reg: bool = false,
    make_sock: bool = false,
    make_fifo: bool = false,
    make_block: bool = false,
    make_sym: bool = false,
    refer: bool = false,
    truncate: bool = false,
    ioctl_dev: bool = false,
    _48: u48 = 0,

    pub inline fn orWith(a: AddPathOptions, b: AddPathOptions) AddPathOptions {
        return @bitCast(@as(u64, @bitCast(a)) | @as(u64, @bitCast(b)));
    }

    pub inline fn andWith(a: AddPathOptions, b: AddPathOptions) AddPathOptions {
        return @bitCast(@as(u64, @bitCast(a)) & @as(u64, @bitCast(b)));
    }
};
pub const AddPortOptions = packed struct(u64) {
    bind_tcp: bool = false,
    connect_tcp: bool = false,
    _62: u62 = 0,

    pub inline fn orWith(a: AddPortOptions, b: AddPortOptions) AddPortOptions {
        return @bitCast(@as(u64, @bitCast(a)) | @as(u64, @bitCast(b)));
    }

    pub inline fn andWith(a: AddPortOptions, b: AddPortOptions) AddPortOptions {
        return @bitCast(@as(u64, @bitCast(a)) & @as(u64, @bitCast(b)));
    }
};

pub const Options = struct {
    fs: FilesystemControls = .{},
    net: NetControls = .{},
    scope: ScopeControls = .{},
};

pub const FilesystemControls = packed struct(u64) {
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
    _: u48 = 0,
};

pub const NetControls = packed struct(u64) {
    bind_tcp: bool = true,
    connect_tcp: bool = true,
    _: u62 = 0,
};

pub const ScopeControls = packed struct(u64) {
    abstract_unix_socket: bool = true,
    signal: bool = true,
    _: u62 = 0,
};

pub const RestrictionType = enum { fs, net, scope };

/// The maximum Landlock version supported by this library. Higher versions will be assumed
/// to support all features this library does.
pub const max_abi_version = 6;

/// Index into this array is determined by `(landlock ABI version) - 1`
const fs_compatibility_array: [max_abi_version]u64 = .{
    (sys.LANDLOCK_ACCESS_FS.MAKE_SYM << 1) - 1,
    (sys.LANDLOCK_ACCESS_FS.REFER << 1) - 1,
    (sys.LANDLOCK_ACCESS_FS.TRUNCATE << 1) - 1,
    (sys.LANDLOCK_ACCESS_FS.TRUNCATE << 1) - 1,
    (sys.LANDLOCK_ACCESS_FS.IOCTL_DEV << 1) - 1,
    (sys.LANDLOCK_ACCESS_FS.IOCTL_DEV << 1) - 1,
};

/// Index into this array is determined by `(landlock ABI version) - 1`
const net_compatibility_array: [max_abi_version]u64 = .{
    0,
    0,
    0,
    (sys.LANDLOCK_ACCESS_NET.CONNECT_TCP << 1) - 1,
    (sys.LANDLOCK_ACCESS_NET.CONNECT_TCP << 1) - 1,
    (sys.LANDLOCK_ACCESS_NET.CONNECT_TCP << 1) - 1,
};

/// Index into this array is determined by `(landlock ABI version) - 1`
const scope_compatibility_array: [max_abi_version]u64 = .{
    0,
    0,
    0,
    0,
    0,
    (sys.LANDLOCK_SCOPE.SIGNAL << 1) - 1,
};

comptime {
    if (builtin.os.tag != .linux)
        @compileError("Landlock is a mechanism implemented only by the Linux kernel; operating system '" ++ @tagName(builtin.os.tag) ++ "' is not Linux");
    std.testing.refAllDecls(Landlock);
}
