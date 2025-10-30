//! `landlock-zig` is a Zig wrapper around the [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
//! API supported by Linux kernels 5.13 and greater as a Linux Security Module. To use it, add it as a module
//! in a `build.zig` file:
//! ```zig
//! pub fn build(b: *Build) !void {
//!     ...
//!     const my_cool_module: std.Build.Module = ...;
//!
//!     const landlock_dep = b.dependency("Landlock");
//!     my_cool_module.addImport(landlock_dep.module("Landlock"));
//!     ...
//! }
//! ```
//!
//! This module's root is a distinct `struct` providing the features offered by this library.
//! It should be used directly and should be treated like any regular data structure (e.g. [std.ArrayListUnmanaged]):
//! ```zig
//! const Landlock = @import("Landlock");
//!
//! ...
//!
//! var ll = try Landlock.init(.{});
//! // add rules...
//! try ll.commit(true);
//! ```

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;


/// Low-level wrappers around the `landlock_*` system calls, as well as definitions for Landlock-related constants.
pub const sys = @import("sys.zig");

const posix = std.posix;
const linux = std.os.linux;

const fd_t = linux.fd_t;

const Landlock = @This();
pub const Deferred = @import("Deferred.zig");

pub const Options = struct {
    path_beneath: Rule.PathBeneath.Access = .{},
    net_port: Rule.NetPort.Access = .{},
    scoped: Rule.Scoped.Access = .{},
    version: ?u32 = null, 
};

pub const Rule = union(Tag) {
    path_beneath: PathBeneath,
    net_port: NetPort,
    /// This variant is currently unused (hence the `noreturn` payload). It exists for if Landlock's
    /// scope capabilities are ever extended in such a way that custom scope rules may be added.
    scoped: noreturn,

    pub const PathBeneath = struct {
        access: Access,
        fd: posix.fd_t,

        pub const Access = packed struct(u64) {
            exec: bool = false,
            write_file: bool = false,
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

            const compatibility_array: [max_abi_version]u64 = .{
                (sys.LANDLOCK_ACCESS_FS.MAKE_SYM << 1) - 1,
                (sys.LANDLOCK_ACCESS_FS.REFER << 1) - 1,
                (sys.LANDLOCK_ACCESS_FS.TRUNCATE << 1) - 1,
                (sys.LANDLOCK_ACCESS_FS.TRUNCATE << 1) - 1,
                (sys.LANDLOCK_ACCESS_FS.IOCTL_DEV << 1) - 1,
                (sys.LANDLOCK_ACCESS_FS.IOCTL_DEV << 1) - 1,
            };

            pub fn orWith(a: Access, b: Access) Access {
                return @bitCast(@as(u64, @bitCast(a)) | @as(u64, @bitCast(b)));
            }

            pub fn andWith(a: Access, b: Access) Access {
                return @bitCast(@as(u64, @bitCast(a)) & @as(u64, @bitCast(b)));
            }

            pub fn filled(version: u32) Access {
                return @bitCast(compatibility_array[compatIndex(version)]);
            }

            pub fn fileMask(version: u32) Access {
                return (Access{
                    .exec = true,
                    .write_file = true,
                    .read_file = true,
                    .remove_file = true,
                    .refer = true,
                    .truncate = true,
                    .ioctl_dev = true,
                }).andWith(.filled(version));
            }

            pub fn dirMask(version: u32) Access {
                return .filled(version);
            }
        };
        
        pub const FileKind = enum {
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

        pub const InitError = error{
            NotDirectory,
            NotCharDevice,
            NotBlockDevice,
            NotFile,
            NotFifo,
            NotSock,
        } || posix.FStatError;

        pub fn init(path: []const u8, access: Access, expected_type: FileKind) (posix.OpenError||InitError)!PathBeneath {
            const fd = try posix.open(path, .{ .PATH = true, .CLOEXEC = true }, 0);
            errdefer posix.close(fd);

            return initFd(fd, access, expected_type);
        }

        pub fn initFd(fd: posix.fd_t, access: Access, expected_type: FileKind) InitError!PathBeneath {
            if (expected_type != .any) {
                const stat = try posix.fstat(fd);
                const S = posix.S;
                const ty = stat.mode;
                switch (expected_type) {
                    .any => unreachable,
                    .dir => if (!S.ISDIR(ty))
                        return error.NotDirectory,
                    .char => if (!S.ISCHR(ty))
                        return error.NotCharDevice,
                    .block => if (!S.ISBLK(ty))
                        return error.NotBlockDevice,
                    .file => if (!S.ISREG(ty))
                        return error.NotFile,
                    .fifo => if (!S.ISFIFO(ty))
                        return error.NotFifo,
                    .sock => if (!S.ISSOCK(ty))
                        return error.NotSock,
                }
            }

            return .{ .fd = fd, .access = access };
        }

        pub fn deinit(pb: PathBeneath) void {
            posix.close(pb.fd);
        }
    };

    pub const NetPort = struct {
        port: u16,
        access: Access,

        pub const Access = packed struct(u64) {
            bind_tcp: bool = false,
            connect_tcp: bool = false,
            _62: u62 = 0,

            const compatibility_array: [max_abi_version]u64 = .{
                0,
                0,
                0,
                (sys.LANDLOCK_ACCESS_NET.CONNECT_TCP << 1) - 1,
                (sys.LANDLOCK_ACCESS_NET.CONNECT_TCP << 1) - 1,
                (sys.LANDLOCK_ACCESS_NET.CONNECT_TCP << 1) - 1,
            };

            pub inline fn orWith(a: Access, b: Access) Access {
                return @bitCast(@as(u64, @bitCast(a)) | @as(u64, @bitCast(b)));
            }

            pub inline fn andWith(a: Access, b: Access) Access {
                return @bitCast(@as(u64, @bitCast(a)) & @as(u64, @bitCast(b)));
            }

            pub fn filled(version: u32) Access {
                return @bitCast(compatibility_array[compatIndex(version)]);
            }
        };
    };

    pub const Scoped = struct {
        access: Access,

        pub const Access = packed struct(u64) {
            abstract_unix_socket: bool = true,
            signal: bool = true,
            _62: u62 = 0,

            const compatibility_array: [max_abi_version]u64 = .{
                0,
                0,
                0,
                0,
                0,
                (sys.LANDLOCK_SCOPE.SIGNAL << 1) - 1,
            };

            pub inline fn orWith(a: Access, b: Access) Access {
                return @bitCast(@as(u64, @bitCast(a)) | @as(u64, @bitCast(b)));
            }

            pub inline fn andWith(a: Access, b: Access) Access {
                return @bitCast(@as(u64, @bitCast(a)) & @as(u64, @bitCast(b)));
            }

            pub fn filled(version: u32) Access {
                return @bitCast(compatibility_array[compatIndex(version)]);
            }
        };
        
    };

    pub const Tag = enum {
        path_beneath,
        net_port,
        scoped,
    };
};

/// The Landlock file descriptor which is referenced in any related syscalls.
fd: fd_t,
/// The (cached) detected Landlock ABI version supported by the Linux kernel. If for
/// whatever reason this needs to be recomputed, set this to the result returned by [queryVersion].
version: u32,

pub fn init(options: Options) !Landlock {
    const version = options.version orelse try queryVersion();

    var attrs: sys.landlock_ruleset_attr = .{
        .handled_access_fs = @as(u64, @bitCast(options.path_beneath)),
        .handled_access_net = @as(u64, @bitCast(options.net_port)),
        .scoped = @as(u64, @bitCast(options.scoped)),
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

/// Adds a rule to the ruleset. As the kernel manages the queued rules, no allocator
/// is required. Do note, however, that the rule will still need to have its resources
/// cleaned up (`path_beneath` rules will need to have their file descriptor closed).
/// For a function that automatically does that, see [addRuleImmediate].
pub fn addRule(ll: *Landlock, rule: Rule) !void {
    switch (rule) {
        .path_beneath => |p| {
            const path_beneath: sys.landlock_path_beneath_attr = .{
                .parent_fd = p.fd,
                .allowed_access = @bitCast(p.access),
            };

            try sys.landlock_add_rule(ll.fd, .PATH_BENEATH, &path_beneath, 0);
        },
        .net_port => |np| {
            const net_port: sys.landlock_net_port_attr = .{
                .allowed_access = @bitCast(np.access),
                .port = np.port,    
            };

            try sys.landlock_add_rule(ll.fd, .NET_PORT, &net_port, 0);
        },
        .scoped => unreachable,
    }
}

pub fn addRuleImmediate(ll: *Landlock, rule: Rule) !void {
   defer switch (rule) {
       .path_beneath => |p| p.deinit(),
       else => {},
   };

    return addRule(ll, rule);
}


/// Attempts to obtain the Landlock ABI version from the kernel directly.
pub fn queryVersion() !u32 {
    const version: i32 = try sys.landlock_create_ruleset(null, 0, sys.LANDLOCK_CREATE_RULESET_VERSION);
    if (version == 0)
        return error.Unexpected; // Landlock LSM is broken!

    return @intCast(version);
}

inline fn compatIndex(version: u32) usize {
    return @min(version, max_abi_version) - 1;
}

/// The maximum Landlock version supported by this library. Higher versions will be assumed
/// to support all features this library does.
pub const max_abi_version = 6;

test {
    const ver = try queryVersion() catch |e| switch (e) {
        error.LandlockDisabled, error.LandlockNotSupported => return error.SkipZigTest,
        else => return e,
    };

    std.posix.accessZ("/proc/self", posix.F_OK) catch return error.SkipZigTest;

    var ll: Landlock = try .init(.{
        .path_beneath = .filled(ver),
        .net_port = .filled(ver),
        .scoped = .filled(ver),
        .version = ver,
    });

    try ll.addRuleImmediate(.{ .path_beneath = try .init("/proc/self", .{ .read_file = true, .read_dir = true, .exec = true }, .dir) });

    try ll.commit(true);
    try std.posix.accessZ("/proc/self", 0);

    try std.testing.expectError(error.AccessDenied, posix.open("/proc", .{ .DIRECTORY = true, .ACCMODE = .RDONLY }, 0));
}

comptime {
    std.testing.refAllDecls(Landlock);
}
