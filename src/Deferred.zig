//! A structure that stores Landlock rules that can be used to restrict a
//! process' capabilities at a later time.

const Deferred = @This();
const std = @import("std");
const Landlock = @import("Landlock.zig");
const Allocator = std.mem.Allocator;

options: Landlock.Options,
rules: std.ArrayList(Landlock.Rule),

pub fn init(options: Landlock.Options) !Deferred {
    var var_options = options;

    if (var_options.version == null)
        var_options.version = try Landlock.queryVersion();

    return .{
        .options = var_options,
        .rules = .empty,
    };
}

pub fn deinit(deferred: *Deferred, gpa: Allocator) void {
    defer deferred.* = undefined;

    for (deferred.rules.items) |rule| {
        switch (rule) {
            .path_beneath => |pb| pb.deinit(),
            else => {},
        }
    }

    deferred.rules.deinit(gpa);
}

pub fn addRule(deferred: *Deferred, gpa: Allocator, rule: Landlock.Rule) !void {
    // TODO add verification logic into here and extract out a version that ignores
    // incompatible restrictions.
    try deferred.rules.append(gpa, rule);
}


pub fn get(deferred: *const Deferred) !Landlock {
    var ll: Landlock = try .init(deferred.options);
    errdefer ll.deinit();

    for (deferred.rules.items) |rule| 
        try ll.addRule(rule);

    return ll;
}

test {
    _= std.testing.refAllDecls(Deferred);
}
