const std = @import("std");

const Landlock = @import("landlock.zig");

const read_only: Landlock.AddPathOptions = .{
    .exec = true,
    .read_file = true,
    .read_dir = true,
};

pub fn main() !void {
    var ll: Landlock = try .init(.{});
    try ll.addPath("/usr", read_only, .any);
    try ll.addPath("/etc", read_only, .any);
    try ll.addPath("/proc/self", read_only, .any);
    try ll.addPath("/lib", read_only, .any);
    try ll.addPath("/home/gabeu/.cache", read_only, .any);
    try ll.addPath("/home/gabeu/.config", read_only, .any);
    try ll.addPath("/home/gabeu/.local/share", read_only, .any);
    try ll.addPath("/home/gabeu/devel/zig", .{ .exec = true, .read_file = true, .read_dir = true, .ioctl_dev = true, .make_block = true, .make_char = true, .make_fifo = true, .make_sock = true, .make_sym = true, .refer = true, .remove_files = true, .truncate = true, .write = true, .remove = true, .make_reg = true, .make_dir = true }, .dir);
    try ll.addPath("/home/gabeu/devel", read_only, .any);

    try ll.addPath("/dev/null", .{
        .read_file = true,
        .write = true,
    }, .char);
    try ll.addPath("/dev/zero", .{ .read_file = true, .write = true }, .char);
    try ll.addPort(80, .{ .bind_tcp = true });
    try ll.addPort(443, .{ .bind_tcp = true });
    try ll.commit(true);
    const gpa = std.heap.page_allocator;

    return std.process.execv(gpa, &.{ "/usr/bin/bash", "-i" });
}
