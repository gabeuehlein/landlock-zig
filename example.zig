const Landlock = @import("src/landlock.zig");

fn setupLandlock() !void {
    // .ignore makes isolation best-effort instead of mandatory, to support kernels that don't support
    // certain Landlock features.
    var ll = Landlock.init(.{}, .ignore) catch |e| switch (e) {
        // Kernel is too old to use any Landlock features
        error.LandlockNotSupported,
        // Kernel knows about Landlock, but it is currently disabled.
        error.LandlockDisabled,
        => return,
        else => return e,
    };
    defer ll.deinit();
    // .read => list directory contents
    // .read_files => read the contents of the directory's contents
    try ll.addDirectory("/srv/http", .{ .read = true, .read_files = true });
    try ll.addDirectory("/etc/httpd", .{ .read = true, .read_files = true });
    try ll.addFile("/var/log/httpd", .{ .read = true, .write = true });
    // Network
    try ll.addPort(443, .{ .bind_tcp = true });
    try ll.addPort(80, .{ .bind_tcp = true });
    // After this is called, the Landlock restrictions are active and
    // cannot be removed. The `true` parameter also prevents the process
    // from acquiring new capabilities, which is necessary for unprivileged
    // execution.
    try ll.commit(true);
}

pub fn main() !void {
    try setupLandlock();
    // start the HTTP(S) server...
}
