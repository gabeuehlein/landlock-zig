# landlock-zig

`landlock-zig` is a [Zig](https://ziglang.org) library that provides an interface for the [Landlock](https://docs.kernel.org/userspace-api/landlock.html) API provided
by recent versions of the Linux kernel. As of current, the Landlock API allows unprivileged processes to potentially restrict their own access to files, IPC mechanisms,
and network ports, which allows programs to easily isolate themselves in attempt to reduce the damage that could be caused by vulnerabilities.

## Example

Note that Landlock uses a deny-by-default approach for file and port access. This includes "special" files like those in `/proc` and `/dev`.
Therefore, it is necessary to communicate with the kernel *all* files that a program may use before committing to a particular Landlock ruleset

See the code below for how a hypothetical HTTP server may use `landlock-zig` to try to restrict its access to unintended files.

```zig
const Landlock = @import("landlock");

fn setupLandlock() !void {
    // Note: most essential filesystem isolation features are supported by kernels 5.13+,
    // and basic TCP port restriction requires kernels from version 6.2+.
    // -----
    // This is only always safe if .ignore_unsupported is set to `true` in the build options.
    // This is the default, so "best-effort" security doesn't need explicit build options.
    var ll = Landlock.init(.{}) catch |e| switch (e) {
        // Kernel is too old to use any Landlock features
        error.LandlockNotSupported,
        // Kernel knows about Landlock, but it is currently disabled.
        error.LandlockDisabled,
        => return,
        else => return e,
    };
    defer ll.deinit();
    // .read_dir + .exec => list directory contents
    // .read_file => read the contents of the directory's contents
    try ll.addPath("/srv/http", .{ .read_file = true, .read_dir = true, .exec = true }, .dir);
    try ll.addPath("/etc/httpd", .{ .read_file = true, .read_dir = true, .exec = true }, .dir);
    try ll.addPath("/var/log/httpd", .{ .read = true, .write = true }, .file);
    if (ll.version < 4)
        return; // Landlock versions less than 4 don't support TCP port restrictions
    // Network 
    try ll.addPort(443, .{ .bind_tcp = true });
    try ll.addPort(80, .{ .bind_tcp = true });
    // After this is called, the Landlock restrictions are active and
    // cannot be removed. The `true` parameter also prevents the process
    // from acquiring new capabilities, which is necessary for unprivileged
    // execution.
    try ll.commit(true);
    // From now on, the only resources the process can access are:
    //     - (read-only) `/srv/http/**`
    //     - (read-only) `/etc/httpd/**`
    //     - (read-write) `/var/log/httpd`
    //     - (bind) TCP Ports 80 and 443
    // The process cannot read or write to any other files, bind to other ports, or
    // communicate through any other network device through TCP or UDP.
}

pub fn main() !void {
    try setupLandlock();
    // start the HTTP(S) server...
}
```
