# landlock-zig

`landlock-zig` is a [Zig](https://ziglang.org) library that provides an interface for the [Landlock](https://docs.kernel.org/userspace-api/landlock.html) API provided
by recent versions of the Linux kernel. As of current, the Landlock API allows unprivileged processes to potentially restrict their own access to files, IPC mechanisms,
and network interfaces.

`landlock-zig` can be used by Zig programs to easily isolate themselves in attempt to reduce the damage that could be caused by vulnerabilities.
`landlock-zig` only depends on small parts of the Zig standard library, which combined with the small codebase limits binary size increases and
performance slowdowns, which should make integrating this library into another Zig project painless and straightforward.

## Example

Note that Landlock uses a deny-by-default approach for file and port access. This includes "special" files like those in `/proc` and `/dev`.
Therefore, it is necessary to communicate with the kernel *all* files that a program may use before revoking its access to other files.

See the code below for how a hypothetical HTTP server may use `landlock-zig` to try to restrict its access to unintended files.

```zig
const Landlock = @import("landlock");

fn setupLandlock() !void {
    // Note: most essential filesystem isolation features are supported by kernels 5.13+,
    // and basic TCP port restriction requires kernels from version 6.2+.
    // --------
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
    // From now on, the only resources the process can access are:
    //     - (read-only) `/srv/http/**`
    //     - (read-only) `/etc/httpd/**`
    //     - (read-write) `/var/log/httpd`
    //     - (bind) TCP Ports 80 and 443
    // The process cannot read or write to any other files, bind to another TCP port, or
    // communicate through any other network device through TCP.
}

pub fn main() !void {
    try setupLandlock();
    // start the HTTP(S) server...
}
```
