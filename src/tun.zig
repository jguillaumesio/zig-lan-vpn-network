//! Cross-platform TUN device abstraction.
//!
//! A `Device` gives you a layer-3 (raw IP packet) tunnel. `read` returns one
//! IP packet, `write` sends one. Platform header quirks (macOS's 4-byte address
//! family prefix, Wintun's packet API) are hidden behind this interface, so the
//! rest of the program only ever sees bare IPv4 packets.
//!
//! IP address assignment, MTU and routing are handled by `configure`, which
//! shells out to the platform's standard tooling (`ip`, `ifconfig`, `netsh`).
//! This keeps us out of the business of hand-rolling fragile ioctl structs for
//! address configuration on three different kernels.

const std = @import("std");
const builtin = @import("builtin");

const backend = switch (builtin.os.tag) {
    .linux => @import("tun_linux.zig"),
    .macos => @import("tun_macos.zig"),
    .windows => @import("tun_windows.zig"),
    else => @compileError("unsupported OS for TUN backend"),
};

/// Overlay MTU. Kept well below 1500 to leave headroom for the outer UDP/IP
/// headers plus our 5-byte data header, avoiding fragmentation of the carrier.
pub const mtu: u32 = 1400;

/// Largest IP packet we ever read from the device.
pub const max_packet = mtu;

pub const Device = struct {
    impl: backend.Impl,
    name_buf: [64]u8,
    name_len: usize,

    /// Open (creating if necessary) a TUN device. `requested_name` is a hint;
    /// the OS may hand back a different name (e.g. macOS always picks utunN),
    /// so always consult `name()` afterwards.
    pub fn open(gpa: std.mem.Allocator, requested_name: []const u8) !Device {
        var dev: Device = undefined;
        dev.impl = try backend.open(gpa, requested_name, &dev.name_buf, &dev.name_len);
        return dev;
    }

    pub fn deinit(self: *Device) void {
        backend.close(&self.impl);
    }

    pub fn read(self: *Device, buf: []u8) !usize {
        return backend.read(&self.impl, buf);
    }

    pub fn write(self: *Device, pkt: []const u8) !usize {
        return backend.write(&self.impl, pkt);
    }

    pub fn name(self: *const Device) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

/// Assign the overlay address, bring the interface up, set MTU and route the
/// overlay subnet through it.
pub fn configure(
    gpa: std.mem.Allocator,
    ifname: []const u8,
    vaddr: [4]u8,
    prefix: u8,
) !void {
    switch (builtin.os.tag) {
        .linux => try configureLinux(gpa, ifname, vaddr, prefix),
        .macos => try configureMacos(gpa, ifname, vaddr, prefix),
        .windows => try configureWindows(gpa, ifname, vaddr, prefix),
        else => @compileError("unsupported OS"),
    }
}

fn run(gpa: std.mem.Allocator, argv: []const []const u8) !void {
    var child = std.process.Child.init(argv, gpa);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Inherit;
    const term = try child.spawnAndWait();
    switch (term) {
        .Exited => |code| if (code != 0) {
            std.log.err("command failed ({d}): {s}", .{ code, argv[0] });
            return error.CommandFailed;
        },
        else => return error.CommandFailed,
    }
}

fn ipStr(buf: []u8, v: [4]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ v[0], v[1], v[2], v[3] }) catch unreachable;
}

fn netmask(prefix: u8) [4]u8 {
    const bits: u32 = if (prefix == 0) 0 else @as(u32, 0xffffffff) << @intCast(32 - prefix);
    return .{
        @intCast((bits >> 24) & 0xff),
        @intCast((bits >> 16) & 0xff),
        @intCast((bits >> 8) & 0xff),
        @intCast(bits & 0xff),
    };
}

fn network(vaddr: [4]u8, prefix: u8) [4]u8 {
    const m = netmask(prefix);
    return .{ vaddr[0] & m[0], vaddr[1] & m[1], vaddr[2] & m[2], vaddr[3] & m[3] };
}

fn configureLinux(gpa: std.mem.Allocator, ifname: []const u8, vaddr: [4]u8, prefix: u8) !void {
    var ipbuf: [16]u8 = undefined;
    var cidr: [24]u8 = undefined;
    const cidr_str = try std.fmt.bufPrint(&cidr, "{s}/{d}", .{ ipStr(&ipbuf, vaddr), prefix });
    var mtubuf: [8]u8 = undefined;
    const mtu_str = try std.fmt.bufPrint(&mtubuf, "{d}", .{mtu});

    try run(gpa, &.{ "ip", "addr", "add", cidr_str, "dev", ifname });
    try run(gpa, &.{ "ip", "link", "set", "dev", ifname, "mtu", mtu_str });
    try run(gpa, &.{ "ip", "link", "set", "dev", ifname, "up" });
    // `ip addr add` installs the connected route for the whole subnet already.
}

fn configureMacos(gpa: std.mem.Allocator, ifname: []const u8, vaddr: [4]u8, prefix: u8) !void {
    var ipbuf: [16]u8 = undefined;
    const ip = ipStr(&ipbuf, vaddr);
    var mtubuf: [8]u8 = undefined;
    const mtu_str = try std.fmt.bufPrint(&mtubuf, "{d}", .{mtu});

    // utun is point-to-point; give it our address on both ends and bring it up.
    try run(gpa, &.{ "ifconfig", ifname, ip, ip, "up" });
    try run(gpa, &.{ "ifconfig", ifname, "mtu", mtu_str });

    // Route the whole overlay subnet into the tunnel.
    var netbuf: [16]u8 = undefined;
    var netcidr: [24]u8 = undefined;
    const net_cidr = try std.fmt.bufPrint(&netcidr, "{s}/{d}", .{ ipStr(&netbuf, network(vaddr, prefix)), prefix });
    try run(gpa, &.{ "route", "-q", "-n", "add", "-inet", "-net", net_cidr, ip });
}

fn configureWindows(gpa: std.mem.Allocator, ifname: []const u8, vaddr: [4]u8, prefix: u8) !void {
    var ipbuf: [16]u8 = undefined;
    const ip = ipStr(&ipbuf, vaddr);
    var maskbuf: [16]u8 = undefined;
    const mask = ipStr(&maskbuf, netmask(prefix));

    var namearg: [96]u8 = undefined;
    const name_eq = try std.fmt.bufPrint(&namearg, "name={s}", .{ifname});
    var mtuarg: [32]u8 = undefined;
    const mtu_eq = try std.fmt.bufPrint(&mtuarg, "mtu={d}", .{mtu});

    try run(gpa, &.{ "netsh", "interface", "ip", "set", "address", name_eq, "static", ip, mask });
    try run(gpa, &.{ "netsh", "interface", "ipv4", "set", "subinterface", ifname, mtu_eq, "store=persistent" });
    // The connected route for the subnet is installed by the static address.
}

test "netmask and network math" {
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 0 }, netmask(24));
    try std.testing.expectEqual([4]u8{ 255, 255, 0, 0 }, netmask(16));
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, netmask(0));
    try std.testing.expectEqual([4]u8{ 10, 66, 0, 0 }, network(.{ 10, 66, 0, 42 }, 24));
}
