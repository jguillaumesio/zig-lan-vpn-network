//! Linux TUN backend using /dev/net/tun and the TUNSETIFF ioctl.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
// _IOW('T', 202, int)
const TUNSETIFF: u32 = 0x400454ca;

const IFNAMSIZ = 16;
// struct ifreq is 40 bytes: char ifr_name[16] + a 24-byte union.
const IFREQ_SIZE = 40;

pub const Impl = struct {
    fd: posix.fd_t,
};

pub fn open(
    _: std.mem.Allocator,
    requested_name: []const u8,
    name_buf: []u8,
    name_len: *usize,
) !Impl {
    const fd = posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0) catch |e| {
        std.log.err("cannot open /dev/net/tun ({s}); need root/CAP_NET_ADMIN", .{@errorName(e)});
        return e;
    };
    errdefer posix.close(fd);

    var ifr = [_]u8{0} ** IFREQ_SIZE;
    const name = requested_name[0..@min(requested_name.len, IFNAMSIZ - 1)];
    @memcpy(ifr[0..name.len], name);
    std.mem.writeInt(u16, ifr[IFNAMSIZ..][0..2], IFF_TUN | IFF_NO_PI, .little);

    const rc = linux.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr));
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            std.log.err("TUNSETIFF failed: {s}", .{@tagName(e)});
            return error.TunSetIff;
        },
    }

    // The kernel writes the actual interface name back into ifr_name.
    const actual = std.mem.sliceTo(ifr[0..IFNAMSIZ], 0);
    @memcpy(name_buf[0..actual.len], actual);
    name_len.* = actual.len;

    return .{ .fd = fd };
}

pub fn close(impl: *Impl) void {
    posix.close(impl.fd);
}

pub fn read(impl: *Impl, buf: []u8) !usize {
    // With IFF_NO_PI each read yields exactly one bare IP packet.
    return posix.read(impl.fd, buf);
}

pub fn write(impl: *Impl, pkt: []const u8) !usize {
    return posix.write(impl.fd, pkt);
}
