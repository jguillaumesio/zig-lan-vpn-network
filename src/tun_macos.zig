//! macOS TUN backend using the built-in utun kernel control interface.
//!
//! There is no character device; instead you open a PF_SYSTEM/SYSPROTO_CONTROL
//! socket, resolve the "com.apple.net.utun_control" kernel control id, and
//! connect() to it. The kernel picks the next free utunN. Every packet on the
//! socket is prefixed with a 4-byte address family (AF_INET), which we add on
//! write and strip on read using scatter/gather I/O.

const std = @import("std");
const posix = std.posix;

const PF_SYSTEM: u32 = 32;
const SYSPROTO_CONTROL: u32 = 2;
const AF_SYS_CONTROL: u16 = 2;
const AF_INET: u32 = 2;

// _IOWR('N', 3, struct ctl_info)
const CTLIOCGINFO: c_ulong = 0xc0644e03;
const UTUN_OPT_IFNAME: c_int = 2;
const UTUN_CONTROL_NAME = "com.apple.net.utun_control";

extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
extern "c" fn getsockopt(fd: c_int, level: c_int, optname: c_int, optval: *anyopaque, optlen: *c_uint) c_int;

const ctl_info = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

const sockaddr_ctl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

pub const Impl = struct {
    fd: posix.fd_t,
};

pub fn open(
    _: std.mem.Allocator,
    _: []const u8,
    name_buf: []u8,
    name_len: *usize,
) !Impl {
    const fd = try posix.socket(PF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL);
    errdefer posix.close(fd);

    var info = std.mem.zeroes(ctl_info);
    @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &info) != 0) {
        std.log.err("CTLIOCGINFO failed; cannot resolve utun control", .{});
        return error.UtunControl;
    }

    var addr = std.mem.zeroes(sockaddr_ctl);
    addr.sc_len = @sizeOf(sockaddr_ctl);
    addr.sc_family = @intCast(PF_SYSTEM);
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0; // 0 => kernel assigns the next free utunN

    posix.connect(fd, @ptrCast(&addr), @sizeOf(sockaddr_ctl)) catch |e| {
        std.log.err("connect to utun failed ({s}); need root", .{@errorName(e)});
        return e;
    };

    // Read back the assigned interface name (e.g. "utun4").
    var optlen: c_uint = @intCast(name_buf.len);
    if (getsockopt(fd, @intCast(SYSPROTO_CONTROL), UTUN_OPT_IFNAME, name_buf.ptr, &optlen) != 0) {
        return error.UtunIfname;
    }
    // optlen includes the trailing NUL.
    const n = std.mem.sliceTo(name_buf[0..optlen], 0).len;
    name_len.* = n;

    return .{ .fd = fd };
}

pub fn close(impl: *Impl) void {
    posix.close(impl.fd);
}

pub fn read(impl: *Impl, buf: []u8) !usize {
    var family: [4]u8 = undefined;
    var iov = [_]posix.iovec{
        .{ .base = &family, .len = 4 },
        .{ .base = buf.ptr, .len = buf.len },
    };
    const n = try posix.readv(impl.fd, &iov);
    if (n < 4) return 0;
    return n - 4;
}

pub fn write(impl: *Impl, pkt: []const u8) !usize {
    // 4-byte protocol family header in network byte order.
    const family = std.mem.toBytes(std.mem.nativeToBig(u32, AF_INET));
    var iov = [_]posix.iovec_const{
        .{ .base = &family, .len = 4 },
        .{ .base = pkt.ptr, .len = pkt.len },
    };
    const n = try posix.writev(impl.fd, &iov);
    return if (n >= 4) n - 4 else 0;
}
