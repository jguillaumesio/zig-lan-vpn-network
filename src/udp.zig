//! Thin UDP helpers shared by the server and client, built directly on the
//! POSIX socket layer so the same code compiles on Linux, macOS and Windows.

const std = @import("std");
const posix = std.posix;
const proto = @import("protocol.zig");

/// Create and bind a UDP socket to `addr`. Returns the socket fd.
pub fn bind(addr: std.net.Address) !posix.socket_t {
    const sock = try posix.socket(
        addr.any.family,
        posix.SOCK.DGRAM,
        posix.IPPROTO.UDP,
    );
    errdefer posix.close(sock);
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));
    try posix.bind(sock, &addr.any, addr.getOsSockLen());
    return sock;
}

/// Local port the socket is bound to (after an ephemeral :0 bind).
pub fn localPort(sock: posix.socket_t) !u16 {
    var sa: posix.sockaddr.in = undefined;
    var sl: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    try posix.getsockname(sock, @ptrCast(&sa), &sl);
    return std.mem.bigToNative(u16, sa.port);
}

pub const RecvResult = struct {
    n: usize,
    from: std.net.Address,
};

pub fn recvFrom(sock: posix.socket_t, buf: []u8) !RecvResult {
    var from: posix.sockaddr align(4) = undefined;
    var from_len: posix.socklen_t = @sizeOf(posix.sockaddr);
    const n = try posix.recvfrom(sock, buf, 0, &from, &from_len);
    return .{ .n = n, .from = .{ .any = from } };
}

pub fn sendTo(sock: posix.socket_t, buf: []const u8, to: std.net.Address) !usize {
    return posix.sendto(sock, buf, 0, &to.any, to.getOsSockLen());
}

pub fn sendToEndpoint(sock: posix.socket_t, buf: []const u8, ep: proto.Endpoint) !usize {
    return sendTo(sock, buf, ep.toAddress());
}

/// Resolve "host:port" (host may be a name or a dotted IPv4) to an address.
pub fn resolveHostPort(gpa: std.mem.Allocator, s: []const u8) !std.net.Address {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.MissingPort;
    const host = s[0..colon];
    const port = try std.fmt.parseInt(u16, s[colon + 1 ..], 10);

    // Fast path: already a dotted-quad.
    if (std.net.Address.parseIp4(host, port)) |a| {
        return a;
    } else |_| {}

    const list = try std.net.getAddressList(gpa, host, port);
    defer list.deinit();
    for (list.addrs) |a| {
        if (a.any.family == posix.AF.INET) return a;
    }
    return error.NoIpv4Address;
}
