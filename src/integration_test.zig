//! End-to-end test of the coordination server over loopback UDP.
//!
//! Spins up a real Server on an ephemeral port and drives it with two raw UDP
//! "clients" (no TUN, so no root needed), asserting the full control handshake:
//! authentication, virtual-IP assignment, and peer-list broadcast.

const std = @import("std");
const posix = std.posix;
const proto = @import("protocol.zig");
const udp = @import("udp.zig");
const Server = @import("server.zig").Server;

fn setRecvTimeout(sock: posix.socket_t, ms: u32) !void {
    const tv = posix.timeval{ .sec = @intCast(ms / 1000), .usec = @intCast((ms % 1000) * 1000) };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(tv));
}

const Raw = struct {
    sock: posix.socket_t,
    server: std.net.Address,

    fn init(server: std.net.Address) !Raw {
        const s = try udp.bind(try std.net.Address.parseIp4("127.0.0.1", 0));
        try setRecvTimeout(s, 2000);
        return .{ .sock = s, .server = server };
    }
    fn deinit(self: *Raw) void {
        posix.close(self.sock);
    }
    fn send(self: *Raw, buf: []const u8) !void {
        _ = try udp.sendTo(self.sock, buf, self.server);
    }
    fn recv(self: *Raw, buf: []u8) ![]u8 {
        const r = try udp.recvFrom(self.sock, buf);
        return buf[0..r.n];
    }
};

test "coordinator handshake: auth, assignment, broadcast" {
    // The server runs forever on a detached thread and is torn down with the
    // process, so use a non-tracking allocator to avoid false leak reports.
    const gpa = std.heap.page_allocator;

    var srv = try Server.init(gpa, .{
        .listen = try std.net.Address.parseIp4("127.0.0.1", 0),
        .secret = "test-secret",
        .subnet = .{ 10, 66, 0, 0 },
        .prefix = 24,
    });
    // Server.run loops forever on a detached thread; the process tears it down.
    const port = try udp.localPort(srv.sock);
    const server_addr = try std.net.Address.parseIp4("127.0.0.1", port);
    (try std.Thread.spawn(.{}, Server.run, .{&srv})).detach();

    const good = proto.authDigest("test-secret");

    // --- Peer A registers -> expects an ack with an in-subnet address.
    var a = try Raw.init(server_addr);
    defer a.deinit();
    var buf: [2048]u8 = undefined;
    {
        const msg = proto.encodeRegister(&buf, good, "lan", .{ 0, 0, 0, 0 });
        var sbuf: [256]u8 = undefined;
        @memcpy(sbuf[0..msg.len], msg);
        try a.send(sbuf[0..msg.len]);
    }
    const a_vaddr = blk: {
        while (true) {
            const dg = try a.recv(&buf);
            if (proto.peekType(dg).? == .register_ack) {
                const ack = try proto.decodeRegisterAck(dg[1..]);
                try std.testing.expectEqual(@as(u8, 24), ack.prefix);
                try std.testing.expectEqual(@as(u8, 10), ack.assigned[0]);
                break :blk ack.assigned;
            }
        }
    };

    // --- Peer B registers -> distinct address.
    var b = try Raw.init(server_addr);
    defer b.deinit();
    {
        var sbuf: [256]u8 = undefined;
        const msg = proto.encodeRegister(&sbuf, good, "lan", .{ 0, 0, 0, 0 });
        try b.send(sbuf[0..msg.len]);
    }
    const b_vaddr = blk: {
        while (true) {
            const dg = try b.recv(&buf);
            if (proto.peekType(dg).? == .register_ack) {
                break :blk (try proto.decodeRegisterAck(dg[1..])).assigned;
            }
        }
    };
    try std.testing.expect(proto.vaddrToU32(a_vaddr) != proto.vaddrToU32(b_vaddr));

    // --- A must eventually receive a peer list containing B.
    var found_b = false;
    var tries: usize = 0;
    while (tries < 10 and !found_b) : (tries += 1) {
        const dg = a.recv(&buf) catch break;
        if (proto.peekType(dg).? != .peer_list) continue;
        var scratch: [proto.max_peers_per_list]proto.PeerEntry = undefined;
        const entries = try proto.decodePeerList(dg[1..], &scratch);
        for (entries) |e| {
            if (proto.vaddrToU32(e.vaddr) == proto.vaddrToU32(b_vaddr)) found_b = true;
        }
    }
    try std.testing.expect(found_b);

    // --- Wrong secret is denied.
    var c = try Raw.init(server_addr);
    defer c.deinit();
    {
        var sbuf: [256]u8 = undefined;
        const bad = proto.authDigest("wrong");
        const msg = proto.encodeRegister(&sbuf, bad, "lan", .{ 0, 0, 0, 0 });
        try c.send(sbuf[0..msg.len]);
    }
    {
        const dg = try c.recv(&buf);
        try std.testing.expectEqual(proto.MsgType.register_deny, proto.peekType(dg).?);
    }
}
