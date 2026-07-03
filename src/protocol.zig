//! Wire protocol for the hamachi-like overlay network.
//!
//! Every datagram begins with a single type byte. Control traffic
//! (client <-> coordination server) and peer traffic (client <-> client) all
//! share one UDP socket per client so that the NAT mapping punched open for the
//! server is the same one peers reach us on.
//!
//! Integers on the wire are big-endian. IPv4 addresses are 4 raw bytes, ports
//! are 2 bytes. There is intentionally no framing beyond the type byte: UDP
//! preserves datagram boundaries, so one datagram == one message.

const std = @import("std");

/// Bumped whenever the wire format changes incompatibly.
pub const version: u8 = 1;

/// Length of the auth digest carried in Register (SHA-256 of the shared secret).
pub const auth_len = 32;

pub const MsgType = enum(u8) {
    register = 0x01,
    register_ack = 0x02,
    register_deny = 0x03,
    peer_list = 0x04,
    ping = 0x05,
    pong = 0x06,
    punch = 0x10,
    punch_ack = 0x11,
    data = 0x20,
    _,
};

/// A public (post-NAT) UDP endpoint as observed on the wire.
pub const Endpoint = struct {
    ip: [4]u8,
    port: u16,

    pub fn fromAddress(a: std.net.Address) Endpoint {
        // Only IPv4 is supported in v1.
        const in = a.in;
        const raw: u32 = in.sa.addr; // already network byte order
        return .{
            .ip = @bitCast(raw),
            .port = std.mem.bigToNative(u16, in.sa.port),
        };
    }

    pub fn toAddress(self: Endpoint) std.net.Address {
        return std.net.Address.initIp4(self.ip, self.port);
    }

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        return std.mem.eql(u8, &a.ip, &b.ip) and a.port == b.port;
    }

    pub fn format(
        self: Endpoint,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{d}.{d}.{d}.{d}:{d}", .{
            self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port,
        });
    }
};

/// A virtual (overlay) IPv4 address, e.g. 10.66.0.2.
pub const VAddr = [4]u8;

pub fn vaddrToU32(v: VAddr) u32 {
    return std.mem.readInt(u32, &v, .big);
}

pub fn u32ToVaddr(x: u32) VAddr {
    var v: VAddr = undefined;
    std.mem.writeInt(u32, &v, x, .big);
    return v;
}

// ---------------------------------------------------------------------------
// Encoding helpers: a tiny append-only writer over a caller-provided buffer.
// ---------------------------------------------------------------------------

pub const Writer = struct {
    buf: []u8,
    len: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub fn u8v(self: *Writer, v: u8) void {
        self.buf[self.len] = v;
        self.len += 1;
    }

    pub fn u16v(self: *Writer, v: u16) void {
        std.mem.writeInt(u16, self.buf[self.len..][0..2], v, .big);
        self.len += 2;
    }

    pub fn bytes(self: *Writer, b: []const u8) void {
        @memcpy(self.buf[self.len..][0..b.len], b);
        self.len += b.len;
    }

    pub fn slice(self: *Writer) []u8 {
        return self.buf[0..self.len];
    }
};

/// A bounds-checked reader over a received datagram.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub const Error = error{Truncated};

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn u8v(self: *Reader) Error!u8 {
        if (self.pos + 1 > self.buf.len) return error.Truncated;
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }

    pub fn u16v(self: *Reader) Error!u16 {
        if (self.pos + 2 > self.buf.len) return error.Truncated;
        const v = std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }

    pub fn take(self: *Reader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.Truncated;
        const s = self.buf[self.pos..][0..n];
        self.pos += n;
        return s;
    }

    pub fn rest(self: *Reader) []const u8 {
        return self.buf[self.pos..];
    }
};

// ---------------------------------------------------------------------------
// Message builders. Each returns the encoded slice within `buf`.
// ---------------------------------------------------------------------------

/// register := type | version | auth[32] | name_len | name | requested_ip[4]
pub fn encodeRegister(
    buf: []u8,
    auth: [auth_len]u8,
    name: []const u8,
    requested_ip: VAddr,
) []u8 {
    var w = Writer.init(buf);
    w.u8v(@intFromEnum(MsgType.register));
    w.u8v(version);
    w.bytes(&auth);
    w.u8v(@intCast(name.len));
    w.bytes(name);
    w.bytes(&requested_ip);
    return w.slice();
}

pub const Register = struct {
    version: u8,
    auth: [auth_len]u8,
    name: []const u8,
    requested_ip: VAddr,
};

pub fn decodeRegister(payload: []const u8) !Register {
    var r = Reader.init(payload);
    const ver = try r.u8v();
    const auth = try r.take(auth_len);
    const name_len = try r.u8v();
    const name = try r.take(name_len);
    const ip = try r.take(4);
    return .{
        .version = ver,
        .auth = auth[0..auth_len].*,
        .name = name,
        .requested_ip = ip[0..4].*,
    };
}

/// register_ack := type | assigned_ip[4] | prefix_len
pub fn encodeRegisterAck(buf: []u8, assigned: VAddr, prefix: u8) []u8 {
    var w = Writer.init(buf);
    w.u8v(@intFromEnum(MsgType.register_ack));
    w.bytes(&assigned);
    w.u8v(prefix);
    return w.slice();
}

pub const RegisterAck = struct { assigned: VAddr, prefix: u8 };

pub fn decodeRegisterAck(payload: []const u8) !RegisterAck {
    var r = Reader.init(payload);
    const ip = try r.take(4);
    const prefix = try r.u8v();
    return .{ .assigned = ip[0..4].*, .prefix = prefix };
}

/// register_deny := type | reason_len | reason
pub fn encodeRegisterDeny(buf: []u8, reason: []const u8) []u8 {
    var w = Writer.init(buf);
    w.u8v(@intFromEnum(MsgType.register_deny));
    w.u8v(@intCast(reason.len));
    w.bytes(reason);
    return w.slice();
}

pub fn decodeRegisterDeny(payload: []const u8) ![]const u8 {
    var r = Reader.init(payload);
    const n = try r.u8v();
    return try r.take(n);
}

pub const PeerEntry = struct { vaddr: VAddr, endpoint: Endpoint };

/// peer_list := type | count[2] | count * (vaddr[4] | ip[4] | port[2])
pub fn encodePeerList(buf: []u8, peers: []const PeerEntry) []u8 {
    var w = Writer.init(buf);
    w.u8v(@intFromEnum(MsgType.peer_list));
    w.u16v(@intCast(peers.len));
    for (peers) |p| {
        w.bytes(&p.vaddr);
        w.bytes(&p.endpoint.ip);
        w.u16v(p.endpoint.port);
    }
    return w.slice();
}

/// Max peers that fit in one datagram given a conservative MTU.
pub const max_peers_per_list = 100;

pub fn decodePeerList(payload: []const u8, out: []PeerEntry) ![]PeerEntry {
    var r = Reader.init(payload);
    const count = try r.u16v();
    if (count > out.len) return error.TooMany;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const vaddr = try r.take(4);
        const ip = try r.take(4);
        const port = try r.u16v();
        out[i] = .{
            .vaddr = vaddr[0..4].*,
            .endpoint = .{ .ip = ip[0..4].*, .port = port },
        };
    }
    return out[0..count];
}

/// ping := type | vaddr[4]
pub fn encodePing(buf: []u8, vaddr: VAddr) []u8 {
    var w = Writer.init(buf);
    w.u8v(@intFromEnum(MsgType.ping));
    w.bytes(&vaddr);
    return w.slice();
}

pub fn decodePing(payload: []const u8) !VAddr {
    var r = Reader.init(payload);
    const ip = try r.take(4);
    return ip[0..4].*;
}

pub fn encodePong(buf: []u8) []u8 {
    var w = Writer.init(buf);
    w.u8v(@intFromEnum(MsgType.pong));
    return w.slice();
}

/// punch / punch_ack := type | sender_vaddr[4] | nonce[2]
pub fn encodePunch(buf: []u8, kind: MsgType, sender: VAddr, nonce: u16) []u8 {
    var w = Writer.init(buf);
    w.u8v(@intFromEnum(kind));
    w.bytes(&sender);
    w.u16v(nonce);
    return w.slice();
}

pub const Punch = struct { sender: VAddr, nonce: u16 };

pub fn decodePunch(payload: []const u8) !Punch {
    var r = Reader.init(payload);
    const ip = try r.take(4);
    const nonce = try r.u16v();
    return .{ .sender = ip[0..4].*, .nonce = nonce };
}

/// data := type | src_vaddr[4] | ip_packet...
pub fn encodeDataHeader(buf: []u8, src: VAddr) usize {
    var w = Writer.init(buf);
    w.u8v(@intFromEnum(MsgType.data));
    w.bytes(&src);
    return w.len; // == 5; caller appends the IP packet after this offset
}

pub const data_header_len = 5;

/// Compute the SHA-256 digest used as the network auth token.
pub fn authDigest(secret: []const u8) [auth_len]u8 {
    var out: [auth_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(secret, &out, .{});
    return out;
}

pub fn peekType(datagram: []const u8) ?MsgType {
    if (datagram.len == 0) return null;
    return @enumFromInt(datagram[0]);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "register round-trip" {
    var buf: [256]u8 = undefined;
    const auth = authDigest("hunter2");
    const enc = encodeRegister(&buf, auth, "mylan", .{ 10, 66, 0, 5 });
    try std.testing.expectEqual(MsgType.register, peekType(enc).?);
    const dec = try decodeRegister(enc[1..]);
    try std.testing.expectEqualStrings("mylan", dec.name);
    try std.testing.expectEqual(version, dec.version);
    try std.testing.expect(std.mem.eql(u8, &auth, &dec.auth));
    try std.testing.expectEqual([4]u8{ 10, 66, 0, 5 }, dec.requested_ip);
}

test "peer list round-trip" {
    var buf: [1024]u8 = undefined;
    const peers = [_]PeerEntry{
        .{ .vaddr = .{ 10, 66, 0, 2 }, .endpoint = .{ .ip = .{ 1, 2, 3, 4 }, .port = 1111 } },
        .{ .vaddr = .{ 10, 66, 0, 3 }, .endpoint = .{ .ip = .{ 5, 6, 7, 8 }, .port = 2222 } },
    };
    const enc = encodePeerList(&buf, &peers);
    var out: [max_peers_per_list]PeerEntry = undefined;
    const dec = try decodePeerList(enc[1..], &out);
    try std.testing.expectEqual(@as(usize, 2), dec.len);
    try std.testing.expectEqual([4]u8{ 5, 6, 7, 8 }, dec[1].endpoint.ip);
    try std.testing.expectEqual(@as(u16, 2222), dec[1].endpoint.port);
}

test "endpoint address conversion" {
    const ep = Endpoint{ .ip = .{ 192, 168, 1, 50 }, .port = 7777 };
    const addr = ep.toAddress();
    const back = Endpoint.fromAddress(addr);
    try std.testing.expect(ep.eql(back));
}
