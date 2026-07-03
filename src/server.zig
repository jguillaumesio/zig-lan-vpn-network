//! Coordination / rendezvous server.
//!
//! Peers all speak to this one public-IP process over UDP. It:
//!   * authenticates registrations against a shared secret,
//!   * hands each peer a stable virtual (overlay) IP,
//!   * records the public endpoint it observed each peer arrive from
//!     (the NAT-reflexive address), and
//!   * periodically pushes every peer the roster of all other peers so they
//!     can hole-punch direct tunnels to each other.
//!
//! The server never carries data traffic — only control. Once peers learn each
//! other's endpoints they talk directly.

const std = @import("std");
const posix = std.posix;
const proto = @import("protocol.zig");
const udp = @import("udp.zig");

const peer_timeout_ms: i64 = 30_000;
const broadcast_interval_ms: i64 = 5_000;

const Peer = struct {
    vaddr: proto.VAddr,
    endpoint: proto.Endpoint,
    last_seen_ms: i64,
    name_buf: [64]u8 = undefined,
    name_len: usize = 0,

    fn name(self: *const Peer) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const Config = struct {
    listen: std.net.Address,
    secret: []const u8,
    /// Overlay subnet base address, e.g. 10.66.0.0.
    subnet: proto.VAddr,
    prefix: u8,
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    sock: posix.socket_t,
    auth: [proto.auth_len]u8,
    subnet: u32,
    prefix: u8,
    mutex: std.Thread.Mutex = .{},
    /// keyed by virtual address as u32
    peers: std.AutoHashMap(u32, Peer),

    pub fn init(gpa: std.mem.Allocator, cfg: Config) !Server {
        const sock = try udp.bind(cfg.listen);
        return .{
            .gpa = gpa,
            .sock = sock,
            .auth = proto.authDigest(cfg.secret),
            .subnet = proto.vaddrToU32(cfg.subnet),
            .prefix = cfg.prefix,
            .peers = std.AutoHashMap(u32, Peer).init(gpa),
        };
    }

    pub fn deinit(self: *Server) void {
        self.peers.deinit();
        posix.close(self.sock);
    }

    pub fn run(self: *Server) !void {
        const maint = try std.Thread.spawn(.{}, maintenanceLoop, .{self});
        maint.detach();

        var buf: [2048]u8 = undefined;
        while (true) {
            const r = udp.recvFrom(self.sock, &buf) catch |e| {
                std.log.warn("recv error: {s}", .{@errorName(e)});
                continue;
            };
            self.handle(buf[0..r.n], r.from);
        }
    }

    fn handle(self: *Server, datagram: []const u8, from: std.net.Address) void {
        const t = proto.peekType(datagram) orelse return;
        const from_ep = proto.Endpoint.fromAddress(from);
        switch (t) {
            .register => self.handleRegister(datagram[1..], from_ep),
            .ping => self.handlePing(datagram[1..], from_ep),
            else => {}, // servers ignore peer-to-peer message types
        }
    }

    fn handleRegister(self: *Server, payload: []const u8, from: proto.Endpoint) void {
        const reg = proto.decodeRegister(payload) catch {
            std.log.warn("malformed register from {f}", .{from});
            return;
        };
        if (reg.version != proto.version) {
            self.deny(from, "protocol version mismatch");
            return;
        }
        if (!std.crypto.utils.timingSafeEql([proto.auth_len]u8, reg.auth, self.auth)) {
            std.log.warn("bad secret from {f}", .{from});
            self.deny(from, "authentication failed");
            return;
        }

        self.mutex.lock();
        const vaddr = self.assignAddress(reg.requested_ip, from) catch {
            self.mutex.unlock();
            self.deny(from, "no free addresses");
            return;
        };
        const key = proto.vaddrToU32(vaddr);
        const gop = self.peers.getOrPut(key) catch {
            self.mutex.unlock();
            return;
        };
        gop.value_ptr.* = .{
            .vaddr = vaddr,
            .endpoint = from,
            .last_seen_ms = std.time.milliTimestamp(),
        };
        const nlen = @min(reg.name.len, 63);
        @memcpy(gop.value_ptr.name_buf[0..nlen], reg.name[0..nlen]);
        gop.value_ptr.name_len = nlen;
        self.mutex.unlock();

        std.log.info("registered {d}.{d}.{d}.{d} at {f} (\"{s}\")", .{
            vaddr[0], vaddr[1], vaddr[2], vaddr[3], from, reg.name[0..nlen],
        });

        var out: [64]u8 = undefined;
        const ack = proto.encodeRegisterAck(&out, vaddr, self.prefix);
        _ = udp.sendToEndpoint(self.sock, ack, from) catch {};

        self.broadcastPeerList();
    }

    fn handlePing(self: *Server, payload: []const u8, from: proto.Endpoint) void {
        const vaddr = proto.decodePing(payload) catch return;
        const key = proto.vaddrToU32(vaddr);

        self.mutex.lock();
        if (self.peers.getPtr(key)) |p| {
            p.last_seen_ms = std.time.milliTimestamp();
            // Track NAT rebinding: if the observed endpoint moved, update it.
            if (!p.endpoint.eql(from)) {
                std.log.info("endpoint for {d}.{d}.{d}.{d} moved {f} -> {f}", .{
                    vaddr[0], vaddr[1], vaddr[2], vaddr[3], p.endpoint, from,
                });
                p.endpoint = from;
                self.mutex.unlock();
                self.broadcastPeerList();
                self.mutex.lock();
            }
        }
        self.mutex.unlock();

        var out: [8]u8 = undefined;
        const pong = proto.encodePong(&out);
        _ = udp.sendToEndpoint(self.sock, pong, from) catch {};
    }

    /// Caller must hold the mutex.
    fn assignAddress(self: *Server, requested: proto.VAddr, from: proto.Endpoint) !proto.VAddr {
        // Reconnection: if this exact endpoint is already known, reuse its addr.
        var it = self.peers.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.endpoint.eql(from)) return e.value_ptr.vaddr;
        }

        const host_bits: u5 = @intCast(32 - self.prefix);
        const count: u32 = if (host_bits >= 32) 0xffffffff else (@as(u32, 1) << host_bits);

        // Honor a valid, free requested address.
        const req = proto.vaddrToU32(requested);
        if (req != 0 and (req & masked(self.prefix)) == self.subnet) {
            if (!self.peers.contains(req)) return requested;
        }

        // Otherwise take the first free host address (skip .0 network and the
        // all-ones broadcast address).
        var host: u32 = 1;
        while (host < count - 1) : (host += 1) {
            const cand = self.subnet + host;
            if (!self.peers.contains(cand)) return proto.u32ToVaddr(cand);
        }
        return error.Exhausted;
    }

    fn deny(self: *Server, to: proto.Endpoint, reason: []const u8) void {
        var out: [128]u8 = undefined;
        const msg = proto.encodeRegisterDeny(&out, reason);
        _ = udp.sendToEndpoint(self.sock, msg, to) catch {};
    }

    fn broadcastPeerList(self: *Server) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var entries: [proto.max_peers_per_list]proto.PeerEntry = undefined;
        var all: [proto.max_peers_per_list]Peer = undefined;
        var n: usize = 0;
        var it = self.peers.iterator();
        while (it.next()) |e| {
            if (n >= all.len) break;
            all[n] = e.value_ptr.*;
            n += 1;
        }

        var buf: [2048]u8 = undefined;
        for (all[0..n]) |target| {
            // Build a roster excluding the target itself.
            var m: usize = 0;
            for (all[0..n]) |p| {
                if (proto.vaddrToU32(p.vaddr) == proto.vaddrToU32(target.vaddr)) continue;
                entries[m] = .{ .vaddr = p.vaddr, .endpoint = p.endpoint };
                m += 1;
            }
            const msg = proto.encodePeerList(&buf, entries[0..m]);
            _ = udp.sendToEndpoint(self.sock, msg, target.endpoint) catch {};
        }
    }

    fn maintenanceLoop(self: *Server) void {
        while (true) {
            std.time.sleep(broadcast_interval_ms * std.time.ns_per_ms);
            const now = std.time.milliTimestamp();

            self.mutex.lock();
            var it = self.peers.iterator();
            var dead: [proto.max_peers_per_list]u32 = undefined;
            var d: usize = 0;
            while (it.next()) |e| {
                if (now - e.value_ptr.last_seen_ms > peer_timeout_ms and d < dead.len) {
                    dead[d] = e.key_ptr.*;
                    d += 1;
                }
            }
            for (dead[0..d]) |k| {
                const p = self.peers.fetchRemove(k);
                if (p) |kv| {
                    const v = kv.value.vaddr;
                    std.log.info("expired {d}.{d}.{d}.{d}", .{ v[0], v[1], v[2], v[3] });
                }
            }
            self.mutex.unlock();

            self.broadcastPeerList();
        }
    }
};

fn masked(prefix: u8) u32 {
    return if (prefix == 0) 0 else @as(u32, 0xffffffff) << @intCast(32 - prefix);
}

test "masked prefix" {
    try std.testing.expectEqual(@as(u32, 0xffffff00), masked(24));
    try std.testing.expectEqual(@as(u32, 0), masked(0));
}
