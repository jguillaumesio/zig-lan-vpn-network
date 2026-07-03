//! Coordination server - and a full member of the overlay itself.
//!
//! Running the server puts you *inside* the network: this process is both the
//! rendezvous point that introduces peers to each other AND an ordinary member
//! with its own overlay address (the first host address, e.g. 10.66.0.1) and
//! TUN device.
//!
//! As the rendezvous it:
//!   * authenticates registrations against a shared secret,
//!   * hands each peer a stable virtual (overlay) IP,
//!   * records the public endpoint it observed each peer arrive from, and
//!   * periodically pushes every peer the roster of all members.
//!
//! As a member it also carries its own data traffic: packets other members send
//! to its address are written to its TUN, and packets its OS emits toward the
//! overlay are forwarded straight to the right peer. It never relays traffic
//! *between* other peers - those talk directly after being introduced.
//!
//! The server doesn't need to know its own public IP: every member already
//! reaches it at the address they were configured with, so it advertises itself
//! in the roster with a zero "sentinel" endpoint that each member resolves to
//! the server address it is already using.

const std = @import("std");
const posix = std.posix;
const proto = @import("protocol.zig");
const udp = @import("udp.zig");
const tun = @import("tun.zig");

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
    /// TUN interface name hint for the server's own membership.
    device_name: []const u8 = "ham0",
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    sock: posix.socket_t,
    auth: [proto.auth_len]u8,
    subnet: u32,
    prefix: u8,
    /// The server's own overlay address (subnet + 1), reserved from assignment.
    self_vaddr: proto.VAddr,
    self_u32: u32,
    device_name: []const u8,

    dev_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    dev: ?*tun.Device = null,

    mutex: std.Thread.Mutex = .{},
    /// keyed by virtual address as u32 - holds *other* members (not self)
    peers: std.AutoHashMap(u32, Peer),

    pub fn init(gpa: std.mem.Allocator, cfg: Config) !Server {
        const sock = try udp.bind(cfg.listen);
        const subnet = proto.vaddrToU32(cfg.subnet);
        const self_u32 = subnet + 1;
        return .{
            .gpa = gpa,
            .sock = sock,
            .auth = proto.authDigest(cfg.secret),
            .subnet = subnet,
            .prefix = cfg.prefix,
            .self_vaddr = proto.u32ToVaddr(self_u32),
            .self_u32 = self_u32,
            .device_name = cfg.device_name,
            .peers = std.AutoHashMap(u32, Peer).init(gpa),
        };
    }

    pub fn deinit(self: *Server) void {
        self.peers.deinit();
        posix.close(self.sock);
    }

    /// Run as a full member: bring up our own TUN, then serve forever.
    pub fn run(self: *Server) !void {
        var device = try tun.Device.open(self.gpa, self.device_name);
        defer device.deinit();
        std.log.info("opened tunnel interface {s}", .{device.name()});
        try tun.configure(self.gpa, device.name(), self.self_vaddr, self.prefix);
        self.dev = &device;
        self.dev_ready.store(true, .release);
        std.log.info("joined overlay as {d}.{d}.{d}.{d}/{d}", .{
            self.self_vaddr[0], self.self_vaddr[1], self.self_vaddr[2], self.self_vaddr[3], self.prefix,
        });

        (try std.Thread.spawn(.{}, tunRxLoop, .{ self, &device })).detach();
        (try std.Thread.spawn(.{}, maintenanceLoop, .{self})).detach();
        self.serve();
    }

    /// Serve only the control plane (no TUN). Used by tests.
    pub fn runControlPlane(self: *Server) void {
        (std.Thread.spawn(.{}, maintenanceLoop, .{self}) catch return).detach();
        self.serve();
    }

    fn serve(self: *Server) void {
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
            .data => self.handleData(datagram[1..]),
            .punch => self.handlePunch(datagram[1..], from),
            else => {},
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

    /// A member sent us overlay data; write the inner IP packet to our TUN.
    fn handleData(self: *Server, payload: []const u8) void {
        if (payload.len < 4) return;
        const ip_packet = payload[4..];
        if (self.dev_ready.load(.acquire)) {
            if (self.dev) |d| _ = d.write(ip_packet) catch {};
        }
    }

    /// Answer punches so members see the host as a reachable, connected peer.
    fn handlePunch(self: *Server, payload: []const u8, from: std.net.Address) void {
        const p = proto.decodePunch(payload) catch return;
        var out: [16]u8 = undefined;
        const ack = proto.encodePunch(&out, .punch_ack, self.self_vaddr, p.nonce);
        _ = udp.sendTo(self.sock, ack, from) catch {};
    }

    /// Read IP packets off our TUN and forward each to the destination member.
    fn tunRxLoop(self: *Server, device: *tun.Device) void {
        var buf: [proto.data_header_len + tun.max_packet]u8 = undefined;
        while (true) {
            const n = device.read(buf[proto.data_header_len..]) catch continue;
            const pkt = buf[proto.data_header_len .. proto.data_header_len + n];
            const dst = ipv4Dest(pkt) orelse continue;

            self.mutex.lock();
            const peer = self.peers.get(proto.vaddrToU32(dst));
            self.mutex.unlock();

            if (peer) |pr| {
                _ = proto.encodeDataHeader(&buf, self.self_vaddr);
                _ = udp.sendToEndpoint(self.sock, buf[0 .. proto.data_header_len + n], pr.endpoint) catch {};
            }
        }
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

        // Honor a valid, free requested address (but never our own reserved one).
        const req = proto.vaddrToU32(requested);
        if (req != 0 and req != self.self_u32 and (req & masked(self.prefix)) == self.subnet) {
            if (!self.peers.contains(req)) return requested;
        }

        // Otherwise take the first free host address. Skip .0 (network), the
        // all-ones broadcast, and .1 (reserved for the server itself).
        var host: u32 = 2;
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

        var all: [proto.max_peers_per_list]Peer = undefined;
        var n: usize = 0;
        var it = self.peers.iterator();
        while (it.next()) |e| {
            if (n >= all.len) break;
            all[n] = e.value_ptr.*;
            n += 1;
        }

        // Sentinel endpoint (0.0.0.0:0) => "the server address you already use".
        const self_entry = proto.PeerEntry{
            .vaddr = self.self_vaddr,
            .endpoint = .{ .ip = .{ 0, 0, 0, 0 }, .port = 0 },
        };

        var entries: [proto.max_peers_per_list]proto.PeerEntry = undefined;
        var buf: [2048]u8 = undefined;
        for (all[0..n]) |target| {
            var m: usize = 0;
            // Every member always learns about the host.
            entries[m] = self_entry;
            m += 1;
            for (all[0..n]) |p| {
                if (proto.vaddrToU32(p.vaddr) == proto.vaddrToU32(target.vaddr)) continue;
                if (m >= entries.len) break;
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

fn ipv4Dest(pkt: []const u8) ?proto.VAddr {
    if (pkt.len < 20) return null;
    if (pkt[0] >> 4 != 4) return null;
    return pkt[16..20].*;
}

test "masked prefix" {
    try std.testing.expectEqual(@as(u32, 0xffffff00), masked(24));
    try std.testing.expectEqual(@as(u32, 0), masked(0));
}
