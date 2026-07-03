//! Overlay peer client.
//!
//! One UDP socket carries everything: control traffic to the coordination
//! server and data/hole-punch traffic to peers. Using a single socket is what
//! makes UDP hole punching work - the NAT mapping the server sees is the same
//! one peers send to.
//!
//! Three threads cooperate:
//!   * rx      - blocking recvfrom loop; dispatches every inbound datagram.
//!   * tun_rx  - reads IP packets off the TUN device and forwards them to the
//!               right peer.
//!   * maint   - periodic keepalive to the server and hole-punch/keepalive
//!               probes to every known peer.

const std = @import("std");
const posix = std.posix;
const proto = @import("protocol.zig");
const udp = @import("udp.zig");
const tun = @import("tun.zig");

const loop_interval_ms: u64 = 2_000;
const peer_dead_ms: i64 = 15_000;

const PeerState = enum { unknown, connected };

const PeerConn = struct {
    vaddr: proto.VAddr,
    endpoint: proto.Endpoint,
    state: PeerState = .unknown,
    last_rx_ms: i64 = 0,
    last_punch_ms: i64 = 0,
};

pub const Config = struct {
    server: std.net.Address,
    secret: []const u8,
    network_name: []const u8,
    requested_ip: proto.VAddr, // all-zero => let the server choose
    device_name: []const u8,
};

pub const Client = struct {
    gpa: std.mem.Allocator,
    sock: posix.socket_t,
    server: std.net.Address,
    server_ep: proto.Endpoint,
    auth: [proto.auth_len]u8,
    cfg: Config,

    vaddr: proto.VAddr = .{ 0, 0, 0, 0 },
    prefix: u8 = 24,

    registered: std.Thread.ResetEvent = .{},
    dev_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    dev: ?*tun.Device = null,

    mutex: std.Thread.Mutex = .{},
    peers: std.AutoHashMap(u32, PeerConn),

    pub fn init(gpa: std.mem.Allocator, cfg: Config) !Client {
        const sock = try udp.bind(try std.net.Address.parseIp4("0.0.0.0", 0));
        return .{
            .gpa = gpa,
            .sock = sock,
            .server = cfg.server,
            .server_ep = proto.Endpoint.fromAddress(cfg.server),
            .auth = proto.authDigest(cfg.secret),
            .cfg = cfg,
            .peers = std.AutoHashMap(u32, PeerConn).init(gpa),
        };
    }

    pub fn deinit(self: *Client) void {
        self.peers.deinit();
        posix.close(self.sock);
    }

    pub fn run(self: *Client) !void {
        // Register synchronously on this thread before starting any workers, so
        // that if the next steps fail (e.g. no privileges to open the TUN) we
        // exit cleanly with no background threads to race during teardown.
        try self.registerBlocking();
        std.log.info("assigned overlay address {d}.{d}.{d}.{d}/{d}", .{
            self.vaddr[0], self.vaddr[1], self.vaddr[2], self.vaddr[3], self.prefix,
        });

        // Open and configure the TUN device now that we know our address.
        var device = try tun.Device.open(self.gpa, self.cfg.device_name);
        defer device.deinit();
        std.log.info("opened tunnel interface {s}", .{device.name()});
        try tun.configure(self.gpa, device.name(), self.vaddr, self.prefix);

        self.dev = &device;
        self.dev_ready.store(true, .release);
        std.log.info("overlay is up; forwarding traffic", .{});

        // Now spawn the background workers.
        (try std.Thread.spawn(.{}, rxLoop, .{self})).detach();
        (try std.Thread.spawn(.{}, maintLoop, .{self})).detach();

        // This thread becomes the TUN reader.
        self.tunRxLoop(&device);
    }

    /// Send Register and wait for the ack, retrying every second. Runs on the
    /// main thread using a receive timeout so no worker thread is needed yet.
    fn registerBlocking(self: *Client) !void {
        try setRecvTimeout(self.sock, 1000);
        var buf: [2048]u8 = undefined;
        var attempt: usize = 0;
        while (!self.registered.isSet()) : (attempt += 1) {
            var sbuf: [256]u8 = undefined;
            const msg = proto.encodeRegister(&sbuf, self.auth, self.cfg.network_name, self.cfg.requested_ip);
            _ = udp.sendTo(self.sock, msg, self.server) catch {};

            const r = udp.recvFrom(self.sock, &buf) catch {
                if (attempt > 0 and attempt % 5 == 0)
                    std.log.warn("still waiting for server {f}...", .{self.server_ep});
                continue;
            };
            self.dispatch(buf[0..r.n], r.from);
        }
        // Back to blocking mode for the rx worker.
        try setRecvTimeout(self.sock, 0);
    }

    fn rxLoop(self: *Client) void {
        var buf: [2048]u8 = undefined;
        while (true) {
            const r = udp.recvFrom(self.sock, &buf) catch continue;
            self.dispatch(buf[0..r.n], r.from);
        }
    }

    fn dispatch(self: *Client, datagram: []const u8, from: std.net.Address) void {
        const t = proto.peekType(datagram) orelse return;
        const payload = datagram[1..];
        const from_ep = proto.Endpoint.fromAddress(from);
        switch (t) {
            .register_ack => {
                const ack = proto.decodeRegisterAck(payload) catch return;
                self.vaddr = ack.assigned;
                self.prefix = ack.prefix;
                self.registered.set();
            },
            .register_deny => {
                const reason = proto.decodeRegisterDeny(payload) catch "unknown";
                std.log.err("server denied registration: {s}", .{reason});
                std.process.exit(1);
            },
            .peer_list => self.handlePeerList(payload),
            .pong => {},
            .punch => {
                const p = proto.decodePunch(payload) catch return;
                self.learnPeer(p.sender, from_ep);
                // Answer so the initiator learns the path is open.
                var out: [16]u8 = undefined;
                const ack = proto.encodePunch(&out, .punch_ack, self.vaddr, p.nonce);
                _ = udp.sendTo(self.sock, ack, from) catch {};
            },
            .punch_ack => {
                const p = proto.decodePunch(payload) catch return;
                self.learnPeer(p.sender, from_ep);
            },
            .data => self.handleData(payload, from_ep),
            else => {},
        }
    }

    fn handlePeerList(self: *Client, payload: []const u8) void {
        var scratch: [proto.max_peers_per_list]proto.PeerEntry = undefined;
        const entries = proto.decodePeerList(payload, &scratch) catch return;

        self.mutex.lock();
        defer self.mutex.unlock();
        for (entries) |e| {
            if (proto.vaddrToU32(e.vaddr) == proto.vaddrToU32(self.vaddr)) continue;
            // A zero sentinel endpoint means "the server itself" - reach it at
            // the address we already use for the server.
            const endpoint = if (isSentinel(e.endpoint))
                proto.Endpoint.fromAddress(self.server)
            else
                e.endpoint;
            const gop = self.peers.getOrPut(proto.vaddrToU32(e.vaddr)) catch continue;
            if (!gop.found_existing) {
                gop.value_ptr.* = .{ .vaddr = e.vaddr, .endpoint = endpoint };
                std.log.info("discovered peer {d}.{d}.{d}.{d} at {f}", .{
                    e.vaddr[0], e.vaddr[1], e.vaddr[2], e.vaddr[3], endpoint,
                });
            } else if (gop.value_ptr.state != .connected) {
                // Not yet talking directly - trust the server's latest view.
                gop.value_ptr.endpoint = endpoint;
            }
        }
    }

    fn handleData(self: *Client, payload: []const u8, from: proto.Endpoint) void {
        if (payload.len < 4) return;
        const sender: proto.VAddr = payload[0..4].*;
        const ip_packet = payload[4..];
        self.learnPeer(sender, from);
        if (self.dev_ready.load(.acquire)) {
            if (self.dev) |d| _ = d.write(ip_packet) catch {};
        }
    }

    /// Record that we received a live packet from `vaddr` at `ep`: mark the peer
    /// connected and pin the endpoint to the address we actually heard from
    /// (which is the real, possibly-repunched, path).
    fn learnPeer(self: *Client, vaddr: proto.VAddr, ep: proto.Endpoint) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const gop = self.peers.getOrPut(proto.vaddrToU32(vaddr)) catch return;
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .vaddr = vaddr, .endpoint = ep };
        }
        if (gop.value_ptr.state != .connected) {
            std.log.info("direct tunnel established with {d}.{d}.{d}.{d} via {f}", .{
                vaddr[0], vaddr[1], vaddr[2], vaddr[3], ep,
            });
        }
        gop.value_ptr.endpoint = ep;
        gop.value_ptr.state = .connected;
        gop.value_ptr.last_rx_ms = std.time.milliTimestamp();
    }

    fn tunRxLoop(self: *Client, device: *tun.Device) void {
        var buf: [proto.data_header_len + tun.max_packet]u8 = undefined;
        while (true) {
            const n = device.read(buf[proto.data_header_len..]) catch |e| {
                std.log.warn("tun read error: {s}", .{@errorName(e)});
                continue;
            };
            const pkt = buf[proto.data_header_len .. proto.data_header_len + n];
            const dst = ipv4Dest(pkt) orelse continue;

            self.mutex.lock();
            const peer = self.peers.get(proto.vaddrToU32(dst));
            self.mutex.unlock();

            if (peer) |p| {
                _ = proto.encodeDataHeader(&buf, self.vaddr);
                const frame = buf[0 .. proto.data_header_len + n];
                _ = udp.sendToEndpoint(self.sock, frame, p.endpoint) catch {};
            }
            // Unknown destination: silently drop (like a LAN with no such host).
        }
    }

    fn maintLoop(self: *Client) void {
        while (true) {
            const now = std.time.milliTimestamp();

            // Keepalive to the server (also refreshes our NAT mapping there).
            var pbuf: [16]u8 = undefined;
            const ping = proto.encodePing(&pbuf, self.vaddr);
            _ = udp.sendTo(self.sock, ping, self.server) catch {};

            // Punch / keepalive every known peer.
            self.mutex.lock();
            var it = self.peers.iterator();
            while (it.next()) |e| {
                const p = e.value_ptr;
                if (p.state == .connected and now - p.last_rx_ms > peer_dead_ms) {
                    p.state = .unknown; // lost the path; fall back to punching
                }
                var out: [16]u8 = undefined;
                const nonce: u16 = @truncate(@as(u64, @bitCast(now)));
                const punch = proto.encodePunch(&out, .punch, self.vaddr, nonce);
                _ = udp.sendToEndpoint(self.sock, punch, p.endpoint) catch {};
                p.last_punch_ms = now;
            }
            self.mutex.unlock();

            std.time.sleep(loop_interval_ms * std.time.ns_per_ms);
        }
    }
};

/// Set a receive timeout on the socket. `ms == 0` restores blocking mode.
fn setRecvTimeout(sock: posix.socket_t, ms: u32) !void {
    const tv = posix.timeval{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &std.mem.toBytes(tv));
}

fn isSentinel(ep: proto.Endpoint) bool {
    return ep.port == 0 and std.mem.allEqual(u8, &ep.ip, 0);
}

/// Extract the destination address of an IPv4 packet, or null if it isn't one.
fn ipv4Dest(pkt: []const u8) ?proto.VAddr {
    if (pkt.len < 20) return null;
    if (pkt[0] >> 4 != 4) return null; // IPv6 / non-IP: unsupported in v1
    return pkt[16..20].*;
}

test "ipv4 dest extraction" {
    var pkt = [_]u8{0} ** 20;
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[16] = 10;
    pkt[17] = 66;
    pkt[18] = 0;
    pkt[19] = 7;
    try std.testing.expectEqual([4]u8{ 10, 66, 0, 7 }, ipv4Dest(&pkt).?);

    pkt[0] = 0x60; // IPv6
    try std.testing.expect(ipv4Dest(&pkt) == null);
}
