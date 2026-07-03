//! hamachi-like: a tiny peer-to-peer overlay VPN.
//!
//! Two roles:
//!   server  - a public-IP coordinator that peers rendezvous through.
//!   join    - a peer that opens a TUN device and hole-punches to other peers.

const std = @import("std");
const builtin = @import("builtin");
const proto = @import("protocol.zig");
const udp = @import("udp.zig");
const Server = @import("server.zig").Server;
const Client = @import("client.zig").Client;

const default_port = 7777;

const usage =
    \\hamachi-like - peer-to-peer overlay network (TUN + UDP hole punching)
    \\
    \\USAGE:
    \\  hamachi-like server [options]
    \\  hamachi-like join   [options]
    \\
    \\SERVER OPTIONS (host the network AND join it; needs a reachable address
    \\                and root/Administrator - the server takes the first
    \\                overlay address, e.g. 10.66.0.1):
    \\  --listen <ip:port>    Address to listen on         (default 0.0.0.0:7777)
    \\  --secret <key>        Shared network secret         (required)
    \\  --subnet <cidr>       Overlay subnet                (default 10.66.0.0/24)
    \\  --dev <name>          TUN interface name hint       (default per-OS)
    \\
    \\JOIN OPTIONS (run this on each peer; needs root/Administrator):
    \\  --server <host:port>  Coordinator address           (required)
    \\  --secret <key>        Shared network secret         (required)
    \\  --name <name>         Network name label            (default "default")
    \\  --ip <a.b.c.d>        Preferred overlay address     (default: assigned)
    \\  --dev <name>          TUN interface name hint       (default per-OS)
    \\
    \\EXAMPLES:
    \\  # On the host (reachable address; hosts the network and joins it):
    \\  sudo hamachi-like server --secret s3cret
    \\
    \\  # On each peer:
    \\  sudo hamachi-like join --server vpn.example.com:7777 --secret s3cret
    \\
;

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len < 2) {
        try printUsage();
        return error.MissingCommand;
    }

    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "server")) {
        // Fatal errors: log and exit immediately rather than unwinding, which
        // would race the detached worker threads during teardown.
        runServer(gpa, args[2..]) catch |e| fatal("server", e);
    } else if (std.mem.eql(u8, cmd, "join")) {
        runJoin(gpa, args[2..]) catch |e| fatal("join", e);
    } else if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try printUsage();
    } else {
        std.log.err("unknown command: {s}", .{cmd});
        try printUsage();
        return error.UnknownCommand;
    }
}

fn fatal(role: []const u8, e: anyerror) noreturn {
    std.log.err("{s} failed: {s}", .{ role, @errorName(e) });
    std.process.exit(1);
}

fn printUsage() !void {
    try std.io.getStdOut().writeAll(usage);
}

fn runServer(gpa: std.mem.Allocator, args: []const []const u8) !void {
    var listen_str: []const u8 = "0.0.0.0:7777";
    var secret: ?[]const u8 = null;
    var subnet_str: []const u8 = "10.66.0.0/24";
    var dev: []const u8 = defaultDevName();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--listen")) {
            listen_str = try nextArg(args, &i, "--listen");
        } else if (std.mem.eql(u8, a, "--secret")) {
            secret = try nextArg(args, &i, "--secret");
        } else if (std.mem.eql(u8, a, "--subnet")) {
            subnet_str = try nextArg(args, &i, "--subnet");
        } else if (std.mem.eql(u8, a, "--dev")) {
            dev = try nextArg(args, &i, "--dev");
        } else {
            std.log.err("unknown server option: {s}", .{a});
            return error.BadArgs;
        }
    }

    const sec = secret orelse {
        std.log.err("--secret is required", .{});
        return error.BadArgs;
    };

    const listen = try udp.resolveHostPort(gpa, listen_str);
    const cidr = try parseCidr(subnet_str);

    var srv = try Server.init(gpa, .{
        .listen = listen,
        .secret = sec,
        .subnet = cidr.base,
        .prefix = cidr.prefix,
        .device_name = dev,
    });
    defer srv.deinit();

    std.log.info("coordination server listening on {s}, overlay {s}", .{ listen_str, subnet_str });
    try srv.run();
}

fn runJoin(gpa: std.mem.Allocator, args: []const []const u8) !void {
    var server_str: ?[]const u8 = null;
    var secret: ?[]const u8 = null;
    var name: []const u8 = "default";
    var ip_str: ?[]const u8 = null;
    var dev: []const u8 = defaultDevName();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--server")) {
            server_str = try nextArg(args, &i, "--server");
        } else if (std.mem.eql(u8, a, "--secret")) {
            secret = try nextArg(args, &i, "--secret");
        } else if (std.mem.eql(u8, a, "--name")) {
            name = try nextArg(args, &i, "--name");
        } else if (std.mem.eql(u8, a, "--ip")) {
            ip_str = try nextArg(args, &i, "--ip");
        } else if (std.mem.eql(u8, a, "--dev")) {
            dev = try nextArg(args, &i, "--dev");
        } else {
            std.log.err("unknown join option: {s}", .{a});
            return error.BadArgs;
        }
    }

    const srv = server_str orelse {
        std.log.err("--server is required", .{});
        return error.BadArgs;
    };
    const sec = secret orelse {
        std.log.err("--secret is required", .{});
        return error.BadArgs;
    };

    const requested_ip: proto.VAddr = if (ip_str) |s| try parseVAddr(s) else .{ 0, 0, 0, 0 };
    const server_addr = try udp.resolveHostPort(gpa, srv);

    var client = try Client.init(gpa, .{
        .server = server_addr,
        .secret = sec,
        .network_name = name,
        .requested_ip = requested_ip,
        .device_name = dev,
    });
    defer client.deinit();

    std.log.info("joining network \"{s}\" via {s}", .{ name, srv });
    try client.run();
}

fn defaultDevName() []const u8 {
    return switch (builtin.os.tag) {
        .linux => "ham0",
        .windows => "hamachi-like",
        else => "ham0", // macOS ignores the hint and picks utunN
    };
}

fn nextArg(args: []const []const u8, i: *usize, flag: []const u8) ![]const u8 {
    if (i.* + 1 >= args.len) {
        std.log.err("{s} requires a value", .{flag});
        return error.BadArgs;
    }
    i.* += 1;
    return args[i.*];
}

fn parseVAddr(s: []const u8) !proto.VAddr {
    var out: proto.VAddr = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var n: usize = 0;
    while (it.next()) |octet| {
        if (n >= 4) return error.BadAddress;
        out[n] = std.fmt.parseInt(u8, octet, 10) catch return error.BadAddress;
        n += 1;
    }
    if (n != 4) return error.BadAddress;
    return out;
}

const Cidr = struct { base: proto.VAddr, prefix: u8 };

fn parseCidr(s: []const u8) !Cidr {
    const slash = std.mem.indexOfScalar(u8, s, '/') orelse return error.BadCidr;
    const base = try parseVAddr(s[0..slash]);
    const prefix = try std.fmt.parseInt(u8, s[slash + 1 ..], 10);
    if (prefix > 32) return error.BadCidr;
    return .{ .base = base, .prefix = prefix };
}

test "parse vaddr and cidr" {
    try std.testing.expectEqual([4]u8{ 10, 66, 0, 1 }, try parseVAddr("10.66.0.1"));
    try std.testing.expectError(error.BadAddress, parseVAddr("10.66.0"));
    const c = try parseCidr("192.168.5.0/24");
    try std.testing.expectEqual([4]u8{ 192, 168, 5, 0 }, c.base);
    try std.testing.expectEqual(@as(u8, 24), c.prefix);
}
