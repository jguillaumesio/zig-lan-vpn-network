//! Windows TUN backend built on Wintun (https://www.wintun.net).
//!
//! Windows has no native layer-3 tunnel, so we depend on WireGuard's Wintun
//! driver. `wintun.dll` is loaded dynamically at runtime (no import-library or
//! link-time dependency), and the matching driver must be installed. Drop
//! `wintun.dll` next to the executable, or install it system-wide.

const std = @import("std");
const windows = std.os.windows;
const WINAPI = windows.WINAPI;
const HANDLE = windows.HANDLE;
const HMODULE = windows.HMODULE;
const DWORD = windows.DWORD;
const BOOL = windows.BOOL;

const ERROR_NO_MORE_ITEMS: DWORD = 259;
const INFINITE: DWORD = 0xFFFFFFFF;
// Ring buffer capacity handed to WintunStartSession (must be a power of two
// between 128 KiB and 64 MiB). 4 MiB is a comfortable default.
const RING_CAPACITY: DWORD = 0x400000;

extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(WINAPI) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(WINAPI) ?*anyopaque;
extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, ms: DWORD) callconv(WINAPI) DWORD;

const ADAPTER = *opaque {};
const SESSION = *opaque {};

const CreateAdapterFn = *const fn ([*:0]const u16, [*:0]const u16, ?*const anyopaque) callconv(WINAPI) ?ADAPTER;
const CloseAdapterFn = *const fn (ADAPTER) callconv(WINAPI) void;
const StartSessionFn = *const fn (ADAPTER, DWORD) callconv(WINAPI) ?SESSION;
const EndSessionFn = *const fn (SESSION) callconv(WINAPI) void;
const GetReadWaitEventFn = *const fn (SESSION) callconv(WINAPI) HANDLE;
const ReceivePacketFn = *const fn (SESSION, *DWORD) callconv(WINAPI) ?[*]u8;
const ReleaseReceiveFn = *const fn (SESSION, [*]const u8) callconv(WINAPI) void;
const AllocateSendFn = *const fn (SESSION, DWORD) callconv(WINAPI) ?[*]u8;
const SendPacketFn = *const fn (SESSION, [*]const u8) callconv(WINAPI) void;

const Api = struct {
    createAdapter: CreateAdapterFn,
    closeAdapter: CloseAdapterFn,
    startSession: StartSessionFn,
    endSession: EndSessionFn,
    getReadWaitEvent: GetReadWaitEventFn,
    receivePacket: ReceivePacketFn,
    releaseReceive: ReleaseReceiveFn,
    allocateSend: AllocateSendFn,
    sendPacket: SendPacketFn,
};

fn load(dll: HMODULE, comptime T: type, name: [*:0]const u8) !T {
    const p = GetProcAddress(dll, name) orelse {
        std.log.err("wintun.dll missing export: {s}", .{name});
        return error.WintunSymbol;
    };
    return @ptrCast(@alignCast(p));
}

pub const Impl = struct {
    api: Api,
    adapter: ADAPTER,
    session: SESSION,
    read_event: HANDLE,
};

pub fn open(
    _: std.mem.Allocator,
    requested_name: []const u8,
    name_buf: []u8,
    name_len: *usize,
) !Impl {
    const dll = LoadLibraryW(std.unicode.utf8ToUtf16LeStringLiteral("wintun.dll")) orelse {
        std.log.err("cannot load wintun.dll; download it from https://www.wintun.net and place it next to the executable", .{});
        return error.WintunNotFound;
    };

    const api = Api{
        .createAdapter = try load(dll, CreateAdapterFn, "WintunCreateAdapter"),
        .closeAdapter = try load(dll, CloseAdapterFn, "WintunCloseAdapter"),
        .startSession = try load(dll, StartSessionFn, "WintunStartSession"),
        .endSession = try load(dll, EndSessionFn, "WintunEndSession"),
        .getReadWaitEvent = try load(dll, GetReadWaitEventFn, "WintunGetReadWaitEvent"),
        .receivePacket = try load(dll, ReceivePacketFn, "WintunReceivePacket"),
        .releaseReceive = try load(dll, ReleaseReceiveFn, "WintunReleaseReceivePacket"),
        .allocateSend = try load(dll, AllocateSendFn, "WintunAllocateSendPacket"),
        .sendPacket = try load(dll, SendPacketFn, "WintunSendPacket"),
    };

    // Adapter + tunnel-type names as UTF-16.
    var wname: [128]u16 = undefined;
    const name = requested_name[0..@min(requested_name.len, 63)];
    const wlen = std.unicode.utf8ToUtf16Le(&wname, name) catch return error.BadName;
    wname[wlen] = 0;
    const wname_z: [*:0]const u16 = @ptrCast(&wname);
    const tunnel_type = std.unicode.utf8ToUtf16LeStringLiteral("hamachi-like");

    const adapter = api.createAdapter(wname_z, tunnel_type, null) orelse {
        std.log.err("WintunCreateAdapter failed (err {d}); run as Administrator", .{@intFromEnum(windows.kernel32.GetLastError())});
        return error.WintunAdapter;
    };
    errdefer api.closeAdapter(adapter);

    const session = api.startSession(adapter, RING_CAPACITY) orelse {
        return error.WintunSession;
    };

    // We keep the caller's requested name; netsh configures the interface by it.
    @memcpy(name_buf[0..name.len], name);
    name_len.* = name.len;

    return .{
        .api = api,
        .adapter = adapter,
        .session = session,
        .read_event = api.getReadWaitEvent(session),
    };
}

pub fn close(impl: *Impl) void {
    impl.api.endSession(impl.session);
    impl.api.closeAdapter(impl.adapter);
}

pub fn read(impl: *Impl, buf: []u8) !usize {
    while (true) {
        var size: DWORD = 0;
        if (impl.api.receivePacket(impl.session, &size)) |pkt| {
            const n = @min(@as(usize, size), buf.len);
            @memcpy(buf[0..n], pkt[0..n]);
            impl.api.releaseReceive(impl.session, pkt);
            return n;
        }
        switch (@intFromEnum(windows.kernel32.GetLastError())) {
            ERROR_NO_MORE_ITEMS => _ = WaitForSingleObject(impl.read_event, INFINITE),
            else => return error.WintunReceive,
        }
    }
}

pub fn write(impl: *Impl, pkt: []const u8) !usize {
    const out = impl.api.allocateSend(impl.session, @intCast(pkt.len)) orelse
        return error.WintunSendBuffer;
    @memcpy(out[0..pkt.len], pkt);
    impl.api.sendPacket(impl.session, out);
    return pkt.len;
}
