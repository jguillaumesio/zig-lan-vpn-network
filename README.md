# hamachi-like

A small VPN-like tool that puts your machines on the same virtual LAN, no matter
where they are. Like LogMeIn Hamachi or ZeroTier: each machine gets a private
address (e.g. `10.66.0.2`), and you can `ssh`, `ping`, share files, or play LAN
games between them as if they were plugged into the same switch.

**Right now it's command-line only.** A GUI is the next big step (see below).

## What it does, step by step

1. **A TUN interface.** On each machine we create a virtual network card (a
   "TUN" device). Anything the OS sends to `10.66.0.x` gets handed to our program
   instead of a real cable.

2. **A coordination server.** You run one small server somewhere with a public IP.
   Machines check in with it (using a shared secret), and it hands each one a
   virtual address and tells everyone who else is on the network. It only does
   introductions — your actual traffic never goes through it.

3. **UDP hole punching.** Two machines behind home routers normally can't reach
   each other directly. Using the endpoints the server saw, both sides fire UDP
   packets at each other at the same time, which tricks their routers into
   leaving a path open. After that, the two machines talk **directly**.

4. **Forwarding.** Once the path is open, packets read off the TUN device are
   wrapped in UDP and sent straight to the right machine. The other side unwraps
   them and writes them back to its TUN device. That's the whole VPN.

## Why Zig 0.14

This is written in Zig, pinned to **version 0.14.0**.

Zig is still evolving fast, and the newer 0.15/0.16 releases (including the one
Homebrew installs today) ripped out and rewrote the standard-library socket and
low-level OS layers that this project depends on — they're mid-migration and not
stable yet. 0.14.0 is the last release with the settled `std.posix`
socket/ioctl API we build on, so everything here targets it.

Get it from <https://ziglang.org/download/#release-0.14.0>.

## Build & run

```sh
zig build -Doptimize=ReleaseSafe          # -> zig-out/bin/hamachi-like
zig build test                            # run the tests
```

On a machine with a public IP (no root needed):

```sh
hamachi-like server --secret s3cret
```

On each machine that should join (needs root/Administrator to create the TUN):

```sh
sudo hamachi-like join --server vpn.example.com:7777 --secret s3cret
```

Then just use the virtual addresses: `ping 10.66.0.3`, `ssh user@10.66.0.3`, etc.

Windows note: install the [Wintun](https://www.wintun.net) driver and drop
`wintun.dll` next to the executable — Windows has no built-in TUN device.

## Status & limitations

- CLI only for now.
- **Not encrypted yet** — the secret only gates joining the server; peer traffic
  is currently plaintext. Encryption is planned.
- No relay fallback, so two peers behind very strict (symmetric) NATs may fail to
  connect directly.
- IPv4 only.

## The goal from here

Finish it by adding a **GUI** — a simple app to start/stop the network, see who's
online, and copy addresses — so it's usable without touching a terminal.

## License

MIT — see [LICENSE](LICENSE).
