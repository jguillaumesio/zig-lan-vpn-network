# hamachi-like

A tiny peer-to-peer overlay VPN in [Zig](https://ziglang.org), in the spirit of
LogMeIn Hamachi / ZeroTier. Peers get a virtual LAN address and talk to each
other directly over UDP, punching through NATs with the help of a lightweight
coordination server. Traffic is carried on a real OS TUN interface, so any
IP application (SSH, ping, game servers, …) works unmodified.

This is **v1: a working command-line client + server** for macOS, Linux and
Windows.

```
        ┌──────────────┐   register / peer list (UDP)   ┌──────────────┐
        │   peer A      │ ─────────────┐   ┌───────────► │   peer B     │
        │ tun 10.66.0.2 │              ▼   │             │ tun 10.66.0.3│
        └───────┬───────┘        ┌─────────────┐         └──────┬───────┘
                │                │ coordination │                │
                │                │   server     │                │
                │                └─────────────┘                 │
                └───────── direct UDP tunnel (hole-punched) ──────┘
                          (data never flows through the server)
```

## How it works

1. **Coordination server** — a process on a public IP. Peers register with it
   over UDP using a shared secret. It hands each peer a stable virtual address
   (default subnet `10.66.0.0/24`), remembers the public endpoint it saw each
   peer arrive from (the NAT-reflexive address), and periodically pushes every
   peer the roster of all other peers.

2. **Peers** open a TUN device, register, and receive their virtual address plus
   the peer roster. For every peer they fire UDP "punch" probes at the other's
   public endpoint; because both sides do this on the *same socket they used to
   reach the server*, the NAT mappings line up and a direct path opens.

3. **Data** — once a direct path exists, IP packets read off the TUN device are
   wrapped in a 5-byte header and sent straight to the destination peer's
   endpoint. Nothing but control traffic touches the server.

A single UDP socket per peer carries both control and data traffic — this is
what makes hole punching work.

## Requirements

- **Zig 0.14.0** exactly. The 0.15/0.16 standard library reorganised the socket
  and I/O layers incompatibly; this project targets the stable 0.14.0 API.
  Download it from <https://ziglang.org/download/#release-0.14.0>.
- **Root / Administrator** on peers (creating a TUN interface is privileged).
- **Windows only:** the [Wintun](https://www.wintun.net) driver. Drop
  `wintun.dll` (matching your CPU architecture) next to the executable. Windows
  has no built-in layer-3 tunnel.

## Build

```sh
zig build                      # native build -> zig-out/bin/hamachi-like
zig build -Doptimize=ReleaseSafe
```

Cross-compile for another platform:

```sh
zig build -Dtarget=x86_64-linux-gnu   -Doptimize=ReleaseSafe
zig build -Dtarget=aarch64-linux-gnu  -Doptimize=ReleaseSafe
zig build -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseSafe
zig build -Dtarget=aarch64-macos      -Doptimize=ReleaseSafe
```

Run the tests:

```sh
zig build test
```

## Usage

On a machine with a public IP (no root needed — it never touches a TUN device):

```sh
hamachi-like server --secret s3cret
# --listen 0.0.0.0:7777   (default)
# --subnet 10.66.0.0/24   (default)
```

On each peer (needs root/Administrator):

```sh
sudo hamachi-like join --server vpn.example.com:7777 --secret s3cret
# --name default          network label
# --ip 10.66.0.10         request a specific overlay address
# --dev ham0              TUN interface name hint
```

Once two peers are up you can use their overlay addresses directly:

```sh
ping 10.66.0.3
ssh user@10.66.0.3
```

## Security status (read this)

**v1 does not encrypt data traffic.** The shared secret only authenticates
registration with the coordination server (via a SHA-256 digest); it is not used
to encrypt or authenticate peer-to-peer packets. Do not treat this as a secure
VPN yet. Adding an authenticated-encryption layer (e.g. Noise / X25519 +
ChaCha20-Poly1305 per peer) is the top item on the roadmap.

## Known limitations (v1)

- **No encryption** (see above).
- **No relay fallback.** If both peers are behind *symmetric* NATs, direct hole
  punching can fail and those two peers won't connect. A TURN-style relay through
  the server is planned.
- **IPv4 only** on the overlay and for the carrier.
- **No persistent identity.** Addresses are assigned per session (though you can
  request one with `--ip`).

## Project layout

| File | Responsibility |
|------|----------------|
| `src/main.zig` | CLI parsing and command dispatch |
| `src/protocol.zig` | Wire format: encode/decode of all message types |
| `src/server.zig` | Coordination server: auth, address assignment, roster broadcast |
| `src/client.zig` | Peer: registration, hole punching, TUN⇆UDP forwarding |
| `src/udp.zig` | Small UDP socket helpers |
| `src/tun.zig` | Cross-platform TUN abstraction + IP configuration |
| `src/tun_linux.zig` | `/dev/net/tun` backend |
| `src/tun_macos.zig` | `utun` (PF_SYSTEM control socket) backend |
| `src/tun_windows.zig` | Wintun backend (dynamically loads `wintun.dll`) |
| `src/integration_test.zig` | End-to-end coordinator handshake test over loopback |

## Verification status

Built and link-checked for `aarch64-macos`, `x86_64-linux-gnu`,
`aarch64-linux-gnu`, `x86_64-linux-musl` and `x86_64-windows-gnu`. Unit tests and
an end-to-end coordinator handshake test (auth, address assignment, peer-list
broadcast) pass. The TUN data plane requires root and has been exercised via the
real CLI binaries up to the point of device creation; end-to-end packet
forwarding should be validated on two real hosts.

## License

MIT — see [LICENSE](LICENSE).
