# Trinetra

> A low-level, high-performance TCP scanner and service fingerprinter
> built on Linux `io_uring`.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)]()
[![Kernel](https://img.shields.io/badge/kernel-6.12%2B-critical.svg)]()
[![C++](https://img.shields.io/badge/C%2B%2B-20-blue.svg)]()

---

## What is Trinetra?

Trinetra is a from-scratch, raw-packet TCP scanner that leverages Linux
`io_uring` for batched asynchronous I/O. It is designed as a
**learning-first** tool: the implementation comes first, and the theory
follows by observing real packet behavior. Trinetra provides deep,
low-level control over every header and option it sends: making it a
practical lab for understanding networking internals, protocol
behavior, and kernel I/O subsystems.

---

## ⚠️ Disclaimer

Trinetra performs **raw packet manipulation** and may crash or
destabilize target TCP/IP stacks. It is intended **strictly** for:

- Educational purposes
- Home labs
- Authorized penetration testing / red-team engagements

**Do not use Trinetra against systems you do not own or have explicit
written permission to test.** You are responsible for complying with
all applicable laws.

---

## Features

### Scanning
- **Multiple TCP scan types**: SYN (default), FIN, ACK, NULL, Xmas,
  Window, Maimon, plus per-flag scans (CWR, ECE, URG, PSH) and custom
  named combinations (HANUMAN, KAKABHUSUNDI, GANESH, RAM, GARUD, JATAYU)
- **State-machine handshake scan (`-G`)**: completes a real 4-way TCP
  handshake with graceful teardown inside an isolated network namespace
- **Host discovery**: `-sn` (ICMP) and `-sn6` (ICMPv6), with optional
  `-Pn` to skip discovery
- **IPv4 / IPv6 traceroute** (`--traceroute`, add `-6` for IPv6)
- **Passive discovery (`--netradar`)**: observe existing traffic on the
  wire (SYN/ACK/FIN/QUIC/DNS) without sending any packets of your own

### Fingerprinting & Enumeration
- **Service/version detection (`-sV`)**: dual-stage: Nmap-style probe
  DB for probe selection/matching, followed by a dynamic response-body
  signature layer (titles, asset paths, platform/CDN fingerprints)
- **UDP service probing (`-sV --udp`)**
- **TLS / HTTP fingerprinting**: certificate extraction (SANs, issuer,
  validity), HTTP title/asset fingerprinting, optional mTLS
- **OS fingerprinting** (`--os-detect`): passive, from replies received
- **Enumeration modules (`--enum`)**: `shodan`, `ssl`, `dns`,
  `trail:<api-key>` (SecurityTrails); comma-separated, any order
- **Discovery module**: ASN/org lookup (`--cn`, `--org`), country
  IP-range fetch (`--country`, `--owner`, `--ipv4`/`--ipv6`), and
  reverse IP/ASN to domains (`--ip`, `--range`, `--asn`)

### Performance & I/O
- **`io_uring`-based async I/O** with per-thread rings
- **SQPOLL mode**: kernel-thread submission; auto-enabled by probe
  volume (adaptive pacing) or estimated duration (fixed pacing), or
  forced with `--sqpoll`
- **Congestion-aware batching** with adaptive rate/delay tuning
  (`--cong-curve`, `--cong-alpha-*`, `--rate-dyn-*`, `--batch-delay-dyn-*`)
- **EWMA RTT estimation** with retry logic (`--set-rtt`, `--rto-mult`,
  `--rto-pad1/2`)

### Networking & Isolation
- **Network namespace isolation** (`--split`, `--split-ip`,
  `--split-gw`, `--split-ip6`, `--split-gw6`, `--split-mac`,
  `--split-iface`) via macvlan
- **MAC spoofing** (`--src-mac`) and **ARP-based on-link resolution**
  (`--dst-mac` to skip ARP)
- **TCP option crafting**: MSS, window scale, SACK, timestamps, NOPs,
  MPTCP, TCP-AO, TFO cookie injection, custom sequence numbers
- **IP-layer control**: TTL, DSCP/TOS, IP ID generation modes,
  fragmentation (`-f`, `--frag ofo|zof|lap`), Router Alert, IPSO
- **IPv6 extension headers**: Hop-by-Hop, Destination, Routing, AH,
  ESP, Flow Label, extension-header chain manipulation, early chain
  termination
- **Checksum manipulation**: invalid checksums (`--badsum`), partial
  invalid checksum patterns (`--prsum`)
- **Ethernet / VLAN**: single and double 802.1Q (QinQ) tagging,
  custom EtherType, multicast destination MAC, padding

### Robustness
- SIGINT handling with safe shutdown
- RAII-based resource management
- Structured output with per-host packet-sent counters
- Send-path drop detection at three checkpoints (buffer-pool
  exhaustion, SQ backpressure, `sendmsg()` rejection)
- `--grep` for a plain, copy-friendly target list

### Server Mode
- **`--server`**: start Trinetra as a LAN control panel accessible over
  HTTPS (TLS handled automatically via `stunnel`); configurable port
  (`--server-port`, default 8443) and auth token (`--server-token`)

### DNS
- Custom DNS servers (IPv4/IPv6) via `--dns-servers`
- **DNS-over-TLS** via `--dns-servers-tls` (port 853, certificate-verified)
- Reverse DNS / PTR lookups
- Full DNS enumeration via `--enum dns`

---

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| **Linux kernel** | **6.12** | Enforced by `setup.sh`; required for the `io_uring` feature set Trinetra uses |
| Architecture | x86_64 / aarch64 | Others may work but are untested |
| OS | Debian, Ubuntu, or Arch Linux | Auto-detected by `setup.sh` |
| Compiler | GCC or Clang with **C++20** | `build-essential` / `base-devel` |
| Build tools | `make`, `cmake`, `pkg-config`, `git` | |
| Privileges | `root` (sudo) | Raw sockets + namespace isolation |
| Capabilities (if not root) | `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` | For raw sockets and `unshare(CLONE_NEWNET)` |

**Runtime libraries installed by the setup script:**
- [`liburing`](https://github.com/axboe/liburing): built from source
- [`concurrentqueue`](https://github.com/cameron314/concurrentqueue): headers
- `libcurl4-openssl-dev`, `libssl-dev` / `openssl`
- `nlohmann-json3-dev`
- `libpugixml-dev`
- `libpcre2-dev`
- `zlib1g-dev`
- `stunnel4` (Debian/Ubuntu) or `stunnel` (Arch)

> ⚠️ **Kernel 6.12 or newer is mandatory.** The installer will refuse
> to continue on older kernels.

---

## Quick Start

### Automated install (recommended)

The included `setup.sh` handles OS detection, kernel check, dependency
installation, `liburing` build, header installation, data-file
placement, and the final build + install.

    git clone https://github.com/gh1m1reh4rd1k/trinetra.git
    cd trinetra
    sudo ./setup.sh

The script will:

1. Detect your distribution (Debian/Ubuntu or Arch).
2. Verify your kernel is **≥ 6.12**.
3. Install system build dependencies.
4. Build and install `liburing` from source.
5. Install `concurrentqueue` headers.
6. Copy data files (MAC vendors, ports, signatures, cloud ranges) to
   the install prefix.
7. Build and `make install` the project.
8. Run a final verification pass.

### Manual build

If you already have all dependencies installed:

    make -j"$(nproc)"
    sudo make install

---

## Usage

> The examples below use the installed binary name. See
> [A note on naming](#a-note-on-naming) if your install uses a
> different name.

### Basic TCP scans

    # Default SYN scan over a /24
    sudo shiv 192.168.1.0/24 -p 1-1024

    # Xmas scan on selected ports
    sudo shiv 10.0.0.5 -p 80,443,8080 -sX

    # Full 4-way handshake scan inside an isolated namespace
    sudo shiv 10.0.0.5 -p 80,443 -G 

    # Scan inside an isolated namespace
    sudo shiv --split 192.168.1.254 -p 443,22

### Service / version detection

    # HTTP/TLS-aware version detection
    sudo shiv example.com -p 1-10000 -sV

    # Force HTTPS probe with strict TLS verification
    sudo shiv example.com -p 443 -sV --force-https --tls-verify

    # UDP service probing
    sudo shiv 10.0.0.1 -p 53,123,161 -sV --udp

### Host discovery

    # ICMP host discovery
    sudo shiv -sn 192.168.1.0/24

    # Discover, then only scan hosts that responded
    sudo shiv -sn -sS -Pn 192.168.1.0/24

### Enumeration

    # Shodan InternetDB + DNS enumeration on a domain
    sudo shiv example.com --enum shodan,dns

    # SecurityTrails subdomain lookup
    sudo shiv example.com --enum trail:<api-key>

### Discovery (ASN / country / reverse IP)

    # List ASNs and orgs for a country
    sudo shiv --cn nepal

    # Fetch all public IPv4 ranges for a country
    sudo shiv --country nepal --ipv4 -o np.txt

    # Reverse-lookup domains on an IP
    sudo shiv --ip 103.48.88.33

    # Routes announced by an ASN
    sudo shiv --asn AS45353 --ipv6

### Passive discovery

    # Watch the wire until Ctrl-C
    sudo shiv --netradar

    # Capture for 30 seconds on a specific interface
    sudo shiv --netradar --time 30s --interface eth0

### Traceroute

    sudo shiv 8.8.8.8 --traceroute

    sudo shiv scanme.nmap.org --traceroute

### Server mode

    # Start LAN control panel (prints a ready-to-use HTTPS link)
    sudo shiv --server

    # Custom port and fixed token
    sudo shiv --server --server-port 9443 --server-token <token>

> For the full flag reference: pacing, IP/TCP header crafting, IPv6
> extension-header control, buffer management, debug modes, and more,
> see [`https://github.com/gh1m1reh4rd1k/trinetra/wiki/standard_documentation`](https://github.com/gh1m1reh4rd1k/trinetra/wiki/standard_documentation) (or run `shiv --help`)

---

## Architecture (for contributors)

### Sending Packets
- TCP: `io_uring_prep_sendmsg()`
- ARP: `io_uring_prep_sendto()` for batched ARP requests
- Raw sockets: `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` for custom
  IP/TCP header crafting

### Receiving Packets
- Primary: `io_uring_prep_recvmsg()` for async reception
- Raw TCP socket: `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)`
- ARP: `io_uring_prep_recvmsg()`
- Non-blocking sockets via `fcntl()` + `O_NONBLOCK`

### `io_uring` Configuration
- Separate send and receive rings (`io_uring_queue_init()`)
- `io_uring_wait_cqe_timeout()` for response timeouts
- Configurable queue depths (`--send-uring`, `--rcv-uring`)
- `IORING_SETUP_SQPOLL` with a non-SQPOLL fallback if kernel init
  fails

### Namespace Isolation
- `unshare(CLONE_NEWNET)` + macvlan device bridged off a physical
  interface (`--split*` family of flags)
- Keeps scanner traffic separate from host routing/stack
- `-G` (state-machine handshake) auto-enters the namespace

### Concurrency
- `moodycamel::ConcurrentQueue` for task queuing
- Per-thread `io_uring` rings for batch transmission
- `std::atomic` for coordination; `std::mutex` for output sync

### Buffer Management
- Custom `PacketBufferPool`
- Thread-local pools to reduce contention
- Concurrent queue for buffer reuse

---

## A note on naming

The CLI reference and `setup.sh` currently refer to the binary as
**`shiv`**, and the installer writes data files under
`/usr/share/shiv/`. The repository is named **Trinetra**. Until the
two are unified, use whichever name your build actually produces:
`shiv` in most builds today.

> **Maintainers:** see [Action Items](#action-items-for-maintainers)
> for the rename plan.

---

## Troubleshooting

**"Shiv's minimum requirement kernel version is 6.12"**
Your kernel is too old. Upgrade to 6.12+ and reboot. On Debian/Ubuntu,
consider the HWE or mainline kernels; on Arch, `linux` or `linux-lts`
(current LTS is fine).

**"Missing source files: ..."**
`setup.sh` expects the data files (`mac-vendors.txt`, `ports.txt`,
`signatures.conf`, `shiv_split.conf`, and the `ranges/*.txt` files) to
be present in the repo root. Make sure you cloned the full repository
and are running the script from the project root.

**"This script requires sudo privileges"**
Run with `sudo ./setup.sh`. For manual runs, either be root or grant
the binary `CAP_NET_RAW` / `CAP_NET_ADMIN` / `CAP_SYS_ADMIN`.

**"UDP scan doesn't seem to work standalone"**
UDP probing is only available through service detection: `-sV --udp`.
There is no standalone `-sU` mode yet.

**"`--handshake` / `--isolate` / `--version` are unknown flags"**
Those aren't real flags. Use `-G` for state-machine handshake,
`--split` for namespace isolation, and `-sV` for version detection.

---

## Action Items for Maintainers

Before the next tagged release, consider:

1. **Unify the binary name.** The repo says *Trinetra*; the binary and
   install paths say *shiv*. Either rename the binary to `trinetra`
   (recommended: matches the repo) or keep `shiv` and add a
   short note at the top of the README explaining the codename.
2. **Rename `/usr/share/shiv/` to `/usr/share/trinetra/`** in
   `setup.sh`, `Makefile`, and any path constants in the source.
3. **Fix the error string** `"Shiv's minimum requirement kernel
   version is 6.12"` to `"Trinetra requires Linux kernel 6.12 or
   newer"`.
4. **Add `docs/CLI.md`.** Your CLI reference is excellent and too long
   for the README. Split it out and link from the README's Usage
   section. This is the single biggest readability win.
5. **Reorder `main()` in `setup.sh`.** Move `check_sudo` before
   `check_io_uring_support`: the kernel check doesn't need root.
6. **Remove dead `if [ $? -eq 0 ]` blocks** after `make` /
   `make install`: with `set -euo pipefail`, the failure branch never
   runs.
7. **Add a demo GIF** (`asciinema` + `agg` is fastest) below the
   badges.
8. **Fill in the LICENSE file** with the MIT text and your name/year.

---

## Contributing

Issues and pull requests are welcome. Please open an issue before
starting work on significant changes.

## License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for
details.

## Acknowledgments

- The `io_uring` and `liburing` teams
- The Nmap project (probe-signature database format)
- [`moodycamel::ConcurrentQueue`](https://github.com/cameron314/concurrentqueue)
- SecurityTrails and Shodan InternetDB APIs
