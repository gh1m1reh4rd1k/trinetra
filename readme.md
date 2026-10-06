# Trinetra

> A low-level, high-performance TCP/UDP port scanner and service
> fingerprinter built on Linux `io_uring`.

[![License](https://img.shields.io/badge/license-<YOUR_LICENSE>-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)]()
[![Kernel](https://img.shields.io/badge/kernel-6.12%2B-critical.svg)]()
[![C++](https://img.shields.io/badge/C%2B%2B-20-blue.svg)]()

![Trinetra demo](https://github.com/gh1m1reh4rd1k/trinetra/blob/main/images/io_uring.jpeg)

---

## What is Trinetra?

Trinetra is a from-scratch, raw-packet TCP/UDP scanner that leverages
Linux `io_uring` for batched asynchronous I/O. It is designed as a
**learning-first** tool: the implementation comes first, and the theory
follows by observing real packet behavior. Trinetra provides deep,
low-level control over every header and option it sends — making it a
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
- **Multiple TCP scan types** — SYN (default), NULL, FIN, Xmas, ACK,
  Maimon, Window, and arbitrary custom flag combinations
- **Full state-machine handshake scan** — completes a real 4-way TCP
  handshake with graceful teardown
- **UDP scanning** and **host discovery** modes
- **IPv4 and IPv6 traceroute** (`run_traceroute` / `run_traceroute6`)

### Fingerprinting
- **Dual-stage version detection** — Nmap-style probe DB for probe
  selection/matching, followed by a dynamic response-body signature
  layer (titles, asset paths, platform/CDN fingerprints)
- **TLS & HTTP fingerprinting** — certificate extraction (SANs,
  issuer, validity), HTTP title/asset fingerprinting

### Performance & I/O
- **`io_uring`-based async I/O** with per-thread rings
- **SQPOLL mode** — kernel-thread submission, auto-enabled by probe
  volume (adaptive pacing) or estimated duration (fixed pacing), or
  forced manually
- **Congestion-aware batching** with adaptive rate/delay tuning
- **EWMA RTT estimation** for accurate timing and retries

### Networking & Isolation
- **Network namespace isolation** (`unshare(CLONE_NEWNET)`) via a
  macvlan bridged off a physical interface
- **MAC spoofing** and **ARP-based on-link resolution**
- **TCP option crafting** — MSS, window scale, SACK, timestamps, TFO
  cookie injection, and more
- **Checksum manipulation** — invalid-checksum patterns and bit-level
  manipulation for stack testing

### DNS
- Custom DNS servers (IPv4/IPv6)
- **DNS-over-TLS** (port 853, with certificate verification)
- Reverse DNS / PTR lookups
- **`--enum dns`** — active + passive recon (record sweep, AXFR,
  wildcard-aware brute force, DNSSEC/NSEC, SPF/DKIM/DMARC/BIMI,
  SRV/TLSA, CNAME takeover, PTR sweep, CT logs, Wayback, RDAP,
  ASN/BGP, passive-DNS aggregators, optional Google dorking)

### Robustness
- SIGINT handling with safe shutdown
- RAII-based resource management
- Structured output with per-host packet-sent counters
- Send-path drop detection at three checkpoints (buffer-pool
  exhaustion, SQ backpressure, `sendmsg()` rejection)

### Integrations
- Enrichment via **SecurityTrails** and **Shodan InternetDB**

---

## Requirements

| Component | Minimum | Notes |
|---|---|---|
| **Linux kernel** | **6.12** | Enforced by the setup script; required for the `io_uring` feature set Trinetra uses |
| Architecture | x86_64 / aarch64 | Others may work but are untested |
| OS | Debian, Ubuntu, or Arch Linux | Auto-detected by `setup.sh` |
| Compiler | GCC or Clang with **C++20** | `build-essential` / `base-devel` |
| Build tools | `make`, `cmake`, `pkg-config`, `git` | |
| Privileges | `root` (sudo) | Raw sockets + namespace isolation |
| Capabilities (if not root) | `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_SYS_ADMIN` | For raw sockets and `unshare(CLONE_NEWNET)` |

**Runtime libraries installed by the setup script:**
- `liburing` (built from source — https://github.com/axboe/liburing)
- `concurrentqueue` (headers — https://github.com/cameron314/concurrentqueue)
- `libcurl4-openssl-dev`, `libssl-dev` / `openssl`
- `nlohmann-json3-dev`
- `libpugixml-dev`
- `libpcre2-dev`
- `zlib1g-dev`
- `stunnel4` (Debian/Ubuntu) or `stunnel` (Arch)

> ⚠️ **Kernel 6.12 or newer is mandatory.** The installer will refuse to
> continue on older kernels.

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
   `/usr/share/<install-prefix>/`.
7. Build and `make install` the project.
8. Run a final verification pass.

### Manual build

If you already have all dependencies installed:

    make -j"$(nproc)"
    sudo make install

### Run

    # Basic SYN scan
    sudo trinetra -t 192.168.1.0/24 -p 1-1024

    # Full handshake scan inside an isolated namespace
    sudo trinetra -t 10.0.0.5 -p 80,443 --handshake --isolate

    # Version detection
    sudo trinetra -t example.com -p 1-10000 --version

    # DNS enumeration
    sudo trinetra --enum dns example.com

> See `trinetra --help` for the full CLI reference.

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
- Configurable queue depths via CLI
- `IORING_SETUP_SQPOLL` with a non-SQPOLL fallback if kernel init
  fails

### Namespace Isolation
- `unshare(CLONE_NEWNET)` + macvlan device bridged off a physical
  interface
- Keeps scanner traffic separate from host routing/stack
- Handshake mode auto-enters the namespace

### Concurrency
- `moodycamel::ConcurrentQueue` for task queuing
- Per-thread `io_uring` rings for batch transmission
- `std::atomic` for coordination; `std::mutex` for output sync

### Buffer Management
- Custom `PacketBufferPool`
- Thread-local pools to reduce contention
- Concurrent queue for buffer reuse

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

---

## Contributing

Issues and pull requests are welcome. Please open an issue before
starting work on significant changes.

## License

Distributed under the <YOUR LICENSE> License. See `LICENSE` for details.

## Acknowledgments

- The `io_uring` and `liburing` teams
- The Nmap project (probe-signature database format)
- `moodycamel::ConcurrentQueue`
- SecurityTrails and Shodan InternetDB APIs
