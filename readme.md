## Features

<details open>
<summary><strong>Scanning</strong></summary>

<br>

- **Multiple TCP scan types**
  - SYN (default), FIN, ACK, NULL, Xmas, Window, Maimon
  - Per-flag scans: CWR, ECE, URG, PSH
  - Custom named combinations: HANUMAN, KAKABHUSUNDI, GANESH, RAM, GARUD, JATAYU

- **State-machine handshake scan (`-G`)**
  - Completes a real 4-way TCP handshake with graceful teardown
  - Runs inside an isolated network namespace

- **Host discovery**
  - `-sn` for ICMP
  - `-sn6` for ICMPv6
  - Optional `-Pn` to skip discovery

- **IPv4 / IPv6 traceroute**
  - `--traceroute`, add `-6` for IPv6

- **Passive discovery (`--netradar`)**
  - Observe existing traffic on the wire: SYN, ACK, FIN, QUIC, DNS
  - Sends no packets of its own

</details>

<details open>
<summary><strong>Fingerprinting & Enumeration</strong></summary>

<br>

- **Service/version detection (`-sV`)**
  - Dual-stage pipeline
  - Stage 1: Nmap-style probe DB for probe selection and matching
  - Stage 2: Dynamic response-body signature layer (titles, asset paths, platform/CDN fingerprints)

- **UDP service probing**
  - Enabled via `-sV --udp`

- **TLS / HTTP fingerprinting**
  - Certificate extraction: SANs, issuer, validity
  - HTTP title and asset fingerprinting
  - Optional mTLS

- **OS fingerprinting (`--os-detect`)**
  - Passive, from replies received

- **Enumeration modules (`--enum`)**
  - `shodan`
  - `ssl`
  - `dns`
  - `trail:<api-key>` (SecurityTrails)
  - Comma-separated, any order

- **Discovery module**
  - ASN/org lookup: `--cn`, `--org`
  - Country IP-range fetch: `--country`, `--owner`, `--ipv4`/`--ipv6`
  - Reverse IP/ASN to domains: `--ip`, `--range`, `--asn`

</details>

<details open>
<summary><strong>Performance & I/O</strong></summary>

<br>

- **`io_uring`-based async I/O**
  - Per-thread rings

- **SQPOLL mode**
  - Kernel-thread submission
  - Auto-enabled by probe volume (adaptive pacing)
  - Auto-enabled by estimated duration (fixed pacing)
  - Force with `--sqpoll`

- **Congestion-aware batching**
  - Adaptive rate/delay tuning
  - Flags: `--cong-curve`, `--cong-alpha-*`, `--rate-dyn-*`, `--batch-delay-dyn-*`

- **EWMA RTT estimation**
  - Retry logic
  - Flags: `--set-rtt`, `--rto-mult`, `--rto-pad1/2`

</details>

<details open>
<summary><strong>Networking & Isolation</strong></summary>

<br>

- **Network namespace isolation**
  - Flags: `--split`, `--split-ip`, `--split-gw`, `--split-ip6`, `--split-gw6`, `--split-mac`, `--split-iface`
  - Backed by macvlan

- **MAC spoofing and ARP-based on-link resolution**
  - `--src-mac` for spoofing
  - `--dst-mac` to skip ARP

- **TCP option crafting**
  - MSS, window scale, SACK, timestamps, NOPs
  - MPTCP, TCP-AO, TFO cookie injection
  - Custom sequence numbers

- **IP-layer control**
  - TTL, DSCP/TOS
  - IP ID generation modes
  - Fragmentation: `-f`, `--frag ofo|zof|lap`
  - Router Alert, IPSO

- **IPv6 extension headers**
  - Hop-by-Hop, Destination, Routing
  - AH, ESP, Flow Label
  - Extension-header chain manipulation
  - Early chain termination

- **Checksum manipulation**
  - Invalid checksums: `--badsum`
  - Partial invalid checksum patterns: `--prsum`

- **Ethernet / VLAN**
  - Single and double 802.1Q (QinQ) tagging
  - Custom EtherType
  - Multicast destination MAC
  - Padding

</details>

<details open>
<summary><strong>Robustness</strong></summary>

<br>

- **Signal handling**
  - SIGINT handling with safe shutdown

- **Resource safety**
  - RAII-based resource management

- **Output**
  - Structured output
  - Per-host packet-sent counters

- **Drop detection**
  - Three checkpoints
  - Buffer-pool exhaustion
  - SQ backpressure
  - `sendmsg()` rejection

- **Target export**
  - `--grep` for a plain, copy-friendly target list

</details>

<details open>
<summary><strong>Server Mode</strong></summary>

<br>

- **`--server`**
  - Start Trinetra as a LAN control panel
  - Accessible over HTTPS
  - TLS handled automatically via `stunnel`
  - Configurable port: `--server-port`, default 8443
  - Configurable auth token: `--server-token`

</details>

<details open>
<summary><strong>DNS</strong></summary>

<br>

- **Custom DNS servers**
  - IPv4/IPv6 via `--dns-servers`

- **DNS-over-TLS**
  - Via `--dns-servers-tls`
  - Port 853, certificate-verified

- **Reverse DNS**
  - PTR lookups

- **DNS enumeration**
  - Full enumeration via `--enum dns`

</details>
