#include "dns_enum.hpp"
#include "handler.hpp"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdio>
#include <random>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <regex>
#include <iostream>
#include <thread>
#include <iomanip>
#include <map>
#include <netdb.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace color {
    const std::string reset   = "\033[0m";
    const std::string bold    = "\033[1m";
    const std::string green   = "\033[32m";
    const std::string blue    = "\033[94m";
    const std::string yellow  = "\033[93m";
    const std::string white   = "\033[97m";
    const std::string red     = "\033[91m";
    const std::string dim     = "\033[2m";
    const std::string cyan    = "\033[36m";
    const std::string bright_cyan = "\033[96m";
    const std::string magenta = "\033[35m";
}

namespace {

#pragma pack(push, 1)
struct DnsHdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

void encode_name(const std::string& host, std::vector<uint8_t>& out) {
    size_t start = 0;
    std::string h = host;
    if (!h.empty() && h.back() == '.') h.pop_back();
    while (start < h.size()) {
        size_t dot = h.find('.', start);
        size_t len = (dot == std::string::npos) ? h.size() - start : dot - start;
        if (len > 63) len = 63;
        out.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i) out.push_back(static_cast<uint8_t>(h[start + i]));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    out.push_back(0);
}

std::vector<uint8_t> build_query(uint16_t txn_id, const std::string& host, DnsRRType qtype,
                                  bool edns0 = true) {
    std::vector<uint8_t> pkt;
    pkt.reserve(host.size() + 43);
    DnsHdr hdr{};
    hdr.id = htons(txn_id);
    hdr.flags = htons(0x0100); // recursion desired; AXFR caller clears this
    hdr.qdcount = htons(1);
    hdr.arcount = htons(edns0 ? 1 : 0);
    const auto* hp = reinterpret_cast<const uint8_t*>(&hdr);
    pkt.insert(pkt.end(), hp, hp + sizeof(hdr));
    encode_name(host, pkt);
    uint16_t qt = htons(static_cast<uint16_t>(qtype));
    uint16_t qc = htons(1);
    const auto* qtp = reinterpret_cast<const uint8_t*>(&qt);
    const auto* qcp = reinterpret_cast<const uint8_t*>(&qc);
    pkt.insert(pkt.end(), qtp, qtp + 2);
    pkt.insert(pkt.end(), qcp, qcp + 2);

    if (edns0) {
        pkt.push_back(0x00);
        uint16_t opt_type = htons(41);
        uint16_t udp_size = htons(4096);
        const auto* otp = reinterpret_cast<const uint8_t*>(&opt_type);
        const auto* usp = reinterpret_cast<const uint8_t*>(&udp_size);
        pkt.insert(pkt.end(), otp, otp + 2);
        pkt.insert(pkt.end(), usp, usp + 2);
        uint8_t ttl4[4] = {0, 0, 0, 0};
        pkt.insert(pkt.end(), ttl4, ttl4 + 4);
        uint16_t rdlen = 0;
        const auto* rdp = reinterpret_cast<const uint8_t*>(&rdlen);
        pkt.insert(pkt.end(), rdp, rdp + 2);
    }
    return pkt;
}

size_t skip_name(const uint8_t* buf, size_t len, size_t pos) {
    while (pos < len) {
        uint8_t b = buf[pos];
        if (b == 0) return pos + 1;
        if ((b & 0xC0) == 0xC0) return pos + 2;
        pos += 1 + b;
    }
    return pos;
}

size_t decode_name(const uint8_t* buf, size_t len, size_t pos, std::string& out) {
    out.clear();
    size_t original_pos = pos;
    bool jumped = false;
    size_t hops = 0;
    while (pos < len) {
        uint8_t b = buf[pos];
        if (b == 0) { pos += 1; break; }
        if ((b & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return original_pos;
            size_t target = (static_cast<size_t>(b & 0x3F) << 8) | buf[pos + 1];
            if (!jumped) { original_pos = pos + 2; jumped = true; }
            pos = target;
            if (++hops > 128) return original_pos;
            continue;
        }
        size_t label_len = b;
        pos += 1;
        if (pos + label_len > len) return original_pos;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(buf + pos), label_len);
        pos += label_len;
    }
    return jumped ? original_pos : pos;
}

std::string to_hex(const uint8_t* p, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(digits[(p[i] >> 4) & 0xF]);
        out.push_back(digits[p[i] & 0xF]);
    }
    return out;
}

std::string render_rdata(const uint8_t* buf, size_t len, size_t rpos, uint16_t rtype, uint16_t rdlen) {
    switch (rtype) {
        case 1: { // A
            if (rdlen != 4) return "";
            char out[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, buf + rpos, out, sizeof(out));
            return out;
        }
        case 28: { // AAAA
            if (rdlen != 16) return "";
            char out[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, buf + rpos, out, sizeof(out));
            return out;
        }
        case 2: case 5: case 12: { // NS, CNAME, PTR
            std::string name;
            decode_name(buf, len, rpos, name);
            return name;
        }
        case 15: { // MX: preference(2) + exchange name
            if (rdlen < 3) return "";
            uint16_t pref; memcpy(&pref, buf + rpos, 2); pref = ntohs(pref);
            std::string name;
            decode_name(buf, len, rpos + 2, name);
            return std::to_string(pref) + " " + name;
        }
        case 16: { // TXT: one or more length-prefixed strings, concatenated
            std::string out;
            size_t p = rpos, end = rpos + rdlen;
            while (p < end && p < len) {
                uint8_t slen = buf[p++];
                if (p + slen > len) break;
                out.append(reinterpret_cast<const char*>(buf + p), slen);
                p += slen;
            }
            return out;
        }
        case 6: { // SOA: mname, rname, serial, refresh, retry, expire, minimum
            std::string mname, rname;
            size_t p = decode_name(buf, len, rpos, mname);
            p = decode_name(buf, len, p, rname);
            if (p + 20 > len) return mname + " " + rname;
            uint32_t serial, refresh, retry, expire, minimum;
            memcpy(&serial, buf + p, 4);  serial  = ntohl(serial);  p += 4;
            memcpy(&refresh, buf + p, 4); refresh = ntohl(refresh); p += 4;
            memcpy(&retry, buf + p, 4);   retry   = ntohl(retry);   p += 4;
            memcpy(&expire, buf + p, 4);  expire  = ntohl(expire);  p += 4;
            memcpy(&minimum, buf + p, 4); minimum = ntohl(minimum);
            std::ostringstream ss;
            ss << mname << " " << rname << " " << serial << " " << refresh
               << " " << retry << " " << expire << " " << minimum;
            return ss.str();
        }
        case 33: { // SRV: priority(2) weight(2) port(2) target
            if (rdlen < 7) return "";
            uint16_t prio, weight, port;
            memcpy(&prio, buf + rpos, 2);   prio = ntohs(prio);
            memcpy(&weight, buf + rpos + 2, 2); weight = ntohs(weight);
            memcpy(&port, buf + rpos + 4, 2);   port = ntohs(port);
            std::string target;
            decode_name(buf, len, rpos + 6, target);
            std::ostringstream ss;
            ss << prio << " " << weight << " " << port << " " << target;
            return ss.str();
        }
        case 257: { // CAA: flags(1) tag_len(1) tag value
            if (rdlen < 2) return "";
            uint8_t flags = buf[rpos];
            uint8_t tag_len = buf[rpos + 1];
            if (2u + tag_len > rdlen) return "";
            std::string tag(reinterpret_cast<const char*>(buf + rpos + 2), tag_len);
            size_t val_off = rpos + 2 + tag_len;
            size_t val_len = rdlen - 2 - tag_len;
            std::string value(reinterpret_cast<const char*>(buf + val_off), val_len);
            std::ostringstream ss;
            ss << (int)flags << " " << tag << " \"" << value << "\"";
            return ss.str();
        }
        case 52: { // TLSA: cert_usage(1) selector(1) matching_type(1) data
            if (rdlen < 3) return "";
            uint8_t usage = buf[rpos], sel = buf[rpos + 1], mtype = buf[rpos + 2];
            std::string data_hex = to_hex(buf + rpos + 3, rdlen - 3);
            std::ostringstream ss;
            ss << (int)usage << " " << (int)sel << " " << (int)mtype << " " << data_hex;
            return ss.str();
        }
        case 47: { // NSEC: next-domain-name + type bitmap (bitmap shown as raw size only)
            std::string next;
            size_t p = decode_name(buf, len, rpos, next);
            size_t bitmap_len = (p < rpos + rdlen) ? (rpos + rdlen - p) : 0;
            return next + "  <bitmap " + std::to_string(bitmap_len) + "B>";
        }
        case 48: // DNSKEY
            return "<dnskey present, " + std::to_string(rdlen) + "B>";
        case 43: // DS
            return "<ds present, " + std::to_string(rdlen) + "B>";
        case 46: // RRSIG
            return "<rrsig present>";
        default:
            return "<type " + std::to_string(rtype) + ", " + std::to_string(rdlen) + "B>";
    }
}

void parse_message(const uint8_t* buf, size_t len, std::vector<DnsRecord>& out,
                    const std::string& source_tag, bool include_authority = false) {
    if (len < sizeof(DnsHdr)) return;
    DnsHdr hdr{};
    memcpy(&hdr, buf, sizeof(hdr));
    uint16_t qd = ntohs(hdr.qdcount);
    uint16_t an = ntohs(hdr.ancount);
    uint16_t ns = ntohs(hdr.nscount);

    size_t pos = sizeof(DnsHdr);
    for (uint16_t i = 0; i < qd; ++i) {
        pos = skip_name(buf, len, pos);
        pos += 4;
        if (pos > len) return;
    }

    uint16_t total = an + (include_authority ? ns : 0);
    uint16_t seen_an = 0;
    for (uint16_t i = 0; i < an + ns; ++i) {
        if (i >= an && !include_authority) break;
        std::string owner;
        pos = decode_name(buf, len, pos, owner);
        if (pos + 10 > len) return;
        uint16_t rtype, rclass, rdlen;
        uint32_t ttl;
        memcpy(&rtype, buf + pos, 2);  rtype = ntohs(rtype);  pos += 2;
        memcpy(&rclass, buf + pos, 2); rclass = ntohs(rclass); pos += 2;
        memcpy(&ttl, buf + pos, 4);    ttl = ntohl(ttl);       pos += 4;
        memcpy(&rdlen, buf + pos, 2);  rdlen = ntohs(rdlen);   pos += 2;
        if (pos + rdlen > len) return;

        if (rclass == 1) {
            DnsRecord rec;
            rec.type = static_cast<DnsRRType>(rtype);
            rec.name = owner;
            rec.ttl = ttl;
            rec.value = render_rdata(buf, len, pos, rtype, rdlen);
            rec.source = source_tag;
            out.push_back(std::move(rec));
        }
        pos += rdlen;
        if (i < an) ++seen_an;
    }
    (void)total; (void)seen_an;
}

int make_udp_socket(int family) {
    int fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    return fd;
}

bool send_to_server(int fd, int family, const std::string& server,
                     const std::vector<uint8_t>& pkt, uint16_t port = 53) {
    sockaddr_storage ss{};
    socklen_t slen;
    if (family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family = AF_INET;
        a->sin_port = htons(port);
        if (inet_pton(AF_INET, server.c_str(), &a->sin_addr) != 1) return false;
        slen = sizeof(*a);
    } else {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        if (inet_pton(AF_INET6, server.c_str(), &a->sin6_addr) != 1) return false;
        slen = sizeof(*a);
    }
    return sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&ss), slen) >= 0;
}

int family_of(const std::string& ip) {
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, ip.c_str(), &a4) == 1) return AF_INET;
    if (inet_pton(AF_INET6, ip.c_str(), &a6) == 1) return AF_INET6;
    return -1;
}

// System resolvers, read once, used when the user hasn't set
// --dns-servers/--dns-servers-tls.
std::vector<std::string> system_resolvers() {
    std::vector<std::string> out;
    std::ifstream f("/etc/resolv.conf");
    std::string line;
    while (f && std::getline(f, line)) {
        if (line.rfind("nameserver", 0) == 0) {
            std::istringstream ss(line);
            std::string tok, ip;
            ss >> tok >> ip;
            if (!ip.empty()) out.push_back(ip);
        }
    }
    if (out.empty()) { out.push_back("1.1.1.1"); out.push_back("8.8.8.8"); }
    return out;
}

std::vector<std::string> active_server_list() {
    if (!g_dns_servers.empty()) return g_dns_servers;
    return system_resolvers();
}

} 

bool dns_query_generic(const std::string& qname, DnsRRType qtype,
                        const std::vector<std::string>& servers,
                        int timeout_ms, int retries,
                        std::vector<DnsRecord>& out_records,
                        std::string* used_server) {
    if (servers.empty()) return false;
    std::mt19937 rng(std::random_device{}());

    for (int attempt = 0; attempt <= retries; ++attempt) {
        for (const auto& srv : servers) {
            int fam = family_of(srv);
            if (fam < 0) continue;
            int fd = make_udp_socket(fam);
            if (fd < 0) continue;

            uint16_t txn = static_cast<uint16_t>(rng());
            auto pkt = build_query(txn, qname, qtype, /*edns0=*/true);
            if (!send_to_server(fd, fam, srv, pkt)) { close(fd); continue; }

            pollfd pfd{fd, POLLIN, 0};
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr <= 0) { close(fd); continue; }

            uint8_t buf[4096];
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            close(fd);
            if (n < static_cast<ssize_t>(sizeof(DnsHdr))) continue;

            DnsHdr hdr{};
            memcpy(&hdr, buf, sizeof(hdr));
            if (ntohs(hdr.id) != txn) continue; // stray/spoofed reply
            bool truncated = (ntohs(hdr.flags) & 0x0200) != 0;

            std::vector<DnsRecord> recs;
            parse_message(buf, static_cast<size_t>(n), recs, "active:" + srv);

            if (truncated) {
                // Retry same query over TCP for the full answer.
                int tfd = socket(fam, SOCK_STREAM, 0);
                if (tfd >= 0) {
                    sockaddr_storage ss{}; socklen_t slen;
                    if (fam == AF_INET) {
                        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
                        a->sin_family = AF_INET; a->sin_port = htons(53);
                        inet_pton(AF_INET, srv.c_str(), &a->sin_addr);
                        slen = sizeof(*a);
                    } else {
                        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
                        a->sin6_family = AF_INET6; a->sin6_port = htons(53);
                        inet_pton(AF_INET6, srv.c_str(), &a->sin6_addr);
                        slen = sizeof(*a);
                    }
                    if (connect(tfd, reinterpret_cast<sockaddr*>(&ss), slen) == 0) {
                        uint16_t plen = htons(static_cast<uint16_t>(pkt.size()));
                        std::vector<uint8_t> framed;
                        framed.insert(framed.end(), reinterpret_cast<uint8_t*>(&plen),
                                      reinterpret_cast<uint8_t*>(&plen) + 2);
                        framed.insert(framed.end(), pkt.begin(), pkt.end());
                        if (send(tfd, framed.data(), framed.size(), 0) > 0) {
                            uint8_t lenbuf[2];
                            if (recv(tfd, lenbuf, 2, MSG_WAITALL) == 2) {
                                uint16_t rlen = (lenbuf[0] << 8) | lenbuf[1];
                                std::vector<uint8_t> rbuf(rlen);
                                if (recv(tfd, rbuf.data(), rlen, MSG_WAITALL) == rlen) {
                                    recs.clear();
                                    parse_message(rbuf.data(), rbuf.size(), recs, "active-tcp:" + srv);
                                }
                            }
                        }
                    }
                    close(tfd);
                }
            }

            if (!recs.empty() || (ntohs(hdr.flags) & 0x000F) == 3 /* NXDOMAIN, definitive */) {
                out_records = std::move(recs);
                if (used_server) *used_server = srv;
                return true;
            }
        }
    }
    return false;
}

std::vector<AsyncDnsResult> dns_query_batch(const std::vector<AsyncDnsJob>& jobs,
                                             const std::vector<std::string>& servers,
                                             int timeout_ms, int concurrency,
                                             bool use_edns0) {
    std::vector<AsyncDnsResult> out;
    if (servers.empty() || jobs.empty()) return out;
    out.reserve(jobs.size());

    struct InFlight {
        int fd;
        int family;
        size_t job_idx;
        uint16_t txn;
        std::string server;
        std::vector<uint8_t> raw_query; // kept for a TCP retry on truncation
    };
    std::unordered_map<int, std::vector<int>> free_sockets; // family -> fds
    int total_open = 0;
    auto acquire_socket = [&](int fam) -> int {
        auto it = free_sockets.find(fam);
        if (it != free_sockets.end() && !it->second.empty()) {
            int fd = it->second.back();
            it->second.pop_back();
            return fd;
        }
        if (total_open >= concurrency) return -1;
        int fd = make_udp_socket(fam);
        if (fd >= 0) ++total_open;
        return fd;
    };
    auto release_socket = [&](int fam, int fd) {
        free_sockets[fam].push_back(fd);
    };

    size_t next_job = 0;
    std::vector<InFlight> inflight;
    inflight.reserve(concurrency);
    std::mt19937 rng(std::random_device{}());
    size_t server_rr = 0;
    std::vector<bool> answered(jobs.size(), false);
    out.resize(jobs.size());
    for (size_t i = 0; i < jobs.size(); ++i) {
        out[i].tag = jobs[i].tag;
        out[i].qname = jobs[i].qname;
        out[i].qtype = jobs[i].qtype;
    }

    auto launch_one = [&]() -> bool {
        while (next_job < jobs.size()) {
            size_t idx = next_job++;
            const auto& job = jobs[idx];
            const auto& srv = servers[server_rr++ % servers.size()];
            int fam = family_of(srv);
            if (fam < 0) continue; // skip, but keep pumping
            int fd = acquire_socket(fam);
            if (fd < 0) { --next_job; return false; } // pool exhausted; try later
            uint16_t txn = static_cast<uint16_t>(rng());
            auto pkt = build_query(txn, job.qname, job.qtype, use_edns0);
            if (!send_to_server(fd, fam, srv, pkt)) { release_socket(fam, fd); continue; }
            inflight.push_back({fd, fam, idx, txn, srv, std::move(pkt)});
            return true;
        }
        return false;
    };

    while (static_cast<int>(inflight.size()) < concurrency && launch_one()) {}

    auto batch_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);

    while (!inflight.empty()) {
        std::vector<pollfd> pfds;
        pfds.reserve(inflight.size());
        for (auto& f : inflight) pfds.push_back({f.fd, POLLIN, 0});

        int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            batch_deadline - std::chrono::steady_clock::now()).count());
        if (remaining < 0) remaining = 0;
        int pr = poll(pfds.data(), pfds.size(), std::min(remaining, 250));

        std::vector<size_t> done; // indices into inflight
        std::vector<size_t> needs_tcp; // indices into inflight that were truncated

        if (pr > 0) {
            for (size_t i = 0; i < pfds.size(); ++i) {
                if (!(pfds[i].revents & POLLIN)) continue;
                uint8_t buf[4096];
                ssize_t n = recv(inflight[i].fd, buf, sizeof(buf), 0);
                if (n >= static_cast<ssize_t>(sizeof(DnsHdr))) {
                    DnsHdr hdr{};
                    memcpy(&hdr, buf, sizeof(hdr));
                    if (ntohs(hdr.id) == inflight[i].txn) {
                        bool truncated = (ntohs(hdr.flags) & 0x0200) != 0;
                        size_t idx = inflight[i].job_idx;
                        std::vector<DnsRecord> recs;
                        parse_message(buf, static_cast<size_t>(n), recs,
                                      "active:" + inflight[i].server);
                        bool nxdomain = (ntohs(hdr.flags) & 0x000F) == 3;
                        if (truncated && !recs.empty()) {
                            // still useful, but flag for a TCP top-up
                            needs_tcp.push_back(i);
                        }
                        if (!recs.empty() || nxdomain) {
                            out[idx].records = std::move(recs);
                            out[idx].answered = true;
                            answered[idx] = true;
                        }
                    }
                }
                done.push_back(i);
            }
        }
        for (size_t i : needs_tcp) {
            auto& f = inflight[i];
            int tfd = socket(f.family, SOCK_STREAM, 0);
            if (tfd < 0) continue;
            sockaddr_storage ss{}; socklen_t slen;
            if (f.family == AF_INET) {
                auto* a = reinterpret_cast<sockaddr_in*>(&ss);
                a->sin_family = AF_INET; a->sin_port = htons(53);
                inet_pton(AF_INET, f.server.c_str(), &a->sin_addr);
                slen = sizeof(*a);
            } else {
                auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
                a->sin6_family = AF_INET6; a->sin6_port = htons(53);
                inet_pton(AF_INET6, f.server.c_str(), &a->sin6_addr);
                slen = sizeof(*a);
            }
            if (connect(tfd, reinterpret_cast<sockaddr*>(&ss), slen) == 0) {
                uint16_t plen = htons(static_cast<uint16_t>(f.raw_query.size()));
                std::vector<uint8_t> framed;
                framed.insert(framed.end(), reinterpret_cast<uint8_t*>(&plen),
                              reinterpret_cast<uint8_t*>(&plen) + 2);
                framed.insert(framed.end(), f.raw_query.begin(), f.raw_query.end());
                if (send(tfd, framed.data(), framed.size(), 0) > 0) {
                    uint8_t lenbuf[2];
                    if (recv(tfd, lenbuf, 2, MSG_WAITALL) == 2) {
                        uint16_t rlen = (lenbuf[0] << 8) | lenbuf[1];
                        std::vector<uint8_t> rbuf(rlen);
                        if (recv(tfd, rbuf.data(), rlen, MSG_WAITALL) == rlen) {
                            std::vector<DnsRecord> recs;
                            parse_message(rbuf.data(), rbuf.size(), recs, "active-tcp:" + f.server);
                            if (!recs.empty()) out[f.job_idx].records = std::move(recs);
                        }
                    }
                }
            }
            close(tfd);
        }

        if (std::chrono::steady_clock::now() >= batch_deadline) {
            // Drop anything still outstanding for this pass; best-effort,
            // not a guarantee every job gets a full retry.
            for (size_t i = 0; i < inflight.size(); ++i) done.push_back(i);
            std::sort(done.begin(), done.end());
            done.erase(std::unique(done.begin(), done.end()), done.end());
        }

        std::sort(done.rbegin(), done.rend());
        for (size_t idx : done) {
            release_socket(inflight[idx].family, inflight[idx].fd);
            inflight.erase(inflight.begin() + idx);
            launch_one();
        }

        if (pr <= 0 && inflight.size() == pfds.size()) {
            batch_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        }
    }

    for (auto& [fam, fds] : free_sockets) for (int fd : fds) close(fd);
    (void)answered;
    return out;
}

namespace {

ZoneTransferAttempt try_axfr(const std::string& domain, const std::string& ns_host,
                              const std::string& ns_ip, int timeout_ms,
                              std::vector<DnsRecord>& out_records) {
    ZoneTransferAttempt att;
    att.ns_host = ns_host;
    att.ns_ip = ns_ip;

    int fam = family_of(ns_ip);
    if (fam < 0) { att.error = "unresolvable NS"; return att; }

    int fd = socket(fam, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) { att.error = "socket() failed"; return att; }

    sockaddr_storage ss{}; socklen_t slen;
    if (fam == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&ss);
        a->sin_family = AF_INET; a->sin_port = htons(53);
        inet_pton(AF_INET, ns_ip.c_str(), &a->sin_addr);
        slen = sizeof(*a);
    } else {
        auto* a = reinterpret_cast<sockaddr_in6*>(&ss);
        a->sin6_family = AF_INET6; a->sin6_port = htons(53);
        inet_pton(AF_INET6, ns_ip.c_str(), &a->sin6_addr);
        slen = sizeof(*a);
    }

    int rc = connect(fd, reinterpret_cast<sockaddr*>(&ss), slen);
    if (rc < 0 && errno != EINPROGRESS) { close(fd); att.error = "connect failed"; return att; }
    pollfd wfd{fd, POLLOUT, 0};
    if (poll(&wfd, 1, timeout_ms) <= 0) { close(fd); att.error = "connect timeout"; return att; }
    int soerr = 0; socklen_t soerrlen = sizeof(soerr);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &soerrlen);
    if (soerr != 0) { close(fd); att.error = "connect refused/error"; return att; }

    uint16_t txn = static_cast<uint16_t>(std::random_device{}());
    auto pkt = build_query(txn, domain, DnsRRType::AXFR, /*edns0=*/false);
    uint16_t plen = htons(static_cast<uint16_t>(pkt.size()));
    std::vector<uint8_t> framed;
    framed.insert(framed.end(), reinterpret_cast<uint8_t*>(&plen), reinterpret_cast<uint8_t*>(&plen) + 2);
    framed.insert(framed.end(), pkt.begin(), pkt.end());
    if (send(fd, framed.data(), framed.size(), 0) < 0) { close(fd); att.error = "send failed"; return att; }

    size_t soa_seen = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms * 3);
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd pfd{fd, POLLIN, 0};
        int remaining_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count());
        if (remaining_ms <= 0) break;
        int pr = poll(&pfd, 1, remaining_ms);
        if (pr <= 0) break;

        uint8_t lenbuf[2];
        ssize_t got = recv(fd, lenbuf, 2, MSG_WAITALL);
        if (got != 2) break;
        uint16_t rlen = (lenbuf[0] << 8) | lenbuf[1];
        if (rlen == 0) break;
        std::vector<uint8_t> rbuf(rlen);
        if (recv(fd, rbuf.data(), rlen, MSG_WAITALL) != rlen) break;

        std::vector<DnsRecord> recs;
        parse_message(rbuf.data(), rbuf.size(), recs, "axfr:" + ns_host);
        if (recs.empty()) break; // REFUSED / NOTAUTH etc. -> empty answer section
        for (auto& r : recs) {
            if (r.type == DnsRRType::SOA) ++soa_seen;
            out_records.push_back(r);
        }
        att.succeeded = true;
        if (soa_seen >= 2) break; // AXFR framing: starts and ends with SOA
    }
    close(fd);

    if (att.succeeded) {
        att.records_pulled = out_records.size();
    } else if (att.error.empty()) {
        att.error = "refused or empty zone";
    }
    return att;
}

}

namespace {

const std::vector<std::string>& builtin_subdomain_wordlist() {
    static const std::vector<std::string> list = {
        "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2","ns3","ns4",
        "webdisk","autodiscover","autoconfig","m","imap","test","ns","blog","pop3","dev",
        "www2","admin","forum","news","vpn","ns5","mail2","new","mysql","old","www1",
        "beta","dns","dns1","dns2","staging","shop","sql","secure","demo","cp","calendar",
        "wiki","web","media","email","images","img","static","cdn","api","api-dev","api-staging",
        "app","apps","mobile","gateway","gw","portal","auth","sso","login","id","idp",
        "dashboard","console","status","status-page","monitor","monitoring","grafana","kibana",
        "prometheus","jenkins","ci","git","gitlab","github","svn","repo","docker","registry",
        "k8s","kube","kubernetes","internal","intranet","corp","extranet","partner","partners",
        "vpn1","vpn2","remote","office","proxy","cache","backup","backups","db","db1","db2",
        "redis","elastic","es","search","files","file","upload","uploads","download","downloads",
        "assets","cdn1","cdn2","edge","origin","direct","legacy","archive","docs","support",
        "help","kb","tickets","chat","irc","voip","sip","meet","zoom","stream","video","tv",
        "ns0","mx","mx1","mx2","smtp1","smtp2","relay","alerts","exchange","owa","lync","skype",
        "sharepoint","confluence","jira","bugzilla","wordpress","cms","preprod","pre-prod",
        "sandbox","uat","qa","test1","test2","dev1","dev2","local","lab","labs","research",
    };
    return list;
}

std::vector<std::string> mutate_label(const std::string& label) {
    static const std::vector<std::string> env_prefixes = {"dev-", "stage-", "staging-", "uat-", "qa-", "test-", "int-"};
    static const std::vector<std::string> env_suffixes = {"-dev", "-stage", "-staging", "-uat", "-qa", "-test", "-int", "-old", "-new", "-bak"};
    std::vector<std::string> out;
    for (auto& p : env_prefixes) out.push_back(p + label);
    for (auto& s : env_suffixes) out.push_back(label + s);
    for (int i = 1; i <= 3; ++i) out.push_back(label + std::to_string(i));
    return out;
}

} 

namespace {


const std::vector<std::string>& builtin_dkim_selectors() {
    static const std::vector<std::string> list = {
        // generic / self-hosted
        "default","dkim","mail","smtp","s1","s2","s3","s4",
        "k1","k2","key1","key2","dkim1","dkim2","dkim01","dkim02","google","googleapps",
        // Microsoft 365 / Exchange Online (default autoprovisioned names)
        "selector1","selector2",
        // Google Workspace
        "google2","google3",
        // Mailchimp / Mandrill
        "k1","mandrill","mte1","mte2",
        // SendGrid
        "sendgrid","s1sendgrid","s2sendgrid","em1","em2","em3","em4","em5","em6","em7","em8","em9","em10",
        // Amazon SES
        "amazonses",
        // Mailgun
        "mg","mailo","k1mailgun","krs",
        // Mailjet
        "mailjet","mailjet1","mailjet2",
        // Zoho Mail
        "zoho","zmail",
        // Postmark
        "pm","20161025",
        // ProtonMail
        "protonmail","protonmail2","protonmail3",
        // Fastmail
        "fm1","fm2","fm3",
        // Everlytic
        "everlytickey1","everlytickey2",
        // HubSpot
        "hs1","hs2",
        // Klaviyo
        "dkim-klaviyo","kl","kl2","kl3",
        // SparkPost
        "scph0220","scph0119","scph0221",
        // Salesforce / Marketing Cloud (ExactTarget)
        "salesforce","et","exacttarget",
        // Marketo
        "mkto","m1",
        // Mimecast
        "mimecast","mimecast1","mimecast2",
        // Constant Contact / iContact / AWeber / ActiveCampaign / GetResponse
        "cm","icontact","aweber","activecampaign","getresponse",
        // Zendesk / Freshdesk / Intercom (support-tool mail)
        "zendesk1","zendesk2","freshdesk","intercom",
        // Litmus / campaign QA tooling
        "litmus","cctld",
        // Braze / Iterable / Customer.io
        "braze","iterable","customerio",
    };
    return list;
}

const std::vector<std::string>& builtin_srv_services() {
    static const std::vector<std::string> list = {
        // Active Directory / Kerberos
        "_ldap._tcp", "_ldap._tcp.dc._msdcs", "_kerberos._tcp", "_kerberos._udp",
        "_kerberos-master._tcp", "_kpasswd._tcp", "_kpasswd._udp", "_gc._tcp", "_autodiscover._tcp",
        // Mail submission / retrieval (beyond MX)
        "_submission._tcp", "_submissions._tcp", "_imap._tcp", "_imaps._tcp",
        "_pop3._tcp", "_pop3s._tcp", "_smtps._tcp",
        // Realtime comms / VoIP / chat
        "_sip._tcp", "_sip._udp", "_sips._tcp", "_stun._udp", "_stuns._tcp",
        "_turn._udp", "_turns._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
        "_jabber._tcp", "_matrix._tcp", "_matrix-fed._tcp",
        // Calendar / contacts
        "_caldav._tcp", "_caldavs._tcp", "_carddav._tcp", "_carddavs._tcp",
        // File / remote access
        "_ftp._tcp", "_ftps._tcp", "_nfs._tcp", "_rsync._tcp", "_smb._tcp", "_afpovertcp._tcp",
        // Service discovery / config management / cluster coordination
        "_consul._tcp", "_etcd-client._tcp", "_etcd-server._tcp", "_puppet._tcp",
        "_mongodb._tcp", "_elasticsearch._tcp", "_couchdb._tcp",
        // Misc self-hosted
        "_minecraft._tcp", "_teamspeak._udp", "_wss._tcp",
    };
    return list;
}

std::string first_txt(const std::vector<DnsRecord>& recs) {
    for (const auto& r : recs) if (r.type == DnsRRType::TXT) return r.value;
    return "";
}

} 


bool http_get(const std::string& url, std::string& out, long timeout_ms, long* http_code);

namespace {


std::vector<AsyncDnsResult> batch_with_retry(const std::vector<AsyncDnsJob>& jobs,
                                              const std::vector<std::string>& servers,
                                              int timeout_ms, int retries, int concurrency,
                                              bool use_edns0) {
    auto results = dns_query_batch(jobs, servers, timeout_ms, concurrency, use_edns0);
    for (int attempt = 0; attempt < retries; ++attempt) {
        std::vector<AsyncDnsJob> leftover;
        std::vector<size_t> leftover_idx;
        for (size_t i = 0; i < results.size(); ++i) {
            if (!results[i].answered) {
                leftover.push_back(jobs[i]);
                leftover_idx.push_back(i);
            }
        }
        if (leftover.empty()) break;
        auto retry_results = dns_query_batch(leftover, servers, timeout_ms, concurrency, use_edns0);
        for (size_t i = 0; i < retry_results.size(); ++i)
            if (retry_results[i].answered) results[leftover_idx[i]] = std::move(retry_results[i]);
    }
    return results;
}

void collect_email_security_batched(const std::string& domain, const std::vector<std::string>& servers,
                                     int timeout_ms, int retries, int concurrency,
                                     const std::vector<std::string>& extra_selectors,
                                     bool use_edns0, EmailSecurityPosture& out) {
    std::vector<AsyncDnsJob> jobs = {
        {domain, DnsRRType::TXT, "spf"},
        {"_dmarc." + domain, DnsRRType::TXT, "dmarc"},
        {"default._bimi." + domain, DnsRRType::TXT, "bimi"},
        {"_mta-sts." + domain, DnsRRType::TXT, "mtasts"},
        {"_smtp._tls." + domain, DnsRRType::TXT, "tlsrpt"},
        {domain, DnsRRType::MX, "mx"},
    };
    std::vector<std::string> selectors = builtin_dkim_selectors();
    selectors.insert(selectors.end(), extra_selectors.begin(), extra_selectors.end());
    for (auto& sel : selectors) jobs.push_back({sel + "._domainkey." + domain, DnsRRType::TXT, "dkim:" + sel});

    auto results = batch_with_retry(jobs, servers, timeout_ms, retries, concurrency, use_edns0);
    for (auto& r : results) {
        if (!r.answered) continue;
        if (r.tag == "spf") {
            for (auto& rec : r.records)
                if (rec.type == DnsRRType::TXT && rec.value.rfind("v=spf1", 0) == 0) {
                    out.has_spf = true; out.spf_record = rec.value; break;
                }
        } else if (r.tag == "dmarc") {
            std::string v = first_txt(r.records);
            if (!v.empty()) { out.has_dmarc = true; out.dmarc_record = v; }
        } else if (r.tag == "bimi") {
            std::string v = first_txt(r.records);
            if (!v.empty()) { out.has_bimi = true; out.bimi_record = v; }
        } else if (r.tag == "mtasts") {
            std::string v = first_txt(r.records);
            if (!v.empty()) { out.has_mta_sts_dns = true; out.mta_sts_dns_record = v; }
        } else if (r.tag == "tlsrpt") {
            std::string v = first_txt(r.records);
            if (!v.empty()) { out.has_tls_rpt = true; out.tls_rpt_record = v; }
        } else if (r.tag == "mx") {
            for (auto& rec : r.records) if (rec.type == DnsRRType::MX) out.mx_hosts.push_back(rec.value);
        } else if (r.tag.rfind("dkim:", 0) == 0) {
            std::string v = first_txt(r.records);
            if (!v.empty() && v.find("v=DKIM1") != std::string::npos)
                out.dkim_selectors_found.emplace_back(r.tag.substr(5), v);
        }
    }
}

void collect_dnssec_batched(const std::string& domain, const std::vector<std::string>& servers,
                             int timeout_ms, int retries, int concurrency, bool use_edns0,
                             DnssecPosture& out) {
    std::vector<AsyncDnsJob> jobs = {
        {domain, DnsRRType::DNSKEY, "dnskey"},
        {domain, DnsRRType::RRSIG, "rrsig"},
        {domain, DnsRRType::DS, "ds"},
    };
    auto results = batch_with_retry(jobs, servers, timeout_ms, retries, concurrency, use_edns0);
    for (auto& r : results) {
        if (!r.answered) continue;
        if (r.tag == "dnskey") {
            for (auto& rec : r.records) if (rec.type == DnsRRType::DNSKEY) { out.dnskey_present = true; ++out.dnskey_count; }
        } else if (r.tag == "rrsig") {
            for (auto& rec : r.records) if (rec.type == DnsRRType::RRSIG) { out.rrsig_seen = true; break; }
        } else if (r.tag == "ds") {
            for (auto& rec : r.records) if (rec.type == DnsRRType::DS) { out.ds_present_at_parent = true; break; }
        }
    }
}

void collect_srv_batched(const std::string& domain, const std::vector<std::string>& servers,
                          int timeout_ms, int retries, int concurrency, bool use_edns0,
                          std::vector<SrvFinding>& out) {
    std::vector<AsyncDnsJob> jobs;
    for (auto& svc : builtin_srv_services())
        jobs.push_back({svc + "." + domain, DnsRRType::SRV, svc});
    auto results = batch_with_retry(jobs, servers, timeout_ms, retries, concurrency, use_edns0);
    for (auto& r : results) {
        if (!r.answered) continue;
        for (auto& rec : r.records) {
            if (rec.type != DnsRRType::SRV) continue;
            std::istringstream ss(rec.value);
            SrvFinding f;
            int prio = 0, weight = 0, port = 0;
            if (ss >> prio >> weight >> port >> f.target) {
                f.service = r.tag;
                f.priority = static_cast<uint16_t>(prio);
                f.weight = static_cast<uint16_t>(weight);
                f.port = static_cast<uint16_t>(port);
                out.push_back(std::move(f));
            }
        }
    }
}

void collect_tlsa_batched(const std::string& domain, const std::vector<int>& ports,
                           const std::vector<std::string>& servers,
                           int timeout_ms, int retries, int concurrency, bool use_edns0,
                           std::vector<TlsaFinding>& out) {
    std::vector<AsyncDnsJob> jobs;
    for (int port : ports) {
        std::string svc = "_" + std::to_string(port) + "._tcp";
        jobs.push_back({svc + "." + domain, DnsRRType::TLSA, svc});
    }
    auto results = batch_with_retry(jobs, servers, timeout_ms, retries, concurrency, use_edns0);
    for (auto& r : results) {
        if (!r.answered) continue;
        for (auto& rec : r.records) {
            if (rec.type != DnsRRType::TLSA) continue;
            std::istringstream ss(rec.value);
            TlsaFinding f;
            int usage = 0, sel = 0, mtype = 0;
            if (ss >> usage >> sel >> mtype >> f.data_hex) {
                f.service = r.tag;
                f.cert_usage = static_cast<uint8_t>(usage);
                f.selector = static_cast<uint8_t>(sel);
                f.matching_type = static_cast<uint8_t>(mtype);
                out.push_back(std::move(f));
            }
        }
    }
}


NsecWalkResult run_nsec_walk(const std::string& domain, const std::vector<std::string>& servers,
                              int timeout_ms, int max_steps) {
    NsecWalkResult res;
    res.attempted = true;
    std::string current = domain;
    std::unordered_set<std::string> seen;
    for (int step = 0; step < max_steps; ++step) {
        std::vector<DnsRecord> recs;
        if (!dns_query_generic(current, DnsRRType::NSEC, servers, timeout_ms, 1, recs)) break;
        std::string next_name;
        bool found = false;
        for (auto& r : recs) {
            if (r.type != DnsRRType::NSEC) continue;
            size_t sep = r.value.find("  <bitmap");
            next_name = (sep == std::string::npos) ? r.value : r.value.substr(0, sep);
            found = true;
            break;
        }
        if (!found || next_name.empty()) break;
        res.zone_signed = true;
        if (next_name == domain && step > 0) { res.wrapped = true; break; }
        if (seen.count(next_name)) break; // guard against loops on odd data
        seen.insert(next_name);
        res.names_from_bitmap_gaps.push_back(next_name);
        current = next_name;
    }
    if (!res.zone_signed) res.note = "no NSEC observed — zone may be unsigned or use NSEC3 opt-out";
    else if (!res.wrapped) res.note = "walk stopped before completing a full loop (max_steps or a break in the chain)";
    return res;
}

const std::vector<std::pair<std::string, std::pair<std::string, std::string>>>& takeover_fingerprints() {
    static const std::vector<std::pair<std::string, std::pair<std::string, std::string>>> list = {
        {".s3.amazonaws.com",       {"AWS S3", "NoSuchBucket"}},
        {".s3-website",             {"AWS S3 (website)", "NoSuchBucket"}},
        {".github.io",              {"GitHub Pages", "There isn't a GitHub Pages site here"}},
        {".herokuapp.com",          {"Heroku", "no-such-app"}},
        {".herokudns.com",          {"Heroku", "no-such-app"}},
        {".azurewebsites.net",      {"Azure App Service", "404 Web Site not found"}},
        {".trafficmanager.net",     {"Azure Traffic Manager", "unavailable"}},
        {".cloudapp.net",           {"Azure Cloud Service", "unavailable"}},
        {".netlify.app",            {"Netlify", "Not Found - Request ID"}},
        {".surge.sh",               {"Surge.sh", "project not found"}},
        {".fastly.net",             {"Fastly", "Fastly error: unknown domain"}},
        {".pantheonsite.io",        {"Pantheon", "The gods are wise"}},
        {".zendesk.com",            {"Zendesk", "Help Center Closed"}},
        {".statuspage.io",          {"Statuspage", "You are being"}},
        {".ghost.io",               {"Ghost(Pro)", "The thing you were looking for is no longer here"}},
        {".bitbucket.io",           {"Bitbucket Pages", "Repository not found"}},
        {".unbouncepages.com",      {"Unbounce", "The requested URL was not found"}},
        {".webflow.io",             {"Webflow", "The page you are looking for doesn't exist"}},
        {".wpengine.com",           {"WP Engine", "The site you were looking for couldn't be found"}},
    };
    return list;
}

std::vector<std::string> chase_cname_chain(const std::string& host, const std::vector<std::string>& servers,
                                            int timeout_ms, int max_hops = 8) {
    std::vector<std::string> chain;
    std::string current = host;
    std::unordered_set<std::string> seen;
    for (int i = 0; i < max_hops; ++i) {
        if (seen.count(current)) break;
        seen.insert(current);
        std::vector<DnsRecord> recs;
        if (!dns_query_generic(current, DnsRRType::CNAME, servers, timeout_ms, 1, recs)) break;
        std::string target;
        for (auto& r : recs) if (r.type == DnsRRType::CNAME) { target = r.value; break; }
        if (target.empty()) break;
        chain.push_back(target);
        current = target;
    }
    return chain;
}

void check_takeovers(const std::unordered_map<std::string, DiscoveredHost>& hosts,
                      const std::vector<std::string>& servers, int timeout_ms,
                      std::vector<TakeoverFinding>& out) {
    for (auto& [name, h] : hosts) {
        auto chain = chase_cname_chain(name, servers, timeout_ms);
        if (chain.empty()) continue;
        const std::string& final_target = chain.back();
        std::string lower = final_target;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        for (auto& [suffix, info] : takeover_fingerprints()) {
            if (lower.size() < suffix.size()) continue;
            if (lower.compare(lower.size() - suffix.size(), suffix.size(), suffix) != 0) continue;

            TakeoverFinding f;
            f.hostname = name;
            f.cname_chain = chain;
            f.matched_service = info.first;

            std::string body;
            long code = 0;
            bool got = http_get("https://" + name + "/", body, 4000, &code);
            if (!got) got = http_get("http://" + name + "/", body, 4000, &code);
            if (got && body.find(info.second) != std::string::npos) {
                f.http_confirmed = true;
                f.fingerprint_snippet = info.second;
            }
            out.push_back(std::move(f));
            break;
        }
    }
}

std::string reverse_arpa_v4(const std::string& ip) {
    struct in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return "";
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&a.s_addr);
    std::ostringstream ss;
    ss << (int)b[3] << "." << (int)b[2] << "." << (int)b[1] << "." << (int)b[0] << ".in-addr.arpa";
    return ss.str();
}

std::string reverse_arpa_v6(const std::string& ip) {
    struct in6_addr a{};
    if (inet_pton(AF_INET6, ip.c_str(), &a) != 1) return "";
    std::ostringstream ss;
    for (int i = 15; i >= 0; --i) {
        uint8_t byte = a.s6_addr[i];
        ss << std::hex << (byte & 0xF) << "." << ((byte >> 4) & 0xF) << ".";
    }
    ss << "ip6.arpa";
    return ss.str();
}

void run_ptr_sweep(const std::unordered_set<std::string>& ips, bool sweep_prefix,
                    size_t max_hosts, const std::vector<std::string>& servers,
                    int timeout_ms, int concurrency, bool use_edns0, PtrSweepResult& out) {
    out.attempted = true;
    std::vector<AsyncDnsJob> jobs;
    std::unordered_set<std::string> queried_ips;

    for (auto& ip : ips) {
        std::string arpa = (family_of(ip) == AF_INET) ? reverse_arpa_v4(ip) : reverse_arpa_v6(ip);
        if (arpa.empty() || queried_ips.count(ip)) continue;
        queried_ips.insert(ip);
        jobs.push_back({arpa, DnsRRType::PTR, ip});
    }

    if (sweep_prefix) {
        std::unordered_set<std::string> bases_done;
        for (auto& ip : ips) {
            if (family_of(ip) != AF_INET) continue; // /64 v6 walking isn't feasible to brute force
            size_t last_dot = ip.rfind('.');
            if (last_dot == std::string::npos) continue;
            std::string base = ip.substr(0, last_dot + 1); // "203.0.113."
            if (bases_done.count(base)) continue;
            bases_done.insert(base);
            out.prefix_swept += (out.prefix_swept.empty() ? "" : ", ") + (base + "0/24");
            for (int i = 0; i < 256 && jobs.size() < max_hosts; ++i) {
                std::string cand = base + std::to_string(i);
                if (queried_ips.count(cand)) continue;
                queried_ips.insert(cand);
                jobs.push_back({reverse_arpa_v4(cand), DnsRRType::PTR, cand});
            }
        }
    }

    out.hosts_checked = jobs.size();
    if (jobs.empty()) return;
    auto results = dns_query_batch(jobs, servers, timeout_ms, concurrency, use_edns0);
    for (auto& r : results) {
        if (!r.answered) continue;
        for (auto& rec : r.records) {
            if (rec.type == DnsRRType::PTR && !rec.value.empty()) {
                out.ptrs.emplace_back(r.tag, rec.value);
                break;
            }
        }
    }
}

}

namespace {

size_t curl_write_cb(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t n = size * nmemb;
    if (size != 0 && n / size != nmemb) return 0;
    try { s->append(static_cast<char*>(contents), n); } catch (...) { return 0; }
    return n;
}

} 

bool http_get(const std::string& url, std::string& out, long timeout_ms, long* http_code) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;
    out.clear();
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "shiv-dns-enum/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    CURLcode rc = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(curl);
    if (http_code) *http_code = code;
    return rc == CURLE_OK && code >= 200 && code < 400;
}

namespace {

bool looks_like_block_or_ratelimit(long http_code, const std::string& body, std::string& reason) {
    if (http_code == 429) { reason = "HTTP 429 Too Many Requests"; return true; }
    if (http_code == 403) { reason = "HTTP 403 Forbidden (often quota/IP block)"; return true; }
    if (http_code == 503) { reason = "HTTP 503 (often upstream rate-limiting)"; return true; }
    static const std::vector<std::string> needles = {
        "unusual traffic", "recaptcha", "captcha", "rateLimitExceeded",
        "dailyLimitExceeded", "quotaExceeded", "Too Many Requests",
        "Access Denied", "blocked due to", "automated queries",
    };
    for (auto& n : needles) {
        if (body.find(n) != std::string::npos) { reason = "response body matched block signature: \"" + n + "\""; return true; }
    }
    return false;
}

struct ParallelFetchRequest { std::string tag; std::string url; };
struct ParallelFetchResult  { std::string tag; std::string url; std::string body; long http_code = 0; bool ok = false; };

std::vector<ParallelFetchResult> parallel_http_get(const std::vector<ParallelFetchRequest>& reqs,
                                                    long timeout_ms, int concurrency) {
    std::vector<ParallelFetchResult> results(reqs.size());
    for (size_t i = 0; i < reqs.size(); ++i) { results[i].tag = reqs[i].tag; results[i].url = reqs[i].url; }
    if (reqs.empty()) return results;

    CURLM* multi = curl_multi_init();
    if (!multi) return results;

    std::vector<std::string> bodies(reqs.size());
    std::vector<CURL*> handles(reqs.size(), nullptr);
    size_t next = 0;
    int still_running = 0;

    auto add_handle = [&](size_t idx) {
        CURL* eh = curl_easy_init();
        if (!eh) return;
        curl_easy_setopt(eh, CURLOPT_URL, reqs[idx].url.c_str());
        curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, curl_write_cb);
        curl_easy_setopt(eh, CURLOPT_WRITEDATA, &bodies[idx]);
        curl_easy_setopt(eh, CURLOPT_TIMEOUT_MS, timeout_ms);
        curl_easy_setopt(eh, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(eh, CURLOPT_MAXREDIRS, 5L);
        curl_easy_setopt(eh, CURLOPT_USERAGENT, "shiv-dns-enum/1.0");
        curl_easy_setopt(eh, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(eh, CURLOPT_PRIVATE, reinterpret_cast<void*>(idx));
        handles[idx] = eh;
        curl_multi_add_handle(multi, eh);
    };

    for (; next < reqs.size() && static_cast<int>(next) < concurrency; ++next) add_handle(next);

    curl_multi_perform(multi, &still_running);
    while (still_running > 0 || next < reqs.size()) {
        int numfds = 0;
        curl_multi_wait(multi, nullptr, 0, 200, &numfds);
        curl_multi_perform(multi, &still_running);

        int msgs_left = 0;
        CURLMsg* msg;
        while ((msg = curl_multi_info_read(multi, &msgs_left)) != nullptr) {
            if (msg->msg != CURLMSG_DONE) continue;
            CURL* eh = msg->easy_handle;
            void* privptr = nullptr;
            curl_easy_getinfo(eh, CURLINFO_PRIVATE, &privptr);
            size_t idx = reinterpret_cast<size_t>(privptr);
            long code = 0;
            curl_easy_getinfo(eh, CURLINFO_RESPONSE_CODE, &code);
            results[idx].body = std::move(bodies[idx]);
            results[idx].http_code = code;
            results[idx].ok = (msg->data.result == CURLE_OK && code >= 200 && code < 400);
            curl_multi_remove_handle(multi, eh);
            curl_easy_cleanup(eh);
            handles[idx] = nullptr;

            if (next < reqs.size()) { add_handle(next); ++next; ++still_running; }
        }
    }

    for (auto* eh : handles) if (eh) { curl_multi_remove_handle(multi, eh); curl_easy_cleanup(eh); }
    curl_multi_cleanup(multi);
    return results;
}

std::string url_encode(const std::string& s) {
    CURL* c = curl_easy_init();
    if (!c) return s;
    char* out = curl_easy_escape(c, s.c_str(), static_cast<int>(s.size()));
    std::string r = out ? out : s;
    if (out) curl_free(out);
    curl_easy_cleanup(c);
    return r;
}

std::string add_host_if_domain_suffix(const std::string& raw, const std::string& domain,
                                       std::unordered_map<std::string, DiscoveredHost>& hosts,
                                       DiscoverySource src) {
    std::string h = raw;
    if (!h.empty() && h.back() == '.') h.pop_back();
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    if (h.size() < domain.size()) return "";
    if (h.compare(h.size() - domain.size(), domain.size(), domain) != 0) return "";
    auto& rec = hosts[h];
    rec.hostname = h;
    rec.sources.insert(src);
    return h;
}

// ---- individual response parsers (body/code already fetched) ----------

void parse_crtsh(const std::string& domain, const std::string& body,
                  std::unordered_map<std::string, DiscoveredHost>& hosts, size_t& found) {
    json j = json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.is_array()) return;
    for (auto& entry : j) {
        if (!entry.contains("name_value")) continue;
        std::istringstream ss(entry["name_value"].get<std::string>());
        std::string line;
        while (std::getline(ss, line)) {
            if (line.empty()) continue;
            if (line[0] == '*') line = line.substr(2); // strip "*."
            if (!add_host_if_domain_suffix(line, domain, hosts, DiscoverySource::PassiveCertLog).empty()) ++found;
        }
    }
}

void parse_certspotter(const std::string& domain, const std::string& body,
                        std::unordered_map<std::string, DiscoveredHost>& hosts, size_t& found) {
    json j = json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.is_array()) return;
    for (auto& entry : j) {
        if (!entry.contains("dns_names")) continue;
        for (auto& n : entry["dns_names"]) {
            if (!n.is_string()) continue;
            std::string name = n.get<std::string>();
            if (name.rfind("*.", 0) == 0) name = name.substr(2);
            if (!add_host_if_domain_suffix(name, domain, hosts, DiscoverySource::PassiveCertspotter).empty()) ++found;
        }
    }
}

void parse_wayback(const std::string& domain, const std::string& body, size_t sample_cap,
                    std::unordered_map<std::string, DiscoveredHost>& hosts,
                    std::vector<std::string>& sample_out, size_t& found) {
    static const std::regex host_re(R"(^[a-zA-Z]+://([^/:\s]+))");
    std::istringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        std::smatch m;
        if (!std::regex_search(line, m, host_re)) continue;
        if (!add_host_if_domain_suffix(m[1].str(), domain, hosts, DiscoverySource::PassiveWayback).empty()) {
            ++found;
            if (sample_out.size() < sample_cap) sample_out.push_back(line);
        }
    }
}

WhoisRdapInfo parse_rdap(const std::string& url, const std::string& body) {
    WhoisRdapInfo info;
    json j = json::parse(body, nullptr, false);
    if (j.is_discarded()) return info;
    info.found = true;
    info.raw_source_url = url;
    if (j.contains("events") && j["events"].is_array()) {
        for (auto& ev : j["events"]) {
            std::string action = ev.value("eventAction", "");
            std::string date = ev.value("eventDate", "");
            if (action == "registration") info.created = date;
            else if (action == "last changed") info.updated = date;
            else if (action == "expiration") info.expires = date;
        }
    }
    if (j.contains("status") && j["status"].is_array())
        for (auto& s : j["status"]) info.statuses.push_back(s.get<std::string>());
    if (j.contains("nameservers") && j["nameservers"].is_array())
        for (auto& ns : j["nameservers"])
            if (ns.contains("ldhName")) info.nameservers.push_back(ns["ldhName"].get<std::string>());
    if (j.contains("entities") && j["entities"].is_array()) {
        for (auto& e : j["entities"]) {
            if (!e.contains("roles")) continue;
            bool is_registrar = false;
            for (auto& r : e["roles"]) if (r.get<std::string>() == "registrar") is_registrar = true;
            if (!is_registrar) continue;
            if (e.contains("vcardArray") && e["vcardArray"].is_array() && e["vcardArray"].size() > 1) {
                for (auto& field : e["vcardArray"][1]) {
                    if (field.is_array() && field.size() > 3 && field[0] == "fn")
                        info.registrar = field[3].get<std::string>();
                }
            }
        }
    }
    return info;
}

void parse_hackertarget(const std::string& domain, const std::string& body,
                         std::unordered_map<std::string, DiscoveredHost>& hosts, size_t& found) {
    std::istringstream ss(body);
    std::string line;
    while (std::getline(ss, line)) {
        size_t comma = line.find(',');
        if (comma == std::string::npos) continue;
        std::string host = line.substr(0, comma);
        std::string ip = line.substr(comma + 1);
        auto added = add_host_if_domain_suffix(host, domain, hosts, DiscoverySource::PassiveHackertarget);
        if (!added.empty()) {
            ++found;
            if (family_of(ip) >= 0) hosts[added].ips.insert(ip);
        }
    }
}

void parse_rapiddns(const std::string& domain, const std::string& body,
                     std::unordered_map<std::string, DiscoveredHost>& hosts, size_t& found) {
    // CSV export: subdomain,address,type,cname ...
    std::istringstream ss(body);
    std::string line;
    bool first = true;
    while (std::getline(ss, line)) {
        if (first) { first = false; continue; } // header row
        size_t comma = line.find(',');
        std::string host = (comma == std::string::npos) ? line : line.substr(0, comma);
        if (!add_host_if_domain_suffix(host, domain, hosts, DiscoverySource::PassiveRapidDns).empty()) ++found;
    }
}

void parse_otx(const std::string& domain, const std::string& body,
               std::unordered_map<std::string, DiscoveredHost>& hosts, size_t& found) {
    json j = json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.contains("passive_dns") || !j["passive_dns"].is_array()) return;
    for (auto& e : j["passive_dns"]) {
        if (!e.contains("hostname")) continue;
        std::string host = e["hostname"].get<std::string>();
        auto added = add_host_if_domain_suffix(host, domain, hosts, DiscoverySource::PassiveOtx);
        if (!added.empty()) {
            ++found;
            if (e.contains("address")) {
                std::string ip = e["address"].get<std::string>();
                if (family_of(ip) >= 0) hosts[added].ips.insert(ip);
            }
        }
    }
}

void parse_urlscan(const std::string& domain, const std::string& body,
                    std::unordered_map<std::string, DiscoveredHost>& hosts, size_t& found) {
    json j = json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.contains("results") || !j["results"].is_array()) return;
    for (auto& e : j["results"]) {
        if (e.contains("page") && e["page"].contains("domain")) {
            std::string host = e["page"]["domain"].get<std::string>();
            if (!add_host_if_domain_suffix(host, domain, hosts, DiscoverySource::PassiveUrlscan).empty()) ++found;
        }
    }
}

bool is_subdomain_discovery_dork(const std::string& rendered_query) {
    return rendered_query.rfind("site:*.", 0) == 0 || rendered_query.find(" -site:www.") != std::string::npos;
}

std::vector<std::string> build_dork_queries(const std::string& domain,
                                             const std::vector<std::string>& extra_templates,
                                             int max_queries) {
    std::vector<std::string> templates = {
        "site:*.{domain} -site:www.{domain}",
        "site:*.{domain} -inurl:www",
        // --- general site footprint / indexable surface
        "site:{domain}",
        "site:{domain} -www",
        "site:{domain} intitle:\"index of\"",
        // --- auth / admin surfaces worth knowing about
        "site:{domain} inurl:login",
        "site:{domain} inurl:admin",
        "site:{domain} inurl:portal",
        "site:{domain} inurl:dashboard",
        // --- exposed config/data/API surfaces
        "site:{domain} ext:sql | ext:env | ext:log | ext:bak | ext:swp | ext:old",
        "site:{domain} inurl:wp-config | inurl:.htpasswd | inurl:.git",
        "site:{domain} inurl:api | inurl:swagger | inurl:graphql",
        "site:{domain} filetype:pdf",
        "site:{domain} filetype:xls | filetype:xlsx | filetype:csv",
        "site:{domain} filetype:doc | filetype:docx",
        "site:{domain} intext:\"internal use only\" | intext:\"confidential\"",
        // --- cloud storage buckets referencing the domain
        "site:s3.amazonaws.com {domain}",
        "site:blob.core.windows.net {domain}",
        "site:storage.googleapis.com {domain}",
        // --- third-party leak / code / doc-sharing surfaces
        "site:pastebin.com {domain}",
        "site:github.com {domain}",
        "site:gitlab.com {domain}",
        "site:trello.com {domain}",
        "site:docs.google.com {domain}",
        "site:stackoverflow.com {domain}",
        // --- tech-stack / org intel
        "site:{domain} inurl:careers | inurl:jobs",
    };
    templates.insert(templates.end(), extra_templates.begin(), extra_templates.end());

    std::vector<std::string> out;
    for (auto& t : templates) {
        if (static_cast<int>(out.size()) >= max_queries) break;
        std::string q = t;
        size_t pos;
        while ((pos = q.find("{domain}")) != std::string::npos) q.replace(pos, 8, domain);
        out.push_back(q);
    }
    return out;
}

std::string extract_host_from_url(const std::string& url) {
    size_t scheme = url.find("://");
    size_t start = (scheme == std::string::npos) ? 0 : scheme + 3;
    size_t end = url.find_first_of("/:?#", start);
    std::string host = (end == std::string::npos) ? url.substr(start) : url.substr(start, end - start);
    std::transform(host.begin(), host.end(), host.begin(), ::tolower);
    return host;
}

void extract_hosts_from_dork_hits(const std::string& domain, const std::vector<DorkHit>& hits,
                                   std::unordered_map<std::string, DiscoveredHost>& hosts, size_t& found) {
    static const std::regex host_in_text_re(R"(([a-zA-Z0-9][a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,})");
    for (auto& hit : hits) {
        if (!hit.url.empty()) {
            std::string host = extract_host_from_url(hit.url);
            if (!host.empty() && !add_host_if_domain_suffix(host, domain, hosts, DiscoverySource::PassiveDork).empty())
                ++found;
        }
        if (is_subdomain_discovery_dork(hit.query)) {
            for (const std::string* text : {&hit.title, &hit.snippet}) {
                auto begin = std::sregex_iterator(text->begin(), text->end(), host_in_text_re);
                auto end = std::sregex_iterator();
                for (auto it = begin; it != end; ++it) {
                    if (!add_host_if_domain_suffix(it->str(), domain, hosts, DiscoverySource::PassiveDork).empty())
                        ++found;
                }
            }
        }
    }
}

std::vector<AsnInfo> passive_asn_lookup_bulk(const std::vector<std::string>& ips, int timeout_ms) {
    std::vector<AsnInfo> out;
    if (ips.empty()) return out;

    int fam = AF_INET;
    for (auto& ip : ips) if (family_of(ip) == AF_INET6) { fam = AF_INET6; break; }

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo("whois.cymru.com", "43", &hints, &res) != 0 || !res) return out;

    int fd = -1;
    for (auto* p = res; p; p = p->ai_next) {
        fd = socket(p->ai_family, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    (void)fam;
    if (fd < 0) return out;

    std::string query = "begin\nverbose\n";
    for (auto& ip : ips) query += ip + "\n";
    query += "end\n";
    if (send(fd, query.data(), query.size(), 0) < 0) { close(fd); return out; }

    std::string resp;
    char buf[4096];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) resp.append(buf, n);
    close(fd);

    std::istringstream ss(resp);
    std::string line;
    bool header_skipped = false;
    while (std::getline(ss, line)) {
        if (line.rfind("Bulk mode", 0) == 0) continue;
        if (line.find('|') == std::string::npos) continue;
        if (!header_skipped) { header_skipped = true; continue; } // "AS | IP | ..." header row
        std::vector<std::string> fields;
        std::stringstream fs(line);
        std::string field;
        while (std::getline(fs, field, '|')) {
            size_t b = field.find_first_not_of(' ');
            size_t e = field.find_last_not_of(' ');
            fields.push_back(b == std::string::npos ? "" : field.substr(b, e - b + 1));
        }
        if (fields.size() >= 7) {
            AsnInfo info;
            info.asn = fields[0]; info.ip = fields[1]; info.prefix = fields[2];
            info.country = fields[3]; info.registry = fields[4];
            info.allocated = fields[5]; info.as_name = fields[6];
            out.push_back(std::move(info));
        }
    }
    return out;
}

std::vector<AsnInfo> passive_asn_ripestat(const std::vector<std::string>& ips, int timeout_ms, int concurrency) {
    std::vector<AsnInfo> out;
    if (ips.empty()) return out;
    std::vector<ParallelFetchRequest> reqs;
    for (auto& ip : ips)
        reqs.push_back({ip, "https://stat.ripe.net/data/network-info/data.json?resource=" + url_encode(ip)});
    auto results = parallel_http_get(reqs, timeout_ms, concurrency);
    for (auto& r : results) {
        if (!r.ok) continue;
        json j = json::parse(r.body, nullptr, false);
        if (j.is_discarded() || !j.contains("data")) continue;
        auto& data = j["data"];
        AsnInfo info;
        info.ip = r.tag;
        info.source = "ripestat";
        info.prefix = data.value("prefix", "");
        if (data.contains("asns") && data["asns"].is_array() && !data["asns"].empty())
            info.asn = data["asns"][0].get<std::string>();
        if (info.asn.empty() && info.prefix.empty()) continue; // nothing useful came back
        out.push_back(std::move(info));
    }
    return out;
}

std::unordered_map<std::string, std::string> ripestat_as_holders(const std::vector<std::string>& asns,
                                                                    int timeout_ms, int concurrency) {
    std::unordered_map<std::string, std::string> out;
    std::unordered_set<std::string> seen;
    std::vector<ParallelFetchRequest> reqs;
    for (auto& asn_field : asns) {
        std::string asn = asn_field;
        size_t sp = asn.find_first_of(" ,");
        if (sp != std::string::npos) asn = asn.substr(0, sp);
        if (asn.empty() || seen.count(asn)) continue;
        seen.insert(asn);
        reqs.push_back({asn, "https://stat.ripe.net/data/as-overview/data.json?resource=AS" + asn});
    }
    if (reqs.empty()) return out;
    auto results = parallel_http_get(reqs, timeout_ms, concurrency);
    for (auto& r : results) {
        if (!r.ok) continue;
        json j = json::parse(r.body, nullptr, false);
        if (j.is_discarded() || !j.contains("data")) continue;
        std::string holder = j["data"].value("holder", "");
        if (!holder.empty()) out[r.tag] = holder;
    }
    return out;
}

std::vector<BgpSiblingPrefix> passive_bgp_siblings(const std::vector<std::string>& asns, int timeout_ms) {
    std::vector<BgpSiblingPrefix> out;
    std::unordered_set<std::string> seen_asn;
    std::vector<ParallelFetchRequest> reqs;
    for (auto& asn_field : asns) {
        std::string asn = asn_field;
        size_t sp = asn.find_first_of(" ,");
        if (sp != std::string::npos) asn = asn.substr(0, sp);
        if (asn.empty() || seen_asn.count(asn)) continue;
        seen_asn.insert(asn);
        reqs.push_back({asn, "https://api.bgpview.io/asn/" + asn + "/prefixes"});
    }
    if (reqs.empty()) return out;
    auto results = parallel_http_get(reqs, timeout_ms, 8);
    for (auto& r : results) {
        if (!r.ok) continue;
        json j = json::parse(r.body, nullptr, false);
        if (j.is_discarded() || !j.contains("data")) continue;
        auto& data = j["data"];
        for (const char* key : {"ipv4_prefixes", "ipv6_prefixes"}) {
            if (!data.contains(key) || !data[key].is_array()) continue;
            for (auto& p : data[key]) {
                BgpSiblingPrefix bp;
                bp.asn = r.tag;
                bp.prefix = p.value("prefix", "");
                bp.description = p.value("description", "");
                if (!bp.prefix.empty()) out.push_back(std::move(bp));
            }
        }
    }
    return out;
}

}

void run_google_dork(const std::string& domain, const DnsEnumOptions& opts,
                      std::vector<DorkHit>& hits, std::vector<DorkQueryStatus>& statuses,
                      PassiveSourceStatus& source_status) {
    source_status.source_name = "google_dork";
    if (!opts.google_dork) { source_status.detail = "disabled (opts.google_dork = false)"; return; }
    if (opts.google_api_key.empty() || opts.google_cx.empty()) {
        source_status.detail = "google_dork enabled but google_api_key/google_cx not configured "
                                "(get a free-tier key+cx at https://programmablesearchengine.google.com/)";
        return;
    }

    auto queries = build_dork_queries(domain, opts.extra_dork_templates, opts.dork_max_queries_per_run);
    std::vector<ParallelFetchRequest> reqs;
    for (auto& q : queries) {
        std::string url = "https://www.googleapis.com/customsearch/v1?key=" + opts.google_api_key +
                           "&cx=" + opts.google_cx + "&num=" + std::to_string(opts.dork_results_per_query) +
                           "&q=" + url_encode(q);
        reqs.push_back({q, url});
    }
    if (reqs.empty()) return;

    auto results = parallel_http_get(reqs, opts.passive_timeout_ms, opts.passive_concurrency);

    size_t blocked_count = 0;
    for (auto& r : results) {
        DorkQueryStatus qs;
        qs.query = r.tag;
        qs.http_status = r.http_code;

        std::string reason;
        if (looks_like_block_or_ratelimit(r.http_code, r.body, reason)) {
            qs.blocked = true;
            qs.block_reason = reason;
            ++blocked_count;
            statuses.push_back(std::move(qs));
            continue;
        }

        json j = json::parse(r.body, nullptr, false);
        if (!j.is_discarded() && j.contains("error")) {
            qs.blocked = true;
            qs.block_reason = j["error"].value("message", "unspecified API error");
            ++blocked_count;
            statuses.push_back(std::move(qs));
            continue;
        }

        if (!j.is_discarded() && j.contains("items") && j["items"].is_array()) {
            for (auto& item : j["items"]) {
                DorkHit hit;
                hit.query = r.tag;
                hit.title = item.value("title", "");
                hit.url = item.value("link", "");
                hit.snippet = item.value("snippet", "");
                hits.push_back(std::move(hit));
                ++qs.result_count;
            }
        }
        statuses.push_back(std::move(qs));
    }

    source_status.ok = blocked_count < results.size();
    source_status.rate_limited = blocked_count > 0;
    source_status.items_found = hits.size();
    source_status.detail = blocked_count > 0
        ? (std::to_string(blocked_count) + "/" + std::to_string(results.size()) + " dork queries blocked/rate-limited")
        : "ok";
}

namespace {

void brute_force_batched(const std::string& domain, const std::vector<std::string>& words,
                          const std::vector<std::string>& servers, int timeout_ms, int concurrency,
                          bool use_edns0, DiscoverySource tag_as,
                          std::unordered_map<std::string, DiscoveredHost>& hosts) {
    if (servers.empty() || words.empty()) return;
    std::vector<AsyncDnsJob> jobs;
    jobs.reserve(words.size() * 2);
    for (auto& w : words) {
        std::string fqdn = w + "." + domain;
        jobs.push_back({fqdn, DnsRRType::A, fqdn});
        jobs.push_back({fqdn, DnsRRType::AAAA, fqdn});
    }
    auto results = dns_query_batch(jobs, servers, timeout_ms, concurrency, use_edns0);
    for (auto& r : results) {
        if (!r.answered || r.records.empty()) continue;
        bool has_addr = false;
        for (auto& rec : r.records) if (rec.type == DnsRRType::A || rec.type == DnsRRType::AAAA) has_addr = true;
        if (!has_addr) continue;
        auto& host = hosts[r.tag];
        host.hostname = r.tag;
        host.sources.insert(tag_as);
        for (auto& rec : r.records)
            if (rec.type == DnsRRType::A || rec.type == DnsRRType::AAAA) host.ips.insert(rec.value);
    }
}

void run_mutation_pass(const std::string& domain, std::unordered_map<std::string, DiscoveredHost>& hosts,
                        const std::vector<std::string>& servers, int timeout_ms, int concurrency,
                        bool use_edns0, size_t max_candidates) {
    std::unordered_set<std::string> seed_labels;
    for (auto& [name, h] : hosts) {
        if (name.size() <= domain.size() + 1) continue;
        std::string label = name.substr(0, name.size() - domain.size() - 1);
        if (label.find('.') != std::string::npos) continue; // only first-level labels
        seed_labels.insert(label);
    }
    if (seed_labels.empty()) return;

    std::unordered_set<std::string> candidates;
    for (auto& label : seed_labels) {
        for (auto& m : mutate_label(label)) {
            if (candidates.size() >= max_candidates) break;
            std::string fqdn = m + "." + domain;
            if (!hosts.count(fqdn)) candidates.insert(fqdn);
        }
        if (candidates.size() >= max_candidates) break;
    }
    if (candidates.empty()) return;

    std::vector<AsyncDnsJob> jobs;
    jobs.reserve(candidates.size() * 2);
    for (auto& fqdn : candidates) {
        jobs.push_back({fqdn, DnsRRType::A, fqdn});
        jobs.push_back({fqdn, DnsRRType::AAAA, fqdn});
    }
    auto results = dns_query_batch(jobs, servers, timeout_ms, concurrency, use_edns0);
    for (auto& r : results) {
        if (!r.answered || r.records.empty()) continue;
        bool has_addr = false;
        for (auto& rec : r.records) if (rec.type == DnsRRType::A || rec.type == DnsRRType::AAAA) has_addr = true;
        if (!has_addr) continue;
        auto& host = hosts[r.tag];
        host.hostname = r.tag;
        host.sources.insert(DiscoverySource::ActiveMutatedBruteForce);
        for (auto& rec : r.records)
            if (rec.type == DnsRRType::A || rec.type == DnsRRType::AAAA) host.ips.insert(rec.value);
    }
}

}


DnsEnumResult run_dns_enum(const std::string& domain, const DnsEnumOptions& opts) {
    DnsEnumResult result;
    result.domain = domain;
    auto servers = active_server_list();
    bool dork_usable = opts.google_dork && !opts.google_api_key.empty() && !opts.google_cx.empty();
    bool skip_active_subdomain_enum = opts.prefer_dork_for_subdomains && dork_usable;

    if (opts.do_active) {
        auto t0 = std::chrono::steady_clock::now();

        {
            std::vector<AsyncDnsJob> jobs;
            for (DnsRRType t : {DnsRRType::A, DnsRRType::AAAA, DnsRRType::NS, DnsRRType::MX,
                                 DnsRRType::TXT, DnsRRType::SOA, DnsRRType::CAA})
                jobs.push_back({domain, t, dns_rrtype_name(t)});
            auto results = batch_with_retry(jobs, servers, opts.timeout_ms, opts.retries,
                                             opts.active_concurrency, opts.use_edns0);
            for (auto& r : results)
                if (r.answered)
                    result.records.insert(result.records.end(), r.records.begin(), r.records.end());
        }

        // 2. Wildcard probe — random label that (almost certainly) doesn't exist.
        {
            std::mt19937 rng(std::random_device{}());
            std::string probe = "shiv-wc-" + std::to_string(rng()) + "." + domain;
            std::vector<DnsRecord> recs;
            if (dns_query_generic(probe, DnsRRType::A, servers, opts.timeout_ms, opts.retries, recs)) {
                for (auto& r : recs) {
                    if (r.type == DnsRRType::A) {
                        result.wildcard_dns = true;
                        result.wildcard_ip_sample = r.value;
                        break;
                    }
                }
            }
        }

        if (opts.attempt_axfr) {
            std::vector<std::string> ns_names;
            for (auto& r : result.records) if (r.type == DnsRRType::NS) ns_names.push_back(r.value);

            std::unordered_map<std::string, std::string> ns_ip;
            if (!ns_names.empty()) {
                std::vector<AsyncDnsJob> ns_jobs;
                for (auto& ns : ns_names) ns_jobs.push_back({ns, DnsRRType::A, ns});
                auto ns_results = dns_query_batch(ns_jobs, servers, opts.timeout_ms,
                                                   opts.active_concurrency, opts.use_edns0);
                for (auto& r : ns_results)
                    for (auto& rec : r.records)
                        if (rec.type == DnsRRType::A) { ns_ip[r.tag] = rec.value; break; }
            }

            for (auto& ns_name : ns_names) {
                auto it = ns_ip.find(ns_name);
                if (it == ns_ip.end() || it->second.empty()) continue;

                std::vector<DnsRecord> zone_recs;
                auto att = try_axfr(domain, ns_name, it->second, opts.timeout_ms, zone_recs);
                result.axfr_attempts.push_back(att);
                if (att.succeeded) {
                    result.records.insert(result.records.end(), zone_recs.begin(), zone_recs.end());
                    for (auto& r : zone_recs) {
                        if (r.name.empty()) continue;
                        std::string h = r.name;
                        if (!h.empty() && h.back() == '.') h.pop_back();
                        std::transform(h.begin(), h.end(), h.begin(), ::tolower);
                        auto& dh = result.hosts[h];
                        dh.hostname = h;
                        dh.sources.insert(DiscoverySource::ActiveZoneTransfer);
                        if (r.type == DnsRRType::A || r.type == DnsRRType::AAAA) dh.ips.insert(r.value);
                    }
                }
            }
        }
        if (!skip_active_subdomain_enum && (!result.wildcard_dns || opts.skip_wildcard_filter)) {
            std::vector<std::string> words = builtin_subdomain_wordlist();
            if (!opts.wordlist_file.empty()) {
                std::ifstream f(opts.wordlist_file);
                std::string line;
                while (f && std::getline(f, line)) {
                    if (!line.empty()) words.push_back(line);
                }
            }
            brute_force_batched(domain, words, servers, opts.timeout_ms, opts.brute_concurrency,
                                 opts.use_edns0, DiscoverySource::ActiveBruteForce, result.hosts);

            if (result.wildcard_dns && !opts.skip_wildcard_filter) {
                for (auto& [name, h] : result.hosts) {
                    if (h.ips.count(result.wildcard_ip_sample))
                        h.wildcard_suspect = true;
                }
            }
        }

        // 5. Email security + DNSSEC + SRV + TLSA — each its own batched wave.
        collect_email_security_batched(domain, servers, opts.timeout_ms, opts.retries,
                                        opts.active_concurrency, opts.extra_dkim_selectors,
                                        opts.use_edns0, result.mail_security);
        collect_dnssec_batched(domain, servers, opts.timeout_ms, opts.retries,
                                opts.active_concurrency, opts.use_edns0, result.dnssec);
        if (opts.query_srv)
            collect_srv_batched(domain, servers, opts.timeout_ms, opts.retries,
                                 opts.active_concurrency, opts.use_edns0, result.srv_findings);
        if (opts.query_tlsa)
            collect_tlsa_batched(domain, opts.tlsa_ports, servers, opts.timeout_ms, opts.retries,
                                  opts.active_concurrency, opts.use_edns0, result.tlsa_findings);

        if (opts.nsec_walk && result.dnssec.dnskey_present)
            result.nsec_walk = run_nsec_walk(domain, servers, opts.timeout_ms, opts.nsec_walk_max_steps);

        result.active_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
    }

    if (opts.do_passive) {
        auto t0 = std::chrono::steady_clock::now();

        // Fire every HTTP-based passive source concurrently in one wave.
        std::vector<ParallelFetchRequest> reqs;
        if (opts.query_crtsh)
            reqs.push_back({"crtsh", "https://crt.sh/?q=%25." + domain + "&output=json"});
        if (opts.query_certspotter)
            reqs.push_back({"certspotter", "https://api.certspotter.com/v1/issuances?domain=" + domain +
                                            "&include_subdomains=true&expand=dns_names"});
        if (opts.query_wayback)
            reqs.push_back({"wayback", "http://web.archive.org/cdx/search/cdx?url=*." + domain +
                                        "&output=text&fl=original&collapse=urlkey&limit=5000"});
        if (opts.query_rdap)
            reqs.push_back({"rdap", "https://rdap.org/domain/" + domain});
        if (opts.query_hackertarget)
            reqs.push_back({"hackertarget", "https://api.hackertarget.com/hostsearch/?q=" + domain});
        if (opts.query_rapiddns)
            reqs.push_back({"rapiddns", "https://rapiddns.io/subdomain/" + domain + "?full=1&down=1"});
        if (opts.query_otx)
            reqs.push_back({"otx", "https://otx.alienvault.com/api/v1/indicators/domain/" + domain + "/passive_dns"});
        if (opts.query_urlscan)
            reqs.push_back({"urlscan", "https://urlscan.io/api/v1/search/?q=domain:" + domain});

        auto fetched = parallel_http_get(reqs, opts.passive_timeout_ms, opts.passive_concurrency);

        for (auto& r : fetched) {
            PassiveSourceStatus st;
            st.source_name = r.tag;
            std::string reason;
            if (looks_like_block_or_ratelimit(r.http_code, r.body, reason)) {
                st.rate_limited = true; st.detail = reason;
                result.passive_source_status.push_back(std::move(st));
                continue;
            }
            if (!r.ok) {
                st.detail = "request failed (http " + std::to_string(r.http_code) + ")";
                result.passive_source_status.push_back(std::move(st));
                continue;
            }

            size_t found = 0;
            try {
                if (r.tag == "crtsh") parse_crtsh(domain, r.body, result.hosts, found);
                else if (r.tag == "certspotter") parse_certspotter(domain, r.body, result.hosts, found);
                else if (r.tag == "wayback") parse_wayback(domain, r.body, opts.wayback_sample_cap,
                                                             result.hosts, result.wayback_urls_sample, found);
                else if (r.tag == "rdap") { result.domain_whois = parse_rdap(r.url, r.body); found = result.domain_whois.found ? 1 : 0; }
                else if (r.tag == "hackertarget") parse_hackertarget(domain, r.body, result.hosts, found);
                else if (r.tag == "rapiddns") parse_rapiddns(domain, r.body, result.hosts, found);
                else if (r.tag == "otx") parse_otx(domain, r.body, result.hosts, found);
                else if (r.tag == "urlscan") parse_urlscan(domain, r.body, result.hosts, found);
            } catch (...) { /* best-effort per source */ }

            st.ok = true;
            st.items_found = found;
            st.detail = "ok";
            result.passive_source_status.push_back(std::move(st));
        }
        if (opts.query_asn) {
            std::unordered_set<std::string> unique_ips;
            for (auto& [name, h] : result.hosts) for (auto& ip : h.ips) unique_ips.insert(ip);
            for (auto& r : result.records)
                if (r.type == DnsRRType::A || r.type == DnsRRType::AAAA) unique_ips.insert(r.value);

            std::vector<std::string> ip_list(unique_ips.begin(), unique_ips.end());
            result.asn_lookups = passive_asn_lookup_bulk(ip_list, opts.passive_timeout_ms);

            PassiveSourceStatus st;
            st.source_name = "team_cymru_asn";
            st.ok = !result.asn_lookups.empty();
            st.items_found = result.asn_lookups.size();
            st.detail = st.ok ? "ok" : "no results (empty IP set or lookup failed)";
            result.passive_source_status.push_back(st);

            if (opts.query_ripestat) {
                std::unordered_set<std::string> covered;
                for (auto& a : result.asn_lookups) covered.insert(a.ip);
                std::vector<std::string> missing;
                for (auto& ip : ip_list) if (!covered.count(ip)) missing.push_back(ip);

                PassiveSourceStatus rst;
                rst.source_name = "ripestat_asn";
                auto filled = passive_asn_ripestat(missing, opts.passive_timeout_ms, opts.passive_concurrency);
                for (auto& f : filled) result.asn_lookups.push_back(std::move(f));
                rst.items_found = filled.size();

                std::vector<std::string> asns_needing_names;
                for (auto& a : result.asn_lookups) if (!a.asn.empty() && a.as_name.empty()) asns_needing_names.push_back(a.asn);
                auto holders = ripestat_as_holders(asns_needing_names, opts.passive_timeout_ms, opts.passive_concurrency);
                size_t enriched = 0;
                for (auto& a : result.asn_lookups) {
                    auto it = holders.find(a.asn);
                    if (it != holders.end() && a.as_name.empty()) { a.as_name = it->second; ++enriched; }
                }

                rst.ok = !filled.empty() || enriched > 0;
                rst.detail = std::to_string(filled.size()) + " gap-filled IP(s), " +
                             std::to_string(enriched) + " AS name(s) enriched";
                result.passive_source_status.push_back(rst);
            }

            if (opts.query_bgp_siblings && !result.asn_lookups.empty()) {
                std::vector<std::string> asns;
                for (auto& a : result.asn_lookups) if (!a.asn.empty()) asns.push_back(a.asn);
                result.sibling_prefixes = passive_bgp_siblings(asns, opts.passive_timeout_ms);
            }
        }

        {
            PassiveSourceStatus dork_status;
            run_google_dork(domain, opts, result.dork_hits, result.dork_query_status, dork_status);
            if (opts.google_dork) {
                if (opts.dork_discover_subdomains && !result.dork_hits.empty()) {
                    size_t dork_hosts_found = 0;
                    extract_hosts_from_dork_hits(domain, result.dork_hits, result.hosts, dork_hosts_found);
                    dork_status.detail += "  (" + std::to_string(dork_hosts_found) + " subdomain(s) extracted)";
                }
                result.passive_source_status.push_back(dork_status);
            }
        }

        result.passive_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
    }
    if (opts.do_active) {
        if (!skip_active_subdomain_enum && opts.mutate_wordlist &&
            (!result.wildcard_dns || opts.skip_wildcard_filter))
            run_mutation_pass(domain, result.hosts, servers, opts.timeout_ms, opts.active_concurrency,
                               opts.use_edns0, opts.mutation_max_candidates);

        if (opts.check_takeovers)
            check_takeovers(result.hosts, servers, opts.timeout_ms, result.takeover_findings);

        if (opts.ptr_sweep_self || opts.ptr_sweep_prefix) {
            std::unordered_set<std::string> all_ips;
            for (auto& [name, h] : result.hosts) for (auto& ip : h.ips) all_ips.insert(ip);
            for (auto& r : result.records)
                if (r.type == DnsRRType::A || r.type == DnsRRType::AAAA) all_ips.insert(r.value);
            run_ptr_sweep(all_ips, opts.ptr_sweep_prefix, opts.ptr_sweep_max_hosts, servers,
                          opts.timeout_ms, opts.active_concurrency, opts.use_edns0, result.ptr_sweep);
        }
    }

    return result;
}

const char* dns_rrtype_name(DnsRRType t) {
    switch (t) {
        case DnsRRType::A: return "A";
        case DnsRRType::NS: return "NS";
        case DnsRRType::CNAME: return "CNAME";
        case DnsRRType::SOA: return "SOA";
        case DnsRRType::PTR: return "PTR";
        case DnsRRType::MX: return "MX";
        case DnsRRType::TXT: return "TXT";
        case DnsRRType::AAAA: return "AAAA";
        case DnsRRType::SRV: return "SRV";
        case DnsRRType::NAPTR: return "NAPTR";
        case DnsRRType::DS: return "DS";
        case DnsRRType::RRSIG: return "RRSIG";
        case DnsRRType::NSEC: return "NSEC";
        case DnsRRType::NSEC3: return "NSEC3";
        case DnsRRType::DNSKEY: return "DNSKEY";
        case DnsRRType::TLSA: return "TLSA";
        case DnsRRType::CAA: return "CAA";
        case DnsRRType::AXFR: return "AXFR";
        case DnsRRType::OPT: return "OPT";
        default: return "ANY";
    }
}

namespace {

std::string sanitize_echo(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out += (c < 0x20 || c == 0x7F) ? '?' : static_cast<char>(c);
    }
    return out;
}

}

void print_dns_enum_result(const DnsEnumResult& r, const DnsEnumOptions& opts) {
    std::cout << "\n" << color::bold << color::cyan << "DNS Enumeration: " << color::reset
              << color::white << r.domain << color::reset << "\n";

    std::cout << color::bold << "\n:: Apex records\n" << color::reset;
    for (auto& rec : r.records) {
        if (rec.source.rfind("axfr", 0) == 0) continue; // shown separately
        std::cout << "  " << color::yellow << dns_rrtype_name(rec.type) << color::reset
                  << "\t" << rec.name << "\t" << sanitize_echo(rec.value)
                  << color::dim << "  (ttl=" << rec.ttl << ")" << color::reset << "\n";
    }

    if (r.wildcard_dns) {
        std::cout << color::bold << "\n:: Wildcard DNS detected" << color::reset
                  << " -> " << r.wildcard_ip_sample
                  << color::dim << "  (brute-force hits matching this IP are flagged wildcard_suspect)"
                  << color::reset << "\n";
    }

    if (!r.axfr_attempts.empty()) {
        std::cout << color::bold << "\n:: Zone transfer (AXFR) attempts\n" << color::reset;
        for (auto& a : r.axfr_attempts) {
            if (a.succeeded) {
                std::cout << "  " << color::red << color::bold << "SUCCEEDED" << color::reset
                          << " against " << a.ns_host << " (" << a.ns_ip << ") — "
                          << a.records_pulled << " records pulled. Full zone contents exposed.\n";
            } else {
                std::cout << "  " << color::green << "refused" << color::reset
                          << "  " << a.ns_host << " (" << a.ns_ip << "): " << a.error << "\n";
            }
        }
    }

    size_t brute = 0, mutated = 0, axfr = 0, cert = 0, certsp = 0, wb = 0, rdap_h = 0,
           ht = 0, rdns = 0, otx = 0, urlscan_h = 0, dork = 0, ptr_h = 0, nsec_h = 0, wc = 0;
    for (auto& [name, h] : r.hosts) {
        for (auto s : h.sources) {
            switch (s) {
                case DiscoverySource::ActiveBruteForce: ++brute; break;
                case DiscoverySource::ActiveMutatedBruteForce: ++mutated; break;
                case DiscoverySource::ActiveZoneTransfer: ++axfr; break;
                case DiscoverySource::PassiveCertLog: ++cert; break;
                case DiscoverySource::PassiveCertspotter: ++certsp; break;
                case DiscoverySource::PassiveWayback: ++wb; break;
                case DiscoverySource::PassiveHackertarget: ++ht; break;
                case DiscoverySource::PassiveRapidDns: ++rdns; break;
                case DiscoverySource::PassiveOtx: ++otx; break;
                case DiscoverySource::PassiveUrlscan: ++urlscan_h; break;
                case DiscoverySource::PassiveDork: ++dork; break;
                case DiscoverySource::ActivePtrSweep: ++ptr_h; break;
                case DiscoverySource::ActiveNsecWalk: ++nsec_h; break;
                default: break;
            }
        }
        if (h.wildcard_suspect) ++wc;
    }
    (void)rdap_h;
    std::cout << color::bold << "\n:: Subdomains — " << r.hosts.size() << " unique host(s)"
              << color::reset << "\n"
              << "  brute-force: " << brute << "   mutated: " << mutated << "   axfr: " << axfr
              << "   crt.sh: " << cert << "   certspotter: " << certsp << "   wayback: " << wb << "\n"
              << "  hackertarget: " << ht << "   rapiddns: " << rdns << "   otx: " << otx
              << "   urlscan: " << urlscan_h << "   dork: " << dork
              << (wc ? ("   " + color::dim + "wildcard_suspect: " + std::to_string(wc) + color::reset) : "")
              << "\n";
    {
        std::vector<std::string> names;
        names.reserve(r.hosts.size());
        for (auto& [name, h] : r.hosts) names.push_back(name);
        std::sort(names.begin(), names.end());
        for (auto& name : names) {
            const auto& h = r.hosts.at(name);
            std::cout << "    " << (h.wildcard_suspect ? color::dim : color::white) << name << color::reset;
            if (!h.ips.empty()) {
                std::cout << "  -> ";
                bool first = true;
                for (auto& ip : h.ips) { if (!first) std::cout << ", "; std::cout << ip; first = false; }
            }
            std::cout << "\n";
        }
    }

    if (!r.takeover_findings.empty()) {
        std::cout << color::bold << color::red << "\n:: Possible subdomain takeovers\n" << color::reset;
        for (auto& f : r.takeover_findings) {
            std::cout << "  " << color::red << color::bold << f.hostname << color::reset
                      << " -> " << f.matched_service
                      << (f.http_confirmed ? (color::red + "  [HTTP-CONFIRMED]" + color::reset)
                                            : (color::dim + "  [CNAME match only, unconfirmed]" + color::reset))
                      << "\n";
            std::cout << "    chain: ";
            for (size_t i = 0; i < f.cname_chain.size(); ++i) {
                if (i) std::cout << " -> ";
                std::cout << f.cname_chain[i];
            }
            std::cout << "\n";
        }
    }

    if (!r.srv_findings.empty()) {
        std::cout << color::bold << "\n:: SRV records\n" << color::reset;
        for (auto& s : r.srv_findings)
            std::cout << "  " << s.service << "  " << s.target << ":" << s.port
                       << color::dim << "  (priority=" << s.priority << ", weight=" << s.weight << ")"
                       << color::reset << "\n";
    }

    if (!r.tlsa_findings.empty()) {
        std::cout << color::bold << "\n:: TLSA (DANE) records\n" << color::reset;
        for (auto& t : r.tlsa_findings)
            std::cout << "  " << t.service << "  usage=" << (int)t.cert_usage
                       << " selector=" << (int)t.selector << " matching=" << (int)t.matching_type
                       << "  " << t.data_hex.substr(0, 24) << (t.data_hex.size() > 24 ? "..." : "") << "\n";
    }

    std::cout << color::bold << "\n:: Email security posture\n" << color::reset;
    auto flag = [](bool b) { return b ? (color::green + "yes" + color::reset)
                                       : (color::red + "no" + color::reset); };
    std::cout << "  SPF: " << flag(r.mail_security.has_spf);
    if (r.mail_security.has_spf) std::cout << "  " << color::dim << sanitize_echo(r.mail_security.spf_record) << color::reset;
    std::cout << "\n  DMARC: " << flag(r.mail_security.has_dmarc);
    if (r.mail_security.has_dmarc) std::cout << "  " << color::dim << sanitize_echo(r.mail_security.dmarc_record) << color::reset;
    std::cout << "\n  BIMI: " << flag(r.mail_security.has_bimi)
               << "   MTA-STS: " << flag(r.mail_security.has_mta_sts_dns)
               << "   TLS-RPT: " << flag(r.mail_security.has_tls_rpt) << "\n";
    if (!r.mail_security.dkim_selectors_found.empty()) {
        std::cout << "  DKIM selectors found: ";
        bool first = true;
        for (auto& [sel, val] : r.mail_security.dkim_selectors_found) {
            if (!first) std::cout << ", ";
            std::cout << sel; first = false;
        }
        std::cout << "\n";
    }

    std::cout << color::bold << "\n:: DNSSEC\n" << color::reset
              << "  DNSKEY: " << flag(r.dnssec.dnskey_present)
              << " (" << r.dnssec.dnskey_count << ")"
              << "   RRSIG observed: " << flag(r.dnssec.rrsig_seen) << "\n";
    if (r.nsec_walk.attempted) {
        std::cout << "  NSEC walk: " << flag(r.nsec_walk.zone_signed)
                   << "  names discovered: " << r.nsec_walk.names_from_bitmap_gaps.size()
                   << (r.nsec_walk.wrapped ? "  (completed full loop)" : "")
                   << color::dim << (r.nsec_walk.note.empty() ? "" : ("  " + r.nsec_walk.note)) << color::reset << "\n";
    }

    if (r.domain_whois.found) {
        std::cout << color::bold << "\n:: WHOIS / RDAP\n" << color::reset
                  << "  registrar: " << r.domain_whois.registrar << "\n"
                  << "  created:   " << r.domain_whois.created << "\n"
                  << "  updated:   " << r.domain_whois.updated << "\n"
                  << "  expires:   " << r.domain_whois.expires << "\n";
    }

    if (!r.asn_lookups.empty()) {
        std::cout << color::bold << "\n:: ASN / infrastructure\n" << color::reset;
        for (auto& a : r.asn_lookups)
            std::cout << "  " << a.ip << "  AS" << a.asn << " " << a.as_name
                       << "  (" << a.prefix << ", " << a.country << ")"
                       << color::dim << "  [" << a.source << "]" << color::reset << "\n";
    }

    if (!r.sibling_prefixes.empty()) {
        std::cout << color::bold << "\n:: Sibling BGP prefixes (same ASN)\n" << color::reset;
        for (auto& p : r.sibling_prefixes)
            std::cout << "  AS" << p.asn << "  " << p.prefix
                       << (p.description.empty() ? "" : ("  " + color::dim + p.description + color::reset)) << "\n";
    }

    if (r.ptr_sweep.attempted) {
        std::cout << color::bold << "\n:: Reverse PTR sweep\n" << color::reset
                  << "  hosts checked: " << r.ptr_sweep.hosts_checked
                  << "   PTR records found: " << r.ptr_sweep.ptrs.size();
        if (!r.ptr_sweep.prefix_swept.empty()) std::cout << "   prefixes: " << r.ptr_sweep.prefix_swept;
        std::cout << "\n";
        if (opts.verbose)
            for (auto& [ip, name] : r.ptr_sweep.ptrs) std::cout << "    " << ip << "  -> " << name << "\n";
    }

    if (!r.wayback_urls_sample.empty()) {
        std::cout << color::bold << "\n:: Wayback Machine sample (" << r.wayback_urls_sample.size()
                   << " of possibly more)\n" << color::reset;
        for (auto& u : r.wayback_urls_sample) std::cout << "  " << u << "\n";
    }

    if (!r.dork_hits.empty()) {
        std::cout << color::bold << color::magenta << "\n:: Google dork hits\n" << color::reset;
        for (auto& h : r.dork_hits)
            std::cout << "  [" << h.query << "] " << h.title << "\n    " << h.url << "\n";
    }
    if (!r.dork_query_status.empty()) {
        size_t blocked = 0;
        for (auto& s : r.dork_query_status) if (s.blocked) ++blocked;
        if (blocked > 0) {
            std::cout << color::yellow << "\n  " << blocked << "/" << r.dork_query_status.size()
                       << " dork queries were blocked/rate-limited:" << color::reset << "\n";
            for (auto& s : r.dork_query_status)
                if (s.blocked) std::cout << "    \"" << s.query << "\": " << s.block_reason << "\n";
        }
    }

    if (!r.passive_source_status.empty()) {
        std::cout << color::bold << "\n:: Passive source status\n" << color::reset;
        for (auto& s : r.passive_source_status) {
            std::string tag = s.rate_limited ? (color::yellow + "RATE-LIMITED" + color::reset)
                             : s.ok           ? (color::green + "ok" + color::reset)
                                              : (color::red + "failed" + color::reset);
            std::cout << "  " << s.source_name << ": " << tag
                       << "  (" << s.items_found << " item(s))"
                       << (s.detail.empty() ? "" : ("  " + color::dim + s.detail + color::reset)) << "\n";
        }
    }

    std::cout << color::dim << "\nactive phase: " << r.active_duration.count()
              << "ms   passive phase: " << r.passive_duration.count() << "ms"
              << color::reset << "\n";
}

bool save_dns_enum_result(const DnsEnumResult& r, const std::string& path) {
    if (path.empty()) return false;
    json j;
    j["domain"] = r.domain;
    j["wildcard_dns"] = r.wildcard_dns;
    j["wildcard_ip_sample"] = r.wildcard_ip_sample;

    j["records"] = json::array();
    for (auto& rec : r.records)
        j["records"].push_back({{"type", dns_rrtype_name(rec.type)}, {"name", rec.name},
                                 {"value", rec.value}, {"ttl", rec.ttl}, {"source", rec.source}});

    j["axfr_attempts"] = json::array();
    for (auto& a : r.axfr_attempts)
        j["axfr_attempts"].push_back({{"ns_host", a.ns_host}, {"ns_ip", a.ns_ip},
                                       {"succeeded", a.succeeded}, {"records_pulled", a.records_pulled},
                                       {"error", a.error}});

    j["hosts"] = json::array();
    for (auto& [name, h] : r.hosts) {
        json hj;
        hj["hostname"] = h.hostname;
        hj["ips"] = h.ips;
        hj["wildcard_suspect"] = h.wildcard_suspect;
        json srcs = json::array();
        for (auto s : h.sources) {
            switch (s) {
                case DiscoverySource::ActiveBruteForce: srcs.push_back("active_bruteforce"); break;
                case DiscoverySource::ActiveMutatedBruteForce: srcs.push_back("active_mutated_bruteforce"); break;
                case DiscoverySource::ActiveZoneTransfer: srcs.push_back("active_axfr"); break;
                case DiscoverySource::ActiveRecordChain: srcs.push_back("active_record_chain"); break;
                case DiscoverySource::ActiveSrv: srcs.push_back("active_srv"); break;
                case DiscoverySource::ActivePtrSweep: srcs.push_back("active_ptr_sweep"); break;
                case DiscoverySource::ActiveNsecWalk: srcs.push_back("active_nsec_walk"); break;
                case DiscoverySource::PassiveCertLog: srcs.push_back("passive_crtsh"); break;
                case DiscoverySource::PassiveCertspotter: srcs.push_back("passive_certspotter"); break;
                case DiscoverySource::PassiveWayback: srcs.push_back("passive_wayback"); break;
                case DiscoverySource::PassiveRdap: srcs.push_back("passive_rdap"); break;
                case DiscoverySource::PassiveHackertarget: srcs.push_back("passive_hackertarget"); break;
                case DiscoverySource::PassiveRapidDns: srcs.push_back("passive_rapiddns"); break;
                case DiscoverySource::PassiveOtx: srcs.push_back("passive_otx"); break;
                case DiscoverySource::PassiveUrlscan: srcs.push_back("passive_urlscan"); break;
                case DiscoverySource::PassiveDork: srcs.push_back("passive_dork"); break;
                case DiscoverySource::PassiveRipestat: srcs.push_back("passive_ripestat"); break;
            }
        }
        hj["sources"] = srcs;
        j["hosts"].push_back(hj);
    }

    j["srv_findings"] = json::array();
    for (auto& s : r.srv_findings)
        j["srv_findings"].push_back({{"service", s.service}, {"target", s.target}, {"port", s.port},
                                      {"priority", s.priority}, {"weight", s.weight}});

    j["tlsa_findings"] = json::array();
    for (auto& t : r.tlsa_findings)
        j["tlsa_findings"].push_back({{"service", t.service}, {"cert_usage", t.cert_usage},
                                       {"selector", t.selector}, {"matching_type", t.matching_type},
                                       {"data_hex", t.data_hex}});

    j["takeover_findings"] = json::array();
    for (auto& f : r.takeover_findings)
        j["takeover_findings"].push_back({{"hostname", f.hostname}, {"cname_chain", f.cname_chain},
                                           {"matched_service", f.matched_service},
                                           {"http_confirmed", f.http_confirmed},
                                           {"fingerprint_snippet", f.fingerprint_snippet}});

    j["mail_security"] = {
        {"spf", {{"present", r.mail_security.has_spf}, {"record", r.mail_security.spf_record}}},
        {"dmarc", {{"present", r.mail_security.has_dmarc}, {"record", r.mail_security.dmarc_record}}},
        {"bimi", {{"present", r.mail_security.has_bimi}, {"record", r.mail_security.bimi_record}}},
        {"mta_sts_dns", {{"present", r.mail_security.has_mta_sts_dns}, {"record", r.mail_security.mta_sts_dns_record}}},
        {"tls_rpt", {{"present", r.mail_security.has_tls_rpt}, {"record", r.mail_security.tls_rpt_record}}},
        {"mx_hosts", r.mail_security.mx_hosts},
    };
    json dkim = json::array();
    for (auto& [sel, val] : r.mail_security.dkim_selectors_found)
        dkim.push_back({{"selector", sel}, {"record", val}});
    j["mail_security"]["dkim_selectors_found"] = dkim;

    j["dnssec"] = {{"dnskey_present", r.dnssec.dnskey_present}, {"dnskey_count", r.dnssec.dnskey_count},
                    {"rrsig_seen", r.dnssec.rrsig_seen}, {"ds_present_at_parent", r.dnssec.ds_present_at_parent}};
    j["nsec_walk"] = {{"attempted", r.nsec_walk.attempted}, {"zone_signed", r.nsec_walk.zone_signed},
                       {"wrapped", r.nsec_walk.wrapped}, {"names", r.nsec_walk.names_from_bitmap_gaps},
                       {"note", r.nsec_walk.note}};

    j["whois"] = {{"found", r.domain_whois.found}, {"registrar", r.domain_whois.registrar},
                   {"created", r.domain_whois.created}, {"updated", r.domain_whois.updated},
                   {"expires", r.domain_whois.expires}, {"statuses", r.domain_whois.statuses},
                   {"nameservers", r.domain_whois.nameservers}};

    j["asn_lookups"] = json::array();
    for (auto& a : r.asn_lookups)
        j["asn_lookups"].push_back({{"ip", a.ip}, {"asn", a.asn}, {"as_name", a.as_name},
                                     {"prefix", a.prefix}, {"country", a.country},
                                     {"registry", a.registry}, {"allocated", a.allocated},
                                     {"source", a.source}});

    j["sibling_prefixes"] = json::array();
    for (auto& p : r.sibling_prefixes)
        j["sibling_prefixes"].push_back({{"asn", p.asn}, {"prefix", p.prefix}, {"description", p.description}});

    j["ptr_sweep"] = {{"attempted", r.ptr_sweep.attempted}, {"prefix_swept", r.ptr_sweep.prefix_swept},
                       {"hosts_checked", r.ptr_sweep.hosts_checked}};
    json ptr_list = json::array();
    for (auto& [ip, name] : r.ptr_sweep.ptrs) ptr_list.push_back({{"ip", ip}, {"ptr", name}});
    j["ptr_sweep"]["results"] = ptr_list;

    j["dork_hits"] = json::array();
    for (auto& h : r.dork_hits)
        j["dork_hits"].push_back({{"query", h.query}, {"title", h.title}, {"url", h.url}, {"snippet", h.snippet}});
    j["dork_query_status"] = json::array();
    for (auto& s : r.dork_query_status)
        j["dork_query_status"].push_back({{"query", s.query}, {"http_status", s.http_status},
                                           {"blocked", s.blocked}, {"block_reason", s.block_reason},
                                           {"result_count", s.result_count}});

    j["passive_source_status"] = json::array();
    for (auto& s : r.passive_source_status)
        j["passive_source_status"].push_back({{"source", s.source_name}, {"ok", s.ok},
                                                {"rate_limited", s.rate_limited}, {"detail", s.detail},
                                                {"items_found", s.items_found}});

    j["wayback_sample"] = r.wayback_urls_sample;
    j["timing_ms"] = {{"active", r.active_duration.count()}, {"passive", r.passive_duration.count()}};

    std::ofstream out(path);
    if (!out) return false;
    out << j.dump(2);
    return true;
}
