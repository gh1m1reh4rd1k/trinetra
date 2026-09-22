#include "discover.hpp"

#include <curl/curl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern std::atomic<bool> terminate_flag;

// Defined in handler.cpp (populated by --dns-servers) with external linkage;
// reused by --owner below so it respects any resolvers the user already chose.
extern std::vector<std::string> g_dns_servers;

namespace discover {

static const Country kCountries[] = {
    {"AF","AFG","Afghanistan",""},
    {"AL","ALB","Albania",""},
    {"DZ","DZA","Algeria",""},
    {"AD","AND","Andorra",""},
    {"AO","AGO","Angola",""},
    {"AG","ATG","Antigua and Barbuda","antigua|barbuda"},
    {"AR","ARG","Argentina",""},
    {"AM","ARM","Armenia",""},
    {"AU","AUS","Australia",""},
    {"AT","AUT","Austria",""},
    {"AZ","AZE","Azerbaijan",""},
    {"BS","BHS","Bahamas","the bahamas"},
    {"BH","BHR","Bahrain",""},
    {"BD","BGD","Bangladesh",""},
    {"BB","BRB","Barbados",""},
    {"BY","BLR","Belarus","byelorussia"},
    {"BE","BEL","Belgium",""},
    {"BZ","BLZ","Belize",""},
    {"BJ","BEN","Benin",""},
    {"BT","BTN","Bhutan",""},
    {"BO","BOL","Bolivia","plurinational state of bolivia"},
    {"BA","BIH","Bosnia and Herzegovina","bosnia|herzegovina|bosnia herzegovina"},
    {"BW","BWA","Botswana",""},
    {"BR","BRA","Brazil","brasil"},
    {"BN","BRN","Brunei","brunei darussalam"},
    {"BG","BGR","Bulgaria",""},
    {"BF","BFA","Burkina Faso",""},
    {"BI","BDI","Burundi",""},
    {"CV","CPV","Cabo Verde","cape verde"},
    {"KH","KHM","Cambodia","kampuchea"},
    {"CM","CMR","Cameroon",""},
    {"CA","CAN","Canada",""},
    {"CF","CAF","Central African Republic","car"},
    {"TD","TCD","Chad",""},
    {"CL","CHL","Chile",""},
    {"CN","CHN","China","prc|peoples republic of china|mainland china"},
    {"CO","COL","Colombia",""},
    {"KM","COM","Comoros",""},
    {"CG","COG","Congo","republic of the congo|congo brazzaville|congo republic"},
    {"CD","COD","Democratic Republic of the Congo","drc|dr congo|congo kinshasa|congo democratic republic|zaire"},
    {"CR","CRI","Costa Rica",""},
    {"CI","CIV","Cote d'Ivoire","ivory coast|cote divoire"},
    {"HR","HRV","Croatia",""},
    {"CU","CUB","Cuba",""},
    {"CY","CYP","Cyprus",""},
    {"CZ","CZE","Czechia","czech republic"},
    {"DK","DNK","Denmark",""},
    {"DJ","DJI","Djibouti",""},
    {"DM","DMA","Dominica",""},
    {"DO","DOM","Dominican Republic","dominicana"},
    {"EC","ECU","Ecuador",""},
    {"EG","EGY","Egypt",""},
    {"SV","SLV","El Salvador",""},
    {"GQ","GNQ","Equatorial Guinea",""},
    {"ER","ERI","Eritrea",""},
    {"EE","EST","Estonia",""},
    {"SZ","SWZ","Eswatini","swaziland"},
    {"ET","ETH","Ethiopia",""},
    {"FJ","FJI","Fiji",""},
    {"FI","FIN","Finland",""},
    {"FR","FRA","France",""},
    {"GA","GAB","Gabon",""},
    {"GM","GMB","Gambia","the gambia"},
    {"GE","GEO","Georgia","sakartvelo"},
    {"DE","DEU","Germany","deutschland"},
    {"GH","GHA","Ghana",""},
    {"GR","GRC","Greece","hellas"},
    {"GD","GRD","Grenada",""},
    {"GT","GTM","Guatemala",""},
    {"GN","GIN","Guinea",""},
    {"GW","GNB","Guinea-Bissau","guinea bissau"},
    {"GY","GUY","Guyana",""},
    {"HT","HTI","Haiti",""},
    {"HN","HND","Honduras",""},
    {"HU","HUN","Hungary",""},
    {"IS","ISL","Iceland",""},
    {"IN","IND","India","bharat"},
    {"ID","IDN","Indonesia",""},
    {"IR","IRN","Iran","islamic republic of iran|persia"},
    {"IQ","IRQ","Iraq",""},
    {"IE","IRL","Ireland","eire|republic of ireland"},
    {"IL","ISR","Israel",""},
    {"IT","ITA","Italy","italia"},
    {"JM","JAM","Jamaica",""},
    {"JP","JPN","Japan","nippon"},
    {"JO","JOR","Jordan",""},
    {"KZ","KAZ","Kazakhstan",""},
    {"KE","KEN","Kenya",""},
    {"KI","KIR","Kiribati",""},
    {"KW","KWT","Kuwait",""},
    {"KG","KGZ","Kyrgyzstan","kirghizia|kyrgyz republic"},
    {"LA","LAO","Laos","lao|lao pdr|lao peoples democratic republic"},
    {"LV","LVA","Latvia",""},
    {"LB","LBN","Lebanon",""},
    {"LS","LSO","Lesotho",""},
    {"LR","LBR","Liberia",""},
    {"LY","LBY","Libya",""},
    {"LI","LIE","Liechtenstein",""},
    {"LT","LTU","Lithuania",""},
    {"LU","LUX","Luxembourg",""},
    {"MG","MDG","Madagascar",""},
    {"MW","MWI","Malawi",""},
    {"MY","MYS","Malaysia",""},
    {"MV","MDV","Maldives",""},
    {"ML","MLI","Mali",""},
    {"MT","MLT","Malta",""},
    {"MH","MHL","Marshall Islands",""},
    {"MR","MRT","Mauritania",""},
    {"MU","MUS","Mauritius",""},
    {"MX","MEX","Mexico",""},
    {"FM","FSM","Micronesia","federated states of micronesia"},
    {"MD","MDA","Moldova","republic of moldova"},
    {"MC","MCO","Monaco",""},
    {"MN","MNG","Mongolia",""},
    {"ME","MNE","Montenegro",""},
    {"MA","MAR","Morocco",""},
    {"MZ","MOZ","Mozambique",""},
    {"MM","MMR","Myanmar","burma"},
    {"NA","NAM","Namibia",""},
    {"NR","NRU","Nauru",""},
    {"NP","NPL","Nepal",""},
    {"NL","NLD","Netherlands","holland|the netherlands"},
    {"NZ","NZL","New Zealand","aotearoa"},
    {"NI","NIC","Nicaragua",""},
    {"NE","NER","Niger",""},
    {"NG","NGA","Nigeria",""},
    {"KP","PRK","North Korea","dprk|democratic peoples republic of korea|korea north|n korea"},
    {"MK","MKD","North Macedonia","macedonia"},
    {"NO","NOR","Norway",""},
    {"OM","OMN","Oman",""},
    {"PK","PAK","Pakistan",""},
    {"PW","PLW","Palau",""},
    {"PA","PAN","Panama",""},
    {"PG","PNG","Papua New Guinea",""},
    {"PY","PRY","Paraguay",""},
    {"PE","PER","Peru",""},
    {"PH","PHL","Philippines","the philippines"},
    {"PL","POL","Poland",""},
    {"PT","PRT","Portugal",""},
    {"QA","QAT","Qatar",""},
    {"RO","ROU","Romania",""},
    {"RU","RUS","Russia","russian federation"},
    {"RW","RWA","Rwanda",""},
    {"KN","KNA","Saint Kitts and Nevis","st kitts and nevis|saint kitts|st kitts|st christopher|kitts and nevis"},
    {"LC","LCA","Saint Lucia","st lucia"},
    {"VC","VCT","Saint Vincent and the Grenadines","st vincent and the grenadines|saint vincent|st vincent|grenadines"},
    {"WS","WSM","Samoa",""},
    {"SM","SMR","San Marino",""},
    {"ST","STP","Sao Tome and Principe","sao tome|sao tome e principe"},
    {"SA","SAU","Saudi Arabia","ksa"},
    {"SN","SEN","Senegal",""},
    {"RS","SRB","Serbia",""},
    {"SC","SYC","Seychelles",""},
    {"SL","SLE","Sierra Leone",""},
    {"SG","SGP","Singapore",""},
    {"SK","SVK","Slovakia","slovak republic"},
    {"SI","SVN","Slovenia",""},
    {"SB","SLB","Solomon Islands",""},
    {"SO","SOM","Somalia",""},
    {"ZA","ZAF","South Africa","rsa"},
    {"KR","KOR","South Korea","republic of korea|korea south|s korea|rok"},
    {"SS","SSD","South Sudan",""},
    {"ES","ESP","Spain","espana"},
    {"LK","LKA","Sri Lanka","ceylon"},
    {"SD","SDN","Sudan",""},
    {"SR","SUR","Suriname",""},
    {"SE","SWE","Sweden",""},
    {"CH","CHE","Switzerland","swiss"},
    {"SY","SYR","Syria","syrian arab republic"},
    {"TJ","TJK","Tajikistan",""},
    {"TZ","TZA","Tanzania","united republic of tanzania"},
    {"TH","THA","Thailand","siam"},
    {"TL","TLS","Timor-Leste","east timor|timor leste"},
    {"TG","TGO","Togo",""},
    {"TO","TON","Tonga",""},
    {"TT","TTO","Trinidad and Tobago","trinidad|tobago"},
    {"TN","TUN","Tunisia",""},
    {"TR","TUR","Turkiye","turkey"},
    {"TM","TKM","Turkmenistan",""},
    {"TV","TUV","Tuvalu",""},
    {"UG","UGA","Uganda",""},
    {"UA","UKR","Ukraine",""},
    {"AE","ARE","United Arab Emirates","uae|emirates"},
    {"GB","GBR","United Kingdom","uk|britain|great britain|united kingdom of great britain and northern ireland"},
    {"US","USA","United States","usa|america|united states of america|the united states|us of a"},
    {"UY","URY","Uruguay",""},
    {"UZ","UZB","Uzbekistan",""},
    {"VU","VUT","Vanuatu",""},
    {"VE","VEN","Venezuela","bolivarian republic of venezuela"},
    {"VN","VNM","Vietnam","viet nam"},
    {"YE","YEM","Yemen",""},
    {"ZM","ZMB","Zambia",""},
    {"ZW","ZWE","Zimbabwe",""},
    {"VA","VAT","Vatican City","holy see|vatican"},
    {"PS","PSE","Palestine","state of palestine|palestinian territories|palestinian territory"},
    {"TW","TWN","Taiwan","republic of china|chinese taipei|formosa"},
    {"HK","HKG","Hong Kong","hong kong sar"},
    {"MO","MAC","Macao","macau|macao sar"},
    {"XK","XKX","Kosovo",""},
};
static constexpr size_t kCountryCount = sizeof(kCountries) / sizeof(kCountries[0]);
static_assert(kCountryCount == 199, "country table must hold 195 UN members/observers + 4 extras");
size_t country_count() { return kCountryCount; }

namespace {

inline bool is_alnum_ascii(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
inline char lower_ascii(char c) { return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c; }
std::string normalize(std::string_view in) {
    static constexpr char kLatin1[65] =
        "AAAAAAACEEEEIIIIDNOOOOO*OUUUUYTs"
        "aaaaaaaceeeeiiiidnooooo/ouuuuyty";
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(in[i]);
        if (c < 0x80) {
            if (is_alnum_ascii(c)) out.push_back(lower_ascii(static_cast<char>(c)));
        } else if (c == 0xC3 && i + 1 < in.size()) {
            unsigned char d = static_cast<unsigned char>(in[i + 1]);
            if (d >= 0x80 && d <= 0xBF) {
                char m = kLatin1[d - 0x80];
                if (is_alnum_ascii(static_cast<unsigned char>(m))) out.push_back(lower_ascii(m));
                ++i;
            }
        }
    }
    return out;
}

int edit_distance(std::string_view a, std::string_view b, int limit) {
    const int la = static_cast<int>(a.size()), lb = static_cast<int>(b.size());
    if (std::abs(la - lb) > limit) return limit + 1;
    std::vector<int> prev(lb + 1), cur(lb + 1);
    for (int j = 0; j <= lb; ++j) prev[j] = j;
    for (int i = 1; i <= la; ++i) {
        cur[0] = i;
        int row_min = cur[0];
        for (int j = 1; j <= lb; ++j) {
            int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
            row_min = std::min(row_min, cur[j]);
        }
        if (row_min > limit) return limit + 1;
        std::swap(prev, cur);
    }
    return prev[lb];
}

struct Index {
    std::unordered_map<std::string, const Country*>              exact;   
    std::vector<std::pair<std::string, const Country*>>         names;  
    const Country*                                              by_iso2[26][26] = {};

    void add(const std::string& key, const Country* c, bool is_name) {
        if (key.empty()) return;
        exact.emplace(key, c);                       
        if (is_name) names.emplace_back(key, c);
    }

    Index() {
        exact.reserve(kCountryCount * 6);
        names.reserve(kCountryCount * 3);
        for (const Country& c : kCountries) {
            by_iso2[c.iso2[0] - 'A'][c.iso2[1] - 'A'] = &c;
            add(normalize(c.iso2), &c, false);
            add(normalize(c.iso3), &c, false);
            add(normalize(c.name), &c, true);
            std::string_view al(c.aliases);
            while (!al.empty()) {
                size_t bar = al.find('|');
                std::string_view one = al.substr(0, bar);
                add(normalize(one), &c, true);
                if (bar == std::string_view::npos) break;
                al.remove_prefix(bar + 1);
            }
        }
    }
};

const Index& index() {
    static const Index idx;    
    return idx;
}

std::string_view trim_sv(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) s.remove_prefix(1);
    while (!s.empty() && (s.back()  == ' ' || s.back()  == '\t' || s.back()  == '\r' || s.back()  == '\n')) s.remove_suffix(1);
    return s;
}

void push_unique(std::vector<const Country*>& v, const Country* c) {
    if (std::find(v.begin(), v.end(), c) == v.end()) v.push_back(c);
}

} 

CountryMatch resolve_country(const std::string& input) {
    CountryMatch r;
    const Index& idx = index();
    std::string_view raw = trim_sv(input);
    if (raw.size() == 2 && is_alnum_ascii(raw[0]) && is_alnum_ascii(raw[1]) &&
        !(raw[0] >= '0' && raw[0] <= '9') && !(raw[1] >= '0' && raw[1] <= '9')) {
        int a = std::toupper(static_cast<unsigned char>(raw[0])) - 'A';
        int b = std::toupper(static_cast<unsigned char>(raw[1])) - 'A';
        if (const Country* c = idx.by_iso2[a][b]) { r.country = c; r.how = CountryMatch::How::Exact; return r; }
    }

    const std::string n = normalize(raw);
    if (n.empty()) return r;
    if (auto it = idx.exact.find(n); it != idx.exact.end()) {
        r.country = it->second; r.how = CountryMatch::How::Exact; return r;
    }
    std::vector<const Country*> prefix_hits;
    if (n.size() >= 3) {
        for (const auto& [key, c] : idx.names)
            if (key.size() >= n.size() && key.compare(0, n.size(), n) == 0) push_unique(prefix_hits, c);
        if (prefix_hits.size() == 1) { r.country = prefix_hits[0]; r.how = CountryMatch::How::Prefix; return r; }
    }
    if (n.size() >= 4) {
        const int max_d = (n.size() >= 8) ? 2 : 1;
        int best = max_d + 1;
        std::vector<const Country*> best_c;
        for (const auto& [key, c] : idx.names) {
            int d = edit_distance(n, key, max_d);
            if (d > max_d) continue;
            if (d < best) { best = d; best_c.clear(); best_c.push_back(c); }
            else if (d == best) push_unique(best_c, c);
        }
        if (best_c.size() == 1) { r.country = best_c[0]; r.how = CountryMatch::How::Fuzzy; return r; }
    }
    for (const Country* c : prefix_hits) { if (r.suggestions.size() < 8) push_unique(r.suggestions, c); }
    if (n.size() >= 3) {
        for (const auto& [key, c] : idx.names) {
            if (r.suggestions.size() >= 8) break;
            if (key.find(n) != std::string::npos) push_unique(r.suggestions, c);
        }
    }
    if (r.suggestions.size() < 5) {
        std::vector<std::pair<int, const Country*>> scored;
        for (const auto& [key, c] : idx.names) {
            int d = edit_distance(n, key, 3);
            if (d <= 3) scored.emplace_back(d, c);
        }
        std::sort(scored.begin(), scored.end(),
                  [](const auto& x, const auto& y) { return x.first < y.first; });
        for (const auto& [d, c] : scored) {
            (void)d;
            if (r.suggestions.size() >= 5) break;
            push_unique(r.suggestions, c);
        }
    }
    return r;
}

namespace {

__extension__ typedef unsigned __int128 u128;

using V4 = std::pair<uint32_t, uint32_t>;         
struct V6 { u128 lo, hi; };                       

bool parse_u64(std::string_view s, uint64_t& out) {
    if (s.empty()) return false;
    auto r = std::from_chars(s.data(), s.data() + s.size(), out);
    return r.ec == std::errc() && r.ptr == s.data() + s.size();
}

bool parse_v4_addr(std::string_view s, uint32_t& host) {
    if (s.empty() || s.size() > 15) return false;
    char buf[16];
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = '\0';
    in_addr a{};
    if (inet_pton(AF_INET, buf, &a) != 1) return false;
    host = ntohl(a.s_addr);
    return true;
}

bool parse_v6_addr(std::string_view s, u128& host) {
    if (s.empty() || s.size() > 45) return false;
    char buf[48];
    std::memcpy(buf, s.data(), s.size());
    buf[s.size()] = '\0';
    in6_addr a{};
    if (inet_pton(AF_INET6, buf, &a) != 1) return false;
    u128 v = 0;
    for (int i = 0; i < 16; ++i) v = (v << 8) | a.s6_addr[i];
    host = v;
    return true;
}

V4 v4_from_prefix(uint32_t base, unsigned len) {                  
    uint32_t mask = 0xFFFFFFFFu << (32 - len);
    uint32_t lo = base & mask;
    return {lo, lo | ~mask};
}

V6 v6_from_prefix(u128 base, unsigned len) {                      
    u128 host_mask = (static_cast<u128>(1) << (128 - len)) - 1;
    u128 lo = base & ~host_mask;
    return {lo, lo | host_mask};
}

bool parse_v4_cidr(std::string_view s, V4& out) {
    size_t slash = s.find('/');
    if (slash == std::string_view::npos) return false;
    uint32_t base;
    uint64_t len;
    if (!parse_v4_addr(s.substr(0, slash), base)) return false;
    if (!parse_u64(s.substr(slash + 1), len) || len < 1 || len > 32) return false;
    out = v4_from_prefix(base, static_cast<unsigned>(len));
    return true;
}

bool parse_v6_cidr(std::string_view s, V6& out) {
    size_t slash = s.find('/');
    if (slash == std::string_view::npos) return false;
    u128 base;
    uint64_t len;
    if (!parse_v6_addr(s.substr(0, slash), base)) return false;
    if (!parse_u64(s.substr(slash + 1), len) || len < 1 || len > 128) return false;
    out = v6_from_prefix(base, static_cast<unsigned>(len));
    return true;
}

int ctz128(u128 x) {                                   
    uint64_t lo = static_cast<uint64_t>(x);
    return lo ? __builtin_ctzll(lo) : 64 + __builtin_ctzll(static_cast<uint64_t>(x >> 64));
}
int floor_log2_128(u128 x) {                           
    uint64_t hi = static_cast<uint64_t>(x >> 64);
    return hi ? 127 - __builtin_clzll(hi) : 63 - __builtin_clzll(static_cast<uint64_t>(x));
}

std::vector<V4> merge_v4(std::vector<V4> v) {
    std::sort(v.begin(), v.end());
    std::vector<V4> out;
    out.reserve(v.size());
    for (const V4& iv : v) {
        if (!out.empty() && static_cast<uint64_t>(iv.first) <= static_cast<uint64_t>(out.back().second) + 1)
            out.back().second = std::max(out.back().second, iv.second);
        else
            out.push_back(iv);
    }
    return out;
}

std::vector<V6> merge_v6(std::vector<V6> v) {
    std::sort(v.begin(), v.end(), [](const V6& a, const V6& b) { return a.lo < b.lo; });
    std::vector<V6> out;
    out.reserve(v.size());
    const u128 kMax = ~static_cast<u128>(0);
    for (const V6& iv : v) {
        if (!out.empty() && (out.back().hi == kMax || iv.lo <= out.back().hi + 1))
            out.back().hi = std::max(out.back().hi, iv.hi);
        else
            out.push_back(iv);
    }
    return out;
}

// `samples`, when non-null, records one (cidr-string, sample-address) pair per
// emitted line -- a single representative host inside that block, used later
// to look up who *owns* the block without touching every address in it.
// Purely additive: `out` is filled identically whether or not `samples` is
// passed, so every existing caller (including the self-test) is unaffected.
size_t emit_v4(V4 iv, std::string& out, std::vector<std::pair<std::string, uint32_t>>* samples = nullptr) {
    size_t lines = 0;
    uint64_t cur = iv.first, end = iv.second;
    char ip[INET_ADDRSTRLEN];
    while (cur <= end) {
        uint64_t remaining = end - cur + 1;
        uint64_t align = cur ? (cur & (~cur + 1)) : (1ULL << 32);
        uint64_t fit   = 1ULL << (63 - __builtin_clzll(remaining));
        uint64_t size  = std::min(align, fit);
        unsigned prefix = 32 - static_cast<unsigned>(__builtin_ctzll(size));
        in_addr a{};
        a.s_addr = htonl(static_cast<uint32_t>(cur));
        inet_ntop(AF_INET, &a, ip, sizeof(ip));
        out += ip;
        out += '/';
        out += std::to_string(prefix);
        out += '\n';
        if (samples) {
            uint32_t sample = static_cast<uint32_t>(cur + (size > 1 ? 1 : 0));
            samples->emplace_back(std::string(ip) + "/" + std::to_string(prefix), sample);
        }
        ++lines;
        cur += size;
    }
    return lines;
}

size_t emit_v6(V6 iv, std::string& out, std::vector<std::pair<std::string, u128>>* samples = nullptr) {
    size_t lines = 0;
    char ip[INET6_ADDRSTRLEN];
    const u128 kMax = ~static_cast<u128>(0);
    u128 cur = iv.lo;
    const u128 end = iv.hi;
    for (;;) {
        int take;
        if (cur == 0 && end == kMax) {
            take = 128;
        } else {
            u128 remaining = end - cur + 1;
            int align = (cur == 0) ? 128 : ctz128(cur);
            int fit   = floor_log2_128(remaining);
            take = std::min(align, fit);
        }
        in6_addr a{};
        for (int i = 0; i < 16; ++i) a.s6_addr[i] = static_cast<uint8_t>(cur >> (8 * (15 - i)));
        inet_ntop(AF_INET6, &a, ip, sizeof(ip));
        out += ip;
        out += '/';
        out += std::to_string(128 - take);
        out += '\n';
        if (samples) {
            u128 sample = cur + (take > 0 ? static_cast<u128>(1) : static_cast<u128>(0));
            samples->emplace_back(std::string(ip) + "/" + std::to_string(128 - take), sample);
        }
        ++lines;
        if (take >= 128) break;
        u128 step = static_cast<u128>(1) << take;
        if (end - cur < step) break;                 
        cur += step;
        if (cur > end || cur == 0) break;
    }
    return lines;
}

}  

// ---------------------------------------------------------------------------
// --owner: who does this range belong to?
//
// Rather than looking up every address in a discovered range, one sample
// address per emitted range is checked (see the `samples` param on emit_v4 /
// emit_v6 above). The sample is resolved via Team Cymru's DNS-based IP-to-ASN
// service (the standard, lightweight way to map an address to the network
// that announces it -- the same technique nmap's asn-query script and mtr
// use): a TXT query on the reversed address under origin.asn.cymru.com
// returns the announcing ASN, then a second TXT query on that ASN returns
// the organisation name. If no ASN is announced for the address (unrouted /
// reserved space), this falls back to a classic PTR lookup so something is
// still shown when possible.
//
// This is a small, self-contained DNS client (own packet building/parsing),
// matching how the rest of discover.cpp already does its own networking
// (curl for HTTP) rather than reaching into scan.cpp/dns_enum.cpp internals.
namespace {

std::vector<std::string> owner_system_resolvers() {
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

std::string trim_field(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Decodes a (possibly compressed) DNS name starting at `pos` in `buf`.
// Returns the position immediately after the name *in the original stream*
// (i.e. after the first compression pointer taken, if any), per RFC 1035.
size_t decode_dns_name(const uint8_t* buf, size_t len, size_t pos, std::string& out) {
    out.clear();
    size_t cur = pos;
    size_t after_first_jump = std::string::npos;
    int jumps = 0;
    while (cur < len) {
        uint8_t c = buf[cur];
        if (c == 0) { cur += 1; break; }
        if ((c & 0xC0) == 0xC0) {
            if (cur + 1 >= len || ++jumps > 20) return len;
            size_t ptr = (static_cast<size_t>(c & 0x3F) << 8) | buf[cur + 1];
            if (after_first_jump == std::string::npos) after_first_jump = cur + 2;
            cur = ptr;
            continue;
        }
        size_t label_len = c;
        cur += 1;
        if (cur + label_len > len) return len;
        if (!out.empty()) out += '.';
        out.append(reinterpret_cast<const char*>(buf + cur), label_len);
        cur += label_len;
    }
    return (after_first_jump != std::string::npos) ? after_first_jump : cur;
}

std::vector<uint8_t> build_dns_query(uint16_t id, const std::string& qname, uint16_t qtype) {
    std::vector<uint8_t> pkt;
    pkt.reserve(qname.size() + 18);
    auto put16 = [&](uint16_t v) { uint16_t n = htons(v); pkt.push_back(static_cast<uint8_t>(n & 0xFF)); pkt.push_back(static_cast<uint8_t>(n >> 8)); };
    // header: id, flags(RD=1), qdcount=1, an/ns/ar=0
    pkt.push_back(static_cast<uint8_t>(id >> 8)); pkt.push_back(static_cast<uint8_t>(id & 0xFF));
    put16(0x0100);
    put16(1); put16(0); put16(0); put16(0);
    size_t start = 0;
    while (start <= qname.size()) {
        size_t dot = qname.find('.', start);
        size_t end = (dot == std::string::npos) ? qname.size() : dot;
        size_t label_len = end - start;
        if (label_len > 63) return {};
        pkt.push_back(static_cast<uint8_t>(label_len));
        pkt.insert(pkt.end(), qname.begin() + start, qname.begin() + end);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    pkt.push_back(0);
    put16(qtype);
    put16(1); // IN
    return pkt;
}

// Extracts the first RR of type `want_type` from the answer section.
bool parse_dns_answer(const uint8_t* buf, size_t len, uint16_t want_type,
                       size_t answers_start, uint16_t ancount, std::string& out) {
    size_t pos = answers_start;
    for (uint16_t i = 0; i < ancount; ++i) {
        std::string name;
        pos = decode_dns_name(buf, len, pos, name);
        if (pos + 10 > len) return false;
        uint16_t rtype, rdlen;
        memcpy(&rtype, buf + pos, 2); rtype = ntohs(rtype); pos += 2;
        pos += 2;  // class
        pos += 4;  // ttl
        memcpy(&rdlen, buf + pos, 2); rdlen = ntohs(rdlen); pos += 2;
        if (pos + rdlen > len) return false;
        if (rtype == want_type) {
            if (want_type == 16) {  // TXT: one or more length-prefixed strings
                std::string txt;
                size_t p = pos, end = pos + rdlen;
                while (p < end) {
                    uint8_t slen = buf[p++];
                    if (p + slen > end) break;
                    txt.append(reinterpret_cast<const char*>(buf + p), slen);
                    p += slen;
                }
                out = txt;
                return true;
            }
            if (want_type == 12) {  // PTR
                std::string name2;
                decode_dns_name(buf, len, pos, name2);
                out = name2;
                return true;
            }
        }
        pos += rdlen;
    }
    return false;
}

bool udp_dns_query_one(const std::string& server, const std::string& qname, uint16_t qtype,
                        int timeout_ms, std::string& out) {
    in_addr a4{}; in6_addr a6{};
    int fam = 0;
    if (inet_pton(AF_INET, server.c_str(), &a4) == 1) fam = AF_INET;
    else if (inet_pton(AF_INET6, server.c_str(), &a6) == 1) fam = AF_INET6;
    else return false;

    uint16_t id = static_cast<uint16_t>(std::random_device{}());
    std::vector<uint8_t> pkt = build_dns_query(id, qname, qtype);
    if (pkt.empty()) return false;

    int fd = socket(fam, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    bool sent;
    if (fam == AF_INET) {
        sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(53); sa.sin_addr = a4;
        sent = sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == static_cast<ssize_t>(pkt.size());
    } else {
        sockaddr_in6 sa{}; sa.sin6_family = AF_INET6; sa.sin6_port = htons(53); sa.sin6_addr = a6;
        sent = sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == static_cast<ssize_t>(pkt.size());
    }
    if (!sent) { close(fd); return false; }

    pollfd pfd{fd, POLLIN, 0};
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) { close(fd); return false; }

    uint8_t buf[2048];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    close(fd);
    if (n < 12) return false;
    const size_t len = static_cast<size_t>(n);

    uint16_t rid; memcpy(&rid, buf, 2);
    if (ntohs(rid) != id) return false;
    uint16_t rflags; memcpy(&rflags, buf + 2, 2); rflags = ntohs(rflags);
    if ((rflags & 0x000F) != 0) return false;  // rcode != NOERROR
    uint16_t qdc, anc;
    memcpy(&qdc, buf + 4, 2); qdc = ntohs(qdc);
    memcpy(&anc, buf + 6, 2); anc = ntohs(anc);
    if (anc == 0) return false;

    size_t pos = 12;
    for (uint16_t i = 0; i < qdc; ++i) {
        std::string dummy;
        pos = decode_dns_name(buf, len, pos, dummy);
        pos += 4;  // qtype + qclass
        if (pos > len) return false;
    }
    return parse_dns_answer(buf, len, qtype, pos, anc, out);
}

bool udp_dns_query(const std::vector<std::string>& servers, const std::string& qname,
                    uint16_t qtype, int timeout_ms, std::string& out) {
    for (const auto& srv : servers) {
        if (terminate_flag.load(std::memory_order_relaxed)) return false;
        if (udp_dns_query_one(srv, qname, qtype, timeout_ms, out) && !out.empty()) return true;
    }
    return false;
}

std::string cymru_qname_v4(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip) & 0xFF) << "." << ((ip >> 8) & 0xFF) << "." << ((ip >> 16) & 0xFF) << "." << ((ip >> 24) & 0xFF)
       << ".origin.asn.cymru.com";
    return ss.str();
}
std::string ptr_qname_v4(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip) & 0xFF) << "." << ((ip >> 8) & 0xFF) << "." << ((ip >> 16) & 0xFF) << "." << ((ip >> 24) & 0xFF)
       << ".in-addr.arpa";
    return ss.str();
}
// Both cymru's origin6 zone and ip6.arpa use the same nibble-reversed form.
std::string nibble_reversed_v6(u128 ip) {
    std::ostringstream ss;
    for (int i = 0; i < 32; ++i) ss << std::hex << static_cast<int>((ip >> (i * 4)) & 0xF) << ".";
    return ss.str();
}
std::string cymru_qname_v6(u128 ip) { return nibble_reversed_v6(ip) + "origin6.asn.cymru.com"; }
std::string ptr_qname_v6(u128 ip)   { return nibble_reversed_v6(ip) + "ip6.arpa"; }

struct OwnerResult { std::string label; bool ok = false; };

// Given an ASN-lookup TXT reply ("ASN | PREFIX | CC | REGISTRY | DATE") and a
// PTR-fallback qname, produces a human-readable owner label.
OwnerResult resolve_owner_label(const std::string& asn_qname, const std::string& ptr_qname,
                                 int timeout_ms, const std::vector<std::string>& servers) {
    OwnerResult r;
    std::string txt;
    if (udp_dns_query(servers, asn_qname, /*TXT=*/16, timeout_ms, txt)) {
        std::string asn_field = trim_field(txt.substr(0, txt.find('|')));
        if (size_t sp = asn_field.find(' '); sp != std::string::npos) asn_field = asn_field.substr(0, sp);
        if (!asn_field.empty() && asn_field != "NA") {
            std::string name_txt;
            if (udp_dns_query(servers, "AS" + asn_field + ".asn.cymru.com", 16, timeout_ms, name_txt)) {
                std::string org = trim_field(name_txt.substr(name_txt.rfind('|') + 1));
                if (!org.empty()) { r.label = org + " (AS" + asn_field + ")"; r.ok = true; return r; }
            }
            r.label = "AS" + asn_field;
            r.ok = true;
            return r;
        }
    }
    std::string ptr;
    if (udp_dns_query(servers, ptr_qname, /*PTR=*/12, timeout_ms, ptr)) {
        if (!ptr.empty() && ptr.back() == '.') ptr.pop_back();
        if (!ptr.empty()) { r.label = "ptr:" + ptr; r.ok = true; }
    }
    return r;
}

// Caps the number of owner lookups fired off in one run, independent of how
// many ranges got printed -- this is the actual guard against "massive IP
// lookup": however many addresses a discovered range covers, only one lookup
// happens per emitted range, and never more than this many overall.
constexpr size_t kMaxOwnerLookups = 20000;

void resolve_owners(const std::vector<std::pair<std::string, uint32_t>>& v4_samples,
                     const std::vector<std::pair<std::string, u128>>& v6_samples,
                     const Options& opts,
                     std::vector<std::string>& v4_labels, std::vector<std::string>& v6_labels,
                     size_t& resolved, size_t& attempted) {
    v4_labels.assign(v4_samples.size(), std::string());
    v6_labels.assign(v6_samples.size(), std::string());
    resolved = 0;
    attempted = v4_samples.size() + v6_samples.size();
    if (attempted == 0) return;

    std::vector<std::string> servers = !opts.dns_servers.empty() ? opts.dns_servers
                                      : !g_dns_servers.empty()   ? g_dns_servers
                                                                  : owner_system_resolvers();
    if (servers.empty()) {
        std::cerr << "[discover] --owner: no DNS servers available, skipping owner lookups\n";
        attempted = 0;
        return;
    }

    const size_t cap = std::min(attempted, kMaxOwnerLookups);
    if (cap < attempted)
        std::cerr << "[discover] --owner: capped at " << kMaxOwnerLookups << " of " << attempted
                   << " ranges to bound DNS load\n";

    std::atomic<size_t> next{0};
    const int nthreads = std::max(1, std::min(opts.dns_concurrency, static_cast<int>(cap)));
    auto worker = [&]() {
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= cap || terminate_flag.load(std::memory_order_relaxed)) return;
            if (i < v4_samples.size()) {
                uint32_t ip = v4_samples[i].second;
                auto res = resolve_owner_label(cymru_qname_v4(ip), ptr_qname_v4(ip), opts.dns_timeout_ms, servers);
                if (res.ok) v4_labels[i] = res.label;
            } else {
                size_t j = i - v4_samples.size();
                u128 ip = v6_samples[j].second;
                auto res = resolve_owner_label(cymru_qname_v6(ip), ptr_qname_v6(ip), opts.dns_timeout_ms, servers);
                if (res.ok) v6_labels[j] = res.label;
            }
        }
    };
    std::vector<std::thread> pool;
    pool.reserve(nthreads);
    for (int t = 0; t < nthreads; ++t) pool.emplace_back(worker);
    for (auto& th : pool) th.join();

    for (auto& s : v4_labels) if (!s.empty()) ++resolved;
    for (auto& s : v6_labels) if (!s.empty()) ++resolved;
}

}  // namespace

namespace {

enum class Kind { NwDb, ApnicDelegated, RirV4, RirV6 };

struct Job {
    char cc[3] = {0, 0, 0};       
    bool want_v4 = true;
    bool want_v6 = true;
};

constexpr size_t kMaxLine        = 8 * 1024;             
constexpr size_t kCapStreamBytes = 128u * 1024 * 1024;   
constexpr size_t kCapPageBytes   = 4u * 1024 * 1024;     

struct Source {
    Kind        kind;
    const char* label;
    std::string url;
    const Job*  job = nullptr;
    bool        streaming = true;
    size_t      cap = kCapStreamBytes;

    CURL*       easy = nullptr;
    std::string buf;                        
    size_t      total_bytes = 0;
    bool        aborted = false;
    const char* abort_reason = nullptr;

    std::vector<V4> v4;
    std::vector<V6> v6;
    bool        done = false;
    bool        ok = false;
    double      secs = 0.0;
    std::string note;                       
};

size_t split_pipe(std::string_view line, std::string_view* f, size_t max) {
    size_t n = 0;
    while (n + 1 < max) {
        size_t bar = line.find('|');
        if (bar == std::string_view::npos) break;
        f[n++] = line.substr(0, bar);
        line.remove_prefix(bar + 1);
    }
    f[n++] = line;
    return n;
}

void apnic_line(Source& s, std::string_view line) {
    if (line[0] == '#') return;
    const size_t p1 = line.find('|');
    if (p1 == std::string_view::npos || p1 + 3 >= line.size()) return;
    if (line[p1 + 3] != '|' || line[p1 + 1] != s.job->cc[0] || line[p1 + 2] != s.job->cc[1]) return;  

    std::string_view f[8];
    if (split_pipe(line, f, 8) < 7) return;
    if (!(f[6] == "allocated" || f[6] == "assigned")) return;

    if (f[2] == "ipv4") {
        if (!s.job->want_v4) return;
        uint32_t start;
        uint64_t count;
        if (!parse_v4_addr(f[3], start) || !parse_u64(f[4], count) || count == 0) return;
        uint64_t last = static_cast<uint64_t>(start) + count - 1;
        if (last > 0xFFFFFFFFull) return;
        s.v4.emplace_back(start, static_cast<uint32_t>(last));
    } else if (f[2] == "ipv6") {
        if (!s.job->want_v6) return;
        u128 start;
        uint64_t plen;
        if (!parse_v6_addr(f[3], start) || !parse_u64(f[4], plen) || plen < 1 || plen > 128) return;
        s.v6.push_back(v6_from_prefix(start, static_cast<unsigned>(plen)));
    }
}

void rir_line(Source& s, std::string_view line) {
    line = trim_sv(line);
    if (line.empty() || line[0] == '#') return;
    if (s.kind == Kind::RirV4) {
        V4 iv;
        if (parse_v4_cidr(line, iv)) s.v4.push_back(iv);
    } else {
        V6 iv;
        if (parse_v6_cidr(line, iv)) s.v6.push_back(iv);
    }
}

void handle_line(Source& s, std::string_view line) {
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (line.empty()) return;
    if (s.kind == Kind::ApnicDelegated) apnic_line(s, line);
    else                                rir_line(s, line);
}

bool feed(Source& s, const char* p, size_t len) {
    s.total_bytes += len;
    if (s.total_bytes > s.cap) { s.aborted = true; s.abort_reason = "response too large"; return false; }

    if (!s.streaming) { s.buf.append(p, len); return true; }

    size_t pos = 0;
    if (!s.buf.empty()) {
        const char* nl = static_cast<const char*>(std::memchr(p, '\n', len));
        if (!nl) {
            if (s.buf.size() + len > kMaxLine) { s.aborted = true; s.abort_reason = "line too long (not a delegation file?)"; return false; }
            s.buf.append(p, len);
            return true;
        }
        const size_t n = static_cast<size_t>(nl - p);
        s.buf.append(p, n);
        handle_line(s, s.buf);
        s.buf.clear();
        pos = n + 1;
    }
    while (pos < len) {
        const char* start = p + pos;
        const char* nl = static_cast<const char*>(std::memchr(start, '\n', len - pos));
        if (!nl) {
            if (len - pos > kMaxLine) { s.aborted = true; s.abort_reason = "line too long (not a delegation file?)"; return false; }
            s.buf.assign(start, len - pos);
            break;
        }
        const size_t n = static_cast<size_t>(nl - start);
        handle_line(s, std::string_view(start, n));
        pos += n + 1;
    }
    return true;
}

void finish(Source& s) {
    if (s.streaming) {
        if (!s.buf.empty()) { handle_line(s, s.buf); s.buf.clear(); }
        return;
    }
    const std::string_view body(s.buf);
    bool country_ok = false;
    for (size_t pos = 0; (pos = body.find("/country/", pos)) != std::string_view::npos; ) {
        pos += 9;
        if (pos + 2 <= body.size() &&
            lower_ascii(body[pos]) == lower_ascii(s.job->cc[0]) &&
            lower_ascii(body[pos + 1]) == lower_ascii(s.job->cc[1]) &&
            (pos + 2 == body.size() || !is_alnum_ascii(static_cast<unsigned char>(body[pos + 2])))) {
            country_ok = true;
            break;
        }
    }
    if (!country_ok) {
        s.note = "page is not attributed to this country (org page of an unrelated entity) - ignored";
        return;
    }

    static constexpr std::string_view kKey = "CIDR:</span>";
    size_t pos = 0;
    while ((pos = body.find(kKey, pos)) != std::string_view::npos) {
        pos += kKey.size();
        while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\r' || body[pos] == '\n')) ++pos;
        size_t e = pos;
        while (e < body.size() && ((body[e] >= '0' && body[e] <= '9') || body[e] == '.' || body[e] == '/')) ++e;
        V4 iv;
        if (e > pos && parse_v4_cidr(body.substr(pos, e - pos), iv)) s.v4.push_back(iv);
        pos = e;
    }
    s.buf.clear();
    s.buf.shrink_to_fit();
}

} 

namespace {

size_t write_cb(char* p, size_t sz, size_t nm, void* ud) {
    auto* s = static_cast<Source*>(ud);
    if (terminate_flag.load(std::memory_order_relaxed)) {
        s->aborted = true;
        s->abort_reason = "interrupted";
        return 0;                                   
    }
    const size_t len = sz * nm;
    return feed(*s, p, len) ? len : 0;
}

void setup_easy(Source& s, const Options& o) {
    CURL* h = s.easy;
    curl_easy_setopt(h, CURLOPT_URL, s.url.c_str());
    curl_easy_setopt(h, CURLOPT_PRIVATE, &s);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &s);

    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);                  
    curl_easy_setopt(h, CURLOPT_FAILONERROR, 1L);               
    curl_easy_setopt(h, CURLOPT_ACCEPT_ENCODING, "");           
    curl_easy_setopt(h, CURLOPT_BUFFERSIZE, 262144L);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "Shiv-discover/1.0");
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, static_cast<long>(o.connect_timeout_sec));
    curl_easy_setopt(h, CURLOPT_TIMEOUT, static_cast<long>(o.total_timeout_sec));
    curl_easy_setopt(h, CURLOPT_LOW_SPEED_LIMIT, 1024L);        
    curl_easy_setopt(h, CURLOPT_LOW_SPEED_TIME, 20L);           
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(h, CURLOPT_MAXREDIRS, 3L);
#if LIBCURL_VERSION_NUM >= 0x075500          
    curl_easy_setopt(h, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS_STR, "https");
#else
    curl_easy_setopt(h, CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTPS));
    curl_easy_setopt(h, CURLOPT_REDIR_PROTOCOLS, static_cast<long>(CURLPROTO_HTTPS));
#endif
}

CURLMcode wait_multi(CURLM* m, int ms, int* nfds) {
#if LIBCURL_VERSION_NUM >= 0x074200          
    return curl_multi_poll(m, nullptr, 0, ms, nfds);
#else
    return curl_multi_wait(m, nullptr, 0, ms, nfds);
#endif
}

std::string nwdb_slug(const char* name) {
    std::string out;
    for (const char* p = name; *p; ++p) {
        unsigned char c = static_cast<unsigned char>(*p);
        if (is_alnum_ascii(c)) out.push_back(lower_ascii(static_cast<char>(c)));
        else if ((c == ' ' || c == '-') && !out.empty() && out.back() != '-') out.push_back('-');
    }
    while (!out.empty() && out.back() == '-') out.pop_back();
    return out;
}

bool err_tty() { static const bool t = isatty(STDERR_FILENO) != 0; return t; }
const char* col(const char* c) { return err_tty() ? c : ""; }
constexpr const char* kReset = "\033[0m";
constexpr const char* kGreen = "\033[32m";
constexpr const char* kYellow = "\033[93m";
constexpr const char* kRed = "\033[91m";
constexpr const char* kBold = "\033[1m";

std::string human_bytes(size_t b) {
    char buf[32];
    if (b >= 1024u * 1024u) std::snprintf(buf, sizeof(buf), "%.1f MB", b / (1024.0 * 1024.0));
    else if (b >= 1024u)    std::snprintf(buf, sizeof(buf), "%.1f KB", b / 1024.0);
    else                    std::snprintf(buf, sizeof(buf), "%zu B", b);
    return buf;
}

void reap(CURLM* multi, size_t& finished) {
    int left = 0;
    while (CURLMsg* m = curl_multi_info_read(multi, &left)) {
        if (m->msg != CURLMSG_DONE) continue;
        char* priv = nullptr;
        curl_easy_getinfo(m->easy_handle, CURLINFO_PRIVATE, &priv);
        Source* s = reinterpret_cast<Source*>(priv);
        curl_multi_remove_handle(multi, m->easy_handle);
        if (!s) continue;

        const CURLcode rc = m->data.result;
        long http = 0;
        curl_easy_getinfo(m->easy_handle, CURLINFO_RESPONSE_CODE, &http);
        curl_easy_getinfo(m->easy_handle, CURLINFO_TOTAL_TIME, &s->secs);

        s->done = true;
        ++finished;
        if (rc == CURLE_OK) {
            finish(*s);
            s->ok = s->note.empty();
        } else {
            s->ok = false;
            if (s->aborted && s->abort_reason)      s->note = s->abort_reason;
            else if (rc == CURLE_HTTP_RETURNED_ERROR) s->note = "HTTP " + std::to_string(http);
            else                                     s->note = curl_easy_strerror(rc);
            s->v4.clear();                                   
            s->v6.clear();
        }
    }
}

}  

int run(const Options& opts) {
    CountryMatch m = resolve_country(opts.country);
    if (!m.country) {
        std::cerr << col(kRed) << "[discover] unknown country '" << opts.country << "'" << col(kReset) << "\n";
        if (!m.suggestions.empty()) {
            std::cerr << "[discover] did you mean:\n";
            for (const Country* c : m.suggestions)
                std::cerr << "             " << c->name << "  (" << c->iso2 << ")\n";
        } else {
            std::cerr << "[discover] use a country name (\"nepal\", \"south korea\") or an ISO code (NP, NPL).\n";
        }
        return 1;
    }
    const Country& country = *m.country;

    Job job;
    job.cc[0] = country.iso2[0];
    job.cc[1] = country.iso2[1];
    job.want_v4 = opts.want_v4;
    job.want_v6 = opts.want_v6;
    if (!job.want_v4 && !job.want_v6) {
        std::cerr << "[discover] nothing to do: both IPv4 and IPv6 are disabled\n";
        return 1;
    }
    const std::string cc_lower = [&] { std::string s(country.iso2); for (char& c : s) c = lower_ascii(c); return s; }();

    std::cerr << col(kBold) << "[discover] country : " << country.name << " (" << country.iso2 << ")" << col(kReset);
    if (m.how == CountryMatch::How::Prefix) std::cerr << "   <- '" << opts.country << "' matched by prefix";
    if (m.how == CountryMatch::How::Fuzzy)  std::cerr << "   <- '" << opts.country << "' corrected to closest name";
    std::cerr << "\n";
    std::vector<std::unique_ptr<Source>> sources;
    auto add = [&](Kind k, const char* label, std::string url, bool streaming, size_t cap) {
        auto s = std::make_unique<Source>();
        s->kind = k; s->label = label; s->url = std::move(url);
        s->job = &job; s->streaming = streaming; s->cap = cap;
        sources.push_back(std::move(s));
    };
    if (job.want_v4)
        add(Kind::NwDb, "networksdb", "https://networksdb.io/ip-addresses-of/" + nwdb_slug(country.name), false, kCapPageBytes);
    add(Kind::ApnicDelegated, "apnic-delegated", "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest", true, kCapStreamBytes);
    if (job.want_v4)
        add(Kind::RirV4, "rir-list-v4", "https://www-public.telecom-sudparis.eu/~maigron/rir-stats/rir-delegations/ip-lists/ipv4/" + cc_lower + "-ipv4-list.txt", true, kCapStreamBytes);
    if (job.want_v6)
        add(Kind::RirV6, "rir-list-v6", "https://www-public.telecom-sudparis.eu/~maigron/rir-stats/rir-delegations/ip-lists/ipv6/" + cc_lower + "-ipv6-list.txt", true, kCapStreamBytes);
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        std::cerr << col(kRed) << "[discover] curl_global_init failed" << col(kReset) << "\n";
        return 1;
    }
    CURLM* multi = curl_multi_init();
    if (!multi) {
        std::cerr << col(kRed) << "[discover] curl_multi_init failed" << col(kReset) << "\n";
        curl_global_cleanup();
        return 1;
    }
    for (auto& s : sources) {
        s->easy = curl_easy_init();
        if (!s->easy) { s->done = true; s->note = "curl_easy_init failed"; continue; }
        setup_easy(*s, opts);
        curl_multi_add_handle(multi, s->easy);
        if (opts.verbose) std::cerr << "[discover]   GET " << s->url << "\n";
    }
    std::cerr << "[discover] fetching " << sources.size() << " endpoints in parallel...\n";
    size_t finished = 0;
    for (auto& s : sources) if (s->done) ++finished;     

    int running = 0;
    curl_multi_perform(multi, &running);
    reap(multi, finished);
    while (running > 0 && !terminate_flag.load(std::memory_order_relaxed)) {
        int nfds = 0;
        if (wait_multi(multi, 200, &nfds) != CURLM_OK) break;     
        curl_multi_perform(multi, &running);
        reap(multi, finished);
    }
    const bool interrupted = terminate_flag.load(std::memory_order_relaxed);
    for (auto& s : sources) {
        if (s->easy) {
            if (!s->done) curl_multi_remove_handle(multi, s->easy);
            curl_easy_cleanup(s->easy);
            s->easy = nullptr;
        }
    }
    curl_multi_cleanup(multi);
    curl_global_cleanup();

    if (interrupted) {
        std::cerr << "[discover] interrupted - transfers aborted, partial results discarded\n";
        return 130;
    }

    size_t ok_count = 0;
    std::vector<V4> all_v4;
    std::vector<V6> all_v6;
    for (auto& s : sources) {
        char line[160];
        if (s->ok) {
            ++ok_count;
            std::snprintf(line, sizeof(line), "[discover]   %sok%s    %-16s %9s  %6zu v4  %6zu v6  %.2fs",
                          col(kGreen), col(kReset), s->label, human_bytes(s->total_bytes).c_str(),
                          s->v4.size(), s->v6.size(), s->secs);
            std::cerr << line << "\n";
            all_v4.insert(all_v4.end(), s->v4.begin(), s->v4.end());
            all_v6.insert(all_v6.end(), s->v6.begin(), s->v6.end());
        } else {
            std::snprintf(line, sizeof(line), "[discover]   %sskip%s  %-16s %s",
                          col(kYellow), col(kReset), s->label, s->note.c_str());
            std::cerr << line << "\n";
        }
    }
    if (ok_count == 0) {
        std::cerr << col(kRed) << "[discover] every source failed - check connectivity / country code" << col(kReset) << "\n";
        return 1;
    }

    const size_t raw_v4 = all_v4.size(), raw_v6 = all_v6.size();
    std::string text;
    size_t out_v4 = 0, out_v6 = 0;
    uint64_t addr_v4 = 0;
    std::vector<std::pair<std::string, uint32_t>> v4_samples;
    std::vector<std::pair<std::string, u128>>     v6_samples;
    if (job.want_v4) {
        std::vector<V4> merged = merge_v4(std::move(all_v4));
        for (const V4& iv : merged) {
            addr_v4 += static_cast<uint64_t>(iv.second) - iv.first + 1;
            out_v4 += emit_v4(iv, text, opts.owner ? &v4_samples : nullptr);
        }
    }
    if (job.want_v6) {
        std::vector<V6> merged = merge_v6(std::move(all_v6));
        for (const V6& iv : merged) out_v6 += emit_v6(iv, text, opts.owner ? &v6_samples : nullptr);
    }

    if (out_v4 + out_v6 == 0) {
        std::cerr << col(kYellow) << "[discover] no ranges found for " << country.name << " (" << country.iso2 << ")" << col(kReset) << "\n";
        return 1;
    }

    if (opts.owner) {
        std::cerr << "[discover] resolving owners for " << (out_v4 + out_v6)
                   << " ranges (1 sample IP per range, Team Cymru ASN lookup)...\n";
        std::vector<std::string> v4_labels, v6_labels;
        size_t owners_resolved = 0, owners_attempted = 0;
        resolve_owners(v4_samples, v6_samples, opts, v4_labels, v6_labels, owners_resolved, owners_attempted);

        std::string annotated;
        annotated.reserve(text.size() + owners_attempted * 24);
        for (size_t i = 0; i < v4_samples.size(); ++i) {
            annotated += v4_samples[i].first;
            if (!v4_labels[i].empty()) { annotated += "  # "; annotated += v4_labels[i]; }
            annotated += '\n';
        }
        for (size_t i = 0; i < v6_samples.size(); ++i) {
            annotated += v6_samples[i].first;
            if (!v6_labels[i].empty()) { annotated += "  # "; annotated += v6_labels[i]; }
            annotated += '\n';
        }
        text = std::move(annotated);
        std::cerr << "[discover] owners  : " << owners_resolved << "/" << owners_attempted << " ranges resolved\n";
    }

    std::cout.write(text.data(), static_cast<std::streamsize>(text.size()));
    std::cout.flush();

    if (!opts.output_file.empty()) {
        std::ofstream f(opts.output_file, std::ios::binary | std::ios::trunc);
        if (!f) std::cerr << col(kRed) << "[discover] cannot write '" << opts.output_file << "'" << col(kReset) << "\n";
        else { f.write(text.data(), static_cast<std::streamsize>(text.size())); std::cerr << "[discover] saved  : " << opts.output_file << "\n"; }
    }

    std::cerr << col(kBold) << "[discover] result  : " << col(kReset);
    if (job.want_v4) std::cerr << out_v4 << " IPv4 ranges (" << addr_v4 << " addresses)";
    if (job.want_v4 && job.want_v6) std::cerr << ", ";
    if (job.want_v6) std::cerr << out_v6 << " IPv6 ranges";
    std::cerr << "  [from " << raw_v4 << " v4 + " << raw_v6 << " v6 raw entries, " << ok_count << "/" << sources.size() << " sources]\n";
    return 0;
}

}  

#ifdef DISCOVER_SELFTEST
std::atomic<bool> terminate_flag(false);
std::vector<std::string> g_dns_servers;  // normally defined in handler.cpp; stubbed for the standalone selftest link

#include <cassert>
#include <set>

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::cerr << "FAIL line " << __LINE__ << ": " #c "\n"; ++g_fail; } } while (0)

int main() {
    using namespace discover;
    std::set<std::string> i2, i3;
    for (const Country& c : kCountries) { CHECK(i2.insert(c.iso2).second); CHECK(i3.insert(c.iso3).second); CHECK(std::strlen(c.iso2) == 2 && std::strlen(c.iso3) == 3); }
    CHECK(country_count() == 199);
    CHECK(std::strlen("AAAAAAACEEEEIIIIDNOOOOO*OUUUUYTsaaaaaaaceeeeiiiidnooooo/ouuuuyty") == 64);
    for (const Country& c : kCountries) {
        CHECK(resolve_country(c.iso2).country == &c);
        CHECK(resolve_country(c.iso3).country == &c);
        CHECK(resolve_country(c.name).country == &c);
        std::string_view al(c.aliases);
        while (!al.empty()) {
            size_t bar = al.find('|');
            std::string one(al.substr(0, bar));
            CHECK(resolve_country(one).country == &c);
            if (bar == std::string_view::npos) break;
            al.remove_prefix(bar + 1);
        }
    }
    auto iso = [](const char* s) { auto m = resolve_country(s); return m.country ? std::string(m.country->iso2) : std::string("??"); };
    CHECK(iso("nepal") == "NP");   CHECK(iso("  NEPAL ") == "NP");  CHECK(iso("np") == "NP");   CHECK(iso("NPL") == "NP");
    CHECK(iso("United States") == "US"); CHECK(iso("usa") == "US"); CHECK(iso("uk") == "GB");
    CHECK(iso("South Korea") == "KR");   CHECK(iso("north-korea") == "KP");
    CHECK(iso("Côte d'Ivoire") == "CI"); CHECK(iso("Türkiye") == "TR"); CHECK(iso("são tomé") == "ST");
    CHECK(iso("neth") == "NL");    
    CHECK(iso("nepl") == "NP");    
    CHECK(iso("germny") == "DE");
    CHECK(iso("bangaldesh") == "BD");
    CHECK(iso("kazakstan") == "KZ");
    CHECK(iso("ind") == "IN");     
    CHECK(iso("guinea") == "GN");  CHECK(iso("niger") == "NE"); CHECK(iso("nigeria") == "NG");
    CHECK(iso("sudan") == "SD");   CHECK(iso("south sudan") == "SS");
    CHECK(iso("xx") == "??");      CHECK(iso("") == "??");  CHECK(iso("atlantis") == "??");
    CHECK(!resolve_country("mal").country && !resolve_country("mal").suggestions.empty());   
    CHECK(!resolve_country("korea").country);                                                 
    std::string t;
    CHECK(emit_v4({0x1B220000u, 0x1B22FFFFu}, t) == 1 && t == "27.34.0.0/16\n");             
    t.clear(); CHECK(emit_v4({0x0A000000u, 0x0A0002FFu}, t) == 2 && t == "10.0.0.0/23\n10.0.2.0/24\n"); 
    t.clear(); CHECK(emit_v4({0x0A000001u, 0x0A000006u}, t) == 4);                            
    t.clear(); CHECK(emit_v4({0u, 0xFFFFFFFFu}, t) == 1 && t == "0.0.0.0/0\n");
    std::vector<V4> v = {{10, 20}, {21, 30}, {5, 12}, {100, 200}};
    auto mv = merge_v4(v);  CHECK(mv.size() == 2 && mv[0] == V4(5, 30) && mv[1] == V4(100, 200));
    V6 a, b; CHECK(parse_v6_cidr("2405:d000::/32", a) && parse_v6_cidr("2405:d001::/32", b));
    auto m6 = merge_v6({b, a});  CHECK(m6.size() == 1);
    t.clear(); CHECK(emit_v6(m6[0], t) == 1 && t == "2405:d000::/31\n");
    V6 all; CHECK(parse_v6_cidr("::/1", all));
    Job job; job.cc[0] = 'N'; job.cc[1] = 'P';
    const std::string body =
        "2|apnic|20260919|9999|19830613|20260918|+1000\n"
        "apnic|*|ipv4|*|9999|summary\n"
        "apnic|NP|ipv4|27.34.0.0|32768|20100322|allocated\n"
        "apnic|IN|ipv4|1.6.0.0|65536|20100322|allocated\n"
        "apnic|NP|ipv4|103.1.92.0|1024|20110316|assigned\r\n"
        "apnic|NP|ipv4|202.79.32.0|8192|20100629|reserved\n"
        "apnic|NP|ipv6|2405:8d40::|32|20120523|allocated\n"
        "apnic|NP|ipv4|202.166.192.0|4096|20100629|allocated";           
    for (size_t cut = 0; cut <= body.size(); ++cut) {
        Source s; s.kind = Kind::ApnicDelegated; s.job = &job;
        CHECK(feed(s, body.data(), cut) && feed(s, body.data() + cut, body.size() - cut));
        finish(s);
        CHECK(s.v4.size() == 3 && s.v6.size() == 1);
        CHECK(s.v4[0] == V4(0x1B220000u, 0x1B227FFFu));
        CHECK(s.v4[1] == V4(0x67015C00u, 0x67015FFFu));
    }
    { 
        Source s; s.kind = Kind::ApnicDelegated; s.job = &job;
        for (char ch : body) CHECK(feed(s, &ch, 1));
        finish(s);  CHECK(s.v4.size() == 3 && s.v6.size() == 1);
    }
    { 
        Job j4 = job; j4.want_v6 = false;
        Source s; s.kind = Kind::ApnicDelegated; s.job = &j4; feed(s, body.data(), body.size()); finish(s);
        CHECK(s.v6.empty() && s.v4.size() == 3);
    }
    { 
        Source s; s.kind = Kind::RirV4; s.job = &job;
        const std::string l = "# generated\n27.34.0.0/17\n\n bad line\n103.1.92.0/22\n";
        feed(s, l.data(), l.size()); finish(s);
        CHECK(s.v4.size() == 2 && s.v4[0] == V4(0x1B220000u, 0x1B227FFFu));
    }
    { 
        std::string html = "<a href=\"/country/NP\">Nepal</a><span>CIDR:</span> 14.137.53.0/24 <span>CIDR:</span> 102.38.241.0/24 <span>CIDR:</span> 14.137.51.128/25";
        Source s; s.kind = Kind::NwDb; s.job = &job; s.streaming = false; s.cap = kCapPageBytes;
        feed(s, html.data(), html.size()); finish(s);
        CHECK(s.note.empty() && s.v4.size() == 3 && s.v4[2] == V4(0x0E893380u, 0x0E8933FFu));
        Source s2; s2.kind = Kind::NwDb; s2.job = &job; s2.streaming = false;
        std::string other = "<a href=\"/country/US\">x</a> <span>CIDR:</span> 1.2.3.0/24";
        feed(s2, other.data(), other.size()); finish(s2);
        CHECK(!s2.note.empty() && s2.v4.empty());
    }
    CHECK(nwdb_slug("Nepal") == "nepal");  CHECK(nwdb_slug("United States") == "united-states");  CHECK(nwdb_slug("Cote d'Ivoire") == "cote-divoire");

    std::cerr << (g_fail ? "SELFTEST FAILED\n" : "SELFTEST OK\n");
    return g_fail ? 1 : 0;
}
#endif
