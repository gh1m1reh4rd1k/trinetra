#include "server.hpp"
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <atomic>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace server {
namespace {

constexpr int    kDefaultPort      = 8787;
constexpr int    kDefaultTlsPort   = 8443;
constexpr size_t kMaxHeaderBytes   = 16 * 1024;
constexpr size_t kMaxBodyBytes     = 4  * 1024;
constexpr size_t kMaxOutbufBytes   = 8 * 1024 * 1024;
constexpr int    kMaxEvents        = 64;
constexpr int    kReadChunk        = 65536;
constexpr int    kEpollTimeoutMs   = 500;

// --- hardening knobs -------------------------------------------------
constexpr int    kTokenBytes            = 24;   // 192-bit random token
constexpr size_t kMinFixedTokenLen      = 16;    // floor for --server-token
constexpr int    kMaxAuthFailures       = 8;     // per-IP failures allowed...
constexpr int    kAuthFailureWindowSec  = 60;    // ...within this window
constexpr int    kCookieMaxAgeSec       = 3600;  // session cookie lifetime
constexpr const char* kCookieName       = "shiv_token";
constexpr int    kConnIdleTimeoutSec    = 20;    // slowloris guard
constexpr int    kSweepIntervalSec      = 5;

constexpr const char* kStunnelDir      = "/etc/stunnel";
constexpr const char* kStunnelConfPath = "/etc/stunnel/shiv.conf";
constexpr const char* kStunnelCertPath = "/etc/stunnel/shiv.pem";


volatile std::sig_atomic_t g_shutdown = 0;
void on_signal(int) { g_shutdown = 1; }
std::atomic<bool> g_scan_busy{false};
pid_t g_running_pid = -1;

std::string g_token;
std::string g_self_path;
bool g_secure_cookies = false;

std::unordered_map<std::string, std::pair<int, std::time_t>> g_auth_fail;

bool set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags == -1) return false;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1;
}

bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

std::string resolve_self_path() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf, static_cast<size_t>(n));
}

void ensure_root(int argc, char* argv[]) {
    if (geteuid() == 0) return;

    std::string self = resolve_self_path();
    if (self.empty()) self = argv[0];

    std::cerr << "shiv --server needs root to run raw-socket scans "
                 "(this is LAN-only, not public-facing).\n"
                 "Refusing to run in user mode. Run it again with sudo:\n  sudo "
              << self;
    for (int i = 1; i < argc; ++i) std::cerr << " " << argv[i];
    std::cerr << "\n";
    std::exit(1);
}

std::string random_token(size_t bytes = kTokenBytes) {
    std::vector<unsigned char> raw(bytes);
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return "";
    size_t got = fread(raw.data(), 1, raw.size(), f);
    fclose(f);
    if (got != raw.size()) return "";
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (unsigned char c : raw) {
        out.push_back(hex[c >> 4]);
        out.push_back(hex[c & 0x0F]);
    }
    return out;
}

// Constant-time compare -- closes the timing side-channel on token checks.
bool tokens_match(const std::string& a, const std::string& b) {
    if (a.empty() || b.empty()) return false;
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return diff == 0;
}

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string html_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default:  out.push_back(c);
        }
    }
    return out;
}

std::string url_decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int hi = hexval(s[i + 1]), lo = hexval(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(s[i] == '+' ? ' ' : s[i]);
    }
    return out;
}

std::unordered_map<std::string, std::string> parse_query(const std::string& q) {
    std::unordered_map<std::string, std::string> out;
    size_t pos = 0;
    while (pos <= q.size()) {
        size_t amp = q.find('&', pos);
        std::string pair = q.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            out[url_decode(pair.substr(0, eq))] = url_decode(pair.substr(eq + 1));
        } else if (!pair.empty()) {
            out[url_decode(pair)] = "";
        }
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return out;
}

// Parses a `Cookie:` header value ("k1=v1; k2=v2") into a map.
std::unordered_map<std::string, std::string> parse_cookies(const std::string& header) {
    std::unordered_map<std::string, std::string> out;
    size_t pos = 0;
    while (pos < header.size()) {
        size_t semi = header.find(';', pos);
        std::string pair = header.substr(pos, semi == std::string::npos ? std::string::npos : semi - pos);
        size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string k = pair.substr(0, eq);
            std::string v = pair.substr(eq + 1);
            size_t ks = k.find_first_not_of(" \t");
            size_t ke = k.find_last_not_of(" \t");
            size_t vs = v.find_first_not_of(" \t");
            size_t ve = v.find_last_not_of(" \t");
            if (ks != std::string::npos && vs != std::string::npos) {
                out[k.substr(ks, ke - ks + 1)] = v.substr(vs, ve - vs + 1);
            }
        }
        if (semi == std::string::npos) break;
        pos = semi + 1;
    }
    return out;
}

std::vector<std::string> list_local_ipv4() {
    std::vector<std::string> out;
    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return out;
    for (struct ifaddrs* p = ifap; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (!(p->ifa_flags & IFF_UP) || (p->ifa_flags & IFF_LOOPBACK)) continue;
        char buf[INET_ADDRSTRLEN];
        auto* sin = reinterpret_cast<struct sockaddr_in*>(p->ifa_addr);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
            out.emplace_back(buf);
        }
    }
    freeifaddrs(ifap);
    return out;
}

bool tokenize_command(const std::string& line, std::vector<std::string>& out, std::string& err) {
    out.clear();
    std::string cur;
    bool in_token = false;
    size_t i = 0, n = line.size();
    while (i < n) {
        char c = line[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            if (in_token) { out.push_back(cur); cur.clear(); in_token = false; }
            ++i;
        } else if (c == '\'') {
            in_token = true;
            ++i;
            while (i < n && line[i] != '\'') { cur.push_back(line[i]); ++i; }
            if (i >= n) { err = "unterminated ' quote"; return false; }
            ++i;
        } else if (c == '"') {
            in_token = true;
            ++i;
            while (i < n && line[i] != '"') {
                if (line[i] == '\\' && i + 1 < n && (line[i + 1] == '"' || line[i + 1] == '\\')) {
                    cur.push_back(line[i + 1]);
                    i += 2;
                } else {
                    cur.push_back(line[i]);
                    ++i;
                }
            }
            if (i >= n) { err = "unterminated \" quote"; return false; }
            ++i;
        } else if (c == '\0') {
            err = "embedded NUL byte";
            return false;
        } else {
            in_token = true;
            cur.push_back(c);
            ++i;
        }
    }
    if (in_token) out.push_back(cur);
    return true;
}


std::string render_terminal_page(const std::string& token) {
    std::ostringstream html;
    html <<
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>shiv</title><style>"
        "html,body{height:100%;margin:0;background:#0b0f10;color:#d7e2e2;"
        "font-family:ui-monospace,Menlo,Consolas,monospace;font-size:14px;"
        "font-weight:700}"
        "#term{height:100%;overflow-y:auto;box-sizing:border-box;padding:10px 12px;"
        "white-space:pre-wrap;word-break:break-word;-webkit-overflow-scrolling:touch}"
        ".banner{color:#7a8a87}"
        ".line{display:flex}"
        ".prompt{flex:none;color:#5fd3a3;white-space:pre}"
        ".typed{flex:1;white-space:pre-wrap;word-break:break-word}"
        ".cmdline{flex:1;background:transparent;color:inherit;border:none;outline:none;"
        "font:inherit;font-weight:inherit;caret-color:#5fd3a3;padding:0;margin:0;min-width:1px}"
        ".err{color:#e06c75}"
        ".interrupt{color:#e5c07b}"
        "</style></head><body>"
        "<div id=\"term\">"
        "<div class=\"banner\">shiv --server — this browser tab is now a shiv terminal.\n"
        "Type a command and press Enter. Up/Down for history, Left/Right to move the cursor.\n"
        "Ctrl+C interrupts a running scan so you can start another.\n</div>"
        "</div>"
        "<script>\n"
        "const TOKEN = \"" << html_escape(token) << "\";\n"
        "const PROMPT = 'root@shiv:~> ';\n"
        "const term = document.getElementById('term');\n"
        "let history = [];\n"
        "let histPos = 0;\n"
        "let draft = '';\n"
        "let activeInput = null;\n"
        "let running = false;\n"
        "let currentAbort = null;\n"
        "\n"
        "function scrollDown() { term.scrollTop = term.scrollHeight; }\n"
        "\n"
        "function clearTerminal() {\n"
        "  term.innerHTML = '';\n"
        "  newPromptLine();\n"
        "}\n"
        "\n"
        "function appendOutput(text, cls) {\n"
        "  const span = document.createElement('span');\n"
        "  if (cls) span.className = cls;\n"
        "  span.textContent = text;\n"
        "  term.appendChild(span);\n"
        "  scrollDown();\n"
        "  return span;\n"
        "}\n"
        "\n"
        "// --- ANSI SGR (color/bold) handling -----------------------------\n"
        "// shiv colors its own terminal output with standard ANSI escape\n"
        "// codes (ESC [ <params> m). A plain textContent write shows those\n"
        "// as literal characters, so we parse them here instead: strip the\n"
        "// escape sequences, track the color they select, and render runs\n"
        "// of text in spans carrying that color. Bold/normal-intensity\n"
        "// codes are recognized (so they don't leak through as text) but\n"
        "// don't change weight -- the terminal is bold by default via CSS,\n"
        "// so every code just picks a color against that fixed weight.\n"
        "const ANSI_COLORS = {\n"
        "  30: '#3b4252', 31: '#e06c75', 32: '#98c379', 33: '#e5c07b',\n"
        "  34: '#61afef', 35: '#c678dd', 36: '#56b6c2', 37: '#d7e2e2',\n"
        "  90: '#5c6370', 91: '#ff6b6b', 92: '#7ee787', 93: '#f5d76e',\n"
        "  94: '#79b8ff', 95: '#d19aff', 96: '#66d9d9', 97: '#ffffff'\n"
        "};\n"
        "let ansiColor = null;   // current CSS color, null = default\n"
        "let ansiPending = '';   // partial escape sequence split across chunks\n"
        "\n"
        "function resetAnsi() { ansiColor = null; ansiPending = ''; }\n"
        "\n"
        "function emitAnsiText(text) {\n"
        "  if (!text) return;\n"
        "  const span = document.createElement('span');\n"
        "  if (ansiColor) span.style.color = ansiColor;\n"
        "  span.textContent = text;\n"
        "  term.appendChild(span);\n"
        "}\n"
        "\n"
        "function applySgr(paramStr) {\n"
        "  const params = paramStr.split(';').filter(p => p !== '').map(Number);\n"
        "  if (params.length === 0) params.push(0);\n"
        "  for (const p of params) {\n"
        "    if (p === 0) ansiColor = null;\n"
        "    else if (p === 39) ansiColor = null;\n"
        "    else if (p === 1 || p === 22) { /* bold/normal: no-op, see above */ }\n"
        "    else if (ANSI_COLORS[p] !== undefined) ansiColor = ANSI_COLORS[p];\n"
        "  }\n"
        "}\n"
        "\n"
        "function appendAnsi(raw) {\n"
        "  let text = ansiPending + raw;\n"
        "  ansiPending = '';\n"
        "  const re = /\\x1b\\[([0-9;]*)m/g;\n"
        "  let lastIndex = 0, match;\n"
        "  while ((match = re.exec(text)) !== null) {\n"
        "    emitAnsiText(text.slice(lastIndex, match.index));\n"
        "    applySgr(match[1]);\n"
        "    lastIndex = re.lastIndex;\n"
        "  }\n"
        "  const rest = text.slice(lastIndex);\n"
        "  const escIdx = rest.indexOf('\\x1b');\n"
        "  if (escIdx !== -1) {\n"
        "    emitAnsiText(rest.slice(0, escIdx));\n"
        "    ansiPending = rest.slice(escIdx); // maybe-incomplete sequence, wait for more\n"
        "  } else if (rest) {\n"
        "    emitAnsiText(rest);\n"
        "  }\n"
        "  scrollDown();\n"
        "}\n"
        "\n"
        "function newPromptLine() {\n"
        "  const line = document.createElement('div');\n"
        "  line.className = 'line';\n"
        "  const prompt = document.createElement('span');\n"
        "  prompt.className = 'prompt';\n"
        "  prompt.textContent = PROMPT;\n"
        "  const input = document.createElement('input');\n"
        "  input.className = 'cmdline';\n"
        "  input.autocomplete = 'off';\n"
        "  input.autocapitalize = 'off';\n"
        "  input.spellcheck = false;\n"
        "  line.appendChild(prompt);\n"
        "  line.appendChild(input);\n"
        "  term.appendChild(line);\n"
        "  activeInput = input;\n"
        "  histPos = history.length;\n"
        "  draft = '';\n"
        "  input.addEventListener('keydown', onKeyDown);\n"
        "  input.focus();\n"
        "  scrollDown();\n"
        "}\n"
        "\n"
        "function freezeLine(input, text) {\n"
        "  const line = input.parentElement;\n"
        "  const typed = document.createElement('span');\n"
        "  typed.className = 'typed';\n"
        "  typed.textContent = text;\n"
        "  line.replaceChild(typed, input);\n"
        "  const nl = document.createElement('span');\n"
        "  nl.textContent = '\\n';\n"
        "  line.appendChild(nl);\n"
        "}\n"
        "\n"
        "function onKeyDown(e) {\n"
        "  const input = e.currentTarget;\n"
        "  if (e.key === 'Enter') {\n"
        "    e.preventDefault();\n"
        "    const text = input.value;\n"
        "    freezeLine(input, text);\n"
        "    activeInput = null;\n"
        "    const trimmed = text.trim();\n"
        "    if (!trimmed) { newPromptLine(); return; }\n"
        "    history.push(text);\n"
        "    histPos = history.length;\n"
        "    draft = '';\n"
        "    if (trimmed === 'clear') {\n"
        "      clearTerminal();\n"
        "      return;\n"
        "    }\n"
        "    runCommand(text);\n"
        "    return;\n"
        "  }\n"
        "  if (e.key === 'ArrowUp') {\n"
        "    e.preventDefault();\n"
        "    if (histPos > 0) {\n"
        "      if (histPos === history.length) draft = input.value;\n"
        "      histPos--;\n"
        "      input.value = history[histPos];\n"
        "      const p = input.value.length;\n"
        "      input.setSelectionRange(p, p);\n"
        "    }\n"
        "    return;\n"
        "  }\n"
        "  if (e.key === 'ArrowDown') {\n"
        "    e.preventDefault();\n"
        "    if (histPos < history.length) {\n"
        "      histPos++;\n"
        "      input.value = (histPos === history.length) ? draft : history[histPos];\n"
        "      const p = input.value.length;\n"
        "      input.setSelectionRange(p, p);\n"
        "    }\n"
        "    return;\n"
        "  }\n"
        "  // Left/Right/Home/End are handled natively by the <input> itself.\n"
        "}\n"
        "\n"
        "async function runCommand(line) {\n"
        "  running = true;\n"
        "  resetAnsi();\n"
        "  const controller = new AbortController();\n"
        "  currentAbort = controller;\n"
        "  try {\n"
        "    const resp = await fetch('/run', {\n"
        "      method: 'POST',\n"
        "      headers: {'X-Shiv-Token': TOKEN, 'Content-Type': 'text/plain'},\n"
        "      body: line,\n"
        "      signal: controller.signal\n"
        "    });\n"
        "    if (!resp.ok) {\n"
        "      const t = await resp.text();\n"
        "      appendOutput('[' + resp.status + '] ' + t + '\\n', 'err');\n"
        "      return;\n"
        "    }\n"
        "    const reader = resp.body.getReader();\n"
        "    const decoder = new TextDecoder();\n"
        "    while (true) {\n"
        "      const { value, done } = await reader.read();\n"
        "      if (done) break;\n"
        "      appendAnsi(decoder.decode(value, { stream: true }));\n"
        "    }\n"
        "  } catch (e) {\n"
        "    if (e.name === 'AbortError') {\n"
        "      appendOutput('^C\\n', 'interrupt');\n"
        "    } else {\n"
        "      appendOutput('[client error] ' + e + '\\n', 'err');\n"
        "    }\n"
        "  } finally {\n"
        "    running = false;\n"
        "    currentAbort = null;\n"
        "    newPromptLine();\n"
        "  }\n"
        "}\n"
        "\n"
        "// Ctrl+C while a command is running: ask the server to SIGINT the\n"
        "// child (same signal a real terminal would send) and stop waiting\n"
        "// on our end, so a fresh prompt shows up immediately instead of\n"
        "// having to wait for the scan to finish on its own.\n"
        "function interruptCommand() {\n"
        "  if (!running) return;\n"
        "  fetch('/kill', { method: 'POST', headers: {'X-Shiv-Token': TOKEN} }).catch(() => {});\n"
        "  if (currentAbort) currentAbort.abort();\n"
        "}\n"
        "\n"
        "document.addEventListener('keydown', (e) => {\n"
        "  if (running && e.ctrlKey && !e.altKey && !e.metaKey && (e.key === 'c' || e.key === 'C')) {\n"
        "    e.preventDefault();\n"
        "    interruptCommand();\n"
        "  }\n"
        "});\n"
        "\n"
        "term.addEventListener('click', () => { if (activeInput) activeInput.focus(); });\n"
        "newPromptLine();\n"
        "</script></body></html>";
    return html.str();
}

struct HttpRequest {
    std::string method;
    std::string path;
    std::string query;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

std::string header_value(const HttpRequest& req, const char* name) {
    auto it = req.headers.find(name);
    return it != req.headers.end() ? it->second : std::string();
}

bool parse_request(const std::string& raw, size_t header_end, HttpRequest& req) {
    std::istringstream stream(raw.substr(0, header_end));
    std::string line;
    if (!std::getline(stream, line)) return false;
    if (!line.empty() && line.back() == '\r') line.pop_back();

    std::istringstream request_line(line);
    std::string target, version;
    if (!(request_line >> req.method >> target >> version)) return false;

    size_t qpos = target.find('?');
    if (qpos == std::string::npos) {
        req.path = target;
    } else {
        req.path = target.substr(0, qpos);
        req.query = target.substr(qpos + 1);
    }

    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string key = to_lower(line.substr(0, colon));
        size_t vstart = colon + 1;
        while (vstart < line.size() && line[vstart] == ' ') ++vstart;
        req.headers[key] = line.substr(vstart);
    }
    return true;
}

enum class ConnState { READING_REQUEST, STREAMING_OUTPUT, DONE };

struct Connection {
    int fd = -1;
    ConnState state = ConnState::READING_REQUEST;
    std::string peer_ip;
    std::time_t created_at = 0;

    std::string inbuf;
    bool headers_parsed = false;
    size_t header_end = 0;
    size_t content_length = 0;

    std::string outbuf;
    bool want_epollout = false;

    pid_t child_pid = -1;
    int child_stdout_fd = -1;
    bool child_eof = false;
};

int g_epfd = -1;
std::unordered_map<int, std::shared_ptr<Connection>> g_conns;

void epoll_add(int fd, uint32_t events) {
    struct epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev);
}

void epoll_mod(int fd, uint32_t events) {
    struct epoll_event ev{};
    ev.events = events;
    ev.data.fd = fd;
    epoll_ctl(g_epfd, EPOLL_CTL_MOD, fd, &ev);
}

void epoll_del(int fd) {
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, fd, nullptr);
}

void reap_child(Connection& c) {
    if (c.child_pid > 0) {
        int status = 0;
        waitpid(c.child_pid, &status, WNOHANG);
        if (g_running_pid == c.child_pid) g_running_pid = -1;
        c.child_pid = -1;
    }
    if (c.child_stdout_fd != -1) {
        epoll_del(c.child_stdout_fd);
        g_conns.erase(c.child_stdout_fd);
        close(c.child_stdout_fd);
        c.child_stdout_fd = -1;
    }
    g_scan_busy = false;
}

void close_connection(std::shared_ptr<Connection> c) {
    if (c->child_pid > 0) {
        kill(c->child_pid, SIGKILL);
        reap_child(*c);
    }
    epoll_del(c->fd);
    g_conns.erase(c->fd);
    close(c->fd);
    c->state = ConnState::DONE;
}

bool flush_outbuf(std::shared_ptr<Connection> c) {
    while (!c->outbuf.empty()) {
        ssize_t n = write(c->fd, c->outbuf.data(), c->outbuf.size());
        if (n > 0) {
            c->outbuf.erase(0, static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!c->want_epollout) {
                c->want_epollout = true;
                epoll_mod(c->fd, EPOLLIN | EPOLLOUT | EPOLLRDHUP);
            }
            return true;
        }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    if (c->want_epollout) {
        c->want_epollout = false;
        epoll_mod(c->fd, EPOLLIN | EPOLLRDHUP);
    }
    return true;
}

void queue_and_flush(std::shared_ptr<Connection> c, const std::string& data) {
    if (c->outbuf.size() + data.size() > kMaxOutbufBytes) {
        close_connection(c);
        return;
    }
    c->outbuf += data;
    if (!flush_outbuf(c)) close_connection(c);
}

std::string security_headers() {
    std::ostringstream h;
    h << "X-Frame-Options: DENY\r\n"
      << "X-Content-Type-Options: nosniff\r\n"
      << "Referrer-Policy: no-referrer\r\n"
      << "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; "
         "style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
         "frame-ancestors 'none'\r\n"
      << "Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n"
      << "Cache-Control: no-store\r\n";
    return h.str();
}

// --- auth / rate limiting ---------------------------------------------

bool auth_rate_limited(const std::string& ip) {
    std::time_t now = std::time(nullptr);
    auto& st = g_auth_fail[ip];
    if (now - st.second > kAuthFailureWindowSec) { st.first = 0; st.second = now; }
    return st.first >= kMaxAuthFailures;
}

void record_auth_failure(const std::string& ip) {
    std::time_t now = std::time(nullptr);
    auto& st = g_auth_fail[ip];
    if (now - st.second > kAuthFailureWindowSec) { st.first = 0; st.second = now; }
    st.first++;
    std::cerr << "[shiv-server] failed auth attempt from " << ip
              << " (failures in window: " << st.first << ")\n";
}

void send_simple_response(std::shared_ptr<Connection> c, int code, const char* status,
                           const std::string& content_type, const std::string& body) {
    std::ostringstream head;
    head << "HTTP/1.1 " << code << " " << status << "\r\n"
         << "Content-Type: " << content_type << "\r\n"
         << "Content-Length: " << body.size() << "\r\n"
         << security_headers()
         << "Connection: close\r\n\r\n";
    c->outbuf += head.str();
    c->outbuf += body;
    if (flush_outbuf(c) && c->outbuf.empty() && c->child_pid <= 0) {
        close_connection(c);
    }
}

bool require_auth(std::shared_ptr<Connection> c, const std::string& provided) {
    if (auth_rate_limited(c->peer_ip)) {
        send_simple_response(c, 429, "Too Many Requests", "text/plain",
                              "too many failed attempts from this address, slow down\n");
        return false;
    }
    if (tokens_match(provided, g_token)) return true;
    record_auth_failure(c->peer_ip);
    send_simple_response(c, 401, "Unauthorized", "text/plain", "Missing or invalid token\n");
    return false;
}

void start_run(std::shared_ptr<Connection> c, const std::string& command_line) {
    if (g_scan_busy.exchange(true)) {
        send_simple_response(c, 409, "Conflict", "text/plain",
                              "A scan is already running on this server. Try again shortly.\n");
        return;
    }

    std::vector<std::string> tokens;
    std::string tok_err;
    if (!tokenize_command(command_line, tokens, tok_err)) {
        g_scan_busy = false;
        send_simple_response(c, 400, "Bad Request", "text/plain", "parse error: " + tok_err + "\n");
        return;
    }
    if (tokens.empty()) {
        g_scan_busy = false;
        send_simple_response(c, 400, "Bad Request", "text/plain", "empty command\n");
        return;
    }
    if (tokens.front() == "shiv") tokens.erase(tokens.begin());
    for (const auto& t : tokens) {
        if (t == "--server") {
            g_scan_busy = false;
            send_simple_response(c, 400, "Bad Request", "text/plain",
                                  "refusing to start a nested --server from here\n");
            return;
        }
    }
    if (g_self_path.empty()) {
        g_scan_busy = false;
        send_simple_response(c, 500, "Internal Server Error", "text/plain",
                              "could not resolve own executable path\n");
        return;
    }

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0) {
        g_scan_busy = false;
        send_simple_response(c, 500, "Internal Server Error", "text/plain", "pipe() failed\n");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        g_scan_busy = false;
        send_simple_response(c, 500, "Internal Server Error", "text/plain", "fork() failed\n");
        return;
    }

    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(g_self_path.c_str()));
        for (auto& t : tokens) argv.push_back(const_cast<char*>(t.c_str()));
        argv.push_back(nullptr);

        execv(g_self_path.c_str(), argv.data());
        const char* msg = "execv() failed\n";
        if (write(STDERR_FILENO, msg, strlen(msg)) < 0) {}
        _exit(127);
    }
    close(pipefd[1]);
    set_nonblocking(pipefd[0]);
    set_cloexec(pipefd[0]);

    c->child_pid = pid;
    g_running_pid = pid;
    c->child_stdout_fd = pipefd[0];
    c->state = ConnState::STREAMING_OUTPUT;
    g_conns[pipefd[0]] = c;
    epoll_add(pipefd[0], EPOLLIN);

    std::ostringstream head;
    head << "HTTP/1.1 200 OK\r\n"
         << "Content-Type: text/plain; charset=utf-8\r\n"
         << "Transfer-Encoding: chunked\r\n"
         << security_headers()
         << "Connection: close\r\n\r\n";
    queue_and_flush(c, head.str());
}

std::string make_chunk(const char* data, size_t len) {
    std::ostringstream chunk;
    chunk << std::hex << len << "\r\n";
    std::string out = chunk.str();
    out.append(data, len);
    out += "\r\n";
    return out;
}

void on_child_pipe_readable(std::shared_ptr<Connection> c) {
    char buf[kReadChunk];
    for (;;) {
        ssize_t n = read(c->child_stdout_fd, buf, sizeof(buf));
        if (n > 0) {
            queue_and_flush(c, make_chunk(buf, static_cast<size_t>(n)));
            if (c->state == ConnState::DONE) return;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n < 0 && errno == EINTR) continue;
        c->child_eof = true;
        reap_child(*c);
        queue_and_flush(c, "0\r\n\r\n");
        if (c->state != ConnState::DONE && c->outbuf.empty()) close_connection(c);
        return;
    }
}

void dispatch(std::shared_ptr<Connection> c, const HttpRequest& req) {
    if (req.method == "GET" && (req.path == "/" || req.path == "/index.html")) {
        auto cookies = parse_cookies(header_value(req, "cookie"));
        auto cit = cookies.find(kCookieName);
        if (cit != cookies.end() && tokens_match(cit->second, g_token)) {
            send_simple_response(c, 200, "OK", "text/html; charset=utf-8", render_terminal_page(g_token));
            return;
        }

        auto q = parse_query(req.query);
        auto it = q.find("token");
        std::string provided = it != q.end() ? it->second : std::string();
        if (!require_auth(c, provided)) return;

        std::ostringstream head;
        head << "HTTP/1.1 303 See Other\r\n"
             << "Location: /\r\n"
             << "Set-Cookie: " << kCookieName << "=" << g_token
             << "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" << kCookieMaxAgeSec
             << (g_secure_cookies ? "; Secure" : "") << "\r\n"
             << security_headers()
             << "Content-Length: 0\r\n"
             << "Connection: close\r\n\r\n";
        c->outbuf += head.str();
        if (flush_outbuf(c) && c->outbuf.empty()) close_connection(c);
        return;
    }

    if (req.method == "POST" && (req.path == "/run" || req.path == "/kill")) {
        std::string provided = header_value(req, "x-shiv-token");
        if (provided.empty()) {
            auto cookies = parse_cookies(header_value(req, "cookie"));
            auto cit = cookies.find(kCookieName);
            if (cit != cookies.end()) provided = cit->second;
        }
        if (!require_auth(c, provided)) return;

        if (req.path == "/run") {
            start_run(c, req.body);
            return;
        }

        // /kill
        if (g_running_pid > 0) {
            std::cerr << "[shiv-server] kill requested from " << c->peer_ip
                       << " for pid " << g_running_pid << "\n";
            kill(g_running_pid, SIGINT);
            send_simple_response(c, 200, "OK", "text/plain", "sent interrupt\n");
        } else {
            send_simple_response(c, 200, "OK", "text/plain", "no scan running\n");
        }
        return;
    }

    send_simple_response(c, 404, "Not Found", "text/plain", "not found\n");
}

void on_client_readable(std::shared_ptr<Connection> c) {
    char buf[kReadChunk];
    for (;;) {
        ssize_t n = read(c->fd, buf, sizeof(buf));
        if (n > 0) {
            if (c->inbuf.size() + static_cast<size_t>(n) > kMaxHeaderBytes + kMaxBodyBytes) {
                send_simple_response(c, 413, "Payload Too Large", "text/plain", "request too large\n");
                return;
            }
            c->inbuf.append(buf, static_cast<size_t>(n));
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n < 0 && errno == EINTR) continue;
        close_connection(c);
        return;
    }

    if (!c->headers_parsed) {
        size_t pos = c->inbuf.find("\r\n\r\n");
        if (pos == std::string::npos) {
            if (c->inbuf.size() > kMaxHeaderBytes) {
                send_simple_response(c, 431, "Request Header Fields Too Large", "text/plain", "headers too large\n");
            }
            return;
        }
        c->header_end = pos + 4;
        c->headers_parsed = true;

        HttpRequest req;
        if (!parse_request(c->inbuf, pos, req)) {
            send_simple_response(c, 400, "Bad Request", "text/plain", "malformed request line\n");
            return;
        }

        if (req.headers.find("transfer-encoding") != req.headers.end()) {
            send_simple_response(c, 400, "Bad Request", "text/plain",
                                  "Transfer-Encoding is not supported\n");
            return;
        }

        if (req.method == "POST") {
            auto cl = req.headers.find("content-length");
            size_t declared = cl != req.headers.end() ? strtoul(cl->second.c_str(), nullptr, 10) : 0;
            if (declared > kMaxBodyBytes) {
                send_simple_response(c, 413, "Payload Too Large", "text/plain", "command too long\n");
                return;
            }
            c->content_length = declared;
        }
        if (req.method != "POST" || c->content_length == 0) {
            dispatch(c, req);
            return;
        }

    }

    if (c->state == ConnState::READING_REQUEST) {
        size_t have_body = c->inbuf.size() > c->header_end ? c->inbuf.size() - c->header_end : 0;
        if (have_body < c->content_length) return;

        HttpRequest req;
        if (!parse_request(c->inbuf, c->header_end - 4, req)) {
            send_simple_response(c, 400, "Bad Request", "text/plain", "malformed request\n");
            return;
        }
        req.body = c->inbuf.substr(c->header_end, c->content_length);
        dispatch(c, req);
    }
}

void on_listener_readable(int listen_fd) {
    for (;;) {
        struct sockaddr_in peer{};
        socklen_t peerlen = sizeof(peer);
        int fd = accept4(listen_fd, reinterpret_cast<struct sockaddr*>(&peer), &peerlen,
                          SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            return;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        auto c = std::make_shared<Connection>();
        c->fd = fd;
        c->created_at = std::time(nullptr);
        char ipbuf[INET_ADDRSTRLEN];
        c->peer_ip = inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf)) ? ipbuf : "unknown";
        g_conns[fd] = c;
        epoll_add(fd, EPOLLIN | EPOLLRDHUP);
    }
}

void sweep_idle_connections() {
    static std::time_t last_sweep = 0;
    std::time_t now = std::time(nullptr);
    if (now - last_sweep < kSweepIntervalSec) return;
    last_sweep = now;

    std::vector<int> stale;
    for (auto& [fd, c] : g_conns) {
        if (c->fd != fd) continue;  // skip child-stdout pipe entries
        if (c->state == ConnState::READING_REQUEST &&
            now - c->created_at > kConnIdleTimeoutSec) {
            stale.push_back(fd);
        }
    }
    for (int fd : stale) {
        auto it = g_conns.find(fd);
        if (it != g_conns.end()) close_connection(it->second);
    }
}

bool command_exists(const std::string& cmd) {
    std::string check = "command -v " + cmd + " >/dev/null 2>&1";
    return std::system(check.c_str()) == 0;
}

bool ensure_stunnel_installed() {
    if (command_exists("stunnel") || command_exists("stunnel4")) return true;

    std::cerr << "stunnel not found. It should have been installed by setup.sh -- "
                 "run 'sudo ./setup.sh' to install stunnel and shiv's other "
                 "dependencies, then try --server again.\n";
    return false;
}

bool ensure_tls_cert() {
    struct stat st{};
    if (stat(kStunnelCertPath, &st) == 0) return true;

    std::cout << "Generating self-signed TLS cert at " << kStunnelCertPath << "...\n";
    std::string mkdir_cmd = std::string("mkdir -p ") + kStunnelDir;
    if (std::system(mkdir_cmd.c_str()) != 0) {}

    char tmp_key[] = "/tmp/shiv_key_XXXXXX";
    char tmp_crt[] = "/tmp/shiv_crt_XXXXXX";
    int kfd = mkstemp(tmp_key);
    int cfd = mkstemp(tmp_crt);
    if (kfd < 0 || cfd < 0) {
        if (kfd >= 0) close(kfd);
        if (cfd >= 0) close(cfd);
        std::cerr << "Could not create temp files for cert generation.\n";
        return false;
    }
    close(kfd);
    close(cfd);

    std::string gen_cmd = std::string("openssl req -x509 -newkey rsa:2048 -nodes -keyout ") +
                           tmp_key + " -out " + tmp_crt +
                           " -days 365 -subj /CN=shiv >/dev/null 2>&1";
    bool ok = (std::system(gen_cmd.c_str()) == 0);
    if (ok) {
        std::string combine_cmd = std::string("cat ") + tmp_crt + " " + tmp_key + " > " +
                                   kStunnelCertPath + " && chmod 600 " + kStunnelCertPath;
        ok = (std::system(combine_cmd.c_str()) == 0);
    } else {
        std::cerr << "openssl failed to generate a certificate.\n";
    }
    std::remove(tmp_key);
    std::remove(tmp_crt);
    return ok && stat(kStunnelCertPath, &st) == 0;
}

bool write_stunnel_config(int tls_port) {
    std::ofstream out(kStunnelConfPath, std::ios::trunc);
    if (!out) return false;
    out << "foreground = yes\n"
        << "[shiv]\n"
        << "accept = 0.0.0.0:" << tls_port << "\n"
        << "connect = 127.0.0.1:" << kDefaultPort << "\n"
        << "cert = " << kStunnelCertPath << "\n"
        << "sslVersionMin = TLSv1.2\n"
        << "ciphers = HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA\n";
    return out.good();
}

std::vector<int> pids_listening_on_port(int port) {
    std::vector<int> pids;
    std::string cmd = "ss -H -tlnp 'sport = :" + std::to_string(port) + "' 2>/dev/null";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return pids;
    char buf[1024];
    while (fgets(buf, sizeof(buf), p)) {
        std::string line(buf);
        size_t pos = line.find("pid=");
        while (pos != std::string::npos) {
            int pid = std::atoi(line.c_str() + pos + 4);
            if (pid > 0) pids.push_back(pid);
            pos = line.find("pid=", pos + 4);
        }
    }
    pclose(p);
    return pids;
}

std::string process_comm(int pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
    std::string name;
    std::getline(f, name);
    return name;
}

std::string process_exe_path(int pid) {
    char buf[4096];
    std::string link = "/proc/" + std::to_string(pid) + "/exe";
    ssize_t n = readlink(link.c_str(), buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf, static_cast<size_t>(n));
}

bool wait_for_port_listening(int port, std::vector<std::string>* occupants = nullptr,
                              int max_attempts = 20, int delay_us = 100000) {
    for (int attempt = 0; attempt < max_attempts; ++attempt) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(static_cast<uint16_t>(port));
            inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            int rc = connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
            close(fd);
            if (rc == 0) return true;
        }
        if (occupants) {
            for (int pid : pids_listening_on_port(port)) {
                std::string tag = std::to_string(pid) + " (" +
                                   (process_comm(pid).empty() ? "unknown" : process_comm(pid)) + ")";
                if (std::find(occupants->begin(), occupants->end(), tag) == occupants->end())
                    occupants->push_back(tag);
            }
        }
        usleep(static_cast<useconds_t>(delay_us));
    }
    return false;
}

constexpr const char* kStunnelManualLogPath = "/tmp/shiv_stunnel_start.log";

void print_captured_stunnel_output() {
    std::ifstream log(kStunnelManualLogPath);
    if (!log) return;
    std::string line;
    bool any = false;
    while (std::getline(log, line)) {
        if (!any) { std::cerr << "stunnel said:\n"; any = true; }
        std::cerr << "  " << line << "\n";
    }
    if (!any) std::cerr << "(stunnel produced no output -- it may have exited before printing anything)\n";
}

void print_systemd_unit_failure(const std::string& unit) {
    std::string cmd = "journalctl -u " + unit + " -n 20 --no-pager 2>/dev/null";
    FILE* p = popen(cmd.c_str(), "r");
    if (!p) return;
    char buf[512];
    bool any = false;
    while (fgets(buf, sizeof(buf), p)) {
        if (!any) { std::cerr << unit << " journal:\n"; any = true; }
        std::cerr << "  " << buf;
    }
    pclose(p);
    if (!any) std::cerr << "(no journal output for " << unit << " -- is journald running?)\n";
}

void clear_stale_listener(int tls_port) {
    [[maybe_unused]] int rc_stop1 = std::system("systemctl stop stunnel4 >/dev/null 2>&1");
    [[maybe_unused]] int rc_stop2 = std::system("systemctl stop stunnel@shiv >/dev/null 2>&1");
    std::string pkill_cmd = std::string("pkill -f '") + kStunnelConfPath + "' >/dev/null 2>&1";
    [[maybe_unused]] int rc_pkill = std::system(pkill_cmd.c_str());
    constexpr int kMaxAttempts        = 20;
    constexpr int kSigkillAfterAttempt = 10;
    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        auto pids = pids_listening_on_port(tls_port);
        if (pids.empty()) return;

        bool killed_any = false;
        for (int pid : pids) {
            std::string comm = process_comm(pid);
            if (comm.find("stunnel") != std::string::npos) {
                kill(pid, attempt < kSigkillAfterAttempt ? SIGTERM : SIGKILL);
                killed_any = true;
            } else {
                std::cerr << "Port " << tls_port << " is already in use by pid " << pid
                           << " (" << (comm.empty() ? "unknown process" : comm)
                           << "), which isn't stunnel -- leaving it alone. Pick a "
                              "different --server-port or stop that process yourself.\n";
            }
        }
        if (!killed_any) return;
        usleep(100000);
    }
    for (int pid : pids_listening_on_port(tls_port)) {
        std::string comm = process_comm(pid);
        if (comm.find("stunnel") != std::string::npos) {
            std::cerr << "Port " << tls_port << " is still held by stunnel pid " << pid
                       << " after SIGTERM/SIGKILL -- it may be stuck (e.g. uninterruptible "
                          "I/O). The next start attempt may still fail with "
                          "\"Address already in use\".\n";
        }
    }
}

bool looks_like_shiv(int pid) {
    if (process_comm(pid) == "shiv") return true;
    std::string exe = process_exe_path(pid);
    return !exe.empty() && !g_self_path.empty() && exe == g_self_path;
}

void clear_stale_shiv_listener(int port) {
    pid_t self = getpid();
    constexpr int kMaxAttempts        = 20;
    constexpr int kSigkillAfterAttempt = 10;
    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        auto pids = pids_listening_on_port(port);
        bool killed_any = false;
        for (int pid : pids) {
            if (pid == self) continue;  // nothing of ours is listening yet at this point
            if (looks_like_shiv(pid)) {
                kill(pid, attempt < kSigkillAfterAttempt ? SIGTERM : SIGKILL);
                killed_any = true;
            } else {
                std::string comm = process_comm(pid);
                std::cerr << "Port " << port << " is already in use by pid " << pid
                           << " (" << (comm.empty() ? "unknown process" : comm)
                           << "), which isn't shiv -- leaving it alone. Stop that "
                              "process yourself before starting shiv --server.\n";
            }
        }
        if (!killed_any) return;
        usleep(100000);
    }
    for (int pid : pids_listening_on_port(port)) {
        if (pid == self) continue;
        if (looks_like_shiv(pid)) {
            std::cerr << "Port " << port << " is still held by a previous shiv pid " << pid
                       << " after SIGTERM/SIGKILL -- it may be stuck (e.g. uninterruptible "
                          "I/O). The bind() below may still fail with "
                          "\"Address already in use\".\n";
        }
    }
}

bool start_stunnel(int tls_port) {
    clear_stale_listener(tls_port);
    bool started = false;
    bool used_manual_launch = false;
    std::string started_via_unit;
    if (std::system("systemctl restart stunnel4 >/dev/null 2>&1") == 0) {
        started = true;
        started_via_unit = "stunnel4";
    } else if (std::system("systemctl restart stunnel@shiv >/dev/null 2>&1") == 0) {
        started = true;
        started_via_unit = "stunnel@shiv";
    } else {
        used_manual_launch = true;
        std::string pkill_cmd = std::string("pkill -f '") + kStunnelConfPath + "' >/dev/null 2>&1; ";
        if (std::system(pkill_cmd.c_str()) != 0) {}
        std::string log_redirect = std::string(" >") + kStunnelManualLogPath + " 2>&1";
        std::string cmd = "stunnel " + std::string(kStunnelConfPath) + log_redirect + " &";
        started = (std::system(cmd.c_str()) == 0);
        if (!started) {
            std::string cmd4 = "stunnel4 " + std::string(kStunnelConfPath) + log_redirect + " &";
            started = (std::system(cmd4.c_str()) == 0);
        }
    }
    if (!started) {
        if (used_manual_launch) print_captured_stunnel_output();
        return false;
    }

    std::vector<std::string> occupants;
    if (!wait_for_port_listening(tls_port, &occupants)) {
        std::cerr << "stunnel did not come up listening on port " << tls_port << ".\n";
        if (!occupants.empty()) {
            std::cerr << "While waiting, this was seen holding the port (even briefly):\n";
            for (const auto& o : occupants) std::cerr << "  pid " << o << "\n";
        } else {
            std::cerr << "No process was observed holding port " << tls_port
                       << " at any point during the ~2s wait either. That means whatever's "
                          "conflicting is faster than this check can catch, or the bind is "
                          "failing for a reason unrelated to another occupant (e.g. a "
                          "dual-stack IPv4/IPv6 edge case, or an LSM like SELinux/AppArmor "
                          "denying the bind). Useful next steps:\n"
                          "  watch -n 0.05 'sudo ss -tlnp | grep " << tls_port << "'   "
                          "(run this in another terminal while retrying, to try to catch it live)\n"
                          "  sudo dmesg | tail -50                                    "
                          "(check for LSM denials around the time of the failure)\n";
        }
        if (used_manual_launch) {
            print_captured_stunnel_output();
        } else if (!started_via_unit.empty()) {
            print_systemd_unit_failure(started_via_unit);
        }
        return false;
    }
    std::string ufw_cmd = "command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | "
                           "grep -q 'Status: active' && ufw allow " + std::to_string(tls_port) +
                           "/tcp >/dev/null 2>&1";
    if (std::system(ufw_cmd.c_str()) != 0) {}
    return true;
}

void stop_stunnel() {
    if (std::system("systemctl stop stunnel4 >/dev/null 2>&1") == 0) return;
    if (std::system("systemctl stop stunnel@shiv >/dev/null 2>&1") == 0) return;
    std::string cmd = std::string("pkill -f '") + kStunnelConfPath + "' >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) {}
}

}

int run(int argc, char* argv[]) {
    ensure_root(argc, argv);

    int tls_port = kDefaultTlsPort;
    const std::string bind_addr = "127.0.0.1";
    std::string fixed_token;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << name << " requires a value\n";
                std::exit(1);
            }
            return argv[++i];
        };
        if (arg == "--server-port") {
            tls_port = std::atoi(next("--server-port").c_str());
        } else if (arg == "--server-token") {
            fixed_token = next("--server-token");
            std::cerr << "warning: --server-token puts the token in argv, which is visible to "
                         "any local user via `ps` or /proc/<pid>/cmdline, and often ends up in "
                         "shell history. Prefer leaving this unset and using the randomly "
                         "generated token shiv prints on startup.\n";
        } else {
            std::cerr << "Unknown --server option: " << arg << "\n";
            return 1;
        }
    }
    if (tls_port <= 0 || tls_port > 65535) {
        std::cerr << "--server-port must be 1-65535\n";
        return 1;
    }
    if (tls_port == kDefaultPort) {
        std::cerr << "--server-port cannot be " << kDefaultPort
                   << " (reserved for shiv's internal loopback listener)\n";
        return 1;
    }
    if (!fixed_token.empty() && fixed_token.size() < kMinFixedTokenLen) {
        std::cerr << "--server-token must be at least " << kMinFixedTokenLen
                   << " characters (needs enough entropy to resist guessing)\n";
        return 1;
    }

    g_self_path = resolve_self_path();
    if (g_self_path.empty()) {
        std::cerr << "Could not resolve /proc/self/exe; refusing to start.\n";
        return 1;
    }

    g_token = !fixed_token.empty() ? fixed_token : random_token();
    if (g_token.empty()) {
        std::cerr << "Could not generate an auth token (/dev/urandom unavailable).\n";
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    signal(SIGCHLD, SIG_DFL);
    clear_stale_shiv_listener(kDefaultPort);

    int listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        std::cerr << "socket() failed: " << strerror(errno) << "\n";
        return 1;
    }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(kDefaultPort));
    if (inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "Internal error: invalid loopback bind address '" << bind_addr << "'\n";
        return 1;
    }
    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::cerr << "bind() failed: " << strerror(errno) << "\n";
        return 1;
    }
    if (listen(listen_fd, 32) != 0) {
        std::cerr << "listen() failed: " << strerror(errno) << "\n";
        return 1;
    }

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0) {
        std::cerr << "epoll_create1() failed: " << strerror(errno) << "\n";
        return 1;
    }
    epoll_add(listen_fd, EPOLLIN);

    std::cout << "shiv server listening on " << bind_addr << ":" << kDefaultPort << " (loopback only)\n";
    std::cout << "Auth token: " << g_token << "\n";

    bool tls_ready = false;
    if (!ensure_stunnel_installed()) {
        std::cout << "Falling back to plaintext, loopback-only: http://127.0.0.1:" << kDefaultPort
                   << "/?token=" << g_token << "\n";
    } else if (!ensure_tls_cert()) {
        std::cout << "Falling back to plaintext, loopback-only: http://127.0.0.1:" << kDefaultPort
                   << "/?token=" << g_token << "\n";
    } else if (!write_stunnel_config(tls_port)) {
        std::cout << "Could not write " << kStunnelConfPath << " (are you root?); TLS not started.\n";
    } else if (!start_stunnel(tls_port)) {
        std::cout << "Could not start stunnel; TLS not started. Is it installed?\n";
    } else {
        tls_ready = true;
    }
    g_secure_cookies = tls_ready;

    if (tls_ready) {
        auto ips = list_local_ipv4();
        if (!ips.empty()) {
            std::cout << "  Open: https://" << ips.front() << ":" << tls_port << "/?token=" << g_token << "\n";
            for (size_t i = 1; i < ips.size(); ++i) {
                std::cout << "  Also reachable at: https://" << ips[i] << ":" << tls_port
                           << "/?token=" << g_token << "\n";
            }
        } else {
            std::cout << "  Open: https://<this-host-ip>:" << tls_port << "/?token=" << g_token << "\n";
        }
        std::cout << "(TLS via stunnel on port " << tls_port
                   << " — your browser will warn about the self-signed cert the first time, that's expected.\n"
                   << " Verify it's YOUR cert before accepting: openssl x509 -in " << kStunnelCertPath
                   << " -noout -fingerprint -sha256)\n";
    }

    std::vector<struct epoll_event> events(kMaxEvents);
    while (!g_shutdown) {
        int n = epoll_wait(g_epfd, events.data(), kMaxEvents, kEpollTimeoutMs);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            uint32_t ev = events[i].events;

            if (fd == listen_fd) {
                on_listener_readable(listen_fd);
                continue;
            }

            auto it = g_conns.find(fd);
            if (it == g_conns.end()) continue;
            std::shared_ptr<Connection> c = it->second;

            if (c->child_stdout_fd == fd) {
                if (ev & (EPOLLIN | EPOLLHUP | EPOLLERR)) on_child_pipe_readable(c);
                continue;
            }
            if (ev & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
                close_connection(c);
                continue;
            }
            if (ev & EPOLLOUT) {
                if (!flush_outbuf(c)) { close_connection(c); continue; }
                if (c->outbuf.empty() && c->child_pid <= 0 && c->state != ConnState::STREAMING_OUTPUT) {
                    close_connection(c);
                    continue;
                }
            }
            if (ev & EPOLLIN) {
                on_client_readable(c);
            }
        }
        sweep_idle_connections();
    }

    std::cout << "\nshiv server shutting down\n";
    for (auto& [fd, c] : g_conns) {
        if (c->fd == fd && c->child_pid > 0) kill(c->child_pid, SIGKILL);
    }
    if (tls_ready) stop_stunnel();
    close(listen_fd);
    close(g_epfd);
    return 0;
}

}
