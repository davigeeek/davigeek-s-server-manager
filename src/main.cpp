#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

struct Proc {
#ifdef _WIN32
    HANDLE h = nullptr, in = nullptr, out = nullptr;
    DWORD pid = 0;
#else
    pid_t pid = -1;
    int in = -1, out = -1;
#endif
    int code = -1;
    bool reaped = false;

    using Env = std::vector<std::pair<std::string, std::string>>;
    bool start(const std::vector<std::string>& argv, const fs::path& cwd = {}, const Env& env = {}) {
#ifdef _WIN32
        SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
        HANDLE inR, inW, outR, outW;
        if (!CreatePipe(&inR, &inW, &sa, 0) || !CreatePipe(&outR, &outW, &sa, 0)) return false;
        SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);
        STARTUPINFOA si{};
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = inR; si.hStdOutput = outW; si.hStdError = outW;
        std::string cmd;
        for (auto& a : argv) { if (!cmd.empty()) cmd += ' '; cmd += '"' + a + '"'; }
        std::string cwds = cwd.string();
        Env saved;
        for (auto& kv : env) {
            std::vector<char> buf(32768); DWORD n = GetEnvironmentVariableA(kv.first.c_str(), buf.data(), (DWORD)buf.size());
            saved.push_back({kv.first, n ? std::string(buf.data(), n) : std::string()});
            SetEnvironmentVariableA(kv.first.c_str(), kv.second.c_str());
        }
        PROCESS_INFORMATION pi{};
        BOOL ok = CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                                 cwds.empty() ? nullptr : cwds.c_str(), &si, &pi);
        for (auto& kv : saved) SetEnvironmentVariableA(kv.first.c_str(), kv.second.empty() ? nullptr : kv.second.c_str());
        CloseHandle(inR); CloseHandle(outW);
        if (!ok) { CloseHandle(inW); CloseHandle(outR); return false; }
        CloseHandle(pi.hThread);
        h = pi.hProcess; pid = pi.dwProcessId; in = inW; out = outR;
        return true;
#else
        int a[2], b[2];
        if (pipe(a) || pipe(b)) return false;
        pid = fork();
        if (pid < 0) return false;
        if (pid == 0) {
            setsid();
            dup2(a[0], 0); dup2(b[1], 1); dup2(b[1], 2);
            close(a[0]); close(a[1]); close(b[0]); close(b[1]);
            if (!cwd.empty() && chdir(cwd.c_str()) != 0) _exit(126);
            for (auto& kv : env) setenv(kv.first.c_str(), kv.second.c_str(), 1);
            std::vector<char*> av;
            for (auto& s : argv) av.push_back(const_cast<char*>(s.c_str()));
            av.push_back(nullptr);
            execvp(av[0], av.data());
            _exit(127);
        }
        close(a[0]); close(b[1]);
        in = a[1]; out = b[0];
        return true;
#endif
    }
    long read(char* buf, size_t n) {
#ifdef _WIN32
        DWORD got = 0;
        if (!ReadFile(out, buf, (DWORD)n, &got, nullptr) || !got) return -1;
        return (long)got;
#else
        ssize_t r;
        do { r = ::read(out, buf, n); } while (r < 0 && errno == EINTR);
        return r > 0 ? (long)r : -1;
#endif
    }
    void write(const std::string& s) {
#ifdef _WIN32
        DWORD w; WriteFile(in, s.data(), (DWORD)s.size(), &w, nullptr);
#else
        ssize_t r = ::write(in, s.data(), s.size()); (void)r;
#endif
    }
    bool running() {
#ifdef _WIN32
        return h && WaitForSingleObject(h, 0) == WAIT_TIMEOUT;
#else
        if (pid <= 0 || reaped) return false;
        int st;
        pid_t r = waitpid(pid, &st, WNOHANG);
        if (r == 0) return true;
        reaped = true; code = (r == pid && WIFEXITED(st)) ? WEXITSTATUS(st) : -1;
        return false;
#endif
    }
    int wait() {
#ifdef _WIN32
        if (h) { WaitForSingleObject(h, INFINITE); DWORD c = 0; GetExitCodeProcess(h, &c); code = (int)c; }
#else
        if (pid > 0 && !reaped) {
            int st; waitpid(pid, &st, 0);
            reaped = true; code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        }
#endif
        return code;
    }
    void terminate(bool force) {
#ifdef _WIN32
        Proc p; p.start({"taskkill", "/T", "/F", "/PID", std::to_string(pid)});
        char b[256]; while (p.read(b, sizeof b) > 0) {} p.wait(); (void)force;
#else
        if (pid > 0) ::kill(-pid, force ? SIGKILL : SIGTERM);
#endif
    }
    ~Proc() {
#ifdef _WIN32
        if (in) CloseHandle(in); if (out) CloseHandle(out); if (h) CloseHandle(h);
#else
        if (in >= 0) close(in); if (out >= 0) close(out);
#endif
    }
};

struct ExecResult { std::string out; int code; };
ExecResult exec_capture(const std::vector<std::string>& argv, const fs::path& cwd = {}) {
    Proc p;
    if (!p.start(argv, cwd)) return {"", -1};
    std::string out; char buf[8192]; long n;
    while ((n = p.read(buf, sizeof buf)) > 0) out.append(buf, n);
    return {out, p.wait()};
}

struct Config {
    std::string root, curseforge_key, java = "java", public_address;
    int port = 8080, default_ram = 4096;
} cfg;
std::mutex cfg_m;
fs::path g_home;
fs::path user_home() { const char* h = getenv("HOME"); if (!h) h = getenv("USERPROFILE"); return h ? h : "."; }
fs::path config_home() {
    if (const char* e = getenv("SERVERMANAGER_HOME")) return e;
#ifdef _WIN32
    const char* a = getenv("APPDATA"); return fs::path(a ? a : ".") / "servermanager";
#else
    const char* x = getenv("XDG_CONFIG_HOME"); return x && *x ? fs::path(x) / "servermanager" : user_home() / ".config" / "servermanager";
#endif
}

void save_config() {
    json j = {{"root", cfg.root}, {"port", cfg.port}, {"curseforge_key", cfg.curseforge_key}, {"java", cfg.java},
              {"public_address", cfg.public_address}, {"default_ram", cfg.default_ram}};
    std::ofstream(g_home / "config.json") << j.dump(2);
}
void load_config() {
    std::error_code ec;
    fs::create_directories(g_home / "servers", ec);
    cfg.root = (user_home() / "minecraft-servers").string();
    if (!fs::exists(g_home / "config.json", ec) && fs::exists("config.json", ec)) fs::copy_file("config.json", g_home / "config.json", ec);
    std::ifstream f(g_home / "config.json");
    if (f) {
        json j = json::parse(f, nullptr, false);
        if (j.is_object()) {
            cfg.root = j.value("root", cfg.root); cfg.port = j.value("port", cfg.port);
            cfg.curseforge_key = j.value("curseforge_key", ""); cfg.java = j.value("java", cfg.java);
            cfg.public_address = j.value("public_address", ""); cfg.default_ram = j.value("default_ram", cfg.default_ram);
        }
    }
    fs::create_directories(cfg.root, ec);
    save_config();
}
int default_ram() { std::lock_guard<std::mutex> l(cfg_m); return cfg.default_ram; }
fs::path root_dir() { std::lock_guard<std::mutex> l(cfg_m); return fs::absolute(cfg.root); }
int config_port() { std::lock_guard<std::mutex> l(cfg_m); return cfg.port; }

std::string url_enc(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string o;
    for (unsigned char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') o += (char)c;
        else { o += '%'; o += hex[c >> 4]; o += hex[c & 15]; }
    }
    return o;
}
std::vector<std::string> curl_base(const std::vector<std::string>& headers) {
    std::vector<std::string> a = {"curl", "-sL", "--fail", "--max-time", "600", "-A", "ServerManager/1.0"};
    for (auto& h : headers) { a.push_back("-H"); a.push_back(h); }
    return a;
}
std::string http_get(const std::string& url, const std::vector<std::string>& headers = {}) {
    auto a = curl_base(headers); a.push_back(url);
    auto r = exec_capture(a);
    if (r.code != 0) throw std::runtime_error("HTTP request failed: " + url);
    return r.out;
}
json jget(const std::string& url, const std::vector<std::string>& headers = {}) {
    json j = json::parse(http_get(url, headers), nullptr, false);
    if (j.is_discarded()) throw std::runtime_error("Invalid JSON from " + url);
    return j;
}
void download(const std::string& url, const fs::path& dest) {
    fs::create_directories(dest.parent_path());
    fs::path tmp = dest; tmp += ".part";
    auto a = curl_base({}); a.push_back("-o"); a.push_back(tmp.string()); a.push_back(url);
    auto r = exec_capture(a);
    if (r.code != 0) { std::error_code ec; fs::remove(tmp, ec); throw std::runtime_error("Download failed: " + url); }
    fs::rename(tmp, dest);
}

std::string read_file(const fs::path& p, size_t maxBytes = 0) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return "";
    std::stringstream ss;
    if (maxBytes) {
        f.seekg(0, std::ios::end); auto sz = (size_t)f.tellg();
        if (sz > maxBytes) f.seekg(sz - maxBytes); else f.seekg(0);
    }
    ss << f.rdbuf();
    return ss.str();
}
std::vector<int> ver_parts(const std::string& v) {
    std::vector<int> o; std::stringstream ss(v); std::string t;
    while (std::getline(ss, t, '.')) o.push_back(atoi(t.c_str()));
    return o;
}
bool ver_less(const std::string& a, const std::string& b) { return ver_parts(a) < ver_parts(b); }

bool safe_name(const std::string& s) {
    if (s.empty() || s.size() > 48 || s[0] == '.') return false;
    for (unsigned char c : s) if (!(isalnum(c) || c == ' ' || c == '-' || c == '_' || c == '.')) return false;
    return s.find("..") == std::string::npos;
}
bool safe_file(const std::string& s) {
    return !s.empty() && s.find('/') == std::string::npos && s.find('\\') == std::string::npos && s != ".." && s != ".";
}
std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t\r\n"); if (a == std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n"); return s.substr(a, b - a + 1);
}
bool safe_version(const std::string& s) {
    if (s.empty() || s.size() > 40) return false;
    for (unsigned char c : s) if (!(isalnum(c) || c == '.' || c == '-' || c == '_' || c == '+')) return false;
    return true;
}
bool is_plugin_loader(const std::string& l) { return l == "paper" || l == "purpur" || l == "spigot" || l == "bukkit"; }
bool is_mod_loader(const std::string& l) { return l == "fabric" || l == "forge" || l == "neoforge" || l == "quilt"; }

std::string sget(const json& j, const char* k) { return j.is_object() && j.contains(k) && j[k].is_string() ? j[k].get<std::string>() : ""; }

std::string content_dir(const std::string& loader) { return is_plugin_loader(loader) ? "plugins" : "mods"; }

fs::path meta_path(const fs::path& dir) { return g_home / "servers" / (dir.filename().string() + ".json"); }
json load_meta(const fs::path& dir) {
    std::error_code ec; fs::path p = meta_path(dir), old = dir / ".servermanager.json";
    if (!fs::exists(p, ec) && fs::exists(old, ec)) { fs::create_directories(p.parent_path(), ec); fs::copy_file(old, p, ec); fs::remove(old, ec); }
    json j = json::parse(read_file(p), nullptr, false);
    return j.is_object() ? j : json::object();
}
void save_meta(const fs::path& dir, const json& j) {
    std::error_code ec; fs::create_directories(meta_path(dir).parent_path(), ec);
    std::ofstream(meta_path(dir)) << j.dump(2);
}

std::mutex g_dc_m;
json g_dc;
bool g_dc_loaded = false;
void dc_load_locked() {
    if (g_dc_loaded) return;
    json j = json::parse(read_file(g_home / "detected.json"), nullptr, false);
    g_dc = j.is_object() ? j : json::object();
    g_dc_loaded = true;
}
json dc_get(const std::string& name) {
    std::lock_guard<std::mutex> l(g_dc_m);
    dc_load_locked();
    return g_dc.contains(name) && g_dc[name].is_object() ? g_dc[name] : json::object();
}
void dc_write_locked() { std::ofstream(g_home / "detected.json") << g_dc.dump(2); }
void dc_set(const std::string& name, const json& v) {
    std::lock_guard<std::mutex> l(g_dc_m);
    dc_load_locked();
    if (g_dc.contains(name) && g_dc[name] == v) return;
    std::error_code ec; fs::create_directories(g_home, ec);
    g_dc[name] = v;
    dc_write_locked();
}
void dc_erase(const std::string& name) {
    std::lock_guard<std::mutex> l(g_dc_m);
    dc_load_locked();
    if (!g_dc.erase(name)) return;
    dc_write_locked();
}

std::map<std::string, std::string> read_props(const fs::path& dir, std::vector<std::string>* order = nullptr) {
    std::map<std::string, std::string> m; std::ifstream f(dir / "server.properties"); std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        auto p = line.find('=');
        if (p == std::string::npos) continue;
        auto k = line.substr(0, p);
        m[k] = line.substr(p + 1);
        if (order) order->push_back(k);
    }
    return m;
}

std::vector<std::string> lan_addresses() {
    std::vector<std::string> out;
#ifdef _WIN32
    ULONG size = 16 * 1024;
    std::vector<char> buf(size);
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    auto get = [&](IP_ADAPTER_ADDRESSES* a) { return GetAdaptersAddresses(AF_INET, flags, nullptr, a, &size); };
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    ULONG rc = get(addrs);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(size);
        addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        rc = get(addrs);
    }
    if (rc == NO_ERROR) {
        for (auto* a = addrs; a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
                if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET) continue;
                char ip[NI_MAXHOST] = {};
                if (getnameinfo(ua->Address.lpSockaddr, (socklen_t)ua->Address.iSockaddrLength, ip, sizeof ip, nullptr, 0, NI_NUMERICHOST) == 0) out.push_back(ip);
            }
        }
    }
#else
    struct ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) == 0) {
        for (auto* i = ifs; i; i = i->ifa_next) {
            if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
            if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK)) continue;
            char ip[NI_MAXHOST] = {};
            if (getnameinfo(i->ifa_addr, sizeof(sockaddr_in), ip, sizeof ip, nullptr, 0, NI_NUMERICHOST) == 0) out.push_back(ip);
        }
        freeifaddrs(ifs);
    }
#endif
    auto score = [](const std::string& ip) {
        if (ip.rfind("192.168.", 0) == 0) return 0;
        if (ip.rfind("10.", 0) == 0) return 1;
        if (ip.rfind("172.", 0) == 0) { int b = atoi(ip.c_str() + 4); if (b >= 16 && b <= 31) return 2; }
        if (ip.rfind("169.254.", 0) == 0) return 9;
        return 3;
    };
    std::sort(out.begin(), out.end(), [&](const std::string& a, const std::string& b) {
        int sa = score(a), sb = score(b);
        return sa != sb ? sa < sb : a < b;
    });
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}
std::vector<std::string> lan_urls() {
    int port = config_port();
    std::vector<std::string> out;
    for (auto& ip : lan_addresses()) out.push_back("http://" + ip + ":" + std::to_string(port));
    return out;
}

std::string version_from_log(const fs::path& dir) {
    std::string log = read_file(dir / "logs" / "latest.log", 256 * 1024);
    std::smatch m;
    if (std::regex_search(log, m, std::regex(R"(starting minecraft server version ([0-9][^\s]*))"))) return m[1];
    if (std::regex_search(log, m, std::regex(R"(loading Minecraft ([0-9][^\s]*))"))) return m[1];
    std::error_code ec;
    fs::path lib = dir / "libraries" / "net" / "minecraft" / "server";
    if (fs::is_directory(lib, ec))
        for (auto& e : fs::directory_iterator(lib, ec)) {
            auto n = e.path().filename().string();
            return n.substr(0, n.find('-'));
        }
    return "";
}
bool has_jar(const fs::path& dir, const std::string& prefix = "") {
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir, ec)) {
        auto n = e.path().filename().string();
        if (e.path().extension() == ".jar" && n.rfind(prefix, 0) == 0) return true;
    }
    return false;
}
std::string loader_version_from_files(const fs::path& dir, const std::string& loader) {
    std::error_code ec; std::smatch m;
    auto firstSub = [&](const fs::path& p) { std::string r; for (auto& e : fs::directory_iterator(p, ec)) r = e.path().filename().string(); return r; };
    if (loader == "forge") { auto n = firstSub(dir / "libraries/net/minecraftforge/forge"); auto d = n.find('-'); return d == std::string::npos ? "" : n.substr(d + 1); }
    if (loader == "neoforge") return firstSub(dir / "libraries/net/neoforged/neoforge");
    if (loader == "fabric" || loader == "quilt") {
        std::string log = read_file(dir / "logs" / "latest.log", 256 * 1024);
        if (std::regex_search(log, m, std::regex(R"(Loader ([0-9][^\s]*))"))) return m[1];
    }
    return "";
}
json detect(const fs::path& dir) {
    std::error_code ec;
    std::string name = dir.filename().string();
    json meta = load_meta(dir);
    std::string loader = meta.value("loader", ""), ver = meta.value("version", "");
    json out = {{"name", name}, {"loader", loader}, {"version", ver}};
    bool any = fs::directory_iterator(dir, ec) != fs::directory_iterator();
    if (!any) { out["loader"] = "empty"; out["icon"] = false; return out; }
    auto ex = [&](const char* p) { return fs::exists(dir / p, ec); };
    if (loader.empty()) {
        if (ex("libraries/net/neoforged")) loader = "neoforge";
        else if (ex("libraries/net/minecraftforge") || has_jar(dir, "forge-")) loader = "forge";
        else if (ex("fabric-server-launch.jar") || ex(".fabric")) loader = "fabric";
        else if (ex("quilt-server-launch.jar")) loader = "quilt";
        else if (ex("purpur.yml")) loader = "purpur";
        else if (ex("config/paper-global.yml") || ex("paper.yml")) loader = "paper";
        else if (ex("spigot.yml")) loader = "spigot";
        else if (has_jar(dir)) loader = "vanilla";
        else loader = "unknown";
    }
    if (ver.empty()) ver = version_from_log(dir);
    std::string lv = meta.value("loader_version", "");
    if (lv.empty()) lv = loader_version_from_files(dir, loader);
    json cached = dc_get(name);
    if (loader == "unknown") { std::string c = sget(cached, "loader"); if (!c.empty()) loader = c; }
    if (ver.empty()) ver = sget(cached, "version");
    if (lv.empty()) lv = sget(cached, "loader_version");
    if (ver.empty()) ver = "unknown";
    out["loader"] = loader; out["version"] = ver; out["loader_version"] = lv;
    out["icon"] = ex("server-icon.png");
    json keep = {{"loader", loader == "unknown" ? "" : loader},
                 {"version", ver == "unknown" ? "" : ver},
                 {"loader_version", lv}};
    if (!keep["loader"].get<std::string>().empty() || !keep["version"].get<std::string>().empty()) dc_set(name, keep);
    return out;
}

struct Running {
    Proc p; std::mutex m; std::deque<std::string> lines; size_t first = 0; std::time_t started = std::time(nullptr);
    std::atomic<long long> viewer_seen{0};
    std::atomic<bool> window_gone{false};
    void push(const std::string& s) {
        std::lock_guard<std::mutex> l(m);
        lines.push_back(s); if (lines.size() > 3000) { lines.pop_front(); first++; }
    }
};
std::map<std::string, std::shared_ptr<Running>> g_run;
std::mutex g_run_m;

void pump(std::shared_ptr<Running> r) {
    char buf[4096]; std::string cur; long n;
    while ((n = r->p.read(buf, sizeof buf)) > 0)
        for (long i = 0; i < n; i++) {
            if (buf[i] == '\n') { r->push(cur); cur.clear(); } else if (buf[i] != '\r') cur += buf[i];
        }
    if (!cur.empty()) r->push(cur);
    r->p.wait();
    r->push("[manager] process exited with code " + std::to_string(r->p.code));
}
std::shared_ptr<Running> get_run(const std::string& name) {
    std::lock_guard<std::mutex> l(g_run_m);
    auto it = g_run.find(name);
    return it == g_run.end() ? nullptr : it->second;
}
bool is_running(const std::string& name) { auto r = get_run(name); return r && r->p.running(); }

struct JavaInst { int major; std::string path; };
#ifdef _WIN32
const char* JAVA_EXE = "java.exe"; const char PATH_SEP = ';';
#else
const char* JAVA_EXE = "java"; const char PATH_SEP = ':';
#endif
int java_major_from(const std::string& a, const std::string& b) { int x = atoi(a.c_str()); return (x == 1 && !b.empty()) ? atoi(b.c_str()) : x; }
int java_major_by_running(const std::string& exe) {
    std::smatch m; auto r = exec_capture({exe, "-version"});
    if (std::regex_search(r.out, m, std::regex(R"(version \"([0-9]+)(?:\.([0-9]+))?)"))) return java_major_from(m[1], m[2].matched ? m[2].str() : "");
    return 0;
}
std::vector<JavaInst> list_javas() {
    static std::mutex mu; static std::vector<JavaInst> cache; static std::time_t at = 0;
    std::lock_guard<std::mutex> l(mu);
    if (at && std::time(nullptr) - at < 30) return cache;
    std::vector<JavaInst> out; std::set<std::string> seen; std::error_code ec;
    std::vector<fs::path> roots;
#ifdef _WIN32
    for (const char* env : {"ProgramFiles", "ProgramFiles(x86)"})
        if (const char* pf = getenv(env)) for (const char* sub : {"Java", "Eclipse Adoptium", "Microsoft", "Zulu", "Amazon Corretto", "BellSoft"}) roots.push_back(fs::path(pf) / sub);
#else
    roots = {"/usr/lib/jvm", "/usr/lib64/jvm", "/opt/java", "/opt/jdk", "/usr/java", user_home() / ".sdkman/candidates/java", user_home() / ".jdks"};
#endif
    for (auto& root : roots) {
        if (!fs::is_directory(root, ec)) continue;
        for (auto& e : fs::directory_iterator(root, ec))
            for (auto home : {e.path(), e.path() / "Contents" / "Home"}) {
                fs::path bin = home / "bin" / JAVA_EXE;
                if (!fs::exists(bin, ec)) continue;
                if (!seen.insert(fs::weakly_canonical(bin, ec).string()).second) break;
                int mj = 0; std::smatch m; std::string rel = read_file(home / "release");
                if (std::regex_search(rel, m, std::regex(R"(JAVA_VERSION=\"([0-9]+)(?:\.([0-9]+))?)"))) mj = java_major_from(m[1], m[2].matched ? m[2].str() : "");
                if (!mj) mj = java_major_by_running(bin.string());
                if (mj) out.push_back({mj, bin.string()});
                break;
            }
    }
    std::string extra; { std::lock_guard<std::mutex> c(cfg_m); extra = cfg.java; }
    for (std::string c : {std::string("java"), extra}) if (!c.empty()) { int mj = java_major_by_running(c); if (mj) out.push_back({mj, c}); }
    std::sort(out.begin(), out.end(), [](const JavaInst& a, const JavaInst& b) { return a.major < b.major; });
    cache = out; at = std::time(nullptr);
    return out;
}
JavaInst pick_java(int req, const std::vector<JavaInst>& all) {
    for (auto& j : all) if (j.major == req) return j;
    for (auto& j : all) if (j.major > req) return j;
    return {0, ""};
}
int required_java(const json& meta, const std::string& ver) {
    int m = meta.value("java_major", 0);
    if (m > 0) return m;
    auto p = ver_parts(ver);
    if (p.empty() || ver == "unknown") return 0;
    if (p[0] >= 26) return 25;
    if (p[0] == 1 && p.size() >= 2) {
        int mi = p[1], pa = p.size() > 2 ? p[2] : 0;
        if (mi <= 16) return 8;
        if (mi <= 19) return 17;
        if (mi == 20) return pa >= 5 ? 21 : 17;
    }
    return 21;
}
JavaInst resolve_java(const json& meta, const std::string& ver) {
    int req = required_java(meta, ver);
    std::string fallback; { std::lock_guard<std::mutex> c(cfg_m); fallback = cfg.java; }
    if (!req) return {0, fallback};
    auto all = list_javas(); JavaInst j = pick_java(req, all);
    if (j.major) return j;
    std::string have; for (auto& x : all) { if (!have.empty()) have += ", "; have += std::to_string(x.major); }
    throw std::runtime_error("minecraft " + ver + " needs java " + std::to_string(req) + ", but " + (have.empty() ? "no java was found" : "only java " + have + " is installed") +
                             ". on ubuntu: sudo apt install openjdk-" + std::to_string(req) + "-jre-headless");
}
Proc::Env java_env(const JavaInst& j) {
    fs::path exe(j.path);
    if (!exe.is_absolute()) return {};
    const char* old = getenv("PATH");
    return {{"JAVA_HOME", exe.parent_path().parent_path().string()}, {"PATH", exe.parent_path().string() + PATH_SEP + (old ? old : "")}};
}

fs::path server_start_script(const fs::path& dir) {
    std::error_code ec;
#ifdef _WIN32
    for (auto name : {"run.bat", "start.bat"})
        if (fs::is_regular_file(dir / name, ec)) return dir / name;
    for (auto name : {"run.sh", "start.sh"})
        if (fs::is_regular_file(dir / name, ec)) return dir / name;
#else
    for (auto name : {"run.sh", "start.sh"})
        if (fs::is_regular_file(dir / name, ec)) return dir / name;
#endif
    return {};
}

#ifndef _WIN32
bool spawn_detached(const std::vector<std::string>& argv) {
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) {
        pid_t grandchild = fork();
        if (grandchild != 0) _exit(0);
        setsid();
        std::vector<char*> av;
        for (auto& s : argv) av.push_back(const_cast<char*>(s.c_str()));
        av.push_back(nullptr);
        execvp(av[0], av.data());
        _exit(127);
    }
    int st = 0; waitpid(pid, &st, 0);
    return true;
}
std::string find_in_path(const std::string& name) {
    const char* env = getenv("PATH");
    if (!env) return "";
    std::stringstream ss(env); std::string dir;
    while (std::getline(ss, dir, PATH_SEP)) {
        fs::path p = (dir.empty() ? fs::path(".") : fs::path(dir)) / name;
        std::error_code ec;
        if (fs::is_regular_file(p, ec)) return p.string();
    }
    return "";
}
#endif

bool start_console_window(const std::string& name, int port) {
    if (getenv("SERVERMANAGER_NO_CONSOLE_WINDOW")) return false;
#ifdef _WIN32
    char exe[32768];
    DWORD n = GetModuleFileNameA(nullptr, exe, (DWORD)sizeof exe);
    if (!n || n >= (DWORD)sizeof exe) return false;
    std::string cmd = "\"" + std::string(exe) + "\" --console-view " + std::to_string(port) + " \"" + name + "\"";
    std::vector<char> buf(cmd.begin(), cmd.end()); buf.push_back('\0');
    STARTUPINFOA si{}; si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) return false;
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return true;
#elif defined(__linux__)
    const char* display = getenv("DISPLAY"); const char* wayland = getenv("WAYLAND_DISPLAY");
    if ((!display || !*display) && (!wayland || !*wayland)) return false;
    char self[4096];
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) return false;
    self[n] = '\0';
    struct Term { const char* exe; const char* flag; };
    const Term terms[] = {
        {"x-terminal-emulator", "-e"}, {"gnome-terminal", "--"}, {"konsole", "-e"},
        {"xfce4-terminal", "-x"}, {"xterm", "-e"}
    };
    for (auto& t : terms) {
        std::string path = find_in_path(t.exe);
        if (path.empty()) continue;
        std::vector<std::string> av = {path, t.flag, self, "--console-view", std::to_string(port), name};
        return spawn_detached(av);
    }
    return false;
#else
    (void)name; (void)port;
    return false;
#endif
}

std::string start_server(const std::string& name, const fs::path& dir) {
    std::lock_guard<std::mutex> l(g_run_m);
    auto it = g_run.find(name);
    if (it != g_run.end() && it->second->p.running()) return "server is already running";
    for (auto& [other, r] : g_run)
        if (other != name && r->p.running()) return "\"" + other + "\" is running. stop it before starting another server.";
    json meta = load_meta(dir);
    int ram = meta.value("ram", default_ram());
    std::string jar = meta.value("jar", "");
    JavaInst ji;
    try { ji = resolve_java(meta, detect(dir)["version"]); } catch (std::exception& e) { return e.what(); }
    std::vector<std::string> argv;
    std::error_code ec;
    fs::path script = jar.empty() ? server_start_script(dir) : fs::path();
    if (!script.empty()) {
        std::ifstream f(dir / "user_jvm_args.txt"); std::string line, content;
        while (std::getline(f, line)) if (line.rfind("-Xmx", 0) != 0) content += line + "\n";
        content += "-Xmx" + std::to_string(ram) + "M\n";
        std::ofstream(dir / "user_jvm_args.txt") << content;
#ifdef _WIN32
        if (script.extension() == ".sh") argv = {"bash", script.filename().string(), "nogui"};
        else argv = {"cmd", "/c", script.filename().string(), "nogui"};
#else
        argv = {"bash", script.filename().string(), "nogui"};
#endif
    } else {
        if (jar.empty()) {
            for (auto& e : fs::directory_iterator(dir, ec))
                if (e.path().extension() == ".jar" && e.path().filename().string().find("installer") == std::string::npos) { jar = e.path().filename().string(); break; }
        }
        if (jar.empty()) return "no server jar found in this folder";
        argv = {ji.path, "-Xmx" + std::to_string(ram) + "M", "-Xms" + std::to_string(std::min(ram, 1024)) + "M", "-jar", jar, "nogui"};
    }
    auto r = std::make_shared<Running>();
    if (!r->p.start(argv, dir, java_env(ji))) return "could not start process";
    g_run[name] = r;
    std::thread(pump, r).detach();
    if (start_console_window(name, config_port())) r->viewer_seen = (long long)std::time(nullptr);
    return "";
}
void stop_server(const std::string& name) { if (auto r = get_run(name)) if (r->p.running()) r->p.write("stop\n"); }

void watch_console_windows() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        std::vector<std::shared_ptr<Running>> runs;
        {
            std::lock_guard<std::mutex> l(g_run_m);
            for (auto& [n, r] : g_run) runs.push_back(r);
        }
        long long now = (long long)std::time(nullptr);
        for (auto& r : runs) {
            long long seen = r->viewer_seen.load();
            if (!seen || now - seen < 4) continue;
            if (!r->p.running()) continue;
            if (r->window_gone.exchange(true)) continue;
            r->push("[manager] console window closed; stopping server");
            r->p.write("stop\n");
            std::thread([r] {
                for (int i = 0; i < 30 && r->p.running(); i++)
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if (r->p.running()) {
                    r->push("[manager] server did not stop in time; terminating it");
                    r->p.terminate(true);
                }
            }).detach();
        }
    }
}

std::map<std::string, std::pair<std::time_t, json>> g_vcache; std::mutex g_vcache_m;

std::string neo_prefix(std::string mc) {
    if (mc.rfind("1.", 0) == 0) mc = mc.substr(2);
    if (std::count(mc.begin(), mc.end(), '.') == 0) mc += ".0";
    return mc + ".";
}
json vanilla_releases() {
    json m = jget("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json");
    json out = json::array();
    for (auto& v : m["versions"]) if (v["type"] == "release") out.push_back(v["id"]);
    return out;
}
json neoforge_versions() { return jget("https://maven.neoforged.net/api/maven/versions/releases/net/neoforged/neoforge")["versions"]; }
json forge_promos() { return jget("https://files.minecraftforge.net/net/minecraftforge/forge/promotions_slim.json")["promos"]; }

json mc_versions(const std::string& loader) {
    {
        std::lock_guard<std::mutex> l(g_vcache_m);
        auto it = g_vcache.find(loader);
        if (it != g_vcache.end() && std::time(nullptr) - it->second.first < 600) return it->second.second;
    }
    json out = json::array();
    if (loader == "vanilla") out = vanilla_releases();
    else if (loader == "paper" || loader == "purpur") {
        json v = jget(loader == "paper" ? "https://api.papermc.io/v2/projects/paper" : "https://api.purpurmc.org/v2/purpur")["versions"];
        for (auto it = v.rbegin(); it != v.rend(); ++it) out.push_back(*it);
    } else if (loader == "fabric") {
        for (auto& v : jget("https://meta.fabricmc.net/v2/versions/game")) if (v["stable"].get<bool>()) out.push_back(v["version"]);
    } else if (loader == "forge") {
        json promos = forge_promos(); std::set<std::string> s;
        for (auto& [k, v] : promos.items()) s.insert(k.substr(0, k.find('-')));
        std::vector<std::string> vs(s.begin(), s.end());
        std::sort(vs.begin(), vs.end(), [](auto& a, auto& b) { return ver_less(b, a); });
        for (auto& v : vs) out.push_back(v);
    } else if (loader == "neoforge") {
        json nv = neoforge_versions();
        for (auto& mc : vanilla_releases()) {
            std::string p = neo_prefix(mc.get<std::string>());
            for (auto& v : nv) if (v.get<std::string>().rfind(p, 0) == 0) { out.push_back(mc); break; }
        }
    } else throw std::runtime_error("Unknown loader");
    std::lock_guard<std::mutex> l(g_vcache_m);
    g_vcache[loader] = {std::time(nullptr), out};
    return out;
}

struct Job { std::mutex m; std::vector<std::string> log; bool done = false; std::string error, name; };
std::map<std::string, std::shared_ptr<Job>> g_jobs; std::mutex g_jobs_m;
void jlog(Job& j, const std::string& s) { std::lock_guard<std::mutex> l(j.m); j.log.push_back(s); }

json loader_versions(const std::string& loader, const std::string& mc) {
    json out = json::array();
    if (loader == "paper") {
        json b = jget("https://api.papermc.io/v2/projects/paper/versions/" + mc + "/builds")["builds"];
        for (auto it = b.rbegin(); it != b.rend(); ++it) out.push_back(std::to_string((*it)["build"].get<int>()));
    } else if (loader == "purpur") {
        json b = jget("https://api.purpurmc.org/v2/purpur/" + mc)["builds"]["all"];
        for (auto it = b.rbegin(); it != b.rend(); ++it) out.push_back(*it);
    } else if (loader == "fabric") {
        for (auto& v : jget("https://meta.fabricmc.net/v2/versions/loader/" + mc)) if (v["loader"]["stable"].get<bool>()) out.push_back(v["loader"]["version"]);
    } else if (loader == "forge") {
        std::string xml = http_get("https://maven.minecraftforge.net/net/minecraftforge/forge/maven-metadata.xml");
        std::regex re("<version>([^<]+)</version>"); std::vector<std::string> v;
        for (auto it = std::sregex_iterator(xml.begin(), xml.end(), re); it != std::sregex_iterator(); ++it) {
            std::string full = (*it)[1]; if (full.rfind(mc + "-", 0) == 0) v.push_back(full.substr(mc.size() + 1));
        }
        for (auto it = v.rbegin(); it != v.rend(); ++it) out.push_back(*it);
    } else if (loader == "neoforge") {
        std::string pre = neo_prefix(mc); std::vector<std::string> v;
        for (auto& x : neoforge_versions()) if (x.get<std::string>().rfind(pre, 0) == 0) v.push_back(x);
        for (auto it = v.rbegin(); it != v.rend(); ++it) out.push_back(*it);
    }
    return out;
}

int mojang_java_major(const std::string& mc) {
    try {
        json m = jget("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json");
        for (auto& v : m["versions"])
            if (v["id"] == mc) return jget(v["url"].get<std::string>())["javaVersion"]["majorVersion"].get<int>();
    } catch (...) {}
    return 0;
}

void run_installer(Job& job, const fs::path& dir, const std::string& installer, const JavaInst& ji) {
    jlog(job, "running installer with java " + std::to_string(ji.major) + " (this can take a few minutes)...");
    auto r = exec_capture({ji.path, "-jar", installer, "--installServer"}, dir);
    std::error_code ec;
    if (r.code != 0) { jlog(job, r.out.substr(r.out.size() > 1500 ? r.out.size() - 1500 : 0)); throw std::runtime_error("installer failed, see the log above"); }
    fs::remove(dir / installer, ec); fs::remove(dir / (installer + ".log"), ec);
}

void create_server(std::shared_ptr<Job> jp, std::string name, std::string loader, std::string mc, std::string lv, int ram, bool eula) {
    Job& job = *jp;
    fs::path dir = root_dir() / name;
    try {
        json meta = {{"loader", loader}, {"version", mc}, {"ram", ram}, {"jar", ""}, {"java_major", mojang_java_major(mc)}};
        JavaInst ji = resolve_java(meta, mc);
        fs::create_directories(dir);
        jlog(job, "Preparing " + loader + " " + mc);
        if (loader == "vanilla") {
            json m = jget("https://piston-meta.mojang.com/mc/game/version_manifest_v2.json");
            std::string vurl;
            for (auto& v : m["versions"]) if (v["id"] == mc) vurl = v["url"];
            if (vurl.empty()) throw std::runtime_error("Version not found");
            std::string surl = jget(vurl)["downloads"]["server"]["url"];
            jlog(job, "downloading server.jar"); download(surl, dir / "server.jar"); meta["jar"] = "server.jar";
        } else if (loader == "paper") {
            json b = jget("https://api.papermc.io/v2/projects/paper/versions/" + mc + "/builds")["builds"];
            if (b.empty()) throw std::runtime_error("no paper build for this version");
            json pick = b.back();
            for (auto& x : b) if (!lv.empty() && std::to_string(x["build"].get<int>()) == lv) pick = x;
            std::string file = pick["downloads"]["application"]["name"], build = std::to_string(pick["build"].get<int>());
            jlog(job, "downloading " + file);
            download("https://api.papermc.io/v2/projects/paper/versions/" + mc + "/builds/" + build + "/downloads/" + file, dir / "server.jar");
            meta["jar"] = "server.jar"; meta["loader_version"] = build;
        } else if (loader == "purpur") {
            if (lv.empty()) lv = jget("https://api.purpurmc.org/v2/purpur/" + mc)["builds"]["latest"].get<std::string>();
            jlog(job, "downloading purpur build " + lv);
            download("https://api.purpurmc.org/v2/purpur/" + mc + "/" + lv + "/download", dir / "server.jar");
            meta["jar"] = "server.jar"; meta["loader_version"] = lv;
        } else if (loader == "fabric") {
            std::string iv;
            if (lv.empty()) for (auto& v : jget("https://meta.fabricmc.net/v2/versions/loader")) if (v["stable"].get<bool>()) { lv = v["version"]; break; }
            for (auto& v : jget("https://meta.fabricmc.net/v2/versions/installer")) if (v["stable"].get<bool>()) { iv = v["version"]; break; }
            jlog(job, "downloading fabric launcher (loader " + lv + ")");
            download("https://meta.fabricmc.net/v2/versions/loader/" + mc + "/" + lv + "/" + iv + "/server/jar", dir / "fabric-server-launch.jar");
            meta["jar"] = "fabric-server-launch.jar"; meta["loader_version"] = lv;
        } else if (loader == "forge") {
            if (lv.empty()) {
                json promos = forge_promos();
                if (promos.contains(mc + "-recommended")) lv = promos[mc + "-recommended"]; else if (promos.contains(mc + "-latest")) lv = promos[mc + "-latest"];
            }
            if (lv.empty()) throw std::runtime_error("no forge build for this version");
            std::string full = mc + "-" + lv, inst = "forge-" + full + "-installer.jar";
            jlog(job, "downloading forge " + lv);
            download("https://maven.minecraftforge.net/net/minecraftforge/forge/" + full + "/" + inst, dir / inst);
            run_installer(job, dir, inst, ji);
            std::error_code ec;
            if (server_start_script(dir).empty())
                for (auto& e : fs::directory_iterator(dir, ec)) { auto n = e.path().filename().string(); if (n.rfind("forge-", 0) == 0 && e.path().extension() == ".jar") meta["jar"] = n; }
            meta["loader_version"] = lv;
        } else if (loader == "neoforge") {
            if (lv.empty()) {
                std::string p = neo_prefix(mc), stable;
                for (auto& v : neoforge_versions()) { std::string x = v; if (x.rfind(p, 0) == 0) { lv = x; if (x.find('-') == std::string::npos) stable = x; } }
                if (!stable.empty()) lv = stable;
            }
            if (lv.empty()) throw std::runtime_error("no neoforge build for this version");
            std::string inst = "neoforge-" + lv + "-installer.jar";
            jlog(job, "downloading neoforge " + lv);
            download("https://maven.neoforged.net/releases/net/neoforged/neoforge/" + lv + "/" + inst, dir / inst);
            run_installer(job, dir, inst, ji);
            meta["loader_version"] = lv;
        } else throw std::runtime_error("unknown loader");

        if (eula) { std::ofstream(dir / "eula.txt") << "eula=true\n"; }
        save_meta(dir, meta);
        std::error_code ec;
        if (loader != "vanilla") fs::create_directories(dir / content_dir(loader), ec);
        jlog(job, "Done");
    } catch (std::exception& e) {
        std::lock_guard<std::mutex> l(job.m); job.error = e.what();
        std::error_code ec; fs::remove_all(dir, ec);
    }
    std::lock_guard<std::mutex> l(job.m); job.done = true;
}


json modrinth_search(const std::string& q, const std::string& loader, const std::string& mc) {
    bool plugin = is_plugin_loader(loader);
    json f = json::array();
    f.push_back(json::array({plugin ? "project_type:plugin" : "project_type:mod"}));
    if (plugin) f.push_back(json::array({"categories:paper", "categories:spigot", "categories:bukkit", "categories:purpur"}));
    else { f.push_back(json::array({"categories:" + loader})); f.push_back(json::array({"server_side:required", "server_side:optional"})); }
    if (!mc.empty() && mc != "unknown") f.push_back(json::array({"versions:" + mc}));
    json r = jget("https://api.modrinth.com/v2/search?limit=20&query=" + url_enc(q) + "&facets=" + url_enc(f.dump()));
    json out = json::array();
    for (auto& h : r["hits"])
        out.push_back({{"source", "modrinth"}, {"id", h["project_id"]}, {"name", h["title"]}, {"summary", h["description"]},
                       {"icon", sget(h, "icon_url")}, {"downloads", h["downloads"]}, {"author", sget(h, "author")}});
    return out;
}
void modrinth_install(const std::string& pid, const std::string& loader, const std::string& mc, const fs::path& dir,
                      std::set<std::string>& seen, json& installed, json& warnings, bool isDep = false) {
    if (!seen.insert(pid).second) return;
    json loaders = is_plugin_loader(loader) ? json::array({"paper", "spigot", "bukkit", "purpur"}) : json::array({loader});
    json vs = jget("https://api.modrinth.com/v2/project/" + pid + "/version?loaders=" + url_enc(loaders.dump()) +
                   "&game_versions=" + url_enc(json::array({mc}).dump()));
    if (!vs.is_array() || vs.empty()) {
        std::string msg = "No " + loader + " build for minecraft " + mc + " (" + pid + ")";
        if (!isDep) throw std::runtime_error(msg);
        warnings.push_back(msg); return;
    }
    auto& v = vs[0]; json file = v["files"][0];
    for (auto& f : v["files"]) if (f.value("primary", false)) file = f;
    std::string fname = fs::path(file["filename"].get<std::string>()).filename().string();
    download(file["url"], dir / fname);
    installed.push_back(fname);
    for (auto& d : v["dependencies"])
        if (d.value("dependency_type", "") == "required" && d["project_id"].is_string())
            try { modrinth_install(d["project_id"], loader, mc, dir, seen, installed, warnings, true); }
            catch (std::exception& e) { warnings.push_back(e.what()); }
}

int cf_loader(const std::string& l) { return l == "forge" ? 1 : l == "fabric" ? 4 : l == "quilt" ? 5 : l == "neoforge" ? 6 : 0; }
std::vector<std::string> cf_headers() { std::lock_guard<std::mutex> l(cfg_m); return {"x-api-key: " + cfg.curseforge_key, "Accept: application/json"}; }
bool cf_has_key() { std::lock_guard<std::mutex> l(cfg_m); return !cfg.curseforge_key.empty(); }

json curseforge_search(const std::string& q, const std::string& loader, const std::string& mc) {
    if (!cf_has_key()) throw std::runtime_error("add your curseforge API key in settings first (free at console.curseforge.com)");
    std::string u = "https://api.curseforge.com/v1/mods/search?gameId=432&pageSize=20&sortField=2&sortOrder=desc&classId=" +
                    std::string(is_plugin_loader(loader) ? "5" : "6") + "&searchFilter=" + url_enc(q);
    if (!mc.empty() && mc != "unknown") u += "&gameVersion=" + url_enc(mc);
    if (cf_loader(loader)) u += "&modLoaderType=" + std::to_string(cf_loader(loader));
    json r = jget(u, cf_headers()), out = json::array();
    for (auto& m : r["data"])
        out.push_back({{"source", "curseforge"}, {"id", std::to_string(m["id"].get<long long>())}, {"name", m["name"]}, {"summary", m["summary"]},
                       {"icon", sget(m["logo"], "thumbnailUrl")},
                       {"downloads", m.value("downloadCount", 0.0)},
                       {"author", m["authors"].empty() ? std::string() : sget(m["authors"][0], "name")}});
    return out;
}
void curseforge_install(const std::string& id, const std::string& loader, const std::string& mc, const fs::path& dir,
                        std::set<std::string>& seen, json& installed, json& warnings, bool isDep = false) {
    if (!seen.insert(id).second) return;
    std::string u = "https://api.curseforge.com/v1/mods/" + id + "/files?pageSize=10&gameVersion=" + url_enc(mc);
    if (cf_loader(loader)) u += "&modLoaderType=" + std::to_string(cf_loader(loader));
    json files = jget(u, cf_headers())["data"];
    json pick;
    for (auto& f : files) if (f["downloadUrl"].is_string()) { pick = f; break; }
    if (pick.is_null()) {
        std::string msg = files.empty() ? "no compatible file for mod " + id : "Mod " + id + " does not allow third-party downloads; get it manually from curseforge";
        if (!isDep) throw std::runtime_error(msg);
        warnings.push_back(msg); return;
    }
    std::string fname = fs::path(pick["fileName"].get<std::string>()).filename().string();
    download(pick["downloadUrl"], dir / fname);
    installed.push_back(fname);
    for (auto& d : pick["dependencies"])
        if (d.value("relationType", 0) == 3)
            try { curseforge_install(std::to_string(d["modId"].get<long long>()), loader, mc, dir, seen, installed, warnings, true); }
            catch (std::exception& e) { warnings.push_back(e.what()); }
}

using httplib::Request; using httplib::Response;
httplib::Server* g_svr = nullptr;

void reply(Response& res, const json& j, int status = 200) { res.status = status; res.set_content(j.dump(), "application/json"); }
void fail(Response& res, const std::string& msg, int status = 400) { reply(res, {{"error", msg}}, status); }
json body(const Request& req) { json j = json::parse(req.body, nullptr, false); return j.is_object() ? j : json::object(); }

bool resolve(const Request& req, Response& res, std::string& name, fs::path& dir) {
    name = req.matches[1];
    std::error_code ec;
    dir = root_dir() / name;
    if (!safe_name(name) || !fs::is_directory(dir, ec)) { fail(res, "server not found", 404); return false; }
    return true;
}

uintmax_t dir_size(const fs::path& d) {
    uintmax_t t = 0; std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec); it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) break;
        if (it->is_regular_file(ec)) t += it->file_size(ec);
    }
    return t;
}
std::time_t mtime(const fs::path& p) {
    std::error_code ec; auto ft = fs::last_write_time(p, ec);
    auto s = ft - decltype(ft)::clock::now() + std::chrono::system_clock::now();
    return std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::system_clock::duration>(s));
}
std::mutex g_size_m;
std::map<std::string, std::pair<std::time_t, uintmax_t>> g_size_cache;
uintmax_t folder_size(const fs::path& d, int ttl = 0) {
    std::string key = d.string();
    if (ttl > 0) {
        std::lock_guard<std::mutex> l(g_size_m);
        auto it = g_size_cache.find(key);
        if (it != g_size_cache.end() && std::time(nullptr) - it->second.first < ttl) return it->second.second;
    }
    uintmax_t s = dir_size(d);
    { std::lock_guard<std::mutex> l(g_size_m); g_size_cache[key] = {std::time(nullptr), s}; }
    return s;
}
std::time_t folder_updated(const fs::path& d) {
    std::time_t t = mtime(d); std::error_code ec;
    for (auto& e : fs::directory_iterator(d, fs::directory_options::skip_permission_denied, ec)) {
        auto m = mtime(e.path()); if (m > t) t = m;
    }
    return t;
}

std::string props_unescape(const std::string& s) {
    std::string o;
    auto put = [&](unsigned cp) {
        if (cp == 0xA7) o += '&'; else if (cp == '&') o += "&&";
        else if (cp < 0x80) o += (char)cp;
        else if (cp < 0x800) { o += (char)(0xC0 | cp >> 6); o += (char)(0x80 | (cp & 63)); }
        else { o += (char)(0xE0 | cp >> 12); o += (char)(0x80 | ((cp >> 6) & 63)); o += (char)(0x80 | (cp & 63)); }
    };
    for (size_t i = 0; i < s.size(); i++) {
        unsigned char c = s[i];
        if (c == '\\' && i + 1 < s.size()) {
            char n = s[i + 1];
            if (n == 'n') { o += '\n'; i++; continue; }
            if (n == 'u' && i + 5 < s.size()) { put((unsigned)strtoul(s.substr(i + 2, 4).c_str(), nullptr, 16)); i += 5; continue; }
            o += n; i++; continue;
        }
        if (c == 0xC2 && i + 1 < s.size() && (unsigned char)s[i + 1] == 0xA7) { o += '&'; i++; continue; }
        if (c == '&') { o += "&&"; continue; }
        o += (char)c;
    }
    return o;
}
std::string props_escape(const std::string& s) {
    std::string o; char buf[8];
    auto esc = [&](unsigned cp) { snprintf(buf, sizeof buf, "\\u%04X", cp); o += buf; };
    for (size_t i = 0; i < s.size();) {
        unsigned char c = s[i];
        if (c == '&') {
            if (i + 1 < s.size() && s[i + 1] == '&') { o += '&'; i += 2; continue; }
            if (i + 1 < s.size() && s[i + 1] && strchr("0123456789abcdefklmnorABCDEF", s[i + 1])) { esc(0xA7); o += (char)tolower(s[i + 1]); i += 2; continue; }
            o += '&'; i++; continue;
        }
        if (c == '\n') { o += "\\n"; i++; continue; }
        if (c == '\r') { i++; continue; }
        if (c == '\\') { o += "\\\\"; i++; continue; }
        if (c < 0x80) { o += (char)c; i++; continue; }
        unsigned cp; int len;
        if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; } else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; } else if ((c & 0xF8) == 0xF0) { cp = c & 7; len = 4; } else { i++; continue; }
        for (int k = 1; k < len && i + k < s.size(); k++) cp = (cp << 6) | ((unsigned char)s[i + k] & 0x3F);
        i += len;
        if (cp >= 0x10000) { cp -= 0x10000; esc(0xD800 + (cp >> 10)); esc(0xDC00 + (cp & 0x3FF)); } else esc(cp);
    }
    return o;
}

fs::path favicon_file() {
    std::error_code ec;
    for (auto ext : {"png", "ico", "svg"}) {
        fs::path p = g_home / ("favicon." + std::string(ext));
        if (fs::is_regular_file(p, ec)) return p;
    }
    return {};
}
std::string favicon_mime(const fs::path& p) {
    auto e = p.extension().string();
    return e == ".png" ? "image/png" : e == ".svg" ? "image/svg+xml" : "image/x-icon";
}

json server_json(const fs::path& dir) {
    json j = detect(dir); std::string name = j["name"];
    j["running"] = is_running(name);
    j["ram"] = load_meta(dir).value("ram", default_ram());
    auto props = read_props(dir);
    j["port"] = props.count("server-port") ? props["server-port"] : "25565";
    if (j["icon"].get<bool>()) j["icon_t"] = (long long)mtime(dir / "server-icon.png");
    return j;
}

void setup_routes(httplib::Server& svr) {
    svr.Get("/api/settings", [](const Request&, Response& res) {
        std::lock_guard<std::mutex> l(cfg_m);
        reply(res, {{"root", cfg.root}, {"curseforge_key_set", !cfg.curseforge_key.empty()}, {"java", cfg.java},
                    {"public_address", cfg.public_address}, {"default_ram", cfg.default_ram}, {"config_dir", g_home.string()},
                    {"favicon", !favicon_file().empty()}});
    });
    svr.Post("/api/settings", [](const Request& req, Response& res) {
        json b = body(req);
        { std::lock_guard<std::mutex> l(cfg_m);
          if (b.contains("root") && !b["root"].get<std::string>().empty()) cfg.root = b["root"];
          if (b.contains("curseforge_key") && !b["curseforge_key"].get<std::string>().empty()) cfg.curseforge_key = b["curseforge_key"];
          if (b.contains("default_ram") && b["default_ram"].is_number()) cfg.default_ram = std::clamp(b["default_ram"].get<int>(), 512, 262144);
          if (b.contains("java") && b["java"].is_string()) cfg.java = b["java"].get<std::string>().empty() ? "java" : b["java"].get<std::string>();
          if (b.contains("public_address")) cfg.public_address = b["public_address"];
          std::error_code ec; fs::create_directories(cfg.root, ec); save_config(); }
        reply(res, {{"ok", true}});
    });
    svr.Get("/api/tunnel", [](const Request&, Response& res) {
        std::string address;
        { std::lock_guard<std::mutex> l(cfg_m); address = cfg.public_address; }
        json lan = json::array();
        for (auto& url : lan_urls()) lan.push_back(url);
        reply(res, {{"address", address}, {"lan", lan}});
    });
    svr.Get("/api/network", [](const Request&, Response& res) {
        json urls = json::array();
        for (auto& url : lan_urls()) urls.push_back(url);
#ifdef _WIN32
        const bool windows = true;
#else
        const bool windows = false;
#endif
        reply(res, {{"urls", urls}, {"port", config_port()}, {"windows", windows}});
    });
    svr.Post("/api/firewall", [](const Request& req, Response& res) {
#ifdef _WIN32
        if (!body(req).value("confirm", false)) return fail(res, "confirmation required");
        char exe[32768];
        DWORD n = GetModuleFileNameA(nullptr, exe, (DWORD)sizeof exe);
        if (!n || n >= (DWORD)sizeof exe) return fail(res, "could not find the program path", 500);
        std::string args = "advfirewall firewall add rule name=\"Server Manager\" dir=in action=allow program=\"" +
                           std::string(exe) + "\" enable=yes profile=any";
        auto rc = reinterpret_cast<INT_PTR>(ShellExecuteA(nullptr, "runas", "netsh.exe", args.c_str(), nullptr, SW_HIDE));
        if (rc <= 32) return fail(res, "windows did not allow the firewall change (error " + std::to_string((int)rc) + ")");
        reply(res, {{"ok", true}, {"note", "if windows asked for permission, choose yes. other devices can now connect."}});
#else
        (void)req;
        fail(res, "the firewall helper is only available on windows");
#endif
    });

    auto favicon = [](const Request&, Response& res) {
        res.set_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        res.set_header("Pragma", "no-cache");
        fs::path p = favicon_file();
        if (p.empty()) { res.status = 404; return; }
        res.set_content(read_file(p), favicon_mime(p));
    };
    svr.Get("/favicon", favicon);
    svr.Get("/favicon.ico", favicon);
    svr.Post("/api/favicon", [](const Request& req, Response& res) {
        const std::string& b = req.body;
        if (b.empty() || b.size() > 512 * 1024) return fail(res, "the favicon must be smaller than 512 KB");
        std::string ext;
        if (b.size() >= 4 && b.compare(0, 4, "\x89PNG") == 0) ext = "png";
        else if (b.size() >= 4 && (unsigned char)b[0] == 0 && (unsigned char)b[1] == 0 && (unsigned char)b[2] == 1 && (unsigned char)b[3] == 0) ext = "ico";
        else if (b.find("<svg") != std::string::npos) ext = "svg";
        if (ext.empty()) return fail(res, "use a PNG, ICO or SVG image");
        std::error_code ec;
        for (auto other : {"png", "ico", "svg"}) if (ext != other) fs::remove(g_home / ("favicon." + std::string(other)), ec);
        std::ofstream(g_home / ("favicon." + ext), std::ios::binary) << b;
        reply(res, {{"ok", true}});
    });
    svr.Delete("/api/favicon", [](const Request&, Response& res) {
        std::error_code ec;
        for (auto ext : {"png", "ico", "svg"}) fs::remove(g_home / ("favicon." + std::string(ext)), ec);
        reply(res, {{"ok", true}});
    });

    svr.Get("/api/servers", [](const Request&, Response& res) {
        json out = json::array(); std::error_code ec;
        std::vector<fs::path> dirs;
        fs::path root = root_dir();
        for (auto& e : fs::directory_iterator(root, ec)) if (e.is_directory(ec) && !e.path().filename().string().empty() && e.path().filename().string()[0] != '.') dirs.push_back(e.path());
        std::sort(dirs.begin(), dirs.end());
        uintmax_t total = 0;
        for (auto& d : dirs) {
            json s = server_json(d);
            s["size"] = folder_size(d, 60);
            s["updated"] = (long long)folder_updated(d);
            total += s["size"].get<uintmax_t>();
            out.push_back(s);
        }
        reply(res, {{"root", root.string()}, {"servers", out}, {"total_size", total}});
    });

    svr.Get("/api/loader-versions", [](const Request& req, Response& res) {
        try { reply(res, loader_versions(req.get_param_value("loader"), req.get_param_value("mc"))); } catch (std::exception& e) { fail(res, e.what(), 502); }
    });
    svr.Get("/api/versions", [](const Request& req, Response& res) {
        try { reply(res, mc_versions(req.get_param_value("loader"))); } catch (std::exception& e) { fail(res, e.what(), 502); }
    });

    svr.Post("/api/servers", [](const Request& req, Response& res) {
        json b = body(req);
        std::string name = b.value("name", ""), loader = b.value("loader", ""), ver = b.value("version", ""), lv = b.value("loader_version", "");
        int ram = std::clamp(b.value("ram", default_ram()), 512, 262144);
        std::error_code ec;
        if (!safe_name(name)) return fail(res, "name may only contain letters, numbers, spaces, - _ .");
        if (fs::exists(root_dir() / name, ec)) return fail(res, "a server with this name already exists");
        if (ver.empty() || loader.empty()) return fail(res, "pick a loader and version");
        auto job = std::make_shared<Job>(); job->name = name;
        std::string id = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
        { std::lock_guard<std::mutex> l(g_jobs_m); g_jobs[id] = job; }
        std::thread(create_server, job, name, loader, ver, lv, ram, b.value("eula", false)).detach();
        reply(res, {{"job", id}});
    });
    svr.Get(R"(/api/jobs/([^/]+))", [](const Request& req, Response& res) {
        std::shared_ptr<Job> j; { std::lock_guard<std::mutex> l(g_jobs_m); auto it = g_jobs.find(req.matches[1]); if (it != g_jobs.end()) j = it->second; }
        if (!j) return fail(res, "unknown job", 404);
        std::lock_guard<std::mutex> l(j->m);
        reply(res, {{"log", j->log}, {"done", j->done}, {"error", j->error}, {"name", j->name}});
    });

    svr.Get(R"(/api/servers/([^/]+))", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        json j = server_json(d);
        if (auto r = get_run(n)) if (r->p.running()) j["uptime"] = (long)(std::time(nullptr) - r->started);
        if (req.has_param("brief")) return reply(res, j);
        std::error_code ec; int mods = 0; std::string cd = content_dir(j["loader"]);
        for (auto& e : fs::directory_iterator(d / cd, ec)) if (e.path().extension() == ".jar") mods++;
        auto p = read_props(d);
        j["mods"] = mods; j["content_dir"] = cd; j["size"] = folder_size(d);
        j["server_ip"] = p.count("server-ip") ? p["server-ip"] : std::string();
        j["motd"] = p.count("motd") ? props_unescape(p["motd"]) : std::string();
        j["eula"] = read_file(d / "eula.txt").find("eula=true") != std::string::npos;
        int req_java = required_java(load_meta(d), j["version"]); auto all = list_javas(); json inst = json::array();
        for (auto& x : all) inst.push_back(x.major);
        JavaInst sel = req_java ? pick_java(req_java, all) : JavaInst{0, ""};
        j["java"] = {{"required", req_java}, {"path", sel.path}, {"ok", req_java == 0 || sel.major != 0}, {"installed", inst}};
        reply(res, j);
    });
    svr.Get(R"(/api/servers/([^/]+)/icon)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        std::string png = read_file(d / "server-icon.png");
        if (png.empty()) { res.status = 404; return; }
        res.set_content(png, "image/png"); res.set_header("Cache-Control", "max-age=30");
    });

    svr.Post(R"(/api/servers/([^/]+)/(start|stop|restart|kill|eula))", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        std::string act = req.matches[2];
        if (act == "start") { auto e = start_server(n, d); return e.empty() ? reply(res, {{"ok", true}}) : fail(res, e); }
        if (act == "stop") { stop_server(n); return reply(res, {{"ok", true}}); }
        if (act == "kill") { if (auto r = get_run(n)) r->p.terminate(true); return reply(res, {{"ok", true}}); }
        if (act == "eula") { std::ofstream(d / "eula.txt") << "eula=true\n"; return reply(res, {{"ok", true}}); }
        stop_server(n);
        std::thread([n, d] {
            for (int i = 0; i < 120 && is_running(n); i++) std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (is_running(n)) if (auto r = get_run(n)) r->p.terminate(true);
            std::this_thread::sleep_for(std::chrono::seconds(1)); start_server(n, d);
        }).detach();
        reply(res, {{"ok", true}});
    });
    svr.Post(R"(/api/servers/([^/]+)/command)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        auto r = get_run(n); std::string c = body(req).value("cmd", "");
        if (!r || !r->p.running()) return fail(res, "server is not running");
        if (c.find('\n') != std::string::npos) return fail(res, "one command at a time");
        r->p.write(c + "\n"); reply(res, {{"ok", true}});
    });
    svr.Get(R"(/api/servers/([^/]+)/console-heartbeat)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        auto r = get_run(n);
        if (!r) return fail(res, "server is not running", 404);
        r->viewer_seen.store((long long)std::time(nullptr));
        reply(res, {{"ok", true}});
    });
    svr.Get(R"(/api/servers/([^/]+)/console)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        auto r = get_run(n);
        if (!r) {
            std::string t = read_file(d / "logs" / "latest.log", 40000);
            return reply(res, {{"lines", json::array({t})}, {"next", 0}, {"running", false}, {"raw", true}});
        }
        size_t since = (size_t)atoll(req.get_param_value("since").c_str());
        std::lock_guard<std::mutex> l(r->m);
        json lines = json::array(); size_t from = std::max(since, r->first);
        for (size_t i = from; i < r->first + r->lines.size(); i++) lines.push_back(r->lines[i - r->first]);
        reply(res, {{"lines", lines}, {"next", r->first + r->lines.size()}, {"running", r->p.running()}});
    });
    svr.Post(R"(/api/servers/([^/]+)/meta)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        json m = load_meta(d), b = body(req);
        if (b.contains("ram") && b["ram"].is_number()) m["ram"] = std::clamp(b["ram"].get<int>(), 512, 262144);
        if (b.contains("version")) {
            std::string v = b["version"].is_string() ? trim(b["version"].get<std::string>()) : "";
            if (!safe_version(v)) return fail(res, "that doesn't look like a minecraft version");
            m["version"] = v;
        }
        if (b.contains("loader_version")) {
            std::string v = b["loader_version"].is_string() ? trim(b["loader_version"].get<std::string>()) : "";
            if (!v.empty() && !safe_version(v)) return fail(res, "that doesn't look like a loader version");
            m["loader_version"] = v;
        }
        save_meta(d, m); reply(res, {{"ok", true}});
    });
    svr.Delete(R"(/api/servers/([^/]+))", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        if (is_running(n)) return fail(res, "stop the server before deleting it");
        std::error_code ec;
        fs::remove_all(d, ec);
        if (ec) return fail(res, "could not delete the folder: " + ec.message(), 500);
        fs::remove(meta_path(d), ec);
        dc_erase(n);
        { std::lock_guard<std::mutex> l(g_size_m); g_size_cache.erase(d.string()); }
        reply(res, {{"ok", true}});
    });

    svr.Post(R"(/api/servers/([^/]+)/icon)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        const std::string& b = req.body;
        if (b.size() < 8 || b.size() > 2 * 1024 * 1024 || b.compare(0, 8, "\x89PNG\r\n\x1a\n") != 0) return fail(res, "the icon must be a PNG image");
        std::ofstream(d / "server-icon.png", std::ios::binary) << b;
        reply(res, {{"ok", true}});
    });
    svr.Delete(R"(/api/servers/([^/]+)/icon)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        std::error_code ec; fs::remove(d / "server-icon.png", ec); reply(res, {{"ok", true}});
    });
    svr.Post(R"(/api/servers/([^/]+)/motd)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        std::string line = "motd=" + props_escape(body(req).value("motd", "")), cur; bool found = false;
        std::vector<std::string> lines; std::ifstream in(d / "server.properties");
        while (std::getline(in, cur)) { if (!cur.empty() && cur.back() == '\r') cur.pop_back(); if (cur.rfind("motd=", 0) == 0) { cur = line; found = true; } lines.push_back(cur); }
        in.close(); if (!found) lines.push_back(line);
        std::ofstream out(d / "server.properties"); for (auto& l : lines) out << l << "\n";
        reply(res, {{"ok", true}, {"note", is_running(n) ? "restart the server to apply the new MOTD" : ""}});
    });

    svr.Get(R"(/api/servers/([^/]+)/mods)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        std::string cd = content_dir(detect(d)["loader"]); json out = json::array(); std::error_code ec;
        for (auto& e : fs::directory_iterator(d / cd, ec)) {
            auto f = e.path().filename().string();
            bool dis = f.size() > 9 && f.substr(f.size() - 9) == ".disabled";
            if (e.path().extension() == ".jar" || dis) out.push_back({{"file", f}, {"size", e.file_size(ec)}, {"enabled", !dis}});
        }
        std::sort(out.begin(), out.end(), [](const json& a, const json& b) { return a["file"].get<std::string>() < b["file"].get<std::string>(); });
        reply(res, {{"dir", cd}, {"items", out}});
    });
    svr.Post(R"(/api/servers/([^/]+)/mods/(delete|toggle))", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        std::string f = body(req).value("file", ""), act = req.matches[2];
        if (!safe_file(f)) return fail(res, "bad file name");
        fs::path p = d / content_dir(detect(d)["loader"]) / f; std::error_code ec;
        if (!fs::exists(p, ec)) return fail(res, "file not found", 404);
        if (act == "delete") fs::remove(p, ec);
        else { fs::path q = p; if (f.size() > 9 && f.substr(f.size() - 9) == ".disabled") q = fs::path(p.string().substr(0, p.string().size() - 9)); else q = fs::path(p.string() + ".disabled"); fs::rename(p, q, ec); }
        reply(res, {{"ok", true}});
    });
    svr.Get("/api/mods/search", [](const Request& req, Response& res) {
        std::string n = req.get_param_value("server"), src = req.get_param_value("source"), q = req.get_param_value("q");
        std::error_code ec; fs::path d = root_dir() / n;
        if (!safe_name(n) || !fs::is_directory(d, ec)) return fail(res, "server not found", 404);
        json info = detect(d); std::string loader = info["loader"], mc = info["version"];
        if (!is_mod_loader(loader) && !is_plugin_loader(loader)) return fail(res, "vanilla servers can't load mods. create a fabric, forge, neoforge or paper server instead.");
        try { reply(res, src == "curseforge" ? curseforge_search(q, loader, mc) : modrinth_search(q, loader, mc)); }
        catch (std::exception& e) { fail(res, e.what(), 502); }
    });
    svr.Post(R"(/api/servers/([^/]+)/mods/install)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        json b = body(req), info = detect(d); std::string loader = info["loader"], mc = info["version"], id = b.value("id", "");
        if (id.empty() || mc == "unknown") return fail(res, "missing mod id or unknown server version");
        fs::path target = d / content_dir(loader); json installed = json::array(), warnings = json::array(); std::set<std::string> seen;
        try {
            if (b.value("source", "") == "curseforge") { if (!cf_has_key()) return fail(res, "add your curseforge API key in settings first"); curseforge_install(id, loader, mc, target, seen, installed, warnings); }
            else modrinth_install(id, loader, mc, target, seen, installed, warnings);
            reply(res, {{"installed", installed}, {"warnings", warnings}});
        } catch (std::exception& e) { fail(res, e.what(), 502); }
    });

    svr.Get(R"(/api/servers/([^/]+)/logs)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        json out = json::array(); std::error_code ec;
        for (auto sub : {"logs", "crash-reports"})
            for (auto& e : fs::directory_iterator(d / sub, ec))
                if (e.is_regular_file(ec)) out.push_back({{"dir", sub}, {"file", e.path().filename().string()}, {"size", e.file_size(ec)}, {"time", (long long)mtime(e.path())}});
        std::sort(out.begin(), out.end(), [](const json& a, const json& b) { return a["time"] > b["time"]; });
        reply(res, out);
    });
    svr.Get(R"(/api/servers/([^/]+)/log)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        std::string sub = req.get_param_value("dir"), f = req.get_param_value("file");
        if ((sub != "logs" && sub != "crash-reports") || !safe_file(f)) return fail(res, "bad request");
        fs::path p = d / sub / f; std::error_code ec;
        if (!fs::is_regular_file(p, ec)) return fail(res, "not found", 404);
        if (p.extension() == ".gz") {
#ifdef _WIN32
            return reply(res, {{"text", "compressed logs can't be opened on windows. unzip the file manually."}});
#else
            auto r = exec_capture({"gzip", "-dc", p.string()}); return reply(res, {{"text", r.out.substr(r.out.size() > 400000 ? r.out.size() - 400000 : 0)}});
#endif
        }
        reply(res, {{"text", read_file(p, 400000)}});
    });

    svr.Get(R"(/api/servers/([^/]+)/properties)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        std::vector<std::string> order; auto m = read_props(d, &order); json out = json::array();
        for (auto& k : order) out.push_back({{"key", k}, {"value", m[k]}});
        reply(res, {{"exists", fs::exists(d / "server.properties")}, {"items", out}});
    });
    svr.Post(R"(/api/servers/([^/]+)/properties)", [](const Request& req, Response& res) {
        std::string n; fs::path d; if (!resolve(req, res, n, d)) return;
        json b = body(req); if (!b.contains("items")) return fail(res, "no data");
        std::ofstream f(d / "server.properties");
        f << "#Minecraft server properties (edited with Server Manager)\n";
        for (auto& it : b["items"]) {
            std::string k = it.value("key", ""), v = it.value("value", "");
            if (k.empty() || k.find_first_of("=\n\r#") != std::string::npos || v.find_first_of("\n\r") != std::string::npos) continue;
            f << k << "=" << v << "\n";
        }
        reply(res, {{"ok", true}, {"note", is_running(n) ? "restart the server to apply changes" : ""}});
    });
}

int console_view(int port, const std::string& name) {
#ifdef _WIN32
    SetConsoleTitleA(("Server Manager - " + name).c_str());
#endif
    std::cout << "==============================================\n"
              << " Server Manager console - " << name << "\n"
              << " type a command and press enter. closing this\n"
              << " window stops the server.\n"
              << "==============================================\n" << std::flush;

    std::atomic<bool> alive{true};
    std::mutex io_m;
    std::thread input([&] {
        std::string line;
        while (alive && std::getline(std::cin, line)) {
            httplib::Client cli("127.0.0.1", port);
            cli.set_connection_timeout(3, 0);
            cli.set_read_timeout(5, 0);
            auto r = cli.Post(("/api/servers/" + url_enc(name) + "/command").c_str(),
                              json{{"cmd", line}}.dump(), "application/json");
            if (!r || r->status >= 300) {
                std::lock_guard<std::mutex> l(io_m);
                std::cout << "[manager] could not send that command\n" << std::flush;
            }
        }
    });

    std::thread beat([&] {
        while (alive) {
            httplib::Client cli("127.0.0.1", port);
            cli.set_connection_timeout(1, 0);
            cli.set_read_timeout(2, 0);
            cli.Get(("/api/servers/" + url_enc(name) + "/console-heartbeat").c_str());
            for (int i = 0; i < 10 && alive; i++)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    size_t since = 0;
    bool was_running = false;
    int failures = 0, idle = 0;
    while (alive) {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(3, 0);
        cli.set_read_timeout(5, 0);
        auto r = cli.Get(("/api/servers/" + url_enc(name) + "/console?since=" + std::to_string(since)).c_str());
        if (!r || r->status != 200) {
            if (++failures >= 3) {
                std::lock_guard<std::mutex> l(io_m);
                std::cout << "\n[manager] lost connection to Server Manager. is it still running?\n" << std::flush;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(700));
            continue;
        }
        failures = 0;
        json j = json::parse(r->body, nullptr, false);
        if (!j.is_object()) break;
        bool running = j.value("running", false);
        if (j.contains("lines") && j["lines"].is_array())
            for (auto& line : j["lines"]) if (line.is_string()) {
                std::lock_guard<std::mutex> l(io_m);
                std::cout << line.get<std::string>() << "\n";
            }
        if (j.contains("next") && j["next"].is_number_unsigned()) since = j["next"].get<size_t>();
        {
            std::lock_guard<std::mutex> l(io_m);
            std::cout << std::flush;
        }
        if (j.value("raw", false)) break;
        if (running) { was_running = true; idle = 0; }
        else if (was_running) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            std::cout << "\n[manager] server stopped. this window will close.\n" << std::flush;
            break;
        } else if (++idle >= 3) {
            std::cout << "\n[manager] this server is not running. this window will close.\n" << std::flush;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
    }
    alive = false;
    input.detach();
    beat.detach();
    return 0;
}

int main(int argc, char** argv) {
    if (argc >= 4 && std::string(argv[1]) == "--console-view") return console_view(atoi(argv[2]), argv[3]);
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    g_home = config_home();
    load_config();
    for (int i = 1; i + 1 < argc; i++) {
        if (std::string(argv[i]) == "--dir") { cfg.root = argv[i + 1]; std::error_code ec; fs::create_directories(cfg.root, ec); save_config(); }
        if (std::string(argv[i]) == "--port") { cfg.port = atoi(argv[i + 1]); save_config(); }
    }
    httplib::Server svr; g_svr = &svr;
    fs::path web = fs::exists("web") ? fs::path("web") : fs::path(argv[0]).parent_path() / "web";
    if (!svr.set_mount_point("/", web.string())) { std::cerr << "web/ folder not found next to the executable\n"; return 1; }
    setup_routes(svr);

    signal(SIGINT, [](int) { if (g_svr) g_svr->stop(); });
    signal(SIGTERM, [](int) { if (g_svr) g_svr->stop(); });

    std::thread(watch_console_windows).detach();
    int port = config_port();
    std::cout << "Server Manager running: http://0.0.0.0:" << port << "  (servers folder: " << root_dir() << ")\n";
    for (auto& url : lan_urls()) std::cout << "open from another device: " << url << "\n";
    std::cout << std::flush;
    if (!svr.listen("0.0.0.0", port)) { std::cerr << "could not listen on port " << port << "\n"; return 1; }

    std::vector<std::string> names; { std::lock_guard<std::mutex> l(g_run_m); for (auto& [k, v] : g_run) names.push_back(k); }
    for (auto& n : names) if (is_running(n)) { std::cout << "stopping " << n << "...\n"; stop_server(n); }
    for (int i = 0; i < 60; i++) {
        bool any = false; for (auto& n : names) any |= is_running(n);
        if (!any) break; std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    return 0;
}

