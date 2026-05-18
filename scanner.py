#!/usr/bin/env python3
"""
Vercel / CDN / Domain-Fronting Scanner
Zero external dependencies — stdlib only
Supports: TCP, HTTP/HTTPS, ICMP (raw socket), DNS validation
"""
 
import os, sys, socket, ssl, time, json, struct, select, threading
import subprocess, multiprocessing, ipaddress, signal, argparse
import http.client, urllib.request, urllib.error
from queue import Queue, Empty
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional
 
# ──────────────────────────────────────────────
# TARGETS  (IPs + domains)
# ──────────────────────────────────────────────
 
VERCEL_CIDR = [
    "76.76.21.0/24", "76.76.22.0/24", "76.223.126.0/24",
    "76.223.127.0/24", "64.29.17.0/24", "64.29.18.0/24",
    "192.169.0.0/24", "192.169.1.0/24",
    "199.232.0.0/22",
]
 
CDN_DOMAINS = [
    # Vercel
    "vercel.com","vercel.app","now.sh","cdn.vercel-insights.com",
    "assets.vercel.com","vercel-dns.com",
    # Cloudflare
    "cloudflare.com","cdn.cloudflare.net","cloudflare-dns.com",
    "1dot1dot1dot1.cloudflare-dns.com","cloudflare.net",
    # AWS CloudFront
    "cloudfront.net","d1.awsstatic.com","d2.awsstatic.com",
    "d3.awsstatic.com","aws.amazon.com",
    "s3.amazonaws.com","execute-api.us-east-1.amazonaws.com",
    # Fastly
    "fastly.net","fastly.com","global.fastly.net",
    "a.sni.fastly.net","b.sni.fastly.net",
    # Akamai
    "akamai.net","akamaiedge.net","akamaized.net",
    "akamaihd.net","edgesuite.net","edgekey.net",
    # Azure CDN
    "azureedge.net","azurefd.net","azure.com",
    "msecnd.net","azurewebsites.net",
    # Google CDN
    "googleusercontent.com","googleapis.com","gstatic.com",
    "storage.googleapis.com","run.app","cloudfunctions.net",
    # Netlify
    "netlify.app","netlify.com","netlify-dns.com",
    # BunnyCDN / StackPath
    "b-cdn.net","stackpathdns.com","stackpathcdn.com",
    # Imperva / Incapsula
    "impervadns.net","incapdns.net",
    # Domain Fronting common hosts
    "ajax.microsoft.com","ajax.aspnetcdn.com",
    "dl.delivery.mp.microsoft.com",
    "software.download.prss.microsoft.com",
    "appspot.com","firebaseapp.com","web.app",
    "github.io","githubusercontent.com","githubassets.com",
    "pages.dev","workers.dev","r2.dev",      # Cloudflare Pages/Workers
    "fly.dev","fly.io",
    "render.com","onrender.com",
    "railway.app",
    "deno.dev","deno.land",
    "surge.sh",
]
 
# ──────────────────────────────────────────────
# COLOURS
# ──────────────────────────────────────────────
 
class C:
    RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'
    BLU='\033[94m'; MAG='\033[95m'; CYN='\033[96m'
    WHT='\033[97m'; DIM='\033[2m';  BLD='\033[1m'
    RST='\033[0m'
    @staticmethod
    def ok(s):   return f"{C.GRN}✔{C.RST} {s}"
    @staticmethod
    def fail(s): return f"{C.RED}✘{C.RST} {s}"
    @staticmethod
    def info(s): return f"{C.CYN}→{C.RST} {s}"
    @staticmethod
    def warn(s): return f"{C.YLW}⚠{C.RST} {s}"
 
# ──────────────────────────────────────────────
# SYSTEM INFO
# ──────────────────────────────────────────────
 
def get_cpu_count() -> int:
    return multiprocessing.cpu_count()
 
def get_ram_gb() -> float:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    kb = int(line.split()[1])
                    return round(kb / 1024 / 1024, 2)
    except Exception:
        pass
    return 1.0
 
def detect_os() -> str:
    for path in ["/etc/os-release", "/etc/centos-release", "/etc/redhat-release"]:
        try:
            with open(path) as f:
                content = f.read()
                if "Ubuntu" in content: return "Ubuntu"
                if "CentOS" in content: return "CentOS"
                if "Red Hat" in content: return "RHEL"
                if "Fedora" in content: return "Fedora"
                if "Debian" in content: return "Debian"
        except: pass
    return "Linux"
 
def is_root() -> bool:
    return os.geteuid() == 0
 
# ──────────────────────────────────────────────
# BANNER
# ──────────────────────────────────────────────
 
def print_banner():
    print(f"""
{C.CYN}{C.BLD}
 ██╗   ██╗███████╗██████╗  ██████╗███████╗██╗      ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝██║      ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║█████╗  ██████╔╝██║     █████╗  ██║█████╗███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██╔══╝  ██╔══██╗██║     ██╔══╝  ██║╚════╝╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ███████╗██║  ██║╚██████╗███████╗███████╗  ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝  ╚══════╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚══════╝  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RST}
{C.DIM}  CDN / Vercel / Domain-Fronting Scanner  |  Zero-dependency  |  Background-capable{C.RST}
""")
 
# ──────────────────────────────────────────────
# PROTOCOL PROBES
# ──────────────────────────────────────────────
 
TIMEOUT_DEFAULT = 3.0
 
def probe_tcp(host: str, port: int, timeout: float) -> Optional[float]:
    """Raw TCP connect probe — returns latency in ms or None."""
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout):
            return (time.perf_counter() - t0) * 1000
    except Exception:
        return None
 
def probe_http(host: str, port: int, use_ssl: bool, timeout: float,
               sni: str = None) -> Optional[float]:
    """HTTP/HTTPS GET probe — returns latency ms or None."""
    try:
        t0 = time.perf_counter()
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        req_host = sni if sni else host
        conn.request("HEAD", "/", headers={"Host": req_host,
                                           "User-Agent": "Mozilla/5.0"})
        resp = conn.getresponse()
        latency = (time.perf_counter() - t0) * 1000
        conn.close()
        if resp.status < 600:          # any HTTP response = reachable
            return latency
    except Exception:
        pass
    return None
 
def probe_icmp(host: str, timeout: float) -> Optional[float]:
    """ICMP echo (raw socket) — requires root. Returns ms or None."""
    if not is_root():
        return None
    ICMP_ECHO = 8
    try:
        resolved = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        # build ICMP packet
        pid = os.getpid() & 0xFFFF
        seq = 1
        header = struct.pack("bbHHh", ICMP_ECHO, 0, 0, pid, seq)
        data = b"vercel-scan"
        chk = _icmp_checksum(header + data)
        header = struct.pack("bbHHh", ICMP_ECHO, 0, chk, pid, seq)
        packet = header + data
        t0 = time.perf_counter()
        sock.sendto(packet, (resolved, 0))
        while True:
            ready = select.select([sock], [], [], timeout)
            if not ready[0]:
                break
            recv, _ = sock.recvfrom(1024)
            if len(recv) >= 28:
                icmp_hdr = recv[20:28]
                r_type, _, _, r_pid, _ = struct.unpack("bbHHh", icmp_hdr)
                if r_type == 0 and r_pid == pid:
                    return (time.perf_counter() - t0) * 1000
        sock.close()
    except Exception:
        pass
    return None
 
def _icmp_checksum(data: bytes) -> int:
    s = 0
    n = len(data) % 2
    for i in range(0, len(data) - n, 2):
        s += (data[i]) + ((data[i+1]) << 8)
    if n:
        s += data[-1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF
 
def probe_dns(host: str, timeout: float) -> Optional[float]:
    """DNS resolution time — validates the domain resolves at all."""
    try:
        t0 = time.perf_counter()
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, None)
        return (time.perf_counter() - t0) * 1000
    except Exception:
        return None
 
def probe_tls(host: str, port: int = 443, timeout: float = 3.0) -> Optional[float]:
    """Full TLS handshake probe."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t0 = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return (time.perf_counter() - t0) * 1000
    except Exception:
        return None
 
# ──────────────────────────────────────────────
# MULTI-PROTOCOL SCANNER CORE
# ──────────────────────────────────────────────
 
class ScanResult:
    __slots__ = ("target","probes","avg_ping","alive")
    def __init__(self, target: str):
        self.target   = target
        self.probes: Dict[str, Optional[float]] = {}
        self.avg_ping: float = 9999.0
        self.alive: bool = False
 
    def compute(self):
        vals = [v for v in self.probes.values() if v is not None]
        if vals:
            self.avg_ping = round(sum(vals) / len(vals), 2)
            self.alive = True
        else:
            self.alive = False
 
    def to_line(self) -> str:
        detail = "  ".join(
            f"{k}={round(v,1)}ms" if v is not None else f"{k}=FAIL"
            for k, v in self.probes.items()
        )
        return f"{self.target:<55} avg={self.avg_ping:>8.1f}ms  [{detail}]"
 
 
def scan_target(target: str, protocols: List[str], timeout: float,
                repeat: int = 3) -> ScanResult:
    res = ScanResult(target)
    # Helper: average over repeat
    def avg_probe(fn, *args) -> Optional[float]:
        samples = []
        for _ in range(repeat):
            v = fn(*args)
            if v is not None:
                samples.append(v)
            time.sleep(0.05)
        return round(sum(samples)/len(samples), 2) if samples else None
 
    for proto in protocols:
        if proto == "tcp80":
            res.probes["tcp80"]  = avg_probe(probe_tcp,  target, 80,  timeout)
        elif proto == "tcp443":
            res.probes["tcp443"] = avg_probe(probe_tcp,  target, 443, timeout)
        elif proto == "http":
            res.probes["http"]   = avg_probe(probe_http, target, 80,  False, timeout)
        elif proto == "https":
            res.probes["https"]  = avg_probe(probe_http, target, 443, True,  timeout)
        elif proto == "icmp":
            res.probes["icmp"]   = avg_probe(probe_icmp, target, timeout)
        elif proto == "dns":
            res.probes["dns"]    = avg_probe(probe_dns,  target, timeout)
        elif proto == "tls":
            res.probes["tls"]    = avg_probe(probe_tls,  target, 443, timeout)
 
    res.compute()
    return res
 
# ──────────────────────────────────────────────
# IP RANGE EXPANSION
# ──────────────────────────────────────────────
 
def expand_cidrs(cidrs: List[str]) -> List[str]:
    ips = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            ips.extend(str(ip) for ip in net.hosts())
        except Exception:
            pass
    return ips
 
# ──────────────────────────────────────────────
# WORKER POOL
# ──────────────────────────────────────────────
 
class ScanEngine:
    def __init__(self, targets: List[str], protocols: List[str],
                 workers: int, timeout: float, repeat: int,
                 status_file: str, result_file: str):
        self.targets      = targets
        self.protocols    = protocols
        self.workers      = workers
        self.timeout      = timeout
        self.repeat       = repeat
        self.status_file  = status_file
        self.result_file  = result_file
        self.q            = Queue()
        self.lock         = threading.Lock()
        self.results: List[ScanResult] = []
        self.scanned      = 0
        self.total        = len(targets)
        self.alive_count  = 0
        self.start_time   = time.time()
        self._stop        = threading.Event()
 
    def _worker(self):
        while not self._stop.is_set():
            try:
                target = self.q.get(timeout=0.5)
            except Empty:
                break
            r = scan_target(target, self.protocols, self.timeout, self.repeat)
            with self.lock:
                self.results.append(r)
                self.scanned += 1
                if r.alive:
                    self.alive_count += 1
                self._update_status()
            self.q.task_done()
 
    def _update_status(self):
        elapsed = time.time() - self.start_time
        rate = self.scanned / elapsed if elapsed > 0 else 0
        eta  = (self.total - self.scanned) / rate if rate > 0 else 0
        pct  = self.scanned / self.total * 100
        data = {
            "status"    : "running" if self.scanned < self.total else "done",
            "scanned"   : self.scanned,
            "total"     : self.total,
            "alive"     : self.alive_count,
            "percent"   : round(pct, 2),
            "rate_per_s": round(rate, 2),
            "eta_s"     : round(eta, 0),
            "elapsed_s" : round(elapsed, 1),
            "timestamp" : datetime.now().isoformat(),
        }
        with open(self.status_file, "w") as f:
            json.dump(data, f, indent=2)
 
    def run(self):
        for t in self.targets:
            self.q.put(t)
        threads = [threading.Thread(target=self._worker, daemon=True)
                   for _ in range(self.workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self._finalize()
 
    def _finalize(self):
        alive = [r for r in self.results if r.alive]
        alive.sort(key=lambda r: r.avg_ping)
        # Write results
        with open(self.result_file, "w") as f:
            f.write(f"# Vercel/CDN Scan Results — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Protocols: {', '.join(self.protocols)}\n")
            f.write(f"# Targets: {self.total}   Alive: {len(alive)}\n")
            f.write("#\n")
            for r in alive:
                f.write(r.to_line() + "\n")
        # Final status
        data = {
            "status"   : "done",
            "scanned"  : self.scanned,
            "total"    : self.total,
            "alive"    : len(alive),
            "percent"  : 100.0,
            "elapsed_s": round(time.time() - self.start_time, 1),
            "timestamp": datetime.now().isoformat(),
            "result_file": self.result_file,
        }
        with open(self.status_file, "w") as f:
            json.dump(data, f, indent=2)
 
# ──────────────────────────────────────────────
# STATUS VIEWER
# ──────────────────────────────────────────────
 
def show_status(status_file: str, result_file: str):
    if not os.path.exists(status_file):
        print(C.fail("No scan is running or was started."))
        print(C.info(f"Expected status file: {status_file}"))
        return
    with open(status_file) as f:
        d = json.load(f)
 
    print(f"\n{C.BLD}{C.CYN}═══ Scan Status ═══{C.RST}")
    st = d.get("status","?")
    color = C.GRN if st == "done" else C.YLW
    print(f"  Status    : {color}{st.upper()}{C.RST}")
    print(f"  Progress  : {d['scanned']} / {d['total']}  ({d['percent']}%)")
    print(f"  Alive     : {C.GRN}{d['alive']}{C.RST}")
    print(f"  Elapsed   : {d['elapsed_s']}s")
    if st != "done":
        print(f"  Rate      : {d.get('rate_per_s','?')} targets/s")
        print(f"  ETA       : {d.get('eta_s','?')}s")
    bar_len = 40
    filled  = int(bar_len * d['percent'] / 100)
    bar     = "█" * filled + "░" * (bar_len - filled)
    print(f"\n  [{C.GRN}{bar}{C.RST}] {d['percent']}%\n")
    if st == "done":
        print(C.ok(f"Results saved → {d.get('result_file', result_file)}"))
        if os.path.exists(result_file):
            with open(result_file) as f:
                lines = [l for l in f if not l.startswith("#") and l.strip()]
            print(f"\n{C.BLD}  Top 10 results:{C.RST}")
            for line in lines[:10]:
                print(f"  {C.GRN}{line.rstrip()}{C.RST}")
            if len(lines) > 10:
                print(f"  {C.DIM}... and {len(lines)-10} more{C.RST}")
    print()
 
# ──────────────────────────────────────────────
# INTERACTIVE SETUP
# ──────────────────────────────────────────────
 
PROTO_CHOICES = {
    "1": ("tcp80",  "TCP port 80  (fast connect test)"),
    "2": ("tcp443", "TCP port 443 (fast connect test)"),
    "3": ("http",   "HTTP GET     (checks HTTP response)"),
    "4": ("https",  "HTTPS GET    (checks HTTPS response, ignore cert)"),
    "5": ("icmp",   "ICMP ping    (requires root)"),
    "6": ("dns",    "DNS resolve  (checks hostname resolves)"),
    "7": ("tls",    "TLS handshake (full crypto test)"),
}
 
def interactive_setup(ram_gb: float, cpu_count: int) -> dict:
    print(f"\n{C.BLD}{C.CYN}═══ System Resources ═══{C.RST}")
    print(f"  CPU cores : {cpu_count}")
    print(f"  RAM       : {ram_gb} GB")
    print(f"  Root      : {'YES (ICMP available)' if is_root() else 'NO  (ICMP disabled)'}")
    print(f"  OS        : {detect_os()}\n")
 
    # Best settings calculation
    if ram_gb >= 8 and cpu_count >= 8:
        best_workers = 512; best_timeout = 2.5; best_repeat = 3
        tier = "High-Performance"
    elif ram_gb >= 4 and cpu_count >= 4:
        best_workers = 256; best_timeout = 3.0; best_repeat = 3
        tier = "Standard"
    elif ram_gb >= 2:
        best_workers = 128; best_timeout = 3.5; best_repeat = 2
        tier = "Medium"
    else:
        best_workers = 64;  best_timeout = 4.0; best_repeat = 2
        tier = "Low-Resource"
 
    best_protocols = ["tcp443", "https", "dns"]
    if is_root():
        best_protocols.append("icmp")
 
    print(f"{C.BLD}Recommended profile: {C.GRN}{tier}{C.RST}")
    print(f"  Workers : {best_workers}")
    print(f"  Timeout : {best_timeout}s")
    print(f"  Repeats : {best_repeat} pings per target")
    print(f"  Protocols: {', '.join(best_protocols)}")
 
    print(f"\n{C.YLW}[1]{C.RST} Use best settings for your server")
    print(f"{C.YLW}[2]{C.RST} Customize settings manually\n")
    choice = input(f"  {C.BLD}Your choice [1/2]: {C.RST}").strip()
 
    if choice == "2":
        print(f"\n{C.BLD}{C.CYN}═══ Protocol Selection ═══{C.RST}")
        print(f"{C.DIM}  Select one or more (comma-separated, e.g. 1,3,4):{C.RST}\n")
        for k, (proto, desc) in PROTO_CHOICES.items():
            flag = f"{C.DIM}(root required){C.RST}" if proto == "icmp" and not is_root() else ""
            print(f"  [{C.YLW}{k}{C.RST}] {proto:<12} — {desc} {flag}")
        sel = input(f"\n  {C.BLD}Protocols [default: 1,2,3,4,6]: {C.RST}").strip() or "1,2,3,4,6"
        chosen_protos = []
        for s in sel.split(","):
            s = s.strip()
            if s in PROTO_CHOICES:
                p = PROTO_CHOICES[s][0]
                if p == "icmp" and not is_root():
                    print(C.warn("ICMP skipped — not running as root"))
                else:
                    chosen_protos.append(p)
        if not chosen_protos:
            chosen_protos = ["tcp443", "https", "dns"]
 
        print(f"\n{C.BLD}{C.CYN}═══ Custom Settings ═══{C.RST}")
        try:
            workers = int(input(f"  Worker threads [{best_workers}]: ").strip() or best_workers)
        except: workers = best_workers
        try:
            timeout = float(input(f"  Timeout seconds [{best_timeout}]: ").strip() or best_timeout)
        except: timeout = best_timeout
        try:
            repeat = int(input(f"  Ping repeats per target [{best_repeat}]: ").strip() or best_repeat)
        except: repeat = best_repeat
 
        scan_ips     = input(f"\n  Scan Vercel IP ranges? [Y/n]: ").strip().lower() != "n"
        scan_domains = input(f"  Scan CDN domains?       [Y/n]: ").strip().lower() != "n"
 
        return dict(workers=workers, timeout=timeout, repeat=repeat,
                    protocols=chosen_protos,
                    scan_ips=scan_ips, scan_domains=scan_domains)
    else:
        scan_ips     = input(f"\n  Scan Vercel IP ranges? [Y/n]: ").strip().lower() != "n"
        scan_domains = input(f"  Scan CDN domains?       [Y/n]: ").strip().lower() != "n"
        return dict(workers=best_workers, timeout=best_timeout, repeat=best_repeat,
                    protocols=best_protocols,
                    scan_ips=scan_ips, scan_domains=scan_domains)
 
# ──────────────────────────────────────────────
# BACKGROUND RUNNER
# ──────────────────────────────────────────────
 
def launch_background(config: dict, status_file: str, result_file: str,
                      log_file: str):
    """Fork a detached child process for the scan."""
    pid = os.fork()
    if pid > 0:
        # Parent
        print(f"\n{C.GRN}{C.BLD}✔ Scan launched in background (PID {pid}){C.RST}")
        print(C.info(f"Status file : {status_file}"))
        print(C.info(f"Result file : {result_file}"))
        print(C.info(f"Log file    : {log_file}"))
        print(f"\n{C.YLW}Check progress anytime:{C.RST}")
        script = os.path.abspath(__file__)
        print(f"  python3 {script} --status\n")
        sys.exit(0)
 
    # Child: detach
    os.setsid()
    # Redirect stdio to log
    with open(log_file, "w") as log:
        sys.stdout = log
        sys.stderr = log
        _run_scan(config, status_file, result_file)
    sys.exit(0)
 
def _run_scan(config: dict, status_file: str, result_file: str):
    targets = []
    if config.get("scan_ips", True):
        targets.extend(expand_cidrs(VERCEL_CIDR))
    if config.get("scan_domains", True):
        targets.extend(CDN_DOMAINS)
 
    # Remove duplicates
    seen = set(); unique = []
    for t in targets:
        if t not in seen:
            seen.add(t); unique.append(t)
    targets = unique
 
    print(f"[{datetime.now().isoformat()}] Starting scan: {len(targets)} targets", flush=True)
 
    engine = ScanEngine(
        targets     = targets,
        protocols   = config["protocols"],
        workers     = config["workers"],
        timeout     = config["timeout"],
        repeat      = config["repeat"],
        status_file = status_file,
        result_file = result_file,
    )
    engine.run()
    print(f"[{datetime.now().isoformat()}] Scan complete. Alive: {engine.alive_count}", flush=True)
 
# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
 
STATUS_FILE = "/tmp/vercel_scan_status.json"
RESULT_FILE = os.path.expanduser("~/vercel_scan_results.txt")
LOG_FILE    = "/tmp/vercel_scan.log"
 
def main():
    parser = argparse.ArgumentParser(
        description="Vercel/CDN Scanner — zero external dependencies",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--status", action="store_true",
                        help="Show current scan status")
    parser.add_argument("--status-file", default=STATUS_FILE)
    parser.add_argument("--result-file", default=RESULT_FILE)
    parser.add_argument("--foreground", action="store_true",
                        help="Run scan in foreground (don't fork)")
    args = parser.parse_args()
 
    if args.status:
        show_status(args.status_file, args.result_file)
        return
 
    print_banner()
 
    ram_gb    = get_ram_gb()
    cpu_count = get_cpu_count()
 
    config = interactive_setup(ram_gb, cpu_count)
 
    # Summary
    print(f"\n{C.BLD}{C.CYN}═══ Scan Summary ═══{C.RST}")
    total = 0
    if config["scan_ips"]:
        ips = expand_cidrs(VERCEL_CIDR)
        total += len(ips)
        print(f"  IP targets   : {len(ips)}  (from {len(VERCEL_CIDR)} CIDR ranges)")
    if config["scan_domains"]:
        total += len(CDN_DOMAINS)
        print(f"  CDN domains  : {len(CDN_DOMAINS)}")
    print(f"  Total targets: {total}")
    print(f"  Protocols    : {', '.join(config['protocols'])}")
    print(f"  Workers      : {config['workers']}")
    print(f"  Timeout      : {config['timeout']}s")
    print(f"  Repeat pings : {config['repeat']}")
    print(f"  Output file  : {args.result_file}")
 
    est = total * config["repeat"] * len(config["protocols"]) * 0.05
    est_real = est / config["workers"]
    print(f"  Est. time    : ~{round(est_real)}s with {config['workers']} workers\n")
 
    ok = input(f"{C.BLD}Start scan? [Y/n]: {C.RST}").strip().lower()
    if ok == "n":
        print("Aborted.")
        return
 
    if args.foreground:
        print(f"\n{C.YLW}Running in foreground…{C.RST}\n")
        _run_scan(config, args.status_file, args.result_file)
        print()
        show_status(args.status_file, args.result_file)
    else:
        if not hasattr(os, "fork"):
            print(C.warn("os.fork not available on this platform — running foreground"))
            _run_scan(config, args.status_file, args.result_file)
            show_status(args.status_file, args.result_file)
        else:
            launch_background(config, args.status_file, args.result_file, LOG_FILE)
 
if __name__ == "__main__":
    main()