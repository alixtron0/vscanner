# scanner.py

> **فارسی:** [راهنمای فارسی را اینجا بخوانید](README.fa.md)

A network scanner for Vercel IPs, CDN endpoints, and domain-fronting hosts. It probes each target with multiple protocols, measures latency, and writes a sorted result file — fastest first.

No external dependencies. Runs on Ubuntu and CentOS out of the box.

---

## What it does

- Expands Vercel CIDR ranges into individual IPs and scans them
- Tests CDN and domain-fronting domains (Cloudflare, Akamai, AWS CloudFront, Fastly, Azure, Google, Netlify, and more)
- Supports multiple probe protocols per scan: TCP, HTTP, HTTPS, ICMP, DNS, TLS
- Detects your server's RAM and CPU and picks the right thread count automatically
- Runs the scan in the background so you can close your terminal
- Lets you check progress at any time with a single command
- Saves results sorted by average ping — best hosts at the top

---

## Requirements

- Python 3.6 or newer (no pip install needed)
- Linux (Ubuntu 18+, CentOS 7+, Debian 10+)
- Root access if you want ICMP ping — everything else works without it

---

## Installation

### Quick way (automated)

```bash
curl -O https://raw.githubusercontent.com/alixtron0/vscanner/main/install.sh
chmod +x install.sh
sudo bash install.sh
```

### Manual way (recommended for servers in Iran)

Downloading directly on an Iranian server can be unreliable depending on routing. The cleaner approach:

1. Download `scanner.py` on your local machine (laptop or home PC)
2. Transfer it to your server with `scp`:

```bash
scp scanner.py root@YOUR_SERVER_IP:/root/scanner.py
```

3. SSH into your server and run it:

```bash
ssh root@YOUR_SERVER_IP
python3 /root/scanner.py
```

That's it. No installation step needed.

---

## Usage

**Start a scan (runs in background):**
```bash
python3 scanner.py
```

**Check scan progress:**
```bash
python3 scanner.py --status
```

**Run in foreground instead (useful for debugging):**
```bash
python3 scanner.py --foreground
```

**Custom status and result file paths:**
```bash
python3 scanner.py --status-file /tmp/my_status.json --result-file /root/results.txt
```

---

## Protocol options

When you start a scan, you can pick one or more protocols:

| # | Protocol | What it checks |
|---|----------|----------------|
| 1 | tcp80 | TCP connect on port 80 |
| 2 | tcp443 | TCP connect on port 443 |
| 3 | http | Full HTTP GET request |
| 4 | https | HTTPS GET (certificate ignored) |
| 5 | icmp | Raw ICMP ping (root required) |
| 6 | dns | DNS resolution time |
| 7 | tls | Full TLS handshake |

Picking multiple protocols gives a more accurate average latency per host.

---

## Results

Results are saved to `~/vercel_scan_results.txt` by default and overwritten on each run. Format:

```
cdn.cloudflare.net          avg=   12.3ms  [tcp443=11.2ms  https=13.4ms  dns=8.1ms]
vercel.com                  avg=   24.7ms  [tcp443=22.1ms  https=27.3ms  dns=14.2ms]
assets.vercel.com           avg=   31.0ms  [tcp443=28.5ms  https=33.4ms  dns=9.1ms]
```

Sorted from lowest average ping to highest.

---

## Tips for Iranian servers

- Use `scp` to copy the file manually instead of `wget`/`curl` inside the server — more reliable
- Run as root (`sudo`) to unlock ICMP probes, which give the most accurate latency
- If you're behind heavy filtering, start with TCP and DNS probes only — they complete faster and don't depend on HTTP stacks
- The background mode (`python3 scanner.py`) keeps running even after you close your SSH session as long as you don't kill the process
- For very low-RAM VPS (512 MB or less), choose fewer workers when prompted — 32 to 64 is stable

---

## Files created at runtime

| File | Purpose |
|------|---------|
| `/tmp/vercel_scan_status.json` | Live scan progress (JSON) |
| `/tmp/vercel_scan.log` | Background process log |
| `~/vercel_scan_results.txt` | Final sorted results |

---

## License

MIT
