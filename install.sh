#!/usr/bin/env bash
set -e

# ─────────────────────────────────────────────────────────
#  scanner.py — install & run
#  github.com/alixtron0/vscanner
# ─────────────────────────────────────────────────────────

RED='\033[91m'; GRN='\033[92m'; YLW='\033[93m'
CYN='\033[96m'; BLD='\033[1m';  RST='\033[0m'

ok()   { echo -e "${GRN}✔${RST}  $*"; }
fail() { echo -e "${RED}✘${RST}  $*"; exit 1; }
info() { echo -e "${CYN}→${RST}  $*"; }
warn() { echo -e "${YLW}⚠${RST}  $*"; }
sep()  { echo -e "${CYN}────────────────────────────────────────${RST}"; }

REPO="https://raw.githubusercontent.com/alixtron0/vscanner/main"
INSTALL_DIR="/opt/scanner"
SCRIPT="scanner.py"

echo ""
echo -e "${BLD}${CYN}  scanner.py — CDN / Vercel / Domain-Fronting Scanner${RST}"
echo -e "${CYN}  github.com/alixtron0/vscanner${RST}"
sep
echo ""

# ── root check ───────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. ICMP probes will be unavailable."
    warn "Re-run with: sudo bash install.sh"
    echo ""
fi

# ── detect OS ────────────────────────────────────────────
if   [[ -f /etc/os-release ]]; then source /etc/os-release; DISTRO=$ID
elif [[ -f /etc/centos-release ]]; then DISTRO="centos"
elif [[ -f /etc/redhat-release ]]; then DISTRO="rhel"
else DISTRO="unknown"; fi

info "Detected OS: ${DISTRO}"

# ── python3 check ────────────────────────────────────────
if command -v python3 &>/dev/null; then
    PY=$(python3 --version 2>&1)
    ok "Python found: $PY"
else
    warn "python3 not found — attempting install..."
    case $DISTRO in
        ubuntu|debian)
            apt-get update -qq && apt-get install -y -qq python3
            ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &>/dev/null; then
                dnf install -y -q python3
            else
                yum install -y -q python3
            fi
            ;;
        *)
            fail "Cannot auto-install python3 on '$DISTRO'. Install it manually and re-run."
            ;;
    esac
    command -v python3 &>/dev/null || fail "python3 install failed. Install it manually."
    ok "python3 installed"
fi

# ── verify python version ≥ 3.6 ──────────────────────────
PY_VER=$(python3 -c "import sys; print(sys.version_info.minor if sys.version_info.major==3 else 0)")
if [[ $PY_VER -lt 6 ]]; then
    fail "Python 3.6+ required. Found: $(python3 --version)"
fi

# ── create install dir ───────────────────────────────────
mkdir -p "$INSTALL_DIR"
info "Install directory: $INSTALL_DIR"

# ── download or copy scanner.py ──────────────────────────
sep
echo ""

# If script is sitting next to install.sh, just copy it
SCRIPT_LOCAL="$(dirname "$0")/$SCRIPT"
if [[ -f "$SCRIPT_LOCAL" ]]; then
    cp "$SCRIPT_LOCAL" "$INSTALL_DIR/$SCRIPT"
    ok "Copied $SCRIPT from local directory"
else
    info "Downloading $SCRIPT from GitHub..."
    DL_OK=0

    if command -v curl &>/dev/null; then
        curl -fsSL "$REPO/$SCRIPT" -o "$INSTALL_DIR/$SCRIPT" && DL_OK=1
    fi

    if [[ $DL_OK -eq 0 ]] && command -v wget &>/dev/null; then
        wget -q "$REPO/$SCRIPT" -O "$INSTALL_DIR/$SCRIPT" && DL_OK=1
    fi

    if [[ $DL_OK -eq 0 ]]; then
        echo ""
        warn "Could not download automatically (common on Iranian servers)."
        echo ""
        echo -e "  ${BLD}Download the file manually on your local machine:${RST}"
        echo ""
        echo -e "    ${YLW}https://raw.githubusercontent.com/alixtron0/vscanner/main/scanner.py${RST}"
        echo ""
        echo -e "  Then copy it to this server:"
        echo ""
        echo -e "    ${YLW}scp scanner.py root@$(hostname -I | awk '{print $1}'):$INSTALL_DIR/scanner.py${RST}"
        echo ""
        echo -e "  After that, run this script again."
        echo ""
        exit 1
    fi

    ok "Downloaded $SCRIPT"
fi

chmod +x "$INSTALL_DIR/$SCRIPT"

# ── create global shortcut ───────────────────────────────
cat > /usr/local/bin/scanner << EOF
#!/usr/bin/env bash
exec python3 $INSTALL_DIR/$SCRIPT "\$@"
EOF
chmod +x /usr/local/bin/scanner
ok "Created shortcut: /usr/local/bin/scanner"

# ── create status shortcut ───────────────────────────────
cat > /usr/local/bin/scanner-status << EOF
#!/usr/bin/env bash
exec python3 $INSTALL_DIR/$SCRIPT --status "\$@"
EOF
chmod +x /usr/local/bin/scanner-status
ok "Created shortcut: /usr/local/bin/scanner-status"

# ── done ─────────────────────────────────────────────────
echo ""
sep
echo ""
echo -e "${GRN}${BLD}  Installation complete.${RST}"
echo ""
echo -e "  Start a scan:         ${BLD}scanner${RST}"
echo -e "  Check progress:       ${BLD}scanner-status${RST}"
echo -e "  Run in foreground:    ${BLD}scanner --foreground${RST}"
echo ""
echo -e "  Results saved to:     ${YLW}~/vercel_scan_results.txt${RST}"
echo -e "  Status file:          ${YLW}/tmp/vercel_scan_status.json${RST}"
echo ""

# ── ask to run now ───────────────────────────────────────
read -rp "  Run scanner now? [Y/n]: " RUN_NOW
RUN_NOW="${RUN_NOW:-Y}"

if [[ "${RUN_NOW^^}" == "Y" ]]; then
    echo ""
    exec python3 "$INSTALL_DIR/$SCRIPT"
else
    echo ""
    info "Run it later with: scanner"
    echo ""
fi
