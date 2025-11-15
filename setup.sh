#!/bin/bash

# AD Enumeration Tool Setup Script
# This script installs the required dependencies for the AD enumeration tool

set -euo pipefail

# Color and formatting helpers
if [ -t 1 ]; then
	RED=$(printf '\033[31m')
	YELLOW=$(printf '\033[33m')
	GREEN=$(printf '\033[32m')
	BLUE=$(printf '\033[34m')
	BOLD=$(printf '\033[1m')
	RESET=$(printf '\033[0m')
else
	RED=''
	YELLOW=''
	GREEN=''
	BLUE=''
	BOLD=''
	RESET=''
fi

header() { printf "%s%s==> %s%s\n\n" "$BOLD" "$BLUE" "$*" "$RESET"; }
err() { printf "%s[!] %s%s\n" "$RED$BOLD" "$*" "$RESET" >&2; }
warn() { printf "%s[!] %s%s\n" "$YELLOW$BOLD" "$*" "$RESET" >&2; }
info() { printf "%s[+] %s%s\n" "$BLUE$BOLD" "$*" "$RESET"; }
success() { printf "%s[+] %s%s\n" "$GREEN$BOLD" "$*" "$RESET"; }

run_as_sudo() {
	if [ "${EUID:-$(id -u)}" -ne 0 ]; then
		sudo "$@"
	else
		"$@"
	fi
}

header "AD Enumeration Tool Setup"

ask_yes_no() {
	# $1 = prompt, returns 0=yes, 1=no
	while true; do
		read -r -p "$1 [y/N]: " yn
		case "$yn" in
			[Yy]*) return 0 ;;
			[Nn]|"") return 1 ;;
			*) echo "Please answer y or n." ;;
		esac
	done
}

# Basic environment checks
if ! command -v apt >/dev/null 2>&1; then
	err "apt not found. This script expects a Debian-like environment (Kali). Aborting."
	exit 1
fi

if [ -r /etc/os-release ]; then
	if ! grep -qi "kali" /etc/os-release; then
		warn "/etc/os-release does not mention 'Kali'. Continuing, but this script assumes Kali/Debian." 
	else
		info "Kali detected via /etc/os-release"
	fi
fi

info "Updating package lists (apt)..."
run_as_sudo apt update -y

# Ensure sudo is available for later operations
if ! command -v sudo >/dev/null 2>&1; then
	warn "sudo not found. You should run this script as root if sudo is unavailable."
fi

info "Checking required base tools..."

ensure_pkg_installed() {
	# $1 = package name (for apt)
	# $2 = optional command to check (defaults to package name)
	pkg="$1"
	check_cmd="${2:-$1}"
	if dpkg -s "$pkg" >/dev/null 2>&1 || command -v "$check_cmd" >/dev/null 2>&1; then
		info "$pkg is already installed"
		return 0
	fi
	info "$pkg is missing. Installing $pkg..."
	run_as_sudo apt install -y "$pkg"
}

# Install basic tools we will use in this script (wget, unzip, curl)
ensure_pkg_installed wget wget
ensure_pkg_installed unzip unzip
ensure_pkg_installed curl curl

echo
warn "Python package installation warning"
info "Installing Python packages with pip can alter or conflict with system-managed packages."
if ask_yes_no "Do you want to continue and let this script run pip installs on your current Python environment? (If you choose no, the script will exit and recommend creating a virtualenv)"; then
	PIP_OK=1
else
	err "Skipping Python installs. Please create and activate a Python virtual environment and then install required Python packages manually."
	echo
	info "Recommended steps:" 
	echo "  python3 -m venv .venv; source .venv/bin/activate; pip install -r requirements.txt (or pip3 install netexec enum4linux-ng)"
	exit 1
fi

# Ensure pip3 exists
if ! command -v pip3 >/dev/null 2>&1; then
	info "pip3 not found. Installing python3-pip..."
	run_as_sudo apt install -y python3-pip
fi

info "Installing Python packages (user-level where appropriate)..."

# asyncio is part of stdlib for Python 3.4+, skip if present
if python3 - <<'PY' 2>/dev/null
import sys
try:
	import asyncio
	sys.exit(0)
except Exception:
	sys.exit(1)
PY
then
	info "asyncio present in stdlib; skipping install"
else
	pip3 install --user asyncio || true
fi

# Install netexec (formerly CrackMapExec) if missing
if ! command -v netexec >/dev/null 2>&1 && ! pip3 show netexec >/dev/null 2>&1; then
	info "Installing netexec via pip3 --user"
	pip3 install --user netexec
else
	info "netexec already installed"
fi

# Install enum4linux-ng via pip if missing
if ! command -v enum4linux-ng >/dev/null 2>&1 && ! pip3 show enum4linux-ng >/dev/null 2>&1; then
	info "Installing enum4linux-ng via apt on kali"
	run_as_sudo apt install -y enum4linux-ng
else
	info "enum4linux-ng already installed"
fi

echo
info "Installing enumeration and helper tools via apt (if missing)..."

# Install nmap
if ! command -v nmap >/dev/null 2>&1; then
	info "Installing nmap..."
	run_as_sudo apt install -y nmap
else
	info "nmap already installed"
fi

# Install gobuster
if ! command -v gobuster >/dev/null 2>&1; then
	info "Installing gobuster..."
	run_as_sudo apt install -y gobuster
else
	info "gobuster already installed"
fi

# Install nikto
if ! command -v nikto >/dev/null 2>&1; then
	info "Installing nikto..."
	run_as_sudo apt install -y nikto
else
	info "nikto already installed"
fi

# Cuti potati
# Install coercer
if ! command -v coercer >/dev/null 2>&1; then
	info "Installing coercer..."
	run_as_sudo apt install -y coercer
else
	info "coercer already installed"
fi

# Install wordlists
if ! dpkg -s seclists >/dev/null 2>&1; then
	info "Installing seclists and dirb wordlists..."
	run_as_sudo apt install -y seclists dirb
else
	info "seclists/dirb already installed"
fi

echo
if command -v rustscan >/dev/null 2>&1; then
	success "rustscan already installed: $(rustscan --version 2>/dev/null | head -n1 || echo '(version output unavailable)')"
else
	info "Installing RustScan (prebuilt binary)"

	RUSTSCAN_URL="https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz.zip"
	TMPDIR="$(mktemp -d)"
	cleanup() {
		rm -rf "$TMPDIR"
	}
	trap cleanup EXIT

	RUSTZIP="$TMPDIR/rustscan.zip"

	info "Downloading RustScan to $RUSTZIP"
	if wget -q -O "$RUSTZIP" "$RUSTSCAN_URL"; then
		info "Downloaded RustScan archive"
	else
		err "Failed to download RustScan from $RUSTSCAN_URL"
		exit 1
	fi

	info "Unpacking RustScan archive"
	if unzip -q "$RUSTZIP" -d "$TMPDIR"; then
		info "Unzipped archive"
	else
		err "Failed to unzip RustScan archive"
		exit 1
	fi

	# The zip contains a tar.gz; extract any .tar.gz found
	TARFILE="$(find "$TMPDIR" -type f -name '*.tar.gz' | head -n1 || true)"
	if [ -n "$TARFILE" ]; then
		info "Found tarball: $TARFILE. Extracting..."
		tar -xzf "$TARFILE" -C "$TMPDIR"
	fi

	# Find executable candidate
	RUSTBIN="$(find "$TMPDIR" -type f -iname 'rustscan*' -perm /111 | head -n1 || true)"
	if [ -z "$RUSTBIN" ]; then
		# try non-executable file names and make them executable
		RUSTBIN="$(find "$TMPDIR" -type f -iname 'rustscan*' | head -n1 || true)"
	fi

	if [ -z "$RUSTBIN" ]; then
		err "Could not find rustscan binary in the archive"
		exit 1
	fi

	info "Found rustscan binary: $RUSTBIN"
	run_as_sudo chmod +x "$RUSTBIN"

	info "Moving rustscan to /usr/bin (requires sudo)"
	run_as_sudo mv -f "$RUSTBIN" /usr/bin/rustscan
	run_as_sudo chmod +x /usr/bin/rustscan

	if command -v rustscan >/dev/null 2>&1; then
		success "RustScan successfully installed: $(rustscan --version 2>/dev/null | head -n1 || echo '(version output unavailable)')"
	else
		err "rustscan not found in PATH after installation"
	fi
fi

echo
success "Setup complete! Printing tool versions (best-effort):"

print_version() {
	# $1 = display name, $2 = check command, $3 = version command (optional)
	name="$1"
	check_cmd="$2"
	version_cmd="${3:-}" 

	if command -v $check_cmd >/dev/null 2>&1; then
		if [ -n "$version_cmd" ]; then
			ver=$(eval "$version_cmd" 2>/dev/null | head -n1 || true)
		else
			ver=$($check_cmd --version 2>/dev/null | head -n1 || true)
		fi
		if [ -z "$ver" ]; then
			ver="(installed, version unknown)"
		fi
		info "  - $name: $ver"
	else
		# special-case python/pip and pip-installed packages
		if [ "$name" = "enum4linux-ng" ]; then
			if pip3 show enum4linux-ng >/dev/null 2>&1; then
				ver="pip-installed $(pip3 show enum4linux-ng 2>/dev/null | awk -F': ' '/Version:/{print $2;exit}')"
				info "  - $name: $ver"
				return
			fi
		fi
		info "  - $name: NOT FOUND"
	fi
}

print_version "nmap" nmap "nmap --version"
# netexec installs the `nxc` CLI; calling `netexec` may print an interactive
# first-run message like "[*] First time use detected". Prefer `nxc` if
# available and fall back to `netexec`.
if command -v nxc >/dev/null 2>&1; then
	# Use full path in case PATH differs when running under sudo
	nxc_bin="$(command -v nxc)"
	# 1) Direct capture (stdout+stderr)
	ver=$($nxc_bin --version 2>&1 | head -n1 || true)
	# 2) If empty and `script` is available, try forcing a pty (some programs only print on a tty)
	if [ -z "$ver" ] && command -v script >/dev/null 2>&1; then
		ver=$(script -q -c "$nxc_bin --version" /dev/null 2>&1 | head -n1 || true)
	fi
	if [ -n "$ver" ]; then
		info "  - netexec (nxc): $ver"
	else
		info "  - netexec (nxc): installed (version unknown)"
	fi
elif command -v netexec >/dev/null 2>&1; then
	ver=$(netexec --version 2>&1 | head -n1 || true)
	if [ -n "$ver" ]; then
		info "  - netexec: $ver"
	else
		info "  - netexec: installed (version unknown)"
	fi
else
	info "  - netexec: NOT FOUND"
fi
print_version "gobuster" gobuster "gobuster --version"
print_version "nikto" nikto "nikto -Version"
print_version "curl" curl "curl --version"
print_version "wget" wget "wget --version"
print_version "enum4linux-ng" enum4linux-ng "enum4linux-ng --version"
print_version "rustscan" rustscan "rustscan --version"
print_version "python3" python3 "python3 --version"
print_version "pip3" pip3 "pip3 --version"
info "  - coercer cutipotati versioning:"
set +e
coercer 2>/dev/null | sed -E 's/(.*)@podalirius_.*/\1/' | sed 's/.*/\x1b[32m&\x1b[0m/'
set -e

echo
info "You can now run the AD enumeration tool with:"
echo "    python3 main.py --help"