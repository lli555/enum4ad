# AD Enumeration Tool

A comprehensive tool for automated Active Directory environment enumeration. This tool provides port scanning, full enumeration, vulnerability assessment, and authenticated enumeration capabilities with service-specific reconnaissance.

## Features

- **Port Scanning**: Targeted nmap scans with service detection
- **Full Enumeration**: Complete automated enumeration based on discovered services
- **Vulnerability Scanning**: SMB vulnerability testing using NetExec modules
- **Authenticated Enumeration**: Credential-based enumeration for deeper access assessment
- **Service-Specific Enumeration**:
  - SMB/NetBIOS (port 139, 445)
  - LDAP (port 389, 636, 3268, 3269)
  - HTTP/HTTPS (port 80, 443, 8080, 8443)
  - WinRM (port 5985, 5986)
  - RDP (port 3389)
  - And more...
- **Concurrent Processing**: Multi-threaded scanning and enumeration
- **Organized Output**: Timestamped results with categorized output files

## Installation

1. Clone or download the tool:
```bash
git clone <repository> ADTool
cd ADTool
```

2. Run the setup script to install dependencies:
```bash
chmod +x setup.sh
./setup.sh
```

3. Make the main script executable:
```bash
chmod +x main.py
```

## Usage

### Port Scan Only
Perform nmap scans on specific IP addresses:
```bash
python3 main.py -ps 10.1.1.1,10.1.1.2
```

### Full Enumeration
Complete enumeration including port scanning and service-specific enumeration:
```bash
# Single IPs
python3 main.py -f 10.1.1.1,10.1.1.5

# CIDR notation
python3 main.py -f 192.168.1.0/24

# Custom output directory
python3 main.py -f 10.1.1.0/24 -o my_scan_results

# Verbose output
python3 main.py -f 10.1.1.1 -v

# Custom thread count
python3 main.py -f 10.1.1.0/24 -t 20
```

### Vulnerability Scanning
Test for common SMB vulnerabilities:
```bash
# Basic vulnerability scan
python3 main.py -vulns 192.168.1.10,192.168.1.11

# Vulnerability scan with verbose output
python3 main.py -vulns 192.168.1.0/24 -v
```

### Authenticated Enumeration
Perform enumeration with valid domain or local credentials:
```bash
# Domain authentication
python3 main.py -auth 192.168.1.10 -user DOMAIN/administrator -p Password123

# Local authentication
python3 main.py -auth 192.168.1.0/24 -user administrator -p Password123 --local-auth

# Multiple targets with domain credentials
python3 main.py -auth 10.1.1.1,10.1.1.2 -user CONTOSO/john.doe -p ComplexPass2024
```

## Command Line Options

### Scan Modes (mutually exclusive)
- `-ps, --portscan`: Port scan mode - comma-separated IPs
- `-f, --full`: Full enumeration mode - comma-separated IPs or CIDR
- `-vulns, --vulnerabilities`: Vulnerability scan mode - comma-separated IPs
- `-auth, --authenticated`: Authenticated enumeration mode - comma-separated IPs

### General Options
- `-o, --output`: Output directory (default: ad_enum_results)
- `-t, --threads`: Number of concurrent threads (default: 10)
- `-v, --verbose`: Enable verbose logging

### Authentication Options (required for -auth mode)
- `-user, --username`: Domain username (format: domain/username or username)
- `-p, --password`: Password for authentication
- `--local-auth`: Use local authentication instead of domain authentication

## Output Structure

```
ad_enum_results_YYYYMMDD_HHMMSS/
├── nmap/
│   ├── nmap_10.1.1.1.txt
│   └── nmap_10.1.1.2.txt
├── enumeration/
│   ├── smb_shares_10.1.1.1.txt
│   ├── ldap_basic_10.1.1.1.txt
│   ├── web_dirs_10.1.1.2_80.txt
│   ├── vuln_zerologon_10.1.1.1.txt
│   ├── vuln_ms17-010_10.1.1.1.txt
│   ├── smb_shares_domain_10.1.1.1.txt
│   ├── winrm_access_domain_10.1.1.1.txt
│   ├── rdp_access_local_10.1.1.1.txt
│   └── enum4linux_auth_10.1.1.1.txt
├── enumeration_summary.txt
├── vulnerability_summary.txt
└── authenticated_enumeration_summary.txt
```

## Service Enumeration

### SMB/NetBIOS
- Anonymous share enumeration
- SMB version detection
- Null session attempts
- User enumeration

Commands used:
```bash
netexec smb {ip} -u "" -p "" --shares
netexec smb {ip}
netexec smb {ip} -u "" -p "" --rid-brute
netexec smb {ip} -u guest -p "" --users
```

### LDAP
- Basic LDAP enumeration
- Anonymous bind attempts
- Domain enumeration
- User enumeration

Commands used:
```bash
netexec ldap {ip}
netexec ldap {ip} -u "" -p ""
netexec ldap {ip} -u "" -p "" --trusted-for-delegation
netexec ldap {ip} -u "" -p "" --users
```

### Web Services
- Directory busting
- Nikto vulnerability scanning
- Header analysis

Commands used:
```bash
gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt
nikto -h {ip}:{port}
curl -I -k --connect-timeout 10 {url}
```

## Vulnerability Scanning

Tests for common SMB vulnerabilities using NetExec modules:

### Supported Vulnerability Checks
- **Zerologon (CVE-2020-1472)**: Domain Controller privilege escalation
- **PrintNightmare (CVE-2021-1675)**: Print Spooler privilege escalation
- **SMBGhost (CVE-2020-0796)**: SMBv3 compression vulnerability
- **MS17-010 (EternalBlue)**: SMB vulnerability exploited by WannaCry
- **Coerce Plus**: Authentication coercion attacks

Commands used:
```bash
nxc smb {ip} -u '' -p '' -M zerologon
nxc smb {ip} -u '' -p '' -M printnightmare
nxc smb {ip} -u '' -p '' -M smbghost
nxc smb {ip} -u '' -p '' -M ms17-010
nxc smb {ip} -u '' -p '' -M coerce_plus
```

## Authenticated Enumeration

Performs comprehensive enumeration with valid credentials to assess the level of access:

### Domain Authentication Tests
- **SMB Share Access**: Enumerate accessible shares with credentials
- **Password Policy**: Retrieve domain password policy
- **WinRM Access**: Test Windows Remote Management access
- **RDP Access**: Test Remote Desktop Protocol access
- **LDAP User Descriptions**: Extract user descriptions from LDAP
- **enum4linux-ng**: Comprehensive SMB/NetBIOS enumeration with credentials

### Local Authentication Tests
All domain tests are also performed with local authentication using the `--local-auth` flag to test local user accounts.

Commands used:
```bash
# Domain authentication
netexec smb {ip} -u {username} -p {password} --shares
netexec smb {ip} -u {username} -p {password} --pass-pol
netexec winrm {ip} -u {username} -p {password}
netexec rdp {ip} -u {username} -p {password}
netexec ldap {ip} -u {username} -p {password} -M get-desc-users
enum4linux-ng {ip} -u {username} -p {password} -oY {username}_enumlinux.txt

# Local authentication (same commands with --local-auth flag)
netexec smb {ip} -u {username} -p {password} --shares --local-auth
# ... etc
```

## Dependencies

### Required Tools
- **nmap**: Port scanning and service detection
- **netexec/nxc**: SMB and LDAP enumeration and vulnerability testing
- **gobuster**: Directory and file brute forcing
- **nikto**: Web vulnerability scanner
- **curl**: HTTP client for header analysis
- **enum4linux-ng**: SMB/NetBIOS enumeration tool

### Python Packages
- **asyncio**: Asynchronous processing (built-in)
- **ipaddress**: IP address validation (built-in)

### Installation Commands
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap gobuster nikto curl
pip3 install netexec
pip3 install enum4linux-ng

# Alternative: Install nxc (newer netexec alias)
pipx install netexec
```

## Examples

### Basic Port Scan
```bash
python3 main.py -ps 192.168.1.10,192.168.1.20
```

### Full Network Enumeration
```bash
python3 main.py -f 192.168.1.0/24 -o domain_scan -v
```

### Targeted Full Enumeration
```bash
python3 main.py -f 10.10.10.10,10.10.10.11 -t 5
```

### Vulnerability Assessment
```bash
# Scan multiple domain controllers for common AD vulnerabilities
python3 main.py -vulns 192.168.1.10,192.168.1.11 -v

# Quick vulnerability check on discovered systems
python3 main.py -vulns 10.1.1.0/24
```

### Authenticated Enumeration Examples
```bash
# Test domain admin access across multiple systems
python3 main.py -auth 192.168.1.0/24 -user CORP/administrator -p P@ssw0rd123

# Check local admin access on specific targets
python3 main.py -auth 10.1.1.5,10.1.1.10 -user administrator -p LocalPass123 --local-auth

# Assess user privileges with verbose output
python3 main.py -auth 192.168.1.20 -user DOMAIN/john.doe -p UserPass2024 -v
```

### Combined Workflow Examples
```bash
# Complete assessment workflow
python3 main.py -f 192.168.1.0/24 -o complete_assessment -v
python3 main.py -vulns 192.168.1.0/24 -o complete_assessment -v  
python3 main.py -auth 192.168.1.0/24 -user CORP/testuser -p TestPass123 -o complete_assessment -v
```

## File Structure

```
ADTool/
├── main.py                     # Main CLI interface
├── modules/
│   ├── __init__.py
│   ├── utils.py               # Utility functions
│   ├── port_scanner.py        # Nmap scanning module
│   └── enumerators/
│       ├── __init__.py
│       ├── smb_enum.py        # SMB enumeration
│       ├── ldap_enum.py       # LDAP enumeration
│       ├── web_enum.py        # Web enumeration
│       ├── vuln_enum.py       # Vulnerability scanning
│       ├── auth_enum.py       # Authenticated enumeration
│       └── full_enum.py       # Full enumeration coordinator
├── config/
│   └── services.json          # Service detection rules
├── setup.sh                   # Dependency installation script
└── README.md                  # This file
```

## License

This tool is for educational and authorized penetration testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks or systems.

## Contributing

Feel free to submit issues and enhancement requests. Contributions are welcome for additional service enumeration modules and improvements.

## Troubleshooting

1. **netexec/nxc not found**: Install netexec using `pip3 install netexec` or `pipx install netexec`
2. **Permission denied for nmap**: Run nmap scans as root or configure capabilities: `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap`
3. **Wordlists not found**: Install wordlists using `sudo apt install seclists dirb`
4. **Network unreachable**: Check network connectivity and firewall rules
5. **enum4linux-ng not found**: Install using `pip3 install enum4linux-ng`
6. **Authentication failures**: Verify credentials and ensure target systems allow the authentication method (domain vs local)
7. **Vulnerability modules not working**: Ensure you have the latest version of netexec/nxc with updated modules

### Common Issues
- **False positives in vulnerability scans**: Review individual module outputs for context
- **Timeouts on large networks**: Reduce thread count with `-t` parameter or scan smaller subnets
- **Missing results**: Check verbose output (`-v`) for detailed error messages