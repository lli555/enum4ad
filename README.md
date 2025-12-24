# enum4ad - AD Enumeration Tool

A comprehensive tool for automated Active Directory environment enumeration. This tool provides port scanning, full enumeration, vulnerability assessment, and authenticated enumeration capabilities with service-specific reconnaissance.

## Features

- **Port Scanning**: Fast port scanning with nmap or RustScan support
- **Full Enumeration**: Complete automated enumeration based on discovered services
- **Vulnerability Scanning**: SMB vulnerability testing using NetExec modules
- **Authenticated Enumeration**: Credential-based enumeration for deeper access assessment
  - Password authentication
  - NTLM hash authentication (Pass-the-Hash)
  - Domain and local authentication modes
  - Advanced attack techniques (Kerberoasting, AS-REP Roasting, BloodHound collection)
- **Service-Specific Enumeration**:
  - SMB/NetBIOS (port 139, 445)
  - LDAP (port 389, 636, 3268, 3269)
  - HTTP/HTTPS (port 80, 443, 8080, 8443)
  - WinRM (port 5985, 5986)
  - RDP (port 3389)
  - And more...
- **Concurrent Processing**: Asynchronous multi-threaded scanning and enumeration
- **Organized Output**: Timestamped results with categorized output files and comprehensive summaries

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
Perform fast port scans on specific IP addresses:
```bash
# Standard nmap scan
python3 main.py -ps 10.1.1.1,10.1.1.2

# Fast RustScan mode (requires rustscan installation)
python3 main.py -ps 10.1.1.1,10.1.1.2 --rustscan
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

# Custom output directory with path prefix
python3 main.py -f 10.1.1.0/24 -o output --path-prefix cptc

# Verbose output
python3 main.py -f 10.1.1.1 -v

# Custom thread count
python3 main.py -f 10.1.1.0/24 -t 20

# Use RustScan for faster port discovery
python3 main.py -f 192.168.1.0/24 --rustscan
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
# Domain authentication with password
python3 main.py -auth 192.168.1.10 -user DOMAIN/administrator -p Password123

# Pass-the-Hash with NTLM hash
python3 main.py -auth 192.168.1.10 -user DOMAIN/administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c

# Pass-the-Hash with LM:NT format
python3 main.py -auth 192.168.1.10 -user DOMAIN/administrator -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Local authentication with password
python3 main.py -auth 192.168.1.0/24 -user administrator -p Password123 --local-auth

# Local authentication with hash
python3 main.py -auth 192.168.1.0/24 -user administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c --local-auth

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
- `-p, --password`: Password for authentication (mutually exclusive with -hashes)
- `-hashes, --hashes`: NTLM hash for Pass-the-Hash attacks (format: LM:NT or :NT) (mutually exclusive with -p)
- `--local-auth`: Use local authentication instead of domain authentication

### Port Scanning Options
- `--rustscan`: Use RustScan for faster port scanning (requires rustscan to be installed)

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
│   ├── enum4linux_auth_10.1.1.1.txt
│   ├── kerberoasting_10.1.1.1.txt
│   ├── asrep_roasting_10.1.1.1.txt
│   └── bloodhound_collection_10.1.1.1.txt
├── bloodhound/
│   ├── {timestamp}_computers.json
│   ├── {timestamp}_users.json
│   ├── {timestamp}_groups.json
│   └── {timestamp}_bloodhound.zip
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

Performs comprehensive enumeration with valid credentials (password or NTLM hash) to assess the level of access:

### Domain Authentication Tests
- **SMB Share Access**: Enumerate accessible shares with credentials
- **Password Policy Enumeration**: Extract domain password policy settings
- **WinRM Access Testing**: Test Windows Remote Management access and identify admin rights
- **RDP Access Testing**: Test Remote Desktop Protocol access and identify admin rights
- **LDAP User Descriptions**: Extract user descriptions from LDAP (often contains passwords!)
- **enum4linux-ng**: Comprehensive SMB/NetBIOS enumeration with credentials
- **Kerberoasting**: Extract service account TGS tickets for offline cracking
- **AS-REP Roasting**: Identify and extract AS-REP hashes from accounts without Kerberos pre-auth
- **BloodHound Collection**: Automated Active Directory data collection for BloodHound analysis

### Local Authentication Tests
All domain tests (except Kerberos attacks and BloodHound) are also performed with local authentication using the `--local-auth` flag to test local user accounts.

### Pass-the-Hash Support
All authenticated enumeration can be performed using NTLM hashes instead of passwords:
- Supports LM:NT format (e.g., `aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`)
- Supports NT-only format (e.g., `:8846f7eaee8fb117ad06bdd830b7586c`)
- Compatible with all NetExec/nxc operations
- Compatible with Impacket tools (Kerberoasting, AS-REP Roasting)
- Compatible with BloodHound collection

Commands used:
```bash
# Domain authentication with password
netexec smb {ip} -u {username} -p {password} --shares
netexec smb {ip} -u {username} -p {password} --pass-pol
netexec winrm {ip} -u {username} -p {password}
netexec rdp {ip} -u {username} -p {password}
netexec ldap {ip} -u {username} -p {password} -M get-desc-users
enum4linux-ng {ip} -u {username} -p {password} -oY {username}_enumlinux.txt

# Domain authentication with NTLM hash (Pass-the-Hash)
netexec smb {ip} -u {username} -H {nt_hash} --shares
netexec winrm {ip} -u {username} -H {nt_hash}
# ... etc

# Kerberos attacks
impacket-GetUserSPNs -request -dc-ip {ip} {domain}/{username}:{password}
impacket-GetUserSPNs -request -dc-ip {ip} -hashes {lm_hash}:{nt_hash} {domain}/{username}
impacket-GetNPUsers -request -dc-ip {ip} {domain}/{username}:{password}
impacket-GetNPUsers -request -dc-ip {ip} -hashes {lm_hash}:{nt_hash} {domain}/{username}

# BloodHound collection
bloodhound-python -d {domain} -u {username} -p {password} -ns {ip} -c all --zip
bloodhound-python -d {domain} -u {username} --hashes {nt_hash} -ns {ip} -c all --zip

# Local authentication (same commands with --local-auth flag)
netexec smb {ip} -u {username} -p {password} --shares --local-auth
netexec smb {ip} -u {username} -H {nt_hash} --shares --local-auth
# ... etc
```

### Parallel Execution
All authenticated enumeration tasks run in parallel for maximum efficiency:
- All checks for a target execute concurrently
- Multiple targets are processed simultaneously
- Automatic retry logic for handling temporary conflicts
- Optimized for large-scale assessment

## Dependencies

### Required Tools
- **nmap**: Port scanning and service detection
- **netexec/nxc**: SMB and LDAP enumeration and vulnerability testing
- **gobuster**: Directory and file brute forcing
- **nikto**: Web vulnerability scanner
- **curl**: HTTP client for header analysis

### Optional Tools (for enhanced authenticated enumeration)
- **enum4linux-ng**: Enhanced SMB/NetBIOS enumeration
- **impacket-GetUserSPNs**: Kerberoasting attacks
- **impacket-GetNPUsers**: AS-REP Roasting attacks
- **bloodhound-python**: Active Directory data collection for BloodHound
- **rustscan**: Ultra-fast port scanner (faster alternative to nmap)

### Python Packages
- **asyncio**: Asynchronous processing (built-in)
- **ipaddress**: IP address validation (built-in)

### Installation Commands
```bash
# Ubuntu/Debian - Core tools
sudo apt update
sudo apt install nmap gobuster nikto curl python3-pip

# NetExec/nxc
pip3 install netexec
# OR using pipx (recommended)
pipx install netexec

# Optional tools for authenticated enumeration
pip3 install enum4linux-ng
pip3 install impacket
pip3 install bloodhound

# Optional: RustScan for faster port scanning
# Install from: https://github.com/RustScan/RustScan
wget https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb
sudo dpkg -i rustscan_2.1.1_amd64.deb
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

# Pass-the-Hash attack with NTLM hash
python3 main.py -auth 192.168.1.0/24 -user CORP/administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c

# Check local admin access on specific targets
python3 main.py -auth 10.1.1.5,10.1.1.10 -user administrator -p LocalPass123 --local-auth

# Local admin Pass-the-Hash
python3 main.py -auth 10.1.1.5,10.1.1.10 -user administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c --local-auth

# Assess user privileges with verbose output (includes Kerberoasting, AS-REP, BloodHound)
python3 main.py -auth 192.168.1.20 -user DOMAIN/john.doe -p UserPass2024 -v

# Full domain assessment with hash
python3 main.py -auth 192.168.1.0/24 -user CONTOSO/serviceaccount -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c -v
```

### Combined Workflow Examples
```bash
# Complete assessment workflow
python3 main.py -f 192.168.1.0/24 -o complete_assessment --rustscan -v
python3 main.py -vulns 192.168.1.0/24 -o complete_assessment -v  
python3 main.py -auth 192.168.1.0/24 -user CORP/testuser -p TestPass123 -o complete_assessment -v

# Post-exploitation workflow with Pass-the-Hash
python3 main.py -auth 192.168.1.0/24 -user CORP/Administrator -hashes :8846f7eaee8fb117ad06bdd830b7586c -o pth_assessment -v
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

### Installation Issues
1. **netexec/nxc not found**: Install netexec using `pip3 install netexec` or `pipx install netexec`
2. **Permission denied for nmap**: Run nmap scans as root or configure capabilities: `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap`
3. **Wordlists not found**: Install wordlists using `sudo apt install seclists dirb`
4. **enum4linux-ng not found**: Install using `pip3 install enum4linux-ng`
5. **impacket tools not found**: Install using `pip3 install impacket` or `sudo apt install python3-impacket`
6. **bloodhound-python not found**: Install using `pip3 install bloodhound`
7. **rustscan not found**: Download from https://github.com/RustScan/RustScan/releases

### Authentication Issues
1. **Authentication failures**: Verify credentials and ensure target systems allow the authentication method (domain vs local)
2. **Hash format errors**: Use LM:NT format (e.g., `aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`) or NT-only format (e.g., `:8846f7eaee8fb117ad06bdd830b7586c`)
3. **Cannot use both password and hash**: Use either `-p` or `-hashes`, not both
4. **Domain not specified**: Include domain in username (e.g., `DOMAIN/username`) for Kerberos attacks and BloodHound
5. **Kerberos attacks failing**: Ensure domain is specified and target is a domain controller
6. **BloodHound collection failing**: Verify DNS resolution and domain controller accessibility

### Performance Issues
1. **Vulnerability modules not working**: Ensure you have the latest version of netexec/nxc with updated modules
2. **False positives in vulnerability scans**: Review individual module outputs for context
3. **Timeouts on large networks**: Reduce thread count with `-t` parameter or scan smaller subnets
4. **Slow port scanning**: Use `--rustscan` flag for significantly faster scanning
5. **Parallel execution conflicts**: Tool automatically retries with small delays to handle nxc temporary directory conflicts

### Output Issues
1. **Missing results**: Check verbose output (`-v`) for detailed error messages
2. **Network unreachable**: Check network connectivity and firewall rules
3. **Empty BloodHound directory**: Check if bloodhound-python completed successfully in verbose output
4. **No Kerberoastable accounts**: This is normal if no service accounts with SPNs exist
5. **No AS-REP roastable accounts**: This is normal if all accounts require Kerberos pre-authentication
4. **Network unreachable**: Check network connectivity and firewall rules
5. **enum4linux-ng not found**: Install using `pip3 install enum4linux-ng`
6. **Authentication failures**: Verify credentials and ensure target systems allow the authentication method (domain vs local)
7. **Vulnerability modules not working**: Ensure you have the latest version of netexec/nxc with updated modules

### Common Issues
- **False positives in vulnerability scans**: Review individual module outputs for context
- **Timeouts on large networks**: Reduce thread count with `-t` parameter or scan smaller subnets
- **Missing results**: Check verbose output (`-v`) for detailed error messages
