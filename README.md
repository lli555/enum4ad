# AD Enumeration Tool

A comprehensive tool for automated Active Directory environment enumeration. This tool provides both targeted port scanning and full enumeration capabilities with service-specific reconnaissance.

## Features

- **Port Scanning**: Targeted nmap scans with service detection
- **Full Enumeration**: Complete automated enumeration based on discovered services
- **Service-Specific Enumeration**:
  - SMB/NetBIOS (port 139, 445)
  - LDAP (port 389, 636, 3268, 3269)
  - HTTP/HTTPS (port 80, 443, 8080, 8443)
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
python3 main.py -pc 10.1.1.1,10.1.1.2
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

## Command Line Options

- `-pc, --portscan`: Port scan mode - comma-separated IPs
- `-f, --full`: Full enumeration mode - comma-separated IPs or CIDR
- `-o, --output`: Output directory (default: ad_enum_results)
- `-t, --threads`: Number of concurrent threads (default: 10)
- `-v, --verbose`: Enable verbose logging

## Output Structure

```
ad_enum_results_YYYYMMDD_HHMMSS/
├── nmap/
│   ├── nmap_10.1.1.1.txt
│   └── nmap_10.1.1.2.txt
├── enumeration/
│   ├── smb_shares_10.1.1.1.txt
│   ├── ldap_basic_10.1.1.1.txt
│   └── web_dirs_10.1.1.2_80.txt
└── enumeration_summary.txt
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

## Dependencies

### Required Tools
- **nmap**: Port scanning and service detection
- **netexec**: SMB and LDAP enumeration (successor to CrackMapExec)
- **gobuster**: Directory and file brute forcing
- **nikto**: Web vulnerability scanner
- **curl**: HTTP client for header analysis

### Python Packages
- **asyncio**: Asynchronous processing (built-in)
- **ipaddress**: IP address validation (built-in)

## Examples

### Basic Port Scan
```bash
python3 main.py -pc 192.168.1.10,192.168.1.20
```

### Full Network Enumeration
```bash
python3 main.py -f 192.168.1.0/24 -o domain_scan -v
```

### Targeted Full Enumeration
```bash
python3 main.py -f 10.10.10.10,10.10.10.11 -t 5
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

1. **netexec not found**: Install netexec using `pip3 install netexec`
2. **Permission denied**: Run nmap scans as root or configure capabilities
3. **Wordlists not found**: Install wordlists using `sudo apt install seclists dirb`
4. **Network unreachable**: Check network connectivity and firewall rules