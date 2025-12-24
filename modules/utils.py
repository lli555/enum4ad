"""
Utility functions for AD enumeration tool
"""

import os
import re
import sys
import logging
import ipaddress
from typing import List, Union
from datetime import datetime


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Setup logging configuration"""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Configure logging format
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # Get logger
    logger = logging.getLogger('adtool')
    logger.setLevel(log_level)
    logger.addHandler(console_handler)
    
    return logger


def create_output_directory(base_dir: str, path_prefix: str = 'ad_enum_results', scan_mode: str = "full", port_scan_only: bool = False, username: str = None) -> str:  
    """Create output directory with timestamp"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Use different directory naming based on scan mode
    if scan_mode == "authenticated":
        # Include username in directory name for authenticated scans
        if username:
            # Sanitize username for directory name (replace / and \ with _)
            safe_username = username.replace('/', '_').replace('\\', '_')
            output_dir_name = f"auth_{safe_username}_{timestamp}"
        else:
            output_dir_name = f"auth_{timestamp}"
    else:
        output_dir_name = f"{path_prefix}_{timestamp}"
    
    if base_dir:
        # Use the provided base path
        output_dir = os.path.join(base_dir, output_dir_name)
    else:
        # Use current directory
        output_dir = output_dir_name
    
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        if scan_mode == "authenticated":
            # For authenticated scans, create minimal structure
            # Only create directories that will actually be used
            services = ["ldap", "smb", "misc", "bloodhound"]  # Added bloodhound directory
            
            for service in services:
                service_dir = os.path.join(output_dir, service)
                os.makedirs(service_dir, exist_ok=True)
        else:
            # For other scan modes, create full structure
            os.makedirs(os.path.join(output_dir, "nmap"), exist_ok=True)
            
            # Create main enumeration directory, only if not port_scan_only
            
            if not port_scan_only:
                enumeration_dir = os.path.join(output_dir, "enumeration")
                os.makedirs(enumeration_dir, exist_ok=True)
                
            # Create service-specific directories
            services = ["ldap", "smb", "web", "vuln", "misc", "bloodhound"]
            auth_types = ["unauthenticated", "authenticated"]
            
            for service in services:
                    service_dir = os.path.join(enumeration_dir, service)
                    os.makedirs(service_dir, exist_ok=True)
                    
                    # Create auth subdirectories for each service
                    for auth_type in auth_types:
                        auth_dir = os.path.join(service_dir, auth_type)
                        os.makedirs(auth_dir, exist_ok=True)
        
        return output_dir
    except Exception as e:
        raise Exception(f"Failed to create output directory: {e}")


def validate_ips(ip_input: str) -> List[str]:
    """
    Validate and expand IP addresses from input string
    Supports individual IPs, comma-separated IPs, and CIDR notation
    """
    ips = []
    
    # Split by comma and clean up
    ip_parts = [ip.strip() for ip in ip_input.split(',')]
    
    for ip_part in ip_parts:
        if not ip_part:
            continue
            
        try:
            # Check if it's CIDR notation
            if '/' in ip_part:
                network = ipaddress.ip_network(ip_part, strict=False)
                # Convert network to list of IPs (skip network and broadcast for /24 and smaller)
                if network.prefixlen >= 24:
                    ips.extend([str(ip) for ip in network.hosts()])
                else:
                    # For larger networks, include all IPs
                    ips.extend([str(ip) for ip in network])
            else:
                # Single IP address
                ip = ipaddress.ip_address(ip_part)
                ips.append(str(ip))
                
        except ValueError:
            logger = logging.getLogger('adtool')
            logger.warning(f"Invalid IP address or network: {ip_part}")
            continue
    
    # Remove duplicates while preserving order
    unique_ips = list(dict.fromkeys(ips))
    return unique_ips


def parse_nmap_output(file_path: str) -> dict:
    """Parse nmap output file and extract open ports and services"""
    result = {
        'ip': '',
        'ports': [],
        'services': {}
    }
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Extract IP address
        ip_match = re.search(r'Nmap scan report for ([0-9.]+)', content)
        if ip_match:
            result['ip'] = ip_match.group(1)
        
        # Extract open ports
        port_pattern = r'(\d+)/(tcp|udp)\s+open\s+([^\s]+)(?:\s+(.+))?'
        for match in re.finditer(port_pattern, content):
            port = int(match.group(1))
            protocol = match.group(2)
            service = match.group(3)
            version = match.group(4) if match.group(4) else ''
            
            port_info = {
                'port': port,
                'protocol': protocol,
                'service': service,
                'version': version.strip() if version else ''
            }
            
            result['ports'].append(port_info)
            result['services'][port] = {
                'service': service,
                'version': version.strip() if version else ''
            }
    
    except Exception as e:
        logger = logging.getLogger('adtool')
        logger.error(f"Failed to parse nmap output {file_path}: {e}")
    
    return result


def get_service_type(port: int, service_name: str) -> str:
    """Determine service type for enumeration"""
    service_name = service_name.lower()
    
    # SMB/NetBIOS
    if port in [139, 445] or 'smb' in service_name or 'netbios' in service_name:
        return 'smb'
    
    # LDAP
    elif port in [389, 636, 3268, 3269] or 'ldap' in service_name:
        return 'ldap'
    
    # HTTP/HTTPS
    elif port in [80, 443, 8080, 8443] or 'http' in service_name:
        return 'web'
    
    # RDP
    elif port in [3389] or 'rdp' in service_name or 'ms-wbt-server' in service_name:
        return 'rdp'
    
    # SSH
    elif port in [22] or 'ssh' in service_name:
        return 'ssh'
    
    # DNS
    elif port in [53] or 'domain' in service_name:
        return 'dns'
    
    # Kerberos
    elif port in [88] or 'kerberos' in service_name:
        return 'kerberos'
    
    # WinRM
    elif port in [5985, 5986] or 'winrm' in service_name:
        return 'winrm'
    
    # MSSQL
    elif port in [1433] or 'mssql' in service_name or 'ms-sql' in service_name:
        return 'mssql'
    
    # Unknown service
    else:
        return 'unknown'


def save_enumeration_result(output_dir: str, ip: str, service: str, data: str, filename: str = None, service_type: str = None, authenticated: bool = False) -> str:
    """Save enumeration results to file in appropriate subdirectory"""
    if not filename:
        timestamp = datetime.now().strftime("%H%M%S")
        filename = f"{service}_{ip}_{timestamp}.txt"
    
    # Determine service type for directory structure
    if service_type is None:
        # Try to infer service type from service name
        service_lower = service.lower()
        if 'ldap' in service_lower:
            service_type = 'ldap'
        elif 'smb' in service_lower:
            service_type = 'smb'
        elif 'web' in service_lower or 'http' in service_lower:
            service_type = 'web'
        elif 'vuln' in service_lower or 'vulnerability' in service_lower:
            service_type = 'vuln'
        elif 'bloodhound' in service_lower:
            service_type = 'bloodhound'
        else:
            service_type = 'misc'
    
    # Check if this is a simplified authenticated directory structure
    enumeration_path = os.path.join(output_dir, "enumeration")
    if os.path.exists(enumeration_path):
        # Full directory structure (non-authenticated scans)
        auth_subdir = 'authenticated' if authenticated else 'unauthenticated'
        file_path = os.path.join(output_dir, "enumeration", service_type, auth_subdir, filename)
    else:
        # Simplified directory structure (authenticated scans)
        file_path = os.path.join(output_dir, service_type, filename)
    
    try:
        with open(file_path, 'w') as f:
            f.write(f"Service: {service}\n")
            f.write(f"Target: {ip}\n")
            f.write(f"Service Type: {service_type}\n")
            f.write(f"Authentication: {'authenticated' if authenticated else 'unauthenticated'}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write("=" * 50 + "\n\n")
            f.write(data)
        
        return file_path
    except Exception as e:
        logger = logging.getLogger('adtool')
        logger.error(f"Failed to save enumeration result: {e}")
        return ""


def is_command_available(command: str) -> bool:
    """Check if a command is available in the system"""
    import shutil
    return shutil.which(command) is not None