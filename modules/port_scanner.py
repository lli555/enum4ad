"""
Port scanning module using nmap
"""

import asyncio
import subprocess
import os
import logging
import shutil
import re
import ipaddress
from typing import List, Dict
from utils import parse_nmap_output, get_service_type


class PortScanner:
    """Port scanner using nmap"""
    
    def __init__(self, output_dir: str, max_concurrent: int = 10, use_rustscan: bool = False, ad_only: bool = False):
        self.output_dir = output_dir
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger('adtool')
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.use_rustscan = use_rustscan
        self.ad_only = ad_only
    
    async def scan_target(self, ip: str) -> Dict:
        """Scan a single target with nmap"""
        async with self.semaphore:
            # sanitize ip for filenames (handles IPv6 and CIDR)
            safe_ip = ip.replace(':', '_').replace('/', '_') # Probably not needed here but just in case
            output_dir_nmap = os.path.join(self.output_dir, "nmap")
            os.makedirs(output_dir_nmap, exist_ok=True)
            output_file = os.path.join(output_dir_nmap, f"nmap_{safe_ip}.txt")

            # Build command. Put IP last for nmap so options are interpreted correctly.
            if self.use_rustscan:
                # rustscan will call nmap with the provided args after --
                rustscan_bin = shutil.which('rustscan') or 'rustscan'
                nmap_args = ['-Pn', '-n', '-sC', '-sV', '-oN', output_file]
                cmd = [rustscan_bin, '-a', ip, '-r', '1-65535', '-u', '5000', '--'] + nmap_args
            else:
                cmd = [
                    'nmap',
                    '-Pn',      # Skip host discovery
                    '-n',       # No DNS resolution
                    '-sC',      # Default scripts
                    '-sV',      # Version detection
                    '-oN',      # Normal output
                    output_file,
                    ip
                ]
            
            self.logger.info(f"Scanning {ip}...")
            
            try:
                # Run nmap
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    self.logger.info(f"Scan completed for {ip}")
                else:
                    self.logger.error(f"Scan process returned code {process.returncode} for {ip}: {stderr.decode()}")

                # Parse the results if the output file exists
                try:
                    if os.path.exists(output_file):
                        result = parse_nmap_output(output_file) or {}
                        result.setdefault('ip', ip)
                        result['success'] = True if process.returncode == 0 else result.get('success', False)
                        return result
                    else:
                        err_msg = stderr.decode() if stderr else 'nmap did not produce output file'
                        return {'ip': ip, 'success': False, 'error': err_msg}
                except Exception as e:
                    self.logger.exception(f"Error parsing nmap output for {ip}: {e}")
                    return {'ip': ip, 'success': False, 'error': str(e)}
                    
            except Exception as e:
                self.logger.error(f"Error scanning {ip}: {e}")
                return {'ip': ip, 'success': False, 'error': str(e)}
    
    async def perform_host_discovery(self, ip_range: str) -> List[str]:
        """
        Perform host discovery using nmap -sn to identify live hosts
        Returns list of IPs that are up
        """
        self.logger.info(f"Performing host discovery on {ip_range}...")
        
        output_file = os.path.join(self.output_dir, "live_hosts.txt")
        
        cmd = [
            'nmap',
            '-v',
            '-sn',      # Ping scan - disable port scan
            ip_range,
            '-oG',      # Grepable output
            output_file
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                self.logger.error(f"Host discovery failed: {stderr.decode()}")
                return []
            
            # Parse the grepable output to extract live hosts
            live_hosts = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        # Look for lines with "Status: Up"
                        if 'Status: Up' in line:
                            # Extract IP address - format: Host: IP (hostname) Status: Up
                            match = re.search(r'Host:\s+(\S+)', line)
                            if match:
                                ip = match.group(1)
                                # Filter out non-IP entries (like hostnames without IPs)
                                try:
                                    ipaddress.ip_address(ip)
                                    live_hosts.append(ip)
                                except ValueError:
                                    continue
            
            self.logger.info(f"Host discovery complete: {len(live_hosts)} live hosts found")
            return live_hosts
            
        except Exception as e:
            self.logger.error(f"Error during host discovery: {e}")
            return []
    
    async def filter_windows_hosts(self, ips: List[str]) -> List[str]:
        """
        Discover Windows hosts using NetExec
        ips can be individual IPs, comma-separated IPs, or CIDR ranges
        Returns list of IPs that responded to SMB probes
        """
        if not ips:
            return []
        
        self.logger.info(f"Discovering Windows/AD hosts using NetExec...")
        
        output_file = os.path.join(self.output_dir, "netexec_smb.txt")
        
        cmd = [
            'netexec',
            'smb',
            *ips,  # Pass each IP/CIDR as separate argument
        ]
        
        try:
            # Run netexec and capture output
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode()
            
            # Save the full output
            try:
                with open(output_file, 'w') as f:
                    f.write(output)
                self.logger.info(f"NetExec output saved to {output_file}")
            except Exception as e:
                self.logger.warning(f"Could not save NetExec output: {e}")
            
            # Extract all IPs from output (any line with an IP is a responding host)
            windows_hosts = []
            for line in output.split('\n'):
                # Look for IP addresses in the output
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    if ip not in windows_hosts:
                        windows_hosts.append(ip)
            
            self.logger.info(f"NetExec scan complete: {len(windows_hosts)} hosts found")
            self.logger.info(f"Results: {output}")
            return windows_hosts
            
        except FileNotFoundError:
            self.logger.error("NetExec not found. Please install NetExec to use -AD flag.")
            self.logger.info("Install with: pipx install git+https://github.com/Pennyw0rth/NetExec")
            return []
        except Exception as e:
            self.logger.error(f"Error during NetExec scan: {e}")
            return []
    
    async def scan_targets(self, ips: List[str], ip_input: str = None) -> List[Dict]:
        """
        Scan multiple targets concurrently
        If ip_input contains CIDR notation, perform host discovery first
        ips can be a mix of individual IPs and CIDR ranges
        """
        # Import here to avoid circular import
        from utils import has_cidr_notation
        
        targets_to_scan = ips
        
        # Check if we should perform host discovery (only for CIDR ranges)
        if ip_input and has_cidr_notation(ip_input):
            # If -AD flag is set, use netexec directly for Windows host discovery
            if self.ad_only:
                self.logger.info(f"CIDR notation detected with -AD flag, using NetExec to find Windows hosts...")
                
                # NetExec can handle CIDR ranges directly, so pass them as-is
                windows_hosts = await self.filter_windows_hosts(ips)
                
                if not windows_hosts:
                    self.logger.warning("No Windows hosts found")
                    return []
                
                # self.logger.info(f"Windows/AD hosts ({len(windows_hosts)}):")
                # for host in windows_hosts:
                #     self.logger.info(f"  - {host}")
                
                targets_to_scan = windows_hosts
            else:
                # Use nmap for general host discovery
                self.logger.info(f"CIDR notation detected, performing host discovery first...")
                
                # Extract CIDR ranges from input
                cidr_ranges = [ip.strip() for ip in ips if '/' in ip]
                individual_ips = [ip.strip() for ip in ips if '/' not in ip]
                
                # Perform host discovery on CIDR ranges
                all_live_hosts = list(individual_ips)  # Start with individual IPs
                for cidr_range in cidr_ranges:
                    live_hosts = await self.perform_host_discovery(cidr_range)
                    all_live_hosts.extend(live_hosts)
                
                if not all_live_hosts:
                    self.logger.warning("No live hosts found during discovery")
                    return []
                
                # Remove duplicates
                all_live_hosts = list(dict.fromkeys(all_live_hosts))
                
                self.logger.info(f"Live hosts ({len(all_live_hosts)}):")
                for host in all_live_hosts:
                    self.logger.info(f"  - {host}")
                
                targets_to_scan = all_live_hosts
        
        self.logger.info(f"Starting nmap scans for {len(targets_to_scan)} targets")
        
        # Create scan tasks
        tasks = [self.scan_target(ip) for ip in targets_to_scan]
        
        # Run scans concurrently
        results = await asyncio.gather(*tasks)
        
        # Log summary
        successful_scans = [r for r in results if r.get('success', False)]
        failed_scans = [r for r in results if not r.get('success', False)]
        
        self.logger.info(f"Scan summary: {len(successful_scans)} successful, {len(failed_scans)} failed")
        
        for result in successful_scans:
            if result.get('ports'):
                self.logger.info(f"{result['ip']}: {len(result['ports'])} open ports")
            else:
                self.logger.info(f"{result['ip']}: No open ports found")
        
        for result in failed_scans:
            self.logger.warning(f"{result['ip']}: Scan failed - {result.get('error', 'Unknown error')}")
        
        return results
    
    def get_enumerable_services(self, scan_result: Dict) -> Dict[str, List[Dict]]:
        """Group services by type for enumeration"""
        services = {}
        
        if not scan_result.get('success') or not scan_result.get('ports'):
            return services
        
        for port_info in scan_result['ports']:
            service_type = get_service_type(port_info['port'], port_info['service'])
            
            if service_type not in services:
                services[service_type] = []
            
            services[service_type].append(port_info)
        
        return services