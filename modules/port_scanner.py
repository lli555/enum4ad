"""
Port scanning module using nmap
"""

import asyncio
import subprocess
import os
import logging
import shutil
from typing import List, Dict
from utils import parse_nmap_output, get_service_type


class PortScanner:
    """Port scanner using nmap"""
    
    def __init__(self, output_dir: str, max_concurrent: int = 10, use_rustscan: bool = False):
        self.output_dir = output_dir
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger('adtool')
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.use_rustscan = use_rustscan
    
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
    
    async def scan_targets(self, ips: List[str]) -> List[Dict]:
        """Scan multiple targets concurrently"""
        self.logger.info(f"Starting nmap scans for {len(ips)} targets")
        
        # Create scan tasks
        tasks = [self.scan_target(ip) for ip in ips]
        
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