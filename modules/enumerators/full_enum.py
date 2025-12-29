"""
Full enumeration orchestrator
"""

import asyncio
import logging
import os
from typing import List, Dict
from port_scanner import PortScanner
from enumerators.smb_enum import SMBEnumerator
from enumerators.ldap_enum import LDAPEnumerator
from enumerators.web_enum import WebEnumerator


class FullEnumerator:
    """Full enumeration coordinator"""
    
    def __init__(self, output_dir: str, max_concurrent: int = 10, use_rustscan: bool = False, ad_only: bool = False):
        self.output_dir = output_dir
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger('adtool')
        
        # Initialize port scanner
        self.port_scanner = PortScanner(output_dir, max_concurrent, use_rustscan=use_rustscan, ad_only=ad_only)
        
        # Semaphore to limit concurrent IP-level enumerations
        # This prevents resource exhaustion when scanning many targets (e.g., 100+ IPs)
        # Each IP can spawn multiple service enumeration tasks, so we limit IP-level concurrency
        self.enumeration_semaphore = asyncio.Semaphore(max_concurrent)
    
    async def enumerate_targets(self, ips: List[str], ip_input: str = None) -> List[Dict]:
        """Perform full enumeration on targets"""
        self.logger.info(f"Starting full enumeration for {len(ips)} targets")
        
        # Step 1: Port scanning
        self.logger.info("Phase 1: Port scanning")
        scan_results = await self.port_scanner.scan_targets(ips, ip_input=ip_input)
        
        # Step 2: Pre-create all IP directories sequentially to avoid race conditions
        # This prevents concurrent os.makedirs() calls that could cause issues on some filesystems
        # even with exist_ok=True, especially with permission modifications or edge cases
        self.logger.info("Phase 2: Creating directory structures for all targets")
        ip_directories = {}
        failed_ips = []
        for scan_result in scan_results:
            if scan_result.get('success'):
                ip = scan_result['ip']
                try:
                    ip_dir = self._create_ip_directory(ip)
                    ip_directories[ip] = ip_dir
                except Exception as e:
                    # Log the error and skip this IP
                    self.logger.error(f"Skipping enumeration for {ip} due to directory creation failure: {e}")
                    failed_ips.append(ip)
        
        if failed_ips:
            self.logger.warning(f"Failed to create directories for {len(failed_ips)} target(s): {', '.join(failed_ips)}")
        
        # Step 3: Service enumeration (parallel for all IPs)
        successful_count = len(ip_directories)
        self.logger.info(f"Phase 3: Service enumeration (running in parallel for {successful_count} IPs, max {self.max_concurrent} concurrent)")
        
        # Create enumeration tasks only for IPs with successfully created directories
        enumeration_tasks = []
        for scan_result in scan_results:
            if scan_result.get('success'):
                ip = scan_result['ip']
                # Only enumerate IPs that have a valid directory structure
                if ip in ip_directories:
                    ip_dir = ip_directories[ip]
                    task = self._enumerate_single_target(scan_result, ip_dir)
                    enumeration_tasks.append(task)
        
        # Run all enumerations in parallel
        enum_results = await asyncio.gather(*enumeration_tasks, return_exceptions=True)
        
        # Filter out any exceptions and log them
        valid_results = []
        for result in enum_results:
            if isinstance(result, Exception):
                self.logger.error(f"Enumeration task failed: {result}")
            elif result is not None:
                valid_results.append(result)
        
        # Generate summary
        self._generate_summary(valid_results)
        
        return valid_results
    
    async def _enumerate_single_target(self, scan_result: Dict, ip_dir: str) -> Dict:
        """Enumerate a single target (to be run in parallel with concurrency limit)
        
        Args:
            scan_result: Scan result dictionary containing IP and port information
            ip_dir: Pre-created directory path for this IP (avoids concurrent directory creation)
        
        Note:
            Uses semaphore to limit concurrent IP-level enumerations, preventing resource
            exhaustion when scanning many targets. Service-level parallelism within each
            IP is still maintained for optimal performance.
        """
        # Acquire semaphore to limit concurrent IP-level enumerations
        async with self.enumeration_semaphore:
            ip = scan_result['ip']
            
            # Use the pre-created IP-specific subdirectory (no directory creation here)
            # Initialize enumerators with IP-specific directory
            smb_enumerator = SMBEnumerator(ip_dir)
            ldap_enumerator = LDAPEnumerator(ip_dir)
            web_enumerator = WebEnumerator(ip_dir)
            
            enumerators = {
                'smb': smb_enumerator,
                'ldap': ldap_enumerator,
                'web': web_enumerator
            }
            
            services = self.port_scanner.get_enumerable_services(scan_result)
            
            if not services:
                self.logger.info(f"No enumerable services found for {ip}")
                return None
            
            self.logger.info(f"Found enumerable services for {ip}: {list(services.keys())}")
            
            target_results = {
                'ip': ip,
                'scan_result': scan_result,
                'enumeration_results': [],
                'output_dir': ip_dir
            }
            
            # Run all service enumerations for this IP in parallel
            service_tasks = []
            service_info = []
            
            for service_type, ports in services.items():
                if service_type in enumerators and service_type != 'unknown':
                    service_tasks.append(enumerators[service_type].enumerate(ip, ports))
                    service_info.append(service_type)
            
            # Wait for all service enumerations to complete
            if service_tasks:
                try:
                    service_results = await asyncio.gather(*service_tasks, return_exceptions=True)
                    
                    for idx, result in enumerate(service_results):
                        if isinstance(result, Exception):
                            self.logger.error(f"Enumeration failed for {service_info[idx]} on {ip}: {result}")
                        else:
                            target_results['enumeration_results'].append(result)
                except Exception as e:
                    self.logger.error(f"Error during service enumeration for {ip}: {e}")
            
            return target_results
    
    def _create_ip_directory(self, ip: str) -> str:
        """Create a subdirectory for a specific IP
        
        Args:
            ip: The IP address to create a directory for
            
        Returns:
            Path to the created IP-specific directory
            
        Raises:
            Exception: If directory creation fails. This is intentional - we want to fail
                      early rather than fallback to a broken directory structure that will
                      cause enumeration commands to fail.
        """
        # Sanitize IP for directory name (replace dots with underscores)
        safe_ip = ip.replace('.', '_').replace(':', '_')
        ip_dir = os.path.join(self.output_dir, f"target_{safe_ip}")
        
        try:
            os.makedirs(ip_dir, exist_ok=True)
            
            # Create enumeration subdirectory structure for this IP
            enumeration_dir = os.path.join(ip_dir, "enumeration")
            os.makedirs(enumeration_dir, exist_ok=True)
            
            # Create service-specific directories
            services = ["ldap", "smb", "web", "vuln", "misc"]
            auth_types = ["unauthenticated", "authenticated"]
            
            for service in services:
                service_dir = os.path.join(enumeration_dir, service)
                os.makedirs(service_dir, exist_ok=True)
                
                # Create auth subdirectories for each service
                for auth_type in auth_types:
                    auth_dir = os.path.join(service_dir, auth_type)
                    os.makedirs(auth_dir, exist_ok=True)
            
            self.logger.debug(f"Created directory structure for {ip} at {ip_dir}")
            return ip_dir
            
        except Exception as e:
            error_msg = f"Failed to create directory structure for {ip}: {e}"
            self.logger.error(error_msg)
            # Re-raise the exception instead of falling back to a broken directory structure
            # This ensures that enumeration commands won't fail later due to missing directories
            raise Exception(error_msg)
    
    def _generate_summary(self, results: List[Dict]):
        """Generate enumeration summary"""
        summary_file = f"{self.output_dir}/enumeration_summary.txt"
        
        try:
            with open(summary_file, 'w') as f:
                f.write("AD Enumeration Tool - Summary Report\n")
                f.write("=" * 50 + "\n\n")
                
                total_targets = len(results)
                f.write(f"Total targets enumerated: {total_targets}\n\n")
                
                for result in results:
                    ip = result['ip']
                    scan_result = result['scan_result']
                    enum_results = result['enumeration_results']
                    ip_dir = result.get('output_dir', 'N/A')
                    
                    f.write(f"Target: {ip}\n")
                    f.write(f"Output Directory: {ip_dir}\n")
                    f.write("-" * 20 + "\n")
                    
                    # Port summary
                    if scan_result.get('ports'):
                        f.write(f"Open ports: {len(scan_result['ports'])}\n")
                        for port_info in scan_result['ports']:
                            f.write(f"  {port_info['port']}/{port_info['protocol']} - {port_info['service']}\n")
                    
                    # Enumeration summary
                    f.write(f"Services enumerated: {len(enum_results)}\n")
                    for enum_result in enum_results:
                        service = enum_result.get('service', 'unknown')
                        enum_count = len(enum_result.get('enumeration_results', []))
                        f.write(f"  {service}: {enum_count} checks performed\n")
                    
                    f.write("\n")
                
                self.logger.info(f"Summary report saved to {summary_file}")
                
        except Exception as e:
            self.logger.error(f"Failed to generate summary: {e}")