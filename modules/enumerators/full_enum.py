"""
Full enumeration orchestrator
"""

import asyncio
import logging
from typing import List, Dict
from port_scanner import PortScanner
from enumerators.smb_enum import SMBEnumerator
from enumerators.ldap_enum import LDAPEnumerator
from enumerators.web_enum import WebEnumerator


class FullEnumerator:
    """Full enumeration coordinator"""
    
    def __init__(self, output_dir: str, max_concurrent: int = 10):
        self.output_dir = output_dir
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger('adtool')
        
        # Initialize components
        self.port_scanner = PortScanner(output_dir, max_concurrent)
        self.smb_enumerator = SMBEnumerator(output_dir)
        self.ldap_enumerator = LDAPEnumerator(output_dir)
        self.web_enumerator = WebEnumerator(output_dir)
        
        # Service enumerator mapping
        self.enumerators = {
            'smb': self.smb_enumerator,
            'ldap': self.ldap_enumerator,
            'web': self.web_enumerator
        }
    
    async def enumerate_targets(self, ips: List[str]) -> List[Dict]:
        """Perform full enumeration on targets"""
        self.logger.info(f"Starting full enumeration for {len(ips)} targets")
        
        # Step 1: Port scanning
        self.logger.info("Phase 1: Port scanning")
        scan_results = await self.port_scanner.scan_targets(ips)
        
        # Step 2: Service enumeration
        self.logger.info("Phase 2: Service enumeration")
        enum_results = []
        
        for scan_result in scan_results:
            if not scan_result.get('success'):
                continue
            
            ip = scan_result['ip']
            services = self.port_scanner.get_enumerable_services(scan_result)
            
            if not services:
                self.logger.info(f"No enumerable services found for {ip}")
                continue
            
            self.logger.info(f"Found enumerable services for {ip}: {list(services.keys())}")
            
            # Enumerate each service type
            target_results = {
                'ip': ip,
                'scan_result': scan_result,
                'enumeration_results': []
            }
            
            for service_type, ports in services.items():
                if service_type in self.enumerators and service_type != 'unknown':
                    try:
                        enum_result = await self.enumerators[service_type].enumerate(ip, ports)
                        target_results['enumeration_results'].append(enum_result)
                    except Exception as e:
                        self.logger.error(f"Enumeration failed for {service_type} on {ip}: {e}")
            
            enum_results.append(target_results)
        
        # Generate summary
        self._generate_summary(enum_results)
        
        return enum_results
    
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
                    
                    f.write(f"Target: {ip}\n")
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