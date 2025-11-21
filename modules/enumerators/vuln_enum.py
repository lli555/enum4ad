"""
SMB vulnerability enumeration module using netexec
"""

import asyncio
import subprocess
import logging
from typing import Dict, List
from utils import save_enumeration_result, is_command_available


class VulnEnumerator:
    """SMB vulnerability enumeration using netexec (nxc)"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.logger = logging.getLogger('adtool')
        
        # Check if netexec/nxc is available
        self.nxc_cmd = None
        if is_command_available('nxc'):
            self.nxc_cmd = 'nxc'
        elif is_command_available('netexec'):
            self.nxc_cmd = 'netexec'
        else:
            self.logger.warning("Neither 'nxc' nor 'netexec' found. Vulnerability scanning will be unavailable.")
        
        # Define vulnerability modules to test
        self.vuln_modules = [
            'zerologon',
            'printnightmare', 
            'smbghost',
            'ms17-010',
            'coerce_plus'
        ]
    
    async def scan_vulnerabilities(self, ips: List[str]) -> Dict:
        """Scan for SMB vulnerabilities on provided IPs"""
        self.logger.info(f"Starting vulnerability scan for {len(ips)} targets")
        
        if not self.nxc_cmd:
            self.logger.error("NetExec/NXC not found. Cannot perform vulnerability scanning.")
            return {'error': 'NetExec/NXC not available'}
        
        results = {
            'scan_type': 'vulnerabilities',
            'targets': ips,
            'results': []
        }
        
        # Run vulnerability scans for each IP
        for ip in ips:
            self.logger.info(f"Scanning vulnerabilities for {ip}")
            ip_results = await self._scan_ip_vulnerabilities(ip)
            results['results'].append(ip_results)
        
        return results
    
    async def _scan_ip_vulnerabilities(self, ip: str) -> Dict:
        """Scan all vulnerability modules for a single IP"""
        ip_result = {
            'ip': ip,
            'vulnerabilities': []
        }
        
        # Test each vulnerability module
        for module in self.vuln_modules:
            self.logger.info(f"Testing {module} on {ip}")
            vuln_result = await self._test_vulnerability(ip, module)
            if vuln_result:
                ip_result['vulnerabilities'].append(vuln_result)
        
        return ip_result
    
    async def _test_vulnerability(self, ip: str, module: str) -> Dict:
        """Test a specific vulnerability module against an IP"""
        cmd = [self.nxc_cmd, 'smb', ip, '-u', '', '-p', '', '-M', module]
        
        try:
            self.logger.info(f"Running {module} test on {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            file_path = save_enumeration_result(
                self.output_dir, ip, f'vuln_{module}', output, f"vuln_{module}_{ip}.txt",
                service_type='vuln', authenticated=False
            )
            
            # Analyze output for vulnerability indicators
            is_vulnerable = self._analyze_vuln_output(module, output)
            
            return {
                'module': module,
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'vulnerable': is_vulnerable,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Vulnerability test {module} failed for {ip}: {e}")
            return {
                'module': module,
                'command': ' '.join(cmd),
                'error': str(e),
                'vulnerable': False,
                'success': False
            }
    
    def _analyze_vuln_output(self, module: str, output: str) -> bool:
        """Analyze command output to determine if target is vulnerable"""
        output_lower = output.lower()
        
        # Common vulnerability indicators
        vuln_indicators = [
            'vulnerable',
            'exploit',
            'pwned',
            '[+]',
            'target appears vulnerable',
            'exploitation successful'
        ]
        
        # Module-specific indicators
        if module == 'zerologon':
            module_indicators = [
                'target is vulnerable to zerologon',
                'zerologon exploit',
                'dc vulnerable'
            ]
        elif module == 'printnightmare':
            module_indicators = [
                'printnightmare vulnerable',
                'spooler service vulnerable',
                'cve-2021-1675'
            ]
        elif module == 'smbghost':
            module_indicators = [
                'smbghost vulnerable',
                'compression vulnerable',
                'cve-2020-0796'
            ]
        elif module == 'ms17-010':
            module_indicators = [
                'ms17-010 vulnerable',
                'eternalblue',
                'doublepulsar'
            ]
        elif module == 'coerce_plus':
            module_indicators = [
                'coercion successful',
                'authentication coerced',
                'rpc coercion'
            ]
        else:
            module_indicators = []
        
        # Check for general vulnerability indicators
        for indicator in vuln_indicators:
            if indicator in output_lower:
                return True
        
        # Check for module-specific indicators
        for indicator in module_indicators:
            if indicator in output_lower:
                return True
        
        return False
    
    async def generate_summary(self, results: Dict) -> str:
        """Generate a summary of vulnerability scan results"""
        if 'error' in results:
            return f"Vulnerability scan failed: {results['error']}"
        
        summary_lines = []
        summary_lines.append("=== VULNERABILITY SCAN SUMMARY ===")
        summary_lines.append(f"Targets scanned: {len(results['targets'])}")
        summary_lines.append("")
        
        total_vulns = 0
        for target_result in results['results']:
            ip = target_result['ip']
            vulns = target_result['vulnerabilities']
            
            vulnerable_modules = [v['module'] for v in vulns if v.get('vulnerable', False)]
            
            if vulnerable_modules:
                total_vulns += len(vulnerable_modules)
                summary_lines.append(f"[!] {ip} - VULNERABLE to: {', '.join(vulnerable_modules)}")
            else:
                summary_lines.append(f"[+] {ip} - No vulnerabilities detected")
        
        summary_lines.append("")
        summary_lines.append(f"Total vulnerabilities found: {total_vulns}")
        
        # Save summary to file
        summary_text = "\n".join(summary_lines)
        summary_file = save_enumeration_result(
            self.output_dir, "summary", "vulnerability_scan", summary_text, "vulnerability_summary.txt",
            service_type='vuln', authenticated=False
        )
        
        return summary_text