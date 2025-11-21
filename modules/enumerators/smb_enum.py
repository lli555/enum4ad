"""
SMB enumeration module using netexec
"""

import asyncio
import subprocess
import logging
import os
from typing import Dict, List
from utils import save_enumeration_result, is_command_available


class SMBEnumerator:
    """SMB enumeration using netexec"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.logger = logging.getLogger('adtool')
        
        # Check if netexec is available
        if not is_command_available('netexec'):
            self.logger.warning("netexec not found. SMB enumeration will be limited.")
    
    async def enumerate(self, ip: str, ports: List[Dict]) -> Dict:
        """Enumerate SMB services"""
        self.logger.info(f"Starting SMB enumeration for {ip}")
        
        results = {
            'ip': ip,
            'service': 'smb',
            'enumeration_results': []
        }
        
        # Anonymous share enumeration
        shares_result = await self._enumerate_shares(ip)
        if shares_result:
            results['enumeration_results'].append(shares_result)
        
        # enum4linux-ng enumeration
        enum4linux_result = await self._enum4linux_scan(ip)
        if enum4linux_result:
            results['enumeration_results'].append(enum4linux_result)
        
        # Guest user check
        guest_result = await self._check_guest_user(ip)
        if guest_result:
            results['enumeration_results'].append(guest_result)
        
        return results
    
    async def _enumerate_shares(self, ip: str) -> Dict:
        """Enumerate SMB shares anonymously"""
        cmd = ['netexec', 'smb', ip, '-u', '', '-p', '', '--shares']
        
        try:
            self.logger.info(f"Enumerating SMB shares on {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            file_path = save_enumeration_result(
                self.output_dir, ip, 'smb_shares', output, f"smb_shares_{ip}.txt",
                service_type='smb', authenticated=False
            )
            
            return {
                'type': 'shares',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"SMB shares enumeration failed for {ip}: {e}")
            return None
    
    async def _enum4linux_scan(self, ip: str) -> Dict:
        """Run enum4linux-ng for comprehensive SMB/NetBIOS enumeration"""
        if not is_command_available('enum4linux-ng'):
            self.logger.warning("enum4linux-ng not found. Skipping enum4linux scan.")
            return None
        
        output_file = f"enum4linux_{ip}"
        enum_dir = os.path.join(self.output_dir, "enumeration", "smb", "unauthenticated")
        cmd = ['enum4linux-ng', '-A', ip, '-oJ', os.path.join(enum_dir, output_file)]
        
        try:
            self.logger.info(f"Running enum4linux-ng on {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save the text output as well
            file_path = save_enumeration_result(
                self.output_dir, ip, 'enum4linux', output, f"enum4linux_{ip}.txt",
                service_type='smb', authenticated=False
            )
            
            return {
                'type': 'enum4linux',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'json_file': f"{enum_dir}/{output_file}.json",
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"enum4linux-ng scan failed for {ip}: {e}")
            return None
    
    async def _check_guest_user(self, ip: str) -> Dict:
        """Check if Guest user is enabled"""
        cmd = ['netexec', 'smb', ip, '-u', 'Guest', '-p', '']
        
        try:
            self.logger.info(f"Checking Guest user access on {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            file_path = save_enumeration_result(
                self.output_dir, ip, 'smb_guest_check', output, f"smb_guest_{ip}.txt",
                service_type='smb', authenticated=False
            )
            
            # Determine if guest access is enabled based on output
            guest_enabled = "STATUS_SUCCESS" in output or "LOGIN_SUCCESS" in output or "[+]" in output
            
            return {
                'type': 'guest_check',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'guest_enabled': guest_enabled,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Guest user check failed for {ip}: {e}")
            return None