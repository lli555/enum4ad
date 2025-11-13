"""
LDAP enumeration module using netexec
"""

import asyncio
import subprocess
import logging
from typing import Dict, List
from utils import save_enumeration_result, is_command_available


class LDAPEnumerator:
    """LDAP enumeration using netexec"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.logger = logging.getLogger('adtool')
        
        if not is_command_available('netexec'):
            self.logger.warning("netexec not found. LDAP enumeration will be limited.")
    
    async def enumerate(self, ip: str, ports: List[Dict]) -> Dict:
        """Enumerate LDAP services"""
        self.logger.info(f"Starting LDAP enumeration for {ip}")
        
        results = {
            'ip': ip,
            'service': 'ldap',
            'enumeration_results': []
        }
        
        # Basic LDAP enumeration
        basic_result = await self._basic_ldap_enum(ip)
        if basic_result:
            results['enumeration_results'].append(basic_result)
        
        # Anonymous bind enumeration
        anon_result = await self._anonymous_bind_enum(ip)
        if anon_result:
            results['enumeration_results'].append(anon_result)
        
        # Domain enumeration
        domain_result = await self._domain_enum(ip)
        if domain_result:
            results['enumeration_results'].append(domain_result)
        
        # User enumeration
        users_result = await self._enumerate_users(ip)
        if users_result:
            results['enumeration_results'].append(users_result)
        
        return results
    
    async def _basic_ldap_enum(self, ip: str) -> Dict:
        """Basic LDAP enumeration"""
        cmd = ['netexec', 'ldap', ip]
        
        try:
            self.logger.info(f"Basic LDAP enumeration for {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            file_path = save_enumeration_result(
                self.output_dir, ip, 'ldap_basic', output, f"ldap_basic_{ip}.txt"
            )
            
            return {
                'type': 'basic',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Basic LDAP enumeration failed for {ip}: {e}")
            return None
    
    async def _anonymous_bind_enum(self, ip: str) -> Dict:
        """Anonymous LDAP bind enumeration"""
        cmd = ['netexec', 'ldap', ip, '-u', '', '-p', '']
        
        try:
            self.logger.info(f"Anonymous LDAP bind for {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            file_path = save_enumeration_result(
                self.output_dir, ip, 'ldap_anonymous', output, f"ldap_anonymous_{ip}.txt"
            )
            
            return {
                'type': 'anonymous_bind',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Anonymous LDAP bind failed for {ip}: {e}")
            return None
    
    async def _domain_enum(self, ip: str) -> Dict:
        """Domain enumeration via LDAP"""
        cmd = ['netexec', 'ldap', ip, '-u', '', '-p', '', '--trusted-for-delegation']
        
        try:
            self.logger.info(f"Domain enumeration for {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            file_path = save_enumeration_result(
                self.output_dir, ip, 'ldap_domain', output, f"ldap_domain_{ip}.txt"
            )
            
            return {
                'type': 'domain',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Domain enumeration failed for {ip}: {e}")
            return None
    
    async def _enumerate_users(self, ip: str) -> Dict:
        """Enumerate users via LDAP"""
        cmd = ['netexec', 'ldap', ip, '-u', '', '-p', '', '--users']
        
        try:
            self.logger.info(f"User enumeration via LDAP for {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            file_path = save_enumeration_result(
                self.output_dir, ip, 'ldap_users', output, f"ldap_users_{ip}.txt"
            )
            
            return {
                'type': 'users',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"LDAP user enumeration failed for {ip}: {e}")
            return None