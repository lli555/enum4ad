"""
Web enumeration module
"""

import asyncio
import subprocess
import logging
from typing import Dict, List
from utils import save_enumeration_result, is_command_available


class WebEnumerator:
    """Web service enumeration"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.logger = logging.getLogger('adtool')
    
    async def enumerate(self, ip: str, ports: List[Dict]) -> Dict:
        """Enumerate web services"""
        self.logger.info(f"Starting web enumeration for {ip}")
        
        results = {
            'ip': ip,
            'service': 'web',
            'enumeration_results': []
        }
        
        # Check each web port
        for port_info in ports:
            port = port_info['port']
            
            # Directory busting
            dirb_result = await self._directory_busting(ip, port)
            if dirb_result:
                results['enumeration_results'].append(dirb_result)
            
            # Nikto scan
            nikto_result = await self._nikto_scan(ip, port)
            if nikto_result:
                results['enumeration_results'].append(nikto_result)
            
            # Basic curl check
            curl_result = await self._basic_curl(ip, port)
            if curl_result:
                results['enumeration_results'].append(curl_result)
        
        return results
    
    async def _directory_busting(self, ip: str, port: int) -> Dict:
        """Directory busting with gobuster"""
        if not is_command_available('gobuster'):
            return None
        
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{ip}:{port}/"
        
        cmd = [
            'gobuster', 'dir',
            '-u', url,
            '-w', '/usr/share/wordlists/dirb/common.txt',
            '-t', '50',
            '-q'
        ]
        
        try:
            self.logger.info(f"Directory busting on {url}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            file_path = save_enumeration_result(
                self.output_dir, ip, 'web_dirs', output, f"web_dirs_{ip}_{port}.txt"
            )
            
            return {
                'type': 'directory_busting',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0,
                'port': port
            }
            
        except Exception as e:
            self.logger.error(f"Directory busting failed for {ip}:{port}: {e}")
            return None
    
    async def _nikto_scan(self, ip: str, port: int) -> Dict:
        """Nikto vulnerability scan"""
        if not is_command_available('nikto'):
            return None
        
        cmd = ['nikto', '-h', f"{ip}:{port}", '-Format', 'txt']
        
        try:
            self.logger.info(f"Nikto scan on {ip}:{port}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            file_path = save_enumeration_result(
                self.output_dir, ip, 'web_nikto', output, f"web_nikto_{ip}_{port}.txt"
            )
            
            return {
                'type': 'nikto_scan',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0,
                'port': port
            }
            
        except Exception as e:
            self.logger.error(f"Nikto scan failed for {ip}:{port}: {e}")
            return None
    
    async def _basic_curl(self, ip: str, port: int) -> Dict:
        """Basic curl check for headers and content"""
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{ip}:{port}/"
        
        cmd = ['curl', '-I', '-k', '--connect-timeout', '10', url]
        
        try:
            self.logger.info(f"Basic curl check on {url}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            file_path = save_enumeration_result(
                self.output_dir, ip, 'web_headers', output, f"web_headers_{ip}_{port}.txt"
            )
            
            return {
                'type': 'headers',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0,
                'port': port
            }
            
        except Exception as e:
            self.logger.error(f"Curl check failed for {ip}:{port}: {e}")
            return None