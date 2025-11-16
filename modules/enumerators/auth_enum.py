"""
Authenticated enumeration module using provided credentials
"""

import asyncio
import subprocess
import logging
from typing import Dict, List, Optional
from utils import save_enumeration_result, is_command_available


class AuthEnumerator:
    """Authenticated enumeration using domain/local credentials"""
    
    def __init__(self, output_dir: str, username: str, password: str, local_auth: bool = False):
        self.output_dir = output_dir
        self.username = username
        self.password = password
        self.local_auth = local_auth
        self.logger = logging.getLogger('adtool')
        
        # Parse domain and username
        if '/' in username:
            self.domain, self.user = username.split('/', 1)
        elif '\\' in username:
            self.domain, self.user = username.split('\\', 1)
        else:
            self.domain = None
            self.user = username
        
        # Check if required tools are available
        self.nxc_cmd = None
        if is_command_available('nxc'):
            self.nxc_cmd = 'nxc'
        elif is_command_available('netexec'):
            self.nxc_cmd = 'netexec'
        else:
            self.logger.warning("Neither 'nxc' nor 'netexec' found. Authenticated enumeration will be limited.")
        
        self.has_enum4linux = is_command_available('enum4linux-ng')
        
        self.logger.info(f"Initialized authenticated enumerator for user: {self.username}")
        if self.local_auth:
            self.logger.info("Using local authentication")
        else:
            self.logger.info("Using domain authentication")
    
    async def enumerate_targets(self, ips: List[str]) -> Dict:
        """Perform authenticated enumeration on targets"""
        self.logger.info(f"Starting authenticated enumeration for {len(ips)} targets")
        
        if not self.nxc_cmd:
            self.logger.error("NetExec/NXC not found. Cannot perform authenticated enumeration.")
            return {'error': 'NetExec/NXC not available'}
        
        results = {
            'scan_type': 'authenticated_enumeration',
            'username': self.username,
            'local_auth': self.local_auth,
            'targets': ips,
            'results': []
        }
        
        # Run authenticated enumeration for each IP
        for ip in ips:
            self.logger.info(f"Running authenticated enumeration for {ip}")
            ip_results = await self._enumerate_target(ip)
            results['results'].append(ip_results)
        
        return results
    
    async def _enumerate_target(self, ip: str) -> Dict:
        """Run all authenticated enumeration checks for a single target"""
        target_result = {
            'ip': ip,
            'checks': []
        }
        
        # SMB share enumeration
        shares_result = await self._enumerate_smb_shares(ip)
        if shares_result:
            target_result['checks'].append(shares_result)
        
        # Password policy check
        passpol_result = await self._check_password_policy(ip)
        if passpol_result:
            target_result['checks'].append(passpol_result)
        
        # WinRM access check
        winrm_result = await self._check_winrm_access(ip)
        if winrm_result:
            target_result['checks'].append(winrm_result)
        
        # RDP access check
        rdp_result = await self._check_rdp_access(ip)
        if rdp_result:
            target_result['checks'].append(rdp_result)
        
        # LDAP user description enumeration
        ldap_users_result = await self._enumerate_ldap_user_descriptions(ip)
        if ldap_users_result:
            target_result['checks'].append(ldap_users_result)
        
        # enum4linux-ng enumeration
        enum4linux_result = await self._run_enum4linux(ip)
        if enum4linux_result:
            target_result['checks'].append(enum4linux_result)
        
        # If local_auth is enabled, run all checks again with --local-auth
        if self.local_auth:
            # SMB shares with local auth
            shares_local_result = await self._enumerate_smb_shares(ip, local_auth=True)
            if shares_local_result:
                target_result['checks'].append(shares_local_result)
            
            # Password policy with local auth
            passpol_local_result = await self._check_password_policy(ip, local_auth=True)
            if passpol_local_result:
                target_result['checks'].append(passpol_local_result)
            
            # WinRM with local auth
            winrm_local_result = await self._check_winrm_access(ip, local_auth=True)
            if winrm_local_result:
                target_result['checks'].append(winrm_local_result)
            
            # RDP with local auth
            rdp_local_result = await self._check_rdp_access(ip, local_auth=True)
            if rdp_local_result:
                target_result['checks'].append(rdp_local_result)
        
        return target_result
    
    async def _enumerate_smb_shares(self, ip: str, local_auth: bool = False) -> Dict:
        """Enumerate SMB shares with credentials"""
        cmd = [self.nxc_cmd, 'smb', ip, '-u', self.user, '-p', self.password, '--shares']
        
        if local_auth:
            cmd.append('--local-auth')
        
        auth_type = "local" if local_auth else "domain"
        
        try:
            self.logger.info(f"Enumerating SMB shares on {ip} ({auth_type} auth)")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            filename = f"smb_shares_{auth_type}_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, f'smb_shares_{auth_type}', output, filename
            )
            
            return {
                'type': f'smb_shares_{auth_type}',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"SMB shares enumeration failed for {ip} ({auth_type}): {e}")
            return None
    
    async def _check_password_policy(self, ip: str, local_auth: bool = False) -> Dict:
        """Check password policy"""
        cmd = [self.nxc_cmd, 'smb', ip, '-u', self.user, '-p', self.password, '--pass-pol']
        
        if local_auth:
            cmd.append('--local-auth')
        
        auth_type = "local" if local_auth else "domain"
        
        try:
            self.logger.info(f"Checking password policy on {ip} ({auth_type} auth)")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            filename = f"password_policy_{auth_type}_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, f'password_policy_{auth_type}', output, filename
            )
            
            return {
                'type': f'password_policy_{auth_type}',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Password policy check failed for {ip} ({auth_type}): {e}")
            return None
    
    async def _check_winrm_access(self, ip: str, local_auth: bool = False) -> Dict:
        """Check WinRM access"""
        cmd = [self.nxc_cmd, 'winrm', ip, '-u', self.user, '-p', self.password]
        
        if local_auth:
            cmd.append('--local-auth')
        
        auth_type = "local" if local_auth else "domain"
        
        try:
            self.logger.info(f"Checking WinRM access on {ip} ({auth_type} auth)")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            filename = f"winrm_access_{auth_type}_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, f'winrm_access_{auth_type}', output, filename
            )
            
            # Check if login was successful
            login_success = any(indicator in output.lower() for indicator in [
                'pwned', '[+]', 'login successful', 'shell access'
            ])
            
            return {
                'type': f'winrm_access_{auth_type}',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'login_success': login_success,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"WinRM access check failed for {ip} ({auth_type}): {e}")
            return None
    
    async def _check_rdp_access(self, ip: str, local_auth: bool = False) -> Dict:
        """Check RDP access"""
        cmd = [self.nxc_cmd, 'rdp', ip, '-u', self.user, '-p', self.password]
        
        if local_auth:
            cmd.append('--local-auth')
        
        auth_type = "local" if local_auth else "domain"
        
        try:
            self.logger.info(f"Checking RDP access on {ip} ({auth_type} auth)")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            filename = f"rdp_access_{auth_type}_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, f'rdp_access_{auth_type}', output, filename
            )
            
            # Check if login was successful
            login_success = any(indicator in output.lower() for indicator in [
                'pwned', '[+]', 'login successful', 'rdp access'
            ])
            
            return {
                'type': f'rdp_access_{auth_type}',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'login_success': login_success,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"RDP access check failed for {ip} ({auth_type}): {e}")
            return None
    
    async def _enumerate_ldap_user_descriptions(self, ip: str) -> Dict:
        """Enumerate LDAP user descriptions"""
        cmd = [self.nxc_cmd, 'ldap', ip, '-u', self.user, '-p', self.password, '-M', 'get-desc-users']
        
        try:
            self.logger.info(f"Enumerating LDAP user descriptions on {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            filename = f"ldap_user_descriptions_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, 'ldap_user_descriptions', output, filename
            )
            
            return {
                'type': 'ldap_user_descriptions',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"LDAP user descriptions enumeration failed for {ip}: {e}")
            return None
    
    async def _run_enum4linux(self, ip: str) -> Dict:
        """Run enum4linux-ng with credentials"""
        if not self.has_enum4linux:
            self.logger.warning("enum4linux-ng not found. Skipping authenticated enum4linux scan.")
            return None
        
        output_file = f"{self.user}_enumlinux"
        cmd = ['enum4linux-ng', ip, '-u', self.user, '-p', self.password, '-oY', f"{output_file}.txt"]
        
        try:
            self.logger.info(f"Running enum4linux-ng on {ip} with credentials")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=f"{self.output_dir}/enumeration"
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save the command output as well
            filename = f"enum4linux_auth_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, 'enum4linux_auth', output, filename
            )
            
            return {
                'type': 'enum4linux_authenticated',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'yaml_file': f"{self.output_dir}/enumeration/{output_file}.txt",
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"enum4linux-ng authenticated scan failed for {ip}: {e}")
            return None
    
    async def generate_summary(self, results: Dict) -> str:
        """Generate a summary of authenticated enumeration results"""
        if 'error' in results:
            return f"Authenticated enumeration failed: {results['error']}"
        
        summary_lines = []
        summary_lines.append("=== AUTHENTICATED ENUMERATION SUMMARY ===")
        summary_lines.append(f"Username: {results['username']}")
        summary_lines.append(f"Authentication: {'Local' if results['local_auth'] else 'Domain'}")
        summary_lines.append(f"Targets scanned: {len(results['targets'])}")
        summary_lines.append("")
        
        successful_logins = {
            'winrm': [],
            'rdp': [],
            'smb': []
        }
        
        for target_result in results['results']:
            ip = target_result['ip']
            checks = target_result['checks']
            
            summary_lines.append(f"Target: {ip}")
            summary_lines.append("-" * 20)
            
            for check in checks:
                check_type = check['type']
                success = check.get('success', False)
                
                if 'winrm' in check_type and check.get('login_success', False):
                    successful_logins['winrm'].append(ip)
                    summary_lines.append(f"  [+] WinRM access successful")
                
                if 'rdp' in check_type and check.get('login_success', False):
                    successful_logins['rdp'].append(ip)
                    summary_lines.append(f"  [+] RDP access successful")
                
                if 'smb_shares' in check_type and success:
                    successful_logins['smb'].append(ip)
                    summary_lines.append(f"  [+] SMB shares accessible")
                
                if success:
                    summary_lines.append(f"  [+] {check_type}: Success")
                else:
                    summary_lines.append(f"  [-] {check_type}: Failed")
            
            summary_lines.append("")
        
        # Access summary
        summary_lines.append("=== ACCESS SUMMARY ===")
        summary_lines.append(f"WinRM access: {len(successful_logins['winrm'])} targets")
        for ip in successful_logins['winrm']:
            summary_lines.append(f"  - {ip}")
        
        summary_lines.append(f"RDP access: {len(successful_logins['rdp'])} targets")
        for ip in successful_logins['rdp']:
            summary_lines.append(f"  - {ip}")
        
        summary_lines.append(f"SMB access: {len(successful_logins['smb'])} targets")
        for ip in successful_logins['smb']:
            summary_lines.append(f"  - {ip}")
        
        # Save summary to file
        summary_text = "\n".join(summary_lines)
        summary_file = save_enumeration_result(
            self.output_dir, "summary", "authenticated_enumeration", summary_text, "authenticated_enumeration_summary.txt"
        )
        
        return summary_text