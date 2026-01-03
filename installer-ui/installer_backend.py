"""
Backend installation functions for the web UI installer
Uses password authentication for SSH/SCP operations
"""

import subprocess
import os
import sys
import json
from pathlib import Path

def get_deployment_dir():
    """Get deployment directory (parent of installer-ui)"""
    return Path(__file__).parent.parent

def execute_ssh_command(host, user, port, command, password=None, timeout=15):
    """Execute SSH command using password authentication
    
    Args:
        host: VPS hostname or IP
        user: SSH username
        port: SSH port
        command: Command to execute
        password: SSH password (required)
        timeout: Command timeout in seconds
    """
    if not password:
        return False, "", "Password is required for SSH authentication"
    
    if sys.platform == 'win32':
        try:
            import wexpect
        except ImportError:
            return False, "", "wexpect is required on Windows. Install with: pip install wexpect"
    else:
        try:
            import pexpect
        except ImportError:
            return False, "", "pexpect is required. Install with: pip install pexpect"
    
    # Build SSH command - on Windows, use list format to avoid shell splitting issues
    if sys.platform == 'win32':
        # On Windows, wexpect.spawn needs a list of arguments
        ssh_cmd_list = ['ssh', '-p', str(port), '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10', f'{user}@{host}', command]
        ssh_cmd = ssh_cmd_list
    else:
        # On Linux/Mac, pexpect.spawn can use a string
        ssh_cmd = f'ssh -p {port} -o StrictHostKeyChecking=no -o ConnectTimeout=10 {user}@{host} "{command}"'
    
    try:
        if sys.platform == 'win32':
            # On Windows, spawn with list of arguments (command and args separately)
            child = wexpect.spawn(ssh_cmd[0], ssh_cmd[1:], timeout=timeout)
        else:
            # On Linux/Mac, spawn with command string
            child = pexpect.spawn(ssh_cmd, timeout=timeout, encoding='utf-8')
        
        # Helper to check buffer for errors
        def check_for_permission_denied():
            if hasattr(child, 'before'):
                before_str = child.before.decode('utf-8', errors='ignore') if isinstance(child.before, bytes) else str(child.before)
                if 'Permission denied' in before_str or 'please try again' in before_str:
                    return True
            return False
        
        # Handle host key verification and password prompt
        try:
            index = child.expect(['password:', 'Password:', 'Password for', 'yes/no', '(yes/no)', 'Permission denied'], timeout=10)
            
            if index == 5:  # Permission denied before password prompt
                child.close()
                return False, "", "Permission denied. The password may be incorrect or SSH password authentication is disabled."
            
            if index >= 3 and index <= 4:  # yes/no prompt
                child.sendline('yes')
                index = child.expect(['password:', 'Password:', 'Password for', 'Permission denied'], timeout=10)
                if index == 3:  # Permission denied
                    child.close()
                    return False, "", "Permission denied. The password may be incorrect or SSH password authentication is disabled."
            
            # Send password - ensure it's a string, strip whitespace, and handle encoding
            password_str = str(password).strip() if password else ""
            # Debug: log password info
            print(f"[DEBUG SSH] Sending password: length={len(password_str)}, repr={repr(password_str)}")
            print(f"[DEBUG SSH] Password bytes: {password_str.encode('utf-8')}")
            # Send password as-is (wexpect/pexpect handles encoding)
            child.sendline(password_str)
            
            # Wait a moment and check for permission denied
            import time
            time.sleep(0.5)
            if check_for_permission_denied():
                child.close()
                return False, "", "Permission denied. The password is incorrect. Please verify your VPS password."
            
            # Check if command already completed (some SSH connections are fast)
            if sys.platform == 'win32':
                try:
                    # Try to read any immediate output
                    import select
                    # On Windows, wexpect doesn't support select, so we'll just wait for expect
                    pass
                except:
                    pass
            
        except Exception as e:
            # Check buffer for permission denied
            if check_for_permission_denied():
                child.close()
                return False, "", "Permission denied. The password is incorrect. Please verify your VPS password."
            # If we don't get a password prompt, might already be connected
            pass
        
        # Wait for command output - check for password prompt again (retry after wrong password)
        try:
            if sys.platform == 'win32':
                # Check for another password prompt (retry) or EOF
                try:
                    # Use a shorter timeout for the expect to avoid hanging
                    expect_timeout = min(timeout, 20)  # Cap at 20 seconds
                    print(f"[DEBUG SSH] Waiting for command completion (timeout: {expect_timeout}s)...")
                    index = child.expect(['password:', 'Password:', 'Password for', wexpect.EOF], timeout=expect_timeout)
                    print(f"[DEBUG SSH] Expect returned index: {index}")
                    if index < 3:  # Another password prompt (retry)
                        child.close()
                        return False, "", "Permission denied. The password is incorrect. Please verify your VPS password."
                    # index == 3 means EOF - command completed
                except wexpect.TIMEOUT:
                    print(f"[DEBUG SSH] Timeout waiting for EOF after {expect_timeout}s")
                    # Check buffer for permission denied
                    if check_for_permission_denied():
                        child.close()
                        return False, "", "Permission denied. The password is incorrect. Please verify your VPS password."
                    # Timeout waiting for command - try to get output anyway
                    print(f"[DEBUG SSH] Timeout waiting for EOF, checking buffer...")
                    try:
                        output = child.before.decode('utf-8', errors='ignore') if isinstance(child.before, bytes) else str(child.before)
                        print(f"[DEBUG SSH] Buffer content: {output[:200]}")
                        if 'Connection successful' in output:
                            print(f"[DEBUG SSH] Found success message in buffer, returning success")
                            child.close()
                            return True, output, ""
                        else:
                            # Check if process is still alive
                            if hasattr(child, 'isalive') and not child.isalive():
                                print(f"[DEBUG SSH] Process is not alive, assuming completion")
                                child.close()
                                return True, output, ""
                            child.close()
                            return False, output, f"Command timeout after {expect_timeout} seconds"
                    except Exception as e:
                        print(f"[DEBUG SSH] Error getting buffer: {e}")
                        child.close()
                        return False, "", f"Command timeout after {expect_timeout} seconds"
                
                output = child.before.decode('utf-8', errors='ignore') if isinstance(child.before, bytes) else str(child.before)
                
                # Wait a moment for exit status to be set
                import time
                time.sleep(0.2)
                
                # Get exit code - if not available, check output for success indicators
                exit_code = child.exitstatus if hasattr(child, 'exitstatus') and child.exitstatus is not None else None
                
                # If exit code is None, check if output indicates success
                if exit_code is None:
                    # Check if output contains expected success message or no error messages
                    if 'Connection successful' in output or ('Permission denied' not in output and 'please try again' not in output):
                        exit_code = 0  # Assume success if we got expected output
                        print(f"[DEBUG SSH] Assuming success based on output: {output[:100]}")
                    else:
                        exit_code = 1  # Assume failure if we see error messages
                        print(f"[DEBUG SSH] Assuming failure based on output: {output[:100]}")
            else:
                try:
                    # Use a shorter timeout for the expect to avoid hanging
                    expect_timeout = min(timeout, 20)  # Cap at 20 seconds
                    index = child.expect(['password:', 'Password:', 'Password for', pexpect.EOF], timeout=expect_timeout)
                    if index < 3:  # Another password prompt (retry)
                        child.close()
                        return False, "", "Permission denied. The password is incorrect. Please verify your VPS password."
                    # index == 3 means EOF - command completed
                except pexpect.TIMEOUT:
                    # Check buffer for permission denied
                    if check_for_permission_denied():
                        child.close()
                        return False, "", "Permission denied. The password is incorrect. Please verify your VPS password."
                    # Timeout waiting for command - try to get output anyway
                    print(f"[DEBUG SSH] Timeout waiting for EOF, checking buffer...")
                    try:
                        output = child.before
                        if 'Connection successful' in output:
                            child.close()
                            return True, output, ""
                        else:
                            child.close()
                            return False, output, f"Command timeout after {expect_timeout} seconds"
                    except:
                        child.close()
                        return False, "", f"Command timeout after {expect_timeout} seconds"
                
                output = child.before
                exit_code = child.exitstatus if child.exitstatus is not None else 0
        except (wexpect.TIMEOUT if sys.platform == 'win32' else pexpect.TIMEOUT):
            # Final check for permission denied
            if check_for_permission_denied():
                child.close()
                return False, "", "Permission denied. The password is incorrect. Please verify your VPS password."
            raise
        
        child.close()
        
        # Clean up output - remove password prompts and other noise
        if output:
            # Remove common SSH prompts and noise
            lines = output.split('\n')
            cleaned_lines = []
            for line in lines:
                line = line.strip()
                if line and 'password:' not in line.lower() and 'Password:' not in line and 'Password for' not in line:
                    cleaned_lines.append(line)
            output = '\n'.join(cleaned_lines).strip()
        
        # Safe print for Windows encoding issues - show more details
        try:
            print(f"[DEBUG SSH] Command: {command[:100] if len(command) > 100 else command}")
            print(f"[DEBUG SSH] Exit code: {exit_code}, Output length: {len(output) if output else 0}")
            if output:
                # Show more output for debugging (first 500 chars)
                safe_output = output[:500].encode('ascii', errors='replace').decode('ascii')
                print(f"[DEBUG SSH] Output (first 500 chars): {safe_output}")
                # Check if output contains error indicators
                if 'error' in output.lower() or 'failed' in output.lower() or 'traceback' in output.lower():
                    print(f"[DEBUG SSH] Output contains error indicators")
        except UnicodeEncodeError:
            # If encoding fails, just log the length
            print(f"[DEBUG SSH] Command completed. Exit code: {exit_code}, Output length: {len(output) if output else 0}")
        
        # Determine error message from output if exit code indicates failure
        error_msg = ""
        if exit_code != 0 and output:
            # Extract error from output
            error_lines = [line for line in output.split('\n') if 'error' in line.lower() or 'failed' in line.lower() or 'traceback' in line.lower()]
            if error_lines:
                try:
                    error_msg = '\n'.join(error_lines[:5]).encode('ascii', errors='replace').decode('ascii')
                except:
                    error_msg = output[:300].encode('ascii', errors='replace').decode('ascii')
        
        # Ensure output is safe for return (handle Unicode characters)
        # The output string itself is fine, but when it's used in error messages,
        # it needs to be safely encoded. We'll handle that at the call site.
        return exit_code == 0, output, error_msg
        
    except Exception as e:
        error_msg = str(e)
        # Check if it's a timeout with permission denied in buffer
        if 'timeout' in error_msg.lower() or 'TIMEOUT' in error_msg:
            # Try to get buffer content
            try:
                if hasattr(child, 'before'):
                    before_str = child.before.decode('utf-8', errors='ignore') if isinstance(child.before, bytes) else str(child.before)
                    if 'Permission denied' in before_str or 'please try again' in before_str:
                        return False, "", "Permission denied. The password is incorrect. Please verify your VPS password."
            except:
                pass
        return False, "", error_msg

def execute_scp_command(host, user, port, source, destination, password=None):
    """Execute SCP command using password authentication
    
    Args:
        host: VPS hostname or IP
        user: SSH username
        port: SSH port
        source: Source file path
        destination: Destination path on VPS
        password: SSH password (required)
    """
    if not password:
        return False, "", "Password is required for SCP authentication"
    
    if sys.platform == 'win32':
        try:
            import wexpect
        except ImportError:
            return False, "", "wexpect is required on Windows. Install with: pip install wexpect"
    else:
        try:
            import pexpect
        except ImportError:
            return False, "", "pexpect is required. Install with: pip install pexpect"
    
    scp_cmd = f'scp -P {port} -o StrictHostKeyChecking=no {source} {user}@{host}:{destination}'
    
    try:
        if sys.platform == 'win32':
            child = wexpect.spawn(scp_cmd, timeout=60)
        else:
            child = pexpect.spawn(scp_cmd, timeout=60, encoding='utf-8')
        
        # Handle host key verification and password prompt
        try:
            index = child.expect(['password:', 'Password:', 'Password for', 'yes/no', '(yes/no)'], timeout=10)
            if index >= 3:  # yes/no prompt
                child.sendline('yes')
                index = child.expect(['password:', 'Password:', 'Password for'], timeout=10)
            
            # Send password - ensure it's a string, strip whitespace, and handle encoding
            password_str = str(password).strip() if password else ""
            # Debug: log password info
            print(f"[DEBUG SSH] Sending password: length={len(password_str)}, repr={repr(password_str)}")
            print(f"[DEBUG SSH] Password bytes: {password_str.encode('utf-8')}")
            # Send password as-is (wexpect/pexpect handles encoding)
            child.sendline(password_str)
        except Exception as e:
            # If we don't get a password prompt, might already be connected
            pass
        
        # Wait for completion
        if sys.platform == 'win32':
            child.expect(wexpect.EOF, timeout=60)
            exit_code = child.exitstatus if hasattr(child, 'exitstatus') else 0
        else:
            child.expect(pexpect.EOF, timeout=60)
            exit_code = child.exitstatus
        
        child.close()
        
        return exit_code == 0, "", ""
        
    except Exception as e:
        return False, "", str(e)

def deploy_application(config, progress_callback=None):
    """Deploy application to VPS using git clone"""
    host = config['host']
    user = config['user']
    port = config.get('port', 22)
    install_dir = config.get('install_dir', '/opt/oxcookie-manager')
    password = config.get('password')
    git_repo_url = config.get('git_repo_url')
    git_branch = config.get('git_branch', 'main')
    
    if not password:
        return False, "Password is required"
    
    if not git_repo_url:
        return False, "Git repository URL is required"
    
    # Step 1: Check if git is installed
    if progress_callback:
        progress_callback("Checking for git...")
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        "sudo git --version 2>&1",
        password, timeout=10
    )
    if not success:
        # Install git
        if progress_callback:
            progress_callback("Installing git with sudo...")
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "sudo apt-get update -qq && sudo apt-get install -y git 2>&1",
            password, timeout=120
        )
        if not success:
            error_msg = stderr if stderr else stdout if stdout else "Unknown error"
            try:
                error_msg = error_msg.encode('ascii', errors='replace').decode('ascii')
            except:
                error_msg = "Failed to install git"
            if progress_callback:
                progress_callback(f"[ERROR] Failed to install git: {error_msg}")
            return False, f"Failed to install git: {error_msg}"
    if progress_callback:
        git_version = stdout.strip() if stdout else "installed"
        progress_callback(f"[OK] Git found: {git_version}")
    
    # Step 2: Create directory and clone repository
    if progress_callback:
        progress_callback("Creating installation directory...")
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        f"sudo mkdir -p {install_dir} && sudo chown {user}:{user} {install_dir} && sudo chmod 755 {install_dir}",
        password,
        timeout=30
    )
    if not success:
        error_msg = stderr if stderr else stdout if stdout else "Unknown error"
        try:
            error_msg = error_msg.encode('ascii', errors='replace').decode('ascii')
        except:
            error_msg = "Failed to create directory"
        if progress_callback:
            progress_callback(f"[ERROR] Failed to create directory: {error_msg}")
        return False, f"Failed to create directory: {error_msg}"
    if progress_callback:
        progress_callback("[OK] Installation directory created")
    
    # Step 3: Clone or update repository
    if progress_callback:
        progress_callback(f"Cloning repository from {git_repo_url}...")
    
    # Check if directory already has a git repository
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        f"cd {install_dir} && git rev-parse --git-dir > /dev/null 2>&1 && echo 'exists' || echo 'not_found'",
        password, timeout=10
    )
    
    if success and 'exists' in stdout:
        # Repository exists, pull latest changes
        if progress_callback:
            progress_callback(f"Updating repository (pulling {git_branch} branch)...")
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            f"cd {install_dir} && git fetch origin && git reset --hard origin/{git_branch}",
            password, timeout=120
        )
        if not success:
            return False, f"Failed to update repository: {stderr}"
    else:
        # Clone fresh repository
        if progress_callback:
            progress_callback(f"Cloning repository (branch: {git_branch})...")
        # Remove directory contents if exists but not a git repo
        execute_ssh_command(
            host, user, port,
            f"sudo rm -rf {install_dir}/* {install_dir}/.* 2>/dev/null || true",
            password, timeout=10
        )
        
        # Clone repository
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            f"cd {install_dir} && git clone -b {git_branch} --depth 1 {git_repo_url} .",
            password, timeout=300
        )
        if not success:
            return False, f"Failed to clone repository: {stderr}"
    
    if progress_callback:
        progress_callback("Repository cloned successfully")
    
    # Step 4: Check and install system dependencies
    if progress_callback:
        progress_callback("Checking system dependencies...")
    
    # Check for Python 3
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        "python3 --version || python --version",
        password, timeout=10
    )
    if not success:
        return False, "Python 3 not found on VPS. Please install Python 3 first."
    
    # Check for pip
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        "python3 -m pip --version || pip3 --version",
        password, timeout=10
    )
    if not success:
        if progress_callback:
            progress_callback("Installing pip...")
        # Install pip
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "sudo apt-get update -qq && sudo apt-get install -y python3-pip",
            password, timeout=120
        )
        if not success:
            return False, f"Failed to install pip: {stderr}"
    
    # Step 5: Install Python dependencies
    if progress_callback:
        progress_callback("Installing Python dependencies...")
    
    # First, check if requirements.txt exists
    if progress_callback:
        progress_callback("Checking for requirements.txt...")
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        f"sudo test -f {install_dir}/requirements.txt && echo 'EXISTS' || echo 'NOT_FOUND'",
        password, timeout=10
    )
    if not success or 'NOT_FOUND' in stdout:
        if progress_callback:
            progress_callback(f"[ERROR] requirements.txt not found in {install_dir}")
        return False, f"requirements.txt not found in {install_dir}"
    if progress_callback:
        progress_callback("[OK] requirements.txt found")
    
    # Install dependencies using sudo pip3 (more reliable on VPS)
    if progress_callback:
        progress_callback("Installing dependencies with sudo pip3 (this may take a few minutes)...")
    
    # Use sudo pip3 install with verbose output and save to log
    # Install system-wide so service can access it
    install_cmd = f"cd {install_dir} && sudo pip3 install --break-system-packages -r requirements.txt 2>&1 | sudo tee /tmp/pip_install.log; echo 'PIP_EXIT_CODE:' $?"
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        install_cmd,
        password, timeout=600  # Increased timeout for dependency installation
    )
    
    # Check exit code from pip install
    pip_exit_code = None
    if stdout and 'PIP_EXIT_CODE:' in stdout:
        try:
            pip_exit_code = int(stdout.split('PIP_EXIT_CODE:')[-1].strip().split()[0])
        except:
            pass
    
    # Get the installation log
    if progress_callback:
        progress_callback("Checking installation log...")
    log_success, log_stdout, log_stderr = execute_ssh_command(
        host, user, port,
        "sudo cat /tmp/pip_install.log 2>&1 | tail -n 100",
        password, timeout=10
    )
    
    # Log the output (safely encoded) - show more details
    if log_success and log_stdout:
        try:
            log_output = log_stdout.encode('ascii', errors='replace').decode('ascii')
            if progress_callback:
                # Show last 20 lines of log for better visibility
                log_lines = log_output.split('\n')[-20:]
                for line in log_lines:
                    if line.strip():
                        # Show important lines
                        if 'error' in line.lower() or 'failed' in line.lower() or 'successfully installed' in line.lower() or 'requirement already satisfied' in line.lower():
                            progress_callback(f"[LOG] {line[:250]}")
        except:
            pass
    
    # Check if installation actually succeeded by verifying key packages
    if progress_callback:
        progress_callback("Verifying dependencies are installed...")
    
    # Check for Flask (critical dependency) - use system python3
    verify_success, verify_stdout, verify_stderr = execute_ssh_command(
        host, user, port,
        "sudo python3 -c 'import flask; print(\"OK\")' 2>&1",
        password, timeout=10
    )
    
    if not verify_success or 'OK' not in verify_stdout:
        # Installation failed - get detailed error
        error_details = []
        
        # Add pip exit code
        if pip_exit_code is not None:
            error_details.append(f"pip exit code: {pip_exit_code}")
        
        # Add command output
        if stdout:
            try:
                stdout_safe = stdout.encode('ascii', errors='replace').decode('ascii')[:500]
                error_details.append(f"stdout: {stdout_safe}")
            except:
                pass
        
        if stderr:
            try:
                stderr_safe = stderr.encode('ascii', errors='replace').decode('ascii')[:500]
                error_details.append(f"stderr: {stderr_safe}")
            except:
                pass
        
        if verify_stderr:
            try:
                verify_stderr_safe = verify_stderr.encode('ascii', errors='replace').decode('ascii')[:500]
                error_details.append(f"verify error: {verify_stderr_safe}")
            except:
                pass
        
        if verify_stdout:
            try:
                verify_stdout_safe = verify_stdout.encode('ascii', errors='replace').decode('ascii')[:500]
                error_details.append(f"verify output: {verify_stdout_safe}")
            except:
                pass
        
        # Get full pip log for debugging
        if log_success and log_stdout:
            try:
                log_safe = log_stdout.encode('ascii', errors='replace').decode('ascii')[:1000]
                error_details.append(f"pip log (last 100 lines): {log_safe}")
            except:
                pass
        
        error_msg = "Failed to install dependencies - Flask not found after installation"
        if error_details:
            error_msg += f"\n{' | '.join(error_details)}"
        
        if progress_callback:
            progress_callback(f"[ERROR] {error_msg}")
        return False, error_msg
    
    if progress_callback:
        progress_callback("[OK] Dependencies verified - Flask is installed")
    
    # Verify other critical packages
    critical_packages = ['flask', 'flask_cors', 'werkzeug']
    for package in critical_packages:
        if progress_callback:
            progress_callback(f"Verifying {package}...")
        verify_success, verify_stdout, verify_stderr = execute_ssh_command(
            host, user, port,
            f"sudo python3 -c 'import {package}; print(\"OK\")' 2>&1",
            password, timeout=10
        )
        if verify_success and 'OK' in verify_stdout:
            if progress_callback:
                progress_callback(f"[OK] {package} verified")
        else:
            verify_error = verify_stderr if verify_stderr else verify_stdout if verify_stdout else "unknown"
            try:
                verify_error = verify_error.encode('ascii', errors='replace').decode('ascii')[:200]
            except:
                verify_error = "verification failed"
            if progress_callback:
                progress_callback(f"[WARN] {package} verification failed: {verify_error}")
    
    if progress_callback:
        progress_callback("[OK] All dependencies installed and verified")
    
    return True, "Deployment successful"

def setup_dns(config, progress_callback=None):
    """Setup DNS records (Cloudflare or others). Uses progress_callback for detailed logging when provided."""
    domain = config.get('domain')
    dns_provider = config.get('dns_provider')
    
    if not dns_provider or dns_provider == 'manual':
        return True, "DNS setup skipped"
    
    # Get VPS IP
    host = config['host']
    user = config['user']
    port = config.get('port', 22)
    password = config.get('password')
    
    success, vps_ip, stderr = execute_ssh_command(
        host, user, port, "curl -s ifconfig.me",
        password, timeout=10
    )
    
    if not success:
        return False, "Failed to get VPS IP"
    
    vps_ip = vps_ip.strip()
    
    if dns_provider == 'cloudflare':
        # Cloudflare DNS setup
        cf_email = config.get('cf_email')
        cf_api_key = config.get('cf_api_key')
        base_domain = config.get('base_domain')
        subdomain = config.get('subdomain')
        domain = config.get('domain', '')
        
        # If base_domain and subdomain not provided, extract from domain
        if not base_domain or not subdomain:
            if domain:
                domain_parts = domain.split('.')
                if len(domain_parts) > 2:
                    # It's a subdomain, extract base and subdomain
                    base_domain = '.'.join(domain_parts[-2:])
                    subdomain = '.'.join(domain_parts[:-2])
                else:
                    # It's a base domain, we need subdomain
                    base_domain = domain
                    # Generate a random subdomain if not provided (5 random characters)
                    if not subdomain:
                        import random
                        import string
                        random_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
                        subdomain = random_chars
        
        if not base_domain:
            return False, "Base domain is required for DNS setup"
        
        if not subdomain:
            return False, "Subdomain is required for DNS setup"
        
        # Get Zone ID
        import urllib.request
        import urllib.parse
        
        zone_url = f"https://api.cloudflare.com/client/v4/zones?name={base_domain}"
        req = urllib.request.Request(zone_url)
        req.add_header('X-Auth-Email', cf_email)
        req.add_header('X-Auth-Key', cf_api_key)
        req.add_header('Content-Type', 'application/json')
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read())
                if data.get('success') and data.get('result') and len(data.get('result', [])) > 0:
                    zone_id = data['result'][0]['id']
                    
                    # Create DNS record
                    record_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
                    record_data = {
                        "type": "A",
                        "name": subdomain,
                        "content": vps_ip,
                        # TTL 1 = 'Auto' in Cloudflare
                        "ttl": 1,
                        # Always create proxied records (orange cloud) so Cloudflare handles HTTPS/edge
                        "proxied": True
                    }
                    
                    req = urllib.request.Request(record_url, data=json.dumps(record_data).encode(), method='POST')
                    req.add_header('X-Auth-Email', cf_email)
                    req.add_header('X-Auth-Key', cf_api_key)
                    req.add_header('Content-Type', 'application/json')
                    
                    with urllib.request.urlopen(req, timeout=30) as response:
                        result = json.loads(response.read())
                        if result.get('success'):
                            full_domain = f"{subdomain}.{base_domain}"
                            if progress_callback:
                                progress_callback(f"[OK] DNS record created: {full_domain} -> {vps_ip}")
                            return True, f"DNS record created: {full_domain} -> {vps_ip}"
                        else:
                            errors = result.get('errors', [])
                            error_msg = errors[0].get('message', 'Unknown error') if errors else 'DNS creation failed'
                            # Treat 'An identical record already exists.' as success
                            if 'identical record already exists' in error_msg.lower():
                                full_domain = f"{subdomain}.{base_domain}"
                                if progress_callback:
                                    progress_callback(f"[OK] DNS record already exists for {full_domain} -> {vps_ip}")
                                return True, f"DNS record already exists: {full_domain} -> {vps_ip}"
                            if progress_callback:
                                progress_callback(f"[WARN] DNS creation failed: {error_msg}")
                            return False, f"DNS creation failed: {error_msg}"
                else:
                    return False, "Failed to get Zone ID from Cloudflare"
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8', errors='ignore')
            try:
                error_data = json.loads(error_body)
                errors = error_data.get('errors', [])
                error_msg = errors[0].get('message', 'HTTP Error') if errors else f"HTTP {e.code}"
                # Treat identical-record case as success
                if 'identical record already exists' in error_msg.lower():
                    full_domain = f"{subdomain}.{base_domain}" if base_domain and subdomain else domain
                    if progress_callback:
                        progress_callback(f"[OK] DNS record already exists for {full_domain} -> {vps_ip}")
                        progress_callback(f"[DEBUG] Cloudflare response: {error_body}")
                    return True, f"DNS record already exists for {full_domain}"
            except Exception:
                error_msg = f"HTTP {e.code}: {e.reason}"
            if progress_callback:
                progress_callback(f"[WARN] DNS setup error: {error_msg}")
                progress_callback(f"[DEBUG] Cloudflare error body: {error_body[:1000]}")
            return False, f"DNS setup error: {error_msg}"
        except Exception as e:
            if progress_callback:
                progress_callback(f"[WARN] DNS setup exception: {str(e)}")
            return False, f"DNS setup error: {str(e)}"
    
    return True, "DNS setup completed"

def set_cloudflare_ssl_mode(config, mode="strict", progress_callback=None):
    """Set Cloudflare SSL mode for the zone (e.g. 'off', 'flexible', 'full', 'strict').
    Uses Global API key + email (cf_api_key + cf_email)."""
    dns_provider = config.get('dns_provider')
    if dns_provider != 'cloudflare':
        return True, "Cloudflare not configured, skipping SSL mode update"
    
    base_domain = config.get('base_domain')
    domain = config.get('domain', '')
    cf_email = config.get('cf_email')
    cf_api_key = config.get('cf_api_key')
    
    if not (cf_email and cf_api_key):
        return False, "Cloudflare email/API key not configured"
    
    # Derive base_domain from domain if missing
    if not base_domain and domain:
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
    
    if not base_domain:
        return False, "Base domain is required to set Cloudflare SSL mode"
    
    try:
        import urllib.request
        import json as json_module
        
        # 1) Get Zone ID for base_domain
        zone_url = f"https://api.cloudflare.com/client/v4/zones?name={base_domain}"
        req = urllib.request.Request(zone_url)
        req.add_header('X-Auth-Email', cf_email)
        req.add_header('X-Auth-Key', cf_api_key)
        req.add_header('Content-Type', 'application/json')
        
        if progress_callback:
            progress_callback(f"[INFO] Fetching Cloudflare zone for {base_domain} to set SSL mode to {mode}...")
        
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json_module.loads(response.read())
            if not (data.get('success') and data.get('result')):
                return False, "Failed to get Cloudflare zone ID"
            zone_id = data['result'][0]['id']
        
        # 2) Update SSL setting for the zone
        settings_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/ssl"
        payload = {"value": mode}
        req = urllib.request.Request(settings_url, data=json_module.dumps(payload).encode('utf-8'), method='PATCH')
        req.add_header('X-Auth-Email', cf_email)
        req.add_header('X-Auth-Key', cf_api_key)
        req.add_header('Content-Type', 'application/json')
        
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json_module.loads(response.read())
            if result.get('success'):
                if progress_callback:
                    progress_callback(f"[OK] Cloudflare SSL mode set to '{mode}' for zone {base_domain}")
                return True, f"Cloudflare SSL mode set to '{mode}'"
            else:
                errors = result.get('errors', [])
                msg = errors[0].get('message', 'Unknown error') if errors else 'Failed to update SSL mode'
                if progress_callback:
                    progress_callback(f"[WARN] Failed to update Cloudflare SSL mode: {msg}")
                return False, f"Failed to update Cloudflare SSL mode: {msg}"
    except Exception as e:
        if progress_callback:
            progress_callback(f"[WARN] Cloudflare SSL mode update exception: {str(e)}")
        return False, f"Cloudflare SSL mode update error: {str(e)}"

def setup_ssl(config, progress_callback=None):
    """Setup Let's Encrypt SSL certificate via Certbot (for Full/Strict SSL)"""
    domain = config.get('domain')
    if not domain:
        return True, "SSL setup skipped (no domain configured)"
    
    host = config['host']
    user = config['user']
    port = config.get('port', 22)
    password = config.get('password')
    
    # Use a dedicated SSL email if provided, otherwise fall back to Cloudflare email
    ssl_email = config.get('ssl_email') or config.get('cf_email')
    
    if not ssl_email:
        if progress_callback:
            progress_callback("[INFO] SSL email not configured, skipping automatic certificate setup")
        return True, "SSL setup skipped (no email configured)"
    
    if progress_callback:
        progress_callback(f"[INFO] Setting up SSL certificate for domain: {domain}")
    
    # 1) Ensure certbot and nginx plugin are installed
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        "which certbot || echo 'NOT_FOUND'",
        password, timeout=10
    )
    certbot_installed = success and 'NOT_FOUND' not in stdout
    
    if not certbot_installed:
        if progress_callback:
            progress_callback("[INFO] Certbot not found, installing certbot and python3-certbot-nginx...")
        install_cmd = "sudo apt-get update -qq && sudo apt-get install -y certbot python3-certbot-nginx 2>&1"
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            install_cmd,
            password, timeout=300
        )
        if not success:
            error_msg = stderr if stderr else stdout if stdout else "Unknown error installing certbot"
            if progress_callback:
                progress_callback(f"[WARN] Failed to install certbot: {error_msg}")
            return False, f"Failed to install certbot: {error_msg}"
        if progress_callback:
            progress_callback("[OK] Certbot installed successfully")
    
    # 2) Request / renew certificate using certbot --nginx
    certbot_cmd = (
        f"sudo certbot --nginx -d {domain} "
        f"--non-interactive --agree-tos -m {ssl_email} --redirect --no-eff-email 2>&1"
    )
    
    if progress_callback:
        progress_callback(f"[INFO] Requesting/renewing SSL certificate via certbot for {domain}...")
    
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        certbot_cmd,
        password, timeout=600
    )
    
    output = stdout if stdout else stderr if stderr else ""
    if progress_callback and output:
        # Log full (safe-encoded) certbot output for diagnostics (trim to 2000 chars for UI)
        try:
            safe_full = output.encode('ascii', errors='replace').decode('ascii')
            trimmed = safe_full[:2000]
            progress_callback(f"[DEBUG] Certbot output (first 2000 chars):\n{trimmed}")
        except Exception as e:
            progress_callback(f"[DEBUG] Failed to encode certbot output: {str(e)}")
    
    if not success:
        # Some certbot failures are non-fatal (e.g. rate limits, existing cert)
        safe_output = output.encode('ascii', errors='replace').decode('ascii') if output else ""
        if "too many certificates" in safe_output.lower():
            if progress_callback:
                progress_callback(f"[WARN] Certbot rate limit hit: {safe_output}")
            return False, "Certbot rate limit hit"
        if "certificate not yet due for renewal" in safe_output.lower() or "no action taken" in safe_output.lower():
            if progress_callback:
                progress_callback("[OK] Existing certificate is still valid (no renewal needed)")
        else:
            if progress_callback:
                progress_callback(f"[WARN] Certbot reported an issue: {safe_output}")
    
    # 3) Verify certificate files exist
    cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    key_path = f"/etc/letsencrypt/live/{domain}/privkey.pem"
    verify_cert_cmd = f"sudo test -f {cert_path} -a -f {key_path} && echo 'EXISTS' || echo 'NOT_FOUND'"
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        verify_cert_cmd,
        password, timeout=10
    )
    
    if not success or 'NOT_FOUND' in stdout:
        if progress_callback:
            progress_callback(f"[WARN] SSL certificate files not found for {domain} (expected {cert_path})")
        return False, f"SSL certificate files not found for {domain}"
    
    if progress_callback:
        progress_callback(f"[OK] SSL certificate files present for {domain}")
    
    # 4) Reload Nginx to apply SSL configuration (certbot --nginx already edits configs)
    reload_cmd = "sudo systemctl reload nginx 2>&1"
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        reload_cmd,
        password, timeout=15
    )
    
    if not success:
        error_msg = stderr if stderr else stdout if stdout else "Unknown error reloading nginx after SSL"
        if progress_callback:
            progress_callback(f"[WARN] Failed to reload Nginx after SSL setup: {error_msg}")
        return False, f"SSL setup completed but Nginx reload failed: {error_msg}"
    
    if progress_callback:
        progress_callback(f"[OK] SSL certificate configured and Nginx reloaded for {domain}")
    
    # 5) Optionally set Cloudflare SSL mode to 'strict' (Full Strict) if Cloudflare is configured
    cf_ssl_success, cf_ssl_msg = set_cloudflare_ssl_mode(config, mode="strict", progress_callback=progress_callback)
    if not cf_ssl_success and progress_callback:
        progress_callback(f"[WARN] Could not set Cloudflare SSL mode to strict: {cf_ssl_msg}")
    
    return True, f"SSL certificate configured for {domain}"

def check_existing_installation(config, progress_callback=None):
    """Check for existing installation and return status"""
    host = config['host']
    user = config['user']
    port = config.get('port', 22)
    install_dir = config.get('install_dir', '/opt/oxcookie-manager')
    password = config.get('password')
    
    status = {
        'service_exists': False,
        'service_running': False,
        'service_enabled': False,
        'files_exist': False,
        'nginx_configured': False,
        'process_running': False
    }
    
    if not password:
        if progress_callback:
            progress_callback("[WARN] No password provided, skipping installation check")
        return status
    
    # Check if systemd service exists
    if progress_callback:
        progress_callback("[INFO] Checking for systemd service...")
    try:
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "test -f /etc/systemd/system/oxcookie-manager.service && echo 'EXISTS' || echo 'NOT_FOUND'",
            password, timeout=8
        )
        if success and 'EXISTS' in stdout:
            status['service_exists'] = True
            if progress_callback:
                progress_callback("[OK] Systemd service found")
            
            # Check if service is enabled
            if progress_callback:
                progress_callback("[INFO] Checking if service is enabled...")
            try:
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    "sudo systemctl is-enabled oxcookie-manager 2>&1",
                    password, timeout=8
                )
                if success and 'enabled' in stdout.lower():
                    status['service_enabled'] = True
                    if progress_callback:
                        progress_callback("[OK] Service is enabled")
            except Exception as e:
                if progress_callback:
                    progress_callback(f"[WARN] Failed to check if service is enabled: {str(e)}")
            
            # Check if service is running
            if progress_callback:
                progress_callback("[INFO] Checking if service is running...")
            try:
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    "sudo systemctl is-active oxcookie-manager 2>&1",
                    password, timeout=8
                )
                if success and 'active' in stdout.lower():
                    status['service_running'] = True
                    if progress_callback:
                        progress_callback("[OK] Service is running")
            except Exception as e:
                if progress_callback:
                    progress_callback(f"[WARN] Failed to check if service is running: {str(e)}")
        else:
            if progress_callback:
                progress_callback("[INFO] Systemd service not found")
    except Exception as e:
        if progress_callback:
            progress_callback(f"[WARN] Error checking systemd service: {str(e)}")
    
    # Check if installation directory and files exist
    if progress_callback:
        progress_callback(f"[INFO] Checking for installation files in {install_dir}...")
    try:
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            f"test -f {install_dir}/app.py && echo 'EXISTS' || echo 'NOT_FOUND'",
            password, timeout=8
        )
        if success and 'EXISTS' in stdout:
            status['files_exist'] = True
            if progress_callback:
                progress_callback("[OK] Installation files found")
        else:
            if progress_callback:
                progress_callback("[INFO] Installation files not found")
    except Exception as e:
        if progress_callback:
            progress_callback(f"[WARN] Error checking installation files: {str(e)}")
    
    # Check if process is running (by checking if app.py is in process list)
    if progress_callback:
        progress_callback("[INFO] Checking for running process...")
    try:
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            f"pgrep -f '{install_dir}/app.py' > /dev/null 2>&1 && echo 'RUNNING' || echo 'NOT_RUNNING'",
            password, timeout=8
        )
        if success and 'RUNNING' in stdout:
            status['process_running'] = True
            if progress_callback:
                progress_callback("[OK] Process is running")
        else:
            if progress_callback:
                progress_callback("[INFO] Process not running")
    except Exception as e:
        if progress_callback:
            progress_callback(f"[WARN] Error checking process: {str(e)}")
    
    # Check if nginx is configured for this domain
    domain = config.get('domain')
    if domain:
        if progress_callback:
            progress_callback(f"[INFO] Checking Nginx configuration for domain: {domain}...")
        try:
            # Use sanitized domain name for config file
            domain_safe = domain.replace('.', '_').replace('*', '_')
            config_file = f"/etc/nginx/sites-available/{domain_safe}"
            enabled_file = f"/etc/nginx/sites-enabled/{domain_safe}"
            
            # Step 1: Check if config file exists
            if progress_callback:
                progress_callback(f"[INFO] Checking if config file exists: {config_file}")
            success_file, stdout_file, stderr_file = execute_ssh_command(
                host, user, port,
                f"sudo test -f {config_file} && echo 'EXISTS' || echo 'NOT_FOUND'",
                password, timeout=8
            )
            
            file_exists = success_file and 'EXISTS' in stdout_file
            
            if progress_callback:
                if file_exists:
                    progress_callback(f"[OK] Config file exists: {config_file}")
                else:
                    progress_callback(f"[WARN] Config file not found: {config_file}")
            
            # Step 2: If file exists, check if it contains the domain
            if file_exists:
                if progress_callback:
                    progress_callback(f"[INFO] Checking if config contains domain: {domain}")
                success_grep, stdout_grep, stderr_grep = execute_ssh_command(
                    host, user, port,
                    f"sudo grep -q 'server_name {domain}' {config_file} 2>&1 && echo 'FOUND' || echo 'NOT_FOUND'",
                    password, timeout=8
                )
                
                domain_found = success_grep and 'FOUND' in stdout_grep
                
                if progress_callback:
                    if domain_found:
                        progress_callback(f"[OK] Domain found in config file")
                    else:
                        progress_callback(f"[WARN] Domain not found in config file. Output: {stdout_grep if stdout_grep else stderr_grep}")
                
                # Step 3: Check if symlink exists in sites-enabled
                if progress_callback:
                    progress_callback(f"[INFO] Checking if symlink exists: {enabled_file}")
                success_link, stdout_link, stderr_link = execute_ssh_command(
                    host, user, port,
                    f"sudo test -L {enabled_file} && echo 'EXISTS' || echo 'NOT_FOUND'",
                    password, timeout=8
                )
                
                link_exists = success_link and 'EXISTS' in stdout_link
                
                if progress_callback:
                    if link_exists:
                        progress_callback(f"[OK] Symlink exists in sites-enabled")
                    else:
                        progress_callback(f"[WARN] Symlink not found in sites-enabled: {enabled_file}")
                
                # Only mark as configured if file exists, contains domain, and symlink exists
                if file_exists and domain_found and link_exists:
                    status['nginx_configured'] = True
                    if progress_callback:
                        progress_callback(f"[OK] Nginx is fully configured for domain: {domain}")
                else:
                    status['nginx_configured'] = False
                    if progress_callback:
                        progress_callback(f"[WARN] Nginx configuration incomplete for domain: {domain}")
                        progress_callback(f"[INFO] File exists: {file_exists}, Domain found: {domain_found}, Link exists: {link_exists}")
            else:
                status['nginx_configured'] = False
                if progress_callback:
                    progress_callback(f"[WARN] Nginx config file does not exist: {config_file}")
        except Exception as e:
            status['nginx_configured'] = False
            if progress_callback:
                progress_callback(f"[ERROR] Error checking Nginx configuration: {str(e)}")
    
    if progress_callback:
        progress_callback("[OK] Installation check completed")
    
    return status

def configure_services(config, progress_callback=None):
    """Configure systemd and nginx"""
    host = config['host']
    user = config['user']
    port = config.get('port', 22)
    install_dir = config.get('install_dir', '/opt/oxcookie-manager')
    domain = config.get('domain')
    app_port = config.get('app_port', 5004)
    password = config.get('password')
    
    # Check for existing installation
    if progress_callback:
        progress_callback("[INFO] Checking for existing installation...")
    
    existing_status = check_existing_installation(config, progress_callback)
    
    # Stop existing service/process if running
    if existing_status['service_running'] or existing_status['process_running']:
        if progress_callback:
            progress_callback("Stopping existing service/process...")
        
        # Stop systemd service if it exists and is running
        if existing_status['service_exists'] and existing_status['service_running']:
            execute_ssh_command(
                host, user, port,
                "sudo systemctl stop oxcookie-manager",
                password, timeout=30
            )
        
        # Kill any running processes
        if existing_status['process_running']:
            execute_ssh_command(
                host, user, port,
                f"pkill -f '{install_dir}/app.py' || true",
                password, timeout=10
            )
    
    # Create systemd service (skip if already exists)
    if existing_status['service_exists']:
        if progress_callback:
            progress_callback("Systemd service already exists, skipping creation...")
    else:
        if progress_callback:
            progress_callback("Creating systemd service...")
    
    # Ensure install_dir exists and get absolute path
    install_dir_abs = install_dir
    if not install_dir_abs.startswith('/'):
        install_dir_abs = f"/{install_dir_abs}"
    
    service_content = f"""[Unit]
Description=oXCookie Manager Flask Application
After=network.target

[Service]
Type=simple
User={user}
WorkingDirectory={install_dir_abs}
Environment="PATH=/usr/bin:/usr/local/bin:/home/{user}/.local/bin"
Environment="PYTHONPATH={install_dir_abs}"
ExecStart=/usr/bin/python3 {install_dir_abs}/app.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    
    # Upload service file using SSH instead of SCP (more reliable)
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(mode='w', suffix='.service', delete=False, encoding='utf-8') as f:
        f.write(service_content)
        temp_service = f.name
    
    try:
        # Read the service file content
        with open(temp_service, 'r', encoding='utf-8') as f:
            service_file_content = f.read()
        
        # Use SSH to create the file directly (more reliable than SCP)
        # Escape the content for shell
        import shlex
        service_escaped = service_file_content.replace('$', '\\$').replace('`', '\\`').replace('"', '\\"')
        
        # Create the service file via SSH using base64 encoding to avoid shell escaping issues
        import base64
        service_b64 = base64.b64encode(service_file_content.encode('utf-8')).decode('ascii')
        
        create_cmd = f"echo '{service_b64}' | base64 -d > /tmp/oxcookie-manager.service"
        
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            create_cmd,
            password,
            timeout=30
        )
        
        if not success:
            error_msg = stderr if stderr else stdout if stdout else "Unknown error during file creation"
            # Try alternative method if base64 fails
            print(f"[DEBUG] Base64 method failed: {error_msg}, trying heredoc method...")
            # Use heredoc with proper escaping
            service_escaped = service_file_content.replace('\\', '\\\\').replace('$', '\\$').replace('`', '\\`')
            create_cmd_alt = f"cat > /tmp/oxcookie-manager.service << 'EOFSERVICE'\n{service_file_content}\nEOFSERVICE"
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                create_cmd_alt,
                password,
                timeout=30
            )
            if not success:
                error_msg = stderr if stderr else stdout if stdout else "Unknown error during file creation"
                return False, f"Failed to create service file: {error_msg}"
        
        # Verify file was created
        verify_cmd = "test -f /tmp/oxcookie-manager.service && echo 'EXISTS' || echo 'NOT_FOUND'"
        success_verify, stdout_verify, stderr_verify = execute_ssh_command(
            host, user, port,
            verify_cmd,
            password,
            timeout=10
        )
        
        if not success_verify or 'NOT_FOUND' in stdout_verify:
            return False, f"Service file was not created successfully. Verify output: {stdout_verify}"
        
        # Move to systemd directory and reload
        if progress_callback:
            progress_callback("Installing service file to systemd...")
        
        move_cmd = "sudo mv /tmp/oxcookie-manager.service /etc/systemd/system/oxcookie-manager.service && sudo chmod 644 /etc/systemd/system/oxcookie-manager.service && sudo systemctl daemon-reload"
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            move_cmd,
            password,
            timeout=30
        )
        
        if not success:
            error_msg = stderr if stderr else stdout if stdout else "Unknown error during service installation"
            try:
                error_msg = error_msg.encode('ascii', errors='replace').decode('ascii')
            except:
                error_msg = "Failed to install service"
            
            if progress_callback:
                progress_callback(f"[ERROR] Failed to install service: {error_msg}")
            
            # Try to get more details
            debug_cmd = "sudo cat /etc/systemd/system/oxcookie-manager.service 2>&1 | head -n 10 || echo 'FILE_NOT_FOUND'"
            debug_success, debug_stdout, debug_stderr = execute_ssh_command(
                host, user, port,
                debug_cmd,
                password,
                timeout=10
            )
            debug_info = ""
            if debug_success and debug_stdout:
                try:
                    debug_info = f" (Service file: {debug_stdout.encode('ascii', errors='replace').decode('ascii')[:200]})"
                except:
                    pass
            return False, f"Failed to install systemd service: {error_msg}{debug_info}"
        
        if progress_callback:
            progress_callback("[OK] Service file installed and daemon reloaded")
    finally:
        if os.path.exists(temp_service):
            os.unlink(temp_service)
    
    # Configure firewall first (before Nginx)
    if progress_callback:
        progress_callback("[INFO] Configuring firewall (UFW) for application port...")
    
    # Check if UFW is installed
    success, stdout, stderr = execute_ssh_command(
        host, user, port,
        "which ufw || echo 'NOT_FOUND'",
        password, timeout=10
    )
    
    ufw_installed = success and 'NOT_FOUND' not in stdout
    
    if ufw_installed:
        # Allow the application port
        if progress_callback:
            progress_callback(f"[INFO] Allowing port {app_port} in firewall...")
        
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            f"sudo ufw allow {app_port}/tcp 2>&1",
            password, timeout=10
        )
        
        if success:
            if progress_callback:
                progress_callback(f"[OK] Firewall rule added for port {app_port}")
        else:
            # Check if rule already exists
            if 'already' in (stdout + stderr).lower() or 'skipping' in (stdout + stderr).lower():
                if progress_callback:
                    progress_callback(f"[OK] Port {app_port} is already allowed in firewall")
            else:
                if progress_callback:
                    progress_callback(f"[WARN] Could not add firewall rule: {stdout if stdout else stderr}")
        
        # Ensure ports 80 and 443 are allowed (for Nginx) - but don't fail if they're already allowed
        if progress_callback:
            progress_callback("[INFO] Ensuring ports 80 and 443 are allowed in firewall...")
        
        for port_num in [80, 443]:
            try:
                # Check if port is already allowed first (faster)
                check_success, check_stdout, check_stderr = execute_ssh_command(
                    host, user, port,
                    f"sudo ufw status numbered 2>&1 | grep -q '{port_num}/tcp' && echo 'ALLOWED' || echo 'NOT_ALLOWED'",
                    password, timeout=8
                )
                
                if check_success and 'ALLOWED' in check_stdout:
                    if progress_callback:
                        progress_callback(f"[OK] Port {port_num} is already allowed in firewall")
                    continue  # Skip adding if already allowed
                
                # Port not allowed, add it
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    f"sudo ufw allow {port_num}/tcp 2>&1",
                    password, timeout=8
                )
                if success:
                    if 'already' in (stdout + stderr).lower() or 'skipping' in (stdout + stderr).lower():
                        if progress_callback:
                            progress_callback(f"[OK] Port {port_num} is already allowed")
                    else:
                        if progress_callback:
                            progress_callback(f"[OK] Port {port_num} allowed in firewall")
                else:
                    if progress_callback:
                        progress_callback(f"[WARN] Could not verify/add port {port_num}: {stdout if stdout else stderr}")
            except Exception as e:
                if progress_callback:
                    progress_callback(f"[WARN] Error checking port {port_num}: {str(e)}")
                # Continue with next port
                continue
    else:
        if progress_callback:
            progress_callback("[WARN] UFW not found, skipping firewall configuration")
            progress_callback("[INFO] You may need to manually configure firewall rules for port " + str(app_port))
    
    # Configure Nginx (skip if already configured)
    if not domain:
        if progress_callback:
            progress_callback("[WARN] No domain configured, skipping Nginx configuration")
            progress_callback("[INFO] You can configure Nginx later in Step 5 (Status & Logs)")
    elif existing_status['nginx_configured']:
        if progress_callback:
            progress_callback(f"[OK] Nginx already configured for domain: {domain}, skipping...")
    else:
        if progress_callback:
            progress_callback(f"[INFO] Configuring Nginx for domain: {domain}...")
        
        # Validate domain
        if not domain or domain.strip() == '':
            if progress_callback:
                progress_callback("[ERROR] Domain is empty, cannot configure Nginx")
            return False, "Domain is required for Nginx configuration"
        
        domain = domain.strip()
        
        # Check and install nginx if needed
        if progress_callback:
            progress_callback("[INFO] Checking for nginx installation...")
        
        # Check if nginx is installed
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "which nginx || echo 'NOT_FOUND'",
            password, timeout=10
        )
        
        nginx_installed = success and 'NOT_FOUND' not in stdout
        
        if not nginx_installed:
            if progress_callback:
                progress_callback("[INFO] Nginx not found, installing nginx...")
            # Install nginx
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "sudo apt-get update -qq && sudo apt-get install -y nginx 2>&1",
                password, timeout=120
            )
            if not success:
                error_msg = stderr if stderr else stdout if stdout else "Unknown error"
                if progress_callback:
                    progress_callback(f"[ERROR] Failed to install nginx: {error_msg}")
                return False, f"Failed to install nginx: {error_msg}"
            if progress_callback:
                progress_callback("[OK] Nginx installed successfully")
        else:
            if progress_callback:
                nginx_path = stdout.strip() if stdout else "installed"
                progress_callback(f"[OK] Nginx already installed at: {nginx_path}")
        
        # Check nginx version
        if progress_callback:
            progress_callback("[INFO] Checking nginx version...")
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "sudo nginx -v 2>&1",
            password, timeout=10
        )
        if success and stdout:
            nginx_version = stdout.strip()
            if progress_callback:
                progress_callback(f"[OK] Nginx version: {nginx_version}")
        
        # Create Nginx configuration
        if progress_callback:
            progress_callback(f"[INFO] Creating Nginx configuration for domain: {domain}")
        
        # Use domain as filename (sanitize for filesystem) - do this before creating config
        domain_safe = domain.replace('.', '_').replace('*', '_')
        
        # Create Nginx configuration with specific domain (won't conflict with other apps)
        nginx_config = f"""# oXCookie Manager - {domain}
server {{
    listen 80;
    server_name {domain};

    # Logging (separate logs for this app)
    access_log /var/log/nginx/oxcookie-{domain_safe}-access.log;
    error_log /var/log/nginx/oxcookie-{domain_safe}-error.log;

    location / {{
        proxy_pass http://127.0.0.1:{app_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffer settings
        proxy_buffering off;
        proxy_request_buffering off;
    }}
}}
"""
        
        if progress_callback:
            progress_callback(f"[INFO] Nginx config content:\n{nginx_config}")
        
        # Upload Nginx configuration to VPS without using SCP (use base64 over SSH)
        try:
            if progress_callback:
                progress_callback("[INFO] Uploading Nginx configuration to VPS (via base64)...")
            
            import base64
            nginx_b64 = base64.b64encode(nginx_config.encode('utf-8')).decode('ascii')
            
            # Create temporary config file on VPS
            create_cmd = f"echo '{nginx_b64}' | base64 -d > /tmp/oxcookie-manager-nginx"
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                create_cmd,
                password,
                timeout=30
            )
            
            if not success:
                error_msg = stderr if stderr else stdout if stdout else "Unknown error during nginx config upload"
                if progress_callback:
                    progress_callback(f"[ERROR] Failed to upload Nginx config via base64: {error_msg}")
                return False, f"Failed to upload nginx config: {error_msg}"
            
            if progress_callback:
                progress_callback("[OK] Nginx configuration uploaded successfully")
            
            # Install and enable config
            if progress_callback:
                progress_callback("[INFO] Installing Nginx configuration...")
                progress_callback(f"[INFO] Config file path: /etc/nginx/sites-available/{domain_safe}")
                progress_callback(f"[INFO] Symlink path: /etc/nginx/sites-enabled/{domain_safe}")
            
            # Step 1: Move config file
            if progress_callback:
                progress_callback(f"[INFO] Moving config file to /etc/nginx/sites-available/{domain_safe}...")
            move_cmd = f"sudo mv /tmp/oxcookie-manager-nginx /etc/nginx/sites-available/{domain_safe}"
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                move_cmd,
                password,
                timeout=15
            )
            
            if not success:
                error_msg = stderr if stderr else stdout if stdout else "Unknown error"
                if progress_callback:
                    progress_callback(f"[ERROR] Failed to move Nginx config: {error_msg}")
                return False, f"Failed to move nginx config: {error_msg}"
            
            if progress_callback:
                progress_callback(f"[OK] Config file moved to /etc/nginx/sites-available/{domain_safe}")
            
            # Step 2: Verify file exists
            if progress_callback:
                progress_callback(f"[INFO] Verifying config file exists...")
            verify_cmd = f"sudo test -f /etc/nginx/sites-available/{domain_safe} && echo 'EXISTS' || echo 'NOT_FOUND'"
            success_verify, stdout_verify, stderr_verify = execute_ssh_command(
                host, user, port,
                verify_cmd,
                password,
                timeout=10
            )
            
            if success_verify and 'EXISTS' in stdout_verify:
                if progress_callback:
                    progress_callback(f"[OK] Config file verified: /etc/nginx/sites-available/{domain_safe}")
            else:
                if progress_callback:
                    progress_callback(f"[ERROR] Config file verification failed: {stdout_verify if stdout_verify else stderr_verify}")
                return False, f"Config file verification failed: {stdout_verify if stdout_verify else stderr_verify}"
            
            # Step 3: Create symlink
            if progress_callback:
                progress_callback(f"[INFO] Creating symlink in sites-enabled...")
            symlink_cmd = f"sudo ln -sf /etc/nginx/sites-available/{domain_safe} /etc/nginx/sites-enabled/{domain_safe}"
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                symlink_cmd,
                password,
                timeout=15
            )
            
            if not success:
                error_msg = stderr if stderr else stdout if stdout else "Unknown error"
                if progress_callback:
                    progress_callback(f"[ERROR] Failed to create symlink: {error_msg}")
                return False, f"Failed to create symlink: {error_msg}"
            
            if progress_callback:
                progress_callback(f"[OK] Symlink created: /etc/nginx/sites-enabled/{domain_safe}")
            
            # Step 4: Verify symlink exists
            if progress_callback:
                progress_callback(f"[INFO] Verifying symlink exists...")
            verify_link_cmd = f"sudo test -L /etc/nginx/sites-enabled/{domain_safe} && echo 'EXISTS' || echo 'NOT_FOUND'"
            success_link, stdout_link, stderr_link = execute_ssh_command(
                host, user, port,
                verify_link_cmd,
                password,
                timeout=10
            )
            
            if success_link and 'EXISTS' in stdout_link:
                if progress_callback:
                    progress_callback(f"[OK] Symlink verified: /etc/nginx/sites-enabled/{domain_safe}")
            else:
                if progress_callback:
                    progress_callback(f"[WARN] Symlink verification failed: {stdout_link if stdout_link else stderr_link}")
            
            # Step 5: Verify domain in config
            if progress_callback:
                progress_callback(f"[INFO] Verifying domain '{domain}' in config file...")
            verify_domain_cmd = f"sudo grep -q 'server_name {domain}' /etc/nginx/sites-available/{domain_safe} && echo 'FOUND' || echo 'NOT_FOUND'"
            success_domain, stdout_domain, stderr_domain = execute_ssh_command(
                host, user, port,
                verify_domain_cmd,
                password,
                timeout=10
            )
            
            if success_domain and 'FOUND' in stdout_domain:
                if progress_callback:
                    progress_callback(f"[OK] Domain '{domain}' found in config file")
            else:
                if progress_callback:
                    progress_callback(f"[WARN] Domain '{domain}' not found in config. Output: {stdout_domain if stdout_domain else stderr_domain}")
                    # Show actual config content for debugging
                    debug_cmd = f"sudo cat /etc/nginx/sites-available/{domain_safe} | head -n 20"
                    debug_success, debug_stdout, debug_stderr = execute_ssh_command(
                        host, user, port,
                        debug_cmd,
                        password,
                        timeout=10
                    )
                    if debug_success and debug_stdout:
                        if progress_callback:
                            progress_callback(f"[DEBUG] Config file content (first 20 lines):\n{debug_stdout}")
            
            if progress_callback:
                progress_callback("[OK] Nginx configuration installed and verified")
            
            # Test Nginx configuration
            if progress_callback:
                progress_callback("[INFO] Testing Nginx configuration...")
            
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "sudo nginx -t 2>&1",
                password,
                timeout=10
            )
            
            if not success:
                error_msg = stderr if stderr else stdout if stdout else "Unknown error"
                if progress_callback:
                    progress_callback(f"[ERROR] Nginx configuration test failed: {error_msg}")
                return False, f"Nginx configuration test failed: {error_msg}"
            
            if progress_callback:
                progress_callback(f"[OK] Nginx configuration test passed:\n{stdout if stdout else 'Configuration is valid'}")
            
            # Reload Nginx
            if progress_callback:
                progress_callback("[INFO] Reloading Nginx service...")
            
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "sudo systemctl reload nginx 2>&1",
                password,
                timeout=15
            )
            
            if not success:
                error_msg = stderr if stderr else stdout if stdout else "Unknown error"
                if progress_callback:
                    progress_callback(f"[ERROR] Failed to reload Nginx: {error_msg}")
                return False, f"Failed to reload nginx: {error_msg}"
            
            if progress_callback:
                progress_callback("[OK] Nginx reloaded successfully")
            
            # Verify Nginx is running
            if progress_callback:
                progress_callback("[INFO] Verifying Nginx is running...")
            
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "sudo systemctl is-active nginx 2>&1",
                password,
                timeout=10
            )
            
            if success and 'active' in stdout.lower():
                if progress_callback:
                    progress_callback("[OK] Nginx is running")
            else:
                if progress_callback:
                    progress_callback("[WARN] Nginx status check returned: " + (stdout if stdout else stderr))
            
            # Verify the configuration file exists and contains the domain
            if progress_callback:
                progress_callback(f"[INFO] Verifying Nginx configuration for {domain}...")
            
            verify_cmd = f"sudo test -f /etc/nginx/sites-available/{domain_safe} && sudo grep -q '{domain}' /etc/nginx/sites-available/{domain_safe} && echo 'VERIFIED' || echo 'NOT_VERIFIED'"
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                verify_cmd,
                password,
                timeout=10
            )
            
            if success and 'VERIFIED' in stdout:
                if progress_callback:
                    progress_callback(f"[OK] Nginx configuration verified for domain: {domain}")
                    progress_callback(f"[INFO] Configuration file: /etc/nginx/sites-available/{domain_safe}")
                    progress_callback(f"[INFO] Symlink: /etc/nginx/sites-enabled/{domain_safe}")
            else:
                if progress_callback:
                    progress_callback(f"[WARN] Could not verify Nginx configuration: {stdout if stdout else stderr}")
        except Exception as e:
            # Catch any unexpected errors during Nginx configuration
            if progress_callback:
                progress_callback(f"[ERROR] Unexpected error during Nginx configuration: {str(e)}")
            return False, f"Unexpected error during Nginx configuration: {str(e)}"
    
    # Setup SSL certificate if possible (Let's Encrypt via certbot)
    if domain and password:
        ssl_success, ssl_message = setup_ssl(config, progress_callback)
        if not ssl_success:
            # Don't hard-fail installation on SSL issues, but log them
            if progress_callback:
                progress_callback(f"[WARN] SSL setup issue: {ssl_message}")
        else:
            if progress_callback:
                progress_callback(f"[OK] SSL setup completed: {ssl_message}")
    
    # Start service (skip if already running)
    if existing_status['service_running']:
        if progress_callback:
            progress_callback("Service already running, skipping start...")
        return True, "Service already running"
    else:
        if progress_callback:
            progress_callback("Starting application service...")
        
        # Enable service (skip if already enabled)
        if not existing_status['service_enabled']:
            if progress_callback:
                progress_callback("Enabling service to start on boot...")
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "sudo systemctl enable oxcookie-manager",
                password,
                timeout=30
            )
            
            if not success:
                # Get detailed error
                error_msg = stderr if stderr else stdout if stdout else "Unknown error"
                try:
                    error_msg = error_msg.encode('ascii', errors='replace').decode('ascii')
                except:
                    error_msg = "Failed to enable service (encoding error)"
                if progress_callback:
                    progress_callback(f"[ERROR] Failed to enable service: {error_msg}")
                return False, f"Failed to enable service: {error_msg}"
            if progress_callback:
                progress_callback("[OK] Service enabled successfully")
        
        # Start service
        if progress_callback:
            progress_callback("Starting service...")
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "sudo systemctl start oxcookie-manager",
            password,
            timeout=30
        )
        
        if not success:
            error_msg = stderr if stderr else stdout if stdout else "Unknown error"
            try:
                error_msg = error_msg.encode('ascii', errors='replace').decode('ascii')
            except:
                error_msg = "Service start failed"
            if progress_callback:
                progress_callback(f"[ERROR] Service start command failed: {error_msg}")
        
        # Wait for service to activate (up to 30 seconds)
        if progress_callback:
            progress_callback("Waiting for service to activate...")
        
        import time
        max_wait = 30
        wait_interval = 2
        waited = 0
        service_active = False
        
        while waited < max_wait:
            # Check service status
            status_success, status_stdout, status_stderr = execute_ssh_command(
                host, user, port,
                "sudo systemctl is-active oxcookie-manager 2>&1",
                password,
                timeout=5
            )
            
            if status_success:
                status_output = status_stdout.lower() if status_stdout else ""
                if 'active' in status_output:
                    service_active = True
                    if progress_callback:
                        progress_callback(f"[OK] Service is active (waited {waited}s)")
                    break
                elif 'activating' in status_output or 'starting' in status_output:
                    if progress_callback:
                        progress_callback(f"[INFO] Service is activating... (waited {waited}s)")
                elif 'failed' in status_output or 'inactive' in status_output:
                    # Service failed to start, get detailed logs
                    if progress_callback:
                        progress_callback("[ERROR] Service failed to start, checking logs...")
                    
                    # Get service status with details
                    log_success, log_stdout, log_stderr = execute_ssh_command(
                        host, user, port,
                        "sudo systemctl status oxcookie-manager --no-pager -l 2>&1 | head -n 20",
                        password,
                        timeout=10
                    )
                    
                    # Get journal logs
                    journal_success, journal_stdout, journal_stderr = execute_ssh_command(
                        host, user, port,
                        "sudo journalctl -u oxcookie-manager --no-pager -n 20 2>&1",
                        password,
                        timeout=10
                    )
                    
                    error_details = []
                    if log_success and log_stdout:
                        try:
                            error_details.append(f"Status: {log_stdout.encode('ascii', errors='replace').decode('ascii')[:300]}")
                        except:
                            pass
                    if journal_success and journal_stdout:
                        try:
                            error_details.append(f"Logs: {journal_stdout.encode('ascii', errors='replace').decode('ascii')[:300]}")
                        except:
                            pass
                    
                    error_msg = f"Service failed to start: {status_output}"
                    if error_details:
                        error_msg += f"\nDetails: {' | '.join(error_details)}"
                    
                    if progress_callback:
                        progress_callback(f"[ERROR] {error_msg}")
                    return False, error_msg
            
            time.sleep(wait_interval)
            waited += wait_interval
        
        if not service_active:
            # Get final status and logs
            if progress_callback:
                progress_callback("[ERROR] Service did not become active within timeout, checking status...")
            
            # Get detailed status
            final_status_success, final_status_stdout, final_status_stderr = execute_ssh_command(
                host, user, port,
                "sudo systemctl status oxcookie-manager --no-pager -l 2>&1 | head -n 30",
                password,
                timeout=10
            )
            
            # Get journal logs
            final_journal_success, final_journal_stdout, final_journal_stderr = execute_ssh_command(
                host, user, port,
                "sudo journalctl -u oxcookie-manager --no-pager -n 30 2>&1",
                password,
                timeout=10
            )
            
            error_details = []
            if final_status_success and final_status_stdout:
                try:
                    status_info = final_status_stdout.encode('ascii', errors='replace').decode('ascii')
                    error_details.append(f"Status: {status_info[:400]}")
                except:
                    pass
            if final_journal_success and final_journal_stdout:
                try:
                    journal_info = final_journal_stdout.encode('ascii', errors='replace').decode('ascii')
                    error_details.append(f"Logs: {journal_info[:400]}")
                except:
                    pass
            
            error_msg = f"Service did not become active within {max_wait} seconds"
            if error_details:
                error_msg += f"\n{' | '.join(error_details)}"
            
            if progress_callback:
                progress_callback(f"[ERROR] {error_msg}")
            return False, error_msg
        
        # Final verification
        if progress_callback:
            progress_callback("Verifying service is running...")
        
        verify_success, verify_stdout, verify_stderr = execute_ssh_command(
            host, user, port,
            "sudo systemctl is-active oxcookie-manager 2>&1",
            password,
            timeout=5
        )
        
        if verify_success and verify_stdout and 'active' in verify_stdout.lower():
            if progress_callback:
                progress_callback("[OK] Service verified as active")
            return True, "Services configured and started"
        else:
            verify_msg = verify_stdout.encode('ascii', errors='replace').decode('ascii') if verify_stdout else "unknown"
            if progress_callback:
                progress_callback(f"[WARN] Final verification returned: {verify_msg}")
            # Even if verification fails, if we got here the service should be running
            return True, f"Service started (verification: {verify_msg})"
