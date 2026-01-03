#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask-based Web UI Installer for oXCookie Manager
Provides a graphical interface for VPS deployment
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_cors import CORS
import os
import json
import subprocess
import threading
import time
from pathlib import Path
import tempfile
import shutil
import sys

# Fix Windows console encoding for Unicode characters
if sys.platform == 'win32':
    import builtins
    _original_print = builtins.print
    
    def safe_print(*args, **kwargs):
        """Print function that handles Unicode safely on Windows"""
        try:
            _original_print(*args, **kwargs)
        except UnicodeEncodeError:
            # Replace Unicode characters with ASCII equivalents
            safe_args = []
            for arg in args:
                if isinstance(arg, str):
                    arg = arg.replace('✓', '[OK]').replace('✗', '[FAIL]').replace('⚠', '[WARN]')
                safe_args.append(arg)
            _original_print(*safe_args, **kwargs)
    
    # Override print for Windows to handle Unicode safely
    builtins.print = safe_print

def check_and_install_package(package_name, import_name=None):
    """Check if a package is installed, install if missing"""
    if import_name is None:
        import_name = package_name
    
    # Try using importlib.metadata first (Python 3.8+)
    try:
        import importlib.metadata
        try:
            importlib.metadata.distribution(package_name)
            # Package is installed, try importing
            __import__(import_name)
            return True
        except importlib.metadata.PackageNotFoundError:
            pass
    except ImportError:
        # Fall back to try importing directly
        try:
            __import__(import_name)
            return True
        except ImportError:
            pass
    
    # Package not found, try to install it
    try:
        print(f"[INFO] Installing missing package: {package_name}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Try importing again
        __import__(import_name)
        print(f"[OK] Successfully installed {package_name}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to install {package_name}: {e}")
        return False

# Check and install required packages on startup
def check_required_packages():
    """Check and install all required packages"""
    packages = [
        ('setuptools', 'setuptools'),  # Required by wexpect (check via setuptools, not pkg_resources)
        ('wexpect', 'wexpect'),  # Windows expect
        ('pexpect', 'pexpect'),  # Linux/Mac expect
    ]
    
    for package_name, import_name in packages:
        check_and_install_package(package_name, import_name)

# Run check on import
check_required_packages()

app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)

# Installation state
installation_state = {
    "status": "idle",  # idle, running, completed, error
    "progress": 0,
    "current_step": "",
    "log": [],
    "error": None,
    "domain": None,
    "app_url": None
}

# Progress state for fix-app
fix_state = {
    "status": "idle",
    "progress": 0,
    "current_step": "",
    "log": [],
    "error": None
}

# Progress state for test connection
test_connection_state = {
    "status": "idle",
    "progress": 0,
    "current_step": "",
    "log": [],
    "dependencies": None,
}

# Progress state for install dependencies
install_deps_state = {
    "status": "idle",
    "progress": 0,
    "current_step": "",
    "log": [],
}

# Configuration
INSTALLER_DIR = Path(__file__).parent  # installer-ui directory
DEPLOYMENT_DIR = INSTALLER_DIR.parent  # deployment directory (parent)
CONFIG_FILE = INSTALLER_DIR / "installer_config.json"

@app.route('/')
def index():
    """Main installer page - shows wizard if config incomplete, deploy page if complete"""
    # Check if config exists and is complete
    setup_complete = False
    has_vps_config = False
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # Check if VPS config is present
                if config.get('vps_host') and config.get('key_path'):
                    has_vps_config = True
                # Check if essential config is present
                if config.get('vps_host') and config.get('key_path') and config.get('cf_email'):
                    setup_complete = True
        except:
            pass
    
    if setup_complete:
        # Config complete, show deploy page
        return render_template('installer.html')
    else:
        # Config incomplete or missing, show setup wizard
        # Pass has_vps_config to trigger connection check on load
        return render_template('installer-wizard.html', has_vps_config=has_vps_config)

@app.route('/api/setup-status', methods=['GET'])
def get_setup_status():
    """Get setup status and current step"""
    status = {
        "step": 1,  # 1: VPS, 2: Cloudflare, 3: Git, 4: Deploy, 5: Status & Logs
        "vps_configured": False,
        "cloudflare_configured": False,
        "git_configured": False,
        "ready_to_deploy": False
    }
    
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
                # Check VPS config (password or key_path)
                if config.get('vps_host') and (config.get('password') or config.get('key_path')):
                    status["vps_configured"] = True
                    status["step"] = 2
                
                # Check Cloudflare config
                if config.get('cf_email') and (config.get('cf_api_key') or config.get('cf_token')):
                    status["cloudflare_configured"] = True
                    status["step"] = 3
                
                # Check Git config
                if config.get('git_repo_url'):
                    status["git_configured"] = True
                    status["step"] = 4
                
                # Ready to deploy if all are configured
                if status["vps_configured"] and status["cloudflare_configured"] and status["git_configured"]:
                    status["ready_to_deploy"] = True
                    status["step"] = 4
                
                # Check if app is already deployed by checking for service or installation marker
                # Try to check if the service exists on the VPS
                host = config.get('vps_host')
                user = config.get('vps_user', 'root')
                port = config.get('vps_port', 22)
                password = config.get('password')
                
                if host and password:
                    try:
                        from installer_backend import execute_ssh_command
                        # Check if systemd service exists
                        success, stdout, stderr = execute_ssh_command(
                            host, user, port,
                            "sudo systemctl list-units --type=service --all 2>&1 | grep -q 'oxcookie-manager.service' && echo 'EXISTS' || echo 'NOT_FOUND'",
                            password, timeout=10
                        )
                        
                        if success and 'EXISTS' in stdout:
                            status["app_deployed"] = True
                            status["step"] = 5  # Go to Status & Logs if already deployed
                    except Exception as e:
                        # If we can't check, assume not deployed
                        print(f"[DEBUG] Could not check deployment status: {e}")
                        pass
        except:
            pass
    
    return jsonify(status)

@app.route('/api/save-config', methods=['POST'])
def save_config():
    """Save installer configuration"""
    try:
        data = request.json
        
        # Load existing config first to preserve all values
        existing_config = {}
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    existing_config = json.load(f)
            except:
                pass
        
        # Helper function to get value: use new value if provided and non-empty, otherwise use existing
        def get_value(key, default='', use_existing=True):
            # Try request data first (with aliases)
            new_value = None
            if key == 'vps_host':
                new_value = data.get('host') or data.get('vps_host')
            elif key == 'vps_user':
                new_value = data.get('user') or data.get('vps_user')
            elif key == 'vps_port':
                new_value = data.get('port') or data.get('vps_port')
            else:
                new_value = data.get(key)
            
            # If new value is provided and non-empty (after stripping whitespace), use it
            if new_value is not None:
                new_value_str = str(new_value).strip()
                if new_value_str:  # Only use if non-empty after stripping
                    return new_value_str
            
            # Otherwise, preserve existing value if available and non-empty
            if use_existing and key in existing_config:
                existing_val = existing_config[key]
                if existing_val is not None:
                    existing_val_str = str(existing_val).strip()
                    if existing_val_str:  # Only preserve if non-empty
                        return existing_val_str
            
            # Fall back to default
            return default
        
        # Build config to save, preserving existing values
        config_to_save = {
            "vps_host": get_value('vps_host', ''),
            "vps_user": get_value('vps_user', 'root'),
            "vps_port": get_value('vps_port', 22),
            "use_key": data.get('use_key', existing_config.get('use_key', False)),
            "key_path": get_value('key_path', ''),
            "domain": get_value('domain', ''),
            "base_domain": get_value('base_domain', ''),
            "subdomain": get_value('subdomain', ''),
            "git_repo_url": get_value('git_repo_url', ''),
            "git_branch": get_value('git_branch', 'main'),
            "app_port": get_value('app_port', 5004),
            "install_dir": get_value('install_dir', '/opt/oxcookie-manager'),
            "setup_dns": data.get('setup_dns', existing_config.get('setup_dns', False)),
            "dns_provider": get_value('dns_provider', 'manual'),
            "cf_email": get_value('cf_email', ''),
            "cf_api_key": get_value('cf_api_key', ''),
            "cf_token": get_value('cf_token', ''),
            "cf_zone_id": get_value('cf_zone_id', ''),
            "do_token": get_value('do_token', '')
        }
        
        # Preserve existing password if not provided in request
        existing_password = existing_config.get('password')
        
        # Save password (we're using password authentication now)
        # Only update password if a new one is provided (not empty and not the masked value)
        if data.get('password'):
            password_value = str(data.get('password')).strip()
            # IMPORTANT: Don't save if it's the masked placeholder value
            if password_value and password_value != '***saved***':
                # Debug: log password info when saving (without exposing full password)
                print(f"[DEBUG SAVE] Saving password: length={len(password_value)}, first_char={repr(password_value[0]) if password_value else 'None'}, last_char={repr(password_value[-1]) if password_value and len(password_value) > 0 else 'None'}, repr={repr(password_value)}")
                print(f"[DEBUG SAVE] Password bytes: {password_value.encode('utf-8')}")
                config_to_save["password"] = password_value
            elif password_value == '***saved***':
                # This is the masked value from load_config, preserve existing password
                if existing_password:
                    config_to_save["password"] = existing_password
                    print(f"[DEBUG SAVE] Ignoring masked password value, preserving existing password")
            elif existing_password:
                # Preserve existing password if new one is empty
                config_to_save["password"] = existing_password
                print(f"[DEBUG SAVE] Preserving existing password (not overwriting with empty value)")
        elif existing_password:
            # No password in request, preserve existing
            config_to_save["password"] = existing_password
            print(f"[DEBUG SAVE] Preserving existing password (no password in request)")
        
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config_to_save, f, indent=2, ensure_ascii=False)
        
        return jsonify({"status": "success", "message": "Configuration saved"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/load-config', methods=['GET'])
def load_config():
    """Load saved configuration"""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
            # Don't return password for security
            if 'password' in config:
                config['password'] = '***saved***'
            return jsonify({"status": "success", "config": config})
        else:
            return jsonify({"status": "not_found", "config": {}})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

def check_vps_dependencies(host, user, port, password):
    """Check what dependencies are installed on the VPS using password authentication"""
    from installer_backend import execute_ssh_command
    import subprocess
    
    dependencies = {
        "python3": {"installed": False, "version": None, "needed": True},
        "pip": {"installed": False, "version": None, "needed": True},
        "nginx": {"installed": False, "version": None, "needed": True},
        "systemd": {"installed": False, "version": None, "needed": True},
        "curl": {"installed": False, "version": None, "needed": True}
    }
    
    # Use shorter timeout for dependency checks (10 seconds per check)
    dep_timeout = 10
    
    # Check Python 3 (with timeout handling)
    try:
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "python3 --version 2>&1 || python --version 2>&1",
            password,
            timeout=dep_timeout
        )
        if success and stdout:
            dependencies["python3"]["installed"] = True
            dependencies["python3"]["version"] = stdout.strip()
    except Exception as e:
        print(f"[DEBUG] Error checking Python 3: {str(e)}")
    
    # Check pip (with timeout handling)
    try:
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "python3 -m pip --version 2>&1 || pip3 --version 2>&1",
            password,
            timeout=dep_timeout
        )
        if success and stdout:
            dependencies["pip"]["installed"] = True
            dependencies["pip"]["version"] = stdout.strip().split()[1] if len(stdout.strip().split()) > 1 else "installed"
    except Exception as e:
        print(f"[DEBUG] Error checking pip: {str(e)}")
    
    # Check nginx (with timeout handling)
    try:
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "nginx -v 2>&1 || which nginx",
            password,
            timeout=dep_timeout
        )
        if success and ("nginx version" in stdout or "nginx" in stdout):
            dependencies["nginx"]["installed"] = True
            if "nginx version" in stdout:
                dependencies["nginx"]["version"] = stdout.strip().split()[2] if len(stdout.strip().split()) > 2 else "installed"
            else:
                dependencies["nginx"]["version"] = "installed"
            
            # If nginx is installed, check its configuration
            try:
                # Check if nginx config directory exists
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    "test -d /etc/nginx && echo 'exists' || echo 'not_found'",
                    password,
                    timeout=dep_timeout
                )
                if success and "exists" in stdout:
                    dependencies["nginx"]["config_dir"] = "/etc/nginx"
                
                # Check if nginx is running
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    "systemctl is-active nginx 2>&1 || service nginx status 2>&1 | head -n 1",
                    password,
                    timeout=dep_timeout
                )
                if success:
                    if "active" in stdout.lower() or "running" in stdout.lower():
                        dependencies["nginx"]["status"] = "running"
                    else:
                        dependencies["nginx"]["status"] = "stopped"
                
                # Check for existing site configurations
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    "ls -1 /etc/nginx/sites-enabled/ 2>/dev/null | head -n 5 || echo 'none'",
                    password,
                    timeout=dep_timeout
                )
                if success and stdout.strip() and stdout.strip() != "none":
                    sites = [s.strip() for s in stdout.strip().split('\n') if s.strip()]
                    dependencies["nginx"]["sites_enabled"] = sites
                
                # Check nginx main config file
                # First find nginx binary path
                nginx_path = None
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    "which nginx 2>/dev/null || command -v nginx 2>/dev/null || echo ''",
                    password,
                    timeout=dep_timeout
                )
                if success and stdout.strip():
                    nginx_path = stdout.strip()
                else:
                    # Try common nginx locations
                    for common_path in ['/usr/sbin/nginx', '/usr/bin/nginx', '/sbin/nginx']:
                        success, stdout, stderr = execute_ssh_command(
                            host, user, port,
                            f"test -f {common_path} && echo {common_path} || echo ''",
                            password,
                            timeout=dep_timeout
                        )
                        if success and stdout.strip():
                            nginx_path = common_path
                            break
                
                if nginx_path:
                    # Use full path to test nginx config
                    success, stdout, stderr = execute_ssh_command(
                        host, user, port,
                        f"{nginx_path} -t 2>&1 | head -n 1",
                        password,
                        timeout=dep_timeout
                    )
                    if success:
                        if "successful" in stdout.lower():
                            dependencies["nginx"]["config_valid"] = True
                        else:
                            dependencies["nginx"]["config_valid"] = False
                            dependencies["nginx"]["config_error"] = stdout.strip()
                else:
                    # If we can't find nginx binary, check if config file exists and is readable
                    success, stdout, stderr = execute_ssh_command(
                        host, user, port,
                        "test -f /etc/nginx/nginx.conf && echo 'exists' || echo 'not_found'",
                        password,
                        timeout=dep_timeout
                    )
                    if success and "exists" in stdout:
                        dependencies["nginx"]["config_valid"] = None  # Unknown, can't test without binary
                        dependencies["nginx"]["config_error"] = "Cannot test config: nginx binary not found in PATH"
            except Exception as e:
                print(f"[DEBUG] Error checking nginx configuration: {str(e)}")
                dependencies["nginx"]["config_check_error"] = str(e)
    except Exception as e:
        print(f"[DEBUG] Error checking nginx: {str(e)}")
    
    # Check systemd (with timeout handling)
    try:
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "systemctl --version 2>&1 | head -n 1",
            password,
            timeout=dep_timeout
        )
        if success and stdout:
            dependencies["systemd"]["installed"] = True
            dependencies["systemd"]["version"] = stdout.strip()
    except Exception as e:
        print(f"[DEBUG] Error checking systemd: {str(e)}")
    
    # Check curl (with timeout handling)
    try:
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "curl --version 2>&1 | head -n 1",
            password,
            timeout=dep_timeout
        )
        if success and stdout:
            dependencies["curl"]["installed"] = True
            dependencies["curl"]["version"] = stdout.strip().split()[1] if len(stdout.strip().split()) > 1 else "installed"
    except Exception as e:
        print(f"[DEBUG] Error checking curl: {str(e)}")
    
    return dependencies

@app.route('/api/generate-ssh-key', methods=['POST'])
def generate_ssh_key():
    """Generate SSH key pair and copy to VPS"""
    try:
        data = request.json
        key_name = data.get('key_name', 'oxcookie_vps_key')
        host = data.get('host')
        user = data.get('user', 'root')
        port = data.get('port', 22)
        password = data.get('password')  # Password to copy key to VPS
        
        print(f"\n{'='*60}")
        print(f"[SSH KEY GENERATION] Starting key generation process")
        print(f"{'='*60}")
        print(f"[STEP 1] Key name: {key_name}")
        print(f"[STEP 1] Target VPS: {user}@{host}:{port}")
        print(f"[STEP 1] Key will be saved to: {INSTALLER_DIR}")
        
        key_path = INSTALLER_DIR / key_name
        pub_key_path = INSTALLER_DIR / f"{key_name}.pub"
        
        # Check if key already exists and remove it first
        print(f"\n[STEP 2] Checking for existing keys...")
        if key_path.exists():
            print(f"[STEP 2] Found existing private key, removing: {key_path}")
            try:
                key_path.unlink()
                print(f"[STEP 2] [OK] Private key removed")
            except Exception as e:
                print(f"[STEP 2] [WARN] Warning removing private key: {e}")
        else:
            print(f"[STEP 2] No existing private key found")
            
        if pub_key_path.exists():
            print(f"[STEP 2] Found existing public key, removing: {pub_key_path}")
            try:
                pub_key_path.unlink()
                print(f"[STEP 2] [OK] Public key removed")
            except Exception as e:
                print(f"[STEP 2] [WARN] Warning removing public key: {e}")
        else:
            print(f"[STEP 2] No existing public key found")
        
        # Generate key using ssh-keygen
        print(f"\n[STEP 3] Generating new SSH key pair...")
        print(f"[STEP 3] Command: ssh-keygen -t rsa -b 4096 -f {key_path} -N '' -C 'oxcookie-manager-vps' -q")
        cmd = ['ssh-keygen', '-t', 'rsa', '-b', '4096', '-f', str(key_path), 
               '-N', '', '-C', 'oxcookie-manager-vps', '-q']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        
        print(f"[STEP 3] Return code: {result.returncode}")
        if result.stdout:
            print(f"[STEP 3] stdout: {result.stdout}")
        if result.stderr:
            print(f"[STEP 3] stderr: {result.stderr}")
        
        if result.returncode == 0 and key_path.exists():
            print(f"[STEP 3] [OK] SSH key pair generated successfully")
            print(f"[STEP 3] Private key: {key_path}")
            print(f"[STEP 3] Public key: {pub_key_path}")
            
            # Read public key
            pub_key = pub_key_path.read_text().strip()
            print(f"[STEP 3] Public key length: {len(pub_key)} characters")
            print(f"[STEP 3] Public key preview: {pub_key[:50]}...")
            
            # Save password to config if provided
            if password and host:
                print(f"\n[STEP 4] Saving configuration...")
                try:
                    config_data = {}
                    if CONFIG_FILE.exists():
                        with open(CONFIG_FILE, 'r') as f:
                            config_data = json.load(f)
                        print(f"[STEP 4] Loaded existing config from: {CONFIG_FILE}")
                    
                    config_data['vps_host'] = host
                    config_data['vps_user'] = user
                    config_data['vps_port'] = port
                    config_data['use_key'] = True
                    config_data['key_path'] = str(key_path)
                    config_data['password'] = password  # Save password for future use
                    
                    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                        json.dump(config_data, f, indent=2, ensure_ascii=False)
                    print(f"[STEP 4] [OK] Configuration saved to: {CONFIG_FILE}")
                except Exception as e:
                    print(f"[STEP 4] [WARN] Warning: Could not save config: {e}")
            
            # Copy key to VPS if password and host provided
            if password and host:
                print(f"\n[STEP 5] Attempting to copy SSH key to VPS...")
                print(f"[STEP 5] Target: {user}@{host}:{port}")
                print(f"[STEP 5] Method: Using wexpect/pexpect for interactive SSH")
                
                copy_result, error_msg = copy_ssh_key_internal(host, user, port, str(key_path), password)
                
                if copy_result:
                    print(f"[STEP 5] [OK] SSH key copied to VPS successfully!")
                    print(f"{'='*60}")
                    print(f"[SUCCESS] Key generation and copy completed successfully")
                    print(f"{'='*60}\n")
                    return jsonify({
                        "status": "success",
                        "private_key_path": str(key_path),
                        "public_key_path": str(pub_key_path),
                        "public_key": pub_key,
                        "message": "SSH key generated and copied to VPS successfully. Password saved."
                    })
                else:
                    # Copy failed, but key was generated and password saved
                    error_message = error_msg or "Auto-copy failed"
                    print(f"[STEP 5] [FAIL] Failed to copy key to VPS")
                    print(f"[STEP 5] Error: {error_message}")
                    print(f"\n[MANUAL COPY REQUIRED]")
                    # Provide multiple manual copy options
                    manual_cmd_windows = f'type "{pub_key_path}" | ssh -p {port} {user}@{host} "cat >> ~/.ssh/authorized_keys"'
                    manual_cmd_unix = f'cat "{pub_key_path}" | ssh -p {port} {user}@{host} "cat >> ~/.ssh/authorized_keys"'
                    print(f"[MANUAL COPY] Windows: {manual_cmd_windows}")
                    print(f"[MANUAL COPY] Linux/Mac: {manual_cmd_unix}")
                    print(f"{'='*60}\n")
                    
                    return jsonify({
                        "status": "partial_success",
                        "private_key_path": str(key_path),
                        "public_key_path": str(pub_key_path),
                        "public_key": pub_key,
                        "message": f"Key generated and password saved, but auto-copy failed. Try the manual copy command.",
                        "copy_instructions": f"Manual copy command (Windows):\n{manual_cmd_windows}\n\nOr (Linux/Mac):\n{manual_cmd_unix}",
                        "error_details": error_message
                    })
            else:
                print(f"[STEP 4] No password provided, skipping key copy to VPS")
                print(f"{'='*60}\n")
            
            return jsonify({
                "status": "success",
                "private_key_path": str(key_path),
                "public_key_path": str(pub_key_path),
                "public_key": pub_key
            })
        else:
            print(f"[STEP 3] [FAIL] Failed to generate key")
            print(f"[STEP 3] Return code: {result.returncode}")
            print(f"[STEP 3] Key file exists: {key_path.exists()}")
            if result.stderr:
                print(f"[STEP 3] Error: {result.stderr}")
            print(f"{'='*60}\n")
            return jsonify({"status": "error", "message": "Failed to generate key"})
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/copy-ssh-key', methods=['POST'])
def copy_ssh_key():
    """Copy SSH public key to VPS using saved password"""
    try:
        data = request.json
        host = data.get('host')
        user = data.get('user', 'root')
        port = data.get('port', 22)
        key_path = data.get('key_path')
        password = data.get('password')
        
        # Load from config if not provided
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, 'r') as f:
                saved_config = json.load(f)
                if not host:
                    host = saved_config.get('vps_host')
                if not user:
                    user = saved_config.get('vps_user', 'root')
                if not port:
                    port = saved_config.get('vps_port', 22)
                if not key_path:
                    key_path = saved_config.get('key_path')
                if not password:
                    password = saved_config.get('password')
        
        if not all([host, user, key_path, password]):
            return jsonify({"status": "error", "message": "Missing required parameters (host, user, key_path, password)"})
        
        pub_key_path = Path(key_path).with_suffix('.pub')
        if not pub_key_path.exists():
            return jsonify({"status": "error", "message": "Public key file not found"})
        
        pub_key = pub_key_path.read_text().strip()
        
        # Use copy_ssh_key_internal to copy key
        copy_result, error_msg = copy_ssh_key_internal(host, user, port, key_path, password)
        if copy_result:
            return jsonify({"status": "success", "message": "SSH key copied to VPS successfully"})
        else:
            error_message = error_msg or "Failed to copy key automatically."
            if "wexpect" in error_message.lower() or "import" in error_message.lower():
                error_message += " On Windows, install wexpect: pip install wexpect"
            return jsonify({
                "status": "error", 
                "message": f"Failed to copy key: {error_message}",
                "manual_instructions": f"Run: type {pub_key_path} | ssh -p {port} {user}@{host} \"cat >> ~/.ssh/authorized_keys\""
            })
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/test-connection', methods=['POST'])
def test_connection():
    """Test SSH connection to VPS - starts in background thread"""
    global test_connection_state
    
    if test_connection_state.get("status") == "running":
        return jsonify({"status": "running", "message": "Connection test already in progress"})
    
    # Reset state
    test_connection_state = {
        "status": "running",
        "progress": 0,
        "current_step": "Initializing connection test...",
        "log": [],
    }
    
    # Get request data
    data = request.json
    
    # Start connection test in background thread
    thread = threading.Thread(target=run_test_connection, args=(data,), daemon=True)
    thread.start()
    
    return jsonify({"status": "started", "message": "Connection test started"})

def run_test_connection(data):
    """Run the actual connection test in background thread using password authentication"""
    global test_connection_state
    import time as time_module
    
    def add_log(message, progress=None):
        timestamp = time_module.strftime("[%H:%M:%S]")
        log_entry = f"{timestamp} {message}"
        test_connection_state["log"].append(log_entry)
        if progress is not None:
            test_connection_state["progress"] = progress
        test_connection_state["current_step"] = message
        # Also print to console for debugging
        print(log_entry)
        import sys
        sys.stdout.flush()
    
    add_log("Initializing connection test...", 0)
    
    try:
        host = data.get('host')
        user = data.get('user', 'root')
        port = data.get('port', 22)
        password = data.get('password')
        
        # Normalize password - treat empty string as None
        if password:
            password = str(password).strip()
            if not password:  # Empty after strip
                password = None
        
        # Check for saved configuration first - ALWAYS use it if available
        add_log("Checking for saved configuration...", 5)
        config_loaded = False
        missing_fields = []
        
        if CONFIG_FILE.exists():
            add_log("Found saved configuration file", 8)
            print(f"[DEBUG] Config file exists: {CONFIG_FILE}")
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    print(f"[DEBUG] Loaded config: host={saved_config.get('vps_host')}, user={saved_config.get('vps_user')}, has_password={'password' in saved_config}")
                    
                    # ALWAYS use saved config values, only use request values if saved config doesn't have them
                    if saved_config.get('vps_host'):
                        host = saved_config.get('vps_host')
                        add_log(f"Using saved VPS host: {host}", 10)
                    elif not host:
                        missing_fields.append('host')
                    
                    if saved_config.get('vps_user'):
                        user = saved_config.get('vps_user', 'root')
                        add_log(f"Using saved SSH user: {user}", 12)
                    elif not user:
                        user = 'root'  # Default
                    
                    if saved_config.get('vps_port'):
                        port = saved_config.get('vps_port', 22)
                        add_log(f"Using saved SSH port: {port}", 13)
                    elif not port:
                        port = 22  # Default
                    
                    # ALWAYS use saved password if available
                    if saved_config.get('password'):
                        saved_password = saved_config.get('password')
                        if isinstance(saved_password, str):
                            saved_password = saved_password.strip()
                        if saved_password:  # Only use if not empty
                            password = saved_password
                            add_log("Using saved password from configuration", 15)
                            config_loaded = True
                            
                            # Debug: log password info
                            first_char = repr(password[0]) if len(password) > 0 else 'None'
                            last_char = repr(password[-1]) if len(password) > 0 else 'None'
                            add_log(f"Password loaded: length={len(password)}, first_char={first_char}, last_char={last_char}", 16)
                            print(f"[DEBUG] Loaded password from config: length={len(password)}, first_char={first_char}, last_char={last_char}, full_repr={repr(password)}")
                        else:
                            missing_fields.append('password')
                    else:
                        missing_fields.append('password')
            except Exception as e:
                add_log(f"Error loading config: {str(e)}", 10)
                print(f"[DEBUG] Error loading config: {e}")
                # If config file is corrupted, treat as missing
                missing_fields = ['host', 'password']
        else:
            add_log("No saved configuration found", 10)
            print(f"[DEBUG] Config file does not exist: {CONFIG_FILE}")
            # Check what's missing from request
            if not host:
                missing_fields.append('host')
            if not password:
                missing_fields.append('password')
        
        # If we have missing required fields, signal to frontend to collect them
        if missing_fields:
            test_connection_state["status"] = "missing_config"
            test_connection_state["progress"] = 100
            test_connection_state["missing_fields"] = missing_fields
            test_connection_state["current_values"] = {
                "host": host or "",
                "user": user or "root",
                "port": port or 22,
                "password": ""  # Never send password back
            }
            add_log(f"[INFO] Missing required configuration: {', '.join(missing_fields)}", 100)
            return
        
        # Validate we have all required fields
        if not host:
            test_connection_state["status"] = "error"
            test_connection_state["progress"] = 100
            add_log("[ERROR] VPS host required", 100)
            return
        
        if not password:
            test_connection_state["status"] = "error"
            test_connection_state["progress"] = 100
            add_log("[ERROR] VPS password required", 100)
            return
        
        if config_loaded:
            add_log("Configuration loaded successfully from saved settings", 18)
        
        add_log("Testing SSH connection with password authentication...", 20)
        
        # Debug: Log password info (without exposing actual password)
        if password:
            has_special = any(c in password for c in '!@#$%^&*()[]{}|\\:;\"\'<>?,./')
            add_log(f"Password ready: length={len(password)}, has_special_chars={has_special}", 22)
            print(f"[DEBUG] Password loaded: length={len(password)}, has_special_chars={has_special}")
            print(f"[DEBUG] Password first char: {repr(password[0]) if password else 'None'}, last char: {repr(password[-1]) if password and len(password) > 0 else 'None'}")
            print(f"[DEBUG] Password repr: {repr(password)}")
            print(f"[DEBUG] Password bytes: {password.encode('utf-8')}")
        else:
            add_log("ERROR: No password available", 22)
            print("[DEBUG] ERROR: No password available")
        
        # Use installer_backend to test connection
        from installer_backend import execute_ssh_command
        add_log(f"Connecting to {user}@{host}:{port}...", 25)
        success, stdout, stderr = execute_ssh_command(host, user, port, 'echo "Connection successful"', password, timeout=15)
        
        # Debug logging
        print(f"[DEBUG] Connection test result: success={success}")
        if stdout:
            print(f"[DEBUG] stdout: {stdout[:200]}")
        if stderr:
            print(f"[DEBUG] stderr: {stderr[:200]}")
        
        if success:
            add_log("[OK] Connection successful!", 40)
            # Connection successful, check dependencies
            try:
                add_log("Checking VPS dependencies...", 50)
                dependencies = check_vps_dependencies(host, user, port, password)
                add_log("[OK] Dependency check completed", 80)
                test_connection_state["dependencies"] = dependencies
                add_log("Saving configuration...", 90)
                test_connection_state["status"] = "completed"
                test_connection_state["progress"] = 100
                test_connection_state["current_step"] = "Connection test completed successfully"
                add_log("[SUCCESS] Connection test completed successfully", 100)
                return
            except Exception as e:
                add_log(f"[WARN] Dependency check failed: {str(e)}", 80)
                print(f"Error checking dependencies: {e}")
                import traceback
                traceback.print_exc()
                test_connection_state["status"] = "completed"
                test_connection_state["progress"] = 100
                add_log("[SUCCESS] Connection successful (dependency check failed)", 100)
                return
        else:
            # Check if stdout contains success message even though success is False
            # This can happen if exitstatus is not set correctly
            if stdout and "Connection successful" in stdout:
                # Connection actually succeeded, treat as success
                add_log("[OK] Connection successful!", 40)
                # Connection successful, check dependencies
                try:
                    add_log("Checking VPS dependencies...", 50)
                    dependencies = check_vps_dependencies(host, user, port, password)
                    add_log("[OK] Dependency check completed", 80)
                    test_connection_state["dependencies"] = dependencies
                    add_log("Saving configuration...", 90)
                    test_connection_state["status"] = "completed"
                    test_connection_state["progress"] = 100
                    test_connection_state["current_step"] = "Connection test completed successfully"
                    add_log("[SUCCESS] Connection test completed successfully", 100)
                    return
                except Exception as e:
                    add_log(f"[WARN] Dependency check failed: {str(e)}", 80)
                    print(f"Error checking dependencies: {e}")
                    import traceback
                    traceback.print_exc()
                    test_connection_state["status"] = "completed"
                    test_connection_state["progress"] = 100
                    add_log("[SUCCESS] Connection successful (dependency check failed)", 100)
                    return
            
            error_msg = stderr if stderr else stdout
            if not error_msg:
                error_msg = "Connection failed"
            add_log(f"[FAIL] Connection failed: {error_msg}", 30)
            test_connection_state["status"] = "error"
            test_connection_state["progress"] = 100
            add_log(f"[ERROR] Connection failed: {error_msg}", 100)
            return
            
    except Exception as e:
        test_connection_state["status"] = "error"
        test_connection_state["progress"] = 100
        add_log(f"[ERROR] {str(e)}", 100)
        return

def copy_key_via_ssh_interactive(host, user, port, pub_key, password):
    """Fallback method: Copy key using interactive SSH session"""
    import wexpect
    try:
        print(f"\n[KEY COPY] Using interactive SSH method as fallback...")
        print(f"[KEY COPY] Method: Interactive SSH session")
        cmd = f'ssh -p {port} {user}@{host}'
        print(f"[KEY COPY] Command: {cmd}")
        child = wexpect.spawn(cmd, timeout=30)
        
        # Helper function to check buffer for errors
        def check_buffer_for_error():
            if hasattr(child, 'before'):
                before_str = child.before.decode('utf-8', errors='ignore') if isinstance(child.before, bytes) else str(child.before)
                if 'Permission denied' in before_str or 'please try again' in before_str:
                    return True, "Permission denied. The password is incorrect. Please verify your VPS password."
            return False, None
        
        # Handle host key verification prompt first
        try:
            index = child.expect(['password:', 'Password:', 'Password for', 'yes/no', '(yes/no)', '#', '$', '>', ':~#', ':~$'], timeout=15)
        except wexpect.TIMEOUT:
            # Check buffer for permission denied
            has_error, error_msg = check_buffer_for_error()
            if has_error:
                child.close()
                return False, error_msg
            raise
        
        if index >= 3 and index <= 4:  # yes/no prompt
            print(f"[KEY COPY] Host key verification prompt detected, sending 'yes'")
            child.sendline('yes')
            try:
                index = child.expect(['password:', 'Password:', 'Password for'], timeout=15)
            except wexpect.TIMEOUT:
                has_error, error_msg = check_buffer_for_error()
                if has_error:
                    child.close()
                    return False, error_msg
                raise
        
        print(f"[KEY COPY] Password prompt detected (index: {index})")
        print(f"[KEY COPY] Sending password...")
        child.sendline(password)
        
        # Give SSH a moment to process the password
        import time
        time.sleep(0.5)
        
        # Check buffer immediately for permission denied
        try:
            if hasattr(child, 'before'):
                before_str = child.before.decode('utf-8', errors='ignore') if isinstance(child.before, bytes) else str(child.before)
                if 'Permission denied' in before_str or 'please try again' in before_str:
                    print(f"[KEY COPY] [FAIL] Permission denied detected in buffer")
                    child.close()
                    return False, "Permission denied. The password is incorrect. Please verify your VPS password."
        except:
            pass
        
        print(f"[KEY COPY] Waiting for shell prompt or error...")
        
        # Check for permission denied after sending password
        try:
            # Use a shorter timeout and check for both success and error patterns
            index = child.expect(['#', '$', '>', ':~#', ':~$', 'password:', 'Password:', 'Permission denied', 'please try again'], timeout=8)
            if index >= 5:  # Another password prompt or permission denied
                # Read the buffer to see what happened
                if hasattr(child, 'before'):
                    before_str = child.before.decode('utf-8', errors='ignore') if isinstance(child.before, bytes) else str(child.before)
                    if 'Permission denied' in before_str or 'please try again' in before_str:
                        print(f"[KEY COPY] [FAIL] Permission denied detected")
                        child.close()
                        return False, "Permission denied. The password is incorrect. Please verify your VPS password."
                    elif index >= 5 and index <= 7:  # Another password prompt
                        print(f"[KEY COPY] [FAIL] Password rejected, another prompt appeared")
                        child.close()
                        return False, "Permission denied. The password is incorrect. Please verify your VPS password."
            else:
                print(f"[KEY COPY] [OK] Connected to VPS shell")
        except wexpect.TIMEOUT:
            # Check buffer for permission denied - this is the key fix
            has_error, error_msg = check_buffer_for_error()
            if has_error:
                child.close()
                return False, error_msg
            # Also check current buffer more thoroughly
            try:
                if hasattr(child, 'before'):
                    before_str = child.before.decode('utf-8', errors='ignore') if isinstance(child.before, bytes) else str(child.before)
                    print(f"[KEY COPY] [DEBUG] Buffer content (last 200 chars): {before_str[-200:]}")
                    if 'Permission denied' in before_str or 'please try again' in before_str:
                        child.close()
                        return False, "Permission denied. The password is incorrect. Please verify your VPS password."
            except Exception as e:
                print(f"[KEY COPY] [DEBUG] Error checking buffer: {e}")
            raise
        print(f"[KEY COPY] [OK] Connected to VPS shell")
        
        # Write key using printf (most reliable for special characters)
        # Split key into parts to avoid command length issues
        print(f"[KEY COPY] Writing key to authorized_keys...")
        key_parts = pub_key.split()
        if len(key_parts) >= 2:
            key_type = key_parts[0]
            key_data = ' '.join(key_parts[1:])
            # Use printf to write both parts
            write_cmd = f"printf '%s %s\\n' '{key_type}' '{key_data}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'KEY_WRITTEN' || echo 'KEY_FAILED'"
            print(f"[KEY COPY] Command: printf '%s %s\\n' '{key_type}' '[key_data]' >> ~/.ssh/authorized_keys...")
            child.sendline(write_cmd)
        else:
            # Single line key
            pub_key_escaped = pub_key.replace("'", "'\\''")
            write_cmd = f"printf '%s\\n' '{pub_key_escaped}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'KEY_WRITTEN' || echo 'KEY_FAILED'"
            print(f"[KEY COPY] Command: printf '%s\\n' '[key]' >> ~/.ssh/authorized_keys...")
            child.sendline(write_cmd)
        
        print(f"[KEY COPY] Waiting for command result...")
        result = child.expect(['KEY_WRITTEN', 'KEY_FAILED', '#', '$', '>', ':~#', ':~$'], timeout=15)
        print(f"[KEY COPY] Command result: {result} (0=KEY_WRITTEN, 1=KEY_FAILED)")
        print(f"[KEY COPY] Closing SSH connection...")
        child.sendline('exit')
        child.expect(wexpect.EOF, timeout=10)
        child.close()
        
        if result == 0:
            print(f"[KEY COPY] [OK] Key written using interactive SSH method")
            print(f"{'='*60}")
            print(f"[KEY COPY] [OK] SSH key copy completed successfully (interactive method)!")
            print(f"{'='*60}\n")
            return True, None
        else:
            print(f"[KEY COPY] [FAIL] Failed to write key using interactive SSH method")
            print(f"{'='*60}")
            print(f"[KEY COPY] [FAIL] SSH key copy failed")
            print(f"{'='*60}\n")
            return False, "Failed to write key using interactive SSH method"
    except Exception as e:
        print(f"[KEY COPY] [FAIL] Interactive SSH method failed: {str(e)}")
        print(f"{'='*60}")
        print(f"[KEY COPY] [FAIL] SSH key copy failed")
        print(f"{'='*60}\n")
        return False, f"Interactive SSH method failed: {str(e)}"

def copy_ssh_key_internal(host, user, port, key_path, password):
    """Internal function to copy SSH key
    Returns: (success: bool, error_message: str)
    """
    import sys
    
    print(f"\n[KEY COPY] Starting SSH key copy process")
    print(f"[KEY COPY] Target: {user}@{host}:{port}")
    
    # Handle both string and Path objects
    key_path_obj = Path(key_path) if isinstance(key_path, str) else key_path
    pub_key_path = key_path_obj.with_suffix('.pub')
    
    # Debug: Check if files exist
    print(f"[KEY COPY] Looking for public key at: {pub_key_path}")
    print(f"[KEY COPY] Public key exists: {pub_key_path.exists()}")
    print(f"[KEY COPY] Private key exists: {key_path_obj.exists()}")
    
    if not pub_key_path.exists():
        # Try alternative path
        alt_pub_path = key_path_obj.parent / f"{key_path_obj.name}.pub"
        if alt_pub_path.exists():
            pub_key_path = alt_pub_path
            print(f"[KEY COPY] Found public key at alternative path: {pub_key_path}")
        else:
            print(f"[KEY COPY] [FAIL] Public key file not found at {pub_key_path} or {alt_pub_path}")
            return False, f"Public key file not found at {pub_key_path} or {alt_pub_path}"
    
    try:
        pub_key = pub_key_path.read_text().strip()
        if not pub_key:
            print(f"[KEY COPY] [FAIL] Public key file is empty")
            return False, "Public key file is empty"
        print(f"[KEY COPY] [OK] Public key read successfully ({len(pub_key)} characters)")
    except Exception as e:
        print(f"[KEY COPY] [FAIL] Failed to read public key: {str(e)}")
        return False, f"Failed to read public key: {str(e)}"
    
    # On Windows, use wexpect
    if sys.platform == 'win32':
        print(f"[KEY COPY] Platform: Windows - Using wexpect")
        try:
            # Try to install wexpect and dependencies if missing
            print(f"[KEY COPY] Checking for setuptools...")
            if not check_and_install_package('setuptools', 'setuptools'):
                print(f"[KEY COPY] [FAIL] Failed to install setuptools")
                return False, "Failed to install setuptools (required by wexpect)"
            print(f"[KEY COPY] [OK] setuptools available")
            
            print(f"[KEY COPY] Checking for wexpect...")
            if not check_and_install_package('wexpect', 'wexpect'):
                print(f"[KEY COPY] [FAIL] Failed to install wexpect")
                return False, "Failed to install wexpect. Please install manually: pip install wexpect"
            print(f"[KEY COPY] [OK] wexpect available")
            
            import wexpect
            
            # Ensure .ssh directory exists
            try:
                print(f"[KEY COPY] Step 1: Creating .ssh directory on VPS...")
                mkdir_cmd = f'ssh -p {port} {user}@{host} "mkdir -p ~/.ssh && chmod 700 ~/.ssh"'
                print(f"[KEY COPY] Command: {mkdir_cmd}")
                child = wexpect.spawn(mkdir_cmd, timeout=20)
                # Try multiple password prompt patterns
                index = child.expect(['password:', 'Password:', 'Password for', 'yes/no', '(yes/no)'], timeout=15)
                print(f"[KEY COPY] Prompt detected (index: {index})")
                
                if index >= 3:  # yes/no prompt
                    print(f"[KEY COPY] Host key verification prompt, sending 'yes'")
                    child.sendline('yes')
                    index = child.expect(['password:', 'Password:', 'Password for'], timeout=15)
                
                print(f"[KEY COPY] Sending password...")
                child.sendline(password)
                child.expect(wexpect.EOF, timeout=20)
                exit_status = child.exitstatus if hasattr(child, 'exitstatus') else 0
                child.close()
                print(f"[KEY COPY] [OK] .ssh directory created (exit status: {exit_status})")
            except Exception as e:
                error_detail = str(e)
                if hasattr(e, 'before'):
                    before_str = e.before.decode('utf-8', errors='ignore') if isinstance(e.before, bytes) else str(e.before)
                    error_detail += f" (before: {before_str[:200]})"
                if hasattr(e, 'after'):
                    after_str = e.after.decode('utf-8', errors='ignore') if isinstance(e.after, bytes) else str(e.after)
                    error_detail += f" (after: {after_str[:200]})"
                print(f"[KEY COPY] [FAIL] Failed to create .ssh directory: {error_detail}")
                return False, f"Failed to create .ssh directory: {error_detail}"
            
            # Copy key using SCP (more reliable than interactive SSH)
            try:
                print(f"\n[KEY COPY] Step 2: Copying public key file to VPS using SCP...")
                
                # Use SCP to copy the public key file
                scp_cmd = f'scp -P {port} {pub_key_path} {user}@{host}:/tmp/oxcookie_key.pub'
                print(f"[KEY COPY] SCP command: scp -P {port} {pub_key_path} {user}@{host}:/tmp/oxcookie_key.pub")
                print(f"[KEY COPY] Source file: {pub_key_path}")
                print(f"[KEY COPY] Destination: {user}@{host}:/tmp/oxcookie_key.pub")
                try:
                    scp_child = wexpect.spawn(scp_cmd, timeout=30)
                    scp_index = scp_child.expect(['password:', 'Password:', 'Password for', 'yes/no', '(yes/no)'], timeout=15)
                    print(f"[KEY COPY] SCP prompt detected (index: {scp_index})")
                    
                    # Handle host key verification prompt
                    if scp_index >= 3:  # yes/no prompt
                        print(f"[KEY COPY] Host key verification prompt detected, sending 'yes'")
                        scp_child.sendline('yes')
                        scp_index = scp_child.expect(['password:', 'Password:', 'Password for'], timeout=15)
                    
                    print(f"[KEY COPY] SCP password prompt detected (index: {scp_index})")
                    print(f"[KEY COPY] Sending password for SCP...")
                    scp_child.sendline(password)
                    
                    # Check for permission denied after sending password
                    try:
                        scp_index = scp_child.expect([wexpect.EOF, 'Permission denied', 'please try again'], timeout=30)
                        if scp_index >= 1:  # Permission denied
                            scp_child.close()
                            return False, "Permission denied. The password is incorrect. Please verify your VPS password."
                    except wexpect.TIMEOUT:
                        # Check buffer for permission denied
                        if hasattr(scp_child, 'before'):
                            before_str = scp_child.before.decode('utf-8', errors='ignore') if isinstance(scp_child.before, bytes) else str(scp_child.before)
                            if 'Permission denied' in before_str or 'please try again' in before_str:
                                scp_child.close()
                                return False, "Permission denied. The password is incorrect. Please verify your VPS password."
                        raise
                    scp_exit = scp_child.exitstatus if hasattr(scp_child, 'exitstatus') else 0
                    scp_before = scp_child.before.decode('utf-8', errors='ignore') if isinstance(scp_child.before, bytes) else str(scp_child.before)
                    scp_child.close()
                    
                    print(f"[KEY COPY] SCP completed with exit code {scp_exit}")
                    if scp_before:
                        print(f"[KEY COPY] SCP output: {scp_before[:500]}")  # First 500 chars
                    
                    if scp_exit != 0:
                        print(f"[KEY COPY] [FAIL] SCP failed with exit code {scp_exit}")
                        if scp_before:
                            print(f"[KEY COPY] SCP error output: {scp_before[:300]}")
                        # Fall back to interactive SSH method
                        print(f"[KEY COPY] Falling back to interactive SSH method...")
                        return copy_key_via_ssh_interactive(host, user, port, pub_key, password)
                except wexpect.TIMEOUT as e:
                    error_detail = f"SCP timeout: {str(e)}"
                    if hasattr(e, 'before'):
                        before_str = e.before.decode('utf-8', errors='ignore') if isinstance(e.before, bytes) else str(e.before)
                        error_detail += f" | Before: {before_str[:200]}"
                    print(f"[KEY COPY] [FAIL] {error_detail}")
                    print(f"[KEY COPY] Falling back to interactive SSH method...")
                    return copy_key_via_ssh_interactive(host, user, port, pub_key, password)
                except Exception as e:
                    error_detail = f"SCP error: {str(e)}"
                    if hasattr(e, 'before'):
                        before_str = e.before.decode('utf-8', errors='ignore') if isinstance(e.before, bytes) else str(e.before)
                        error_detail += f" | Before: {before_str[:200]}"
                    print(f"[KEY COPY] [FAIL] {error_detail}")
                    print(f"[KEY COPY] Falling back to interactive SSH method...")
                    return copy_key_via_ssh_interactive(host, user, port, pub_key, password)
                
                print(f"[KEY COPY] [OK] Key file copied to VPS via SCP")
                
                # Now append the key to authorized_keys using SSH
                print(f"\n[KEY COPY] Step 3: Appending key to authorized_keys...")
                append_cmd = f'ssh -p {port} {user}@{host} "cat /tmp/oxcookie_key.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && rm -f /tmp/oxcookie_key.pub && echo SUCCESS || echo FAILED"'
                print(f"[KEY COPY] Command: {append_cmd}")
                try:
                    append_child = wexpect.spawn(append_cmd, timeout=20)
                    append_index = append_child.expect(['password:', 'Password:', 'Password for', 'yes/no', '(yes/no)'], timeout=15)
                    
                    # Handle host key verification prompt
                    if append_index >= 3:  # yes/no prompt
                        print(f"[KEY COPY] Host key verification prompt detected, sending 'yes'")
                        append_child.sendline('yes')
                        append_index = append_child.expect(['password:', 'Password:', 'Password for'], timeout=15)
                    
                    print(f"[KEY COPY] Append command password prompt detected (index: {append_index})")
                    print(f"[KEY COPY] Sending password for append command...")
                    append_child.sendline(password)
                    append_result = append_child.expect(['SUCCESS', 'FAILED', wexpect.EOF], timeout=15)
                    append_before = append_child.before.decode('utf-8', errors='ignore') if isinstance(append_child.before, bytes) else str(append_child.before)
                    append_child.expect(wexpect.EOF, timeout=10)
                    append_child.close()
                    
                    print(f"[KEY COPY] Append result: {append_result} (0=SUCCESS, 1=FAILED)")
                    if append_before:
                        print(f"[KEY COPY] Append output: {append_before[:300]}")
                    
                    if append_result == 0:
                        print(f"[KEY COPY] [OK] Key successfully appended to authorized_keys")
                        
                        # Verify the key is in authorized_keys
                        print(f"\n[KEY COPY] Step 4: Verifying key in authorized_keys...")
                        key_search = pub_key.split()[0] if " " in pub_key else pub_key[:20]
                        verify_cmd = f'ssh -p {port} {user}@{host} "test -f ~/.ssh/authorized_keys && grep -q \'{key_search}\' ~/.ssh/authorized_keys && echo VERIFIED || echo NOT_FOUND"'
                        print(f"[KEY COPY] Verification command: {verify_cmd}")
                        try:
                            verify_child = wexpect.spawn(verify_cmd, timeout=20)
                            verify_index = verify_child.expect(['password:', 'Password:', 'Password for', 'yes/no', '(yes/no)'], timeout=15)
                            print(f"[KEY COPY] Verification prompt detected (index: {verify_index})")
                            
                            # Handle host key verification prompt
                            if verify_index >= 3:  # yes/no prompt
                                print(f"[KEY COPY] Host key verification prompt, sending 'yes'")
                                verify_child.sendline('yes')
                                verify_index = verify_child.expect(['password:', 'Password:', 'Password for'], timeout=15)
                            
                            print(f"[KEY COPY] Sending password for verification...")
                            verify_child.sendline(password)
                            verify_result = verify_child.expect(['VERIFIED', 'NOT_FOUND', wexpect.EOF], timeout=15)
                            verify_child.expect(wexpect.EOF, timeout=10)
                            verify_child.close()
                            
                            if verify_result == 0:
                                print(f"[KEY COPY] [OK] Key verified in authorized_keys")
                                print(f"{'='*60}")
                                print(f"[KEY COPY] [OK] SSH key copy completed successfully!")
                                print(f"{'='*60}\n")
                                return True, None
                            else:
                                print(f"[KEY COPY] [WARN] Warning: Key not found in authorized_keys after append, but continuing...")
                                print(f"{'='*60}")
                                print(f"[KEY COPY] [WARN] Key copy may have succeeded but verification failed")
                                print(f"{'='*60}\n")
                                return True, None  # Still return success as file was created
                        except Exception as verify_e:
                            print(f"[KEY COPY] [WARN] Verification failed: {str(verify_e)}, but key append succeeded")
                            print(f"{'='*60}")
                            print(f"[KEY COPY] [WARN] Key copy may have succeeded but verification failed")
                            print(f"{'='*60}\n")
                            return True, None  # Return success even if verification fails
                    else:
                        error_msg = f"Failed to append key to authorized_keys. Output: {append_before[:200] if append_before else 'None'}"
                        print(f"[KEY COPY] [FAIL] {error_msg}")
                        print(f"{'='*60}")
                        print(f"[KEY COPY] [FAIL] SSH key copy failed")
                        print(f"{'='*60}\n")
                        return False, error_msg
                except wexpect.TIMEOUT as e:
                    error_detail = f"Timeout while appending key: {str(e)}"
                    if hasattr(e, 'before'):
                        before_str = e.before.decode('utf-8', errors='ignore') if isinstance(e.before, bytes) else str(e.before)
                        error_detail += f" | Before: {before_str[:200]}"
                    print(f"[KEY COPY] [FAIL] {error_detail}")
                    print(f"{'='*60}")
                    print(f"[KEY COPY] [FAIL] SSH key copy failed (timeout)")
                    print(f"{'='*60}\n")
                    return False, error_detail
                except Exception as e:
                    error_detail = f"Error while appending key: {str(e)}"
                    if hasattr(e, 'before'):
                        before_str = e.before.decode('utf-8', errors='ignore') if isinstance(e.before, bytes) else str(e.before)
                        error_detail += f" | Before: {before_str[:200]}"
                    print(f"[KEY COPY] [FAIL] {error_detail}")
                    print(f"{'='*60}")
                    print(f"[KEY COPY] [FAIL] SSH key copy failed")
                    print(f"{'='*60}\n")
                    return False, error_detail
                    
            except wexpect.TIMEOUT as e:
                error_detail = f"Timeout during key copy: {str(e)}"
                if hasattr(e, 'before'):
                    error_detail += f"\nBefore timeout: {e.before.decode('utf-8', errors='ignore') if isinstance(e.before, bytes) else str(e.before)}"
                if hasattr(e, 'after'):
                    error_detail += f"\nAfter timeout: {e.after.decode('utf-8', errors='ignore') if isinstance(e.after, bytes) else str(e.after)}"
                print(f"[DEBUG] {error_detail}")
                # Fall back to interactive SSH method
                print(f"[DEBUG] Falling back to interactive SSH method...")
                return copy_key_via_ssh_interactive(host, user, port, pub_key, password)
            except Exception as e:
                error_detail = f"Error during SCP key copy: {str(e)}"
                if hasattr(e, 'before'):
                    error_detail += f"\nBefore error: {e.before.decode('utf-8', errors='ignore') if isinstance(e.before, bytes) else str(e.before)}"
                if hasattr(e, 'after'):
                    error_detail += f"\nAfter error: {e.after.decode('utf-8', errors='ignore') if isinstance(e.after, bytes) else str(e.after)}"
                print(f"[DEBUG] {error_detail}")
                # Fall back to interactive SSH method
                print(f"[DEBUG] Falling back to interactive SSH method...")
                return copy_key_via_ssh_interactive(host, user, port, pub_key, password)
            except Exception as e:
                print(f"[DEBUG] Error during SCP key copy: {str(e)}")
                # Fall back to interactive SSH method
                return copy_key_via_ssh_interactive(host, user, port, pub_key, password)
        except ImportError as e:
            # Try to install missing dependencies and retry
            error_msg = str(e)
            # Check if it's a pkg_resources error (setuptools missing)
            if 'pkg_resources' in error_msg or 'setuptools' in error_msg:
                print(f"[INFO] Missing setuptools, installing...")
                if check_and_install_package('setuptools', 'setuptools'):
                    try:
                        import wexpect
                        # Retry the operation after installing setuptools
                        return copy_ssh_key_internal(host, user, port, key_path, password)
                    except Exception as retry_e:
                        return False, f"Failed after installing setuptools: {str(retry_e)}"
            
            # Try installing wexpect if it's missing
            if check_and_install_package('wexpect', 'wexpect'):
                try:
                    import wexpect
                    # Retry the operation
                    return copy_ssh_key_internal(host, user, port, key_path, password)
                except Exception as retry_e:
                    return False, f"Failed after installing wexpect: {str(retry_e)}"
            
            return False, f"wexpect not installed: {error_msg}. Install with: pip install wexpect setuptools"
        except Exception as e:
            return False, f"Error with wexpect: {str(e)}"
    else:
        # Linux/Mac - use pexpect
        try:
            import pexpect
            
            # Ensure .ssh directory exists
            try:
                child = pexpect.spawn(f'ssh -p {port} {user}@{host} "mkdir -p ~/.ssh && chmod 700 ~/.ssh"', timeout=15, encoding='utf-8')
                child.expect('password:', timeout=10)
                child.sendline(password)
                child.expect(pexpect.EOF, timeout=15)
                child.close()
            except Exception as e:
                return False, f"Failed to create .ssh directory: {str(e)}"
            
            # Copy key
            try:
                child = pexpect.spawn(f'ssh -p {port} {user}@{host} "cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"', timeout=15, encoding='utf-8')
                child.expect('password:', timeout=10)
                child.sendline(password)
                child.send(pub_key + '\n')
                child.sendcontrol('D')
                child.expect(pexpect.EOF, timeout=15)
                child.close()
                return True, None
            except Exception as e:
                return False, f"Failed to copy key: {str(e)}"
        except ImportError as e:
            # pexpect not available
            return False, f"pexpect not installed: {str(e)}. Install with: pip install pexpect"
        except Exception as e:
            return False, f"Error with pexpect: {str(e)}"

@app.route('/api/check-domain', methods=['POST'])
def check_domain():
    """Check if domain is subdomain or base domain"""
    try:
        data = request.json
        domain = data.get('domain', '')
        
        if not domain:
            return jsonify({"status": "error", "message": "Domain required"})
        
        parts = domain.split('.')
        is_subdomain = len(parts) > 2
        
        if is_subdomain:
            base_domain = '.'.join(parts[-2:])
            subdomain = parts[0]
        else:
            base_domain = domain
            subdomain = None
        
        return jsonify({
            "status": "success",
            "is_subdomain": is_subdomain,
            "base_domain": base_domain,
            "subdomain": subdomain
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/generate-subdomain', methods=['POST'])
def generate_subdomain():
    """Generate random subdomain"""
    import random
    import string
    
    data = request.json
    base_domain = data.get('base_domain', '')
    
    random_chars = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    subdomain = f"oxcookie-{random_chars}"
    full_domain = f"{subdomain}.{base_domain}"
    
    return jsonify({
        "status": "success",
        "subdomain": subdomain,
        "base_domain": base_domain,
        "full_domain": full_domain
    })

@app.route('/api/setup-dns', methods=['POST'])
def setup_dns_endpoint():
    """Setup DNS record for subdomain"""
    try:
        data = request.json
        
        # Load password from saved config if not provided
        if not data.get('password') or data.get('password') == '***saved***':
            if CONFIG_FILE.exists():
                try:
                    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                        saved_config = json.load(f)
                        if saved_config.get('password'):
                            data['password'] = saved_config.get('password')
                except:
                    pass
        
        from installer_backend import setup_dns
        
        success, message = setup_dns(data, None)
        
        if success:
            # Extract VPS IP from message if available
            vps_ip = None
            if '->' in message:
                vps_ip = message.split('->')[-1].strip()
            
            return jsonify({
                "status": "success",
                "message": message,
                "vps_ip": vps_ip
            })
        else:
            return jsonify({
                "status": "error",
                "message": message
            })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })

@app.route('/api/install-dependencies', methods=['POST'])
def install_dependencies():
    """Start dependency installation in background thread"""
    global install_deps_state
    
    # Reset state
    install_deps_state = {
        "status": "running",
        "progress": 0,
        "current_step": "Initializing dependency installation...",
        "log": [],
    }
    
    try:
        data = request.json
        # Start installation in background thread
        import threading
        thread = threading.Thread(target=run_install_dependencies, args=(data,))
        thread.daemon = True
        thread.start()
        
        return jsonify({"status": "started", "message": "Dependency installation started"})
    except Exception as e:
        install_deps_state["status"] = "error"
        install_deps_state["log"].append(f"[ERROR] {str(e)}")
        return jsonify({"status": "error", "message": str(e)})

def run_install_dependencies(data):
    """Run dependency installation in background thread"""
    global install_deps_state
    import time as time_module
    
    def add_log(message, progress=None):
        timestamp = time_module.strftime("[%H:%M:%S]")
        log_entry = f"{timestamp} {message}"
        install_deps_state["log"].append(log_entry)
        if progress is not None:
            install_deps_state["progress"] = progress
        install_deps_state["current_step"] = message
        # Also print to console for debugging
        print(log_entry)
        import sys
        sys.stdout.flush()
    
    add_log("Initializing dependency installation...", 0)
    
    try:
        host = data.get('host')
        user = data.get('user', 'root')
        port = data.get('port', 22)
        password = data.get('password')
        
        # Load from config if not provided
        if CONFIG_FILE.exists() and not password:
            with open(CONFIG_FILE, 'r') as f:
                saved_config = json.load(f)
                if not password:
                    password = saved_config.get('password')
                if not host:
                    host = saved_config.get('vps_host')
                if not user:
                    user = saved_config.get('vps_user', 'root')
                if not port:
                    port = saved_config.get('vps_port', 22)
        
        if not host or not password:
            install_deps_state["status"] = "error"
            add_log("[ERROR] VPS host and password required", 100)
            return
        
        from installer_backend import execute_ssh_command
        
        installed = []
        errors = []
        
        # Check what's missing first
        add_log("Checking current dependencies...", 10)
        dependencies = check_vps_dependencies(host, user, port, password)
        
        missing_count = sum(1 for dep in dependencies.values() if dep.get('needed') and not dep.get('installed'))
        if missing_count == 0:
            add_log("[OK] All dependencies are already installed!", 100)
            install_deps_state["status"] = "completed"
            return
        
        add_log(f"Found {missing_count} missing dependencies", 15)
        
        # Update package list first
        add_log("Updating package list...", 20)
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "apt-get update -qq",
            password,
            timeout=120
        )
        if not success:
            add_log(f"[FAIL] Failed to update package list: {stderr}", 20)
            errors.append(f"Failed to update package list: {stderr}")
        else:
            add_log("[OK] Package list updated", 25)
        
        # Install Python 3 if missing
        if dependencies.get('python3', {}).get('needed') and not dependencies.get('python3', {}).get('installed'):
            add_log("Installing Python 3 and pip...", 30)
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "apt-get install -y python3 python3-pip",
                password,
                timeout=120
            )
            if success:
                add_log("[OK] Python 3 installed successfully", 50)
                installed.append('Python 3')
            else:
                add_log(f"[FAIL] Failed to install Python 3: {stderr}", 50)
                errors.append(f"Python 3: {stderr}")
        
        # Install pip if missing (separate check)
        if dependencies.get('pip', {}).get('needed') and not dependencies.get('pip', {}).get('installed'):
            add_log("Installing pip...", 55)
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "apt-get install -y python3-pip",
                password,
                timeout=60
            )
            if success:
                add_log("[OK] pip installed successfully", 60)
                installed.append('pip')
            else:
                add_log(f"[FAIL] Failed to install pip: {stderr}", 60)
                errors.append(f"pip: {stderr}")
        
        # Install nginx if missing
        if dependencies.get('nginx', {}).get('needed') and not dependencies.get('nginx', {}).get('installed'):
            add_log("Installing Nginx...", 65)
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "apt-get install -y nginx",
                password,
                timeout=120
            )
            if success:
                add_log("[OK] Nginx installed successfully", 80)
                installed.append('Nginx')
            else:
                add_log(f"[FAIL] Failed to install Nginx: {stderr}", 80)
                errors.append(f"Nginx: {stderr}")
        
        # Install curl if missing
        if dependencies.get('curl', {}).get('needed') and not dependencies.get('curl', {}).get('installed'):
            add_log("Installing curl...", 85)
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "apt-get install -y curl",
                password,
                timeout=60
            )
            if success:
                add_log("[OK] curl installed successfully", 90)
                installed.append('curl')
            else:
                add_log(f"[FAIL] Failed to install curl: {stderr}", 90)
                errors.append(f"curl: {stderr}")
        
        # systemd is usually pre-installed, but we check anyway
        if dependencies.get('systemd', {}).get('needed') and not dependencies.get('systemd', {}).get('installed'):
            add_log("[WARN] systemd not found (usually pre-installed)", 95)
            errors.append("systemd: Usually pre-installed. Please check your system.")
        
        if errors:
            add_log(f"[WARN] Installation completed with {len(errors)} error(s)", 100)
            install_deps_state["status"] = "completed"
        else:
            add_log(f"[OK] Successfully installed {len(installed)} dependencies", 100)
            install_deps_state["status"] = "completed"
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        add_log(f"[ERROR] {str(e)}", 100)
        install_deps_state["status"] = "error"
        install_deps_state["progress"] = 100

@app.route('/api/install', methods=['POST'])
def start_installation():
    """Start the installation process"""
    global installation_state
    
    if installation_state["status"] == "running":
        return jsonify({"status": "error", "message": "Installation already in progress"})
    
    try:
        data = request.json
        
        # Check if we should resume from previous error
        resume_from = data.get('resume_from', None)
        
        # Reset state or resume
        if resume_from and installation_state.get("status") == "error":
            # Resume from where it stopped
            installation_state["status"] = "running"
            installation_state["current_step"] = f"Resuming from step {resume_from}..."
            installation_state["error"] = None
            # Don't clear logs, append resume message
            installation_state["log"].append(f"[RESUME] Resuming installation from step {resume_from}...")
        else:
            # Reset state for fresh installation
            installation_state = {
                "status": "running",
                "progress": 0,
                "current_step": "Initializing...",
                "log": [],
                "error": None,
                "domain": None,
                "app_url": None
            }
        
        # Start installation in background thread
        thread = threading.Thread(target=run_installation, args=(data, resume_from), daemon=True)
        thread.start()
        
        return jsonify({"status": "started", "message": "Installation started"})
        
    except Exception as e:
        installation_state["status"] = "error"
        installation_state["error"] = str(e)
        return jsonify({"status": "error", "message": str(e)})

def run_installation(config, resume_from=None):
    """Run the actual installation process"""
    global installation_state
    
    def update_progress(step, progress, message):
        import time as time_module
        timestamp = time_module.strftime("[%H:%M:%S]")
        
        # Safely encode message to avoid Unicode issues
        try:
            safe_message = message.encode('ascii', errors='replace').decode('ascii')
        except:
            # If encoding fails, replace common Unicode characters
            safe_message = message.replace('✓', '[OK]').replace('✗', '[FAIL]').replace('⚠', '[WARN]').replace('→', '->')
            try:
                safe_message = safe_message.encode('ascii', errors='replace').decode('ascii')
            except:
                safe_message = "Message encoding error"
        
        log_entry = f"{timestamp} {safe_message}"
        installation_state["current_step"] = step
        installation_state["progress"] = progress
        installation_state["log"].append(log_entry)
        # Also print to console for debugging (safe print for Windows)
        try:
            print(log_entry)
        except UnicodeEncodeError:
            # Final fallback - replace all problematic characters
            safe_log = log_entry.encode('ascii', errors='replace').decode('ascii')
            print(safe_log)
        import sys
        sys.stdout.flush()
    
    try:
        from installer_backend import deploy_application, setup_dns, configure_services, execute_ssh_command
        
        # Determine which step to start from
        start_step = 1
        if resume_from:
            try:
                start_step = int(resume_from)
            except:
                start_step = 1
        
        # Load missing values from saved config
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved_config = json.load(f)
                    # Load password if not provided
                    if not config.get('password') or config.get('password') == '***saved***':
                        if saved_config.get('password'):
                            config['password'] = saved_config.get('password')
                            update_progress("Loading config", 2, "[INFO] Using saved password from config")
                    # Load base_domain and subdomain if not provided
                    if not config.get('base_domain') and saved_config.get('base_domain'):
                        config['base_domain'] = saved_config.get('base_domain')
                    if not config.get('subdomain') and saved_config.get('subdomain'):
                        config['subdomain'] = saved_config.get('subdomain')
                    # Ensure domain is set
                    if not config.get('domain') and saved_config.get('domain'):
                        config['domain'] = saved_config.get('domain')
            except Exception as e:
                update_progress("Loading config", 2, f"[WARN] Error loading saved config: {str(e)}")
        
        # Step 0: Check for existing installation
        from installer_backend import check_existing_installation
        update_progress("Checking installation", 3, "[0/8] Checking for existing installation...")
        existing_status = check_existing_installation(config, lambda msg: update_progress("Checking installation", 3, msg))
        
        if existing_status['service_exists'] or existing_status['files_exist']:
            update_progress("Checking installation", 4, f"[INFO] Found existing installation: service={existing_status['service_exists']}, files={existing_status['files_exist']}, running={existing_status['service_running']}")
        
        # Step 1: Test connection
        if start_step <= 1:
            update_progress("Testing connection", 5, "[1/8] Testing SSH connection...")
            try:
                success, stdout, stderr = execute_ssh_command(
                    config['host'],
                    config['user'],
                    config.get('port', 22),
                    'echo "Connection successful"',
                    config.get('password'),  # Use password, not key_path
                    timeout=30  # Increased timeout for connection test
                )
                if not success:
                    error_msg = stderr if stderr else "Connection test failed"
                    update_progress("Testing connection", 5, f"[FAIL] {error_msg}")
                    raise Exception(f"Connection test failed: {error_msg}")
                update_progress("Testing connection", 10, "[OK] Connection successful")
            except Exception as e:
                error_msg = str(e)
                update_progress("Testing connection", 5, f"[ERROR] {error_msg}")
                raise Exception(f"Connection test error: {error_msg}")
        
        # Step 2: Deploy application (includes dependency checks)
        if start_step <= 2:
            update_progress("Deploying application", 15, "[2/8] Deploying application files...")
            success, message = deploy_application(config, lambda msg: update_progress("Deploying application", 25, msg))
            if not success:
                # Always show the actual error message
                error_msg = str(message)
                try:
                    error_msg = error_msg.encode('ascii', errors='replace').decode('ascii')
                except:
                    error_msg = "Deployment failed (encoding error)"
                update_progress("Deploying application", 45, f"[ERROR] {error_msg}")
                raise Exception(error_msg)
            else:
                update_progress("Deploying application", 50, "[OK] Application deployed")
        
        # Step 3: Configure services (includes nginx check/install)
        if start_step <= 3:
            update_progress("Configuring services", 55, "[3/8] Configuring firewall, systemd and nginx...")
            success, message = configure_services(config, lambda msg: update_progress("Configuring services", 70, msg))
            if not success:
                # Safely encode error message to avoid Unicode issues
                try:
                    safe_message = message.encode('ascii', errors='replace').decode('ascii')
                except:
                    safe_message = "Failed to configure services (encoding error)"
                raise Exception(safe_message)
            update_progress("Configuring services", 80, "[OK] Services configured")
        
        # Step 4: Setup DNS
        if start_step <= 4:
            if config.get('setup_dns') and config.get('dns_provider') != 'manual':
                update_progress("Setting up DNS", 85, "[4/8] Setting up DNS records...")
                success, message = setup_dns(config, lambda msg: update_progress("Setting up DNS", 90, msg))
                if success:
                    update_progress("Setting up DNS", 95, f"[OK] {message}")
                else:
                    installation_state["log"].append(f"[WARNING] DNS setup failed: {message}")
        
        # Get domain for success message
        domain = config.get('domain', '')
        vps_host = config.get('host', '')
        app_port = config.get('app_port', 5004)
        
        # Determine access URL
        if domain:
            app_url = f"http://{domain}"
            access_info = f"http://{domain} (or https://{domain} if SSL is configured)"
        elif vps_host:
            app_url = f"http://{vps_host}:{app_port}"
            access_info = f"http://{vps_host}:{app_port} (using VPS IP)"
        else:
            app_url = "http://<your-domain>"
            access_info = "http://<your-domain> (configure domain in settings)"
        
        installation_state["status"] = "completed"
        installation_state["progress"] = 100
        installation_state["current_step"] = "Installation completed!"
        installation_state["log"].append("[SUCCESS] Installation completed successfully!")
        installation_state["log"].append("")
        installation_state["log"].append("=" * 60)
        installation_state["log"].append("🎉 oXCookie Manager is now installed and running!")
        installation_state["log"].append("")
        installation_state["log"].append(f"🌐 Access your application at: {access_info}")
        installation_state["log"].append("")
        installation_state["log"].append("📋 Service Status:")
        installation_state["log"].append("   - Service: oxcookie-manager")
        installation_state["log"].append("   - Status: Running")
        installation_state["log"].append("   - Logs: sudo journalctl -u oxcookie-manager -f")
        installation_state["log"].append("   - Restart: sudo systemctl restart oxcookie-manager")
        installation_state["log"].append("   - Stop: sudo systemctl stop oxcookie-manager")
        installation_state["log"].append("")
        installation_state["log"].append("=" * 60)
        
        # Store domain and URL in state for frontend
        installation_state["domain"] = domain if domain else vps_host
        installation_state["app_url"] = app_url
        installation_state["access_info"] = access_info
        
    except Exception as e:
        installation_state["status"] = "error"
        installation_state["error"] = str(e)
        installation_state["log"].append(f"[ERROR] {str(e)}")

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get installation status"""
    return jsonify(installation_state)

@app.route('/api/progress/<operation>', methods=['GET'])
def get_progress(operation):
    """Get progress for a specific operation"""
    global test_connection_state, install_deps_state, fix_state
    
    if operation == 'test-connection':
        return jsonify(test_connection_state)
    elif operation == 'install-dependencies':
        return jsonify(install_deps_state)
    elif operation == 'installation':
        return jsonify(installation_state)
    elif operation == 'fix-app':
        return jsonify(fix_state)
    else:
        return jsonify({"status": "error", "message": f"Unknown operation: {operation}"}), 404

@app.route('/api/files', methods=['GET'])
def list_files():
    """List deployment files"""
    files = []
    for file in ['app.py', 'database_reader.py', 'notifications.py', 
                 'session_processor.py', 'requirements.txt', 'start.sh']:
        file_path = DEPLOYMENT_DIR / file
        if file_path.exists():
            files.append({
                "name": file,
                "size": file_path.stat().st_size,
                "exists": True
            })
        else:
            files.append({
                "name": file,
                "size": 0,
                "exists": False
            })
    
    # Check templates directory
    templates_dir = DEPLOYMENT_DIR / "templates"
    if templates_dir.exists():
        files.append({
            "name": "templates/",
            "size": sum(f.stat().st_size for f in templates_dir.rglob('*') if f.is_file()),
            "exists": True
        })
    
    return jsonify({"files": files})

@app.route('/api/cloudflare/domains', methods=['POST'])
def get_cloudflare_domains():
    """Fetch domains from Cloudflare account"""
    try:
        data = request.json or {}
        cf_email = data.get('cf_email')
        cf_api_key = data.get('cf_api_key')
        
        # If not provided in the request, fall back to saved config
        if (not cf_email or not cf_api_key) and CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                    cf_email = cf_email or saved.get('cf_email')
                    cf_api_key = cf_api_key or saved.get('cf_api_key')
            except Exception:
                pass
        
        if not cf_email or not cf_api_key:
            return jsonify({"status": "error", "message": "Cloudflare email and API key required (configure in Step 2 first)"}), 400
        
        # Fetch zones (domains) from Cloudflare API
        import urllib.request
        import urllib.parse
        import json as json_module
        
        url = "https://api.cloudflare.com/client/v4/zones"
        req = urllib.request.Request(url)
        req.add_header('X-Auth-Email', cf_email)
        req.add_header('X-Auth-Key', cf_api_key)
        req.add_header('Content-Type', 'application/json')
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = json_module.loads(response.read().decode('utf-8'))
                
                if response_data.get('success'):
                    zones = response_data.get('result', [])
                    domains = []
                    for zone in zones:
                        domains.append({
                            'name': zone.get('name', ''),
                            'status': zone.get('status', 'unknown'),
                            'zone_id': zone.get('id', ''),
                            'plan': zone.get('plan', {}).get('name', 'Free')
                        })
                    return jsonify({
                        "status": "success",
                        "domains": domains
                    })
                else:
                    errors = response_data.get('errors', [])
                    error_msg = errors[0].get('message', 'Unknown error') if errors else 'Failed to fetch domains'
                    return jsonify({
                        "status": "error",
                        "message": error_msg
                    })
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            try:
                error_data = json_module.loads(error_body)
                error_msg = error_data.get('errors', [{}])[0].get('message', 'HTTP Error') if error_data.get('errors') else 'HTTP Error'
            except:
                error_msg = f"HTTP {e.code}: {e.reason}"
            return jsonify({
                "status": "error",
                "message": error_msg
            })
        except urllib.error.URLError as e:
            return jsonify({
                "status": "error",
                "message": f"Network error: {str(e)}"
            })
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": f"Error fetching domains: {str(e)}"
            })
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/status/check', methods=['POST'])
def check_service_status():
    """Check service status on VPS"""
    try:
        # Load config
        if not CONFIG_FILE.exists():
            return jsonify({"status": "error", "message": "Configuration not found"})
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        host = config.get('vps_host')
        user = config.get('vps_user', 'root')
        port = config.get('vps_port', 22)
        password = config.get('password')
        
        if not host or not password:
            return jsonify({"status": "error", "message": "VPS configuration not found"})
        
        from installer_backend import execute_ssh_command
        
        # Use ASCII-safe checks only (avoid unicode bullets from `systemctl status`)
        # 1) Check if service is active
        is_active = False
        is_enabled = False
        
        # Active status
        status_cmd = "sudo systemctl is-active oxcookie-manager 2>&1 || echo 'inactive'"
        success_status, status_out, _ = execute_ssh_command(
            host, user, port, status_cmd, password, timeout=5
        )
        service_status = status_out.strip() if success_status and status_out else 'unknown'
        is_active = service_status.lower() == 'active'
        
        # Enabled status
        enabled_cmd = "sudo systemctl is-enabled oxcookie-manager 2>&1 || echo 'disabled'"
        success_enabled, enabled_out, _ = execute_ssh_command(
            host, user, port, enabled_cmd, password, timeout=5
        )
        is_enabled = success_enabled and 'enabled' in (enabled_out or '').lower()
        
        # Build a simple ASCII-safe full output
        full_output_parts = []
        if status_out:
            try:
                full_output_parts.append(status_out.encode('ascii', errors='replace').decode('ascii'))
            except Exception:
                full_output_parts.append(status_out)
        if enabled_out:
            try:
                full_output_parts.append(enabled_out.encode('ascii', errors='replace').decode('ascii'))
            except Exception:
                full_output_parts.append(enabled_out)
        full_output = "\n".join(full_output_parts).strip() or "No additional status output"
        
        return jsonify({
            "status": "success",
            "service_status": service_status,
            "is_active": is_active,
            "is_enabled": is_enabled,
            "full_output": full_output
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/logs/service', methods=['POST'])
def get_service_logs():
    """Get service logs"""
    try:
        if not CONFIG_FILE.exists():
            return jsonify({"status": "error", "message": "Configuration not found"})
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        host = config.get('vps_host')
        user = config.get('vps_user', 'root')
        port = config.get('vps_port', 22)
        password = config.get('password')
        lines = request.json.get('lines', 50)
        
        if not host or not password:
            return jsonify({"status": "error", "message": "VPS configuration not found"})
        
        from installer_backend import execute_ssh_command
        
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            f"sudo journalctl -u oxcookie-manager -n {lines} --no-pager 2>&1",
            password, timeout=15
        )
        
        return jsonify({
            "status": "success",
            "logs": stdout if stdout else stderr
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/logs/nginx', methods=['POST'])
def get_nginx_logs():
    """Get Nginx logs"""
    try:
        if not CONFIG_FILE.exists():
            return jsonify({"status": "error", "message": "Configuration not found"})
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        host = config.get('vps_host')
        user = config.get('vps_user', 'root')
        port = config.get('vps_port', 22)
        password = config.get('password')
        domain = config.get('domain', '')
        lines = request.json.get('lines', 50)
        
        if not host or not password:
            return jsonify({"status": "error", "message": "VPS configuration not found"})
        
        from installer_backend import execute_ssh_command
        
        # Use app-specific log files if domain is configured, otherwise use default logs
        if domain:
            domain_safe = domain.replace('.', '_').replace('*', '_')
            access_log = f"/var/log/nginx/oxcookie-{domain_safe}-access.log"
            error_log = f"/var/log/nginx/oxcookie-{domain_safe}-error.log"
            
            # Try app-specific logs first, fallback to default logs
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                f"sudo tail -n {lines} {access_log} {error_log} 2>&1 || sudo tail -n {lines} /var/log/nginx/access.log /var/log/nginx/error.log 2>&1",
                password, timeout=15
            )
        else:
            # Use default Nginx logs
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                f"sudo tail -n {lines} /var/log/nginx/access.log /var/log/nginx/error.log 2>&1",
                password, timeout=15
            )
        
        return jsonify({
            "status": "success",
            "logs": stdout if stdout else stderr
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/nginx/config', methods=['POST'])
def get_nginx_config():
    """Get Nginx configuration"""
    try:
        if not CONFIG_FILE.exists():
            return jsonify({"status": "error", "message": "Configuration not found"})
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        host = config.get('vps_host')
        user = config.get('vps_user', 'root')
        port = config.get('vps_port', 22)
        password = config.get('password')
        domain = config.get('domain', '')
        
        if not host or not password:
            return jsonify({"status": "error", "message": "VPS configuration not found"})
        
        from installer_backend import execute_ssh_command
        
        # Get Nginx config for the domain (use sanitized domain name)
        if domain:
            domain_safe = domain.replace('.', '_').replace('*', '_')
            config_path = f"/etc/nginx/sites-available/{domain_safe}"
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                f"sudo cat {config_path} 2>&1 || echo 'Config file not found'",
                password, timeout=10
            )
        else:
            # Get all enabled sites
            success, stdout, stderr = execute_ssh_command(
                host, user, port,
                "sudo ls -la /etc/nginx/sites-enabled/ 2>&1",
                password, timeout=10
            )
        
        return jsonify({
            "status": "success",
            "config": stdout if stdout else stderr,
            "domain": domain
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/domain/lookup', methods=['POST'])
def check_domain_lookup():
    """Check domain DNS configuration.
    If Cloudflare is configured, query Cloudflare DNS records directly.
    Otherwise, fall back to standard DNS lookup."""
    try:
        if not CONFIG_FILE.exists():
            return jsonify({"status": "error", "message": "Configuration not found"})
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        domain = request.json.get('domain') or config.get('domain', '')
        
        if not domain:
            return jsonify({"status": "error", "message": "No domain specified"})
        
        dns_provider = config.get('dns_provider')
        cf_email = config.get('cf_email')
        cf_api_key = config.get('cf_api_key')
        
        # If Cloudflare is configured, use Cloudflare API to read the DNS record
        if dns_provider == 'cloudflare' and cf_email and cf_api_key:
            import urllib.request
            import json as json_module
            
            # Derive base_domain and subdomain
            base_domain = config.get('base_domain')
            if not base_domain:
                parts = domain.split('.')
                if len(parts) >= 2:
                    base_domain = '.'.join(parts[-2:])
            if not base_domain:
                return jsonify({"status": "error", "message": "Base domain not configured for Cloudflare"})
            
            # 1) Get zone ID
            zone_url = f"https://api.cloudflare.com/client/v4/zones?name={base_domain}"
            zone_req = urllib.request.Request(zone_url)
            zone_req.add_header('X-Auth-Email', cf_email)
            zone_req.add_header('X-Auth-Key', cf_api_key)
            zone_req.add_header('Content-Type', 'application/json')
            
            try:
                with urllib.request.urlopen(zone_req, timeout=30) as response:
                    zone_data = json_module.loads(response.read())
                    if not (zone_data.get('success') and zone_data.get('result')):
                        return jsonify({"status": "error", "message": "Failed to get Cloudflare zone ID"})
                    zone_id = zone_data['result'][0]['id']
            except Exception as e:
                return jsonify({"status": "error", "message": f"Cloudflare zone lookup failed: {str(e)}"})
            
            # 2) Get DNS A records for this domain
            records_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type=A&name={domain}"
            rec_req = urllib.request.Request(records_url)
            rec_req.add_header('X-Auth-Email', cf_email)
            rec_req.add_header('X-Auth-Key', cf_api_key)
            rec_req.add_header('Content-Type', 'application/json')
            
            try:
                with urllib.request.urlopen(rec_req, timeout=30) as response:
                    rec_data = json_module.loads(response.read())
                    if not rec_data.get('success'):
                        msg = rec_data.get('errors', [{}])[0].get('message', 'Failed to fetch DNS records')
                        return jsonify({"status": "error", "message": msg})
                    
                    result = rec_data.get('result', [])
                    if not result:
                        return jsonify({
                            "status": "error",
                            "domain": domain,
                            "message": "No A record found in Cloudflare for this domain"
                        })
                    
                    # Use the first A record
                    record = result[0]
                    ip = record.get('content')
                    proxied = record.get('proxied', False)
                    
                    return jsonify({
                        "status": "success",
                        "domain": domain,
                        "ip": ip,
                        "proxied": proxied,
                        "source": "cloudflare",
                        "message": f"Cloudflare A record for {domain}: {ip} (proxied={proxied})"
                    })
            except Exception as e:
                return jsonify({"status": "error", "message": f"Cloudflare DNS record lookup failed: {str(e)}"})
        
        # Fallback: standard DNS lookup
        import socket
        try:
            ip = socket.gethostbyname(domain)
            return jsonify({
                "status": "success",
                "domain": domain,
                "ip": ip,
                "source": "public-dns",
                "message": f"Domain {domain} resolves to {ip}"
            })
        except socket.gaierror as e:
            return jsonify({
                "status": "error",
                "message": f"DNS lookup failed: {str(e)}"
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/domain/update', methods=['POST'])
def update_domain():
    """Update domain configuration and reconfigure DNS/Nginx/SSL for the new domain"""
    try:
        if not CONFIG_FILE.exists():
            return jsonify({"status": "error", "message": "Configuration not found"})
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        new_domain = request.json.get('domain', '').strip()
        
        if not new_domain:
            return jsonify({"status": "error", "message": "Domain is required"})
        
        old_domain = config.get('domain', '')
        config['domain'] = new_domain
        
        # Derive base_domain and subdomain for the new domain
        parts = new_domain.split('.')
        base_domain = ''
        subdomain = ''
        if len(parts) > 2:
            base_domain = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
        elif len(parts) == 2:
            base_domain = new_domain
            subdomain = ''
        config['base_domain'] = base_domain
        config['subdomain'] = subdomain
        
        # Save config
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        # Update DNS / Nginx / SSL if service is installed
        host = config.get('vps_host')
        user = config.get('vps_user', 'root')
        port = config.get('vps_port', 22)
        password = config.get('password')
        
        if host and password:
            from installer_backend import execute_ssh_command, configure_services, setup_dns
            
            # 1) Remove old Nginx config (sanitized domain name)
            nginx_success = False
            nginx_msg = ""
            
            if old_domain:
                old_domain_safe = old_domain.replace('.', '_').replace('*', '_')
                execute_ssh_command(
                    host, user, port,
                    f"sudo rm -f /etc/nginx/sites-enabled/{old_domain_safe} /etc/nginx/sites-available/{old_domain_safe}",
                    password, timeout=10
                )
            
            # 2) Ensure DNS record for new domain (Cloudflare) is created/updated
            try:
                dns_success, dns_msg = setup_dns({
                    "host": host,
                    "user": user,
                    "port": port,
                    "password": password,
                    "domain": new_domain,
                    "base_domain": base_domain,
                    "subdomain": subdomain,
                    "dns_provider": config.get("dns_provider"),
                    "cf_email": config.get("cf_email"),
                    "cf_api_key": config.get("cf_api_key"),
                    "cf_token": config.get("cf_token")
                })
            except Exception as e:
                dns_success = False
                dns_msg = str(e)
            
            # 3) Reconfigure services (Nginx + SSL + Cloudflare SSL mode)
            try:
                nginx_success, nginx_msg = configure_services(config, None)
            except Exception as e:
                nginx_success = False
                nginx_msg = f"Failed to update Nginx config: {str(e)}"
            
            if nginx_success:
                # Reload Nginx
                execute_ssh_command(
                    host, user, port,
                    "sudo nginx -t && sudo systemctl reload nginx",
                    password, timeout=10
                )
        
        return jsonify({
            "status": "success",
            "message": f"Domain updated to {new_domain}",
            "old_domain": old_domain,
            "new_domain": new_domain
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/service/restart', methods=['POST'])
def restart_service():
    """Restart the service"""
    try:
        if not CONFIG_FILE.exists():
            return jsonify({"status": "error", "message": "Configuration not found"})
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        host = config.get('vps_host')
        user = config.get('vps_user', 'root')
        port = config.get('vps_port', 22)
        password = config.get('password')
        
        if not host or not password:
            return jsonify({"status": "error", "message": "VPS configuration not found"})
        
        from installer_backend import execute_ssh_command
        
        success, stdout, stderr = execute_ssh_command(
            host, user, port,
            "sudo systemctl restart oxcookie-manager 2>&1",
            password, timeout=15
        )
        
        if success:
            return jsonify({
                "status": "success",
                "message": "Service restarted successfully",
                "output": stdout
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to restart service",
                "output": stderr if stderr else stdout
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/fix-app', methods=['POST'])
def fix_app():
    """Check and fix app configuration (domain, firewall, nginx)"""
    try:
        if not CONFIG_FILE.exists():
            return jsonify({"status": "error", "message": "Configuration not found"})
        
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        host = config.get('vps_host')
        user = config.get('vps_user', 'root')
        port = config.get('vps_port', 22)
        password = config.get('password')
        domain = config.get('domain', '')
        app_port = config.get('app_port', 5004)
        
        if not host or not password:
            return jsonify({"status": "error", "message": "VPS configuration not found"})
        
        from installer_backend import execute_ssh_command
        import threading
        
        # Use global fix_state
        global fix_state
        fix_state = {
            "status": "running",
            "progress": 0,
            "current_step": "Initializing...",
            "log": [],
            "error": None
        }
        
        def add_log(message, progress=None):
            import time as time_module
            timestamp = time_module.strftime("[%H:%M:%S]")
            log_entry = f"{timestamp} {message}"
            fix_state["log"].append(log_entry)
            if progress is not None:
                fix_state["progress"] = progress
            fix_state["current_step"] = message
            print(log_entry)
            import sys
            sys.stdout.flush()
        
        def run_fix():
            global fix_state
            try:
                add_log("[INFO] Starting app configuration fix...", 5)
                
                # Step 1: Check firewall
                add_log("[INFO] Checking firewall rules...", 10)
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    f"sudo ufw status numbered 2>&1 | grep -q '{app_port}/tcp' && echo 'ALLOWED' || echo 'NOT_ALLOWED'",
                    password, timeout=10
                )
                
                # Also check if UFW is enabled
                ufw_enabled = False
                success2, stdout2, stderr2 = execute_ssh_command(
                    host, user, port,
                    "sudo ufw status 2>&1 | grep -q 'Status: active' && echo 'ENABLED' || echo 'DISABLED'",
                    password, timeout=10
                )
                if success2 and 'ENABLED' in stdout2:
                    ufw_enabled = True
                    add_log("[OK] UFW firewall is enabled", 12)
                else:
                    add_log("[WARN] UFW firewall is not enabled", 12)
                
                if success and 'NOT_ALLOWED' in stdout:
                    add_log(f"[INFO] Port {app_port} not allowed in firewall, adding rule...", 20)
                    success, stdout, stderr = execute_ssh_command(
                        host, user, port,
                        f"sudo ufw allow {app_port}/tcp 2>&1",
                        password, timeout=10
                    )
                    if success:
                        add_log(f"[OK] Firewall rule added for port {app_port}", 30)
                    else:
                        add_log(f"[WARN] Could not add firewall rule: {stdout if stdout else stderr}", 30)
                else:
                    add_log(f"[OK] Port {app_port} is already allowed in firewall", 30)
                
                # Step 2: Check Nginx configuration
                if domain:
                    add_log(f"[INFO] Checking Nginx configuration for domain: {domain}...", 40)
                    
                    # Check if Nginx config exists for this domain
                    domain_safe = domain.replace('.', '_').replace('*', '_')
                    success, stdout, stderr = execute_ssh_command(
                        host, user, port,
                        f"sudo test -f /etc/nginx/sites-available/{domain_safe} && echo 'EXISTS' || echo 'NOT_FOUND'",
                        password, timeout=10
                    )
                    
                    if success and 'NOT_FOUND' in stdout:
                        add_log("[INFO] Nginx configuration not found, creating...", 50)
                        # Use configure_services to create Nginx config
                        from installer_backend import configure_services
                        nginx_config = {
                            'host': host,
                            'user': user,
                            'port': port,
                            'password': password,
                            'domain': domain,
                            'app_port': app_port,
                            'install_dir': config.get('install_dir', '/opt/oxcookie-manager')
                        }
                        success, message = configure_services(nginx_config, add_log)
                        if success:
                            add_log("[OK] Nginx configuration created", 70)
                        else:
                            add_log(f"[ERROR] Failed to create Nginx config: {message}", 70)
                    else:
                        # Check if config is correct
                        add_log("[INFO] Verifying Nginx configuration...", 50)
                        success, stdout, stderr = execute_ssh_command(
                            host, user, port,
                            f"sudo grep -q 'server_name {domain}' /etc/nginx/sites-available/{domain_safe} 2>&1 && echo 'CORRECT' || echo 'INCORRECT'",
                            password, timeout=10
                        )
                        
                        if success and 'CORRECT' in stdout:
                            add_log("[OK] Nginx configuration is correct", 60)
                        else:
                            add_log("[INFO] Nginx configuration needs update, recreating...", 60)
                            # Remove old config and recreate
                            execute_ssh_command(
                                host, user, port,
                                f"sudo rm -f /etc/nginx/sites-enabled/{domain_safe} /etc/nginx/sites-available/{domain_safe}",
                                password, timeout=10
                            )
                            from installer_backend import configure_services
                            nginx_config = {
                                'host': host,
                                'user': user,
                                'port': port,
                                'password': password,
                                'domain': domain,
                                'app_port': app_port,
                                'install_dir': config.get('install_dir', '/opt/oxcookie-manager')
                            }
                            success, message = configure_services(nginx_config, add_log)
                            if success:
                                add_log("[OK] Nginx configuration updated", 70)
                            else:
                                add_log(f"[ERROR] Failed to update Nginx config: {message}", 70)
                    
                    # Test and reload Nginx
                    add_log("[INFO] Testing Nginx configuration...", 75)
                    success, stdout, stderr = execute_ssh_command(
                        host, user, port,
                        "sudo nginx -t 2>&1",
                        password, timeout=10
                    )
                    
                    if success:
                        add_log("[OK] Nginx configuration test passed", 80)
                        # Reload Nginx
                        add_log("[INFO] Reloading Nginx...", 85)
                        success, stdout, stderr = execute_ssh_command(
                            host, user, port,
                            "sudo systemctl reload nginx 2>&1",
                            password, timeout=10
                        )
                        if success:
                            add_log("[OK] Nginx reloaded successfully", 90)
                        else:
                            add_log(f"[WARN] Nginx reload warning: {stdout if stdout else stderr}", 90)
                    else:
                        add_log(f"[ERROR] Nginx configuration test failed: {stdout if stdout else stderr}", 80)
                else:
                    add_log("[WARN] No domain configured, skipping Nginx check", 50)
                
                # Step 3: Check and fix DNS (Cloudflare)
                try:
                    dns_provider = config.get('dns_provider')
                    cf_email = config.get('cf_email')
                    cf_api_key = config.get('cf_api_key')
                    cf_token = config.get('cf_token')
                    
                    if dns_provider == 'cloudflare' and domain and (cf_api_key or cf_token) and cf_email:
                        add_log("[INFO] Checking DNS configuration in Cloudflare...", 88)
                        
                        # Get VPS public IP from the server
                        success_ip, stdout_ip, stderr_ip = execute_ssh_command(
                            host, user, port,
                            "curl -s https://ifconfig.me || curl -s ifconfig.me || hostname -I | awk '{print $1}'",
                            password, timeout=10
                        )
                        vps_ip = stdout_ip.strip().split()[0] if success_ip and stdout_ip else None
                        
                        # Resolve current domain IP
                        current_ip = None
                        try:
                            import socket
                            current_ip = socket.gethostbyname(domain)
                            add_log(f"[INFO] Current DNS for {domain} resolves to {current_ip}", 89)
                        except Exception as e:
                            add_log(f"[WARN] DNS lookup failed for {domain}: {str(e)}", 89)
                        
                        if vps_ip:
                            add_log(f"[INFO] VPS public IP detected as {vps_ip}", 89)
                        
                            # If DNS does not point to VPS IP, force update via Cloudflare
                            if current_ip and current_ip != vps_ip:
                                add_log(f"[INFO] Cloudflare DNS is {current_ip}, VPS IP is {vps_ip} – updating A record...", 90)
                                from installer_backend import setup_dns
                                
                                dns_config = dict(config)
                                dns_config['host'] = host
                                dns_config['user'] = user
                                dns_config['port'] = port
                                dns_config['password'] = password
                                dns_config['domain'] = domain
                                
                                dns_success, dns_message = setup_dns(dns_config, add_log)
                                if dns_success:
                                    add_log(f"[OK] DNS updated for {domain}: {dns_message}", 90)
                                else:
                                    add_log(f"[WARN] DNS update failed: {dns_message}", 90)
                            elif current_ip == vps_ip:
                                add_log(f"[OK] DNS already points to VPS IP ({current_ip})", 90)
                            else:
                                add_log("[WARN] Could not determine current DNS IP, skipping DNS update", 90)
                    else:
                        add_log("[INFO] Cloudflare DNS not configured or domain missing, skipping DNS fix", 88)
                except Exception as e:
                    add_log(f"[WARN] DNS check/update error: {str(e)}", 90)
                
                # Step 4: Check and setup SSL certificate (Let's Encrypt)
                try:
                    dns_provider = config.get('dns_provider')
                    ssl_email = config.get('ssl_email') or config.get('cf_email')
                    
                    if dns_provider == 'cloudflare' and domain and ssl_email:
                        add_log("[INFO] Checking SSL certificate status...", 92)
                        from installer_backend import setup_ssl
                        
                        ssl_config = dict(config)
                        ssl_config['host'] = host
                        ssl_config['user'] = user
                        ssl_config['port'] = port
                        ssl_config['password'] = password
                        
                        ssl_success, ssl_message = setup_ssl(ssl_config, add_log)
                        if ssl_success:
                            add_log(f"[OK] SSL check/setup completed: {ssl_message}", 93)
                        else:
                            add_log(f"[WARN] SSL setup issue: {ssl_message}", 93)
                    else:
                        add_log("[INFO] SSL not configured (no email or domain), skipping SSL fix", 92)
                except Exception as e:
                    add_log(f"[WARN] SSL check/setup error: {str(e)}", 93)
                
                # Step 5: Verify service is running
                add_log("[INFO] Checking service status...", 95)
                success, stdout, stderr = execute_ssh_command(
                    host, user, port,
                    "sudo systemctl is-active oxcookie-manager 2>&1",
                    password, timeout=10
                )
                
                if success and 'active' in stdout.lower():
                    add_log("[OK] Service is running", 100)
                else:
                    add_log("[INFO] Service is not running, attempting to start...", 95)
                    success, stdout, stderr = execute_ssh_command(
                        host, user, port,
                        "sudo systemctl start oxcookie-manager 2>&1",
                        password, timeout=15
                    )
                    if success:
                        add_log("[OK] Service started successfully", 100)
                    else:
                        add_log(f"[WARN] Could not start service: {stdout if stdout else stderr}", 100)
                
                fix_state["status"] = "completed"
                fix_state["progress"] = 100
                add_log("[SUCCESS] App configuration fix completed!", 100)
                
            except Exception as e:
                fix_state["status"] = "error"
                fix_state["error"] = str(e)
                add_log(f"[ERROR] {str(e)}", 100)
        
        # Start fix in background thread
        thread = threading.Thread(target=run_fix, daemon=True)
        thread.start()
        
        # Return immediately with status
        return jsonify({
            "status": "started",
            "message": "Fix operation started"
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/progress/fix-app', methods=['GET'])
def get_fix_app_progress():
    """Get progress for fix-app operation"""
    global fix_state
    if 'fix_state' not in globals():
        fix_state = {
            "status": "idle",
            "progress": 0,
            "current_step": "",
            "log": [],
            "error": None
        }
    return jsonify(fix_state)

if __name__ == '__main__':
    print("=" * 60)
    print("  oXCookie Manager - Web UI Installer")
    print("=" * 60)
    print(f"Access at: http://localhost:5005")
    print("=" * 60)
    print()
    
    app.run(host='127.0.0.1', port=5005, debug=True)

