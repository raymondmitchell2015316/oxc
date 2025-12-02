"""
SQLite Database for Admin/User Management
Uses transactions to ensure data integrity
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import contextmanager

# Database path
CONFIG_DIR = Path.home() / ".evilginx_monitor"
DB_FILE = CONFIG_DIR / "admins.db"

def get_db_connection():
    """Get database connection"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row  # Return rows as dict-like objects
    return conn

@contextmanager
def get_db_transaction():
    """Context manager for database transactions"""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def init_database():
    """Initialize database schema"""
    with get_db_transaction() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                subscription_expires TEXT,
                subscription_status TEXT DEFAULT 'active',
                account_locked INTEGER DEFAULT 0,
                lock_reason TEXT,
                locked_at TEXT,
                allowed_ips TEXT,  -- JSON array of IPs
                failed_ip_attempts TEXT,  -- JSON object of IP -> count
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Check if default admin exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', ('admin',))
        if cursor.fetchone()[0] == 0:
            # Create default super_admin
            now = datetime.now().isoformat()
            cursor.execute('''
                INSERT INTO users (username, password, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', ('admin', generate_password_hash('admin123'), 'super_admin', now, now))
        
        conn.commit()

def get_user_by_username(username):
    """Get user by username"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

def get_all_users():
    """Get all users"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def create_user(username, password, role='admin', subscription_days=30):
    """Create a new user with transaction"""
    with get_db_transaction() as conn:
        cursor = conn.cursor()
        
        # Check if username exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
        if cursor.fetchone()[0] > 0:
            raise ValueError("Username already exists")
        
        # Calculate subscription expiration
        expires_date = datetime.now()
        if subscription_days:
            from datetime import timedelta
            expires_date = expires_date + timedelta(days=subscription_days)
        
        now = datetime.now().isoformat()
        cursor.execute('''
            INSERT INTO users (username, password, role, subscription_expires, 
                            subscription_status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, generate_password_hash(password), role, 
              expires_date.isoformat(), 'active', now, now))
        
        return cursor.lastrowid

def update_user_subscription(username, subscription_days=None, subscription_status=None):
    """Update user subscription with transaction"""
    with get_db_transaction() as conn:
        cursor = conn.cursor()
        
        # Get current user
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            raise ValueError("User not found")
        
        user_dict = dict(user)
        updates = []
        params = []
        
        if subscription_days is not None:
            from datetime import datetime, timedelta
            old_expires = user_dict.get('subscription_expires')
            if old_expires:
                try:
                    old_date = datetime.fromisoformat(old_expires)
                    if old_date > datetime.now():
                        expires_date = old_date + timedelta(days=int(subscription_days))
                    else:
                        expires_date = datetime.now() + timedelta(days=int(subscription_days))
                except:
                    expires_date = datetime.now() + timedelta(days=int(subscription_days))
            else:
                expires_date = datetime.now() + timedelta(days=int(subscription_days))
            
            updates.append('subscription_expires = ?')
            params.append(expires_date.isoformat())
        
        if subscription_status is not None:
            if subscription_status not in ['active', 'suspended', 'expired']:
                raise ValueError("Invalid subscription status")
            updates.append('subscription_status = ?')
            params.append(subscription_status)
        
        if updates:
            updates.append('updated_at = ?')
            params.append(datetime.now().isoformat())
            params.append(username)
            
            cursor.execute(f'''
                UPDATE users 
                SET {', '.join(updates)}
                WHERE username = ?
            ''', params)
        
        # Return updated user
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        return dict(cursor.fetchone())

def update_user_ip_whitelist(username, allowed_ips):
    """Update user IP whitelist with transaction"""
    with get_db_transaction() as conn:
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
        if cursor.fetchone()[0] == 0:
            raise ValueError("User not found")
        
        allowed_ips_json = json.dumps(allowed_ips) if allowed_ips else '[]'
        
        cursor.execute('''
            UPDATE users 
            SET allowed_ips = ?, failed_ip_attempts = '{}', updated_at = ?
            WHERE username = ?
        ''', (allowed_ips_json, datetime.now().isoformat(), username))

def update_user_ip_access(username, failed_attempts=None, account_locked=None, 
                         lock_reason=None, locked_at=None, clear_failed=False):
    """Update user IP access tracking with transaction"""
    with get_db_transaction() as conn:
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            raise ValueError("User not found")
        
        updates = []
        params = []
        
        if clear_failed:
            updates.append('failed_ip_attempts = ?')
            params.append('{}')
        elif failed_attempts is not None:
            updates.append('failed_ip_attempts = ?')
            params.append(json.dumps(failed_attempts))
        
        if account_locked is not None:
            updates.append('account_locked = ?')
            params.append(1 if account_locked else 0)
        
        if lock_reason is not None:
            updates.append('lock_reason = ?')
            params.append(lock_reason)
        
        if locked_at is not None:
            updates.append('locked_at = ?')
            params.append(locked_at)
        
        if account_locked is False:
            # Clear lock fields when unlocking
            updates.append('lock_reason = NULL')
            updates.append('locked_at = NULL')
        
        if updates:
            updates.append('updated_at = ?')
            params.append(datetime.now().isoformat())
            params.append(username)
            
            cursor.execute(f'''
                UPDATE users 
                SET {', '.join(updates)}
                WHERE username = ?
            ''', params)
        
        # Return updated user
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        return dict(cursor.fetchone())

def delete_user(username):
    """Delete user with transaction"""
    with get_db_transaction() as conn:
        cursor = conn.cursor()
        
        # Don't allow deleting super_admin
        cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if not user:
            raise ValueError("User not found")
        
        if dict(user).get('role') == 'super_admin':
            raise ValueError("Cannot delete super admin")
        
        cursor.execute('DELETE FROM users WHERE username = ?', (username,))
        return cursor.rowcount > 0

def get_locked_accounts():
    """Get all locked accounts"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM users 
            WHERE account_locked = 1 
            ORDER BY locked_at DESC
        ''')
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def migrate_from_json():
    """Migrate data from JSON auth file to SQLite"""
    AUTH_FILE = CONFIG_DIR / "auth.json"
    
    if not AUTH_FILE.exists():
        return False
    
    try:
        with open(AUTH_FILE, 'r') as f:
            auth_data = json.load(f)
        
        users = auth_data.get('users', [])
        if not users:
            return False
        
        with get_db_transaction() as conn:
            cursor = conn.cursor()
            
            for user in users:
                username = user.get('username')
                if not username:
                    continue
                
                # Check if user already exists
                cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (username,))
                if cursor.fetchone()[0] > 0:
                    continue  # Skip if already exists
                
                # Parse JSON fields
                allowed_ips = user.get('allowed_ips', [])
                failed_attempts = user.get('failed_ip_attempts', {})
                
                now = datetime.now().isoformat()
                cursor.execute('''
                    INSERT INTO users (username, password, role, subscription_expires,
                                    subscription_status, account_locked, lock_reason,
                                    locked_at, allowed_ips, failed_ip_attempts,
                                    created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    username,
                    user.get('password', generate_password_hash('admin123')),
                    user.get('role', 'admin'),
                    user.get('subscription_expires'),
                    user.get('subscription_status', 'active'),
                    1 if user.get('account_locked', False) else 0,
                    user.get('lock_reason'),
                    user.get('locked_at'),
                    json.dumps(allowed_ips) if allowed_ips else '[]',
                    json.dumps(failed_attempts) if failed_attempts else '{}',
                    user.get('created_at', now),
                    user.get('updated_at', now)
                ))
        
        return True
    except Exception as e:
        print(f"Migration error: {e}")
        return False

# Initialize database on import
init_database()

