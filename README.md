# oXCookie Manager v3

Complete deployment package for oXCookie Manager - Flask Admin Interface for Evilginx Monitor.

## 📁 Files Included

### Core Application
- `app.py` - Main Flask application (1825 lines)
- `requirements.txt` - Python dependencies
- `start.sh` - Startup script

### Supporting Modules
- `notifications.py` - Telegram, Discord, and Email notification functions
- `database_reader.py` - Database reading utilities
- `session_processor.py` - Session processing and cookie extraction

### Templates
- `templates/index.html` - Main dashboard with modal system
- `templates/login.html` - Login page
- `templates/manage_admins.html` - Admin management
- `templates/notifications.html` - Notifications settings
- `templates/database_viewer.html` - Database viewer

### Configuration
- `config/` - Configuration directory (created at runtime)
- `DEFAULT_SETTINGS.md` - Default settings documentation
- `DEPLOYMENT.md` - Deployment instructions

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python3 app.py
   ```
   Or use the startup script:
   ```bash
   ./start.sh
   ```

3. **Access the web interface:**
   - Default URL: `http://localhost:5004`
   - Default credentials: Check `DEFAULT_SETTINGS.md`

## 📋 Features

- **Session Management** - View and manage evilginx sessions
- **Cookie Extraction** - Extract cookies in JSON format
- **Admin Management** - Multi-admin support with roles
- **Notifications** - Telegram, Discord, and Email notifications
- **Database Viewer** - View and search session database
- **Modal System** - Modern modal UI for session details

## 🔧 Configuration

Configuration files are stored in `~/.evilginx_monitor/`:
- `config.json` - Application settings
- `auth.json` - Admin authentication data

## 📝 Notes

- This is a complete, ready-to-deploy package
- All necessary files for deployment are included
- Compatible with 0x-Deployer module system
- Uses port 5004 by default
