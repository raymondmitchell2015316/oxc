# Deployment Guide for oXCookie Manager

## Quick Start

1. **Upload files to VPS**
   ```bash
   # Upload entire deployment folder to your VPS
   scp -r deployment/ user@your-vps:/opt/oxcookie-manager/
   ```

2. **SSH into VPS**
   ```bash
   ssh user@your-vps
   cd /opt/oxcookie-manager
   ```

3. **Install dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python3 app.py
   ```

5. **Configure via Web UI**
   - Access: `http://your-vps-ip:5004`
   - Login: `admin` / `admin123`
   - Go to **⚙️ Configuration** (Super Admin only)
   - **Set Database File Path** to your Evilginx database location
   - Configure other settings as needed

## Production Deployment with systemd

1. **Create systemd service**
   ```bash
   sudo nano /etc/systemd/system/oxcookie-manager.service
   ```

2. **Add this content** (update paths):
   ```ini
   [Unit]
   Description=oXCookie Manager Flask Application
   After=network.target

   [Service]
   Type=simple
   User=your-username
   WorkingDirectory=/opt/oxcookie-manager
   Environment="PATH=/usr/bin:/usr/local/bin"
   ExecStart=/usr/bin/python3 /opt/oxcookie-manager/app.py
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable and start**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable oxcookie-manager
   sudo systemctl start oxcookie-manager
   sudo systemctl status oxcookie-manager
   ```

## Nginx Reverse Proxy Setup

1. **Install Nginx** (if not installed)
   ```bash
   sudo apt-get update
   sudo apt-get install nginx
   ```

2. **Create Nginx config**
   ```bash
   sudo nano /etc/nginx/sites-available/oxcookie-manager
   ```

3. **Add configuration**:
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

4. **Enable site**
   ```bash
   sudo ln -s /etc/nginx/sites-available/oxcookie-manager /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

## SSL Setup (Let's Encrypt)

1. **Install Certbot**
   ```bash
   sudo apt-get install certbot python3-certbot-nginx
   ```

2. **Get SSL certificate**
   ```bash
   sudo certbot --nginx -d your-domain.com
   ```

## Firewall Configuration

```bash
# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow SSH (if needed)
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable
```

## Logs

- **Application logs**: Check systemd journal
  ```bash
  sudo journalctl -u oxcookie-manager -f
  ```

- **Nginx logs**: 
  ```bash
  sudo tail -f /var/log/nginx/access.log
  sudo tail -f /var/log/nginx/error.log
  ```

## Backup

1. **Backup configuration and auth files**
   ```bash
   # Config files are stored in ~/.evilginx_monitor/
   tar -czf oxcookie-backup-$(date +%Y%m%d).tar.gz ~/.evilginx_monitor/
   ```

2. **Backup database**
   ```bash
   cp /path/to/data.db /path/to/backup/data-$(date +%Y%m%d).db
   ```

## Updates

1. **Stop service**
   ```bash
   sudo systemctl stop oxcookie-manager
   ```

2. **Backup current version**
   ```bash
   cp -r /opt/oxcookie-manager /opt/oxcookie-manager-backup
   ```

3. **Upload new files**
   ```bash
   # Upload new files to /opt/oxcookie-manager
   ```

4. **Restart service**
   ```bash
   sudo systemctl start oxcookie-manager
   sudo systemctl status oxcookie-manager
   ```

## Troubleshooting

### Service won't start
```bash
# Check logs
sudo journalctl -u oxcookie-manager -n 50

# Check if port is in use
sudo netstat -tulpn | grep 5004

# Check file permissions
ls -la /opt/oxcookie-manager/
```

### Database not found
- Configure database path in Super Admin UI (⚙️ Configuration → Database File Path)
- Verify the path is correct and file exists
- Check file permissions: `ls -la /path/to/data.db`
- Ensure user has read access

### Notifications not working
- Verify Telegram token and chat ID
- Check network connectivity
- Review application logs

