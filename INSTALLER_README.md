# Automated VPS Installer

The `installer.bat` script automates the complete deployment of oXCookie Manager to your VPS.

## Prerequisites

### Windows Requirements
- Windows 10/11 with OpenSSH client installed
  - Install from: Settings → Apps → Optional Features → OpenSSH Client
- Or use WSL (Windows Subsystem for Linux)

### VPS Requirements
- Ubuntu/Debian-based Linux server
- SSH access with sudo privileges
- Python 3.8 or higher
- Internet connection

## What the Installer Does

1. **Collects Information**
   - VPS connection details (IP, username, port)
   - Domain name
   - DNS provider credentials (optional)
   - Application configuration

2. **Deploys Application**
   - Uploads all application files to VPS
   - Installs Python dependencies
   - Creates systemd service
   - Configures Nginx reverse proxy

3. **Sets Up DNS** (optional)
   - Creates A record for your domain
   - Supports Cloudflare, DigitalOcean, AWS Route53

4. **Starts Service**
   - Enables and starts the application
   - Verifies it's running

## Usage

1. **Run the installer**
   ```cmd
   installer.bat
   ```

2. **Follow the prompts**
   - Enter VPS connection details
   - Enter domain name
   - Choose DNS setup (optional)
   - Review and confirm

3. **Wait for installation**
   - The script will show progress for each step
   - Installation typically takes 2-5 minutes

4. **Access your application**
   - Open browser: `http://your-domain.com`
   - Login with: `admin` / `admin123`
   - **Change password immediately!**

## SSH Authentication

### Option 1: SSH Key (Recommended)
- More secure
- No password prompts
- Generate key: `ssh-keygen -t rsa -b 4096`
- Copy to VPS: `ssh-copy-id user@vps-ip`

### Option 2: Password (Automated)
- Password is asked once and saved for the session
- Uses `sshpass` for automated authentication
- Install sshpass on Windows: https://github.com/keimpx/sshpass-windows
- Or use WSL which includes sshpass
- Less secure but convenient for quick deployments

## DNS Setup

### Automatic DNS Setup
The installer supports automatic DNS record creation for:
- **Cloudflare (Global API Key)**: Requires Email and Global API Key (automatically gets Zone ID)
- **Cloudflare (API Token)**: Requires API Token and Zone ID
- **DigitalOcean**: Requires API Token
- **AWS Route53**: Requires Access Key, Secret Key, and Zone ID

### Subdomain Auto-Generation
- If you enter a base domain (e.g., `example.com`), the installer will ask if you want to create a subdomain
- If yes, it automatically generates a random subdomain (e.g., `oxcookie-abc12345.example.com`)
- The subdomain is then automatically configured in DNS
- If you enter a subdomain directly, it uses that subdomain

### Manual DNS Setup
If you skip automatic DNS setup, manually create an A record:
- **Type**: A
- **Name**: your-domain.com (or subdomain)
- **Value**: Your VPS IP address
- **TTL**: 3600 (or default)

## Post-Installation

### 1. Change Default Password
- Login to application
- Go to Manage Admins
- Change admin password

### 2. Configure Database Path
- Go to ⚙️ Configuration
- Set Database File Path to your Evilginx database location

### 3. Configure Notifications
- Set Telegram token and chat ID
- Configure Discord (optional)
- Configure Email (optional)

### 4. Set Up SSL Certificate
```bash
ssh user@your-vps
sudo apt-get install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## Troubleshooting

### SSH Connection Failed
- Verify VPS IP address
- Check SSH port (default: 22)
- Ensure firewall allows SSH
- Test connection manually: `ssh user@vps-ip`

### File Upload Failed
- Check disk space on VPS
- Verify SSH permissions
- Try using SSH key instead of password

### Service Won't Start
```bash
ssh user@vps-ip
sudo systemctl status oxcookie-manager
sudo journalctl -u oxcookie-manager -n 50
```

### Nginx Configuration Error
```bash
ssh user@vps-ip
sudo nginx -t
sudo systemctl status nginx
```

### DNS Not Working
- Verify DNS record was created
- Check DNS propagation: `nslookup your-domain.com`
- Wait a few minutes for DNS to propagate

## Manual Installation

If the installer fails, follow the manual installation guide in `DEPLOYMENT.md`.

## Security Notes

1. **Change default password immediately**
2. **Use SSH keys, not passwords**
3. **Set up SSL/HTTPS**
4. **Configure firewall** (only allow 22, 80, 443)
5. **Keep system updated**: `sudo apt-get update && sudo apt-get upgrade`

## Support

For issues or questions:
- Check application logs: `sudo journalctl -u oxcookie-manager -f`
- Review Nginx logs: `sudo tail -f /var/log/nginx/error.log`
- Check service status: `sudo systemctl status oxcookie-manager`

