# oXCookie Manager - Web UI Installer

A beautiful web-based installer for deploying oXCookie Manager to your VPS.

## Features

- 🎨 **Modern Web UI**: Beautiful black and glassy design
- 🔐 **SSH Key Management**: Generate and manage SSH keys
- 🌐 **DNS Automation**: Automatic DNS setup for Cloudflare, DigitalOcean
- 📊 **Real-time Progress**: Live installation progress and logs
- 🔄 **Connection Testing**: Test SSH connection before installation
- 📦 **File Validation**: Checks all required files before installation

## Quick Start

1. **Install dependencies**
   ```bash
   cd installer-ui
   pip install -r requirements.txt
   ```

2. **Run the installer**
   ```bash
   python app.py
   ```

3. **Open in browser**
   ```
   http://localhost:5005
   ```

## Usage

1. **VPS Connection**
   - Enter VPS IP, username, and port
   - Choose SSH key or password authentication
   - Generate new SSH key if needed
   - Test connection

2. **Domain Configuration**
   - Enter domain name
   - Auto-detect if subdomain or base domain
   - Generate random subdomain if needed
   - Configure DNS (optional)

3. **Application Configuration**
   - Set application port
   - Set installation directory

4. **Install**
   - Review configuration
   - Click "Start Installation"
   - Watch real-time progress

## Requirements

- Python 3.8+
- Flask 3.0.0+
- OpenSSH client (for SSH/SCP)
- sshpass (optional, for password auth - installer can download it)

## Notes

- The installer runs locally on your machine
- It connects to your VPS to deploy the application
- All deployment files should be in the parent `deployment/` directory
- SSH keys are saved in the installer directory

