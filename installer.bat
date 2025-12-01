@echo off
setlocal enabledelayedexpansion

:: oXCookie Manager - Automated VPS Installer
:: This script will deploy and configure oXCookie Manager on your VPS

echo.
echo ========================================
echo   oXCookie Manager - VPS Installer
echo ========================================
echo.

:: Check if required tools are available
where ssh >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] SSH client not found. Please install OpenSSH or use WSL.
    echo.
    echo You can install OpenSSH from Windows Settings ^> Apps ^> Optional Features
    pause
    exit /b 1
)

where scp >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] SCP client not found. Please install OpenSSH or use WSL.
    pause
    exit /b 1
)

:: Step 1: Collect VPS Information
echo [Step 1/6] VPS Connection Information
echo ----------------------------------------
set /p VPS_HOST="Enter VPS IP address or hostname: "
set /p VPS_USER="Enter SSH username (default: root): "
if "%VPS_USER%"=="" set VPS_USER=root
set /p VPS_PORT="Enter SSH port (default: 22): "
if "%VPS_PORT%"=="" set VPS_PORT=22

echo.
echo [INFO] SSH Key Authentication is recommended for security.
set /p USE_KEY="Use SSH key authentication? (y/n, default: n): "
if /i "%USE_KEY%"=="y" (
    set /p SSH_KEY_PATH="Enter path to SSH private key: "
    if not exist "%SSH_KEY_PATH%" (
        echo [ERROR] SSH key file not found: %SSH_KEY_PATH%
        pause
        exit /b 1
    )
    set SSH_OPTS=-i "%SSH_KEY_PATH%" -p %VPS_PORT%
    set SCP_OPTS=-i "%SSH_KEY_PATH%" -P %VPS_PORT%
) else (
    echo [WARNING] Password authentication will be used.
    echo [WARNING] You will be prompted for password multiple times.
    set SSH_OPTS=-p %VPS_PORT%
    set SCP_OPTS=-P %VPS_PORT%
)

echo.
echo [Step 2/6] Domain Configuration
echo ----------------------------------------
set /p DOMAIN="Enter your domain name (e.g., cookies.example.com): "
if "%DOMAIN%"=="" (
    echo [ERROR] Domain name is required
    pause
    exit /b 1
)

echo.
echo [Step 3/6] DNS Configuration
echo ----------------------------------------
echo [INFO] DNS setup requires API credentials from your DNS provider.
set /p SETUP_DNS="Do you want to set up DNS automatically? (y/n, default: n): "
if /i "%SETUP_DNS%"=="y" (
    echo.
    echo Select your DNS provider:
    echo 1. Cloudflare
    echo 2. DigitalOcean
    echo 3. AWS Route53
    echo 4. Manual (skip DNS setup)
    set /p DNS_PROVIDER="Enter choice (1-4, default: 4): "
    
    if "%DNS_PROVIDER%"=="1" (
        set /p CF_API_TOKEN="Enter Cloudflare API Token: "
        set /p CF_ZONE_ID="Enter Cloudflare Zone ID: "
    ) else if "%DNS_PROVIDER%"=="2" (
        set /p DO_API_TOKEN="Enter DigitalOcean API Token: "
    ) else if "%DNS_PROVIDER%"=="3" (
        set /p AWS_ACCESS_KEY="Enter AWS Access Key ID: "
        set /p AWS_SECRET_KEY="Enter AWS Secret Access Key: "
        set /p AWS_ZONE_ID="Enter Route53 Hosted Zone ID: "
    )
)

echo.
echo [Step 4/6] Application Configuration
echo ----------------------------------------
set /p APP_PORT="Enter application port (default: 5004): "
if "%APP_PORT%"=="" set APP_PORT=5004

set /p INSTALL_DIR="Enter installation directory on VPS (default: /opt/oxcookie-manager): "
if "%INSTALL_DIR%"=="" set INSTALL_DIR=/opt/oxcookie-manager

echo.
echo [Step 5/6] Review Configuration
echo ----------------------------------------
echo VPS Host: %VPS_HOST%
echo SSH User: %VPS_USER%
echo SSH Port: %VPS_PORT%
echo Domain: %DOMAIN%
echo App Port: %APP_PORT%
echo Install Dir: %INSTALL_DIR%
echo.
set /p CONFIRM="Continue with installation? (y/n): "
if /i not "%CONFIRM%"=="y" (
    echo Installation cancelled.
    exit /b 0
)

echo.
echo ========================================
echo   Starting Installation...
echo ========================================
echo.

:: Step 6: Deploy and Install
echo [1/8] Testing SSH connection...
ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "echo 'SSH connection successful'" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Failed to connect to VPS. Please check credentials.
    pause
    exit /b 1
)
echo [OK] SSH connection successful

echo.
echo [2/8] Creating installation directory...
ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "sudo mkdir -p %INSTALL_DIR% && sudo chown %VPS_USER%:%VPS_USER% %INSTALL_DIR%"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create directory
    pause
    exit /b 1
)
echo [OK] Directory created

echo.
echo [3/8] Uploading application files...
:: Upload all files except installer and docs
for %%f in (app.py database_reader.py notifications.py session_processor.py requirements.txt start.sh) do (
    echo   Uploading %%f...
    scp %SCP_OPTS% "%%f" %VPS_USER%@%VPS_HOST%:%INSTALL_DIR%/
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to upload %%f
        pause
        exit /b 1
    )
)

echo   Uploading templates...
scp %SCP_OPTS% -r templates %VPS_USER%@%VPS_HOST%:%INSTALL_DIR%/
if %errorlevel% neq 0 (
    echo [ERROR] Failed to upload templates
    pause
    exit /b 1
)
echo [OK] Files uploaded

echo.
echo [4/8] Installing Python dependencies...
ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "cd %INSTALL_DIR% && python3 -m pip install --user -r requirements.txt"
if %errorlevel% neq 0 (
    echo [WARNING] pip install failed, trying with sudo...
    ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "cd %INSTALL_DIR% && sudo pip3 install -r requirements.txt"
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
)
echo [OK] Dependencies installed

echo.
echo [5/8] Creating systemd service...
ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "cat > /tmp/oxcookie-manager.service << 'EOF'
[Unit]
Description=oXCookie Manager Flask Application
After=network.target

[Service]
Type=simple
User=%VPS_USER%
WorkingDirectory=%INSTALL_DIR%
Environment=\"PATH=/usr/bin:/usr/local/bin:/home/%VPS_USER%/.local/bin\"
ExecStart=/usr/bin/python3 %INSTALL_DIR%/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
sudo mv /tmp/oxcookie-manager.service /etc/systemd/system/oxcookie-manager.service && sudo systemctl daemon-reload"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create systemd service
    pause
    exit /b 1
)
echo [OK] Systemd service created

echo.
echo [6/8] Installing and configuring Nginx...
ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "sudo apt-get update -qq && sudo apt-get install -y nginx > /dev/null 2>&1"
if %errorlevel% neq 0 (
    echo [WARNING] Nginx installation may have failed, continuing...
)

:: Create Nginx config
ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "cat > /tmp/oxcookie-manager-nginx << 'EOF'
server {
    listen 80;
    server_name %DOMAIN%;

    location / {
        proxy_pass http://127.0.0.1:%APP_PORT%;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
sudo mv /tmp/oxcookie-manager-nginx /etc/nginx/sites-available/oxcookie-manager && sudo ln -sf /etc/nginx/sites-available/oxcookie-manager /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload nginx"
if %errorlevel% neq 0 (
    echo [WARNING] Nginx configuration may have issues
) else (
    echo [OK] Nginx configured
)

echo.
echo [7/8] Starting application service...
ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "sudo systemctl enable oxcookie-manager && sudo systemctl start oxcookie-manager"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to start service
    pause
    exit /b 1
)
echo [OK] Service started

:: Wait a moment and check status
timeout /t 3 /nobreak >nul
ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "sudo systemctl status oxcookie-manager --no-pager -l | head -n 10"
echo.

echo [8/8] Setting up DNS...
if /i "%SETUP_DNS%"=="y" (
    if "%DNS_PROVIDER%"=="1" (
        echo [INFO] Setting up Cloudflare DNS...
        ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "curl -s -X GET \"https://api.cloudflare.com/client/v4/zones/%CF_ZONE_ID%/dns_records?name=%DOMAIN%\" -H \"Authorization: Bearer %CF_API_TOKEN%\" -H \"Content-Type: application/json\" > /tmp/dns_check.json"
        :: Check if record exists and create/update
        ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "VPS_IP=\$(curl -s ifconfig.me) && curl -s -X POST \"https://api.cloudflare.com/client/v4/zones/%CF_ZONE_ID%/dns_records\" -H \"Authorization: Bearer %CF_API_TOKEN%\" -H \"Content-Type: application/json\" --data '{\"type\":\"A\",\"name\":\"%DOMAIN%\",\"content\":\"'\"\$VPS_IP\"'\",\"ttl\":3600}' > /tmp/dns_result.json && cat /tmp/dns_result.json"
        echo [OK] DNS record created/updated
    ) else if "%DNS_PROVIDER%"=="2" (
        echo [INFO] Setting up DigitalOcean DNS...
        ssh %SSH_OPTS% %VPS_USER%@%VPS_HOST% "VPS_IP=\$(curl -s ifconfig.me) && curl -s -X POST \"https://api.digitalocean.com/v2/domains/\$(echo %DOMAIN% | cut -d. -f2-)/records\" -H \"Authorization: Bearer %DO_API_TOKEN%\" -H \"Content-Type: application/json\" --data '{\"type\":\"A\",\"name\":\"\$(echo %DOMAIN% | cut -d. -f1)\",\"data\":\"'\"\$VPS_IP\"'\",\"ttl\":3600}'"
        echo [OK] DNS record created/updated
    ) else if "%DNS_PROVIDER%"=="3" (
        echo [INFO] Setting up AWS Route53 DNS...
        echo [WARNING] AWS Route53 setup requires AWS CLI. Please configure DNS manually.
    ) else (
        echo [INFO] Skipping DNS setup. Please configure manually:
        echo        Create an A record: %DOMAIN% -> [VPS IP]
    )
) else (
    echo [INFO] DNS setup skipped. Please configure manually:
    echo        Create an A record: %DOMAIN% -> [VPS IP]
)

echo.
echo ========================================
echo   Installation Complete!
echo ========================================
echo.
echo Application URL: http://%DOMAIN%
echo                  http://%VPS_HOST%:%APP_PORT%
echo.
echo Default Login:
echo   Username: admin
echo   Password: admin123
echo.
echo [IMPORTANT] Next Steps:
echo   1. Access the application and login
echo   2. Change the default password immediately
echo   3. Configure database path in Settings
echo   4. Configure Telegram/Discord/Email notifications
echo   5. Set up SSL certificate (Let's Encrypt)
echo.
echo To set up SSL:
echo   ssh %VPS_USER%@%VPS_HOST%
echo   sudo apt-get install certbot python3-certbot-nginx
echo   sudo certbot --nginx -d %DOMAIN%
echo.
echo Service Management:
echo   sudo systemctl status oxcookie-manager
echo   sudo systemctl restart oxcookie-manager
echo   sudo journalctl -u oxcookie-manager -f
echo.
pause

