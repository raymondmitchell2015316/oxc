# oXCookie Manager - Automated VPS Installer (PowerShell)
# This script will deploy and configure oXCookie Manager on your VPS
# Requirements: sshpass (for password auth) or SSH keys
# Install sshpass on Windows: https://github.com/keimpx/sshpass-windows

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  oXCookie Manager - VPS Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if SSH is available
try {
    $null = Get-Command ssh -ErrorAction Stop
} catch {
    Write-Host "[ERROR] SSH client not found. Please install OpenSSH." -ForegroundColor Red
    Write-Host "Install from: Settings > Apps > Optional Features > OpenSSH Client" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Step 1: Collect VPS Information
Write-Host "[Step 1/6] VPS Connection Information" -ForegroundColor Green
Write-Host "----------------------------------------"
$VPS_HOST = Read-Host "Enter VPS IP address or hostname"
$VPS_USER = Read-Host "Enter SSH username (default: root)"
if ([string]::IsNullOrWhiteSpace($VPS_USER)) { $VPS_USER = "root" }
$VPS_PORT = Read-Host "Enter SSH port (default: 22)"
if ([string]::IsNullOrWhiteSpace($VPS_PORT)) { $VPS_PORT = "22" }

Write-Host ""
Write-Host "[INFO] SSH Key Authentication is recommended for security." -ForegroundColor Yellow
$USE_KEY = Read-Host "Use SSH key authentication? (y/n, default: n)"
$SSH_OPTS = "-p $VPS_PORT"
$SCP_OPTS = "-P $VPS_PORT"
$SSH_PASSWORD = ""
$SSH_KEY_PATH = ""
$GENERATE_KEY = $false

if ($USE_KEY -eq "y" -or $USE_KEY -eq "Y") {
    $SSH_KEY_PATH = Read-Host "Enter path to SSH private key (leave empty to generate new key)"
    
    if ([string]::IsNullOrWhiteSpace($SSH_KEY_PATH)) {
        Write-Host "[INFO] No key path provided. Will generate a new SSH key pair." -ForegroundColor Yellow
        
        # Ask for password to copy key to VPS
        $securePassword = Read-Host "Enter SSH password (to copy generated key to VPS)" -AsSecureString
        $SSH_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
        
        # Generate key pair in deployment folder
        $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $keyName = "oxcookie_vps_key"
        $SSH_KEY_PATH = Join-Path $scriptDir "$keyName"
        $SSH_PUB_KEY_PATH = "$SSH_KEY_PATH.pub"
        
        Write-Host "[INFO] Generating SSH key pair..." -ForegroundColor Yellow
        Write-Host "  Private key: $SSH_KEY_PATH" -ForegroundColor Gray
        Write-Host "  Public key: $SSH_PUB_KEY_PATH" -ForegroundColor Gray
        
        # Generate SSH key using ssh-keygen
        $keygenCmd = "ssh-keygen -t rsa -b 4096 -f `"$SSH_KEY_PATH`" -N `"`" -C `"oxcookie-manager-vps`""
        Invoke-Expression $keygenCmd
        
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $SSH_KEY_PATH)) {
            Write-Host "[ERROR] Failed to generate SSH key" -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }
        
        Write-Host "[OK] SSH key pair generated" -ForegroundColor Green
        $GENERATE_KEY = $true
        
        # Check for sshpass to copy key
        $null = sshpass -V 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[WARNING] sshpass not found. Required to copy key to VPS." -ForegroundColor Yellow
            Write-Host ""
            $installSshpass = Read-Host "Do you want to install sshpass automatically? (y/n, default: y)"
            
            if ($installSshpass -eq "" -or $installSshpass -eq "y" -or $installSshpass -eq "Y") {
                Write-Host "[INFO] Installing sshpass..." -ForegroundColor Yellow
                
                # Try Chocolatey first
                $chocoAvailable = $false
                try {
                    $null = choco --version 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $chocoAvailable = $true
                    }
                } catch {
                    $chocoAvailable = $false
                }
                
                if ($chocoAvailable) {
                    Write-Host "  Installing via Chocolatey..." -ForegroundColor Gray
                    $null = choco install sshpass -y
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "[OK] sshpass installed via Chocolatey" -ForegroundColor Green
                    } else {
                        Write-Host "[WARNING] Chocolatey installation failed, trying direct download..." -ForegroundColor Yellow
                        $chocoAvailable = $false
                    }
                }
                
                # If Chocolatey failed or not available, try direct download
                if (-not $chocoAvailable) {
                    Write-Host "  Downloading sshpass from GitHub..." -ForegroundColor Gray
                    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
                    $sshpassDir = Join-Path $scriptDir "sshpass"
                    $sshpassExe = Join-Path $sshpassDir "sshpass.exe"
                    
                    # Create sshpass directory
                    if (-not (Test-Path $sshpassDir)) {
                        New-Item -ItemType Directory -Path $sshpassDir | Out-Null
                    }
                    
                    # Download sshpass
                    $sshpassUrl = "https://github.com/keimpx/sshpass-windows/releases/latest/download/sshpass.exe"
                    try {
                        Write-Host "  Downloading from: $sshpassUrl" -ForegroundColor Gray
                        Invoke-WebRequest -Uri $sshpassUrl -OutFile $sshpassExe -UseBasicParsing -ErrorAction Stop
                        
                        if (Test-Path $sshpassExe) {
                            Write-Host "[OK] sshpass downloaded" -ForegroundColor Green
                            
                            # Add to PATH for current session
                            $env:Path += ";$sshpassDir"
                            
                            # Verify installation
                            $null = & $sshpassExe -V 2>&1
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "[OK] sshpass is ready to use" -ForegroundColor Green
                                Write-Host "[INFO] sshpass.exe saved to: $sshpassDir" -ForegroundColor Gray
                                
                                # Update sshpass command to use full path
                                $SSH_PASS_CMD = "& `"$sshpassExe`" -p `"$SSH_PASSWORD`" "
                                $SCP_PASS_CMD = "& `"$sshpassExe`" -P `"$SSH_PASSWORD`" "
                            } else {
                                Write-Host "[ERROR] sshpass download failed verification" -ForegroundColor Red
                                $SSH_PASS_CMD = ""
                                $SCP_PASS_CMD = ""
                            }
                        } else {
                            Write-Host "[ERROR] Failed to download sshpass" -ForegroundColor Red
                            $SSH_PASS_CMD = ""
                            $SCP_PASS_CMD = ""
                        }
                    } catch {
                        Write-Host "[ERROR] Failed to download sshpass: $_" -ForegroundColor Red
                        Write-Host "[INFO] You can manually download from: $sshpassUrl" -ForegroundColor Yellow
                        $SSH_PASS_CMD = ""
                        $SCP_PASS_CMD = ""
                    }
                }
                
                # Final check
                $null = sshpass -V 2>&1
                if ($LASTEXITCODE -ne 0 -and $SSH_PASS_CMD -eq "") {
                    Write-Host "[WARNING] sshpass installation failed" -ForegroundColor Yellow
                    Write-Host "[INFO] You'll need to manually copy the key:" -ForegroundColor Yellow
                    Write-Host "       type $SSH_PUB_KEY_PATH | ssh $VPS_USER@$VPS_HOST `"cat >> ~/.ssh/authorized_keys`"" -ForegroundColor Cyan
                    $SSH_PASS_CMD = ""
                    $SCP_PASS_CMD = ""
                } else {
                    if ($SSH_PASS_CMD -eq "") {
                        $SSH_PASS_CMD = "sshpass -p `"$SSH_PASSWORD`" "
                        $SCP_PASS_CMD = "sshpass -p `"$SSH_PASSWORD`" "
                    }
                    Write-Host "[OK] sshpass is ready" -ForegroundColor Green
                }
            } else {
                Write-Host "[INFO] Skipping sshpass installation." -ForegroundColor Yellow
                Write-Host "[INFO] You'll need to manually copy the key:" -ForegroundColor Yellow
                Write-Host "       type $SSH_PUB_KEY_PATH | ssh $VPS_USER@$VPS_HOST `"cat >> ~/.ssh/authorized_keys`"" -ForegroundColor Cyan
                $SSH_PASS_CMD = ""
                $SCP_PASS_CMD = ""
            }
        } else {
            $SSH_PASS_CMD = "sshpass -p `"$SSH_PASSWORD`" "
            $SCP_PASS_CMD = "sshpass -p `"$SSH_PASSWORD`" "
        }
        
        $SSH_OPTS = "-i `"$SSH_KEY_PATH`" -p $VPS_PORT"
        $SCP_OPTS = "-i `"$SSH_KEY_PATH`" -P $VPS_PORT"
    } else {
        if (-not (Test-Path $SSH_KEY_PATH)) {
            Write-Host "[ERROR] SSH key file not found: $SSH_KEY_PATH" -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }
        $SSH_OPTS = "-i `"$SSH_KEY_PATH`" -p $VPS_PORT"
        $SCP_OPTS = "-i `"$SSH_KEY_PATH`" -P $VPS_PORT"
    }
} else {
    Write-Host "[INFO] Password authentication will be used." -ForegroundColor Yellow
    $securePassword = Read-Host "Enter SSH password" -AsSecureString
    $SSH_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
    
    # Check for sshpass (for password authentication)
    Write-Host "[INFO] Checking for sshpass..." -ForegroundColor Gray
    $null = sshpass -V 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[WARNING] sshpass not found!" -ForegroundColor Yellow
        Write-Host "[INFO] sshpass is required for automated password authentication." -ForegroundColor Yellow
        Write-Host ""
        $installSshpass = Read-Host "Do you want to install sshpass automatically? (y/n, default: y)"
        
        if ($installSshpass -eq "" -or $installSshpass -eq "y" -or $installSshpass -eq "Y") {
            Write-Host "[INFO] Installing sshpass..." -ForegroundColor Yellow
            
            # Try Chocolatey first
            $chocoAvailable = $false
            try {
                $null = choco --version 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $chocoAvailable = $true
                }
            } catch {
                $chocoAvailable = $false
            }
            
            if ($chocoAvailable) {
                Write-Host "  Installing via Chocolatey..." -ForegroundColor Gray
                $null = choco install sshpass -y
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "[OK] sshpass installed via Chocolatey" -ForegroundColor Green
                } else {
                    Write-Host "[WARNING] Chocolatey installation failed, trying direct download..." -ForegroundColor Yellow
                    $chocoAvailable = $false
                }
            }
            
            # If Chocolatey failed or not available, try direct download
            if (-not $chocoAvailable) {
                Write-Host "  Downloading sshpass from GitHub..." -ForegroundColor Gray
                $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
                $sshpassDir = Join-Path $scriptDir "sshpass"
                $sshpassExe = Join-Path $sshpassDir "sshpass.exe"
                
                # Create sshpass directory
                if (-not (Test-Path $sshpassDir)) {
                    New-Item -ItemType Directory -Path $sshpassDir | Out-Null
                }
                
                # Download sshpass
                $sshpassUrl = "https://github.com/keimpx/sshpass-windows/releases/latest/download/sshpass.exe"
                try {
                    Write-Host "  Downloading from: $sshpassUrl" -ForegroundColor Gray
                    Invoke-WebRequest -Uri $sshpassUrl -OutFile $sshpassExe -UseBasicParsing -ErrorAction Stop
                    
                    if (Test-Path $sshpassExe) {
                        Write-Host "[OK] sshpass downloaded" -ForegroundColor Green
                        
                        # Add to PATH for current session
                        $env:Path += ";$sshpassDir"
                        
                        # Verify installation
                        $null = & $sshpassExe -V 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "[OK] sshpass is ready to use" -ForegroundColor Green
                            Write-Host "[INFO] sshpass.exe saved to: $sshpassDir" -ForegroundColor Gray
                            Write-Host "[INFO] It will be used for this installation session." -ForegroundColor Gray
                            
                            # Update sshpass command to use full path
                            $SSH_PASS_CMD = "& `"$sshpassExe`" -p `"$SSH_PASSWORD`" "
                            $SCP_PASS_CMD = "& `"$sshpassExe`" -P `"$SSH_PASSWORD`" "
                        } else {
                            Write-Host "[ERROR] sshpass download failed verification" -ForegroundColor Red
                            $SSH_PASS_CMD = ""
                            $SCP_PASS_CMD = ""
                        }
                    } else {
                        Write-Host "[ERROR] Failed to download sshpass" -ForegroundColor Red
                        $SSH_PASS_CMD = ""
                        $SCP_PASS_CMD = ""
                    }
                } catch {
                    Write-Host "[ERROR] Failed to download sshpass: $_" -ForegroundColor Red
                    Write-Host "[INFO] You can manually download from: $sshpassUrl" -ForegroundColor Yellow
                    $SSH_PASS_CMD = ""
                    $SCP_PASS_CMD = ""
                }
            }
            
            # Final check
            $null = sshpass -V 2>&1
            if ($LASTEXITCODE -ne 0 -and $SSH_PASS_CMD -eq "") {
                Write-Host "[WARNING] sshpass installation failed or not in PATH" -ForegroundColor Yellow
                Write-Host "[INFO] You can:" -ForegroundColor Yellow
                Write-Host "   1. Manually install from: https://github.com/keimpx/sshpass-windows" -ForegroundColor Cyan
                Write-Host "   2. Use WSL (Windows Subsystem for Linux)" -ForegroundColor Cyan
                Write-Host "   3. Use SSH key authentication (recommended)" -ForegroundColor Cyan
                Write-Host ""
                $continue = Read-Host "Continue anyway? You'll be prompted for password multiple times (y/n)"
                if ($continue -ne "y" -and $continue -ne "Y") {
                    Write-Host "Installation cancelled. Please install sshpass or use SSH keys." -ForegroundColor Red
                    exit 1
                }
            } else {
                if ($SSH_PASS_CMD -eq "") {
                    $SSH_PASS_CMD = "sshpass -p `"$SSH_PASSWORD`" "
                    $SCP_PASS_CMD = "sshpass -p `"$SSH_PASSWORD`" "
                }
                Write-Host "[OK] sshpass is ready" -ForegroundColor Green
            }
        } else {
            Write-Host "[INFO] Skipping sshpass installation." -ForegroundColor Yellow
            Write-Host "[WARNING] You'll be prompted for password multiple times." -ForegroundColor Yellow
            $SSH_PASS_CMD = ""
            $SCP_PASS_CMD = ""
        }
    } else {
        Write-Host "[OK] sshpass found" -ForegroundColor Green
        $SSH_PASS_CMD = "sshpass -p `"$SSH_PASSWORD`" "
        $SCP_PASS_CMD = "sshpass -p `"$SSH_PASSWORD`" "
    }
    
    # Use sshpass for password authentication
    $SSH_OPTS = "-p $VPS_PORT"
    $SCP_OPTS = "-P $VPS_PORT"
}

# Step 2: Domain Configuration
Write-Host ""
Write-Host "[Step 2/6] Domain Configuration" -ForegroundColor Green
Write-Host "----------------------------------------"
$DOMAIN = Read-Host "Enter your domain name (e.g., cookies.example.com or example.com)"
if ([string]::IsNullOrWhiteSpace($DOMAIN)) {
    Write-Host "[ERROR] Domain name is required" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if domain is a subdomain (has more than 2 parts when split by dot)
$domainParts = $DOMAIN.Split('.')
$isSubdomain = $domainParts.Length -gt 2
$BASE_DOMAIN = ""
$SUBDOMAIN = ""

if (-not $isSubdomain) {
    Write-Host "[INFO] You entered a base domain: $DOMAIN" -ForegroundColor Yellow
    $createSubdomain = Read-Host "Do you want to create a random subdomain? (y/n, default: y)"
    if ($createSubdomain -eq "" -or $createSubdomain -eq "y" -or $createSubdomain -eq "Y") {
        # Generate random subdomain
        $randomChars = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 8 | ForEach-Object {[char]$_})
        $SUBDOMAIN = "oxcookie-$randomChars"
        $DOMAIN = "$SUBDOMAIN.$DOMAIN"
        $BASE_DOMAIN = $domainParts[-2] + "." + $domainParts[-1]
        Write-Host "[OK] Generated subdomain: $DOMAIN" -ForegroundColor Green
    } else {
        $BASE_DOMAIN = $DOMAIN
    }
} else {
    # Extract base domain from subdomain
    $BASE_DOMAIN = $domainParts[-2] + "." + $domainParts[-1]
    $SUBDOMAIN = $domainParts[0]
}

# Step 3: DNS Configuration
Write-Host ""
Write-Host "[Step 3/6] DNS Configuration" -ForegroundColor Green
Write-Host "----------------------------------------"
Write-Host "[INFO] DNS setup requires API credentials from your DNS provider." -ForegroundColor Yellow
$SETUP_DNS = Read-Host "Do you want to set up DNS automatically? (y/n, default: n)"
$DNS_PROVIDER = ""
$CF_API_TOKEN = ""
$CF_ZONE_ID = ""
$DO_API_TOKEN = ""

if ($SETUP_DNS -eq "y" -or $SETUP_DNS -eq "Y") {
    Write-Host ""
    Write-Host "Select your DNS provider:"
    Write-Host "1. Cloudflare (Global API Key + Email)"
    Write-Host "2. Cloudflare (API Token)"
    Write-Host "3. DigitalOcean"
    Write-Host "4. Manual (skip DNS setup)"
    $DNS_PROVIDER = Read-Host "Enter choice (1-4, default: 1)"
    
    if ($DNS_PROVIDER -eq "" -or $DNS_PROVIDER -eq "1") {
        $CF_EMAIL = Read-Host "Enter Cloudflare Email"
        $secureCFKey = Read-Host "Enter Cloudflare Global API Key" -AsSecureString
        $CF_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCFKey))
        $DNS_PROVIDER = "1"
    } elseif ($DNS_PROVIDER -eq "2") {
        $secureCFToken = Read-Host "Enter Cloudflare API Token" -AsSecureString
        $CF_API_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCFToken))
        $CF_ZONE_ID = Read-Host "Enter Cloudflare Zone ID"
    } elseif ($DNS_PROVIDER -eq "3") {
        $secureDOToken = Read-Host "Enter DigitalOcean API Token" -AsSecureString
        $DO_API_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureDOToken))
    }
}

# Step 4: Application Configuration
Write-Host ""
Write-Host "[Step 4/6] Application Configuration" -ForegroundColor Green
Write-Host "----------------------------------------"
$APP_PORT = Read-Host "Enter application port (default: 5004)"
if ([string]::IsNullOrWhiteSpace($APP_PORT)) { $APP_PORT = "5004" }

$INSTALL_DIR = Read-Host "Enter installation directory on VPS (default: /opt/oxcookie-manager)"
if ([string]::IsNullOrWhiteSpace($INSTALL_DIR)) { $INSTALL_DIR = "/opt/oxcookie-manager" }

# Step 5: Review Configuration
Write-Host ""
Write-Host "[Step 5/6] Review Configuration" -ForegroundColor Green
Write-Host "----------------------------------------"
Write-Host "VPS Host: $VPS_HOST"
Write-Host "SSH User: $VPS_USER"
Write-Host "SSH Port: $VPS_PORT"
Write-Host "Domain: $DOMAIN"
Write-Host "App Port: $APP_PORT"
Write-Host "Install Dir: $INSTALL_DIR"
Write-Host ""
$CONFIRM = Read-Host "Continue with installation? (y/n)"
if ($CONFIRM -ne "y" -and $CONFIRM -ne "Y") {
    Write-Host "Installation cancelled."
    exit 0
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Starting Installation..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to execute SSH command with password if needed
function Invoke-SSHCommand {
    param($Command)
    if ($USE_KEY -ne "y" -and $USE_KEY -ne "Y" -and $SSH_PASSWORD -ne "") {
        $fullCmd = "$SSH_PASS_CMD ssh $SSH_OPTS $VPS_USER@$VPS_HOST `"$Command`""
        Invoke-Expression $fullCmd
    } else {
        ssh $SSH_OPTS "$VPS_USER@$VPS_HOST" $Command
    }
}

# Function to execute SCP command with password if needed
function Invoke-SCPCommand {
    param($Source, $Destination)
    if ($USE_KEY -ne "y" -and $USE_KEY -ne "Y" -and $SSH_PASSWORD -ne "") {
        $fullCmd = "$SCP_PASS_CMD scp $SCP_OPTS `"$Source`" ${VPS_USER}@${VPS_HOST}:${Destination}"
        Invoke-Expression $fullCmd
    } else {
        scp $SCP_OPTS $Source "${VPS_USER}@${VPS_HOST}:${Destination}"
    }
}

# Step 6: Deploy and Install

# If we generated a new key, copy it to VPS first
if ($GENERATE_KEY -and $SSH_PASSWORD -ne "") {
    Write-Host "[0/8] Copying SSH public key to VPS..." -ForegroundColor Yellow
    
    # Read public key content
    $pubKeyContent = Get-Content $SSH_PUB_KEY_PATH -Raw | Out-String
    $pubKeyContent = $pubKeyContent.Trim()
    
    # Copy key to VPS using password
    if ($SSH_PASS_CMD -ne "") {
        # Use sshpass to copy key via script
        Write-Host "  Copying public key to VPS..." -ForegroundColor Gray
        $copyKeyScript = @"
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo '$pubKeyContent' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo "Key copied successfully"
"@
        $copyKeyScript | Out-File -FilePath "temp_copy_key.sh" -Encoding ASCII
        $null = scp $SCP_OPTS "temp_copy_key.sh" "${VPS_USER}@${VPS_HOST}:/tmp/copy_key.sh"
        Remove-Item temp_copy_key.sh
        
        $copyKeyCmd = "$SSH_PASS_CMD ssh $VPS_USER@$VPS_HOST `"bash /tmp/copy_key.sh`""
        $null = Invoke-Expression $copyKeyCmd
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[OK] SSH key copied to VPS" -ForegroundColor Green
            Write-Host "[INFO] Key files saved in: $(Split-Path -Parent $MyInvocation.MyCommand.Path)" -ForegroundColor Gray
            Write-Host "[INFO] Keep these keys safe for future use!" -ForegroundColor Yellow
        } else {
            Write-Host "[WARNING] Failed to copy key automatically. Trying alternative method..." -ForegroundColor Yellow
            # Try using ssh-copy-id if available
            if ($SSH_PASS_CMD -ne "") {
                $sshCopyIdCmd = "$SSH_PASS_CMD ssh-copy-id -i `"$SSH_PUB_KEY_PATH`" $VPS_USER@$VPS_HOST"
                $null = Invoke-Expression $sshCopyIdCmd
            }
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] SSH key copied to VPS (using ssh-copy-id)" -ForegroundColor Green
            } else {
                Write-Host "[WARNING] Automatic key copy failed. Please copy manually:" -ForegroundColor Yellow
                Write-Host "       type $SSH_PUB_KEY_PATH | ssh $VPS_USER@$VPS_HOST `"cat >> ~/.ssh/authorized_keys`"" -ForegroundColor Cyan
                $manualCopy = Read-Host "Have you copied the key manually? (y/n)"
                if ($manualCopy -ne "y" -and $manualCopy -ne "Y") {
                    Write-Host "Installation cancelled." -ForegroundColor Red
                    exit 1
                }
            }
        }
    } else {
        # Manual copy - user will be prompted
        Write-Host "[INFO] sshpass not available. Please copy the key manually:" -ForegroundColor Yellow
        Write-Host "       type $SSH_PUB_KEY_PATH | ssh $VPS_USER@$VPS_HOST `"cat >> ~/.ssh/authorized_keys`"" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Or use ssh-copy-id:" -ForegroundColor Yellow
        Write-Host "       ssh-copy-id -i $SSH_PUB_KEY_PATH $VPS_USER@$VPS_HOST" -ForegroundColor Cyan
        Write-Host ""
        $manualCopy = Read-Host "Have you copied the key manually? (y/n)"
        if ($manualCopy -ne "y" -and $manualCopy -ne "Y") {
            Write-Host "Installation cancelled." -ForegroundColor Red
            exit 1
        }
    }
}

Write-Host "[1/8] Testing SSH connection..." -ForegroundColor Yellow
$null = Invoke-SSHCommand "echo 'SSH connection successful'"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to connect to VPS. Please check credentials." -ForegroundColor Red
    if ($GENERATE_KEY) {
        Write-Host "[INFO] SSH key files are saved in: $(Split-Path -Parent $MyInvocation.MyCommand.Path)" -ForegroundColor Yellow
        Write-Host "[INFO] You may need to manually copy the public key to the VPS." -ForegroundColor Yellow
    }
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] SSH connection successful" -ForegroundColor Green

Write-Host ""
Write-Host "[2/8] Creating installation directory..." -ForegroundColor Yellow
Invoke-SSHCommand "sudo mkdir -p $INSTALL_DIR && sudo chown $VPS_USER`:$VPS_USER $INSTALL_DIR"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to create directory" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] Directory created" -ForegroundColor Green

Write-Host ""
Write-Host "[3/8] Uploading application files..." -ForegroundColor Yellow
$files = @("app.py", "database_reader.py", "notifications.py", "session_processor.py", "requirements.txt", "start.sh")
foreach ($file in $files) {
    if (Test-Path $file) {
        Write-Host "  Uploading $file..." -ForegroundColor Gray
        Invoke-SCPCommand $file "${INSTALL_DIR}/"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Failed to upload $file" -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

Write-Host "  Uploading templates..." -ForegroundColor Gray
if ($USE_KEY -eq "y" -or $USE_KEY -eq "Y") {
    scp $SCP_OPTS -r templates "${VPS_USER}@${VPS_HOST}:${INSTALL_DIR}/"
} elseif ($SSH_PASSWORD -ne "" -and $SCP_PASS_CMD -ne "") {
    if ($SCP_PASS_CMD.StartsWith("&")) {
        $fullCmd = "$SCP_PASS_CMD scp $SCP_OPTS -r templates ${VPS_USER}@${VPS_HOST}:${INSTALL_DIR}/"
    } else {
        $fullCmd = "$SCP_PASS_CMD scp $SCP_OPTS -r templates ${VPS_USER}@${VPS_HOST}:${INSTALL_DIR}/"
    }
    Invoke-Expression $fullCmd
} else {
    scp $SCP_OPTS -r templates "${VPS_USER}@${VPS_HOST}:${INSTALL_DIR}/"
}
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to upload templates" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] Files uploaded" -ForegroundColor Green

Write-Host ""
Write-Host "[4/8] Installing Python dependencies..." -ForegroundColor Yellow
Invoke-SSHCommand "cd $INSTALL_DIR && python3 -m pip install --user -r requirements.txt"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARNING] pip install failed, trying with sudo..." -ForegroundColor Yellow
    Invoke-SSHCommand "cd $INSTALL_DIR && sudo pip3 install -r requirements.txt"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install dependencies" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}
Write-Host "[OK] Dependencies installed" -ForegroundColor Green

Write-Host ""
Write-Host "[5/8] Creating systemd service..." -ForegroundColor Yellow
$serviceContent = @"
[Unit]
Description=oXCookie Manager Flask Application
After=network.target

[Service]
Type=simple
User=$VPS_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=/usr/bin:/usr/local/bin:/home/$VPS_USER/.local/bin"
ExecStart=/usr/bin/python3 $INSTALL_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"@

$serviceContent | Out-File -FilePath "temp_service.txt" -Encoding ASCII
Invoke-SCPCommand "temp_service.txt" "/tmp/oxcookie-manager.service"
Remove-Item temp_service.txt

Invoke-SSHCommand "sudo mv /tmp/oxcookie-manager.service /etc/systemd/system/oxcookie-manager.service && sudo systemctl daemon-reload"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to create systemd service" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] Systemd service created" -ForegroundColor Green

Write-Host ""
Write-Host "[6/8] Installing and configuring Nginx..." -ForegroundColor Yellow
Invoke-SSHCommand "sudo apt-get update -qq && sudo apt-get install -y nginx > /dev/null 2>&1"

$nginxConfig = @"
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_set_header Host `$host;
        proxy_set_header X-Real-IP `$remote_addr;
        proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto `$scheme;
    }
}
"@

$nginxConfig | Out-File -FilePath "temp_nginx.txt" -Encoding ASCII
Invoke-SCPCommand "temp_nginx.txt" "/tmp/oxcookie-manager-nginx"
Remove-Item temp_nginx.txt

Invoke-SSHCommand "sudo mv /tmp/oxcookie-manager-nginx /etc/nginx/sites-available/oxcookie-manager && sudo ln -sf /etc/nginx/sites-available/oxcookie-manager /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload nginx"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARNING] Nginx configuration may have issues" -ForegroundColor Yellow
} else {
    Write-Host "[OK] Nginx configured" -ForegroundColor Green
}

Write-Host ""
Write-Host "[7/8] Starting application service..." -ForegroundColor Yellow
Invoke-SSHCommand "sudo systemctl enable oxcookie-manager && sudo systemctl start oxcookie-manager"
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to start service" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "[OK] Service started" -ForegroundColor Green

Start-Sleep -Seconds 3
Write-Host ""
Write-Host "Service Status:" -ForegroundColor Cyan
Invoke-SSHCommand "sudo systemctl status oxcookie-manager --no-pager -l | head -n 10"

Write-Host ""
Write-Host "[8/8] DNS Setup..." -ForegroundColor Yellow
if ($SETUP_DNS -eq "y" -or $SETUP_DNS -eq "Y") {
    if ($DNS_PROVIDER -eq "1") {
        Write-Host "[INFO] Setting up Cloudflare DNS with Global API Key..." -ForegroundColor Yellow
        
        # First, get Zone ID from base domain
        Write-Host "  Getting Zone ID for $BASE_DOMAIN..." -ForegroundColor Gray
        $getZoneScript = @"
ZONE_ID=`$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$BASE_DOMAIN" \
  -H "X-Auth-Email: $CF_EMAIL" \
  -H "X-Auth-Key: $CF_API_KEY" \
  -H "Content-Type: application/json" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo `$ZONE_ID
"@
        $getZoneScript | Out-File -FilePath "temp_get_zone.sh" -Encoding ASCII
        Invoke-SCPCommand "temp_get_zone.sh" "/tmp/get_zone.sh"
        Remove-Item temp_get_zone.sh
        
        $zoneIdResult = Invoke-SSHCommand "chmod +x /tmp/get_zone.sh && bash /tmp/get_zone.sh"
        $CF_ZONE_ID = $zoneIdResult.Trim()
        
        if ([string]::IsNullOrWhiteSpace($CF_ZONE_ID)) {
            Write-Host "[ERROR] Failed to get Zone ID. Please check your Cloudflare credentials." -ForegroundColor Red
        } else {
            Write-Host "  Zone ID: $CF_ZONE_ID" -ForegroundColor Gray
            
            # Create DNS record
            $dnsScript = @"
VPS_IP=`$(curl -s ifconfig.me)
echo "Creating A record: $SUBDOMAIN.$BASE_DOMAIN -> `$VPS_IP"
RESULT=`$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
  -H "X-Auth-Email: $CF_EMAIL" \
  -H "X-Auth-Key: $CF_API_KEY" \
  -H "Content-Type: application/json" \
  --data "{\"type\":\"A\",\"name\":\"$SUBDOMAIN\",\"content\":\"`$VPS_IP\",\"ttl\":3600}")
echo `$RESULT
"@
            $dnsScript | Out-File -FilePath "temp_dns.sh" -Encoding ASCII
            Invoke-SCPCommand "temp_dns.sh" "/tmp/setup_dns.sh"
            Remove-Item temp_dns.sh
            
            $dnsResult = Invoke-SSHCommand "chmod +x /tmp/setup_dns.sh && bash /tmp/setup_dns.sh"
            Write-Host $dnsResult
            
            if ($dnsResult -match '"success":true') {
                Write-Host "[OK] DNS record created/updated: $DOMAIN -> [VPS IP]" -ForegroundColor Green
            } else {
                Write-Host "[WARNING] DNS record creation may have failed. Please check manually." -ForegroundColor Yellow
            }
        }
    } elseif ($DNS_PROVIDER -eq "2") {
        Write-Host "[INFO] Setting up Cloudflare DNS with API Token..." -ForegroundColor Yellow
        $dnsScript = @"
VPS_IP=`$(curl -s ifconfig.me)
curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"type\":\"A\",\"name\":\"$SUBDOMAIN\",\"content\":\"`$VPS_IP\",\"ttl\":3600}"
"@
        $dnsScript | Out-File -FilePath "temp_dns.sh" -Encoding ASCII
        Invoke-SCPCommand "temp_dns.sh" "/tmp/setup_dns.sh"
        Remove-Item temp_dns.sh
        Invoke-SSHCommand "chmod +x /tmp/setup_dns.sh && bash /tmp/setup_dns.sh"
        Write-Host "[OK] DNS record created/updated" -ForegroundColor Green
    } elseif ($DNS_PROVIDER -eq "3") {
        Write-Host "[INFO] Setting up DigitalOcean DNS..." -ForegroundColor Yellow
        if ($DO_API_TOKEN -ne "") {
            $dnsScript = @"
VPS_IP=`$(curl -s ifconfig.me)
DOMAIN_NAME=`$(echo $DOMAIN | cut -d. -f1)
BASE_DOMAIN=`$(echo $DOMAIN | sed 's/^[^.]*\.//')
curl -s -X POST "https://api.digitalocean.com/v2/domains/`$BASE_DOMAIN/records" \
  -H "Authorization: Bearer $DO_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data "{\"type\":\"A\",\"name\":\"`$DOMAIN_NAME\",\"data\":\"`$VPS_IP\",\"ttl\":3600}"
"@
            $dnsScript | Out-File -FilePath "temp_dns.sh" -Encoding ASCII
            Invoke-SCPCommand "temp_dns.sh" "/tmp/setup_dns.sh"
            Remove-Item temp_dns.sh
            $dnsResult = Invoke-SSHCommand "chmod +x /tmp/setup_dns.sh && bash /tmp/setup_dns.sh"
            Write-Host "[OK] DNS record created/updated" -ForegroundColor Green
        } else {
            Write-Host "[WARNING] DigitalOcean API token not provided" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[INFO] Skipping DNS setup. Please configure manually:" -ForegroundColor Yellow
        Write-Host "        Create an A record: $DOMAIN -> [VPS IP]" -ForegroundColor Yellow
    }
} else {
    Write-Host "[INFO] DNS setup skipped. Please configure manually:" -ForegroundColor Yellow
    Write-Host "        Create an A record: $DOMAIN -> [VPS IP]" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Application URL: http://$DOMAIN" -ForegroundColor Cyan
Write-Host "                 http://${VPS_HOST}:${APP_PORT}" -ForegroundColor Cyan
Write-Host ""
Write-Host "Default Login:" -ForegroundColor Yellow
Write-Host "  Username: admin"
Write-Host "  Password: admin123"
Write-Host ""
Write-Host "[IMPORTANT] Next Steps:" -ForegroundColor Red
Write-Host "  1. Access the application and login"
Write-Host "  2. Change the default password immediately"
Write-Host "  3. Configure database path in Settings"
Write-Host "  4. Configure Telegram/Discord/Email notifications"
Write-Host "  5. Set up SSL certificate (Let's Encrypt)"
Write-Host ""
Write-Host "To set up SSL:" -ForegroundColor Yellow
Write-Host "  ssh $VPS_USER@$VPS_HOST"
Write-Host "  sudo apt-get install certbot python3-certbot-nginx"
Write-Host "  sudo certbot --nginx -d $DOMAIN"
Write-Host ""
Write-Host "Service Management:" -ForegroundColor Yellow
Write-Host "  sudo systemctl status oxcookie-manager"
Write-Host "  sudo systemctl restart oxcookie-manager"
Write-Host "  sudo journalctl -u oxcookie-manager -f"
Write-Host ""
Read-Host "Press Enter to exit"

