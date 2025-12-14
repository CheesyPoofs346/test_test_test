# CyberPatriot Linux Auto-Remediation Engine

A comprehensive, modular security remediation engine for CyberPatriot Linux competitions. Supports **Linux Mint 21** and **Ubuntu 24**.

## Features

- **Modular Architecture**: 22 independent security modules that can be enabled/disabled
- **AI-Powered README Parsing**: Uses OpenRouter AI to extract structured information from README files
 - **AI-Powered README Parsing**: Uses an AI API (Google Gemini preferred, OpenRouter supported) to extract structured information from README files
- **Automated Security Checks**: Comprehensive vulnerability scanning and remediation
- **Service Hardening**: Comprehensive hardening for SSH, FTP, Apache, NGINX, PostgreSQL, MySQL, Samba, and PHP
- **Score Tracking**: Logs all remediation actions for scoring verification
- **Backup System**: Automatically backs up files before modification
- **Flexible Configuration**: Easy-to-edit configuration file for customization
- **Intelligent Module Ordering**: Modules execute in optimized order to prevent conflicts

## Project Structure

```
cp-linux-auto/
├── cp-engine.sh              # Main engine script
├── config.conf               # Configuration file
├── lib/                      # Core libraries
│   ├── utils.sh             # Utility functions
│   └── openrouter.sh        # AI API interface (Gemini or OpenRouter)
├── modules/                  # Security modules (22 total)
│   ├── dependencies.sh      # Install required dependencies
│   ├── readme_parser.sh     # README parsing with AI
│   ├── forensics_questions.sh
│   ├── os_updates.sh        # System updates
│   ├── user_auditing.sh     # User management
│   ├── account_policy.sh    # Password policies
│   ├── local_policy.sh      # Local security policies
│   ├── security_policy.sh   # Kernel hardening (sysctl)
│   ├── ssh_hardening.sh     # SSH server hardening
│   ├── ftp_hardening.sh     # FTP server hardening
│   ├── postgres_hardening.sh # PostgreSQL hardening
│   ├── samba_hardening.sh   # Samba/SMB hardening
│   ├── mysql_hardening.sh   # MySQL/MariaDB hardening
│   ├── php_hardening.sh     # PHP hardening
│   ├── nginx_hardening.sh   # NGINX hardening
│   ├── apache_hardening.sh  # Apache hardening
│   ├── service_auditing.sh  # Service management
│   ├── unwanted_software.sh # Remove unwanted packages
│   ├── malware.sh          # Malware detection
│   ├── prohibited_files.sh # Media file detection
│   ├── defensive_countermeasures.sh # Firewall/IDS
│   └── os_settings.sh      # OS configuration
└── data/                     # Runtime data and logs
    ├── readme_parsed.json   # Parsed README data
    └── readme_plaintext.txt # README plain text
```

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd cp-linux-auto

# Make the main script executable
chmod +x cp-engine.sh

# Install dependencies
sudo apt-get update
sudo apt-get install curl jq
```

### 2. Configuration

Edit `config.conf` and set your AI API key. For Google Gemini set `GEMINI_API_KEY` or `GOOGLE_API_KEY`.

```bash
# Example: GEMINI_API_KEY="ya29.your_google_api_key"
GEMINI_API_KEY="your_api_key_here"
OPENROUTER_MODEL="google/gemini-3-pro-preview"
```

### 3. Usage

```bash
# Run all modules (requires root)
sudo ./cp-engine.sh

# Run in interactive mode
sudo ./cp-engine.sh -i

# Run specific module
sudo ./cp-engine.sh -m user_auditing

# Test API connection
sudo ./cp-engine.sh -t

# Quick AI connectivity test (alternatively)
scripts/test_ai.sh

# Check system compatibility
sudo ./cp-engine.sh -c

# Show help
./cp-engine.sh -h
```

## Module Load Order

The engine executes modules in a specific order to prevent conflicts and ensure dependencies are met. The default execution order is:

1. **dependencies** - Installs required system packages
2. **readme_parser** - Parses README with AI (provides data to other modules)
3. **forensics_questions** - Answers forensics questions
4. **os_updates** - Updates system packages
5. **user_auditing** - Manages user accounts
6. **account_policy** - Configures password policies
7. **local_policy** - Sets local security policies
8. **security_policy** - Kernel hardening via sysctl
9. **ssh_hardening** - Hardens SSH configuration
10. **ftp_hardening** - Hardens FTP configuration
11. **postgres_hardening** - Hardens PostgreSQL
12. **samba_hardening** - Hardens Samba/SMB
13. **mysql_hardening** - Hardens MySQL/MariaDB
14. **php_hardening** - Hardens PHP configuration
15. **nginx_hardening** - Hardens NGINX
16. **apache_hardening** - Hardens Apache
17. **service_auditing** - Manages system services
18. **unwanted_software** - Removes unwanted packages
19. **malware** - Scans for malware
20. **prohibited_files** - Scans for prohibited media files
21. **defensive_countermeasures** - Configures firewall and IDS
22. **os_settings** - Final OS configuration tweaks

This order is defined in `cp-engine.sh` (lines 23-46) and ensures that foundation modules like dependencies and README parsing run first, followed by user management, service hardening, and finally detection/cleanup modules.

## Modules

### 1. **Dependencies** (Foundation)
- Automatically installs required system packages
- Ensures curl, jq, and other essential tools are available
- Repairs APT sources if needed
- Updates package lists

### 2. **README Parser** (Core Module)
- Automatically finds README.html files
- Strips HTML content and extracts plain text
- Uses an AI API (Google Gemini preferred, OpenRouter supported) to parse structured information
- Provides data to all other modules

### 3. **Forensics Questions**
- Identifies forensics questions in README
- Helps answer common forensics questions
- Saves answers for manual submission

### 4. **OS Updates**
- Checks kernel version and updates
- Installs OS security patches
- Configures automatic security updates
- Detects required system reboots
- Runs full system upgrade (apt-get full-upgrade)
- Handles all package updates and dependencies

### 5. **User Auditing**
- Compares system users against README authorized list
- Identifies unauthorized users
- Detects terminated users with active accounts
- Creates missing authorized users
- Verifies admin privileges

### 6. **Account Policy**
- Configures password complexity requirements
- Sets password aging policies
- Configures account lockout
- Enforces minimum password length
- Sets up password history

### 7. **Local Policy**
- Configures sudo permissions
- Sets secure file permissions
- Configures audit logging (auditd)
- Sets secure umask values

### 8. **Security Policy**
- Implements kernel hardening via sysctl parameters
- Disables IP forwarding and source routing
- Enables SYN cookies and reverse path filtering
- Configures ICMP and network security settings
- Disables X Server TCP connections for security
- Hardens kernel security parameters

### 9. **SSH Hardening**
- Comprehensive SSH server hardening (PermitRootLogin, PasswordAuthentication, etc.)
- Configures strong cryptographic algorithms (ciphers, MACs, key exchange)
- Hardens SSH file and directory permissions
- Creates SSH banner for unauthorized access warnings
- Removes weak Diffie-Hellman moduli (>= 3071-bit only)
- Configures UFW firewall rules for custom SSH ports
- Sets up user SSH directories and authorized_keys
- Validates configuration before applying changes
- Supports Ubuntu 24.04 and Linux Mint 21

### 10. **FTP Hardening**
- Hardens vsftpd and ProFTPD configurations
- Disables anonymous FTP access
- Enforces TLS/SSL encryption
- Configures passive mode ports
- Sets proper file permissions on configuration files
- Implements chroot jails for local users

### 11. **PostgreSQL Hardening**
- Hardens PostgreSQL server configuration
- Configures authentication methods (pg_hba.conf)
- Enforces SSL/TLS for remote connections
- Sets secure listen addresses and port configuration
- Implements password encryption (scram-sha-256)
- Hardens file system permissions on data directories
- Configures connection limits and timeouts
- Disables dangerous extensions and functions
- Validates configuration before restart

### 12. **Samba Hardening**
- Comprehensive Samba/SMB file sharing hardening
- Disables SMBv1 protocol (security vulnerability)
- Enforces encrypted connections
- Configures proper authentication methods
- Sets strict file permissions on shares
- Implements access control lists
- Disables guest access and null sessions
- Configures allowed networks and hosts

### 13. **MySQL/MariaDB Hardening**
- Hardens MySQL/MariaDB configuration
- Removes anonymous users and test databases
- Disables remote root login
- Enforces strong password policies
- Configures SSL/TLS for connections
- Disables dangerous features (local_infile, symbolic links)
- Sets proper bind-address (localhost)
- Hardens file system permissions on config and data directories
- Implements connection limits and timeouts

### 14. **PHP Hardening**
- Hardens PHP configuration for both PHP-FPM and mod_php
- Disables dangerous functions (exec, shell_exec, system, etc.)
- Configures open_basedir restrictions
- Disables file uploads or restricts upload directory
- Sets proper file permissions on PHP config files
- Configures secure session handling
- Disables expose_php and display_errors
- Implements memory and execution limits
- Removes dangerous PHP files and shells

### 15. **NGINX Hardening**
- Comprehensive NGINX web server hardening
- Hides server version and tokens
- Configures secure SSL/TLS settings
- Implements security headers (X-Frame-Options, CSP, etc.)
- Disables unnecessary modules
- Sets proper timeouts to prevent DoS
- Configures request size limits
- Hardens file permissions on config and web root
- Protects sensitive files and directories

### 16. **Apache Hardening**
- Comprehensive Apache2 web server hardening
- Hides server version and OS information (ServerTokens, ServerSignature)
- Disables HTTP TRACE method to prevent XST attacks
- Configures secure timeouts to prevent DoS attacks
- Implements request size limits
- Disables directory browsing and access to sensitive files
- Enables security headers (X-Frame-Options, X-Content-Type-Options, X-XSS-Protection)
- Removes server information disclosure headers
- Disables unnecessary modules (CGI, WebDAV, userdir, autoindex)
- Hardens Apache configuration directory permissions (640 for files, 755 for directories)
- Hardens web root permissions (www-data ownership, 750 for directories, 640 for files)
- Protects version control directories (.git, .svn, etc.)
- Blocks access to backup and temporary files
- Validates configuration before applying changes
- Supports both Ubuntu 24.04 and Linux Mint 21

### 17. **Service Auditing**
- Lists all running services
- Ensures critical services are running
- Identifies unnecessary/dangerous services
- Manages service startup configuration

### 18. **Unwanted Software**
- Lists all installed packages
- Identifies hacking tools (nmap, john, hydra, etc.)
- Detects P2P software and games
- Recommends packages for removal

### 19. **Malware**
- Runs ClamAV virus scans
- Executes rkhunter for rootkit detection
- Checks for suspicious processes
- Scans for backdoors and reverse shells
- Examines cron jobs and startup scripts

### 20. **Prohibited Files**
- Scans for prohibited media files (.mp3, .mp4, etc.)
- Identifies hacking tools and unauthorized software
- Generates reports of found files
- Optional automatic removal

### 21. **Defensive Countermeasures**
- Enables and configures UFW firewall
- Sets up fail2ban for intrusion prevention
- Enables auditd for system auditing
- Configures file integrity monitoring (AIDE)

### 22. **OS Settings**
- Configures kernel security parameters (sysctl)
- Disables unnecessary kernel modules
- Sets up system banners
- Configures DNS and network settings

## README Parsing

The engine uses OpenRouter AI to parse README files similar to your Windows version. It extracts:

- **Authorized Users**: All users who should have accounts
- **Authorized Admins**: Users who should have administrator privileges
- **Recent Hires**: New users that need accounts created
- **Terminated Users**: Users whose accounts should be removed
- **Critical Services**: Services that must remain running
- **Group Memberships**: User group assignments

### Example README Structure

The parser can handle various README formats and extracts information about:
- User lists with roles
- Service requirements
- Forensics questions
- Specific security directives

## Linux Mint 21 vs Ubuntu 24 Differences

### Package Management
- **Both**: Use APT package manager (`apt-get`, `apt`)
- **Mint 21**: Based on Ubuntu 22.04 LTS (Jammy)
- **Ubuntu 24**: Uses newer package versions

### Display Manager
- **Mint 21**: Uses LightDM by default (Cinnamon edition)
- **Ubuntu 24**: Uses GDM3 (GNOME Display Manager)

### Desktop Environment
- **Mint 21**: Cinnamon, MATE, or Xfce
- **Ubuntu 24**: GNOME (typically newer version)

### Default Applications
- **Mint 21**: Custom Mint tools (mintUpdate, mintInstall, etc.)
- **Ubuntu 24**: GNOME/Ubuntu-specific tools

### System Services
- **Both**: Use systemd for service management
- **Mint 21**: May have Mint-specific services
- **Ubuntu 24**: May have Ubuntu-specific services

### Software Sources
- **Mint 21**: Uses Mint and Ubuntu 22.04 repositories
- **Ubuntu 24**: Uses Ubuntu 24.04 repositories
- **Note**: Some PPAs may differ between versions

### Key Locations to Check

Both distributions share:
- User accounts: `/etc/passwd`, `/etc/shadow`
- Groups: `/etc/group`
- Sudoers: `/etc/sudoers`, `/etc/sudoers.d/`
- SSH config: `/etc/ssh/sshd_config`
- PAM config: `/etc/pam.d/`
- Service configs: `/etc/systemd/system/`

### Module Compatibility

All modules in this engine are designed to work with both distributions:
- Use systemd commands (not init.d)
- Check for both distribution-specific paths
- Use APT for package management
- Handle both Cinnamon/MATE (Mint) and GNOME (Ubuntu) settings

## Configuration Options

### API Settings
```bash
GEMINI_API_KEY=""              # Your Google/Gemini API key (preferred)
# For legacy OpenRouter usage you may still set OPENROUTER_API_KEY
OPENROUTER_API_KEY=""
OPENROUTER_MODEL=""            # AI model to use (prefix with "google/" to use Gemini)
```

### Logging
```bash
LOG_LEVEL=1                    # 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
SCORE_FILE=""                  # Path to score log file
BACKUP_DIR=""                  # Path for backups
```

### Module Settings
```bash
MODULES=(...)                  # List of modules to run
CHECK_UNAUTHORIZED_USERS=true  # Enable/disable features
REMOVE_UNAUTHORIZED_USERS=false
# ... and many more settings
```

## Extending the Engine

### Adding a New Module

1. Create module file: `modules/my_module.sh`

```bash
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

run_my_module() {
    log_info "Starting My Module..."

    # Your implementation here

    return 0
}

export -f run_my_module
```

2. Add to `config.conf`:

```bash
MODULES=(
    # ... existing modules
    "my_module"
)
```

3. Run: `sudo ./cp-engine.sh -m my_module`

### Removing a Module

Simply comment out or remove the module name from the `MODULES` array in `config.conf`:

```bash
MODULES=(
    "user_auditing"
    # "unwanted_software"  # Disabled
    "account_policy"
)
```

## Development Status

### ✅ Fully Implemented
- Core engine architecture with intelligent module ordering
- Module loading system with automatic discovery
- OpenRouter API integration for README parsing
- Configuration system with flexible settings
- Comprehensive logging and utilities
- **All 22 security modules with full functionality:**
  - User management and auditing
  - Password and account policies
  - Service hardening (SSH, FTP, Apache, NGINX, PostgreSQL, MySQL, Samba, PHP)
  - Malware and rootkit detection
  - Prohibited file scanning
  - Forensics question assistance
  - System updates and patch management
  - Firewall and intrusion detection setup
  - Kernel hardening and security policies

## Dependencies

### Required (Auto-installed by dependencies module)
- `bash` (4.0+)
- `curl` - For API calls
- `jq` - For JSON parsing
- `sed`, `awk`, `grep` - Text processing
- `mlocate` - For file searching (updatedb/locate)

### Optional (Installed as needed by modules)
- `clamav` - Virus scanning (malware module)
- `rkhunter` - Rootkit detection (malware module)
- `lynis` - Security auditing (malware module)
- `fail2ban` - Intrusion prevention (defensive countermeasures)
- `ufw` - Firewall management (defensive countermeasures)
- `auditd` - System auditing (local policy)
- `aide` - File integrity monitoring (defensive countermeasures)
- `libpam-pwquality` - Password quality enforcement (account policy)
- `libpam-cracklib` - Password strength checking (account policy)

The **dependencies** module automatically installs required packages. Service-specific packages (Apache, NGINX, PostgreSQL, MySQL, Samba, PHP) are only configured if already installed on the system.

Install all optional dependencies:
```bash
sudo apt-get install clamav rkhunter lynis fail2ban ufw auditd aide libpam-pwquality libpam-cracklib
```

## Scoring

All remediation actions are logged to the score file (default: `/var/log/cyberpatriot/score.log`):

```
[2025-11-04_10:30:15] +2 points: Disabled root SSH login
[2025-11-04_10:30:22] +3 points: Removed unauthorized user: hacker
[2025-11-04_10:30:45] +1 points: Updated all packages
```

## Best Practices

1. **Always backup**: The engine backs up files automatically, but keep system snapshots
2. **Test first**: Run with `-c` to check compatibility before full run
3. **Review actions**: Check logs and score file after execution
4. **Manual verification**: Always verify critical changes manually
5. **README first**: Ensure README is parsed correctly before running remediation

## Troubleshooting

### AI API Issues
```bash
# Test API connection
sudo ./cp-engine.sh -t

# Check API key in config.conf
cat config.conf | grep OPENROUTER_API_KEY
```

### Module Not Running
```bash
# Check if module exists
ls -l modules/

# Try running module directly
sudo ./cp-engine.sh -m module_name

# Check logs for errors
tail -f /var/log/cyberpatriot/score.log
```

### Permission Denied
```bash
# Ensure running as root
sudo ./cp-engine.sh

# Check file permissions
chmod +x cp-engine.sh
```

## Contributing

When implementing module functionality:
1. Follow existing code style
2. Use utility functions from `lib/utils.sh`
3. Add logging for all actions
4. Back up files before modification
5. Use `log_score()` for scoring events
6. Test on both Mint 21 and Ubuntu 24

## License

This project is designed for CyberPatriot competition use.

## Support

- Check README.md (this file)
- Review module comments for implementation TODOs
- Test on practice images before competition

---

**Note**: This is a scaffold implementation. Module functionality needs to be implemented based on specific CyberPatriot competition requirements and your team's strategy.
