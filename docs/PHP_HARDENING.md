# PHP Hardening Module

## Overview

The PHP Hardening module (`php_hardening.sh`) implements comprehensive security hardening for PHP installations, covering both PHP-FPM and Apache (mod_php) configurations. This module applies industry best practices and CyberPatriot-specific security measures to minimize attack surface and prevent common PHP vulnerabilities.

## Features

### 1. Multi-Version & Multi-SAPI Support

The module automatically detects and hardens:
- **All installed PHP versions** (e.g., PHP 7.4, 8.0, 8.1, 8.3)
- **Multiple SAPIs (Server Application Programming Interfaces)**:
  - `apache2` - Apache module (mod_php)
  - `fpm` - FastCGI Process Manager
  - `cli` - Command Line Interface
  - `cgi` - Common Gateway Interface

### 2. Comprehensive Security Configuration

The module creates a shared security INI file (`99-cyberpatriot-security.ini`) that is applied to all detected PHP installations. This ensures consistent security posture across all PHP environments.

#### Information Disclosure Protection

```ini
expose_php = Off                    # Hides PHP version from HTTP headers
display_errors = Off                # Prevents error disclosure to users
display_startup_errors = Off        # Prevents startup error disclosure
log_errors = On                     # Enables error logging to file
html_errors = Off                   # Disables HTML formatting in errors
```

**Impact**: Prevents attackers from fingerprinting PHP version and gathering information about application internals through error messages.

#### Code Execution & File Inclusion Protection

```ini
allow_url_fopen = Off               # Prevents URL-based file operations
allow_url_include = Off             # Prevents URL-based includes (RFI)
enable_dl = Off                     # Prevents runtime extension loading
```

**Impact**: Blocks Remote File Inclusion (RFI) attacks and prevents attackers from loading malicious PHP extensions at runtime.

#### Dangerous Functions Disabled

The module disables a comprehensive list of dangerous PHP functions:

```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,
                   curl_exec,curl_multi_exec,parse_ini_file,show_source,
                   highlight_file,phpinfo,pcntl_exec,pcntl_fork,
                   pcntl_signal,posix_kill,posix_setuid,dl
```

**Impact**: Prevents code execution, process manipulation, and privilege escalation attacks.

#### Session Security (Complete Protection)

```ini
session.cookie_secure = 1           # HTTPS-only session cookies
session.cookie_httponly = 1         # Prevents JavaScript cookie access
session.use_strict_mode = 1         # Prevents session fixation
session.use_only_cookies = 1        # No session IDs in URLs
session.cookie_samesite = Strict    # CSRF protection
session.hash_function = sha256      # Strong hash algorithm
```

**Impact**: Protects against session hijacking, fixation, XSS-based cookie theft, and CSRF attacks.

#### File Upload Security

```ini
file_uploads = Off                  # Disables file uploads (default)
upload_max_filesize = 2M           # Limits upload size if enabled
max_file_uploads = 2               # Limits number of uploads
```

**Impact**: Prevents web shell uploads and other file-based attacks. Set to Off by default for maximum security.

#### Resource Limits

```ini
max_execution_time = 30            # Maximum script execution time
max_input_time = 60                # Maximum input parsing time
memory_limit = 128M                # Memory limit per script
post_max_size = 8M                 # Maximum POST data size
max_input_vars = 1000              # Limit input variables
```

**Impact**: Prevents resource exhaustion and DoS attacks.

#### File System Security (Directory Jailing)

```ini
open_basedir = /var/www:/tmp:/usr/share/php:/dev/urandom
```

**Impact**: Restricts PHP file operations to specific directories, preventing access to sensitive system files like `/etc/passwd`.

#### SQL Injection Protection

```ini
sql.safe_mode = On                 # Enables SQL safe mode
```

**Impact**: Additional layer of protection against SQL injection attacks.

#### CGI Security

```ini
cgi.force_redirect = 1             # Prevents direct CGI execution
cgi.fix_pathinfo = 0               # Prevents path info manipulation
```

**Impact**: Prevents CGI-based attacks and path traversal vulnerabilities.

### 3. PHPInfo File Removal

The module searches for and removes dangerous phpinfo files that leak configuration details:

**Searched patterns:**
- `phpinfo.php`
- `info.php`
- `test.php`
- `pi.php`
- `php_info.php`

**Additional scan:** Searches for any PHP file containing `phpinfo()` calls in the web root.

**Impact**: Prevents information disclosure through phpinfo pages that reveal all PHP settings, paths, and environment variables.

### 4. Permission Hardening

#### PHP Configuration Files

```bash
/etc/php/**/*.ini → 644 root:root
/etc/php/**/       → 755 root:root
```

**Impact**: Prevents web user (www-data) from modifying PHP configuration files.

#### Web Directory Permissions

```bash
/var/www/html directories → 755 www-data:www-data
/var/www/html files       → 644 www-data:www-data
```

**Impact**: Web user cannot modify executable code, preventing malicious file modifications.

#### Upload Directory Protection

For detected upload directories, the module:
1. Sets restrictive permissions (750)
2. Creates `.htaccess` to prevent script execution

```apache
<FilesMatch "\.(?i:php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
```

**Impact**: Prevents uploaded files from being executed as scripts.

### 5. Service Reload

The module automatically reloads PHP services after applying changes:
- All PHP-FPM services (e.g., `php8.3-fpm.service`)
- Apache2 (if running)
- Nginx (if running)

### 6. Configuration Validation

After applying changes, the module validates PHP configurations to ensure no syntax errors were introduced.

## Configuration Options

The module supports customization through environment variables:

```bash
# Dangerous functions to disable (default shown)
PHP_DISABLE_FUNCTIONS="exec,passthru,shell_exec,system,..."

# Open basedir restriction
PHP_OPEN_BASEDIR="/var/www:/tmp:/usr/share/php:/dev/urandom"

# Resource limits
PHP_MAX_EXECUTION_TIME="30"
PHP_MAX_INPUT_TIME="60"
PHP_MEMORY_LIMIT="128M"
PHP_POST_MAX_SIZE="8M"
PHP_UPLOAD_MAX_FILESIZE="2M"

# Session settings
PHP_SESSION_NAME="PHPSESSID"
PHP_SESSION_COOKIE_LIFETIME="0"

# Feature toggles
PHP_REMOVE_PHPINFO="yes"
PHP_HARDEN_PERMISSIONS="yes"

# Web root directory
PHP_WEB_ROOT="/var/www/html"
```

## Execution

### Standalone

```bash
sudo ./cp-engine.sh -m php_hardening
```

### As part of full scan

```bash
sudo ./cp-engine.sh
```

The module will run automatically in the correct order (after SSH and FTP hardening, before service auditing).

## Scoring

The module tracks points for each security improvement:

| Action | Points |
|--------|--------|
| Hardened PHP configurations (per SAPI) | 3 |
| Removed phpinfo file | 1 per file |
| Hardened PHP config file permissions | 1 |
| Hardened web directory permissions | 2 |
| Prevented script execution in uploads | 1 |

## Compatibility

- **Supported OS**: Ubuntu 20.04+, Linux Mint 21+
- **PHP Versions**: 7.0 through 8.x
- **Web Servers**: Apache2, Nginx
- **PHP Modes**: mod_php, PHP-FPM

## Files Modified

The module creates backups before modifying files:

- `/etc/php/[VERSION]/[SAPI]/conf.d/99-cyberpatriot-security.ini` (created)
- `/var/www/html/**/.htaccess` (created in upload directories)
- Removed: various phpinfo files

**Backups**: All original files are backed up to `/var/backups/cyberpatriot/`

## Situational Considerations

### File Uploads

By default, file uploads are **disabled** (`file_uploads = Off`). If the application requires uploads:

1. Edit the security INI file:
   ```bash
   sudo nano /etc/php/8.3/fpm/conf.d/99-cyberpatriot-security.ini
   ```

2. Change:
   ```ini
   file_uploads = On
   ```

3. Reload PHP-FPM:
   ```bash
   sudo systemctl reload php8.3-fpm
   ```

### Open Basedir

The default `open_basedir` setting restricts file access. If the application needs access to additional directories:

1. Edit the security INI file
2. Add required paths to `open_basedir`:
   ```ini
   open_basedir = /var/www:/tmp:/usr/share/php:/custom/path
   ```

### Disabled Functions

Some applications may require functions that are disabled by default. Review application documentation and only enable necessary functions.

## Log Output Example

```
═══════════════════════════════════════════════════════════
  Applying PHP Configuration Hardening
═══════════════════════════════════════════════════════════
[INFO] Processing PHP version: 8.3
[INFO]   Hardening PHP 8.3 fpm SAPI
[INFO] Creating hardened PHP configuration: /etc/php/8.3/fpm/conf.d/99-cyberpatriot-security.ini
[SUCCESS] Security configuration created
[INFO]   Hardening PHP 8.3 apache2 SAPI
[INFO] Creating hardened PHP configuration: /etc/php/8.3/apache2/conf.d/99-cyberpatriot-security.ini
[SUCCESS] Security configuration created
[SUCCESS] Hardened 2 PHP configuration(s)
[SCORE] +3 Applied PHP security hardening to 2 configuration(s)

═══════════════════════════════════════════════════════════
  Removing PHPInfo Files
═══════════════════════════════════════════════════════════
[INFO] Searching for phpinfo files in /var/www/html
[WARN]   Removing dangerous file: /var/www/html/info.php
[SUCCESS] Removed 1 phpinfo file(s)
[SCORE] +1 Removed phpinfo file

[SUCCESS] PHP Hardening module completed
```

## Security Impact

This module addresses multiple OWASP Top 10 vulnerabilities:

1. **A03:2021 – Injection**: Disables dangerous functions, enables sql.safe_mode
2. **A05:2021 – Security Misconfiguration**: Hardens all PHP settings
3. **A07:2021 – Identification and Authentication Failures**: Secures sessions
4. **A08:2021 – Software and Data Integrity Failures**: Prevents unauthorized file modifications
5. **A09:2021 – Security Logging and Monitoring Failures**: Enables comprehensive error logging

## References

- [PHP Security Manual](https://www.php.net/manual/en/security.php)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [CIS PHP Benchmark](https://www.cisecurity.org/)

## Troubleshooting

### Module reports "No PHP installations detected"

**Cause**: PHP is not installed or not in standard locations.

**Solution**: Install PHP:
```bash
sudo apt update
sudo apt install php php-fpm
```

### Web application breaks after hardening

**Cause**: Application may require disabled functions or relaxed settings.

**Solution**:
1. Check web server error logs: `/var/log/apache2/error.log` or `/var/log/nginx/error.log`
2. Check PHP error log: `/var/log/php_errors.log`
3. Adjust settings in the security INI file as needed
4. Reload PHP service

### Upload functionality doesn't work

**Cause**: File uploads are disabled by default.

**Solution**: Enable file uploads (see Situational Considerations above).

## Author

CyberPatriot Linux Auto-Remediation Engine
Module: PHP Hardening
Version: 1.0.0
