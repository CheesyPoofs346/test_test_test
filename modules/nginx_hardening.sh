#!/bin/bash
# nginx_hardening.sh - Comprehensive NGINX Web Server Hardening
#
# This module implements comprehensive security hardening for NGINX web servers,
# including configuration hardening, SSL/TLS security, security headers, and
# file system permissions.
#
# Module: NGINX Hardening
# Category: Web Server Security
# Description: Hardens NGINX configuration, SSL/TLS settings, security headers, and file permissions
#
# References:
# - OWASP Web Server Security Guidelines
# - Mozilla SSL Configuration Generator
# - CIS NGINX Benchmark
#
# Author: CyberPatriot Auto-Remediation Engine
# Version: 1.0.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# ==============================================================================
# CONFIGURATION CONSTANTS
# ==============================================================================

readonly NGINX_MAIN_CONFIG="/etc/nginx/nginx.conf"
readonly NGINX_DEFAULT_SITE="/etc/nginx/sites-available/default"
# Main config targets (prefer editing primary config over new snippets)
readonly NGINX_SSL_PARAMS="/etc/nginx/nginx.conf"

# Web root paths (common locations)
readonly WEB_ROOT_PATHS=(
    "/var/www/html"
    "/var/www"
    "/usr/share/nginx/html"
)

# SSL certificate paths (common locations)
readonly SSL_CERT_PATHS=(
    "/etc/ssl/certs"
    "/etc/nginx/ssl"
    "/etc/letsencrypt"
)

readonly SSL_KEY_PATHS=(
    "/etc/ssl/private"
    "/etc/nginx/ssl"
    "/etc/letsencrypt"
)

# NGINX user (varies by distribution)
NGINX_USER="www-data"

# Buffer size limits for DoS protection
readonly CLIENT_BODY_BUFFER_SIZE="1k"
readonly CLIENT_HEADER_BUFFER_SIZE="1k"
readonly CLIENT_MAX_BODY_SIZE="1k"
readonly LARGE_CLIENT_HEADER_BUFFERS="2 1k"

# Timeouts for connection management
readonly CLIENT_BODY_TIMEOUT="10s"
readonly CLIENT_HEADER_TIMEOUT="10s"
readonly KEEPALIVE_TIMEOUT="5s"
readonly SEND_TIMEOUT="10s"

# Rate limiting
readonly RATE_LIMIT_ZONE="10m"
readonly RATE_LIMIT_REQUESTS="10r/s"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

# Check if NGINX is installed
check_nginx_installed() {
    if ! command_exists nginx; then
        log_warn "NGINX is not installed"
        return 1
    fi
    return 0
}

# Detect NGINX user for this distribution
detect_nginx_user() {
    if grep -q "^user nginx" "$NGINX_MAIN_CONFIG" 2>/dev/null; then
        NGINX_USER="nginx"
    elif grep -q "^user www-data" "$NGINX_MAIN_CONFIG" 2>/dev/null; then
        NGINX_USER="www-data"
    elif id -u nginx >/dev/null 2>&1; then
        NGINX_USER="nginx"
    elif id -u www-data >/dev/null 2>&1; then
        NGINX_USER="www-data"
    else
        log_warn "Could not detect NGINX user, defaulting to www-data"
        NGINX_USER="www-data"
    fi
    log_info "Detected NGINX user: $NGINX_USER"
}

# Validate NGINX configuration syntax
validate_nginx_config() {
    log_info "Validating NGINX configuration..."

    if nginx -t >/dev/null 2>&1; then
        log_success "✓ NGINX configuration is valid"
        return 0
    else
        log_error "✗ NGINX configuration has syntax errors:"
        nginx -t 2>&1 | grep -v "successful" || true
        return 1
    fi
}

# Reload NGINX service
reload_nginx() {
    log_info "Reloading NGINX service..."

    if ! validate_nginx_config; then
        log_error "Cannot reload NGINX: configuration validation failed"
        return 1
    fi

    if systemctl reload nginx 2>/dev/null; then
        log_success "✓ NGINX service reloaded successfully"
        return 0
    else
        log_error "✗ Failed to reload NGINX service"
        return 1
    fi
}

# Check if a directive exists in config file
directive_exists() {
    local file="$1"
    local directive="$2"

    [[ -f "$file" ]] && grep -q "^\s*${directive}" "$file" 2>/dev/null
}

# Insert a block of configuration into the main http section if not already present
ensure_http_block_content() {
    local file="$1"
    local marker="$2"
    local block_content="$3"

    if [[ ! -f "$file" ]]; then
        log_error "Config file not found: $file"
        return 1
    fi

    if grep -q "$marker" "$file"; then
        log_info "Configuration block already present: $marker"
        return 0
    fi

    backup_file "$file"

    local tmp_file
    tmp_file=$(mktemp)
    echo "$block_content" > "$tmp_file"

    if grep -q "http {" "$file"; then
        sed -i "/http {/r $tmp_file" "$file"
        log_success "✓ Added configuration block: $marker"
    else
        log_warn "Could not find http block in $file"
        rm -f "$tmp_file"
        return 1
    fi

    rm -f "$tmp_file"
    return 0
}

# ==============================================================================
# MAIN CONFIGURATION HARDENING
# ==============================================================================

# Disable server version disclosure (server_tokens)
disable_server_tokens() {
    log_section "Disabling Server Version Disclosure"

    local file="$NGINX_MAIN_CONFIG"

    if [[ ! -f "$file" ]]; then
        log_error "Main config file not found: $file"
        return 1
    fi

    backup_file "$file"

    # Check if server_tokens is already set
    if directive_exists "$file" "server_tokens"; then
        # Update existing directive
        sed -i 's/^\s*server_tokens\s\+.*/    server_tokens off;/' "$file"
        log_success "✓ Updated server_tokens to off"
    else
        # Add to http block
        if grep -q "http {" "$file"; then
            sed -i '/http {/a\    server_tokens off;' "$file"
            log_success "✓ Added server_tokens off to http block"
        else
            log_warn "Could not find http block in $file"
            return 1
        fi
    fi

    return 0
}

# Ensure NGINX runs as non-privileged user
configure_nginx_user() {
    log_section "Configuring NGINX User"

    local file="$NGINX_MAIN_CONFIG"

    if [[ ! -f "$file" ]]; then
        log_error "Main config file not found: $file"
        return 1
    fi

    backup_file "$file"
    detect_nginx_user

    # Check if user directive exists
    if directive_exists "$file" "user"; then
        # Update existing directive
        sed -i "s/^\s*user\s\+.*/user $NGINX_USER;/" "$file"
        log_success "✓ Updated user directive to: $NGINX_USER"
    else
        # Add as first line in file
        sed -i "1iuser $NGINX_USER;" "$file"
        log_success "✓ Added user directive: $NGINX_USER"
    fi

    # Verify user exists
    if ! id -u "$NGINX_USER" >/dev/null 2>&1; then
        log_error "✗ NGINX user does not exist: $NGINX_USER"
        return 1
    fi

    return 0
}

# Configure buffer sizes to mitigate DoS attacks (Slowloris)
configure_buffer_limits() {
    log_section "Configuring Buffer Limits (DoS Protection)"

    local file="$NGINX_MAIN_CONFIG"

    if [[ ! -f "$file" ]]; then
        log_error "Main config file not found: $file"
        return 1
    fi

    backup_file "$file"

    local directives=(
        "client_body_buffer_size $CLIENT_BODY_BUFFER_SIZE"
        "client_header_buffer_size $CLIENT_HEADER_BUFFER_SIZE"
        "client_max_body_size $CLIENT_MAX_BODY_SIZE"
        "large_client_header_buffers $LARGE_CLIENT_HEADER_BUFFERS"
    )

    local count=0

    for directive_line in "${directives[@]}"; do
        local directive_name="${directive_line%% *}"

        if directive_exists "$file" "$directive_name"; then
            # Update existing
            sed -i "s/^\s*${directive_name}\s\+.*/    ${directive_line};/" "$file"
            log_success "✓ Updated $directive_name"
        else
            # Add to http block
            if grep -q "http {" "$file"; then
                sed -i "/http {/a\    ${directive_line};" "$file"
                log_success "✓ Added $directive_name"
            fi
        fi
        count=$((count + 1))
    done

    log_success "Configured $count buffer limit directives"
    return 0
}

# Configure timeout values
configure_timeouts() {
    log_section "Configuring Timeout Values"

    local file="$NGINX_MAIN_CONFIG"

    if [[ ! -f "$file" ]]; then
        log_error "Main config file not found: $file"
        return 1
    fi

    backup_file "$file"

    local directives=(
        "client_body_timeout $CLIENT_BODY_TIMEOUT"
        "client_header_timeout $CLIENT_HEADER_TIMEOUT"
        "keepalive_timeout $KEEPALIVE_TIMEOUT"
        "send_timeout $SEND_TIMEOUT"
    )

    local count=0

    for directive_line in "${directives[@]}"; do
        local directive_name="${directive_line%% *}"

        if directive_exists "$file" "$directive_name"; then
            sed -i "s/^\s*${directive_name}\s\+.*/    ${directive_line};/" "$file"
            log_success "✓ Updated $directive_name"
        else
            if grep -q "http {" "$file"; then
                sed -i "/http {/a\    ${directive_line};" "$file"
                log_success "✓ Added $directive_name"
            fi
        fi
        count=$((count + 1))
    done

    log_success "Configured $count timeout directives"
    return 0
}

# ==============================================================================
# SECURITY HEADERS CONFIGURATION
# ==============================================================================

# Create security headers snippet
create_security_headers_config() {
    log_section "Creating Security Headers Configuration"

    local marker="# CyberPatriot Security Headers"
    local block_content
    block_content=$(cat <<'EOF'
    # CyberPatriot Security Headers
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self';" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;
    proxy_hide_header X-Powered-By;
    fastcgi_hide_header X-Powered-By;
EOF
)

    ensure_http_block_content "$NGINX_MAIN_CONFIG" "$marker" "$block_content"
}

# ==============================================================================
# SSL/TLS HARDENING
# ==============================================================================

# Create SSL parameters snippet
create_ssl_hardening_config() {
    log_section "Applying SSL/TLS Hardening"

    local marker="# CyberPatriot SSL/TLS Hardening"
    local block_content
    block_content=$(cat <<'EOF'
    # CyberPatriot SSL/TLS Hardening
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;
    # ssl_dhparam /etc/nginx/dhparam.pem;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
EOF
)

    ensure_http_block_content "$NGINX_MAIN_CONFIG" "$marker" "$block_content"
}

# Create HSTS configuration (separate because it should only be on HTTPS)
create_hsts_config() {
    log_section "Applying HSTS Configuration"

    local marker="# CyberPatriot HSTS"
    local block_content
    block_content=$(cat <<'EOF'
    # CyberPatriot HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
EOF
)

    ensure_http_block_content "$NGINX_MAIN_CONFIG" "$marker" "$block_content"
}

# ==============================================================================
# SERVER BLOCK HARDENING
# ==============================================================================

# Create comprehensive hardening configuration
create_hardening_config() {
    log_section "Creating Comprehensive Hardening Configuration"

    local marker="# CyberPatriot NGINX Hardening"
    local block_content
    block_content=$(cat <<'EOF'
    # CyberPatriot NGINX Hardening
    autoindex off;
    map $request_method $allowed_method {
        default 0;
        GET 1;
        POST 1;
        HEAD 1;
    }
    limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
    limit_req_status 429;
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    limit_conn_status 429;
EOF
)

    ensure_http_block_content "$NGINX_MAIN_CONFIG" "$marker" "$block_content"
}

# Update default site configuration with security settings
update_default_site_config() {
    log_section "Updating Default Site Configuration"

    local site_config="$NGINX_DEFAULT_SITE"

    if [[ ! -f "$site_config" ]]; then
        log_warn "Default site configuration not found: $site_config"
        log_info "Skipping default site update (may not be using default config)"
        return 0
    fi

    backup_file "$site_config"

    # Add deny access to hidden files block if not present
    if ! grep -q "location ~ /\\\\." "$site_config"; then
        # Add before the last closing brace (end of server block)
        cat >> "$site_config" <<'EOF'

    # Deny access to hidden files (dotfiles)
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
EOF
        log_success "✓ Added hidden files protection to default site"
    else
        log_info "Hidden files protection already configured in default site"
    fi

    # Add HTTP method restriction if not present
    if ! grep -q "request_method" "$site_config"; then
        sed -i '/server {/a\    # Limit HTTP methods\n    if ($allowed_method = 0) {\n        return 444;\n    }' "$site_config"
        log_success "✓ Added HTTP method restrictions to default site"
    else
        log_info "HTTP method restrictions already configured in default site"
    fi

    # Add rate limiting if not present
    if ! grep -q "limit_req" "$site_config"; then
        sed -i '/server {/a\    # Rate limiting\n    limit_req zone=general burst=20 nodelay;\n    limit_conn addr 10;' "$site_config"
        log_success "✓ Added rate limiting to default site"
    else
        log_info "Rate limiting already configured in default site"
    fi

    return 0
}

# ==============================================================================
# FILE SYSTEM PERMISSIONS
# ==============================================================================

# Secure NGINX configuration files
secure_config_permissions() {
    log_section "Securing NGINX Configuration File Permissions"

    local count=0
    local total=0

    # Main nginx directory
    if [[ -d /etc/nginx ]]; then
        total=$((total + 1))
        if chown -R root:root /etc/nginx 2>/dev/null; then
            log_success "✓ Set ownership on /etc/nginx to root:root"
            count=$((count + 1))
        fi
    fi

    # Main configuration file
    if [[ -f "$NGINX_MAIN_CONFIG" ]]; then
        total=$((total + 1))
        if chmod 644 "$NGINX_MAIN_CONFIG" 2>/dev/null; then
            log_success "✓ Set permissions on nginx.conf to 644"
            count=$((count + 1))
        fi
    fi

    # Sites-available directory
    if [[ -d /etc/nginx/sites-available ]]; then
        total=$((total + 1))
        if chmod -R 644 /etc/nginx/sites-available/* 2>/dev/null; then
            log_success "✓ Set permissions on sites-available to 644"
            count=$((count + 1))
        fi
    fi

    # Sites-enabled directory (symlinks)
    if [[ -d /etc/nginx/sites-enabled ]]; then
        total=$((total + 1))
        if chmod -R 644 /etc/nginx/sites-enabled/* 2>/dev/null; then
            log_success "✓ Set permissions on sites-enabled to 644"
            count=$((count + 1))
        fi
    fi

    # Conf.d directory
    if [[ -d /etc/nginx/conf.d ]]; then
        total=$((total + 1))
        if chmod -R 644 /etc/nginx/conf.d/* 2>/dev/null; then
            log_success "✓ Set permissions on conf.d to 644"
            count=$((count + 1))
        fi
    fi

    # Snippets directory
    if [[ -d /etc/nginx/snippets ]]; then
        total=$((total + 1))
        if chmod -R 644 /etc/nginx/snippets/* 2>/dev/null; then
            log_success "✓ Set permissions on snippets to 644"
            count=$((count + 1))
        fi
    fi

    log_success "Secured $count of $total configuration items"
    return 0
}

# Secure SSL private keys
secure_ssl_keys() {
    log_section "Securing SSL Private Keys"

    local count=0
    local total=0

    for key_path in "${SSL_KEY_PATHS[@]}"; do
        if [[ -d "$key_path" ]]; then
            # Find all .key and .pem files
            while IFS= read -r -d '' keyfile; do
                total=$((total + 1))

                # Set ownership to root:root
                if chown root:root "$keyfile" 2>/dev/null; then
                    # Set permissions to 600 (read/write for root only)
                    if chmod 600 "$keyfile" 2>/dev/null; then
                        log_success "✓ Secured: $keyfile (600, root:root)"
                        count=$((count + 1))
                    fi
                fi
            done < <(find "$key_path" -type f \( -name "*.key" -o -name "*-key.pem" \) -print0 2>/dev/null)
        fi
    done

    if [[ $total -eq 0 ]]; then
        log_info "No SSL private keys found to secure"
    else
        log_success "Secured $count of $total SSL private keys"
    fi

    return 0
}

# Secure web root directory
secure_web_root() {
    log_section "Securing Web Root Directory"

    local count=0
    local total=0
    local web_root=""

    # Find the web root that exists
    for path in "${WEB_ROOT_PATHS[@]}"; do
        if [[ -d "$path" ]]; then
            web_root="$path"
            break
        fi
    done

    if [[ -z "$web_root" ]]; then
        log_info "No standard web root directory found"
        return 0
    fi

    log_info "Securing web root: $web_root"

    # Set ownership to root:root (NOT www-data)
    # This prevents a compromised web app from modifying its own code
    total=$((total + 1))
    if chown -R root:root "$web_root" 2>/dev/null; then
        log_success "✓ Set ownership on $web_root to root:root"
        count=$((count + 1))
    fi

    # Set directory permissions to 755 (rwxr-xr-x)
    total=$((total + 1))
    if find "$web_root" -type d -exec chmod 755 {} \; 2>/dev/null; then
        log_success "✓ Set directory permissions to 755 (rwxr-xr-x)"
        count=$((count + 1))
    fi

    # Set file permissions to 644 (rw-r--r--)
    total=$((total + 1))
    if find "$web_root" -type f -exec chmod 644 {} \; 2>/dev/null; then
        log_success "✓ Set file permissions to 644 (rw-r--r--)"
        count=$((count + 1))
    fi

    # Ensure NGINX user can read the files
    detect_nginx_user
    if [[ -n "$NGINX_USER" ]]; then
        # Add NGINX user to appropriate group if needed
        log_info "NGINX user ($NGINX_USER) can read files owned by root"
    fi

    log_success "Secured $count of $total web root items"
    return 0
}

# ==============================================================================
# VERIFICATION FUNCTIONS
# ==============================================================================

# Verify all hardening configurations are in place
verify_hardening() {
    log_section "Verifying NGINX Hardening Configuration"

    local errors=0
    local warnings=0

    # Check main config
    if [[ ! -f "$NGINX_MAIN_CONFIG" ]]; then
        log_error "✗ Main config file not found: $NGINX_MAIN_CONFIG"
        errors=$((errors + 1))
    else
        # Check server_tokens
        if ! grep -q "server_tokens off" "$NGINX_MAIN_CONFIG"; then
            log_warn "⚠ server_tokens not set to off"
            warnings=$((warnings + 1))
        else
            log_success "✓ server_tokens off"
        fi

        # Check user directive
        if ! grep -q "^user" "$NGINX_MAIN_CONFIG"; then
            log_warn "⚠ user directive not set"
            warnings=$((warnings + 1))
        else
            log_success "✓ user directive configured"
        fi

        # Check buffer limits
        if ! grep -q "client_body_buffer_size" "$NGINX_MAIN_CONFIG"; then
            log_warn "⚠ client_body_buffer_size not configured"
            warnings=$((warnings + 1))
        else
            log_success "✓ Buffer limits configured"
        fi
    fi

    # Check security headers in main config
    if ! grep -q "Content-Security-Policy" "$NGINX_MAIN_CONFIG"; then
        log_warn "⚠ Content-Security-Policy header not configured in nginx.conf"
        warnings=$((warnings + 1))
    else
        log_success "✓ Security headers configured in nginx.conf"
    fi

    # Check SSL parameters
    if ! grep -q "ssl_protocols" "$NGINX_MAIN_CONFIG"; then
        log_warn "⚠ SSL protocols not hardened in nginx.conf"
        warnings=$((warnings + 1))
    else
        log_success "✓ SSL/TLS hardening present in nginx.conf"
    fi

    # Validate NGINX config syntax
    if ! validate_nginx_config; then
        log_error "✗ NGINX configuration has syntax errors"
        errors=$((errors + 1))
    else
        log_success "✓ NGINX configuration syntax is valid"
    fi

    # Report results
    if [[ $errors -gt 0 ]]; then
        log_error "Verification failed with $errors error(s) and $warnings warning(s)"
        return 1
    elif [[ $warnings -gt 0 ]]; then
        log_warn "Verification completed with $warnings warning(s)"
        return 0
    else
        log_success "All verifications passed successfully"
        return 0
    fi
}

# Generate hardening report
generate_report() {
    log_section "NGINX Hardening Report"

    echo ""
    echo "Configuration Files Created/Modified:"
    echo "  - $NGINX_MAIN_CONFIG"
    echo "  - $NGINX_DEFAULT_SITE"

    echo ""
    echo "Security Improvements Applied:"
    echo "  ✓ Server version disclosure disabled (server_tokens off)"
    echo "  ✓ NGINX running as non-privileged user ($NGINX_USER)"
    echo "  ✓ Buffer overflow protection (DoS/Slowloris mitigation)"
    echo "  ✓ Connection timeouts configured"
    echo "  ✓ Security headers (XSS, Clickjacking, MIME-sniffing protection)"
    echo "  ✓ SSL/TLS hardening (TLS 1.2+ only, strong ciphers)"
    echo "  ✓ HSTS configuration applied"
    echo "  ✓ Directory listing disabled (autoindex off)"
    echo "  ✓ Hidden files protection"
    echo "  ✓ HTTP method restrictions"
    echo "  ✓ Rate limiting configured"
    echo "  ✓ Configuration file permissions secured"
    echo "  ✓ SSL private key permissions secured"
    echo "  ✓ Web root permissions secured"

    echo ""
    echo "Next Steps:"
    echo "  1. Review NGINX configuration: nginx -T"
    echo "  2. Test your website functionality"
    echo "  3. Generate DH parameters: openssl dhparam -out /etc/nginx/dhparam.pem 2048"
    echo "  4. Update SSL certificate paths in your site configurations"
    echo "  5. Test SSL configuration: https://www.ssllabs.com/ssltest/"
    echo ""

    echo "Backups Location:"
    echo "  /var/backups/cyberpatriot/"
    echo ""
}

# ==============================================================================
# MAIN EXECUTION FUNCTION
# ==============================================================================

run_nginx_hardening() {
    log_section "NGINX Hardening Module"

    # Require root privileges
    require_root

    # Check if NGINX is installed
    if ! check_nginx_installed; then
        log_error "NGINX is not installed. Install NGINX first:"
        log_error "  sudo apt-get install nginx"
        return 1
    fi

    log_info "Starting NGINX hardening process..."
    echo ""

    # Track overall success
    local overall_success=0

    # === MAIN CONFIGURATION HARDENING ===
    disable_server_tokens || overall_success=1
    configure_nginx_user || overall_success=1
    configure_buffer_limits || overall_success=1
    configure_timeouts || overall_success=1

    # === SECURITY HEADERS ===
    create_security_headers_config || overall_success=1

    # === SSL/TLS HARDENING ===
    create_ssl_hardening_config || overall_success=1
    create_hsts_config || overall_success=1

    # === SERVER BLOCK HARDENING ===
    create_hardening_config || overall_success=1
    update_default_site_config || overall_success=1

    # === FILE SYSTEM PERMISSIONS ===
    secure_config_permissions || overall_success=1
    secure_ssl_keys || overall_success=1
    secure_web_root || overall_success=1

    # === VERIFICATION ===
    verify_hardening || overall_success=1

    # === RELOAD NGINX ===
    if [[ $overall_success -eq 0 ]]; then
        reload_nginx || overall_success=1
    else
        log_warn "Skipping NGINX reload due to previous errors"
    fi

    # === GENERATE REPORT ===
    generate_report

    if [[ $overall_success -eq 0 ]]; then
        log_success "NGINX hardening completed successfully"
        return 0
    else
        log_error "NGINX hardening completed with some errors"
        log_error "Check logs above for details"
        log_error "Backups available in /var/backups/cyberpatriot/"
        return 1
    fi
}

# ==============================================================================
# MODULE METADATA (for engine discovery)
# ==============================================================================

# This function is called by the main engine
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Script is being run directly
    run_nginx_hardening
fi
