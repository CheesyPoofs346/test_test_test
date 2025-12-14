#!/bin/bash
# apache_hardening.sh - Apache Web Server Hardening Module
# Implements comprehensive Apache2 hardening for CyberPatriot competitions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Apache Hardening
# Category: Application Security
# Description: Hardens Apache2 configuration, permissions, headers, and modules

# ====== EDITABLE DEFAULTS ======
readonly APACHE_CONFIG_NAME="${APACHE_CONFIG_NAME:-99-cyberpatriot-hardening.conf}"
readonly APACHE_WEB_ROOT="${APACHE_WEB_ROOT:-/var/www/html}"
readonly APACHE_TIMEOUT="${APACHE_TIMEOUT:-60}"
readonly APACHE_KEEPALIVE_TIMEOUT="${APACHE_KEEPALIVE_TIMEOUT:-5}"
readonly APACHE_REQUEST_BODY_LIMIT="${APACHE_REQUEST_BODY_LIMIT:-10485760}"  # 10MB in bytes
readonly APACHE_DISABLE_DIRECTORY_LISTING="${APACHE_DISABLE_DIRECTORY_LISTING:-yes}"
readonly APACHE_ENABLE_SECURITY_HEADERS="${APACHE_ENABLE_SECURITY_HEADERS:-yes}"
readonly APACHE_DISABLE_UNNECESSARY_MODULES="${APACHE_DISABLE_UNNECESSARY_MODULES:-yes}"

# Apache configuration paths
readonly APACHE_CONF_DIR="/etc/apache2"
readonly APACHE_CONF_AVAILABLE="${APACHE_CONF_DIR}/conf-available"
readonly APACHE_CONF_ENABLED="${APACHE_CONF_DIR}/conf-enabled"
readonly APACHE_SITES_AVAILABLE="${APACHE_CONF_DIR}/sites-available"
readonly APACHE_MODS_AVAILABLE="${APACHE_CONF_DIR}/mods-available"
readonly APACHE_MODS_ENABLED="${APACHE_CONF_DIR}/mods-enabled"
readonly APACHE_SECURITY_CONF="${APACHE_CONF_AVAILABLE}/${APACHE_CONFIG_NAME}"

# Modules to disable (if enabled and unused)
readonly MODULES_TO_DISABLE=(
    "autoindex"      # Directory listing (if not needed)
    "cgi"            # CGI scripts
    "cgid"           # CGI daemon
    "dav"            # WebDAV
    "dav_fs"         # WebDAV filesystem
    "userdir"        # User directories (~username)
    "status"         # Server status page (security risk)
    "info"           # Server info page (security risk)
)

# Check if Apache service exists
apache_service_exists() {
    if command_exists systemctl; then
        systemctl list-unit-files | grep -qE '^apache2\.service' && return 0
    fi
    if command_exists service; then
        service --status-all 2>&1 | grep -qE 'apache2' && return 0
    fi
    return 1
}

# Check if Apache is installed
apache_is_installed() {
    command_exists apache2 || command_exists apachectl || [[ -d "$APACHE_CONF_DIR" ]]
}

# Reload Apache service
apache_service_reload() {
    log_info "Reloading Apache service..."

    # First test the configuration
    if command_exists apache2ctl; then
        if ! apache2ctl configtest >/dev/null 2>&1; then
            log_error "Apache configuration test failed"
            return 1
        fi
    elif command_exists apachectl; then
        if ! apachectl configtest >/dev/null 2>&1; then
            log_error "Apache configuration test failed"
            return 1
        fi
    fi

    if command_exists systemctl; then
        if systemctl list-unit-files | grep -q '^apache2\.service'; then
            systemctl reload apache2 >/dev/null 2>&1
            log_success "Apache service reloaded"
            return 0
        fi
    fi

    if command_exists service; then
        service apache2 reload >/dev/null 2>&1
        log_success "Apache service reloaded"
        return 0
    fi

    log_warn "Unable to reload Apache service"
    return 1
}

# Create hardened Apache security configuration
create_hardened_security_config() {
    log_section "Creating Hardened Apache Security Configuration"

    # Create conf-available directory if it doesn't exist
    if [[ ! -d "$APACHE_CONF_AVAILABLE" ]]; then
        log_info "Creating $APACHE_CONF_AVAILABLE directory"
        mkdir -p "$APACHE_CONF_AVAILABLE"
        chmod 0755 "$APACHE_CONF_AVAILABLE"
    fi

    # Backup existing config if present
    if [[ -f "$APACHE_SECURITY_CONF" ]]; then
        backup_file "$APACHE_SECURITY_CONF"
    fi

    log_info "Writing hardened security configuration to $APACHE_SECURITY_CONF"
    cat > "$APACHE_SECURITY_CONF" <<'EOF'
# === CyberPatriot Apache Hardening (auto) ===
# This configuration file implements comprehensive Apache security hardening
# for CyberPatriot competitions

# ============================================
# Core Security Directives
# ============================================

# ServerTokens: Controls the Server HTTP response header
# Setting to "Prod" hides version, OS, and module information
# This prevents attackers from identifying specific vulnerabilities
ServerTokens Prod

# ServerSignature: Disables server signature on error pages
# Prevents disclosure of Apache version on auto-generated pages (404, 403, etc.)
ServerSignature Off

# TraceEnable: Disables HTTP TRACE method
# TRACE can be exploited in Cross-Site Tracing (XST) attacks
# It should always be disabled
TraceEnable Off

# FileETag: Controls ETag header generation
# Default ETags can leak inode numbers and other filesystem info
# Setting to "None" disables ETags entirely
FileETag None

# ============================================
# Timeout and Connection Settings
# ============================================

# Timeout: Maximum time to wait for a request
# Prevents slowloris-type DoS attacks where clients hold connections open
Timeout 60

# KeepAliveTimeout: Time to wait for next request on persistent connection
# Lower values reduce resource consumption from idle connections
KeepAliveTimeout 5

# ============================================
# Request Size Limits
# ============================================

# LimitRequestBody: Maximum size of HTTP request body
# Prevents DoS attacks via huge file uploads or form submissions
# Set to 10MB (10485760 bytes)
LimitRequestBody 10485760

# LimitRequestFields: Maximum number of request header fields
LimitRequestFields 100

# LimitRequestFieldSize: Maximum size of request header field
LimitRequestFieldSize 8190

# LimitRequestLine: Maximum size of HTTP request line
LimitRequestLine 8190

# ============================================
# Directory Security
# ============================================

# Disable directory browsing globally
# Prevents auto-generation of file listings when no index file exists
<Directory />
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

# Web root hardening
<Directory /var/www/>
    Options -Indexes -FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# Disable access to .ht files (Apache configuration)
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# Disable access to version control directories
<DirectoryMatch "/\.(git|svn|hg|bzr)">
    Require all denied
</DirectoryMatch>

# Disable access to backup and temporary files
<FilesMatch "(~|\.bak|\.swp|\.tmp|\.old|\.orig)$">
    Require all denied
</FilesMatch>

EOF

    chmod 0644 "$APACHE_SECURITY_CONF"
    log_success "Hardened security configuration created"
    return 0
}

# Create security headers configuration (requires mod_headers)
create_security_headers_config() {
    log_section "Creating Security Headers Configuration"

    if [[ "$APACHE_ENABLE_SECURITY_HEADERS" != "yes" ]]; then
        log_info "Security headers disabled, skipping"
        return 0
    fi

    local headers_conf="${APACHE_CONF_AVAILABLE}/security-headers.conf"

    # Backup existing config if present
    if [[ -f "$headers_conf" ]]; then
        backup_file "$headers_conf"
    fi

    log_info "Writing security headers configuration to $headers_conf"
    cat > "$headers_conf" <<'EOF'
# === Apache Security Headers Configuration ===
# These headers protect clients from web-based attacks

<IfModule mod_headers.c>
    # X-Frame-Options: Prevents clickjacking attacks
    # SAMEORIGIN allows framing only by pages from the same origin
    # This prevents the site from being embedded in malicious iframes
    Header always set X-Frame-Options "SAMEORIGIN"

    # X-Content-Type-Options: Prevents MIME sniffing
    # "nosniff" stops browsers from trying to guess content types
    # This helps prevent XSS attacks via uploaded files
    Header always set X-Content-Type-Options "nosniff"

    # X-XSS-Protection: Enables browser XSS filtering
    # "1; mode=block" enables the filter and blocks the page if attack detected
    # Note: Modern browsers use Content-Security-Policy instead
    Header always set X-XSS-Protection "1; mode=block"

    # Referrer-Policy: Controls referrer information sent with requests
    # "strict-origin-when-cross-origin" provides good balance of privacy and functionality
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # Remove server information headers
    Header unset Server
    Header always unset X-Powered-By

    # Strict-Transport-Security: Forces HTTPS connections (only if using SSL)
    # Uncomment if using HTTPS:
    # Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    # Content-Security-Policy: Defines content sources browser should load
    # This is a basic policy - customize based on your application needs
    # Uncomment and adjust as needed:
    # Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"

    # Permissions-Policy: Controls browser features and APIs
    # Restricts access to potentially dangerous features
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>
EOF

    chmod 0644 "$headers_conf"
    log_success "Security headers configuration created"

    # Enable the configuration
    if [[ -d "$APACHE_CONF_ENABLED" ]]; then
        ln -sf "$headers_conf" "${APACHE_CONF_ENABLED}/security-headers.conf" 2>/dev/null || true
        log_info "Security headers configuration enabled"
    fi

    return 0
}

# Enable required Apache modules
enable_required_modules() {
    log_section "Enabling Required Apache Modules"

    if ! command_exists a2enmod; then
        log_warn "a2enmod command not found, skipping module management"
        return 0
    fi

    local modules_to_enable=()

    # mod_headers is required for security headers
    if [[ "$APACHE_ENABLE_SECURITY_HEADERS" == "yes" ]]; then
        modules_to_enable+=("headers")
    fi

    for module in "${modules_to_enable[@]}"; do
        if [[ ! -e "${APACHE_MODS_ENABLED}/${module}.load" ]]; then
            log_info "Enabling module: $module"
            a2enmod "$module" >/dev/null 2>&1 || log_warn "Failed to enable module: $module"
            log_success "Module enabled: $module"
            log_score 1 "Enabled Apache module: $module"
        else
            log_debug "Module already enabled: $module"
        fi
    done

    return 0
}

# Disable unnecessary Apache modules
disable_unnecessary_modules() {
    log_section "Disabling Unnecessary Apache Modules"

    if [[ "$APACHE_DISABLE_UNNECESSARY_MODULES" != "yes" ]]; then
        log_info "Module disabling disabled, skipping"
        return 0
    fi

    if ! command_exists a2dismod; then
        log_warn "a2dismod command not found, skipping module management"
        return 0
    fi

    for module in "${MODULES_TO_DISABLE[@]}"; do
        if [[ -e "${APACHE_MODS_ENABLED}/${module}.load" ]]; then
            log_info "Disabling module: $module"
            a2dismod "$module" >/dev/null 2>&1 || log_warn "Failed to disable module: $module"
            log_success "Module disabled: $module"
            log_score 2 "Disabled unnecessary Apache module: $module"
        else
            log_debug "Module not enabled: $module"
        fi
    done

    return 0
}

# Harden Apache directory permissions
harden_apache_permissions() {
    log_section "Hardening Apache File and Directory Permissions"

    # Apache configuration directory permissions
    log_info "Setting ownership and permissions on $APACHE_CONF_DIR"
    if [[ -d "$APACHE_CONF_DIR" ]]; then
        chown -R root:root "$APACHE_CONF_DIR" 2>/dev/null || true
        chmod -R 640 "$APACHE_CONF_DIR" 2>/dev/null || true

        # Ensure directories are executable/accessible
        find "$APACHE_CONF_DIR" -type d -exec chmod 755 {} \; 2>/dev/null || true

        log_success "Apache configuration directory permissions hardened"
        log_score 2 "Hardened Apache configuration directory permissions"
    fi

    # Web root permissions
    if [[ -d "$APACHE_WEB_ROOT" ]]; then
        log_info "Hardening web root permissions: $APACHE_WEB_ROOT"

        # Set ownership to www-data (typical Apache user)
        if id www-data >/dev/null 2>&1; then
            chown -R www-data:www-data "$APACHE_WEB_ROOT" 2>/dev/null || true
            log_debug "Set ownership to www-data:www-data"
        fi

        # Set directory permissions (750 = rwxr-x---)
        find "$APACHE_WEB_ROOT" -type d -exec chmod 750 {} \; 2>/dev/null || true
        log_debug "Set directory permissions to 750"

        # Set file permissions (640 = rw-r-----)
        find "$APACHE_WEB_ROOT" -type f -exec chmod 640 {} \; 2>/dev/null || true
        log_debug "Set file permissions to 640"

        # Ensure no files are executable unless they're scripts
        find "$APACHE_WEB_ROOT" -type f -name "*.sh" -exec chmod 750 {} \; 2>/dev/null || true
        find "$APACHE_WEB_ROOT" -type f -name "*.cgi" -exec chmod 750 {} \; 2>/dev/null || true

        log_success "Web root permissions hardened"
        log_score 3 "Hardened Apache web root permissions"
    else
        log_warn "Web root not found at $APACHE_WEB_ROOT"
    fi

    # Log directory permissions
    if [[ -d "/var/log/apache2" ]]; then
        log_info "Hardening log directory permissions"
        chown -R root:adm /var/log/apache2 2>/dev/null || true
        chmod 750 /var/log/apache2 2>/dev/null || true
        find /var/log/apache2 -type f -exec chmod 640 {} \; 2>/dev/null || true
        log_success "Apache log directory permissions hardened"
    fi

    return 0
}

# Enable security configuration
enable_security_config() {
    log_section "Enabling Apache Security Configuration"

    if ! command_exists a2enconf; then
        log_warn "a2enconf command not found, attempting manual enabling"
        if [[ -d "$APACHE_CONF_ENABLED" && -f "$APACHE_SECURITY_CONF" ]]; then
            ln -sf "$APACHE_SECURITY_CONF" "${APACHE_CONF_ENABLED}/${APACHE_CONFIG_NAME}" 2>/dev/null || true
            log_info "Security configuration manually enabled"
        fi
        return 0
    fi

    local conf_name="${APACHE_CONFIG_NAME%.conf}"
    log_info "Enabling configuration: $conf_name"
    a2enconf "$conf_name" >/dev/null 2>&1 || log_warn "Failed to enable configuration: $conf_name"
    log_success "Security configuration enabled"
    log_score 5 "Enabled Apache security configuration"

    return 0
}

# Validate Apache configuration
validate_apache_config() {
    log_section "Validating Apache Configuration"

    # Find Apache control binary
    local apache_ctl
    if command_exists apache2ctl; then
        apache_ctl="apache2ctl"
    elif command_exists apachectl; then
        apache_ctl="apachectl"
    else
        log_error "Apache control binary not found"
        return 1
    fi

    # Test configuration
    log_info "Running configuration test: $apache_ctl configtest"
    local test_output
    test_output=$($apache_ctl configtest 2>&1 || true)

    if echo "$test_output" | grep -qi "syntax ok"; then
        log_success "Apache configuration is valid"
    else
        log_error "Apache configuration has errors:"
        echo "$test_output" | while IFS= read -r line; do
            log_error "  $line"
        done
        return 1
    fi

    # Show loaded modules
    log_info "Currently loaded Apache modules:"
    if command_exists apache2ctl; then
        apache2ctl -M 2>/dev/null | grep -E "(headers|rewrite|ssl)" | while IFS= read -r line; do
            log_debug "  $line"
        done || true
    fi

    return 0
}

# Display summary
display_summary() {
    log_section "Apache Hardening Summary"

    log_success "Apache hardened successfully"
    log_info "Security improvements applied:"
    log_info "  ✓ ServerTokens set to Prod (version hiding)"
    log_info "  ✓ ServerSignature disabled"
    log_info "  ✓ HTTP TRACE method disabled"
    log_info "  ✓ FileETag set to None"
    log_info "  ✓ Timeout set to ${APACHE_TIMEOUT} seconds"
    log_info "  ✓ KeepAliveTimeout set to ${APACHE_KEEPALIVE_TIMEOUT} seconds"
    log_info "  ✓ Request body limit set to ${APACHE_REQUEST_BODY_LIMIT} bytes"

    if [[ "$APACHE_DISABLE_DIRECTORY_LISTING" == "yes" ]]; then
        log_info "  ✓ Directory listing disabled"
    fi

    if [[ "$APACHE_ENABLE_SECURITY_HEADERS" == "yes" ]]; then
        log_info "  ✓ Security headers enabled:"
        log_info "    - X-Frame-Options: SAMEORIGIN"
        log_info "    - X-Content-Type-Options: nosniff"
        log_info "    - X-XSS-Protection: 1; mode=block"
        log_info "    - Referrer-Policy: strict-origin-when-cross-origin"
    fi

    log_info "  ✓ Configuration directory permissions hardened"
    log_info "  ✓ Web root permissions hardened"

    if [[ "$APACHE_DISABLE_UNNECESSARY_MODULES" == "yes" ]]; then
        log_info "  ✓ Unnecessary modules disabled"
    fi

    log_info ""
    log_info "Configuration files:"
    log_info "  - Security: $APACHE_SECURITY_CONF"
    if [[ "$APACHE_ENABLE_SECURITY_HEADERS" == "yes" ]]; then
        log_info "  - Headers: ${APACHE_CONF_AVAILABLE}/security-headers.conf"
    fi

    return 0
}

# Main module function
run_apache_hardening() {
    log_info "Starting Apache Hardening module..."

    # Check if Apache is installed
    if ! apache_is_installed; then
        log_warn "Apache is not installed on this system, skipping module"
        return 0
    fi

    # Verify we have necessary permissions
    if [[ $EUID -ne 0 ]]; then
        log_error "Apache hardening requires root privileges"
        return 1
    fi

    # Execute hardening steps
    create_hardened_security_config
    create_security_headers_config
    enable_required_modules
    disable_unnecessary_modules
    enable_security_config
    harden_apache_permissions

    # Validate and reload
    if ! validate_apache_config; then
        log_error "Apache configuration validation failed, not reloading service"
        log_error "Please review the configuration errors above"
        return 1
    fi

    # Only reload if service is running
    if apache_service_exists && systemctl is-active apache2 >/dev/null 2>&1; then
        apache_service_reload
    else
        log_info "Apache service is not running, skipping reload"
        log_info "Configuration will take effect when Apache is started"
    fi

    display_summary

    log_success "Apache Hardening module completed"
    return 0
}

export -f run_apache_hardening
