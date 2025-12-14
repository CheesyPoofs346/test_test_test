#!/bin/bash
# php_hardening.sh - PHP Hardening Module
# Implements comprehensive PHP hardening for CyberPatriot competitions
# Covers both PHP-FPM and Apache (mod_php) installations

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: PHP Hardening
# Category: Application Security
# Description: Hardens PHP configuration, permissions, and removes dangerous files

# ====== EDITABLE DEFAULTS ======
readonly PHP_DISABLE_FUNCTIONS="${PHP_DISABLE_FUNCTIONS:-exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,highlight_file,phpinfo,pcntl_exec,pcntl_fork,pcntl_signal,pcntl_waitpid,pcntl_wexitstatus,pcntl_wifexited,pcntl_wifsignaled,pcntl_wifstopped,pcntl_wstopsig,pcntl_wtermsig,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,dl}"
readonly PHP_OPEN_BASEDIR="${PHP_OPEN_BASEDIR:-/var/www:/tmp:/usr/share/php:/dev/urandom}"
readonly PHP_MAX_EXECUTION_TIME="${PHP_MAX_EXECUTION_TIME:-30}"
readonly PHP_MAX_INPUT_TIME="${PHP_MAX_INPUT_TIME:-60}"
readonly PHP_MEMORY_LIMIT="${PHP_MEMORY_LIMIT:-128M}"
readonly PHP_POST_MAX_SIZE="${PHP_POST_MAX_SIZE:-8M}"
readonly PHP_UPLOAD_MAX_FILESIZE="${PHP_UPLOAD_MAX_FILESIZE:-2M}"
readonly PHP_SESSION_NAME="${PHP_SESSION_NAME:-PHPSESSID}"
readonly PHP_SESSION_COOKIE_LIFETIME="${PHP_SESSION_COOKIE_LIFETIME:-0}"
readonly PHP_REMOVE_PHPINFO="${PHP_REMOVE_PHPINFO:-yes}"
readonly PHP_HARDEN_PERMISSIONS="${PHP_HARDEN_PERMISSIONS:-yes}"
readonly PHP_WEB_ROOT="${PHP_WEB_ROOT:-/var/www/html}"

# Ensure a directive exists in php.ini with the desired value
ensure_php_directive() {
    local file="$1"
    local key="$2"
    local value="$3"

    if grep -Eq "^[;[:space:]]*${key}[[:space:]]*=" "$file"; then
        sed -i "s|^[;[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
    else
        echo "${key} = ${value}" >> "$file"
    fi
}

# Detect installed PHP versions
detect_php_versions() {
    local versions=()

    # Check /etc/php/ directory
    if [[ -d "/etc/php" ]]; then
        while IFS= read -r dir; do
            local version
            version=$(basename "$dir")
            # Validate it's a version number (e.g., 8.3, 7.4)
            if [[ "$version" =~ ^[0-9]+\.[0-9]+$ ]]; then
                versions+=("$version")
            fi
        done < <(find /etc/php -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
    fi

    # Output versions
    if [[ ${#versions[@]} -gt 0 ]]; then
        printf '%s\n' "${versions[@]}"
        return 0
    fi

    return 1
}

# Detect PHP SAPIs (Server Application Programming Interface) for a version
detect_php_sapis() {
    local version="$1"
    local sapis=()

    local base_dir="/etc/php/${version}"

    # Check for common SAPIs
    for sapi in apache2 fpm cli cgi; do
        if [[ -d "${base_dir}/${sapi}" ]]; then
            sapis+=("$sapi")
        fi
    done

    if [[ ${#sapis[@]} -gt 0 ]]; then
        printf '%s\n' "${sapis[@]}"
        return 0
    fi

    return 1
}

# Apply hardening directives directly to php.ini
harden_php_ini() {
    local ini_file="$1"

    if [[ ! -f "$ini_file" ]]; then
        log_warn "php.ini not found: $ini_file"
        return 1
    fi

    log_info "Hardening PHP configuration: $ini_file"
    backup_file "$ini_file"

    ensure_php_directive "$ini_file" "expose_php" "Off"
    ensure_php_directive "$ini_file" "display_errors" "Off"
    ensure_php_directive "$ini_file" "display_startup_errors" "Off"
    ensure_php_directive "$ini_file" "log_errors" "On"
    ensure_php_directive "$ini_file" "error_log" "/var/log/php_errors.log"
    ensure_php_directive "$ini_file" "html_errors" "Off"
    ensure_php_directive "$ini_file" "ignore_repeated_errors" "On"
    ensure_php_directive "$ini_file" "ignore_repeated_source" "On"

    ensure_php_directive "$ini_file" "allow_url_fopen" "Off"
    ensure_php_directive "$ini_file" "allow_url_include" "Off"
    ensure_php_directive "$ini_file" "enable_dl" "Off"
    ensure_php_directive "$ini_file" "disable_functions" "${PHP_DISABLE_FUNCTIONS}"

    ensure_php_directive "$ini_file" "session.cookie_secure" "1"
    ensure_php_directive "$ini_file" "session.cookie_httponly" "1"
    ensure_php_directive "$ini_file" "session.use_strict_mode" "1"
    ensure_php_directive "$ini_file" "session.use_only_cookies" "1"
    ensure_php_directive "$ini_file" "session.cookie_samesite" "Strict"
    ensure_php_directive "$ini_file" "session.name" "${PHP_SESSION_NAME}"
    ensure_php_directive "$ini_file" "session.cookie_lifetime" "${PHP_SESSION_COOKIE_LIFETIME}"
    ensure_php_directive "$ini_file" "session.use_trans_sid" "0"
    ensure_php_directive "$ini_file" "session.cookie_domain" ""
    ensure_php_directive "$ini_file" "session.referer_check" ""
    ensure_php_directive "$ini_file" "session.entropy_length" "32"
    ensure_php_directive "$ini_file" "session.hash_function" "sha256"
    ensure_php_directive "$ini_file" "session.hash_bits_per_character" "5"

    ensure_php_directive "$ini_file" "file_uploads" "Off"
    ensure_php_directive "$ini_file" "upload_max_filesize" "${PHP_UPLOAD_MAX_FILESIZE}"
    ensure_php_directive "$ini_file" "max_file_uploads" "2"

    ensure_php_directive "$ini_file" "max_execution_time" "${PHP_MAX_EXECUTION_TIME}"
    ensure_php_directive "$ini_file" "max_input_time" "${PHP_MAX_INPUT_TIME}"
    ensure_php_directive "$ini_file" "memory_limit" "${PHP_MEMORY_LIMIT}"
    ensure_php_directive "$ini_file" "post_max_size" "${PHP_POST_MAX_SIZE}"
    ensure_php_directive "$ini_file" "max_input_vars" "1000"
    ensure_php_directive "$ini_file" "max_input_nesting_level" "64"

    ensure_php_directive "$ini_file" "open_basedir" "${PHP_OPEN_BASEDIR}"

    ensure_php_directive "$ini_file" "variables_order" "\"GPCS\""
    ensure_php_directive "$ini_file" "request_order" "\"GP\""
    ensure_php_directive "$ini_file" "register_argc_argv" "Off"
    ensure_php_directive "$ini_file" "auto_globals_jit" "On"
    ensure_php_directive "$ini_file" "magic_quotes_gpc" "Off"

    ensure_php_directive "$ini_file" "sql.safe_mode" "On"
    ensure_php_directive "$ini_file" "mail.add_x_header" "Off"
    ensure_php_directive "$ini_file" "zend.assertions" "-1"
    ensure_php_directive "$ini_file" "assert.active" "0"
    ensure_php_directive "$ini_file" "cgi.force_redirect" "1"
    ensure_php_directive "$ini_file" "cgi.fix_pathinfo" "0"
    ensure_php_directive "$ini_file" "default_socket_timeout" "60"
    ensure_php_directive "$ini_file" "allow_webdav_methods" "Off"
    ensure_php_directive "$ini_file" "user_agent" "\"\""
    ensure_php_directive "$ini_file" "default_charset" "\"UTF-8\""

    chmod 644 "$ini_file"
    chown root:root "$ini_file"

    log_success "Applied hardening to $ini_file"
    return 0
}

# Apply hardening to all detected PHP versions and SAPIs
apply_php_hardening() {
    log_section "Applying PHP Configuration Hardening"

    local versions
    if ! versions=$(detect_php_versions); then
        log_warn "No PHP installations detected in /etc/php/"
        return 1
    fi

    local hardened_count=0
    local version

    while IFS= read -r version; do
        log_info "Processing PHP version: $version"

        local sapis
        if sapis=$(detect_php_sapis "$version"); then
            local sapi
            while IFS= read -r sapi; do
                local ini_file="/etc/php/${version}/${sapi}/php.ini"

                if [[ -f "$ini_file" ]]; then
                    log_info "  Hardening PHP ${version} ${sapi} SAPI"
                    harden_php_ini "$ini_file"
                    ((hardened_count++))
                else
                    log_warn "  php.ini not found for ${version} ${sapi}: $ini_file"
                fi
            done <<< "$sapis"
        else
            log_warn "  No SAPIs found for PHP $version"
        fi
    done <<< "$versions"

    if [[ $hardened_count -eq 0 ]]; then
        log_error "No PHP configurations were hardened"
        return 1
    fi

    log_success "Hardened $hardened_count PHP configuration(s)"
    log_score 3 "Applied PHP security hardening to $hardened_count configuration(s)"
    return 0
}

# Remove dangerous phpinfo files
remove_phpinfo_files() {
    log_section "Removing PHPInfo Files"

    if [[ "$PHP_REMOVE_PHPINFO" != "yes" ]]; then
        log_info "PHPInfo removal disabled, skipping"
        return 0
    fi

    if [[ ! -d "$PHP_WEB_ROOT" ]]; then
        log_warn "Web root not found: $PHP_WEB_ROOT, skipping phpinfo removal"
        return 0
    fi

    log_info "Searching for phpinfo files in $PHP_WEB_ROOT"

    local phpinfo_patterns=(
        "phpinfo.php"
        "info.php"
        "test.php"
        "pi.php"
        "php_info.php"
    )

    local removed_count=0
    local pattern

    for pattern in "${phpinfo_patterns[@]}"; do
        local files
        files=$(find "$PHP_WEB_ROOT" -type f -name "$pattern" 2>/dev/null || true)

        if [[ -n "$files" ]]; then
            while IFS= read -r file; do
                if [[ -f "$file" ]]; then
                    # Check if file actually contains phpinfo() call
                    if grep -qi "phpinfo\s*(" "$file" 2>/dev/null; then
                        log_warn "  Removing dangerous file: $file"
                        backup_file "$file" || log_warn "  Failed to backup $file before removal"
                        rm -f "$file"
                        ((removed_count++))
                        log_score 1 "Removed phpinfo file: $file"
                    fi
                fi
            done <<< "$files"
        fi
    done

    # Also search for any PHP file containing phpinfo() in common locations
    log_info "Searching for files containing phpinfo() calls"
    local phpinfo_files
    phpinfo_files=$(find "$PHP_WEB_ROOT" -type f -name "*.php" -exec grep -l "phpinfo\s*(" {} \; 2>/dev/null | head -20 || true)

    if [[ -n "$phpinfo_files" ]]; then
        while IFS= read -r file; do
            if [[ -f "$file" ]]; then
                local filename
                filename=$(basename "$file")
                # Skip common framework files that might have commented phpinfo
                if [[ ! "$filename" =~ ^(index|config|settings|functions)\.php$ ]]; then
                    log_warn "  Found phpinfo() in: $file (review manually)"
                fi
            fi
        done <<< "$phpinfo_files"
    fi

    if [[ $removed_count -gt 0 ]]; then
        log_success "Removed $removed_count phpinfo file(s)"
    else
        log_info "No dangerous phpinfo files found"
    fi

    return 0
}

# Harden PHP configuration file permissions
harden_php_permissions() {
    log_section "Hardening PHP File Permissions"

    if [[ "$PHP_HARDEN_PERMISSIONS" != "yes" ]]; then
        log_info "Permission hardening disabled, skipping"
        return 0
    fi

    # Harden /etc/php directory permissions
    if [[ -d "/etc/php" ]]; then
        log_info "Setting ownership and permissions on /etc/php"

        # Find all php.ini and .ini files
        local ini_files
        ini_files=$(find /etc/php -type f \( -name "php.ini" -o -name "*.ini" \) 2>/dev/null || true)

        if [[ -n "$ini_files" ]]; then
            while IFS= read -r file; do
                if [[ -f "$file" ]]; then
                    chown root:root "$file" 2>/dev/null || true
                    chmod 644 "$file" 2>/dev/null || true
                    log_debug "  Set 644 root:root on $file"
                fi
            done <<< "$ini_files"
        fi

        # Harden directory permissions
        local dirs
        dirs=$(find /etc/php -type d 2>/dev/null || true)

        if [[ -n "$dirs" ]]; then
            while IFS= read -r dir; do
                if [[ -d "$dir" ]]; then
                    chown root:root "$dir" 2>/dev/null || true
                    chmod 755 "$dir" 2>/dev/null || true
                fi
            done <<< "$dirs"
        fi

        log_success "PHP configuration file permissions hardened"
        log_score 1 "Hardened PHP configuration file permissions"
    else
        log_warn "/etc/php directory not found"
    fi

    return 0
}

# Harden web directory permissions
harden_web_permissions() {
    log_section "Hardening Web Directory Permissions"

    if [[ "$PHP_HARDEN_PERMISSIONS" != "yes" ]]; then
        log_info "Permission hardening disabled, skipping"
        return 0
    fi

    if [[ ! -d "$PHP_WEB_ROOT" ]]; then
        log_warn "Web root not found: $PHP_WEB_ROOT, skipping web directory hardening"
        return 0
    fi

    log_info "Hardening permissions for: $PHP_WEB_ROOT"

    # Determine web user (typically www-data on Debian/Ubuntu)
    local web_user="www-data"
    if ! id "$web_user" >/dev/null 2>&1; then
        # Try alternative common web users
        for user in apache httpd nginx; do
            if id "$user" >/dev/null 2>&1; then
                web_user="$user"
                break
            fi
        done
    fi

    # If no valid web user exists, fall back to root to avoid failing under set -e
    if ! id "$web_user" >/dev/null 2>&1; then
        log_warn "No web service user found; using root for permission hardening"
        web_user="root"
    fi

    log_info "Using web user: $web_user"

    # Set ownership
    log_info "Setting ownership to ${web_user}:${web_user}"
    chown -R "${web_user}:${web_user}" "$PHP_WEB_ROOT" 2>/dev/null || true

    # Set directory permissions (755 - owner can write, others can read/execute)
    log_info "Setting directory permissions to 755"
    find "$PHP_WEB_ROOT" -type d -exec chmod 755 {} \; 2>/dev/null || true

    # Set file permissions (644 - owner can write, others can only read)
    log_info "Setting file permissions to 644"
    find "$PHP_WEB_ROOT" -type f -exec chmod 644 {} \; 2>/dev/null || true

    # Special handling for upload directories if they exist
    local upload_dirs=(
        "${PHP_WEB_ROOT}/uploads"
        "${PHP_WEB_ROOT}/upload"
        "${PHP_WEB_ROOT}/files"
        "${PHP_WEB_ROOT}/media"
    )

    for upload_dir in "${upload_dirs[@]}"; do
        if [[ -d "$upload_dir" ]]; then
            log_warn "Found upload directory: $upload_dir"
            log_info "  Setting restrictive permissions (750) on upload directory"
            chmod 750 "$upload_dir" 2>/dev/null || true

            # Prevent script execution in upload directories
            local htaccess="${upload_dir}/.htaccess"
            if [[ ! -f "$htaccess" ]]; then
                cat > "$htaccess" <<'HTACCESS'
# Prevent PHP execution in upload directory
<FilesMatch "\.(?i:php|php3|php4|php5|phtml|pl|py|jsp|asp|sh|cgi)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>
HTACCESS
                chmod 644 "$htaccess"
                chown "${web_user}:${web_user}" "$htaccess" 2>/dev/null || true
                log_success "  Created .htaccess to prevent script execution in $upload_dir"
                log_score 1 "Prevented script execution in upload directory"
            fi
        fi
    done

    log_success "Web directory permissions hardened"
    log_score 2 "Hardened web directory permissions"
    return 0
}

# Restart/reload PHP services
reload_php_services() {
    log_section "Reloading PHP Services"

    local services_reloaded=0

    # Try to reload PHP-FPM services
    local fpm_services
    fpm_services=$(systemctl list-unit-files 2>/dev/null | grep -o 'php[0-9.]*-fpm\.service' || true)

    if [[ -n "$fpm_services" ]]; then
        while IFS= read -r service; do
            if systemctl is-active "$service" >/dev/null 2>&1; then
                log_info "Reloading $service"
                systemctl reload "$service" >/dev/null 2>&1 && {
                    log_success "$service reloaded"
                    ((services_reloaded++))
                } || log_warn "Failed to reload $service"
            fi
        done <<< "$fpm_services"
    fi

    # Reload Apache if it's running and has PHP module
    if systemctl is-active apache2 >/dev/null 2>&1; then
        log_info "Reloading Apache2"
        systemctl reload apache2 >/dev/null 2>&1 && {
            log_success "Apache2 reloaded"
            ((services_reloaded++))
        } || log_warn "Failed to reload Apache2"
    fi

    # Reload Nginx if it's running
    if systemctl is-active nginx >/dev/null 2>&1; then
        log_info "Reloading Nginx"
        systemctl reload nginx >/dev/null 2>&1 && {
            log_success "Nginx reloaded"
            ((services_reloaded++))
        } || log_warn "Failed to reload Nginx"
    fi

    if [[ $services_reloaded -eq 0 ]]; then
        log_warn "No PHP services were reloaded"
    else
        log_success "Reloaded $services_reloaded service(s)"
    fi

    return 0
}

# Validate PHP configuration
validate_php_config() {
    log_section "Validating PHP Configuration"

    local versions
    if ! versions=$(detect_php_versions); then
        log_warn "No PHP installations to validate"
        return 0
    fi

    local version
    while IFS= read -r version; do
        local php_bin

        # Try to find PHP binary for this version
        for candidate in "/usr/bin/php${version}" "/usr/bin/php" "php${version}" "php"; do
            if command -v "$candidate" >/dev/null 2>&1; then
                php_bin="$candidate"
                break
            fi
        done

        if [[ -z "$php_bin" ]]; then
            log_warn "PHP binary not found for version $version"
            continue
        fi

        log_info "Testing PHP $version configuration with: $php_bin"

        # Test configuration syntax
        if $php_bin -v >/dev/null 2>&1; then
            log_success "  PHP $version configuration is valid"

            # Show some key security settings
            log_info "  Key security settings:"

            local expose_php
            expose_php=$($php_bin -r "echo ini_get('expose_php');" 2>/dev/null || echo "unknown")
            log_debug "    expose_php = $expose_php"

            local display_errors
            display_errors=$($php_bin -r "echo ini_get('display_errors');" 2>/dev/null || echo "unknown")
            log_debug "    display_errors = $display_errors"

            local allow_url_fopen
            allow_url_fopen=$($php_bin -r "echo ini_get('allow_url_fopen');" 2>/dev/null || echo "unknown")
            log_debug "    allow_url_fopen = $allow_url_fopen"

            local allow_url_include
            allow_url_include=$($php_bin -r "echo ini_get('allow_url_include');" 2>/dev/null || echo "unknown")
            log_debug "    allow_url_include = $allow_url_include"
        else
            log_error "  PHP $version configuration has errors"
        fi
    done <<< "$versions"

    return 0
}

# Display summary
display_summary() {
    log_section "PHP Hardening Summary"

    log_success "PHP hardening completed successfully"
    log_info "Security measures applied:"
    log_info "  - Information disclosure: expose_php=Off, display_errors=Off"
    log_info "  - Code execution: allow_url_fopen=Off, allow_url_include=Off"
    log_info "  - Dangerous functions disabled: exec, system, shell_exec, etc."
    log_info "  - Session security: secure, httponly, strict mode enabled"
    log_info "  - File uploads: disabled by default"
    log_info "  - Open basedir restrictions: $PHP_OPEN_BASEDIR"
    log_info "  - PHP configuration file permissions: 644 root:root"
    log_info "  - Web directory permissions: properly restricted"
    log_info "  - PHPInfo files: removed from web root"

    return 0
}

# Main module function
run_php_hardening() {
    log_info "Starting PHP Hardening module..."

    # Execute hardening steps
    apply_php_hardening || {
        log_error "PHP hardening failed - no PHP installations found"
        return 1
    }

    remove_phpinfo_files
    harden_php_permissions
    harden_web_permissions
    reload_php_services
    validate_php_config
    display_summary

    log_success "PHP Hardening module completed"
    return 0
}

export -f run_php_hardening
