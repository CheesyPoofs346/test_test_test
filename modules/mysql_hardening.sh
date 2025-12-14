#!/bin/bash
# MySQL/MariaDB Hardening Module
#
# Category: Database Security
# Description: Hardens MySQL/MariaDB configuration, removes insecure defaults,
#              enforces encryption, applies strong password policies, and secures
#              file system permissions.
#
# This module implements comprehensive MySQL/MariaDB security hardening including:
# - Configuration file hardening (bind-address, SSL/TLS, user privileges)
# - Removal of anonymous users and test databases
# - Disabling remote root login
# - Enforcing strong password policies
# - Securing file system permissions (config and data directory)
# - Disabling dangerous features (local_infile, symbolic links)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Configuration defaults
readonly DEFAULT_MYSQL_BIND_ADDRESS="127.0.0.1"
readonly DEFAULT_MYSQL_USER="mysql"
readonly DEFAULT_MYSQL_CONFIG_PERMS="644"
readonly DEFAULT_MYSQL_DATA_DIR="/var/lib/mysql"
readonly DEFAULT_MYSQL_DATA_PERMS="750"
readonly MYSQL_CONFIG_SNIPPET="/etc/mysql/mysql.conf.d/99-cyberpatriot.cnf"
readonly MYSQL_ALT_CONFIG_SNIPPET="/etc/mysql/conf.d/99-cyberpatriot.cnf"

# Configurable parameters (can be overridden)
MYSQL_BIND_ADDRESS="${MYSQL_BIND_ADDRESS:-$DEFAULT_MYSQL_BIND_ADDRESS}"
MYSQL_ENFORCE_SSL="${MYSQL_ENFORCE_SSL:-yes}"
MYSQL_DISABLE_LOCAL_INFILE="${MYSQL_DISABLE_LOCAL_INFILE:-yes}"
MYSQL_REMOVE_ANONYMOUS="${MYSQL_REMOVE_ANONYMOUS:-yes}"
MYSQL_REMOVE_TEST_DB="${MYSQL_REMOVE_TEST_DB:-yes}"
MYSQL_DISABLE_REMOTE_ROOT="${MYSQL_DISABLE_REMOTE_ROOT:-yes}"
MYSQL_INSTALL_PASSWORD_VALIDATOR="${MYSQL_INSTALL_PASSWORD_VALIDATOR:-yes}"
MYSQL_SECURE_PERMISSIONS="${MYSQL_SECURE_PERMISSIONS:-yes}"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-}"  # If set, will be used for auth

# Detect MySQL/MariaDB service name
detect_mysql_service() {
    local service_name=""

    if systemctl list-unit-files 2>/dev/null | grep -qE '^mysql\.service'; then
        service_name="mysql"
    elif systemctl list-unit-files 2>/dev/null | grep -qE '^mariadb\.service'; then
        service_name="mariadb"
    elif service --status-all 2>&1 | grep -qE 'mysql|mariadb'; then
        # Fallback for non-systemd systems
        if service mysql status >/dev/null 2>&1; then
            service_name="mysql"
        elif service mariadb status >/dev/null 2>&1; then
            service_name="mariadb"
        fi
    fi

    echo "$service_name"
}

# Check if MySQL/MariaDB is installed
mysql_installed() {
    command_exists mysql || command_exists mariadb
}

# Check if MySQL/MariaDB server is installed (not just client)
mysql_server_installed() {
    command_exists mysqld || systemctl list-unit-files 2>/dev/null | grep -qE 'mysql|mariadb'
}

# Ensure [mysqld] section exists in a config file
ensure_mysqld_section() {
    local config_file="$1"

    if ! grep -q "^\[mysqld\]" "$config_file" 2>/dev/null; then
        echo "[mysqld]" >> "$config_file"
    fi
}

# Ensure a MySQL directive is present (creates or replaces)
ensure_mysql_directive() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    local line="$key"

    [[ -n "$value" ]] && line="$key = $value"

    ensure_mysqld_section "$config_file"

    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$config_file"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*=.*|$line|" "$config_file"
    elif grep -Eq "^[[:space:]]*${key}[[:space:]]*$" "$config_file"; then
        sed -i "s|^[[:space:]]*${key}[[:space:]]*$|$line|" "$config_file"
    else
        echo "$line" >> "$config_file"
    fi
}

# Detect MySQL/MariaDB configuration file path
detect_mysql_config() {
    local config_path=""

    # Common MySQL/MariaDB config file locations
    local possible_configs=(
        "/etc/mysql/my.cnf"
        "/etc/my.cnf"
        "/etc/mysql/mysql.conf.d/mysqld.cnf"
        "/etc/mysql/mariadb.conf.d/50-server.cnf"
    )

    for cfg in "${possible_configs[@]}"; do
        if [[ -f "$cfg" ]]; then
            config_path="$cfg"
            break
        fi
    done

    echo "$config_path"
}

# Detect MySQL data directory
detect_mysql_data_dir() {
    local data_dir="$DEFAULT_MYSQL_DATA_DIR"

    # Try to get from running MySQL instance
    if command_exists mysql; then
        local detected
        detected=$(mysql -NBe "SELECT @@datadir;" 2>/dev/null | tr -d '\n' | sed 's/[[:space:]]*$//')
        if [[ -n "$detected" && -d "$detected" ]]; then
            data_dir="$detected"
        fi
    fi

    # Fallback: check common locations
    if [[ ! -d "$data_dir" ]]; then
        if [[ -d "/var/lib/mysql" ]]; then
            data_dir="/var/lib/mysql"
        elif [[ -d "/var/lib/mariadb" ]]; then
            data_dir="/var/lib/mariadb"
        fi
    fi

    echo "$data_dir"
}

# Create hardened MySQL configuration snippet
create_mysql_hardened_config() {
    local config_file="$1"

    log_info "Hardening MySQL configuration at: $config_file"

    local config_dir
    config_dir="$(dirname "$config_file")"
    mkdir -p "$config_dir"

    if [[ ! -f "$config_file" ]]; then
        log_warn "Main MySQL config missing, creating: $config_file"
        echo "[mysqld]" > "$config_file"
    fi

    backup_file "$config_file"

    ensure_mysql_directive "$config_file" "bind-address" "$MYSQL_BIND_ADDRESS"
    ensure_mysql_directive "$config_file" "skip-name-resolve" "1"
    ensure_mysql_directive "$config_file" "user" "$DEFAULT_MYSQL_USER"

    if [[ "$MYSQL_ENFORCE_SSL" == "yes" ]]; then
        ensure_mysql_directive "$config_file" "require_secure_transport" "ON"
    fi

    if [[ "$MYSQL_DISABLE_LOCAL_INFILE" == "yes" ]]; then
        ensure_mysql_directive "$config_file" "local-infile" "0"
        ensure_mysql_directive "$config_file" "local_infile" "0"
    fi

    ensure_mysql_directive "$config_file" "symbolic-links" "0"
    ensure_mysql_directive "$config_file" "skip-symbolic-links" ""

    ensure_mysql_directive "$config_file" "innodb_file_per_table" "1"
    ensure_mysql_directive "$config_file" "skip_name_resolve" "1"
    ensure_mysql_directive "$config_file" "log_warnings" "2"

    chmod "$DEFAULT_MYSQL_CONFIG_PERMS" "$config_file" || {
        log_error "Failed to set permissions on $config_file"
        return 1
    }

    chown root:root "$config_file" 2>/dev/null || {
        log_warn "Could not set ownership to root:root on $config_file"
    }

    log_success "Applied hardening to main MySQL config: $config_file"
    return 0
}

# Secure MySQL configuration file permissions
secure_mysql_config_permissions() {
    log_section "Securing MySQL Configuration File Permissions"

    local main_config
    main_config="$(detect_mysql_config)"

    if [[ -z "$main_config" || ! -f "$main_config" ]]; then
        log_warn "MySQL main configuration file not found, skipping permission hardening"
        return 0
    fi

    log_info "Securing permissions on: $main_config"

    # Backup before modifying
    backup_file "$main_config"

    # Set ownership to root:root
    if chown root:root "$main_config" 2>/dev/null; then
        log_success "Set ownership to root:root on $main_config"
    else
        log_warn "Could not set ownership on $main_config (may require elevated privileges)"
    fi

    # Set permissions to 644 (readable by all, writable only by root)
    if chmod "$DEFAULT_MYSQL_CONFIG_PERMS" "$main_config" 2>/dev/null; then
        log_success "Set permissions to $DEFAULT_MYSQL_CONFIG_PERMS on $main_config"
    else
        log_error "Failed to set permissions on $main_config"
        return 1
    fi

    # Also secure our custom config snippet
    if [[ -f "$MYSQL_CONFIG_SNIPPET" ]]; then
        chown root:root "$MYSQL_CONFIG_SNIPPET" 2>/dev/null
        chmod "$DEFAULT_MYSQL_CONFIG_PERMS" "$MYSQL_CONFIG_SNIPPET" 2>/dev/null
        log_success "Secured custom config snippet: $MYSQL_CONFIG_SNIPPET"
    fi

    return 0
}

# Secure MySQL data directory permissions
secure_mysql_data_directory() {
    log_section "Securing MySQL Data Directory Permissions"

    local data_dir
    data_dir="$(detect_mysql_data_dir)"

    if [[ -z "$data_dir" || ! -d "$data_dir" ]]; then
        log_warn "MySQL data directory not found: $data_dir"
        return 0
    fi

    log_info "Securing MySQL data directory: $data_dir"

    # Set ownership to mysql:mysql (recursively)
    if chown -R "$DEFAULT_MYSQL_USER:$DEFAULT_MYSQL_USER" "$data_dir" 2>/dev/null; then
        log_success "Set ownership to $DEFAULT_MYSQL_USER:$DEFAULT_MYSQL_USER on $data_dir"
    else
        log_warn "Could not set ownership on $data_dir"
    fi

    # Set permissions to 750 (owner: rwx, group: r-x, others: none)
    if chmod -R "$DEFAULT_MYSQL_DATA_PERMS" "$data_dir" 2>/dev/null; then
        log_success "Set permissions to $DEFAULT_MYSQL_DATA_PERMS on $data_dir"
        log_score "+5 MySQL data directory permissions hardened"
    else
        log_error "Failed to set permissions on $data_dir"
        return 1
    fi

    return 0
}

# Execute MySQL command with proper authentication
execute_mysql_query() {
    local query="$1"
    local result

    # Try authentication methods in order of preference
    local auth_methods=(
        "mysql -e"                                    # Try without password (unix socket auth)
        "mysql -u root -e"                           # Try as root without password
    )

    # If password is provided, add it to methods
    if [[ -n "$MYSQL_ROOT_PASSWORD" ]]; then
        auth_methods=("mysql -u root -p'$MYSQL_ROOT_PASSWORD' -e" "${auth_methods[@]}")
    fi

    for method in "${auth_methods[@]}"; do
        if result=$($method "$query" 2>/dev/null); then
            echo "$result"
            return 0
        fi
    done

    # All methods failed
    log_debug "All MySQL authentication methods failed for query: ${query:0:50}..."
    return 1
}

# Remove anonymous MySQL users
remove_anonymous_users() {
    log_section "Removing Anonymous MySQL Users"

    if [[ "$MYSQL_REMOVE_ANONYMOUS" != "yes" ]]; then
        log_info "Skipping anonymous user removal (disabled in config)"
        return 0
    fi

    log_info "Checking for anonymous users..."

    # Query to find anonymous users
    local anon_users
    anon_users=$(execute_mysql_query "SELECT User, Host FROM mysql.user WHERE User = '';" 2>/dev/null)

    if [[ -z "$anon_users" ]]; then
        log_info "No anonymous users found (or unable to query - may already be secure)"
        return 0
    fi

    log_info "Found anonymous users, removing..."

    # Remove anonymous users
    if execute_mysql_query "DELETE FROM mysql.user WHERE User = '';" >/dev/null 2>&1; then
        log_success "Removed anonymous users"

        # Flush privileges to apply changes
        if execute_mysql_query "FLUSH PRIVILEGES;" >/dev/null 2>&1; then
            log_success "Flushed privileges"
            log_score "+10 Removed anonymous MySQL users"
        else
            log_warn "Removed users but failed to flush privileges"
        fi
    else
        log_warn "Unable to remove anonymous users (authentication may be required)"
        log_info "Consider running: sudo mysql -e \"DELETE FROM mysql.user WHERE User = ''; FLUSH PRIVILEGES;\""
    fi

    return 0
}

# Disable remote root login
disable_remote_root_login() {
    log_section "Disabling Remote Root Login"

    if [[ "$MYSQL_DISABLE_REMOTE_ROOT" != "yes" ]]; then
        log_info "Skipping remote root login disable (disabled in config)"
        return 0
    fi

    log_info "Checking for remote root access..."

    # Remove root users that can connect from non-localhost
    local remote_roots
    remote_roots=$(execute_mysql_query "SELECT User, Host FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null)

    if [[ -z "$remote_roots" ]]; then
        log_info "No remote root accounts found (already secure)"
        return 0
    fi

    log_info "Found remote root accounts, removing..."

    if execute_mysql_query "DELETE FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" >/dev/null 2>&1; then
        log_success "Disabled remote root login"

        if execute_mysql_query "FLUSH PRIVILEGES;" >/dev/null 2>&1; then
            log_success "Flushed privileges"
            log_score "+15 Disabled remote root login for MySQL"
        fi
    else
        log_warn "Unable to disable remote root login (authentication may be required)"
        log_info "Consider running: sudo mysql -e \"DELETE FROM mysql.user WHERE User = 'root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); FLUSH PRIVILEGES;\""
    fi

    return 0
}

# Remove test database
remove_test_database() {
    log_section "Removing Test Database"

    if [[ "$MYSQL_REMOVE_TEST_DB" != "yes" ]]; then
        log_info "Skipping test database removal (disabled in config)"
        return 0
    fi

    log_info "Checking for test database..."

    # Check if test database exists
    local test_exists
    test_exists=$(execute_mysql_query "SHOW DATABASES LIKE 'test';" 2>/dev/null)

    if [[ -z "$test_exists" ]]; then
        log_info "Test database not found (already removed or never existed)"
        return 0
    fi

    log_info "Found test database, removing..."

    if execute_mysql_query "DROP DATABASE IF EXISTS test;" >/dev/null 2>&1; then
        log_success "Removed test database"
        log_score "+5 Removed MySQL test database"
    else
        log_warn "Unable to remove test database (authentication may be required)"
        log_info "Consider running: sudo mysql -e 'DROP DATABASE IF EXISTS test;'"
    fi

    return 0
}

# Install and configure password validation plugin
install_password_validator() {
    log_section "Installing Password Validation Plugin"

    if [[ "$MYSQL_INSTALL_PASSWORD_VALIDATOR" != "yes" ]]; then
        log_info "Skipping password validator installation (disabled in config)"
        return 0
    fi

    log_info "Attempting to install password validation component..."

    # Check MySQL version to determine correct component/plugin name
    local version_info
    version_info=$(execute_mysql_query "SELECT VERSION();" 2>/dev/null | tail -n 1)

    if [[ -z "$version_info" ]]; then
        log_warn "Unable to determine MySQL version, skipping password validator"
        return 0
    fi

    log_debug "MySQL version: $version_info"

    # Try installing the password validation component (MySQL 8.0+ / MariaDB 10.4+)
    if execute_mysql_query "INSTALL COMPONENT 'file://component_validate_password';" >/dev/null 2>&1; then
        log_success "Installed password validation component"
        log_score "+10 Installed MySQL password validation"

        # Configure password policy to STRONG (if supported)
        execute_mysql_query "SET GLOBAL validate_password.policy = 'STRONG';" >/dev/null 2>&1 && \
            log_info "Set password policy to STRONG"

        execute_mysql_query "SET GLOBAL validate_password.length = 12;" >/dev/null 2>&1 && \
            log_info "Set minimum password length to 12"

    # Fallback: Try plugin-based installation (older MySQL/MariaDB)
    elif execute_mysql_query "INSTALL PLUGIN validate_password SONAME 'validate_password.so';" >/dev/null 2>&1; then
        log_success "Installed password validation plugin (legacy method)"
        log_score "+10 Installed MySQL password validation"

        # Configure for legacy plugin
        execute_mysql_query "SET GLOBAL validate_password_policy = 'STRONG';" >/dev/null 2>&1 && \
            log_info "Set password policy to STRONG"

    # MariaDB alternative: simple_password_check or cracklib_password_check
    elif execute_mysql_query "INSTALL SONAME 'simple_password_check';" >/dev/null 2>&1; then
        log_success "Installed simple_password_check plugin (MariaDB)"
        log_score "+10 Installed MySQL password validation"

    else
        log_info "Password validation plugin/component already installed or not available for this version"
        log_info "You may need to manually install it or it may already be active"
    fi

    return 0
}

# Validate MySQL configuration
validate_mysql_config() {
    log_section "Validating MySQL Configuration"

    local service_name
    service_name="$(detect_mysql_service)"

    if [[ -z "$service_name" ]]; then
        log_warn "MySQL service not detected, skipping configuration validation"
        return 0
    fi

    # Check if mysqld binary is available for validation
    if ! command_exists mysqld; then
        log_warn "mysqld binary not found, skipping syntax validation"
        return 0
    fi

    log_info "Validating MySQL configuration syntax..."

    # Validate configuration (this checks syntax but doesn't verify all runtime settings)
    if mysqld --validate-config 2>/dev/null; then
        log_success "MySQL configuration syntax is valid"
        return 0
    else
        # Some MySQL versions don't support --validate-config
        # Try alternative: check if service can be started or is running
        if systemctl is-active "$service_name" >/dev/null 2>&1; then
            log_success "MySQL service is running (configuration assumed valid)"
            return 0
        else
            log_warn "Could not validate MySQL configuration (service not running)"
            log_info "Configuration changes will be applied on next MySQL restart"
        fi
    fi

    return 0
}

# Restart or reload MySQL service
restart_mysql_service() {
    log_section "Restarting MySQL Service"

    local service_name
    service_name="$(detect_mysql_service)"

    if [[ -z "$service_name" ]]; then
        log_warn "MySQL service not detected, cannot restart"
        return 0
    fi

    # Check if service is active before attempting restart
    if ! systemctl is-active "$service_name" >/dev/null 2>&1; then
        log_info "MySQL service is not currently running, skipping restart"
        log_info "Start MySQL manually with: sudo systemctl start $service_name"
        return 0
    fi

    log_info "Restarting MySQL service: $service_name"

    # Attempt graceful restart
    if systemctl restart "$service_name" 2>/dev/null; then
        log_success "MySQL service restarted successfully"

        # Wait a moment for service to fully start
        sleep 2

        # Verify service is running
        if systemctl is-active "$service_name" >/dev/null 2>&1; then
            log_success "MySQL service is running and healthy"
            return 0
        else
            log_error "MySQL service failed to start after restart"
            log_info "Check logs with: sudo journalctl -xeu $service_name"
            return 1
        fi
    else
        log_error "Failed to restart MySQL service"
        log_info "Check status with: sudo systemctl status $service_name"
        return 1
    fi
}

# Display current MySQL security settings
display_mysql_security_status() {
    log_section "MySQL Security Status"

    local service_name
    service_name="$(detect_mysql_service)"

    if [[ -n "$service_name" ]]; then
        log_info "Service: $service_name"

        if systemctl is-active "$service_name" >/dev/null 2>&1; then
            log_success "Status: Running"
        else
            log_warn "Status: Not Running"
        fi
    fi

    # Display configuration file locations
    local main_config
    main_config="$(detect_mysql_config)"
    if [[ -n "$main_config" ]]; then
        log_info "Main config: $main_config"
    fi

    if [[ -f "$MYSQL_CONFIG_SNIPPET" ]]; then
        log_success "Hardened config: $MYSQL_CONFIG_SNIPPET"
    fi

    # Display data directory
    local data_dir
    data_dir="$(detect_mysql_data_dir)"
    if [[ -n "$data_dir" ]]; then
        log_info "Data directory: $data_dir"
    fi

    # Try to display some security-relevant settings
    log_info "Current MySQL security settings:"

    local bind_addr
    bind_addr=$(execute_mysql_query "SELECT @@bind_address;" 2>/dev/null | tail -n 1)
    if [[ -n "$bind_addr" ]]; then
        log_info "  bind-address: $bind_addr"
    fi

    local local_infile
    local_infile=$(execute_mysql_query "SELECT @@local_infile;" 2>/dev/null | tail -n 1)
    if [[ -n "$local_infile" ]]; then
        if [[ "$local_infile" == "0" ]]; then
            log_success "  local_infile: OFF (secure)"
        else
            log_warn "  local_infile: ON (insecure)"
        fi
    fi

    local secure_transport
    secure_transport=$(execute_mysql_query "SELECT @@require_secure_transport;" 2>/dev/null | tail -n 1)
    if [[ -n "$secure_transport" ]]; then
        if [[ "$secure_transport" == "1" || "$secure_transport" == "ON" ]]; then
            log_success "  require_secure_transport: ON (secure)"
        else
            log_warn "  require_secure_transport: OFF"
        fi
    fi

    return 0
}

# Main entry point for MySQL hardening
run_mysql_hardening() {
    log_section "MySQL/MariaDB Security Hardening"

    # Pre-flight checks
    if ! mysql_installed; then
        log_info "MySQL/MariaDB client not found on this system, skipping"
        return 0
    fi

    if ! mysql_server_installed; then
        log_info "MySQL/MariaDB server not installed on this system, skipping"
        return 0
    fi

    local service_name
    service_name="$(detect_mysql_service)"

    if [[ -z "$service_name" ]]; then
        log_warn "MySQL/MariaDB service not detected, proceeding with limited hardening"
    else
        log_info "Detected MySQL/MariaDB service: $service_name"
    fi

    # Determine main configuration file (prefer existing primary file)
    local config_file
    config_file="$(detect_mysql_config)"
    if [[ -z "$config_file" ]]; then
        config_file="/etc/mysql/my.cnf"
    fi

    # Step 1: Apply hardening directly to main config
    if create_mysql_hardened_config "$config_file"; then
        log_score "+20 Hardened MySQL main configuration"
    else
        log_error "Failed to create hardened configuration"
        return 1
    fi

    # Step 2: Secure configuration file permissions
    if [[ "$MYSQL_SECURE_PERMISSIONS" == "yes" ]]; then
        secure_mysql_config_permissions
    fi

    # Step 3: Secure data directory permissions
    if [[ "$MYSQL_SECURE_PERMISSIONS" == "yes" ]]; then
        secure_mysql_data_directory
    fi

    # Step 4: Validate configuration
    validate_mysql_config

    # Step 5: Database-level hardening (requires MySQL to be running)
    if [[ -n "$service_name" ]] && systemctl is-active "$service_name" >/dev/null 2>&1; then
        log_info "MySQL is running, performing database-level hardening..."

        remove_anonymous_users
        disable_remote_root_login
        remove_test_database
        install_password_validator
    else
        log_warn "MySQL service is not running, skipping database-level hardening"
        log_info "Database-level hardening includes:"
        log_info "  - Removing anonymous users"
        log_info "  - Disabling remote root login"
        log_info "  - Removing test database"
        log_info "  - Installing password validation plugin"
        log_info "Start MySQL and re-run this module to apply these hardenings"
    fi

    # Step 6: Restart service to apply configuration changes
    # Only restart if service is running and we made config changes
    if [[ -n "$service_name" ]] && systemctl is-active "$service_name" >/dev/null 2>&1; then
        log_info "Restarting MySQL to apply configuration changes..."

        if restart_mysql_service; then
            log_success "MySQL service restarted with hardened configuration"
        else
            log_warn "MySQL service restart failed, changes will apply on next start"
            log_info "Manually restart with: sudo systemctl restart $service_name"
        fi
    fi

    # Step 7: Display final security status
    display_mysql_security_status

    log_success "MySQL/MariaDB hardening completed"
    log_info ""
    log_info "Next steps:"
    log_info "  1. If require_secure_transport is enabled, ensure SSL certificates are configured"
    log_info "  2. Review user accounts and privileges: SELECT User, Host FROM mysql.user;"
    log_info "  3. Consider setting up regular backups with mysqldump or MariaDB Backup"
    log_info "  4. Monitor MySQL logs: /var/log/mysql/"
    log_info "  5. Review and adjust max_connections based on your workload"

    return 0
}

# Export main function for cp-engine
export -f run_mysql_hardening
