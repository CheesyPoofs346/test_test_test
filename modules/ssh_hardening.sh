#!/bin/bash
# ssh_hardening.sh - SSH Hardening Module
# Implements comprehensive SSH hardening for CyberPatriot competitions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: SSH Hardening
# Category: Application Security
# Description: Hardens SSH configuration, permissions, and firewall rules

# ====== EDITABLE DEFAULTS ======
readonly SSH_PORT="${SSH_PORT:-222}"               # Custom SSH port
readonly SSH_KEEP_22="${SSH_KEEP_22:-yes}"         # Keep port 22 allowed in UFW
readonly SSH_DO_UFW="${SSH_DO_UFW:-yes}"           # Configure UFW firewall
readonly SSH_DO_MODULI="${SSH_DO_MODULI:-yes}"     # Prune weak moduli
readonly SSH_BANNER_TEXT="${SSH_BANNER_TEXT:-Authorized use only. Activity may be monitored and reported.}"
readonly SSH_TARGET_USER="${SUDO_USER:-${USER:-root}}"  # User for SSH key setup
readonly SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"      # Optional public key to install
readonly SSH_ALLOW_USERS="${SSH_ALLOW_USERS:-}"    # Optional: space-separated list
readonly SSH_CONFIG_NAME="${SSH_CONFIG_NAME:-99-cyberpatriot.conf}"

# SSH configuration paths
readonly SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
readonly SSHD_CONFIG_FILE="${SSHD_CONFIG_DIR}/${SSH_CONFIG_NAME}"
readonly SSH_BANNER_FILE="/etc/issue.net"
readonly SSH_MODULI="/etc/ssh/moduli"
readonly SSH_DIR="/etc/ssh"

# Check if SSH service exists
ssh_service_exists() {
    if command_exists systemctl; then
        systemctl list-unit-files | grep -qE '^(ssh|sshd)\.service' && return 0
    fi
    if command_exists service; then
        service --status-all 2>&1 | grep -qE '(ssh|sshd)' && return 0
    fi
    return 1
}

# Reload SSH service
ssh_service_reload() {
    log_info "Reloading SSH service..."

    if command_exists systemctl; then
        if systemctl list-unit-files | grep -q '^ssh\.service'; then
            systemctl reload ssh >/dev/null 2>&1
            log_success "SSH service reloaded (ssh.service)"
            return 0
        elif systemctl list-unit-files | grep -q '^sshd\.service'; then
            systemctl reload sshd >/dev/null 2>&1
            log_success "SSH service reloaded (sshd.service)"
            return 0
        fi
    fi

    if command_exists service; then
        service ssh reload >/dev/null 2>&1 || service sshd reload >/dev/null 2>&1
        log_success "SSH service reloaded"
        return 0
    fi

    log_warn "Unable to reload SSH service"
    return 1
}

# Create hardened SSH configuration
create_hardened_config() {
    log_section "Creating Hardened SSH Configuration"

    # Create config directory if it doesn't exist
    if [[ ! -d "$SSHD_CONFIG_DIR" ]]; then
        log_info "Creating $SSHD_CONFIG_DIR directory"
        mkdir -p "$SSHD_CONFIG_DIR"
        chmod 0755 "$SSHD_CONFIG_DIR"
    fi

    # Backup existing config if present
    if [[ -f "$SSHD_CONFIG_FILE" ]]; then
        backup_file "$SSHD_CONFIG_FILE"
    fi

    # Build AllowUsers line
    local allow_users_line="# AllowUsers not set"
    if [[ -n "$SSH_ALLOW_USERS" ]]; then
        allow_users_line="AllowUsers ${SSH_ALLOW_USERS}"
        log_info "Restricting SSH access to users: $SSH_ALLOW_USERS"
    fi

    # Create hardened configuration
    log_info "Writing hardened SSH configuration to $SSHD_CONFIG_FILE"
    cat > "$SSHD_CONFIG_FILE" <<EOF
# === CyberPatriot SSH Hardening (auto) ===
# Protocol 1 is removed in modern OpenSSH; Protocol 2 is implicit.
Port ${SSH_PORT}

# Logging and DNS
SyslogFacility AUTHPRIV
LogLevel VERBOSE
StrictModes yes
UseDNS no
VersionAddendum none

# Authentication settings
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitUserEnvironment no
UsePAM yes

# Forwarding and tunneling (all disabled)
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no

# Timing and limits
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# Host-based authentication (disabled)
IgnoreRhosts yes
HostbasedAuthentication no

# Keys and banner
AuthorizedKeysFile .ssh/authorized_keys
Banner ${SSH_BANNER_FILE}
PrintMotd no
PrintLastLog yes

# Algorithms (compatible with Ubuntu 24/Mint 21 OpenSSH)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Subsystem
Subsystem sftp internal-sftp

${allow_users_line}
EOF

    chmod 0644 "$SSHD_CONFIG_FILE"
    log_success "Hardened SSH configuration created"
    return 0
}

# Create SSH banner
create_ssh_banner() {
    log_section "Creating SSH Banner"

    if [[ -f "$SSH_BANNER_FILE" ]]; then
        backup_file "$SSH_BANNER_FILE"
    fi

    log_info "Writing banner to $SSH_BANNER_FILE"
    printf '%s\n' "$SSH_BANNER_TEXT" > "$SSH_BANNER_FILE"
    chmod 0644 "$SSH_BANNER_FILE"

    log_success "SSH banner created"
    return 0
}

# Harden SSH directory permissions
harden_ssh_permissions() {
    log_section "Hardening SSH Permissions"

    # System SSH directory
    log_info "Setting ownership and permissions on $SSH_DIR"
    chown -R root:root "$SSH_DIR" 2>/dev/null || true
    chmod 0755 "$SSH_DIR" 2>/dev/null || true

    # SSH configuration files
    log_info "Setting permissions on SSH configuration files"
    shopt -s nullglob
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        if [[ -e "$f" ]]; then
            chmod 0644 "$f" 2>/dev/null || true
            log_debug "Set 0644 on $f"
        fi
    done

    # SSH host keys (private)
    log_info "Setting permissions on SSH host keys"
    for k in /etc/ssh/ssh_host_*_key; do
        if [[ -e "$k" ]]; then
            chmod 0600 "$k" 2>/dev/null || true
            log_debug "Set 0600 on $k"
        fi
        if [[ -e "${k}.pub" ]]; then
            chmod 0644 "${k}.pub" 2>/dev/null || true
            log_debug "Set 0644 on ${k}.pub"
        fi
    done
    shopt -u nullglob

    log_success "SSH system permissions hardened"
    return 0
}

# Setup user SSH directory and optional key
setup_user_ssh() {
    log_section "Setting Up User SSH Configuration"

    # Check if target user exists
    if ! getent passwd "$SSH_TARGET_USER" >/dev/null 2>&1; then
        log_warn "Target user '$SSH_TARGET_USER' does not exist, skipping user SSH setup"
        return 0
    fi

    local home_dir
    home_dir="$(getent passwd "$SSH_TARGET_USER" | cut -d: -f6 || true)"

    if [[ -z "$home_dir" || ! -d "$home_dir" ]]; then
        log_warn "Home directory not found for user '$SSH_TARGET_USER', skipping"
        return 0
    fi

    log_info "Setting up SSH directory for user: $SSH_TARGET_USER"

    # Create .ssh directory with proper permissions
    local ssh_user_dir="${home_dir}/.ssh"
    install -d -m 700 -o "$SSH_TARGET_USER" -g "$SSH_TARGET_USER" "$ssh_user_dir"
    log_debug "Created/verified $ssh_user_dir with mode 700"

    # Ensure authorized_keys exists and has proper permissions
    local auth_keys="${ssh_user_dir}/authorized_keys"
    if [[ ! -f "$auth_keys" ]]; then
        touch "$auth_keys"
        log_debug "Created $auth_keys"
    fi
    chown "$SSH_TARGET_USER:$SSH_TARGET_USER" "$auth_keys"
    chmod 600 "$auth_keys"
    log_debug "Set permissions 600 on $auth_keys"

    # Install public key if provided
    if [[ -n "$SSH_PUBLIC_KEY" ]]; then
        if ! grep -qF "$SSH_PUBLIC_KEY" "$auth_keys" 2>/dev/null; then
            log_info "Installing public key for $SSH_TARGET_USER"
            echo "$SSH_PUBLIC_KEY" >> "$auth_keys"
            log_success "Public key installed"
        else
            log_info "Public key already present in authorized_keys"
        fi
    fi

    log_success "User SSH configuration completed for $SSH_TARGET_USER"
    return 0
}

# Harden SSH moduli (remove weak DH groups)
harden_moduli() {
    log_section "Hardening SSH Moduli"

    if [[ "$SSH_DO_MODULI" != "yes" ]]; then
        log_info "Moduli hardening disabled, skipping"
        return 0
    fi

    if [[ ! -f "$SSH_MODULI" ]]; then
        log_info "Moduli file not found at $SSH_MODULI, skipping"
        return 0
    fi

    backup_file "$SSH_MODULI"

    log_info "Removing weak Diffie-Hellman groups (keeping >= 3071-bit)"
    local temp_moduli="${SSH_MODULI}.safe"
    awk '$5 >= 3071' "$SSH_MODULI" > "$temp_moduli" 2>/dev/null || true

    if [[ -s "$temp_moduli" ]]; then
        mv "$temp_moduli" "$SSH_MODULI"
        chmod 0644 "$SSH_MODULI"
        log_success "SSH moduli hardened (weak groups removed)"
    else
        rm -f "$temp_moduli"
        log_warn "No strong moduli found, keeping original file"
    fi

    return 0
}

# Configure UFW firewall for SSH
configure_ufw_ssh() {
    log_section "Configuring UFW Firewall for SSH"

    if [[ "$SSH_DO_UFW" != "yes" ]]; then
        log_info "UFW configuration disabled, skipping"
        return 0
    fi

    if ! command_exists ufw; then
        log_warn "UFW not found, skipping firewall configuration"
        return 0
    fi

    # Allow custom SSH port
    log_info "Allowing SSH port ${SSH_PORT}/tcp in UFW"
    ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    log_success "Port ${SSH_PORT}/tcp allowed"

    # Handle port 22
    if [[ "$SSH_KEEP_22" == "no" ]]; then
        log_info "Removing allow rule for port 22/tcp"
        ufw delete allow 22/tcp 2>/dev/null || true
        ufw delete allow ssh 2>/dev/null || true
        log_success "Port 22/tcp rule removed"
    else
        log_info "Keeping port 22 allowed (SSH_KEEP_22=yes)"
    fi

    # Ensure UFW is enabled
    log_info "Enabling UFW firewall"
    echo "y" | ufw enable >/dev/null 2>&1 || true

    # Show status
    local status_output
    status_output=$(ufw status 2>/dev/null || true)
    if echo "$status_output" | grep -q "${SSH_PORT}/tcp"; then
        log_success "UFW configured: port ${SSH_PORT}/tcp allowed"
    fi

    return 0
}

# Validate SSH configuration
validate_ssh_config() {
    log_section "Validating SSH Configuration"

    # Find sshd binary
    local sshd_bin
    if command_exists sshd; then
        sshd_bin="sshd"
    elif [[ -x /usr/sbin/sshd ]]; then
        sshd_bin="/usr/sbin/sshd"
    else
        log_error "sshd binary not found"
        return 1
    fi

    # Test configuration
    log_info "Running configuration test: $sshd_bin -t"
    if $sshd_bin -t 2>&1; then
        log_success "SSH configuration is valid"
    else
        log_error "SSH configuration has errors"
        return 1
    fi

    # Show effective configuration (key settings)
    log_info "Effective SSH configuration (key settings):"
    local effective_config
    effective_config=$($sshd_bin -T 2>/dev/null | \
        grep -iE '(port|maxauthtries|maxsessions|permitrootlogin|pubkeyauthentication|passwordauthentication|permitemptypasswords|permituserenvironment|x11forwarding|allowtcpforwarding|loglevel|ciphers|macs|kexalgorithms|banner|usepam|challengeresponseauthentication|kbdinteractiveauthentication)' || true)

    while IFS= read -r line; do
        [[ -n "$line" ]] && log_debug "  $line"
    done <<< "$effective_config"

    return 0
}

# Display summary
display_summary() {
    log_section "SSH Hardening Summary"

    log_success "SSH hardened successfully"
    log_info "Configuration details:"
    log_info "  - Port: ${SSH_PORT}"
    log_info "  - PermitRootLogin: no"
    log_info "  - PasswordAuthentication: no (public key only)"
    log_info "  - PermitEmptyPasswords: no"
    log_info "  - PermitUserEnvironment: no"
    log_info "  - X11Forwarding: no"
    log_info "  - AllowTcpForwarding: no"
    log_info "  - MaxAuthTries: 3"
    log_info "  - LogLevel: VERBOSE"

    if [[ -n "$SSH_ALLOW_USERS" ]]; then
        log_info "  - AllowUsers: $SSH_ALLOW_USERS"
    fi

    if [[ -n "$SSH_PUBLIC_KEY" ]]; then
        log_info "  - Public key installed for: $SSH_TARGET_USER"
    fi

    return 0
}

# Main module function
run_ssh_hardening() {
    log_info "Starting SSH Hardening module..."

    # Check if SSH service exists
    if ! ssh_service_exists; then
        log_warn "SSH service not found on this system, skipping module"
        return 0
    fi

    # Execute hardening steps
    create_hardened_config
    create_ssh_banner
    harden_ssh_permissions
    setup_user_ssh
    harden_moduli
    configure_ufw_ssh

    # Validate and reload
    if ! validate_ssh_config; then
        log_error "SSH configuration validation failed, not reloading service"
        return 1
    fi

    ssh_service_reload
    display_summary

    log_success "SSH Hardening module completed"
    return 0
}

export -f run_ssh_hardening
