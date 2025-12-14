#!/bin/bash
# defensive_countermeasures.sh - Defensive Countermeasures Module
# Implements defensive security measures and monitoring

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Defensive Countermeasures
# Category: Defensive Countermeasures
# Description: Sets up defensive security tools and monitoring including UFW firewall

readonly UFW_CONF="/etc/ufw/ufw.conf"
readonly UFW_DEFAULT="/etc/default/ufw"
readonly UFW_SYSCTL="/etc/ufw/sysctl.conf"

# Ensure UFW is installed
ensure_ufw_installed() {
    log_section "Ensuring UFW is Installed"

    if command_exists ufw; then
        log_success "UFW is already installed"
        return 0
    fi

    log_info "UFW not found, installing..."
    if apt-get install -y ufw >/dev/null 2>&1; then
        log_success "UFW installed successfully"
        return 0
    else
        log_error "Failed to install UFW"
        return 1
    fi
}

# Configure UFW defaults
configure_ufw_defaults() {
    log_section "Configuring UFW Default Policies"

    # Set default policies: deny incoming, allow outgoing, deny routed
    log_info "Setting default policy: deny incoming"
    ufw default deny incoming >/dev/null 2>&1

    log_info "Setting default policy: allow outgoing"
    ufw default allow outgoing >/dev/null 2>&1

    log_info "Setting default policy: deny routed"
    ufw default deny routed >/dev/null 2>&1

    log_success "UFW default policies configured"
    return 0
}

# Configure loopback rules (CIS control)
configure_loopback() {
    log_section "Configuring Loopback Rules"

    # Allow all traffic on loopback interface
    log_info "Allowing traffic on loopback interface (lo)"
    ufw allow in on lo >/dev/null 2>&1
    ufw allow out on lo >/dev/null 2>&1

    # Deny all traffic from loopback network interface (IPv4)
    log_info "Denying traffic from 127.0.0.0/8 not on loopback"
    ufw deny in from 127.0.0.0/8 >/dev/null 2>&1

    # Deny all traffic from loopback network interface (IPv6)
    log_info "Denying traffic from ::1 not on loopback"
    ufw deny in from ::1 >/dev/null 2>&1

    log_success "Loopback rules configured"
    return 0
}

# Configure SSH rate limiting
configure_ssh_rate_limit() {
    log_section "Configuring SSH Rate Limiting"

    # First, remove any existing SSH rules to avoid conflicts
    ufw --force delete allow 22/tcp >/dev/null 2>&1
    ufw --force delete allow ssh >/dev/null 2>&1

    # Rate limit SSH connections to prevent brute-force attacks
    log_info "Enabling SSH rate limiting on port 22/tcp"
    ufw limit 22/tcp >/dev/null 2>&1

    log_success "SSH rate limiting configured"
    return 0
}

# Enable UFW logging
enable_ufw_logging() {
    log_section "Enabling UFW Logging"

    # Set logging to high level for better visibility
    log_info "Setting UFW logging level to high"
    ufw logging high >/dev/null 2>&1

    log_success "UFW logging enabled at high level"
    return 0
}

# Ensure IPv6 is properly configured in UFW
configure_ipv6_parity() {
    log_section "Configuring IPv6 Parity"

    # Check if IPv6 is enabled on the system
    local ipv6_enabled=0
    if [[ -f /proc/net/if_inet6 ]] && [[ -s /proc/net/if_inet6 ]]; then
        ipv6_enabled=1
        log_info "IPv6 is enabled on this system"
    else
        log_info "IPv6 is not enabled on this system"
    fi

    # Ensure UFW is configured to handle IPv6
    if [[ -f "$UFW_DEFAULT" ]]; then
        if grep -q "^IPV6=yes" "$UFW_DEFAULT"; then
            log_success "UFW IPv6 support is enabled"
        else
            log_info "Enabling UFW IPv6 support"
            sed -i 's/^IPV6=.*/IPV6=yes/' "$UFW_DEFAULT" 2>/dev/null || \
                echo "IPV6=yes" >> "$UFW_DEFAULT"
            log_success "UFW IPv6 support enabled"
        fi
    fi

    return 0
}

# Deny unnecessary and unused ports
deny_unnecessary_ports() {
    log_section "Denying Unnecessary Ports"

    # Ports that are commonly unused on hardened systems
    local unnecessary_ports=(
        "21/tcp"   # FTP
        "23/tcp"   # Telnet
        "25/tcp"   # SMTP (server)
        "80/tcp"   # HTTP
        "110/tcp"  # POP3
        "143/tcp"  # IMAP
        "445/tcp"  # SMB
        "3389/tcp" # RDP
        "1900/udp" # SSDP
    )

    # Helper: check if a port is currently listening to avoid blocking active services
    is_port_listening() {
        local port_proto="$1"
        local port="${port_proto%/*}"
        local proto="${port_proto#*/}"

        if command_exists ss; then
            ss -lntu | awk -v p="$port" -v proto="$proto" '$1 == proto && $5 ~ (":" p "$") {found=1} END {exit !found}'
        elif command_exists netstat; then
            netstat -lntu | awk -v p="$port" -v proto="$proto" '$1 ~ proto && $4 ~ (":" p "$") {found=1} END {exit !found}'
        else
            log_warn "Cannot detect listening services (ss/netstat unavailable); skipping port safety checks"
            return 0
        fi
    }

    for port_proto in "${unnecessary_ports[@]}"; do
        if is_port_listening "$port_proto"; then
            log_info "Port $port_proto appears to be in use; skipping deny rule"
            continue
        fi

        # Only add deny rule if not already present
        if ufw status | grep -q "DENY[[:space:]]\+$port_proto"; then
            log_info "Deny rule for $port_proto already exists"
        else
            log_info "Denying unused port $port_proto"
            ufw deny "$port_proto" >/dev/null 2>&1
        fi
    done

    log_success "Unnecessary ports reviewed and denied where safe"
    return 0
}

# Enable and start UFW
enable_ufw() {
    log_section "Enabling UFW Firewall"

    # Enable UFW (will auto-start on boot)
    log_info "Enabling UFW and setting to start at boot"
    echo "y" | ufw enable >/dev/null 2>&1

    # Ensure UFW service is enabled at boot
    if command_exists systemctl; then
        systemctl enable ufw >/dev/null 2>&1
        log_success "UFW enabled and set to start at boot"
    else
        log_success "UFW enabled"
    fi

    return 0
}

# Verify UFW configuration
verify_ufw_status() {
    log_section "Verifying UFW Configuration"

    # Get verbose status
    log_info "Current UFW status:"
    local status_output=$(ufw status verbose 2>/dev/null)

    if echo "$status_output" | grep -q "Status: active"; then
        log_success "UFW is active"
    else
        log_warn "UFW may not be active"
    fi

    # Check default policies
    if echo "$status_output" | grep -q "deny (incoming)"; then
        log_success "Default incoming: deny"
    else
        log_warn "Default incoming policy may not be set to deny"
    fi

    if echo "$status_output" | grep -q "allow (outgoing)"; then
        log_success "Default outgoing: allow"
    else
        log_warn "Default outgoing policy may not be set to allow"
    fi

    if echo "$status_output" | grep -q "deny (routed)" || echo "$status_output" | grep -q "disabled (routed)"; then
        log_success "Default routed: deny/disabled"
    else
        log_warn "Default routed policy may not be set to deny"
    fi

    # Check logging
    if echo "$status_output" | grep -qi "logging.*high"; then
        log_success "Logging: high"
    elif echo "$status_output" | grep -qi "logging.*on"; then
        log_info "Logging is enabled"
    else
        log_warn "Logging may not be enabled"
    fi

    # Display rules
    log_info "Active UFW rules:"
    ufw status numbered 2>/dev/null | grep -v "^Status:" | while read -r line; do
        [[ -n "$line" ]] && log_info "  $line"
    done

    return 0
}

run_defensive_countermeasures() {
    log_info "Starting Defensive Countermeasures module..."

    # Prevent errexit from terminating the interactive engine if a single UFW command fails
    local had_errexit=0
    if [[ $- == *e* ]]; then
        had_errexit=1
        set +e
    fi

    local status=0

    # Ensure UFW is installed
    if ! ensure_ufw_installed; then
        log_error "Cannot proceed without UFW installed"
        status=1
    else
        # Configure UFW step by step
        configure_ufw_defaults
        configure_loopback
        enable_ufw_logging
        configure_ipv6_parity
        configure_ssh_rate_limit
        deny_unnecessary_ports
        enable_ufw
        verify_ufw_status
    fi

    if (( had_errexit )); then
        set -e
    fi

    if [[ $status -eq 0 ]]; then
        log_success "Defensive Countermeasures module completed"
    fi

    return $status
}

export -f run_defensive_countermeasures
