#!/bin/bash
# os_updates.sh - Operating System Updates Module
# Manages operating system and kernel updates

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Operating System Updates
# Category: Operating System Updates
# Description: Ensures OS and kernel are up to date, installs and configures automatic updates

# Update package lists
update_package_lists() {
    log_section "Updating Package Lists"

    log_info "Running apt-get update..."
    if apt-get update >/dev/null 2>&1; then
        log_success "Package lists updated successfully"
        return 0
    else
        log_error "Failed to update package lists"
        return 1
    fi
}

# Install unattended-upgrades package
install_unattended_upgrades() {
    log_section "Installing Unattended Upgrades"

    # Check if already installed
    if dpkg -l | grep -q "^ii.*unattended-upgrades"; then
        log_success "unattended-upgrades is already installed"
        return 0
    fi

    log_info "Installing unattended-upgrades package..."
    if apt-get install -y unattended-upgrades >/dev/null 2>&1; then
        log_success "unattended-upgrades installed successfully"
        return 0
    else
        log_error "Failed to install unattended-upgrades"
        return 1
    fi
}

# Configure unattended-upgrades
configure_unattended_upgrades() {
    log_section "Configuring Unattended Upgrades"

    log_info "Configuring unattended-upgrades with dpkg-reconfigure..."
    if dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1; then
        log_success "unattended-upgrades configured successfully"
        return 0
    else
        log_error "Failed to configure unattended-upgrades"
        return 1
    fi
}

# Enable automatic update timers
enable_auto_update_timers() {
    log_section "Enabling Automatic Update Timers"

    # Check if systemd is available
    if ! command_exists systemctl; then
        log_warn "systemctl not found, skipping timer configuration"
        return 0
    fi

    # Enable apt-daily.timer
    log_info "Enabling apt-daily.timer..."
    if systemctl enable apt-daily.timer >/dev/null 2>&1; then
        log_success "apt-daily.timer enabled"
    else
        log_warn "Failed to enable apt-daily.timer"
    fi

    # Start apt-daily.timer
    log_info "Starting apt-daily.timer..."
    systemctl start apt-daily.timer >/dev/null 2>&1

    # Enable apt-daily-upgrade.timer
    log_info "Enabling apt-daily-upgrade.timer..."
    if systemctl enable apt-daily-upgrade.timer >/dev/null 2>&1; then
        log_success "apt-daily-upgrade.timer enabled"
    else
        log_warn "Failed to enable apt-daily-upgrade.timer"
    fi

    # Start apt-daily-upgrade.timer
    log_info "Starting apt-daily-upgrade.timer..."
    systemctl start apt-daily-upgrade.timer >/dev/null 2>&1

    # Verify timers are active
    log_info "Verifying timer status..."
    if systemctl is-active --quiet apt-daily.timer; then
        log_success "apt-daily.timer is active"
    else
        log_warn "apt-daily.timer is not active"
    fi

    if systemctl is-active --quiet apt-daily-upgrade.timer; then
        log_success "apt-daily-upgrade.timer is active"
    else
        log_warn "apt-daily-upgrade.timer is not active"
    fi

    return 0
}

# Perform full system upgrade
perform_full_upgrade() {
    log_section "Performing Full System Upgrade"

    log_info "Current kernel version: $(uname -r)"

    log_info "Running full system upgrade (this may take a while)..."
    log_info "This will upgrade all packages and install new dependencies as needed"

    # Use DEBIAN_FRONTEND to avoid interactive prompts
    export DEBIAN_FRONTEND=noninteractive

    if apt-get -y full-upgrade -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" >/dev/null 2>&1; then
        log_success "Full system upgrade completed successfully"
    else
        log_error "System upgrade encountered errors"
        return 1
    fi

    return 0
}

# Remove unnecessary packages
autoremove_packages() {
    log_section "Removing Unnecessary Packages"

    log_info "Running apt-get autoremove to clean up unused packages..."

    if apt-get -y autoremove --purge >/dev/null 2>&1; then
        log_success "Unnecessary packages removed successfully"
        return 0
    else
        log_error "Failed to remove unnecessary packages"
        return 1
    fi
}

# Check if system reboot is required
check_reboot_required() {
    log_section "Checking Reboot Status"

    if [[ -f /var/run/reboot-required ]]; then
        log_warn "=========================================="
        log_warn "SYSTEM REBOOT REQUIRED/ADVISED"
        log_warn "=========================================="
        log_warn "A system reboot is required to complete updates"

        if [[ -f /var/run/reboot-required.pkgs ]]; then
            log_info "Packages requiring reboot:"
            cat /var/run/reboot-required.pkgs | while read pkg; do
                log_info "  - $pkg"
            done
        fi

        log_warn "Please reboot the system at your earliest convenience"
        log_warn "Run: sudo reboot"
    else
        log_success "No reboot required at this time"
    fi

    return 0
}

# Configure APT periodic settings for Mint to allow automatic updates
enable_automatic_apt_updates() {
    log_section "Configuring Automatic APT Updates"

    local auto_conf="/etc/apt/apt.conf.d/20auto-upgrades"
    backup_file "$auto_conf" 2>/dev/null || true

    cat >"$auto_conf" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Autoremove "1";
APT::Periodic::AutoremoveInterval "7";
EOF

    log_success "Automatic APT update policies enabled"
}

# Ensure unattended-upgrades will clean up old kernels and dependencies
configure_unattended_cleanup_policy() {
    log_section "Configuring Unattended-Upgrades Cleanup"

    local unattended_conf="/etc/apt/apt.conf.d/50unattended-upgrades"

    if [[ -f "$unattended_conf" ]]; then
        backup_file "$unattended_conf"
    fi

    touch "$unattended_conf"

    if ! grep -q "Remove-Unused-Kernel-Packages" "$unattended_conf"; then
        echo "Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";" >>"$unattended_conf"
    fi

    if ! grep -q "Remove-Unused-Dependencies" "$unattended_conf"; then
        echo "Unattended-Upgrade::Remove-Unused-Dependencies \"true\";" >>"$unattended_conf"
    fi

    log_success "Unattended-upgrades cleanup policies configured"
}

# Create a timer to run flatpak updates automatically
enable_flatpak_auto_updates() {
    log_section "Configuring Automatic Flatpak Updates"

    if ! command_exists flatpak; then
        log_warn "Flatpak not installed; skipping automatic Flatpak updates"
        return 0
    fi

    if ! command_exists systemctl; then
        log_warn "systemd not available; cannot configure Flatpak update timer"
        return 0
    fi

    local service="/etc/systemd/system/cp-flatpak-update.service"
    local timer="/etc/systemd/system/cp-flatpak-update.timer"

    cat >"$service" <<'EOF'
[Unit]
Description=CyberPatriot - Automatic Flatpak Updates

[Service]
Type=oneshot
ExecStart=/usr/bin/flatpak update -y --noninteractive
EOF

    cat >"$timer" <<'EOF'
[Unit]
Description=Run automatic Flatpak updates daily

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable cp-flatpak-update.timer >/dev/null 2>&1 && systemctl start cp-flatpak-update.timer >/dev/null 2>&1

    log_success "Flatpak auto-update timer enabled"
}

# Refresh Mint update metadata shortly after login and regularly afterwards
configure_mint_update_manager_refresh() {
    log_section "Configuring Mint Update Manager Refresh"

    if ! command_exists systemctl; then
        log_warn "systemd not available; cannot configure refresh schedule"
        return 0
    fi

    local service="/etc/systemd/system/cp-mintupdate-refresh.service"
    local timer="/etc/systemd/system/cp-mintupdate-refresh.timer"

    cat >"$service" <<'EOF'
[Unit]
Description=CyberPatriot - Refresh Mint updates and Flatpak catalog
ConditionACPower=true

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'if command -v mintupdate-cli >/dev/null 2>&1; then mintupdate-cli refresh; fi; if command -v flatpak >/dev/null 2>&1; then flatpak update --app --runtime --assumeyes --noninteractive --no-related; fi'
EOF

    cat >"$timer" <<'EOF'
[Unit]
Description=Schedule Mint update refreshes (10 minutes after login, then every 2 hours)

[Timer]
OnBootSec=10min
OnUnitActiveSec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable cp-mintupdate-refresh.timer >/dev/null 2>&1 && systemctl start cp-mintupdate-refresh.timer >/dev/null 2>&1

    log_success "Mint Update Manager refresh schedule enabled"
}

# Clear package holds that would block updates
clear_mint_blocklist() {
    log_section "Clearing Blocked Packages"

    local held_packages
    held_packages=$(apt-mark showhold)

    if [[ -z "$held_packages" ]]; then
        log_info "No held packages found"
        return 0
    fi

    while read -r pkg; do
        if [[ -n "$pkg" ]]; then
            log_info "Removing hold on $pkg"
            apt-mark unhold "$pkg" >/dev/null 2>&1
        fi
    done <<<"$held_packages"

    log_success "Blocked packages cleared"
}

# Enable Mint-specific update features
configure_mint_specific_updates() {
    local os_id=$(detect_os)

    if [[ "$os_id" == "ubuntu" ]]; then
        log_info "Ubuntu detected; skipping Mint-specific update configuration"
        return 0
    fi

    if [[ "$os_id" != "linuxmint" ]]; then
        log_warn "Mint-specific update tasks skipped (unsupported distribution: $os_id)"
        return 0
    fi

    enable_automatic_apt_updates
    configure_unattended_cleanup_policy
    enable_flatpak_auto_updates
    configure_mint_update_manager_refresh
    clear_mint_blocklist

    log_success "Mint-specific update settings applied"
}

# Display update summary
display_update_summary() {
    log_section "Update Summary"

    log_info "Current kernel version: $(uname -r)"
    log_info "System information:"
    log_info "  OS: $(detect_os)"
    log_info "  Version: $(detect_os_version)"

    # Check for available updates
    log_info "Checking for remaining updates..."
    local updates=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst")

    if [[ $updates -eq 0 ]]; then
        log_success "System is fully up to date"
    else
        log_info "There are $updates package(s) that could be updated"
    fi

    return 0
}

run_os_updates() {
    log_info "Starting OS Updates module..."

    log_section "Choose Update Mode"
    log_info "1) Fix APT and configure automatic updates"
    log_info "2) Full run (includes full upgrade) [default]"
    read -r -p "Select update mode [1/2]: " update_choice

    # Default to option 2 (full run) if no choice provided
    if [[ -z "$update_choice" ]]; then
        update_choice=2
    fi

    case "$update_choice" in
        1)
            log_info "Running APT repair and auto-update configuration only"
            ;;
        2)
            log_info "Running full OS update flow"
            ;;
        *)
            log_warn "Unrecognized choice '$update_choice', defaulting to full OS update"
            update_choice=2
            ;;
    esac

    # Update package lists
    if ! update_package_lists; then
        log_error "Cannot proceed without updated package lists"
        return 1
    fi

    # Install unattended-upgrades
    install_unattended_upgrades

    # Configure automatic updates
    configure_unattended_upgrades

    # Enable systemd timers for automatic updates
    enable_auto_update_timers

    if [[ "$update_choice" == "1" ]]; then
        log_warn "Skipping full system upgrade per user selection"
    else
        # Perform full system upgrade
        perform_full_upgrade

        # Clean up unnecessary packages
        autoremove_packages

        # Check if reboot is needed (after kernel updates)
        check_reboot_required
    fi

    # Display summary
    display_update_summary

    # Apply Mint Update Manager automation if applicable
    configure_mint_specific_updates

    log_success "OS Updates module completed"
    return 0
}

export -f run_os_updates
