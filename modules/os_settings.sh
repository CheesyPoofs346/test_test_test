#!/bin/bash
# os_settings.sh - Operating System Settings Module
# Configures miscellaneous OS security settings

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Uncategorized Operating System Settings
# Category: Uncategorized Operating System Settings
# Description: Configures various OS security settings that don't fit other categories

readonly BACKUP_DIR="/var/backups/cyberpatriot"

# Fix GRUB configuration file permissions
fix_grub_permissions() {
    log_section "Hardening GRUB Configuration Permissions"

    local grub_files=(
        "/boot/grub/grub.cfg"
        "/boot/grub2/grub.cfg"
        "/boot/efi/EFI/ubuntu/grub.cfg"
        "/boot/efi/EFI/linuxmint/grub.cfg"
        "/boot/efi/EFI/BOOT/grub.cfg"
    )

    local fixed_count=0

    for grub_file in "${grub_files[@]}"; do
        if [[ -f "$grub_file" ]]; then
            log_info "Securing $grub_file..."

            # Backup first
            backup_file "$grub_file"

            # Set ownership to root:root
            chown root:root "$grub_file" 2>/dev/null

            # Set permissions to 600 (owner read/write only)
            chmod 600 "$grub_file" 2>/dev/null

            if [[ $? -eq 0 ]]; then
                log_success "✓ Secured $grub_file (600, root:root)"
                fixed_count=$((fixed_count + 1))
            else
                log_warn "Failed to secure $grub_file"
            fi
        fi
    done

    if [[ $fixed_count -gt 0 ]]; then
        log_success "Secured $fixed_count GRUB configuration file(s)"
    else
        log_info "No GRUB configuration files found to secure"
    fi

    return 0
}

# Setup GRUB password protection
setup_grub_password() {
    log_section "Configuring GRUB Password Protection"

    # Check if GRUB password is already configured
    if [[ -f /etc/grub.d/01_password ]]; then
        log_info "GRUB password configuration already exists at /etc/grub.d/01_password"
        log_info "To reconfigure, delete /etc/grub.d/01_password and run this module again"
        return 0
    fi

    log_info "GRUB password protection helps prevent unauthorized boot modifications"
    log_warn "Skipping automatic GRUB password setup (requires interactive password entry)"
    log_info "To manually enable GRUB password protection:"
    echo ""
    echo "  1. Generate password hash:"
    echo "     sudo grub-mkpasswd-pbkdf2"
    echo ""
    echo "  2. Create /etc/grub.d/01_password with:"
    echo "     set superusers=\"admin\""
    echo "     password_pbkdf2 admin <YOUR_HASH_HERE>"
    echo ""
    echo "  3. Set permissions:"
    echo "     sudo chmod 600 /etc/grub.d/01_password"
    echo ""
    echo "  4. Update GRUB:"
    echo "     sudo update-grub"
    echo ""

    return 0
}

# Remove restricted bash binaries if present
remove_rbash() {
    log_section "Removing Restricted Bash Binaries"

    local targets=(
        "/usr/bin/rbash"
        "/usr/share/doc/bash/RBASH"
    )

    local removed=0

    for target in "${targets[@]}"; do
        if [[ -e "$target" ]]; then
            log_info "Removing $target..."
            rm -rf "$target" 2>/dev/null && removed=$((removed + 1))
        fi
    done

    if [[ $removed -gt 0 ]]; then
        log_success "Removed $removed restricted bash artifact(s)"
    else
        log_info "No restricted bash artifacts found"
    fi

    return 0
}

# Fix critical system file permissions
fix_system_file_permissions() {
    log_section "Fixing Critical System File Permissions"

    local fixed_count=0
    local total_checks=0

    # /etc/passwd - world readable, root owned
    if [[ -f /etc/passwd ]]; then
        total_checks=$((total_checks + 1))
        log_info "Checking /etc/passwd..."
        chown root:root /etc/passwd 2>/dev/null
        chmod 644 /etc/passwd 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "✓ /etc/passwd (644, root:root)"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    # /etc/group - world readable, root owned
    if [[ -f /etc/group ]]; then
        total_checks=$((total_checks + 1))
        log_info "Checking /etc/group..."
        chown root:root /etc/group 2>/dev/null
        chmod 644 /etc/group 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "✓ /etc/group (644, root:root)"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    # /etc/shadow - shadow group readable only
    if [[ -f /etc/shadow ]]; then
        total_checks=$((total_checks + 1))
        log_info "Checking /etc/shadow..."

        # Ensure shadow group exists
        if ! getent group shadow >/dev/null 2>&1; then
            groupadd shadow 2>/dev/null
        fi

        chown root:shadow /etc/shadow 2>/dev/null
        chmod 640 /etc/shadow 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "✓ /etc/shadow (640, root:shadow)"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    # /etc/gshadow - shadow group readable only
    if [[ -f /etc/gshadow ]]; then
        total_checks=$((total_checks + 1))
        log_info "Checking /etc/gshadow..."

        # Ensure shadow group exists
        if ! getent group shadow >/dev/null 2>&1; then
            groupadd shadow 2>/dev/null
        fi

        chown root:shadow /etc/gshadow 2>/dev/null
        chmod 640 /etc/gshadow 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "✓ /etc/gshadow (640, root:shadow)"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    # /etc/sudoers - root read only
    if [[ -f /etc/sudoers ]]; then
        total_checks=$((total_checks + 1))
        log_info "Checking /etc/sudoers..."
        chown root:root /etc/sudoers 2>/dev/null
        chmod 440 /etc/sudoers 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "✓ /etc/sudoers (440, root:root)"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    # /etc/sudoers.d/* - root read only
    if [[ -d /etc/sudoers.d ]]; then
        log_info "Checking /etc/sudoers.d/ files..."
        local sudoers_d_count=0
        while IFS= read -r -d '' file; do
            total_checks=$((total_checks + 1))
            chown root:root "$file" 2>/dev/null
            chmod 440 "$file" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                fixed_count=$((fixed_count + 1))
                sudoers_d_count=$((sudoers_d_count + 1))
            fi
        done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)

        if [[ $sudoers_d_count -gt 0 ]]; then
            log_success "✓ Fixed $sudoers_d_count file(s) in /etc/sudoers.d/ (440, root:root)"
        fi
    fi

    # /etc/crontab - root read/write only
    if [[ -f /etc/crontab ]]; then
        total_checks=$((total_checks + 1))
        log_info "Checking /etc/crontab..."
        chown root:root /etc/crontab 2>/dev/null
        chmod 600 /etc/crontab 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "✓ /etc/crontab (600, root:root)"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    # /etc/cron.d/* - root read/write only
    if [[ -d /etc/cron.d ]]; then
        log_info "Checking /etc/cron.d/ files..."
        local cron_d_count=0
        while IFS= read -r -d '' file; do
            total_checks=$((total_checks + 1))
            chown root:root "$file" 2>/dev/null
            chmod 600 "$file" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                fixed_count=$((fixed_count + 1))
                cron_d_count=$((cron_d_count + 1))
            fi
        done < <(find /etc/cron.d -type f -print0 2>/dev/null)

        if [[ $cron_d_count -gt 0 ]]; then
            log_success "✓ Fixed $cron_d_count file(s) in /etc/cron.d/ (600, root:root)"
        fi
    fi

    # /etc/cron.{hourly,daily,weekly,monthly} directories
    for cron_dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$cron_dir" ]]; then
            log_info "Checking $cron_dir/ scripts..."
            local cron_script_count=0
            while IFS= read -r -d '' file; do
                total_checks=$((total_checks + 1))
                chown root:root "$file" 2>/dev/null
                chmod 700 "$file" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    fixed_count=$((fixed_count + 1))
                    cron_script_count=$((cron_script_count + 1))
                fi
            done < <(find "$cron_dir" -type f -print0 2>/dev/null)

            if [[ $cron_script_count -gt 0 ]]; then
                log_success "✓ Fixed $cron_script_count script(s) in $cron_dir/ (700, root:root)"
            fi
        fi
    done

    # /etc/at.allow and /etc/at.deny
    for at_file in /etc/at.allow /etc/at.deny; do
        if [[ -f "$at_file" ]]; then
            total_checks=$((total_checks + 1))
            log_info "Checking $at_file..."
            chown root:root "$at_file" 2>/dev/null
            chmod 600 "$at_file" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                log_success "✓ $at_file (600, root:root)"
                fixed_count=$((fixed_count + 1))
            fi
        fi
    done

    # /etc/cron.allow and /etc/cron.deny
    for cron_file in /etc/cron.allow /etc/cron.deny; do
        if [[ -f "$cron_file" ]]; then
            total_checks=$((total_checks + 1))
            log_info "Checking $cron_file..."
            chown root:root "$cron_file" 2>/dev/null
            chmod 600 "$cron_file" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                log_success "✓ $cron_file (600, root:root)"
                fixed_count=$((fixed_count + 1))
            fi
        fi
    done

    # /var/log directory - syslog group can read
    if [[ -d /var/log ]]; then
        total_checks=$((total_checks + 1))
        log_info "Checking /var/log directory..."

        # Ensure syslog group exists
        if ! getent group syslog >/dev/null 2>&1; then
            groupadd syslog 2>/dev/null
        fi

        chown root:syslog /var/log 2>/dev/null
        chmod 750 /var/log 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "✓ /var/log directory (750, root:syslog)"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    # Critical log files
    local log_files=(
        "/var/log/auth.log"
        "/var/log/syslog"
        "/var/log/messages"
        "/var/log/secure"
    )

    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            total_checks=$((total_checks + 1))
            log_info "Checking $log_file..."

            # Ensure syslog group exists
            if ! getent group syslog >/dev/null 2>&1; then
                groupadd syslog 2>/dev/null
            fi

            chown root:adm "$log_file" 2>/dev/null || chown root:syslog "$log_file" 2>/dev/null
            chmod 640 "$log_file" 2>/dev/null
            if [[ $? -eq 0 ]]; then
                log_success "✓ $log_file (640, root:adm/syslog)"
                fixed_count=$((fixed_count + 1))
            fi
        fi
    done

    # /etc/security directory
    if [[ -d /etc/security ]]; then
        total_checks=$((total_checks + 1))
        log_info "Checking /etc/security directory..."
        chown root:root /etc/security 2>/dev/null
        chmod 755 /etc/security 2>/dev/null
        if [[ $? -eq 0 ]]; then
            log_success "✓ /etc/security directory (755, root:root)"
            fixed_count=$((fixed_count + 1))
        fi
    fi

    log_success "Fixed $fixed_count out of $total_checks system file permissions"

    return 0
}

# Enforce sticky bit and secure mount options on /tmp
ensure_tmp_sticky_bit() {
    log_section "Ensuring /tmp Sticky Bit and Secure Options"

    if [[ -d /tmp ]]; then
        log_info "Setting sticky bit on /tmp (1777)..."
        chmod 1777 /tmp 2>/dev/null && log_success "✓ /tmp permissions set to 1777"
    fi

    return 0
}

# Enforce secure default umask in login.defs
enforce_default_umask() {
    log_section "Enforcing Secure Default UMASK"

    local login_defs="/etc/login.defs"
    local desired_umask="027"

    if [[ -f "$login_defs" ]]; then
        backup_file "$login_defs"
        if grep -qE "^\s*UMASK" "$login_defs"; then
            sed -i "s/^\s*UMASK.*/UMASK $desired_umask/" "$login_defs"
        else
            echo "UMASK $desired_umask" >> "$login_defs"
        fi
        log_success "✓ Set UMASK to $desired_umask in $login_defs"
    else
        log_warn "$login_defs not found; skipping UMASK enforcement"
    fi

    return 0
}

# Restrict home directory permissions
secure_home_directories() {
    log_section "Securing Home Directory Permissions"

    local adjusted=0

    for dir in /home/*; do
        [[ -d "$dir" ]] || continue

        local perm
        perm=$(stat -c "%a" "$dir" 2>/dev/null)

        if [[ "$perm" -gt 750 ]]; then
            log_info "Tightening permissions on $dir (current: $perm)"
            chmod 750 "$dir" 2>/dev/null && adjusted=$((adjusted + 1))
        fi
    done

    if [[ $adjusted -gt 0 ]]; then
        log_success "Adjusted permissions on $adjusted home directories"
    else
        log_info "Home directory permissions already restricted"
    fi

    return 0
}

# Detect and fix world-writable system files
fix_world_writable_files() {
    log_section "Fixing World-Writable System Files"

    local search_paths=(/etc /usr /var /root)
    local fixed=0

    while IFS= read -r -d '' file; do
        log_info "Removing world-writable flag from $file"
        chmod o-w "$file" 2>/dev/null && fixed=$((fixed + 1))
    done < <(find "${search_paths[@]}" -xdev -type f -perm -0002 -print0 2>/dev/null)

    if [[ $fixed -gt 0 ]]; then
        log_success "Removed world-writable permissions from $fixed file(s)"
    else
        log_info "No unexpected world-writable files found"
    fi

    return 0
}

# Harden sudo configuration
harden_sudo_config() {
    log_section "Hardening Sudo Configuration"

    local sudoers="/etc/sudoers"

    sanitize_sudoers_file() {
        local file="$1"

        [[ -f "$file" ]] || return 0

        backup_file "$file"

        # Enforce password prompts (replace NOPASSWD with PASSWD)
        sed -i 's/NOPASSWD/PASSWD/g' "$file"

        # Require PTY and configure logging
        if grep -q "^Defaults" "$file"; then
            grep -q "Defaults\s\+use_pty" "$file" || echo "Defaults use_pty" >> "$file"
            grep -q "Defaults\s\+logfile=\"/var/log/sudo.log\"" "$file" || echo "Defaults logfile=\"/var/log/sudo.log\"" >> "$file"
        else
            cat >> "$file" <<'EOF'
Defaults use_pty
Defaults logfile="/var/log/sudo.log"
EOF
        fi

        # Restrict sudo group entries to approved groups
        local allowed_groups=(sudo admin wheel)
        while IFS= read -r line; do
            local group_name
            group_name=$(echo "$line" | awk '{print $1}' | sed 's/^%//')
            local allowed=false
            for ag in "${allowed_groups[@]}"; do
                [[ "$group_name" == "$ag" ]] && allowed=true && break
            done
            if [[ "$allowed" == false ]]; then
                log_warn "Disabling unauthorized sudo group entry: $line"
                local escaped_line
                escaped_line=$(printf '%s' "$line" | sed 's/[\[\].*^$\\|?+{}()\/&]/\\&/g')
                sed -i "s/^${escaped_line}$/# ${line}/" "$file"
            fi
        done < <(grep -E "^%[^#]+ALL" "$file")

        # Disable insecure user entries (non-root)
        while IFS= read -r line; do
            local user
            user=$(echo "$line" | awk '{print $1}')
            [[ "$user" == "root" ]] && continue
            log_warn "Disabling unauthorized sudo user entry: $line"
            local escaped_line
            escaped_line=$(printf '%s' "$line" | sed 's/[\[\].*^$\\|?+{}()\/&]/\\&/g')
            sed -i "s/^${escaped_line}$/# ${line}/" "$file"
        done < <(grep -E "^[^#%].*ALL" "$file")
    }

    if [[ -f "$sudoers" ]]; then
        sanitize_sudoers_file "$sudoers"
    else
        log_warn "$sudoers not found; skipping sudo hardening"
    fi

    # Harden files in /etc/sudoers.d similarly
    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r -d '' file; do
            sanitize_sudoers_file "$file"
        done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
    fi

    return 0
}

# Configure screen timeout, locking, and power management for GNOME and Cinnamon
configure_screen_security() {
    log_section "Configuring Screen Timeout and Locking"

    local dconf_dir="/etc/dconf/db/local.d"
    local lock_dir="/etc/dconf/db/local.d/locks"
    local config_file="$dconf_dir/00-cyberpatriot-screen"
    local lock_file="$lock_dir/00-cyberpatriot-screen"

    mkdir -p "$dconf_dir" "$lock_dir"

    cat > "$config_file" <<'EOF'
[org/gnome/desktop/session]
idle-delay=uint32 300

[org/gnome/desktop/screensaver]
idle-activation-enabled=true
lock-delay=uint32 0
lock-enabled=true

[org/gnome/settings-daemon/plugins/power]
sleep-inactive-ac-type='suspend'
sleep-inactive-ac-timeout=1800
sleep-inactive-battery-type='suspend'
sleep-inactive-battery-timeout=1200
power-button-action='interactive'

[org/cinnamon/desktop/session]
idle-delay=uint32 300

[org/cinnamon/desktop/screensaver]
idle-activation-enabled=true
lock-delay=uint32 0
lock-enabled=true

[org/cinnamon/settings-daemon/plugins/power]
sleep-inactive-ac-type='suspend'
sleep-inactive-ac-timeout=1800
sleep-inactive-battery-type='suspend'
sleep-inactive-battery-timeout=1200
power-button-action='interactive'
EOF

    cat > "$lock_file" <<'EOF'
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/screensaver/idle-activation-enabled
/org/gnome/desktop/screensaver/lock-delay
/org/gnome/desktop/screensaver/lock-enabled
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-timeout
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type
/org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-timeout
/org/gnome/settings-daemon/plugins/power/power-button-action
/org/cinnamon/desktop/session/idle-delay
/org/cinnamon/desktop/screensaver/idle-activation-enabled
/org/cinnamon/desktop/screensaver/lock-delay
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/settings-daemon/plugins/power/sleep-inactive-ac-type
/org/cinnamon/settings-daemon/plugins/power/sleep-inactive-ac-timeout
/org/cinnamon/settings-daemon/plugins/power/sleep-inactive-battery-type
/org/cinnamon/settings-daemon/plugins/power/sleep-inactive-battery-timeout
/org/cinnamon/settings-daemon/plugins/power/power-button-action
EOF

    if command_exists dconf; then
        if dconf update 2>/dev/null; then
            log_success "✓ Applied screen timeout, locking, and power policies (requires relogin)"
        else
            log_warn "Failed to run 'dconf update'; apply settings manually if needed"
        fi
    else
        log_warn "dconf command not found; settings written but database not rebuilt"
    fi

    return 0
}

# Enforce GRUB signature verification and remove insecure overrides
enforce_grub_signature_checks() {
    log_section "Enforcing GRUB Signature Verification"

    local grub_default="/etc/default/grub"
    local grub_custom="/etc/grub.d/40_custom"
    local updated=false

    if [[ -f "$grub_default" ]]; then
        backup_file "$grub_default"

        if grep -q "^GRUB_VERIFY_SIGNATURES" "$grub_default"; then
            sed -i 's/^GRUB_VERIFY_SIGNATURES=.*/GRUB_VERIFY_SIGNATURES=true/' "$grub_default"
        else
            echo 'GRUB_VERIFY_SIGNATURES=true' >> "$grub_default"
        fi

        updated=true
        log_success "✓ Enabled GRUB signature verification in $grub_default"
    else
        log_warn "$grub_default not found; skipping signature verification toggle"
    fi

    if [[ -f "$grub_custom" ]]; then
        backup_file "$grub_custom"
        local temp_file
        temp_file=$(mktemp)
        local removed=false
        while IFS= read -r line; do
            if [[ "$line" =~ ^set\s+superusers || "$line" =~ ^password ]]; then
                removed=true
                continue
            fi
            echo "$line" >> "$temp_file"
        done < "$grub_custom"

        if ! grep -q "^set check_signatures" "$temp_file"; then
            echo "set check_signatures=enforce" >> "$temp_file"
        fi

        cat "$temp_file" > "$grub_custom"
        rm -f "$temp_file"

        if [[ "$removed" == true ]]; then
            log_success "✓ Removed insecure GRUB superuser entries from $grub_custom"
        else
            log_info "No GRUB superuser entries found in $grub_custom"
        fi

        updated=true
    else
        log_info "$grub_custom not present; skipping custom GRUB hardening"
    fi

    if command_exists update-grub && [[ "$updated" == true ]]; then
        if update-grub >/dev/null 2>&1; then
            log_success "✓ Regenerated GRUB configuration with signature enforcement"
        else
            log_warn "Failed to regenerate GRUB configuration; run update-grub manually"
        fi
    fi

    return 0
}

# Remove insecure or unexpected entries from /etc/hosts
sanitize_hosts_file() {
    log_section "Sanitizing /etc/hosts"

    local hosts_file="/etc/hosts"
    local hostname_value
    hostname_value=$(hostname 2>/dev/null || echo localhost)

    if [[ -f "$hosts_file" ]]; then
        backup_file "$hosts_file"
    fi

    cat > "$hosts_file" <<EOF
127.0.0.1   localhost
127.0.1.1   ${hostname_value} ${hostname_value}.localdomain
::1         ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
EOF

    log_success "✓ Reset /etc/hosts to a secure default"

    return 0
}

# Ensure GDM3 is not configured to run under a custom user
reset_gdm3_user_configuration() {
    log_section "Validating GDM3 User Configuration"

    local custom_conf="/etc/gdm3/custom.conf"
    local dropin_dir="/etc/systemd/system/gdm.service.d"
    local sanitized=false

    if [[ -f "$custom_conf" ]]; then
        backup_file "$custom_conf"
        if grep -q "^User=" "$custom_conf"; then
            sed -i '/^User=/d' "$custom_conf"
            sanitized=true
        fi
        if grep -q "^Group=" "$custom_conf"; then
            sed -i '/^Group=/d' "$custom_conf"
            sanitized=true
        fi
    fi

    if [[ -d "$dropin_dir" ]]; then
        while IFS= read -r -d '' file; do
            backup_file "$file"
            if grep -q "^User=" "$file"; then
                sed -i '/^User=/d' "$file"
                sanitized=true
            fi
            if grep -q "^Group=" "$file"; then
                sed -i '/^Group=/d' "$file"
                sanitized=true
            fi
        done < <(find "$dropin_dir" -type f -name '*.conf' -print0 2>/dev/null)
    fi

    if [[ "$sanitized" == true ]]; then
        log_success "✓ Removed custom user/group overrides for GDM3"
        if command_exists systemctl; then
            systemctl daemon-reload >/dev/null 2>&1 || true
        fi
    else
        log_info "No custom GDM3 user configuration found"
    fi

    return 0
}

# Configure /etc/host.conf for anti-spoofing
setup_host_conf() {
    log_section "Configuring Host Resolver Anti-Spoofing"

    local host_conf="/etc/host.conf"

    # Backup existing file if it exists
    if [[ -f "$host_conf" ]]; then
        backup_file "$host_conf"
    fi

    log_info "Writing secure $host_conf configuration..."

    cat > "$host_conf" <<'EOF'
# /etc/host.conf - Resolver configuration
# CyberPatriot Hardened Configuration

# Order of name resolution: DNS first, then hosts file
order bind,hosts

# Allow multiple IP addresses per hostname
multi on

# Enable spoof checking (reverse DNS lookups)
nospoof on
EOF

    if [[ $? -eq 0 ]]; then
        chown root:root "$host_conf"
        chmod 644 "$host_conf"
        log_success "✓ Configured $host_conf with anti-spoofing protections"
    else
        log_error "Failed to configure $host_conf"
        return 1
    fi

    return 0
}

# Secure /dev/shm with strict mount options
secure_dev_shm() {
    log_section "Securing /dev/shm (Shared Memory)"

    log_info "Checking current /dev/shm mount options..."
    local current_options=$(mount | grep "/dev/shm" | grep -oP '\(.*\)' || echo "")
    log_debug "Current: $current_options"

    # Check if /dev/shm is already in /etc/fstab
    if grep -qE '^\s*tmpfs\s+/dev/shm\s+tmpfs' /etc/fstab 2>/dev/null; then
        log_info "/dev/shm already configured in /etc/fstab"

        # Update the existing entry to ensure secure options
        backup_file /etc/fstab
        sed -i 's|^\s*tmpfs\s\+/dev/shm\s\+tmpfs\s\+.*|tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0|' /etc/fstab
        log_success "Updated /dev/shm entry in /etc/fstab"
    else
        log_info "Adding /dev/shm to /etc/fstab..."
        backup_file /etc/fstab
        echo 'tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0' >> /etc/fstab
        log_success "Added /dev/shm to /etc/fstab"
    fi

    # Remount with secure options immediately
    log_info "Remounting /dev/shm with secure options..."
    if mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null; then
        log_success "✓ Remounted /dev/shm (noexec,nosuid,nodev)"
    else
        log_warn "Failed to remount /dev/shm (changes will apply on next boot)"
    fi

    # Set proper permissions
    chmod 1777 /dev/shm 2>/dev/null

    return 0
}

# Secure /tmp with systemd mount unit
secure_tmp_mount() {
    log_section "Securing /tmp with Systemd Mount Unit"

    local tmp_mount="/etc/systemd/system/tmp.mount"

    # Check if /tmp is a symlink (some systems link to /var/tmp)
    if [[ -L /tmp ]]; then
        log_warn "/tmp is a symbolic link, skipping mount unit creation"
        log_info "Target: $(readlink -f /tmp)"
        return 0
    fi

    # Check if tmp.mount already exists
    if [[ -f "$tmp_mount" ]]; then
        log_info "tmp.mount already exists"
        backup_file "$tmp_mount"
    fi

    log_info "Creating systemd mount unit for /tmp..."

    cat > "$tmp_mount" <<'EOF'
[Unit]
Description=Temporary Directory (/tmp)
Documentation=man:hier(7)
Documentation=https://www.freedesktop.org/wiki/Software/systemd/APIFileSystems
ConditionPathIsSymbolicLink=!/tmp
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target

[Mount]
What=tmpfs
Where=/tmp
Type=tmpfs
Options=mode=1777,strictatime,nosuid,nodev,noexec

[Install]
WantedBy=local-fs.target
EOF

    if [[ $? -ne 0 ]]; then
        log_error "Failed to create tmp.mount unit"
        return 1
    fi

    log_success "Created $tmp_mount"

    if command_exists systemctl; then
        # Reload systemd daemon
        log_info "Reloading systemd daemon..."
        if systemctl daemon-reload 2>/dev/null; then
            log_success "✓ Reloaded systemd daemon"
        else
            log_warn "systemctl daemon-reload failed; tmp.mount may not activate"
        fi

        # Enable the mount unit
        log_info "Enabling tmp.mount..."
        if systemctl enable tmp.mount 2>/dev/null; then
            log_success "✓ Enabled tmp.mount"
        else
            log_warn "Failed to enable tmp.mount"
        fi

        # Try to start the mount unit (may fail if /tmp is in use)
        log_info "Attempting to start tmp.mount..."
        if systemctl start tmp.mount 2>/dev/null; then
            log_success "✓ Started tmp.mount (secure /tmp is now active)"
        else
            log_warn "Failed to start tmp.mount (changes will apply on next reboot)"
            log_info "This is normal if /tmp is currently in use"
        fi
    else
        log_warn "systemctl not available; skipping tmp.mount activation"
    fi

    return 0
}

# Configure /proc with hidepid for process hiding
setup_proc_hidepid() {
    log_section "Configuring Process Hiding (/proc hidepid)"

    log_info "Configuring /proc to hide processes from other users..."

    # Create proc group if it doesn't exist
    if ! getent group proc >/dev/null 2>&1; then
        log_info "Creating 'proc' group..."
        groupadd -f proc
        log_success "Created 'proc' group"
    fi

    local proc_gid=$(getent group proc | cut -d: -f3)
    log_debug "proc group GID: $proc_gid"

    # Check if /proc is already configured in /etc/fstab
    if grep -qE '^\s*proc\s+/proc\s+proc' /etc/fstab 2>/dev/null; then
        log_info "/proc already in /etc/fstab, updating options..."
        backup_file /etc/fstab
        sed -i "s|^\s*proc\s\+/proc\s\+proc\s\+.*|proc /proc proc defaults,hidepid=2,gid=$proc_gid 0 0|" /etc/fstab
        log_success "Updated /proc entry in /etc/fstab"
    else
        log_info "Adding /proc to /etc/fstab..."
        backup_file /etc/fstab
        echo "proc /proc proc defaults,hidepid=2,gid=$proc_gid 0 0" >> /etc/fstab
        log_success "Added /proc to /etc/fstab"
    fi

    # Remount /proc with hidepid immediately
    log_info "Remounting /proc with hidepid=2..."
    if mount -o remount,hidepid=2,gid="$proc_gid" /proc 2>/dev/null; then
        log_success "✓ Remounted /proc (hidepid=2, gid=proc)"
        log_info "Users in the 'proc' group can see all processes"
        log_info "Add admin users to 'proc' group: usermod -aG proc <username>"
    else
        log_warn "Failed to remount /proc (changes will apply on next boot)"
    fi

    return 0
}

# Disable X Server TCP connections
disable_xserver_tcp() {
    log_section "Disabling X Server TCP Connections"

    local configs_created=0

    # Create Xorg configuration to disable TCP
    log_info "Creating Xorg configuration to disable TCP listening..."
    mkdir -p /etc/X11/xorg.conf.d

    cat > /etc/X11/xorg.conf.d/10-nolisten.conf <<'EOF'
# Disable X Server TCP connections
# CyberPatriot Security Hardening

Section "ServerFlags"
    Option "DisallowTCP" "true"
EndSection
EOF

    if [[ $? -eq 0 ]]; then
        log_success "✓ Created /etc/X11/xorg.conf.d/10-nolisten.conf"
        configs_created=$((configs_created + 1))
    fi

    # Configure GDM3 (Ubuntu 24.04 default)
    if [[ -f /etc/gdm3/custom.conf ]]; then
        log_info "Configuring GDM3 to disable TCP..."
        backup_file /etc/gdm3/custom.conf

        # Add or update DisallowTCP setting
        if grep -q "^DisallowTCP=" /etc/gdm3/custom.conf; then
            sed -i 's/^DisallowTCP=.*/DisallowTCP=true/' /etc/gdm3/custom.conf
        elif grep -q "^\[security\]" /etc/gdm3/custom.conf; then
            sed -i '/^\[security\]/a DisallowTCP=true' /etc/gdm3/custom.conf
        else
            echo -e "\n[security]\nDisallowTCP=true" >> /etc/gdm3/custom.conf
        fi

        log_success "✓ Configured GDM3 to disable TCP"
        configs_created=$((configs_created + 1))
    fi

    # Configure LightDM (Linux Mint 21 default)
    if [[ -f /etc/lightdm/lightdm.conf ]] || [[ -d /etc/lightdm/lightdm.conf.d ]]; then
        log_info "Configuring LightDM to disable TCP..."
        mkdir -p /etc/lightdm/lightdm.conf.d

        cat > /etc/lightdm/lightdm.conf.d/50-nolisten.conf <<'EOF'
# Disable X Server TCP connections
# CyberPatriot Security Hardening

[Seat:*]
xserver-allow-tcp=false
EOF

        if [[ $? -eq 0 ]]; then
            log_success "✓ Configured LightDM to disable TCP"
            configs_created=$((configs_created + 1))
        fi
    fi

    if [[ $configs_created -gt 0 ]]; then
        log_success "Created $configs_created X Server TCP disable configuration(s)"
        log_info "Changes will take effect after restarting the display manager or rebooting"
    else
        log_warn "No display managers found to configure"
    fi

    return 0
}

# Print OS settings checklist
print_os_settings_checklist() {
    log_section "OS Settings Security Checklist"

    echo ""
    echo "54. Kernel security parameters configured (see Security Policy module)"
    echo "55. Restricted bash artifacts removed (rbash)"
    echo "56. GRUB configuration files are not world-readable"
    echo "57. GRUB password protection configured (manual step)"
    echo "58. Critical system file permissions fixed (/etc/passwd, /etc/shadow, /etc/gshadow, etc.)"
    echo "59. Default UMASK set to 027 and home directories restricted"
    echo "60. /tmp sticky bit enforced and mounted securely"
    echo "61. Shared memory (/dev/shm) mounted with noexec, nosuid, nodev"
    echo "62. Temporary directory (/tmp) mounted with noexec, nosuid, nodev"
    echo "63. World-writable system files removed"
    echo "64. Screen timeout, locking, and power policies enforced (GNOME/Cinnamon)"
    echo "65. Process information hidden from other users (/proc hidepid=2)"
    echo "66. Sudo requires password, PTY, logging, and only approved groups"
    echo "67. GRUB signature verification enforced and superuser overrides removed"
    echo "68. /etc/hosts sanitized to default loopback entries"
    echo "69. GDM3 not configured to run under a custom user"
    echo "70. X Server TCP connections disabled"
    echo ""

    return 0
}

# Main module execution
run_os_settings() {
    log_section "Uncategorized OS Settings Module"

    # Print checklist
    print_os_settings_checklist

    # Execute all hardening functions
    remove_rbash
    fix_grub_permissions
    enforce_grub_signature_checks
    setup_grub_password
    fix_system_file_permissions
    harden_sudo_config
    enforce_default_umask
    secure_home_directories
    ensure_tmp_sticky_bit
    sanitize_hosts_file
    setup_host_conf
    fix_world_writable_files
    secure_dev_shm
    secure_tmp_mount
    configure_screen_security
    setup_proc_hidepid
    reset_gdm3_user_configuration
    disable_xserver_tcp

    log_section "OS Settings Module Complete"
    log_success "All OS security settings have been configured"
    log_warn "Some changes require a reboot to take full effect"

    return 0
}

export -f run_os_settings
