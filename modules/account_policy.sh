#!/bin/bash
# account_policy.sh - Account Policy Module
# Configures password policies and account security settings

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Account Policy
# Category: Account Policy
# Description: Enforces secure password policies and account settings

# Configuration defaults
readonly DEFAULT_PASS_MAX_DAYS=90
readonly DEFAULT_PASS_MIN_DAYS=7
readonly DEFAULT_PASS_WARN_AGE=7
readonly DEFAULT_PW_REMEMBER=5
readonly DEFAULT_PW_MINLEN=14
readonly DEFAULT_PW_MINCLASS=4
readonly DEFAULT_PW_DIFOK=8
readonly DEFAULT_PW_MAXREPEAT=5
readonly DEFAULT_PW_MAXCLASSREPEAT=3
readonly DEFAULT_PW_RETRY=3
readonly DEFAULT_LOCK_DENY=5
readonly DEFAULT_LOCK_TIME=900
readonly DEFAULT_LOCK_INTERVAL=900

# Detect display manager
detect_display_manager() {
    if systemctl is-active --quiet lightdm 2>/dev/null; then
        echo "lightdm"
    elif systemctl is-active --quiet gdm 2>/dev/null || systemctl is-active --quiet gdm3 2>/dev/null; then
        echo "gdm3"
    elif systemctl is-active --quiet sddm 2>/dev/null; then
        echo "sddm"
    else
        echo "unknown"
    fi
}

# Check if PAM module exists
pam_module_exists() {
    local module="$1"
    ldconfig -p | grep -q "$module" || find /lib* /usr/lib* -name "$module" 2>/dev/null | grep -q .
}

# Check if line exists in file (for idempotency)
line_exists_in_file() {
    local file="$1"
    local pattern="$2"
    [[ -f "$file" ]] && grep -qF "$pattern" "$file"
}

# 23, 24: Configure password aging in /etc/login.defs
configure_login_defs() {
    log_section "Configuring Password Aging Policies"

    local file="/etc/login.defs"
    [[ ! -f "$file" ]] && { log_error "$file not found"; return 1; }

    backup_file "$file"

    # Set ENCRYPT_METHOD to SHA512 (must be set before password operations)
    if grep -q "^ENCRYPT_METHOD" "$file"; then
        sed -i "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/" "$file"
        log_success "Updated ENCRYPT_METHOD to SHA512"
    else
        echo -e "ENCRYPT_METHOD SHA512" >> "$file"
        log_success "Added ENCRYPT_METHOD=SHA512"
    fi

    # Set PASS_MAX_DAYS (23)
    if grep -q "^PASS_MAX_DAYS" "$file"; then
        sed -i "s/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t$DEFAULT_PASS_MAX_DAYS/" "$file"
        log_success "Updated PASS_MAX_DAYS to $DEFAULT_PASS_MAX_DAYS"
    else
        echo -e "PASS_MAX_DAYS\t$DEFAULT_PASS_MAX_DAYS" >> "$file"
        log_success "Added PASS_MAX_DAYS=$DEFAULT_PASS_MAX_DAYS"
    fi

    # Set PASS_MIN_DAYS (24)
    if grep -q "^PASS_MIN_DAYS" "$file"; then
        sed -i "s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t$DEFAULT_PASS_MIN_DAYS/" "$file"
        log_success "Updated PASS_MIN_DAYS to $DEFAULT_PASS_MIN_DAYS"
    else
        echo -e "PASS_MIN_DAYS\t$DEFAULT_PASS_MIN_DAYS" >> "$file"
        log_success "Added PASS_MIN_DAYS=$DEFAULT_PASS_MIN_DAYS"
    fi

    # Set PASS_WARN_AGE if not present
    if ! grep -q "^PASS_WARN_AGE" "$file"; then
        echo -e "PASS_WARN_AGE\t$DEFAULT_PASS_WARN_AGE" >> "$file"
        log_success "Added PASS_WARN_AGE=$DEFAULT_PASS_WARN_AGE"
    fi

    return 0
}

# 26-29: Configure pwquality for password strength requirements
configure_pwquality() {
    log_section "Configuring Password Quality Requirements"

    # Ensure libpam-pwquality is installed
    if ! dpkg -l | grep -q libpam-pwquality; then
        log_info "Installing libpam-pwquality..."
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libpam-pwquality cracklib-runtime
    fi

    # Prefer drop-in configuration directory if supported
    local conf_dir="/etc/security/pwquality.conf.d"
    local main_conf="/etc/security/pwquality.conf"
    local conf_file

    if [[ -d "$conf_dir" ]]; then
        conf_file="$conf_dir/99-cyberpatriot.conf"
    else
        mkdir -p "$conf_dir"
        conf_file="$conf_dir/99-cyberpatriot.conf"
    fi

    # Detect cracklib dictionary
    local dict_path=""
    for path in /var/cache/cracklib/cracklib_dict /usr/share/cracklib/cracklib-small; do
        if [[ -f "${path}.pwd" ]] || [[ -f "${path}.pwi" ]]; then
            dict_path="$path"
            break
        fi
    done

    backup_file "$main_conf" 2>/dev/null || true

    # Create comprehensive pwquality configuration
    cat > "$conf_file" <<EOF
# CyberPatriot Password Quality Requirements
# 26: Minimum password length
minlen = $DEFAULT_PW_MINLEN

# 28: Non-dictionary based checks
minclass = $DEFAULT_PW_MINCLASS
difok = $DEFAULT_PW_DIFOK
maxrepeat = $DEFAULT_PW_MAXREPEAT
maxclassrepeat = $DEFAULT_PW_MAXCLASSREPEAT

# 29: GECOS (user info) checks
gecoscheck = 1

# 27: Dictionary-based checks
dictcheck = 1
EOF

    # Add dictionary path if found
    if [[ -n "$dict_path" ]]; then
        echo "dictpath = $dict_path" >> "$conf_file"
        log_info "Configured cracklib dictionary: $dict_path"
    fi

    cat >> "$conf_file" <<EOF

# Retry attempts
retry = $DEFAULT_PW_RETRY

# Enforce for root too
enforce_for_root

# User checks
usercheck = 1

# Require at least one uppercase, lowercase, digit, and special char
ucredit = -1
lcredit = -1
dcredit = -1
ocredit = -1
EOF

    log_success "Created pwquality configuration at $conf_file"
    log_success "Password strength requirements enabled:"
    log_info "  - Min length: $DEFAULT_PW_MINLEN (26)"
    log_info "  - Dictionary checks enabled (27)"
    log_info "  - Non-dictionary checks enabled (28)"
    log_info "  - GECOS checks enabled (29)"

    return 0
}

# Ensure pam_pwquality is enabled in PAM
enable_pwquality_pam() {
    log_section "Enabling pwquality in PAM"

    local pam_file="/etc/pam.d/common-password"
    [[ ! -f "$pam_file" ]] && { log_error "$pam_file not found"; return 1; }

    backup_file "$pam_file"

    # Check if pwquality is already configured
    if grep -q "pam_pwquality.so" "$pam_file"; then
        log_info "pam_pwquality already configured"
    else
        # Add pwquality at the beginning of password stack
        sed -i '1i password requisite pam_pwquality.so retry='"$DEFAULT_PW_RETRY" "$pam_file"
        log_success "Added pam_pwquality to PAM configuration"
    fi

    # Ensure retry parameter is set
    if ! grep -Eq "pam_pwquality\\.so[^#]*retry=" "$pam_file"; then
        sed -i "s/\(pam_pwquality.so\)/\1 retry=$DEFAULT_PW_RETRY/" "$pam_file"
        log_success "Added retry parameter to pam_pwquality"
    fi

    # Ensure additional hardening options on pam_pwquality.so
    local pwq_numeric_opts=(
        "minlen=$DEFAULT_PW_MINLEN"
        "minclass=$DEFAULT_PW_MINCLASS"
        "difok=$DEFAULT_PW_DIFOK"
        "maxrepeat=$DEFAULT_PW_MAXREPEAT"
        "maxclassrepeat=$DEFAULT_PW_MAXCLASSREPEAT"
        "dcredit=-1"
        "ucredit=-1"
        "ocredit=-1"
        "lcredit=-1"
    )

    local opt key value
    for opt in "${pwq_numeric_opts[@]}"; do
        key="${opt%%=*}"
        value="${opt#*=}"
        if ! grep -Eq "pam_pwquality\\.so[^#]*${key}=" "$pam_file"; then
            sed -i -E "s/(pam_pwquality\\.so[^#]*)/\\1 ${key}=${value}/" "$pam_file"
            log_success "Added pam_pwquality option: ${key}=${value}"
        fi
    done

    # Boolean-style options (and numeric-only options that don't need '=')
    local pwq_bool_opts=(
        "gecoscheck=1"
        "dictcheck=1"
        "reject_username"
        "enforce_for_root"
        "usercheck"
    )

    for opt in "${pwq_bool_opts[@]}"; do
        # Extract the key for checking
        local check_key="${opt%%=*}"
        if ! grep -Eq "pam_pwquality\\.so[^#]*\\b${check_key}" "$pam_file"; then
            sed -i -E "s/(pam_pwquality\\.so[^#]*)/\\1 ${opt}/" "$pam_file"
            log_success "Added pam_pwquality option: ${opt}"
        fi
    done

    return 0
}

# 25: Configure password history (remember previous passwords)
configure_password_history() {
    log_section "Configuring Password History"

    local pam_file="/etc/pam.d/common-password"
    [[ ! -f "$pam_file" ]] && { log_error "$pam_file not found"; return 1; }

    backup_file "$pam_file"

    # Check if pwhistory is already configured
    if grep -q "pam_pwhistory.so" "$pam_file"; then
        # Update existing configuration
        sed -i "s/\(pam_pwhistory.so.*remember=\)[0-9]\+/\1$DEFAULT_PW_REMEMBER/" "$pam_file"
        log_success "Updated password history to remember $DEFAULT_PW_REMEMBER passwords"
    else
        # Add pwhistory before pam_unix to ensure it's enforced
        # Find the first pam_unix line and insert before it
        if grep -q "pam_unix.so" "$pam_file"; then
            sed -i "/pam_unix.so/i password required pam_pwhistory.so remember=$DEFAULT_PW_REMEMBER use_authtok" "$pam_file"
            log_success "Added password history (remember $DEFAULT_PW_REMEMBER passwords)"
        else
            # If no pam_unix line, add at the end
            echo "password required pam_pwhistory.so remember=$DEFAULT_PW_REMEMBER use_authtok" >> "$pam_file"
            log_success "Added password history (remember $DEFAULT_PW_REMEMBER passwords)"
        fi
    fi

    return 0
}

# 30: Configure secure password hashing algorithm
configure_password_hashing() {
    log_section "Configuring Secure Password Hashing"

    local pam_file="/etc/pam.d/common-password"
    [[ ! -f "$pam_file" ]] && { log_error "$pam_file not found"; return 1; }

    backup_file "$pam_file"

    # Use yescrypt as requested for system-wide encryption
    local hash_algo="yescrypt"
    log_info "Configuring yescrypt password hashing"

    # Update pam_unix line with secure hashing
    if grep -q "pam_unix.so" "$pam_file"; then
        # Remove any existing hash algorithm
        sed -i "s/\(pam_unix.so[^#]*\)\(sha512\|yescrypt\|md5\|des\)/\1/" "$pam_file"
        # Add the secure hash algorithm
        sed -i "s/\(pam_unix.so\)/\1 $hash_algo/" "$pam_file"
        log_success "Configured password hashing to use $hash_algo in PAM"
    fi

    # login.defs is now configured in configure_login_defs(), but verify it's set
    local login_defs="/etc/login.defs"
    if [[ -f "$login_defs" ]]; then
        if ! grep -q "^ENCRYPT_METHOD.*YESCRYPT" "$login_defs"; then
            log_warn "ENCRYPT_METHOD not set to YESCRYPT in login.defs, fixing..."
            backup_file "$login_defs"
            if grep -q "^ENCRYPT_METHOD" "$login_defs"; then
                sed -i "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD YESCRYPT/" "$login_defs"
            else
                echo "ENCRYPT_METHOD YESCRYPT" >> "$login_defs"
            fi
            log_success "Set ENCRYPT_METHOD to YESCRYPT in login.defs"
        else
            log_info "ENCRYPT_METHOD already set to YESCRYPT in login.defs"
        fi
    fi

    return 0
}

# 31, 32: Remove nullok from PAM (prevent null password authentication)
disable_null_passwords() {
    log_section "Disabling Null Password Authentication"

    local modified=0

    # Remove nullok and nullok_secure from all PAM files
    # This now runs *after* pam-auth-update, so it will clean up common-auth
    for pam_file in /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/login /etc/pam.d/sshd; do
        if [[ -f "$pam_file" ]] && grep -q "nullok" "$pam_file"; then
            backup_file "$pam_file"
            sed -i 's/\s*nullok_secure//g; s/\s*nullok//g' "$pam_file"
            log_success "Removed nullok from $pam_file"
            modified=$((modified + 1))
        fi
    done

    # Ensure PermitEmptyPasswords is disabled in SSH
    local sshd_dir="/etc/ssh/sshd_config.d"
    mkdir -p "$sshd_dir"
    local sshd_conf="$sshd_dir/60-no-empty-passwords.conf"

    if [[ ! -f "$sshd_conf" ]] || ! grep -q "PermitEmptyPasswords no" "$sshd_conf"; then
        echo "# Disable empty passwords" > "$sshd_conf"
        echo "PermitEmptyPasswords no" >> "$sshd_conf"
        log_success "Disabled empty passwords in SSH"

        # Reload SSH if it's running
        if systemctl is-active --quiet sshd 2>/dev/null; then
            systemctl reload sshd 2>/dev/null || log_warn "Failed to reload sshd service"
        elif systemctl is-active --quiet ssh 2>/dev/null; then
            systemctl reload ssh 2>/dev/null || log_warn "Failed to reload ssh service"
        fi
    fi

    if [[ $modified -gt 0 ]]; then
        log_success "Null password authentication disabled on all PAM modules"
    else
        log_info "Null password authentication already disabled"
    fi

    return 0
}

# 35: Ensure root account has no blank password
lock_root_account_if_blank() {
    log_section "Ensuring Root Account is Locked"

    local shadow_entry
    if ! shadow_entry=$(getent shadow root 2>/dev/null); then
        log_error "Unable to read root entry from /etc/shadow"
        return 1
    fi

    local username password_hash rest
    local IFS=':'
    read -r username password_hash rest <<< "$shadow_entry"

    if [[ -z "$password_hash" ]]; then
        log_warn "Root account has a blank password hash; locking account"
        if passwd -l root >/dev/null 2>&1; then
            log_score 4 "Locked root account to remove blank password"
            log_success "Root account locked (blank password removed)"
            return 0
        else
            log_error "Failed to lock root account"
            return 1
        fi
    elif [[ "$password_hash" == '!'* || "$password_hash" == '*'* ]]; then
        log_info "Root account is already locked"
    else
        log_info "Root account already has a password hash configured"
    fi

    return 0
}

# 33: Configure account lockout policy with faillock (pam-auth-update method)
configure_account_lockout() {
    log_section "Configuring Account Lockout Policy (pam-auth-update method)"

    # Ensure pam_faillock is available
    if ! pam_module_exists "pam_faillock.so"; then
        log_warn "pam_faillock not available, skipping lockout configuration"
        return 1
    fi

    # 1. Create pam-config profiles
    local pam_config_dir="/usr/share/pam-configs"
    mkdir -p "$pam_config_dir"

    log_info "Creating pam-config profile: faillock_notify"
    tee "$pam_config_dir/faillock_notify" >/dev/null <<'EOF'
Name: Notify on account lockout
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
    requisite                       pam_faillock.so preauth
EOF

    log_info "Creating pam-config profile: faillock_reset"
    tee "$pam_config_dir/faillock_reset" >/dev/null <<'EOF'
Name: Reset lockout on success
Default: no
Priority: 0
Auth-Type: Additional
Auth:
    required                        pam_faillock.so authsucc
EOF

    log_info "Creating pam-config profile: faillock"
    tee "$pam_config_dir/faillock" >/dev/null <<'EOF'
Name: Lockout on failed logins
Default: no
Priority: 0
Auth-Type: Primary
Auth:
    [default=die]                   pam_faillock.so authfail
EOF

    # 2. Enable profiles using pam-auth-update non-interactively
    log_info "Enabling faillock profiles with pam-auth-update..."
    if pam-auth-update --enable faillock faillock_reset faillock_notify --force; then
        log_success "Successfully enabled faillock profiles via pam-auth-update"
    else
        log_error "pam-auth-update command failed!"
        return 1
    fi
    
    # 3. Configure /etc/security/faillock.conf
    local faillock_conf="/etc/security/faillock.conf"
    if [[ -f "$faillock_conf" ]]; then
        backup_file "$faillock_conf"
    fi

    log_info "Configuring $faillock_conf..."
    cat > "$faillock_conf" <<EOF
# CyberPatriot - Account Lockout Configuration
# Lock account after failed login attempts

# Deny access after this many failed attempts
deny = $DEFAULT_LOCK_DENY

# Unlock time in seconds (900 = 15 minutes)
unlock_time = $DEFAULT_LOCK_TIME

# Time window for counting failures (900 = 15 minutes)
fail_interval = $DEFAULT_LOCK_INTERVAL

# Also enforce for root account
even_deny_root
EOF

    log_success "Configured faillock.conf"
    log_success "Account lockout policy configured:"
    log_info "  - Lock after $DEFAULT_LOCK_DENY failed attempts"
    log_info "  - Lock duration: $DEFAULT_LOCK_TIME seconds ($((DEFAULT_LOCK_TIME/60)) minutes)"
    log_info "  - Failure interval: $DEFAULT_LOCK_INTERVAL seconds ($((DEFAULT_LOCK_INTERVAL/60)) minutes)"
    log_info "  - Enforcement applies to root as well"
    log_info "  - Using pam-auth-update (faillock, faillock_reset, faillock_notify)"

    return 0
}

# 34: Disable user enumeration in greeter
disable_user_enumeration() {
    log_section "Disabling User Enumeration in Login Greeter"

    local dm=$(detect_display_manager)
    log_info "Detected display manager: $dm"

    case "$dm" in
        lightdm)
            log_info "Configuring LightDM..."

            # Configure LightDM main config
            local lightdm_dir="/etc/lightdm/lightdm.conf.d"
            mkdir -p "$lightdm_dir"
            local lightdm_conf="$lightdm_dir/50-hide-users.conf"

            cat > "$lightdm_conf" <<EOF
# CyberPatriot - Disable user enumeration
[Seat:*]
greeter-hide-users=true
greeter-show-manual-login=true
allow-guest=false
EOF
            log_success "Created LightDM configuration"

            # Configure Slick Greeter if present (Linux Mint)
            local slick_conf="/etc/lightdm/slick-greeter.conf"
            if [[ -f "$slick_conf" ]]; then
                backup_file "$slick_conf"
                if ! grep -q "^\[Greeter\]" "$slick_conf"; then
                    echo "[Greeter]" >> "$slick_conf"
                fi
                if ! grep -q "^show-hostname=" "$slick_conf"; then
                    sed -i "/^\[Greeter\]/a show-hostname=false" "$slick_conf"
                fi
                if ! grep -q "^show-a11y=" "$slick_conf"; then
                    sed -i "/^\[Greeter\]/a show-a11y=true" "$slick_conf"
                fi
                log_success "Configured Slick Greeter"
            fi

            log_info "LightDM configured. Changes take effect on next display manager restart"
            ;;

        gdm3)
            log_info "Configuring GDM3..."

            # Configure via dconf
            local dconf_dir="/etc/dconf/db/gdm.d"
            mkdir -p "$dconf_dir"
            local dconf_file="$dconf_dir/00-login-screen"

            cat > "$dconf_file" <<EOF
# CyberPatriot - Disable user enumeration
[org/gnome/login-screen]
disable-user-list=true
EOF
            log_success "Created GDM3 dconf configuration"

            # Update dconf database
            if command -v dconf &>/dev/null; then
                dconf update 2>/dev/null || true
                log_success "Updated dconf database"
            fi

            # Also configure in custom.conf
            local gdm_conf="/etc/gdm3/custom.conf"
            if [[ -f "$gdm_conf" ]]; then
                backup_file "$gdm_conf"
                if ! grep -q "disable-user-list=true" "$gdm_conf"; then
                    # Add under [greeter] section or create it
                    if grep -q "^\[greeter\]" "$gdm_conf"; then
                        sed -i "/^\[greeter\]/a disable-user-list=true" "$gdm_conf"
                    else
                        echo -e "\n[greeter]\ndisable-user-list=true" >> "$gD'M_conf"
                    fi
                    log_success "Updated GDM3 custom.conf"
                fi
            fi

            log_info "GDM3 configured. Changes take effect on next display manager restart"
            ;;

        sddm)
            log_info "Configuring SDDM..."
            local sddm_conf="/etc/sddm.conf"

            if [[ -f "$sddm_conf" ]]; then
                backup_file "$sddm_conf"
            else
                touch "$sddm_conf"
            fi

            if ! grep -q "^\[Theme\]" "$sddm_conf"; then
                echo "[Theme]" >> "$sddm_conf"
            fi

            if ! grep -q "^EnableAvatars=" "$sddm_conf"; then
                sed -i "/^\[Theme\]/a EnableAvatars=false" "$sddm_conf"
                log_success "Disabled user avatars in SDDM"
            fi
            ;;

        *)
            log_warn "Unknown or no display manager detected"
            log_info "Manual configuration may be required"
            return 1
            ;;
    esac

    log_success "User enumeration disabled in login greeter"
    return 0
}

# Verify PAM configuration integrity
verify_pam_integrity() {
    log_section "Verifying PAM Configuration Integrity"

    local errors=0

    # Check that critical PAM files have required modules
    if ! grep -q "pam_unix.so" /etc/pam.d/common-auth; then
        log_error "pam_unix.so missing from common-auth - authentication may fail!"
        errors=$((errors + 1))
    fi

    if ! grep -q "pam_permit.so\|pam_unix.so" /etc/pam.d/common-account; then
        log_error "Required module missing from common-account"
        errors=$((errors + 1))
    fi

    if ! grep -q "pam_unix.so" /etc/pam.d/common-password; then
        log_error "pam_unix.so missing from common-password - password changes may fail!"
        errors=$((errors + 1))
    fi

    if [[ $errors -gt 0 ]]; then
        log_error "PAM configuration has $errors error(s) - please review manually!"
        log_error "Backups are available in /var/backups/cyberpatriot/"
        return 1
    fi

    log_success "PAM configuration integrity verified"
    return 0
}

# Main module execution
run_account_policy() {
    log_section "Account Policy Module"

    # Ensure running as root
    require_root

    # Run non-PAM or non-conflicting configs first
    configure_login_defs              # Items 23, 24
    configure_pwquality               # Items 26, 27, 28, 29 (sets up /etc/security/pwquality.conf)
    lock_root_account_if_blank        # Item 35
    disable_user_enumeration          # Item 34

    # --- PAM Configuration Block ---
    # Run pam-auth-update (faillock) FIRST to establish the PAM baseline
    # This regenerates common-auth and common-account
    configure_account_lockout         # Item 33 (NEW VERSION)

    # Now, apply all direct PAM edits on top of the new baseline
    # These functions primarily edit common-password, which is less
    # likely to be overwritten by the faillock update, but this
    # is the safest order.
    enable_pwquality_pam              # Enable pwquality in /etc/pam.d/common-password
    configure_password_history        # Item 25 (edits /etc/pam.d/common-password)
    configure_password_hashing        # Item 30 (edits /etc/pam.d/common-password)
    
    # Run disable_null_passwords LAST to ensure nullok is removed
    # from the newly regenerated common-auth and from common-password.
    disable_null_passwords            # Items 31, 32 (edits common-auth, common-password)

    # Verify that we didn't break PAM
    if ! verify_pam_integrity; then
        log_error "PAM integrity check failed!"
        log_error "You may need to restore from backups"
        return 1
    fi

    log_section "Account Policy Module Complete"
    log_success "All account policy configurations applied successfully"
    log_info ""
    log_info "Summary of changes:"
    log_info "  ✓ Password aging policies configured (max: $DEFAULT_PASS_MAX_DAYS, min: $DEFAULT_PASS_MIN_DAYS)"
    log_info "  ✓ Password history enabled (remember $DEFAULT_PW_REMEMBER passwords)"
    log_info "  ✓ Password strength requirements enforced (min length: $DEFAULT_PW_MINLEN)"
    log_info "  ✓ Dictionary-based password checks enabled"
    log_info "  ✓ Non-dictionary password checks enabled"
    log_info "  ✓ GECOS password checks enabled"
    log_info "  ✓ Secure password hashing configured"
    log_info "  ✓ Null password authentication disabled"
    log_info "  ✓ Root account checked for blank password"
    log_info "  ✓ Account lockout policy configured (lock after $DEFAULT_LOCK_DENY attempts)"
    log_info "  ✓ User enumeration disabled in login greeter"
    log_info ""
    log_warn "Note: Display manager changes require restart to take effect"
    log_info "Backups saved to: /var/backups/cyberpatriot/"

    return 0
}

export -f run_account_policy
