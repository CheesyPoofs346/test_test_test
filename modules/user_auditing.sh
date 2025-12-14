#!/bin/bash
# user_auditing.sh - User Auditing Module
# Audits system users against authorized user list from README
# Handles user creation, removal, password policies, and access control

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/readme_parser.sh"

# Module: User Auditing
# Category: User Auditing
# Description: Comprehensive user management based on README requirements

# Configuration
readonly DEFAULT_PASSWORD="CyberPatr!0t2024"
readonly SECURE_PASSWORD_MIN_LENGTH=12
readonly PASSWORD_MAX_DAYS=90
readonly PASSWORD_MIN_DAYS=7
readonly PASSWORD_WARN_DAYS=14
readonly DEFAULT_SYSTEM_USERS_TO_RESTRICT=("guest" "ftp")

# System accounts that should never be removed
readonly SYSTEM_ACCOUNTS=(
    "root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp"
    "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network"
    "systemd-resolve" "systemd-timesync" "messagebus" "avahi" "cups" "ssl-cert"
    "avahi-autoipd" "usbmux" "pulse" "rtkit" "saned" "whoopsie" "kernoops"
    "speech-dispatcher" "hplip" "sshd" "geoclue" "gnome-initial-setup" "gdm"
    "mysql" "postgres" "redis" "mongodb" "nginx" "apache" "_apt" "systemd-coredump"
    "lightdm" "colord" "nm-openvpn" "dnsmasq" "tss" "landscape" "pollinate"
    "lxd" "uuidd" "tcpdump" "syslog" "snap" "_flatpak" "cups-pk-helper"
)

# Get the main user (the user who is running the system, usually first UID >= 1000)
get_main_user() {
    # Get the first user with UID >= 1000 and < 65534 (excluding nobody)
    awk -F: '$3 >= 1000 && $3 < 65534 { print $1; exit }' /etc/passwd
}

# Get all current users (UID >= 1000, excluding nobody)
get_current_users() {
    awk -F: '$3 >= 1000 && $3 < 65534 && $1 != "nobody" { print $1 }' /etc/passwd
}

# Get current admins based on group membership
# We use sudo/admin for *identification* of admins.
# The adm group is cleaned up separately so it doesn't affect
# who we consider to be an "admin" for logic/score purposes.
get_current_admins() {
    local group users user

    # Determine "current admins" based on sudo/admin group membership ONLY.
    # adm is handled separately so that we can still clean it up without
    # treating every adm member as a full administrator.
    (
        for group in sudo admin; do
            if getent group "$group" &>/dev/null; then
                users=$(getent group "$group" | awk -F: '{print $4}')

                # Replace comma-separated list with newlines and trim whitespace
                echo "$users" | tr ',' '\n' | while IFS= read -r user; do
                    user=$(echo "$user" | xargs)
                    [[ -z "$user" ]] && continue
                    echo "$user"
                done
            fi
        done
    ) | sort -u
}

# Check if user is a system account
is_system_account() {
    local username="$1"

    for sys_account in "${SYSTEM_ACCOUNTS[@]}"; do
        if [[ "$username" == "$sys_account" ]]; then
            return 0
        fi
    done

    return 1
}

# Check if user exists
user_exists() {
    local username="$1"
    id "$username" &>/dev/null
}

# Check if group exists
group_exists() {
    local groupname="$1"
    getent group "$groupname" &>/dev/null
}

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

# Disable guest account
disable_guest_account() {
    log_section "Disabling Guest Account"

    local dm=$(detect_display_manager)
    log_info "Detected display manager: $dm"

    case "$dm" in
        lightdm)
            log_info "Disabling guest account in LightDM..."

            if [[ -f /etc/lightdm/lightdm.conf ]]; then
                if grep -q "^allow-guest=false" /etc/lightdm/lightdm.conf; then
                    log_info "Guest account already disabled in lightdm.conf"
                else
                    # Add or update allow-guest setting
                    if grep -q "^allow-guest=" /etc/lightdm/lightdm.conf; then
                        sed -i 's/^allow-guest=.*/allow-guest=false/' /etc/lightdm/lightdm.conf
                    else
                        echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
                    fi
                    log_success "Guest account disabled in LightDM"
                fi
            else
                mkdir -p /etc/lightdm
                cat > /etc/lightdm/lightdm.conf <<EOF
[Seat:*]
allow-guest=false
EOF
                log_success "Created LightDM config and disabled guest account"
            fi
            ;;

        gdm3)
            log_info "Disabling guest account in GDM3..."

            # Create custom.conf if it doesn't exist
            mkdir -p /etc/gdm3
            if [[ ! -f /etc/gdm3/custom.conf ]]; then
                cat > /etc/gdm3/custom.conf <<EOF
[daemon]
TimedLoginEnable=false
AutomaticLoginEnable=false
EOF
                log_success "Created GDM3 config and disabled automatic login"
            else
                log_info "GDM3 custom.conf already exists"
            fi

            # GDM3 doesn't have a direct "guest" account, but we ensure it's not in the system
            if user_exists "guest"; then
                log_warn "Found 'guest' user account, will be handled in user removal"
            fi
            ;;

        *)
            log_warn "Unknown display manager, attempting generic guest account handling"
            if user_exists "guest"; then
                log_warn "Found 'guest' user account, will be handled in user removal"
            fi
            ;;
    esac

    return 0
}

# Remove unauthorized users
remove_unauthorized_users() {
    log_section "Removing Unauthorized Users"

    local main_user=$(get_main_user)
    log_info "Main user: $main_user"

    local removed_count=0

    # Get all current users
    while IFS= read -r current_user; do
        # Skip if empty
        [[ -z "$current_user" ]] && continue

        # Skip system accounts
        if is_system_account "$current_user"; then
            log_debug "Skipping system account: $current_user"
            continue
        fi

        # Skip if authorized
        if is_user_authorized "$current_user"; then
            log_debug "User is authorized: $current_user"
            continue
        fi

        # This is an unauthorized user
        log_warn "Found unauthorized user: $current_user"

        if userdel -r "$current_user" 2>/dev/null; then
            log_success "Removed unauthorized user: $current_user"
            removed_count=$((removed_count + 1))
        else
            # Try without removing home directory
            if userdel "$current_user" 2>/dev/null; then
                log_success "Removed unauthorized user (kept home): $current_user"
                removed_count=$((removed_count + 1))
            else
                log_error "Failed to remove user: $current_user"
            fi
        fi
    done < <(get_current_users)

    if [[ $removed_count -eq 0 ]]; then
        log_info "No unauthorized users found"
    else
        log_success "Removed $removed_count unauthorized user(s)"
    fi

    return 0
}

# Fix non-root users with UID 0 (root UID)
fix_root_uid_users() {
    log_section "Checking for Non-Root Users with UID 0"

    local fixed_count=0

    # Find all users with UID 0
    while IFS=: read -r username _ uid _; do
        [[ $uid -ne 0 ]] && continue  # Only process UID 0

        # Skip the actual root user
        if [[ "$username" == "root" ]]; then
            log_debug "Skipping legitimate root user"
            continue
        fi

        # Found a non-root user with UID 0 - this is a security issue
        log_warn "Found non-root user with UID 0: $username"

        # Check if user is authorized (though unlikely for UID 0)
        auth_status=1
        if is_user_authorized "$username" 2>/dev/null; then
            auth_status=0
        fi

        if [[ $auth_status -eq 0 ]]; then
            log_warn "User $username has UID 0 but is authorized in README"
            log_info "Changing UID for $username to avoid root UID conflict"

            # Find next available UID in system range (100-999)
            local new_uid=900
            while getent passwd "$new_uid" &>/dev/null; do
                new_uid=$((new_uid + 1))
                [[ $new_uid -ge 1000 ]] && break
            done

            if [[ $new_uid -lt 1000 ]]; then
                log_info "Changing $username UID from 0 to $new_uid"
                if usermod -u "$new_uid" "$username" 2>/dev/null; then
                    log_success "Changed $username UID to $new_uid (was 0)"
                    log_score 3 "Fixed non-root user with UID 0: $username"
                    fixed_count=$((fixed_count + 1))
                else
                    log_error "Failed to change UID for $username"
                fi
            else
                log_error "Could not find available UID for $username"
            fi
        else
            # User is not authorized and has UID 0 - remove them
            log_warn "Removing unauthorized user with UID 0: $username"
            if userdel -r "$username" 2>/dev/null; then
                log_success "Removed unauthorized user with UID 0: $username"
                log_score 3 "Removed non-root user with UID 0: $username"
                fixed_count=$((fixed_count + 1))
            else
                if userdel "$username" 2>/dev/null; then
                    log_success "Removed unauthorized user with UID 0 (kept home): $username"
                    log_score 3 "Removed non-root user with UID 0: $username"
                    fixed_count=$((fixed_count + 1))
                else
                    log_error "Failed to remove user with UID 0: $username"
                fi
            fi
        fi
    done < /etc/passwd

    if [[ $fixed_count -eq 0 ]]; then
        log_info "No non-root users with UID 0 found"
    else
        log_success "Fixed $fixed_count user(s) with UID 0"
    fi

    return 0
}

# Remove hidden users (UID < 1000 but not system accounts)
remove_hidden_users() {
    log_section "Checking for Hidden Users"

    local removed_count=0

    # Find users with UID < 1000 that aren't in our system accounts list
    while IFS=: read -r username _ uid _; do
        # Skip UID 0 entirely - handled by fix_root_uid_users()
        [[ $uid -eq 0 ]] && continue
        [[ $uid -ge 65534 ]] && continue
        [[ $uid -ge 1000 ]] && continue

        # Skip if it's a known system account
        if is_system_account "$username"; then
            continue
        fi

        # Skip if authorized in README
        # We call this and check its return code in a way that
        # prevents 'set -e' from exiting the whole script if it fails.
        auth_status=1 # Default to "not authorized" (1 = false)
        if is_user_authorized "$username" 2>/dev/null; then
            auth_status=0 # 0 = "authorized" (true)
        fi

        if [[ $auth_status -eq 0 ]]; then
            log_warn "User $username has UID < 1000 but is authorized in README"
            continue
        fi

        # This is a hidden user
        log_warn "Found hidden user: $username (UID: $uid)"

        if userdel -r "$username" 2>/dev/null; then
            log_success "Removed hidden user: $username"
            removed_count=$((removed_count + 1))
        else
            if userdel "$username" 2>/dev/null; then
                log_success "Removed hidden user (kept home): $username"
                removed_count=$((removed_count + 1))
            else
                log_error "Failed to remove hidden user: $username"
            fi
        fi
    done < /etc/passwd

    if [[ $removed_count -eq 0 ]]; then
        log_info "No hidden users found"
    else
        log_success "Removed $removed_count hidden user(s)"
    fi

    return 0
}

# Handle FTP and system users based on README
handle_system_users() {
    log_section "Handling System Users to Restrict"

    local restricted_count=0

    # Get users that should be restricted (defaults plus README)
    while IFS= read -r username; do
        [[ -z "$username" ]] && continue

        log_info "Processing system user to restrict: $username"

        # If user doesn't exist, skip
        if ! user_exists "$username"; then
            log_debug "User $username doesn't exist, skipping"
            continue
        fi

        # If user is authorized, don't restrict
        auth_status=1 # Default to "not authorized"
        if is_user_authorized "$username" 2>/dev/null; then
            auth_status=0 # 0 = "authorized"
        fi

        if [[ $auth_status -eq 0 ]]; then
            log_info "User $username is authorized in README, not restricting"
            continue
        fi

        # Check if it's a critical system account we shouldn't remove
        if is_system_account "$username"; then
            log_info "Disabling login for system user: $username"
            # Disable password and shell login
            usermod -L "$username" 2>/dev/null
            usermod -s /usr/sbin/nologin "$username" 2>/dev/null
            log_success "Disabled login for system user: $username"
            restricted_count=$((restricted_count + 1))
        else
            # Not a critical system account and not authorized - remove it
            log_warn "Removing unauthorized user: $username"
            if userdel -r "$username" 2>/dev/null; then
                log_success "Removed user: $username"
                restricted_count=$((restricted_count + 1))
            else
                if userdel "$username" 2>/dev/null; then
                    log_success "Removed user (kept home): $username"
                    restricted_count=$((restricted_count + 1))
                else
                    log_error "Failed to remove user: $username"
                fi
            fi
        fi
    done < <(build_system_users_to_restrict)

    if [[ $restricted_count -eq 0 ]]; then
        log_info "No system users to restrict"
    else
        log_success "Restricted/removed $restricted_count system user(s)"
    fi

    return 0
}

# Manage admin privileges
manage_admin_privileges() {
    log_section "Managing Admin Privileges"

    local changes_made=0
    local current_admin auth_admin group
    local remove_admin_changes cleanup_adm_changes add_changes

    # ------------------------------------------------------------------
    # 1. Remove unauthorized *admins* based on sudo/admin group membership
    #    (primary indicator of administrative access).
    # ------------------------------------------------------------------
    remove_admin_changes=$(get_current_admins | {
        local count=0
        while IFS= read -r current_admin; do
            [[ -z "$current_admin" ]] && continue

            if ! is_user_admin "$current_admin"; then
                log_warn "User $current_admin has administrative access via sudo/admin but isn't authorized"

                # Strip them from all admin-ish groups
                for group in sudo admin adm; do
                    if getent group "$group" &>/dev/null && groups "$current_admin" | grep -qw "$group"; then
                        log_info "Removing $current_admin from $group group"
                        if deluser "$current_admin" "$group" >/dev/null 2>&1; then
                            log_success "Removed $current_admin from $group group"
                            count=$((count + 1))
                        else
                            log_error "Failed to remove $current_admin from $group group"
                        fi
                    fi
                done
            fi
        done
        echo "$count"
    })

    # ------------------------------------------------------------------
    # 2. Separately clean up the adm group:
    #    any non-admin lingering in adm should be removed, even if they
    #    are not in sudo. This satisfies "remove unauthorized from adm".
    # ------------------------------------------------------------------
    cleanup_adm_changes=0
    if getent group adm &>/dev/null; then
        cleanup_adm_changes=$(
            getent group adm | awk -F: '{print $4}' | tr ',' '\n' | {
                local adm_user count=0

                while IFS= read -r adm_user; do
                    adm_user=$(echo "$adm_user" | xargs)
                    [[ -z "$adm_user" ]] && continue

                    # Authorized admins are allowed to stay in adm
                    if is_user_admin "$adm_user"; then
                        continue
                    fi

                    log_warn "User $adm_user is in adm group but isn't authorized"
                    log_info "Removing $adm_user from adm group"
                    if deluser "$adm_user" "adm" >/dev/null 2>&1; then
                        log_success "Removed $adm_user from adm group"
                        count=$((count + 1))
                    else
                        log_error "Failed to remove $adm_user from adm group"
                    fi
                done

                echo "$count"
            }
        )
    fi

    # ------------------------------------------------------------------
    # 3. Ensure authorized admins are present in sudo/adm
    # ------------------------------------------------------------------
    add_changes=$(get_authorized_admins | sort -u | {
        local count=0
        while IFS= read -r auth_admin; do
            [[ -z "$auth_admin" ]] && continue

            if ! user_exists "$auth_admin"; then
                log_warn "Admin user $auth_admin doesn't exist yet"
                continue
            fi

            for group in sudo adm; do
                if ! getent group "$group" &>/dev/null; then
                    continue
                fi

                if groups "$auth_admin" | grep -qw "$group"; then
                    log_debug "User $auth_admin already in $group group"
                else
                    log_info "Adding $auth_admin to $group group"
                    if usermod -aG "$group" "$auth_admin" 2>/dev/null; then
                        log_success "Added $auth_admin to $group group"
                        count=$((count + 1))
                    else
                        log_error "Failed to add $auth_admin to $group group"
                    fi
                fi
            done
        done
        echo "$count"
    })

    changes_made=$((remove_admin_changes + cleanup_adm_changes + add_changes))

    if [[ $changes_made -eq 0 ]]; then
        log_info "Admin privileges are correct"
    else
        log_success "Made $changes_made admin privilege change(s)"
    fi

    return 0
}

# Create groups
create_groups() {
    log_section "Creating Required Groups"

    local created_count=0

    # Get groups from README (JSON array of objects)
    local groups_json=$(echo "$README_DATA" | jq -r '.groups_to_create[]? | @json')

    if [[ -z "$groups_json" ]]; then
        log_info "No groups to create"
        return 0
    fi

    while IFS= read -r group_json; do
        [[ -z "$group_json" ]] && continue

        local entry_type=$(echo "$group_json" | jq -r 'type')
        local groupname=""

        if [[ "$entry_type" == "string" ]]; then
            groupname=$(echo "$group_json" | jq -r '.')
        else
            groupname=$(echo "$group_json" | jq -r '.name // empty')
        fi

        [[ -z "$groupname" || "$groupname" == "null" ]] && continue

        if group_exists "$groupname"; then
            log_debug "Group already exists: $groupname"
        else
            log_info "Creating group: $groupname"
            if groupadd "$groupname" 2>/dev/null; then
                log_success "Created group: $groupname"
                created_count=$((created_count + 1))
            else
                log_error "Failed to create group: $groupname"
            fi
        fi
    done <<< "$groups_json"

    if [[ $created_count -gt 0 ]]; then
        log_success "Created $created_count group(s)"
    fi

    return 0
}

# Create missing user accounts
create_missing_users() {
    log_section "Creating Missing User Accounts"

    local created_count=0

    # Get recent hires from README
    local hires_json=$(echo "$README_DATA" | jq -r '.recent_hires[]? | @json')

    if [[ -z "$hires_json" ]]; then
        log_info "No users to create"
        return 0
    fi

    while IFS= read -r hire_json; do
        [[ -z "$hire_json" ]] && continue

        local entry_type=$(echo "$hire_json" | jq -r 'type')
        local username=""
        local account_type="standard"

        if [[ "$entry_type" == "string" ]]; then
            username=$(echo "$hire_json" | jq -r '.')
        else
            username=$(echo "$hire_json" | jq -r '.name // empty')
            account_type=$(echo "$hire_json" | jq -r '(.account_type // "standard") | ascii_downcase')
        fi

        [[ -z "$username" || "$username" == "null" ]] && continue

        if user_exists "$username"; then
            log_debug "User already exists: $username"
            continue
        fi

        log_info "Creating user account: $username"

        # Create user with home directory
        if useradd -m -s /bin/bash "$username" 2>/dev/null; then
            log_success "Created user account: $username"

            # Set initial password
            echo "$username:$DEFAULT_PASSWORD" | chpasswd

            # Force password change on first login
            passwd -e "$username" 2>/dev/null

            log_info "Set default password for $username (will be forced to change)"
            created_count=$((created_count + 1))

            if [[ "$account_type" == "admin" ]]; then
                for group in sudo adm; do
                    if getent group "$group" &>/dev/null; then
                        if groups "$username" | grep -qw "$group"; then
                            continue
                        fi

                        if usermod -aG "$group" "$username" 2>/dev/null; then
                            log_success "Added $username to $group group"
                        else
                            log_error "Failed to add $username to $group group"
                        fi
                    fi
                done
            fi
        else
            log_error "Failed to create user: $username"
        fi
    done <<< "$hires_json"

    if [[ $created_count -gt 0 ]]; then
        log_success "Created $created_count user account(s)"
    fi

    return 0
}

# Add users to their groups
add_users_to_groups() {
    log_section "Adding Users to Groups"

    local changes_made=0

    # Process each authorized user and their groups
    while IFS= read -r username; do
        [[ -z "$username" ]] && continue

        # Skip if user doesn't exist
        if ! user_exists "$username"; then
            continue
        fi

        # Get groups for this user
        while IFS= read -r groupname; do
            [[ -z "$groupname" ]] && continue

            # Skip if group doesn't exist
            if ! group_exists "$groupname"; then
                log_warn "Group $groupname doesn't exist for user $username"
                continue
            fi

            # Check if user is already in group
            if groups "$username" | grep -q "\b$groupname\b"; then
                log_debug "User $username already in group $groupname"
            else
                log_info "Adding $username to group $groupname"
                if usermod -aG "$groupname" "$username" 2>/dev/null; then
                    log_success "Added $username to group $groupname"
                    changes_made=$((changes_made + 1))
                else
                    log_error "Failed to add $username to group $groupname"
                fi
            fi
        done < <(get_user_groups "$username")
    done < <(get_authorized_users)

    # Also process groups_to_create and their members
    local groups_json=$(echo "$README_DATA" | jq -r '.groups_to_create[]? | @json')

    while IFS= read -r group_json; do
        [[ -z "$group_json" ]] && continue

        local entry_type=$(echo "$group_json" | jq -r 'type')
        local groupname=""

        if [[ "$entry_type" == "string" ]]; then
            groupname=$(echo "$group_json" | jq -r '.')
        else
            groupname=$(echo "$group_json" | jq -r '.name // empty')
        fi

        [[ -z "$groupname" || "$groupname" == "null" ]] && continue

        while IFS= read -r member; do
            [[ -z "$member" ]] && continue

            if ! user_exists "$member"; then
                log_warn "User $member doesn't exist for group $groupname"
                continue
            fi

            if groups "$member" | grep -q "\b$groupname\b"; then
                log_debug "User $member already in group $groupname"
            else
                log_info "Adding $member to group $groupname"
                if usermod -aG "$groupname" "$member" 2>/dev/null; then
                    log_success "Added $member to group $groupname"
                    changes_made=$((changes_made + 1))
                else
                    log_error "Failed to add $member to group $groupname"
                fi
            fi
        done <<< "$(echo "$group_json" | jq -r 'if type == "object" then .members[]? else empty end')"
    done <<< "$groups_json"

    if [[ $changes_made -eq 0 ]]; then
        log_info "All users are in correct groups"
    else
        log_success "Made $changes_made group membership change(s)"
    fi

    return 0
}

# Check for null/blank passwords
fix_null_passwords() {
    log_section "Checking for Null/Blank Passwords"

    local fixed_count=0
    local main_user=$(get_main_user)

    # Check shadow file for users with empty password field
    while IFS=: read -r username password_field _; do
        # Skip if username is empty
        [[ -z "$username" ]] && continue

        # Skip system accounts except root
        if is_system_account "$username" && [[ "$username" != "root" ]]; then
            continue
        fi

        # Check if password field is empty or just contains special markers
        if [[ -z "$password_field" ]] || [[ "$password_field" == "!" ]] || [[ "$password_field" == "*" ]]; then
            log_warn "User $username has no password set"

            # Set a password (skip main user as per requirements)
            if [[ "$username" != "$main_user" ]]; then
                echo "$username:$DEFAULT_PASSWORD" | chpasswd
                passwd -e "$username" 2>/dev/null  # Force change on login
                log_success "Set password for user: $username"
                fixed_count=$((fixed_count + 1))
            else
                log_warn "Skipping main user $username (don't change main user password)"
            fi
        fi
    done < /etc/shadow

    if [[ $fixed_count -eq 0 ]]; then
        log_info "No null passwords found"
    else
        log_success "Fixed $fixed_count null password(s)"
    fi

    return 0
}

# Enforce password policies
enforce_password_policies() {
    log_section "Enforcing Password Policies"

    local changes_made=0

    # Build a unified list of users to enforce policy on (all regular users and root)
    local target_users_list
    target_users_list=$( (
        if user_exists "root"; then
            echo "root"
        fi
        get_current_users
        get_authorized_users
    ) | sort -u )

    # Apply password policy to each target (skip system accounts except root)
    while IFS= read -r username; do
        [[ -z "$username" ]] && continue

        if [[ "$username" != "root" ]] && is_system_account "$username"; then
            continue
        fi

        # Skip if user doesn't exist
        if ! user_exists "$username"; then
            continue
        fi

        log_info "Setting password policy for: $username"

        # Set password aging
        # -M: max days, -m: min days, -W: warn days
        if chage -M "$PASSWORD_MAX_DAYS" -m "$PASSWORD_MIN_DAYS" -W "$PASSWORD_WARN_DAYS" "$username" 2>/dev/null; then
            log_success "Set password aging for $username (max: $PASSWORD_MAX_DAYS, min: $PASSWORD_MIN_DAYS, warn: $PASSWORD_WARN_DAYS)"
            changes_made=$((changes_made + 1))
        else
            log_error "Failed to set password policy for $username"
        fi

        # Ensure password expires (remove -1 which means never)
        chage -E -1 "$username" 2>/dev/null

    done <<< "$target_users_list" # Read from the sorted list variable

    if [[ $changes_made -gt 0 ]]; then
        log_success "Applied password policies to $changes_made user(s)"
    fi

    return 0
}

# Check password hashing algorithm
check_password_hashing() {
    log_section "Checking Password Hashing Algorithm"

    # Check what hashing algorithm is configured
    if [[ -f /etc/pam.d/common-password ]]; then
        if grep -q "pam_unix.so.*yescrypt" /etc/pam.d/common-password; then
            log_success "Password hashing is set to yescrypt (modern)"
        elif grep -q "pam_unix.so.*sha512" /etc/pam.d/common-password; then
            log_warn "Password hashing is set to SHA512; consider migrating to yescrypt"
        else
            log_warn "Password hashing may not be using a secure algorithm"
            log_info "Consider configuring yescrypt in /etc/pam.d/common-password"
        fi
    fi

    # Check /etc/login.defs
    if [[ -f /etc/login.defs ]]; then
        local encrypt_method=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}')
        if [[ "$encrypt_method" == "YESCRYPT" ]]; then
            log_success "ENCRYPT_METHOD in login.defs is set to $encrypt_method"
        elif [[ "$encrypt_method" == "SHA512" ]]; then
            log_warn "ENCRYPT_METHOD in login.defs is set to SHA512; consider updating to YESCRYPT"
        else
            log_warn "ENCRYPT_METHOD in login.defs is: ${encrypt_method:-not set}"
        fi
    fi

    return 0
}

# build_system_users_to_restrict
build_system_users_to_restrict() {
    # Use a subshell to group all output and pipe to sort -u
    (
        # Always include baseline system accounts that must be restricted
        for default_user in "${DEFAULT_SYSTEM_USERS_TO_RESTRICT[@]}"; do
            [[ -z "$default_user" ]] && continue
            echo "$default_user"
        done

        # Merge in any explicit README entries
        # This function is from readme_parser.sh and just echos users
        get_system_users_to_restrict 2>/dev/null || true
    ) | sort -u
}

# Disable password login for system users
disable_system_user_logins() {
    log_section "Disabling Login for System Users"

    local disabled_count=0

    # Get system users to restrict (defaults plus README entries)
    while IFS= read -r username; do
        [[ -z "$username" ]] && continue

        # Only process if it's a system account
        if ! is_system_account "$username"; then
            continue
        fi

        # Skip if user doesn't exist
        if ! user_exists "$username"; then
            continue
        fi

        log_info "Disabling login for system user: $username"

        # Lock the password
        usermod -L "$username" 2>/dev/null

        # Set shell to nologin
        usermod -s /usr/sbin/nologin "$username" 2>/dev/null

        log_success "Disabled password login for: $username"
        disabled_count=$((disabled_count + 1))
    done < <(build_system_users_to_restrict)

    if [[ $disabled_count -gt 0 ]]; then
        log_success "Disabled login for $disabled_count system user(s)"
    fi

    return 0
}

# Ensure ALL system accounts (including root) have nologin shells
ensure_system_accounts_nologin() {
    log_section "Ensuring All System Accounts Have Nologin Shells"

    local modified_count=0

    # Process all users with UID < 1000 (system accounts)
    while IFS=: read -r username _ uid _ _ _ current_shell; do
        # Skip if UID >= 1000 (regular users)
        [[ $uid -ge 1000 ]] && continue

        # Skip nobody (UID 65534)
        [[ $uid -eq 65534 ]] && continue

        # Check if shell is already nologin or false
        if [[ "$current_shell" == "/usr/sbin/nologin" ]] || [[ "$current_shell" == "/bin/false" ]]; then
            log_debug "User $username already has nologin shell"
            continue
        fi

        # NOTE: This enforces nologin even for root; adjust if your rules differ.
        if [[ "$username" == "root" ]]; then
             log_warn "Root user does not have a nologin shell. Enforcing policy."
        fi

        log_info "Setting nologin shell for system account: $username (UID: $uid, current shell: $current_shell)"

        # Set shell to nologin
        if usermod -s /usr/sbin/nologin "$username" 2>/dev/null; then
            log_success "Set nologin shell for: $username"
            modified_count=$((modified_count + 1))
        else
            log_error "Failed to set nologin shell for: $username"
        fi
    done < /etc/passwd

    if [[ $modified_count -eq 0 ]]; then
        log_info "All system accounts already have nologin shells"
    else
        log_success "Set nologin shell for $modified_count system account(s)"
    fi

    return 0
}

# Ensure all user accounts have matching UID:GID (primary group)
ensure_matching_uid_gid() {
    log_section "Ensuring User Accounts Have Matching UID:GID"

    local fixed_count=0

    # Process all users with UID >= 1000 (regular users)
    while IFS=: read -r username _ uid gid _ _ _; do
        # Skip if UID < 1000 (system accounts)
        [[ $uid -lt 1000 ]] && continue

        # Skip nobody (UID 65534)
        [[ $uid -eq 65534 ]] && continue

        # Skip if not an authorized user
        if ! is_user_authorized "$username"; then
            log_debug "Skipping unauthorized user: $username"
            continue
        fi

        # Check if UID matches GID
        if [[ $uid -eq $gid ]]; then
            log_debug "User $username has matching UID:GID ($uid:$gid)"
            continue
        fi

        log_warn "User $username has mismatched UID:GID ($uid:$gid)"

        # Check if a group with the same name as the user exists
        local user_group_gid=""
        if group_exists "$username"; then
            user_group_gid=$(getent group "$username" | cut -d: -f3)
            log_info "Group $username exists with GID: $user_group_gid"

            # If the group GID matches the UID, just change the user's primary group
            if [[ $user_group_gid -eq $uid ]]; then
                log_info "Setting primary group for $username to $username (GID: $user_group_gid)"
                if usermod -g "$username" "$username" 2>/dev/null; then
                    log_success "Updated primary group for $username to match UID"
                    fixed_count=$((fixed_count + 1))
                else
                    log_error "Failed to update primary group for $username"
                fi
            else
                log_warn "Group $username exists but has GID $user_group_gid (expected $uid)"
                log_info "Creating new group with matching UID:GID for $username"

                # Try to create a new group with GID matching UID
                local new_group="${username}_group"
                if ! group_exists "$new_group"; then
                    if groupadd -g "$uid" "$new_group" 2>/dev/null; then
                        log_success "Created group $new_group with GID $uid"
                        if usermod -g "$new_group" "$username" 2>/dev/null; then
                            log_success "Updated primary group for $username to $new_group"
                            fixed_count=$((fixed_count + 1))
                        fi
                    else
                        log_error "Failed to create group with GID $uid"
                    fi
                fi
            fi
        else
            # Group doesn't exist, create it with matching GID
            log_info "Creating group $username with GID $uid"
            if groupadd -g "$uid" "$username" 2>/dev/null; then
                log_success "Created group $username with GID $uid"
                if usermod -g "$username" "$username" 2>/dev/null; then
                    log_success "Updated primary group for $username"
                    fixed_count=$((fixed_count + 1))
                fi
            else
                log_error "Failed to create group $username with GID $uid (GID may be in use)"
            fi
        fi
    done < /etc/passwd

    if [[ $fixed_count -eq 0 ]]; then
        log_info "All user accounts already have matching UID:GID"
    else
        log_success "Fixed $fixed_count user account(s) to have matching UID:GID"
    fi

    return 0
}

# Verify user account shells are properly configured
verify_user_account_shells() {
    log_section "Verifying User Account Shells"

    local fixed_count=0

    # Process all users with UID >= 1000 (regular users)
    while IFS=: read -r username _ uid _ _ _ current_shell; do
        # Skip if UID < 1000 (system accounts)
        [[ $uid -lt 1000 ]] && continue

        # Skip nobody (UID 65534)
        [[ $uid -eq 65534 ]] && continue

        # Skip if not an authorized user
        if ! is_user_authorized "$username"; then
            log_debug "Skipping unauthorized user: $username"
            continue
        fi

        # Check if shell is valid and appropriate for a user account
        case "$current_shell" in
            /bin/bash|/bin/sh|/bin/dash|/bin/zsh|/usr/bin/zsh|/bin/ksh|/usr/bin/fish)
                log_debug "User $username has valid shell: $current_shell"
                ;;
            /usr/sbin/nologin|/bin/false)
                log_warn "User $username has nologin shell but is an authorized user"
                log_info "Setting shell to /bin/bash for $username"
                if usermod -s /bin/bash "$username" 2>/dev/null; then
                    log_success "Set shell to /bin/bash for $username"
                    fixed_count=$((fixed_count + 1))
                fi
                ;;
            *)
                log_warn "User $username has non-standard shell: $current_shell"
                log_info "Setting shell to /bin/bash for $username"
                if usermod -s /bin/bash "$username" 2>/dev/null; then
                    log_success "Set shell to /bin/bash for $username"
                    fixed_count=$((fixed_count + 1))
                fi
                ;;
        esac
    done < /etc/passwd

    if [[ $fixed_count -eq 0 ]]; then
        log_info "All user account shells are properly configured"
    else
        log_success "Fixed $fixed_count user account shell(s)"
    fi

    return 0
}

# Main module execution
run_user_auditing() {
    log_section "User Auditing Module"

    # Ensure README is parsed
    if [[ $README_PARSED -eq 0 ]]; then
        log_warn "README not parsed, parsing now..."
        parse_readme || {
            log_error "Failed to parse README"
            return 1
        }
    fi

    # Log the AI output for debugging
    local parsed_json_file="$SCRIPT_DIR/../data/readme_parsed.json"
    if [[ -f "$parsed_json_file" ]]; then
        log_debug "--- AI PARSER OUTPUT START ---"
        # Log the file content, using jq to format it if possible
        if command -v jq >/dev/null; then
            log_debug "$(jq . "$parsed_json_file")"
        else
            log_debug "$(cat "$parsed_json_file")"
        fi
        log_debug "--- AI PARSER OUTPUT END ---"
    else
        log_warn "Could not find parsed JSON file to log"
    fi

    # Run all auditing functions
    disable_guest_account
    fix_root_uid_users                # Fix any non-root users with UID 0 (MUST run early)
    remove_unauthorized_users
    remove_hidden_users
    handle_system_users
    manage_admin_privileges
    create_groups
    create_missing_users
    add_users_to_groups
    fix_null_passwords
    enforce_password_policies
    check_password_hashing
    disable_system_user_logins

    # New comprehensive user auditing functions
    ensure_system_accounts_nologin    # Ensure all system accounts (including root) have nologin
    ensure_matching_uid_gid           # Ensure all user accounts have matching UID:GID
    verify_user_account_shells        # Verify user account shells are properly configured

    log_section "User Auditing Complete"
    log_success "All user auditing tasks completed"

    return 0
}

export -f run_user_auditing
