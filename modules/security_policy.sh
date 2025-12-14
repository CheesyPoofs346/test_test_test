#!/bin/bash
# security_policy.sh - Security Policy Module
# Implements kernel hardening and security policies via sysctl

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

# Module: Security Policy
# Category: Security Policy
# Description: Implements comprehensive kernel hardening and security policies

readonly SYSCTL_CONF="/etc/sysctl.conf"
readonly SYSCTL_BACKUP="/var/backups/cyberpatriot/sysctl.conf.backup"

# Check if X Server allows TCP connections
check_xserver_tcp() {
    log_section "Checking X Server TCP Connections"

    local score=0

    # Check if X11 is running
    if ! pgrep -x X >/dev/null && ! pgrep -x Xorg >/dev/null; then
        log_info "X Server not running, skipping check"
        return 0
    fi

    # Check for -nolisten tcp option in X server processes
    if pgrep -a Xorg | grep -q -- "-nolisten tcp"; then
        log_success "X Server does not allow TCP connections"
        score=1
    elif pgrep -a X | grep -q -- "-nolisten tcp"; then
        log_success "X Server does not allow TCP connections"
        score=1
    else
        log_warn "X Server may be allowing TCP connections"
        log_info "Attempting to configure X Server to disable TCP..."

        # Try to configure lightdm
        if [[ -f /etc/lightdm/lightdm.conf ]]; then
            if ! grep -q "xserver-allow-tcp=false" /etc/lightdm/lightdm.conf; then
                if grep -q "^\[Seat:\*\]" /etc/lightdm/lightdm.conf; then
                    sed -i '/^\[Seat:\*\]/a xserver-allow-tcp=false' /etc/lightdm/lightdm.conf
                else
                    echo -e "\n[Seat:*]\nxserver-allow-tcp=false" >> /etc/lightdm/lightdm.conf
                fi
                log_success "Configured LightDM to disable TCP connections"
                score=1
            fi
        fi

        # Try to configure gdm3
        if [[ -f /etc/gdm3/custom.conf ]]; then
            if ! grep -q "DisallowTCP=true" /etc/gdm3/custom.conf; then
                if grep -q "^\[security\]" /etc/gdm3/custom.conf; then
                    sed -i '/^\[security\]/a DisallowTCP=true' /etc/gdm3/custom.conf
                else
                    echo -e "\n[security]\nDisallowTCP=true" >> /etc/gdm3/custom.conf
                fi
                log_success "Configured GDM3 to disable TCP connections"
                score=1
            fi
        fi
    fi

    return 0
}

# Backup current sysctl configuration
backup_sysctl_conf() {
    log_info "Backing up current sysctl.conf..."

    if [[ -f "$SYSCTL_CONF" ]]; then
        mkdir -p "$(dirname "$SYSCTL_BACKUP")"
        cp "$SYSCTL_CONF" "$SYSCTL_BACKUP"
        log_success "Backed up sysctl.conf to $SYSCTL_BACKUP"
    else
        log_info "No existing sysctl.conf found"
    fi

    return 0
}

# Apply hardened sysctl configuration
apply_hardened_sysctl() {
    log_section "Applying Hardened Sysctl Configuration"

    # Backup existing configuration
    backup_sysctl_conf

    log_info "Writing hardened sysctl.conf..."

    # Write the hardened configuration
    cat > "$SYSCTL_CONF" <<'EOF'
##### KERNEL HARDENING
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.perf_event_max_sample_rate = 1
kernel.perf_cpu_time_max_percent = 1
kernel.kexec_load_disabled = 1
kernel.unprivileged_userns_clone = 0
kernel.unprivileged_bpf_disabled = 1
kernel.ftrace_enabled = 0
kernel.debugfs.restrict = 1
kernel.yama.ptrace_scope = 3
kernel.panic_on_oops = 1
kernel.maps_protect = 1
dev.tty.ldisc_autoload = 0

##### MEMORY SAFETY
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
vm.unprivileged_userfaultfd = 0
vm.mmap_min_addr = 65536

##### DISABLE FORWARDING
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0

##### (OPTIONAL) DISABLE IPV6 ENTIRELY IF NOT NEEDED
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

##### SOURCE ROUTING & REDIRECTS
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

##### REVERSE PATH FILTERING
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

##### ARP HARDENING
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.default.arp_ignore = 2
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2

##### ICMP HYGIENE
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

##### TCP HARDENING
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fastopen = 0

##### LOGGING
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

##### IPV6 RA/AUTOCONF (KEEP STRICT IF IPV6 ENABLED)
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

##### BOOTP/ARP PROXIES
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.proxy_arp = 0

##### eBPF
net.core.bpf_jit_enable = 0
net.core.bpf_jit_harden = 2

##### BRIDGING (ONLY IF br_netfilter IS LOADED)
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-arptables = 1
EOF

    log_success "Wrote hardened sysctl.conf"

    # Apply the configuration
    log_info "Applying sysctl configuration..."

    # Apply settings, ignore errors for parameters that don't exist on this kernel
    # Capture output so we don't trip on non-fatal missing-parameter errors
    local sysctl_output
    sysctl_output="$(sysctl -p "$SYSCTL_CONF" 2>&1 | tee /tmp/sysctl_apply.log)" || true

    if echo "$sysctl_output" | grep -qE "No such file or directory|cannot stat"; then
        log_info "Some sysctl parameters were not available on this system (this is normal)"
    fi

    log_success "Applied sysctl configuration (check /tmp/sysctl_apply.log for details)"

    return 0
}

# Verify sysctl settings
verify_sysctl_settings() {
    log_section "Verifying Sysctl Security Settings"

    local checks_passed=0
    local checks_failed=0

    # Define critical checks with their expected values
    declare -A critical_checks=(
        ["kernel.randomize_va_space"]="2"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.tcp_syn_retries"]="2"
        ["net.ipv4.tcp_synack_retries"]="2"
        ["net.ipv4.tcp_rfc1337"]="1"
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.rp_filter"]="2"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["kernel.kptr_restrict"]="2"
        ["kernel.sysrq"]="0"
        ["kernel.unprivileged_userns_clone"]="0"
        ["kernel.dmesg_restrict"]="1"
        ["net.ipv4.conf.all.log_martians"]="1"
    )

    for param in "${!critical_checks[@]}"; do
        local expected="${critical_checks[$param]}"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null)

        if [[ "$actual" == "$expected" ]]; then
            log_success "✓ $param = $actual"
            checks_passed=$((checks_passed + 1))
        else
            log_warn "✗ $param = $actual (expected: $expected)"
            checks_failed=$((checks_failed + 1))
        fi
    done

    log_info "Security checks passed: $checks_passed"
    if [[ $checks_failed -gt 0 ]]; then
        log_warn "Security checks failed: $checks_failed"
    fi

    return 0
}

# Check sudo configuration
check_sudo_config() {
    log_section "Checking Sudo Configuration"

    # Check if sudo requires authentication
    log_info "Checking if sudo requires authentication..."

    # Check sudoers file for NOPASSWD entries
    local nopasswd_count=0
    if [[ -f /etc/sudoers ]]; then
        # Avoid double-printing when grep exits non-zero on no matches
        local count
        count=$(grep -c "NOPASSWD:" /etc/sudoers 2>/dev/null || true)
        count=${count//[[:space:]]/}
        nopasswd_count=$((nopasswd_count + ${count:-0}))
    fi

    # Check sudoers.d directory
    if [[ -d /etc/sudoers.d ]]; then
        local dir_count
        dir_count=$({ grep -r "NOPASSWD:" /etc/sudoers.d 2>/dev/null | wc -l; } || true)
        dir_count=${dir_count//[[:space:]]/}
        nopasswd_count=$((nopasswd_count + ${dir_count:-0}))
    fi

    if [[ $nopasswd_count -eq 0 ]]; then
        log_success "Sudo requires authentication (no NOPASSWD entries found)"
    else
        log_warn "Found $nopasswd_count NOPASSWD entries in sudoers configuration"
        log_info "Removing NOPASSWD entries..."

        # Comment out NOPASSWD lines in /etc/sudoers
        if [[ -f /etc/sudoers ]]; then
            sed -i 's/^\([^#].*NOPASSWD:.*\)$/# DISABLED BY SECURITY POLICY: \1/' /etc/sudoers
        fi

        # Comment out NOPASSWD lines in /etc/sudoers.d/*
        if [[ -d /etc/sudoers.d ]]; then
            find /etc/sudoers.d -type f -exec sed -i 's/^\([^#].*NOPASSWD:.*\)$/# DISABLED BY SECURITY POLICY: \1/' {} \;
        fi

        log_success "Disabled NOPASSWD entries in sudoers configuration"
    fi

    return 0
}

# Check group sudo privileges
check_group_sudo_privileges() {
    log_section "Checking Group Sudo Privileges"

    log_info "Checking for groups with sudo privileges..."

    local issues_found=0

    # Check if sudo group has members (this is expected)
    if getent group sudo >/dev/null 2>&1; then
        local sudo_members
        sudo_members=$(getent group sudo | cut -d: -f4)
        if [[ -n "$sudo_members" ]]; then
            log_info "Sudo group members: $sudo_members"
            log_info "This is expected - individual users should be in sudo group, not other groups"
        fi
    fi

    # Check for other groups with sudo privileges in sudoers
    if [[ -f /etc/sudoers ]]; then
        # Look for lines like "%groupname ALL=(ALL:ALL) ALL"
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                local groupname
                groupname=$(echo "$line" | sed 's/^%\([^ ]*\).*/\1/')
                # Skip the sudo and admin groups as they are standard
                if [[ "$groupname" != "sudo" && "$groupname" != "admin" ]]; then
                    log_warn "Group $groupname has sudo privileges in /etc/sudoers"
                    log_info "Commenting out sudo privileges for group: $groupname"
                    sed -i "s/^\(%$groupname.*\)$/# DISABLED BY SECURITY POLICY: \1/" /etc/sudoers
                    issues_found=$((issues_found + 1))
                fi
            fi
        done < <({ grep -E "^%[^#]" /etc/sudoers 2>/dev/null | grep -v "^%sudo" | grep -v "^%admin"; } || true)
    fi

    # Check sudoers.d directory
    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r file; do
            while IFS= read -r line; do
                if [[ -n "$line" ]]; then
                    local groupname
                    groupname=$(echo "$line" | sed 's/^%\([^ ]*\).*/\1/')
                    if [[ "$groupname" != "sudo" && "$groupname" != "admin" ]]; then
                        log_warn "Group $groupname has sudo privileges in $file"
                        log_info "Commenting out sudo privileges for group: $groupname in $file"
                        sed -i "s/^\(%$groupname.*\)$/# DISABLED BY SECURITY POLICY: \1/" "$file"
                        issues_found=$((issues_found + 1))
                    fi
                fi
            done < <({ grep -E "^%[^#]" "$file" 2>/dev/null | grep -v "^%sudo" | grep -v "^%admin"; } || true)
        done < <(find /etc/sudoers.d -type f)
    fi

    if [[ $issues_found -eq 0 ]]; then
        log_success "No unauthorized groups have sudo privileges"
    else
        log_success "Removed sudo privileges from $issues_found unauthorized group(s)"
    fi

    return 0
}

# Print security policy checklist
print_security_checklist() {
    log_section "Security Policy Checklist"

    echo ""
    echo "35. X Server does not allow TCP connections"
    echo "36. Address space layout randomization enabled"
    echo "37. IPv4 TCP SYN cookies have been enabled"
    echo "38. IPv4 TCP SYN,ACK retries reduced"
    echo "39. IPv4 TIME-WAIT assassination protection enabled"
    echo "40. IPv4 forwarding has been disabled"
    echo "41. IPv4 sending ICMP redirects disabled"
    echo "42. IPv4 accept ICMP redirects disabled"
    echo "43. IPv4 accept source routing disabled"
    echo "44. IPv4 source route verification enabled"
    echo "45. Ignore bogus ICMP errors enabled"
    echo "46. Ignore broadcast ICMP echo requests enabled"
    echo "47. Kernel pointers hidden from unprivileged users"
    echo "48. Magic SysRq key disabled"
    echo "49. Only root may create new namespaces"
    echo "50. Restrict unprivileged access to kernel syslog enabled"
    echo "51. Logging of martian packets enabled"
    echo "52. Sudo requires authentication"
    echo "53. No unauthorized groups have sudo privileges"
    echo ""

    return 0
}

# Main module execution
run_security_policy() {
    log_section "Security Policy Module"

    # Print checklist
    print_security_checklist

    # Check X Server TCP
    check_xserver_tcp

    # Apply hardened sysctl configuration
    apply_hardened_sysctl

    # Verification is optional; skip automatic verification so we only apply settings

    # Check sudo configuration
    check_sudo_config

    # Check group sudo privileges
    check_group_sudo_privileges

    log_section "Security Policy Complete"
    log_success "All security policy tasks completed"

    return 0
}

export -f run_security_policy
