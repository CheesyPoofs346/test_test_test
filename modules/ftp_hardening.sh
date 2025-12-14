#!/bin/bash
# ftp_hardening.sh - FTP service hardening module
# Applies secure baseline configuration for vsftpd or ProFTPD.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"

readonly FTP_ALT_PORT="${FTP_ALT_PORT:-2121}"
readonly FTP_PASSIVE_MIN="${FTP_PASSIVE_MIN:-40000}"
readonly FTP_PASSIVE_MAX="${FTP_PASSIVE_MAX:-50000}"
readonly FTP_CERT_PATH="${FTP_CERT_PATH:-/etc/ssl/certs/ssl-cert-snakeoil.pem}"
readonly FTP_KEY_PATH="${FTP_KEY_PATH:-/etc/ssl/private/ssl-cert-snakeoil.key}"

# Detect configuration files
vsftpd_config_path() {
    local candidates=(
        "/etc/vsftpd.conf"
        "/etc/vsftpd/vsftpd.conf"
    )

    for file in "${candidates[@]}"; do
        if [[ -f "$file" ]]; then
            echo "$file"
            return 0
        fi
    done

    return 1
}

proftpd_config_path() {
    local candidates=(
        "/etc/proftpd/proftpd.conf"
        "/etc/proftpd.conf"
    )

    for file in "${candidates[@]}"; do
        if [[ -f "$file" ]]; then
            echo "$file"
            return 0
        fi
    done

    return 1
}

filter_comments_only() {
    awk '/^\s*#/ || /^\s*$/' "$1"
}

apply_vsftpd_hardening() {
    local config="$1"

    log_section "Hardening vsftpd ($config)"
    backup_file "$config"

    local tmp
    tmp="$(mktemp)"
    filter_comments_only "$config" > "$tmp"

    cat <<CONF >> "$tmp"

# === CyberPatriot FTP Hardening (auto) ===
listen=YES
listen_ipv6=NO
listen_port=${FTP_ALT_PORT}

# Identity
ftpd_banner=FTP server ready.

# Users
anonymous_enable=NO
local_enable=YES
write_enable=NO
chroot_local_user=YES
allow_writeable_chroot=NO
hide_ids=YES

# Run unprivileged
nopriv_user=nobody

# Logging
xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES

# Passive mode
pasv_enable=YES
pasv_min_port=${FTP_PASSIVE_MIN}
pasv_max_port=${FTP_PASSIVE_MAX}
pasv_promiscuous=NO
port_promiscuous=NO

# TLS
ssl_enable=YES
require_ssl_reuse=NO
force_local_logins_ssl=YES
force_local_data_ssl=YES
allow_anon_ssl=NO
ssl_tlsv1=NO
ssl_sslv2=NO
ssl_sslv3=NO
ssl_ciphers=HIGH
rsa_cert_file=${FTP_CERT_PATH}
rsa_private_key_file=${FTP_KEY_PATH}

# PAM
pam_service_name=vsftpd
CONF

    cat "$tmp" > "$config"
    rm -f "$tmp"

    chmod 600 "$config"
    chown root:root "$config"

    log_success "vsftpd configuration hardened"
    log_score 2 "Hardened vsftpd configuration"
}

apply_proftpd_hardening() {
    local config="$1"

    log_section "Hardening ProFTPD ($config)"
    backup_file "$config"

    local tmp
    tmp="$(mktemp)"
    filter_comments_only "$config" > "$tmp"

    cat <<CONF >> "$tmp"

# === CyberPatriot FTP Hardening (auto) ===
ServerName "FTP server"
ServerType standalone
DefaultServer on
UseIPv6 off
Port ${FTP_ALT_PORT}
Umask 077 077
MaxInstances 20
RequireValidShell on
RootLogin off
AllowOverwrite off
AllowRetrieveRestart off
AllowStoreRestart off
DefaultRoot ~
PassivePorts ${FTP_PASSIVE_MIN} ${FTP_PASSIVE_MAX}
TimesGMT off
IdentLookups off
UseReverseDNS off
TransferLog /var/log/proftpd/transfer.log
LogFormat default "%h %l %u %t \"%r\" %s %b"
ExtendedLog /var/log/proftpd/proftpd.log ALL default

<Limit WRITE>
  DenyAll
</Limit>

<IfModule mod_auth_pam.c>
  AuthPAMConfig proftpd
  AuthOrder mod_auth_pam.c mod_auth_unix.c
</IfModule>

<IfModule mod_sftp.c>
  SFTPEngine off
</IfModule>

<IfModule mod_tls.c>
  TLSEngine on
  TLSLog /var/log/proftpd/tls.log
  TLSProtocol TLSv1.2 TLSv1.3
  TLSCipherSuite HIGH
  TLSOptions NoCertRequest NoSessionReuseRequired
  TLSRSACertificateFile ${FTP_CERT_PATH}
  TLSRSACertificateKeyFile ${FTP_KEY_PATH}
  TLSVerifyClient off
  TLSRequired on
</IfModule>
CONF

    cat "$tmp" > "$config"
    rm -f "$tmp"

    chmod 600 "$config"
    chown root:root "$config"

    log_success "ProFTPD configuration hardened"
    log_score 2 "Hardened ProFTPD configuration"
}

restart_service_if_present() {
    local svc="$1"

    if command_exists systemctl && systemctl list-unit-files | grep -q "^${svc}\.service"; then
        if systemctl is-enabled "$svc" >/dev/null 2>&1 || systemctl is-active "$svc" >/dev/null 2>&1; then
            systemctl restart "$svc" >/dev/null 2>&1 && log_success "Restarted ${svc}.service"
        fi
    elif command_exists service; then
        service "$svc" restart >/dev/null 2>&1 && log_success "Restarted $svc"
    fi
}

run_ftp_hardening() {
    require_root

    local vsftpd_conf proftpd_conf
    local hardened_any=0

    if vsftpd_conf=$(vsftpd_config_path); then
        apply_vsftpd_hardening "$vsftpd_conf"
        restart_service_if_present vsftpd
        hardened_any=1
    fi

    if proftpd_conf=$(proftpd_config_path); then
        apply_proftpd_hardening "$proftpd_conf"
        restart_service_if_present proftpd
        hardened_any=1
    fi

    if [[ $hardened_any -eq 0 ]]; then
        log_warn "No vsftpd or ProFTPD configuration found. Skipping."
        return 1
    fi

    return 0
}
