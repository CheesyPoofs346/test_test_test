#!/bin/bash
# cp-engine.sh - CyberPatriot Linux Remediation Engine
# Main script that orchestrates all security modules

set -euo pipefail

# Get engine directory (stable even after sourcing modules that define SCRIPT_DIR)
ENGINE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ENGINE_DIR

# Load core libraries
source "$ENGINE_DIR/lib/utils.sh"
source "$ENGINE_DIR/lib/openrouter.sh"

# Default settings
SCORE_FILE="${SCORE_FILE:-/var/log/cyberpatriot/score.log}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/cyberpatriot}"

# All available modules (populated dynamically)
MODULES=()

# Preferred module execution order to avoid conflicts and redundant work
DESIRED_MODULE_ORDER=(
    dependencies
    readme_parser
    forensics_questions
    os_updates
    user_auditing
    account_policy
    local_policy
    security_policy
    ssh_hardening
    ftp_hardening
    postgres_hardening
    samba_hardening
    mysql_hardening
    php_hardening
    nginx_hardening
    apache_hardening
    service_auditing
    unwanted_software
    malware
    prohibited_files
    defensive_countermeasures
    os_settings
)

# Remove common formatting issues from module identifiers
sanitize_module_name() {
    local raw="$1"

    # Strip carriage returns that can show up when archives are extracted on Windows
    raw="${raw//$'\r'/}"

    # Use sed to trim leading/trailing whitespace without altering interior spacing
    raw="$(printf '%s' "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

    printf '%s' "$raw"
}

# Discover modules present in the modules directory
discover_modules() {
    MODULES=()

    if [[ ! -d "$ENGINE_DIR/modules" ]]; then
        log_error "Modules directory not found: $ENGINE_DIR/modules"
        return 1
    fi

    local available_modules=()
    while IFS= read -r module_path; do
        local module_name
        module_name="$(basename "$module_path" .sh)"
        module_name="$(sanitize_module_name "$module_name")"

        [[ -n "$module_name" ]] && available_modules+=("$module_name")
    done < <(find "$ENGINE_DIR/modules" -maxdepth 1 -type f -name '*.sh' -print)

    # Track which modules have already been added to avoid duplicates
    declare -A added_modules=()

    for preferred in "${DESIRED_MODULE_ORDER[@]}"; do
        for candidate in "${available_modules[@]}"; do
            if [[ "$preferred" == "$candidate" && -z "${added_modules[$candidate]:-}" ]]; then
                MODULES+=("$candidate")
                added_modules[$candidate]=1
                break
            fi
        done
    done

    # Append any remaining modules not in the preferred list, sorted for stability
    local remaining=()
    for candidate in "${available_modules[@]}"; do
        if [[ -z "${added_modules[$candidate]:-}" ]]; then
            remaining+=("$candidate")
            added_modules[$candidate]=1
        fi
    done

    if [[ ${#remaining[@]} -gt 0 ]]; then
        IFS=$'\n' remaining=($(printf '%s\n' "${remaining[@]}" | sort))
        unset IFS
        MODULES+=("${remaining[@]}")
    fi

    return 0
}

# Ensure module scripts are executable so they can be sourced reliably
ensure_module_permissions() {
    if [[ ! -d "$ENGINE_DIR/modules" ]]; then
        log_warn "Modules directory not found when ensuring permissions"
        return
    fi

    while IFS= read -r module_script; do
        if [[ -f "$module_script" && ! -x "$module_script" ]]; then
            if chmod +x "$module_script"; then
                log_debug "Set executable permission on $(basename "$module_script")"
            else
                log_warn "Failed to set executable permission on $module_script"
            fi
        fi
    done < <(find "$ENGINE_DIR/modules" -maxdepth 1 -type f -name '*.sh')
}

# Load configuration (only API key, model, and LOG_LEVEL)
CONFIG_FILE="$ENGINE_DIR/config.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
    log_debug "Loaded configuration from: $CONFIG_FILE"
else
    log_warn "Configuration file not found: $CONFIG_FILE"
    log_warn "Using default settings"
fi

# Ensure module scripts are ready and build the module list dynamically
ensure_module_permissions
if ! discover_modules; then
    log_error "Failed to discover modules"
    exit 1
fi

# Banner
show_banner() {
    echo -e "${COLOR_BOLD}${COLOR_CYAN}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║   CyberPatriot Linux Auto-Remediation Engine                 ║
║   Version 1.0.0                                              ║
║   Supported: Linux Mint 21, Ubuntu 24                        ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${COLOR_RESET}"
}

# Check system compatibility
check_system() {
    log_section "System Check"

    local os=$(detect_os)
    local version=$(detect_os_version)

    log_info "Operating System: $os"
    log_info "OS Version: $version"

    if ! is_supported_os; then
        log_warn "This OS may not be fully supported"
        log_warn "Supported: Linux Mint 21.x, Ubuntu 24.x"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        log_success "OS is supported"
    fi
}

# Repair APT sources for supported distributions without touching /etc/apt/sources.list
repair_apt_sources() {
    log_section "Repairing APT Sources"

    local os
    os=$(detect_os)
    local version
    version=$(detect_os_version)

    log_info "Detected OS: $os $version"

    # Use VERSION_CODENAME when available to avoid relying on lsb_release
    local codename=""
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        codename=${VERSION_CODENAME:-}
    fi

    if [[ "$os" == "linuxmint" && "$version" == "21"* ]]; then
        local repo_file="/etc/apt/sources.list.d/official-package-repositories.list"

        [[ -f "$repo_file" ]] && backup_file "$repo_file"

        cat <<'EOF' | tee "$repo_file" >/dev/null
deb http://packages.linuxmint.com virginia main upstream import backport

deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-backports main restricted universe multiverse

deb http://security.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse
EOF

        log_success "Linux Mint 21 APT sources repaired in $repo_file"

    elif [[ "$os" == "ubuntu" && "$version" == "24."* ]]; then
        local repo_file="/etc/apt/sources.list.d/ubuntu.list"
        codename=${codename:-$(lsb_release -cs 2>/dev/null || echo noble)}

        [[ -f "$repo_file" ]] && backup_file "$repo_file"

        cat <<EOF | tee "$repo_file" >/dev/null
deb http://archive.ubuntu.com/ubuntu $codename main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-security main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $codename-backports main universe restricted multiverse
EOF

        log_success "Ubuntu 24 APT sources repaired in $repo_file"

    else
        log_warn "Skipping APT source repair on unsupported OS: $os $version"
        return 0
    fi

    if apt-get update -qq; then
        log_success "APT package lists refreshed"
    else
        log_warn "Failed to refresh package lists after repairing sources"
    fi
}

# Update locate database for forensics module
update_locate_database() {
    log_section "Updating Locate Database"

    if ! command_exists updatedb; then
        log_warn "updatedb not found; skipping locate database update"
        return 0
    fi

    log_info "Updating locate database for file searches..."
    if updatedb 2>/dev/null; then
        log_success "Locate database updated successfully"
    else
        log_warn "Failed to update locate database (non-critical)"
    fi
}

# Check dependencies
check_deps() {
    log_section "Dependency Check"

    local required_deps=("sed" "awk" "grep")
    local optional_deps=("clamav" "rkhunter" "lynis")

    log_info "Checking required dependencies..."
    if check_dependencies "${required_deps[@]}"; then
        log_success "All required dependencies installed"
    else
        log_error "Missing required dependencies. Please install them and try again."
        exit 1
    fi

    log_info "Checking optional dependencies..."
    for dep in "${optional_deps[@]}"; do
        if command_exists "$dep"; then
            log_success "  $dep: installed"
        else
            log_warn "  $dep: not installed (optional)"
        fi
    done
}

# Load a module
load_module() {
    local module_name
    module_name="$(sanitize_module_name "$1")"
    local module_path="$ENGINE_DIR/modules/${module_name}.sh"

    if [[ ! -f "$module_path" ]]; then
        # Attempt a case-insensitive search as a fallback in case the filesystem changed
        local fallback_path
        fallback_path=$(find "$ENGINE_DIR/modules" -maxdepth 1 -type f -iname "${module_name}.sh" -print -quit 2>/dev/null || true)

        if [[ -n "$fallback_path" && -f "$fallback_path" ]]; then
            log_warn "Module $module_name not found with exact name, using $(basename "$fallback_path") instead"
            module_path="$fallback_path"
        else
            log_error "Module not found: $module_name (looked for $module_path)"
            return 1
        fi
    fi

    log_debug "Loading module: $module_name"
    local had_nounset=0
    if [[ $- == *u* ]]; then
        had_nounset=1
        set +u
    fi

    # shellcheck source=/dev/null
    source "$module_path"
    local source_status=$?

    if (( had_nounset )); then
        set -u
    fi

    if [[ $source_status -ne 0 ]]; then
        log_error "Failed to load module script: $module_path"
        return $source_status
    fi
    return 0
}

# Run a module
run_module() {
    local module_name="$1"

    log_section "Running Module: $module_name"

    # Load module if not already loaded
    if ! declare -f "run_${module_name}" >/dev/null 2>&1; then
        if ! load_module "$module_name"; then
            log_error "Failed to load module: $module_name"
            return 1
        fi
    fi

    # Check if module has run function
    if ! declare -f "run_${module_name}" >/dev/null 2>&1; then
        log_warn "Module $module_name does not have a run_${module_name} function"
        return 1
    fi

    # Run the module
    local start_time=$(date +%s)
    local had_nounset=0
    if [[ $- == *u* ]]; then
        had_nounset=1
        set +u
    fi

    "run_${module_name}"
    local exit_code=$?

    if (( had_nounset )); then
        set -u
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    if [[ $exit_code -eq 0 ]]; then
        log_success "Module $module_name completed successfully (${duration}s)"
    else
        log_error "Module $module_name failed with exit code $exit_code (${duration}s)"
    fi

    return $exit_code
}

# Run all enabled modules
run_all_modules() {
    log_section "Running All Modules"

    local failed_modules=()
    local successful_modules=()

    for module in "${MODULES[@]}"; do
        # Skip comments
        [[ "$module" =~ ^#.*$ ]] && continue

        if run_module "$module"; then
            successful_modules+=("$module")
        else
            failed_modules+=("$module")
        fi
    done

    log_section "Execution Summary"
    log_info "Successful modules: ${#successful_modules[@]}"
    for module in "${successful_modules[@]}"; do
        log_success "  ✓ $module"
    done

    if [[ ${#failed_modules[@]} -gt 0 ]]; then
        log_info "Failed modules: ${#failed_modules[@]}"
        for module in "${failed_modules[@]}"; do
            log_error "  ✗ $module"
        done
    fi
}

# Interactive mode
interactive_mode() {
    log_section "Interactive Mode"

    while true; do
        echo
        echo "Available modules:"
        local i=1
        for module in "${MODULES[@]}"; do
            echo "  $i) $module"
            i=$((i + 1))
        done
        echo "  a) Run all modules"
        echo "  q) Quit"
        echo

        read -p "Select module to run: " choice

        if [[ "$choice" == "q" ]]; then
            log_info "Exiting interactive mode"
            exit 0
        elif [[ "$choice" == "a" ]]; then
            run_all_modules
            echo
            read -p "Run another module? (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Exiting interactive mode"
                exit 0
            fi
            continue
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#MODULES[@]} ]]; then
            local selected_module="${MODULES[$((choice-1))]}"
            run_module "$selected_module"

            echo
            read -p "Run another module? (y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Exiting interactive mode"
                exit 0
            fi
        else
            log_error "Invalid selection"
        fi
    done
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  -h, --help              Show this help message
  -i, --interactive       Run in interactive mode
  -m, --module MODULE     Run a specific module
  -a, --all               Run all enabled modules (default)
  -l, --list              List available modules
  -t, --test              Test OpenRouter API connection
  -c, --check             Check system and dependencies only

Modules:
$(for module in "${MODULES[@]}"; do echo "  - $module"; done)

Examples:
  $0                      # Run all modules
  $0 -m user_auditing     # Run user auditing module only
  $0 -i                   # Interactive mode
  $0 -t                   # Test API connection

Configuration:
  Edit config.conf to set your OpenRouter API key, model, and log level
EOF
}

# Main function
main() {
    local mode="all"
    local selected_module=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_usage
                exit 0
                ;;
            -i|--interactive)
                mode="interactive"
                shift
                ;;
            -m|--module)
                mode="single"
                selected_module="$2"
                shift 2
                ;;
            -a|--all)
                mode="all"
                shift
                ;;
            -l|--list)
                echo "Available modules:"
                for module in "${MODULES[@]}"; do
                    echo "  - $module"
                done
                exit 0
                ;;
            -t|--test)
                show_banner
                test_openrouter
                exit $?
                ;;
            -c|--check)
                show_banner
                check_system
                check_deps
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Show banner
    show_banner

    # Check root privileges
    require_root

    # Check system
    check_system

    # Repair APT sources early to ensure package operations succeed
    repair_apt_sources

    # Update locate database for forensics module
    update_locate_database

    # Check dependencies
    check_deps

    # Create necessary directories
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$(dirname "$SCORE_FILE")"
    mkdir -p "$ENGINE_DIR/data"

    # Ensure all module scripts are executable before running them
    ensure_module_permissions

    # Run based on mode
    case "$mode" in
        all)
            run_all_modules
            ;;
        single)
            run_module "$selected_module"
            ;;
        interactive)
            interactive_mode
            ;;
    esac

    log_section "Complete"
    log_success "CyberPatriot remediation engine finished"
    log_info "Check score log: $SCORE_FILE"
}

# Run main function
main "$@"
