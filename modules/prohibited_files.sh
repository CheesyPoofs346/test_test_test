#!/bin/bash
# prohibited_files.sh - Prohibited Files Module
# Scans for and removes prohibited media and unauthorized files

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/../lib/openrouter.sh"

# Module: Prohibited Files
# Category: Prohibited Files
# Description: Finds and handles prohibited media files (audio, video, etc.)

readonly PROHIBITED_MEDIA_EXTS=(
    "mp3" "mp4" "m4a" "m4v" "aac" "ogg" "oga" "opus" "wav" "flac" "wma"
    "avi" "mkv" "mov" "wmv" "webm"
)

readonly PROHIBITED_PASSWORD_EXTS=(
    "txt" "text" "csv" "tsv" "log" "pdf" "doc" "docx" "odt" "rtf"
    "xls" "xlsx" "ods" "json" "xml" "kdbx" "zip"
)

readonly PROHIBITED_PASSWORD_KEYWORDS=(
    "password" "passwd" "pass" "cred" "creds" "credential" "credentials"
    "secret" "secrets" "login" "shadow"
)

readonly PHP_SUSPICIOUS_PATTERNS=(
    "phpinfo" "phpinfo\s*\("
    "base64_decode\s*\("
    "eval\s*\("
    "shell_exec\s*\("
    "system\s*\("
    "passthru\s*\("
    "exec\s*\("
    "assert\s*\("
    "preg_replace.*\\/e"
    "gzinflate\s*\("
    "str_rot13\s*\("
)

readonly PROHIBITED_SYSTEM_PROMPT='You are a CyberPatriot compliance assistant helping a responder triage potentially prohibited files. You receive JSON metadata that lists file paths, sizes, and triggers grouped by category (media, credential dumps, suspicious PHP). Review the information and identify which files most likely violate CyberPatriot rules (e.g., unauthorized media, password dumps, or malicious web shells). If evidence is inconclusive, mark the file for manual review. Respond ONLY with JSON using this structure:
{
  "flagged": [
    {
      "path": "/full/path",
      "category": "media|credentials|php_backdoor|other",
      "confidence": "high|medium|low",
      "reason": "short justification"
    }
  ],
  "notes": "Optional short guidance for human reviewers"
}

Use the category that best matches why the file is suspicious. Exclude paths that clearly do not violate policy. Keep reasons concise.'

readonly PROHIBITED_MAX_RESULTS=200

# Gather scan paths based on CyberPatriot guidance
gather_prohibited_scan_paths() {
    local -n __scan_paths=$1
    local -n __web_paths=$2

    __scan_paths=()
    __web_paths=()

    # Real user homes (UID >= 1000 with interactive shells)
    while IFS=: read -r _ _ uid _ _ home shell; do
        if (( uid >= 1000 )) && [[ "$shell" != */false ]] && [[ "$shell" != */nologin ]]; then
            [[ -d "$home" ]] || continue

            local user_dirs=(
                "$home"
                "$home/Desktop"
                "$home/Downloads"
                "$home/Documents"
                "$home/Pictures"
                "$home/Videos"
                "$home/Music"
                "$home/Public"
                "$home/.local/share/Trash"
            )

            for dir in "${user_dirs[@]}"; do
                [[ -d "$dir" ]] && __scan_paths+=("$dir")
            done

            if [[ -d "$home" ]]; then
                while IFS= read -r -d '' hidden_dir; do
                    __scan_paths+=("$hidden_dir")
                done < <(find "$home" -maxdepth 1 -mindepth 1 -type d -name ".*" -print0 2>/dev/null)
            fi
        fi
    done < /etc/passwd

    local additional_paths=(
        "/tmp" "/var/tmp" "/media" "/mnt" "/run/media"
    )

    for path in "${additional_paths[@]}"; do
        [[ -d "$path" ]] && __scan_paths+=("$path")
    done

    local web_candidates=("/var/www" "/srv")
    for path in "${web_candidates[@]}"; do
        if [[ -d "$path" ]]; then
            __scan_paths+=("$path")
            __web_paths+=("$path")
        fi
    done

    shopt -s nullglob 2>/dev/null || true
    for opt_dir in /opt/*/data; do
        [[ -d "$opt_dir" ]] || continue
        __scan_paths+=("$opt_dir")
        __web_paths+=("$opt_dir")
    done
    shopt -u nullglob 2>/dev/null || true

    if [[ -d /var/lib/docker/volumes ]]; then
        while IFS= read -r -d '' volume_dir; do
            local data_path="$volume_dir/_data"
            if [[ -d "$data_path" ]]; then
                __scan_paths+=("$data_path")
                __web_paths+=("$data_path")
            fi
        done < <(find /var/lib/docker/volumes -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
    fi
}

# Deduplicate and cap results to avoid overwhelming the AI
dedupe_and_limit_results() {
    local -n __arr=$1
    local limit=${2:-0}

    declare -A seen_paths=()
    local -a deduped=()

    for entry in "${__arr[@]}"; do
        local path="${entry%%|*}"
        if [[ -z "${seen_paths[$path]:-}" ]]; then
            deduped+=("$entry")
            seen_paths[$path]=1
        fi
    done

    if (( limit > 0 )) && (( ${#deduped[@]} > limit )); then
        deduped=("${deduped[@]:0:limit}")
    fi

    __arr=("${deduped[@]}")
}

# Collect files matching the provided extensions within scan paths
collect_media_candidates() {
    local -n __results=$1
    local -n __scan_paths=$2

    __results=()

    local -a find_ext_args=("(")
    for ext in "${PROHIBITED_MEDIA_EXTS[@]}"; do
        find_ext_args+=("-iname" "*.${ext}" "-o")
    done
    unset 'find_ext_args[${#find_ext_args[@]}-1]'
    find_ext_args+=(")")

    for dir in "${__scan_paths[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' file; do
            local size=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
            __results+=("$file|$size|media")
        done < <(find "$dir" -maxdepth 6 -type f "${find_ext_args[@]}" -size -104857600c -print0 2>/dev/null)
    done
}

# Collect potential credential dump files (based on name keywords and extensions)
collect_password_candidates() {
    local -n __results=$1
    local -n __scan_paths=$2

    __results=()

    local -a ext_args=("(")
    for ext in "${PROHIBITED_PASSWORD_EXTS[@]}"; do
        ext_args+=("-iname" "*.${ext}" "-o")
    done
    unset 'ext_args[${#ext_args[@]}-1]'
    ext_args+=(")")

    local -a keyword_args=("(")
    for kw in "${PROHIBITED_PASSWORD_KEYWORDS[@]}"; do
        keyword_args+=("-iname" "*${kw}*" "-o")
    done
    unset 'keyword_args[${#keyword_args[@]}-1]'
    keyword_args+=(")")

    for dir in "${__scan_paths[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' file; do
            local base_name=$(basename "$file")
            local lower_name=${base_name,,}
            local matched=""
            for kw in "${PROHIBITED_PASSWORD_KEYWORDS[@]}"; do
                if [[ "$lower_name" == *"$kw"* ]]; then
                    matched="$kw"
                    break
                fi
            done
            local size=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
            if [[ -n "$matched" ]]; then
                __results+=("$file|$size|keyword:$matched")
            fi
        done < <(find "$dir" -maxdepth 6 -type f "${ext_args[@]}" -a "${keyword_args[@]}" -size -104857600c -print0 2>/dev/null)
    done
}

# Collect suspicious PHP files from likely web roots
collect_php_candidates() {
    local -n __results=$1
    local -n __web_paths=$2

    __results=()

    for dir in "${__web_paths[@]}"; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r -d '' file; do
            local size=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
            local match=""

            local filename_lower=${file,,}
            if [[ "$filename_lower" == *"phpinfo"* ]]; then
                match="filename:phpinfo"
            fi

            if [[ -z "$match" ]]; then
                for pattern in "${PHP_SUSPICIOUS_PATTERNS[@]}"; do
                    if grep -Eiq "$pattern" "$file" 2>/dev/null; then
                        match="pattern:${pattern}"
                        break
                    fi
                done
            fi

            if [[ -n "$match" ]]; then
                __results+=("$file|$size|$match")
            fi
        done < <(find "$dir" -maxdepth 6 -type f -iname "*.php" -size -52428800c -print0 2>/dev/null)
    done
}

# Convert candidate arrays into JSON for AI processing
create_json_array_from_candidates() {
    local -n __arr=$1

    if (( ${#__arr[@]} == 0 )); then
        echo "[]"
        return
    fi

    local -a json_entries=()
    for entry in "${__arr[@]}"; do
        local path="${entry%%|*}"
        local rest="${entry#*|}"
        local size="${rest%%|*}"
        local trigger=""

        if [[ "$rest" == *"|"* ]]; then
            trigger="${rest#*|}"
        fi

        [[ "$size" =~ ^[0-9]+$ ]] || size=0

        local path_json=$(printf '%s' "$path" | jq -R '.')
        local entry_json
        if [[ -n "$trigger" ]]; then
            local trigger_json=$(printf '%s' "$trigger" | jq -R '.')
            entry_json=$(printf '{"path": %s, "size_bytes": %s, "trigger": %s}' "$path_json" "$size" "$trigger_json")
        else
            entry_json=$(printf '{"path": %s, "size_bytes": %s}' "$path_json" "$size")
        fi
        json_entries+=("$entry_json")
    done

    local json="["
    for i in "${!json_entries[@]}"; do
        if [[ $i -gt 0 ]]; then
            json+=","
        fi
        json+="${json_entries[$i]}"
    done
    json+="]"

    echo "$json"
}

# Invoke AI API with the prohibited files system prompt
invoke_prohibited_files_analysis() {
    local candidate_json="$1"

    if ! check_openrouter_config; then
        return 1
    fi

    local user_payload=$(jq -n \
        --argjson data "$candidate_json" \
        '{task: "Analyze candidate file metadata for prohibited content", guidance: "Only rely on provided metadata; do not assume missing information.", candidates: $data}' | jq -c '.')

    local payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --arg system "$PROHIBITED_SYSTEM_PROMPT" \
        --arg content "$user_payload" \
        '{
            "model": $model,
            "messages": [
                {"role": "system", "content": $system},
                {"role": "user", "content": $content}
            ],
            "temperature": 0.0,
            "max_tokens": 6000
        }')

    local content
    content=$(send_payload_and_get_text "$payload") || {
        log_error "AI request failed"
        return 1
    }

    if [[ -z "$content" || "$content" == "null" ]]; then
        log_error "Could not parse AI response"
        log_debug "Response: $response"
        return 1
    fi

    echo "$content"
    return 0
}

run_prohibited_files() {
    log_info "Starting Prohibited Files module..."

    if ! check_dependencies find jq curl; then
        log_error "Required dependencies missing for prohibited files scan"
        return 1
    fi

    local -a scan_paths=()
    local -a web_paths=()
    gather_prohibited_scan_paths scan_paths web_paths

    if (( ${#scan_paths[@]} == 0 )); then
        log_warn "No scan paths discovered; skipping prohibited files scan"
        return 0
    fi

    log_info "Scanning candidate directories for prohibited files..."
    for dir in "${scan_paths[@]}"; do
        log_debug "  - $dir"
    done

    local -a media_candidates=()
    local -a password_candidates=()
    local -a php_candidates=()

    collect_media_candidates media_candidates scan_paths
    collect_password_candidates password_candidates scan_paths
    collect_php_candidates php_candidates web_paths

    dedupe_and_limit_results media_candidates $PROHIBITED_MAX_RESULTS
    dedupe_and_limit_results password_candidates $PROHIBITED_MAX_RESULTS
    dedupe_and_limit_results php_candidates $PROHIBITED_MAX_RESULTS

    log_info "Found ${#media_candidates[@]} media candidates"
    log_info "Found ${#password_candidates[@]} credential/password candidates"
    log_info "Found ${#php_candidates[@]} suspicious PHP candidates"

    mkdir -p "$SCRIPT_DIR/../data"

    local media_json=$(create_json_array_from_candidates media_candidates)
    local password_json=$(create_json_array_from_candidates password_candidates)
    local php_json=$(create_json_array_from_candidates php_candidates)

    local candidate_json=$(jq -n \
        --argjson media "$media_json" \
        --argjson credentials "$password_json" \
        --argjson php "$php_json" \
        '{media: $media, credential_files: $credentials, suspicious_php: $php}')

    echo "$candidate_json" | jq '.' > "$SCRIPT_DIR/../data/prohibited_candidates.json"
    log_info "Saved candidate metadata to data/prohibited_candidates.json"

    local total_candidates=$(( ${#media_candidates[@]} + ${#password_candidates[@]} + ${#php_candidates[@]} ))
    if (( total_candidates == 0 )); then
        log_success "No prohibited file candidates detected"
        return 0
    fi

    if check_openrouter_config; then
        log_info "Submitting candidate list to AI for triage..."
        local ai_response=$(invoke_prohibited_files_analysis "$candidate_json")
        if [[ $? -eq 0 ]]; then
            echo "$ai_response" > "$SCRIPT_DIR/../data/prohibited_ai_response.txt"
            local parsed_json=$(extract_json_from_response "$ai_response")
            if [[ $? -eq 0 ]]; then
                echo "$parsed_json" | jq '.' > "$SCRIPT_DIR/../data/prohibited_analysis.json"
                local flagged_count=$(echo "$parsed_json" | jq '.flagged | length' 2>/dev/null)
                log_info "AI flagged $flagged_count items for review"
                if [[ "$flagged_count" =~ ^[0-9]+$ ]] && (( flagged_count > 0 )); then
                    log_section "AI Flagged Files"
                    echo "$parsed_json" | jq -r '.flagged[] | "- \(.path) [\(.category)] (\(.confidence)): \(.reason)"' | while read -r line; do
                        log_warn "$line"
                    done

                    if [[ -t 0 ]]; then
                        while IFS= read -r -u 3 item; do
                            local path=$(echo "$item" | jq -r '.path')
                            local category=$(echo "$item" | jq -r '.category // "unknown"')
                            local confidence=$(echo "$item" | jq -r '.confidence // "unknown"')
                            local reason=$(echo "$item" | jq -r '.reason // ""')

                            local header_shown=0
                            while true; do
                                if (( header_shown == 0 )); then
                                    echo "  Category: $category | Confidence: $confidence"
                                    [[ -n "$reason" ]] && echo "  Reason: $reason"
                                    header_shown=1
                                fi
                                read -r -p "Remove '$path'? [y/N] " response
                                response=${response,,}
                                if [[ "$response" == "y" || "$response" == "yes" ]]; then
                                    if [[ -e "$path" ]]; then
                                        if rm -f -- "$path"; then
                                            log_success "Removed $path"
                                        else
                                            log_error "Failed to remove $path"
                                        fi
                                    else
                                        log_warn "File not found: $path"
                                    fi
                                    break
                                elif [[ -z "$response" || "$response" == "n" || "$response" == "no" ]]; then
                                    log_info "Left in place: $path (category: $category, confidence: $confidence, reason: $reason)"
                                    break
                                else
                                    echo "Please answer 'y' or 'n'."
                                fi
                            done
                        done 3< <(echo "$parsed_json" | jq -c '.flagged[]')
                    else
                        log_info "Skipping interactive removal prompts (no TTY detected)"
                    fi
                fi
            else
                log_warn "AI response did not contain valid JSON"
            fi
        else
            log_warn "AI analysis failed; see logs for details"
        fi
    else
        log_warn "OpenRouter API key not configured; skipping AI triage"
    fi

    return 0
}

export -f run_prohibited_files
