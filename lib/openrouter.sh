#!/bin/bash
# openrouter.sh - AI API interface (OpenRouter, Google Gemini, NVIDIA Integrate)
# Supports OpenRouter (legacy), Google Gemini (when OPENROUTER_MODEL starts with "google/"),
# and NVIDIA Integrate (when OPENROUTER_MODEL starts with "nvidia/")
# Requires: curl, jq

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    if [[ -n "${OPENROUTER_SH_LOADED:-}" ]]; then
        return 0
    fi
    declare -gr OPENROUTER_SH_LOADED=1
fi

source "$(dirname "${BASH_SOURCE[0]}")/utils.sh"

# API configuration
# Primary (legacy) key: OPENROUTER_API_KEY (kept for backward compatibility)
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
# Google/Gemini keys (used when OPENROUTER_MODEL starts with "google/")
GEMINI_API_KEY="${GEMINI_API_KEY:-}"
GOOGLE_API_KEY="${GOOGLE_API_KEY:-}"

# OpenRouter compatibility defaults
OPENROUTER_API_URL="https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-anthropic/claude-3.5-sonnet}"


# NVIDIA Integrate API (optional)
# Example: NVIDIA_API_KEY="sk-..." and set OPENROUTER_MODEL to "nvidia/google/gemma-3n-e4b-it"
NVIDIA_API_KEY="${NVIDIA_API_KEY:-}"
# Toggle streaming when using NVIDIA Integrate (true/false)
NVIDIA_STREAM="${NVIDIA_STREAM:-false}"

# System prompt for README extraction (adapted from PowerShell version)
# Use a heredoc to populate SYSTEM_PROMPT. read -d '' returns 1 at EOF when
# no NUL delimiter is encountered, so append `|| true` to avoid set -e exiting
# the script before initialization completes.
read -r -d '' SYSTEM_PROMPT <<'EOF' || true
You are a specialized assistant that extracts structured information from CyberPatriot competition README files.

Your task is to parse the README content and extract:
1. Every authorized user and their account type ("admin" or "standard"). Administrators are always authorized users, but not every authorized user is an administrator.
2. Recently hired/new users who need accounts created (recognize wording like "new department members" or "newly added users" as recent hires).
3. Terminated/unauthorized users whose accounts should be removed (recognize wording such as "terminated", "former", "to delete").
4. Critical services that must remain running.
5. Group memberships for each authorized user (include any groups mentioned for them).
6. Groups that need to be created along with the members to place in those groups (these may describe new departments such as "Create a group called \"spider\" and add may, peni, stan, miguel"—treat this as an example, not something to hardcode).
7. System users explicitly mentioned as needing restricted login.

Return ONLY valid JSON in this exact format:
{
  "all_users": [
    {"name": "username", "account_type": "admin|standard", "groups": ["group1", "group2"]}
  ],
  "recent_hires": [
    {"name": "username", "account_type": "admin|standard", "groups": ["group1"]}
  ],
  "terminated_users": ["username1", "username2"],
  "critical_services": ["ssh", "apache2"],
  "groups_to_create": [
    {"name": "groupname", "members": ["user1", "user2"]}
  ],
  "system_users_to_restrict": ["mysql"]
}

Guidelines:
- Extract ALL authorized users, and always include an "account_type" and any listed "groups" for each one.
- Identify users described as new, recently hired, to be created, or part of a newly formed department as recent hires.
- Identify users marked as terminated, removed, unauthorized, or former as terminated_users.
- Service names should be actual service names (e.g., "ssh", "apache2", "mysql").
- Account types: "admin" for administrators, "standard" for regular users.
- Extract any groups mentioned that should be created and capture all members listed for those groups (do not invent members; use only what appears in the README).
- Extract group memberships for all users, including admins and standard users.
- Capture system users to restrict ONLY when explicitly mentioned in the README.
- If information is not present, use empty arrays [].
- Return ONLY the JSON object, no additional text or explanation.
EOF

# Check if API key is configured
check_openrouter_config() {
    # If the configured model is a Google/Gemini model, require GEMINI/GOOGLE API key

    if [[ "$OPENROUTER_MODEL" == nvidia/* ]]; then
        if [[ -z "${NVIDIA_API_KEY:-}" ]]; then
            log_error "NVIDIA API key not configured (set NVIDIA_API_KEY)"
            log_info "Set NVIDIA_API_KEY environment variable or in config.conf"
            return 1
        fi
        return 0
    fi

    if [[ "$OPENROUTER_MODEL" == google/* ]]; then
        if [[ -z "${GEMINI_API_KEY:-}${GOOGLE_API_KEY:-}${OPENROUTER_API_KEY:-}" ]]; then
            log_error "Google/Gemini API key not configured"
            log_info "Set GEMINI_API_KEY or GOOGLE_API_KEY (or fallback to OPENROUTER_API_KEY)"
            return 1
        fi
        return 0
    fi

    # Otherwise require the legacy OpenRouter key
    if [[ -z "$OPENROUTER_API_KEY" ]]; then
        log_error "OpenRouter API key not configured"
        log_info "Set OPENROUTER_API_KEY environment variable or in config.conf"
        return 1
    fi
    return 0
}

# ---
# --- THIS IS THE FIXED FUNCTION ---
# ---
# Remove HTML tags from content (re-written with perl for multi-line support)
remove_html_tags() {
    local content="$1"

    # Use Perl for multi-line regex replacements
    # -0777 slurps the whole file
    # -p prints the result
    # 's|...|...|gis' -> g=global, i=case-insensitive, s=dot matches newline

    # Remove head, script, and style tags with their content (non-greedy)
    content=$(echo "$content" | perl -0777 -p -e 's|<head[^>]*>.*?</head>||gis')
    content=$(echo "$content" | perl -0777 -p -e 's|<script[^>]*>.*?</script>||gis')
    content=$(echo "$content" | perl -0777 -p -e 's|<style[^>]*>.*?</style>||gis')

    # Remove all remaining HTML tags
    content=$(echo "$content" | perl -0777 -p -e 's|<[^>]+>||g')

    # Collapse multiple whitespace to single space
    content=$(echo "$content" | tr -s '[:space:]' ' ')

    # Trim leading/trailing whitespace
    content=$(echo "$content" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

    echo "$content"
}
# --- END OF FIXED FUNCTION ---

# Call OpenRouter API with README content
invoke_readme_extraction() {
    local plain_text="$1"

    if ! check_openrouter_config; then
        return 1
    fi

    log_debug "Calling AI API for README extraction..."
    log_debug "Using model: $OPENROUTER_MODEL"

    # Construct JSON payload (OpenRouter/chat style)
    local payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --arg system "$SYSTEM_PROMPT" \
        --arg content "$plain_text" \
        '{
            "model": $model,
            "messages": [
                {"role": "system", "content": $system},
                {"role": "user", "content": $content}
            ],
            "temperature": 0.1,
            "max_tokens": 4000
        }')

    # Send payload and extract text using provider-aware helper
    local content
    content=$(send_payload_and_get_text "$payload") || return 1

    echo "$content"
    return 0
}

# Provider-aware payload sender: supports OpenRouter (legacy), Google Gemini, and NVIDIA Integrate
send_payload_and_get_text() {
    local payload="$1"

    if [[ "$OPENROUTER_MODEL" == google/* ]]; then
        # Gemini/Google path
        local model_name="${OPENROUTER_MODEL#google/}"
        local key="${GEMINI_API_KEY:-${GOOGLE_API_KEY:-$OPENROUTER_API_KEY}}"
        if [[ -z "$key" ]]; then
            log_error "Missing Google/Gemini API key"
            return 1
        fi

        # Combine messages into a single prompt text for Gemini
        local combined
        combined=$(echo "$payload" | jq -r '[.messages[] | (.role + ": " + .content)] | join("\n\n")')

        # Build Gemini payload (simple text prompt) - compatible with Generative Language API
        local gemini_payload
        gemini_payload=$(jq -n --arg text "$combined" '{prompt: {text: $text}, temperature: 0.1, maxOutputTokens: 4000}')

        local url="https://generativelanguage.googleapis.com/v1/models/${model_name}:generate?key=${key}"

        local response
        response=$(curl -s -X POST "$url" -H "Content-Type: application/json" -d "$gemini_payload")
        if [[ $? -ne 0 ]]; then
            log_error "Failed to call Gemini API"
            return 1
        fi

        # Try multiple common response fields to extract text
        local content
        content=$(echo "$response" | jq -r '(.candidates[0].content // .output[0].content // .candidates[0].message.content[0].text // .candidates[0].message.content[].text // "")' 2>/dev/null)
        if [[ -z "$content" ]]; then
            log_error "Failed to parse Gemini response"
            log_debug "Response: $response"
            return 1
        fi

        echo "$content"
        return 0
    fi

    if [[ "$OPENROUTER_MODEL" == nvidia/* ]]; then
        # NVIDIA Integrate API path (supports streaming and non-streaming)
        local model_name="${OPENROUTER_MODEL#nvidia/}"
        local key="${NVIDIA_API_KEY:-}"
        if [[ -z "$key" ]]; then
            log_error "Missing NVIDIA API key"
            return 1
        fi

        # Combine messages into a single prompt text
        local combined
        combined=$(echo "$payload" | jq -r '[.messages[] | (.role + ": " + .content)] | join("\n\n")')

        # Build payload similar to the provided Python example
        local stream_flag=false
        if [[ "${NVIDIA_STREAM,,}" == "true" ]]; then
            stream_flag=true
        fi

        local nvidia_payload
        nvidia_payload=$(jq -n --arg model "$model_name" --arg content "$combined" --argjson stream $stream_flag '{model: $model, messages: [{role: "user", content: $content}], max_tokens: 512, temperature: 0.20, top_p: 0.70, frequency_penalty: 0.00, presence_penalty: 0.00, stream: $stream}')

        local url="https://integrate.api.nvidia.com/v1/chat/completions"

        if [[ "$stream_flag" == true ]]; then
            # Stream SSE lines and print the JSON content payloads (data: ...)
            curl -s -N -X POST "$url" \
                -H "Authorization: Bearer $key" \
                -H "Accept: text/event-stream" \
                -H "Content-Type: application/json" \
                -d "$nvidia_payload" | while IFS= read -r line; do
                    if [[ -n "$line" ]]; then
                        # Strip leading "data: " if present
                        case "$line" in
                            data:*) echo "${line#data: }" ;; 
                            *) echo "$line" ;;
                        esac
                    fi
                done
            return 0
        else
            local response
            response=$(curl -s -X POST "$url" -H "Authorization: Bearer $key" -H "Accept: application/json" -H "Content-Type: application/json" -d "$nvidia_payload")
            if [[ $? -ne 0 ]]; then
                log_error "Failed to call NVIDIA Integrate API"
                return 1
            fi

            # Try common response fields to extract text
            local content
            content=$(echo "$response" | jq -r '(.choices[0].message.content // .choices[0].content // .output[0].content // .generated_text // "")' 2>/dev/null)
            if [[ -z "$content" ]]; then
                log_error "Failed to parse NVIDIA Integrate response"
                log_debug "Response: $response"
                return 1
            fi

            echo "$content"
            return 0
        fi
    fi

    else
        # Legacy OpenRouter path (kept for backward compatibility)
        local response
        response=$(curl -s -X POST "$OPENROUTER_API_URL" \
            -H "Authorization: Bearer $OPENROUTER_API_KEY" \
            -H "Content-Type: application/json" \
            -H "HTTP-Referer: https://github.com/cyberpatriot-linux-auto" \
            -d "$payload")

        if [[ $? -ne 0 ]]; then
            log_error "Failed to call OpenRouter API"
            return 1
        fi

        local content
        content=$(echo "$response" | jq -r '.choices[0].message.content' 2>/dev/null)
        if [[ -z "$content" || "$content" == "null" ]]; then
            log_error "Failed to parse OpenRouter API response"
            log_debug "Response: $response"
            return 1
        fi

        echo "$content"
        return 0
    fi
}

# ---
# --- THIS IS THE SECOND FIXED FUNCTION (more robust) ---
# ---
# Extract JSON from model response (handles cases where model adds extra text)
extract_json_from_response() {
    local text="$1"

    # Try to parse as-is first
    if echo "$text" | jq -e '.' >/dev/null 2>&1; then
        echo "$text"
        return 0
    fi

    # Try to parse JSON that is wrapped in a fenced ```json code block
    local fenced_json=$(echo "$text" | sed -n '/```json/,/```/p' | sed '1d;$d')
    if [[ -n "$fenced_json" ]] && echo "$fenced_json" | jq -e '.' >/dev/null 2>&1; then
        echo "$fenced_json"
        return 0
    fi

    # Try to parse JSON from any fenced code block
    local fenced_block=$(echo "$text" | sed -n '/```/,/```/p' | sed '1d;$d')
    if [[ -n "$fenced_block" ]] && echo "$fenced_block" | jq -e '.' >/dev/null 2>&1; then
        echo "$fenced_block"
        return 0
    fi

    # Try to extract JSON object from text
    # Use (?s) to make . (dot) match newlines, in case the JSON is multi-line
    local extracted=$(echo "$text" | grep -oP '(?s)\{.*\}' | head -1)

    if [[ -n "$extracted" ]] && echo "$extracted" | jq -e '.' >/dev/null 2>&1; then
        echo "$extracted"
        return 0
    fi

    # Try to extract a JSON array if no object was found
    local extracted_array=$(echo "$text" | grep -oP '(?s)\[.*\]' | head -1)
    if [[ -n "$extracted_array" ]] && echo "$extracted_array" | jq -e '.' >/dev/null 2>&1; then
        echo "$extracted_array"
        return 0
    fi

    log_error "Could not extract valid JSON from model response"
    log_debug "Raw model response: $text" # Added for better debugging
    return 1
}
# --- END OF FIXED FUNCTION ---

# Test OpenRouter connection
test_openrouter() {
    if ! check_openrouter_config; then
        return 1
    fi

    log_info "Testing AI API connection..."

    local test_payload
    test_payload=$(jq -n --arg model "$OPENROUTER_MODEL" '{model: $model, messages: [{role: "user", content: "Say hello"}], max_tokens: 10}')

    local content
    content=$(send_payload_and_get_text "$test_payload") || true

    if [[ -n "$content" ]]; then
        log_success "AI API connection successful"
        return 0
    else
        log_error "AI API connection failed"
        return 1
    fi
}

export -f check_openrouter_config remove_html_tags invoke_readme_extraction
export -f extract_json_from_response test_openrouter send_payload_and_get_text
