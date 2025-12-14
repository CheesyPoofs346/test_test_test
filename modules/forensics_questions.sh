#!/bin/bash
# forensics_questions.sh - Forensics Questions Module
# Handles discovery and AI-assisted answering of CyberPatriot forensic questions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/utils.sh"
source "$SCRIPT_DIR/../lib/openrouter.sh"

readonly FORENSICS_SYSTEM_PROMPT='You are a CyberPatriot Linux forensic analyst. Analyze the provided forensic question files and craft clear, concise answers that students can enter into the scoring report. When needed you may request safe, read-only shell commands to gather extra evidence, but combine them into a single consolidated request whenever possible and avoid unnecessary steps. For finding files, use the "locate" command as the system database is already updated and available. Always respond with valid JSON in the exact format:
{
  "answers": [
    {"number": 1, "answers": ["Answer text"], "explanation": "(optional short reasoning)", "needs_manual_review": false}
  ],
  "command_requests": [
    {"command": "cat /path && strings /file", "reason": "Why the consolidated command is needed"}
  ]
}
Use an array for answers even when there is only one. Set needs_manual_review to true if you are not confident. Omit command_requests or return an empty array when no additional data is required. Provide a complete set of command requests in a single step whenever feasible, and you have at most three total exchanges to finish the task. After receiving command output, provide final answers and avoid asking for more commands.'

# Discover forensic question files on user desktops
discover_forensics_questions() {
    local -a entries=()
    local -a search_paths=("/home"/*/Desktop "/root/Desktop")

    for desktop in "${search_paths[@]}"; do
        [[ -d "$desktop" ]] || continue

        shopt -s nullglob
        local files=("$desktop"/Forensics\ Question\ *.txt)
        shopt -u nullglob

        for file in "${files[@]}"; do
            [[ -f "$file" ]] || continue

            local filename=$(basename "$file")
            if [[ "$filename" =~ ^Forensics[[:space:]]Question[[:space:]]([1-9])\.txt$ ]]; then
                local number="${BASH_REMATCH[1]}"
                local content
                content=$(cat "$file")
                local entry
                entry=$(jq -n \
                    --argjson number "$number" \
                    --arg path "$file" \
                    --arg content "$content" \
                    '{number: $number, path: $path, content: $content}'
                )
                entries+=("$entry")
            fi
        done
    done

    if (( ${#entries[@]} == 0 )); then
        echo "[]"
        return 0
    fi

    printf '%s\n' "${entries[@]}" | jq -s 'sort_by(.number)'
}

# Prepare the initial user message payload for the AI API
build_forensics_user_message() {
    local questions_json="$1"
    jq -n \
        --argjson questions "$questions_json" \
        '{
            task: "Analyze CyberPatriot forensic question files and produce answers.",
            instructions: {
                response_format: "Return JSON with keys answers (array of objects) and command_requests (array).",
                command_guidance: "Request only the safe, read-only commands you need, then decide if manual review is required."
            },
            questions: $questions
        }' | jq -c '.'
}

# Call AI API with the provided chat history
call_forensics_openrouter() {
    local messages_json="$1"

    if ! check_openrouter_config; then
        return 1
    fi

    local payload
    payload=$(jq -n \
        --arg model "$OPENROUTER_MODEL" \
        --argjson messages "$messages_json" \
        '{
            model: $model,
            messages: $messages,
            temperature: 0.1,
            max_tokens: 7000
        }')

    local content
    content=$(send_payload_and_get_text "$payload") || {
        log_error "AI request failed"
        return 1
    }

    if [[ -z "$content" || "$content" == "null" ]]; then
        log_error "AI response did not contain content"
        return 1
    fi

    echo "$content"
    return 0
}

# Ensure the requested command is not empty before execution
is_safe_forensics_command() {
    local command="$1"
    [[ -n "${command//[[:space:]]/}" ]]
}

# Normalize command requests into a JSON array
extract_forensics_command_requests() {
    local response_json="$1"

    echo "$response_json" | jq -c '
        if type == "object" then
            if has("command_requests") then
                if (.command_requests | type == "array") then .command_requests else [] end
            elif has("command_request") then
                if (.command_request | type == "object") then [.command_request] else [] end
            else
                []
            end
        elif type == "array" then
            # Some models may return a bare array; use the first object if present
            (.[0] // {}) as $first |
            if ($first | has("command_requests")) then
                if ($first.command_requests | type == "array") then $first.command_requests else [] end
            elif ($first | has("command_request")) then
                if ($first.command_request | type == "object") then [$first.command_request] else [] end
            else
                []
            end
        else
            []
        end | map(select(.command and (.command | length > 0)))'
}

# Write AI-provided answers into the forensic question text files
write_forensics_answers() {
    local questions_json="$1"
    local answers_json="$2"

    while IFS= read -r answer_entry; do
        local number
        number=$(echo "$answer_entry" | jq -r '.number // empty')
        [[ -z "$number" ]] && continue

        local needs_manual
        needs_manual=$(echo "$answer_entry" | jq -r '.needs_manual_review // false')

        local path
        path=$(echo "$questions_json" | jq -r --argjson num "$number" '.[] | select(.number == $num) | .path' | head -n1)

        if [[ -z "$path" ]]; then
            log_warn "Could not locate file for Question $number"
            continue
        fi

        if [[ "$needs_manual" == "true" ]]; then
            log_warn "Question $number flagged for manual review; not updating $path"
            continue
        fi

        mapfile -t answers < <(echo "$answer_entry" | jq -r '
            if has("answers") then
                if (.answers | type == "array") then .answers[] else .answers end
            elif has("answer") then
                if (.answer | type == "array") then .answer[] else .answer end
            else
                empty
            end')

        if (( ${#answers[@]} == 0 )); then
            log_warn "No answers provided for Question $number; skipping file update"
            continue
        fi

        local tmp_file
        tmp_file=$(mktemp)
        local replaced=0

        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" =~ ^ANSWER: ]]; then
                if (( replaced == 0 )); then
                    for ans in "${answers[@]}"; do
                        echo "ANSWER: $ans" >>"$tmp_file"
                    done
                    replaced=1
                fi
            else
                echo "$line" >>"$tmp_file"
            fi
        done < "$path"

        if (( replaced == 0 )); then
            echo >>"$tmp_file"
            for ans in "${answers[@]}"; do
                echo "ANSWER: $ans" >>"$tmp_file"
            done
        fi

        mv "$tmp_file" "$path"
        log_success "Updated answers for Question $number at $path"
    done < <(echo "$answers_json" | jq -c '.answers[]' 2>/dev/null)

    return 0
}

# Execute an AI-requested command and capture output
execute_forensics_command() {
    local command="$1"

    if ! is_safe_forensics_command "$command"; then
        log_warn "Rejected unsafe command request: $command"
        jq -n \
            --arg command "$command" \
            '{command: $command, exit_code: 126, stdout: "", stderr: "Command rejected by policy"}'
        return 0
    fi

    local stdout_file stderr_file
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)

    bash -c "$command" >"$stdout_file" 2>"$stderr_file"
    local exit_code=$?
    local stdout
    local stderr
    stdout=$(cat "$stdout_file")
    stderr=$(cat "$stderr_file")
    rm -f "$stdout_file" "$stderr_file"

    jq -n \
        --arg command "$command" \
        --arg stdout "$stdout" \
        --arg stderr "$stderr" \
        --argjson exit_code "$exit_code" \
        '{command: $command, exit_code: $exit_code, stdout: $stdout, stderr: $stderr}'
}

# Handle AI interaction workflow and return the final JSON payload of answers
obtain_forensics_answers() {
    local questions_json="$1"
    local label="${2:-all}"

    if ! check_openrouter_config; then
        return 1
    fi

    if ! check_dependencies curl jq; then
        log_error "curl and jq are required for AI-assisted forensics analysis"
        return 1
    fi

    local user_message
    user_message=$(build_forensics_user_message "$questions_json")

    local messages
    messages=$(jq -n \
        --arg system "$FORENSICS_SYSTEM_PROMPT" \
        --arg user "$user_message" \
        '[
            {"role": "system", "content": $system},
            {"role": "user", "content": $user}
        ]')

    local round=1
    local max_rounds=3

    mkdir -p "$SCRIPT_DIR/../data"

    while (( round <= max_rounds )); do
        local content
        content=$(call_forensics_openrouter "$messages") || return 1

        echo "$content" > "$SCRIPT_DIR/../data/forensics_ai_round${round}_${label}.txt"

        local parsed
        parsed=$(extract_json_from_response "$content") || {
            log_error "Failed to parse AI response for forensics questions"
            return 1
        }

        local command_requests
        command_requests=$(extract_forensics_command_requests "$parsed")

        if [[ "$command_requests" == "[]" || $round -eq $max_rounds ]]; then
            echo "$parsed"
            return 0
        fi

        local command_results=()
        local index=0

        while IFS= read -r command_obj; do
            local command
            command=$(echo "$command_obj" | jq -r '.command')
            local reason
            reason=$(echo "$command_obj" | jq -r '.reason // ""')
            index=$((index + 1))

            log_info "AI requested command ($index): $command"
            [[ -n "$reason" ]] && log_info "Reason: $reason"

            local command_result
            command_result=$(execute_forensics_command "$command")
            command_results+=("$command_result")

            local exit_code
            exit_code=$(echo "$command_result" | jq -r '.exit_code')
            log_info "Command exit code: $exit_code"
        done < <(echo "$command_requests" | jq -c '.[]')

        local command_results_json
        command_results_json=$(printf '%s\n' "${command_results[@]}" | jq -s '.')
        echo "$command_results_json" | jq '.' > "$SCRIPT_DIR/../data/forensics_ai_command_result_${label}_round${round}.json"

        local followup_user
        followup_user=$(jq -n \
            --argjson command_results "$command_results_json" \
            --argjson questions "$questions_json" \
            --arg summary "Use these command outputs to finalize answers. If absolutely necessary, provide a single consolidated command request; otherwise, deliver final answers now." \
            '{
                task: "Provide final answers using the supplied command outputs.",
                command_results: $command_results,
                questions: $questions,
                guidance: $summary
            }' | jq -c '.')

        messages=$(echo "$messages" | jq \
            --arg assistant "$content" \
            --arg user "$followup_user" \
            '. + [ {"role": "assistant", "content": $assistant}, {"role": "user", "content": $user} ]')

        round=$((round + 1))
    done

    return 0
}

# Module: Forensics Questions
# Category: Forensics Questions
# Description: Searches for forensic question files, reads their content, and obtains AI-assisted answers

run_forensics_questions() {
    log_info "Starting Forensics Questions module..."

    if ! check_dependencies jq; then
        log_error "jq is required for forensics question processing"
        return 1
    fi

    local questions_json
    questions_json=$(discover_forensics_questions)

    if [[ -z "$questions_json" || "$questions_json" == "[]" ]]; then
        log_warn "No Forensics Question text files found on user desktops"
        return 0
    fi

    mkdir -p "$SCRIPT_DIR/../data"
    echo "$questions_json" | jq '.' > "$SCRIPT_DIR/../data/forensics_questions.json"

    local question_count
    question_count=$(echo "$questions_json" | jq '. | length')
    log_info "Detected $question_count forensic question(s)"

    log_section "Forensics Questions"
    echo "$questions_json" | jq -r '.[] | "Question \(.number) (\(.path)):\n\(.content)\n"'

    if check_openrouter_config; then
        log_info "Submitting forensic questions to AI assistant..."

        local tmp_answer_dir
        tmp_answer_dir=$(mktemp -d)

        while IFS= read -r question_entry; do
            (
                local number
                number=$(echo "$question_entry" | jq -r '.number')
                local question_wrapper
                question_wrapper=$(jq -n --argjson q "$question_entry" '[ $q ]')

                local answer_payload
                answer_payload=$(obtain_forensics_answers "$question_wrapper" "q${number}") || answer_payload=""

                if [[ -n "$answer_payload" ]]; then
                    echo "$answer_payload" > "$tmp_answer_dir/answers_${number}.json"
                else
                    log_warn "No AI answers returned for Question $number"
                fi
            ) &
        done < <(echo "$questions_json" | jq -c '.[]')

        wait

        shopt -s nullglob
        local answer_files=("$tmp_answer_dir"/answers_*.json)
        shopt -u nullglob

        if (( ${#answer_files[@]} > 0 )); then
            local answers_json
            answers_json=$(jq -s '
                def pull_answers(obj):
                    if obj | type == "object" then
                        if obj | has("answers") then obj.answers
                        elif obj | has("answer") then [obj.answer] else [] end
                    elif obj | type == "array" then obj
                    else [] end;

                {answers: (map(pull_answers(.)) | add // [])}
            ' "${answer_files[@]}")

            echo "$answers_json" | jq '.' > "$SCRIPT_DIR/../data/forensics_answers.json"

            if echo "$answers_json" | jq -e '.answers and (.answers | type == "array")' >/dev/null 2>&1; then
                log_section "Forensics Answers"
                echo "$answers_json" | jq -r '
                    .answers[] |
                    "Question \(.number): " +
                    (if has("answers") then
                        (if (.answers | type == "array") then (.answers | join(" | ")) else (.answers | tostring) end)
                     else
                        (.answer // "")
                     end) +
                    (if (.needs_manual_review // false) then " (manual review requested)" else "" end)
                '
                if echo "$answers_json" | jq -e '.answers[] | select(has("explanation"))' >/dev/null 2>&1; then
                    echo
                    echo "$answers_json" | jq -r '.answers[] | select(has("explanation")) | "Q\(.number) Explanation: \(.explanation)"'
                fi
                write_forensics_answers "$questions_json" "$answers_json"
                log_success "Module forensics_questions completed successfully"
                return 0
            else
                log_warn "AI response did not include an answers array"
            fi
        else
            log_warn "No AI responses were generated for the forensic questions"
        fi
    else
        log_warn "OpenRouter API key not configured; skipping AI-assisted answers"
    fi

    log_info "Manual review of forensic questions may still be required"
    return 0
}

export -f run_forensics_questions
