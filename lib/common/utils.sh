#!/usr/bin/env bash
# ClawSec Common - Utilities

# Atomic write: write content to tmp file, validate, then mv
# Usage: atomic_write <target_path> <content_from_stdin>
atomic_write() {
    local target="$1"
    local tmp
    tmp=$(mktemp "${target}.XXXXXX.new")
    cat > "$tmp"
    if [[ -s "$tmp" ]]; then
        mv -f "$tmp" "$target"
        return 0
    else
        rm -f "$tmp"
        echo "atomic_write: refused to write empty file to $target" >&2
        return 1
    fi
}

# Validate JSON file
validate_json() {
    local f="$1"
    if jq empty "$f" 2>/dev/null; then
        return 0
    else
        echo "validate_json: $f is not valid JSON" >&2
        return 1
    fi
}

# Safe download: fetch URL, validate, atomic write
# Usage: safe_download <url> <target_path> [validate_cmd]
safe_download() {
    local url="$1"
    local target="$2"
    local validate_cmd="${3:-}"
    local tmp
    tmp=$(mktemp "${target}.XXXXXX.new")

    if ! curl -fsSL --max-time 120 --retry 3 --retry-delay 5 "$url" -o "$tmp"; then
        rm -f "$tmp"
        echo "safe_download: FAILED to fetch $url" >&2
        return 1
    fi

    if [[ -n "$validate_cmd" ]]; then
        if ! eval "$validate_cmd" "$tmp"; then
            rm -f "$tmp"
            echo "safe_download: validation failed for $url" >&2
            return 1
        fi
    fi

    mv -f "$tmp" "$target"
    return 0
}

# Get script directory
script_dir() {
    local src="${BASH_SOURCE[0]}"
    while [[ -L "$src" ]]; do
        local dir
        dir="$(cd -P "$(dirname "$src")" && pwd)"
        src="$(readlink "$src")"
        [[ "$src" != /* ]] && src="$dir/$src"
    done
    cd -P "$(dirname "$src")" && pwd
}