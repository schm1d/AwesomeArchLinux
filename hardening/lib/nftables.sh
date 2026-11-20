#!/usr/bin/env bash

# Shared nftables helpers for the hardening scripts. The installer owns the
# base ruleset; feature scripts may only add or replace their marked blocks.
#
# Block order is significant. Every block uses "insert rule", which prepends,
# so the block loaded last ends up at the top of its chain. A block that
# contains nothing but drop/reject rules (a "guard" block, such as the
# container isolation rules) must therefore stay after every other block:
# otherwise an accept persisted later by another script lands above it and
# silently overrides it. Guard blocks are kept at the end of the file, and
# aal_nft_raise_guard_rules restores the same order in the live ruleset.

#
# AAL_NFT_BACKUP_KEEP (default 5) sets how many backups of the config are kept
# per managed block.

# awk fragment shared by the guard helpers: classifies the lines between a
# BEGIN/END marker pair. A guard block has at least one statement, consists
# only of "insert rule"/"add rule" statements, and every one of them ends in
# drop or reject (never accept).
_AAL_NFT_GUARD_AWK='
    function block_line(line) {
        if (line ~ /^[[:space:]]*(#|$)/) return
        if (line !~ /^[[:space:]]*(insert|add)[[:space:]]+rule[[:space:]]/) { bad = 1; return }
        rules++
        if (line ~ /[[:space:]]accept([[:space:]]|$)/) bad = 1
        if (line !~ /[[:space:]](drop|reject)([[:space:]]|$)/) bad = 1
    }
    function is_guard() { return rules > 0 && !bad }
'

# Succeeds when the nft statements on stdin form a guard block.
_aal_nft_is_guard_body() {
    awk "$_AAL_NFT_GUARD_AWK"'
        { block_line($0) }
        END { exit is_guard() ? 0 : 1 }
    '
}

# Prints the line number of the first guard block's BEGIN marker in FILE, or
# nothing when the file has no guard block.
_aal_nft_first_guard_line() {
    awk "$_AAL_NFT_GUARD_AWK"'
        /^# BEGIN AwesomeArchLinux: [a-z0-9-]+$/ { start = NR; inside = 1; rules = 0; bad = 0; next }
        /^# END AwesomeArchLinux: [a-z0-9-]+$/ {
            if (inside && is_guard()) { print start; exit }
            inside = 0
            next
        }
        inside { block_line($0) }
    ' "$1"
}

# Prints the handles of the live rules carrying exactly this comment.
_aal_nft_rule_handles() {
    local family="$1" table="$2" chain="$3" rule_comment="$4"

    nft -a list chain "$family" "$table" "$chain" 2>/dev/null |
        AAL_MARKER="comment \"${rule_comment}\"" awk '
            index($0, ENVIRON["AAL_MARKER"]) {
                for (i = 1; i <= NF; i++) {
                    if ($i == "handle") print $(i + 1)
                }
            }
        '
}

aal_nft_persist_block() (
    set -euo pipefail

    local block_id="${1:-}"
    local config="${AAL_NFT_CONFIG:-/etc/nftables.conf}"
    local begin_marker end_marker body stripped candidate backup begin_count end_count
    local guard_line="" keep="${AAL_NFT_BACKUP_KEEP:-5}"
    local -a old_backups=()

    [[ "$block_id" =~ ^[a-z0-9-]+$ ]] || {
        printf 'Invalid nftables block id: %s\n' "$block_id" >&2
        return 1
    }
    [[ -f "$config" ]] || {
        printf 'nftables config not found: %s\n' "$config" >&2
        return 1
    }
    grep -Eq '^[[:space:]]*flush[[:space:]]+ruleset([[:space:]]|$)' "$config" || {
        printf '%s must own the complete ruleset with "flush ruleset" before managed blocks can be installed.\n' "$config" >&2
        return 1
    }

    begin_marker="# BEGIN AwesomeArchLinux: $block_id"
    end_marker="# END AwesomeArchLinux: $block_id"
    begin_count=$(grep -Fxc "$begin_marker" "$config" || true)
    end_count=$(grep -Fxc "$end_marker" "$config" || true)
    if (( begin_count != end_count || begin_count > 1 )); then
        printf 'Refusing malformed or duplicate nftables block %s.\n' "$block_id" >&2
        return 1
    fi
    umask 077
    body=""
    stripped=""
    candidate=""
    trap 'rm -f -- "${body:-}" "${stripped:-}" "${candidate:-}"' EXIT
    body=$(mktemp "$(dirname "$config")/.${block_id}.body.XXXXXX") || return 1
    stripped=$(mktemp "$(dirname "$config")/.nftables.conf.XXXXXX") || return 1
    candidate=$(mktemp "$(dirname "$config")/.nftables.conf.XXXXXX") || return 1
    cat > "$body"

    # Remove the previous copy of this block together with the blank lines
    # directly above it, and drop blank lines at the end of the file, so that
    # repeated runs reproduce the same file instead of growing it.
    AAL_BEGIN="$begin_marker" AAL_END="$end_marker" awk '
        $0 == ENVIRON["AAL_BEGIN"] { managed = 1; blanks = 0; next }
        $0 == ENVIRON["AAL_END"]   { managed = 0; next }
        managed                    { next }
        /^[[:space:]]*$/           { blanks++; next }
        {
            while (blanks > 0) { print ""; blanks-- }
            print
        }
    ' "$config" > "$stripped"

    # Guard blocks go last. Any other block is placed above the first guard
    # block already present, so the guard rules are still loaded after it.
    if ! _aal_nft_is_guard_body < "$body"; then
        guard_line=$(_aal_nft_first_guard_line "$stripped")
        # Split above the blank separator line that precedes the guard block.
        if [[ -n "$guard_line" ]] && (( guard_line > 1 )) &&
            awk -v n="$((guard_line - 1))" 'NR == n { blank = ($0 ~ /^[[:space:]]*$/); exit } END { exit blank ? 0 : 1 }' "$stripped"; then
            guard_line=$((guard_line - 1))
        fi
    fi
    {
        if [[ -n "$guard_line" ]]; then
            awk -v stop="$guard_line" 'NR >= stop { exit } { print }' "$stripped"
        else
            cat "$stripped"
        fi
        printf '\n%s\n' "$begin_marker"
        cat "$body"
        printf '%s\n' "$end_marker"
        if [[ -n "$guard_line" ]]; then
            awk -v stop="$guard_line" 'NR >= stop' "$stripped"
        fi
    } > "$candidate"

    if ! nft -c -f "$candidate"; then
        printf 'Refusing to install invalid nftables configuration for %s.\n' "$block_id" >&2
        return 1
    fi

    if cmp -s -- "$candidate" "$config"; then
        printf 'nftables block %s is already up to date.\n' "$block_id"
        return 0
    fi

    backup=$(mktemp "${config}.bak.$(date +%Y%m%d-%H%M%S).${block_id}.XXXXXX") || return 1
    cp -a -- "$config" "$backup"
    chmod 0600 "$backup"
    install -o root -g root -m 0644 "$candidate" "$config"

    # Keep only the newest backups of this block; the names sort by timestamp.
    if [[ "$keep" =~ ^[0-9]+$ ]] && (( keep > 0 )); then
        shopt -s nullglob
        old_backups=("${config}.bak."*".${block_id}."??????)
        shopt -u nullglob
        while (( ${#old_backups[@]} > keep )); do
            rm -f -- "${old_backups[0]}"
            old_backups=("${old_backups[@]:1}")
        done
    fi
    printf 'Persisted nftables block %s (backup: %s).\n' "$block_id" "$backup"
)

aal_nft_remove_live_rules() {
    local family="$1" table="$2" chain="$3" rule_comment="$4"
    local handle

    while IFS= read -r handle; do
        [[ "$handle" =~ ^[0-9]+$ ]] || continue
        nft delete rule "$family" "$table" "$chain" handle "$handle"
    done < <(_aal_nft_rule_handles "$family" "$table" "$chain" "$rule_comment")
}

# Re-inserts the live rules of every guard block so they sit above rules that
# were inserted after them. Call this once a script has added its own live
# accept rules. Only rules that are currently live are moved; the new copy is
# added before the old one is deleted, so the guard is never absent.
aal_nft_raise_guard_rules() {
    local config="${AAL_NFT_CONFIG:-/etc/nftables.conf}"
    local rule_re='^[[:space:]]*insert[[:space:]]+rule[[:space:]]+([a-z0-9]+)[[:space:]]+([A-Za-z0-9_-]+)[[:space:]]+([A-Za-z0-9_-]+)[[:space:]].*[[:space:]]comment[[:space:]]+"([^"]+)"[[:space:]]*$'
    local line family table chain rule_comment handle
    local -a old_handles

    command -v nft &>/dev/null || return 0
    [[ -f "$config" ]] || return 0

    while IFS= read -r line; do
        [[ "$line" =~ $rule_re ]] || continue
        family="${BASH_REMATCH[1]}"
        table="${BASH_REMATCH[2]}"
        chain="${BASH_REMATCH[3]}"
        rule_comment="${BASH_REMATCH[4]}"
        old_handles=()
        while IFS= read -r handle; do
            [[ "$handle" =~ ^[0-9]+$ ]] && old_handles+=("$handle")
        done < <(_aal_nft_rule_handles "$family" "$table" "$chain" "$rule_comment")
        (( ${#old_handles[@]} > 0 )) || continue
        nft -f - <<< "$line" || return 1
        for handle in "${old_handles[@]}"; do
            nft delete rule "$family" "$table" "$chain" handle "$handle" || true
        done
    done < <(
        awk "$_AAL_NFT_GUARD_AWK"'
            /^# BEGIN AwesomeArchLinux: [a-z0-9-]+$/ { inside = 1; rules = 0; bad = 0; count = 0; next }
            /^# END AwesomeArchLinux: [a-z0-9-]+$/ {
                if (inside && is_guard()) {
                    for (i = 1; i <= count; i++) print buffered[i]
                }
                inside = 0
                next
            }
            inside { block_line($0); buffered[++count] = $0 }
        ' "$config"
    )
}
