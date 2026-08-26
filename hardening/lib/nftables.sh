#!/usr/bin/env bash

# Shared nftables helpers for the hardening scripts. The installer owns the
# base ruleset; feature scripts may only add or replace their marked blocks.

aal_nft_persist_block() (
    local block_id="$1"
    local config="${AAL_NFT_CONFIG:-/etc/nftables.conf}"
    local begin_marker end_marker body candidate backup begin_count end_count

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
    body=$(mktemp "$(dirname "$config")/.${block_id}.body.XXXXXX") || return 1
    candidate=$(mktemp "$(dirname "$config")/.nftables.conf.XXXXXX") || {
        rm -f -- "$body"
        return 1
    }
    cat > "$body"
    awk -v begin="$begin_marker" -v end="$end_marker" '
        $0 == begin { managed = 1; next }
        $0 == end   { managed = 0; next }
        !managed    { print }
    ' "$config" > "$candidate"
    {
        printf '\n%s\n' "$begin_marker"
        cat "$body"
        printf '%s\n' "$end_marker"
    } >> "$candidate"

    if ! nft -c -f "$candidate"; then
        printf 'Refusing to install invalid nftables configuration for %s.\n' "$block_id" >&2
        rm -f -- "$body" "$candidate"
        return 1
    fi

    backup=$(mktemp "${config}.bak.$(date +%Y%m%d-%H%M%S).${block_id}.XXXXXX") || {
        rm -f -- "$body" "$candidate"
        return 1
    }
    cp -a -- "$config" "$backup"
    install -o root -g root -m 0644 "$candidate" "$config"
    rm -f -- "$body" "$candidate"
    printf 'Persisted nftables block %s (backup: %s).\n' "$block_id" "$backup"
)

aal_nft_remove_live_rules() {
    local family="$1" table="$2" chain="$3" rule_comment="$4"
    local handle

    while IFS= read -r handle; do
        [[ "$handle" =~ ^[0-9]+$ ]] || continue
        nft delete rule "$family" "$table" "$chain" handle "$handle"
    done < <(
        nft -a list chain "$family" "$table" "$chain" 2>/dev/null |
            awk -v marker="comment \"${rule_comment}\"" '
                index($0, marker) {
                    for (i = 1; i <= NF; i++) {
                        if ($i == "handle") print $(i + 1)
                    }
                }
            '
    )
}
