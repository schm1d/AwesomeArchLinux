#!/usr/bin/env bash

# Shared validation helpers for values written into service configuration or
# filesystem paths. Callers decide whether single-label hostnames such as
# "localhost" are appropriate for their use case.

aal_valid_hostname() {
    local name="$1" label
    local -a labels

    (( ${#name} >= 1 && ${#name} <= 253 )) || return 1
    [[ "$name" != .* && "$name" != *. && "$name" != *..* ]] || return 1
    IFS='.' read -r -a labels <<< "$name"
    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

aal_valid_email() {
    local address="$1" local_part domain_part

    [[ "$address" == *@* && "$address" != *@*@* ]] || return 1
    local_part="${address%@*}"
    domain_part="${address##*@}"
    (( ${#local_part} >= 1 && ${#local_part} <= 64 )) || return 1
    [[ "$local_part" =~ ^[A-Za-z0-9_%+-]+([.][A-Za-z0-9_%+-]+)*$ ]] || return 1
    aal_valid_hostname "$domain_part"
}
