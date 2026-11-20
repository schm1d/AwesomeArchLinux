#!/usr/bin/env bash

# Shared validation helpers for values written into service configuration or
# filesystem paths. Callers decide whether single-label hostnames such as
# "localhost" are appropriate for their use case.
#
# ASCII letters and digits are spelled out on purpose: in a UTF-8 locale the
# ranges A-Z/a-z also match accented letters, so "bücher.de" would pass and
# then break the consuming service. Internationalized names must be supplied
# in their punycode (xn--) form.

aal_valid_hostname() {
    local name="$1" label
    local alnum='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    local whole_re="^[${alnum}.-]+\$"
    local label_re="^[${alnum}]([${alnum}-]*[${alnum}])?\$"
    local -a labels

    # Validate the complete string before splitting it. The read below only
    # consumes the first line, so an embedded newline would otherwise carry
    # unchecked text into the configuration file the value is written to.
    [[ "$name" =~ $whole_re ]] || return 1
    (( ${#name} >= 1 && ${#name} <= 253 )) || return 1
    [[ "$name" != .* && "$name" != *. && "$name" != *..* ]] || return 1
    IFS='.' read -r -a labels <<< "$name"
    (( ${#labels[@]} >= 1 )) || return 1
    for label in "${labels[@]}"; do
        (( ${#label} >= 1 && ${#label} <= 63 )) || return 1
        [[ "$label" =~ $label_re ]] || return 1
    done
}

aal_valid_email() {
    local address="$1" local_part domain_part
    local alnum='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    local local_re="^[${alnum}_%+-]+([.][${alnum}_%+-]+)*\$"

    [[ "$address" == *@* && "$address" != *@*@* ]] || return 1
    local_part="${address%@*}"
    domain_part="${address##*@}"
    (( ${#local_part} >= 1 && ${#local_part} <= 64 )) || return 1
    [[ "$local_part" =~ $local_re ]] || return 1
    aal_valid_hostname "$domain_part"
}

aal_valid_fqdn() {
    local name="$1"

    [[ "$name" == *.* ]] && aal_valid_hostname "$name"
}
