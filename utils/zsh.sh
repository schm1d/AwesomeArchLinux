#!/usr/bin/env bash

# =============================================================================
# Script:      zsh.sh
# Description: Installs and configures Zsh with Oh My Zsh, syntax highlighting,
#              autosuggestions, Powerlevel10k theme, and umask/history hardening.
#
# Author:      Bruno Schmid @brulliant
# LinkedIn:    https://www.linkedin.com/in/schmidbruno/
#
# Usage:       ./zsh.sh
# =============================================================================

set -euo pipefail

BBlue='\033[1;34m'
BRed='\033[1;31m'
BGreen='\033[1;32m'
BYellow='\033[1;33m'
NC='\033[0m'

# Must NOT run as root — Oh My Zsh installs into user home
if [ "$(id -u)" -eq 0 ]; then
    echo -e "${BRed}Do not run this script as root. Run as your normal user.${NC}" >&2
    exit 1
fi

for cmd in git curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${BRed}Required command '$cmd' not found. Install it first.${NC}" >&2
        exit 1
    fi
done

if ! command -v zsh &>/dev/null; then
    echo -e "${BBlue}Installing Zsh...${NC}"
    sudo pacman -S --needed --noconfirm zsh
fi

ZSH_PATH="$(command -v zsh)"
CURRENT_LOGIN_SHELL="$(getent passwd "$(id -un)" | cut -d: -f7)"
if [ "$(basename "${CURRENT_LOGIN_SHELL:-}")" != "zsh" ]; then
    echo -e "${BBlue}Setting Zsh as the default shell...${NC}"
    chsh -s "$ZSH_PATH" || {
        echo -e "${BYellow}chsh failed. You can set it manually: chsh -s $ZSH_PATH${NC}" >&2
    }
fi

# Oh My Zsh and the two plugins are third-party code that runs in every
# interactive shell. Install fixed revisions instead of whatever each default
# branch holds today; for tags the commit is checked as well, because a tag
# can be moved upstream. Updating later stays a deliberate step (`omz update`
# asks first), and moving a pin here means reading upstream's changes first.
OHMYZSH_COMMIT="c0140703a53eb0d22be44f7bac318d0baacc927c"   # master on 2026-11-20 (upstream has no release tags)
ZSH_AUTOSUGGESTIONS_TAG="v0.7.1"
ZSH_AUTOSUGGESTIONS_COMMIT="e52ee8ca55bcc56a17c828767a3f98f22a68d4eb"
ZSH_SYNTAX_HIGHLIGHTING_TAG="0.8.0"
ZSH_SYNTAX_HIGHLIGHTING_COMMIT="db085e4661f6aafd24e5acb5b2e17e4dd5dddf3e"

clone_pinned() {
    local url="$1" tag="$2" commit="$3" dest="$4" head
    git -c advice.detachedHead=false clone --depth=1 --branch "$tag" -- "$url" "$dest"
    head="$(git -C "$dest" rev-parse HEAD)"
    if [ "$head" != "$commit" ]; then
        # Do not leave unverified code where the shell would load it.
        rm -rf -- "$dest"
        echo -e "${BRed}${url}: tag ${tag} is at ${head}, expected ${commit}. Not installed.${NC}" >&2
        exit 1
    fi
}

if [ ! -d "$HOME/.oh-my-zsh" ]; then
    echo -e "${BBlue}Installing Oh My Zsh...${NC}"
    # Blob-less clone with full history: the work tree is the pinned commit on
    # a normal 'master' branch, so `omz update` keeps working.
    git clone --filter=blob:none --no-checkout https://github.com/ohmyzsh/ohmyzsh.git "$HOME/.oh-my-zsh"
    if ! git -C "$HOME/.oh-my-zsh" checkout -q -B master "$OHMYZSH_COMMIT"; then
        rm -rf -- "$HOME/.oh-my-zsh"
        echo -e "${BRed}Could not check out Oh My Zsh commit ${OHMYZSH_COMMIT}. Not installed.${NC}" >&2
        exit 1
    fi
fi
chmod 700 "$HOME/.oh-my-zsh"

ZSH_CUSTOM="${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}"
ZSHRC="$HOME/.zshrc"

if [ ! -f "$ZSHRC" ] && [ -f "$HOME/.oh-my-zsh/templates/zshrc.zsh-template" ]; then
    cp "$HOME/.oh-my-zsh/templates/zshrc.zsh-template" "$ZSHRC"
fi

if [ ! -d "$ZSH_CUSTOM/plugins/zsh-autosuggestions" ]; then
    echo -e "${BBlue}Installing zsh-autosuggestions...${NC}"
    clone_pinned https://github.com/zsh-users/zsh-autosuggestions.git \
        "$ZSH_AUTOSUGGESTIONS_TAG" "$ZSH_AUTOSUGGESTIONS_COMMIT" "$ZSH_CUSTOM/plugins/zsh-autosuggestions"
fi

if [ ! -d "$ZSH_CUSTOM/plugins/zsh-syntax-highlighting" ]; then
    echo -e "${BBlue}Installing zsh-syntax-highlighting...${NC}"
    clone_pinned https://github.com/zsh-users/zsh-syntax-highlighting.git \
        "$ZSH_SYNTAX_HIGHLIGHTING_TAG" "$ZSH_SYNTAX_HIGHLIGHTING_COMMIT" "$ZSH_CUSTOM/plugins/zsh-syntax-highlighting"
fi

# Powerlevel10k and its font are AUR recipes: mutable, user-submitted build
# instructions. They go through the reviewed builder (recipe shown, typed
# confirmation on the terminal, disposable build user) instead of
# `yay --noconfirm`. Both are optional, so a declined review only skips them.
P10K_MISSING=()
if ! pacman -Qq ttf-meslo-nerd-font-powerlevel10k &>/dev/null; then
    P10K_MISSING+=(ttf-meslo-nerd-font-powerlevel10k)
fi
if ! pacman -Qq zsh-theme-powerlevel10k-git &>/dev/null && ! pacman -Qq zsh-theme-powerlevel10k &>/dev/null; then
    P10K_MISSING+=(zsh-theme-powerlevel10k-git)
fi

if [ "${#P10K_MISSING[@]}" -gt 0 ]; then
    SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    AUR_LIB=""
    for candidate in "$SCRIPT_DIR/../hardening/lib/aur-review.sh" "$SCRIPT_DIR/aur-review.sh"; do
        if [ -r "$candidate" ]; then
            AUR_LIB="$candidate"
            break
        fi
    done

    if [ -z "$AUR_LIB" ]; then
        echo -e "${BYellow}hardening/lib/aur-review.sh not found — skipping Powerlevel10k installation.${NC}" >&2
        echo "Run this script from a full checkout of the repository if Powerlevel10k is desired." >&2
    else
        echo -e "${BBlue}Installing Powerlevel10k font and theme (each recipe is shown for review first)...${NC}"
        sudo pacman -S --needed --noconfirm base-devel git
        for package in "${P10K_MISSING[@]}"; do
            # shellcheck disable=SC2016
            if ! sudo bash -c 'set -euo pipefail; source "$1"; aal_aur_install_reviewed "$2"' _ "$AUR_LIB" "$package"; then
                echo -e "${BYellow}${package} was not installed (review declined, no terminal, or the build failed) — continuing without it.${NC}" >&2
            fi
        done
    fi
fi

if [ -f "$ZSHRC" ]; then
    # Keep plugins loaded once in the proper order (autosuggestions before syntax-highlighting)
    if grep -q '^plugins=(git)$' "$ZSHRC"; then
        echo -e "${BBlue}Enabling plugins in .zshrc...${NC}"
        sed -i 's/^plugins=(git)$/plugins=(git zsh-autosuggestions zsh-syntax-highlighting)/' "$ZSHRC"
    fi

    if ! grep -q "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE" "$ZSHRC"; then
        echo "ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=8'" >> "$ZSHRC"
    fi

    if ! grep -qxF 'umask 027' "$ZSHRC"; then
        echo 'umask 027' >> "$ZSHRC"
    fi

    if ! grep -q 'HIST_IGNORE_SPACE' "$ZSHRC"; then
        echo 'setopt HIST_IGNORE_SPACE HIST_IGNORE_ALL_DUPS' >> "$ZSHRC"
    fi

    if [ -r /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme ] && ! grep -q "powerlevel10k.zsh-theme" "$ZSHRC"; then
        echo 'source /usr/share/zsh-theme-powerlevel10k/powerlevel10k.zsh-theme' >> "$ZSHRC"
    fi

    chmod 600 "$ZSHRC"
fi

echo -e "${BGreen}Zsh configuration completed. Log out and back in to use Zsh.${NC}"
