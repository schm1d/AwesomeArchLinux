# Browser Hardening (enterprise policies + optional Firejail)

Writes machine-wide enterprise policies for Firefox, Chromium/Chrome, and Brave. Optionally wraps installed browser binaries in Firejail and can apply [arkenfox](https://github.com/arkenfox/user.js) to an existing Firefox profile.

Custom AppArmor browser profiles are **not** shipped. They bit-rot against GPU, PipeWire, WebRTC, xdg-desktop-portal, and downloads.

```bash
sudo ./browser.sh                       # Auto-detect installed browsers (/usr/bin/*)
sudo ./browser.sh --firefox --chromium  # Explicit Firefox + Chromium/Chrome
sudo ./browser.sh --brave               # Explicit Brave policy (/etc/brave/policies/managed/10-awesome-hardening.json)
sudo ./browser.sh --firejail            # Add /usr/local/bin Firejail wrappers
sudo ./browser.sh --arkenfox            # Clone/update arkenfox into user's Firefox profile
sudo ./browser.sh --no-packages         # Write policies without running pacman
```

## Gotchas

- `kernel.unprivileged_userns_clone=0` (sysctl `strict` profile) breaks Chromium/Brave's layer-1 sandbox and many Firejail features. Desktops should stay on the `workstation` profile.
- Auto-detection checks real `/usr/bin/{firefox,chromium,google-chrome-stable,brave,brave-browser}` binaries rather than `PATH` (so `/usr/local/bin` Firejail wrappers do not skew detection), and does not install `chromium` when only `google-chrome-stable` was detected. When no browser is installed at all, the Firefox and Chromium policy files are staged and **no browser package is installed**; pass `--firefox` and/or `--chromium` to install one.
- Firefox reads a single `/etc/firefox/policies/policies.json`. If one already exists and differs, it is saved next to it as `policies.json.bak.<timestamp>` before being replaced (merge your own policies back by hand).
- Policies apply to every profile on the machine. Firefox `Preferences` use `"Status": "default"` so they remain user-toggleable.
- Chromium and Brave use `SafeBrowsingProtectionLevel=1` (Standard local hash-prefix protection, avoiding Enhanced Safe Browsing telemetry) and force-install uBlock Origin Lite.
- `--brave` matches `utils/brave.sh`: it disables Brave Rewards, Crypto Wallet, Brave VPN, Leo AI chat, built-in password manager, search suggestions, sync, and non-proxied WebRTC UDP leaks, and blocks geolocation, notifications, and sensors by default.
- Chromium/Brave block third-party cookies with `BlockThirdPartyCookies=true`. `DefaultCookiesSetting` is deliberately left unset: `4` means session-only (every cookie is wiped when the browser exits, logging users out on each restart) and `2` blocks all cookies. Re-running the script rewrites the managed policy file and drops the old `DefaultCookiesSetting=4`.
- Do not symlink over `/usr/bin/firefox`, `/usr/bin/chromium`, `/usr/bin/google-chrome-stable`, `/usr/bin/brave`, or `/usr/bin/brave-browser`. Pacman will fight you. `/usr/local/bin` wrappers are the supported shadow.
- arkenfox is cloned and executed entirely as the target user (`updater.sh -s -d`, plus `prefsCleaner.sh -s -d` staged inside the profile when `prefs.js` exists); a stale vendored `user.js` is not kept in this repo.

## References

- [Firefox Enterprise Policies](https://mozilla.github.io/policy-templates/)
- [Chrome Enterprise Policy List](https://chromeenterprise.google/policies/)
- [Brave Group Policy](https://support.brave.app/hc/en-us/articles/360039248271-Group-Policy)
- [arkenfox user.js](https://github.com/arkenfox/user.js)
- [ArchWiki: Firejail](https://wiki.archlinux.org/title/Firejail)
