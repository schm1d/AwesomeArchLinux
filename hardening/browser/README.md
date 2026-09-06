# Browser Hardening (enterprise policies + optional Firejail)

Writes machine-wide enterprise policies for Firefox and Chromium/Chrome. Optionally wraps the binary in Firejail and can apply [arkenfox](https://github.com/arkenfox/user.js) to an existing Firefox profile.

Custom AppArmor browser profiles are **not** shipped. They bit-rot against GPU, PipeWire, WebRTC, xdg-desktop-portal, and downloads.

```bash
sudo ./browser.sh
sudo ./browser.sh --firefox --chromium
sudo ./browser.sh --firejail
sudo ./browser.sh --arkenfox
```

## Gotchas

- `kernel.unprivileged_userns_clone=0` (sysctl `strict` profile) breaks Chromium's layer-1 sandbox and many Firejail features. Desktops should stay on the `workstation` profile.
- Policies apply to every profile on the machine. Preferences use `"Status": "default"` so they remain user-toggleable.
- Chromium `DefaultCookiesSetting=4` blocks third-party cookies only. `2` would block all cookies and log everyone out.
- Do not symlink over `/usr/bin/firefox`. Pacman will fight you. `/usr/local/bin` wrappers are the supported shadow.
- arkenfox is cloned at runtime; a stale vendored `user.js` is not kept in this repo.

## References

- [Firefox Enterprise Policies](https://mozilla.github.io/policy-templates/)
- [Chrome Enterprise Policy List](https://chromeenterprise.google/policies/)
- [arkenfox user.js](https://github.com/arkenfox/user.js)
- [ArchWiki: Firejail](https://wiki.archlinux.org/title/Firejail)
