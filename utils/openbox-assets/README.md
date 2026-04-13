# openbox-assets

Vendored Openbox / Tint2 / Rofi / Dunst / Picom configuration tree, plus the
Fleon Openbox theme. Installed and recolored at install time by
`utils/openbox.sh`.

## Origin

Vendored from [owl4ce/dotfiles](https://github.com/owl4ce/dotfiles).

| Path | Upstream | License |
|---|---|---|
| `config/openbox/`, `config/tint2/`, `config/rofi/`, `config/dunst/`, `config/picom.conf` | `.config/...` | GPL-3.0 (`LICENSE-dotfiles-ng`) |
| `themes/Fleon/` | `.themes/Fleon/` | GPL-2.0 (`LICENSE-Fleon`) |

See `NOTICE` for full licensing details. The rest of the AwesomeArchLinux
repository remains MIT-licensed; `utils/openbox.sh` installs these files but
does not derive from them.

## What's in here

```
openbox-assets/
├── LICENSE-dotfiles-ng        GPL-3.0 (covers config/)
├── LICENSE-Fleon              GPL-2.0 (covers themes/Fleon/)
├── NOTICE                     directory-level licensing summary
├── README.md                  this file
├── config/
│   ├── openbox/
│   │   ├── autostart.sh       (rewritten — see modifications)
│   │   ├── environment        (verbatim)
│   │   ├── menu.xml           (verbatim; replaced at install time by overlay)
│   │   └── rc.xml             (verbatim; patched at install time by overlays)
│   ├── tint2/
│   │   └── tint2rc            (vendored from eyecandy-vertical.artistic; stripped)
│   ├── dunst/
│   │   └── dunstrc            (vendored from eyecandy.artistic)
│   ├── rofi/
│   │   ├── config.rasi        (patched: imports eyecandy colorscheme)
│   │   └── themes/
│   │       ├── main.rasi
│   │       ├── shared.rasi
│   │       ├── exts.rasi
│   │       └── colorschemes/
│   │           └── eyecandy.rasi
│   └── picom.conf             (verbatim)
└── themes/
    └── Fleon/openbox-3/
        ├── themerc
        └── *.xbm              (10 button mask files)
```

## Install pipeline

`utils/openbox.sh` performs three transformations on these files at install:

1. **Copy** to the user's `~/.config/` (and Fleon to `/usr/share/themes/Fleon-ArchBlue/`).
2. **Recolor** — case-insensitive `sed` swap of the upstream pink/magenta
   palette to Arch Linux blue (`#1793D1` and derivatives), plus a
   `your_web_browser` placeholder fix in `dunstrc`.
3. **Overlay** — six idempotent patches: window-snapping keybinds,
   power-menu keybind, theme-name patch (`Fleon` → `Fleon-ArchBlue`),
   `obexit` script + rofi theme installation, `menu.xml` replacement
   with a richer root menu (dynamic via `obmenu-generator` if installed),
   and `xrandr --auto` + `autorandr` block in autostart.

## Modifications already applied at vendor time

- **`config/openbox/autostart.sh`** — full rewrite. Upstream sources
  `${HOME}/.joyfuld` and calls `joyd_*` functions; we ship a clean
  standalone version preserving the launcher ordering intent
  (polkit → xsettingsd → dunst → tray → compositor → wallpaper → panel).
- **`config/tint2/tint2rc`** — removed 9 launcher buttons + the music
  executor that pointed at unshipped helper scripts. Stripped sections
  carry inline `# AwesomeArch: removed ...` comments.
- **`config/rofi/config.rasi`** — single-line patch to import
  `themes/colorschemes/eyecandy.rasi` (we don't vendor the upstream
  default `mechanical.rasi`).
- All other files are byte-for-byte verbatim copies of the upstream
  sources at the commit date this directory was vendored.

## Updating the vendored tree

To bump to a newer upstream commit, re-vendor by re-running the same
file copies, re-applying the three modifications above, and updating
the `LICENSE-*` files if the upstream license texts changed.
