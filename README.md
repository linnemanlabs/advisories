# LinnemanLabs Advisories

Advisories and PoCs for vulnerabilities I have discovered during research. Links to write-ups and PoCs for each.

## Advisories

| Project | Findings | CVEs | Result | Write-up | PoC |
|---|---|---|---|---|---|
| [bluez](https://github.com/bluez/bluez) | ? | ? | LPE to root | Coordinating Post-Embargo | Withheld |
| [nm-l2tp](https://github.com/nm-l2tp/NetworkManager-l2tp) | 1 | 1 | LPE to root | soon | soon |
| [open-iscsi](https://github.com/open-iscsi/open-iscsi) | ? | ? | Authorization bypass on control socket | soon | soon |
| [open-isns](https://github.com/open-iscsi/open-isns) | ? | ? | ? | Embargo | Withheld |
| [pi-hole](https://github.com/pi-hole/pi-hole/) | 5 | Pending | 2 authenticated-RCE, 2 root LPE, 1 file disclosure | [Pi-hole: root with extra steps](https://linnemanlabs.com/posts/pi-hole-root-with-extra-steps) | [Available](/poc/pi-hole/) |
| [ceph](https://github.com/ceph/ceph) | 6 | Pending | Cross-tenant and cross-pool file disclosure | Embargo | Withheld |
| [fprintd](https://gitlab.freedesktop.org/libfprint/fprintd) | 17 | 1 | Fingerprint bypass, LPE to root | soon | soon |
| [KWin](https://invent.kde.org/plasma/kwin) / [Mutter](https://gitlab.gnome.org/GNOME/mutter) | 1 | x | Unprivileged keylogging via compositor accessibility D-Bus | [Hello, my name is Orca](https://linnemanlabs.com/posts/hello-my-name-is-orca/) | [Available](poc/a11y-keyboardmonitor/) |


## Legal

These tools are intended for authorized security testing and research only.

Unauthorized use against systems you do not own or have explicit permission to test is illegal.

## License

MIT. Copy it, steal it, modify it, learn from it, share your improvements with me. Or don't. It's code, do what you want with it.