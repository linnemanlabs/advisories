# LinnemanLabs Pi-Hole Advisories

Pi-hole v6.0.0 through current have several vulnerabilities. 2 web-session -> RCE, 2 pihole -> root LPE, and 1 pihole arbitrary file disclosure.

Write-up is at [linnemanlabs.com/pi-hole-root-with-extra-steps](https://linnemanlabs.com/pi-hole-root-with-extra-steps)

## Vulnerabilities

| Finding                       | PoC                                                                  | CVE | Result |
| ----------------------------- | -------------------------------------------------------------------- | --- | ------ |
| dnsmasq_lines config -> pihole exec     | [dnsmasq_lines_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/dnsmasq_lines_exec.sh) |     | code exec as pihole user |
| CivitWeb advancedOpts config -> pihole exec  | [civitweb_advancedopts_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/civetweb_advancedopts_exec.sh) | [CVE-2026-65963](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x) ([SakusenSec](https://github.com/SakusenSec)) | code exec as pihole user |
| CAP_CHOWN pihole -> root exec     | [cap_chown_cron.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/cap_chown_cron.sh) |     | pihole to root LPE |
| prestart pihole -> root exec       | [prestart_logrotate.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/prestart_logrotate.sh) | [CVE-2026-50130](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww) ([supperhellokitty20](https://github.com/supperhellokitty20)) | pihole to root LPE |
| Updatechecker symlink race    |  [updatecheck_symlink_flip.py](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/updatecheck_symlink_flip.py) |     | pihole arbitrary file disclosure |
| Web -> Root exec chain    |  [chain_web_root_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_web_root_exec.sh) |     | root code exec from a web-session |

## Credits

I independently found and privately disclosed each of these bugs.

Two were publicly-disclosed from other researchers in the following days by the project. Those were almost certainly found earlier but not public yet as they went through the disclosure process.

| Bug | Researcher | CVE | GHSA |
| --- | ---------- | --- | ---- |
| Pi-hole prestart logrotate | [supperhellokitty20](https://github.com/supperhellokitty20) | CVE-2026-50130 | [GHSA-h8w9-qx2v-wrww](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww)|
| CivetWeb advancedOpts | [SakusenSec](https://github.com/SakusenSec) | CVE-2026-65963 | [GHSA-8j7w-m3cr-6q6x](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x) |

## Legal

These tools are intended for authorized security testing and research only.

Unauthorized use against systems you do not own or have explicit permission to test is illegal.

## License

MIT. Copy it, steal it, modify it, learn from it, share your improvements with me. Or don't. It's code, do what you want with it.