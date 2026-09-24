# LinnemanLabs Pi-Hole Advisories

Pi-hole v6.0.0 through current have several vulnerabilities. The PoCs I wrote here cover 4 web-session -> RCE, 2 pihole -> root exec LPE, and 1 pihole arbitrary file disclosure. There are several more vulnerabilities covered in the write-up.

Web-session -> pihole exec is possible through the latest v6.7.1 with the bugs covered here.

pihole -> root exec LPE is possible directly through v6.7, and potentially indirectly through file disclosures and the gravity technique documented in the post through the current release.

Write-up is at [linnemanlabs.com/pi-hole-root-with-extra-steps](https://linnemanlabs.com/posts/pi-hole-root-with-extra-steps/).

## Vulnerabilities

| Finding                                         | CVE/GHSA | Result |
| ----------------------------------------------- | -------- | ------ |
| dnsmasq_lines config -> pihole exec             | [GHSA-ww5x-xx4x-qvjr](https://github.com/pi-hole/FTL/security/advisories/GHSA-ww5x-xx4x-qvjr)     | code exec as pihole user |
| CivetWeb advancedOpts config -> pihole exec     | [CVE-2026-65963](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x)          | code exec as pihole user |
| CivetWeb advancedOpts fix bypass -> pihole exec | [GHSA-2794-hrj8-5jg9](https://github.com/pi-hole/FTL/security/advisories/GHSA-2794-hrj8-5jg9)     | code exec as pihole user |
| webroot+serveall -> log poison -> pihole exec   | [GHSA-gx63-h4w6-f46g](https://github.com/pi-hole/FTL/security/advisories/GHSA-gx63-h4w6-f46g)     | code exec as pihole user |
| CAP_CHOWN pihole -> root exec                   | [GHSA-j8vh-6fp9-cjcx](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-j8vh-6fp9-cjcx) | pihole to root LPE |
| prestart pihole -> root exec                    | [CVE-2026-50130](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww)      | pihole to root LPE |
| Updatechecker symlink race                      | [GHSA-xch2-4qxw-g5vj](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-xch2-4qxw-g5vj) | arbitrary file disclosure |

## Proofs of Concept

These PoCs modify live Pi-hole configuration and may alter DHCP leases, root’s crontab, logrotate configuration, file ownership, or the mode of security-sensitive files. Run them only on disposable test systems and/or review and understand each script before running them.

| PoC                                                                                                                             | Ran on               | Affected    | Fixed        | Result          |
| ------------------------------------------------------------------------------------------------------------------------------- | -------------------- | ----------- | ------------ | --------------- |
| [dnsmasq_lines_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/dnsmasq_lines_exec.sh)                 | FTL 6.7              | ≤6.7        | 6.7.1        | pihole exec     |
| [civetweb_advancedopts_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/civetweb_advancedopts_exec.sh) | FTL 6.6.2            | 6.3 - 6.6.2 | 6.7          | pihole exec     |
| [civetweb_advancedopts_put.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/civetweb_advancedopts_put.sh)   | FTL 6.7              | ≤6.7        | 6.7.1        | pihole exec     |
| [logpoison_lp_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/logpoison_lp_exec.sh)                   | FTL 6.7              | ≤6.7.1      | in HEAD only | pihole exec     |
| [updatecheck_symlink.py](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/updatecheck_symlink.py)               | Core 6.4.3           | ≤current    | unfixed      | file disclosure |
| [cap_chown_cron.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/cap_chown_cron.sh)                         | Core 6.4.3 / FTL 6.7 | ≤6.7        | 6.7.1        | pihole -> root  |
| [prestart_logrotate.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/prestart_logrotate.sh)                 | Core 6.4.2           | 6.0 - 6.4.2 | 6.4.3        | pihole -> root  |

| Chain PoC                     | Ran on                | Affected | Fixed  | Result      |
| ----------------------------- | --------------------- | -------- | ------ | ----------- |
| [chain_dnsmasq_logrotate_root.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_dnsmasq_logrotate_root.sh)        | FTL 6.6.2 /Core 6.4.2 | ≤6.7     | 6.7.1  | web -> root |
| [chain_part2.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_part2.sh)                | FTL 6.7 / Core 6.4.3  | ≤6.7     | 6.7.1  | web -> root |
| [chain_part3.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_part3.sh)                | FTL 6.7 / Core 6.4.3  | ≤6.7     | 6.7.1  | web -> root |

The end-to-end chain combines vulnerabilities to go from web-session to pi-hole code-exec, then escalate to root code-exec.

- [chain_dnsmasq_logrotate_root.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_dnsmasq_logrotate_root.sh) was the first version using dnsmas_lines. It will attempt both the CAP_CHOWN and the logrotate escalations.
- [chain_advancedopts_webdav_capchown.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_advancedopts_webdav_capchown.sh) uses the newer CivetWeb `webserver.advancedOpts` -> WebDAV `PUT` vulnerabilities. It is cleaner since it provides a direct webshell with output.
- [chain_logpoison_lp_capchown.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_logpoison_lp_capchown.sh) uses the latest webroot+log poison vulnerabilities. If you are on v6.7+ that patched the other vulnerabilities, this is the one to use.

## Credits

Three of these bugs were also found by other researchers around the same time as me:

| Bug | Researcher | GHSA |
| --- | ---------- | ---- |
| Pi-hole prestart logrotate | [supperhellokitty20](https://github.com/supperhellokitty20) | [GHSA-h8w9-qx2v-wrww](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww)|
| CivetWeb advancedOpts | [SakusenSec](https://github.com/SakusenSec) | [GHSA-8j7w-m3cr-6q6x](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x) |
| dnsmasq_lines config | [Michael-JRead](https://github.com/Michael-JRead) and [m19simmons](https://github.com/m19simmons) | [GHSA-ww5x-xx4x-qvjr](https://github.com/pi-hole/FTL/security/advisories/GHSA-ww5x-xx4x-qvjr) |

## Legal

These tools are intended for authorized security testing and research only.

Unauthorized use against systems you do not own or have explicit permission to test is illegal.

## License

MIT. Copy it, steal it, modify it, learn from it, share your improvements with me. Or don't. It's code, do what you want with it.
